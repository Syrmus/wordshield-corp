from __future__ import annotations

import asyncio
import bisect
import json
import os
import re
from collections import defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from time import monotonic

import httpx

from .config import Settings
from .models import Block, Detection, EntityType, Finding, hard_boundaries
from .technical_metadata import is_technical_schema_value, omit_technical_schemas

PATTERNS: list[tuple[EntityType, re.Pattern[str], float]] = [
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-zА-Яа-я]{2,}\b"), 0.99),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?\d[\d ()-]{7,}\d)(?!\d)"), 0.96),
    ("URL", re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\]\[\"']+"), 0.99),
    (
        "IP",
        re.compile(
            r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?(?!\d)"
        ),
        0.99,
    ),
    (
        "TAX_ID",
        re.compile(r"(?i)(?:(?<=\bИНН[: №\s])\d{10,12}|\bИНН\s*[:№]?\s*\d{10,12})"),
        0.98,
    ),
    ("TAX_ID", re.compile(r"(?i)\bКПП\s*[:№]?\s*\d{9}\b"), 0.98),
    ("REG_ID", re.compile(r"(?i)\bОГРН(?:ИП)?\s*[:№]?\s*\d{13,15}\b"), 0.98),
    ("BANK", re.compile(r"(?i)\b(?:р/?с|к/?с|сч[её]т)\s*[:№]?\s*\d{20}\b"), 0.99),
    (
        "BANK",
        re.compile(r"(?i)\b(?:БИК|BIC|SWIFT)\s*[:№]?\s*[A-ZА-Я0-9]{8,11}\b"),
        0.98,
    ),
    ("BANK", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), 0.98),
    (
        "DOCUMENT_ID",
        re.compile(
            r"(?i)\b(?:договор|сч[её]т|акт|заказ|дело|клиент|объект)\s*(?:№|N|#)\s*[\w./-]{2,}\b"
        ),
        0.94,
    ),
    (
        "PASSPORT",
        re.compile(r"(?i)\b(?:паспорт|серия\s+паспорта|passport)\s*[:№]?\s*\d{4}[\s-]?\d{6}\b"),
        0.99,
    ),
    (
        "SECRET",
        re.compile(
            r"(?i)\b(?:api[_ -]?key|token|bearer|temporary\s+password|password|парол[ья]|секрет)"
            r"\s*(?:[:=]\s*|\s+)[^\s,;]{6,}"
        ),
        0.99,
    ),
    (
        "ACCOUNT",
        re.compile(r"(?i)\b(?:login|username|логин)\s*[:=]\s*[A-ZА-Я0-9._@+-]{3,}"),
        0.99,
    ),
    (
        "PRICE",
        re.compile(
            r"(?i)(?<!\w)(?:[$€£₽]\s?\d[\d .,\u00a0\u202f]*|\d[\d .\u00a0\u202f]*(?:[,.]\d{1,2})?\s?(?:руб(?:\.|лей)?|₽|USD|EUR|доллар(?:ов|а)?|евро))(?!\w)"
        ),
        0.98,
    ),
    (
        "DATE",
        re.compile(
            r"(?i)\b(?:от\s+)?(?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:19|20)\d{2}\b"
        ),
        0.88,
    ),
    (
        "DATE",
        re.compile(
            r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:T\d{2}:\d{2}(?::\d{2})?Z?)?\b"
        ),
        0.88,
    ),
]

LABEL_MAP: dict[str, EntityType] = {
    "account_number": "ACCOUNT",
    "private_address": "ADDRESS",
    "private_email": "EMAIL",
    "private_person": "PERSON",
    "private_phone": "PHONE",
    "private_url": "URL",
    "private_date": "DATE",
    "secret": "SECRET",
}


class DetectorUnavailable(RuntimeError):
    pass


DATE_TIME_RE = re.compile(
    r"(?P<date>(?:(?:19|20)\d{2}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2}))"
    r"(?:[Tt]|\s+(?:в\s+)?)"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?)Z?"
)
FULL_MONTH_DATE_RE = re.compile(
    r"(?i)(?<!\w)(?:«(?:0?[1-9]|[12]\d|3[01])»|(?:0?[1-9]|[12]\d|3[01]))"
    r"[ \t.,:;/-]{1,4}"
    r"(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)"
    r"[ \t.,:;/-]{1,4}(?:19|20)\d{2}\b(?:[ \t]+(?:года\b|г\.))?"
)
PERSON_TRIPLE_RE = re.compile(
    r"(?<!\w)[А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁ][а-яё]{2,})?"
    r"(?:[ \t]{1,3}[А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁ][а-яё]{2,})?){2}(?!\w)"
)
PATRONYMIC_RE = re.compile(
    r"(?i)(?:вич(?:а|у|ем|е)?|ич(?:а|у|ем|е)?|"
    r"вн(?:а|ы|е|у|ой|ою)|ичн(?:а|ы|е|у|ой|ою)|Ильич(?:а|у|ем|е)?)$"
)
PASSPORT_ISSUER_RE = re.compile(
    r"(?i)\b(?:[А-ЯЁ]{2,4}\s*№\s*\d{1,3}\s+)?отдел(?:а|ом)?\s+"
    r"[А-ЯЁA-Z]{2,15}\s+России\s+по\s+Санкт-Петербургу\s+и\s+"
    r"[А-ЯЁ][а-яё]{5,30}\s+(?:области\b|обл\.)"
)
PASSPORT_CITY_RE = re.compile(r"(?i)\bСанкт-Петербург[а-яё]{0,8}\b")
PASSPORT_SERIES_RE = re.compile(r"(?i)\bсерия\s*[:№]?\s*\d{4}\b")
PASSPORT_NUMBER_RE = re.compile(r"(?i)\bномер\s*[:№]?\s*\d{6}\b")
CADASTRAL_LABELED_RE = re.compile(
    r"(?i)\bкадастровый\s+номер\s*[:№]?\s*"
    r"\d{2}:\d{2}:\d{6,7}:\d{1,4}\b"
)
PATTERNS.append(("DATE", FULL_MONTH_DATE_RE, 0.92))
LATIN_COMPANY_WORD = r"(?:[A-Z0-9][A-Za-zÀ-ÖØ-öø-ÿ0-9’'&.\-]*|[a-z]+[A-Z][A-Za-z0-9’'&.\-]*)"
LATIN_COMPANY_FORM = (
    r"(?i:GmbH[ \t]+&[ \t]+Co\.?[ \t]+KG|(?:Pte|Pty|Co)\.?[ \t]+(?:Ltd\.?|Limited)|"
    r"Limited|Incorporated|Corporation|GmbH|UG[ \t]*\(haftungsbeschränkt\)|"
    r"L\.?L\.?C\.?|L\.?L\.?P\.?|Ltd\.?|Inc\.?|PLC|Corp\.?|"
    r"S\.?A\.?R\.?L\.?|S\.?R\.?L\.?|B\.V\.|N\.V\.|AG|KG)"
)
LATIN_COMPANY_RE = re.compile(
    r"(?<![\w’'])"
    r"(?!(?:The|This|Supplier|Customer|Buyer|Seller|Party|Company|Between|Dear)\b)"
    r"(?:[«\"“][A-Za-z0-9][^»\"”\r\n]{0,100}[»\"”]|"
    + LATIN_COMPANY_WORD + r"(?:[ \t\u00a0]+(?:(?:of|the|and|&|de|van|von)[ \t\u00a0]+)?"
    + LATIN_COMPANY_WORD + r"){0,7})"
    r"(?:[ \t\u00a0]*,[ \t\u00a0]*|[ \t\u00a0]+)" + LATIN_COMPANY_FORM + r"(?!\w)"
)
PATTERNS.extend([
    ("ORG", re.compile(r'(?i)\b(?:общество\s+с\s+ограниченной\s+ответственностью|публичное\s+акционерное\s+общество|акционерное\s+общество)\s*[«"][^»"\n]{2,100}[»"]'), 0.99),
    ("DOCUMENT_ID", re.compile(r"(?i)\b(?:contract|invoice|order)\s*(?:(?:no\.?|number|#|№)\s*)?[\w./-]{2,}\b"), 0.99),
    ("DOCUMENT_ID", re.compile(r"(?i)\b(?:company|registration)\s+(?:no\.?|number|#|№)\s*[A-Z0-9./-]{4,}\b"), 0.99),
    ("ORG", re.compile(r'\b(?:ООО|АО|ПАО|ЗАО|ОАО)\s*[«"][^»"\n]{2,100}[»"]'), 0.99),
    ("ORG", LATIN_COMPANY_RE, 0.99),
    ("ADDRESS", re.compile(
        r"(?i)\b\d{1,5}\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,4},\s*"
        r"[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+){0,3}\s+"
        r"[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2},\s*(?:United\s+Kingdom|UK)\b"
    ), 0.99),
    ("PRICE", re.compile(r"(?i)\b(?:EUR|USD|GBP)\s+\d[\d ,]*(?:\.\d{1,2})?\b"), 0.99),
    ("PRICE", re.compile(r"(?i)\b(?:оплата\s+в\s+течение\s+\d+\s+(?:рабочих\s+|календарных\s+)?дней(?:\s+после\s+(?:подписания|получения\s+сч[её]та))?|payment\s+within\s+\d+\s+(?:business\s+)?days(?:\s+of\s+(?:signing|invoice\s+receipt))?)\b"), 0.99),
    ("ORG", PASSPORT_ISSUER_RE, 0.97),
    ("PASSPORT", PASSPORT_SERIES_RE, 0.99),
    ("PASSPORT", PASSPORT_NUMBER_RE, 0.99),
    ("REG_ID", CADASTRAL_LABELED_RE, 0.99),
])
FIELD_VALUE_RE = re.compile(
    r"(?im)(?=(?<!\w)(?P<label>фио|full name|адрес(?:\s+(?:регистрации|проживания|для\s+корреспонденции))?|address|выдан|issued by|"
    r"ИНН|КПП|tax id|registration|р/с|account|БИК|BIC|паспорт|passport|"
    r"api key|internal login)\s*[:№]?\s+(?P<value>[^;\n]+))"
)
FIELD_TYPES = {"фио": "PERSON", "full name": "PERSON", "адрес": "ADDRESS", "address": "ADDRESS",
               "выдан": "ORG", "issued by": "ORG", "инн": "TAX_ID", "кпп": "TAX_ID",
               "tax id": "TAX_ID", "registration": "REG_ID", "р/с": "BANK", "account": "ACCOUNT",
               "бик": "BANK", "bic": "BANK", "паспорт": "PASSPORT", "passport": "PASSPORT",
               "api key": "SECRET", "internal login": "ACCOUNT"}
PURE_DATE_RE = re.compile(
    r"(?:(?:19|20)\d{2}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2})"
)
PURE_TIME_RE = re.compile(r"\d{1,2}:\d{2}(?::\d{2})?")
DOC_DATE_CONTEXT = re.compile(
    r"(?i)договор|подписан|составлен|сч[её]т|акт\b|выдан|рожд|"
    r"паспор|invoice|contract|signed|issued|born|date\b"
)
PUBLIC_DATE_CONTEXT = re.compile(
    r"(?i)закон|кодекс|постановлен|федеральн|regulation|directive|law\b|public\s+date"
)


def qwen_chunks(
    blocks: list[Block], max_payload_bytes: int = 4_000, max_blocks: int = 24
) -> list[tuple[list[Block], list[dict]]]:
    chunks: list[tuple[list[Block], list[dict]]] = []
    current_blocks: list[Block] = []
    current_payload: list[dict] = []
    for block in blocks:
        item = {"block_id": block.id, "text": block.text}
        candidate = current_payload + [item]
        candidate_bytes = len(
            json.dumps(candidate, ensure_ascii=False, separators=(",", ":")).encode()
        )
        if current_payload and (
            candidate_bytes > max_payload_bytes or len(current_payload) >= max_blocks
        ):
            chunks.append((current_blocks, current_payload))
            current_blocks = [block]
            current_payload = [item]
        else:
            current_blocks.append(block)
            current_payload.append(item)
    if current_payload:
        chunks.append((current_blocks, current_payload))
    return chunks


class RulesDetector:
    def detect(self, blocks: Iterable[Block]) -> list[Detection]:
        out: list[Detection] = []
        remap: dict[str, tuple[str, int]] = {}
        segmented: list[Block] = []
        for block in blocks:
            cuts = [0, *sorted(hard_boundaries(block)), len(block.text)]
            if len(cuts) == 2:
                segmented.append(block)
                continue
            for number, (start, end) in enumerate(zip(cuts, cuts[1:])):
                if start == end:
                    continue
                segment_id = f"{block.id}::hard-segment:{number}"
                remap[segment_id] = (block.id, start)
                segmented.append(Block(segment_id, block.part, block.kind,
                                       block.text[start:end]))
        for block in segmented:
            for match in PERSON_TRIPLE_RE.finditer(block.text):
                if any(PATRONYMIC_RE.search(word) for word in match.group().split()):
                    out.append(Detection(
                        block.id, match.start(), match.end(), match.group(),
                        "PERSON", "rules", 0.99, True,
                    ))
            for match in re.finditer(
                r"(?i)\bпаспорт(?:а|ом)?[ \t]*[:№]?[ \t]*"
                r"(?P<value>\d{2}[ \t\u00a0\u202f]*\d{2}[ \t\u00a0\u202f]*"
                r"(?:№[ \t\u00a0\u202f]*)?\d{6})(?!\d)", block.text
            ):
                a, b = match.span("value")
                out.append(Detection(block.id, a, b, block.text[a:b], "PASSPORT", "rules", 0.99, True))
            for match in FIELD_VALUE_RE.finditer(block.text):
                label = match.group("label").casefold()
                kind = "ADDRESS" if label.startswith("адрес") else FIELD_TYPES[label]
                value = match.group("value").rstrip(" .\t")
                if kind in {"ADDRESS", "ORG"}:
                    # Sentence boundaries, but not street/house abbreviations.
                    for boundary in re.finditer(r"[.!?]\s+(?=[А-ЯЁA-Z][а-яёa-z]{2,})", value):
                        word = re.search(r"[А-Яа-яЁёA-Za-z]+$", value[:boundary.start()])
                        if not word or word.group().casefold() not in {"г", "ул", "д", "корп", "кв", "обл", "р", "пр", "им", "наб", "стр"}:
                            value = value[:boundary.start()]
                            break
                    if kind == "ORG":
                        boundary = re.search(r"\s+(?:\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2}|(?:19|20)\d{2}-\d{2}-\d{2})\b|,\s*(?:код\s+подразделения|адрес|паспорт)\b|\s+с\s+регистрацией\b", value, re.I)
                        if boundary:
                            value = value[:boundary.start()].rstrip(" ,")
                    if kind == "ADDRESS" and ("@" in value or re.search(r"(?i)\b(?:email|телефон|уведомлен|связаться)", value)):
                        continue
                # A second field without a separator is ambiguous: leave it to
                # the span detector instead of swallowing the rest of the row.
                if not value or len(value) > 240 or re.search(
                    r"(?i)\b(?:паспорт|адрес|email|телефон|passport|address|phone|фио|стоимость|цена|ИНН|КПП|signed|price)\s*[:№]", value
                ):
                    continue
                valid = False
                if kind == "PERSON":
                    valid = bool(re.fullmatch(r"[А-ЯЁA-Z][а-яёa-z]+(?:-[А-ЯЁA-Z][а-яёa-z]+)?(?:\s+[А-ЯЁA-Z][а-яёa-z]+(?:-[А-ЯЁA-Z][а-яёa-z]+)?){1,2}", value))
                    if match.group("label").casefold() == "full name":
                        valid = valid or bool(re.fullmatch(r"[A-Z][a-z'-]+(?:\s+[A-Z][A-Za-z0-9'-]+){1,2}", value))
                elif kind == "ADDRESS":
                    valid = bool(re.search(r"(?i)\b(?:ул\.|улица|street|lane|road|проспект|наб\.|дом|д\.)", value) and re.search(r"\d", value))
                elif kind == "ORG":
                    valid = bool(re.search(r"(?i)МВД|УФМС|ОВД|отдел|управлен|passport office", value))
                elif kind in {"TAX_ID", "REG_ID", "BANK", "PASSPORT", "ACCOUNT"}:
                    valid = bool(re.fullmatch(r"[A-ZА-Я0-9][A-ZА-Я0-9 /-]{4,34}", value))
                elif kind == "SECRET":
                    valid = bool(re.fullmatch(r"[^\s,;]{6,}", value))
                if valid:
                    a = match.start("value")
                    out.append(Detection(block.id, a, a+len(value), value, kind, "rules", 0.99, True))
            for match in re.finditer(r"(?i)\b(?:скидка|комиссия|аванс|предоплата|discount|commission)\s*[:=]?\s*(\d+(?:[.,]\d+)?\s*(?:%|процент(?:ов|а)?\b))", block.text):
                a, b = match.span(1)
                out.append(Detection(block.id, a, b, block.text[a:b], "PRICE", "rules", 0.99, True))
            for match in re.finditer(
                r"(?i)\b(?:НДС|VAT|комиссия|commission|аванс|advance|предоплата|"
                r"скидка|discount|service\s+fee)\b[^\d%\r\n]{0,24}"
                r"(?P<value>\d+(?:[.,]\d+)?\s*%)", block.text
            ):
                a, b = match.span("value")
                out.append(Detection(block.id, a, b, block.text[a:b], "PRICE", "rules", 0.99, True))
            for match in re.finditer(
                r"(?i)(?P<value>\d+(?:[.,]\d+)?\s*%)\s*"
                r"(?:аванс|advance|предоплат|service\s+fee|комисси|commission|НДС|VAT)",
                block.text,
            ):
                a, b = match.span("value")
                out.append(Detection(block.id, a, b, block.text[a:b], "PRICE", "rules", 0.99, True))
            for match in re.finditer(r"(?i)\bкод\s+подразделения\s*[:№]?\s*(\d{3}-\d{3})\b", block.text):
                a, b = match.span(1)
                out.append(Detection(block.id, a, b, block.text[a:b], "DOCUMENT_ID", "rules", 0.99, True))
            if re.search(r"(?i)оплат|уплач|плат[её]ж|аванс", block.text):
                for match in re.finditer(r"(?i)\bв\s+течение\s+\d+\s+(?:(?:рабочих|календарных|банковских)\s+)?дней\s+после\s+(?:при[её]мки|подписания|получения\s+сч[её]та)\b", block.text):
                    a, b = match.span()
                    if not any(d.block_id == block.id and d.entity_type == "PRICE" and d.start <= a and b <= d.end for d in out):
                        out.append(Detection(block.id, a, b, block.text[a:b], "PRICE", "rules", 0.99, True))
            if DOC_DATE_CONTEXT.search(block.text) or re.match(
                r"(?i)^\s*(?:г\.?\s*)?Санкт-Петербург", block.text
            ):
                for match in re.finditer(r"(?<!\d)(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?!\d)", block.text):
                    a, b = match.span()
                    out.append(Detection(block.id, a, b, block.text[a:b], "TIME", "rules", 0.99, True))
            intro_city = re.match(
                r"(?i)^\s*(?:г\.?\s*)?(?P<city>Санкт-Петербург[а-яё]{0,8})"
                r"\s*[,—-].{0,20}(?:19|20)\d{2}", block.text,
            )
            if intro_city:
                a, b = intro_city.span("city")
                out.append(Detection(block.id, a, b, block.text[a:b], "ADDRESS", "rules", 0.99, True))
            if block.kind.startswith("custom-xml-"):
                out.append(
                    Detection(
                        block.id,
                        0,
                        len(block.text),
                        block.text,
                        "SECRET",
                        "custom-xml",
                        0.5,
                        False,
                    )
                )
            if block.kind == "hyperlink":
                out.append(
                    Detection(
                        block.id,
                        0,
                        len(block.text),
                        block.text,
                        "URL",
                        "rules",
                        0.99,
                        True,
                    )
                )
                continue
            if block.kind.startswith("property:"):
                prop = block.kind.split(":", 1)[1].casefold()
                if prop in {"creator", "lastmodifiedby", "manager"}:
                    out.append(
                        Detection(
                            block.id,
                            0,
                            len(block.text),
                            block.text,
                            "PERSON",
                            "rules",
                            0.99,
                            True,
                        )
                    )
                    continue
                if prop == "company":
                    out.append(
                        Detection(
                            block.id,
                            0,
                            len(block.text),
                            block.text,
                            "ORG",
                            "rules",
                            0.99,
                            True,
                        )
                    )
                    continue
                if block.part.endswith("custom.xml") or prop in {
                    "title",
                    "subject",
                    "keywords",
                    "description",
                    "category",
                    "contentstatus",
                    "hyperlinkbase",
                }:
                    out.append(
                        Detection(
                            block.id,
                            0,
                            len(block.text),
                            block.text,
                            "SECRET",
                            "rules",
                            0.95,
                            True,
                        )
                    )
                    continue
            for entity_type, pattern, confidence in PATTERNS:
                for match in pattern.finditer(block.text):
                    text = match.group(0)
                    start, end = match.span()
                    if entity_type == "URL":
                        text = text.rstrip(".,;:!?")
                        end = start + len(text)
                    elif entity_type in {"ACCOUNT", "SECRET"}:
                        text = text.rstrip(".")
                        end = start + len(text)
                    before = block.text[max(0, start - 150):start]
                    if pattern is PASSPORT_ISSUER_RE and not re.search(
                        r"(?i)паспорт|выдан", before
                    ):
                        continue
                    if pattern in {PASSPORT_SERIES_RE, PASSPORT_NUMBER_RE} \
                            and not re.search(r"(?i)паспорт", before):
                        continue
                    if entity_type == "DATE":
                        prefix = re.match(r"(?i)^от\s+", text)
                        if prefix:
                            start += prefix.end()
                            text = block.text[start:end]
                        nearby = block.text[
                            max(0, start - 50) : min(len(block.text), end + 50)
                        ].casefold()
                        if any(
                            word in nearby
                            for word in (
                                "федеральн",
                                "закон",
                                "кодекс",
                                "постановлен",
                                "directive",
                                "regulation",
                            )
                        ):
                            continue
                    # Remove labels such as "ИНН:" from the alias only when safely separable.
                    label = re.match(
                        r"(?i)^(?:ИНН|КПП|ОГРН(?:ИП)?|БИК|BIC|SWIFT|р/?с|к/?с|сч[её]т|паспорт|серия\s+паспорта|passport|серия|номер|кадастровый\s+номер)\s*[:№]?\s*",
                        text,
                    )
                    if label and label.end() < len(text):
                        start += label.end()
                        text = block.text[start:end]
                    if entity_type == "DOCUMENT_ID":
                        label = re.match(
                            r"(?i)^(?:(?:договор|сч[её]т|акт|заказ|дело|клиент|объект)\s*(?:№|N|#)\s*|"
                            r"(?:contract|invoice|order)\s*(?:(?:no\.?|number|№|N|#)\s*)?|"
                            r"(?:company|registration)\s+(?:no\.?|number|№|N|#)\s*)",
                            text,
                        )
                        if label:
                            start += label.end()
                            text = block.text[start:end]
                        if not any(char.isdigit() for char in text):
                            continue
                    if entity_type == "SECRET":
                        label = re.match(
                            r"(?i)^(?:api[_ -]?key|token|bearer|temporary\s+password|password|парол[ья]|секрет)"
                            r"\s*(?:[:=]\s*|\s+)", text
                        )
                        if label:
                            start += label.end()
                            text = block.text[start:end]
                    if entity_type == "ACCOUNT":
                        label = re.match(r"(?i)^(?:login|username|логин)\s*[:=]\s*", text)
                        if label:
                            start += label.end()
                            text = block.text[start:end]
                    out.append(
                        Detection(
                            block.id,
                            start,
                            end,
                            text,
                            entity_type,
                            "rules",
                            confidence,
                            entity_type not in {"DATE", "TIME"},
                        )
                    )
            for issuer in PASSPORT_ISSUER_RE.finditer(block.text):
                nearby = block.text[max(0, issuer.start()-150):issuer.start()]
                if not re.search(r"(?i)паспорт|выдан", nearby):
                    continue
                tail = block.text[issuer.end():min(len(block.text), issuer.end()+90)]
                for city in PASSPORT_CITY_RE.finditer(tail):
                    start = issuer.end()+city.start()
                    end = issuer.end()+city.end()
                    out.append(Detection(
                        block.id, start, end, block.text[start:end],
                        "ADDRESS", "rules", 0.96, True,
                    ))
            standalone_city = re.fullmatch(
                r"(?i)\s*(?:г\.|город)\s+(?P<city>Санкт-Петербург[а-яё]{0,8})\s*",
                block.text,
            )
            if standalone_city:
                start, end = standalone_city.span("city")
                out.append(Detection(
                    block.id, start, end, block.text[start:end],
                    "ADDRESS", "rules", 0.96, True,
                ))
        remapped: list[Detection] = []
        for detection in out:
            original = remap.get(detection.block_id)
            if not original:
                remapped.append(detection)
                continue
            block_id, offset = original
            remapped.append(Detection(
                block_id, detection.start + offset, detection.end + offset,
                detection.exact_text, detection.entity_type, detection.source,
                detection.confidence, detection.format_confirmed,
            ))
        return remapped


class PrivacyFilterDetector:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._opf = None

    def _load(self):
        checkpoint = Path(self.settings.privacy_checkpoint)
        if not checkpoint.is_dir() or not (checkpoint / "model.safetensors").exists():
            raise DetectorUnavailable(
                "локальные веса openai/privacy-filter не установлены"
            )
        os.environ["HF_HUB_OFFLINE"] = "1"
        os.environ["TRANSFORMERS_OFFLINE"] = "1"
        try:
            from opf import OPF
        except ImportError as exc:
            raise DetectorUnavailable(
                "пакет openai/privacy-filter не установлен"
            ) from exc
        self._opf = OPF(
            model=str(checkpoint),
            device=self.settings.privacy_device,
            output_mode="typed",
        )

    def _detect_sync(self, blocks: list[Block]) -> list[Detection]:
        if self._opf is None:
            self._load()
        out: list[Detection] = []
        for chunk in privacy_chunks(blocks):
            pieces: list[str] = []
            starts: list[int] = []
            ends: list[int] = []
            cursor = 0
            for block in chunk:
                if pieces:
                    pieces.append("\n\n")
                    cursor += 2
                starts.append(cursor)
                pieces.append(block.text)
                cursor += len(block.text)
                ends.append(cursor)
            text = "".join(pieces)
            runtime = self._opf.get_runtime()
            for offset, window in privacy_token_windows(text, runtime.encoding, runtime.n_ctx):
                result = self._opf.redact(window)
                if getattr(result, "warning", None):
                    raise DetectorUnavailable("privacy-filter сообщил о несовпадении токенизации")
                for span in result.detected_spans:
                    if span.label not in LABEL_MAP:
                        raise DetectorUnavailable("privacy-filter: неизвестный тип данных")
                    if not 0 <= span.start < span.end <= len(window) or span.text != window[span.start:span.end]:
                        raise DetectorUnavailable("privacy-filter: несовпадение диапазонов")
                    a, b = span.start + offset, span.end + offset
                    # A span crossing paragraph separators must not disappear.
                    for index, block in enumerate(chunk):
                        start, end = max(a, starts[index])-starts[index], min(b, ends[index])-starts[index]
                        if start < end:
                            out.append(Detection(block.id, start, end, block.text[start:end],
                                                 LABEL_MAP[span.label], "privacy-filter", 0.82))
        return list({(d.block_id, d.start, d.end, d.entity_type): d for d in out}.values())

    async def detect(self, blocks: list[Block]) -> list[Detection]:
        return await asyncio.to_thread(self._detect_sync, blocks)


def privacy_token_windows(text, encoding, n_ctx):
    tokens = encoding.encode(text, allowed_special="all")
    decoded, offsets = encoding.decode_with_offsets(tokens)
    if decoded != text:
        raise DetectorUnavailable("privacy-filter: несовпадение токенизации")
    limit = n_ctx - 32
    if limit <= 256:
        raise DetectorUnavailable("privacy-filter: недостаточный контекст")
    for cursor in range(0, len(tokens), limit-256):
        stop = min(cursor+limit, len(tokens))
        a = offsets[cursor] if cursor else 0
        b = offsets[stop] if stop < len(tokens) else len(text)
        window = text[a:b]
        if len(encoding.encode(window, allowed_special="all")) > n_ctx:
            raise DetectorUnavailable("privacy-filter: окно превышает контекст")
        yield a, window
        if stop == len(tokens):
            break


def privacy_chunks(blocks: list[Block], max_chars: int = 80_000) -> list[list[Block]]:
    chunks: list[list[Block]] = []
    current: list[Block] = []
    current_chars = 0
    for block in blocks:
        added = len(block.text) + (2 if current else 0)
        if current and current_chars + added > max_chars:
            chunks.append(current)
            current = []
            current_chars = 0
            added = len(block.text)
        current.append(block)
        current_chars += added
    if current:
        chunks.append(current)
    return chunks


def __getattr__(name):
    # Compatibility for older evaluation scripts; no Qwen import in production.
    if name == 'QwenDetector':
        from .qwen_detector import QwenDetector
        return QwenDetector
    raise AttributeError(name)


def normalize_detections(blocks: list[Block], detections: list[Detection]) -> list[Detection]:
    blocks_by_id = {b.id: b for b in blocks}
    block_map = {b.id: b.text for b in blocks}
    normalized: list[Detection] = []
    for d in detections:
        text = block_map.get(d.block_id)
        if text is None or text[d.start:d.end] != d.exact_text:
            continue
        if any(d.start < boundary < d.end
               for boundary in hard_boundaries(blocks_by_id[d.block_id])):
            from dataclasses import replace
            cuts = [d.start, *sorted(boundary for boundary in hard_boundaries(blocks_by_id[d.block_id])
                                     if d.start < boundary < d.end), d.end]
            normalized.extend(replace(d, start=a, end=b, exact_text=text[a:b])
                              for a, b in zip(cuts, cuts[1:]) if text[a:b].strip())
            continue
        if d.entity_type == "URL" and is_technical_schema_value(d.exact_text):
            continue
        if d.entity_type == "ADDRESS" and d.source == "privacy-filter" and (
            re.fullmatch(r"(?i)\s*page\s+\d+\s*,?\s*section\s+[\d.]+\s*", d.exact_text)
            or (re.search(r"(?i)\bISO\s*\d+|Regulation\s*\(EU\)|Article\s+\d+", d.exact_text)
                and not re.search(r"(?i)\b(?:street|road|lane|avenue|address|город|улиц|дом)\b", d.exact_text))
        ):
            continue
        if d.entity_type == "PERSON" and d.source in {"gliner-ru", "privacy-filter"}:
            for match in PERSON_TRIPLE_RE.finditer(text):
                if any(match.start() < boundary < match.end() for boundary in hard_boundaries(blocks_by_id[d.block_id])):
                    continue
                if match.start() <= d.start and d.end <= match.end() and any(
                    PATRONYMIC_RE.search(word) for word in match.group().split()
                ):
                    d = Detection(d.block_id, match.start(), match.end(), match.group(), "PERSON", d.source, d.confidence, False)
                    break
        if d.entity_type == "ADDRESS" and d.source == "privacy-filter" \
                and 30 <= len(d.exact_text) <= 100:
            cadastral = CADASTRAL_LABELED_RE.search(d.exact_text)
            if cadastral and cadastral.end() == len(d.exact_text):
                prefix = d.exact_text[:cadastral.start()].rstrip(" ,;\t")
                if len(prefix) >= 20:
                    normalized.append(Detection(
                        d.block_id, d.start, d.start+len(prefix), prefix,
                        "ADDRESS", "privacy-split", d.confidence, False,
                    ))
                    continue
            series = PASSPORT_SERIES_RE.search(d.exact_text)
            if series and series.end() == len(d.exact_text):
                separator = max(d.exact_text.rfind(",", 0, series.start()),
                                d.exact_text.rfind(";", 0, series.start()))
                prefix = d.exact_text[:separator].rstrip() if separator >= 20 else ""
                between = d.exact_text[separator:series.start()] if separator >= 0 else ""
                if len(prefix) >= 20 and sum(c.isdigit() for c in prefix) >= 3 \
                        and not any(c.isdigit() for c in between):
                    normalized.append(Detection(
                        d.block_id, d.start, d.start+len(prefix), prefix,
                        "ADDRESS", (d.source if re.search(
                            r"(?i)\b(?:ул\.|улица|город|г\.|квартир|дом|street|road)\b", prefix
                        ) else "privacy-split"), d.confidence, False,
                    ))
                    continue
        stamp = DATE_TIME_RE.fullmatch(d.exact_text) if d.entity_type == "DATE" else None
        if stamp:
            for name, entity_type in (("date", "DATE"), ("time", "TIME")):
                a, b = stamp.span(name)
                normalized.append(Detection(
                    d.block_id, d.start + a, d.start + b, d.exact_text[a:b],
                    entity_type, d.source, d.confidence, False,
                ))
            continue
        if d.entity_type == "DATE" and PURE_TIME_RE.fullmatch(d.exact_text):
            normalized.append(Detection(
                d.block_id, d.start, d.end, d.exact_text, "TIME",
                d.source, d.confidence, False,
            ))
            continue
        if d.entity_type == "DOCUMENT_ID" and sum(c.isdigit() for c in d.exact_text) >= 6:
            before = text[max(0, d.start - 30):d.start].casefold()
            if "паспорт" in before or "passport" in before:
                normalized.append(Detection(
                    d.block_id, d.start, d.end, d.exact_text, "PASSPORT",
                    d.source, d.confidence, d.format_confirmed,
                ))
                continue
        normalized.append(d)
    return normalized


def _solo_auto(entity_type: EntityType, exact: str, context: str, source: str) -> bool:
    digits = sum(c.isdigit() for c in exact)
    if source == "gliner-ru" and entity_type == "PERSON" \
            and PERSON_TRIPLE_RE.fullmatch(exact):
        # A complete Russian name with a patronymic is stronger evidence than
        # the model's confidence score or a single capitalised word.
        return any(PATRONYMIC_RE.search(word) for word in exact.split())
    if source in {"privacy-filter", "rules"} and entity_type in {"DATE", "TIME"}:
        shape = (PURE_DATE_RE.fullmatch(exact) or FULL_MONTH_DATE_RE.fullmatch(exact)) \
            if entity_type == "DATE" else PURE_TIME_RE.fullmatch(exact)
        return bool(shape and not PUBLIC_DATE_CONTEXT.search(context)
                    and (DOC_DATE_CONTEXT.search(context) or DATE_TIME_RE.search(context)
                         or re.search(r"(?i)Санкт-Петербург.{0,35}$", context[:context.find(exact)])
                         or (entity_type == "DATE" and exact.startswith("«")
                             and FULL_MONTH_DATE_RE.fullmatch(exact))))
    if source == "privacy-filter":
        if entity_type == "ADDRESS":
            return 5 <= len(exact) <= 240 \
                and not re.search(r"(?i)паспорт|email|парол|банк|ИНН|passport|договор|сторон|соглашен", exact) \
                and (len(exact) <= 80 or bool(re.search(
                    r"(?i)\b(?:ул\.|улица|дом|город|г\.|район|квартир|street|avenue|road|postal|zip)\b",
                    exact,
                )))
        if entity_type in {"ACCOUNT", "REG_ID", "PASSPORT"}:
            return 6 <= digits <= 30 and len(exact) <= 45
        if entity_type == "PHONE":
            return 7 <= digits <= 15 and len(exact) <= 35
        if entity_type == "DOCUMENT_ID":
            return len(exact) <= 45 and bool(re.search(r"[№#]|\d{3,}", exact))
        if entity_type == "PERSON":
            return bool(len(exact) <= 60
                        and re.fullmatch(r"[А-ЯЁA-Z][а-яёa-z]+(?:[- ][А-ЯЁA-Z][а-яёa-z]+){1,2}", exact))
    if source == "qwen" and entity_type == "PRICE":
        return digits > 0 and len(exact) <= 60 and bool(re.search(
            r"(?i)[$€£₽]|руб|usd|eur|доллар|евро|стоимост|цен[аы]|комисси", exact + context
        ))
    return False


def _prefer_precise(candidates: list[Finding], block_map: dict[str, Block]) -> list[Finding]:
    remove: set[str] = set()
    residual_findings: list[Finding] = []
    generic_labels = set(
        "фио паспорт адрес дата телефон выдан серия номер счет счёт регистрация "
        "место гражданин гражданка подписан подпись документ личность родился "
        "рождения проживает банк фамилия имя отчество российской федерации "
        "россия договор сторона арендодатель арендатор настоящий жилое помещение "
        "регистрации орган отделом мвд выдавший область район город улица "
        "индекс код подразделения".split()
    )
    issuers = [f for f in candidates if f.entity_type == "ORG" and "rules" in f.sources
               and PASSPORT_ISSUER_RE.fullmatch(f.exact_text)]
    for issuer in issuers:
        for other in candidates:
            if other is issuer or other.block_id != issuer.block_id \
                    or other.start >= issuer.end or issuer.start >= other.end:
                continue
            if issuer.start <= other.start and other.end <= issuer.end:
                remove.add(other.id)
                continue
            # A privacy/model span may include the issuer plus another field.
            # Retire it only when exact-format children cover remaining numbers,
            # contacts and names; otherwise retain the overlap for review.
            if "rules" in other.sources or len(other.exact_text) < 18:
                continue
            uncovered = list(other.exact_text)
            for start, end in [(max(other.start, issuer.start), min(other.end, issuer.end))] + [
                (child.start, child.end) for child in candidates
                if child is not other and child is not issuer and "rules" in child.sources
                and child.block_id == other.block_id
                and other.start <= child.start and child.end <= other.end
            ]:
                for index in range(start - other.start, end - other.start):
                    uncovered[index] = " "
            residue = "".join(uncovered)
            if not re.search(r"\d{3,}|@|[А-ЯЁA-Z][а-яёa-z]{2,}\s{1,3}[А-ЯЁA-Z][а-яёa-z]{2,}", residue):
                remove.add(other.id)
    for outer in sorted(candidates, key=lambda f: len(f.exact_text)):
        if outer.id in remove:
            continue
        if outer in issuers:
            continue
        children = [inner for inner in candidates
                    if inner is not outer and inner.id not in remove
                    and inner.block_id == outer.block_id
                    and outer.start <= inner.start and inner.end <= outer.end]
        if not children:
            continue
        if "rules" in outer.sources and outer.entity_type in {"PERSON", "ADDRESS", "ORG", "PASSPORT", "BANK", "TAX_ID", "REG_ID", "SECRET", "ACCOUNT", "PRICE", "DOCUMENT_ID", "EMAIL", "PHONE", "URL", "IP"}:
            # Complete labelled fields dominate smaller model fragments.
            # Only absorb spans that are wholly contained in this one field.
            remove.update(child.id for child in children)
            continue
        # Keep the entire dated expression, not the isolated day or month-year
        # emitted by a span detector. A separate time after it stays separate.
        if outer.entity_type == "DATE" and FULL_MONTH_DATE_RE.fullmatch(outer.exact_text) \
                and all(child.entity_type == "DATE" for child in children):
            remove.update(child.id for child in children)
            continue
        covered = [False] * len(outer.exact_text)
        for child in children:
            for index in range(child.start - outer.start, child.end - outer.start):
                covered[index] = True
        total = sum(c.isalnum() for c in outer.exact_text)
        fraction = (sum(c.isalnum() and covered[i]
                        for i, c in enumerate(outer.exact_text)) / total) if total else 0
        residue = "".join(c for i, c in enumerate(outer.exact_text) if not covered[i])
        if outer.entity_type == "PII":
            if all(not c.isalnum() or covered[i] for i, c in enumerate(outer.exact_text)):
                remove.add(outer.id)
            continue
        # A broad label/paragraph must not overwrite separately identified values.
        if (fraction >= 0.5 or (outer.entity_type == "DOCUMENT_ID" and children)
                or (outer.entity_type == "REG_ID" and "кадастр" in outer.exact_text.casefold() and children)
                or (len(outer.exact_text) > 80 and len(children) >= 2 and fraction >= 0.35)) \
                and not re.search(r"\d{3,}|@", residue):
            remove.add(outer.id)
            if len(outer.exact_text) > 80 and outer.entity_type in {"PERSON", "ORG", "ADDRESS", "BANK", "EMAIL", "ACCOUNT"}:
                uncovered = "".join(c if not covered[i] else " "
                                    for i, c in enumerate(outer.exact_text))
                # A residual full name is itself a precise review candidate;
                # keeping the whole paragraph would also alias safe labels.
                pairs = list(re.finditer(
                    r"\b[А-ЯЁA-Z][а-яёa-z]{2,}\s{1,3}[А-ЯЁA-Z][а-яёa-z]{2,}\b", uncovered
                ))
                singles = list(re.finditer(r"\b[А-ЯЁA-Z][а-яёa-z]{3,}\b", uncovered))
                for number, match in enumerate(pairs + singles):
                    if match in singles and any(p.start() <= match.start() < p.end() for p in pairs):
                        continue
                    if match.group(0).casefold() in generic_labels:
                        continue
                    start = outer.start + match.start()
                    end = outer.start + match.end()
                    text = block_map[outer.block_id].text
                    residual_findings.append(Finding(
                        f"g-{outer.id}-{number}", outer.block_id, start, end,
                        text[start:end], "PERSON", ["compound-gap"], "pending", 0.3,
                        text[max(0, start - 45):min(len(text), end + 45)],
                    ))
    return [f for f in candidates if f.id not in remove] + residual_findings


def _coalesce_person_names(candidates: list[Finding], blocks: list[Block]) -> list[Finding]:
    removed: set[str] = set()
    joined: list[Finding] = []
    for block in blocks:
        for match in PERSON_TRIPLE_RE.finditer(block.text):
            if any(match.start() < boundary < match.end() for boundary in hard_boundaries(block)):
                continue
            parts = [f for f in candidates if f.id not in removed
                     and f.block_id == block.id and f.entity_type == "PERSON"
                     and match.start() <= f.start and f.end <= match.end()]
            if len(parts) < 2 or not any(set(f.sources) & {"privacy-filter", "gliner-ru"} for f in parts):
                continue
            if not any(set(f.sources) & {"privacy-filter", "gliner-ru"} and len(f.exact_text.split()) >= 2
                       for f in parts):
                continue
            covered = [False] * len(match.group())
            for part in parts:
                for index in range(part.start - match.start(), part.end - match.start()):
                    covered[index] = True
            alnum = sum(c.isalnum() for c in match.group())
            fraction = (sum(c.isalnum() and covered[i] for i, c in enumerate(match.group()))
                        / alnum) if alnum else 0
            if fraction < 0.85:
                continue
            removed.update(part.id for part in parts)
            joined.append(Finding(
                f"fio-{block.id}-{match.start()}", block.id, match.start(), match.end(),
                match.group(), "PERSON", sorted({"fio-joined"} | {
                    source for part in parts for source in part.sources
                }), "accepted", max(part.confidence for part in parts),
                block.text[max(0, match.start()-45):min(len(block.text), match.end()+45)],
            ))
    return [f for f in candidates if f.id not in removed] + joined


def expand_approved_repetitions(blocks: list[Block], findings: list[Finding], protected_ranges=()) -> list[Finding]:
    """Propagate approved names and validated emails without touching nearby text."""
    extras: list[Finding] = []
    superseded: set[str] = set()
    full_names = [f.exact_text for f in findings if f.status == "accepted"
                  and f.entity_type == "PERSON" and "fio-joined" in f.sources]
    surname_roots = {f.exact_text for f in findings if f.status == "accepted"
                     and f.entity_type == "PERSON"
                     and re.fullmatch(r"[А-ЯЁ][а-яё]{5,}", f.exact_text)
                     and any(f.exact_text in name for name in full_names)}
    seeds = [f for f in findings if f.status == "accepted" and (
        f.entity_type == "PERSON" and (
            f.exact_text in surname_roots or bool(PERSON_TRIPLE_RE.fullmatch(f.exact_text))
            or bool(re.fullmatch(r"[A-Z][a-z'-]+(?:\s+[A-Z][A-Za-z0-9'-]+){1,2}", f.exact_text))
        ) or f.entity_type == "EMAIL" and bool(PATTERNS[0][1].fullmatch(f.exact_text))
    )]

    def free(block_id: str, start: int, end: int) -> bool:
        return not any(f.block_id == block_id and f.start < end and start < f.end
                       for f in findings + extras if f.id not in superseded)

    def known_name_free(block_id, start, end):
        if any(bid == block_id and a < end and start < b for bid, a, b in protected_ranges):
            return False
        overlaps = [f for f in findings + extras if f.id not in superseded
                    and f.block_id == block_id and f.start < end and start < f.end]
        if any(f.start == start and f.end == end and f.status != "pending" for f in overlaps):
            return False
        if overlaps and all(start <= f.start and f.end <= end and f.status != "rejected"
                            and f.entity_type in {"PERSON", "PII"} for f in overlaps):
            superseded.update(f.id for f in overlaps)
            return True
        return not overlaps

    def add(block: Block, start: int, end: int, kind: EntityType, source: str) -> None:
        extras.append(Finding(
            f"repeat-{block.id}-{start}", block.id, start, end,
            block.text[start:end], kind, [source], "accepted", 0.94,
            block.text[max(0,start-45):min(len(block.text),end+45)],
        ))

    for seed in seeds:
        value = seed.exact_text
        for block in blocks:
            cursor = 0
            while (start := block.text.find(value, cursor)) >= 0:
                end = start + len(value)
                cursor = end
                before = block.text[start-1] if start else ""
                after = block.text[end] if end < len(block.text) else ""
                if (not before.isalnum() and before != "_"
                        and not after.isalnum() and after != "_"
                        and (known_name_free(block.id, start, end) if seed.entity_type == "PERSON" else free(block.id, start, end))):
                    add(block, start, end, seed.entity_type, "repeat-local")

        if seed.entity_type == "PERSON" and PERSON_TRIPLE_RE.fullmatch(value):
            words = value.split()
            patronymic_index = next(
                (index for index, word in enumerate(words) if PATRONYMIC_RE.search(word)),
                2,
            )
            if patronymic_index == 1:
                first, middle, surname = words
            else:
                surname, first, middle = words
            variants = [surname + " " + first[0] + "." + middle[0] + ".",
                        surname + " " + first[0] + ". " + middle[0] + ".",
                        first[0] + "." + middle[0] + ". " + surname,
                        first[0] + ". " + middle[0] + ". " + surname]
            # Only the regular masculine consonant-ending paradigm. Other
            # names remain the model's responsibility; originals are retained.
            if re.search(r"(?:вич|Ильич)$", middle) and all(re.search(r"[бвгджзклмнпрстфхцчшщ]$", w) for w in (surname, first)):
                variants.extend(" ".join(w + suffix for w in (first, middle, surname)) for suffix in ("а", "у"))
            for variant in variants:
                pattern = re.compile(r"(?<!\w)" + re.escape(variant) + r"(?!\w)")
                for block in blocks:
                    for match in pattern.finditer(block.text):
                        if known_name_free(block.id, match.start(), match.end()):
                            add(block, match.start(), match.end(), "PERSON", "known-name-form")

    inflections = {"а", "у", "ы", "е", "ой", "ом", "ым", "ою", "ему", "ого",
                   "ому", "ими", "ами", "ах", "ов", "ев", "ин", "на"}
    for root in surname_roots:
        pattern = re.compile(r"(?<!\w)" + re.escape(root) + r"(?P<suffix>[а-яё]{1,3})(?!\w)")
        for block in blocks:
            for match in pattern.finditer(block.text):
                if match.group("suffix") not in inflections or not free(
                    block.id, match.start(), match.end()
                ):
                    continue
                add(block, match.start(), match.end(), "PERSON", "case-form-local")
    return [f for f in findings + extras if f.id not in superseded]


def resolve_clear_document_id_overlaps(findings: list[Finding]) -> bool:
    """Prefer a complete series-and-number over its six-digit suffix."""
    changed = False
    for outer in findings:
        if outer.status != "accepted" or outer.entity_type != "DOCUMENT_ID":
            continue
        if not re.fullmatch(r"\d{4}\s*[№#]\s*\d{6}", outer.exact_text):
            continue
        for inner in findings:
            if inner is outer or inner.block_id != outer.block_id:
                continue
            if inner.entity_type != "DOCUMENT_ID" or inner.status == "rejected":
                continue
            if inner.end != outer.end or inner.start <= outer.start:
                continue
            if not re.fullmatch(r"\d{6}", inner.exact_text):
                continue
            if outer.exact_text.endswith(inner.exact_text):
                inner.status = "rejected"
                changed = True
    return changed


def merge_detections(blocks: list[Block], detections: list[Detection]) -> list[Finding]:
    block_map = {b.id: b for b in blocks}
    groups: dict[tuple[str, int, int], list[Detection]] = defaultdict(list)
    for d in normalize_detections(blocks, omit_technical_schemas(blocks, detections)):
        block = block_map.get(d.block_id)
        if (
            block
            and 0 <= d.start < d.end <= len(block.text)
            and block.text[d.start : d.end] == d.exact_text
        ):
            groups[(d.block_id, d.start, d.end)].append(d)
    candidates: list[Finding] = []
    for index, ((block_id, start, end), ds) in enumerate(sorted(groups.items())):
        # A model's generic PII and specific label are one observation.
        sources = sorted({d.source for d in ds})
        families = {"privacy-filter" if source.startswith("privacy") else
                    "rules" if source == "rules" else source for source in sources}
        types = [d.entity_type for d in ds if d.entity_type != "PII"] or ["PII"]
        confirmed = {d.entity_type for d in ds if d.source == "rules" and d.format_confirmed}
        if len(confirmed) > 1 and "PHONE" in confirmed:
            confirmed.discard("PHONE")
        if len(confirmed) == 1:
            types = list(confirmed)
        entity_type = sorted(set(types), key=lambda kind: (-types.count(kind), kind))[0]
        conflict = len(set(types)) > 1
        accepted = not conflict and (
            any(d.format_confirmed for d in ds)
            or len(families) >= 2
            or (len(sources) == 1 and _solo_auto(
                entity_type, block_map[block_id].text[start:end],
                block_map[block_id].text[max(0, start - 55):min(len(block_map[block_id].text), end + 55)],
                sources[0],
            ))
        )
        if "custom-xml" in sources and not any(d.format_confirmed for d in ds):
            accepted = False
        text = block_map[block_id].text
        context = text[max(0, start - 45) : min(len(text), end + 45)]
        public_date = entity_type in {"DATE", "TIME"} and bool(
            re.search(r"(?i)public\s+date", context)
            or (PUBLIC_DATE_CONTEXT.search(context) and not DOC_DATE_CONTEXT.search(context))
        )
        if public_date:
            accepted = False
        status = "rejected" if public_date else ("accepted" if accepted else "pending")
        # Only an explicit citation of a federal law; personal and document
        # dates elsewhere in the same paragraph retain their own decisions.
        if entity_type == "DATE" and PURE_DATE_RE.fullmatch(text[start:end]) \
                and re.search(r"(?i)\bфедеральн(?:ый|ого|ому|ым|ом)\s+закон(?:а|у|ом|е)?\s+от\s*$", text[max(0, start-70):start]) \
                and re.match(r"\s*№\s*\d{1,4}[-–]ФЗ\b", text[end:], re.I):
            status = "rejected"
        if entity_type in {"ACCOUNT", "DOCUMENT_ID", "REG_ID", "DATE", "PII"} \
                and re.fullmatch(r"\d{4}/\d{1,4}", text[start:end]) \
                and re.search(r"(?i)\bRegulation\s*\(EU\)\s*$", text[max(0, start-40):start]):
            status = "rejected"
        candidates.append(
            Finding(
                f"f{index:05d}",
                block_id,
                start,
                end,
                text[start:end],
                entity_type,
                sources,
                status,
                max(d.confidence for d in ds),
                context,
            )
        )
    candidates = _prefer_precise(candidates, block_map)
    candidates = _coalesce_person_names(candidates, blocks)
    resolve_clear_document_id_overlaps(candidates)
    # Remaining overlaps are genuinely ambiguous and require a decision.
    by_block: dict[str, list[Finding]] = defaultdict(list)
    for f in candidates:
        by_block[f.block_id].append(f)
    for items in by_block.values():
        for i, left in enumerate(items):
            for right in items[i + 1 :]:
                if left.status != "rejected" and right.status != "rejected" \
                        and left.start < right.end and right.start < left.end:
                    left.status = right.status = "pending"
    return candidates
