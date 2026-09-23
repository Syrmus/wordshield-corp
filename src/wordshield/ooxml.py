from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass
from itertools import pairwise
from pathlib import PurePosixPath
from urllib.parse import urlsplit, quote, unquote

from lxml import etree

from .models import Block, Finding, hard_boundaries

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_R = "http://schemas.openxmlformats.org/package/2006/relationships"
TEXT_TAGS = {f"{{{W}}}t", f"{{{W}}}instrText", f"{{{W}}}delText"}
XML_PART_PATTERNS = (
    re.compile(r"^word/document\.xml$"),
    re.compile(r"^word/header\d+\.xml$"),
    re.compile(r"^word/footer\d+\.xml$"),
    re.compile(r"^word/(?:footnotes|endnotes|comments[^/]*|people)\.xml$"),
    re.compile(r"^docProps/(?:core|app|custom)\.xml$"),
    re.compile(r"^customXml/(?:item|itemProps)\d+\.xml$"),
)
FORBIDDEN_PREFIXES = (
    "word/media/",
    "word/embeddings/",
    "word/activeX/",
    "word/charts/",
    "word/diagrams/",
)
FORBIDDEN_NAMES = {"word/vbaProject.bin", "word/glossary/document.xml"}
FORBIDDEN_LOCAL_TAGS = {
    "drawing",
    "pict",
    "object",
    "altChunk",
    "control",
    "movie",
    "background",
}
SENSITIVE_ATTRIBUTES = {
    "author",
    "initials",
    "date",
    "userId",
    "providerId",
    "email",
    "name",
}
MAX_UNCOMPRESSED = 100 * 1024 * 1024
MAX_ENTRIES = 2000
ALIAS_TOKEN_RE = re.compile(r"\[\[([A-Z_]+-[A-Z2-7]{4}-\d{3,}(?::[^\[\]\r\n]{1,80})?)\]\]")
SAFE_MAILTO_RE = re.compile(
    r"mailto:wordshield-([A-Z_]+-[A-Z2-7]{4}-\d{3,}(?:%3A[^/@?#]+)?)@wordshield\.invalid",
    re.IGNORECASE,
)
SAFE_WEB_RE = re.compile(
    r"https://wordshield\.invalid/a/([A-Z_]+-[A-Z2-7]{4}-\d{3,}(?:%3A[^/@?#]+)?)",
    re.IGNORECASE,
)


class UnsafeDocument(ValueError):
    pass


@dataclass
class ParsedDocx:
    entries: dict[str, bytes]
    blocks: list[Block]


def _safe_zip(raw: bytes) -> dict[str, bytes]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise UnsafeDocument("Файл не является исправным DOCX/ZIP") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise UnsafeDocument("Слишком много частей в DOCX")
    total = 0
    result: dict[str, bytes] = {}
    for info in infos:
        if info.filename in result or info.flag_bits & 1:
            raise UnsafeDocument('Дублированная или зашифрованная часть DOCX')
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
            raise UnsafeDocument("Небезопасное имя части в DOCX")
        total += info.file_size
        if total > MAX_UNCOMPRESSED:
            raise UnsafeDocument("Распакованный DOCX слишком велик")
        if info.compress_size and info.file_size / info.compress_size > 200:
            raise UnsafeDocument("Подозрительное сжатие DOCX")
        result[info.filename] = zf.read(info)
    required = {"[Content_Types].xml", "word/document.xml"}
    if not required.issubset(result):
        raise UnsafeDocument("Это не обычный DOCX")
    return result


def _is_text_part(name: str) -> bool:
    return any(p.match(name) for p in XML_PART_PATTERNS)


def _xml(data: bytes) -> etree._Element:
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, recover=False, huge_tree=False
    )
    try:
        return etree.fromstring(data, parser)
    except etree.XMLSyntaxError as exc:
        raise UnsafeDocument("Повреждённый XML внутри DOCX") from exc


def _inspect(entries: dict[str, bytes]) -> None:
    for name in entries:
        if name in FORBIDDEN_NAMES or name.startswith(FORBIDDEN_PREFIXES):
            raise UnsafeDocument(f'Неподдерживаемое содержимое: {name}')
        structural = name in {
            '[Content_Types].xml', '_rels/.rels', 'word/styles.xml',
            'word/stylesWithEffects.xml', 'word/settings.xml', 'word/webSettings.xml',
            'word/fontTable.xml', 'word/numbering.xml',
        } or bool(re.fullmatch(r'word/theme/theme\d+\.xml', name))
        relationship = bool(re.fullmatch(r'(?:word|customXml)(?:/[^/]+)*/_rels/[^/]+\.rels', name))
        if not (_is_text_part(name) or structural or relationship):
            raise UnsafeDocument(f'Неподдерживаемая часть DOCX: {name}')
        if name in FORBIDDEN_NAMES or name.startswith(FORBIDDEN_PREFIXES):
            raise UnsafeDocument(f"Неподдерживаемое содержимое: {name}")
        lower = name.lower()
        if lower.endswith(".bin") or "signature" in lower:
            raise UnsafeDocument(f"Неподдерживаемое бинарное содержимое: {name}")
    content_types = entries["[Content_Types].xml"].decode("utf-8", "ignore").lower()
    if "macroenabled" in content_types or "activex" in content_types:
        raise UnsafeDocument("Макросы и ActiveX запрещены")
    for name, data in entries.items():
        if not name.endswith(".xml"):
            continue
        root = _xml(data)
        for element in root.iter():
            if etree.QName(element).localname in FORBIDDEN_LOCAL_TAGS:
                raise UnsafeDocument(f"Неподдерживаемый объект в {name}")
    for name, data in entries.items():
        if not name.endswith(".rels"):
            continue
        root = _xml(data)
        for rel in root:
            if rel.get("TargetMode") != "External":
                continue
            rel_type = (rel.get("Type") or "").rsplit("/", 1)[-1]
            if rel_type != "hyperlink":
                raise UnsafeDocument(f"Запрещённая внешняя связь: {rel_type}")


def _text_nodes(container: etree._Element) -> list[etree._Element]:
    return [node for node in container.iter() if node.tag in TEXT_TAGS]


def _hard_boundary_offsets(container: etree._Element) -> list[int]:
    """Record visible run breaks while retaining legacy concatenated offsets."""
    cursor = 0
    boundaries: set[int] = set()
    for node in container.iter():
        if node.tag in TEXT_TAGS:
            cursor += len(node.text or "")
        elif node.tag in {f"{{{W}}}br", f"{{{W}}}tab", f"{{{W}}}cr"} and cursor:
            boundaries.add(cursor)
    return sorted(boundaries)


def _attribute_nodes(root: etree._Element) -> list[tuple[etree._Element, str, str]]:
    result = []
    for node in root.iter():
        for key, value in node.attrib.items():
            if etree.QName(key).localname in SENSITIVE_ATTRIBUTES and value.strip():
                result.append((node, key, value))
    return result


def _custom_xml_text_nodes(
    root: etree._Element,
) -> list[tuple[etree._Element, str, str]]:
    result = []
    for node in root.iter():
        if (node.text or "").strip():
            result.append((node, "text", node.text or ""))
        if (node.tail or "").strip():
            result.append((node, "tail", node.tail or ""))
    return result


def _custom_xml_attribute_nodes(
    root: etree._Element, part: str
) -> list[tuple[etree._Element, str, str]]:
    result = []
    item_props = bool(re.match(r"^customXml/itemProps\d+\.xml$", part))
    for node in root.iter():
        for key, value in node.attrib.items():
            local = etree.QName(key).localname
            # The datastore GUID links Word content controls to their XML store.
            # It is an internal random structural identifier, not document data.
            if item_props and local == "itemID":
                continue
            if value.strip():
                result.append((node, key, value))
    return result


def parse_docx(raw: bytes) -> ParsedDocx:
    entries = _safe_zip(raw)
    _inspect(entries)
    blocks: list[Block] = []
    for part in sorted(entries):
        if _is_text_part(part):
            root = _xml(entries[part])
            if part.startswith("customXml/"):
                for idx, (node, slot, value) in enumerate(
                    _custom_xml_text_nodes(root)
                ):
                    local = etree.QName(node).localname
                    blocks.append(
                        Block(
                            f"{part}::customtext::{idx}",
                            part,
                            f"custom-xml-text:{local}:{slot}",
                            value,
                        )
                    )
                for idx, (node, key, value) in enumerate(
                    _custom_xml_attribute_nodes(root, part)
                ):
                    local = etree.QName(key).localname
                    blocks.append(
                        Block(
                            f"{part}::customattr::{idx}",
                            part,
                            f"custom-xml-attribute:{local}",
                            value,
                        )
                    )
                continue
            paragraphs = root.xpath("//*[local-name()='p']")
            covered: set[int] = set()
            for idx, paragraph in enumerate(paragraphs):
                nodes = _text_nodes(paragraph)
                text = "".join(node.text or "" for node in nodes)
                if text:
                    boundaries = _hard_boundary_offsets(paragraph)
                    blocks.append(Block(
                        f"{part}::p::{idx}", part, "paragraph", text,
                        [f"hard-boundary:{offset}" for offset in boundaries
                         if offset < len(text)],
                    ))
                    covered.update(id(n) for n in nodes)
            leaf_idx = 0
            for node in root.iter():
                if (
                    node.tag in TEXT_TAGS
                    or id(node) in covered
                    or len(node)
                    or not (node.text or "").strip()
                ):
                    continue
                local = etree.QName(node).localname
                kind = f"property:{local}" if part.startswith("docProps/") else "leaf"
                blocks.append(
                    Block(f"{part}::leaf::{leaf_idx}", part, kind, node.text or "")
                )
                leaf_idx += 1
            for attr_idx, (_, _, value) in enumerate(_attribute_nodes(root)):
                blocks.append(
                    Block(f"{part}::attr::{attr_idx}", part, "attribute", value)
                )
        if part.endswith(".rels"):
            root = _xml(entries[part])
            hidx = 0
            for rel in root:
                if rel.get("TargetMode") == "External" and (
                    rel.get("Type") or ""
                ).endswith("/hyperlink"):
                    target = rel.get("Target") or ""
                    blocks.append(
                        Block(f"{part}::hyperlink::{hidx}", part, "hyperlink", target)
                    )
                    hidx += 1
    if not blocks:
        raise UnsafeDocument("В документе нет поддерживаемого текста")
    return ParsedDocx(entries, blocks)


def _resolve(
    root: etree._Element, block: Block
) -> tuple[list[etree._Element], str | None]:
    _, kind, index_text = block.id.rsplit("::", 2)
    index = int(index_text)
    if kind == "p":
        paragraphs = root.xpath("//*[local-name()='p']")
        return _text_nodes(paragraphs[index]), None
    if kind == "leaf":
        leaves = [
            n
            for n in root.iter()
            if n.tag not in TEXT_TAGS and not len(n) and (n.text or "").strip()
        ]
        return [leaves[index]], None
    if kind == "hyperlink":
        rels = [
            r
            for r in root
            if r.get("TargetMode") == "External"
            and (r.get("Type") or "").endswith("/hyperlink")
        ]
        return [rels[index]], "Target"
    if kind == "attr":
        node, attr, _ = _attribute_nodes(root)[index]
        return [node], attr
    if kind == "customtext":
        node, slot, _ = _custom_xml_text_nodes(root)[index]
        return [node], "__wordshield_tail__" if slot == "tail" else None
    if kind == "customattr":
        node, attr, _ = _custom_xml_attribute_nodes(root, block.part)[index]
        return [node], attr
    raise ValueError(kind)


def _safe_hyperlink_target(original: str, alias: str) -> str:
    match = ALIAS_TOKEN_RE.fullmatch(alias)
    if not match:
        raise UnsafeDocument("Некорректный алиас внешней ссылки")
    token = quote(match.group(1), safe='-_')
    scheme = urlsplit(original).scheme.lower()
    if scheme == "mailto":
        return f"mailto:wordshield-{token}@wordshield.invalid"
    if scheme in {"http", "https"}:
        return f"https://wordshield.invalid/a/{token}"
    raise UnsafeDocument("Неподдерживаемая схема внешней ссылки")


def hyperlink_alias(target: str) -> str | None:
    for pattern in (SAFE_MAILTO_RE, SAFE_WEB_RE):
        if match := pattern.fullmatch(target):
            token = unquote(match.group(1))
            base, sep, label = token.partition(':')
            alias = f"[[{base.upper()}{sep}{label}]]"
            return alias if ALIAS_TOKEN_RE.fullmatch(alias) else None
    return None


def _apply_to_nodes(
    nodes: list[etree._Element],
    attr: str | None,
    original: str,
    replacements: list[tuple[int, int, str, str]],
) -> None:
    positions: list[tuple[int, int, etree._Element]] = []
    cursor = 0
    for node in nodes:
        if attr == "__wordshield_tail__":
            value = node.tail
        else:
            value = node.get(attr) if attr else node.text
        value = value or ""
        positions.append((cursor, cursor + len(value), node))
        cursor += len(value)
    if cursor != len(original):
        raise UnsafeDocument("Структура DOCX изменилась между анализом и экспортом")
    for start, end, expected, replacement in sorted(replacements, reverse=True):
        if original[start:end] != expected:
            raise UnsafeDocument("exact_text не совпадает с исходным диапазоном")
        touched = [(a, b, n) for a, b, n in positions if a < end and b > start]
        if not touched:
            raise UnsafeDocument("Диапазон не попал в текстовый узел")
        a0, _, first = touched[0]
        al, _, last = touched[-1]
        if attr == "__wordshield_tail__":
            first_value = first.tail or ""
            last_value = last.tail or ""
        else:
            first_value = (first.get(attr) if attr else first.text) or ""
            last_value = (last.get(attr) if attr else last.text) or ""
        prefix = first_value[: start - a0]
        suffix = last_value[end - al :]
        # Word may split one visible value into more XML text nodes than there
        # are characters in the alias (tracked changes and field formatting do
        # this especially often). Keep as many carrier nodes as the alias can
        # populate and remove only the surplus text elements. Their surrounding
        # runs and run properties stay in place, which is valid OOXML and avoids
        # the empty w:t elements that make Word repair otherwise sound files.
        carrier_count = min(len(touched), len(replacement))
        if not carrier_count:
            raise UnsafeDocument("Пустая замена недопустима")
        if carrier_count == 1:
            carrier_indexes = [0]
        else:
            carrier_indexes = [
                round(index * (len(touched) - 1) / (carrier_count - 1))
                for index in range(carrier_count)
            ]
        weights = [
            min(touched[index][1], end) - max(touched[index][0], start)
            for index in carrier_indexes
        ]
        remaining = len(replacement)
        chunks: list[str] = []
        offset = 0
        for index, weight in enumerate(weights):
            count = (
                remaining
                if index == len(weights) - 1
                else min(
                    remaining - (carrier_count - index - 1),
                    max(1, round(len(replacement) * weight / (end - start))),
                )
            )
            chunks.append(replacement[offset : offset + count])
            offset += count
            remaining -= count
        chunks_by_index = dict(zip(carrier_indexes, chunks))
        for index, (_, _, node) in enumerate(touched):
            value = (prefix if index == 0 else "") + chunks_by_index.get(index, "")
            if index == len(touched) - 1:
                value += suffix
            if attr == "__wordshield_tail__":
                node.tail = value
            elif attr:
                node.set(attr, value)
            else:
                if not value and node.tag in TEXT_TAGS:
                    parent = node.getparent()
                    if parent is None:
                        raise UnsafeDocument("Текстовый узел DOCX не имеет родителя")
                    parent.remove(node)
                    continue
                node.text = value
                if node.tag == f"{{{W}}}t" and value and (
                    value[0].isspace() or value[-1].isspace()
                ):
                    node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")


def patch_docx(
    raw: bytes, blocks: list[Block], findings: list[Finding]
) -> tuple[bytes, set[str]]:
    parsed = parse_docx(raw)
    original_blocks = {b.id: b for b in parsed.blocks}
    provided_blocks = {b.id: b for b in blocks}
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.status != "accepted" or not finding.alias:
            continue
        grouped.setdefault(finding.block_id, []).append(finding)
    changed: set[str] = set()
    entries = dict(parsed.entries)
    for block_id, items in grouped.items():
        block = original_blocks.get(block_id)
        prior = provided_blocks.get(block_id)
        if not block or not prior or block.text != prior.text:
            raise UnsafeDocument("Блок не совпадает с проанализированным оригиналом")
        ordered = sorted(items, key=lambda x: (x.start, x.end))
        if any(f.start < boundary < f.end for f in ordered for boundary in hard_boundaries(block)):
            raise UnsafeDocument('Старая замена пересекает перенос Word. Повторите анализ документа.')
        if any(a.end > b.start for a, b in pairwise(ordered)):
            raise UnsafeDocument("Перекрывающиеся подтверждённые диапазоны")
        root = _xml(entries[block.part])
        nodes, attr = _resolve(root, block)
        replacements = [(f.start, f.end, f.exact_text, f.alias or "") for f in items]
        if block.kind == "hyperlink":
            if len(replacements) != 1 or replacements[0][:2] != (0, len(block.text)):
                raise UnsafeDocument("Внешнюю ссылку можно заменить только целиком")
            start, end, expected, alias = replacements[0]
            replacements = [(start, end, expected, _safe_hyperlink_target(block.text, alias))]
        _apply_to_nodes(
            nodes,
            attr,
            block.text,
            replacements,
        )
        entries[block.part] = etree.tostring(
            root, xml_declaration=True, encoding="UTF-8", standalone=True
        )
        changed.add(block.part)
    result = _zip(entries)
    assert_expected_text(raw, result, findings)
    return result, changed


def assert_expected_text(before: bytes, after: bytes, findings: list[Finding]) -> None:
    """Independently prove all text outside selected ranges is preserved."""
    left, right = parse_docx(before), parse_docx(after)
    original = {b.id: b for b in left.blocks}
    actual = {b.id: b for b in right.blocks}
    if original.keys() != actual.keys():
        raise UnsafeDocument('Набор текстовых полей изменился при экспорте')
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.status == 'accepted' and finding.alias:
            grouped.setdefault(finding.block_id, []).append(finding)
    if grouped.keys() - original.keys():
        raise UnsafeDocument('Замена ссылается на неизвестное поле')
    for bid, block in original.items():
        expected = block.text
        boundaries = hard_boundaries(block)
        edits = sorted(grouped.get(bid, []), key=lambda f: f.start, reverse=True)
        for f in edits:
            if not 0 <= f.start < f.end <= len(block.text) or block.text[f.start:f.end] != f.exact_text:
                raise UnsafeDocument('Замена не совпадает с оригиналом')
            replacement = _safe_hyperlink_target(block.text, f.alias) if block.kind == 'hyperlink' else f.alias
            expected = expected[:f.start] + replacement + expected[f.end:]
            delta = len(replacement) - (f.end-f.start)
            boundaries = {boundary + delta if boundary >= f.end else boundary for boundary in boundaries}
        if actual[bid].text != expected or hard_boundaries(actual[bid]) != boundaries:
            raise UnsafeDocument('Текст или переносы вне выбранных замен изменились')
    # Prove the XML outside authorised value slots is identical, too. Text-node
    # redistribution is checked by the block proof above and Word integrity gate.
    for part in left.entries:
        if left.entries[part] == right.entries.get(part):
            continue
        if not part.endswith(('.xml', '.rels')):
            raise UnsafeDocument('Изменена нетекстовая часть DOCX')
        roots = [_xml(left.entries[part]), _xml(right.entries[part])]
        for root in roots:
            for bid in grouped:
                block = original[bid]
                if block.part != part:
                    continue
                nodes, attr = _resolve(root, block)
                if attr:
                    for node in nodes:
                        if attr == '__wordshield_tail__':
                            node.tail = 'ALLOWED'
                        else:
                            node.set(attr, 'ALLOWED')
                elif block.kind != 'paragraph':
                    for node in nodes:
                        node.text = 'ALLOWED'
            for node in list(root.iter()):
                if node.tag in TEXT_TAGS:
                    node.getparent().remove(node)
        if etree.tostring(roots[0], method='c14n') != etree.tostring(roots[1], method='c14n'):
            raise UnsafeDocument('OOXML вне разрешённых значений изменился')


def replace_aliases(
    raw: bytes, replacements: dict[str, str]
) -> tuple[bytes, dict[str, int], list[str]]:
    parsed = parse_docx(raw)
    counts = {alias: 0 for alias in replacements}
    unknown: set[str] = set()
    token_re = ALIAS_TOKEN_RE
    entries = dict(parsed.entries)
    by_part: dict[str, list[Block]] = {}
    for block in parsed.blocks:
        if "[[" in block.text or (block.kind == "hyperlink" and hyperlink_alias(block.text)):
            by_part.setdefault(block.part, []).append(block)
    for part, blocks in by_part.items():
        root = _xml(entries[part])
        part_changed = False
        for block in blocks:
            spans = []
            if block.kind == "hyperlink" and (alias := hyperlink_alias(block.text)):
                candidates = [(0, len(block.text), alias)]
            else:
                candidates = [(m.start(), m.end(), m.group(0)) for m in token_re.finditer(block.text)]
            for start, end, alias in candidates:
                if alias not in replacements:
                    unknown.add(alias)
                    continue
                counts[alias] += 1
                spans.append((start, end, block.text[start:end], replacements[alias]))
            if spans:
                nodes, attr = _resolve(root, block)
                _apply_to_nodes(nodes, attr, block.text, spans)
                part_changed = True
        if part_changed:
            entries[part] = etree.tostring(
                root, xml_declaration=True, encoding="UTF-8", standalone=True
            )
    return _zip(entries), counts, sorted(unknown)


def _zip(entries: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return out.getvalue()


def assert_only_parts_changed(before: bytes, after: bytes, allowed: set[str]) -> None:
    left, right = _safe_zip(before), _safe_zip(after)
    if set(left) != set(right):
        raise UnsafeDocument("Набор частей DOCX изменился")
    actual = {name for name in left if left[name] != right[name]}
    if not actual.issubset(allowed):
        raise UnsafeDocument(f"Изменены запрещённые части: {sorted(actual - allowed)}")


def assert_word_text_integrity(before: bytes, after: bytes) -> None:
    """Reject text edits that make Word runs or whitespace structurally unsafe."""
    left, right = _safe_zip(before), _safe_zip(after)
    if left.get("word/styles.xml") != right.get("word/styles.xml"):
        raise UnsafeDocument("Стили Word изменились при замене текста")
    for part, source in left.items():
        if not part.startswith("word/") or not part.endswith(".xml"):
            continue
        if source == right.get(part):
            continue
        old_root, new_root = _xml(source), _xml(right[part])
        old_elements, new_elements = list(old_root.iter()), list(new_root.iter())
        old_structure = [node.tag for node in old_elements if node.tag not in TEXT_TAGS]
        new_structure = [node.tag for node in new_elements if node.tag not in TEXT_TAGS]
        if old_structure != new_structure:
            raise UnsafeDocument("Структура Word XML изменилась при замене текста")
        old_run_properties = [
            etree.tostring(node, method="c14n")
            for node in old_elements if node.tag == f"{{{W}}}rPr"
        ]
        new_run_properties = [
            etree.tostring(node, method="c14n")
            for node in new_elements if node.tag == f"{{{W}}}rPr"
        ]
        if old_run_properties != new_run_properties:
            raise UnsafeDocument("Свойства символов Word изменились")
        for new in new_elements:
            if new.tag in TEXT_TAGS and not new.text:
                raise UnsafeDocument("Замена создала пустой текстовый узел Word")
            if new.tag != f"{{{W}}}t":
                continue
            if new.text and (new.text[0].isspace() or new.text[-1].isspace()):
                if new.get("{http://www.w3.org/XML/1998/namespace}space") != "preserve":
                    raise UnsafeDocument("Пробел на границе Word run не сохранён")


def raw_archive_contains(raw: bytes, needles: list[str]) -> list[str]:
    entries = _safe_zip(raw)
    found: list[str] = []
    for needle in {n for n in needles if n}:
        encoded = (needle.encode("utf-8"), needle.encode("utf-16le"))
        if any(any(e in data for e in encoded) for data in entries.values()):
            found.append(needle)
    return found
