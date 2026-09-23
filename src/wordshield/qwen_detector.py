"""Optional experimental Qwen adapter; the production path does not load it."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from collections.abc import Callable
import httpx
from .models import Block, Detection
from .config import Settings
from .detectors import DetectorUnavailable, qwen_chunks


class QwenDetector:
    _lock = asyncio.Lock()

    def __init__(self, settings: Settings):
        self.settings = settings
        self._tokenizer = None

    def prepare_blocks(self, blocks):
        path = getattr(self.settings, "qwen_tokenizer", "")
        if not path:
            return [b for b in blocks if b.text], {b.id: (b.id, 0) for b in blocks}
        if self._tokenizer is None:
            from tokenizers import Tokenizer
            if not Path(path).is_file():
                raise DetectorUnavailable("Локальный токенизатор Qwen не установлен")
            self._tokenizer = Tokenizer.from_file(path)
        tokenizer = self._tokenizer
        class Offsets:
            def __call__(self, text, **kwargs):
                return {"offset_mapping": tokenizer.encode(text, add_special_tokens=False).offsets}
        from .local_worker import token_windows
        expanded, mapping = [], {}
        for block in blocks:
            for offset, text in token_windows(block.text, Offsets()):
                key = block.id if offset == 0 and text == block.text else f"{block.id}::window:{offset}"
                expanded.append(Block(key, block.part, block.kind, text))
                mapping[key] = (block.id, offset)
        return expanded, mapping

    async def detect(
        self,
        blocks: list[Block],
        completed: set[str] | None = None,
        on_chunk: Callable[[list[Block], list[Detection]], None] | None = None,
    ) -> list[Detection]:
        expanded, mapping = self.prepare_blocks(blocks)
        remaining = [b for b in expanded if b.id not in (completed or set())]
        if not remaining:
            return []
        schema = {
            "name": "sensitive_spans",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["findings"],
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["block_id", "exact_text", "entity_type"],
                            "properties": {
                                "block_id": {"type": "string"},
                                "exact_text": {"type": "string", "minLength": 1},
                                "entity_type": {
                                    "type": "string",
                                    "enum": [
                                        "PII",
                                        "PERSON",
                                        "ORG",
                                        "ADDRESS",
                                        "CITY",
                                        "EMAIL",
                                        "PHONE",
                                        "URL",
                                        "PRICE",
                                        "BANK",
                                        "TAX_ID",
                                        "REG_ID",
                                        "DOCUMENT_ID",
                                        "PASSPORT",
                                        "DATE",
                                        "TIME",
                                        "SECRET",
                                        "IP",
                                        "ACCOUNT",
                                    ],
                                },
                            },
                        },
                    }
                },
            },
        }
        headers = {"Content-Type": "application/json"}
        if self.settings.lm_token:
            headers["Authorization"] = f"Bearer {self.settings.lm_token}"
        out: list[Detection] = []
        def remap(found):
            converted = {}
            for d in found:
                original, offset = mapping[d.block_id]
                value = Detection(original, d.start+offset, d.end+offset, d.exact_text,
                                  d.entity_type, d.source, d.confidence, d.format_confirmed)
                converted[(original, value.start, value.end, value.entity_type)] = value
            return list(converted.values())
        def checkpoint(chunk, found):
            if on_chunk:
                on_chunk(chunk, remap(found))
        async with httpx.AsyncClient(
            base_url=self.settings.lm_base_url,
            headers=headers,
            timeout=httpx.Timeout(connect=10, read=120, write=30, pool=30),
        ) as client:
            for chunk, compact in qwen_chunks(remaining):
                found = await self._detect_chunk(client, schema, chunk, compact, checkpoint)
                out.extend(remap(found))
        return list({(d.block_id, d.start, d.end, d.entity_type): d for d in out}.values())

    async def _detect_chunk(
        self,
        client: httpx.AsyncClient,
        schema: dict,
        chunk: list[Block],
        compact: list[dict],
        on_chunk: Callable[[list[Block], list[Detection]], None] | None,
    ) -> list[Detection]:
        for attempt in range(4):
            try:
                payload = {
                    "model": getattr(self.settings, "lm_instance", self.settings.lm_model),
                    "temperature": 0,
                    "max_tokens": 2048,
                    "messages": [
                        {
                            "role": "system",
                            "content": "/no_think\nТы детектор точных чувствительных подстрок. Найди людей, организации, города, адреса, контакты, цены, платежи, реквизиты, паспорта, номера документов, даты и время документа, секреты и внутренние IP. Если строка содержит имя, паспорт и адрес, верни три отдельных точных значения, а не всю строку. Не включай подписи полей и соседние значения в exact_text. Для даты и времени верни отдельные DATE и TIME. Верни только дословные подстроки текста с block_id и типом. Не отмечай страны, публичные даты законов и общие числа. Ничего не переписывай.",
                        },
                        {"role": "user", "content": json.dumps(compact, ensure_ascii=False)},
                    ],
                    "response_format": {"type": "json_schema", "json_schema": schema},
                }
                if self.settings.lm_model == "qwen/qwen3.5-9b":
                    # LM Studio ignores chat_template_kwargs on this endpoint.
                    # Without this, schema-constrained JSON lands in reasoning_content.
                    payload["reasoning_effort"] = "none"
                    payload["messages"][0]["content"] = payload["messages"][0]["content"].removeprefix("/no_think\n")
                async with self._lock:
                    response = await client.post("/chat/completions", json=payload)
                response.raise_for_status()
                choice = response.json()["choices"][0]
                if choice.get("finish_reason") == "length":
                    raise ValueError("truncated JSON")
                data = json.loads(choice["message"]["content"])
                if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
                    raise ValueError("invalid detection envelope")
                found: list[Detection] = []
                by_id = {b.id: b for b in chunk}
                valid_types = schema["schema"]["properties"]["findings"]["items"]["properties"]["entity_type"]["enum"]
                for item in data.get("findings", []):
                    block = by_id.get(item.get("block_id"))
                    exact = item.get("exact_text")
                    entity_type = item.get("entity_type")
                    if not block or not isinstance(exact, str) or not exact or entity_type not in valid_types or exact not in block.text:
                        raise ValueError("invalid exact detection")
                    cursor = 0
                    while (start := block.text.find(exact, cursor)) >= 0:
                        found.append(Detection(block.id, start, start + len(exact), exact,
                                               entity_type, "qwen", 0.72))
                        cursor = start + len(exact)
                if on_chunk:
                    on_chunk(chunk, found)
                return found
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in {400, 401, 403, 404, 422}:
                    raise DetectorUnavailable(f"LM Studio/Qwen HTTP {exc.response.status_code}") from exc
                error: Exception = exc
            except (httpx.RequestError, ValueError, KeyError, IndexError, TypeError) as exc:
                error = exc
            if len(chunk) > 1:
                middle = len(chunk) // 2
                result: list[Detection] = []
                for part in (chunk[:middle], chunk[middle:]):
                    result.extend(await self._detect_chunk(
                        client, schema, part,
                        [{"block_id": b.id, "text": b.text} for b in part],
                        on_chunk,
                    ))
                return result
            if attempt < 3:
                await asyncio.sleep(min(2 ** attempt * 5, 20))
        raise DetectorUnavailable(
            f"LM Studio/Qwen не ответил на одиночный блок: {type(error).__name__}"
        ) from error
