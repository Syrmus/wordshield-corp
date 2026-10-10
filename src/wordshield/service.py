from __future__ import annotations

import asyncio
import io
import json
import hashlib
import logging
import re
import subprocess
import sys
import tempfile
import zipfile
import threading
from functools import wraps
from pathlib import Path
from time import monotonic, time
from .progress import progress_snapshot

from .config import Settings
from .detectors import (
    DetectorUnavailable,
    PrivacyFilterDetector,
    RulesDetector,
    expand_approved_repetitions,
    merge_detections,
    resolve_clear_document_id_overlaps,
)
from .models import Block, Detection, Finding
from .gliner_detector import GlinerDetector, SandboxedPrivacyDetector
from .ooxml import (
    UnsafeDocument,
    assert_only_parts_changed,
    assert_word_text_integrity,
    hyperlink_alias,
    parse_docx,
    patch_docx,
    raw_archive_contains,
    replace_aliases,
)
from .storage import SessionStore
from .checkpoints import model_identity, runtime_identity
from .dictionary import DictionaryStore, apply_dictionary
from .export_checks import (
    add_exact_repeats,
    remaining_sensitive_fragments,
    remaining_values,
    secret_defaults,
)
from .overlaps import widest_replacements
from .technical_metadata import omit_technical_schemas
from .image_removal import remove_images
from .replacement_plan import compile_plan
from .replacement_options import validate_options, selected_types, selected_findings, short_aliases
from .ram_workspace import ram_workspace

ALIAS_RE = re.compile(r"\[\[([A-Z_]+)-([A-Z2-7]{4})-(\d{3,})(?::[^\[\]\r\n]{1,80})?\]\]")
ENTITY_TYPES = {
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
    "PERSONAL_ID",
    "DATE",
    "TIME",
    "SECRET",
    "IP",
    "ACCOUNT",
}
LOG = logging.getLogger("wordshield")


def serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._write_lock:
            return method(self, *args, **kwargs)
    return call


class WordShieldService:
    def __init__(self, settings: Settings):
        settings.validate()
        self.settings = settings
        self._write_lock = threading.RLock()
        self.store = SessionStore(settings.data_dir)
        self.dictionary = DictionaryStore(self.store)
        self.rules = RulesDetector()
        self.privacy = SandboxedPrivacyDetector(settings)
        self.qwen = None
        if settings.qwen_required:
            from .qwen_detector import QwenDetector
            self.qwen = QwenDetector(settings)
        self.gliner = GlinerDetector(settings)

    def begin_session(self, raw: bytes, filename: str | None = None, original: bytes | None = None, options: dict | None = None) -> str:
        # Omitted options preserve the pre-v2 Python integration; HTTP uploads
        # always supply validated v2 defaults. Existing sessions never migrate.
        options = validate_options(options) if options is not None else None
        if len(raw) > self.settings.max_upload_bytes:
            raise UnsafeDocument("Файл превышает допустимый размер")
        source = original if original is not None else raw
        raw, removed_images = remove_images(raw)
        parsed = parse_docx(raw)
        from .ooxml import ALIAS_TOKEN_RE
        if any(ALIAS_TOKEN_RE.search(b.text) or (b.kind == "hyperlink" and hyperlink_alias(b.text)) for b in parsed.blocks):
            raise UnsafeDocument("В документе уже есть алиасы WordShield. Используйте восстановление, а не повторный анализ")
        sid, _ = self.store.create(raw, self.settings.retention_days)
        # Names and dictionary snapshots can themselves contain PII.
        filename = (filename or "").replace("\\", "/").split("/")[-1]
        filename = "".join(c for c in filename if c.isprintable())[:240] or None
        self.store.put_json(sid, "metadata_blob", {"filename": filename,
                            "dictionary": self.dictionary.list(), "removed_images": removed_images,
                            "replacement_options": options})
        if source != raw:
            self.store.put_original(sid, source)
        self.store.update_state(sid, "detecting")
        return sid

    async def analyze_session(
        self, sid: str, preserve_decisions: bool = False
    ) -> list[Finding]:
        started = monotonic()
        try:
            raw = self.store.raw(sid)
            parsed = parse_docx(raw)
            row = self.store._row(sid)
            prefix = row["prefix"]
            fingerprint = hashlib.sha256(json.dumps({
                "raw": hashlib.sha256(raw).hexdigest(), "model": self.settings.lm_model,
                "privacy": self.settings.privacy_checkpoint, "gliner": self.settings.gliner_checkpoint,
                "threshold": self.settings.gliner_threshold,
                "privacy_weights": model_identity(self.settings.privacy_checkpoint) if self.settings.privacy_required else None,
                "privacy_tokenizer": model_identity(Path(self.settings.privacy_checkpoint).parent / "tokenizer-cache") if self.settings.privacy_required else None,
                "privacy_runtime": runtime_identity(self.settings.privacy_python or sys.executable) if self.settings.privacy_required else None,
                "gliner_runtime": runtime_identity(self.settings.gliner_python or sys.executable) if self.settings.gliner_required else None,
                "tokenizer": hashlib.sha256(Path(self.settings.qwen_tokenizer).read_bytes()).hexdigest()
                    if self.settings.qwen_tokenizer else None,
                "enabled": [self.settings.privacy_required, self.settings.qwen_required, self.settings.gliner_required],
                "manifest": hashlib.sha256((Path(self.settings.gliner_checkpoint) / "wordshield-manifest.json").read_bytes()).hexdigest()
                    if self.settings.gliner_required else None,
                "pipeline": hashlib.sha256(Path(__file__).with_name("detectors.py").read_bytes()).hexdigest(),
                "gliner_adapter": hashlib.sha256(Path(__file__).with_name("local_worker.py").read_bytes()).hexdigest(),
                "adapter": hashlib.sha256(Path(__file__).with_name("gliner_detector.py").read_bytes()).hexdigest(),
                "document_adapter": hashlib.sha256(Path(__file__).with_name('models.py').read_bytes()).hexdigest(),
                "parser": hashlib.sha256(Path(__file__).with_name('ooxml.py').read_bytes()).hexdigest(),
                "schema": 4,
            }, sort_keys=True).encode()).hexdigest()
            meta = self.store.get_json(sid, "detector_blob") or {}
            if meta.get("fingerprint") != fingerprint:
                self.store.put_json(sid, "qwen_blob", {"completed": [], "detections": []})
                self.store.put_json(sid, "privacy_blob", None)
                self.store.put_json(sid, "gliner_blob", {"completed": [], "detections": []})
                self.store.put_json(sid, "detector_blob", {"fingerprint": fingerprint})
            self.store.update_stage(sid, "detecting", 0, 0)
            detections = self.rules.detect(parsed.blocks)
            qwen_checkpoint = self.store.get_json(sid, "qwen_blob") or {
                "completed": [], "detections": []
            }
            privacy_checkpoint = self.store.get_json(sid, "privacy_blob") or {"completed": [], "detections": []}
            privacy_completed = set(privacy_checkpoint["completed"])
            completed = set(qwen_checkpoint["completed"])
            total = len(self.qwen.prepare_blocks(parsed.blocks)[0]) if self.settings.qwen_required else sum(bool(b.text) for b in parsed.blocks)
            self.store.update_progress(sid, len(completed), total)

            # Per-detector counters survive page reloads; retries start fresh timing
            # from cached work rather than counting cached fragments as new speed.
            progress = {'stages': {}, 'active': None}
            block_total = sum(bool(b.text) for b in parsed.blocks)
            gliner_cache = self.store.get_json(sid, 'gliner_blob') or {'completed': []}
            for name, enabled, count, size in (
                ('privacy-detector', self.settings.privacy_required, len(privacy_completed), block_total),
                ('context-analysis', self.settings.qwen_required, len(completed), total),
                ('russian-detector', self.settings.gliner_required, len(gliner_cache['completed']), block_total),
            ):
                if enabled:
                    progress['stages'][name] = {'done': min(count, size), 'total': size, 'baseline': min(count, size)}

            def track(name, count=None):
                entry = progress['stages'][name]
                now = time()
                entry.setdefault('started', now)
                entry['updated'] = now
                if count is not None:
                    entry['done'] = min(count, entry['total'])
                progress['active'] = name
                self.store.put_json(sid, 'detector_blob', {'fingerprint': fingerprint, 'progress': progress})
                self.store.update_stage(sid, name, entry['done'], entry['total'])

            for name in ('privacy-detector', 'context-analysis'):
                if name in progress['stages']:
                    track(name)

            def record_qwen(chunk: list[Block], found: list[Detection]) -> None:
                completed.update(b.id for b in chunk)
                qwen_checkpoint["completed"] = sorted(completed)
                qwen_checkpoint["detections"].extend(d.__dict__ for d in found)
                self.store.put_json(sid, "qwen_blob", qwen_checkpoint)
                self.store.update_progress(sid, len(completed), total)
                self.store.update_stage(sid, "context-analysis", len(completed), total)
                track('context-analysis', len(completed))

            def record_privacy(chunk: list[Block], found: list[Detection]) -> None:
                privacy_completed.update(b.id for b in chunk)
                privacy_checkpoint["completed"] = sorted(privacy_completed)
                privacy_checkpoint["detections"].extend(d.__dict__ for d in found)
                self.store.put_json(sid, "privacy_blob", privacy_checkpoint)
                self.store.update_stage(sid, "privacy-detector", len(privacy_completed), len(parsed.blocks))
                track('privacy-detector', len(privacy_completed))

            privacy_call = (
                self.privacy.detect(parsed.blocks, privacy_completed, record_privacy)
                if self.settings.privacy_required else asyncio.sleep(0, result=[])
            )
            qwen_call = (
                self.qwen.detect(parsed.blocks, completed, record_qwen)
                if self.settings.qwen_required
                else asyncio.sleep(0, result=[])
            )
            privacy_result, qwen_result = await asyncio.gather(
                privacy_call, qwen_call, return_exceptions=True
            )
            if isinstance(privacy_result, Exception):
                if self.settings.privacy_required:
                    raise DetectorUnavailable(
                        str(privacy_result) if isinstance(privacy_result, DetectorUnavailable)
                        else f"privacy-filter: {type(privacy_result).__name__}"
                    )
            else:
                if self.settings.privacy_required:
                    detections.extend(Detection(**d) for d in privacy_checkpoint["detections"])
            if isinstance(qwen_result, Exception):
                if self.settings.qwen_required:
                    raise DetectorUnavailable(
                        f"Qwen: {type(qwen_result.__cause__ or qwen_result).__name__}"
                    )
            if self.settings.qwen_required:
                detections.extend(Detection(**d) for d in qwen_checkpoint["detections"])
            if self.settings.gliner_required:
                cache = self.store.get_json(sid, "gliner_blob") or {"completed": [], "detections": []}
                done = set(cache["completed"])
                self.store.update_stage(sid, "russian-detector", len(done), total)
                track('russian-detector')
                def record_gliner(chunk, found):
                    done.update(b.id for b in chunk)
                    cache["completed"] = sorted(done)
                    cache["detections"].extend(d.__dict__ for d in found)
                    self.store.put_json(sid, "gliner_blob", cache)
                    self.store.update_stage(sid, "russian-detector", len(done), total)
                    track('russian-detector', len(done))
                await self.gliner.detect(parsed.blocks, done, record_gliner)
                detections.extend(Detection(**d) for d in cache["detections"])
            self.store.update_stage(sid, "combining", total, total)
            metadata = self.store.get_json(sid, "metadata_blob") or {}
            options = metadata.get('replacement_options')
            types = selected_types(options)
            # Resolve specific types before filtering: e.g. a recognised SNILS
            # must not turn into PHONE just because personal IDs were unchecked.
            findings = merge_detections(parsed.blocks, detections)
            findings = selected_findings(findings, options)
            findings = apply_dictionary(parsed.blocks, findings, [e for e in metadata.get("dictionary", []) if e['entity_type'] in types])
            protected_ranges = []
            if preserve_decisions:
                old_payload = self.store.get_json(sid, "findings_blob")
                if old_payload:
                    old = old_payload["findings"]
                    protected_ranges = [(f["block_id"], f["start"], f["end"]) for f in old if f["status"] in {"accepted", "rejected"}]
                    by_range = {(f["block_id"], f["start"], f["end"]): f for f in old}
                    for finding in findings:
                        previous = by_range.get((finding.block_id, finding.start, finding.end))
                        if previous:
                            finding.status = previous["status"]
                            finding.entity_type = previous["entity_type"]
                        elif any(f["block_id"] == finding.block_id and f["start"] < finding.end
                                 and f["end"] > finding.start and f["status"] in {"accepted", "rejected"}
                                 for f in old):
                            finding.status = "pending"
                            continue
                        elif "compound-gap" not in finding.sources or any(
                            f["status"] == "accepted"
                            and f["entity_type"] == "DOCUMENT_ID"
                            and f["end"] - f["start"] > 45
                            and f["sources"] == ["privacy-filter"]
                            and f["block_id"] == finding.block_id
                            and f["start"] <= finding.start
                            and finding.end <= f["end"]
                            for f in old
                        ):
                            parents = [f for f in old if f["status"] == "accepted"
                                       and f["block_id"] == finding.block_id
                                       and f["start"] <= finding.start
                                       and finding.end <= f["end"]]
                            if parents:
                                finding.status = "accepted"
                        if "fio-joined" in finding.sources and any(
                            f["entity_type"] == "PERSON" and f["status"] == "rejected"
                            and f["block_id"] == finding.block_id
                            and finding.start <= f["start"] and f["end"] <= finding.end
                            for f in old
                        ):
                            finding.status = "pending"
                resolve_clear_document_id_overlaps(findings)
                for index, left in enumerate(findings):
                    for right in findings[index + 1:]:
                        if left.status == right.status == "accepted" \
                                and left.block_id == right.block_id \
                                and left.start < right.end and right.start < left.end:
                            left.status = right.status = "pending"
            findings = expand_approved_repetitions(parsed.blocks, findings, protected_ranges)
            findings = compile_plan(parsed.blocks, findings, options)
            payload = {
                "prefix": prefix,
                "blocks": [b.__dict__ for b in parsed.blocks],
                "findings": [f.json() for f in findings],
                "replacement_options": options,
            }
            self.store.put_json(sid, "findings_blob", payload)
            self.store.update_state(sid, "review", len(findings))
            self.store.update_stage(sid, "review", total, total)
            LOG.info(
                "job=%s status=review duration_ms=%d entities=%d",
                sid,
                int((monotonic() - started) * 1000),
                len(findings),
            )
            return findings
        except Exception as exc:
            code = str(exc) if isinstance(exc, DetectorUnavailable) else type(exc).__name__
            self.store.update_error(sid, code[:120])
            LOG.warning(
                "job=%s status=failed duration_ms=%d",
                sid,
                int((monotonic() - started) * 1000),
            )
            raise

    async def create_session(self, raw: bytes) -> tuple[str, list[Finding]]:
        sid = self.begin_session(raw)
        return sid, await self.analyze_session(sid)

    def status(self, sid: str) -> dict:
        row = self.store._row(sid)
        detector = self.store.get_json(sid, 'detector_blob') or {}
        return {
            'progress': progress_snapshot(detector.get('progress', {}), row['state']),
            "id": row["id"],
            "state": row["state"],
            "entity_count": row["entity_count"],
            "completed_blocks": row["completed_blocks"],
            "total_blocks": row["total_blocks"],
            "error_code": row["error_code"],
            "stage": row["stage"],
            "completed_chunks": row["completed_chunks"],
            "total_chunks": row["total_chunks"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
        }

    @serialized
    def findings(self, sid: str) -> dict:
        payload = self.store.get_json(sid, "findings_blob")
        if payload is None:
            raise KeyError(sid)
        if self.store._row(sid)['state'] == 'exported':
            return payload
        normalized = compile_plan([Block(**b) for b in payload['blocks']],
                                  [Finding(**f) for f in payload['findings']], payload.get('replacement_options'))
        if [f.json() for f in normalized] != payload['findings']:
            payload['findings'] = [f.json() for f in normalized]
            self.store.put_json(sid, 'findings_blob', payload)
        return payload

    @serialized
    def decide(
        self, sid: str, decisions: list[dict], additions: list[dict] | None = None
    ) -> dict:
        if self.store._row(sid)["state"] != "review":
            raise ValueError("Изменять решения можно только до экспорта")
        payload = self.findings(sid)
        by_id = {f["id"]: f for f in payload["findings"]}
        types = selected_types(payload.get('replacement_options'))
        for decision in decisions:
            finding = by_id.get(str(decision.get("id")))
            status = decision.get("status")
            if finding and status in {"accepted", "rejected", "pending"}:
                finding["status"] = status
                if decision.get("entity_type"):
                    if decision['entity_type'] != finding['entity_type'] and decision['entity_type'] not in types:
                        raise ValueError('Этот тип данных не выбран для данной сессии')
                    if decision["entity_type"] not in ENTITY_TYPES:
                        raise ValueError("Неизвестный тип сущности")
                    finding["entity_type"] = decision["entity_type"]
                    if finding.get("alias") and not finding["alias"].startswith("[[" + finding["entity_type"] + "-"):
                        finding["alias"] = None
        block_map = {b["id"]: b for b in payload["blocks"]}
        expanded: list[dict] = []
        for item in additions or []:
            if item.get("block_id"):
                expanded.append(item)
                continue
            exact = item.get("exact_text")
            if not isinstance(exact, str) or not exact:
                raise ValueError("Укажите точный ручной фрагмент")
            for block in block_map.values():
                cursor = 0
                while (start := block["text"].find(exact, cursor)) >= 0:
                    expanded.append(
                        {
                            **item,
                            "block_id": block["id"],
                            "start": start,
                            "end": start + len(exact),
                        }
                    )
                    cursor = start + len(exact)
            if not any(x.get("exact_text") == exact for x in expanded):
                raise ValueError("Ручной фрагмент не найден")
        for item in expanded:
            block = block_map.get(item.get("block_id"))
            start, end = item.get("start"), item.get("end")
            if (
                not block
                or not isinstance(start, int)
                or not isinstance(end, int)
                or not (0 <= start < end <= len(block["text"]))
            ):
                raise ValueError("Некорректный ручной диапазон")
            exact = block["text"][start:end]
            if exact != item.get("exact_text"):
                raise ValueError("Ручной exact_text не совпадает")
            if item.get("entity_type") not in types:
                raise ValueError("Неизвестный тип сущности")
            duplicate = next(
                (
                    f
                    for f in payload["findings"]
                    if f["block_id"] == block["id"]
                    and f["start"] == start
                    and f["end"] == end
                ),
                None,
            )
            if duplicate:
                duplicate.update(
                    status="accepted",
                    entity_type=item["entity_type"],
                    sources=sorted(set(duplicate["sources"] + ["manual"])),
                    confidence=1.0,
                )
                continue
            for old in payload["findings"]:
                if (
                    old["block_id"] == block["id"]
                    and old["start"] < end
                    and start < old["end"]
                ):
                    old["status"] = "rejected"
            next_id = f"manual-{len(payload['findings']) + 1}"
            payload["findings"].append(
                {
                    "id": next_id,
                    "block_id": block["id"],
                    "start": start,
                    "end": end,
                    "exact_text": exact,
                    "entity_type": item["entity_type"],
                    "sources": ["manual"],
                    "status": "accepted",
                    "confidence": 1.0,
                    "context": block["text"][
                        max(0, start - 45) : min(len(block["text"]), end + 45)
                    ],
                    "alias": None,
                }
            )
        derived = {
            (f["block_id"], f["start"], f["end"]): f
            for f in payload["findings"]
            if f["sources"] in (["repeat-local"], ["case-form-local"])
        }
        primary = [Finding(**f) for f in payload["findings"]
                   if f["sources"] not in (["repeat-local"], ["case-form-local"])]
        updated = expand_approved_repetitions(
            [Block(**b) for b in payload["blocks"]], primary,
            [(f["block_id"], f["start"], f["end"]) for f in payload["findings"]
             if f["status"] == "rejected"]
        )
        for finding in updated:
            if finding.sources in (["repeat-local"], ["case-form-local"]):
                previous = derived.get((finding.block_id, finding.start, finding.end))
                if previous:
                    finding.status = previous["status"]
                    finding.entity_type = previous["entity_type"]
        resolve_clear_document_id_overlaps(updated)
        updated = compile_plan([Block(**b) for b in payload['blocks']], updated, payload.get('replacement_options'))
        payload["findings"] = [finding.json() for finding in updated]
        self.store.put_json(sid, "findings_blob", payload)
        return payload

    def _render(self, raw: bytes) -> None:
        if not self.settings.render_required:
            return
        with ram_workspace() as tmp:
            source = Path(tmp) / "document.docx"
            out = Path(tmp) / "rendered"
            source.write_bytes(raw)
            out.mkdir()
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": tmp, "TMPDIR": tmp}
            try:
                proc = subprocess.run(
                    [
                    self.settings.libreoffice_path,
                    "-env:UserInstallation=" + (Path(tmp) / "lo-profile").as_uri(),
                    "--headless",
                    "--nologo",
                    "--nodefault",
                    "--nolockcheck",
                    "--convert-to",
                    "pdf",
                    "--outdir",
                    str(out),
                    str(source),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=240,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                raise UnsafeDocument("Проверочный рендер LibreOffice превысил 4 минуты") from exc
            pdf = out / "document.pdf"
            if proc.returncode != 0 or not pdf.exists() or pdf.stat().st_size == 0:
                raise UnsafeDocument("Проверочный рендер LibreOffice не прошёл")

    @serialized
    def export(self, sid: str) -> bytes:
        started = monotonic()
        if self.store._row(sid)["state"] == "exported":
            try:
                output = remove_images(self.store.result(sid), previews_only=True)[0]
                parse_docx(output)
                return output
            except KeyError:
                raise UnsafeDocument("Результат старой сессии не сохранялся. Используйте ранее скачанный файл")
        if self.store._row(sid)["state"] != "review":
            raise UnsafeDocument("Экспорт доступен только после завершения анализа")
        payload = self.findings(sid)
        findings = [Finding(**f) for f in payload["findings"]]
        if resolve_clear_document_id_overlaps(findings):
            payload["findings"] = [f.json() for f in findings]
            self.store.put_json(sid, "findings_blob", payload)
        if any(f.status == "pending" for f in findings):
            raise UnsafeDocument("Сначала проверьте все сомнительные находки")
        blocks = [Block(**b) for b in payload['blocks']]
        # findings() returns the persisted plan already shown in the review UI.
        accepted = [f for f in findings if f.status == "accepted"]
        overlapping = sum(
            a.block_id == b.block_id and a.start < b.end and b.start < a.end
            for index, a in enumerate(accepted) for b in accepted[index + 1:]
        )
        if overlapping:
            raise UnsafeDocument(
                f"Подтверждённые диапазоны пересекаются: {overlapping}. Уточните находки перед экспортом"
            )
        prefix = payload["prefix"]
        alias_by_value: dict[tuple[str, str], str] = {
            (f.entity_type, f.exact_text): f.alias for f in accepted
            if f.alias and "-GLOB-" in f.alias
        }
        for finding in accepted:
            key = (finding.entity_type, finding.exact_text)
            if key not in alias_by_value:
                alias_by_value[key] = finding.alias or (
                    f"[[{finding.entity_type}-{prefix}-{len(alias_by_value) + 1:03d}]]"
                )
            finding.alias = alias_by_value[key]
        if payload.get('replacement_options'):
            # Reset legacy generated tokens while retaining dictionary tokens.
            for finding in accepted:
                if finding.alias and '-GLOB-' not in finding.alias:
                    finding.alias = None
            alias_by_value = short_aliases(accepted, payload['replacement_options'])
        original = self.store.raw(sid)
        blocks = [Block(**b) for b in payload["blocks"]]
        output, changed = patch_docx(original, blocks, accepted)
        assert_only_parts_changed(original, output, changed)
        assert_word_text_integrity(original, output)
        leaked = remaining_values(output, [f.exact_text for f in accepted],
                                  [f.alias for f in accepted])
        if leaked:
            raise UnsafeDocument(
                f"Не удалось безопасно скрыть все повторения выбранных данных: {len(leaked)}. "
                "Некоторые повторения пропущены, пересекаются с другими заменами или находятся в служебных свойствах. "
                "Файл не выдан, чтобы не раскрыть данные. Вернитесь к проверке сессии."
            )
        fragments = remaining_sensitive_fragments(
            output, accepted, [f.alias for f in accepted]
        )
        if fragments:
            raise UnsafeDocument(
                f"После замены остались части чувствительных значений: {len(fragments)}. "
                "Файл не выдан, чтобы не раскрыть данные. Вернитесь к проверке сессии."
            )
        if b"mapping_blob" in output:
            raise UnsafeDocument("Служебная таблица попала в DOCX")
        parse_docx(output)
        self._render(output)
        mapping = {
            alias: value for (entity_type, value), alias in alias_by_value.items()
        }
        self.store.put_json(sid, "mapping_blob", {"prefix": prefix, "mapping": mapping})
        payload['findings'] = [f.json() for f in findings]
        self.store.put_json(sid, 'findings_blob', payload)
        self.store.put_result(sid, output)
        self.store.update_state(sid, "exported", len(accepted))
        LOG.info(
            "job=%s status=exported duration_ms=%d entities=%d",
            sid,
            int((monotonic() - started) * 1000),
            len(accepted),
        )
        return output

    def restore(self, raw: bytes, session_id: str | None = None) -> tuple[bytes, dict]:
        started = monotonic()
        raw = remove_images(raw, previews_only=True)[0]
        parsed = parse_docx(raw)
        tokens = ALIAS_RE.findall("\n".join(b.text for b in parsed.blocks))
        tokens.extend(
            match.groups()
            for block in parsed.blocks
            if block.kind == "hyperlink"
            if (alias := hyperlink_alias(block.text))
            if (match := ALIAS_RE.fullmatch(alias))
        )
        prefixes = {prefix for _, prefix, _ in tokens if prefix != "GLOB"}
        if session_id:
            row = self.store._row(session_id)
            if prefixes and prefixes != {row["prefix"]}:
                raise UnsafeDocument("Выбранная сессия не соответствует алиасам документа")
        elif len(prefixes) == 1:
            row = self.store.find_by_prefix(next(iter(prefixes)))
        else:
            raise UnsafeDocument("Выберите исходную сессию: короткие и постоянные плейсхолдеры могут совпадать в разных документах. Откройте «Восстановить» из карточки нужной сессии")
        payload = self.store.get_json(row["id"], "mapping_blob")
        if not payload:
            raise UnsafeDocument("Таблица алиасов недоступна или истекла")
        restored, counts, unknown = replace_aliases(raw, payload["mapping"])
        parse_docx(restored)
        assert_word_text_integrity(raw, restored)
        self._render(restored)
        missing = sorted(alias for alias, count in counts.items() if count == 0)
        duplicates = {alias: count for alias, count in counts.items() if count > 1}
        report = {
            "session_id": row["id"],
            "restored": sum(counts.values()),
            "missing": missing,
            "duplicates": duplicates,
            "unknown": unknown,
        }
        LOG.info(
            "job=%s status=restored duration_ms=%d entities=%d missing=%d duplicates=%d unknown=%d",
            row["id"],
            int((monotonic() - started) * 1000),
            report["restored"],
            len(missing),
            len(duplicates),
            len(unknown),
        )
        return restored, report

    @staticmethod
    def restore_bundle(document: bytes, report: dict) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("restored.docx", document)
            zf.writestr(
                "restore-report.json", json.dumps(report, ensure_ascii=False, indent=2)
            )
        return out.getvalue()
