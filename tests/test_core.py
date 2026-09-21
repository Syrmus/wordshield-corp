from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

import pytest
from lxml import etree

from wordshield.config import Settings
from wordshield.detectors import (
    RulesDetector,
    expand_approved_repetitions,
    merge_detections,
    privacy_chunks,
    qwen_chunks,
)
from wordshield.models import Block, Detection, Finding, hard_boundaries
from wordshield.ooxml import (
    UnsafeDocument,
    assert_word_text_integrity,
    parse_docx,
    patch_docx,
    raw_archive_contains,
    replace_aliases,
)
from wordshield.service import WordShieldService

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""


def make_docx(parts: list[str], extra: dict[str, bytes] | None = None) -> bytes:
    runs = "".join(f'<w:r><w:t xml:space="preserve">{p}</w:t></w:r>' for p in parts)
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p>{runs}</w:p><w:sectPr/></w:body></w:document>""".encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CONTENT_TYPES)
        zf.writestr("_rels/.rels", RELS)
        zf.writestr("word/document.xml", document)
        for name, data in (extra or {}).items():
            zf.writestr(name, data)
    return out.getvalue()


def text(raw: bytes) -> str:
    return "\n".join(b.text for b in parse_docx(raw).blocks)


def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        allowed_user="owner@example.com",
        trust_tailscale_headers=False,
        lm_base_url="http://127.0.0.1:1234/v1",
        lm_token="",
        lm_model="qwen/qwen3-14b",
        privacy_checkpoint=str(tmp_path / "privacy"),
        privacy_device="cpu",
        privacy_required=False,
        qwen_required=False,
        render_required=False,
        libreoffice_path="soffice",
        retention_days=90,
        upload_ttl_hours=24,
        max_upload_bytes=25 * 1024 * 1024,
    )


def test_cloud_lm_endpoint_is_rejected(tmp_path: Path):
    cfg = settings(tmp_path)
    bad = Settings(**{**cfg.__dict__, "lm_base_url": "https://api.example.com/v1"})
    with pytest.raises(ValueError, match="local HTTP"):
        bad.validate()


def test_span_across_runs_and_restore():
    raw = make_docx(["ООО «Ро", "машка»", " платит 120 000 ₽."])
    parsed = parse_docx(raw)
    block = parsed.blocks[0]
    start = block.text.index("ООО")
    end = block.text.index(" платит")
    finding = Finding(
        "f1",
        block.id,
        start,
        end,
        block.text[start:end],
        "ORG",
        ["qwen"],
        "accepted",
        0.9,
        alias="[[ORG-A7K3-001]]",
    )
    anon, changed = patch_docx(raw, parsed.blocks, [finding])
    assert changed == {"word/document.xml"}
    assert "ООО «Ромашка»" not in text(anon)
    assert "[[ORG-A7K3-001]] платит 120 000 ₽." in text(anon)
    with zipfile.ZipFile(io.BytesIO(anon)) as zf:
        root = etree.fromstring(zf.read("word/document.xml"))
    assert all(node.text for node in root.iter() if node.tag == f"{{{W}}}t")
    restored, counts, unknown = replace_aliases(
        anon, {"[[ORG-A7K3-001]]": "ООО «Ромашка»"}
    )
    assert text(restored) == block.text
    assert counts["[[ORG-A7K3-001]]"] == 1
    assert unknown == []


def test_visible_word_break_is_recorded_without_changing_legacy_offsets():
    raw = make_docx(["Emily Rose CarterNorthbridge Analytics Ltd"])
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            data = src.read(name)
            if name == "word/document.xml":
                data = data.replace(
                    b"CarterNorthbridge",
                    b"Carter</w:t></w:r><w:r><w:br/></w:r><w:r><w:t>Northbridge",
                )
            dst.writestr(name, data)
    block = parse_docx(out.getvalue()).blocks[0]
    assert block.text == "Emily Rose CarterNorthbridge Analytics Ltd"
    assert hard_boundaries(block) == {len("Emily Rose Carter")}


def test_replacement_keeps_each_word_run_and_preserves_boundary_spaces():
    raw = make_docx(["before ", "ОО", "О Ро", "машка", " after"])
    parsed = parse_docx(raw)
    block = parsed.blocks[0]
    value = "ООО Ромашка"
    start = block.text.index(value)
    selected = Finding(
        "f1", block.id, start, start + len(value), value, "ORG",
        ["manual"], "accepted", 1.0, alias="[[ORG-A7K3-001]]",
    )
    anonymous, _ = patch_docx(raw, parsed.blocks, [selected])
    assert text(anonymous) == "before [[ORG-A7K3-001]] after"
    with zipfile.ZipFile(io.BytesIO(anonymous)) as zf:
        root = etree.fromstring(zf.read("word/document.xml"))
    nodes = [node for node in root.iter() if node.tag == f"{{{W}}}t"]
    assert len(nodes) == 5
    assert all(node.text for node in nodes)
    assert nodes[0].get("{http://www.w3.org/XML/1998/namespace}space") == "preserve"
    assert nodes[-1].get("{http://www.w3.org/XML/1998/namespace}space") == "preserve"
    assert_word_text_integrity(raw, anonymous)


def test_alias_shorter_than_fragmented_word_runs_exports_and_restores():
    value = "Очень длинное чувствительное значение"
    raw = make_docx(["before ", *value, " after"])
    parsed = parse_docx(raw)
    block = parsed.blocks[0]
    start = block.text.index(value)
    alias = "[[PII-A7K3-001]]"
    assert len(alias) < len(value)
    selected = Finding(
        "f1", block.id, start, start + len(value), value, "PII",
        ["manual"], "accepted", 1.0, alias=alias,
    )

    anonymous, _ = patch_docx(raw, parsed.blocks, [selected])

    assert text(anonymous) == f"before {alias} after"
    assert value not in text(anonymous)
    with zipfile.ZipFile(io.BytesIO(anonymous)) as zf:
        root = etree.fromstring(zf.read("word/document.xml"))
    text_nodes = [node for node in root.iter() if node.tag == f"{{{W}}}t"]
    assert all(node.text for node in text_nodes)
    assert_word_text_integrity(raw, anonymous)

    restored, counts, unknown = replace_aliases(anonymous, {alias: value})
    assert text(restored) == f"before {value} after"
    assert counts == {alias: 1}
    assert unknown == []
    assert_word_text_integrity(anonymous, restored)


def test_word_integrity_rejects_empty_run_text():
    original = make_docx(["Alpha", " Beta"])
    parsed = parse_docx(original)
    root = etree.fromstring(parsed.entries["word/document.xml"])
    nodes = [node for node in root.iter() if node.tag == f"{{{W}}}t"]
    nodes[1].text = ""
    parts = dict(parsed.entries)
    parts["word/document.xml"] = etree.tostring(root, encoding="UTF-8")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, value in parts.items():
            zf.writestr(name, value)
    with pytest.raises(UnsafeDocument, match="пустой текстовый узел"):
        assert_word_text_integrity(original, out.getvalue())


def test_format_findings_auto_accept_and_qwen_only_pending():
    block = Block(
        "word/document.xml::p::0",
        "word/document.xml",
        "paragraph",
        "mail a@example.org and AcmeWorks",
    )
    rules = RulesDetector().detect([block])
    start = block.text.index("AcmeWorks")
    merged = merge_detections(
        [block],
        rules
        + [Detection(block.id, start, start + 9, "AcmeWorks", "ORG", "qwen", 0.7)],
    )
    assert next(f for f in merged if f.entity_type == "EMAIL").status == "accepted"
    assert next(f for f in merged if f.entity_type == "ORG").status == "pending"


def test_qwen_chunks_by_payload_size_instead_of_tiny_fixed_batches():
    blocks = [
        Block(f"p{i}", "word/document.xml", "paragraph", "короткий абзац")
        for i in range(250)
    ]
    chunks = qwen_chunks(blocks, max_payload_bytes=16_000, max_blocks=128)
    assert 1 < len(chunks) < 10
    assert sum(len(chunk) for chunk, _ in chunks) == len(blocks)
    assert all(len(chunk) <= 128 for chunk, _ in chunks)


@pytest.mark.parametrize("model", ["qwen/qwen3-14b", "qwen/qwen3.5-9b"])
def test_qwen_splits_timed_out_chunk_and_resumes_completed_blocks(monkeypatch, model):
    import asyncio
    import json
    from types import SimpleNamespace

    import httpx
    from wordshield import detectors

    blocks = [
        Block(f"p{i}", "word/document.xml", "paragraph", f"Компания Тест {i}")
        for i in range(4)
    ]
    requests = []

    def handler(request):
        payload = json.loads(request.content)
        if model == "qwen/qwen3.5-9b":
            assert payload["reasoning_effort"] == "none"
            assert not payload["messages"][0]["content"].startswith("/no_think")
        else:
            assert "reasoning_effort" not in payload
        items = json.loads(payload["messages"][1]["content"])
        requests.append(len(items))
        if len(items) > 1:
            raise httpx.ReadTimeout("synthetic timeout")
        finding = {
            "block_id": items[0]["block_id"],
            "exact_text": "Компания Тест",
            "entity_type": "ORG",
        }
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "stop", "message": {
                "content": json.dumps({"findings": [finding]})
            }}]
        })

    original_client = httpx.AsyncClient

    def mock_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(detectors.httpx, "AsyncClient", mock_client)
    detector = detectors.QwenDetector(SimpleNamespace(
        lm_token="", lm_base_url="http://127.0.0.1:1234/v1",
        lm_model=model
    ))
    completed = set()
    cached = []

    def checkpoint(chunk, found):
        completed.update(b.id for b in chunk)
        cached.extend(found)

    result = asyncio.run(detector.detect(blocks, completed, checkpoint))
    assert len(result) == len(cached) == 4
    assert completed == {b.id for b in blocks}
    assert requests[0] == 4 and requests[-1] == 1
    calls = len(requests)
    assert asyncio.run(detector.detect(blocks, completed, checkpoint)) == []
    assert len(requests) == calls


def test_analysis_uses_encrypted_qwen_checkpoint_after_failure(tmp_path, monkeypatch):
    import asyncio
    from wordshield.detectors import DetectorUnavailable

    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = Settings(**{**settings(tmp_path).__dict__, "qwen_required": True})
    svc = WordShieldService(cfg)
    sid = svc.begin_session(make_docx(["Компания Тест подписала договор"]))
    block = parse_docx(svc.store.raw(sid)).blocks[0]
    calls = 0

    async def fake_detect(blocks, completed, on_chunk):
        nonlocal calls
        calls += 1
        if calls == 1:
            on_chunk([block], [Detection(
                block.id, 0, len("Компания Тест"), "Компания Тест",
                "ORG", "qwen", 0.72
            )])
            raise DetectorUnavailable("synthetic timeout")
        assert block.id in completed
        return []

    monkeypatch.setattr(svc.qwen, "detect", fake_detect)
    with pytest.raises(DetectorUnavailable):
        asyncio.run(svc.analyze_session(sid))
    assert svc.status(sid)["state"] == "failed"
    assert svc.status(sid)["completed_blocks"] == 1
    encrypted = (tmp_path / "data" / "blobs" / f"{sid}.qwen_blob.enc").read_bytes()
    assert "Компания Тест".encode() not in encrypted

    svc.store.update_state(sid, "detecting")
    asyncio.run(svc.analyze_session(sid))
    assert calls == 2
    assert svc.status(sid)["state"] == "review"
    assert any(f["exact_text"] == "Компания Тест" for f in svc.findings(sid)["findings"])


def test_refine_keeps_decisions_but_removes_compound_overlap(tmp_path, monkeypatch):
    import asyncio

    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = Settings(**{**settings(tmp_path).__dict__, "qwen_required": True})
    svc = WordShieldService(cfg)
    line = "ФИО: Иван Петров; паспорт: 1234 567890; адрес: Москва, ул. Тверская, д. 1"
    sid = svc.begin_session(make_docx([line]))
    block = parse_docx(svc.store.raw(sid)).blocks[0]
    broad = Detection(block.id, 0, len(line), line, "PERSON", "qwen", 0.72)
    person_start = line.index("Иван Петров")
    person = Detection(block.id, person_start, person_start + 11,
                       "Иван Петров", "PERSON", "privacy-filter", 0.82)
    address = "Москва, ул. Тверская, д. 1"
    address_start = line.index(address)
    address_detection = Detection(block.id, address_start,
                                  address_start + len(address), address,
                                  "ADDRESS", "privacy-filter", 0.82)
    # Populate current-version checkpoints through the detector boundary.
    async def fake_qwen(blocks, completed, on_chunk):
        on_chunk([block], [broad])
        return [broad]
    async def fake_privacy(blocks, completed, on_chunk):
        on_chunk([block], [person, address_detection])
        return [person, address_detection]
    object.__setattr__(cfg, "privacy_required", True)
    monkeypatch.setattr(svc.qwen, "detect", fake_qwen)
    monkeypatch.setattr(svc.privacy, "detect", fake_privacy)
    svc.store.put_json(sid, "qwen_blob", {
        "completed": [block.id], "detections": [broad.__dict__]
    })
    svc.store.put_json(sid, "privacy_blob", [person.__dict__, address_detection.__dict__])
    svc.store.update_progress(sid, 1, 1)
    svc.store.put_json(sid, "findings_blob", {
        "prefix": svc.store._row(sid)["prefix"],
        "blocks": [block.__dict__],
        "findings": [
            Finding("old0", block.id, 0, len(line), line, "PERSON", ["qwen"],
                    "accepted", 0.72).json(),
            Finding("old1", block.id, person_start, person_start + 11,
                    "Иван Петров", "PERSON", ["privacy-filter"],
                    "accepted", 0.82).json(),
        ],
    })
    asyncio.run(svc.analyze_session(sid, preserve_decisions=True))
    findings = svc.findings(sid)["findings"]
    assert not any(f["exact_text"] == line for f in findings)
    assert next(f for f in findings if f["exact_text"] == "Иван Петров")["status"] == "accepted"
    selected = [f for f in findings if f["status"] == "accepted"]
    assert all(a["end"] <= b["start"] or b["end"] <= a["start"]
               for i, a in enumerate(selected) for b in selected[i + 1:])


def test_export_merges_overlapping_accepted_ranges(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    line = "Иван Петров и телефон +7 999 123-45-67"
    sid = svc.begin_session(make_docx([line]))
    block = parse_docx(svc.store.raw(sid)).blocks[0]
    svc.store.put_json(sid, "findings_blob", {
        "prefix": svc.store._row(sid)["prefix"],
        "blocks": [block.__dict__],
        "findings": [
            Finding("wide", block.id, 0, len(line), line, "PERSON", ["qwen"],
                    "accepted", 0.72).json(),
            Finding("narrow", block.id, 0, len("Иван Петров"), "Иван Петров", "PERSON",
                    ["privacy-filter"], "accepted", 0.82).json(),
        ],
    })
    svc.store.update_state(sid, "review")
    output=svc.export(sid)
    assert line not in text(output)
    assert len(svc.findings(sid)['findings'])==1
    assert text(svc.restore(output)[0])==line


def test_complete_document_number_wins_over_its_suffix(tmp_path, monkeypatch):
    line = "Номер: 4010 № 123456."
    block = Block("b", "word/document.xml", "paragraph", line)
    whole = "4010 № 123456"
    suffix = "123456"
    whole_start = line.index(whole)
    suffix_start = line.index(suffix)
    merged = merge_detections([block], [
        Detection(block.id, whole_start, whole_start + len(whole), whole,
                  "DOCUMENT_ID", "privacy-filter", 0.9),
        Detection(block.id, suffix_start, suffix_start + len(suffix), suffix,
                  "DOCUMENT_ID", "gliner-ru", 0.8),
    ])
    assert [(f.exact_text, f.status) for f in merged] == [
        (whole, "accepted"), (suffix, "rejected")]

    # Existing sessions with both choices accepted can also export safely.
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    sid = svc.begin_session(make_docx([line]))
    parsed = parse_docx(svc.store.raw(sid))
    real_block = parsed.blocks[0]
    for f in merged:
        f.block_id = real_block.id
        f.status = "accepted"
    svc.store.put_json(sid, "findings_blob", {
        "prefix": svc.store._row(sid)["prefix"],
        "blocks": [real_block.__dict__],
        "findings": [f.json() for f in merged],
    })
    svc.store.update_state(sid, "review")
    exported = svc.export(sid)
    assert whole not in text(exported)
    assert len(svc.findings(sid)["findings"]) == 1
    assert svc.findings(sid)["findings"][0]["exact_text"] == whole


def test_privacy_filter_chunks_whole_short_document():
    blocks = [
        Block(f"p{i}", "word/document.xml", "paragraph", "короткий абзац")
        for i in range(250)
    ]
    chunks = privacy_chunks(blocks, max_chars=80_000)
    assert len(chunks) == 1
    assert chunks[0] == blocks


def test_public_law_date_is_not_auto_selected():
    block = Block(
        "word/document.xml::p::0",
        "word/document.xml",
        "paragraph",
        "Федеральный закон от 27.07.2006 № 152-ФЗ",
    )
    assert not [d for d in RulesDetector().detect([block]) if d.entity_type == "DATE"]


def test_document_timestamp_is_split_into_date_and_time():
    block = Block("p0", "word/document.xml", "paragraph", "Договор подписан 2026-09-15T13:45:00Z")
    stamp = "2026-09-15T13:45:00Z"
    start = block.text.index(stamp)
    found = merge_detections([block], [Detection(
        block.id, start, start + len(stamp), stamp, "DATE", "rules", 0.88
    )])
    assert [(f.entity_type, f.exact_text, f.status) for f in found] == [
        ("DATE", "2026-09-15", "accepted"),
        ("TIME", "13:45:00", "accepted"),
    ]
    raw = make_docx([block.text])
    actual = parse_docx(raw).blocks[0]
    for finding, kind in zip(found, ("DATE", "TIME")):
        finding.block_id = actual.id
        finding.alias = f"[[{kind}-A7K3-001]]"
    anonymous, _ = patch_docx(raw, [actual], found)
    assert "2026-09-15T13:45:00Z" not in text(anonymous)
    restored, counts, unknown = replace_aliases(
        anonymous, {f.alias: f.exact_text for f in found}
    )
    assert text(restored) == block.text
    assert set(counts.values()) == {1} and not unknown


def test_russian_written_date_keeps_whole_span_over_short_privacy_spans():
    line = "Договор подписан 12: февраля 2026 года в 13:45"
    block = Block("p0", "word/document.xml", "paragraph", line)
    whole = "12: февраля 2026 года"
    fragment = "12"
    month = "февраля 2026"
    date = line.index(whole)
    detections = RulesDetector().detect([block]) + [
        Detection(block.id, date, date + len(fragment), fragment,
                  "DATE", "privacy-filter", 0.82),
        Detection(block.id, line.index(month), line.index(month) + len(month), month,
                  "DATE", "privacy-filter", 0.82),
    ]
    found = merge_detections([block], detections)
    dates = [f for f in found if f.entity_type == "DATE"]
    assert [(f.exact_text, f.status) for f in dates] == [(whole, "accepted")]


def test_written_public_law_date_is_not_auto_selected():
    block = Block("p0", "word/document.xml", "paragraph",
                  "Федеральный закон от 27 июля 2006 года")
    assert not [d for d in RulesDetector().detect([block]) if d.entity_type == "DATE"]


def test_quoted_written_date_includes_both_quotes_and_year_word():
    line = "Подписано «12» февраля 2026 года в 13:45"
    block = Block("p0", "word/document.xml", "paragraph", line)
    full = "«12» февраля 2026 года"
    year = "февраля 2026 года"
    detections = RulesDetector().detect([block]) + [
        Detection(block.id, line.index("12"), line.index("12") + 2, "12",
                  "DATE", "privacy-filter", 0.82),
        Detection(block.id, line.index(year), line.index(year) + len(year), year,
                  "DATE", "privacy-filter", 0.82),
    ]
    dates = [f for f in merge_detections([block], detections) if f.entity_type == "DATE"]
    assert [(f.exact_text, f.status) for f in dates] == [(full, "accepted")]


def test_quoted_written_date_includes_abbreviated_year_word():
    line = "Подписано «12» февраля 2026 г."
    block = Block("p0", "word/document.xml", "paragraph", line)
    full = "«12» февраля 2026 г."
    month = "февраля 2026 г."
    detections = RulesDetector().detect([block]) + [
        Detection(block.id, line.index(month), line.index(month) + len(month), month,
                  "DATE", "privacy-filter", 0.82),
    ]
    dates = [f for f in merge_detections([block], detections) if f.entity_type == "DATE"]
    assert [(f.exact_text, f.status) for f in dates] == [(full, "accepted")]


def test_compound_person_span_prefers_exact_nested_values():
    line = "ФИО: Иван Петров; паспорт: 1234 567890; адрес: Москва, ул. Тверская, д. 1"
    block = Block("p0", "word/document.xml", "paragraph", line)

    def detection(value, entity_type, source, format_confirmed=False):
        start = line.index(value)
        return Detection(block.id, start, start + len(value), value,
                         entity_type, source, 0.9, format_confirmed)

    found = merge_detections([block], [
        detection(line, "PERSON", "qwen"),
        detection("Иван Петров", "PERSON", "privacy-filter"),
        detection("1234 567890", "PASSPORT", "rules", True),
        detection("Москва, ул. Тверская, д. 1", "ADDRESS", "privacy-filter"),
    ])
    assert not any(f.exact_text == line for f in found)
    assert {f.entity_type for f in found} == {"PERSON", "PASSPORT", "ADDRESS"}
    assert all(f.status == "accepted" for f in found)


def test_compound_person_with_uncovered_name_becomes_short_review_gap():
    line = ("ФИО: Иван Петров; паспорт: 1234 567890; адрес: Москва, ул. Тверская, д. 1; "
            "представитель: Пётр Сидоров; дата: 12.02.2026; телефон: +7 900 000 00 00")
    block = Block("p0", "word/document.xml", "paragraph", line)
    def part(value, kind, source):
        start = line.index(value)
        return Detection(block.id, start, start + len(value), value, kind, source, 0.9)
    detections = [part(line, "PERSON", "qwen"),
                  part("Иван Петров", "PERSON", "privacy-filter"),
                  part("1234 567890", "PASSPORT", "privacy-filter"),
                  part("Москва, ул. Тверская, д. 1", "ADDRESS", "privacy-filter"),
                  part("12.02.2026", "DATE", "rules"),
                  part("+7 900 000 00 00", "PHONE", "rules")]
    found = merge_detections([block], detections)
    assert not any(f.exact_text == line for f in found)
    assert any(f.exact_text == "Пётр Сидоров" and f.status == "pending"
               and "compound-gap" in f.sources for f in found)
    assert not any(g.start < value.end and value.start < g.end
                   for g in found if "compound-gap" in g.sources
                   for value in found if "compound-gap" not in value.sources)


def test_compound_contact_block_does_not_alias_labels():
    line = ("Реквизиты организации: электронная почта test@example.org; "
            "расчётный счёт 12345678901234567890")
    block = Block("p0", "word/document.xml", "paragraph", line)
    email = "test@example.org"
    account = "12345678901234567890"
    detections = [Detection(block.id, 0, len(line), line, "EMAIL", "qwen", 0.8),
                  Detection(block.id, line.index(email), line.index(email) + len(email),
                            email, "EMAIL", "rules", 0.99, True),
                  Detection(block.id, line.index(account), line.index(account) + len(account),
                            account, "BANK", "rules", 0.99, True)]
    found = merge_detections([block], detections)
    assert not any(f.exact_text == line for f in found)
    assert {f.exact_text for f in found if f.status == "accepted"} == {email, account}


def test_surname_and_given_patronymic_join_into_one_alias():
    line = "Арендодатель: Иванов Иван Иванович, паспорт 1234 567890"
    block = Block("p0", "word/document.xml", "paragraph", line)
    surname = "Иванов"
    given = "Иван Иванович"
    detections = [
        Detection(block.id, line.index(surname), line.index(surname)+len(surname),
                  surname, "PERSON", "qwen", 0.8),
        Detection(block.id, line.index(given), line.index(given)+len(given),
                  given, "PERSON", "privacy-filter", 0.9),
    ]
    found = merge_detections([block], detections)
    person = [f for f in found if f.entity_type == "PERSON"]
    assert [(f.exact_text, f.status) for f in person] == [
        ("Иванов Иван Иванович", "accepted")
    ]


def test_passport_issuer_is_whole_but_series_number_and_city_are_separate():
    issuer = "ОП №12 отдела УМВД России по Санкт-Петербургу и Ленинградской обл."
    line = ("паспорт гражданина: серия 1234, номер 567890, выдан " + issuer
            + " с регистрацией в г. Санкт-Петербурга")
    block = Block("p0", "word/document.xml", "paragraph", line)
    broad1 = line[line.index("серия"):line.index("России")+len("России")]
    broad2 = line[line.index("отдела"):]
    detections = RulesDetector().detect([block]) + [
        Detection(block.id, line.index(broad1), line.index(broad1)+len(broad1),
                  broad1, "ACCOUNT", "privacy-filter", 0.82),
        Detection(block.id, line.index(broad2), line.index(broad2)+len(broad2),
                  broad2, "ADDRESS", "privacy-filter", 0.82),
    ]
    found = merge_detections([block], detections)
    accepted = [f for f in found if f.status == "accepted"]
    assert any(f.entity_type == "ORG" and f.exact_text == issuer for f in accepted)
    assert {f.exact_text for f in accepted if f.entity_type == "PASSPORT"} == {
        "1234", "567890"
    }
    assert any(f.entity_type == "ADDRESS" and f.exact_text == "Санкт-Петербурга"
               for f in accepted)
    assert not any(a.start < b.end and b.start < a.end for i,a in enumerate(accepted)
                   for b in accepted[i+1:])
    assert not any(f.exact_text in {broad1, broad2} for f in found)


def test_mixed_privacy_address_does_not_absorb_passport_series():
    address = "г. Москва, улица Тверская, дом 12, квартира 34"
    line = "Паспорт и адрес: " + address + ", паспорт: серия 1234"
    block = Block("p0", "word/document.xml", "paragraph", line)
    mixed = line[line.index(address):]
    found = merge_detections([block], RulesDetector().detect([block]) + [
        Detection(block.id, line.index(mixed), line.index(mixed)+len(mixed),
                  mixed, "ADDRESS", "privacy-filter", 0.8),
    ])
    assert any(f.entity_type == "ADDRESS" and f.exact_text == address
               and f.status == "accepted" for f in found)
    assert any(f.entity_type == "PASSPORT" and f.exact_text == "1234"
               and f.status == "accepted" for f in found)
    assert not any(f.exact_text == mixed for f in found)


def test_standalone_city_line_keeps_generic_city_label():
    for line in ("г. Санкт-Петербург", "г. Санкт-Петербурга "):
        block = Block("p0", "word/document.xml", "paragraph", line)
        found = merge_detections([block], RulesDetector().detect([block]))
        accepted = [f for f in found if f.status == "accepted"]
        assert len(accepted) == 1 and accepted[0].entity_type == "ADDRESS"
        assert accepted[0].exact_text.startswith("Санкт-")
        assert not accepted[0].exact_text.startswith("г.")


def test_cadastral_number_is_aliased_without_label_or_object_description():
    description = "1-комнатная квартира площадью 123,4 кв. м"
    tail = "кадастровый номер 12:34:1234567:8901"
    line = description + ", " + tail
    block = Block("p0", "word/document.xml", "paragraph", line)
    found = merge_detections([block], RulesDetector().detect([block]) + [
        Detection(block.id, 0, len(line), line, "ADDRESS", "privacy-filter", 0.8),
        Detection(block.id, line.index(tail), len(line), tail, "REG_ID", "qwen", 0.8),
    ])
    assert any(f.exact_text == description and f.status == "pending" for f in found)
    assert any(f.entity_type == "REG_ID" and f.exact_text == "12:34:1234567:8901"
               and f.status == "accepted" for f in found)
    assert not any(f.exact_text == line or f.exact_text == tail for f in found)


def test_full_name_issuer_and_cadastral_number_restore_exactly():
    issuer = "ОП №12 отдела УМВД России по Санкт-Петербургу и Ленинградской обл."
    line = ("Договор: Иванов Иван Иванович; паспорт: серия 1234, номер 567890, "
            "выдан " + issuer + "; кадастровый номер 12:34:1234567:8901")
    raw = make_docx([line])
    block = parse_docx(raw).blocks[0]
    given = "Иван Иванович"
    surname = "Иванов"
    found = merge_detections([block], RulesDetector().detect([block]) + [
        Detection(block.id, line.index(surname), line.index(surname)+len(surname),
                  surname, "PERSON", "qwen", 0.8),
        Detection(block.id, line.index(given), line.index(given)+len(given),
                  given, "PERSON", "privacy-filter", 0.9),
    ])
    selected = [f for f in found if f.status == "accepted"]
    assert any(f.exact_text == "Иванов Иван Иванович" for f in selected)
    assert any(f.exact_text == issuer for f in selected)
    for number, finding in enumerate(selected):
        finding.alias = f"[[{finding.entity_type}-A7K3-{number:03d}]]"
    anonymous, _ = patch_docx(raw, [block], selected)
    restored, counts, unknown = replace_aliases(
        anonymous, {f.alias: f.exact_text for f in selected}
    )
    assert text(restored) == line
    assert all(value == 1 for value in counts.values()) and not unknown


def test_approved_surname_repeats_and_case_form_restore_without_overlap():
    line = "Иванов Иван Иванович; подпись Иванов; от Иванова; второй Иванов"
    raw = make_docx([line])
    block = parse_docx(raw).blocks[0]
    full = "Иванов Иван Иванович"
    standalone = line.index("Иванов", len(full))
    found = [
        Finding("full", block.id, 0, len(full), full, "PERSON",
                ["fio-joined", "privacy-filter"], "accepted", 0.95),
        Finding("root", block.id, standalone, standalone+len("Иванов"),
                "Иванов", "PERSON", ["compound-gap"], "accepted", 0.8),
    ]
    expanded = expand_approved_repetitions([block], found)
    assert {(f.exact_text, f.sources[0]) for f in expanded if f.id.startswith("repeat-")} == {
        ("Иванова", "case-form-local"), ("Иванов", "repeat-local")
    }
    aliases = {}
    for finding in expanded:
        key = (finding.entity_type, finding.exact_text)
        finding.alias = aliases.setdefault(
            key, f"[[{finding.entity_type}-A7K3-{len(aliases)+1:03d}]]"
        )
    anonymous, _ = patch_docx(raw, [block], expanded)
    assert not raw_archive_contains(anonymous, [f.exact_text for f in expanded])
    restored, _, unknown = replace_aliases(
        anonymous, {alias: value for (_, value), alias in aliases.items()}
    )
    assert text(restored) == line and not unknown


def test_saving_name_decision_refreshes_repeats_and_respects_rejections(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    line = "Иванов Иван Иванович; подпись Иванов; от Иванова; снова Иванов"
    sid = svc.begin_session(make_docx([line]))
    block = parse_docx(svc.store.raw(sid)).blocks[0]
    root_start = line.index("Иванов", len("Иванов Иван Иванович"))
    payload = {
        "prefix": svc.store._row(sid)["prefix"],
        "blocks": [block.__dict__],
        "findings": [
            Finding("full", block.id, 0, 20, "Иванов Иван Иванович", "PERSON",
                    ["fio-joined", "privacy-filter"], "accepted", 0.95).json(),
            Finding("root", block.id, root_start, root_start+6, "Иванов", "PERSON",
                    ["compound-gap"], "pending", 0.8).json(),
        ],
    }
    svc.store.put_json(sid, "findings_blob", payload)
    svc.store.update_state(sid, "review")
    saved = svc.decide(sid, [{"id": "root", "status": "accepted"}])
    derived = [f for f in saved["findings"] if f["id"].startswith("repeat-")]
    assert {f["exact_text"] for f in derived} == {"Иванов", "Иванова"}
    case = next(f for f in derived if f["exact_text"] == "Иванова")
    saved = svc.decide(sid, [{"id": case["id"], "status": "rejected"}])
    assert next(f for f in saved["findings"] if f["id"] == case["id"])["status"] == "rejected"
    saved = svc.decide(sid, [{"id": "root", "status": "rejected"}])
    assert not any(f["id"].startswith("repeat-") for f in saved["findings"])


def test_privacy_person_accepts_full_name_but_not_single_word():
    block = Block("p0", "word/document.xml", "paragraph", "Иван Петров и Иван")
    first = Detection(block.id, 0, 11, "Иван Петров", "PERSON", "privacy-filter", 0.82)
    second = Detection(block.id, 14, 18, "Иван", "PERSON", "privacy-filter", 0.82)
    found = merge_detections([block], [first, second])
    assert next(f for f in found if f.exact_text == "Иван Петров").status == "accepted"
    assert next(f for f in found if f.exact_text == "Иван").status == "pending"


def test_long_address_requires_address_cue_and_no_contract_text():
    address = "г. Москва, улица Тверская, дом 1, квартира 12, почтовый индекс 123456"
    unrelated = "Договор между сторонами предусматривает оказание услуг и сохранение содержания документа"
    blocks = [Block("a", "word/document.xml", "paragraph", address),
              Block("b", "word/document.xml", "paragraph", unrelated)]
    found = merge_detections(blocks, [
        Detection("a", 0, len(address), address, "ADDRESS", "privacy-filter", 0.82),
        Detection("b", 0, len(unrelated), unrelated, "ADDRESS", "privacy-filter", 0.82),
    ])
    assert next(f for f in found if f.block_id == "a").status == "accepted"
    assert next(f for f in found if f.block_id == "b").status == "pending"


def test_unsupported_media_blocks_export():
    raw = make_docx(["safe"], {"word/media/image1.png": b"not really png"})
    with pytest.raises(UnsafeDocument, match="Неподдерживаемое"):
        parse_docx(raw)


def test_service_same_value_same_alias_and_encrypted_storage(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    raw = make_docx(["Иван Петров и Иван Петров"])
    svc = WordShieldService(settings(tmp_path))
    parsed = parse_docx(raw)
    sid, prefix = svc.store.create(raw, 90)
    block = parsed.blocks[0]
    starts = [0, block.text.rindex("Иван")]
    findings = [
        Finding(
            f"f{i}",
            block.id,
            s,
            s + 11,
            "Иван Петров",
            "PERSON",
            ["manual"],
            "accepted",
            1,
        ).json()
        for i, s in enumerate(starts)
    ]
    svc.store.put_json(
        sid,
        "findings_blob",
        {
            "prefix": prefix,
            "blocks": [b.__dict__ for b in parsed.blocks],
            "findings": findings,
        },
    )
    svc.store.update_state(sid, "review")
    output = svc.export(sid)
    aliases = re.findall(r"\[\[PERSON-[A-Z2-7]{4}-001\]\]", text(output))
    assert len(aliases) == 2 and aliases[0] == aliases[1]
    assert not raw_archive_contains(output, ["Иван Петров"])
    encrypted = b"".join(
        p.read_bytes() for p in (tmp_path / "data" / "blobs").iterdir()
    )
    assert "Иван Петров".encode() not in encrypted
    assert any(
        p.name.endswith("raw.enc") for p in (tmp_path / "data" / "blobs").iterdir()
    )
    with svc.store._conn() as conn:
        row = conn.execute(
            "SELECT wrapped_raw_key FROM sessions WHERE id=?", (sid,)
        ).fetchone()
    assert row["wrapped_raw_key"] is not None
    assert svc.store.original(sid) == raw


def test_restore_reports_missing_duplicate_unknown(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    raw = make_docx(["Анна и Борис"])
    sid, prefix = svc.store.create(raw, 90)
    mapping = {f"[[PERSON-{prefix}-001]]": "Анна", f"[[PERSON-{prefix}-002]]": "Борис"}
    svc.store.put_json(sid, "mapping_blob", {"prefix": prefix, "mapping": mapping})
    edited = make_docx(
        [
            f"[[PERSON-{prefix}-001]], снова [[PERSON-{prefix}-001]], неизвестный [[ORG-{prefix}-999]]"
        ]
    )
    restored, report = svc.restore(edited)
    assert text(restored).startswith("Анна, снова Анна")
    assert report["duplicates"][f"[[PERSON-{prefix}-001]]"] == 2
    assert report["missing"] == [f"[[PERSON-{prefix}-002]]"]
    assert report["unknown"] == [f"[[ORG-{prefix}-999]]"]


def test_header_and_hyperlink_are_patchable():
    header = b"""<?xml version="1.0" encoding="UTF-8"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>secret@example.org</w:t></w:r></w:p></w:hdr>"""
    rels = b"""<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="mailto:secret@example.org" TargetMode="External"/></Relationships>"""
    raw = make_docx(
        ["Обычный текст"],
        {"word/header1.xml": header, "word/_rels/document.xml.rels": rels},
    )
    parsed = parse_docx(raw)
    selected = []
    for i, block in enumerate(parsed.blocks):
        if block.kind == "hyperlink":
            selected.append(Finding(
                f"x{i}", block.id, 0, len(block.text), block.text,
                "URL", ["rules"], "accepted", 1,
                alias="[[URL-A7K3-002]]",
            ))
        elif "secret@example.org" in block.text:
            start = block.text.index("secret@example.org")
            selected.append(
                Finding(
                    f"x{i}",
                    block.id,
                    start,
                    start + 18,
                    "secret@example.org",
                    "EMAIL",
                    ["rules"],
                    "accepted",
                    1,
                    alias="[[EMAIL-A7K3-001]]",
                )
            )
    output, changed = patch_docx(raw, parsed.blocks, selected)
    assert changed == {"word/header1.xml", "word/_rels/document.xml.rels"}
    assert not raw_archive_contains(output, ["secret@example.org"])
    with zipfile.ZipFile(io.BytesIO(output)) as zf:
        rel_root = etree.fromstring(zf.read("word/_rels/document.xml.rels"))
    assert rel_root[0].get("Target") == "mailto:wordshield-URL-A7K3-002@wordshield.invalid"
    restored, counts, unknown = replace_aliases(output, {
        "[[EMAIL-A7K3-001]]": "secret@example.org",
        "[[URL-A7K3-002]]": "mailto:secret@example.org",
    })
    assert unknown == []
    assert counts == {"[[EMAIL-A7K3-001]]": 1, "[[URL-A7K3-002]]": 1}
    with zipfile.ZipFile(io.BytesIO(restored)) as zf:
        rel_root = etree.fromstring(zf.read("word/_rels/document.xml.rels"))
    assert rel_root[0].get("Target") == "mailto:secret@example.org"


def test_partial_external_hyperlink_replacement_is_rejected():
    rels = b"""<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="mailto:secret@example.org" TargetMode="External"/></Relationships>"""
    raw = make_docx(["text"], {"word/_rels/document.xml.rels": rels})
    parsed = parse_docx(raw)
    block = next(b for b in parsed.blocks if b.kind == "hyperlink")
    value = "secret@example.org"
    selected = Finding(
        "link", block.id, block.text.index(value), len(block.text), value,
        "EMAIL", ["manual"], "accepted", 1,
        alias="[[EMAIL-A7K3-001]]",
    )
    with pytest.raises(UnsafeDocument, match="только целиком"):
        patch_docx(raw, parsed.blocks, [selected])


def test_external_template_is_blocked():
    rels = b"""<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://example.org/template.dotx" TargetMode="External"/></Relationships>"""
    with pytest.raises(UnsafeDocument, match="внешняя связь"):
        parse_docx(make_docx(["text"], {"word/_rels/settings.xml.rels": rels}))


def test_manual_exact_fragment_adds_all_occurrences(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    raw = make_docx(["Северск и Северск"])
    parsed = parse_docx(raw)
    sid, prefix = svc.store.create(raw, 90)
    svc.store.put_json(
        sid,
        "findings_blob",
        {
            "prefix": prefix,
            "blocks": [b.__dict__ for b in parsed.blocks],
            "findings": [],
        },
    )
    svc.store.update_state(sid, "review")
    result = svc.decide(sid, [], [{"exact_text": "Северск", "entity_type": "CITY"}])
    assert len(result["findings"]) == 2
    assert all(f["status"] == "accepted" for f in result["findings"])


def test_revision_author_attribute_and_properties_are_detected_and_patchable():
    document = """<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:ins w:author="Иван Петров" w:date="2026-09-14T10:00:00Z"><w:r><w:t>Правка</w:t></w:r></w:ins></w:p></w:body></w:document>""".encode()
    core = """<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Анна Смирнова</dc:creator><dc:title>Договор Ромашки</dc:title></cp:coreProperties>""".encode()
    raw = make_docx(["placeholder"])
    entries = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        entries = {n: zf.read(n) for n in zf.namelist()}
    entries["word/document.xml"] = document
    entries["docProps/core.xml"] = core
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, value in entries.items():
            zf.writestr(name, value)
    parsed = parse_docx(out.getvalue())
    rules = RulesDetector().detect(parsed.blocks)
    assert any(
        d.exact_text == "Анна Смирнова" and d.entity_type == "PERSON" for d in rules
    )
    assert any(
        d.exact_text == "Договор Ромашки" and d.entity_type == "SECRET" for d in rules
    )
    author = next(
        b for b in parsed.blocks if b.kind == "attribute" and b.text == "Иван Петров"
    )
    finding = Finding(
        "author",
        author.id,
        0,
        len(author.text),
        author.text,
        "PERSON",
        ["manual"],
        "accepted",
        1,
        alias="[[PERSON-A7K3-001]]",
    )
    patched, _ = patch_docx(out.getvalue(), parsed.blocks, [finding])
    assert not raw_archive_contains(patched, ["Иван Петров"])


def test_custom_xml_is_reviewed_patchable_and_restorable():
    custom = """<?xml version="1.0" encoding="UTF-8"?><root customer="Acme Ltd"><person>Иван Петров</person><amount>500</amount></root>""".encode()
    props = """<?xml version="1.0" encoding="UTF-8"?><ds:dataStoreItem xmlns:ds="http://schemas.openxmlformats.org/officeDocument/2006/customXml" ds:itemID="{D5CB27EE-AE18-48C7-B53F-E921F4653E70}"><ds:schemaRefs><ds:schemaRef ds:uri="https://private.example/schema"/></ds:schemaRefs></ds:dataStoreItem>""".encode()
    raw = make_docx(
        ["visible"],
        {"customXml/item1.xml": custom, "customXml/itemProps1.xml": props},
    )
    parsed = parse_docx(raw)
    custom_blocks = [b for b in parsed.blocks if b.kind.startswith("custom-xml-")]
    assert {b.text for b in custom_blocks} == {
        "Acme Ltd",
        "Иван Петров",
        "500",
        "https://private.example/schema",
    }
    detections = RulesDetector().detect(custom_blocks)
    findings = merge_detections(custom_blocks, detections)
    assert findings
    assert any(f.exact_text == "Acme Ltd" and f.status == "accepted" for f in findings)
    assert any(f.exact_text == "https://private.example/schema" and f.status == "accepted"
               for f in findings)
    assert any(f.status == "pending" for f in findings if f.sources == ["custom-xml"])
    person = next(b for b in custom_blocks if b.text == "Иван Петров")
    selected = Finding(
        "custom-person",
        person.id,
        0,
        len(person.text),
        person.text,
        "PERSON",
        ["manual"],
        "accepted",
        1,
        alias="[[PERSON-A7K3-001]]",
    )
    patched, changed = patch_docx(raw, parsed.blocks, [selected])
    assert changed == {"customXml/item1.xml"}
    assert not raw_archive_contains(patched, ["Иван Петров"])
    restored, counts, unknown = replace_aliases(
        patched, {"[[PERSON-A7K3-001]]": "Иван Петров"}
    )
    assert raw_archive_contains(restored, ["Иван Петров"])
    assert counts["[[PERSON-A7K3-001]]"] == 1
    assert unknown == []
