import asyncio
import json
from dataclasses import replace
from pathlib import Path
import pytest
from wordshield.detectors import RulesDetector, merge_detections
from wordshield.local_worker import token_windows, verify_model
from wordshield.models import Block, Detection, Finding
from wordshield.service import WordShieldService
from test_core import settings, make_docx


def test_privacy_tokenizer_requires_persistent_verified_cache(tmp_path):
    import hashlib
    from wordshield.local_worker import verify_tokenizer_cache
    with pytest.raises(FileNotFoundError):
        verify_tokenizer_cache(tmp_path)
    asset = tmp_path / "synthetic-cache"
    asset.write_bytes(b"synthetic tokenizer")
    (tmp_path / "manifest.json").write_text(json.dumps({"encoding": "o200k_base",
        "files": {asset.name: hashlib.sha256(asset.read_bytes()).hexdigest()}}))
    assert verify_tokenizer_cache(tmp_path) == tmp_path.resolve()
    asset.write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="checksum"):
        verify_tokenizer_cache(tmp_path)


def test_no_qwen_status_and_refinement_do_not_require_qwen_progress(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from wordshield.app import create_app
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = replace(settings(tmp_path), trust_tailscale_headers=False)
    app = create_app(cfg)
    svc = app.state.service
    sid, _ = asyncio.run(svc.create_session(make_docx(["Нейтральный текст"])))
    with TestClient(app) as client:
        assert client.get("/healthz").json()["model"] is None
        assert client.post(f"/sessions/{sid}/refine", follow_redirects=False).status_code == 303


def test_generic_and_specific_are_one_detector_not_two_votes():
    b = Block("b", "x", "paragraph", "Иван Петров")
    found = merge_detections([b], [Detection("b", 0, len(b.text), b.text, k, "gliner-ru", .99)
                                    for k in ["PERSON", "PII"]])
    assert len(found) == 1 and found[0].entity_type == "PERSON"
    assert found[0].status == "pending"
    assert found[0].sources == ["gliner-ru"]


def test_privacy_revision_and_checksums_are_pinned(tmp_path):
    from wordshield.local_worker import verify_privacy_checkpoint
    manifest = {"repo":"apararti/privacy-filter-ru","revision":"unapproved",
                "files":{"config.json":"fake","model.safetensors":"fake"}}
    (tmp_path/"wordshield-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="unapproved privacy checkpoint"):
        verify_privacy_checkpoint(tmp_path)
    manifest["revision"] = "a1650a1927ed8aceb9e15fa8ed13ffdf60cbf107"
    (tmp_path/"wordshield-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="unapproved privacy checksums"):
        verify_privacy_checkpoint(tmp_path)
    manifest["files"] = {"config.json":"9c2f2baa96f6b49190a4bda30c8c32a0c2f03e36b65773d2ed8f99651295964a",
                         "model.safetensors":"dad75869b6130d1cefcaae0efc77eb1885524a7fc2aa47b5a96528d2c0a1904c"}
    (tmp_path/"wordshield-manifest.json").write_text(json.dumps(manifest))
    (tmp_path/"config.json").write_text("{}")
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_privacy_checkpoint(tmp_path)


def test_complete_fields_remain_separate_and_email_is_automatic():
    text = "ФИО: Образцов-Тестов Артём Павлович; паспорт 40 11 654321; выдан отделом УФМС России по Санкт-Петербургу; адрес: Санкт-Петербург, ул. Учебная, д. 9; email artem@example.invalid"
    b = Block("b", "x", "paragraph", text)
    found = RulesDetector().detect([b])
    for value, kind in [("Артём Павлович", "PERSON"), ("Санкт", "ADDRESS")]:
        a = text.index(value)
        found.append(Detection("b", a, a+len(value), value, kind, "gliner-ru", .9))
    merged = merge_detections([b], found)
    for value in ["Образцов-Тестов Артём Павлович", "40 11 654321", "отделом УФМС России по Санкт-Петербургу", "Санкт-Петербург, ул. Учебная, д. 9", "artem@example.invalid"]:
        assert any(f.exact_text == value and f.status == "accepted" for f in merged)
    assert not any(f.exact_text == "Санкт" for f in merged)


def test_token_windows_cover_every_character_with_overlap():
    class Tokenizer:
        def __call__(self, text, **kwargs):
            assert kwargs["truncation"] is False
            return {"offset_mapping": [(i, i+1) for i in range(len(text))]}
    text = "абвгдеёжз" * 50
    windows = list(token_windows(text, Tokenizer(), limit=50, overlap=10))
    assert all(len(value) <= 50 for _, value in windows)
    assert all(any(a <= i < a+len(value) for a, value in windows) for i in range(len(text)))
    assert windows[1][0] < windows[0][0]+len(windows[0][1])


def test_manifest_rejects_unapproved_revision(tmp_path):
    (tmp_path / "wordshield-manifest.json").write_text(json.dumps({"revision": "unknown", "files": {}}))
    with pytest.raises(ValueError, match="revision"):
        verify_model(tmp_path)


def test_pii_alias_restores_and_encrypted_cache_is_removed(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    sid = svc.begin_session(make_docx(["Секретный код: SYNTHETIC-44"]))
    from wordshield.ooxml import parse_docx
    block = parse_docx(svc.store.raw(sid)).blocks[0]
    value = "SYNTHETIC-44"
    start = block.text.index(value)
    svc.store.put_json(sid, "findings_blob", {"prefix": svc.store._row(sid)["prefix"],
        "blocks": [block.__dict__], "findings": [Finding("f0", block.id, start, start+len(value), value,
        "PII", ["gliner-ru"], "accepted", .99).json()]})
    svc.store.update_state(sid, "review", 1)
    svc.store.put_json(sid, "gliner_blob", {"value": value})
    assert value.encode() not in (svc.store.blobs / f"{sid}.gliner_blob.enc").read_bytes()
    exported = svc.export(sid)
    restored, _ = svc.restore(exported)
    assert value in " ".join(b.text for b in parse_docx(restored).blocks)
    svc.store.delete(sid)
    assert not (svc.store.blobs / f"{sid}.gliner_blob.enc").exists()


def test_cache_invalidates_after_model_change(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = replace(settings(tmp_path), qwen_required=True)
    svc = WordShieldService(cfg)
    sid = svc.begin_session(make_docx(["Нейтральный текст"]))
    observed = []
    async def fake(blocks, completed, on_chunk):
        observed.append(set(completed))
        for block in blocks:
            on_chunk([block], [])
        return []
    monkeypatch.setattr(svc.qwen, "detect", fake)
    asyncio.run(svc.analyze_session(sid))
    asyncio.run(svc.analyze_session(sid))
    assert observed[1]
    svc.settings = replace(cfg, lm_model="qwen/qwen3.5-9b")
    asyncio.run(svc.analyze_session(sid))
    assert observed[2] == set()


def test_privacy_checkpoint_resumes_after_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(replace(settings(tmp_path), privacy_required=True))
    sid = svc.begin_session(make_docx(["Нейтральный первый", "Нейтральный второй"]))
    observed = []
    async def fake(blocks, completed, on_chunk):
        observed.append(set(completed))
        for block in blocks:
            if block.id in completed:
                continue
            on_chunk([block], [])
            if len(observed) == 1:
                raise RuntimeError("synthetic interruption")
        return []
    monkeypatch.setattr(svc.privacy, "detect", fake)
    with pytest.raises(Exception):
        asyncio.run(svc.analyze_session(sid))
    assert svc.status(sid)["state"] == "failed"
    asyncio.run(svc.analyze_session(sid))
    assert len(observed[1]) == 1
    assert svc.status(sid)["state"] == "review"


def test_changed_name_boundaries_do_not_override_rejected_fragment():
    from wordshield.detectors import expand_approved_repetitions
    name = "Тестов Иван Иванович"
    blocks = [Block("a", "x", "paragraph", name), Block("b", "x", "paragraph", name)]
    findings = [Finding("f1", "a", 0, len(name), name, "PERSON", ["manual"], "accepted", 1),
                Finding("f2", "b", 0, 6, "Тестов", "PERSON", ["manual"], "rejected", 1)]
    result = expand_approved_repetitions(blocks, findings, [("b", 0, 6)])
    assert not any(f.block_id == "b" and f.status == "accepted" for f in result)
    assert any(f.id == "f2" and f.status == "rejected" for f in result)


def test_old_session_schema_is_migrated_without_losing_aliases(tmp_path, monkeypatch):
    import sqlite3
    from wordshield.storage import SessionStore
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    svc = WordShieldService(settings(tmp_path))
    sid = svc.begin_session(make_docx(["Синтетический документ"]))
    mapping = {"[[PERSON-ABCD-001]]": "Тестов Иван Иванович"}
    svc.store.put_json(sid, "mapping_blob", mapping)
    with sqlite3.connect(svc.store.db) as db:
        for column in ("gliner_blob", "detector_blob", "stage", "completed_chunks", "total_chunks"):
            db.execute("ALTER TABLE sessions DROP COLUMN " + column)
    reopened = SessionStore(settings(tmp_path).data_dir)
    assert reopened.get_json(sid, "mapping_blob") == mapping
    assert reopened._row(sid)["stage"] == "detecting"


def test_privacy_token_windows_overlap_and_never_truncate():
    from wordshield.detectors import privacy_token_windows
    class Encoding:
        def encode(self, text, **kwargs):
            return [ord(c) for c in text]
        def decode_with_offsets(self, tokens):
            return "".join(chr(c) for c in tokens), list(range(len(tokens)))
    text = "тест ёж " * 1000
    windows = list(privacy_token_windows(text, Encoding(), 1024))
    assert all(len(w) <= 1024 for _, w in windows)
    assert all(any(a <= i < a+len(w) for a, w in windows) for i in range(len(text)))
    assert windows[1][0] < len(windows[0][1])
