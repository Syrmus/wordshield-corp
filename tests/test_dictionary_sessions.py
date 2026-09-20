import asyncio
import io
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from test_core import make_docx, settings, text
from wordshield.app import create_app
from wordshield.dictionary import apply_dictionary
from wordshield.models import Block, Finding
from wordshield.ooxml import UnsafeDocument
from wordshield.service import WordShieldService


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    return WordShieldService(settings(tmp_path))


def analyze(service, value="ООО Синтетика", filename="example.docx"):
    sid = service.begin_session(make_docx([value]), filename)
    asyncio.run(service.analyze_session(sid))
    findings = service.findings(sid)["findings"]
    service.decide(sid, [{"id": f["id"], "status": "rejected"} for f in findings if f["status"] == "pending"])
    return sid


def test_stable_alias_snapshots_and_result_encryption(service):
    entry = service.dictionary.save("ООО Синтетика", "ORG")
    first = analyze(service)
    second = analyze(service)
    one, two = service.export(first), service.export(second)
    assert text(one) == text(two) == entry["alias"]
    assert service.store.result(first) == one == service.export(first)
    assert text(service.store.raw(first)) == "ООО Синтетика"
    assert text(service.store.original(first)) == "ООО Синтетика"
    with pytest.raises(UnsafeDocument, match="Выберите исходную сессию"):
        service.restore(one)
    assert text(service.restore(one, first)[0]) == "ООО Синтетика"
    changed = service.dictionary.save("ООО Другая", "ORG", entry_id=entry["id"])
    assert changed["alias"] != entry["alias"]
    service.dictionary.delete(entry["id"])
    assert text(service.restore(one, first)[0]) == "ООО Синтетика"
    for path in service.store.root.rglob("*"):
        if path.is_file():
            assert "ООО Синтетика".encode() not in path.read_bytes()
            assert b"example.docx" not in path.read_bytes()
    with pytest.raises(ValueError):
        service.dictionary.save("ООО Третья", "ORG", alias=entry["alias"])


def test_plain_named_replacements_restore_and_keep_old_sessions(service):
    entry=service.dictionary.save('ООО Синтетика','ORG',alias='Компания 1')
    assert entry['label']=='Компания 1'
    assert entry['alias'].endswith(':Компания 1]]')
    sid=analyze(service)
    output=service.export(sid)
    assert text(output)==entry['alias']
    assert text(service.restore(output,sid)[0])=='ООО Синтетика'
    same=service.dictionary.save('ООО Синтетика','ORG',entry_id=entry['id'],alias='Компания 1')
    assert same['alias']==entry['alias']
    changed=service.dictionary.save('ООО Синтетика','ORG',entry_id=entry['id'],alias='Заказчик')
    assert changed['alias']!=entry['alias']
    assert text(service.restore(output,sid)[0])=='ООО Синтетика'


def test_named_alias_hyperlinks():
    from wordshield.ooxml import _safe_hyperlink_target, hyperlink_alias
    token='[[EMAIL-GLOB-001:Почта Заказчика]]'
    for url in ('mailto:synthetic@example.org','https://example.org'):
        target=_safe_hyperlink_target(url,token)
        assert 'Заказчика' not in target
        assert hyperlink_alias(target)==token


def test_both_export_formats_use_same_anonymized_result(tmp_path, monkeypatch):
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    with TestClient(create_app(settings(tmp_path))) as client:
        svc=client.app.state.service
        svc.dictionary.save('ООО Синтетика','ORG')
        sid=analyze(svc)
        md=client.post(f'/api/sessions/{sid}/export?format=md')
        assert md.status_code==200 and md.headers['content-type'].startswith('text/markdown')
        assert 'ООО Синтетика' not in md.text and '[[ORG-GLOB-' in md.text
        docx=client.post(f'/api/sessions/{sid}/export')
        assert docx.status_code==200
        assert text(docx.content).strip()==md.text.strip()
        assert client.get(f'/api/sessions/{sid}/result?format=md').text==md.text
        assert client.get(f'/api/sessions/{sid}/result?format=invalid').status_code==422


def test_snapshot_fixed_at_upload_and_disabled_entries(service):
    entry = service.dictionary.save("ООО Синтетика", "ORG")
    sid = service.begin_session(make_docx(["ООО Синтетика"]))
    service.dictionary.delete(entry["id"])
    asyncio.run(service.analyze_session(sid))
    assert any(f["alias"] == entry["alias"] and f["status"] == "accepted" for f in service.findings(sid)["findings"])
    disabled = service.dictionary.save("ООО Синтетика", "ORG", enabled=False)
    sid2 = analyze(service)
    assert not any(f["alias"] == disabled["alias"] for f in service.findings(sid2)["findings"])


def test_dictionary_whole_words_longest_and_partial_conflicts():
    b = Block("b", "p", "text", "Анна Аннабель Анна Иванова")
    entries = [{"id":"a", "value":"Анна", "entity_type":"PERSON", "alias":"[[PERSON-GLOB-001]]", "enabled":True},
               {"id":"b", "value":"Анна Иванова", "entity_type":"PERSON", "alias":"[[PERSON-GLOB-002]]", "enabled":True}]
    model = Finding("model", "b", 0, len(b.text), b.text, "PERSON", ["model"], "accepted", .9)
    result = apply_dictionary([b], [model], entries)
    assert model.status == "pending"
    assert [f.exact_text for f in result if f.sources == ["global-dictionary"]] == ["Анна Иванова", "Анна"]


def test_expiry_removes_saved_result_and_dictionary_survives(service):
    entry = service.dictionary.save("ООО Синтетика", "ORG")
    sid = analyze(service)
    service.export(sid)
    with service.store._conn() as c:
        c.execute("UPDATE sessions SET expires_at=? WHERE id=?", ((datetime.now(UTC)-timedelta(days=1)).isoformat(), sid))
    with pytest.raises(KeyError):
        service.store.result(sid)
    assert not list(service.store.blobs.glob(sid + "*"))
    assert service.dictionary.list()[0]["alias"] == entry["alias"]


def test_forms_history_download_and_global_only_restore(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = settings(tmp_path)
    with TestClient(create_app(cfg)) as client:
        assert client.get("/dictionary").status_code == 200
        assert client.post("/dictionary/save", data={"value":"ООО Синтетика", "entity_type":"ORG", "enabled":"true"}).status_code == 200
        s = client.app.state.service
        sid = analyze(s, filename="Договор <script>.docx")
        first = client.post(f"/api/sessions/{sid}/export")
        assert first.status_code == 200
        history = client.get("/sessions")
        assert "Исходный файл" in history.text and "✅ Экспортирован" in history.text
        assert "&lt;script&gt;" in history.text and "<th>Код</th>" not in history.text
        assert history.headers["cache-control"] == "no-store"
        download = client.get(f"/api/sessions/{sid}/result")
        assert download.content == first.content
        assert text(client.get(f"/api/sessions/{sid}/original").content) == "ООО Синтетика"
        assert "filename*=UTF-8''" in download.headers["content-disposition"]
        restored = client.post("/api/restore", files={"file":("fixed.docx", first.content)}, data={"session_id":sid})
        assert restored.status_code == 200
        with zipfile.ZipFile(io.BytesIO(restored.content)) as z:
            assert text(z.read("restored.docx")) == "ООО Синтетика"
        assert client.delete(f"/api/sessions/{sid}").status_code == 204
        assert client.get(f"/api/sessions/{sid}/result").status_code == 404


def test_validation_and_reserved_input(service):
    for value, kind in [("", "ORG"), ("[[ORG-GLOB-001]]", "ORG"), ("Example", "BAD")]:
        with pytest.raises(ValueError):
            service.dictionary.save(value, kind)
    entry = service.dictionary.save("Example", "ORG", alias="[[ORG-GLOB-1000]]")
    with pytest.raises(ValueError):
        service.dictionary.save("Example", "PERSON")
    sid = analyze(service, "Example")
    anon = service.export(sid)
    assert text(anon) == entry["alias"]
    assert text(service.restore(anon, sid)[0]) == "Example"
    with pytest.raises(UnsafeDocument, match="уже есть алиасы"):
        service.begin_session(anon)


def test_common_deadline_not_extended_by_late_export(service):
    service.dictionary.save("ООО Синтетика", "ORG")
    sid = analyze(service)
    original = service.store.original(sid)
    created = datetime.now(UTC) - timedelta(days=30)
    expiry = created + timedelta(days=90)
    with service.store._conn() as c:
        c.execute("UPDATE sessions SET created_at=?,expires_at=? WHERE id=?", (created.isoformat(), expiry.isoformat(), sid))
    service.export(sid)
    assert service.store.original(sid) == original
    assert service.store.result(sid)
    assert service.store._row(sid)["expires_at"] == expiry.isoformat()
    service.export(sid)
    assert service.store._row(sid)["expires_at"] == expiry.isoformat()
    with service.store._conn() as c:
        c.execute("UPDATE sessions SET expires_at=? WHERE id=?", ((datetime.now(UTC)-timedelta(seconds=1)).isoformat(), sid))
    for getter in (service.store.original, service.store.result):
        with pytest.raises(KeyError):
            getter(sid)
    assert not list(service.store.blobs.glob(sid + "*"))


@pytest.mark.parametrize("state", ["created", "detecting", "failed", "review"])
def test_completed_upload_survives_24_hours_even_after_analysis_failure(service, state):
    sid = service.begin_session(make_docx(["Synthetic original"]))
    service.store.update_state(sid, state)
    with service.store._conn() as c:
        c.execute("UPDATE sessions SET created_at=? WHERE id=?", ((datetime.now(UTC)-timedelta(days=2)).isoformat(), sid))
    service.store.purge(24)
    assert text(service.store.original(sid)) == "Synthetic original"


def test_doc_upload_retains_exact_original_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    source = b"synthetic-legacy-doc-bytes"
    converted = make_docx(["Synthetic converted DOCX"])
    monkeypatch.setattr("wordshield.app.convert_doc", lambda raw, cfg: converted)
    with TestClient(create_app(settings(tmp_path))) as client:
        response = client.post("/api/sessions", files={"file":("legacy.doc", source)})
        assert response.status_code == 202
        sid = response.json()["id"]
        downloaded = client.get(f"/api/sessions/{sid}/original")
        assert downloaded.content == source
        assert downloaded.headers["content-type"] == "application/msword"
        s = client.app.state.service
        assert s.store.raw(sid) == converted
        assert source not in (s.store.blobs / s.store._row(sid)["original_blob"]).read_bytes()
        client.delete(f"/api/sessions/{sid}")
        assert not list(s.store.blobs.glob(sid + "*"))


@pytest.mark.parametrize("state,statuses,expected", [
    ("created", [], "Ожидает анализа"),
    ("detecting", [], "Идёт анализ документа"),
    ("failed", [], "Анализ не завершён — требуется повтор"),
    ("review", ["pending"], "Требуется проверка данных"),
    ("review", ["accepted"], "Готов к экспорту"),
    ("review", ["accepted", "accepted"], "Нужно уточнить пересекающиеся замены"),
    ("exported", [], "Копия ранее не сохранялась"),
])
def test_missing_result_reason(tmp_path, monkeypatch, state, statuses, expected):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    with TestClient(create_app(settings(tmp_path))) as client:
        s = client.app.state.service
        sid, prefix = s.store.create(make_docx(["Synthetic"]), 90)
        s.store.update_state(sid, state)
        s.store.put_json(sid, "findings_blob", {"findings":[
            Finding(str(i), "b", 0, 3, "Syn", "PERSON", [], status, 1).json()
            for i, status in enumerate(statuses)]})
        response = client.get("/sessions")
        assert expected in response.text
        assert "Ещё не создан" not in response.text


def test_legacy_doc_conversion_not_presented_as_original(service):
    sid = service.begin_session(make_docx(["Converted legacy"]), "old.doc")
    with pytest.raises(KeyError, match="legacy DOC"):
        service.store.original(sid)


def test_blocked_export_reason_and_original_retained(tmp_path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    with TestClient(create_app(settings(tmp_path))) as client:
        s = client.app.state.service
        s.dictionary.save("ООО Синтетика", "ORG")
        sid = analyze(s)
        def fail_render(raw):
            raise UnsafeDocument("Synthetic render failure")
        monkeypatch.setattr(s, "_render", fail_render)
        response = client.post(f"/api/sessions/{sid}/export")
        assert response.status_code == 422
        assert "Экспорт заблокирован — откройте сессию" in client.get("/sessions").text
        assert text(s.store.original(sid)) == "ООО Синтетика"
        with pytest.raises(KeyError):
            s.store.result(sid)
