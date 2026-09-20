from pathlib import Path

from fastapi.testclient import TestClient

from wordshield.app import create_app
from wordshield.config import Settings
from wordshield.models import Finding


def test_health_does_not_require_identity(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WORDSHIELD_DEV_KEY_FILE", str(tmp_path / "key"))
    cfg = Settings(
        data_dir=tmp_path / "data",
        allowed_user="owner@example.com",
        trust_tailscale_headers=True,
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
        max_upload_bytes=1024,
    )
    with TestClient(create_app(cfg)) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/").status_code == 403
        headers = {"Tailscale-User-Login": "owner@example.com"}
        assert client.get("/help").status_code == 403
        help_response = client.get("/help", headers=headers)
        assert help_response.status_code == 200
        assert "no-store" in help_response.headers["cache-control"]
        assert help_response.headers['referrer-policy'] == 'same-origin'
        # Valid native forms pass the gate; foreign and opaque origins do not.
        path = '/sessions/nonexistent/retry'
        assert client.post(path, headers={**headers, 'Origin': 'http://testserver'}).status_code == 404
        for origin in ('https://other.example', 'null'):
            assert client.post(path, headers={**headers, 'Origin': origin}).status_code == 403
        for text in ("Как пользоваться", "Выбор сохраняется автоматически", "оставить значение", "90 дней с даты первоначальной загрузки", "restored.docx", "новых загрузках", "Отменить удаление нельзя"):
            assert text in help_response.text
        assert "href='/help'" in help_response.text
        assert "{{CONTENT}}" not in help_response.text
        assert '<script src=' not in help_response.text
        assert 'fonts.googleapis' not in help_response.text
        for endpoint in ("/api/sessions", "/upload"):
            for extension in ("doc", "docx"):
                empty = client.post(endpoint, headers=headers,
                                    files={"file": (f"empty.{extension}", b"", "application/octet-stream")})
                assert empty.status_code == 422
                assert "0 байт" in empty.text
        home = client.get("/", headers=headers)
        assert home.status_code == 200
        assert "href='/favicon.svg?v=1'" in home.text
        favicon = client.get('/favicon.svg', headers=headers)
        assert favicon.status_code == 200
        assert favicon.headers['content-type'].startswith('image/svg+xml')
        from lxml import etree
        assert etree.fromstring(favicon.content).tag == '{http://www.w3.org/2000/svg}svg'
        assert "class='sidebar'" in home.text
        assert "Последние сессии" in home.text
        assert "class='file-picker'" in home.text
        assert "aria-label='Выбрать файл'" in home.text
        assert 'aria-current' in home.text
        assert '<script src=' not in home.text
        assert 'fonts.googleapis' not in home.text
        assert "id='dropzone'" in home.text
        assert "Перетащите DOC или DOCX сюда" in home.text
        assert "const allowDoc = true" in home.text
        assert "action='/upload'" in home.text
        assert "const maxBytes = 1024;" in home.text
        assert "data.append('file', selectedFile, selectedFile.name)" in home.text
        restore = client.get("/restore", headers=headers)
        assert restore.status_code == 200
        assert "id='dropzone'" in restore.text
        assert "action='/api/restore'" in restore.text
        assert "const allowDoc = false" in restore.text
        store = client.app.state.service.store
        sid, prefix = store.create(b"synthetic", 90)
        store.put_json(sid, "findings_blob", {
            "prefix": prefix,
            "blocks": [{"id":"block","part":"word/document.xml","kind":"paragraph","text":"SYN-0000/26X"+" "*8+"TEST"+" "*6+"KEEP"}],
            "findings": [
                    Finding("whole", "block", 0, 12, "SYN-0000/26X", "DOCUMENT_ID",
                        ["privacy-filter"], "accepted", 0.8).json(),
                    Finding("part", "block", 6, 12, "00/26X", "DOCUMENT_ID",
                        ["gliner-ru"], "accepted", 0.8).json(),
                Finding("unsure", "block", 20, 24, "TEST", "PERSON",
                        ["gliner-ru"], "pending", 0.5).json(),
                Finding("skipped", "block", 30, 34, "KEEP", "PERSON",
                        ["gliner-ru"], "rejected", 0.5).json(),
            ],
        })
        review = client.get(f"/sessions/{sid}", headers=headers)
        assert review.status_code == 200
        import re
        for finding_id, checked in (("whole", True), ("unsure", False), ("skipped", False)):
            row = re.search(rf"<tr data-id='{finding_id}'>(.*?)</tr>", review.text).group(1)
            switch = re.search(r"<input[^>]+role='switch'[^>]*>", row).group(0)
            assert (" checked" in switch) == checked
        assert "checked?'accepted':'rejected'" in review.text
        assert "querySelector('.status').checked=true" in review.text
        assert "Серый — оставить данные в документе" in review.text
        assert "Конфликты перед экспортом" not in review.text
        assert "<tr data-id='part'>" not in review.text
        assert "id='export-form'" in review.text
        assert "<details class='manual-addition'><summary>Не всё найдено? Добавить вручную</summary>" in review.text
        assert '<h2>Добавить пропущенный фрагмент</h2>' not in review.text
        assert "Сохранить решения" not in review.text
        assert "Уточнить диапазоны" not in review.text
        assert "addEventListener('change'" in review.text
        blocked = client.post(
            "/api/restore",
            headers={
                "Tailscale-User-Login": "owner@example.com",
                "Origin": "https://evil.example",
            },
        )
        assert blocked.status_code == 403
