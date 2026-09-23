import io
import zipfile

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from test_core import make_docx
from wordshield.detectors import RulesDetector, merge_detections
from wordshield.export_checks import remaining_sensitive_fragments, remaining_values
from wordshield.image_removal import remove_images
from wordshield.models import Block, Detection, Finding, inference_view, map_detection
from wordshield.ooxml import UnsafeDocument, parse_docx, patch_docx, assert_expected_text
from wordshield.uploads import read_document_upload


def test_unknown_zip_part_cannot_escape_detection():
    raw = make_docx(['Neutral'], {'unreviewed/customer.txt': b'secret@example.test'})
    with pytest.raises(UnsafeDocument, match='часть DOCX'):
        parse_docx(raw)


def test_thumbnail_is_removed_before_analysis():
    raw = make_docx(['Neutral'], {'docProps/thumbnail.jpeg': b'private preview'})
    cleaned, count = remove_images(raw)
    assert count == 1
    assert 'docProps/thumbnail.jpeg' not in parse_docx(cleaned).entries


def test_model_sees_newline_and_crossing_person_is_not_lost():
    block = Block('b', 'word/document.xml', 'paragraph', 'Alice CarterBob Smith', ['hard-boundary:12'])
    view, _ = inference_view(block)
    assert view.text == 'Alice Carter\nBob Smith'
    found = Detection('b', 0, len(view.text), view.text, 'PERSON', 'privacy-filter', .9)
    assert [d.exact_text for d in map_detection(block, found)] == ['Alice Carter', 'Bob Smith']
    legacy = Detection('b', 0, len(block.text), block.text, 'PERSON', 'privacy-filter', .9)
    assert len(merge_detections([block], [legacy])) == 2


def test_neutral_contract_text_is_not_a_document_number():
    block = Block('b', 'word/document.xml', 'paragraph', 'contract terms; invoice details; order processing')
    assert not RulesDetector().detect([block])


def test_common_company_word_does_not_block_export():
    f = Finding('f', 'b', 0, 21, 'Example Analytics Ltd', 'ORG', ['rules'], 'accepted', 1)
    assert not remaining_sensitive_fragments(make_docx(['Analytics services']), [f], [])


def test_export_proof_detects_unrelated_text_change():
    raw = make_docx(['Alice; safe text'])
    block = parse_docx(raw).blocks[0]
    f = Finding('f', block.id, 0, 5, 'Alice', 'PERSON', ['manual'], 'accepted', 1, alias='[[PERSON-ABCD-001]]')
    output, _ = patch_docx(raw, [block], [f])
    assert_expected_text(raw, output, [f])
    altered = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(output)) as source, zipfile.ZipFile(altered, 'w') as target:
        for name in source.namelist():
            target.writestr(name, source.read(name).replace(b'safe text', b'changed text'))
    with pytest.raises(UnsafeDocument, match='вне выбранных'):
        assert_expected_text(raw, altered.getvalue(), [f])


def test_upload_remains_in_memory_and_rejects_multiple_files(monkeypatch):
    import starlette.formparsers as parser
    original = parser.SpooledTemporaryFile
    rollovers = []
    def tracked(*args, **kwargs):
        file = original(*args, **kwargs)
        rollover = file.rollover
        def track():
            rollovers.append(True)
            rollover()
        file.rollover = track
        return file
    monkeypatch.setattr(parser, 'SpooledTemporaryFile', tracked)
    app = FastAPI()
    @app.post('/')
    async def upload(request: Request):
        raw, _, _ = await read_document_upload(request, 2 * 1024 * 1024)
        return {'size': len(raw)}
    with TestClient(app) as client:
        data = b'x' * (1024 * 1024 + 100)
        assert client.post('/', files={'file': ('test.docx', data)}).json()['size'] == len(data)
        assert not rollovers
        assert client.post('/', files={'file': ('test.docx', b'x' * (3*1024*1024))}).status_code == 413
        assert client.post('/', files=[('file', ('one.docx', b'x')), ('file', ('two.docx', b'x'))]).status_code == 413


def test_identity_header_alone_does_not_grant_access(tmp_path, monkeypatch):
    from wordshield.auth import provision, COOKIE
    from wordshield.app import create_app
    from test_core import settings
    from dataclasses import replace
    auth_file = tmp_path / 'auth.json'
    password = provision(auth_file)
    monkeypatch.setenv('WORDSHIELD_AUTH_FILE', str(auth_file))
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE', str(tmp_path / 'key'))
    cfg = replace(settings(tmp_path), trust_tailscale_headers=True)
    headers = {'Tailscale-User-Login': cfg.allowed_user}
    with TestClient(create_app(cfg), base_url='https://testserver') as client:
        assert client.get('/api/sessions/nonexistent/findings', headers=headers).status_code == 401
        response = client.post('/login', data={'password': password}, headers=headers, follow_redirects=False)
        assert response.status_code == 303
        assert 'HttpOnly' in response.headers['set-cookie']
        assert 'Secure' in response.headers['set-cookie']
        assert client.get('/', headers=headers).status_code == 200
        assert client.get('/').status_code == 403
        client.cookies.set(COOKIE, 'invalid')
        assert client.get('/api/sessions/nonexistent/findings', headers=headers).status_code == 401


def test_cookie_expiry_and_tampering(tmp_path, monkeypatch):
    from wordshield.auth import provision, BrowserAuth, LIFETIME
    import wordshield.auth as auth
    path = tmp_path / 'auth.json'
    password = provision(path)
    browser = BrowserAuth(path)
    assert browser.verify_password(password)
    token = browser.issue()
    assert browser.valid(token)
    assert not browser.valid(token + 'x')
    now = auth.time.time()
    monkeypatch.setattr(auth.time, 'time', lambda: now + LIFETIME + 1)
    assert not browser.valid(token)


def test_offline_production_does_not_instantiate_qwen(tmp_path, monkeypatch):
    import wordshield.qwen_detector as qwen
    from wordshield.service import WordShieldService
    from test_core import settings
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE', str(tmp_path / 'key'))
    def forbidden(*args):
        raise AssertionError('Qwen must not be instantiated')
    monkeypatch.setattr(qwen, 'QwenDetector', forbidden)
    assert WordShieldService(settings(tmp_path)).qwen is None


def test_analysis_queue_has_one_active_and_four_admitted(tmp_path, monkeypatch):
    import asyncio
    from wordshield.app import create_app
    from wordshield.service import WordShieldService
    from test_core import settings
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE', str(tmp_path / 'key'))
    counters = {'active': 0, 'maximum': 0}
    async def slow(self, sid, **kwargs):
        counters['active'] += 1
        counters['maximum'] = max(counters['maximum'], counters['active'])
        try:
            await asyncio.sleep(3600)
        finally:
            counters['active'] -= 1
    monkeypatch.setattr(WordShieldService, 'analyze_session', slow)
    with TestClient(create_app(settings(tmp_path))) as client:
        for _ in range(4):
            response = client.post('/api/sessions', files={'file': ('sample.docx', make_docx(['safe']))})
            assert response.status_code == 202
        response = client.post('/api/sessions', files={'file': ('sample.docx', make_docx(['safe']))})
        assert response.status_code == 429
        assert counters['maximum'] == 1
        assert len(client.app.state.service.store.list()) == 4


def test_replacement_plan_is_stable_across_review_and_export():
    from wordshield.replacement_plan import compile_plan
    block = Block('b', 'word/document.xml', 'paragraph', 'Alpha Ltd; Alpha Ltd')
    f = Finding('f', 'b', 0, 9, 'Alpha Ltd', 'ORG', ['rules'], 'accepted', 1)
    once = compile_plan([block], [f])
    assert len(once) == 2
    assert compile_plan([block], once) == once


def test_changed_run_properties_fail_xml_proof():
    raw = make_docx(['Alice; safe'])
    blocks = parse_docx(raw).blocks
    f = Finding('f', blocks[0].id, 0, 5, 'Alice', 'PERSON', ['manual'], 'accepted', 1, alias='[[PERSON-ABCD-001]]')
    output, _ = patch_docx(raw, blocks, [f])
    altered = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(output)) as src, zipfile.ZipFile(altered, 'w') as target:
        for name in src.namelist():
            data = src.read(name)
            if name == 'word/document.xml':
                data = data.replace(b'<w:r>', b'<w:r><w:rPr><w:b/></w:rPr>', 1)
            target.writestr(name, data)
    with pytest.raises(UnsafeDocument, match='OOXML'):
        assert_expected_text(raw, altered.getvalue(), [f])


def test_stalled_upload_times_out_and_releases_parser(monkeypatch):
    import asyncio
    from starlette.requests import Request
    from fastapi import HTTPException
    import wordshield.uploads as uploads
    timeout = asyncio.timeout
    monkeypatch.setattr(uploads.asyncio, 'timeout', lambda seconds: timeout(.01))
    async def receive():
        await asyncio.sleep(60)
    async def run():
        request = Request({'type': 'http', 'headers': [(b'content-type', b'multipart/form-data; boundary=test')]}, receive)
        with pytest.raises(HTTPException) as error:
            await uploads.read_document_upload(request, 1024)
        assert error.value.status_code == 408
    asyncio.run(run())
