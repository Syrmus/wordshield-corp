import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from wordshield.accounts import Accounts
from wordshield.auth import provision, COOKIE
from wordshield.corp_init import initialize
from wordshield.crypto import KeyProvider
from wordshield.oidc import CorporateOIDC
from test_core import settings, make_docx


@pytest.fixture
def corporate(tmp_path, monkeypatch):
    initialize(tmp_path)
    accounts = Accounts(tmp_path/'data', json.loads((tmp_path/'secrets/bootstrap.json').read_text()))
    secret = tmp_path/'oidc-secret'
    secret.write_text('synthetic-client-secret')
    for key, value in {'WORDSHIELD_OIDC_ISSUER':'https://idp.example.invalid/realm',
        'WORDSHIELD_PUBLIC_URL':'https://wordshield.example.invalid',
        'WORDSHIELD_OIDC_CLIENT_ID':'wordshield', 'WORDSHIELD_OIDC_CLIENT_SECRET_FILE':str(secret),
        'WORDSHIELD_OIDC_USER_GROUP':'users', 'WORDSHIELD_OIDC_ADMIN_GROUP':'admins'}.items():
        monkeypatch.setenv(key, value)
    return accounts, CorporateOIDC(accounts)


def test_bootstrap_never_replaces_keys(tmp_path, monkeypatch):
    initialize(tmp_path)
    path = tmp_path/'secrets/master.key'
    before = path.read_bytes()
    initialize(tmp_path)
    assert path.read_bytes() == before
    monkeypatch.setenv('WORDSHIELD_MASTER_KEY_FILE', str(path))
    assert len(KeyProvider(tmp_path).master_key()) == 32
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match='mode'):
        KeyProvider(tmp_path).master_key()


def test_partial_bootstrap_fails_without_rekey(tmp_path):
    initialize(tmp_path)
    key = (tmp_path/'secrets/master.key').read_bytes()
    (tmp_path/'secrets/bootstrap.json').unlink()
    with pytest.raises(RuntimeError, match='Partial'):
        initialize(tmp_path)
    assert (tmp_path/'secrets/master.key').read_bytes() == key


def test_oidc_state_binding_single_use_and_expiry(corporate):
    accounts, oidc = corporate
    state, binding, nonce, verifier = oidc.begin()
    assert oidc.consume(state, binding)['verifier'] == verifier
    with pytest.raises(ValueError):
        oidc.consume(state, binding)
    state, binding, *_ = oidc.begin()
    with pytest.raises(ValueError):
        oidc.consume(state, 'different-browser')
    with pytest.raises(ValueError):
        oidc.consume(state, binding)
    state, binding, *_ = oidc.begin()
    with accounts.connect() as db:
        db.execute('UPDATE oidc_flows SET expires=0')
    with pytest.raises(ValueError):
        oidc.consume(state, binding)


def signed_token(oidc, expected_nonce, **changes):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'synthetic-key'
    claims = dict(iss=oidc.issuer, sub='stable-id', aud=oidc.client_id,
                  iat=int(time.time()), exp=int(time.time())+300, nonce=expected_nonce, groups=['users'])
    claims.update(changes)
    return jwt.encode(claims, key, algorithm='RS256', headers={'kid':'synthetic-key'}), {'keys':[jwk]}


@pytest.mark.parametrize('changes', [{'iss':'https://evil.invalid'}, {'aud':'other-app'},
                                    {'exp':1}, {'nonce':'wrong'}, {'azp':'other'},
                                    {'aud':['wordshield','other']}])
def test_invalid_id_tokens_rejected(corporate, changes):
    _, oidc = corporate
    token, keys = signed_token(oidc, 'nonce', **changes)
    with pytest.raises((ValueError, jwt.PyJWTError)):
        oidc.validate_token(token, keys, 'nonce')


def test_valid_token_and_unapproved_endpoints(corporate, monkeypatch):
    _, oidc = corporate
    token, keys = signed_token(oidc, 'nonce')
    assert oidc.validate_token(token, keys, 'nonce')['sub'] == 'stable-id'
    with pytest.raises(ValueError, match='Unapproved'):
        asyncio.run(oidc.request('GET', 'https://evil.invalid/keys'))
    async def fake(*args, **kwargs):
        return dict(issuer=oidc.issuer, authorization_endpoint='https://evil.invalid/login',
                    token_endpoint=oidc.issuer+'/token', jwks_uri=oidc.issuer+'/keys')
    monkeypatch.setattr(oidc, 'request', fake)
    with pytest.raises(ValueError):
        asyncio.run(oidc.metadata())


def test_external_identity_is_stable_scoped_and_not_password_resettable(corporate):
    accounts, _ = corporate
    token = accounts.external_login('issuer', 'subject', 'Synthetic name', 'user', time.time()+900)
    user = accounts.current(token)
    again = accounts.external_login('issuer', 'subject', 'Changed name', 'admin', time.time()+900)
    assert accounts.current(again)['id'] == user['id']
    assert accounts.current(again)['display_name'] == 'Changed name'
    assert accounts.current(token) is None
    with pytest.raises(ValueError, match='корпоративного'):
        accounts.update(user['id'], 'reset', 'admin', password='Synthetic-password-123')
    assert accounts.authenticate(user['username'], 'Synthetic-password-123', 'local') is None
    with pytest.raises(ValueError):
        accounts.external_login('issuer', 'subject', 'Changed name', None, time.time()+900)
    assert accounts.current(again) is None
    other = accounts.external_login('different-issuer', 'subject', 'Changed name', 'user', time.time()+900)
    assert accounts.current(other)['id'] != user['id']
    accounts.update(user['id'], 'block', 'other-admin')
    with pytest.raises(ValueError):
        accounts.external_login('issuer', 'subject', 'Name', 'admin', time.time()+900)


def test_oidc_browser_flow(corporate, tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    accounts, oidc = corporate
    app = FastAPI()
    oidc.install(app)
    async def metadata():
        return dict(authorization_endpoint=oidc.issuer+'/authorize', token_endpoint=oidc.issuer+'/token', jwks_uri=oidc.issuer+'/keys')
    monkeypatch.setattr(oidc, 'metadata', metadata)
    from urllib.parse import urlsplit, parse_qs
    with TestClient(app, base_url=oidc.public_url) as client:
        start = client.get('/auth/login', follow_redirects=False)
        query = parse_qs(urlsplit(start.headers['location']).query)
        assert query['code_challenge_method'] == ['S256']
        encoded, keys = signed_token(oidc, query['nonce'][0])
        async def request(method, url, **kwargs):
            if method == 'POST':
                assert kwargs['data']['redirect_uri'] == oidc.callback
                challenge = base64.urlsafe_b64encode(hashlib.sha256(kwargs['data']['code_verifier'].encode()).digest()).rstrip(b'=').decode()
                assert challenge == query['code_challenge'][0]
                return {'id_token':encoded}
            return keys
        monkeypatch.setattr(oidc, 'request', request)
        callback = '/auth/callback?code=synthetic&state='+query['state'][0]
        result = client.get(callback, follow_redirects=False)
        assert result.status_code == 303
        assert accounts.current(client.cookies[COOKIE])['role'] == 'user'
        assert client.get(callback, follow_redirects=False).status_code == 403


def test_corp_config_and_authenticated_admin_routes(corporate, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from wordshield.app import create_app
    from wordshield.corp_runtime import validate_corp
    accounts, oidc = corporate
    for key, value in {'WORDSHIELD_EDITION':'corp', 'WORDSHIELD_USERS_ENABLED':'1',
        'WORDSHIELD_REGISTRATION_ENABLED':'0', 'WORDSHIELD_AUTH_FILE':str(tmp_path/'secrets/bootstrap.json'),
        'WORDSHIELD_MASTER_KEY_FILE':str(tmp_path/'secrets/master.key')}.items():
        monkeypatch.setenv(key, value)
    cfg = replace(settings(tmp_path), gliner_required=True, gliner_checkpoint=str(tmp_path/'models/gliner'),
                  privacy_required=True, render_required=True)
    validate_corp(cfg)
    with pytest.raises(ValueError):
        validate_corp(replace(cfg, privacy_required=False))
    with pytest.raises(ValueError):
        validate_corp(replace(cfg, trust_tailscale_headers=True))
    app = create_app(cfg)
    # No lifespan/model bootstrap: route tests only. Real runtime has separate probes.
    client = TestClient(app, base_url=oidc.public_url)
    assert client.get('/login').status_code == 200
    assert 'Войти через компанию' in client.get('/login').text
    assert client.get('/register').status_code == 404
    assert client.post('/register', data={}).status_code == 404
    assert client.get('/login', headers={'Host':'evil.invalid'}).status_code == 400
    token = app.state.accounts.external_login(oidc.issuer, 'user', 'User', 'user', time.time()+900)
    client.cookies.set(COOKIE, token)
    assert client.get('/admin/system').status_code == 403
    assert client.get('/admin/users').status_code == 403
    assert client.post('/logout', headers={'Origin':'https://evil.invalid'}).status_code == 403
    admin_token = app.state.accounts.external_login(oidc.issuer, 'admin', 'Admin', 'admin', time.time()+900)
    client.cookies.set(COOKIE, admin_token)
    assert client.get('/admin/system').status_code == 200
    assert 'synthetic-client-secret' not in client.get('/admin/system').text
    assert client.post('/login', data={'username':'sso-user', 'password':'irrelevant'}).status_code == 403


@pytest.mark.skipif(sys.platform != 'linux', reason='Real kernel filter requires Linux')
def test_linux_network_denial_and_unix_ipc():
    from wordshield.linux_sandbox import sandbox_command
    code = """
import socket
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family)
    except PermissionError:
        continue
    raise AssertionError('network allowed')
with socket.socket(socket.AF_UNIX):
    pass
print('network-denied')
"""
    proc = subprocess.run(sandbox_command([sys.executable, '-c', code]), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == 'network-denied'


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux tmpfs verification')
def test_linux_temp_requires_tmpfs(monkeypatch, tmp_path):
    from wordshield.ram_workspace import linux_tmpfs_root
    from wordshield.ooxml import UnsafeDocument
    monkeypatch.setenv('WORDSHIELD_TMP_DIR', str(tmp_path))
    with pytest.raises(UnsafeDocument, match='tmpfs'):
        linux_tmpfs_root()


@pytest.mark.skipif(not Path('/run/wordshield-tmp').exists(), reason='Requires dedicated test tmpfs')
def test_real_linux_libreoffice_render(tmp_path, monkeypatch):
    from wordshield.service import WordShieldService
    # Only synthetic data: exercise real LO + seccomp on developer VMs with swap.
    # Production has no such override; swap refusal is tested separately below.
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda self, *a, **kw:
                        'Filename Type Size Used Priority\n' if str(self) == '/proc/swaps' else original(self, *a, **kw))
    cfg = replace(settings(tmp_path), render_required=True, libreoffice_path='/usr/bin/soffice')
    WordShieldService(cfg)._render(make_docx(['Synthetic contract. Тестовый документ.']))


@pytest.mark.skipif(not Path('/run/wordshield-tmp').exists(), reason='Requires dedicated test tmpfs')
def test_linux_refuses_swap(monkeypatch):
    from wordshield.ram_workspace import linux_tmpfs_root
    from wordshield.ooxml import UnsafeDocument
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda self, *a, **kw:
                        'Filename Type Size Used Priority\n/swap file 1 0 -1\n'
                        if str(self) == '/proc/swaps' else original(self, *a, **kw))
    with pytest.raises(UnsafeDocument, match='swap'):
        linux_tmpfs_root()
