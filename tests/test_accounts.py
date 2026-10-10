import asyncio
from dataclasses import replace
import json
import time

import pytest
from fastapi.testclient import TestClient

from test_core import settings, make_docx, text
from wordshield.accounts import Accounts
from wordshield.app import create_app
from wordshield.auth import provision, COOKIE, BrowserAuth, LIFETIME
from wordshield.service import WordShieldService

PASSWORD = 'Synthetic-password-2026'


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    monkeypatch.setenv('WORDSHIELD_USERS_ENABLED','1')
    path = tmp_path/'auth.json'
    password = provision(path)
    monkeypatch.setenv('WORDSHIELD_AUTH_FILE',str(path))
    cfg = settings(tmp_path)
    # A pre-existing private session and dictionary must belong only to the owner.
    legacy = WordShieldService(cfg)
    legacy.dictionary.save('Synthetic Legacy Ltd','ORG')
    sid = legacy.begin_session(make_docx(['Synthetic Legacy Ltd']), 'owner-private.docx')
    asyncio.run(legacy.analyze_session(sid))
    return cfg, password, sid, path


def login(client, username, password=PASSWORD):
    client.cookies.clear()
    response = client.post('/login',data={'username':username,'password':password},follow_redirects=False)
    assert response.status_code == 303, response.text
    return client.cookies.get(COOKIE)


def test_migration_preserves_owner_and_separates_all_document_routes(setup):
    cfg, password, sid, _ = setup
    app = create_app(cfg)
    with TestClient(app,base_url='https://testserver') as client:
        login(client,'admin',password)
        assert 'owner-private.docx' in client.get('/sessions').text
        assert client.post('/admin/users',data={'username':'alice','password':PASSWORD}).status_code==200
        alice = next(u for u in app.state.accounts.list() if u['username']=='alice')
        alice_service = app.state.tenants.for_user(alice)
        assert alice_service.privacy is app.state.service.privacy
        assert alice_service.gliner is app.state.service.gliner
        login(client,'alice')
        assert 'owner-private.docx' not in client.get('/sessions').text
        assert 'Synthetic Legacy Ltd' not in client.get('/dictionary').text
        assert 'owner-private.docx' not in client.get('/restore').text
        for path in [f'/sessions/{sid}', f'/api/sessions/{sid}/findings',f'/api/sessions/{sid}/status',f'/api/sessions/{sid}/original',f'/api/sessions/{sid}/result']:
            assert client.get(path).status_code==404, path
        for path in [f'/api/sessions/{sid}/export',f'/sessions/{sid}/retry',f'/sessions/{sid}/refine']:
            assert client.post(path).status_code==404, path
        assert client.patch(f'/api/sessions/{sid}/decisions',json={'decisions':[]}).status_code==404
        client.delete(f'/api/sessions/{sid}')
        client.post(f'/sessions/{sid}/delete')
        assert app.state.service.store._row(sid)
        assert client.get('/admin/users').status_code==403
        assert client.post('/admin/users',data={'username':'bad','password':PASSWORD}).status_code==403
        assert client.post('/admin/users/missing/block').status_code==403
        assert client.post('/dictionary/save',data={'value':'Alice Company Ltd','entity_type':'ORG','enabled':'true'}).status_code==200
        assert not any(e['value']=='Alice Company Ltd' for e in app.state.service.dictionary.list())
        result = app.state.service.export(sid)
        # Global-only aliases need an explicit session; neither path reveals the owner's data.
        assert client.post('/api/restore',files={'file':('export.docx',result)}).status_code==422
        assert client.post('/api/restore',files={'file':('export.docx',result)},data={'session_id':sid}).status_code==404
        # Recreate the application: bootstrap neither overwrites passwords nor loses ownership.
        again = create_app(cfg)
        assert len(again.state.accounts.list())==2
        assert again.state.service.store.raw(sid)


def test_registration_approval_revocation_and_csrf(setup):
    cfg, password, _, path = setup
    app = create_app(cfg)
    with TestClient(app,base_url='https://testserver') as client:
        assert client.get('/api/sessions/any/status').status_code==401
        client.cookies.set(COOKIE,BrowserAuth(path).issue())
        assert client.get('/api/sessions/any/status').status_code==401
        client.cookies.clear()
        assert client.post('/register',data={'username':'newuser','password':PASSWORD,'role':'admin','status':'active'}).status_code==200
        user = next(u for u in app.state.accounts.list() if u['username']=='newuser')
        assert user['role']=='user' and user['status']=='pending'
        assert client.post('/login',data={'username':'newuser','password':PASSWORD}).status_code==403
        login(client,'admin',password)
        assert client.post(f"/admin/users/{user['id']}/approve",headers={'Origin':'https://evil.test'}).status_code==403
        assert client.post(f"/admin/users/{user['id']}/approve",headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
        assert client.post(f"/admin/users/{user['id']}/approve").status_code==200
        token = login(client,'newuser')
        assert client.get('/account').status_code==200
        login(client,'admin',password)
        assert client.post(f"/admin/users/{user['id']}/block").status_code==200
        assert not app.state.accounts.current(token)
        assert client.post(f"/admin/users/{user['id']}/unblock").status_code==200
        assert not app.state.accounts.current(token)
        token = login(client,'newuser')
        assert client.post('/logout').status_code==200
        assert not app.state.accounts.current(token)


def test_passwords_roles_and_persistent_sessions(setup):
    cfg, password, _, path = setup
    app = create_app(cfg)
    accounts = app.state.accounts
    owner = next(u for u in accounts.list() if u['legacy_owner'])
    with pytest.raises(ValueError):
        accounts.update(owner['id'],'block',owner['id'])
    with pytest.raises(ValueError):
        accounts.update(owner['id'],'block','different-admin')
    with pytest.raises(ValueError):
        accounts.create('../outside',PASSWORD)
    with pytest.raises(ValueError):
        accounts.create('validname','short')
    uid = accounts.create('someone',PASSWORD,approved=True)
    token = accounts.authenticate('someone',PASSWORD,'test')
    accounts2 = Accounts(cfg.data_dir,json.loads(path.read_text()))
    assert accounts2.current(token)['id']==uid
    accounts.update(uid,'reset',owner['id'],PASSWORD+'-new')
    assert not accounts.current(token)
    assert not accounts.authenticate('someone',PASSWORD,'test')
    token = accounts.authenticate('someone',PASSWORD+'-new','test')
    accounts.change_password(uid,PASSWORD+'-new',PASSWORD+'-newer')
    assert not accounts.current(token)
    token = accounts.authenticate('someone',PASSWORD+'-newer','test')
    with accounts.connect() as db:
        db.execute('UPDATE logins SET expires=?',(time.time()-1,))
    assert not accounts.current(token)
    # Neither password nor raw session token is persisted in SQLite.
    raw = accounts.path.read_bytes()
    assert PASSWORD.encode() not in raw
    assert token.encode() not in raw
    for _ in range(35):
        accounts.authenticate('nonexistent','wrong','attacker')
    assert not accounts.authenticate('admin',password,'attacker')


def test_real_upload_export_restore_and_background_owner(setup):
    cfg,password,_,_ = setup
    app=create_app(cfg)
    app.state.accounts.create('alice',PASSWORD,approved=True)
    app.state.accounts.create('bob',PASSWORD,approved=True,role='admin')
    with TestClient(app,base_url='https://testserver') as client:
        login(client,'alice')
        response=client.post('/api/sessions',files={'file':('alice-private.docx',make_docx(['alice@example.test']))})
        assert response.status_code==202
        sid=response.json()['id']
        for _ in range(100):
            if client.get(f'/api/sessions/{sid}/status').json()['state']=='review':
                break
            time.sleep(.01)
        else:
            pytest.fail('Analysis did not finish')
        result=client.post(f'/api/sessions/{sid}/export')
        assert result.status_code==200,result.text
        assert 'alice@example.test' not in text(result.content)
        assert client.post('/api/restore',files={'file':('alice-export.docx',result.content)}).status_code==422
        assert client.post('/api/restore',files={'file':('alice-export.docx',result.content)},data={'session_id':sid}).status_code==200
        assert client.get(f'/api/sessions/{sid}/original').status_code==200
        login(client,'bob')
        assert client.get('/admin/users').status_code==200
        assert 'alice-private.docx' not in client.get('/sessions').text
        assert client.get(f'/api/sessions/{sid}/original').status_code==404
        assert client.post('/api/restore',files={'file':('alice-export.docx',result.content)},data={'session_id':sid}).status_code==404
        login(client,'admin',password)
        assert 'alice-private.docx' not in client.get('/sessions').text


def test_tailscale_gate_remains_required(setup):
    cfg,password,_,_=setup
    app=create_app(replace(cfg,trust_tailscale_headers=True))
    with TestClient(app,base_url='https://testserver') as client:
        assert client.get('/register').status_code==403
        assert client.post('/login',data={'username':'admin','password':password}).status_code==403
        client.headers['Tailscale-User-Login']=cfg.allowed_user
        login(client,'admin',password)
        assert client.get('/account').status_code==200
        del client.headers['Tailscale-User-Login']
        assert client.get('/account').status_code==403


def test_password_reset_during_login_cannot_issue_stale_token(setup,monkeypatch):
    import wordshield.accounts as module
    accounts=create_app(setup[0]).state.accounts
    uid=accounts.create('racinguser',PASSWORD,approved=True)
    original=module.password_hash
    reset=[True]
    def racing_hash(password,salt):
        result=original(password,salt)
        if reset[0]:
            reset[0]=False
            accounts.update(uid,'reset','owner',PASSWORD+'-new')
        return result
    monkeypatch.setattr(module,'password_hash',racing_hash)
    assert accounts.authenticate('racinguser',PASSWORD,'test') is None
    assert accounts.authenticate('racinguser',PASSWORD+'-new','test')


def test_missing_context_never_falls_back_to_owner(setup):
    app=create_app(setup[0])
    with pytest.raises(LookupError):
        app.state.tenants.store.list()


def test_concurrent_requests_never_mix_tenant_context(setup):
    from concurrent.futures import ThreadPoolExecutor
    cfg,password,_,_=setup
    app=create_app(cfg)
    credentials=[]
    for name in ['alpha','bravo']:
        uid=app.state.accounts.create(name,PASSWORD,approved=True)
        user=next(u for u in app.state.accounts.list() if u['id']==uid)
        own=app.state.tenants.for_user(user)
        own.begin_session(make_docx([name]),name+'-private.docx')
        token=app.state.accounts.authenticate(name,PASSWORD,name)
        credentials.append((name,token))
    with TestClient(app,base_url='https://testserver') as client:
        def check(index):
            name,token=credentials[index%2]
            other=credentials[(index+1)%2][0]
            response=client.get('/sessions',headers={'Cookie':COOKIE+'='+token})
            assert response.status_code==200
            assert name+'-private.docx' in response.text
            assert other+'-private.docx' not in response.text
            assert 'owner-private.docx' not in response.text
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(check,range(30)))


def test_restart_resumes_other_owner_and_purges_blocked_owner(setup):
    from datetime import datetime, UTC, timedelta
    cfg,_,_,_=setup
    app=create_app(cfg)
    uid=app.state.accounts.create('resumeme',PASSWORD,approved=True)
    user=next(u for u in app.state.accounts.list() if u['id']==uid)
    service=app.state.tenants.for_user(user)
    sid=service.begin_session(make_docx(['resume@example.test']),'resumed.docx')
    service.store.update_state(sid,'detecting')
    app2=create_app(cfg)
    with TestClient(app2,base_url='https://testserver') as client:
        login(client,'resumeme')
        for _ in range(100):
            if client.get(f'/api/sessions/{sid}/status').json()['state']=='review':
                break
            time.sleep(.01)
        else:
            pytest.fail('Tenant analysis was not resumed')
    app2.state.accounts.update(uid,'block','owner')
    with service.store._conn() as db:
        db.execute('UPDATE sessions SET expires_at=? WHERE id=?',((datetime.now(UTC)-timedelta(days=1)).isoformat(),sid))
    app3=create_app(cfg)
    with TestClient(app3,base_url='https://testserver'):
        with pytest.raises(KeyError):
            app3.state.tenants.for_user(user).store._row(sid)
