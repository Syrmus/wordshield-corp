"""Corporate OIDC code flow: server-side one-use state, PKCE and signed ID tokens."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import time
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import COOKIE

FLOW_COOKIE = 'wordshield_oidc_flow'


def https_origin(url):
    value = urlsplit(url)
    if value.scheme != 'https' or not value.hostname or value.username or value.password or value.fragment:
        raise ValueError('OIDC and public URLs must use HTTPS without credentials or fragments')
    return value.scheme, value.hostname, value.port or 443


class CorporateOIDC:
    def __init__(self, accounts):
        self.accounts = accounts
        self.issuer = os.environ['WORDSHIELD_OIDC_ISSUER'].rstrip('/')
        self.origin = https_origin(self.issuer)
        if urlsplit(self.issuer).query:
            raise ValueError('Invalid OIDC issuer')
        self.public_url = os.environ['WORDSHIELD_PUBLIC_URL'].rstrip('/')
        https_origin(self.public_url)
        self.callback = self.public_url + '/auth/callback'
        self.client_id = os.environ['WORDSHIELD_OIDC_CLIENT_ID']
        self.secret = Path(os.environ['WORDSHIELD_OIDC_CLIENT_SECRET_FILE']).read_text().strip()
        self.user_group = os.environ['WORDSHIELD_OIDC_USER_GROUP']
        self.admin_group = os.environ['WORDSHIELD_OIDC_ADMIN_GROUP']
        self.group_claim = os.getenv('WORDSHIELD_OIDC_GROUP_CLAIM', 'groups')
        if not all((self.client_id, self.secret, self.user_group, self.admin_group)) or self.user_group == self.admin_group:
            raise ValueError('OIDC requires distinct explicit access groups and a client secret')
        with accounts.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS oidc_flows (
                state TEXT PRIMARY KEY, binding TEXT NOT NULL, nonce TEXT NOT NULL,
                verifier TEXT NOT NULL, expires REAL NOT NULL)''')

    async def metadata(self):
        metadata = await self.request('GET', self.issuer + '/.well-known/openid-configuration')
        if metadata.get('issuer') != self.issuer:
            raise ValueError('OIDC issuer mismatch')
        for name in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
            if https_origin(metadata[name]) != self.origin:
                raise ValueError('OIDC endpoints must belong to the configured issuer origin')
        return metadata

    async def request(self, method, url, **kwargs):
        if https_origin(url) != self.origin:
            raise ValueError('Unapproved OIDC endpoint')
        context = ssl.create_default_context(cafile=os.getenv('WORDSHIELD_OIDC_CA_FILE'))
        async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False, verify=context) as client:
            async with client.stream(method, url, **kwargs) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 1024 * 1024:
                        raise ValueError('OIDC response too large')
        return json.loads(body)

    def begin(self):
        state, binding, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
        with self.accounts.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM oidc_flows WHERE expires<=?', (time.time(),))
            if db.execute('SELECT count(*) FROM oidc_flows').fetchone()[0] >= 200:
                raise ValueError('Too many pending logins')
            db.execute('INSERT INTO oidc_flows VALUES (?,?,?,?,?)',
                       (hashlib.sha256(state.encode()).hexdigest(), hashlib.sha256(binding.encode()).hexdigest(),
                        nonce, verifier, time.time() + 300))
        return state, binding, nonce, verifier

    def consume(self, state, binding):
        if not state or not binding or len(state) > 128 or len(binding) > 128:
            raise ValueError('Missing login state')
        with self.accounts.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            digest = hashlib.sha256(state.encode()).hexdigest()
            flow = db.execute('SELECT * FROM oidc_flows WHERE state=?', (digest,)).fetchone()
            db.execute('DELETE FROM oidc_flows WHERE state=?', (digest,))
        if not flow or flow['expires'] <= time.time() or not hmac.compare_digest(
                flow['binding'], hashlib.sha256(binding.encode()).hexdigest()):
            raise ValueError('Expired or mismatched login state')
        return dict(flow)

    def validate_token(self, encoded, keys, nonce):
        import jwt
        header = jwt.get_unverified_header(encoded)
        if header.get('alg') not in {'RS256', 'ES256'}:
            raise ValueError('Unsupported ID token algorithm')
        candidates = [key for key in keys['keys'] if key.get('kid') == header.get('kid')
                      and key.get('use', 'sig') == 'sig' and key.get('alg', header['alg']) == header['alg']]
        if len(candidates) != 1:
            raise ValueError('Ambiguous signing key')
        key = jwt.PyJWK.from_dict(candidates[0], algorithm=header['alg']).key
        claims = jwt.decode(encoded, key, algorithms=[header['alg']], issuer=self.issuer,
                            audience=self.client_id, leeway=30,
                            options={'require': ['iss', 'aud', 'exp', 'iat', 'sub', 'nonce']})
        if not isinstance(claims['nonce'], str) or not hmac.compare_digest(claims['nonce'], nonce):
            raise ValueError('Invalid OIDC nonce')
        if (isinstance(claims['aud'], list) and len(claims['aud']) > 1) or 'azp' in claims:
            if claims.get('azp') != self.client_id:
                raise ValueError('Invalid authorized party')
        return claims

    def install(self, app):
        @app.get('/auth/login')
        async def start(request: Request):
            try:
                if not self.accounts.allow('oidc-start', 60):
                    return HTMLResponse('Слишком много попыток входа', 429)
                metadata = await self.metadata()
                state, binding, nonce, verifier = self.begin()
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
                query = urlencode(dict(response_type='code', client_id=self.client_id,
                                       redirect_uri=self.callback, scope='openid profile', state=state,
                                       nonce=nonce, code_challenge=challenge, code_challenge_method='S256'))
                separator = '&' if '?' in metadata['authorization_endpoint'] else '?'
                response = RedirectResponse(metadata['authorization_endpoint'] + separator + query, 303)
                response.set_cookie(FLOW_COOKIE, binding, max_age=300, secure=True,
                                    httponly=True, samesite='lax', path='/auth')
                return response
            except Exception:
                return HTMLResponse('Корпоративный вход недоступен. Обратитесь к ИТ.', 503)

        @app.get('/auth/callback')
        async def callback(request: Request):
            try:
                if len(request.url.query) > 8192 or request.query_params.get('error'):
                    raise ValueError('OIDC callback rejected')
                flow = self.consume(request.query_params.get('state', ''), request.cookies.get(FLOW_COOKIE, ''))
                code = request.query_params.get('code', '')
                if not code:
                    raise ValueError('Missing authorization code')
                metadata = await self.metadata()
                token = await self.request('POST', metadata['token_endpoint'], data={
                    'grant_type': 'authorization_code', 'code': code, 'redirect_uri': self.callback,
                    'client_id': self.client_id, 'client_secret': self.secret, 'code_verifier': flow['verifier']})
                keys = await self.request('GET', metadata['jwks_uri'])
                claims = self.validate_token(token['id_token'], keys, flow['nonce'])
                groups = claims.get(self.group_claim, [])
                if not isinstance(groups, list) or any(not isinstance(group, str) for group in groups):
                    raise ValueError('OIDC groups must be an explicit list')
                role = ('admin' if self.admin_group in groups else
                        'user' if self.user_group in groups else None)
                session = self.accounts.external_login(self.issuer, claims['sub'],
                    str(claims.get('name') or claims.get('preferred_username') or 'Сотрудник')[:160], role,
                    expires=min(time.time() + 900, claims['exp']))
                response = RedirectResponse('/', 303)
                response.set_cookie(COOKIE, session, max_age=900, secure=True,
                                    httponly=True, samesite='lax', path='/')
            except Exception:
                # Never expose token response, claims, credentials or provider errors.
                response = HTMLResponse('Вход не выполнен. Проверьте доступ у ИТ и попробуйте снова.', 403)
            response.delete_cookie(FLOW_COOKIE, path='/auth', secure=True, httponly=True, samesite='lax')
            return response
