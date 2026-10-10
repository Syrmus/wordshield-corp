"""Local accounts and revocable browser sessions. No email or external identity APIs."""
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .auth import LIFETIME


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def validate_password(password):
    if not 12 <= len(password) <= 256:
        raise ValueError('Пароль должен содержать от 12 до 256 символов')


class Accounts:
    def __init__(self, root: Path, legacy):
        self.path = root / 'accounts.sqlite3'
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','user')),
                    status TEXT NOT NULL CHECK(status IN ('pending','active','blocked')),
                    created REAL NOT NULL, legacy_owner INTEGER NOT NULL DEFAULT 0);
                CREATE UNIQUE INDEX IF NOT EXISTS one_legacy_owner ON users(legacy_owner) WHERE legacy_owner=1;
                CREATE TABLE IF NOT EXISTS logins (
                    digest TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (bucket TEXT NOT NULL, created REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS attempt_bucket ON attempts(bucket, created);
            ''')
            # Additive, transactional and idempotent. Existing document files never move.
            if not db.execute('SELECT 1 FROM users WHERE legacy_owner=1').fetchone():
                db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
                           (secrets.token_hex(16), 'admin', legacy['salt'], legacy['password_hash'],
                            'admin', 'active', time.time(), 1))
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA secure_delete=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def list(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT id,username,role,status,created,legacy_owner FROM users ORDER BY created')]

    def allow(self, bucket, limit, window=300):
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE created<?', (now-window,))
            if db.execute('SELECT count(*) FROM attempts WHERE bucket=?', (bucket,)).fetchone()[0] >= limit:
                return False
            db.execute('INSERT INTO attempts VALUES (?,?)', (bucket, now))
        return True

    def create(self, username, password, *, approved=False, role='user'):
        username = username.strip().casefold()
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.@-]{2,79}', username):
            raise ValueError('Логин: 3–80 символов, латинские буквы, цифры, точка, @, дефис или подчёркивание')
        validate_password(password)
        if role not in {'admin', 'user'}:
            raise ValueError('Неизвестная роль')
        salt = secrets.token_hex(16)
        digest = password_hash(password, salt)
        uid = secrets.token_hex(16)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM users').fetchone()[0] >= 1000:
                raise ValueError('Достигнут лимит аккаунтов. Обратитесь к администратору')
            try:
                db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?,?)',
                           (uid, username, salt, digest, role, 'active' if approved else 'pending', time.time(), 0))
            except sqlite3.IntegrityError:
                raise ValueError('Этот логин недоступен') from None
        return uid

    def authenticate(self, username, password, client):
        username = username.strip().casefold()
        if not self.allow('client:'+client, 30) or not self.allow('login:'+username, 8):
            return None
        with self.connect() as db:
            user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if len(password) > 256:
            return None
        # Unknown users do the same expensive hash; errors never disclose account state.
        digest = password_hash(password, user['salt'] if user else '00'*16)
        if not user or not hmac.compare_digest(digest, user['password_hash']) or user['status'] != 'active':
            return None
        token = secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            latest = db.execute('SELECT password_hash,status FROM users WHERE id=?', (user['id'],)).fetchone()
            # A reset/block racing the expensive hash must not mint a fresh login.
            if not latest or latest['status'] != 'active' or latest['password_hash'] != user['password_hash']:
                return None
            db.execute('DELETE FROM logins WHERE expires<=?', (time.time(),))
            db.execute('INSERT INTO logins VALUES (?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), user['id'], time.time()+LIFETIME))
        return token

    def current(self, token):
        if not token or len(token) > 128:
            return None
        with self.connect() as db:
            row = db.execute('''SELECT u.id,u.username,u.role,u.status,u.legacy_owner FROM users u
                JOIN logins l ON l.user_id=u.id WHERE l.digest=? AND l.expires>? AND u.status='active' ''',
                (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        return dict(row) if row else None

    def logout(self, token):
        with self.connect() as db:
            db.execute('DELETE FROM logins WHERE digest=?', (hashlib.sha256(token.encode()).hexdigest(),))

    def update(self, uid, action, actor, password=''):
        if action not in {'approve', 'block', 'unblock', 'reset'}:
            raise ValueError('Неизвестное действие')
        if action == 'reset':
            validate_password(password)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if not row:
                raise KeyError(uid)
            if action == 'block':
                if uid == actor:
                    raise ValueError('Нельзя заблокировать собственный аккаунт')
                if row['role'] == 'admin' and row['status'] == 'active' and db.execute(
                    "SELECT count(*) FROM users WHERE role='admin' AND status='active'").fetchone()[0] <= 1:
                    raise ValueError('Нельзя заблокировать последнего администратора')
            if action == 'reset':
                salt = secrets.token_hex(16)
                db.execute('UPDATE users SET salt=?,password_hash=? WHERE id=?', (salt,password_hash(password,salt),uid))
            else:
                if action == 'approve' and row['status'] != 'pending':
                    raise ValueError('Заявка уже обработана')
                if action == 'unblock' and row['status'] != 'blocked':
                    raise ValueError('Аккаунт не заблокирован')
                db.execute('UPDATE users SET status=? WHERE id=?', ('blocked' if action=='block' else 'active', uid))
            db.execute('DELETE FROM logins WHERE user_id=?', (uid,))

    def change_password(self, uid, old, new):
        validate_password(new)
        if len(old) > 256 or not self.allow('password:'+uid, 8):
            raise ValueError('Слишком много попыток. Повторите через пять минут')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if not row or not hmac.compare_digest(password_hash(old,row['salt']),row['password_hash']):
                raise ValueError('Текущий пароль неверный')
            salt = secrets.token_hex(16)
            db.execute('UPDATE users SET salt=?,password_hash=? WHERE id=?', (salt,password_hash(new,salt),uid))
            db.execute('DELETE FROM logins WHERE user_id=?', (uid,))
