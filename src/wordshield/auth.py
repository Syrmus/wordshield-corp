"""Application authentication in addition to the private Tailscale identity."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

COOKIE = 'wordshield_access'
LIFETIME = 30 * 24 * 3600


def provision(path: Path) -> str:
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    data = {
        'salt': salt.hex(),
        'password_hash': hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex(),
        'signing_key': secrets.token_hex(32),
    }
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    return password


class BrowserAuth:
    def __init__(self, path):
        self.data = json.loads(Path(path).read_text()) if path else None
        self.attempts = []

    def verify_password(self, password):
        now = time.monotonic()
        self.attempts = [t for t in self.attempts if now-t < 300]
        if len(self.attempts) >= 5 or not self.data or len(password) > 256:
            return False
        self.attempts.append(now)
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(self.data['salt']), n=16384, r=8, p=1)
        valid = hmac.compare_digest(digest.hex(), self.data['password_hash'])
        if valid:
            self.attempts.clear()
        return valid

    def issue(self):
        payload = f'{int(time.time())}.{secrets.token_hex(16)}'
        signature = hmac.new(bytes.fromhex(self.data['signing_key']), payload.encode(), hashlib.sha256).hexdigest()
        return f'{payload}.{signature}'

    def valid(self, token):
        if not self.data:
            return True
        try:
            timestamp, nonce, signature = token.split('.')
            age = time.time() - int(timestamp)
            if not 0 <= age < LIFETIME or len(nonce) != 32:
                return False
            expected = hmac.new(bytes.fromhex(self.data['signing_key']), f'{timestamp}.{nonce}'.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)
        except (ValueError, AttributeError):
            return False
