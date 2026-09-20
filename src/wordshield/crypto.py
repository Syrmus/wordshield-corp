from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

from nacl.secret import Aead
from nacl.utils import random as random_bytes


class KeyProvider:
    """Reads the master key from macOS Keychain; env/file are explicit dev fallbacks."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def master_key(self) -> bytes:
        encoded = os.getenv("WORDSHIELD_MASTER_KEY")
        if encoded:
            key = base64.urlsafe_b64decode(encoded)
        elif os.getenv("WORDSHIELD_DEV_KEY_FILE"):
            path = Path(os.environ["WORDSHIELD_DEV_KEY_FILE"])
            if path.exists():
                key = base64.urlsafe_b64decode(path.read_text().strip())
            else:
                key = random_bytes(Aead.KEY_SIZE)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(base64.urlsafe_b64encode(key).decode())
                path.chmod(0o600)
        else:
            command = [
                "security",
                "find-generic-password",
                "-s",
                "wordshield-local",
                "-a",
                "master",
                "-w",
            ]
            if keychain_path := os.getenv("WORDSHIELD_KEYCHAIN_PATH"):
                command.append(keychain_path)
            proc = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise RuntimeError("master key is absent from macOS Keychain")
            key = base64.urlsafe_b64decode(proc.stdout.strip())
        if len(key) != Aead.KEY_SIZE:
            raise RuntimeError("invalid master key length")
        return key


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return bytes(Aead(key).encrypt(plaintext, aad=aad))


def decrypt(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return Aead(key).decrypt(ciphertext, aad=aad)


def new_key() -> bytes:
    return random_bytes(Aead.KEY_SIZE)
