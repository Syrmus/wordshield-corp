"""Explicit provisioning commands; never invoked by document processing."""
import base64
import os
from pathlib import Path
import subprocess
import sys

from .auth import provision
from .crypto import new_key


def initialize(root):
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ('data', 'models', 'secrets', 'tls'):
        folder = root / name
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink() or folder.stat().st_mode & 0o077:
            raise RuntimeError('Bootstrap directories must be private non-symlink directories')
    key, auth, password = (root / 'secrets' / name for name in
                           ('master.key', 'bootstrap.json', 'initial-admin-password.txt'))
    if key.exists() or auth.exists():
        if key.is_file() and auth.is_file():
            print('Existing keys retained; bootstrap was not repeated.')
            return
        raise RuntimeError('Partial bootstrap: restore missing secret; never replace the existing master key')
    with os.fdopen(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        output.write(base64.urlsafe_b64encode(new_key()).decode())
    generated = provision(auth)
    placeholder = root / 'secrets/oidc-client.secret'
    with os.fdopen(os.open(placeholder, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w'):
        pass
    with os.fdopen(os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        output.write('Login: admin\nPassword: ' + generated + '\n')
    print('Initialized. Initial login is in secrets/initial-admin-password.txt; no secret was logged.')


def provision_models(root):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    scripts = Path('/opt/wordshield/tools')
    for script, name in [('install_gliner_weights.py', 'gliner'), ('install_privacy_ru.py', 'privacy'),
                         ('provision_privacy_tokenizer.py', 'tokenizer-cache')]:
        subprocess.run([sys.executable, str(scripts / script), str(root / name)], check=True)
    from .local_worker import verify_model, verify_privacy_checkpoint, verify_tokenizer_cache
    verify_model(root / 'gliner')
    verify_privacy_checkpoint(root / 'privacy')
    verify_tokenizer_cache(root / 'tokenizer-cache')
    print('Provisioned model manifests verified. Runtime does not download models.')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--models':
        provision_models(sys.argv[2])
    elif len(sys.argv) == 2:
        initialize(sys.argv[1])
    else:
        raise SystemExit('Usage: python -m wordshield.corp_init [--models] DIRECTORY')
