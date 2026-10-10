"""Install a verified source tree, auth and backup exclusion with automatic rollback."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--enable-users', action='store_true')
    args = parser.parse_args()
    config = plistlib.loads(args.agent.read_bytes())
    env = config['EnvironmentVariables']
    root = Path(config['WorkingDirectory'])
    data = Path(env['WORDSHIELD_DATA_DIR'])
    with sqlite3.connect(f'file:{data / "sessions.sqlite3"}?mode=ro', uri=True) as db:
        active = db.execute("SELECT count(*) FROM sessions WHERE state IN ('created','detecting')").fetchone()[0]
    for tenant_db in (data / 'users').glob('*/sessions.sqlite3'):
        with sqlite3.connect(f'file:{tenant_db}?mode=ro', uri=True) as db:
            active += db.execute("SELECT count(*) FROM sessions WHERE state IN ('created','detecting')").fetchone()[0]
    if active:
        raise SystemExit('An analysis is active; retry after completion.')
    if not (args.source / 'wordshield/auth.py').is_file():
        raise SystemExit('Verified source tree is missing.')
    if args.check_only:
        print(json.dumps({'ready': True, 'active': active, 'data': str(data)}))
        return
    backup = root / 'release-backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-security')
    backup.mkdir(mode=0o700)
    shutil.copytree(root / 'src', backup / 'src')
    shutil.copy2(args.agent, backup / args.agent.name)
    sys.path.insert(0, str(args.source))
    from wordshield.auth import provision
    auth_file = data / 'browser-auth.json'
    credential = Path.home() / 'WordShield-access.txt'
    if not auth_file.exists():
        password = provision(auth_file)
        fd = os.open(credential, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write('Пароль входа в WordShield (сохраните в Bitwarden):\n' + password + '\n')
    domain = f'gui/{os.getuid()}'
    label = config['Label']
    try:
        subprocess.run(['launchctl', 'bootout', domain, str(args.agent)], check=True)
        shutil.copytree(args.source, root / 'src', dirs_exist_ok=True)
        env['WORDSHIELD_AUTH_FILE'] = str(auth_file)
        if args.enable_users:
            env['WORDSHIELD_USERS_ENABLED'] = '1'
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        args.agent.write_bytes(plistlib.dumps(config))
        subprocess.run(['launchctl', 'bootstrap', domain, str(args.agent)], check=True)
        url = 'http://127.0.0.1:' + env.get('WORDSHIELD_PORT', '8845') + '/healthz'
        for _ in range(30):
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    health = json.load(response)
                    if health.get('status') == 'ok' and (not args.enable_users or health.get('users_enabled')):
                        break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError('Health check failed')
    except BaseException:
        subprocess.run(['launchctl', 'bootout', domain, str(args.agent)], check=False, capture_output=True)
        shutil.copytree(backup / 'src', root / 'src', dirs_exist_ok=True)
        shutil.copy2(backup / args.agent.name, args.agent)
        subprocess.run(['launchctl', 'bootstrap', domain, str(args.agent)], check=True)
        raise
    exclusion = subprocess.run(['tmutil', 'addexclusion', str(data)], capture_output=True)
    print(json.dumps({'installed': True, 'backup': str(backup), 'credential_file': str(credential) if credential.exists() else None,
                      'backup_excluded': exclusion.returncode == 0}))


if __name__ == '__main__':
    main()
