"""Administrative, reversible move from a login agent to an isolated service user.

Run --check without sudo first. No session keys or document stores are copied.
The old agent is retained for rollback, but disabled after successful migration.
"""
import argparse
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import sqlite3
import stat
import subprocess
import time
import urllib.request

ROOT = Path('/Library/Application Support/WordShieldService')
STATE = ROOT / 'migration.json'
DAEMON = Path('/Library/LaunchDaemons/com.wordshield.isolated.plist')
ACCOUNT = '_wordshield'


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, **kwargs)


def tree_owner(path, uid, gid):
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        os.chmod(root, 0o700)
        for name in files:
            p = Path(root) / name
            if p.is_symlink():
                raise RuntimeError('Symlinks are forbidden in the data store')
            os.chown(p, uid, gid)
            os.chmod(p, 0o600)


def clone(source, target):
    if target.exists():
        raise RuntimeError('Runtime target already exists: ' + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    run('/bin/cp', '-cR', source, target)
    # Preserve executable bits, but never inherit group-writable model/code files.
    for root, dirs, files in os.walk(target):
        for path in [Path(root), *(Path(root) / name for name in dirs + files)]:
            if path.is_symlink():
                os.lchown(path, 0, 0)
            else:
                os.chown(path, 0, 0)
                os.chmod(path, stat.S_IMODE(path.stat().st_mode) & ~0o022)


def account():
    try:
        return pwd.getpwnam(ACCOUNT)
    except KeyError:
        used = {p.pw_uid for p in pwd.getpwall()}
        uid = next(i for i in range(450, 499) if i not in used)
        path = '/Users/' + ACCOUNT
        run('/usr/bin/dscl', '.', '-create', path)
        for key, value in {
            'UniqueID': str(uid), 'PrimaryGroupID': '20', 'UserShell': '/usr/bin/false',
            'NFSHomeDirectory': str(ROOT / 'home'), 'RealName': 'WordShield service',
            'IsHidden': '1', 'Password': '*',
        }.items():
            run('/usr/bin/dscl', '.', '-create', path, key, value)
        return pwd.getpwnam(ACCOUNT)


def health(port):
    for _ in range(30):
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=2) as response:
                if json.load(response).get('status') == 'ok':
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError('Isolated service health check failed')


def rollback(state):
    subprocess.run(['launchctl', 'bootout', 'system', str(DAEMON)], capture_output=True)
    old_data, new_data = Path(state['old_data']), Path(state['new_data'])
    if old_data.exists() and new_data.exists():
        raise RuntimeError('Both stores exist; refusing to overwrite either one')
    if new_data.exists() and not old_data.exists():
        shutil.move(new_data, old_data)
    tree_owner(old_data, state['old_uid'], state['old_gid'])
    domain = f"gui/{state['old_uid']}"
    subprocess.run(['launchctl', 'bootout', domain, state['agent']], capture_output=True)
    subprocess.run(['launchctl', 'enable', domain + '/' + state['old_label']], check=True)
    subprocess.run(['launchctl', 'bootstrap', domain, state['agent']], check=True)
    state['phase'] = 'rolled_back'
    STATE.write_text(json.dumps(state))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if args.rollback:
        if os.geteuid() != 0:
            raise SystemExit('Rollback requires sudo')
        rollback(json.loads(STATE.read_text()))
        print('Rollback completed. Original data store and agent restored.')
        return
    if not args.agent:
        parser.error('--agent is required')
    config = plistlib.loads(args.agent.read_bytes())
    env = config['EnvironmentVariables']
    old_data = Path(env['WORDSHIELD_DATA_DIR']).resolve(strict=True)
    with sqlite3.connect(f'file:{old_data / "sessions.sqlite3"}?mode=ro', uri=True) as db:
        active = db.execute("SELECT count(*) FROM sessions WHERE state IN ('created','detecting')").fetchone()[0]
    if active:
        raise SystemExit('Wait until active analyses finish')
    auth = Path(env.get('WORDSHIELD_AUTH_FILE', '/nonexistent'))
    if not auth.is_file() or auth.parent != old_data:
        raise SystemExit('Install the security revision and browser authentication first')
    if args.check:
        print(json.dumps({'ready': True, 'active': active, 'account': ACCOUNT,
                          'root': str(ROOT), 'admin_required': True}))
        return
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo. No administrative password is stored.')
    if STATE.exists():
        raise SystemExit('Migration already started; inspect migration.json or use --rollback')
    owner = args.agent.stat()
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    user = account()
    home = ROOT / 'home'
    home.mkdir(mode=0o700, exist_ok=True)
    os.chown(home, user.pw_uid, user.pw_gid)
    # Prove access without printing or storing the master key.
    run('/usr/bin/sudo', '-u', ACCOUNT, '/usr/bin/security', 'find-generic-password',
        '-s', 'wordshield-local', '-a', 'master', '-w', '/Library/Keychains/System.keychain')
    runtime = ROOT / 'runtime'
    if runtime.exists():
        raise SystemExit('Runtime already exists; inspect partial preparation before retrying')
    runtime.mkdir(mode=0o755)
    source = Path(config['WorkingDirectory'])
    clone(source / 'src', runtime / 'src')
    clone(source / 'legacy-deps', runtime / 'legacy-deps')
    clone(Path(env['WORDSHIELD_PRIVACY_PYTHON']).parent.parent, runtime / 'app-venv')
    clone(Path(env['WORDSHIELD_GLINER_PYTHON']).parent.parent, runtime / 'gliner-venv')
    clone(Path(env['WORDSHIELD_GLINER_CHECKPOINT']), runtime / 'models/gliner')
    clone(Path(env['WORDSHIELD_PRIVACY_CHECKPOINT']).parent, runtime / 'models/privacy')
    policy = ROOT / 'service.sb'
    port = int(env.get('WORDSHIELD_PORT', '8845'))
    policy.write_text('(version 1)\n(allow default)\n'
                      '(deny network-outbound (remote ip "*:*"))\n'
                      '(deny network-inbound (local ip "*:*"))\n'
                      f'(allow network-inbound (local ip "localhost:{port}"))\n'
                      '(deny file-read* file-write* (subpath "/Users"))\n'
                      '(deny file-write* (subpath "' + str(runtime) + '"))\n')
    new_data = home / 'data'
    new_env = dict(env)
    new_env.update({
        'HOME': str(home), 'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONPATH': str(runtime / 'src') + ':' + str(runtime / 'legacy-deps'),
        'WORDSHIELD_DATA_DIR': str(new_data),
        'WORDSHIELD_AUTH_FILE': str(new_data / auth.name),
        'WORDSHIELD_GLINER_CHECKPOINT': str(runtime / 'models/gliner'),
        'WORDSHIELD_PRIVACY_CHECKPOINT': str(runtime / 'models/privacy' / Path(env['WORDSHIELD_PRIVACY_CHECKPOINT']).name),
        'WORDSHIELD_GLINER_PYTHON': str(runtime / 'gliner-venv/bin/python'),
        'WORDSHIELD_PRIVACY_PYTHON': str(runtime / 'app-venv/bin/python'),
        'WORDSHIELD_INHERIT_NETWORK_SANDBOX': '1',
    })
    daemon = dict(config)
    daemon.update({
        'Label': 'com.wordshield.isolated', 'UserName': ACCOUNT, 'GroupName': 'staff',
        'WorkingDirectory': str(runtime), 'EnvironmentVariables': new_env,
        'ProgramArguments': ['/usr/bin/sandbox-exec', '-f', str(policy),
                             str(runtime / 'app-venv/bin/python'), '-m', 'wordshield.main'],
        'StandardOutPath': str(home / 'service.log'), 'StandardErrorPath': str(home / 'error.log'),
    })
    # Check imports in the exact account/sandbox before touching the live service.
    run('/usr/bin/sudo', '-u', ACCOUNT, '/usr/bin/env',
        *[f'{key}={value}' for key, value in new_env.items()],
        '/usr/bin/sandbox-exec', '-f', policy, runtime / 'app-venv/bin/python',
        '-c', 'from wordshield.app import create_app; from wordshield.ram_workspace import ram_workspace; '
        'import socket; s=socket.socket(); '
        '\ntry: s.connect(("1.1.1.1",443)); raise RuntimeError("Network not denied")'
        '\nexcept PermissionError: pass'
        '\nwith ram_workspace() as workspace: pass')
    state = {'old_data': str(old_data), 'new_data': str(new_data), 'agent': str(args.agent.resolve()),
             'old_uid': owner.st_uid, 'old_gid': owner.st_gid, 'old_label': config['Label'], 'phase': 'prepared'}
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    domain = f'gui/{owner.st_uid}'
    try:
        run('launchctl', 'bootout', domain, args.agent)
        shutil.move(old_data, new_data)
        tree_owner(new_data, user.pw_uid, user.pw_gid)
        run('/usr/bin/tmutil', 'addexclusion', home)
        DAEMON.write_bytes(plistlib.dumps(daemon))
        DAEMON.chmod(0o644)
        run('launchctl', 'bootstrap', 'system', DAEMON)
        health(port)
        run('launchctl', 'disable', domain + '/' + config['Label'])
        state['phase'] = 'installed'
        STATE.write_text(json.dumps(state))
    except BaseException:
        rollback(state)
        raise
    print('Isolated service installed. Session store moved without creating a second copy.')
    print('Rollback: sudo python3 ' + str(Path(__file__).resolve()) + ' --rollback')


if __name__ == '__main__':
    main()
