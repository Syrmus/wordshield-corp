"""Crash a synthetic-only RAM workspace, then verify safe startup cleanup."""
import subprocess
import sys
from wordshield.ram_workspace import cleanup_stale_workspaces


def main():
    cleanup_stale_workspaces()
    child = subprocess.run([
        sys.executable, '-c',
        'from wordshield.ram_workspace import ram_workspace; import os; from pathlib import Path; '
        '\nwith ram_workspace() as root:'
        '\n Path(root,"synthetic.txt").write_text("Synthetic crash cleanup test")'
        '\n os._exit(0)',
    ], capture_output=True, timeout=90)
    if child.returncode:
        raise RuntimeError('Synthetic RAM crash setup failed')
    removed = cleanup_stale_workspaces()
    assert removed == 1, 'Stale RAM volume was not cleaned'
    assert cleanup_stale_workspaces() == 0, 'Cleanup is not idempotent'
    print('RAM_CRASH_CLEANUP_OK')


if __name__ == '__main__':
    main()
