"""Private temporary conversion workspace backed by a newly created macOS RAM disk."""
from contextlib import contextmanager
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import uuid
import threading
import json
import os

from .ooxml import UnsafeDocument


_workspace_lock = threading.Lock()


def cleanup_stale_workspaces():
    """Detach only our verified RAM volumes whose owning process no longer exists."""
    info = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], capture_output=True,
                          check=True, timeout=20)
    removed = 0
    for entry in plistlib.loads(info.stdout).get('images', []):
        if not str(entry.get('image-path', '')).startswith('ram://'):
            continue
        entities = entry.get('system-entities', [])
        for entity in entities:
            mount = Path(entity.get('mount-point', '/nonexistent'))
            if mount.parent != Path('/Volumes') or not re.fullmatch(r'WordShieldRAM-[0-9a-f]{12}', mount.name):
                continue
            marker = mount / '.wordshield-owner.json'
            if not marker.is_file() or marker.is_symlink() or marker.stat().st_uid != os.getuid():
                continue
            try:
                owner = json.loads(marker.read_text())
                pid = int(owner['pid'])
                if owner.get('version') != 1 or pid < 2:
                    continue
                os.kill(pid, 0)
                continue
            except ProcessLookupError:
                pass
            except (ValueError, KeyError, OSError):
                continue
            device = entity.get('dev-entry', '')
            if not re.fullmatch(r'/dev/disk\d+(?:s\d+)?', device):
                continue
            subprocess.run(['/usr/bin/hdiutil', 'detach', '-force', device],
                           capture_output=True, check=True, timeout=20)
            removed += 1
            break
    return removed


@contextmanager
def ram_workspace():
    """One bounded RAM workspace for conversion and rendering, cleaned on exit."""
    if not _workspace_lock.acquire(timeout=30):
        raise UnsafeDocument('Проверка файла занята. Повторите через минуту.')
    try:
        with _ram_workspace() as root:
            yield root
    finally:
        _workspace_lock.release()


@contextmanager
def _ram_workspace():
    device = None
    try:
        attached = subprocess.run(['/usr/bin/hdiutil', 'attach', '-nomount', 'ram://524288'],
                                  capture_output=True, check=True, timeout=20)
        name = attached.stdout.decode().strip()
        if not re.fullmatch(r'/dev/disk\d+', name):
            raise UnsafeDocument('Не удалось создать временный диск конвертера')
        device = name
        info = subprocess.run(['/usr/bin/hdiutil', 'info', '-plist'], capture_output=True,
                              check=True, timeout=10)
        images = plistlib.loads(info.stdout).get('images', [])
        if not any(str(image.get('image-path', '')).startswith('ram://') and
                   any(entity.get('dev-entry') == device for entity in image.get('system-entities', []))
                   for image in images):
            raise UnsafeDocument('Не подтверждён временный диск в оперативной памяти')
        volume = 'WordShieldRAM-' + uuid.uuid4().hex[:12]
        subprocess.run(['/usr/sbin/diskutil', 'eraseVolume', 'HFS+', volume, device],
                       capture_output=True, check=True, timeout=30)
        mount = Path('/Volumes') / volume
        mount.chmod(0o700)
        marker = mount / '.wordshield-owner.json'
        marker.write_text(json.dumps({'version': 1, 'pid': os.getpid()}))
        marker.chmod(0o600)
        with tempfile.TemporaryDirectory(prefix='convert-', dir=mount) as temporary:
            yield temporary
    except UnsafeDocument:
        raise
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise UnsafeDocument('Недоступна конвертация DOC в оперативной памяти') from exc
    finally:
        if device:
            subprocess.run(['/usr/bin/hdiutil', 'detach', '-force', device],
                           capture_output=True, timeout=20, check=False)
