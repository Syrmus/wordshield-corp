"""Private temporary conversion workspace backed by a newly created macOS RAM disk."""
from contextlib import contextmanager
from pathlib import Path
import plistlib
import re
import subprocess
import tempfile
import uuid

from .ooxml import UnsafeDocument


@contextmanager
def ram_workspace():
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
