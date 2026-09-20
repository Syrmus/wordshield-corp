import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import olefile

from wordshield.legacy import validate_legacy_doc, convert_doc
from wordshield.ooxml import UnsafeDocument


def fake_doc(paths=None, flags=0):
    header = bytearray(32)
    struct.pack_into('<HH', header, 0, 0xA5EC, 0xC1)
    struct.pack_into('<H', header, 10, flags)
    from io import BytesIO
    doc = SimpleNamespace(listdir=lambda **kwargs: paths or [['WordDocument'], ['1Table']],
                          exists=lambda name: True, openstream=lambda name: BytesIO(header))
    return doc


@pytest.mark.parametrize('paths,flags', [
    ([['WordDocument'], ['Macros', 'VBA']], 0),
    ([['WordDocument'], ['ObjectPool']], 0),
    (None, 0x100), (None, 0x8100), (None, 1),
])
def test_rejects_active_or_encrypted_doc_before_conversion(paths, flags):
    with patch.object(olefile, 'OleFileIO') as factory:
        factory.return_value.__enter__.return_value = fake_doc(paths, flags)
        with pytest.raises(UnsafeDocument):
            validate_legacy_doc(bytes.fromhex('d0cf11e0a1b11ae1'))


def test_rejects_renamed_rtf_zip_and_corrupt_ole():
    for raw in [b'{\\rtf1 text}', b'PK\x03\x04', bytes.fromhex('d0cf11e0a1b11ae1')]:
        with pytest.raises(UnsafeDocument):
            validate_legacy_doc(raw)


def test_converter_rejects_missing_isolation(monkeypatch):
    monkeypatch.delenv('WORDSHIELD_INHERIT_NETWORK_SANDBOX', raising=False)
    with patch('wordshield.legacy.validate_legacy_doc'):
        with pytest.raises(UnsafeDocument, match='изолированного'):
            convert_doc(b'doc', SimpleNamespace(max_upload_bytes=100))


def test_converter_cleans_temp_files_on_timeout(monkeypatch):
    from pathlib import Path
    import subprocess
    monkeypatch.setenv('WORDSHIELD_INHERIT_NETWORK_SANDBOX','1')
    source_paths = []
    def timeout(args, **kwargs):
        source_paths.append(Path(args[-1]))
        assert source_paths[-1].read_bytes() == b'doc'
        raise subprocess.TimeoutExpired(args,60)
    import tempfile
    with patch('wordshield.legacy.ram_workspace', tempfile.TemporaryDirectory), patch('wordshield.legacy.validate_legacy_doc'), patch('wordshield.legacy.subprocess.run',side_effect=timeout):
        with pytest.raises(UnsafeDocument,match='60 секунд'):
            convert_doc(b'doc',SimpleNamespace(max_upload_bytes=100,libreoffice_path='soffice'))
    assert not source_paths[0].parent.exists()


def test_ram_workspace_never_formats_unverified_device():
    import plistlib
    from wordshield.ram_workspace import ram_workspace
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if 'attach' in args:
            return SimpleNamespace(stdout=b'/dev/disk99\n')
        if 'info' in args:
            return SimpleNamespace(stdout=plistlib.dumps({'images': []}))
        if 'detach' in args:
            return SimpleNamespace(returncode=0)
        pytest.fail('An unverified device must never be formatted')
    with patch('wordshield.ram_workspace.subprocess.run', side_effect=run):
        with pytest.raises(UnsafeDocument, match='Не подтверждён'):
            with ram_workspace():
                pytest.fail('Workspace must not open')
    assert not any('eraseVolume' in args for args in calls)
