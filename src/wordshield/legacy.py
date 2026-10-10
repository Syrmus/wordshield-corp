"""Local Word 97–2003 import. Conversion precedes the normal OOXML checks."""
import io
import os
import struct
import subprocess
import threading
import sys
from pathlib import Path

from .ooxml import UnsafeDocument, parse_docx
from .ram_workspace import ram_workspace
from .linux_sandbox import sandbox_command

_converter = threading.Lock()
_CFB = bytes.fromhex("d0cf11e0a1b11ae1")
_STREAMS = {"WordDocument", "0Table", "1Table", "Data", "\x05SummaryInformation",
            "\x05DocumentSummaryInformation", "\x01CompObj", "\x01Ole"}


def validate_legacy_doc(raw: bytes) -> None:
    if not raw.startswith(_CFB):
        raise UnsafeDocument("Ожидается обычный Word 97–2003 (.doc), а не переименованный файл")
    import olefile
    try:
        with olefile.OleFileIO(io.BytesIO(raw), raise_defects=olefile.DEFECT_INCORRECT) as doc:
            paths = doc.listdir(streams=True, storages=True)
            if any(len(p) != 1 or p[0] not in _STREAMS for p in paths):
                raise UnsafeDocument("DOC содержит макросы, вложенные объекты или неподдерживаемые части")
            if not doc.exists("WordDocument"):
                raise UnsafeDocument("В файле отсутствует документ Word")
            header = doc.openstream("WordDocument").read(32)
            if len(header) != 32 or header[:2] != b"\xec\xa5":
                raise UnsafeDocument("Повреждён заголовок DOC")
            # MS-DOC FibBase: flags at offset 10, fEncrypted is bit 8.
            version = struct.unpack_from("<H", header, 2)[0]
            flags = struct.unpack_from("<H", header, 10)[0]
            if version not in {0xC1, 0xD9, 0x101, 0x10C, 0x112}:
                raise UnsafeDocument("Эта версия DOC не поддерживается")
            if flags & 0x8100:
                raise UnsafeDocument("DOC защищён паролем или зашифрован")
            if flags & 1:
                raise UnsafeDocument("Шаблоны Word не поддерживаются")
    except UnsafeDocument:
        raise
    except Exception as exc:
        raise UnsafeDocument("Не удалось безопасно прочитать DOC") from exc


def convert_doc(raw: bytes, settings) -> bytes:
    if len(raw) > settings.max_upload_bytes:
        raise UnsafeDocument("Файл превышает допустимый размер")
    validate_legacy_doc(raw)
    # The deployed service inherits its OS network-denial sandbox.
    if sys.platform != 'linux' and os.getenv("WORDSHIELD_INHERIT_NETWORK_SANDBOX") != "1":
        raise UnsafeDocument("Конвертация DOC требует изолированного локального режима")
    if not _converter.acquire(timeout=30):
        raise UnsafeDocument("Конвертер занят. Повторите загрузку через минуту")
    try:
        with ram_workspace() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            source = root / "input.doc"
            source.write_bytes(raw)
            source.chmod(0o600)
            profile = root / "profile"
            (profile / "user").mkdir(parents=True)
            (profile / "user/registrymodifications.xcu").write_text(
                '<?xml version="1.0"?><oor:items xmlns:oor="http://openoffice.org/2001/registry">'
                '<item oor:path="/org.openoffice.Office.Common/Security/Scripting">'
                '<prop oor:name="MacroSecurityLevel" oor:op="fuse"><value>3</value></prop>'
                '<prop oor:name="DisableMacrosExecution" oor:op="fuse"><value>true</value></prop>'
                '</item></oor:items>', encoding="utf-8")
            output = root / "out"
            output.mkdir()
            try:
                proc = subprocess.run(sandbox_command([
                    settings.libreoffice_path, "-env:UserInstallation=" + profile.as_uri(),
                    "--headless", "--nologo", "--nodefault", "--nolockcheck", "--norestore",
                    "--convert-to", "docx:Office Open XML Text", "--outdir", str(output), str(source),
                ]), capture_output=True, timeout=60,
                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": temporary, "TMPDIR": temporary})
            except (subprocess.TimeoutExpired, OSError) as exc:
                raise UnsafeDocument("Не удалось конвертировать DOC локально за 60 секунд") from exc
            target = output / "input.docx"
            if proc.returncode or not target.is_file():
                raise UnsafeDocument("LibreOffice не смог преобразовать этот DOC")
            if target.stat().st_size > settings.max_upload_bytes:
                raise UnsafeDocument("После конвертации файл превышает допустимый размер")
            converted = target.read_bytes()
            from .image_removal import remove_images
            parse_docx(remove_images(converted)[0])
            return converted
    finally:
        _converter.release()
