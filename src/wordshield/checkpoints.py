"""Cache identity includes local weights, code and runtime dependency versions."""
from functools import lru_cache
import hashlib
import json
from pathlib import Path


@lru_cache(maxsize=32)
def _digest_file(path, size, modified_ns, changed_ns):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def model_identity(directory):
    root = Path(directory)
    if not root.is_dir():
        return "missing"
    values = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".safetensors", ".model", ".tiktoken"}:
            continue
        stat = path.stat()
        values[str(path.relative_to(root))] = _digest_file(str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def runtime_identity(python):
    # Local dependency metadata only; no model imports or subprocess execution.
    root = Path(python).absolute().parent.parent
    metadata = sorted(root.glob("lib/python*/site-packages/*.dist-info/METADATA"))
    digest = hashlib.sha256()
    for path in metadata:
        digest.update(path.parent.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()
