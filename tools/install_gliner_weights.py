"""Explicit online provisioning step, never called while processing documents."""
import hashlib
import json
import sys
from pathlib import Path
from huggingface_hub import snapshot_download

REPO = "vladlinv/ru-pii-ner-gliner2.5"
REVISION = "7ed92ea48f59ca7044ecde89f9c802fe63d360ee"
target = Path(sys.argv[1]).resolve()
snapshot_download(REPO, revision=REVISION, local_dir=target,
                  allow_patterns=["config.json", "encoder_config/config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json"])
files = {}
for path in sorted(target.rglob("*")):
    if path.is_file() and ".cache" not in path.parts:
        with path.open("rb") as stream:
            files[str(path.relative_to(target))] = hashlib.file_digest(stream, "sha256").hexdigest()
(target / "wordshield-manifest.json").write_text(json.dumps({"repo": REPO, "revision": REVISION, "files": files}, indent=2))
print(json.dumps({"revision": REVISION, "verified_files": len(files)}))
