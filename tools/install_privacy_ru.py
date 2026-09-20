"""Explicit model provisioning; no documents or runtime inference involved."""
import hashlib
import json
import sys
from pathlib import Path
from huggingface_hub import snapshot_download

REPO = "apararti/privacy-filter-ru"
REVISION = "a1650a1927ed8aceb9e15fa8ed13ffdf60cbf107"
target = Path(sys.argv[1]).resolve()
snapshot_download(REPO, revision=REVISION, local_dir=target,
                  allow_patterns=["config.json", "model.safetensors", "README.md", "finetune_summary.json"])
files = {}
for name in ("config.json", "model.safetensors"):
    with (target/name).open("rb") as stream:
        files[name] = hashlib.file_digest(stream,"sha256").hexdigest()
(target/"wordshield-manifest.json").write_text(json.dumps({"repo":REPO,"revision":REVISION,"files":files},indent=2))
print(json.dumps({"provisioned":True,"revision":REVISION,"files":files}))
