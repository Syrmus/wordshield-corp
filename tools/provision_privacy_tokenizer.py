"""Provisioning only: downloads tokenizer assets, never reads documents."""
import hashlib
import json
import os
import sys
from pathlib import Path

target = Path(sys.argv[1]).resolve()
target.mkdir(parents=True, exist_ok=True)
os.environ["TIKTOKEN_CACHE_DIR"] = str(target)
import tiktoken
encoding = tiktoken.get_encoding("o200k_base")
assert encoding.decode(encoding.encode("Синтетическая проверка ёж")) == "Синтетическая проверка ёж"
files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir() if p.is_file() and p.name != "manifest.json"}
(target / "manifest.json").write_text(json.dumps({"encoding": "o200k_base", "files": files}, indent=2))
print(json.dumps({"provisioned": True, "files": len(files)}))
