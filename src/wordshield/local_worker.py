"""Private JSON-lines subprocess; stdin/stdout are pipes, never a network API."""
from __future__ import annotations
import hashlib
import json
import os
import socket
import sys
from pathlib import Path

LABELS = {"ru_pii_person": "PERSON", "ru_pii_location": "ADDRESS", "ru_pii_date": "DATE",
          "ru_pii_phone": "PHONE", "ru_pii_email": "EMAIL", "ru_pii": "PII"}


def verify_tokenizer_cache(root):
    root = Path(root).resolve(strict=True)
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("encoding") != "o200k_base" or not manifest.get("files"):
        raise ValueError("unprovisioned privacy tokenizer")
    for name, expected in manifest["files"].items():
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("privacy tokenizer checksum mismatch")
    return root


def verify_privacy_checkpoint(root):
    root = Path(root).resolve(strict=True)
    manifest_path = root / "wordshield-manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if (manifest.get("repo"), manifest.get("revision")) != (
            "apararti/privacy-filter-ru", "a1650a1927ed8aceb9e15fa8ed13ffdf60cbf107"
        ) or set(manifest.get("files", {})) != {"config.json", "model.safetensors"}:
            raise ValueError("unapproved privacy checkpoint")
        expected = manifest["files"]
        if expected != {"config.json":"9c2f2baa96f6b49190a4bda30c8c32a0c2f03e36b65773d2ed8f99651295964a",
                        "model.safetensors":"dad75869b6130d1cefcaae0efc77eb1885524a7fc2aa47b5a96528d2c0a1904c"}:
            raise ValueError("unapproved privacy checksums")
    else:
        # The already provisioned original OpenAI checkpoint is retained for rollback.
        expected = {"model.safetensors":"9c262cbe68a0c8a50590a648ef8341a2b7d3be1fa11dfb79893fe0b03ce57b5c"}
    for name, digest in expected.items():
        with (root/name).open("rb") as stream:
            if hashlib.file_digest(stream,"sha256").hexdigest() != digest:
                raise ValueError("privacy checkpoint checksum mismatch")
    return root


def verify_model(root):
    root = Path(root).resolve(strict=True)
    manifest = json.loads((root / "wordshield-manifest.json").read_text())
    if manifest["revision"] != "7ed92ea48f59ca7044ecde89f9c802fe63d360ee":
        raise ValueError("unapproved model revision")
    if not {"model.safetensors", "config.json", "tokenizer.json", "tokenizer_config.json", "encoder_config/config.json"} <= manifest["files"].keys():
        raise ValueError("incomplete model manifest")
    for relative, expected in manifest["files"].items():
        path = (root / relative).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError("invalid model path")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError("model checksum mismatch")
    return root


def token_windows(text, tokenizer, limit=3000, overlap=256):
    """Offset-based windows; reserve 1096 model tokens for schema/special tokens."""
    encoded = tokenizer(text, add_special_tokens=False, return_offsets_mapping=True, truncation=False)
    offsets = encoded["offset_mapping"]
    if not offsets:
        return
    for cursor in range(0, len(offsets), limit-overlap):
        stop = min(cursor+limit, len(offsets))
        a = offsets[cursor][0] if cursor else 0
        b = offsets[stop-1][1] if stop < len(offsets) else len(text)
        yield a, text[a:b]
        if stop == len(offsets):
            break


def main():
    for key in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_HUB_DISABLE_TELEMETRY", "DO_NOT_TRACK"):
        os.environ[key] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    # EPERM proves process-level denial; a timeout is NOT a successful test.
    try:
        with socket.socket() as sock:
            sock.settimeout(2)
            sock.connect(("1.1.1.1", 443))
        raise RuntimeError("network access unexpectedly allowed")
    except PermissionError:
        pass
    mode = sys.argv[2] if len(sys.argv) > 2 else "gliner"
    if mode == "privacy":
        checkpoint = verify_privacy_checkpoint(sys.argv[1])
        # tiktoken ignores HF offline flags and otherwise uses a temporary
        # cache. Provision this permanent directory separately, without inputs.
        os.environ["TIKTOKEN_CACHE_DIR"] = str(verify_tokenizer_cache(checkpoint.parent / "tokenizer-cache"))
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from types import SimpleNamespace
        from wordshield.detectors import PrivacyFilterDetector
        from wordshield.models import Block
        from contextlib import redirect_stdout
        with redirect_stdout(sys.stderr):
            detector = PrivacyFilterDetector(SimpleNamespace(privacy_checkpoint=str(checkpoint), privacy_device="cpu"))
            detector._load()
            detector._opf.get_runtime()
        print(json.dumps({"ready": True, "network_denied": True}), flush=True)
        for line in sys.stdin:
            try:
                request = json.loads(line)
                blocks = [Block(b["id"], "local", "paragraph", b["text"]) for b in request["blocks"]]
                with redirect_stdout(sys.stderr):
                    detections = detector._detect_sync(blocks)
                print(json.dumps({"detections": [d.__dict__ for d in detections]}, ensure_ascii=False), flush=True)
            except Exception as exc:
                print(json.dumps({"error": type(exc).__name__}), flush=True)
        return
    if mode != "gliner":
        raise ValueError("invalid local detector")
    root = verify_model(sys.argv[1])
    # Third-party loaders may print startup messages; never contaminate protocol.
    from contextlib import redirect_stdout
    with redirect_stdout(sys.stderr):
        import torch
        from gliner2 import AutoExtractor
        from transformers import AutoTokenizer
        torch.set_num_threads(4)
        tokenizer = AutoTokenizer.from_pretrained(str(root), local_files_only=True, trust_remote_code=False, extra_special_tokens={})
        # AutoExtractor dispatches only to packaged architectures and rejects
        # trust_remote_code entirely; its loader has no remote-code path.
        model = AutoExtractor.from_pretrained(str(root), local_files_only=True)
        model.to("cpu")
        model.eval()
    print(json.dumps({"ready": True, "network_denied": True}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            found = {}
            for block in request["blocks"]:
                for offset, text in token_windows(block["text"], tokenizer):
                    with redirect_stdout(sys.stderr), torch.inference_mode():
                        result = model.extract_entities(text, list(LABELS), threshold=request.get("threshold", 0.5),
                                                        include_spans=True, include_confidence=True)
                    for label, values in result["entities"].items():
                        for item in values:
                            a, b = item["start"], item["end"]
                            if not 0 <= a < b <= len(text) or text[a:b] != item["text"]:
                                raise ValueError("detector offset mismatch")
                            key = (block["id"], a+offset, b+offset, LABELS[label])
                            found[key] = {"block_id": block["id"], "start": a+offset, "end": b+offset,
                                          "exact_text": item["text"], "entity_type": LABELS[label],
                                          "source": "gliner-ru", "confidence": float(item.get("confidence", item.get("score", 0.5)))}
            print(json.dumps({"detections": list(found.values())}, ensure_ascii=False), flush=True)
        except Exception as exc:
            # Exception messages can contain source text, so return the class only.
            print(json.dumps({"error": type(exc).__name__}), flush=True)


if __name__ == "__main__":
    main()
