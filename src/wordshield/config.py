from __future__ import annotations

import ipaddress
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


def _lm_token() -> str:
    if "WORDSHIELD_LM_TOKEN" in os.environ:
        return os.environ["WORDSHIELD_LM_TOKEN"]
    if os.uname().sysname != "Darwin":
        return ""
    command = [
        "security",
        "find-generic-password",
        "-s",
        "wordshield-lm-studio",
        "-a",
        "api",
        "-w",
    ]
    if keychain_path := os.getenv("WORDSHIELD_KEYCHAIN_PATH"):
        command.append(keychain_path)
    proc = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    allowed_user: str
    trust_tailscale_headers: bool
    lm_base_url: str
    lm_token: str
    lm_model: str
    privacy_checkpoint: str
    privacy_device: str
    privacy_required: bool
    qwen_required: bool
    render_required: bool
    libreoffice_path: str
    retention_days: int
    upload_ttl_hours: int
    max_upload_bytes: int
    gliner_required: bool = False
    gliner_checkpoint: str = ""
    gliner_python: str = ""
    gliner_threshold: float = 0.5
    privacy_python: str = ""
    qwen_tokenizer: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        corporate = os.getenv('WORDSHIELD_EDITION') == 'corp'
        qwen_required = _bool('WORDSHIELD_QWEN_REQUIRED', not corporate)
        return cls(
            data_dir=Path(os.getenv("WORDSHIELD_DATA_DIR", "/data" if corporate else "./data")).resolve(),
            allowed_user=os.getenv("WORDSHIELD_ALLOWED_USER", ""),
            trust_tailscale_headers=_bool("WORDSHIELD_TRUST_TAILSCALE_HEADERS", not corporate),
            lm_base_url=os.getenv("WORDSHIELD_LM_BASE_URL", "http://127.0.0.1:1234/v1"),
            lm_token=_lm_token() if qwen_required else '',
            lm_model=os.getenv("WORDSHIELD_LM_MODEL", "qwen/qwen3-14b"),
            privacy_checkpoint=os.getenv(
                "WORDSHIELD_PRIVACY_CHECKPOINT",
                "/models/privacy" if corporate else "/Library/Application Support/WordShield/models/privacy-filter",
            ),
            privacy_device=os.getenv("WORDSHIELD_PRIVACY_DEVICE", "cpu"),
            privacy_required=_bool("WORDSHIELD_PRIVACY_REQUIRED", True),
            qwen_required=qwen_required,
            render_required=_bool("WORDSHIELD_RENDER_REQUIRED", True),
            libreoffice_path=os.getenv("WORDSHIELD_LIBREOFFICE", "/usr/bin/soffice" if corporate else "soffice"),
            retention_days=int(os.getenv("WORDSHIELD_RETENTION_DAYS", "90")),
            upload_ttl_hours=int(os.getenv("WORDSHIELD_UPLOAD_TTL_HOURS", "24")),
            max_upload_bytes=int(
                os.getenv("WORDSHIELD_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024))
            ),
            gliner_required=_bool("WORDSHIELD_GLINER_REQUIRED", corporate),
            gliner_checkpoint=os.getenv("WORDSHIELD_GLINER_CHECKPOINT", "/models/gliner" if corporate else ""),
            gliner_python=os.getenv("WORDSHIELD_GLINER_PYTHON", ""),
            gliner_threshold=float(os.getenv("WORDSHIELD_GLINER_THRESHOLD", "0.5")),
            privacy_python=os.getenv("WORDSHIELD_PRIVACY_PYTHON", ""),
            qwen_tokenizer=os.getenv("WORDSHIELD_QWEN_TOKENIZER", ""),
        )

    def validate(self) -> None:
        if self.trust_tailscale_headers and not self.allowed_user.strip():
            raise ValueError("WORDSHIELD_ALLOWED_USER is required when Tailscale identity checks are enabled")
        if not 0 < self.gliner_threshold < 1:
            raise ValueError("GLiNER threshold must be between zero and one")
        if self.gliner_required and not Path(self.gliner_checkpoint).is_absolute():
            raise ValueError("GLiNER must use an absolute local model directory")
        if self.retention_days != 90:
            raise ValueError("retention is fixed at 90 days for this deployment")
        if os.getenv('WORDSHIELD_EDITION') == 'corp' and not self.qwen_required:
            return  # No LM Studio client or endpoint is used in the Corp pipeline.
        if self.lm_model not in {"qwen/qwen3-14b", "qwen/qwen3.5-9b"}:
            raise ValueError("WORDSHIELD_LM_MODEL must be an approved local Qwen model")
        parsed = urlparse(self.lm_base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("LM Studio URL must be an explicit local HTTP URL")
        host = parsed.hostname
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if host not in {"localhost"} and not host.endswith(".ts.net"):
                raise ValueError(
                    "LM Studio host must be loopback or a Tailscale address"
                )
        else:
            if not (ip.is_loopback or ip in ipaddress.ip_network("100.64.0.0/10")):
                raise ValueError(
                    "LM Studio host must be loopback or CGNAT Tailscale IP"
                )
