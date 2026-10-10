"""Fail-closed production settings for the isolated corporate edition."""
import os
from pathlib import Path
from urllib.parse import urlsplit


def validate_corp(settings):
    from .oidc import https_origin
    public = os.environ.get('WORDSHIELD_PUBLIC_URL', '')
    https_origin(public)
    parsed = urlsplit(public)
    if parsed.path not in {'', '/'} or parsed.query:
        raise ValueError('Corp public URL must be an HTTPS origin without a path')
    if settings.trust_tailscale_headers:
        raise ValueError('Corp does not trust personal Tailscale headers')
    if os.getenv('WORDSHIELD_USERS_ENABLED') != '1':
        raise ValueError('Corp requires user accounts')
    if os.getenv('WORDSHIELD_REGISTRATION_ENABLED') != '0':
        raise ValueError('Corp requires admin-managed registration')
    if not all((settings.gliner_required, settings.privacy_required, settings.render_required)) or settings.qwen_required:
        raise ValueError('Corp requires GLiNER, Privacy Filter, renderer, and no Qwen fallback')
    if not os.getenv('WORDSHIELD_MASTER_KEY_FILE') or os.getenv('WORDSHIELD_MASTER_KEY') or os.getenv('WORDSHIELD_DEV_KEY_FILE'):
        raise ValueError('Corp requires a dedicated mounted master-key secret')
    if not Path(os.environ.get('WORDSHIELD_AUTH_FILE', '')).is_file():
        raise ValueError('Corp requires provisioned bootstrap credentials')
    if settings.privacy_device not in {'cpu', 'cuda', 'cuda:0'} or os.getenv('WORDSHIELD_GLINER_DEVICE', 'cpu') not in {'cpu','cuda','cuda:0'}:
        raise ValueError('Unsupported detector device')
