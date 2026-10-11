"""Regression proof for Linux deployment without personal infrastructure."""
import asyncio
from dataclasses import replace
import os
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

import pytest

from wordshield.config import Settings
from wordshield.crypto import KeyProvider
from wordshield.gliner_detector import GlinerDetector, SandboxedPrivacyDetector
from wordshield.corp_init import initialize
from test_core import settings


def test_corp_defaults_do_not_require_personal_infrastructure():
    with patch.dict(os.environ, {'WORDSHIELD_EDITION':'corp'}, clear=True), patch(
            'wordshield.config._lm_token', side_effect=AssertionError('No keychain token read')):
        cfg = Settings.from_env()
        cfg.validate()
        assert not cfg.trust_tailscale_headers
        assert not cfg.qwen_required and cfg.lm_token == ''
        assert cfg.privacy_checkpoint == '/models/privacy'
        assert cfg.gliner_checkpoint == '/models/gliner' and cfg.gliner_required
        assert cfg.data_dir == Path('/data')
        assert cfg.libreoffice_path == '/usr/bin/soffice'
        replace(cfg, lm_base_url='unused', lm_model='unused').validate()
        with pytest.raises(ValueError, match='retention'):
            replace(cfg, retention_days=1).validate()


@pytest.mark.parametrize('kind', ['absent', 'empty', 'wrong_length'])
def test_invalid_corp_key_never_runs_platform_command(tmp_path, kind):
    with patch.dict(os.environ, {'WORDSHIELD_EDITION':'corp'}, clear=True), patch(
            'wordshield.crypto.subprocess.run', side_effect=AssertionError('No OS keychain command')) as command:
        if kind != 'absent':
            key = tmp_path/'master.key'
            key.write_text('' if kind == 'empty' else 'YWJj')
            key.chmod(0o600)
            os.environ['WORDSHIELD_MASTER_KEY_FILE'] = str(key)
        with pytest.raises(RuntimeError):
            KeyProvider(tmp_path).master_key()
        command.assert_not_called()


def test_missing_linux_key_never_runs_security_command(tmp_path, monkeypatch):
    with patch.dict(os.environ, {}, clear=True), patch('wordshield.crypto.sys.platform', 'linux'), patch(
            'wordshield.crypto.subprocess.run', side_effect=AssertionError('No security command')) as command:
        with pytest.raises(RuntimeError, match='Linux'):
            KeyProvider(tmp_path).master_key()
        command.assert_not_called()


@pytest.mark.parametrize('detector', [GlinerDetector, SandboxedPrivacyDetector])
def test_linux_workers_launch_through_seccomp_not_sandbox_exec(tmp_path, detector):
    process = AsyncMock()
    process.stdout.readline.return_value = b'{"ready": true, "network_denied": true}\n'
    with patch('wordshield.gliner_detector.sys.platform', 'linux'), patch(
            'wordshield.gliner_detector.asyncio.create_subprocess_exec', return_value=process) as launch:
        asyncio.run(detector(settings(tmp_path))._start())
    args = launch.call_args.args
    assert any(str(arg).endswith('linux_sandbox.py') for arg in args)
    assert not any('sandbox-exec' in str(arg) for arg in args)


def test_bad_key_stops_corp_before_serving_uploads(tmp_path, monkeypatch):
    from wordshield.corp_runtime import validate_corp
    initialize(tmp_path)
    with patch.dict(os.environ, {
            'WORDSHIELD_EDITION':'corp', 'WORDSHIELD_USERS_ENABLED':'1',
            'WORDSHIELD_REGISTRATION_ENABLED':'0', 'WORDSHIELD_PUBLIC_URL':'https://test.example.invalid',
            'WORDSHIELD_AUTH_FILE':str(tmp_path/'secrets/bootstrap.json'),
            'WORDSHIELD_MASTER_KEY_FILE':str(tmp_path/'secrets/master.key')}, clear=True):
        cfg = Settings.from_env()
        validate_corp(cfg)
        (tmp_path/'secrets/master.key').write_text('')
        with pytest.raises(RuntimeError, match='empty'):
            validate_corp(cfg)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux-specific startup path')
def test_linux_temp_failure_never_invokes_macos_commands(monkeypatch, tmp_path):
    from wordshield.ram_workspace import cleanup_stale_workspaces
    from wordshield.ooxml import UnsafeDocument
    monkeypatch.setenv('WORDSHIELD_TMP_DIR', str(tmp_path))
    with patch('wordshield.ram_workspace.subprocess.run', side_effect=AssertionError('No diskutil/hdiutil')) as command:
        with pytest.raises(UnsafeDocument, match='tmpfs'):
            cleanup_stale_workspaces()
        command.assert_not_called()
