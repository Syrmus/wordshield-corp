import importlib.util
import json
import os
from pathlib import Path

import pytest


def isolation_module():
    spec = importlib.util.spec_from_file_location('isolation', Path(__file__).parents[1] / 'tools/isolate_service.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rollback_moves_store_without_duplicate_keys(tmp_path, monkeypatch):
    module = isolation_module()
    monkeypatch.setattr(module, 'STATE', tmp_path / 'migration.json')
    commands = []
    monkeypatch.setattr(module.subprocess, 'run', lambda args, **kwargs: commands.append(args))
    old, new = tmp_path / 'old', tmp_path / 'new'
    new.mkdir()
    (new / 'synthetic.enc').write_bytes(b'encrypted-synthetic')
    state = dict(old_data=str(old), new_data=str(new), old_uid=os.getuid(), old_gid=os.getgid(),
                 agent=str(tmp_path / 'agent.plist'), old_label='test')
    module.rollback(state)
    assert not new.exists()
    assert (old / 'synthetic.enc').read_bytes() == b'encrypted-synthetic'
    assert json.loads(module.STATE.read_text())['phase'] == 'rolled_back'
    assert commands[-1][:2] == ['launchctl', 'bootstrap']
    module.rollback(state)  # retry preserves the same store
    assert not new.exists()


def test_rollback_refuses_two_stores(tmp_path, monkeypatch):
    module = isolation_module()
    monkeypatch.setattr(module.subprocess, 'run', lambda *args, **kwargs: None)
    old, new = tmp_path / 'old', tmp_path / 'new'
    old.mkdir()
    new.mkdir()
    with pytest.raises(RuntimeError, match='Both stores'):
        module.rollback({'old_data': str(old), 'new_data': str(new)})
