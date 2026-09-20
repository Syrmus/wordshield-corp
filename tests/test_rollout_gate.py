import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("rollout_gate", Path(__file__).parents[1]/"tools/rollout_gate.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_high_coverage_alone_never_allows_rollout():
    languages = {lang: {"coverage": 1, "quality_pass": True, "missing": 0, "errors": 0, "pending": 10}
                 for lang in ("ru", "en")}
    result = module.admissible({"split": "heldout", "languages": languages},
                               {"split": "heldout", "languages": languages}, {})
    assert not result["admitted"]
    assert any("offline" in r for r in result["reasons"])
    assert any("timings" in r for r in result["reasons"])
