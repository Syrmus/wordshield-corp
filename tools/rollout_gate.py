"""Fail-closed evaluation gate. Missing evidence never permits a model rollout."""


def admissible(candidate, baseline, evidence):
    reasons = []
    if candidate.get('split') != 'heldout' or baseline.get('split') != 'heldout':
        reasons.append('heldout split required')
    for language in ('ru', 'en'):
        actual = candidate.get('languages', {}).get(language, {})
        control = baseline.get('languages', {}).get(language, {})
        if (actual.get('coverage', 0) < max(.99, control.get('coverage', 1))
                or not actual.get('quality_pass') or actual.get('errors', 1) != 0):
            reasons.append(language + ': coverage or quality gate failed')
        if actual.get('auto_precision', 0) < .99 or actual.get('critical_misses', 1) != 0:
            reasons.append(language + ': precision or critical cases missing')
        if actual.get('pending', float('inf')) >= control.get('pending', 0):
            reasons.append(language + ': manual decisions not reduced')
    for name in ('offline', 'docx', 'resume', 'legacy_restore'):
        if evidence.get(name) is not True:
            reasons.append(name + ': passing evidence required')
    timings = evidence.get('timings', {})
    if not timings or any(not isinstance(timings.get(k), (int, float)) or timings[k] <= 0
                          for k in ('candidate_p95', 'baseline_p95')):
        reasons.append('timings: comparable positive p95 required')
    elif timings['candidate_p95'] > timings['baseline_p95']:
        reasons.append('timings: p95 regressed')
    return {'admitted': not reasons, 'reasons': reasons}
