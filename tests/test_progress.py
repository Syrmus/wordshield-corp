from wordshield.progress import progress_snapshot, ANALYSIS_PAGE


def sample():
    return {'active': 'privacy-detector', 'stages': {
        'privacy-detector': {'done': 5, 'total': 10, 'baseline': 0, 'started': 100, 'updated': 120},
        'russian-detector': {'done': 0, 'total': 10, 'baseline': 0},
    }}


def test_counts_all_detectors_and_estimates_current_stage():
    p = progress_snapshot(sample(), 'detecting', 120)
    assert p['percent'] == 24
    assert p['stage_remaining_seconds'] == 20


def test_no_fake_progress_or_stale_eta():
    p = sample()
    assert progress_snapshot(p, 'detecting', 190)['stage_remaining_seconds'] is None
    assert progress_snapshot(p, 'detecting', 190)['percent'] == 24
    assert progress_snapshot(p, 'detecting', 190)['waiting_for_progress']
    assert progress_snapshot({}, 'detecting', 100)['percent'] is None


def test_retry_baseline_excludes_cached_work():
    p = sample()
    p['stages']['privacy-detector']['baseline'] = 5
    assert progress_snapshot(p, 'detecting', 120)['stage_remaining_seconds'] is None
    p['stages']['privacy-detector']['done'] = 6
    assert progress_snapshot(p, 'detecting', 120)['stage_remaining_seconds'] == 80


def test_completion_and_failure():
    assert progress_snapshot(sample(), 'review', 120)['percent'] == 100
    assert progress_snapshot(sample(), 'failed', 120)['stage_remaining_seconds'] is None
    p = sample()
    for stage in p['stages'].values():
        stage['done'] = stage['total']
    assert progress_snapshot(p, 'detecting', 120)['percent'] < 100


def test_polling_is_bounded_and_accessible():
    assert '<progress ' in ANALYSIS_PAGE
    assert 'AbortSignal.timeout(15000)' in ANALYSIS_PAGE
    assert 'setTimeout(poll,2000)' in ANALYSIS_PAGE
    assert 'setInterval' not in ANALYSIS_PAGE
    assert "role='status'" in ANALYSIS_PAGE
