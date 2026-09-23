"""The same replacement plan is displayed, edited and exported."""
from .detectors import expand_approved_repetitions
from .export_checks import add_exact_repeats, secret_defaults
from .overlaps import widest_replacements
from .technical_metadata import omit_technical_schemas


def compile_plan(blocks, findings):
    result = omit_technical_schemas(blocks, findings)
    result = secret_defaults(blocks, result)
    protected = [(f.block_id, f.start, f.end) for f in result if f.status == 'rejected']
    result = expand_approved_repetitions(blocks, result, protected)
    result = widest_replacements(blocks, result)
    result = add_exact_repeats(blocks, result)
    return widest_replacements(blocks, result)
