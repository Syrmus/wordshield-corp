"""Entity-aware checks: XML markup and generated aliases are not source values."""
import re
from .models import Finding, hard_boundaries
from .ooxml import parse_docx, _xml, TEXT_TAGS


def occurrences(text, value, boundaries=()):
    if not value:
        return
    for match in re.finditer(re.escape(value), text):
        start, end = match.span()
        # A detected letter must not replace every letter inside other words;
        # likewise a date alone is not a phone inside an ISO timestamp.
        if value[0].isalnum() and start not in boundaries and start and (text[start-1].isalnum() or text[start-1]=='_'):
            continue
        if value[-1].isalnum() and end not in boundaries and end<len(text) and (text[end].isalnum() or text[end]=='_'):
            continue
        yield start, end


def add_exact_repeats(blocks, findings):
    """Cover unreviewed exact repeats, including properties and comment authors.

    Never override an explicit skip or extend a partially overlapping decision.
    """
    result = list(findings)
    seeds = sorted((f for f in findings if f.status=='accepted'), key=lambda f:-len(f.exact_text))
    seen = set()
    for seed in seeds:
        # A one-character selection is changed only where explicitly selected;
        # it is not authority to replace a common letter throughout the file.
        if len(seed.exact_text.strip()) < 2:
            continue
        if seed.exact_text in seen:
            continue
        seen.add(seed.exact_text)
        for block in blocks:
            for start,end in occurrences(block.text, seed.exact_text, hard_boundaries(block)):
                overlaps = [f for f in result if f.block_id==block.id and f.start<end and start<f.end
                            and (f.status!='rejected' or f.entity_type==seed.entity_type
                                 or f.exact_text==seed.exact_text or 'manual' in f.sources)]
                if overlaps:
                    continue
                result.append(Finding(f'export-repeat-{len(result)}',block.id,start,end,seed.exact_text,
                    seed.entity_type,['exact-repeat'], 'accepted',1.0,
                    block.text[max(0,start-35):end+35],seed.alias))
    return result


def remaining_values(raw, values, aliases):
    parsed = parse_docx(raw)
    texts = [(b.text, hard_boundaries(b)) for b in parsed.blocks]
    # joins Word runs and decodes XML entities while retaining visible breaks
    # Check all XML text and attributes as well, including unsupported metadata.
    # Do not search tag names, declarations or namespace syntax as document data.
    for name,data in parsed.entries.items():
        if name.endswith(('.xml','.rels')):
            for node in _xml(data).iter():
                texts.extend((value, set()) for value in (
                    '' if node.tag in TEXT_TAGS else node.text or '',
                    node.tail or '', *node.attrib.values()
                ))
    markers = sorted({a for a in aliases if a},key=len,reverse=True)
    if markers:
        pattern = re.compile('|'.join(re.escape(a) for a in markers))
        texts = [(pattern.sub('\uFFFC', text), boundaries)
                 for text, boundaries in texts]
    return [v for v in set(values) if len(v.strip()) >= 2
            and any(next(occurrences(text, v, boundaries), None) is not None
                    for text, boundaries in texts)]


def remaining_sensitive_fragments(raw, findings, aliases):
    """Fail closed when a wider replacement leaves a recognisable fragment."""
    parsed = parse_docx(raw)
    markers = sorted({alias for alias in aliases if alias}, key=len, reverse=True)
    alias_pattern = re.compile('|'.join(re.escape(alias) for alias in markers)) if markers else None
    texts = []
    for block in parsed.blocks:
        text = alias_pattern.sub('\uFFFC', block.text) if alias_pattern else block.text
        texts.append((text, hard_boundaries(block)))

    ignored_org = {
        'company', 'limited', 'ltd', 'llc', 'inc', 'corp', 'corporation',
        'ооо', 'ао', 'пао', 'зао', 'оао', 'общество', 'ответственностью',
    }
    fragments = set()
    for finding in findings:
        if finding.status != 'accepted':
            continue
        if finding.entity_type == 'EMAIL' and '@' in finding.exact_text:
            local, domain = finding.exact_text.split('@', 1)
            if len(local) >= 4:
                fragments.add(local)
            if len(domain) >= 8:
                fragments.add(domain)
        elif finding.entity_type in {'PERSON', 'ORG'}:
            for word in re.findall(r"[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'’\-]{3,}", finding.exact_text):
                if word.casefold() not in ignored_org:
                    fragments.add(word)
    return sorted(fragment for fragment in fragments if any(
        next(occurrences(text, fragment, boundaries), None) is not None
        for text, boundaries in texts
    ))


def secret_defaults(blocks, findings):
    """Accept SECRET by default, joining overlapping non-rejected ranges."""
    by_block = {b.id:b for b in blocks}
    removed = set()
    for secret in findings:
        if secret.id in removed or secret.entity_type!='SECRET' or secret.status!='pending':
            continue
        secret.status='accepted'
        changed=True
        while changed:
            changed=False
            for other in findings:
                if other is secret or other.id in removed or other.status=='rejected' or other.block_id!=secret.block_id:
                    continue
                if secret.start<other.end and other.start<secret.end:
                    secret.start=min(secret.start,other.start)
                    secret.end=max(secret.end,other.end)
                    removed.add(other.id)
                    changed=True
        secret.exact_text=by_block[secret.block_id].text[secret.start:secret.end]
        secret.alias=None
    return [f for f in findings if f.id not in removed]
