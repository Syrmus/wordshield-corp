"""Compile overlapping non-rejected findings into one reversible replacement."""
from dataclasses import replace


def widest_replacements(blocks, findings):
    texts = {b.id:b.text for b in blocks}
    result = [f for f in findings if f.status == 'rejected']
    by_block = {}
    for f in findings:
        if f.status != 'rejected':
            by_block.setdefault(f.block_id, []).append(f)
    for bid, items in by_block.items():
        ordered = sorted(items, key=lambda f:(f.start, -f.end, f.id))
        groups = []
        for f in ordered:
            if groups and f.start < max(x.end for x in groups[-1]):
                groups[-1].append(f)
            else:
                groups.append([f])
        for group in groups:
            if len(group)==1:
                result.extend(group)
                continue
            start=min(f.start for f in group)
            end=max(f.end for f in group)
            # Prefer the containing range; ties prefer a stable dictionary alias.
            winner=min(group,key=lambda f:(-(f.end-f.start), not bool(f.alias),f.id))
            whole=winner.start==start and winner.end==end
            text=texts[bid]
            if any(text[f.start:f.end]!=f.exact_text for f in group):
                raise ValueError('Диапазон не соответствует исходному тексту')
            result.append(replace(winner,start=start,end=end,exact_text=text[start:end],
                entity_type=winner.entity_type if whole else 'PII',
                alias=winner.alias if whole else None,status='accepted',
                context=text[max(0,start-45):end+45],
                sources=sorted(set(winner.sources)|{'overlap-auto'})))
    return sorted(result,key=lambda f:(f.block_id,f.start,f.end,f.id))
