"""Neutral filenames derived locally; never include party names or original filename."""
import re
from datetime import datetime
from zoneinfo import ZoneInfo
from .ooxml import parse_docx


def document_label(text):
    head=text[:12000]
    english=bool(re.search(r'\b(?:agreement|contract|application|invoice|statement|addendum)\b',head,re.I))
    english=english or len(set(re.findall(r'\b(?:the|shall|hereby|between|this|parties|whereas)\b',head.lower())))>=2
    types=[(r'\b(?:договор\w*|соглашени\w*|agreement|contract)\b','договор','agreement'),
           (r'\b(?:заявлени\w*|заявк\w*|application)\b','заявление','application'),
           (r'\b(?:сч[её]т\w*|invoice)\b','счет','invoice'),
           (r'\b(?:дополнени\w*|addendum)\b','дополнение','addendum')]
    matches=[]
    for pattern,ru,en in types:
        match=re.search(pattern,head,re.I)
        if match:matches.append((match.start(),en if english else ru))
    return min(matches)[1] if matches else ('document' if english else 'документ')


def export_name(store,sid,extension='docx'):
    if extension not in {'docx','md'}:raise ValueError('Unsupported extension')
    row=store._row(sid)
    meta=store.get_json(sid,'metadata_blob') or {}
    label=meta.get('export_document_label')
    if not label:
        try:
            parsed=parse_docx(store.raw(sid))
            content='\n'.join(b.text for b in parsed.blocks if b.part=='word/document.xml' and b.kind=='paragraph')
            label=document_label(content)
        except KeyError:
            label='документ'
        meta['export_document_label']=label
        store.put_json(sid,'metadata_blob',meta)
    with store._conn() as c:
        number=c.execute('SELECT number FROM session_numbers WHERE session_id=?',(sid,)).fetchone()[0]
    date=datetime.fromisoformat(row['created_at']).astimezone(ZoneInfo('Europe/Berlin')).strftime('%y%m%d')
    return f"an-{number:04d}-{date}-{label}-{row['prefix']}.{extension}"
