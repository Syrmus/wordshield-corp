from wordshield.export_checks import add_exact_repeats, remaining_values, secret_defaults
from wordshield.models import Block, Finding
from wordshield.ooxml import parse_docx, patch_docx
from test_core import make_docx


def finding(b, value, kind='ORG', status='accepted', start=0, id='f'):
    a=b.text.index(value,start)
    return Finding(id,b.id,a,a+len(value),value,kind,['model'],status,.8)


def test_exact_repeats_and_alias_roundtrip():
    raw=make_docx(['ООО Пример ','ООО Пример ','Примерный текст'])
    blocks=parse_docx(raw).blocks
    fs=add_exact_repeats(blocks,[finding(blocks[0],'ООО Пример')])
    assert len(fs)==2
    for f in fs: f.alias='[[ORG-ABCD-001]]'
    out,_=patch_docx(raw,blocks,fs)
    assert not remaining_values(out,['ООО Пример'],[fs[0].alias])
    assert remaining_values(raw,['ООО Пример'],[])==['ООО Пример']


def test_dont_replace_letters_inside_words_or_generated_aliases():
    raw=make_docx(['Анна Аннабель [[PERSON-ABCD-001]]'])
    assert not remaining_values(raw,['ORG','PERSON'],['[[PERSON-ABCD-001]]'])
    assert remaining_values(raw,['Анна'],[])==['Анна']
    assert not remaining_values(make_docx(['Аннабель']),['Анна'],[])
    b=Block('b','p','paragraph','А А Арбат')
    assert len(add_exact_repeats([b],[finding(b,'А')]))==1


def test_preserve_same_value_skip_but_not_unrelated_rejected_type():
    b=Block('b','p','paragraph','Компания Компания')
    seed=finding(b,'Компания')
    skipped=finding(b,'Компания',status='rejected',start=9,id='skip')
    assert len(add_exact_repeats([b],[seed,skipped]))==2
    skipped.entity_type='DATE'
    skipped.start=8;skipped.end=len(b.text);skipped.exact_text=b.text[8:]
    assert len(add_exact_repeats([b],[seed,skipped]))==3


def test_secret_autoaccept_and_overlap_union_preserves_rejections():
    b=Block('b','p','paragraph','secret-value extra')
    f=finding(b,'secret-value','SECRET','pending')
    inner=finding(b,'value','PII','pending',id='inner')
    out=secret_defaults([b],[f,inner])
    assert len(out)==1 and out[0].status=='accepted'
    assert out[0].exact_text=='secret-value'
    f.status='rejected'
    assert secret_defaults([b],[f])[0].status=='rejected'


def test_visible_value_split_across_word_runs_is_detected():
    raw=make_docx(['AlphaBeta'])
    import io,zipfile
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src,zipfile.ZipFile(out,'w') as dst:
        for n in src.namelist():
            data=src.read(n)
            if n=='word/document.xml':
                data=data.replace(b'AlphaBeta',b'Alpha</w:t></w:r><w:r><w:t>Beta')
            dst.writestr(n,data)
    assert remaining_values(out.getvalue(),['AlphaBeta'],[])==['AlphaBeta']
