from wordshield.overlaps import widest_replacements
from wordshield.models import Block, Finding
from wordshield.ooxml import parse_docx, patch_docx, replace_aliases
from test_core import make_docx


def f(b,a,z,id,status='accepted',kind='PERSON'):
    return Finding(id,b.id,a,z,b.text[a:z],kind,['test'],status,.9)


def test_containing_widest_wins_and_is_idempotent():
    b=Block('b','p','paragraph','Иванов Иван Иванович')
    result=widest_replacements([b],[f(b,0,6,'short'),f(b,0,len(b.text),'whole','pending')])
    assert len(result)==1 and result[0].id=='whole'
    assert result[0].status=='accepted' and result[0].exact_text==b.text
    assert widest_replacements([b],result)==result


def test_transitive_partial_overlap_unions_but_not_adjacent():
    b=Block('b','p','paragraph','abcdefghijklmnop')
    result=widest_replacements([b],[f(b,0,5,'a'),f(b,4,9,'b'),f(b,8,12,'c'),f(b,12,16,'d')])
    assert [(x.start,x.end) for x in result]==[(0,12),(12,16)]
    assert result[0].entity_type=='PII'


def test_rejected_and_separate_blocks_untouched():
    a=Block('a','p','paragraph','text')
    b=Block('b','p','paragraph','text')
    result=widest_replacements([a,b],[f(a,0,4,'skip','rejected'),f(a,0,2,'yes'),f(b,0,4,'other')])
    assert len(result)==3
    assert next(x for x in result if x.id=='skip').status=='rejected'


def test_union_restores_original_text():
    raw=make_docx(['Иванов Иван Иванович'])
    blocks=parse_docx(raw).blocks;b=blocks[0]
    fs=widest_replacements(blocks,[f(b,0,11,'first'),f(b,7,len(b.text),'second')])
    fs[0].alias='[[PII-ABCD-001]]'
    out,_=patch_docx(raw,blocks,fs)
    restored,_,unknown=replace_aliases(out,{fs[0].alias:fs[0].exact_text})
    assert not unknown
    assert [x.text for x in parse_docx(restored).blocks]==[x.text for x in blocks]
