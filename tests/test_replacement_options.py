import asyncio
import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from test_core import make_docx, settings, text
from wordshield.app import create_app, upload_widget
from wordshield.models import Finding, Block
from wordshield.ooxml import ALIAS_TOKEN_RE, UnsafeDocument, parse_docx, patch_docx, replace_aliases, _safe_hyperlink_target, hyperlink_alias
from wordshield.replacement_options import CATEGORIES, LABELS, validate_options, short_aliases
from wordshield.replacement_plan import compile_plan
from wordshield.service import WordShieldService
from wordshield.markdown_export import escaped, to_markdown


@pytest.fixture
def service(tmp_path,monkeypatch):
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    return WordShieldService(settings(tmp_path))


def process(service,raw,options):
    sid=service.begin_session(raw,'synthetic.docx',options=options)
    asyncio.run(service.analyze_session(sid))
    return sid


@pytest.mark.parametrize('language,marker',[('ru','[почта_1]'),('en','[Email_1]')])
def test_category_selection_export_restore_and_language(service,language,marker):
    source='Email: sample@example.test; password: Synthetic-Secret-998; 1500 USD.'
    sid=process(service,make_docx([source]),{'categories':['email'],'language':language})
    findings=service.findings(sid)
    assert findings['replacement_options']['language']==language
    assert all(f['entity_type']=='EMAIL' for f in findings['findings'])
    # Category selection is enforced during review, not just at first analysis.
    with pytest.raises(ValueError):
        service.decide(sid,[{'id':findings['findings'][0]['id'],'status':'accepted','entity_type':'SECRET'}])
    result=service.export(sid)
    assert text(result)==source.replace('sample@example.test',marker)
    assert marker in to_markdown(result) and '\\_' not in to_markdown(result)
    assert service.export(sid)==result
    with pytest.raises(UnsafeDocument,match='исходную сессию'):
        service.restore(result)
    restored,report=service.restore(result,sid)
    assert text(restored)==source and not report['unknown'] and not report['missing']
    assert service.findings(sid)['replacement_options']==findings['replacement_options']
    with pytest.raises(UnsafeDocument):
        service.begin_session(result,options={})


def test_disabled_secret_is_not_reintroduced_and_legacy_default_stays(service):
    blocks=[Block('b','p','paragraph','password: synthetic')]
    f=Finding('f','b',10,19,'synthetic','SECRET',['privacy-filter'],'pending',.8)
    assert not compile_plan(blocks,[f],{'categories':['email']})
    assert compile_plan(blocks,[f])[0].status=='accepted'
    sid=process(service,make_docx(['hello@example.test']),None)
    result=service.export(sid)
    assert '[[EMAIL-' in text(result)
    assert text(service.restore(result)[0])=='hello@example.test'


def test_all_types_use_short_labels_repeated_values_and_dictionary_stability():
    for language in ['ru','en']:
        findings=[Finding(str(i),'b',0,len(kind),kind,kind,['rules'],'accepted',1) for i,kind in enumerate(LABELS)]
        findings.append(Finding('repeat','b',0,6,'PERSON','PERSON',['rules'],'accepted',1))
        aliases=short_aliases(findings,{'language':language})
        assert len(aliases)==len(LABELS)
        assert len(set(aliases.values()))==len(LABELS)
        for f in findings:
            assert f.alias==f'[{LABELS[f.entity_type][language=="en"]}_1]'
            assert ALIAS_TOKEN_RE.fullmatch(f.alias)
    findings=[Finding('a','b',0,4,'Anna','PERSON',['global-dictionary'],'accepted',1,alias='[[PERSON-GLOB-001]]'),
              Finding('b','b',5,9,'Bill','PERSON',['rules'],'accepted',1),
              Finding('c','b',10,15,'Clara','PERSON',['global-dictionary'],'accepted',1,alias='[[PERSON-GLOB-007:Заказчик]]')]
    short_aliases(findings,{'language':'ru'})
    assert [f.alias for f in findings]==['[ФИО_1]','[ФИО_2]','[Заказчик_7]']


def test_dictionary_obeys_category_selection_and_remains_reversible(service):
    service.dictionary.save('Synthetic Contract Ltd','ORG',alias='Клиент')
    source='Synthetic Contract Ltd; someone@example.test'
    sid=process(service,make_docx([source]),{'categories':['email']})
    assert 'Synthetic Contract Ltd' in text(service.export(sid))
    sid=process(service,make_docx([source]),{'categories':['company','email']})
    output=service.export(sid)
    assert '[Клиент_1]' in text(output)
    service.dictionary.delete(service.dictionary.list()[0]['id'])
    assert text(service.restore(output,sid)[0])==source


def test_short_tokens_across_many_runs_unknown_missing_duplicate_report(service):
    name='Иванов Иван Иванович'
    raw=make_docx(list(name))
    sid=process(service,raw,{'categories':['person']})
    output=service.export(sid)
    assert text(output)=='[ФИО_1]'
    assert text(service.restore(output,sid)[0])==name
    edited=make_docx(list('[ФИО_1] / [ФИО_1]; Правка. [ФИО_999]'))
    restored,report=service.restore(edited,sid)
    assert text(restored)==name+' / '+name+'; Правка. [ФИО_999]'
    assert report['duplicates']=={'[ФИО_1]':2} and report['unknown']==['[ФИО_999]']
    _,report=service.restore(make_docx(['Only edited text']),sid)
    assert report['missing']==['[ФИО_1]']


@pytest.mark.parametrize('scheme',['mailto:synthetic@example.test','https://example.test/private'])
@pytest.mark.parametrize('alias',['[почта_1]','[Email_1]','[Заказчик_7]','[[EMAIL-ABCD-001]]'])
def test_short_and_legacy_link_roundtrip(scheme,alias):
    safe=_safe_hyperlink_target(scheme,alias)
    assert hyperlink_alias(safe)==alias
    rel=f'''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="{scheme}" TargetMode="External"/></Relationships>'''
    raw=make_docx(['Link'],{'word/_rels/document.xml.rels':rel.encode()})
    block=next(b for b in parse_docx(raw).blocks if b.kind=='hyperlink')
    f=Finding('a',block.id,0,len(block.text),block.text,'URL',['rules'],'accepted',1,alias=alias)
    output,_=patch_docx(raw,[block],[f])
    restored,counts,unknown=replace_aliases(output,{alias:scheme})
    assert counts=={alias:1} and not unknown
    assert next(b.text for b in parse_docx(restored).blocks if b.kind=='hyperlink')==scheme


def test_snils_and_ssn_are_distinct_from_phone(service):
    source='СНИЛС: 111-222-333 44; SSN: 123-45-6789'
    sid=process(service,make_docx([source]),{'categories':['personal_id']})
    values=[f['exact_text'] for f in service.findings(sid)['findings']]
    assert '111-222-333 44' in values and '123-45-6789' in values
    result=service.export(sid)
    assert 'СНИЛС:' in text(result) and '[личный_номер_1]' in text(result)
    sid=process(service,make_docx([source]),{'categories':['phone']})
    assert text(service.export(sid))==source


@pytest.mark.parametrize('value',[{'categories':[]},{'categories':['unknown']},{'categories':'email'},{'language':'de'},{'version':3},{'categories':[{}]},False])
def test_invalid_options_are_rejected(value):
    with pytest.raises(ValueError):
        validate_options(value)


def test_upload_api_defaults_options_and_invalid_uploads(tmp_path,monkeypatch):
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    app=create_app(settings(tmp_path))
    with TestClient(app) as client:
        raw=make_docx(['contact@example.test'])
        response=client.post('/api/sessions',files={'file':('synthetic.docx',raw)})
        assert response.status_code==202
        sid=response.json()['id']
        assert app.state.service.store.get_json(sid,'metadata_blob')['replacement_options']==validate_options()
        for _ in range(100):
            if client.get(f'/api/sessions/{sid}/status').json()['state']=='review':
                break
            time.sleep(.01)
        assert '[почта_1]' in text(client.post(f'/api/sessions/{sid}/export').content)
        for options in ['{','[]',json.dumps({'categories':[]}),json.dumps({'language':'xx'})]:
            assert client.post('/api/sessions',files={'file':('synthetic.docx',raw)},data={'options':options}).status_code==422
        assert client.post('/upload',files={'file':('synthetic.docx',raw)},data={'options':json.dumps({'categories':['email'],'language':'en'})},follow_redirects=False).status_code==303


def test_ui_has_all_categories_language_and_drag_upload_serialization():
    page=upload_widget('/upload','Start',1000)
    assert 'categories.filter(item => item.checked)' in page
    assert "data.append('options'" in page
    for key,_,_ in CATEGORIES:
        assert f"value='{key}' checked" in page
    assert "value='ru' selected" in page
    assert 'placeholder-language' not in upload_widget('/api/restore','Restore',1000).split('<script>')[0]
    assert escaped('[Name_1] [ФИО_1]')=='[Name_1] [ФИО_1]'
