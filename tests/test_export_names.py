from wordshield.export_names import document_label, export_name
from wordshield.storage import SessionStore
from test_core import make_docx


def test_language_and_type():
    assert document_label('ДОГОВОР с Example GmbH')=='договор'
    assert document_label('ДОГОВОР / AGREEMENT')=='agreement'
    assert document_label('APPLICATION\nЗаявление')=='application'
    assert document_label('Заявление на отпуск')=='заявление'


def test_sequence_and_formats_and_no_number_reuse(tmp_path,monkeypatch):
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    store=SessionStore(tmp_path/'data')
    sid,prefix=store.create(make_docx(['Договор']),90)
    name=export_name(store,sid)
    assert name.startswith('an-0001-') and name.endswith(f'-договор-{prefix}.docx')
    assert export_name(store,sid,'md')==name.removesuffix('.docx')+'.md'
    store.delete(sid)
    store=SessionStore(tmp_path/'data')
    second,_=store.create(make_docx(['Agreement']),90)
    assert export_name(store,second).startswith('an-0002-')
