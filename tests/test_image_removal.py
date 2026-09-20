import io
import zipfile
import pytest
from test_core import make_docx, settings, text
from wordshield.image_removal import remove_images
from wordshield.ooxml import parse_docx, UnsafeDocument
from wordshield.service import WordShieldService


def pictured(extra=''):
    raw=make_docx(['before'],{
        'word/media/image1.png':b'PRIVATE QR PAYLOAD',
        'word/_rels/document.xml.rels':b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdImage" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image1.png"/></Relationships>'})
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src,zipfile.ZipFile(out,'w') as dst:
        for name in src.namelist():
            data=src.read(name)
            if name=='word/document.xml':
                data=data.replace(b'</w:r>',b'<w:drawing xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><picture r:embed="rIdImage" descr="PRIVATE ALT"/>'+extra.encode()+b'</w:drawing></w:r>',1)
            dst.writestr(name,data)
    return out.getvalue()


def test_payload_and_alt_removed_but_original_retained(tmp_path,monkeypatch):
    original=pictured()
    clean,count=remove_images(original)
    assert count==1
    assert text(clean)=='before[Изображение удалено]'
    assert all(not n.startswith('word/media/') for n in parse_docx(clean).entries)
    assert all(b'PRIVATE' not in data for data in parse_docx(clean).entries.values())
    monkeypatch.setenv('WORDSHIELD_DEV_KEY_FILE',str(tmp_path/'key'))
    svc=WordShieldService(settings(tmp_path))
    sid=svc.begin_session(original,'synthetic.docx')
    assert svc.store.original(sid)==original
    assert svc.store.raw(sid)==clean


def test_active_objects_still_rejected():
    with pytest.raises(UnsafeDocument):remove_images(pictured('<w:object/>'))


def test_text_only_file_unchanged():
    raw=make_docx(['plain text'])
    assert remove_images(raw)==(raw,0)
