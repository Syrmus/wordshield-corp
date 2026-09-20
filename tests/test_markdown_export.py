from test_core import make_docx
from wordshield.markdown_export import to_markdown


def test_markdown_preserves_tokens_and_text_not_metadata():
    raw=make_docx(['Привет [[PERSON-ABCD-001]] и [[ORG-GLOB-001:Компания 1]].'],
                  {'docProps/core.xml':b'<properties><creator>PRIVATE AUTHOR</creator></properties>'})
    md=to_markdown(raw)
    assert '[[PERSON-ABCD-001]]' in md
    assert '[[ORG-GLOB-001:Компания 1]]' in md
    assert 'PRIVATE AUTHOR' not in md


def test_no_active_html_or_markdown_images():
    md=to_markdown(make_docx(['&lt;img src="https://example.org"&gt; ![x](https://example.org)']))
    assert '<img' not in md
    assert '![x]' not in md


def test_table_and_notes_are_not_lost():
    import io,zipfile
    raw=make_docx(['Обычный текст'],{'word/footnotes.xml':b'<notes><p><t>note</t></p></notes>'})
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src,zipfile.ZipFile(out,'w') as dst:
        for name in src.namelist():
            data=src.read(name)
            if name=='word/document.xml':
                data=data.replace(b'<w:sectPr/>',b'<w:tbl><w:tr><w:tc><w:p><w:r><w:t>cell 1</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>cell 2</w:t></w:r></w:p></w:tc></w:tr></w:tbl><w:sectPr/>')
            dst.writestr(name,data)
    md=to_markdown(out.getvalue())
    assert 'cell 1' in md and 'cell 2' in md and 'note' in md
    assert 'Строка 1' in md
