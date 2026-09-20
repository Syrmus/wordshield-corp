"""Text-only Markdown from the already verified anonymized DOCX; no remote IO."""
import re
from .ooxml import parse_docx, _xml, W, ALIAS_TOKEN_RE


def escaped(value):
    # Keep recovery tokens literal, including named global aliases.
    pieces=[];cursor=0
    for m in ALIAS_TOKEN_RE.finditer(value):
        pieces.append(plain(value[cursor:m.start()]));pieces.append(m.group())
        cursor=m.end()
    pieces.append(plain(value[cursor:]))
    return ''.join(pieces)


def plain(value):
    value=value.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    return re.sub(r'([\\`*_\[\]#|~])',r'\\\1',value)


def to_markdown(raw):
    parsed=parse_docx(raw)
    body=_xml(parsed.entries['word/document.xml'])
    paragraphs=body.xpath("//*[local-name()='p']")
    by_id={b.id:b for b in parsed.blocks}
    lookup={p:by_id.get(f'word/document.xml::p::{i}') for i,p in enumerate(paragraphs)}
    seen=set()

    def render(node):
        if node.tag==f'{{{W}}}p':
            block=lookup.get(node)
            if not block:return ''
            seen.add(block.id)
            value=escaped(block.text)
            style=node.find(f'{{{W}}}pPr/{{{W}}}pStyle')
            name=style.get(f'{{{W}}}val','') if style is not None else ''
            heading=re.fullmatch(r'(?i)(?:heading|заголовок)\s*([1-6])',name)
            if heading:value='#'*int(heading[1])+' '+value
            elif node.find(f'{{{W}}}pPr/{{{W}}}numPr') is not None:value='- '+value
            return value+'\n\n'
        if node.tag==f'{{{W}}}tbl':
            # Cell-labelled rows preserve merged/nested tables without inventing
            # column headers or claiming the visual grid is unchanged.
            result=['\n**Таблица**\n\n']
            for i,row in enumerate(node.findall(f'{{{W}}}tr'),1):
                result.append(f'**Строка {i}**\n\n')
                for j,cell in enumerate(row.findall(f'{{{W}}}tc'),1):
                    value=''.join(render(child) for child in cell).strip()
                    result.append(f'Ячейка {j}:\n\n{value}\n\n')
            return ''.join(result)
        return ''.join(render(child) for child in node)

    text=render(body)
    # Preserve textual notes, headers, footers and tracked-change text. Do not
    # copy package metadata, custom XML, attachments, or hyperlink targets.
    extras=[b for b in parsed.blocks if b.id not in seen and b.part.startswith('word/')
            and b.kind in {'paragraph','leaf'}]
    if extras:
        text+='\n---\n\n## Дополнительный текст документа\n\n'
        text+='\n\n'.join(escaped(b.text) for b in extras)+'\n'
    return text.rstrip()+'\n'
