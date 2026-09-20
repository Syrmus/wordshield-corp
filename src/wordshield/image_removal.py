"""Remove drawings and their binary payload before analysis; keep original separately."""
from lxml import etree
from .ooxml import _safe_zip, _xml, _zip, W, UnsafeDocument, FORBIDDEN_LOCAL_TAGS

MC='http://schemas.openxmlformats.org/markup-compatibility/2006'


def remove_images(raw):
    entries=_safe_zip(raw)
    media={n for n in entries if n.startswith('word/media/')}
    count=0
    changed=False
    for name,data in list(entries.items()):
        if not name.endswith('.xml') or name=='[Content_Types].xml':
            continue
        root=_xml(data)
        # Do not let stripping a surrounding illustration bypass OLE, controls,
        # external content, or other unsupported active objects.
        for node in root.iter():
            if etree.QName(node).localname in FORBIDDEN_LOCAL_TAGS-{'drawing','pict'}:
                raise UnsafeDocument(f'Неподдерживаемый объект в {name}')
        targets=[]
        for node in root.iter():
            if node.tag not in {f'{{{W}}}drawing',f'{{{W}}}pict'}:
                continue
            target=node
            for ancestor in node.iterancestors():
                if ancestor.tag==f'{{{MC}}}AlternateContent':target=ancestor
            if target not in targets:targets.append(target)
        targets=[n for n in targets if not any(a in targets for a in n.iterancestors())]
        for node in targets:
            parent=node.getparent()
            if parent is None:raise UnsafeDocument('Не удалось безопасно удалить изображение')
            text=etree.Element(f'{{{W}}}t');text.text='[Изображение удалено]'
            if parent.tag==f'{{{W}}}r':replacement=text
            else:
                run=etree.Element(f'{{{W}}}r');run.append(text)
                if parent.tag==f'{{{W}}}p':replacement=run
                else:
                    replacement=etree.Element(f'{{{W}}}p');replacement.append(run)
            replacement.tail=node.tail
            parent.replace(node,replacement);count+=1
        if targets:
            entries[name]=etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)
            changed=True
    for name,data in list(entries.items()):
        if name.endswith('.rels'):
            root=_xml(data);removed=[]
            for rel in list(root):
                if (rel.get('Type') or '').rsplit('/',1)[-1]=='image':
                    removed.append(rel.get('Id'));root.remove(rel)
            if removed:
                entries[name]=etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)
                changed=True
                # Any unexpected surviving references must not make an invalid DOCX.
                owner=name.replace('/_rels/','/').removesuffix('.rels')
                if owner in entries:
                    for node in _xml(entries[owner]).iter():
                        if any(v in removed for k,v in node.attrib.items()
                               if k.startswith('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}')):
                            raise UnsafeDocument('Осталась неподдерживаемая ссылка на изображение')
    if media:
        root=_xml(entries['[Content_Types].xml'])
        for node in list(root):
            if (node.get('PartName') or '').lstrip('/') in media:root.remove(node)
        entries['[Content_Types].xml']=etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)
        for name in media:del entries[name]
        changed=True
    return (_zip(entries) if changed else raw),max(count,len(media))
