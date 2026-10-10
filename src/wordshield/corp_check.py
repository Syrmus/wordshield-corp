"""End-to-end readiness probe using only a built-in synthetic document."""
import asyncio
from dataclasses import replace
import io
import json
import tempfile
import zipfile

from .config import Settings
from .corp_runtime import validate_corp
from .markdown_export import to_markdown
from .ooxml import parse_docx
from .ram_workspace import linux_tmpfs_root
from .service import WordShieldService


def synthetic_document():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('[Content_Types].xml', '''<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>''')
        archive.writestr('_rels/.rels', '''<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''')
        archive.writestr('word/document.xml', '''<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>
<w:p><w:r><w:t>Синтетический договор / Synthetic agreement. Email: synthetic@example.invalid.</w:t></w:r></w:p>
<w:sectPr/></w:body></w:document>''')
    return output.getvalue()


async def check():
    settings = Settings.from_env()
    validate_corp(settings)
    with tempfile.TemporaryDirectory(prefix='readiness-', dir=linux_tmpfs_root()) as root:
        from pathlib import Path
        service = WordShieldService(replace(settings, data_dir=Path(root)))
        try:
            original = synthetic_document()
            sid = service.begin_session(original, 'synthetic.docx', options={})
            await service.analyze_session(sid)
            if service.store._row(sid)['state'] != 'review':
                raise RuntimeError('Synthetic analysis did not finish')
            findings = service.findings(sid)['findings']
            if not any(f['exact_text'] == 'synthetic@example.invalid' for f in findings):
                raise RuntimeError('Synthetic email not detected')
            service.decide(sid, [{'id': f['id'], 'status':'accepted'} for f in findings])
            result = service.export(sid)
            if 'synthetic@example.invalid' in to_markdown(result):
                raise RuntimeError('Synthetic value remained in export')
            restored, report = service.restore(result, session_id=sid)
            if [b.text for b in parse_docx(restored).blocks] != [b.text for b in parse_docx(original).blocks]:
                raise RuntimeError('Synthetic round trip failed')
            return {'synthetic_check':'passed', 'detectors':['rules','gliner-ru','privacy-filter'],
                    'render':True, 'docx':True, 'markdown':True, 'restore':True,
                    'device':settings.privacy_device}
        finally:
            await service.gliner.close()
            await service.privacy.close()


if __name__ == '__main__':
    try:
        print(json.dumps(asyncio.run(check())))
    except Exception as exc:
        print(json.dumps({'synthetic_check':'failed', 'error_type':type(exc).__name__}))
        raise SystemExit(1)
