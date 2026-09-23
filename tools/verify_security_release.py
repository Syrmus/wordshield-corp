"""Synthetic-only isolated end-to-end check against installed local models."""
import argparse
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import plistlib
import tempfile


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    env = plistlib.loads(args.agent.read_bytes())['EnvironmentVariables']
    os.environ.update(env)
    from wordshield.config import Settings
    from wordshield.service import WordShieldService
    from wordshield.ooxml import parse_docx
    from wordshield.markdown_export import to_markdown
    from wordshield.models import hard_boundaries
    from wordshield.image_removal import remove_images
    with tempfile.TemporaryDirectory(prefix='wordshield-synthetic-release-') as tmp:
        os.environ['WORDSHIELD_DEV_KEY_FILE'] = str(Path(tmp) / 'synthetic.key')
        cfg = replace(Settings.from_env(), data_dir=Path(tmp) / 'data')
        service = WordShieldService(cfg)
        try:
            raw = args.fixture.read_bytes()
            sid = service.begin_session(raw, args.fixture.name)
            await service.analyze_session(sid)
            payload = service.findings(sid)
            findings = payload['findings']
            counts = {status: sum(f['status'] == status for f in findings)
                      for status in ('accepted', 'pending', 'rejected')}
            print(json.dumps({'phase': 'analyzed', **counts}), flush=True)
            if counts['pending']:
                raise RuntimeError('Synthetic fixture still requires review')
            output = service.export(sid)
            markdown = to_markdown(output)
            if isinstance(markdown, bytes):
                markdown = markdown.decode()
            restored, report = service.restore(output, sid)
            before = parse_docx(remove_images(raw)[0]).blocks
            after = parse_docx(restored).blocks
            assert [(b.id, b.text, hard_boundaries(b)) for b in before] == [
                (b.id, b.text, hard_boundaries(b)) for b in after]
            assert not report['missing'] and not report['unknown']
            assert 'ISO 27001' in markdown and '27 April 2016' in markdown
            critical = ['test.owner@aurora-example.test', 'Northbridge Analytics Ltd',
                        'INV-2026-09-8841', 'Winter-Signal-883']
            assert not any(value in markdown for value in critical)
            assert not any(name.startswith('docProps/thumbnail') for name in parse_docx(output).entries)
            print(json.dumps({'phase': 'complete', 'docx_export': True, 'md_export': True,
                              'restored': report['restored'], 'text_and_breaks_preserved': True}), flush=True)
        finally:
            await service.gliner.close()
            await service.privacy.close()


if __name__ == '__main__':
    asyncio.run(main())
