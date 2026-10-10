"""Exercise HTTPS auth and the synthetic document workflow; never print credentials."""
import argparse
import http.cookiejar
import io
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', required=True)
    parser.add_argument('--credential', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--old-export', type=Path)
    parser.add_argument('--old-session')
    parser.add_argument('--username', default='')
    args = parser.parse_args()
    base = args.base.rstrip('/')
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path, data=None, content_type=None, timeout=300):
        headers = {'Origin': base}
        if content_type:
            headers['Content-Type'] = content_type
        with opener.open(urllib.request.Request(base+path, data=data, headers=headers), timeout=timeout) as response:
            return response.read()
    password = args.credential.read_text().splitlines()[-1]
    request('/login', urllib.parse.urlencode({'username': args.username, 'password': password}).encode(), 'application/x-www-form-urlencoded')
    print(json.dumps({'phase': 'authenticated'}), flush=True)
    def upload(path, raw, filename, sid=None):
        boundary = 'WordShieldTest' + uuid.uuid4().hex
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + raw + b'\r\n'
        if sid:
            body += (f'--{boundary}\r\nContent-Disposition: form-data; name="session_id"\r\n\r\n{sid}\r\n').encode()
        body += f'--{boundary}--\r\n'.encode()
        return request(path, body, 'multipart/form-data; boundary=' + boundary)
    if args.old_export:
        bundle = upload('/api/restore', args.old_export.read_bytes(), 'old-synthetic.docx', args.old_session)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            report = json.loads(archive.read('restore-report.json'))
        assert not report['missing'] and not report['unknown']
        print(json.dumps({'phase': 'old-session-compatible', 'restored': report['restored']}), flush=True)
    created = json.loads(upload('/api/sessions', args.fixture.read_bytes(), 'security-synthetic.docx'))
    sid = created['id']
    print(json.dumps({'phase': 'uploaded', 'session_id': sid}), flush=True)
    deadline = time.monotonic() + 900
    last_stage = None
    while time.monotonic() < deadline:
        status = json.loads(request(f'/api/sessions/{sid}/status'))
        if status['stage'] != last_stage:
            print(json.dumps({'phase': status['stage'], 'state': status['state']}), flush=True)
            last_stage = status['stage']
        if status['state'] == 'review':
            break
        assert status['state'] != 'failed', 'Analysis failed'
        time.sleep(5)
    else:
        raise RuntimeError('Analysis did not finish')
    findings = json.loads(request(f'/api/sessions/{sid}/findings'))['findings']
    assert not any(f['status'] == 'pending' for f in findings)
    output = request(f'/api/sessions/{sid}/export?format=docx', b'')
    markdown = request(f'/api/sessions/{sid}/result?format=md').decode()
    assert 'ISO 27001' in markdown and '27 April 2016' in markdown
    assert not any(value in markdown for value in ('Northbridge Analytics Ltd', 'test.owner@aurora-example.test', 'Winter-Signal-883'))
    restored = upload('/api/restore', output, 'synthetic-anonymized.docx', sid)
    with zipfile.ZipFile(io.BytesIO(restored)) as archive:
        report = json.loads(archive.read('restore-report.json'))
    assert not report['missing'] and not report['unknown']
    print(json.dumps({'phase': 'complete', 'session_id': sid, 'restored': report['restored'],
                      'accepted': sum(f['status'] == 'accepted' for f in findings), 'pending': 0}), flush=True)


if __name__ == '__main__':
    main()
