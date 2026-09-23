"""Bounded multipart parsing: sensitive uploads never roll over to disk."""
import asyncio
from fastapi import HTTPException, Request
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.datastructures import UploadFile


async def read_document_upload(request: Request, max_bytes: int, *, restoring=False):
    try:
        async with asyncio.timeout(60):
            return await _read_document_upload(request, max_bytes, restoring=restoring)
    except TimeoutError:
        raise HTTPException(408, 'Загрузка не завершилась за минуту. Повторите отправку.')


async def _read_document_upload(request: Request, max_bytes: int, *, restoring=False):
    limit = max_bytes + 64 * 1024
    length = request.headers.get('content-length')
    if length is not None:
        try:
            if int(length) < 0 or int(length) > limit:
                raise HTTPException(413, 'Файл превышает допустимый размер')
        except ValueError:
            raise HTTPException(400, 'Некорректный размер запроса')

    async def bounded_stream():
        count = 0
        async for chunk in request.stream():
            count += len(chunk)
            if count > limit:
                raise MultiPartException('Файл превышает допустимый размер')
            yield chunk

    parser = MultiPartParser(request.headers, bounded_stream(), max_files=1,
                             max_fields=1, max_part_size=8192)
    # The stream cap is smaller than the rollover threshold, including headers.
    parser.spool_max_size = limit + 1
    parser.max_file_size = limit + 1  # older Starlette compatibility
    form = None
    try:
        form = await parser.parse()
        if set(form.keys()) - {'file', 'session_id'}:
            raise HTTPException(422, 'Неизвестное поле загрузки')
        upload = form.get('file')
        if not isinstance(upload, UploadFile):
            raise HTTPException(422, 'Выберите файл')
        filename = upload.filename or ''
        extensions = ('.docx',) if restoring else ('.docx', '.doc')
        if not filename.lower().endswith(extensions):
            raise HTTPException(415, 'Поддерживается DOCX' if restoring else 'Поддерживаются DOCX и DOC')
        raw = await upload.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise HTTPException(413, 'Файл превышает допустимый размер')
        if not raw:
            raise HTTPException(422, 'Файл пустой (0 байт). Выберите другой файл.')
        sid = form.get('session_id', '')
        if not isinstance(sid, str) or len(sid) > 64:
            raise HTTPException(422, 'Некорректная сессия')
        return raw, filename, sid
    except MultiPartException as exc:
        raise HTTPException(413, 'Превышен размер или число полей загрузки') from exc
    finally:
        if form is not None:
            await form.close()
        # Also close partially parsed files on disconnect and parser errors.
        for file in parser._files_to_close_on_error:
            file.close()
