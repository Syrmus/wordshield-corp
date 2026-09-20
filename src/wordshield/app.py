from __future__ import annotations

import asyncio
import html
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import quote
from contextlib import asynccontextmanager, suppress
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

from .config import Settings
from .detectors import DetectorUnavailable
from .ooxml import UnsafeDocument
from .service import WordShieldService, ENTITY_TYPES
from .legacy import convert_doc
from .ui import PAGE as APP_PAGE, FEATURES, FAVICON, icon
from .help_page import HELP_CONTENT
from .progress import ANALYSIS_PAGE
from .review_ui import REVIEW_SCRIPT
from .markdown_export import to_markdown
from .export_names import export_name


class DecisionPatch(BaseModel):
    decisions: list[dict] = Field(default_factory=list)
    additions: list[dict] = Field(default_factory=list)


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    page = APP_PAGE
    if setup_label := os.getenv("WORDSHIELD_SETUP_LABEL"):
        banner = (
            "<details class='setup'><summary>Модели обработки</summary>"
            f"<p>{html.escape(setup_label)}</p></details>"
        )
        page = page.replace("</header>", banner + "</header>")
    service = WordShieldService(cfg)
    jobs: dict[str, asyncio.Task] = {}

    def launch(sid: str) -> None:
        if sid in jobs and not jobs[sid].done():
            return
        service.store.update_state(sid, "detecting")
        task = asyncio.create_task(service.analyze_session(sid))
        jobs[sid] = task

        def finished(done: asyncio.Task) -> None:
            jobs.pop(sid, None)
            if not done.cancelled():
                with suppress(Exception):
                    done.result()

        task.add_done_callback(finished)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        service.store.purge(cfg.upload_ttl_hours)
        for row in service.store.list():
            if row["state"] == "detecting":
                launch(row["id"])

        async def cleaner():
            while True:
                await asyncio.sleep(3600)
                service.store.purge(cfg.upload_ttl_hours)

        task = asyncio.create_task(cleaner())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            for job in jobs.values():
                job.cancel()
            if jobs:
                await asyncio.gather(*jobs.values(), return_exceptions=True)
            await service.gliner.close()
            await service.privacy.close()

    app = FastAPI(
        title="WordShield Local", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.state.service = service

    async def read_upload(file: UploadFile) -> tuple[bytes, bytes]:
        name = (file.filename or "").lower()
        if not name.endswith((".docx", ".doc")):
            raise HTTPException(415, "Поддерживаются .docx и .doc")
        raw = await file.read(cfg.max_upload_bytes + 1)
        if not raw:
            raise HTTPException(422, "Файл пустой (0 байт). Выберите другой файл.")
        if name.endswith(".doc"):
            return await asyncio.to_thread(convert_doc, raw, cfg), raw
        return raw, raw

    @app.middleware("http")
    async def identity_gate(request: Request, call_next):
        if request.url.path == "/healthz":
            return await call_next(request)
        if cfg.trust_tailscale_headers:
            login = request.headers.get("Tailscale-User-Login", "")
            if login.casefold() != cfg.allowed_user.casefold():
                return Response("Forbidden", 403)
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get(
            "Origin"
        ):
            expected = f"{request.url.scheme}://{request.url.netloc}"
            if request.headers["Origin"].rstrip("/") != expected.rstrip("/"):
                return Response("Cross-site request rejected", 403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        # Native POST forms can receive Origin: null under no-referrer (Safari).
        # Keep same-origin form provenance while leaking nothing cross-origin.
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.exception_handler(UnsafeDocument)
    async def unsafe_handler(_: Request, exc: UnsafeDocument):
        return HTMLResponse(
            f"<h1>Экспорт заблокирован</h1><p>{html.escape(str(exc))}</p>",
            status_code=422,
        )

    @app.exception_handler(DetectorUnavailable)
    async def detector_handler(_: Request, exc: DetectorUnavailable):
        return HTMLResponse(
            f"<h1>Локальный детектор недоступен</h1><p>{html.escape(str(exc))}</p>",
            status_code=503,
        )

    @app.get('/favicon.svg')
    def favicon():
        return Response(FAVICON, media_type='image/svg+xml')

    @app.get("/healthz")
    def health():
        return {"status": "ok", "model": cfg.lm_model if cfg.qwen_required else None,
                "detectors": ["rules"] + (["gliner-ru"] if cfg.gliner_required else [])
                    + (["privacy-filter"] if cfg.privacy_required else [])
                    + (["qwen"] if cfg.qwen_required else []), "cloud_fallback": False}

    @app.get("/", response_class=HTMLResponse)
    def home():
        return page.replace(
            "{{CONTENT}}",
            "<section class='hero'><span class='eyebrow'>Приватная работа с документами</span>"
            "<h1>Обезличьте документ перед отправкой</h1>"
            "<p>Замените персональные и конфиденциальные данные на алиасы. "
            "Проверьте результат и восстановите оригинальные значения после правок.</p></section>"
            + upload_widget("/upload", "Найти чувствительные данные", cfg.max_upload_bytes)
            + FEATURES
            + session_table(5)
            + "<details><summary>Форматы и ограничения</summary><p>DOC и DOCX обрабатываются на офисном Mac mini. "
            "DOC автоматически преобразуется в DOCX; оформление при конвертации может немного измениться. "
            "Изображения удаляются из обезличенной копии. Вложения, макросы и другие неподдерживаемые объекты блокируют экспорт.</p></details>"
            + "<details><summary>Что решается автоматически</summary>"
            "<ul><li>Полные русские ФИО с отчеством и соответствующие им инициалы в этом документе.</li>"
            "<li>Полные паспортные номера после подписи поля, email и проверенные реквизиты.</li>"
            "<li>Полный номер договора вместо ошибочно найденной даты внутри него.</li>"
            "<li>Явные даты федеральных законов и номера Regulation (EU) оставляются без замены.</li></ul>"
            "<p>Все решения доступны для исправления. Неоднозначные фрагменты показываются отдельно.</p></details>",
        )

    @app.get("/sessions", response_class=HTMLResponse)
    def sessions_page():
        return page.replace("{{CONTENT}}", "<div class='card-heading'><div><span class='eyebrow'>Ваши документы</span>"
                            "<h1>Мои сессии</h1></div><a class='primary-link' href='/'>+ Новый документ</a></div>"
                            "<p>Оригинал и обезличенная копия — в одном месте. "
                            "Файлы хранятся 90 дней после загрузки оригинала.</p>" + session_table()
                            + "<p class='retention-note'>Дата — по времени Берлина. Экспорт и скачивание не продлевают срок.</p>")

    def session_table(limit=None):
        statuses = {"created": "📥 Загружен", "detecting": "⏳ Анализ", "review": "🔎 Проверка",
                    "exported": "✅ Экспортирован", "failed": "❌ Ошибка"}
        rows = []
        for r in service.store.list()[:limit]:
            meta = service.store.get_json(r["id"], "metadata_blob") or {}
            name = meta.get("filename") or "Имя не сохранено"
            date = datetime.fromisoformat(r["created_at"]).astimezone(ZoneInfo("Europe/Berlin")).strftime("%d.%m.%Y")
            until = datetime.fromisoformat(r["expires_at"]).astimezone(ZoneInfo("Europe/Berlin")).strftime("%d.%m.%Y")
            output_name = result_name(r["id"], meta)
            result = (f"<a href='/api/sessions/{r['id']}/result'>{html.escape(output_name)}</a>" if r["has_result"] and r["state"] == "exported"
                      else f"<span class='unavailable'>{missing_result_reason(r)}</span>")
            original_available = r["has_original"] or (r["has_raw"] and not (meta.get("filename") or "").lower().endswith(".doc"))
            original = (f"<a href='/api/sessions/{r['id']}/original'>{'Скачать оригинал' if meta.get('filename') else 'Скачать сохранённый DOCX'}</a>"
                        if original_available else "Оригинал ранее не сохранялся")
            rows.append(f"<tr><td class='session-date'>{date}</td><td><div class='session-file'>{icon('file')}<div>"
                        f"<a class='session-name' href='/sessions/{r['id']}'>{html.escape(name)}</a>"
                        f"<small>{original}</small><small>До {until}</small></div></div></td><td>{result}</td><td>{r['entity_count']}</td>"
                        f"<td><span class='status-pill status-{html.escape(r['state'], quote=True)}'>{statuses.get(r['state'], html.escape(r['state']))}</span></td></tr>")
        title = "Последние сессии" if limit else "Все документы"
        more = "<a href='/sessions'>Все сессии →</a>" if limit else "<span class='unavailable'>Оригиналы и результаты</span>"
        table = ("<table><tr><th>Дата</th><th>Исходный файл</th><th>Обезличенный файл</th><th>Сущности</th><th>Статус</th></tr>"
                 + "".join(rows) + "</table>") if rows else "<div class='empty-state'>Пока нет документов. Загрузите первый DOC или DOCX — здесь появится его сессия.</div>"
        return f"<section class='table-card'><div class='card-heading'><h2>{title}</h2>{more}</div>{table}</section>"

    def missing_result_reason(row):
        state = row["state"]
        if state == "review":
            payload = service.store.get_json(row["id"], "findings_blob") or {}
            findings = payload.get("findings", [])
            accepted = [f for f in findings if f["status"] == "accepted"]
            if any(a["block_id"] == b["block_id"] and a["start"] < b["end"] and b["start"] < a["end"]
                   for i, a in enumerate(accepted) for b in accepted[i+1:]):
                return "Нужно уточнить пересекающиеся замены"
            if any(f["status"] == "pending" for f in findings):
                return "Требуется проверка данных"
            metadata = service.store.get_json(row["id"], "metadata_blob") or {}
            if metadata.get("export_blocked"):
                return "Экспорт заблокирован — откройте сессию"
            return "Готов к экспорту"
        return {"created": "Ожидает анализа", "detecting": "Идёт анализ документа",
                "failed": "Анализ не завершён — требуется повтор",
                "exported": "Копия ранее не сохранялась"}.get(state, "Обработка ещё не завершена")

    @app.get("/api/sessions/{sid}/original")
    def download_original(sid: str):
        try:
            raw = service.store.original(sid)
            meta = service.store.get_json(sid, "metadata_blob") or {}
        except KeyError:
            raise HTTPException(404, "Оригинал не сохранился или срок сессии истёк")
        name = meta.get("filename") or f"Оригинал-{sid[:8]}.docx"
        mime = "application/msword" if name.lower().endswith(".doc") else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return Response(raw, media_type=mime, headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(name, safe="")})

    def result_name(sid, meta):
        # Never leak the original filename (which may itself contain PII) on export.
        return export_name(service.store,sid)

    def docx_response(sid, output):
        meta = service.store.get_json(sid, "metadata_blob") or {}
        return Response(output, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": "attachment; filename=anonymized.docx; filename*=UTF-8''" + quote(result_name(sid, meta), safe="")})

    def markdown_response(sid, output):
        return Response(to_markdown(output), media_type='text/markdown; charset=utf-8',
                        headers={'Content-Disposition': 'attachment; filename=anonymized.md; filename*=UTF-8\'\'' + quote(export_name(service.store,sid,'md'),safe='')})

    @app.get("/api/sessions/{sid}/result")
    def download_result(sid: str, format: str = 'docx'):
        if format not in {'docx','md'}:
            raise HTTPException(422, 'Выберите DOCX или MD')
        try:
            output=service.store.result(sid)
            return markdown_response(sid,output) if format=='md' else docx_response(sid,output)
        except KeyError:
            raise HTTPException(404, "Результат не сохранён или срок сессии истёк")

    @app.get("/dictionary", response_class=HTMLResponse)
    def dictionary_page():
        def editor(entry=None):
            e = entry or {"id": "", "value": "", "entity_type": "ORG", "enabled": True, "alias": ""}
            options = "".join(f"<option{' selected' if t == e['entity_type'] else ''}>{t}</option>" for t in sorted(ENTITY_TYPES))
            esc = html.escape
            remove = (f"<form method='post' action='/dictionary/{e['id']}/delete' onsubmit=\"return confirm('Удалить правило для будущих сессий? Старое восстановление сохранится.')\">"
                      "<button class='danger'>Удалить</button></form>") if entry else ""
            return ("<section class='dictionary-entry'>"
                    f"<form method='post' action='/dictionary/save' style='display:flex;flex-wrap:wrap'>"
                    f"<input type='hidden' name='entry_id' value='{e['id']}'>"
                    f"<label>Исходное значение<input required name='value' maxlength='2000' value='{esc(e['value'], quote=True)}'></label>"
                    f"<label>Тип<select name='entity_type'>{options}</select></label>"
                    f"<label>Как назвать замену<input name='alias' maxlength='80' value='{esc(e.get('label',''), quote=True)}' placeholder='Например: Компания 1. Можно не заполнять'></label>"
                    f"<label><input type='checkbox' name='enabled' value='true'{' checked' if e['enabled'] else ''}>Включено</label>"
                    f"<button>{'Сохранить' if entry else 'Добавить'}</button></form>{remove}</section>")
        return page.replace("{{CONTENT}}", "<h1>Постоянные замены</h1><p>Применяются автоматически к новым загрузкам. "
                            "Совпадение точное, с учётом регистра и границ слов; падежные формы добавляйте отдельно. "
                            "Более длинная запись имеет приоритет.</p><p>В названии замены пишите обычный текст — например, «Компания 1» или «Заказчик». "
                            "Скобки, код и номер сервис добавит сам. Можно оставить поле пустым — обозначение будет выбрано автоматически. "
                            "Не используйте в названии реальные чувствительные данные: оно будет видно в обезличенном файле.</p>"
                            "<p>Словарь зашифрован и хранится до удаления записей. Изменения не затрагивают ранее загруженные документы. "
                            "Для восстановления файла только с постоянными алиасами выберите его сессию.</p>"
                            + editor() + "".join(editor(e) for e in service.dictionary.list()))

    @app.post("/dictionary/save")
    def save_dictionary(value: Annotated[str, Form()], entity_type: Annotated[str, Form()],
                        entry_id: Annotated[str, Form()] = "", alias: Annotated[str, Form()] = "",
                        enabled: Annotated[bool, Form()] = False):
        try:
            service.dictionary.save(value, entity_type, enabled, entry_id or None, alias.strip())
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except KeyError:
            raise HTTPException(404, "Запись не найдена")
        return RedirectResponse("/dictionary", 303)

    @app.post("/dictionary/{entry_id}/delete")
    def delete_dictionary(entry_id: str):
        try:
            service.dictionary.delete(entry_id)
        except KeyError:
            raise HTTPException(404, "Запись не найдена")
        return RedirectResponse("/dictionary", 303)

    @app.get("/sessions/{sid}", response_class=HTMLResponse)
    def review_page(sid: str):
        try:
            row = service.store._row(sid)
        except KeyError:
            raise HTTPException(404)
        if row["state"] == "exported":
            meta = service.store.get_json(sid, "metadata_blob") or {}
            download = (f"<p><a href='/api/sessions/{sid}/result'>Скачать Word (.docx)</a> · <a href='/api/sessions/{sid}/result?format=md'>Скачать Markdown (.md)</a></p>"
                        if row["result_blob"] else "<p>В этой старой сессии готовый файл не сохранялся. Используйте ранее скачанную копию.</p>")
            return page.replace("{{CONTENT}}", f"<h1>✅ Документ обезличен</h1><p>{html.escape(meta.get('filename') or 'Имя не сохранено')}</p>"
                                f"<p>Заменено сущностей: {row['entity_count']}.</p>{download}"
                                f"<p><a href='/sessions'>Оригинал и срок хранения — в списке сессий</a></p>"
                                f"<p><a href='/restore?session_id={sid}'>Восстановить исправленный файл этой сессии</a></p>"
                                f"<details><summary>Служебная информация</summary>Код сессии: {row['prefix']}</details>"
                                f"<form action='/sessions/{sid}/delete' method='post' onsubmit=\"return confirm('Удалить сессию и ключ восстановления?')\"><button class='danger'>Удалить сессию</button></form>")
        try:
            data = service.findings(sid)
        except KeyError:
            try:
                status = service.status(sid)
            except KeyError:
                raise HTTPException(404)
            if status["state"] == "detecting":
                return page.replace(
                    "{{CONTENT}}",
                    ANALYSIS_PAGE.replace('__SID__', sid),
                )
            if status["state"] == "failed":
                return page.replace(
                    "{{CONTENT}}",
                    f"<h1>Анализ не завершён</h1><p>Причина: {html.escape(status['error_code'] or 'локальный детектор не ответил')}.</p><p>Прогресс сохранён. При продолжении уже проверенные фрагменты будут использованы повторно.</p><form action='/sessions/{sid}/retry' method='post'><button>Продолжить анализ</button></form><form action='/sessions/{sid}/delete' method='post'><button class='danger'>Удалить сессию</button></form>",
                )
            raise HTTPException(404)
        removed_images = (service.store.get_json(sid, 'metadata_blob') or {}).get('removed_images',0)
        image_notice = ("<p>Изображения удалены из рабочей копии и будут заменены пометками в обоих форматах экспорта. Оригинал сохранён отдельно. При восстановлении по алиасам картинки не возвращаются.</p>" if removed_images else '')
        pending = [f for f in data["findings"] if f["status"] == "pending"]
        overlaps = [
            (left["id"], right["id"])
            for index, left in enumerate(data["findings"])
            for right in data["findings"][index + 1:]
            if left["block_id"] == right["block_id"]
            and left["start"] < right["end"] and right["start"] < left["end"]
        ]
        overlap_ids = {item for pair in overlaps for item in pair}
        accepted_conflicts = [
            (left, right)
            for index, left in enumerate(data["findings"])
            for right in data["findings"][index + 1:]
            if left["status"] == right["status"] == "accepted"
            and left["block_id"] == right["block_id"]
            and left["start"] < right["end"] and right["start"] < left["end"]
        ]

        conflict_cards = "".join(
            "<section style='border:1px solid #ad6700;border-radius:8px;padding:12px;margin:12px 0'>"
            "<p>Два подтверждённых фрагмента занимают одно место. Какой заменить?</p>"
            + "".join(
                "<div class='target' style='margin:8px 0'>"
                f"<b>{html.escape(keep['entity_type'])}:</b> {html.escape(keep['exact_text'])} "
                f"<button type='button' class='resolve-overlap' data-keep='{html.escape(keep['id'], quote=True)}' "
                f"data-drop='{html.escape(drop['id'], quote=True)}'>Оставить эту замену</button></div>"
                for keep, drop in ((left, right), (right, left))
            )
            + "</section>"
            for left, right in accepted_conflicts
        )
        conflict_panel = (
            f"<h2>Конфликты перед экспортом: {len(accepted_conflicts)}</h2>"
            "<p>Выберите целый нужный фрагмент. Второй будет отмечен как «оставить»; "
            "другие решения сохранятся.</p>"
            + conflict_cards
            if accepted_conflicts else ""
        )

        def note(f: dict) -> str:
            if 'overlap-auto' in f['sources']:
                return 'Пересекающиеся находки объединены: заменяется весь показанный фрагмент'
            if "global-dictionary" in f["sources"]:
                return "Постоянная замена из словаря: " + (f.get("alias") or "")
            if "known-name-form" in f["sources"]:
                return "Форма имени или инициалы совпадают с подтверждённым полным ФИО в документе"
            if "case-form-local" in f["sources"]:
                return "Падежная форма подтверждённой фамилии: отдельный алиас для точного восстановления"
            if "repeat-local" in f["sources"]:
                return "Повтор подтверждённого значения: тот же алиас"
            if "fio-joined" in f["sources"]:
                return "Фамилия, имя и отчество собраны в один точный фрагмент"
            if "compound-gap" in f["sources"]:
                return "Остаток большой строки: проверьте это отдельное слово"
            return ""

        def rows(items):
            def toggle(f):
                checked = " checked" if f["status"] == "accepted" else ""
                return (f"<label class='decision-switch'><input type='checkbox' class='status' role='switch' aria-label='Заменить фрагмент'{checked}>"
                        "<span class='switch-track' aria-hidden='true'></span>"
                        "<span class='switch-on'>Заменить</span><span class='switch-off'>Пропустить</span></label>")
            return "".join(
                f"<tr data-id='{html.escape(f['id'])}'><td><select>{''.join(f'<option value={t}' + (' selected' if t == f['entity_type'] else '') + f'>{t}</option>' for t in ENTITY_TYPES)}</select></td><td><div class='target'><b>Фрагмент:</b> {html.escape(f['exact_text'])}</div><small>Контекст для ориентира (не весь будет заменён): {html.escape(f['context'])}</small></td><td>{html.escape(', '.join(f['sources']))}<small>{html.escape(note(f))}</small></td><td>{toggle(f)}</td></tr>"
                for f in items
            )

        accepted = [f for f in data["findings"] if f["status"] != "pending"]
        content = f"""<h1>Нужно проверить</h1>{image_notice}<p>Сомнительных: <strong>{len(pending)}</strong>. Пересекающиеся варианты автоматически объединяются в один широкий фрагмент. Подтверждённые замены доступны ниже.</p>
        <table id='findings'><tr><th>Тип</th><th>Точный фрагмент и контекст</th><th>Источники</th><th>Решение</th></tr>{rows(pending)}</table>
        <p>Переключатели сохраняются автоматически. Серый — оставить данные в документе, зелёный — заменить. При экспорте текущий выбор сохраняется ещё раз; нетронутые серые находки пропускаются.</p>
        <p>При экспорте также скрываются точные повторы подтверждённых значений, в том числе в свойствах файла и комментариях. Явно пропущенное повторение того же значения не заменяется автоматически.</p>
        <style>.decision-switch{{display:inline-flex;align-items:center;gap:9px;cursor:pointer;position:relative;white-space:nowrap;min-height:44px}}.decision-switch input{{position:absolute;width:1px;height:1px;opacity:0}}.switch-track{{display:inline-block;width:51px;height:31px;border-radius:20px;background:#8e949b;position:relative;transition:background .15s;flex-shrink:0}}.switch-track::after{{content:'';position:absolute;width:27px;height:27px;top:2px;left:2px;background:white;border-radius:50%;box-shadow:0 1px 3px #0003;transition:transform .15s}}.decision-switch input:checked ~ .switch-track{{background:#248a3d}}.decision-switch input:checked ~ .switch-track::after{{transform:translateX(20px)}}.decision-switch input:focus-visible ~ .switch-track{{outline:3px solid #174f86;outline-offset:3px}}.switch-on{{display:none}}.decision-switch input:checked ~ .switch-on{{display:inline}}.decision-switch input:checked ~ .switch-off{{display:none}}</style>
        <details><summary>Все остальные находки ({len(accepted)})</summary><table>{rows(accepted)}</table></details>
        <details class='manual-addition'><summary>Не всё найдено? Добавить вручную</summary><p>Если сервис пропустил чувствительные данные, вставьте их точное написание из документа. Все точные повторения будут добавлены для замены.</p>
        <input id='manual-text' placeholder='Точный фрагмент'><select id='manual-type'>{"".join(f"<option>{t}</option>" for t in ENTITY_TYPES)}</select>
        <button id='add-fragment'>Добавить фрагмент</button></details><p id='save-status' role='status' aria-live='polite'>Изменения сохраняются автоматически</p>
        <form id='export-form' action='/api/sessions/{sid}/export' method='post'><button type='submit' data-format='docx'>Скачать Word (.docx)</button> <button type='submit' data-format='md'>Скачать Markdown (.md)</button></form>
        <p><small>Markdown — текст для проверки нейросетью, без исходной вёрстки. Таблицы представлены строками и ячейками, автоматические списки — маркерами. Обратное восстановление пока принимает только DOCX.</small></p>
        <form action='/sessions/{sid}/delete' method='post'><button class='danger'>Удалить сессию</button></form>
        {REVIEW_SCRIPT.replace('__SID__', sid)}"""
        return page.replace("{{CONTENT}}", content)

    @app.get("/help", response_class=HTMLResponse)
    def help_page():
        return page.replace("{{CONTENT}}", HELP_CONTENT)

    @app.get("/restore", response_class=HTMLResponse)
    def restore_page(session_id: str = ""):
        options = ["<option value=''>Определить автоматически</option>"]
        for row in service.store.list():
            if row["state"] == "exported":
                meta = service.store.get_json(row["id"], "metadata_blob") or {}
                name = meta.get("filename") or "Имя не сохранено"
                date = datetime.fromisoformat(row["created_at"]).strftime("%d.%m.%Y")
                options.append(f"<option value='{row['id']}'{' selected' if row['id'] == session_id else ''}>{html.escape(name)} · {date} · {row['prefix']}</option>")
        return page.replace(
            "{{CONTENT}}",
            "<h1>Восстановить файл</h1><p>Загрузите исправленный обезличенный DOCX. "
            "Вернётся ZIP с документом и точным отчётом.</p>"
            + "<label>Сессия (обязательна, если в файле только постоянные алиасы)<select id='restore-session' name='session_id' form='upload-form'>"
            + "".join(options) + "</select></label>"
            + upload_widget("/api/restore", "Восстановить", cfg.max_upload_bytes),
        )

    @app.post("/api/sessions", status_code=202)
    async def create_session_endpoint(
        file: Annotated[UploadFile, File()]
    ):
        raw, original = await read_upload(file)
        sid = service.begin_session(raw, file.filename, original)
        launch(sid)
        return {
            "id": sid,
            "review_url": f"/sessions/{sid}",
            "status": "detecting",
        }

    @app.post("/upload")
    async def upload_page(
        file: Annotated[UploadFile, File()]
    ):
        raw, original = await read_upload(file)
        sid = service.begin_session(raw, file.filename, original)
        launch(sid)
        return RedirectResponse(f"/sessions/{sid}", status_code=303)

    @app.post("/sessions/{sid}/retry")
    async def retry_page(sid: str):
        try:
            row = service.store._row(sid)
        except KeyError:
            raise HTTPException(404)
        if row["state"] != "failed" or not row["raw_blob"]:
            raise HTTPException(409, "Сессию нельзя продолжить")
        launch(sid)
        return RedirectResponse(f"/sessions/{sid}", status_code=303)

    @app.post("/sessions/{sid}/refine")
    async def refine_page(sid: str):
        try:
            row = service.store._row(sid)
        except KeyError:
            raise HTTPException(404)
        if row["state"] != "review" or not row["raw_blob"]:
            raise HTTPException(409, "Сессия не готова к уточнению")
        service.store.update_state(sid, "detecting")
        await service.analyze_session(sid, preserve_decisions=True)
        return RedirectResponse(f"/sessions/{sid}", status_code=303)

    @app.get("/api/sessions/{sid}/status")
    def status_endpoint(sid: str):
        try:
            return service.status(sid)
        except KeyError:
            raise HTTPException(404)

    @app.get("/api/sessions/{sid}/findings")
    def findings_endpoint(sid: str):
        try:
            return service.findings(sid)
        except KeyError:
            raise HTTPException(404)

    @app.patch("/api/sessions/{sid}/decisions")
    def decisions_endpoint(sid: str, patch: DecisionPatch):
        try:
            return service.decide(sid, patch.decisions, patch.additions)
        except KeyError:
            raise HTTPException(404)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.post("/api/sessions/{sid}/export")
    def export_endpoint(sid: str, format: str = 'docx'):
        if format not in {'docx','md'}:
            raise HTTPException(422, 'Выберите DOCX или MD')
        try:
            output = service.export(sid)
        except KeyError:
            raise HTTPException(404)
        except UnsafeDocument:
            metadata = service.store.get_json(sid, "metadata_blob") or {}
            metadata["export_blocked"] = True
            service.store.put_json(sid, "metadata_blob", metadata)
            raise
        return markdown_response(sid,output) if format=='md' else docx_response(sid,output)

    @app.post("/api/restore")
    async def restore_endpoint(file: Annotated[UploadFile, File()], session_id: Annotated[str, Form()] = ""):
        raw = await file.read(cfg.max_upload_bytes + 1)
        try:
            restored, report = service.restore(raw, session_id or None)
        except KeyError:
            raise HTTPException(404, "Сессия восстановления не найдена или истекла")
        bundle = service.restore_bundle(restored, report)
        return Response(
            bundle,
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="restored-with-report.zip"'
            },
        )

    @app.delete("/api/sessions/{sid}", status_code=204)
    def delete_endpoint(sid: str):
        service.store.delete(sid)
        return Response(status_code=204)

    @app.post("/sessions/{sid}/delete")
    def delete_page(sid: str):
        service.store.delete(sid)
        return RedirectResponse("/sessions", status_code=303)

    return app


ENTITY_TYPES = (
    "PII",
    "PERSON",
    "ORG",
    "ADDRESS",
    "CITY",
    "EMAIL",
    "PHONE",
    "URL",
    "PRICE",
    "BANK",
    "TAX_ID",
    "REG_ID",
    "DOCUMENT_ID",
    "PASSPORT",
    "DATE",
    "TIME",
    "SECRET",
    "IP",
    "ACCOUNT",
)


def upload_widget(action: str, button: str, max_bytes: int) -> str:
    return (
        UPLOAD_WIDGET.replace("{{ACTION}}", html.escape(action, quote=True))
        .replace("{{BUTTON}}", html.escape(button))
        .replace("{{MAX_BYTES}}", str(max_bytes))
        .replace("{{FORMATS}}", "DOCX" if action == "/api/restore" else "DOC или DOCX")
        .replace("{{ACCEPT}}", ".docx" if action == "/api/restore" else ".doc,.docx")
        .replace("{{ALLOW_DOC}}", "false" if action == "/api/restore" else "true")
    )


UPLOAD_WIDGET = """
<form id='upload-form' class='upload-form' action='{{ACTION}}' method='post' enctype='multipart/form-data'>
  <div id='dropzone' class='dropzone' role='button' tabindex='0' aria-label='Перетащите {{FORMATS}} или выберите файл'>
    <svg class='upload-illustration' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.4' stroke-linejoin='round' aria-hidden='true'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z'/><path d='M14 2v6h6'/></svg>
    <strong>Перетащите {{FORMATS}} сюда</strong>
    <span>или выберите файл из Finder</span>
    <span class='format-note'>Поддерживаются {{FORMATS}} · обработка на Mac mini</span>
    <span class='file-picker'><span aria-hidden='true'>Выбрать файл</span><input id='docx-file' type='file' name='file' aria-label='Выбрать файл' accept='{{ACCEPT}}' required></span>
    <span id='selected-file' class='selected-file'>Файл не выбран</span>
  </div>
  <button id='upload-button' type='submit'>{{BUTTON}}</button>
  <p id='upload-status' role='status' aria-live='polite'></p>
</form>
<script>
(() => {
  const zone = document.getElementById('dropzone');
  const input = document.getElementById('docx-file');
  const selected = document.getElementById('selected-file');
  const status = document.getElementById('upload-status');
  const form = document.getElementById('upload-form');
  const submit = document.getElementById('upload-button');
  let selectedFile = null;
  let uploading = false;
  form.noValidate = true;
  const maxBytes = {{MAX_BYTES}};
  const allowDoc = {{ALLOW_DOC}};
  const isFileDrag = event => Boolean(event.dataTransfer && (
    event.dataTransfer.files?.length ||
    Array.from(event.dataTransfer.types || []).some(type => type.toLowerCase() === 'files') ||
    Array.from(event.dataTransfer.items || []).some(item => item.kind === 'file')
  ));
  const readableSize = bytes => {
    if (bytes < 1024) return bytes + ' байт';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1).replace('.', ',') + ' КБ';
    return (bytes / 1048576).toFixed(1).replace('.', ',') + ' МБ';
  };
  const validate = files => {
    if (files.length !== 1) return 'Выберите один файл {{FORMATS}}.';
    if (files[0].size === 0) return 'Файл пустой (0 байт). Выберите другой файл.';
    if (!(allowDoc ? /\\.docx?$/i : /\\.docx$/i).test(files[0].name)) return 'Поддерживаются только {{FORMATS}}.';
    if (files[0].size > maxBytes) return 'Файл превышает лимит ' + readableSize(maxBytes) + '.';
    return '';
  };
  const selectFiles = files => {
    if (uploading) return;
    const error = validate(files);
    selectedFile = error ? null : files[0];
    selected.textContent = selectedFile ? selectedFile.name + ' · ' + readableSize(selectedFile.size) : 'Файл не выбран';
    zone.classList.toggle('ready', Boolean(selectedFile));
    status.textContent = error;
  };
  input.addEventListener('change', () => selectFiles(input.files));
  zone.addEventListener('keydown', event => {
    if (event.target === zone && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      input.click();
    }
  });
  zone.addEventListener('click', event => {
    if (event.target !== input) input.click();
  });
  zone.addEventListener('dragenter', event => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    zone.classList.add('dragging');
  });
  zone.addEventListener('dragover', event => {
    if (isFileDrag(event)) event.preventDefault();
  });
  zone.addEventListener('dragleave', event => {
    if (!zone.contains(event.relatedTarget)) zone.classList.remove('dragging');
  });
  zone.addEventListener('drop', event => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    event.stopPropagation();
    zone.classList.remove('dragging');
    selectFiles(event.dataTransfer.files);
  });
  window.addEventListener('dragover', event => {
    if (isFileDrag(event)) {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
    }
  });
  window.addEventListener('drop', event => {
    if (isFileDrag(event)) {
      event.preventDefault();
      zone.classList.remove('dragging');
      selectFiles(event.dataTransfer.files);
    }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (uploading) return;
    const error = validate(selectedFile ? [selectedFile] : []);
    if (error) { status.textContent = error; return; }
    uploading = true;
    submit.disabled = input.disabled = true;
    status.textContent = /\\.doc$/i.test(selectedFile.name)
      ? 'Загружаю и конвертирую DOC в DOCX на Mac mini…'
      : 'Загружаю файл на офисный Mac mini…';
    try {
      const data = new FormData();
      data.append('file', selectedFile, selectedFile.name);
      const restoring = form.getAttribute('action') === '/api/restore';
      const session = document.getElementById('restore-session');
      if (restoring && session?.value) data.append('session_id', session.value);
      const response = await fetch(restoring ? '/api/restore' : '/api/sessions', {
        method: 'POST', body: data, credentials: 'same-origin'
      });
      if (!response.ok) {
        const body = await response.text();
        let message;
        try { message = JSON.parse(body).detail; } catch (_) {
          message = new DOMParser().parseFromString(body, 'text/html').body.textContent;
        }
        throw new Error(typeof message === 'string' && message.trim() ? message.trim() : 'Сервер отклонил загрузку.');
      }
      if (restoring) {
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = url;
        link.download = 'restored-with-report.zip';
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        status.textContent = 'Файл восстановлен. Архив с отчётом скачан.';
      } else {
        const result = await response.json();
        window.location.assign(result.review_url);
      }
    } catch (error) {
      status.textContent = 'Не удалось загрузить файл: ' + error.message + ' Можно повторить отправку.';
    } finally {
      uploading = false;
      submit.disabled = input.disabled = false;
    }
  });
})();
</script>
"""
