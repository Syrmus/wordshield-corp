# WordShield Local

Локальный сервис для обезличивания DOC/DOCX перед отправкой текста во внешние
модели. Документы анализируются на локальной машине; облачного fallback нет.

## Возможности

- локальные правила, русскоязычный GLiNER и Privacy Filter RU;
- точечная замена чувствительных диапазонов алиасами без права модели
  переписывать документ;
- экспорт обезличенного DOCX и Markdown;
- обратное восстановление известных алиасов в DOCX;
- изображения и QR-коды удаляются из обезличенной копии;
- зашифрованное хранение оригинала, результата и таблицы соответствий 90 дней;
- приватный однопользовательский вход через Tailscale Serve;
- интерфейс без CDN, аналитики и внешних шрифтов.

## Важное ограничение

Ни один детектор не гарантирует нахождение 100% конфиденциальных данных.
Проверяйте обезличенный результат перед передачей третьим лицам. Markdown не
сохраняет исходную вёрстку. Восстановление изображений пока не поддерживается.

## Локальная разработка

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
export WORDSHIELD_DEV_KEY_FILE="$PWD/.dev-key"
export WORDSHIELD_TRUST_TAILSCALE_HEADERS=false
export WORDSHIELD_PRIVACY_REQUIRED=false
export WORDSHIELD_QWEN_REQUIRED=false
export WORDSHIELD_RENDER_REQUIRED=false
.venv/bin/pytest
.venv/bin/wordshield
```

В таком режиме детекторы и проверочный рендер отключены только для разработки.
Не используйте эту конфигурацию для настоящих документов.

## Развёртывание на macOS

Требуются Python 3.12+, LibreOffice, Tailscale и локально загруженные веса
детекторов. Перед установкой укажите точный логин единственного разрешённого
пользователя:

```bash
export WORDSHIELD_ALLOWED_USER='your-login@example.com'
export PRIVACY_MODEL='apararti/privacy-filter-ru'
./deploy/create-system-key.sh
./deploy/install-macos.sh
```

Приложение слушает loopback. Публикуйте его только приватно через Tailscale
Serve; Funnel для однопользовательского режима не нужен. Значения секретов и
локальные пути не коммитьте — используйте переменные окружения и macOS Keychain.

## API

- `POST /api/sessions` — загрузить DOC/DOCX;
- `GET /api/sessions/{id}/findings` — получить находки;
- `PATCH /api/sessions/{id}/decisions` — изменить решения;
- `POST /api/sessions/{id}/export?format=docx|md` — экспортировать;
- `POST /api/restore` — восстановить известные алиасы в DOCX;
- `DELETE /api/sessions/{id}` — удалить сессию и её ключ.

## Приватность репозитория

В репозитории должны находиться только исходный код, синтетические тесты и
обобщённые конфигурации. Реальные документы, сессии, логи, отчёты стенда,
адреса устройств и персональные настройки исключены через `.gitignore` и не
должны добавляться вручную.
