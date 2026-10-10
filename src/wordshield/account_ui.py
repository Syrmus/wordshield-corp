"""Account UI; deliberately has no access to document stores."""
import html
import os
from urllib.parse import parse_qs

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .auth import COOKIE, LIFETIME


async def small_form(request):
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 4096:
            raise HTTPException(413, 'Слишком большой запрос')
    return {key: value[0] for key, value in parse_qs(body.decode('utf-8', errors='replace')).items()}


def fields(register=False):
    return ("<label>Логин<input name='username' minlength='3' maxlength='80' autocomplete='username' required></label>"
            + f"<label>Пароль<input type='password' name='password' minlength='12' maxlength='256' autocomplete='{'new-password' if register else 'current-password'}' required></label>")


def install_account_routes(app, accounts, page, oidc=None):
    registration = os.getenv('WORDSHIELD_REGISTRATION_ENABLED', '1') == '1' and not oidc
    def render(content, status=200):
        return HTMLResponse(page.replace('{{CONTENT}}', content), status)

    def error(exc):
        return render('<h1>Не удалось выполнить действие</h1><p>'+html.escape(str(exc))+"</p><a href='/account'>Личный кабинет</a>", 400)

    def admin(request):
        if request.state.user['role'] != 'admin':
            raise HTTPException(403, 'Только для администратора')

    @app.get('/login')
    def login_page():
        if oidc:
            return render("<h1>WordShield Corp</h1><p><a class='button' href='/auth/login'>Войти через компанию</a></p>"
                          + "<details><summary>Аварийный вход администратора</summary><form method='post' action='/login'>"
                          + fields() + "<button>Войти</button></form></details>")
        return render("<h1>Вход в WordShield</h1><p>Введите логин и пароль своего кабинета.</p><form method='post' action='/login'>"
                      + fields() + "<button>Войти</button></form><p>" + ("<a href='/register'>Зарегистрироваться</a> · " if registration else '') + "Если забыли пароль, обратитесь к администратору.</p>")

    @app.post('/login')
    async def login(request: Request):
        data = await small_form(request)
        if oidc and data.get('username', '').strip().casefold() != 'admin':
            return render('Используйте корпоративный вход', 403)
        token = accounts.authenticate(data.get('username',''), data.get('password',''), request.client.host if request.client else 'local')
        if not token:
            return render("<h1>Войти не удалось</h1><p>Проверьте логин и пароль. Новую регистрацию должен одобрить администратор. После нескольких попыток подождите пять минут.</p><a href='/login'>Повторить</a>",403)
        response = RedirectResponse('/',303)
        response.set_cookie(COOKIE, token, max_age=LIFETIME, secure=True, httponly=True, samesite='strict', path='/')
        return response

    @app.get('/register')
    def register_page():
        if not registration:
            raise HTTPException(404)
        return render("<h1>Регистрация</h1><p>Придумайте логин (латиницей) и пароль от 12 символов. Доступ появится только после одобрения администратором. Письма не отправляются.</p>"
                      + "<form method='post' action='/register'>"+fields(True)+"<button>Отправить заявку</button></form><a href='/login'>Уже есть аккаунт</a>")

    @app.post('/register')
    async def register(request: Request):
        if not registration:
            raise HTTPException(404)
        data = await small_form(request)
        if not accounts.allow('register',10):
            raise HTTPException(429,'Слишком много заявок. Повторите через пять минут')
        try:
            accounts.create(data.get('username',''),data.get('password',''))
        except ValueError as exc:
            return error(exc)
        return render("<h1>Заявка отправлена ✅</h1><p>Попросите администратора одобрить ваш аккаунт. До одобрения файлы загружать нельзя.</p><a href='/login'>Перейти ко входу</a>")

    @app.post('/logout')
    def logout(request: Request):
        accounts.logout(request.cookies.get(COOKIE,''))
        response = RedirectResponse('/login',303)
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite='strict')
        return response

    @app.get('/account')
    def account(request: Request):
        user = request.state.user
        if accounts.is_external(user['id']):
            return render('<h1>Личный кабинет</h1><p>'+html.escape(user['display_name'])+'</p>'
                          + ("<p><a href='/admin/users'>Управление пользователями</a></p>" if user['role']=='admin' else '')
                          + "<p>Вход и пароль управляются компанией. Выход здесь завершает только сеанс WordShield.</p>"
                          + "<form method='post' action='/logout'><button>Выйти</button></form>")
        return render('<h1>Личный кабинет</h1><p>Вы вошли как <strong>'+html.escape(user['username'])+'</strong>.</p>'
                      + ("<p><a href='/admin/users'>Управление пользователями →</a></p>" if user['role']=='admin' else '')
                      + "<p>Ваши документы, сессии и постоянные замены не видны другим пользователям. Срок хранения файлов — 90 дней от загрузки.</p>"
                      + "<h2>Сменить пароль</h2><form method='post' action='/account/password'><label>Текущий пароль<input type='password' name='old' maxlength='256' autocomplete='current-password' required></label><label>Новый пароль<input type='password' name='password' minlength='12' maxlength='256' autocomplete='new-password' required></label><button>Сменить пароль</button></form><p>После смены пароля потребуется войти заново на всех устройствах.</p><form method='post' action='/logout'><button>Выйти</button></form>")

    @app.post('/account/password')
    async def change_password(request: Request):
        data = await small_form(request)
        try:
            accounts.change_password(request.state.user['id'],data.get('old',''),data.get('password',''))
        except ValueError as exc:
            return error(exc)
        return RedirectResponse('/login',303)

    @app.get('/admin/users')
    def users(request: Request):
        admin(request)
        rows = []
        statuses = {'pending':'⏳ Ожидает одобрения','active':'✅ Активен','blocked':'⛔ Заблокирован'}
        for user in accounts.list():
            uid = user['id']
            action,label = ('approve','Одобрить') if user['status']=='pending' else ('unblock','Разблокировать') if user['status']=='blocked' else ('block','Заблокировать')
            controls = '' if uid==request.state.user['id'] else f"<form method='post' action='/admin/users/{uid}/{action}'><button>{label}</button></form>"
            if not accounts.is_external(uid):
                controls += f"<details><summary>Задать новый пароль</summary><form method='post' action='/admin/users/{uid}/reset'><input type='password' name='password' minlength='12' maxlength='256' autocomplete='new-password' required aria-label='Новый пароль'><button>Сбросить пароль</button></form></details>"
            rows.append(f"<tr><td>{html.escape(user['display_name'])}</td><td>{'Администратор' if user['role']=='admin' else 'Пользователь'}</td><td>{statuses[user['status']]}</td><td>{controls}</td></tr>")
        return render("<h1>Пользователи</h1>" + ("<p><a href='/admin/system'>Состояние Corp →</a></p>" if os.getenv('WORDSHIELD_EDITION') == 'corp' else '')
                      + "<p>Здесь можно одобрить заявку, создать аккаунт, заблокировать доступ или сбросить пароль. Чужие документы здесь не отображаются. Блокировка завершает вход на всех устройствах; файлы сохраняются до конца их срока хранения.</p>"
                      + "<table><thead><tr><th>Логин</th><th>Роль</th><th>Статус</th><th>Действия</th></tr></thead><tbody>"+''.join(rows)+"</tbody></table>"
                      + "<h2>Создать аккаунт</h2><form method='post' action='/admin/users'>"+fields(True)+"<label>Роль<select name='role'><option value='user'>Пользователь</option><option value='admin'>Администратор</option></select></label><button>Создать</button></form><p>Передайте логин и пароль лично. Получатель может сменить пароль в своём кабинете.</p>")

    @app.post('/admin/users')
    async def create_user(request: Request):
        admin(request)
        data = await small_form(request)
        try:
            accounts.create(data.get('username',''),data.get('password',''),approved=True,role=data.get('role','user'))
        except ValueError as exc:
            return error(exc)
        return RedirectResponse('/admin/users',303)

    @app.post('/admin/users/{uid}/{action}')
    async def update_user(uid: str, action: str, request: Request):
        admin(request)
        data = await small_form(request)
        try:
            accounts.update(uid,action,request.state.user['id'],data.get('password',''))
        except KeyError:
            raise HTTPException(404)
        except ValueError as exc:
            return error(exc)
        return RedirectResponse('/admin/users',303)
