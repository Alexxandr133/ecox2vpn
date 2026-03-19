## Telegram‑бот для VPN WebApp (MVP)

### Идея

- Бот в Telegram с кнопкой **«Открыть панель VPN»**.
- При нажатии открывается **WebApp** — встроенная в Telegram веб‑страница:
  - пока просто статичный сайт-заглушка с текстом «панель VPN»;
  - позже добавим оформление, авторизацию, выдачу VLESS/VMess и т.п.

---

### Стек

- **Язык**: Python 3.12+  
- **Библиотека бота**: `aiogram`  
- **Веб‑часть**: простой HTTP‑сервер на `FastAPI` (можно заменить на другой фреймворк при желании).

---

### Структура проекта

```text
vpn@vpn/
  bot/
    README.md          # эта инструкция
    bot.py             # Telegram-бот
    webapp.py          # FastAPI-приложение (WebApp)
    templates/
      index.html       # страница для WebApp
```

---

### Установка зависимостей

Внутри папки `bot` (на сервере или локально):

```bash
cd vpn@vpn/bot
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install aiogram fastapi uvicorn jinja2
```

---

### Настройка переменных

В файле `bot.py` нужно будет указать:

- токен бота `BOT_TOKEN` (получить у `@BotFather`),
- URL WebApp `WEB_APP_URL` (пока можно использовать `http://IP_СЕРВЕРА:8000/`).

---

### Запуск

1. Запустить WebApp:

```bash
source venv/bin/activate
python webapp.py
# или
uvicorn webapp:app --host 0.0.0.0 --port 8000
```

2. Запустить бота:

```bash
source venv/bin/activate
python bot.py
```

3. В Telegram:
   - найти своего бота,
   - отправить `/start`,
   - нажать кнопку **«Открыть VPN панель»** — должна открыться встроенная страница.

---

### Единый запуск в одном screen (сервер)

Если хочешь поднимать и `webapp`, и `bot` одной командой в одном `screen`:

```bash
cd /opt/ecox2vpn
chmod +x run_all_in_screen.sh stop_all_in_screen.sh
./run_all_in_screen.sh
```

Проверка:

```bash
screen -ls
screen -r ecox2vpn
```

Логи:

```bash
tail -f /tmp/ecox2vpn-webapp.log
tail -f /tmp/ecox2vpn-bot.log
```

Остановка:

```bash
./stop_all_in_screen.sh
```

---

### Дальнейшие шаги

1. Подключить реальную авторизацию через `initData` Telegram WebApp.
2. Привязать аккаунты Telegram к UUID VLESS/VMess.
3. Реализовать:
   - выдачу/просмотр ключей,
   - статус подписки,
   - лимиты трафика и сроков,
   - интеграцию с Xray (изменение `config.json` или вызовы API).

