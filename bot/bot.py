import asyncio
import json
import os
import sqlite3
import subprocess
import time
import uuid

from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart, Command
from aiogram.types import Message
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_APP_URL = os.getenv("WEB_APP_URL", "https://ecox2vpn.online/")
VLESS_HOST = os.getenv("VLESS_HOST", "ecox2vpn.online")
VLESS_PORT = int(os.getenv("VLESS_PORT", "4433"))
VLESS_TRANSPORT = os.getenv("VLESS_TRANSPORT", "tcp")
VLESS_TLS = os.getenv("VLESS_TLS", "none")
XRAY_CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json")
XRAY_SYSTEMD_SERVICE = os.getenv("XRAY_SYSTEMD_SERVICE", "xray")


def ensure_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                tg_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                photo_url TEXT,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                disabled_at INTEGER,
                disabled_reason TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                tg_id INTEGER PRIMARY KEY,
                uuid TEXT NOT NULL,
                sub_token TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (tg_id) REFERENCES users(tg_id)
            )
            """
        )
        # lightweight migrations for existing installs
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "last_seen_at" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0")
        if "disabled" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
        if "disabled_at" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN disabled_at INTEGER")
        if "disabled_reason" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN disabled_reason TEXT")
        sub_cols = {r[1] for r in conn.execute("PRAGMA table_info(subscriptions)").fetchall()}
        if "sub_token" not in sub_cols:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN sub_token TEXT")


def upsert_user(message: Message) -> None:
    ensure_db()
    u = message.from_user
    if not u:
        return
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO users (tg_id, username, first_name, last_name, photo_url, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tg_id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name,
                last_name=excluded.last_name,
                photo_url=excluded.photo_url,
                last_seen_at=excluded.last_seen_at
            """,
            (
                int(u.id),
                u.username,
                u.first_name,
                u.last_name,
                None,
                now,
                now,
            ),
        )


def get_user_disabled(tg_id: int) -> tuple[bool, str | None]:
    ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT disabled, disabled_reason FROM users WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
    if not row:
        return False, None
    return bool(row[0]), row[1]


def get_subscription(tg_id: int) -> dict | None:
    ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT uuid, sub_token, created_at, updated_at FROM subscriptions WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
    if not row:
        return None
    return {"uuid": row[0], "sub_token": row[1], "created_at": row[2], "updated_at": row[3]}


def set_subscription(tg_id: int, sub_uuid: str) -> None:
    ensure_db()
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO subscriptions (tg_id, uuid, sub_token, created_at, updated_at)
            VALUES (?, ?, NULL, ?, ?)
            ON CONFLICT(tg_id) DO UPDATE SET
                uuid=excluded.uuid,
                updated_at=excluded.updated_at
            """,
            (tg_id, sub_uuid, now, now),
        )


def clear_subscription_uuid(tg_id: int) -> None:
    ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE subscriptions SET uuid = NULL, updated_at = strftime('%s','now') WHERE tg_id = ?",
            (tg_id,),
        )


def build_vless_uri(sub_uuid: str) -> str:
    params = []
    if VLESS_TLS and VLESS_TLS != "none":
        params.append(f"security={VLESS_TLS}")
    params.append("encryption=none")
    params.append(f"type={VLESS_TRANSPORT}")
    return f"vless://{sub_uuid}@{VLESS_HOST}:{VLESS_PORT}?{'&'.join(params)}#ecox2vpn"


def build_vless_ws_uri(sub_uuid: str) -> str | None:
    host = os.getenv("VLESS_WS_HOST", VLESS_HOST)
    port = int(os.getenv("VLESS_WS_PORT", "0") or "0")
    path = os.getenv("VLESS_WS_PATH", "/ws")
    security = os.getenv("VLESS_WS_SECURITY", "tls")
    if not port:
        return None
    params = [
        "encryption=none",
        "type=ws",
        f"path={path}",
    ]
    if security and security != "none":
        params.append(f"security={security}")
    return f"vless://{sub_uuid}@{host}:{port}?{'&'.join(params)}#ecox2vpn-ws"


def get_or_create_sub_token(tg_id: int) -> str:
    ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT sub_token FROM subscriptions WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
        if row and row[0]:
            return row[0]
        token = os.urandom(16).hex()
        now = int(time.time())
        conn.execute(
            """
            INSERT INTO subscriptions (tg_id, uuid, sub_token, created_at, updated_at)
            VALUES (
                ?,
                COALESCE((SELECT uuid FROM subscriptions WHERE tg_id = ?), NULL),
                ?,
                COALESCE((SELECT created_at FROM subscriptions WHERE tg_id = ?), ?),
                ?
            )
            ON CONFLICT(tg_id) DO UPDATE SET
                sub_token=excluded.sub_token,
                updated_at=excluded.updated_at
            """,
            (tg_id, tg_id, token, tg_id, now, now),
        )
        return token


def xray_add_client(sub_uuid: str, email: str) -> None:
    with open(XRAY_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    inbounds = cfg.get("inbounds") or []
    vless = next((x for x in inbounds if x.get("protocol") == "vless"), None)
    if not vless:
        raise RuntimeError("No VLESS inbound found in xray config")
    settings = vless.setdefault("settings", {})
    clients = settings.setdefault("clients", [])
    if not any(c.get("id") == sub_uuid for c in clients):
        clients.append({"id": sub_uuid, "email": email})
    tmp = XRAY_CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, XRAY_CONFIG_PATH)
    subprocess.run(["systemctl", "reload", XRAY_SYSTEMD_SERVICE], check=False)
    subprocess.run(["systemctl", "restart", XRAY_SYSTEMD_SERVICE], check=False)


def xray_remove_client(sub_uuid: str) -> None:
    with open(XRAY_CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    changed = False
    for ib in cfg.get("inbounds") or []:
        if ib.get("protocol") != "vless":
            continue
        settings = ib.get("settings") or {}
        clients = settings.get("clients") or []
        new_clients = [c for c in clients if c.get("id") != sub_uuid]
        if len(new_clients) != len(clients):
            settings["clients"] = new_clients
            ib["settings"] = settings
            changed = True
    if changed:
        tmp = XRAY_CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, XRAY_CONFIG_PATH)
        subprocess.run(["systemctl", "reload", XRAY_SYSTEMD_SERVICE], check=False)
        subprocess.run(["systemctl", "restart", XRAY_SYSTEMD_SERVICE], check=False)


async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError("Missing BOT_TOKEN (set in .env or env var)")

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        upsert_user(message)
        await message.answer(
            "Добро пожаловать в ecox2vpn.\n\n"
            "Команды:\n"
            "/vpn — получить ссылку подписки\n"
            "/mykey — как управлять ключом\n"
            "/revoke — удалить текущий ключ\n"
            "/app — открыть личный кабинет"
        )

    @dp.message(Command("app"))
    async def cmd_app(message: Message) -> None:
        upsert_user(message)
        await message.answer(f"Личный кабинет:\n{WEB_APP_URL}")

    @dp.message(Command("mykey"))
    async def cmd_mykey(message: Message) -> None:
        upsert_user(message)
        if not message.from_user:
            return
        await message.answer(
            "Твой VPN‑ключ теперь управляется через подписку.\n"
            "Чтобы получить ссылку подписки, используй команду /vpn."
        )

    @dp.message(Command("vpn"))
    async def cmd_vpn(message: Message) -> None:
        upsert_user(message)
        if not message.from_user:
            return
        tg_id = int(message.from_user.id)
        disabled, reason = get_user_disabled(tg_id)
        if disabled:
            await message.answer(f"Доступ отключён администратором.\n{reason or ''}".strip())
            return
        sub = get_subscription(tg_id)
        sub_uuid = sub["uuid"] if sub and sub.get("uuid") else None
        if not sub_uuid:
            sub_uuid = str(uuid.uuid4())
            try:
                email = message.from_user.username or f"tg:{tg_id}"
                xray_add_client(sub_uuid, str(email))
                set_subscription(tg_id, sub_uuid)
            except Exception as e:
                await message.answer(
                    "Не удалось создать ключ. Попробуй позже.\n"
                    f"Тех. ошибка: {e}"
                )
                return
        else:
            try:
                email = message.from_user.username or f"tg:{tg_id}"
                xray_add_client(sub_uuid, str(email))
            except Exception:
                # игнорируем, если клиент уже был добавлен или перезагрузка не удалась
                pass

        token = get_or_create_sub_token(tg_id)
        url = f"{WEB_APP_URL.rstrip('/')}/sub/{token}"
        await message.answer(f"Твоя ссылка подписки:\n{url}")

    @dp.message(Command("revoke"))
    async def cmd_revoke(message: Message) -> None:
        upsert_user(message)
        if not message.from_user:
            return
        tg_id = int(message.from_user.id)
        sub = get_subscription(tg_id)
        if not sub or not sub.get("uuid"):
            await message.answer("У тебя нет активного ключа.")
            return
        try:
            xray_remove_client(sub["uuid"])
            clear_subscription_uuid(tg_id)
        except Exception as e:
            await message.answer(f"Не удалось удалить ключ.\nТех. ошибка: {e}")
            return
        await message.answer(
            "Ключ удалён. Подписка сохранена.\n"
            "Чтобы получить новый ключ в этой же подписке, используй /vpn."
        )

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())

