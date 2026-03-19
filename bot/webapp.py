import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import time
from typing import Any
from urllib.parse import parse_qsl

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")

app = FastAPI()

# static каталог может пока не существовать — монтируем только если есть
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_APP_URL = os.getenv("WEB_APP_URL", "https://ecox2vpn.online/")
V2RAYTUN_DOWNLOAD_URL = os.getenv("V2RAYTUN_DOWNLOAD_URL", "https://apps.apple.com/app/v2raytun/id6476628951")
VLESS_HOST = os.getenv("VLESS_HOST", "ecox2vpn.online")
VLESS_PORT = int(os.getenv("VLESS_PORT", "4433"))
VLESS_TRANSPORT = os.getenv("VLESS_TRANSPORT", "tcp")
VLESS_TLS = os.getenv("VLESS_TLS", "none")

XRAY_CONFIG_PATH = os.getenv("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json")
XRAY_SYSTEMD_SERVICE = os.getenv("XRAY_SYSTEMD_SERVICE", "xray")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
security = HTTPBasic()


def _ensure_db() -> None:
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


def _telegram_webapp_check(init_data: str, bot_token: str) -> dict[str, Any]:
    """
    Validate Telegram WebApp initData per docs:
    https://core.telegram.org/bots/webapps#validating-data-received-via-the-web-app
    """
    if not bot_token:
        raise HTTPException(status_code=500, detail="Server missing BOT_TOKEN")
    if not init_data:
        raise HTTPException(status_code=401, detail="Missing initData")

    pairs = list(parse_qsl(init_data, keep_blank_values=True))
    data = dict(pairs)
    recv_hash = data.pop("hash", None)
    if not recv_hash:
        raise HTTPException(status_code=401, detail="Missing hash")

    # build data_check_string: key=value sorted by key, joined with \n
    data_check_string = "\n".join(f"{k}={data[k]}" for k in sorted(data.keys()))

    secret_key = hmac.new(
        key=b"WebAppData",
        msg=bot_token.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    calc_hash = hmac.new(
        key=secret_key,
        msg=data_check_string.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(calc_hash, recv_hash):
        raise HTTPException(status_code=401, detail="Bad initData signature")

    # basic freshness check (optional but useful)
    try:
        auth_date = int(data.get("auth_date", "0"))
    except ValueError:
        raise HTTPException(status_code=401, detail="Bad auth_date")
    if auth_date and (time.time() - auth_date) > 60 * 60 * 24:
        raise HTTPException(status_code=401, detail="initData is too old")

    try:
        user = json.loads(data.get("user", "{}"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=401, detail="Bad user payload")
    if not user or "id" not in user:
        raise HTTPException(status_code=401, detail="Missing user")

    return user


def _upsert_user(user: dict[str, Any]) -> None:
    _ensure_db()
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
                int(user["id"]),
                user.get("username"),
                user.get("first_name"),
                user.get("last_name"),
                user.get("photo_url"),
                now,
                now,
            ),
        )

def _get_user_state(tg_id: int) -> dict[str, Any] | None:
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT tg_id, username, first_name, last_name, photo_url, created_at, last_seen_at, disabled, disabled_at, disabled_reason "
            "FROM users WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "tg_id": row[0],
        "username": row[1],
        "first_name": row[2],
        "last_name": row[3],
        "photo_url": row[4],
        "created_at": row[5],
        "last_seen_at": row[6],
        "disabled": bool(row[7]),
        "disabled_at": row[8],
        "disabled_reason": row[9],
    }

def _require_admin_basic(credentials: HTTPBasicCredentials) -> None:
    if not ADMIN_PASSWORD:
        raise HTTPException(status_code=500, detail="ADMIN_PASSWORD is not configured")
    ok_user = hmac.compare_digest(credentials.username, ADMIN_USERNAME)
    ok_pass = hmac.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


def _get_subscription(tg_id: int) -> dict[str, Any] | None:
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT uuid, created_at, updated_at FROM subscriptions WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
    if not row:
        return None
    return {"uuid": row[0], "created_at": row[1], "updated_at": row[2]}


def _set_subscription(tg_id: int, uuid: str) -> None:
    _ensure_db()
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO subscriptions (tg_id, uuid, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(tg_id) DO UPDATE SET
                uuid=excluded.uuid,
                updated_at=excluded.updated_at
            """,
            (tg_id, uuid, now, now),
        )


def _build_vless_uri(uuid: str) -> str:
    params = []
    if VLESS_TLS and VLESS_TLS != "none":
        params.append(f"security={VLESS_TLS}")
    params.append("encryption=none")
    params.append(f"type={VLESS_TRANSPORT}")
    query = "&".join(params)
    return f"vless://{uuid}@{VLESS_HOST}:{VLESS_PORT}?{query}#ecox2vpn"


def _xray_add_client(uuid: str, email: str) -> None:
    """
    Best-effort provisioning: add UUID to VLESS inbound clients and reload xray.
    Expects json config with at least one inbound protocol=vless and settings.clients list.
    """
    try:
        with open(XRAY_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read xray config: {e}")

    inbounds = cfg.get("inbounds") or []
    vless_inbounds = [ib for ib in inbounds if ib.get("protocol") == "vless"]
    if not vless_inbounds:
        raise HTTPException(status_code=500, detail="No VLESS inbound found in xray config")

    inbound = vless_inbounds[0]
    settings = inbound.setdefault("settings", {})
    clients = settings.setdefault("clients", [])

    # idempotent: if uuid already exists, do nothing
    for c in clients:
        if c.get("id") == uuid:
            return

    clients.append({"id": uuid, "email": email})

    try:
        tmp_path = XRAY_CONFIG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, XRAY_CONFIG_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write xray config: {e}")

    # reload xray
    try:
        subprocess.run(
            ["systemctl", "reload", XRAY_SYSTEMD_SERVICE],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["systemctl", "restart", XRAY_SYSTEMD_SERVICE],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        # don't fail hard if systemctl is unavailable
        pass

def _xray_remove_client(uuid: str) -> None:
    try:
        with open(XRAY_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read xray config: {e}")

    inbounds = cfg.get("inbounds") or []
    changed = False
    for ib in inbounds:
        if ib.get("protocol") != "vless":
            continue
        settings = ib.get("settings") or {}
        clients = settings.get("clients") or []
        new_clients = [c for c in clients if c.get("id") != uuid]
        if len(new_clients) != len(clients):
            settings["clients"] = new_clients
            ib["settings"] = settings
            changed = True

    if not changed:
        return

    try:
        tmp_path = XRAY_CONFIG_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, XRAY_CONFIG_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write xray config: {e}")

    try:
        subprocess.run(["systemctl", "reload", XRAY_SYSTEMD_SERVICE], check=False)
        subprocess.run(["systemctl", "restart", XRAY_SYSTEMD_SERVICE], check=False)
    except Exception:
        pass


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "web_app_url": WEB_APP_URL,
            "v2raytun_download_url": V2RAYTUN_DOWNLOAD_URL,
        },
    )

@app.get("/guide", response_class=HTMLResponse)
async def guide(request: Request):
    return templates.TemplateResponse(
        "guide.html",
        {
            "request": request,
            "v2raytun_download_url": V2RAYTUN_DOWNLOAD_URL,
        },
    )

@app.get("/api/ping")
async def api_ping():
    return JSONResponse({"ok": True, "ts": int(time.time() * 1000)})

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "web_app_url": WEB_APP_URL,
        },
    )


@app.post("/api/me")
async def api_me(payload: dict[str, Any]):
    init_data = payload.get("initData") or ""
    user = _telegram_webapp_check(init_data, BOT_TOKEN)
    _upsert_user(user)
    tg_id = int(user["id"])
    state = _get_user_state(tg_id) or {"disabled": False}
    sub = _get_subscription(tg_id)
    return JSONResponse(
        {
            "ok": True,
            "user": {
                "id": tg_id,
                "username": user.get("username"),
                "first_name": user.get("first_name"),
                "last_name": user.get("last_name"),
                "photo_url": user.get("photo_url"),
            },
            "disabled": bool(state.get("disabled")),
            "disabled_reason": state.get("disabled_reason"),
            "subscription": sub,
            "vless_uri": _build_vless_uri(sub["uuid"]) if (sub and not state.get("disabled")) else None,
        }
    )


@app.post("/api/vpn/create")
async def api_vpn_create(payload: dict[str, Any]):
    init_data = payload.get("initData") or ""
    user = _telegram_webapp_check(init_data, BOT_TOKEN)
    _upsert_user(user)
    tg_id = int(user["id"])
    state = _get_user_state(tg_id)
    if state and state.get("disabled"):
        raise HTTPException(status_code=403, detail="Access disabled by admin")

    existing = _get_subscription(tg_id)
    if existing:
        return JSONResponse(
            {
                "ok": True,
                "uuid": existing["uuid"],
                "vless_uri": _build_vless_uri(existing["uuid"]),
                "existing": True,
            }
        )

    # generate UUID v4 (no deps)
    import uuid as _uuid

    new_uuid = str(_uuid.uuid4())
    _set_subscription(tg_id, new_uuid)

    # Real provisioning to Xray
    email = user.get("username") or f"tg:{tg_id}"
    _xray_add_client(new_uuid, str(email))

    return JSONResponse(
        {
            "ok": True,
            "uuid": new_uuid,
            "vless_uri": _build_vless_uri(new_uuid),
            "existing": False,
        }
    )


@app.post("/api/admin/users")
async def api_admin_users(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT u.tg_id, u.username, u.first_name, u.last_name, u.last_seen_at, u.disabled, u.disabled_reason,
                   s.uuid, s.updated_at
            FROM users u
            LEFT JOIN subscriptions s ON s.tg_id = u.tg_id
            ORDER BY u.last_seen_at DESC
            LIMIT 500
            """
        ).fetchall()
    items = []
    for r in rows:
        items.append(
            {
                "tg_id": r[0],
                "username": r[1],
                "first_name": r[2],
                "last_name": r[3],
                "last_seen_at": r[4],
                "disabled": bool(r[5]),
                "disabled_reason": r[6],
                "uuid": r[7],
                "sub_updated_at": r[8],
            }
        )
    return JSONResponse({"ok": True, "users": items})


@app.post("/api/admin/user/disable")
async def api_admin_disable(payload: dict[str, Any], credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    tg_id = int(payload.get("tg_id") or 0)
    reason = str(payload.get("reason") or "").strip()[:200]
    if tg_id <= 0:
        raise HTTPException(status_code=400, detail="Bad tg_id")
    _ensure_db()
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET disabled = 1, disabled_at = ?, disabled_reason = ? WHERE tg_id = ?",
            (now, reason or None, tg_id),
        )
    sub = _get_subscription(tg_id)
    if sub:
        _xray_remove_client(sub["uuid"])
    return JSONResponse({"ok": True})


@app.post("/api/admin/user/enable")
async def api_admin_enable(payload: dict[str, Any], credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    tg_id = int(payload.get("tg_id") or 0)
    if tg_id <= 0:
        raise HTTPException(status_code=400, detail="Bad tg_id")
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET disabled = 0, disabled_at = NULL, disabled_reason = NULL WHERE tg_id = ?",
            (tg_id,),
        )
    # do not auto-readd; user can re-create or admin can re-add later
    return JSONResponse({"ok": True})


@app.post("/api/admin/user/revoke_key")
async def api_admin_revoke_key(payload: dict[str, Any], credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    tg_id = int(payload.get("tg_id") or 0)
    if tg_id <= 0:
        raise HTTPException(status_code=400, detail="Bad tg_id")
    sub = _get_subscription(tg_id)
    if sub:
        _xray_remove_client(sub["uuid"])
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM subscriptions WHERE tg_id = ?", (tg_id,))
    return JSONResponse({"ok": True})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=True)

