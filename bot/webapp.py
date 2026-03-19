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
XRAY_ERROR_LOG_PATH = os.getenv("XRAY_ERROR_LOG_PATH", "/var/log/xray/error.log")
XRAY_ACCESS_LOG_PATH = os.getenv("XRAY_ACCESS_LOG_PATH", "/var/log/xray/access.log")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
CHANNEL_CAPACITY_MBPS = float(os.getenv("CHANNEL_CAPACITY_MBPS", "1000"))
AVG_USER_MBPS = float(os.getenv("AVG_USER_MBPS", "3"))
_CAPACITY_RESERVE_COEFF = 0.6
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_stats (
              ts INTEGER PRIMARY KEY,
              bytes_in INTEGER NOT NULL,
              bytes_out INTEGER NOT NULL
            )
            """
        )


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
            "SELECT uuid, sub_token, created_at, updated_at FROM subscriptions WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
    if not row:
        return None
    return {"uuid": row[0], "sub_token": row[1], "created_at": row[2], "updated_at": row[3]}


def _get_or_create_sub_token(tg_id: int) -> str:
    _ensure_db()
    now = int(time.time())
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT sub_token FROM subscriptions WHERE tg_id = ?",
            (tg_id,),
        ).fetchone()
        if row and row[0]:
            return str(row[0])
        token = os.urandom(16).hex()
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


def _set_subscription(tg_id: int, uuid: str) -> None:
    _ensure_db()
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


def _build_vless_ws_uri(uuid: str) -> str | None:
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
    query = "&".join(params)
    return f"vless://{uuid}@{host}:{port}?{query}#ecox2vpn-ws"


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


def _read_last_lines(path: str, limit: int = 200) -> list[str]:
    if not os.path.exists(path):
        return []
    # simple and robust: read whole file and take tail
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []
    return [ln.rstrip("\n") for ln in lines[-limit:]]


def _build_uuid_map() -> dict[str, int]:
    _ensure_db()
    out: dict[str, int] = {}
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT tg_id, uuid FROM subscriptions").fetchall()
    for tg_id, sub_uuid in rows:
        if sub_uuid:
            out[str(sub_uuid)] = int(tg_id)
    return out


def _parse_access_log() -> list[dict[str, Any]]:
    """
    Best-effort parser for Xray access log.
    Expects lines containing at least date, optional email with tg:ID,
    and bytes_in/bytes_out fields, e.g. 'bytes_in=123 bytes_out=456 email=tg:12345'.
    """
    if not os.path.exists(XRAY_ACCESS_LOG_PATH):
        return []
    entries: list[dict[str, Any]] = []
    now = time.time()
    week_ago = now - 7 * 24 * 3600
    import re

    with open(XRAY_ACCESS_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ln = line.strip()
            if not ln:
                continue
            # find date (YYYY-MM-DD)
            m_date = re.search(r"(\d{4})-(\d{2})-(\d{2})", ln)
            if not m_date:
                continue
            year, month, day = map(int, m_date.groups())
            try:
                ts = int(time.mktime((year, month, day, 0, 0, 0, 0, 0, -1)))
            except Exception:
                continue
            if ts < week_ago:
                # we are only interested in ~last week for aggregates
                continue

            # bytes_in / bytes_out
            m_in = re.search(r"bytes_in=(\d+)", ln)
            m_out = re.search(r"bytes_out=(\d+)", ln)
            if not m_in or not m_out:
                continue
            bytes_in = int(m_in.group(1))
            bytes_out = int(m_out.group(1))

            # email with tg:ID
            m_email = re.search(r"email=([^\s]+)", ln)
            tg_id: int | None = None
            if m_email:
                email = m_email.group(1)
                if "tg:" in email:
                    try:
                        tg_id = int(email.split("tg:")[1].split("@")[0].split(":")[-1])
                    except Exception:
                        tg_id = None

            # try to detect IP
            m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ln)
            ip = m_ip.group(1) if m_ip else None

            entries.append(
                {
                    "ts": ts,
                    "bytes_in": bytes_in,
                    "bytes_out": bytes_out,
                    "tg_id": tg_id,
                    "ip": ip,
                }
            )
    return entries


def _update_traffic_stats_from_log() -> None:
    entries = _parse_access_log()
    if not entries:
        return
    _ensure_db()
    bins: dict[int, dict[str, int]] = {}
    for e in entries:
        ts = int(e["ts"])
        bin_ts = (ts // 300) * 300
        b = bins.setdefault(bin_ts, {"bytes_in": 0, "bytes_out": 0})
        b["bytes_in"] += int(e["bytes_in"])
        b["bytes_out"] += int(e["bytes_out"])
    with sqlite3.connect(DB_PATH) as conn:
        for ts, vals in bins.items():
            conn.execute(
                """
                INSERT INTO traffic_stats (ts, bytes_in, bytes_out)
                VALUES (?, ?, ?)
                ON CONFLICT(ts) DO UPDATE SET
                    bytes_in = bytes_in + excluded.bytes_in,
                    bytes_out = bytes_out + excluded.bytes_out
                """,
                (ts, vals["bytes_in"], vals["bytes_out"]),
            )


def _collect_user_traffic() -> dict[int, dict[str, Any]]:
    entries = _parse_access_log()
    now = time.time()
    today_start = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1))
    week_ago = now - 7 * 24 * 3600
    out: dict[int, dict[str, Any]] = {}
    for e in entries:
        tg_id = e.get("tg_id")
        if not tg_id:
            continue
        ts = float(e["ts"])
        bytes_in = int(e["bytes_in"])
        bytes_out = int(e["bytes_out"])
        total = bytes_in + bytes_out
        u = out.setdefault(
            int(tg_id),
            {
                "bytes_day": 0,
                "bytes_week": 0,
                "sessions": 0,
                "last_ip": None,
                "last_seen_at": 0,
            },
        )
        if ts >= today_start:
            u["bytes_day"] += total
        if ts >= week_ago:
            u["bytes_week"] += total
        u["sessions"] += 1
        if ts >= u["last_seen_at"]:
            u["last_seen_at"] = int(ts)
            if e.get("ip"):
                u["last_ip"] = e["ip"]
    return out


def _get_subscription_by_token(sub_token: str) -> dict[str, Any] | None:
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT tg_id, uuid FROM subscriptions WHERE sub_token = ?",
            (sub_token,),
        ).fetchone()
    if not row:
        return None
    return {"tg_id": int(row[0]), "uuid": row[1]}


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


@app.get("/sub/{token}")
async def sub_feed(token: str):
    token = token.strip()
    if not token:
        raise HTTPException(status_code=404, detail="not found")
    sub = _get_subscription_by_token(token)
    if not sub or not sub.get("uuid"):
        # пустая подписка — клиента не ломаем, но и ничего не даём
        return HTMLResponse(content="", media_type="text/plain")
    uuid = sub["uuid"]
    urls: list[str] = []
    tcp_uri = _build_vless_uri(uuid)
    if tcp_uri:
        urls.append(tcp_uri)
    ws_uri = _build_vless_ws_uri(uuid)
    if ws_uri:
        urls.append(ws_uri)
    body = "\n".join(urls)
    return HTMLResponse(content=body, media_type="text/plain")

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
    sub_url: str | None = None
    if sub and not state.get("disabled"):
        token = sub.get("sub_token") or _get_or_create_sub_token(tg_id)
        sub_url = f"{WEB_APP_URL.rstrip('/')}/sub/{token}"
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
            "subscription_url": sub_url,
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
    uuid_val: str | None = None
    created = False
    if existing and existing.get("uuid"):
        uuid_val = str(existing["uuid"])
    else:
        # generate UUID v4 (no deps)
        import uuid as _uuid

        uuid_val = str(_uuid.uuid4())
        _set_subscription(tg_id, uuid_val)
        created = True

    # Real provisioning to Xray (idempotent)
    email = user.get("username") or f"tg:{tg_id}"
    _xray_add_client(uuid_val, str(email))

    token = _get_or_create_sub_token(tg_id)
    sub_url = f"{WEB_APP_URL.rstrip('/')}/sub/{token}"

    return JSONResponse(
        {
            "ok": True,
            "uuid": uuid_val,
            "subscription_url": sub_url,
            "existing": not created,
        }
    )


@app.post("/api/admin/users")
async def api_admin_users(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT u.tg_id,
                   u.username,
                   u.first_name,
                   u.last_name,
                   u.last_seen_at,
                   u.disabled,
                   u.disabled_reason,
                   s.uuid,
                   s.sub_token,
                   s.updated_at
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
                "sub_token": r[8],
                "sub_updated_at": r[9],
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
    if sub and sub.get("uuid"):
        _xray_remove_client(sub["uuid"])
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE subscriptions SET uuid = NULL, updated_at = strftime('%s','now') WHERE tg_id = ?",
            (tg_id,),
        )
    return JSONResponse({"ok": True})


@app.post("/api/admin/errors")
async def api_admin_errors(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    lines = _read_last_lines(XRAY_ERROR_LOG_PATH, limit=300)
    uuid_map = _build_uuid_map()
    user_cache: dict[int, dict[str, Any]] = {}

    def user_by_tg_id(tg_id: int) -> dict[str, Any]:
        if tg_id in user_cache:
            return user_cache[tg_id]
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT tg_id, username, first_name, last_name FROM users WHERE tg_id = ?",
                (tg_id,),
            ).fetchone()
        user_cache[tg_id] = {
            "tg_id": row[0],
            "username": row[1],
            "first_name": row[2],
            "last_name": row[3],
        } if row else {"tg_id": tg_id}
        return user_cache[tg_id]

    # keep only suspicious/error-like lines
    lowered_needles = ("error", "failed", "timeout", "broken", "refused", "reset", "invalid")
    filtered = [ln for ln in lines if any(n in ln.lower() for n in lowered_needles)]

    items: list[dict[str, Any]] = []
    for ln in filtered[-120:]:
        matched_uuid = None
        matched_user = None
        for sub_uuid, tg_id in uuid_map.items():
            if sub_uuid in ln:
                matched_uuid = sub_uuid
                matched_user = user_by_tg_id(tg_id)
                break
        items.append(
            {
                "line": ln,
                "uuid": matched_uuid,
                "user": matched_user,
            }
        )
    items.reverse()
    return JSONResponse({"ok": True, "errors": items, "source": XRAY_ERROR_LOG_PATH})


@app.get("/api/admin/overview")
async def api_admin_overview(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)

    # CPU / RAM
    cpu_usage = 0.0
    ram_usage = 0.0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            meminfo = f.read()
        import re

        m_total = re.search(r"MemTotal:\s+(\d+)", meminfo)
        m_avail = re.search(r"MemAvailable:\s+(\d+)", meminfo)
        if m_total and m_avail:
            total_kb = float(m_total.group(1))
            avail_kb = float(m_avail.group(1))
            used_kb = max(total_kb - avail_kb, 1.0)
            ram_usage = used_kb / total_kb * 100.0
    except Exception:
        ram_usage = 0.0

    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            first = f.readline()
        parts = first.split()
        if parts[0].startswith("cpu") and len(parts) >= 5:
            user, nice, system, idle, *rest = map(float, parts[1:])
            idle_all = idle
            non_idle = user + nice + system + sum(rest[:3]) if len(rest) >= 3 else user + nice + system
            total = idle_all + non_idle
            # simple snapshot approximation
            cpu_usage = (non_idle / total) * 100.0 if total else 0.0
    except Exception:
        cpu_usage = 0.0

    # traffic
    _update_traffic_stats_from_log()
    entries = _parse_access_log()
    now = time.time()
    today_start = time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1))
    traffic_today_bytes = 0
    for e in entries:
        if e["ts"] >= today_start:
            traffic_today_bytes += int(e["bytes_in"]) + int(e["bytes_out"])

    traffic_today_mb = traffic_today_bytes / (1024 * 1024)

    # stats from traffic_stats for last 24h and last 30/10 minutes
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT ts, bytes_in, bytes_out FROM traffic_stats WHERE ts >= ? ORDER BY ts",
            (int(now) - 24 * 3600,),
        ).fetchall()

    peak_mbps = 0.0
    recent_points: list[tuple[int, int]] = []
    for ts, bi, bo in rows:
        total_bytes = int(bi) + int(bo)
        mbps = total_bytes * 8.0 / 300.0 / 1_000_000.0
        if mbps > peak_mbps:
            peak_mbps = mbps
        if ts >= int(now) - 10 * 60:
            recent_points.append((ts, total_bytes))

    if not recent_points and rows:
        # если за последние 10 минут нет данных — берём последние 30 минут
        for ts, bi, bo in rows:
            if ts >= int(now) - 30 * 60:
                recent_points.append((ts, int(bi) + int(bo)))

    traffic_avg_mbps_10m = 0.0
    if recent_points:
        total_bytes_recent = sum(v for _, v in recent_points)
        duration = len(recent_points) * 300.0
        if duration > 0:
            traffic_avg_mbps_10m = total_bytes_recent * 8.0 / duration / 1_000_000.0

    capacity_used_percent = (peak_mbps / CHANNEL_CAPACITY_MBPS * 100.0) if CHANNEL_CAPACITY_MBPS > 0 else 0.0
    recommended_active_users = (CHANNEL_CAPACITY_MBPS / AVG_USER_MBPS * _CAPACITY_RESERVE_COEFF) if AVG_USER_MBPS > 0 else 0.0

    return JSONResponse(
        {
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "traffic_today_mb": traffic_today_mb,
            "traffic_peak_mbps": peak_mbps,
            "traffic_avg_mbps_10m": traffic_avg_mbps_10m,
            "capacity_used_percent": capacity_used_percent,
            "recommended_active_users": recommended_active_users,
        }
    )


@app.get("/api/admin/traffic/users")
async def api_admin_traffic_users(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    by_user = _collect_user_traffic()
    if not by_user:
        return JSONResponse({"users": []})
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        # fetch basic profile info
        users_map: dict[int, dict[str, Any]] = {}
        tg_ids = list(by_user.keys())
        placeholders = ",".join("?" for _ in tg_ids)
        rows = conn.execute(
            f"SELECT tg_id, username, first_name, last_name FROM users WHERE tg_id IN ({placeholders})",
            tg_ids,
        ).fetchall()
        for row in rows:
            users_map[int(row[0])] = {
                "tg_id": int(row[0]),
                "username": row[1],
                "first_name": row[2],
                "last_name": row[3],
            }

    users_out: list[dict[str, Any]] = []
    for tg_id, stats in by_user.items():
        base = users_map.get(
            tg_id,
            {"tg_id": tg_id, "username": None, "first_name": None, "last_name": None},
        )
        users_out.append(
            {
                "tg_id": tg_id,
                "username": base.get("username"),
                "first_name": base.get("first_name"),
                "last_name": base.get("last_name"),
                "traffic_day_mb": stats["bytes_day"] / (1024 * 1024),
                "traffic_week_mb": stats["bytes_week"] / (1024 * 1024),
                "sessions": stats["sessions"],
                "last_ip": stats["last_ip"],
                "last_seen_at": stats["last_seen_at"],
            }
        )
    return JSONResponse({"users": users_out})


@app.get("/api/admin/traffic/timeseries")
async def api_admin_traffic_timeseries(credentials: HTTPBasicCredentials = Depends(security)):
    _require_admin_basic(credentials)
    _update_traffic_stats_from_log()
    now = int(time.time())
    _ensure_db()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT ts, bytes_in, bytes_out FROM traffic_stats WHERE ts >= ? ORDER BY ts",
            (now - 24 * 3600,),
        ).fetchall()
    points: list[dict[str, Any]] = []
    for ts, bi, bo in rows:
        total_bytes = int(bi) + int(bo)
        mbps = total_bytes * 8.0 / 300.0 / 1_000_000.0
        points.append({"ts": int(ts), "mbps": mbps})
    return JSONResponse({"points": points})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("webapp:app", host="0.0.0.0", port=8000, reload=True)

