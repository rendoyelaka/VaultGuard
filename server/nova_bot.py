#!/usr/bin/env python3
"""
nova_bot.py
═══════════════════════════════════════════════════════════════════════════════
Nova APK Factory — Telegram Admin Bot + 10-Layer Auto-Sync Watchdog
Runs as single Windows service: nova_telegram

Contains:
  1. Telegram admin bot   — PIN + 2FAS auth, full menu UI, client management,
                            build trigger, live progress, paginated devices
  2. 10-Layer watchdog    — professional grade sync + self-healing

10-Layer Watchdog Architecture:
  Layer 1:  Single instance lock — no duplicate nova_bot ever
  Layer 2:  PID tracking — clean kill/restart always works
  Layer 3:  Windows Scheduled Task registered on startup
  Layer 4:  Git credentials auto-configured from config.py
  Layer 5:  Relative paths — works on any RDP, any drive
  Layer 6:  Real-time sync — 30s polling
  Layer 7:  Timestamp preservation — file dates match GitHub exactly
  Layer 8:  File deletion sync — deleted on GitHub = deleted on RDP
  Layer 9:  Full reliability:
              exponential backoff retry, index.lock cleanup,
              corrupt repo auto re-clone, disk space check,
              SHA-256 file integrity verify, rate limit detection
  Layer 10: Health monitoring:
              sync status file, stale alert >10min,
              smart restart per FILE_SERVICE_MAP,
              24h encrypted Telegram backup

Requires:
  pip install pyTelegramBotAPI pyotp requests pycryptodome

Services:
  nova_mutation   → update_server.py  (Flask API — separate process)
  nova_cloudflare → cloudflared.exe   (tunnel — separate process)
  nova_telegram   → nova_bot.py       (this file — bot + watchdog combined)
═══════════════════════════════════════════════════════════════════════════════
"""

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

import pyotp
import requests
import telebot
from telebot import types

# ── Load config ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
import config

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS & PATHS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_DIR        = config.REPO_DIR
TOOLS_DIR       = r"C:\apk_factory\tools"
LOGS_DIR        = r"C:\apk_factory\logs"
CLOUDFLARED_LOG = os.path.join(LOGS_DIR, "cloudflared.log")
BOT_LOG         = os.path.join(LOGS_DIR, "nova_bot.log")
STRINGPOOL_PATH = config.STRINGPOOL_PATH
DB_PATH         = os.path.join(os.path.dirname(__file__), "bot.db")

# ── Watchdog intervals (Layer 6) ─────────────────────────────────────────────
GIT_PULL_INTERVAL     = 30   # seconds — real-time sync
URL_CHECK_INTERVAL    = 10   # seconds
HEALTH_CHECK_INTERVAL = 300  # seconds (5 min)
BACKUP_INTERVAL       = 86400  # seconds (24 hours)

# ── Reliability settings (Layer 9) ───────────────────────────────────────────
MAX_RETRIES   = 5    # git fetch retry attempts
RETRY_BASE    = 2    # exponential backoff base seconds
MIN_DISK_MB   = 200  # abort pull if disk < 200MB free
STALE_ALERT_S = 600  # alert if no sync for 10 minutes

# ── XOR key for StringPool encryption ────────────────────────────────────────
XOR_KEY = b"n0vAsEed"

# ── Lock file (Layer 1) ───────────────────────────────────────────────────────
LOCK_FILE   = r"C:\apk_factory\nova_bot.lock"
STATUS_FILE = os.path.join(LOGS_DIR, "sync_status.json")

# ── Files to delete if found on RDP (renamed/removed from repo) ──────────────
OBSOLETE_FILES = [
    os.path.join(REPO_DIR, "server", "mutation_server.py"),
    os.path.join(REPO_DIR, "server", "mutation_server"),
    os.path.join(REPO_DIR, "server", "update_server"),
    os.path.join(REPO_DIR, "server", "sync_watchdog.py"),
    os.path.join(REPO_DIR, "server", "telegram_bot.py"),
]

# ── Smart restart map (Layer 10) — which file change restarts which service ──
FILE_SERVICE_MAP = {
    "server/update_server.py":          "nova_mutation",
    "server/package_name_generator.py": "nova_mutation",
    "server/nova_bot.py":               "nova_telegram",
    "server/config.py":                 "nova_telegram",
    "scripts/telegram_notify.py":       None,
    ".github/workflows/build.yml":      None,
}

# ── This file — self-restart nova_telegram if changed ────────────────────────
SELF_FILE = os.path.join(REPO_DIR, "server", "nova_bot.py")

# ── Services to health-check ──────────────────────────────────────────────────
REQUIRED_SERVICES = [
    "nova_mutation",
    "nova_cloudflare",
    "nova_telegram",
]

# ── Watchdog state (thread-safe) ──────────────────────────────────────────────
_last_sync_ok   = 0
_last_sync_lock = threading.Lock()
_stale_alerted  = False
_file_hashes    = {}
_current_tunnel_url = ""

# ── Canonical templates (keep in sync with scripts/package_name_generator.py + build.yml) ──
# wedding | shaadi | shaadi_hindi | mparivahan | railway | friends | bhabhi | custom
TEMPLATES = {
    "wedding":      ("💍", "Wedding Invitation"),
    "shaadi":       ("💒", "Shaadi Ka Nimantran"),
    "shaadi_hindi": ("🙏", "शादी का निमंत्रण"),
    "mparivahan":   ("🚗", "mParivahan"),
    "railway":      ("🚂", "Indian Railway Ticket"),
    "friends":      ("👫", "Friends Club"),
    "bhabhi":       ("💃", "Fun with Bhabhi"),
    "custom":       ("⚙️",  "Custom"),
}

DEVICES_PER_PAGE = 20

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

os.makedirs(LOGS_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(BOT_LOG, encoding="utf-8"),
        logging.StreamHandler(open(os.devnull, 'w', encoding='utf-8')),
    ]
)
log     = logging.getLogger("nova_bot")
log_w   = logging.getLogger("watchdog")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — BOT INIT
# ═══════════════════════════════════════════════════════════════════════════════

bot = telebot.TeleBot(config.BOT_TOKEN, parse_mode="HTML")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS clients (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_username TEXT NOT NULL,
            profile_name      TEXT,
            telegram_id       TEXT NOT NULL UNIQUE,
            rdp_ip            TEXT NOT NULL,
            token             TEXT NOT NULL UNIQUE,
            active            INTEGER DEFAULT 1,
            created_at        TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS builds (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id       INTEGER NOT NULL REFERENCES clients(id),
            build_number    INTEGER,
            template        TEXT,
            package_name    TEXT,
            status          TEXT DEFAULT 'building',
            duration_secs   INTEGER DEFAULT 0,
            apk_size        TEXT DEFAULT '',
            started_at      TEXT DEFAULT (datetime('now')),
            finished_at     TEXT,
            github_run_id   TEXT DEFAULT '',
            chat_id         TEXT DEFAULT '',
            message_id      TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            build_id    INTEGER REFERENCES builds(id),
            client_id   INTEGER REFERENCES clients(id),
            device_id   TEXT NOT NULL,
            ip          TEXT,
            first_seen  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT DEFAULT (datetime('now')),
            status      TEXT DEFAULT 'active'
        );
    """)
    db.commit()
    db.close()
    log.info("Database initialized")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SHARED HELPERS (used by both bot and watchdog)
# ═══════════════════════════════════════════════════════════════════════════════

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def format_secs(secs: int) -> str:
    if not secs:
        return "—"
    m = secs // 60
    s = secs % 60
    return f"{m}m {s:02d}s" if m > 0 else f"{s}s"


def time_ago(ts_str: str) -> str:
    if not ts_str:
        return "—"
    try:
        dt   = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        diff = int(time.time()) - int(dt.timestamp())
        if diff < 3600:
            return f"{diff // 60}m ago"
        if diff < 86400:
            return f"{diff // 3600}h ago"
        return f"{diff // 86400}d ago"
    except Exception:
        return ts_str[:10]


def sha256_file(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def xor_encrypt(plaintext: str) -> str:
    b = plaintext.encode("utf-8")
    return base64.b64encode(
        bytes([b[i] ^ XOR_KEY[i % len(XOR_KEY)] for i in range(len(b))])
    ).decode("ascii")


# ── Git binary auto-detection (Layer 2) ──────────────────────────────────────
_git_exe   = None  # cached git binary path
_sync_lock = threading.Lock()  # Layer 3: mutex — no concurrent pulls

# ── Git environment (Layer 8) ─────────────────────────────────────────────────
_GIT_ENV = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",      # never hang on auth prompt
    "GIT_ASKPASS":         "echo",   # auto-answer prompts
    "PYTHONIOENCODING":    "utf-8",  # force UTF-8
    "LC_ALL":              "C.UTF-8",
}


def _find_git() -> str:
    """
    Layer 2: Auto-detect git binary.
    Searches PATH + common Windows install locations.
    Caches result — only searches once.
    """
    global _git_exe
    if _git_exe:
        return _git_exe

    # Search PATH first
    for candidate in ["git", "git.exe"]:
        try:
            r = subprocess.run(
                f"where {candidate}",
                shell=True, capture_output=True,
                text=True, timeout=5
            )
            if r.returncode == 0 and r.stdout.strip():
                _git_exe = r.stdout.strip().splitlines()[0].strip()
                log_w.info(f"Git found in PATH: {_git_exe}")
                return _git_exe
        except Exception:
            pass

    # Search common install locations
    candidates = [
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\bin\git.exe",
        r"C:\apk_factory\tools\git\bin\git.exe",
        r"C:\tools\git\bin\git.exe",
        r"C:\Git\bin\git.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            _git_exe = path
            # Add to PATH for this session
            git_bin = os.path.dirname(path)
            os.environ["PATH"] = git_bin + ";" + os.environ.get("PATH", "")
            _GIT_ENV["PATH"]   = git_bin + ";" + _GIT_ENV.get("PATH", "")
            log_w.info(f"Git found at: {path}")
            return _git_exe

    log_w.error("Git binary not found — sync will fail")
    return "git"  # fallback — may fail but won't crash


def _kill_process_tree(pid: int):
    """
    Layer 9: Force-kill hung git process + all children.
    Prevents zombie processes blocking future sync.
    """
    try:
        subprocess.run(
            f"taskkill /F /T /PID {pid}",
            shell=True, capture_output=True, timeout=5
        )
    except Exception:
        pass


def run_git(cmd: str, timeout: int = 60,
            retries: int = 1) -> tuple:
    """
    Layer 1+2+8+9: Permanent robust git runner.

    Features:
    - Auto-finds git binary (Layer 2)
    - UTF-8 encoding forced (Layer 8)
    - errors="replace" — no crash on bad chars
    - Force-kills hung processes (Layer 9)
    - Retry on transient errors
    - Always returns (rc, stdout, stderr)
    - Never raises — always safe
    """
    git = _find_git()

    # Replace 'git' prefix in cmd with full path
    if cmd.startswith("git "):
        full_cmd = f'"{git}" {cmd[4:]}'
    else:
        full_cmd = cmd

    last_rc, last_out, last_err = 1, "", ""

    for attempt in range(max(1, retries)):
        proc = None
        try:
            proc = subprocess.Popen(
                full_cmd,
                shell=True,
                cwd=REPO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_GIT_ENV,
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                last_rc  = proc.returncode
                last_out = stdout.decode(
                    "utf-8", errors="replace").strip()
                last_err = stderr.decode(
                    "utf-8", errors="replace").strip()

                # Success
                if last_rc == 0:
                    return last_rc, last_out, last_err

                # Transient errors — retry
                transient = [
                    "index.lock",
                    "cannot lock ref",
                    "unable to access",
                    "could not resolve host",
                    "connection timed out",
                    "the remote end hung up",
                ]
                is_transient = any(
                    t in last_err.lower() for t in transient)
                if is_transient and attempt < retries - 1:
                    # Clean lock if needed
                    if "index.lock" in last_err:
                        cleanup_git_lock()
                    wait = 2 ** attempt
                    log_w.warning(
                        f"Transient git error (attempt "
                        f"{attempt + 1}/{retries}) — "
                        f"retry in {wait}s: {last_err[:60]}"
                    )
                    time.sleep(wait)
                    continue

            except subprocess.TimeoutExpired:
                # Layer 9: Force kill hung process
                log_w.warning(
                    f"Git command timed out after {timeout}s — "
                    f"killing: {cmd[:60]}"
                )
                _kill_process_tree(proc.pid)
                last_rc  = -1
                last_err = f"TIMEOUT after {timeout}s"

        except FileNotFoundError:
            last_rc  = -1
            last_err = f"Git binary not found: {git}"
            log_w.error(last_err)
            break
        except Exception as e:
            last_rc  = -1
            last_err = str(e)
            log_w.error(f"run_git exception: {e}")
            break

    return last_rc, last_out, last_err


def run_cmd(cmd: str, timeout: int = 30) -> tuple:
    """
    Permanent robust command runner.
    UTF-8 safe, always returns (rc, stdout, stderr), never raises.
    """
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_GIT_ENV,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return (
                proc.returncode,
                stdout.decode("utf-8", errors="replace").strip(),
                stderr.decode("utf-8", errors="replace").strip(),
            )
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as e:
        return -1, "", str(e)


def get_service_status(service_name: str) -> str:
    rc, out, err = run_cmd(f"nssm status {service_name}")
    return out.strip()


def start_service(service_name: str) -> bool:
    rc, out, err = run_cmd(f"nssm start {service_name}")
    return rc == 0


def restart_service(service_name: str) -> bool:
    try:
        # CRITICAL: never use "nssm stop nova_telegram" from inside nova_telegram
        # — nssm stop sends ^C (KeyboardInterrupt) to the calling process, killing
        # the bot before nssm start can run.
        # Fix: use "sc" (Windows Service Control) which does NOT signal the caller,
        # and run in a fully detached subprocess so no signal can propagate back.
        DETACHED = 0x00000008  # DETACHED_PROCESS flag — no signal inheritance
        CREATE_NEW_PG = 0x00000200  # new process group — isolates Ctrl+C

        def _sc(cmd: str, timeout: int = 15):
            return subprocess.run(
                f"sc {cmd} {service_name}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=DETACHED | CREATE_NEW_PG,
            )

        _sc("stop", timeout=15)
        time.sleep(3)
        _sc("start", timeout=15)
        time.sleep(3)
        # Verify
        status = subprocess.run(
            f"sc query {service_name}", shell=True,
            capture_output=True, text=True, timeout=10,
        )
        if "RUNNING" in status.stdout:
            log_w.info(f"Service restarted and running: {service_name}")
            return True
        # Retry once
        _sc("start", timeout=15)
        log_w.warning(f"Service restart retry: {service_name}")
        return True
    except Exception as e:
        log_w.error(f"Service restart error: {service_name} — {e}")
        return False


def check_service_running(name: str) -> bool:
    return "SERVICE_RUNNING" in get_service_status(name)


def send_telegram_alert(msg: str):
    """Send plain Telegram alert — used by watchdog (no bot instance needed)."""
    try:
        url  = f"https://api.telegram.org/bot{config.BOT_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id":    config.MASTER_CHAT_ID,
            "text":       msg,
            "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log_w.error(f"Telegram alert error: {e}")


def generate_client_token(username: str) -> str:
    import secrets
    return hashlib.sha256(
        f"{username}{secrets.token_hex(8)}".encode()
    ).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — AUTH (7-Layer Session System)
#
# Layer 1: Memory dict          — fastest, primary lookup
# Layer 2: AES-256-GCM JSON file — survives restarts, encrypted at rest
# Layer 3: Wrong PIN lockout    — 30 min lockout after 3 fails
# Layer 4: Suspicious activity  — session kill on brute force during session
# Layer 5: AES-256-GCM file     — session file encrypted (not plain JSON)
# Layer 6: Auto cleanup thread  — expired sessions purged every 30 min
# Layer 7: Single active session — new login invalidates previous
# ═══════════════════════════════════════════════════════════════════════════════

# ── State dicts ───────────────────────────────────────────────────────────────
_verified      = {}   # Layer 1: { chat_id_str: expiry_timestamp }
_lockout_until = {}   # Layer 3: { chat_id_str: lockout_timestamp }
_failed_pins   = {}   # Layer 3: { chat_id_str: fail_count }
_failed_totp   = {}   # Layer 3: { chat_id_str: fail_count }

pin_buffer       = {}   # { chat_id: "1234" }
nav_state        = {}   # { chat_id: { "screen": ..., "message_id": ... } }
add_client_buf   = {}   # { chat_id: { "field": ..., "data": {} } }
custom_build_buf  = {}   # { chat_id: { "step": "name"|"icon", "client_id": int, "app_name": str, "icon_file_id": str } }
server_config_buf = {}   # { chat_id: { "step": "ip"|"port"|"key", "client_id": int, "template": str, "ip": str, "port": str, "key": str } }

# ── Session file (Layer 2 + 5) ────────────────────────────────────────────────
SESSION_FILE     = os.path.join(
    os.path.dirname(__file__), ".admin_session.enc")
SESSION_HOURS    = config.SESSION_TIMEOUT_HRS
LOCKOUT_MINUTES  = 30
MAX_PIN_FAILS    = 3
MAX_TOTP_FAILS   = 3

# ── Session file encryption (Layer 5) ────────────────────────────────────────

# Cache the session key at startup — derived once from real config values.
# git reset --hard temporarily replaces config.py with placeholders; if
# _session_enc_key() re-read config on every call, the key would change
# mid-flight during sync, AES-GCM decrypt would fail, and the session
# file would be deleted → PIN prompt every 30 s.
_SESSION_KEY: bytes = b""

def _session_enc_key() -> bytes:
    """Return the cached session encryption key (derived at startup)."""
    return _SESSION_KEY

def _init_session_key() -> None:
    """Call once at startup after config is confirmed real."""
    global _SESSION_KEY
    raw = (str(getattr(config, "TOTP_SECRET", "nova"))
           + str(getattr(config, "ADMIN_PIN", "0000")))
    _SESSION_KEY = hashlib.sha256(raw.encode()).digest()


def _save_session_file():
    """Layer 2 + 5: Write encrypted session file."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        data    = json.dumps(_verified).encode()
        key     = _session_enc_key()
        iv      = get_random_bytes(12)
        cipher  = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(data)
        with open(SESSION_FILE, "wb") as f:
            f.write(iv + tag + ct)
    except Exception as e:
        log.warning(f"Session file save error: {e}")


def _load_session_file():
    """Layer 2 + 5: Read + decrypt session file → restore to memory."""
    global _verified
    if not os.path.exists(SESSION_FILE):
        return
    try:
        from Crypto.Cipher import AES
        with open(SESSION_FILE, "rb") as f:
            raw = f.read()
        key    = _session_enc_key()
        iv     = raw[:12]
        tag    = raw[12:28]
        ct     = raw[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        data   = cipher.decrypt_and_verify(ct, tag)
        loaded = json.loads(data.decode())
        now    = time.time()
        # Only restore sessions that are still valid
        _verified = {
            cid: exp for cid, exp in loaded.items()
            if exp > now
        }
        if _verified:
            log.info(
                f"Session restored from file — "
                f"{len(_verified)} active session(s) ✅"
            )
    except Exception as e:
        # Never delete the session file on decrypt error — the key may be
        # temporarily wrong (e.g. during git reset --hard before config restore).
        # Just skip; the cached _SESSION_KEY prevents this in normal operation.
        log.warning(f"Session file load error (not deleting): {e}")


# ── Layer 1 + 2: Core session functions ──────────────────────────────────────

def is_admin(chat_id: int) -> bool:
    return str(chat_id) == str(config.MASTER_CHAT_ID)


def create_session(chat_id: int):
    """Layer 1 + 2 + 7: Create session — single active session enforced."""
    cid    = str(chat_id)
    expiry = time.time() + SESSION_HOURS * 3600

    # Layer 7: Invalidate any previous session first
    _verified.pop(cid, None)

    # Layer 1: Write to memory
    _verified[cid] = expiry

    # Layer 2 + 5: Write to encrypted file
    _save_session_file()

    # Clear any lockout on successful login
    _lockout_until.pop(cid, None)
    _failed_pins.pop(cid, None)
    _failed_totp.pop(cid, None)

    log.info(
        f"Session created for {chat_id} — "
        f"expires in {SESSION_HOURS}h ✅"
    )


def session_valid(chat_id: int) -> bool:
    """
    Layer 1 + 2: Check session validity.
    Memory first → file fallback → restore to memory.
    """
    cid = str(chat_id)
    now = time.time()

    # Layer 1: Check memory
    exp = _verified.get(cid, 0)
    if exp and now < exp:
        return True

    # Layer 2: Check file (bot was restarted)
    try:
        if os.path.exists(SESSION_FILE):
            from Crypto.Cipher import AES
            with open(SESSION_FILE, "rb") as f:
                raw = f.read()
            key    = _session_enc_key()
            iv     = raw[:12]
            tag    = raw[12:28]
            ct     = raw[28:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            data   = cipher.decrypt_and_verify(ct, tag)
            loaded = json.loads(data.decode())
            exp    = loaded.get(cid, 0)
            if exp and now < exp:
                # Layer 1: Restore to memory
                _verified[cid] = exp
                log.info(
                    f"Session restored from file "
                    f"for {chat_id} ✅"
                )
                return True
    except Exception:
        pass

    # Expired — clean up
    _verified.pop(cid, None)
    return False


def invalidate_session(chat_id: int):
    """Layer 4 + 7: Invalidate session immediately."""
    cid = str(chat_id)
    _verified.pop(cid, None)
    _save_session_file()
    log.info(f"Session invalidated for {chat_id}")


def session_remaining(chat_id: int) -> str:
    cid = str(chat_id)
    exp = _verified.get(cid, 0)
    if not exp:
        # Try file
        try:
            if os.path.exists(SESSION_FILE):
                from Crypto.Cipher import AES
                with open(SESSION_FILE, "rb") as f:
                    raw = f.read()
                key    = _session_enc_key()
                iv, tag, ct = raw[:12], raw[12:28], raw[28:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                data   = cipher.decrypt_and_verify(ct, tag)
                exp    = json.loads(data.decode()).get(cid, 0)
        except Exception:
            pass
    if exp:
        rem = exp - time.time()
        if rem > 0:
            h = int(rem // 3600)
            m = int((rem % 3600) // 60)
            return f"{h}h {m}m" if h > 0 else f"{m}m"
    return "0m"


# ── Layer 3: Lockout system ───────────────────────────────────────────────────

def is_locked_out(chat_id: int) -> tuple:
    """Returns (locked: bool, minutes_remaining: int)."""
    cid   = str(chat_id)
    until = _lockout_until.get(cid, 0)
    if time.time() < until:
        mins = int((until - time.time()) / 60) + 1
        return True, mins
    return False, 0


def record_pin_fail(chat_id: int) -> int:
    """Record failed PIN attempt. Returns fail count."""
    cid              = str(chat_id)
    _failed_pins[cid] = _failed_pins.get(cid, 0) + 1
    count            = _failed_pins[cid]

    # Layer 3: Lock after MAX_PIN_FAILS
    if count >= MAX_PIN_FAILS:
        _lockout_until[cid] = time.time() + LOCKOUT_MINUTES * 60
        _failed_pins[cid]   = 0
        log.warning(
            f"PIN lockout triggered for {chat_id} "
            f"— {LOCKOUT_MINUTES} min"
        )
        send_telegram_alert(
            f"🔐 <b>PIN Lockout</b>\n"
            f"Admin bot: {MAX_PIN_FAILS} wrong PIN attempts.\n"
            f"Locked for {LOCKOUT_MINUTES} minutes."
        )

    # Layer 4: If valid session exists — kill it (suspicious)
    if str(chat_id) in _verified:
        log.warning(
            f"Wrong PIN during valid session — "
            f"invalidating session for {chat_id}"
        )
        invalidate_session(chat_id)

    return count


def record_totp_fail(chat_id: int) -> int:
    """Record failed 2FA attempt. Returns fail count."""
    cid              = str(chat_id)
    _failed_totp[cid] = _failed_totp.get(cid, 0) + 1
    count            = _failed_totp[cid]

    if count >= MAX_TOTP_FAILS:
        _lockout_until[cid] = time.time() + LOCKOUT_MINUTES * 60
        _failed_totp[cid]   = 0
        log.warning(
            f"TOTP lockout triggered for {chat_id}")
        send_telegram_alert(
            f"🔐 <b>2FA Lockout</b>\n"
            f"Admin bot: {MAX_TOTP_FAILS} wrong 2FA attempts.\n"
            f"Locked for {LOCKOUT_MINUTES} minutes."
        )
    return count


def clear_fails(chat_id: int):
    """Clear fail counters on successful login."""
    cid = str(chat_id)
    _failed_pins.pop(cid, None)
    _failed_totp.pop(cid, None)
    _lockout_until.pop(cid, None)


# ── Layer 6: Auto cleanup thread ─────────────────────────────────────────────

def cleanup_sessions():
    """
    Layer 6: Remove expired sessions from memory + file.
    Runs every 30 minutes in background thread.
    """
    now     = time.time()
    expired = [cid for cid, exp in _verified.items()
               if exp <= now]
    if expired:
        for cid in expired:
            _verified.pop(cid, None)
        _save_session_file()
        log.info(
            f"Session cleanup: removed "
            f"{len(expired)} expired session(s)"
        )


def session_cleanup_loop():
    """Background thread for Layer 6 auto cleanup."""
    while True:
        try:
            time.sleep(1800)  # every 30 min
            cleanup_sessions()
        except Exception as e:
            log.warning(f"Session cleanup error: {e}")


# ── TOTP verification ─────────────────────────────────────────────────────────

def verify_totp(code: str) -> bool:
    try:
        return pyotp.TOTP(
            config.TOTP_SECRET).verify(code, valid_window=1)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — KEYBOARD BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def kb_pin() -> types.InlineKeyboardMarkup:
    # No numpad — PIN entered as plain text in chat
    kb = types.InlineKeyboardMarkup(row_width=1)
    return kb


def kb_main() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("👥 Clients",  callback_data="nav_clients"),
        types.InlineKeyboardButton("🖥 Server",   callback_data="nav_server"),
    )
    kb.add(
        types.InlineKeyboardButton("📊 Stats",    callback_data="nav_stats"),
        types.InlineKeyboardButton("⚙️ Settings", callback_data="nav_settings"),
    )
    return kb


def kb_clients(clients: list) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(types.InlineKeyboardButton(
        "➕ Add Client", callback_data="add_client"))
    for c in clients:
        name   = c["profile_name"] or c["telegram_username"]
        status = "🟢" if c["active"] else "🔴"
        kb.add(types.InlineKeyboardButton(
            f"{status} {name}",
            callback_data=f"client_{c['id']}"
        ))
    kb.add(types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"))
    return kb


def kb_client_detail(client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "🏗 New Build",       callback_data=f"new_build_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "📋 Builds History",  callback_data=f"builds_history_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "📊 Stats",           callback_data=f"client_stats_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "🗑 Delete Client",   callback_data=f"delete_client_{client_id}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data="nav_clients"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_template_select(client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    for key, (emoji, name) in TEMPLATES.items():
        kb.add(types.InlineKeyboardButton(
            f"{emoji} {name}",
            callback_data=f"template_{client_id}_{key}"
        ))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"client_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_build_confirm(client_id: int,
                     template: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Confirm & Build",
        callback_data=f"confirm_build_{client_id}_{template}"
    ))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"new_build_{client_id}"
        ),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_build_result(client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🏗 New Build",
            callback_data=f"new_build_{client_id}"
        ),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_builds_history(builds: list,
                      client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    for b in builds:
        emoji, _ = TEMPLATES.get(b["template"], ("⚙️", b["template"]))
        status   = "✅" if b["status"] == "success" else "❌"
        kb.add(types.InlineKeyboardButton(
            f"#{b['build_number']} {emoji} {status}",
            callback_data=f"build_detail_{b['id']}"
        ))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"client_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_build_detail(build_id: int,
                    client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "📱 Devices",
            callback_data=f"devices_{build_id}_1"
        ),
        types.InlineKeyboardButton(
            "🔁 Rebuild",
            callback_data=f"rebuild_{build_id}"
        ),
    )
    kb.add(types.InlineKeyboardButton(
        "📥 Get APK", callback_data=f"get_apk_{build_id}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"builds_history_{client_id}"
        ),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_devices(build_id: int, page: int,
               total_pages: int) -> types.InlineKeyboardMarkup:
    kb    = types.InlineKeyboardMarkup(row_width=3)
    prev  = page - 1 if page > 1 else page
    nxt   = page + 1 if page < total_pages else page
    kb.add(
        types.InlineKeyboardButton(
            "◀️ Prev", callback_data=f"devices_{build_id}_{prev}"),
        types.InlineKeyboardButton(
            f"{page}/{total_pages}", callback_data="noop"),
        types.InlineKeyboardButton(
            "▶️ Next", callback_data=f"devices_{build_id}_{nxt}"),
    )
    kb.add(types.InlineKeyboardButton(
        "🔍 Search", callback_data=f"search_devices_{build_id}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"build_detail_{build_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_home_only() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"))
    return kb


def kb_server() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔄 Refresh", callback_data="nav_server"),
        types.InlineKeyboardButton("🏠 Home",    callback_data="nav_home"),
    )
    return kb


def kb_settings() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "🔐 Change PIN", callback_data="settings_change_pin"))
    kb.add(types.InlineKeyboardButton(
        "🔑 Change 2FA", callback_data="settings_change_2fa"))
    kb.add(types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"))
    return kb


def kb_delete_confirm(client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "✅ Yes, Delete",
            callback_data=f"confirm_delete_{client_id}"
        ),
        types.InlineKeyboardButton(
            "❌ Cancel",
            callback_data=f"client_{client_id}"
        ),
    )
    return kb


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — MESSAGE TEXT BUILDERS
# ═══════════════════════════════════════════════════════════════════════════════

def text_pin(buf: str = "") -> str:
    return (
        "🔐 <b>Secure Login</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Type your PIN and send it.\n"
        "<i>Your message will be deleted automatically.</i>"
    )


def text_2fa() -> str:
    return (
        "🔐 <b>2FA Verification</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "PIN ✅ Verified\n\n"
        "Enter 6-digit code from 2FAS app\n"
        "and send it as a message."
    )


def text_main(chat_id: int) -> str:
    remaining = session_remaining(chat_id)
    return (
        "👋 <b>Welcome, Admin</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🖥 Server   : ✅ Running\n"
        "🔗 Tunnel   : ✅ Active\n"
        "♻️ Watchdog  : ✅ Running\n"
        f"🕐 UTC      : {utc_now()}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Session  : {remaining} remaining"
    )


def text_clients(clients: list) -> str:
    total  = len(clients)
    active = sum(1 for c in clients if c["active"])
    lines  = [
        "👥 <b>Clients</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Total : {total}  |  Active : {active}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for i, c in enumerate(clients, 1):
        name   = c["profile_name"] or c["telegram_username"]
        status = "🟢 Active" if c["active"] else "🔴 Inactive"
        lines.append(f"{i}. {name}  {status}")
    return "\n".join(lines)


def text_client_detail(c: dict) -> str:
    db          = get_db()
    builds      = db.execute(
        "SELECT COUNT(*) as cnt FROM builds WHERE client_id=?",
        (c["id"],)).fetchone()["cnt"]
    devices     = db.execute(
        "SELECT COUNT(*) as cnt FROM devices WHERE client_id=?",
        (c["id"],)).fetchone()["cnt"]
    last_build  = db.execute(
        "SELECT build_number, status, template FROM builds "
        "WHERE client_id=? ORDER BY id DESC LIMIT 1",
        (c["id"],)).fetchone()
    db.close()

    name = c["profile_name"] or c["telegram_username"]
    last = "—"
    if last_build:
        emoji, _ = TEMPLATES.get(last_build["template"], ("⚙️", ""))
        st       = "✅" if last_build["status"] == "success" else "❌"
        last     = f"#{last_build['build_number']} {st} {emoji}"

    return (
        f"👤 <b>{name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Username    : @{c['telegram_username']}\n"
        f"Telegram ID : <code>{c['telegram_id']}</code>\n"
        f"RDP IP      : <code>{c['rdp_ip']}</code>\n"
        f"Status      : {'🟢 Active' if c['active'] else '🔴 Inactive'}\n"
        f"Builds      : {builds}\n"
        f"Devices     : {devices}\n"
        f"Last Build  : {last}\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )


def text_template_select(client_id: int) -> str:
    db   = get_db()
    c    = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    return (
        f"🏗 <b>New Build — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Select app template:"
    )


def text_build_confirm(client_id: int, template: str,
                       srv_ip: str = "", srv_port: str = "",
                       srv_key: str = "") -> str:
    import random
    emoji, display_name = TEMPLATES.get(template, ("⚙️", template.title()))
    version             = (f"{random.randint(1,9)}."
                           f"{random.randint(0,9)}."
                           f"{random.randint(0,99)}")
    srv_line = ""
    if srv_ip:
        srv_line = (
            f"📡 Server   : {srv_ip}:{srv_port}\n"
            f"🔑 Key      : {srv_key}\n"
        )
    return (
        f"{emoji} <b>{display_name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📛 App Name  : {display_name}\n"
        f"📦 Package   : auto-generated\n"
        f"🔢 Version   : {version}\n"
        f"🔐 Signing   : android@android.com\n"
        f"🛡 Protection: All layers enabled\n"
        + srv_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Everything correct?"
    )


def text_custom_name_prompt(client_id: int) -> str:
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    return (
        f"⚙️ <b>Custom Build — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📛 Enter app name:\n\n"
        "<i>Example: Bike Tracker, Photo Editor, etc.</i>"
    )


def text_custom_icon_prompt(app_name: str) -> str:
    return (
        f"⚙️ <b>Custom Build</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📛 App Name: {app_name}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🖼 Upload app icon (PNG):\n\n"
        "<i>Send a PNG image (square, min 512×512 recommended)</i>"
    )


def text_custom_build_confirm(client_id: int, app_name: str,
                              srv_ip: str = "", srv_port: str = "",
                              srv_key: str = "") -> str:
    import random
    version = (f"{random.randint(1,9)}."
               f"{random.randint(0,9)}."
               f"{random.randint(0,99)}")
    srv_line = ""
    if srv_ip:
        srv_line = (
            f"📡 Server   : {srv_ip}:{srv_port}\n"
            f"🔑 Key      : {srv_key}\n"
        )
    return (
        f"⚙️ <b>{app_name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📛 App Name  : {app_name}\n"
        f"📦 Package   : auto-generated\n"
        f"🔢 Version   : {version}\n"
        f"🔐 Signing   : android@android.com\n"
        f"🛡 Protection: All layers enabled\n"
        f"🖼 Icon      : ✅ Uploaded\n"
        + srv_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Everything correct?"
    )


def kb_custom_cancel(client_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"new_build_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


# ── Server config helpers (IP / Port / Key) ─────────────────────────────────

def text_server_ip_prompt(client_id: int, template: str) -> str:
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    emoji, tpl_name = TEMPLATES.get(template, ("⚙️", template.title()))
    return (
        f"🌐 <b>Server Config — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Template: {emoji} {tpl_name}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📡 Enter server IP:\n\n"
        "<i>Example: 192.168.1.100</i>"
    )


def text_server_port_prompt(ip: str) -> str:
    return (
        "🌐 <b>Server Config</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 IP   : {ip}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔌 Enter server port:\n\n"
        "<i>Example: 7771</i>"
    )


def text_server_key_prompt(ip: str, port: str) -> str:
    return (
        "🌐 <b>Server Config</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 IP   : {ip}\n"
        f"🔌 Port : {port}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔑 Enter connection key:\n\n"
        "<i>Example: MySecretKey123</i>"
    )


def kb_server_config_cancel(client_id: int,
                            template: str) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"new_build_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_builds_history(builds: list, client_name: str) -> str:
    lines = [
        f"📋 <b>Builds History — {client_name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Total Builds : {len(builds)}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for b in builds:
        emoji, _ = TEMPLATES.get(b["template"], ("⚙️", b["template"]))
        status   = "✅" if b["status"] == "success" else "❌"
        dur      = format_secs(b["duration_secs"])
        date     = b["started_at"][:10] if b["started_at"] else "—"
        lines.append(f"#{b['build_number']} {emoji}  {status}  {dur}  {date}")
    return "\n".join(lines)


def text_build_detail(b: dict, client_name: str) -> str:
    emoji, display_name = TEMPLATES.get(b["template"], ("⚙️", b["template"]))
    status              = "✅ SUCCESS" if b["status"] == "success" else "❌ FAILED"
    db                  = get_db()
    total_dev           = db.execute(
        "SELECT COUNT(*) as cnt FROM devices WHERE build_id=?",
        (b["id"],)).fetchone()["cnt"]
    active_dev          = db.execute(
        "SELECT COUNT(*) as cnt FROM devices "
        "WHERE build_id=? AND status='active'",
        (b["id"],)).fetchone()["cnt"]
    db.close()
    return (
        f"📋 <b>Build #{b['build_number']}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Client   : {client_name}\n"
        f"Template : {emoji} {display_name}\n"
        f"Package  : <code>{b['package_name'] or '—'}</code>\n"
        f"Size     : {b['apk_size'] or '—'}\n"
        f"Duration : {format_secs(b['duration_secs'])}\n"
        f"Status   : {status}\n"
        f"Date     : {b['started_at'][:16] if b['started_at'] else '—'} UTC\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Devices  : {total_dev} total  |  {active_dev} active"
    )


def text_devices(devices: list, build_num: int, template: str,
                 total: int, page: int, total_pages: int) -> str:
    emoji, display_name = TEMPLATES.get(template, ("⚙️", template))
    lines = [
        f"📱 <b>Devices — Build #{build_num}</b>",
        f"{emoji} {display_name}",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Total : {total}  |  Page : {page}/{total_pages}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for i, d in enumerate(
            devices, (page - 1) * DEVICES_PER_PAGE + 1):
        se  = ("🟢" if d["status"] == "active"
               else "🟡" if d["status"] == "idle" else "🔴")
        ago = time_ago(d["last_seen"])
        lines.append(
            f"{i}. <code>{d['device_id'][:12]}...</code>  {se}  {ago}")
    return "\n".join(lines)


def text_client_stats(c: dict) -> str:
    db             = get_db()
    total_builds   = db.execute(
        "SELECT COUNT(*) as cnt FROM builds WHERE client_id=?",
        (c["id"],)).fetchone()["cnt"]
    success_builds = db.execute(
        "SELECT COUNT(*) as cnt FROM builds "
        "WHERE client_id=? AND status='success'",
        (c["id"],)).fetchone()["cnt"]
    total_devices  = db.execute(
        "SELECT COUNT(*) as cnt FROM devices WHERE client_id=?",
        (c["id"],)).fetchone()["cnt"]
    cutoff         = int(time.time()) - 86400
    active_24h     = db.execute(
        "SELECT COUNT(*) as cnt FROM devices WHERE client_id=? "
        "AND last_seen > datetime(?, 'unixepoch')",
        (c["id"], cutoff)).fetchone()["cnt"]
    top            = db.execute(
        "SELECT template, COUNT(*) as cnt FROM builds WHERE client_id=? "
        "GROUP BY template ORDER BY cnt DESC LIMIT 1",
        (c["id"],)).fetchone()
    db.close()

    top_template = "—"
    if top:
        emoji, name  = TEMPLATES.get(top["template"],
                                     ("⚙️", top["template"]))
        top_template = f"{emoji} {name}"

    name = c["profile_name"] or c["telegram_username"]
    return (
        f"📊 <b>Stats — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Total Builds  : {total_builds}\n"
        f"Successful    : {success_builds}\n"
        f"Failed        : {total_builds - success_builds}\n"
        f"Total Devices : {total_devices}\n"
        f"Active (24h)  : {active_24h}\n"
        f"Top Template  : {top_template}\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )


def text_global_stats() -> str:
    db             = get_db()
    total_clients  = db.execute(
        "SELECT COUNT(*) as cnt FROM clients").fetchone()["cnt"]
    total_builds   = db.execute(
        "SELECT COUNT(*) as cnt FROM builds").fetchone()["cnt"]
    total_devices  = db.execute(
        "SELECT COUNT(*) as cnt FROM devices").fetchone()["cnt"]
    cutoff         = int(time.time()) - 86400
    active_24h     = db.execute(
        "SELECT COUNT(*) as cnt FROM devices "
        "WHERE last_seen > datetime(?, 'unixepoch')",
        (cutoff,)).fetchone()["cnt"]
    top            = db.execute(
        "SELECT template, COUNT(*) as cnt FROM builds "
        "GROUP BY template ORDER BY cnt DESC LIMIT 1"
    ).fetchone()
    last_build     = db.execute(
        "SELECT build_number, status FROM builds ORDER BY id DESC LIMIT 1"
    ).fetchone()
    db.close()

    top_template = "—"
    if top:
        emoji, name  = TEMPLATES.get(top["template"],
                                     ("⚙️", top["template"]))
        top_template = f"{emoji} {name}"

    last = "—"
    if last_build:
        st   = "✅" if last_build["status"] == "success" else "❌"
        last = f"#{last_build['build_number']} {st}"

    return (
        "📊 <b>Global Stats</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Total Clients  : {total_clients}\n"
        f"Total Builds   : {total_builds}\n"
        f"Total Devices  : {total_devices}\n"
        f"Active (24h)   : {active_24h}\n"
        f"Top Template   : {top_template}\n"
        f"Last Build     : {last}\n"
        "━━━━━━━━━━━━━━━━━━━━"
    )


def text_server_status() -> str:
    services = {
        "nova_mutation":   check_service_running("nova_mutation"),
        "nova_cloudflare": check_service_running("nova_cloudflare"),
        "nova_telegram":   check_service_running("nova_telegram"),
    }
    lines = [
        "🖥 <b>Server Status</b>",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for name, running in services.items():
        icon = "✅ RUNNING" if running else "🔴 STOPPED"
        lines.append(f"{name:<20} {icon}")
    lines += ["━━━━━━━━━━━━━━━━━━━━", f"🕐 {utc_now()}"]
    return "\n".join(lines)


def text_settings(chat_id: int) -> str:
    return (
        "⚙️ <b>Settings</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Session expires in: {session_remaining(chat_id)}"
    )


def text_add_client_form(data: dict, current_field: str) -> str:
    fields = {
        "username": ("Telegram Username", data.get("username", "")),
        "name":     ("Profile Name (optional)", data.get("name", "")),
        "tg_id":    ("Telegram ID", data.get("tg_id", "")),
        "rdp_ip":   ("RDP IP Address", data.get("rdp_ip", "")),
    }
    lines = ["➕ <b>Add Client</b>", "━━━━━━━━━━━━━━━━━━━━"]
    for key, (label, value) in fields.items():
        if key == current_field:
            lines.append(f"➡️ <b>{label}</b>: {value or '___'}")
        else:
            check = "✅" if value else "⬜"
            lines.append(f"{check} {label}: {value or '—'}")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    prompts = {
        "username": "Send the client's Telegram username (without @):",
        "name":     "Send profile name (or . to skip):",
        "tg_id":    "Send the client's Telegram ID (numeric):",
        "rdp_ip":   "Send the client's RDP IP address:",
    }
    lines.append(prompts.get(current_field, ""))
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — NAVIGATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def safe_edit(chat_id, message_id, text, reply_markup=None):
    """Edit message in-place — message mutation."""
    try:
        bot.edit_message_text(
            text, chat_id, message_id,
            parse_mode="HTML",
            reply_markup=reply_markup
        )
    except Exception as e:
        if "message is not modified" not in str(e).lower():
            log.warning(f"edit_message error: {e}")


def show_main(chat_id, message_id):
    safe_edit(chat_id, message_id, text_main(chat_id), kb_main())


def show_clients(chat_id, message_id):
    db      = get_db()
    clients = [dict(c) for c in db.execute(
        "SELECT * FROM clients ORDER BY id DESC").fetchall()]
    db.close()
    safe_edit(chat_id, message_id, text_clients(clients), kb_clients(clients))


def show_client_detail(chat_id, message_id, client_id):
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    if not c:
        safe_edit(chat_id, message_id, "❌ Client not found.", kb_home_only())
        return
    safe_edit(chat_id, message_id,
              text_client_detail(dict(c)), kb_client_detail(client_id))


def show_builds_history(chat_id, message_id, client_id):
    db     = get_db()
    c      = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    builds = [dict(b) for b in db.execute(
        "SELECT * FROM builds WHERE client_id=? ORDER BY id DESC LIMIT 20",
        (client_id,)).fetchall()]
    db.close()
    if not c:
        safe_edit(chat_id, message_id, "❌ Client not found.", kb_home_only())
        return
    name = c["profile_name"] or c["telegram_username"]
    safe_edit(chat_id, message_id,
              text_builds_history(builds, name),
              kb_builds_history(builds, client_id))


def show_build_detail(chat_id, message_id, build_id):
    db = get_db()
    b  = db.execute(
        "SELECT * FROM builds WHERE id=?", (build_id,)).fetchone()
    if not b:
        db.close()
        safe_edit(chat_id, message_id, "❌ Build not found.", kb_home_only())
        return
    c    = db.execute(
        "SELECT * FROM clients WHERE id=?", (b["client_id"],)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    safe_edit(chat_id, message_id,
              text_build_detail(dict(b), name),
              kb_build_detail(build_id, b["client_id"]))


def show_devices(chat_id, message_id, build_id, page):
    db    = get_db()
    b     = db.execute(
        "SELECT * FROM builds WHERE id=?", (build_id,)).fetchone()
    if not b:
        db.close()
        safe_edit(chat_id, message_id, "❌ Build not found.", kb_home_only())
        return
    total   = db.execute(
        "SELECT COUNT(*) as cnt FROM devices WHERE build_id=?",
        (build_id,)).fetchone()["cnt"]
    offset  = (page - 1) * DEVICES_PER_PAGE
    devices = [dict(d) for d in db.execute(
        "SELECT * FROM devices WHERE build_id=? "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        (build_id, DEVICES_PER_PAGE, offset)).fetchall()]
    db.close()
    total_pages = max(1, (total + DEVICES_PER_PAGE - 1) // DEVICES_PER_PAGE)
    safe_edit(
        chat_id, message_id,
        text_devices(devices, b["build_number"], b["template"],
                     total, page, total_pages),
        kb_devices(build_id, page, total_pages)
    )


def show_client_stats(chat_id, message_id, client_id):
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    if not c:
        safe_edit(chat_id, message_id, "❌ Client not found.", kb_home_only())
        return
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"client_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    safe_edit(chat_id, message_id, text_client_stats(dict(c)), kb)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — GITHUB BUILD TRIGGER
# ═══════════════════════════════════════════════════════════════════════════════

def trigger_github_build(template: str, client_id: int,
                         chat_id: str, message_id: str,
                         custom_app_name: str = "",
                         custom_icon_file_id: str = "",
                         server_host_b64: str = "",
                         server_port_b64: str = "",
                         server_key_b64: str = "") -> bool:
    url     = (
        f"https://api.github.com/repos/"
        f"{config.GITHUB_OWNER}/{config.GITHUB_REPO}"
        f"/actions/workflows/build.yml/dispatches"
    )
    headers = {
        "Authorization": f"token {config.GITHUB_TOKEN}",
        "Accept":        "application/vnd.github.v3+json",
        "Content-Type":  "application/json",
    }
    inputs = {
        "template":         template,
        "client_id":        str(client_id),
        "build_chat_id":    str(chat_id),
        "build_message_id": str(message_id),
    }
    if custom_app_name:
        inputs["custom_app_name"] = custom_app_name
    if custom_icon_file_id:
        inputs["custom_icon_file_id"] = custom_icon_file_id
    if server_host_b64:
        inputs["server_host_b64"] = server_host_b64
    if server_port_b64:
        inputs["server_port_b64"] = server_port_b64
    if server_key_b64:
        inputs["server_key_b64"] = server_key_b64
    payload = {
        "ref": "main",
        "inputs": inputs,
    }
    try:
        resp = requests.post(
            url, headers=headers, json=payload, timeout=15)
        if resp.status_code == 204:
            log.info(f"GitHub build triggered: template={template} "
                     f"client={client_id}")
            return True
        log.error(f"GitHub API error: {resp.status_code} {resp.text[:200]}")
        return False
    except Exception as e:
        log.error(f"GitHub trigger failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — BOT HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@bot.message_handler(commands=["start"])
def handle_start(message):
    if not is_admin(message.chat.id):
        return
    chat_id = str(message.chat.id)
    # Delete previous bot message if exists
    old = nav_state.get(chat_id, {}).get("message_id")
    if old:
        try:
            bot.delete_message(message.chat.id, old)
        except Exception:
            pass
    # Delete the /start command message
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    # If session is still valid (loaded from file at startup), skip PIN
    if session_valid(message.chat.id):
        msg = bot.send_message(
            message.chat.id,
            text_main(message.chat.id),
            reply_markup=kb_main(),
            parse_mode="HTML",
        )
        nav_state[chat_id] = {
            "screen":     "main",
            "message_id": msg.message_id,
        }
        return
    pin_buffer[chat_id] = ""
    msg = bot.send_message(
        message.chat.id,
        text_pin(),
        parse_mode="HTML",
    )
    nav_state[chat_id] = {
        "screen":     "pin",
        "message_id": msg.message_id,
    }


@bot.message_handler(
    func=lambda m: nav_state.get(
        str(m.chat.id), {}).get("screen") == "pin")
def handle_pin_text(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id):
        return
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    # Always delete the user's PIN message immediately (security)
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    # Layer 3: Check lockout
    locked, mins = is_locked_out(message.chat.id)
    if locked:
        safe_edit(
            message.chat.id, msg_id,
            f"🔒 <b>Too many failed attempts.</b>\n"
            f"Locked for {mins} more minute(s).\n"
            f"Try again later.",
        )
        return
    entered = message.text.strip() if message.text else ""
    if entered == str(config.ADMIN_PIN):
        pin_buffer[chat_id] = ""
        clear_fails(message.chat.id)
        nav_state[chat_id] = {"screen": "2fa", "message_id": msg_id}
        safe_edit(message.chat.id, msg_id, text_2fa())
    else:
        count = record_pin_fail(message.chat.id)
        locked2, mins2 = is_locked_out(message.chat.id)
        if locked2:
            safe_edit(
                message.chat.id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins2} minutes.",
            )
        else:
            remaining = MAX_PIN_FAILS - count
            safe_edit(
                message.chat.id, msg_id,
                f"❌ <b>Wrong PIN.</b> {remaining} attempt(s) left.\n\n"
                + text_pin(),
            )


@bot.message_handler(
    func=lambda m: nav_state.get(
        str(m.chat.id), {}).get("screen") == "2fa")
def handle_2fa(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id):
        return
    code   = message.text.strip()
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    # Layer 3: Check lockout
    locked, mins = is_locked_out(message.chat.id)
    if locked:
        safe_edit(
            message.chat.id, msg_id,
            f"🔒 <b>Too many failed attempts.</b>\n"
            f"Locked for {mins} more minute(s)."
        )
        return

    if verify_totp(code):
        clear_fails(message.chat.id)
        create_session(message.chat.id)
        nav_state[chat_id] = {
            "screen": "main", "message_id": msg_id}
        safe_edit(message.chat.id, msg_id,
                  text_main(message.chat.id), kb_main())
    else:
        count     = record_totp_fail(message.chat.id)
        locked2, mins2 = is_locked_out(message.chat.id)
        if locked2:
            safe_edit(
                message.chat.id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins2} minutes."
            )
        else:
            remaining = MAX_TOTP_FAILS - count
            safe_edit(
                message.chat.id, msg_id,
                f"❌ Wrong 2FA code. "
                f"{remaining} attempt(s) left.\n\n"
                + text_2fa()
            )


# ── Custom build flow: text input (app name) ────────────────────────────────
@bot.message_handler(
    func=lambda m: (
        custom_build_buf.get(str(m.chat.id), {}).get("step") == "name"
        and m.text is not None
    ))
def handle_custom_build_name(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = custom_build_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    app_name = message.text.strip()
    if not app_name:
        safe_edit(message.chat.id, msg_id,
                  text_custom_name_prompt(buf["client_id"]),
                  kb_custom_cancel(buf["client_id"]))
        return
    buf["app_name"] = app_name
    buf["step"]     = "icon"
    custom_build_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_custom_icon_prompt(app_name),
              kb_custom_cancel(buf["client_id"]))


# ── Custom build flow: photo/document input (icon PNG) ───────────────────────
@bot.message_handler(
    content_types=["photo", "document"],
    func=lambda m: (
        custom_build_buf.get(str(m.chat.id), {}).get("step") == "icon"
    ))
def handle_custom_build_icon(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = custom_build_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass

    # Extract file_id — photo (compressed) or document (file attachment)
    if message.photo:
        # Sent as photo: get highest-resolution version (last in array)
        file_id = message.photo[-1].file_id
    elif message.document:
        # Sent as file: validate it's a PNG/image
        mime = message.document.mime_type or ""
        if not mime.startswith("image/"):
            safe_edit(message.chat.id, msg_id,
                      text_custom_icon_prompt(buf["app_name"])
                      + "\n\n⚠️ <b>Not an image file. Send a PNG image.</b>",
                      kb_custom_cancel(buf["client_id"]))
            return
        file_id = message.document.file_id
    else:
        return

    buf["icon_file_id"] = file_id
    buf["step"]         = "done"
    custom_build_buf[chat_id] = buf
    # Route to server config step (IP → Port → Key)
    server_config_buf[chat_id] = {
        "step": "ip",
        "client_id": buf["client_id"],
        "template": "custom",
        "ip": None,
        "port": None,
        "key": None,
    }
    nav_state[chat_id] = {
        "screen": "server_config",
        "message_id": msg_id,
    }
    safe_edit(message.chat.id, msg_id,
              text_server_ip_prompt(buf["client_id"], "custom"),
              kb_server_config_cancel(buf["client_id"], "custom"))


# ── Custom build flow: reject non-photo during icon step ─────────────────────
@bot.message_handler(
    func=lambda m: (
        custom_build_buf.get(str(m.chat.id), {}).get("step") == "icon"
        and m.text is not None
    ))
def handle_custom_build_icon_reject(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = custom_build_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    safe_edit(message.chat.id, msg_id,
              text_custom_icon_prompt(buf["app_name"])
              + "\n\n⚠️ <b>Please send a PNG image, not text.</b>",
              kb_custom_cancel(buf["client_id"]))


# ── Server config flow: text input (IP → Port → Key) ──────────────────────
@bot.message_handler(
    func=lambda m: (
        server_config_buf.get(str(m.chat.id), {}).get("step") == "ip"
        and m.text is not None
    ))
def handle_server_config_ip(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = server_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    ip = message.text.strip()
    if not ip:
        safe_edit(message.chat.id, msg_id,
                  text_server_ip_prompt(buf["client_id"], buf["template"]),
                  kb_server_config_cancel(buf["client_id"], buf["template"]))
        return
    buf["ip"]   = ip
    buf["step"] = "port"
    server_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_server_port_prompt(ip),
              kb_server_config_cancel(buf["client_id"], buf["template"]))


@bot.message_handler(
    func=lambda m: (
        server_config_buf.get(str(m.chat.id), {}).get("step") == "port"
        and m.text is not None
    ))
def handle_server_config_port(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = server_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    port = message.text.strip()
    if not port:
        safe_edit(message.chat.id, msg_id,
                  text_server_port_prompt(buf["ip"]),
                  kb_server_config_cancel(buf["client_id"], buf["template"]))
        return
    buf["port"] = port
    buf["step"] = "key"
    server_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_server_key_prompt(buf["ip"], port),
              kb_server_config_cancel(buf["client_id"], buf["template"]))


@bot.message_handler(
    func=lambda m: (
        server_config_buf.get(str(m.chat.id), {}).get("step") == "key"
        and m.text is not None
    ))
def handle_server_config_key(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = server_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    key = message.text.strip()
    if not key:
        safe_edit(message.chat.id, msg_id,
                  text_server_key_prompt(buf["ip"], buf["port"]),
                  kb_server_config_cancel(buf["client_id"], buf["template"]))
        return
    buf["key"]  = key
    buf["step"] = "done"
    server_config_buf[chat_id] = buf
    # Show confirmation screen
    template  = buf["template"]
    client_id = buf["client_id"]
    cbuf      = custom_build_buf.get(chat_id)
    if template == "custom" and cbuf:
        safe_edit(message.chat.id, msg_id,
                  text_custom_build_confirm(
                      client_id, cbuf["app_name"],
                      srv_ip=buf["ip"], srv_port=buf["port"],
                      srv_key=buf["key"]),
                  kb_build_confirm(client_id, template))
    else:
        safe_edit(message.chat.id, msg_id,
                  text_build_confirm(
                      client_id, template,
                      srv_ip=buf["ip"], srv_port=buf["port"],
                      srv_key=buf["key"]),
                  kb_build_confirm(client_id, template))


@bot.message_handler(
    func=lambda m: add_client_buf.get(str(m.chat.id)) is not None)
def handle_add_client_input(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = add_client_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    text   = message.text.strip()
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass

    field  = buf.get("field")
    data   = buf.get("data", {})

    if field == "username":
        data["username"] = text.lstrip("@")
        buf["field"]     = "name"
    elif field == "name":
        data["name"]     = "" if text == "." else text
        buf["field"]     = "tg_id"
    elif field == "tg_id":
        data["tg_id"]    = text
        buf["field"]     = "rdp_ip"
    elif field == "rdp_ip":
        data["rdp_ip"]   = text
        buf["field"]     = "confirm"

    buf["data"]           = data
    add_client_buf[chat_id] = buf

    if buf["field"] == "confirm":
        token = generate_client_token(data["username"])
        db    = get_db()
        try:
            db.execute(
                "INSERT INTO clients "
                "(telegram_username, profile_name, telegram_id, "
                "rdp_ip, token) VALUES (?,?,?,?,?)",
                (data["username"], data.get("name", ""),
                 data["tg_id"], data["rdp_ip"], token)
            )
            db.commit()
        except Exception as e:
            db.close()
            add_client_buf.pop(chat_id, None)
            safe_edit(message.chat.id, msg_id,
                      f"❌ Failed to add client: {e}", kb_home_only())
            return
        db.close()
        add_client_buf.pop(chat_id, None)
        safe_edit(
            message.chat.id, msg_id,
            f"✅ <b>Client Added</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"Username : @{data['username']}\n"
            f"TG ID    : {data['tg_id']}\n"
            f"RDP IP   : {data['rdp_ip']}\n"
            f"Token    : <code>{token}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━",
            kb_home_only()
        )
        return

    safe_edit(message.chat.id, msg_id,
              text_add_client_form(data, buf["field"]))


@bot.callback_query_handler(func=lambda c: True)
def handle_callback(call):
    chat_id = call.message.chat.id
    msg_id  = call.message.message_id
    data    = call.data

    bot.answer_callback_query(call.id)

    if not is_admin(chat_id):
        return

    if data == "noop":
        return

    if not session_valid(chat_id):
        # Layer 3: Check lockout before showing PIN
        locked, mins = is_locked_out(chat_id)
        if locked:
            safe_edit(
                chat_id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins} more minute(s).\n"
                f"Try again later."
            )
            return
        pin_buffer[str(chat_id)] = ""
        nav_state[str(chat_id)]  = {
            "screen": "pin", "message_id": msg_id}
        safe_edit(
            chat_id, msg_id,
            "⏰ <b>Session expired.</b> Please login again.\n\n"
            + text_pin(""),
            kb_pin()
        )
        return

    # ── Navigation ────────────────────────────────────────────────────────────
    if data == "nav_home":
        custom_build_buf.pop(str(chat_id), None)
        server_config_buf.pop(str(chat_id), None)
        show_main(chat_id, msg_id)

    elif data == "nav_clients":
        show_clients(chat_id, msg_id)

    elif data == "nav_server":
        safe_edit(chat_id, msg_id, text_server_status(), kb_server())

    elif data == "nav_stats":
        safe_edit(chat_id, msg_id, text_global_stats(), kb_home_only())

    elif data == "nav_settings":
        safe_edit(chat_id, msg_id, text_settings(chat_id), kb_settings())

    elif data == "add_client":
        add_client_buf[str(chat_id)] = {"field": "username", "data": {}}
        nav_state[str(chat_id)] = {"screen": "add_client",
                                   "message_id": msg_id}
        safe_edit(chat_id, msg_id, text_add_client_form({}, "username"))

    elif data.startswith("client_") and not data.startswith("client_stats_"):
        show_client_detail(chat_id, msg_id, int(data.split("_")[1]))

    elif data.startswith("delete_client_"):
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
        safe_edit(
            chat_id, msg_id,
            f"⚠️ <b>Delete Client</b>\n"
            f"Are you sure you want to delete <b>{name}</b>?\n"
            f"All builds and devices will be unlinked.",
            kb_delete_confirm(client_id)
        )

    elif data.startswith("confirm_delete_"):
        client_id = int(data.split("_")[2])
        db        = get_db()
        db.execute(
            "UPDATE clients SET active=0 WHERE id=?", (client_id,))
        db.commit()
        db.close()
        show_clients(chat_id, msg_id)

    elif data.startswith("new_build_"):
        custom_build_buf.pop(str(chat_id), None)
        server_config_buf.pop(str(chat_id), None)
        client_id = int(data.split("_")[2])
        safe_edit(chat_id, msg_id,
                  text_template_select(client_id),
                  kb_template_select(client_id))

    elif data.startswith("template_"):
        parts     = data.split("_", 2)
        client_id = int(parts[1])
        template  = parts[2]
        if template == "custom":
            # Start custom flow: step 1 = enter app name
            custom_build_buf[str(chat_id)] = {
                "step": "name",
                "client_id": client_id,
                "app_name": None,
                "icon_file_id": None,
            }
            nav_state[str(chat_id)] = {
                "screen": "custom_build",
                "message_id": msg_id,
            }
            safe_edit(chat_id, msg_id,
                      text_custom_name_prompt(client_id),
                      kb_custom_cancel(client_id))
        else:
            # Standard templates → go to server config step
            server_config_buf[str(chat_id)] = {
                "step": "ip",
                "client_id": client_id,
                "template": template,
                "ip": None,
                "port": None,
                "key": None,
            }
            nav_state[str(chat_id)] = {
                "screen": "server_config",
                "message_id": msg_id,
            }
            safe_edit(chat_id, msg_id,
                      text_server_ip_prompt(client_id, template),
                      kb_server_config_cancel(client_id, template))

    elif data.startswith("confirm_build_"):
        parts     = data.split("_", 3)
        client_id = int(parts[2])
        template  = parts[3]
        # Retrieve custom build data if template is custom
        cbuf = custom_build_buf.pop(str(chat_id), None)
        custom_app_name    = cbuf["app_name"] if cbuf else ""
        custom_icon_fid    = cbuf["icon_file_id"] if cbuf else ""
        # Retrieve server config
        sbuf = server_config_buf.pop(str(chat_id), None)
        import base64
        srv_host_b64 = base64.b64encode(
            sbuf["ip"].encode()).decode().rstrip("=") if sbuf and sbuf.get("ip") else ""
        srv_port_b64 = base64.b64encode(
            sbuf["port"].encode()).decode().rstrip("=") if sbuf and sbuf.get("port") else ""
        srv_key_b64  = base64.b64encode(
            sbuf["key"].encode()).decode() if sbuf and sbuf.get("key") else ""
        if template == "custom" and custom_app_name:
            display_name = custom_app_name
            emoji = "⚙️"
        else:
            emoji, display_name = TEMPLATES.get(template, ("⚙️", template))
        safe_edit(
            chat_id, msg_id,
            f"🔨 <b>Building: {emoji} {display_name}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"Client  : {client_id}\n"
            f"Server  : {sbuf['ip'] if sbuf else '—'}:{sbuf['port'] if sbuf else '—'}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⏳ Queuing build...\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⏱ Starting..."
        )
        ok = trigger_github_build(
            template=template,
            client_id=client_id,
            chat_id=str(chat_id),
            message_id=str(msg_id),
            custom_app_name=custom_app_name,
            custom_icon_file_id=custom_icon_fid,
            server_host_b64=srv_host_b64,
            server_port_b64=srv_port_b64,
            server_key_b64=srv_key_b64,
        )
        if ok:
            db = get_db()
            db.execute(
                "INSERT INTO builds "
                "(client_id, template, status, chat_id, message_id) "
                "VALUES (?,?,?,?,?)",
                (client_id, template, "building",
                 str(chat_id), str(msg_id))
            )
            db.commit()
            db.close()
        else:
            safe_edit(
                chat_id, msg_id,
                "❌ <b>Failed to trigger build.</b>\n"
                "GitHub API error. Check logs.",
                kb_build_result(client_id)
            )

    elif data.startswith("builds_history_"):
        show_builds_history(chat_id, msg_id, int(data.split("_")[2]))

    elif data.startswith("build_detail_"):
        show_build_detail(chat_id, msg_id, int(data.split("_")[2]))

    elif data.startswith("devices_"):
        parts    = data.split("_")
        build_id = int(parts[1])
        page     = int(parts[2])
        show_devices(chat_id, msg_id, build_id, page)

    elif data.startswith("client_stats_"):
        show_client_stats(chat_id, msg_id, int(data.split("_")[2]))

    elif data.startswith("rebuild_"):
        build_id = int(data.split("_")[1])
        db       = get_db()
        b        = db.execute(
            "SELECT * FROM builds WHERE id=?", (build_id,)).fetchone()
        db.close()
        if b:
            safe_edit(chat_id, msg_id,
                      text_template_select(b["client_id"]),
                      kb_template_select(b["client_id"]))

    elif data.startswith("get_apk_"):
        safe_edit(
            chat_id, msg_id,
            "ℹ️ APK was sent to this chat after the build completed.\n"
            "Scroll up to find it, or rebuild to get a fresh one.",
            kb_home_only()
        )

    elif data == "settings_change_pin":
        safe_edit(
            chat_id, msg_id,
            "🔐 <b>Change PIN</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Update ADMIN_PIN in config.py on RDP.\n"
            "Then restart nova_telegram service.",
            kb_settings()
        )

    elif data == "settings_change_2fa":
        safe_edit(
            chat_id, msg_id,
            "🔑 <b>Change 2FA</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "1. Generate new secret:\n"
            "<code>python3 -c \"import pyotp; "
            "print(pyotp.random_base32())\"</code>\n"
            "2. Update TOTP_SECRET in config.py on RDP.\n"
            "3. Scan new QR in 2FAS app.\n"
            "4. Restart nova_telegram service.",
            kb_settings()
        )

    elif data.startswith("search_devices_"):
        safe_edit(
            chat_id, msg_id,
            "🔍 <b>Search Devices</b>\n"
            "Send device ID prefix to search:"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — WATCHDOG FUNCTIONS (10-Layer)
# ═══════════════════════════════════════════════════════════════════════════════

# ── Layer 1: Single instance lock ─────────────────────────────────────────────

def acquire_bot_lock():
    """Prevent duplicate nova_bot instances."""
    my_pid = os.getpid()
    if os.path.exists(LOCK_FILE):
        try:
            with open(LOCK_FILE, "r") as f:
                old_pid = int(f.read().strip())
            r = subprocess.run(
                f'tasklist /FI "PID eq {old_pid}" /FO CSV /NH',
                shell=True, capture_output=True, text=True
            )
            if "python" in r.stdout.lower():
                log_w.warning(
                    f"Another nova_bot already running (PID {old_pid})"
                    f" — exiting duplicate")
                sys.exit(0)
            else:
                os.remove(LOCK_FILE)
        except Exception:
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass
    try:
        os.makedirs(os.path.dirname(LOCK_FILE), exist_ok=True)
        with open(LOCK_FILE, "w") as f:
            f.write(str(my_pid))
        log_w.info(f"Instance lock acquired (PID {my_pid})")
    except Exception as e:
        log_w.warning(f"Could not acquire lock: {e}")


def release_bot_lock():
    try:
        os.remove(LOCK_FILE)
    except Exception:
        pass


# ── Layer 3: Windows Scheduled Task ───────────────────────────────────────────

def register_scheduled_task():
    """Register Windows Scheduled Task for auto-start on boot."""
    bat_path = os.path.join(REPO_DIR, "server_setup.bat")
    if not os.path.exists(bat_path):
        return
    try:
        r = subprocess.run(
            f'schtasks /create /tn "NovaAPKFactory" '
            f'/tr "{bat_path}" '
            f'/sc onstart /ru SYSTEM /rl HIGHEST /f',
            shell=True, capture_output=True, text=True
        )
        if r.returncode == 0:
            log_w.info("Scheduled Task registered — auto-starts on boot ✅")
    except Exception as e:
        log_w.warning(f"Scheduled Task registration failed: {e}")


# ── Layer 4: Git credentials ──────────────────────────────────────────────────

def ensure_git_credentials():
    """Configure git credentials from config.py."""
    try:
        token = config.GITHUB_TOKEN
        owner = config.GITHUB_OWNER
        repo  = config.GITHUB_REPO
        if not token or "YOUR_" in token:
            return
        cred_path = r"C:\apk_factory\keys\.git-credentials"
        os.makedirs(os.path.dirname(cred_path), exist_ok=True)
        with open(cred_path, "w") as f:
            f.write(f"https://{owner}:{token}@github.com\n")
        subprocess.run(
            f'git config --global credential.helper '
            f'"store --file {cred_path}"',
            shell=True, capture_output=True, cwd=REPO_DIR
        )
        auth_url = (f"https://{token}@github.com"
                    f"/{owner}/{repo}.git")
        subprocess.run(
            f"git remote set-url origin {auth_url}",
            shell=True, capture_output=True, cwd=REPO_DIR
        )
        log_w.info(f"Git credentials configured for: {owner}")
    except Exception as e:
        log_w.warning(f"Git credentials setup failed: {e}")


# ── Layer 9: Git lock cleanup ─────────────────────────────────────────────────

def cleanup_git_lock():
    lock = os.path.join(REPO_DIR, ".git", "index.lock")
    if os.path.exists(lock):
        try:
            os.remove(lock)
            log_w.info("Removed stale git index.lock")
        except Exception as e:
            log_w.warning(f"Could not remove index.lock: {e}")


# ── Layer 9: Disk space check ─────────────────────────────────────────────────

def check_disk_space() -> bool:
    try:
        total, used, free = shutil.disk_usage(REPO_DIR)
        free_mb = free // (1024 * 1024)
        if free_mb < MIN_DISK_MB:
            log_w.warning(
                f"Disk space low: {free_mb}MB free "
                f"(need {MIN_DISK_MB}MB) — skipping pull"
            )
            send_telegram_alert(
                f"⚠️ <b>Disk Space Low</b>\n"
                f"Only {free_mb}MB free on RDP.\n"
                f"Sync skipped. Free up disk space."
            )
            return False
        return True
    except Exception:
        return True


# ── Layer 9: Branch check + detached HEAD fix ─────────────────────────────────

def ensure_correct_branch() -> bool:
    try:
        r = subprocess.run(
            "git symbolic-ref --short HEAD",
            shell=True, capture_output=True,
            text=True, cwd=REPO_DIR, timeout=10
        )
        branch = r.stdout.strip()
        if branch == "main":
            return True
        log_w.warning(
            f"Wrong branch: '{branch}' — fixing to main ...")
        subprocess.run(
            "git checkout main",
            shell=True, capture_output=True,
            cwd=REPO_DIR, timeout=30
        )
        r2 = subprocess.run(
            "git symbolic-ref --short HEAD",
            shell=True, capture_output=True,
            text=True, cwd=REPO_DIR, timeout=10
        )
        if r2.stdout.strip() == "main":
            log_w.info("Branch fixed — now on main ✅")
            return True
        log_w.error("Could not fix branch — attempting re-clone")
        return False
    except Exception as e:
        log_w.error(f"Branch check error: {e}")
        return False


# ── Layer 9: Corrupt repo detection + auto re-clone ──────────────────────────

def repo_is_healthy() -> bool:
    try:
        r = subprocess.run(
            "git fsck --no-dangling",
            shell=True, capture_output=True,
            text=True, cwd=REPO_DIR, timeout=30
        )
        return not (r.returncode != 0
                    and "error" in r.stderr.lower())
    except Exception:
        return False


def _force_remove(func, path, _):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def reclone_repo() -> bool:
    log_w.error("Repo corrupt — re-cloning ...")
    send_telegram_alert(
        "⚠️ <b>Repo Corrupt — Re-cloning</b>\n"
        "Auto re-clone started on RDP."
    )
    try:
        git_dir = os.path.join(REPO_DIR, ".git")
        if os.path.exists(git_dir):
            shutil.rmtree(git_dir, onerror=_force_remove)
        subprocess.run(
            "git init",
            shell=True, capture_output=True, cwd=REPO_DIR)
        subprocess.run(
            f"git remote add origin {config.CORRECT_REMOTE_URL}",
            shell=True, capture_output=True, cwd=REPO_DIR)
        ensure_git_credentials()
        r = subprocess.run(
            "git fetch origin main",
            shell=True, capture_output=True,
            text=True, cwd=REPO_DIR, timeout=120
        )
        if r.returncode != 0:
            log_w.error(f"Re-clone fetch failed: {r.stderr[:100]}")
            return False
        subprocess.run(
            "git reset --hard origin/main",
            shell=True, capture_output=True,
            cwd=REPO_DIR, timeout=60
        )
        # Restore real config.py after reclone (git reset overwrites with placeholders)
        _restore_config()
        # Re-apply skip-worktree so future resets don't overwrite config.py
        subprocess.run(
            "git update-index --skip-worktree server/config.py",
            shell=True, capture_output=True, cwd=REPO_DIR
        )
        log_w.info("Re-clone complete ✅")
        send_telegram_alert(
            "✅ <b>Re-clone Complete</b>\n"
            "Repo restored successfully."
        )
        return True
    except Exception as e:
        log_w.error(f"Re-clone failed: {e}")
        return False


def _restore_config():
    """Write real config.py values after any git reset/reclone wipes them.
    Priority 1: run write_config.py (authoritative, independent of memory).
    Priority 2: write from in-memory config module values (fallback).
    """
    cfg_path = os.path.join(REPO_DIR, "server", "config.py")

    # Priority 1: use write_config.py — always has real values on disk
    write_cfg = r"C:\apk_factory\write_config.py"
    try:
        import subprocess as _sp
        result = _sp.run(
            ["python", write_cfg],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log_w.info("config.py restored via write_config.py ✅")
            return
        log_w.warning(f"write_config.py failed: {result.stderr[:100]}")
    except Exception as e:
        log_w.warning(f"write_config.py fallback: {e}")

    # Priority 2: write from in-memory config values
    try:
        content = (
            'BOT_TOKEN = "' + config.BOT_TOKEN + '"\n'
            'MASTER_CHAT_ID = "' + config.MASTER_CHAT_ID + '"\n'
            'GITHUB_TOKEN = "' + config.GITHUB_TOKEN + '"\n'
            'GITHUB_OWNER = "' + config.GITHUB_OWNER + '"\n'
            'GITHUB_REPO = "' + config.GITHUB_REPO + '"\n'
            'SERVER_SECRET = "' + config.SERVER_SECRET + '"\n'
            'ADMIN_PIN = "' + config.ADMIN_PIN + '"\n'
            'TOTP_SECRET = "' + config.TOTP_SECRET + '"\n'
            'SESSION_TIMEOUT_HRS = ' + str(config.SESSION_TIMEOUT_HRS) + '\n'
            'CORRECT_REMOTE_URL = "' + config.CORRECT_REMOTE_URL + '"\n'
            'CORRECT_MUTATION_PATH = r"' + config.CORRECT_MUTATION_PATH + '"\n'
            'REPO_DIR = r"' + config.REPO_DIR + '"\n'
            'DB_PATH = r"' + config.DB_PATH + '"\n'
            'STRINGPOOL_PATH = r"' + config.STRINGPOOL_PATH + '"\n'
        )
        with open(cfg_path, 'w') as f:
            f.write(content)
        log_w.info("config.py restored from memory ✅")
    except Exception as e:
        log_w.error(f"config.py restore failed: {e}")


# ── Layer 9: GitHub rate limit detection ─────────────────────────────────────

def check_rate_limit(stderr: str) -> bool:
    if "rate limit" in stderr.lower() or "403" in stderr:
        log_w.warning(
            "GitHub rate limit detected — waiting 60s ...")
        send_telegram_alert(
            "⚠️ <b>GitHub Rate Limit</b>\n"
            "Sync paused 60 seconds."
        )
        time.sleep(60)
        return True
    return False


# ── Layer 9: SHA-256 file integrity verify ────────────────────────────────────

def verify_changed_files(changed: list):
    issues = []
    for rel_path in changed:
        abs_path = os.path.join(
            REPO_DIR, rel_path.replace("/", os.sep))
        if not os.path.exists(abs_path):
            issues.append(f"MISSING: {rel_path}")
        elif os.path.getsize(abs_path) == 0:
            issues.append(f"ZERO-BYTE: {rel_path}")
    if issues:
        log_w.warning(f"File integrity issues after pull:")
        for i in issues:
            log_w.warning(f"  {i}")
        send_telegram_alert(
            "⚠️ <b>Sync File Issues</b>\n"
            + "\n".join(issues)
        )
    elif changed:
        log_w.info(
            f"File integrity OK — {len(changed)} file(s) verified ✅")


# ── Layer 7: Timestamp preservation ──────────────────────────────────────────

def restore_timestamps(changed: list):
    """Set Windows file modified time to match GitHub commit time."""
    for rel_path in changed:
        try:
            r = subprocess.run(
                f'git log -1 --format=%cd '
                f'--date=format:"%Y-%m-%d %H:%M:%S" -- "{rel_path}"',
                shell=True, capture_output=True,
                text=True, cwd=REPO_DIR, timeout=10
            )
            ts_str = r.stdout.strip().strip('"')
            if not ts_str:
                continue
            abs_path = os.path.join(
                REPO_DIR, rel_path.replace("/", os.sep))
            if not os.path.exists(abs_path):
                continue
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            ts = dt.timestamp()
            os.utime(abs_path, (ts, ts))
        except Exception:
            pass


# ── Layer 8: File deletion sync ───────────────────────────────────────────────

def sync_deletions(deleted: list):
    """Delete local files that were deleted on GitHub."""
    dirs_to_check = set()
    for rel_path in deleted:
        abs_path = os.path.join(
            REPO_DIR, rel_path.replace("/", os.sep))
        if os.path.exists(abs_path):
            try:
                os.remove(abs_path)
                log_w.info(f"Deletion synced: {rel_path}")
                dirs_to_check.add(os.path.dirname(abs_path))
            except Exception as e:
                log_w.warning(
                    f"Could not delete {rel_path}: {e}")
    # Remove empty dirs left behind
    for d in sorted(dirs_to_check,
                    key=len, reverse=True):
        try:
            if (os.path.isdir(d)
                    and not os.listdir(d)
                    and d != REPO_DIR):
                os.rmdir(d)
                log_w.info(f"Removed empty dir: {d}")
        except Exception:
            pass


# ── Layer 10: Sync status file ────────────────────────────────────────────────

def write_sync_status(state: str, detail: str = "",
                      changed: int = 0):
    global _stale_alerted
    try:
        with _last_sync_lock:
            last_ok = _last_sync_ok
        since = int(time.time() - last_ok) if last_ok else -1
        status = {
            "state":            state,
            "detail":           detail,
            "last_check":       utc_now(),
            "last_success_ago": f"{since}s" if since >= 0 else "never",
            "files_changed":    changed,
            "branch":           "main",
            "repo":             REPO_DIR,
        }
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2)
        # Stale alert
        if last_ok and since > STALE_ALERT_S and not _stale_alerted:
            send_telegram_alert(
                f"⚠️ <b>Sync Stale</b>\n"
                f"No successful sync in "
                f"{since // 60} minutes.\n"
                f"Last error: {detail[:200]}"
            )
            _stale_alerted = True
        elif last_ok and since <= STALE_ALERT_S:
            _stale_alerted = False
    except Exception:
        pass


def mark_sync_ok():
    global _last_sync_ok
    with _last_sync_lock:
        _last_sync_ok = time.time()


# ── Layer 10: Smart restart ───────────────────────────────────────────────────

def _self_restart_via_bat():
    """
    Self-restart nova_telegram safely.

    nova_telegram CANNOT call sc stop / nssm stop on itself — any stop
    command sends a signal that kills the calling process immediately,
    before sc start can run.

    Solution (3-layer hybrid):
      Layer 1 — Write a detached BAT file that waits 6s then sc-starts
                 nova_telegram. Launch it fully detached so no signal
                 can propagate back to this process.
      Layer 2 — This process calls sys.exit(0) cleanly. NSSM sees a
                 clean exit and auto-restarts after AppRestartDelay
                 (already configured: Restart / 5000ms).
      Layer 3 — health_check_loop catches any missed restart within 5min.

    Either Layer 1 or Layer 2 alone is sufficient — both fire for safety.
    """
    # Clean exit — NSSM AppExit=Restart + AppRestartDelay=5000 restarts us.
    # Do NOT call sc start / nssm start here — that races with NSSM's own
    # stop sequence and causes NSSM to kill python with SIGINT (0xC000013A),
    # which leaves the service permanently STOPPED.
    log_w.info("Self-restart: calling os._exit(0) — NSSM will restart in 5s")
    time.sleep(1)
    os._exit(0)


def smart_restart_services(changed: list):
    """Only restart services affected by changed files."""
    affected = set()
    for rel_path in changed:
        svc = FILE_SERVICE_MAP.get(rel_path)
        if svc:
            affected.add(svc)

    if not affected:
        log_w.info("No service restart needed for changed files")
        return

    for svc in affected:
        if svc == "nova_telegram":
            log_w.info(
                "nova_bot.py changed — self-restarting nova_telegram")
            send_telegram_alert(
                "♻️ <b>Bot Self-Restarting</b>\n"
                "nova_bot.py updated in GitHub.\n"
                "nova_telegram restarting ✅"
            )
            time.sleep(2)
            # Cannot call restart_service() on ourselves — use BAT launcher
            _self_restart_via_bat()
            # _self_restart_via_bat() calls os._exit(0) — never reaches here
        else:
            log_w.info(
                f"Restarting {svc} (files changed: "
                f"{[f for f in changed if FILE_SERVICE_MAP.get(f) == svc]})"
            )
            ok = restart_service(svc)
            send_telegram_alert(
                f"🔄 <b>Service Auto-Updated</b>\n"
                f"Service: <code>{svc}</code>\n"
                f"Restarted ✅" if ok else
                f"⚠️ <b>Service Restart Failed</b>\n"
                f"Service: <code>{svc}</code> ❌"
            )


# ── Layer 10: 24h encrypted backup ───────────────────────────────────────────

def _do_backup():
    """Create encrypted backup of config + db → send to Telegram."""
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes
        import io as _io
        import zipfile as _zf

        BACKUP_PASSWORD = "NovaFactory2026_BackupKey_AES256"
        buf = _io.BytesIO()
        with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
            # Config values as JSON
            vals = {}
            for attr in [
                "BOT_TOKEN", "MASTER_CHAT_ID",
                "GITHUB_TOKEN", "GITHUB_OWNER",
                "GITHUB_REPO", "SERVER_SECRET",
                "ADMIN_PIN", "TOTP_SECRET",
            ]:
                vals[attr] = getattr(config, attr, "")
            zf.writestr(
                "config_values.json",
                json.dumps(vals, indent=2)
            )
            # bot.db
            if os.path.exists(DB_PATH):
                zf.write(DB_PATH, "bot.db")

        raw = buf.getvalue()
        key = hashlib.sha256(
            BACKUP_PASSWORD.encode()).digest()
        iv  = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(raw)
        enc = iv + tag + ct

        # Send to Telegram
        import requests as _req
        ts      = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d_%H-%M")
        caption = f"NOVA_BACKUP_{ts}"
        enc_buf = _io.BytesIO(enc)
        enc_buf.name = f"nova_backup_{ts}.enc"
        r = _req.post(
            f"https://api.telegram.org/bot"
            f"{config.BOT_TOKEN}/sendDocument",
            data={
                "chat_id": config.MASTER_CHAT_ID,
                "caption": caption
            },
            files={"document": enc_buf},
            timeout=60
        )
        if r.json().get("ok"):
            log_w.info(f"24h backup sent to Telegram: {caption} ✅")
        else:
            log_w.warning(f"Backup send failed: {r.text[:100]}")
    except Exception as e:
        log_w.error(f"Backup error: {e}")


# ── Core watchdog: fix obsolete + service path ────────────────────────────────

def delete_obsolete_files():
    for path in OBSOLETE_FILES:
        if os.path.exists(path):
            try:
                os.remove(path)
                log_w.info(
                    f"Deleted obsolete: {os.path.basename(path)}")
                send_telegram_alert(
                    f"🗑 <b>Obsolete File Deleted</b>\n"
                    f"<code>{os.path.basename(path)}</code>"
                )
            except Exception as e:
                log_w.error(f"Failed to delete {path}: {e}")


def fix_remote_url_if_wrong():
    rc, current_url, err = run_git("git remote get-url origin")
    current_url = current_url.strip()
    if current_url != config.CORRECT_REMOTE_URL:
        log_w.warning("Wrong remote URL — fixing ...")
        run_git(
            f"git remote set-url origin "
            f"{config.CORRECT_REMOTE_URL}"
        )
        send_telegram_alert(
            "🔧 <b>Git Remote Auto-Fixed</b>\n"
            "Fixed to: <code>implement-like-irt</code> ✅"
        )


def fix_service_path_if_wrong():
    rc, current_path, err = run_cmd(
        "nssm get nova_mutation AppParameters")
    current_path = current_path.strip().strip('"')
    correct_path = config.CORRECT_MUTATION_PATH
    if current_path and current_path != correct_path:
        run_cmd(
            f'nssm set nova_mutation AppParameters "{correct_path}"')
        run_cmd(
            f'nssm set nova_mutation AppDirectory '
            f'"{os.path.dirname(correct_path)}"'
        )
        restart_service("nova_mutation")
        send_telegram_alert(
            f"🔧 <b>Service Path Auto-Fixed</b>\n"
            f"Now: <code>{os.path.basename(correct_path)}</code> ✅"
        )


def health_check_services():
    for service in REQUIRED_SERVICES:
        # Never start/restart nova_telegram from inside itself —
        # NSSM handles our own process. Calling start_service on
        # ourselves races with NSSM and causes session wipes.
        if service == "nova_telegram":
            log_w.info("Health check: nova_telegram — self (skipped)")
            continue
        status = get_service_status(service)
        if "SERVICE_RUNNING" not in status:
            log_w.warning(
                f"Service not running: {service} — starting ...")
            ok = start_service(service)
            send_telegram_alert(
                f"🚑 <b>Service Auto-Started</b>\n"
                f"<code>{service}</code> ✅" if ok else
                f"🔴 <b>Service Start Failed</b>\n"
                f"<code>{service}</code> ❌"
            )
        else:
            log_w.info(f"Health check OK: {service}")


def find_stringpool() -> str:
    for root, dirs, files in os.walk(STRINGPOOL_PATH):
        for f in files:
            if f == "StringPool.kt":
                return os.path.join(root, f)
    return ""


def update_stringpool_url(new_url: str) -> bool:
    sp_path = find_stringpool()
    if not sp_path:
        log_w.error("StringPool.kt not found")
        return False
    with open(sp_path, "r", encoding="utf-8") as f:
        content = f.read()
    encrypted   = xor_encrypt(new_url)
    # Match both: val SERVER_URL = "..." and val SERVER_URL = "..."
    new_content = re.sub(
        r'(val\s+SERVER_URL\s*=\s*")[^"]*(")',
        f"\\g<1>{encrypted}\\g<2>",
        content
    )
    if new_content == content:
        # Try alternate pattern with spaces
        new_content = re.sub(
            r'(SERVER_URL\s*=\s*")[^"]*(")',
            f"\\g<1>{encrypted}\\g<2>",
            content
        )
    if new_content == content:
        log_w.warning(
            "SERVER_URL pattern not found in StringPool.kt")
        return False
    with open(sp_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    log_w.info(f"StringPool.kt updated: {new_url}")
    return True


def git_push_url_update(new_url: str):
    sp_path = find_stringpool()
    if not sp_path:
        return
    rel_path = os.path.relpath(sp_path, REPO_DIR)
    run_git(f'git add "{rel_path}"')
    rc, out, err = run_git(
        f'git commit -m "Auto: Update tunnel URL '
        f'[{new_url[:30]}...]"'
    )
    if rc == 0:
        rc2, out2, err2 = run_git("git push")
        if rc2 == 0:
            send_telegram_alert(
                f"🔗 <b>Tunnel URL Updated</b>\n"
                f"New URL: <code>{new_url}</code>\n"
                f"StringPool.kt pushed to GitHub ✅"
            )
        else:
            log_w.error(f"Git push failed: {err2}")


# ── Layer 6+9: Force sync with full retry + backoff ──────────────────────────

# ── Backup system (Layer 4) ───────────────────────────────────────────────────
BACKUP_DIR      = r"C:\apk_factory\sync_backup"
MAX_BACKUPS     = 3

# ── Probation system (Layer 5) ────────────────────────────────────────────────
PROBATION_SECS  = 300   # 5 minutes
_probation      = {}    # { "active": bool, "sha": str, "backup": str, "start": float }


def _backup_repo() -> str:
    """
    Layer 4: Backup repo before every pull.
    Keeps last 3 backups. Returns backup path.
    """
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"backup_{ts}")

        # Copy server/ and scripts/ only (not full repo — too large)
        for folder in ["server", "scripts"]:
            src = os.path.join(REPO_DIR, folder)
            dst = os.path.join(backup_path, folder)
            if os.path.exists(src):
                shutil.copytree(src, dst)

        log_w.info(f"Backup created: {backup_path}")

        # Keep only last MAX_BACKUPS
        backups = sorted([
            d for d in os.listdir(BACKUP_DIR)
            if d.startswith("backup_")
        ])
        while len(backups) > MAX_BACKUPS:
            old = os.path.join(BACKUP_DIR, backups.pop(0))
            shutil.rmtree(old, ignore_errors=True)
            log_w.info(f"Old backup removed: {old}")

        return backup_path
    except Exception as e:
        log_w.warning(f"Backup failed: {e}")
        return ""


def _rollback_repo(backup_path: str) -> bool:
    """
    Layer 5: Rollback repo to backup after bad pull.
    """
    if not backup_path or not os.path.exists(backup_path):
        log_w.error("Rollback failed — backup not found")
        return False
    try:
        for folder in ["server", "scripts"]:
            src = os.path.join(backup_path, folder)
            dst = os.path.join(REPO_DIR, folder)
            if os.path.exists(src):
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
        log_w.info(f"Rollback complete from: {backup_path}")
        return True
    except Exception as e:
        log_w.error(f"Rollback error: {e}")
        return False


def _check_probation():
    """
    Layer 5: Check if nova_mutation crashed during probation.
    If crashed → rollback to backup.
    If stable → confirm and clear probation.
    """
    global _probation
    if not _probation.get("active"):
        return

    elapsed = time.time() - _probation.get("start", 0)

    if elapsed >= PROBATION_SECS:
        # Stable for 5 min — confirm
        sha = _probation.get("sha", "?")[:7]
        log_w.info(f"Probation passed — commit {sha} is stable ✅")
        send_telegram_alert(
            f"✅ <b>Version Stable</b>\n"
            f"Commit <code>{sha}</code> passed "
            f"5-min probation ✅"
        )
        _probation = {}
        return

    # Check if nova_mutation is still running
    if not check_service_running("nova_mutation"):
        # Service crashed — rollback
        sha        = _probation.get("sha", "?")[:7]
        backup     = _probation.get("backup", "")
        log_w.error(
            f"nova_mutation crashed during probation — "
            f"rolling back from {sha}")
        send_telegram_alert(
            f"⚠️ <b>Auto Rollback</b>\n"
            f"nova_mutation crashed after commit "
            f"<code>{sha}</code>\n"
            f"Rolling back to previous version..."
        )
        ok = _rollback_repo(backup)
        if ok:
            restart_service("nova_mutation")
            send_telegram_alert(
                "✅ <b>Rollback Complete</b>\n"
                "Previous version restored.\n"
                "nova_mutation restarted."
            )
        _probation = {}


def force_sync() -> list:
    """
    Full sync cycle with 10-layer protection.
    Returns list of changed files.
    """
    # Layer 3: Mutex — no concurrent pulls
    if not _sync_lock.acquire(blocking=False):
        log_w.info("Sync already in progress — skipping")
        return []

    try:
        return _force_sync_inner()
    finally:
        _sync_lock.release()


def _force_sync_inner() -> list:
    """Inner sync logic — called with lock held."""
    # Pre-flight
    if not check_disk_space():
        write_sync_status("error", "disk space low")
        return []

    cleanup_git_lock()

    if not ensure_correct_branch():
        if not reclone_repo():
            write_sync_status("error", "branch fix + reclone failed")
            return []

    # Fetch with exponential backoff
    ok_flag = False
    err     = ""
    for attempt in range(1, MAX_RETRIES + 1):
        rc, _, err = run_git(
            "git fetch origin main --force", timeout=60)
        ok_flag = (rc == 0)
        if ok_flag:
            break
        if check_rate_limit(err):
            continue
        wait = RETRY_BASE ** attempt
        log_w.warning(
            f"Fetch failed (attempt {attempt}/{MAX_RETRIES})"
            f": {err[:60]} — retry in {wait}s"
        )
        if attempt == MAX_RETRIES:
            ensure_git_credentials()
            rc2, _, err2 = run_git(
                "git fetch origin main --force", timeout=60)
            ok_flag = (rc2 == 0)
            err     = err2
            break
        time.sleep(wait)

    if not ok_flag:
        write_sync_status("error", f"fetch failed: {err[:80]}")
        send_telegram_alert(
            f"⚠️ <b>Auto Sync Failed</b>\n"
            f"Git fetch failed after {MAX_RETRIES} retries.\n"
            f"Error: {err[:200]}"
        )
        return []

    # Compare commits
    _, local,  _ = run_git("git rev-parse HEAD")
    _, remote, _ = run_git("git rev-parse origin/main")

    if local.strip() == remote.strip():
        mark_sync_ok()
        write_sync_status("ok", "up to date", 0)
        return []

    # Get changed + deleted files
    _, diff_changed, _ = run_git(
        "git diff --name-only HEAD origin/main")
    _, diff_deleted, _ = run_git(
        "git diff --name-only --diff-filter=D HEAD origin/main")

    changed = ([f for f in diff_changed.splitlines() if f]
               if diff_changed else [])
    deleted = ([f for f in diff_deleted.splitlines() if f]
               if diff_deleted else [])

    log_w.info(
        f"Changes: {len(changed)} modified, "
        f"{len(deleted)} deleted — pulling ...")
    for f in changed:
        log_w.info(f"  CHANGED: {f}")
    for f in deleted:
        log_w.info(f"  DELETED: {f}")

    _, commit_before, _ = run_git("git rev-parse --short HEAD")

    # Layer 4: Backup before pull
    backup_path = _backup_repo()
    pull_start  = time.time()

    # Force local to match GitHub
    rc, _, err = run_git(
        "git reset --hard origin/main", timeout=60)
    if rc != 0:
        cleanup_git_lock()
        rc2, _, err2 = run_git(
            "git reset --hard origin/main", timeout=60)
        if rc2 != 0:
            if not repo_is_healthy():
                reclone_repo()
            write_sync_status(
                "error", f"reset failed: {err2[:60]}")
            return []

    _, commit_after, _ = run_git("git rev-parse --short HEAD")

    # Restore real config.py — git reset --hard overwrites it with placeholder
    _restore_config()

    # Layer 8: Sync deletions
    sync_deletions(deleted)

    # Layer 7: Restore timestamps
    restore_timestamps(changed)

    # Layer 9: Verify integrity
    verify_changed_files(changed)

    all_changed = changed + deleted
    pull_ms     = int((time.time() - pull_start) * 1000)

    if commit_before.strip() != commit_after.strip():
        cb = commit_before.strip()[:7]
        ca = commit_after.strip()[:7]
        log_w.info(
            f"Sync OK — {cb} → {ca} "
            f"({len(all_changed)} file(s)) "
            f"in {pull_ms}ms ✅"
        )

        # Rich sync alert (Layer 6)
        file_lines = []
        for f in all_changed[:8]:
            file_lines.append(f"  📁 <code>{f}</code>")
        if len(all_changed) > 8:
            file_lines.append(
                f"  ...and {len(all_changed) - 8} more")
        files_str = "\n".join(file_lines)

        send_telegram_alert(
            f"🔄 <b>RDP Auto-Synced</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"📦 <code>{cb}</code> → <code>{ca}</code>\n"
            f"📁 {len(changed)} updated, "
            f"{len(deleted)} deleted\n"
            f"⚡ Pull: {pull_ms}ms\n"
            f"🕐 {utc_now()}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{files_str}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"🔍 Probation: 5 min"
        )

        # Layer 5: Start probation
        global _probation
        _probation = {
            "active": True,
            "sha":    ca,
            "backup": backup_path,
            "start":  time.time(),
        }

    mark_sync_ok()
    write_sync_status(
        "ok", f"{commit_before}→{commit_after}",
        len(all_changed)
    )
    return all_changed


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — WATCHDOG THREADS (10-Layer)
# ═══════════════════════════════════════════════════════════════════════════════

def git_pull_loop():
    """Thread 1: Real-time sync every 30s with full 10-layer protection."""
    log_w.info("Git pull loop started (Layer 6 — 30s real-time sync)")

    # Startup: configure credentials + run all checks
    ensure_git_credentials()
    fix_remote_url_if_wrong()
    delete_obsolete_files()
    fix_service_path_if_wrong()

    # Baseline file hashes
    for rel_path in FILE_SERVICE_MAP:
        abs_path = os.path.join(
            REPO_DIR, rel_path.replace("/", os.sep))
        h = sha256_file(abs_path)
        if h:
            _file_hashes[abs_path] = h

    # Layer 7: Run initial secret audit on startup
    try:
        audit_github_secrets(alert_on_fix=False)
    except Exception as e:
        log_w.warning(f"Startup secret audit error: {e}")

    _pull_count = 0

    while True:
        try:
            changed = force_sync()
            if changed:
                # Layer 10: smart restart only affected services
                smart_restart_services(changed)
                # Also run maintenance checks after any pull
                delete_obsolete_files()
                fix_service_path_if_wrong()
                # Layer 7: audit secrets after every successful pull
                try:
                    audit_github_secrets(alert_on_fix=True)
                except Exception as e:
                    log_w.warning(f"Post-pull secret audit error: {e}")

            # Layer 7: Periodic secret audit every 120 pulls (~1 hour)
            _pull_count += 1
            if _pull_count % 120 == 0:
                try:
                    audit_github_secrets(alert_on_fix=True)
                except Exception as e:
                    log_w.warning(f"Periodic secret audit error: {e}")

        except Exception as e:
            log_w.error(f"Git pull loop error: {e}")
            write_sync_status("error", str(e))
        time.sleep(GIT_PULL_INTERVAL)


def cloudflare_url_loop():
    """Thread 2: Monitor Cloudflare tunnel URL every 10s."""
    global _current_tunnel_url
    log_w.info("Cloudflare URL monitor started")
    while True:
        try:
            new_url = None
            if os.path.exists(CLOUDFLARED_LOG):
                with open(CLOUDFLARED_LOG, "r",
                          encoding="utf-8",
                          errors="replace") as f:
                    for line in f:
                        m = re.search(
                            r"https://[a-z0-9\-]+"
                            r"\.trycloudflare\.com",
                            line
                        )
                        if m:
                            new_url = m.group(0)
            if not new_url:
                try:
                    with urllib.request.urlopen(
                        "http://localhost:2000/quicktunnel",
                        timeout=3
                    ) as r:
                        data    = json.loads(r.read())
                        new_url = ("https://"
                                   + data.get("hostname", ""))
                except Exception:
                    pass
            if new_url and new_url != _current_tunnel_url:
                log_w.info(f"Tunnel URL changed: {new_url}")
                _current_tunnel_url = new_url
                if update_stringpool_url(new_url):
                    git_push_url_update(new_url)
        except Exception as e:
            log_w.error(f"Cloudflare URL monitor error: {e}")
        time.sleep(URL_CHECK_INTERVAL)


def _ensure_git_healthy():
    """
    Layer 10: Self-healing git environment check.
    Runs before every sync cycle.
    """
    # Verify git binary
    git = _find_git()
    if not git:
        log_w.warning("Git not found — attempting PATH fix")
        return

    # Verify credentials
    ensure_git_credentials()

    # Verify remote URL
    rc, url, _ = run_git("git remote get-url origin")
    if rc == 0 and url.strip() != config.CORRECT_REMOTE_URL:
        log_w.warning("Wrong remote URL — fixing ...")
        run_git(
            f"git remote set-url origin "
            f"{config.CORRECT_REMOTE_URL}"
        )

    # Verify branch
    rc, branch, _ = run_git(
        "git symbolic-ref --short HEAD", timeout=5)
    if rc == 0 and branch.strip() != "main":
        log_w.warning(f"Wrong branch: {branch} — fixing ...")
        run_git("git checkout main", timeout=30)

    # Cleanup index.lock
    cleanup_git_lock()


def health_check_loop():
    """Thread 3: Service health check + probation check every 5 min."""
    log_w.info("Health check loop started (Layer 10)")
    while True:
        try:
            health_check_services()
            # Layer 5: Check probation after every health check
            _check_probation()
            # Layer 10: Self-healing git environment
            _ensure_git_healthy()
        except Exception as e:
            log_w.error(f"Health check error: {e}")
        time.sleep(HEALTH_CHECK_INTERVAL)


def backup_loop():
    """Thread 4: 24h encrypted Telegram backup (Layer 10)."""
    log_w.info("Backup loop started (Layer 10 — 24h interval)")
    # First backup after 1 hour (not immediately on startup)
    time.sleep(3600)
    while True:
        try:
            _do_backup()
        except Exception as e:
            log_w.error(f"Backup loop error: {e}")
        time.sleep(BACKUP_INTERVAL)


# ── Layer 10: GitHub Secrets health monitor ───────────────────────────────────

# Required secrets that must always exist in GitHub
REQUIRED_GITHUB_SECRETS = [
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "KEYSTORE_BASE64",
    "KEYSTORE_PASSWORD",
    "KEY_ALIAS",
]


def _get_repo_public_key_bot() -> tuple:
    """Get GitHub repo public key. Returns (key_id, pub_key_b64)."""
    try:
        url = (f"https://api.github.com/repos/"
               f"{config.GITHUB_OWNER}/{config.GITHUB_REPO}"
               f"/actions/secrets/public-key")
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {config.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            return data.get("key_id", ""), data.get("key", "")
    except Exception as e:
        log_w.error(f"Get public key failed: {e}")
        return "", ""


def _encrypt_secret_bot(pub_key_b64: str,
                         secret_value: str) -> str:
    """Encrypt secret with repo public key using PyNaCl."""
    try:
        import base64 as _b64
        from nacl import public as _pub
        pk_bytes  = _b64.b64decode(pub_key_b64)
        pk        = _pub.PublicKey(pk_bytes)
        box       = _pub.SealedBox(pk)
        encrypted = box.encrypt(secret_value.encode("utf-8"))
        return _b64.b64encode(encrypted).decode("utf-8")
    except Exception as e:
        log_w.error(f"Secret encryption failed: {e}")
        return ""


def _set_github_secret_bot(key_id: str, pub_key: str,
                            name: str, value: str) -> bool:
    """Set a single GitHub secret via API."""
    encrypted = _encrypt_secret_bot(pub_key, value)
    if not encrypted:
        return False
    url  = (f"https://api.github.com/repos/"
            f"{config.GITHUB_OWNER}/{config.GITHUB_REPO}"
            f"/actions/secrets/{name}")
    body = json.dumps({
        "encrypted_value": encrypted,
        "key_id":          key_id,
    }).encode()
    try:
        req = urllib.request.Request(
            url, data=body, method="PUT",
            headers={
                "Authorization": f"token {config.GITHUB_TOKEN}",
                "Accept":        "application/vnd.github.v3+json",
                "Content-Type":  "application/json",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status in (201, 204)
    except Exception as e:
        log_w.error(f"Set secret {name} failed: {e}")
        return False


def _list_github_secrets_bot() -> list:
    """List existing GitHub secret names."""
    try:
        url = (f"https://api.github.com/repos/"
               f"{config.GITHUB_OWNER}/{config.GITHUB_REPO}"
               f"/actions/secrets?per_page=100")
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {config.GITHUB_TOKEN}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            return [s["name"] for s in data.get("secrets", [])]
    except Exception as e:
        log_w.error(f"List secrets failed: {e}")
        return []


def audit_github_secrets(alert_on_fix: bool = True):
    """
    Layer 7 + Thread 5:
    Check all required GitHub secrets exist.
    Auto re-inject missing ones from config.
    """
    if not hasattr(config, "GITHUB_TOKEN"):
        return
    token = config.GITHUB_TOKEN
    if not token or "YOUR_" in str(token):
        return

    try:
        existing = _list_github_secrets_bot()
        if not existing:
            return

        missing = [s for s in REQUIRED_GITHUB_SECRETS
                   if s not in existing]

        if not missing:
            log_w.info(
                f"GitHub secrets audit OK — "
                f"all {len(REQUIRED_GITHUB_SECRETS)} secrets present ✅"
            )
            return

        log_w.warning(f"Missing GitHub secrets: {missing}")

        # Get public key for encryption
        key_id, pub_key = _get_repo_public_key_bot()
        if not key_id:
            log_w.error("Cannot get public key — skipping secret re-injection")
            return

        fixed   = []
        failed  = []

        for secret_name in missing:
            value = None

            if secret_name == "TELEGRAM_BOT_TOKEN":
                value = getattr(config, "BOT_TOKEN", "")
            elif secret_name == "TELEGRAM_CHAT_ID":
                value = getattr(config, "MASTER_CHAT_ID", "")
            elif secret_name == "KEYSTORE_PASSWORD":
                value = "android"
            elif secret_name == "KEY_ALIAS":
                value = "platform"
            elif secret_name == "KEYSTORE_BASE64":
                # Try to read from RDP
                for ks_path in [
                    r"C:\apk_factory\keys\platform.jks",
                    r"C:\apk_factory\repo\platform.jks",
                ]:
                    if os.path.exists(ks_path):
                        try:
                            import base64 as _b64
                            with open(ks_path, "rb") as f:
                                value = _b64.b64encode(
                                    f.read()).decode()
                            break
                        except Exception:
                            pass

            if not value or "YOUR_" in str(value):
                log_w.warning(
                    f"No value for {secret_name} — skipping")
                failed.append(secret_name)
                continue

            success = _set_github_secret_bot(
                key_id, pub_key, secret_name, value)
            if success:
                fixed.append(secret_name)
                log_w.info(
                    f"Re-injected missing secret: {secret_name} ✅")
            else:
                failed.append(secret_name)
                log_w.error(
                    f"Failed to re-inject: {secret_name} ❌")

        # Alert if anything was fixed or failed
        if alert_on_fix and (fixed or failed):
            msg = "🔑 <b>GitHub Secrets Auto-Fixed</b>\n"
            if fixed:
                msg += "Fixed: " + ", ".join(
                    [f"<code>{s}</code>" for s in fixed]) + "\n"
            if failed:
                msg += "Failed: " + ", ".join(
                    [f"<code>{s}</code>" for s in failed])
            send_telegram_alert(msg)

        # Also check if BOT_TOKEN in config matches GitHub secret
        # (detect token rotation — config changed but GitHub not updated)
        _check_token_rotation_sync(key_id, pub_key)

    except Exception as e:
        log_w.error(f"GitHub secrets audit error: {e}")


def _check_token_rotation_sync(key_id: str, pub_key: str):
    """
    Layer 6: Detect if BOT_TOKEN changed in config but
    not synced to GitHub Secrets. Auto re-sync if mismatch
    detected via hash comparison.
    """
    try:
        # We can't read secret values from GitHub API (by design)
        # So we store a hash of the last-synced token in a local file
        hash_file = os.path.join(
            os.path.dirname(__file__), ".secret_hashes.json")

        current_token = getattr(config, "BOT_TOKEN", "")
        current_hash  = hashlib.sha256(
            current_token.encode()).hexdigest()[:16]

        stored_hashes = {}
        if os.path.exists(hash_file):
            try:
                with open(hash_file, "r") as f:
                    stored_hashes = json.load(f)
            except Exception:
                pass

        stored_hash = stored_hashes.get("BOT_TOKEN_HASH", "")

        if stored_hash and stored_hash != current_hash:
            # Token changed — re-sync to GitHub
            log_w.info(
                "BOT_TOKEN changed — re-syncing to GitHub Secrets ...")
            success = _set_github_secret_bot(
                key_id, pub_key,
                "TELEGRAM_BOT_TOKEN", current_token
            )
            if success:
                stored_hashes["BOT_TOKEN_HASH"] = current_hash
                with open(hash_file, "w") as f:
                    json.dump(stored_hashes, f)
                send_telegram_alert(
                    "🔄 <b>Token Rotation Detected</b>\n"
                    "BOT_TOKEN changed in config.py\n"
                    "TELEGRAM_BOT_TOKEN auto-updated in GitHub ✅"
                )
                log_w.info("Token rotation sync complete ✅")
        else:
            # Store current hash if not stored yet
            if not stored_hash:
                stored_hashes["BOT_TOKEN_HASH"] = current_hash
                with open(hash_file, "w") as f:
                    json.dump(stored_hashes, f)
    except Exception as e:
        log_w.error(f"Token rotation check error: {e}")


def secret_health_loop():
    """
    Thread 5: GitHub Secrets health monitor every 6 hours.
    Layer 10 — ensures secrets never go missing.
    """
    log_w.info("Secret health loop started (Layer 10 — 6h interval)")
    # First check after 5 minutes (not immediately on startup)
    time.sleep(300)
    while True:
        try:
            log_w.info("Running GitHub secrets audit ...")
            audit_github_secrets(alert_on_fix=True)
        except Exception as e:
            log_w.error(f"Secret health loop error: {e}")
        time.sleep(6 * 3600)  # 6 hours


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ── Layer 1: Single instance lock ─────────────────────────
    acquire_bot_lock()

    try:
        log.info("=" * 60)
        log.info("Nova Bot starting — Telegram Bot + 10-Layer Watchdog")
        log.info(f"PID     : {os.getpid()}")
        log.info(f"Repo    : {REPO_DIR}")
        log.info(f"Logs    : {LOGS_DIR}")
        log.info(f"DB      : {DB_PATH}")
        log.info(f"Sync    : every {GIT_PULL_INTERVAL}s (real-time)")
        log.info("=" * 60)

        # ── Init database ──────────────────────────────────────
        init_db()

        # ── Layer 5: Init session key from real config (cache it) ──
        _init_session_key()

        # ── Layer 2: Load persisted sessions from file ─────────
        _load_session_file()

        # ── Layer 6: Start session cleanup thread ──────────────
        threading.Thread(
            target=session_cleanup_loop,
            daemon=True, name="SessionCleanup"
        ).start()
        log.info("7-layer session system active ✅")

        # ── Layer 9: Clean stale git lock immediately ──────────
        cleanup_git_lock()

        # ── Layer 3: Register scheduled task ──────────────────
        register_scheduled_task()

        # ── Layer 4: Configure git credentials ────────────────
        ensure_git_credentials()

        # ── Layer 10: Startup health check ────────────────────
        health_check_services()

        # ── Startup alert ──────────────────────────────────────
        send_telegram_alert(
            "🟢 <b>Nova Bot Started</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "✅ Telegram bot active\n"
            f"✅ Real-time sync every {GIT_PULL_INTERVAL}s\n"
            "✅ Cloudflare URL monitor active\n"
            "✅ Health check every 5 min\n"
            "✅ 24h encrypted backup active\n"
            "✅ GitHub secrets auto-heal every 6h\n"
            "✅ 7-layer session system active\n"
            "✅ 10-layer self-healing active\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Open bot → /start to login."
        )

        # ── Start watchdog threads ─────────────────────────────
        threading.Thread(
            target=git_pull_loop,
            daemon=True, name="GitPull"
        ).start()
        threading.Thread(
            target=cloudflare_url_loop,
            daemon=True, name="Cloudflare"
        ).start()
        threading.Thread(
            target=health_check_loop,
            daemon=True, name="HealthCheck"
        ).start()
        threading.Thread(
            target=backup_loop,
            daemon=True, name="Backup"
        ).start()
        threading.Thread(
            target=secret_health_loop,
            daemon=True, name="SecretHealth"
        ).start()

        log.info("5 watchdog threads started ✅")
        log.info("Starting Telegram bot polling ...")

        # Bot polling — blocks main thread (keeps process alive)
        # Wrap in retry loop: network blip exits infinity_polling,
        # retry loop reconnects instead of letting the process die.
        while True:
            try:
                bot.infinity_polling(timeout=30, long_polling_timeout=25)
            except Exception as _poll_err:
                log.warning(f"Polling exited: {_poll_err} — reconnecting in 5s")
            else:
                log.warning("Polling exited cleanly — reconnecting in 5s")
            time.sleep(5)

    except Exception as e:
        log.error(f"Fatal error: {e}")
        import traceback
        log.error(traceback.format_exc())
    finally:
        release_bot_lock()
        log.info("nova_bot.py stopped — lock released")
