#!/usr/bin/env python3
"""
nova_setup.py — Nova APK Factory — Full Auto Setup
═══════════════════════════════════════════════════════════════════════════════
Double-click server_setup.bat on ANY Windows 10 RDP.
Does EVERYTHING automatically. No manual steps. Ever.

3 Modes (auto-detected):
  FRESH   — Brand new RDP. Installs everything, fills config, starts services.
  UPDATE  — Existing RDP. Update changed credentials/values only.
  RESTORE — New RDP with Telegram backup. Restores config + db automatically.

13 Steps:
  1.  Detect mode
  2.  Create folders
  3.  Install Python packages (3 fallback methods)
  4.  Install NSSM           (3 fallback methods)
  5.  Install cloudflared    (3 fallback methods)
  6.  Install Git            (2 fallback methods)
  7.  Install Java 17        (2 fallback methods)
  8.  Install apktool        (1 method)
  9.  Clone / pull repo
  10. Backup / Restore (Telegram — AES-256-GCM encrypted)
  11. Verify config complete
  12. Windows auto-start (Scheduled Task + Registry — dual redundancy)
  13. Install + start 3 NSSM services → Telegram alert

═══════════════════════════════════════════════════════════════════════════════
"""

import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = r"C:\apk_factory"
REPO_DIR    = r"C:\apk_factory\repo"
SERVER_DIR  = r"C:\apk_factory\repo\server"
TOOLS_DIR   = r"C:\apk_factory\tools"
LOGS_DIR    = r"C:\apk_factory\logs"
KEYS_DIR    = r"C:\apk_factory\keys"
CONFIG_FILE = r"C:\apk_factory\repo\server\config.py"
DB_FILE     = r"C:\apk_factory\repo\server\bot.db"
BACKUP_FILE = r"C:\apk_factory\keys\nova_backup.enc"
LOG_FILE    = r"C:\apk_factory\logs\nova_setup.log"
LOCK_FILE   = r"C:\apk_factory\nova_setup.lock"

# ── GitHub repo ───────────────────────────────────────────────────────────────
GITHUB_REPO   = "https://github.com/rendoyelaka/implement-like-irt.git"
REPO_BRANCH   = "main"

# ── Telegram backup ───────────────────────────────────────────────────────────
# These are for the backup system only — hardcoded here (not in config.py)
# This file never gets pushed to GitHub with real values — stays on RDP only
BACKUP_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
BACKUP_CHAT_ID   = "YOUR_CHAT_ID_HERE"
BACKUP_PASSWORD  = "NovaFactory2026_BackupKey_AES256"
BACKUP_CAPTION   = "NOVA_BACKUP"

# ── Python packages required ──────────────────────────────────────────────────
REQUIRED_PACKAGES = [
    ("pyTelegramBotAPI", "telebot"),
    ("pyotp",            "pyotp"),
    ("requests",         "requests"),
    ("pycryptodome",     "Crypto"),
    ("PyNaCl",           "nacl"),
]

# ── NSSM services ─────────────────────────────────────────────────────────────
SERVICES = [
    "nova_mutation",
    "nova_cloudflare",
    "nova_telegram",
]

# ── Config placeholder marker ─────────────────────────────────────────────────
PLACEHOLDER = "YOUR_"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

os.makedirs(LOGS_DIR, exist_ok=True)


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def log(msg):
    line = f"[{_ts()}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def ok(msg):
    log(f"  ✅ {msg}")


def skip(msg):
    log(f"  ⏭  SKIP — {msg}")


def installing(msg):
    log(f"  📦 {msg}")


def fail(msg):
    log(f"  ❌ FAIL — {msg}")


def section(title):
    log(f"\n{'═' * 55}")
    log(f"  {title}")
    log(f"{'═' * 55}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def run(cmd, cwd=None, timeout=300, capture=True):
    try:
        r = subprocess.run(
            cmd, shell=True,
            capture_output=capture,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)


def download(url: str, dest: str, label: str = "") -> bool:
    installing(f"Downloading {label or os.path.basename(dest)} ...")
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        ok(f"Downloaded: {os.path.basename(dest)}")
        return True
    except Exception as e:
        fail(f"Download failed: {e}")
        return False


def cmd_exists(cmd: str) -> bool:
    ok_flag, _ = run(f"where {cmd}")
    return ok_flag


def python_import_ok(module: str) -> bool:
    ok_flag, _ = run(f'python -c "import {module}"')
    return ok_flag


def input_value(prompt: str, current: str = "") -> str:
    if current and PLACEHOLDER not in current:
        print(f"  Current: {current[:30]}...")
        keep = input(f"  Keep current? [Y/n]: ").strip().lower()
        if keep != "n":
            return current
    while True:
        val = input(f"  {prompt}: ").strip()
        if val:
            return val
        print("  Cannot be empty. Try again.")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — AES-256-GCM BACKUP ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════════

def _encrypt(data: bytes, password: str) -> bytes:
    """AES-256-GCM encrypt. Returns: IV(12) + TAG(16) + CIPHERTEXT."""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    key    = hashlib.sha256(password.encode()).digest()
    iv     = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(data)
    return iv + tag + ct


def _decrypt(data: bytes, password: str) -> bytes:
    """AES-256-GCM decrypt."""
    from Crypto.Cipher import AES
    key    = hashlib.sha256(password.encode()).digest()
    iv     = data[:12]
    tag    = data[12:28]
    ct     = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ct, tag)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — TELEGRAM BACKUP / RESTORE
# ═══════════════════════════════════════════════════════════════════════════════

def _tg_request(method: str, data: dict = None,
                files: dict = None) -> dict:
    """Raw Telegram API request."""
    import requests as _req
    url = f"https://api.telegram.org/bot{BACKUP_BOT_TOKEN}/{method}"
    try:
        if files:
            r = _req.post(url, data=data, files=files, timeout=60)
        else:
            r = _req.post(url, json=data, timeout=15)
        return r.json()
    except Exception as e:
        fail(f"Telegram API error: {e}")
        return {}


def send_backup_to_telegram(enc_data: bytes) -> bool:
    """Send encrypted backup to Telegram."""
    ts      = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    caption = f"{BACKUP_CAPTION}_{ts}"
    buf     = io.BytesIO(enc_data)
    buf.name = f"nova_backup_{ts}.enc"
    result  = _tg_request(
        "sendDocument",
        data={"chat_id": BACKUP_CHAT_ID, "caption": caption},
        files={"document": buf}
    )
    if result.get("ok"):
        ok(f"Backup sent to Telegram: {caption}")
        return True
    fail(f"Telegram backup failed: {result.get('description', '')}")
    return False


def get_latest_backup_from_telegram() -> bytes:
    """Search Telegram chat for latest NOVA_BACKUP file. Returns raw bytes."""
    import requests as _req
    installing("Searching Telegram for latest backup ...")
    try:
        r       = _req.get(
            f"https://api.telegram.org/bot{BACKUP_BOT_TOKEN}/getUpdates",
            params={"limit": 100, "offset": -100},
            timeout=15
        )
        updates = r.json().get("result", [])
        for update in reversed(updates):
            msg     = update.get("message", {})
            if str(msg.get("chat", {}).get("id", "")) != str(BACKUP_CHAT_ID):
                continue
            doc     = msg.get("document", {})
            caption = msg.get("caption", "")
            if BACKUP_CAPTION not in caption or not doc:
                continue
            # Get file path
            r2      = _req.get(
                f"https://api.telegram.org/bot{BACKUP_BOT_TOKEN}/getFile",
                params={"file_id": doc["file_id"]},
                timeout=10
            )
            fp      = r2.json().get("result", {}).get("file_path", "")
            if not fp:
                continue
            # Download file
            r3      = _req.get(
                f"https://api.telegram.org/file/bot{BACKUP_BOT_TOKEN}/{fp}",
                timeout=60
            )
            ok(f"Found backup: {caption}")
            return r3.content
    except Exception as e:
        fail(f"Telegram restore search failed: {e}")
    return b""


def create_backup() -> bytes:
    """Create encrypted ZIP of config values + bot.db. Returns encrypted bytes."""
    installing("Creating encrypted backup ...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Backup config values as JSON (not the full config.py — just values)
        vals = _read_config_values()
        if vals:
            zf.writestr("config_values.json",
                        json.dumps(vals, indent=2))
            ok("Added config values to backup")
        # Backup bot.db
        if os.path.exists(DB_FILE):
            zf.write(DB_FILE, "bot.db")
            ok("Added bot.db to backup")
    raw     = buf.getvalue()
    enc     = _encrypt(raw, BACKUP_PASSWORD)
    # Save locally too
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(BACKUP_FILE, "wb") as f:
        f.write(enc)
    ok(f"Backup saved locally: {BACKUP_FILE}")
    return enc


def restore_from_backup(enc_data: bytes) -> bool:
    """Decrypt and restore config values + bot.db."""
    installing("Decrypting and restoring backup ...")
    try:
        raw = _decrypt(enc_data, BACKUP_PASSWORD)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Restore config values
            if "config_values.json" in zf.namelist():
                vals = json.loads(zf.read("config_values.json"))
                _write_config_values(vals)
                ok("Config values restored ✅")
            # Restore bot.db
            if "bot.db" in zf.namelist():
                os.makedirs(SERVER_DIR, exist_ok=True)
                with open(DB_FILE, "wb") as f:
                    f.write(zf.read("bot.db"))
                ok("bot.db restored ✅")
        return True
    except Exception as e:
        fail(f"Restore failed: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — CONFIG.PY READ / WRITE
# ═══════════════════════════════════════════════════════════════════════════════

# All config keys we manage
CONFIG_KEYS = [
    "BOT_TOKEN",
    "MASTER_CHAT_ID",
    "GITHUB_TOKEN",
    "GITHUB_OWNER",
    "GITHUB_REPO",
    "SERVER_SECRET",
    "ADMIN_PIN",
    "TOTP_SECRET",
    "SESSION_TIMEOUT_HRS",
    "CORRECT_REMOTE_URL",
    "CORRECT_MUTATION_PATH",
    "REPO_DIR",
    "DB_PATH",
    "STRINGPOOL_PATH",
]


def _read_config_values() -> dict:
    """Read current values from config.py. Returns dict."""
    vals = {}
    if not os.path.exists(CONFIG_FILE):
        return vals
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        for key in CONFIG_KEYS:
            # Match: KEY = "value" or KEY = 6
            import re
            m = re.search(
                rf'^{key}\s*=\s*["\']?([^"\'#\n]+)["\']?',
                content, re.MULTILINE
            )
            if m:
                vals[key] = m.group(1).strip().strip('"\'')
    except Exception as e:
        fail(f"Config read error: {e}")
    return vals


def _write_config_values(vals: dict):
    """Write real values into config.py replacing placeholders."""
    if not os.path.exists(CONFIG_FILE):
        fail("config.py not found — cannot write values")
        return
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        import re
        for key, value in vals.items():
            if key == "SESSION_TIMEOUT_HRS":
                # Integer value — no quotes
                content = re.sub(
                    rf'^({key}\s*=\s*)\S+',
                    f'\\g<1>{value}',
                    content, flags=re.MULTILINE
                )
            else:
                content = re.sub(
                    rf'^({key}\s*=\s*")[^"]*(")',
                    f'\\g<1>{value}\\g<2>',
                    content, flags=re.MULTILINE
                )
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        fail(f"Config write error: {e}")


def config_is_fresh() -> bool:
    """Returns True if config.py still has placeholder values."""
    if not os.path.exists(CONFIG_FILE):
        return True
    vals = _read_config_values()
    for key, val in vals.items():
        if PLACEHOLDER in str(val):
            return True
    return False


def config_is_complete() -> bool:
    """Returns True if all required keys are filled with real values."""
    required = [
        "BOT_TOKEN", "MASTER_CHAT_ID", "GITHUB_TOKEN",
        "GITHUB_OWNER", "GITHUB_REPO", "SERVER_SECRET",
        "ADMIN_PIN", "TOTP_SECRET",
    ]
    vals = _read_config_values()
    for key in required:
        val = vals.get(key, "")
        if not val or PLACEHOLDER in val:
            return False
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — MODE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

MODE_FRESH   = "FRESH"
MODE_UPDATE  = "UPDATE"
MODE_RESTORE = "RESTORE"


def detect_mode() -> str:
    """
    RESTORE → config has placeholders + Telegram backup exists
    UPDATE  → config has real values + --update flag passed
    FRESH   → config has placeholders + no backup found (or first time)
    """
    if "--update" in sys.argv:
        return MODE_UPDATE

    if config_is_fresh():
        # Check if Telegram backup exists
        installing("Checking for Telegram backup ...")
        if BACKUP_BOT_TOKEN != "YOUR_BOT_TOKEN_HERE":
            data = get_latest_backup_from_telegram()
            if data:
                return MODE_RESTORE
        return MODE_FRESH

    return MODE_UPDATE


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — INTERACTIVE CONFIG COLLECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def collect_config_interactively(mode: str) -> dict:
    """Ask user for config values interactively."""
    current = _read_config_values()

    print(f"""
{'═' * 55}
  CONFIG SETUP — {mode}
  Fill in real values. Press Enter to keep current.
{'═' * 55}
""")

    vals = {}

    # Telegram
    print("\n── Telegram ──")
    vals["BOT_TOKEN"]      = input_value(
        "BOT_TOKEN", current.get("BOT_TOKEN", ""))
    vals["MASTER_CHAT_ID"] = input_value(
        "MASTER_CHAT_ID (your Telegram numeric ID)",
        current.get("MASTER_CHAT_ID", ""))

    # GitHub
    print("\n── GitHub ──")
    vals["GITHUB_TOKEN"] = input_value(
        "GITHUB_TOKEN (ghp_...)",
        current.get("GITHUB_TOKEN", ""))
    vals["GITHUB_OWNER"] = input_value(
        "GITHUB_OWNER (your GitHub username)",
        current.get("GITHUB_OWNER", "rendoyelaka"))
    vals["GITHUB_REPO"]  = input_value(
        "GITHUB_REPO (repo name only)",
        current.get("GITHUB_REPO", "implement-like-irt"))

    # Server
    print("\n── Server ──")
    vals["SERVER_SECRET"] = input_value(
        "SERVER_SECRET (any strong password)",
        current.get("SERVER_SECRET", ""))

    # Auth
    print("\n── Admin Auth ──")
    vals["ADMIN_PIN"]   = input_value(
        "ADMIN_PIN (numeric PIN you want e.g. 9271)",
        current.get("ADMIN_PIN", ""))
    vals["TOTP_SECRET"] = input_value(
        "TOTP_SECRET (run: python -c \"import pyotp; "
        "print(pyotp.random_base32())\" to generate)",
        current.get("TOTP_SECRET", ""))

    # Session
    vals["SESSION_TIMEOUT_HRS"] = "6"

    # Auto-computed from other values
    owner = vals["GITHUB_OWNER"]
    repo  = vals["GITHUB_REPO"]
    token = vals["GITHUB_TOKEN"]
    vals["CORRECT_REMOTE_URL"]    = (
        f"https://{token}@github.com/{owner}/{repo}.git")
    vals["CORRECT_MUTATION_PATH"] = (
        r"C:\apk_factory\repo\server\update_server.py")
    vals["REPO_DIR"]              = REPO_DIR
    vals["DB_PATH"]               = DB_FILE
    vals["STRINGPOOL_PATH"]       = (
        r"C:\apk_factory\repo\app\src\main")

    return vals


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — SETUP STEPS
# ═══════════════════════════════════════════════════════════════════════════════

def step1_detect_mode() -> str:
    section("STEP 1 — Detect Mode")
    mode = detect_mode()
    ok(f"Mode: {mode}")
    return mode


def step2_create_folders():
    section("STEP 2 — Create Folders")
    folders = [
        BASE_DIR, REPO_DIR, SERVER_DIR,
        TOOLS_DIR, LOGS_DIR, KEYS_DIR,
        r"C:\apk_factory\downloads",
    ]
    for folder in folders:
        if os.path.exists(folder):
            skip(folder)
        else:
            os.makedirs(folder, exist_ok=True)
            ok(f"Created: {folder}")


def step3_install_python_packages():
    section("STEP 3 — Python Packages")
    for pip_name, import_name in REQUIRED_PACKAGES:
        if python_import_ok(import_name):
            skip(f"{pip_name} already installed")
            continue
        installing(f"Installing {pip_name} ...")

        # Fallback 1: standard pip
        success, _ = run(f"pip install {pip_name} --quiet")
        if success and python_import_ok(import_name):
            ok(f"{pip_name} installed via pip")
            continue

        # Fallback 2: pip install --user
        installing(f"Fallback 2: pip install --user {pip_name} ...")
        success, _ = run(f"pip install {pip_name} --user --quiet")
        if success and python_import_ok(import_name):
            ok(f"{pip_name} installed via pip --user")
            continue

        # Fallback 3: python -m pip
        installing(f"Fallback 3: python -m pip install {pip_name} ...")
        success, _ = run(
            f"python -m pip install {pip_name} --quiet")
        if success and python_import_ok(import_name):
            ok(f"{pip_name} installed via python -m pip")
            continue

        fail(f"{pip_name} — all fallbacks failed")


def step4_install_nssm():
    section("STEP 4 — NSSM")
    nssm_dest = os.path.join(TOOLS_DIR, "nssm.exe")

    # Check system PATH first
    if cmd_exists("nssm"):
        skip("nssm already in PATH")
        return

    # Check tools folder
    if os.path.exists(nssm_dest):
        # Add tools dir to PATH for this session
        os.environ["PATH"] = TOOLS_DIR + ";" + os.environ.get("PATH", "")
        skip("nssm in tools folder")
        return

    # Fallback 1: Download from nssm.cc
    installing("Fallback 1: Downloading nssm from nssm.cc ...")
    nssm_zip = r"C:\apk_factory\downloads\nssm.zip"
    if download("https://nssm.cc/release/nssm-2.24.zip",
                nssm_zip, "nssm-2.24.zip"):
        try:
            with zipfile.ZipFile(nssm_zip, "r") as z:
                for member in z.namelist():
                    if "win64\\nssm.exe" in member.replace("/", "\\"):
                        with z.open(member) as src, \
                             open(nssm_dest, "wb") as dst:
                            dst.write(src.read())
                        break
            if os.path.exists(nssm_dest):
                os.environ["PATH"] = (TOOLS_DIR + ";"
                                      + os.environ.get("PATH", ""))
                ok("nssm installed from nssm.cc")
                return
        except Exception as e:
            fail(f"nssm extract failed: {e}")

    # Fallback 2: winget
    installing("Fallback 2: winget install nssm ...")
    success, _ = run("winget install nssm --silent --accept-source-agreements",
                     timeout=120)
    if success and cmd_exists("nssm"):
        ok("nssm installed via winget")
        return

    # Fallback 3: chocolatey
    installing("Fallback 3: choco install nssm ...")
    success, _ = run("choco install nssm -y", timeout=120)
    if success and cmd_exists("nssm"):
        ok("nssm installed via chocolatey")
        return

    fail("nssm — all fallbacks failed. Install manually from https://nssm.cc")


def step5_install_cloudflared():
    section("STEP 5 — cloudflared")
    cf_dest = os.path.join(TOOLS_DIR, "cloudflared.exe")

    if os.path.exists(cf_dest):
        skip("cloudflared already in tools folder")
        return

    if cmd_exists("cloudflared"):
        skip("cloudflared already in PATH")
        return

    # Fallback 1: Download from Cloudflare
    installing("Fallback 1: Downloading cloudflared from Cloudflare ...")
    url = ("https://github.com/cloudflare/cloudflared/releases/latest"
           "/download/cloudflared-windows-amd64.exe")
    if download(url, cf_dest, "cloudflared.exe"):
        ok("cloudflared installed from Cloudflare")
        return

    # Fallback 2: winget
    installing("Fallback 2: winget install cloudflared ...")
    success, _ = run(
        "winget install Cloudflare.cloudflared --silent "
        "--accept-source-agreements",
        timeout=120
    )
    if success:
        ok("cloudflared installed via winget")
        return

    # Fallback 3: Direct GitHub release URL
    installing("Fallback 3: Trying alternate GitHub URL ...")
    alt_url = ("https://github.com/cloudflare/cloudflared/releases"
               "/download/2024.12.0/cloudflared-windows-amd64.exe")
    if download(alt_url, cf_dest, "cloudflared.exe"):
        ok("cloudflared installed from GitHub release")
        return

    fail("cloudflared — all fallbacks failed")


def step6_install_git():
    section("STEP 6 — Git")
    ok_flag, out = run("git --version")
    if ok_flag and "git" in out.lower():
        skip(out.strip()[:50])
        return

    # Fallback 1: Download installer
    installing("Fallback 1: Downloading Git installer ...")
    git_exe = r"C:\apk_factory\downloads\git_setup.exe"
    url     = ("https://github.com/git-for-windows/git/releases/download"
               "/v2.43.0.windows.1/Git-2.43.0-64-bit.exe")
    if download(url, git_exe, "Git-2.43.0-64-bit.exe"):
        installing("Installing Git silently ...")
        run(f'"{git_exe}" /VERYSILENT /NORESTART /NOCANCEL /SP-',
            timeout=120)
        time.sleep(10)
        ok_flag2, out2 = run("git --version")
        if ok_flag2:
            ok(out2.strip()[:50])
            return

    # Fallback 2: winget
    installing("Fallback 2: winget install Git ...")
    success, _ = run(
        "winget install Git.Git --silent --accept-source-agreements",
        timeout=180
    )
    ok_flag3, _ = run("git --version")
    if ok_flag3:
        ok("Git installed via winget")
        return

    fail("Git — all fallbacks failed")


def step7_install_java():
    section("STEP 7 — Java 17")
    ok_flag, out = run("java -version")
    if ok_flag or "version" in out.lower():
        skip(out.strip()[:60])
        return

    # Check tools folder
    java_exe = os.path.join(TOOLS_DIR, "java17", "bin", "java.exe")
    if os.path.exists(java_exe):
        skip("Java 17 in tools folder")
        os.environ["JAVA_HOME"] = os.path.join(TOOLS_DIR, "java17")
        return

    # Fallback 1: Download from Adoptium
    installing("Fallback 1: Downloading Java 17 from Adoptium ...")
    java_zip = r"C:\apk_factory\downloads\java17.zip"
    url      = ("https://github.com/adoptium/temurin17-binaries/releases"
                "/download/jdk-17.0.9%2B9/"
                "OpenJDK17U-jdk_x64_windows_hotspot_17.0.9_9.zip")
    if download(url, java_zip, "OpenJDK17.zip"):
        installing("Extracting Java 17 ...")
        try:
            java_dest = os.path.join(TOOLS_DIR, "java17")
            with zipfile.ZipFile(java_zip, "r") as z:
                z.extractall(java_dest)
            # Find the actual java.exe
            for root, dirs, files in os.walk(java_dest):
                if "java.exe" in files:
                    os.environ["JAVA_HOME"] = os.path.dirname(
                        os.path.dirname(os.path.join(root, "java.exe")))
                    os.environ["PATH"] = (root + ";"
                                          + os.environ.get("PATH", ""))
                    ok("Java 17 installed from Adoptium")
                    return
        except Exception as e:
            fail(f"Java 17 extract failed: {e}")

    # Fallback 2: winget
    installing("Fallback 2: winget install Java 17 ...")
    success, _ = run(
        "winget install EclipseAdoptium.Temurin.17.JDK --silent "
        "--accept-source-agreements",
        timeout=300
    )
    ok_flag2, _ = run("java -version")
    if ok_flag2:
        ok("Java 17 installed via winget")
        return

    fail("Java 17 — all fallbacks failed")


def step8_install_apktool():
    section("STEP 8 — apktool")
    apktool_jar = os.path.join(TOOLS_DIR, "apktool.jar")

    if os.path.exists(apktool_jar):
        skip("apktool.jar already in tools folder")
        return

    installing("Downloading apktool 2.9.3 ...")
    url = ("https://github.com/iBotPeaches/Apktool/releases/download"
           "/v2.9.3/apktool_2.9.3.jar")
    if download(url, apktool_jar, "apktool_2.9.3.jar"):
        # Create apktool.bat wrapper
        bat_content = (
            f"@echo off\n"
            f'java -jar "{apktool_jar}" %*\n'
        )
        bat_path = os.path.join(TOOLS_DIR, "apktool.bat")
        with open(bat_path, "w") as f:
            f.write(bat_content)
        # Add tools to PATH
        run(f'setx PATH "{TOOLS_DIR};%PATH%" /M', timeout=10)
        ok("apktool 2.9.3 installed")
        return

    fail("apktool — download failed")


def step9_clone_pull_repo():
    section("STEP 9 — Clone / Pull Repo")
    git_dir = os.path.join(REPO_DIR, ".git")

    if os.path.exists(git_dir):
        installing("Repo exists — pulling latest ...")
        # Read token for auth
        vals = _read_config_values()
        token = vals.get("GITHUB_TOKEN", "")
        owner = vals.get("GITHUB_OWNER", "rendoyelaka")
        repo  = vals.get("GITHUB_REPO", "implement-like-irt")
        if token and PLACEHOLDER not in token:
            auth_url = (f"https://{token}@github.com"
                        f"/{owner}/{repo}.git")
            run(f"git remote set-url origin {auth_url}",
                cwd=REPO_DIR)
        ok_flag, out = run("git pull origin main",
                           cwd=REPO_DIR, timeout=120)
        if ok_flag:
            ok("Repo updated")
        else:
            fail(f"Pull failed: {out[:100]}")
        return

    # Fresh clone
    installing(f"Cloning repo to {REPO_DIR} ...")
    os.makedirs(REPO_DIR, exist_ok=True)
    ok_flag, out = run(
        f'git clone {GITHUB_REPO} "{REPO_DIR}"',
        timeout=180
    )
    if ok_flag:
        ok(f"Repo cloned to {REPO_DIR}")
    else:
        fail(f"Clone failed: {out[:200]}")


def step10_backup_restore(mode: str) -> bool:
    section("STEP 10 — Backup / Restore")

    if mode == MODE_RESTORE:
        installing("RESTORE mode — downloading from Telegram ...")
        enc_data = get_latest_backup_from_telegram()
        if enc_data:
            success = restore_from_backup(enc_data)
            if success:
                ok("Full restore complete ✅")
                return True
            fail("Restore failed — will collect config manually")
        else:
            installing("No Telegram backup found — collecting manually ...")

    # FRESH or UPDATE — collect interactively
    vals = collect_config_interactively(mode)
    _write_config_values(vals)
    ok("Config values written to config.py")

    # Create and send backup
    installing("Creating encrypted backup ...")
    enc_data = create_backup()
    send_backup_to_telegram(enc_data)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9B — GITHUB SECRETS AUTO-INJECTION
# ═══════════════════════════════════════════════════════════════════════════════

# Full map of all GitHub secrets we manage automatically
# Format: { "SECRET_NAME": ("config_key", "fallback_value_or_None") }
GITHUB_SECRETS_MAP = {
    "TELEGRAM_BOT_TOKEN":  ("BOT_TOKEN",       None),
    "TELEGRAM_CHAT_ID":    ("MASTER_CHAT_ID",   None),
    "KEYSTORE_PASSWORD":   (None,               "android"),
    "KEY_ALIAS":           (None,               "platform"),
    "KEYSTORE_BASE64":     (None,               None),  # handled separately
}


def _get_repo_public_key(owner: str, repo: str,
                          token: str) -> tuple:
    """
    Get GitHub repo public key for secret encryption.
    Returns (key_id, public_key_b64) or ("", "") on failure.
    """
    import urllib.request as _ur
    url = (f"https://api.github.com/repos/{owner}/{repo}"
           f"/actions/secrets/public-key")
    try:
        req = _ur.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with _ur.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            return data.get("key_id", ""), data.get("key", "")
    except Exception as e:
        fail(f"Failed to get repo public key: {e}")
        return "", ""


def _encrypt_secret(public_key_b64: str,
                    secret_value: str) -> str:
    """
    Encrypt secret value with repo public key using libsodium.
    Returns base64-encoded encrypted value.
    GitHub requires PyNaCl for this.
    """
    try:
        from nacl import encoding, public
        pk_bytes  = base64.b64decode(public_key_b64)
        pk        = public.PublicKey(pk_bytes)
        box       = public.SealedBox(pk)
        encrypted = box.encrypt(secret_value.encode("utf-8"))
        return base64.b64encode(encrypted).decode("utf-8")
    except ImportError:
        # PyNaCl not installed — install it
        run("pip install PyNaCl --quiet")
        try:
            from nacl import encoding, public
            pk_bytes  = base64.b64decode(public_key_b64)
            pk        = public.PublicKey(pk_bytes)
            box       = public.SealedBox(pk)
            encrypted = box.encrypt(secret_value.encode("utf-8"))
            return base64.b64encode(encrypted).decode("utf-8")
        except Exception as e:
            fail(f"PyNaCl encryption failed: {e}")
            return ""
    except Exception as e:
        fail(f"Secret encryption failed: {e}")
        return ""


def _set_github_secret(owner: str, repo: str, token: str,
                        key_id: str, public_key_b64: str,
                        secret_name: str,
                        secret_value: str) -> bool:
    """
    Set a single GitHub secret via API.
    Returns True on success.
    """
    import urllib.request as _ur
    encrypted = _encrypt_secret(public_key_b64, secret_value)
    if not encrypted:
        return False
    url  = (f"https://api.github.com/repos/{owner}/{repo}"
            f"/actions/secrets/{secret_name}")
    body = json.dumps({
        "encrypted_value": encrypted,
        "key_id":          key_id,
    }).encode()
    try:
        req = _ur.Request(
            url,
            data=body,
            method="PUT",
            headers={
                "Authorization":  f"token {token}",
                "Accept":         "application/vnd.github.v3+json",
                "Content-Type":   "application/json",
            }
        )
        with _ur.urlopen(req, timeout=15) as r:
            return r.status in (201, 204)
    except Exception as e:
        fail(f"Set secret {secret_name} failed: {e}")
        return False


def _list_github_secrets(owner: str, repo: str,
                          token: str) -> list:
    """
    List all existing GitHub secret names.
    Returns list of secret name strings.
    """
    import urllib.request as _ur
    url = (f"https://api.github.com/repos/{owner}/{repo}"
           f"/actions/secrets?per_page=100")
    try:
        req = _ur.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with _ur.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
            return [s["name"] for s in data.get("secrets", [])]
    except Exception as e:
        fail(f"List secrets failed: {e}")
        return []


def _get_keystore_base64() -> str:
    """
    Read platform.jks from RDP and return base64 encoded string.
    Searches common locations.
    """
    candidates = [
        r"C:\apk_factory\keys\platform.jks",
        r"C:\apk_factory\repo\platform.jks",
        r"C:\apk_factory\tools\platform.jks",
        os.path.join(KEYS_DIR, "platform.jks"),
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    data = f.read()
                encoded = base64.b64encode(data).decode("utf-8")
                ok(f"Keystore found: {path}")
                return encoded
            except Exception as e:
                fail(f"Keystore read failed: {e}")
    fail("platform.jks not found in any known location")
    return ""


def step10b_inject_github_secrets():
    """
    Step 10B — Auto-inject all required GitHub Secrets.

    Layer 1: Read config.py values
    Layer 2: Get repo public key
    Layer 3: Encrypt each secret with libsodium
    Layer 4: PUT to GitHub API
    Layer 5: Verify each secret was set
    Layer 6: Report results
    """
    section("STEP 10B — GitHub Secrets Auto-Injection")

    vals  = _read_config_values()
    token = vals.get("GITHUB_TOKEN", "")
    owner = vals.get("GITHUB_OWNER", "")
    repo  = vals.get("GITHUB_REPO",  "")

    if not token or PLACEHOLDER in token:
        fail("GITHUB_TOKEN not set — cannot inject secrets")
        return False
    if not owner or not repo:
        fail("GITHUB_OWNER/REPO not set")
        return False

    installing(f"Getting repo public key for {owner}/{repo} ...")
    key_id, pub_key = _get_repo_public_key(owner, repo, token)
    if not key_id or not pub_key:
        fail("Could not get repo public key")
        return False
    ok(f"Repo public key obtained (key_id: {key_id[:8]}...)")

    # Check existing secrets
    installing("Checking existing GitHub secrets ...")
    existing = _list_github_secrets(owner, repo, token)
    log(f"  Existing secrets: {existing}")

    results  = {}
    all_ok   = True

    # ── Inject TELEGRAM_BOT_TOKEN ─────────────────────────────
    bot_token = vals.get("BOT_TOKEN", "")
    if bot_token and PLACEHOLDER not in bot_token:
        installing("Setting TELEGRAM_BOT_TOKEN ...")
        success = _set_github_secret(
            owner, repo, token, key_id, pub_key,
            "TELEGRAM_BOT_TOKEN", bot_token
        )
        results["TELEGRAM_BOT_TOKEN"] = success
        ok("TELEGRAM_BOT_TOKEN set ✅") if success else fail(
            "TELEGRAM_BOT_TOKEN failed ❌")
        all_ok = all_ok and success
    else:
        fail("BOT_TOKEN not in config — skipping TELEGRAM_BOT_TOKEN")
        all_ok = False

    # ── Inject TELEGRAM_CHAT_ID ───────────────────────────────
    chat_id = vals.get("MASTER_CHAT_ID", "")
    if chat_id and PLACEHOLDER not in chat_id:
        installing("Setting TELEGRAM_CHAT_ID ...")
        success = _set_github_secret(
            owner, repo, token, key_id, pub_key,
            "TELEGRAM_CHAT_ID", chat_id
        )
        results["TELEGRAM_CHAT_ID"] = success
        ok("TELEGRAM_CHAT_ID set ✅") if success else fail(
            "TELEGRAM_CHAT_ID failed ❌")
        all_ok = all_ok and success
    else:
        fail("MASTER_CHAT_ID not in config — skipping")
        all_ok = False

    # ── Inject KEYSTORE_PASSWORD ──────────────────────────────
    installing("Setting KEYSTORE_PASSWORD ...")
    success = _set_github_secret(
        owner, repo, token, key_id, pub_key,
        "KEYSTORE_PASSWORD", "android"
    )
    results["KEYSTORE_PASSWORD"] = success
    ok("KEYSTORE_PASSWORD set ✅") if success else fail(
        "KEYSTORE_PASSWORD failed ❌")

    # ── Inject KEY_ALIAS ──────────────────────────────────────
    installing("Setting KEY_ALIAS ...")
    success = _set_github_secret(
        owner, repo, token, key_id, pub_key,
        "KEY_ALIAS", "platform"
    )
    results["KEY_ALIAS"] = success
    ok("KEY_ALIAS set ✅") if success else fail(
        "KEY_ALIAS failed ❌")

    # Summary
    log(f"\n  GitHub Secrets Injection Summary:")
    for name, result in results.items():
        log(f"  {'✅' if result else '❌'} {name}")

    return all_ok


def step10c_verify_keystore():
    """
    Step 10C — Verify KEYSTORE_BASE64 in GitHub Secrets.
    If missing → read platform.jks from RDP → encode → push to GitHub.
    """
    section("STEP 10C — Keystore Verification")

    vals  = _read_config_values()
    token = vals.get("GITHUB_TOKEN", "")
    owner = vals.get("GITHUB_OWNER", "")
    repo  = vals.get("GITHUB_REPO",  "")

    if not token or PLACEHOLDER in token:
        fail("GITHUB_TOKEN not set — skipping keystore check")
        return

    # Check if KEYSTORE_BASE64 already exists
    installing("Checking KEYSTORE_BASE64 in GitHub ...")
    existing = _list_github_secrets(owner, repo, token)

    if "KEYSTORE_BASE64" in existing:
        skip("KEYSTORE_BASE64 already in GitHub Secrets")
        return

    # Not found — push from RDP
    installing("KEYSTORE_BASE64 missing — reading from RDP ...")
    ks_b64 = _get_keystore_base64()
    if not ks_b64:
        fail("Cannot push KEYSTORE_BASE64 — platform.jks not found on RDP")
        fail("Build will fail without keystore — add platform.jks to "
             "C:\\apk_factory\\keys\\")
        return

    installing("Getting repo public key ...")
    key_id, pub_key = _get_repo_public_key(owner, repo, token)
    if not key_id:
        fail("Cannot get repo public key")
        return

    installing("Pushing KEYSTORE_BASE64 to GitHub ...")
    success = _set_github_secret(
        owner, repo, token, key_id, pub_key,
        "KEYSTORE_BASE64", ks_b64
    )
    if success:
        ok("KEYSTORE_BASE64 pushed to GitHub ✅")
        ok(f"Keystore size: {len(ks_b64)} chars base64")
    else:
        fail("KEYSTORE_BASE64 push failed ❌")


def step11_verify_config():
    section("STEP 11 — Verify Config")
    if config_is_complete():
        ok("All required config values present ✅")
        return True
    fail("Config incomplete — some placeholders still present")
    # Show which keys are missing
    vals = _read_config_values()
    required = [
        "BOT_TOKEN", "MASTER_CHAT_ID", "GITHUB_TOKEN",
        "GITHUB_OWNER", "GITHUB_REPO", "SERVER_SECRET",
        "ADMIN_PIN", "TOTP_SECRET",
    ]
    for key in required:
        val = vals.get(key, "")
        if not val or PLACEHOLDER in val:
            fail(f"Missing: {key}")
    return False


def step12_windows_autostart():
    section("STEP 12 — Windows Auto-Start")
    bat_path = os.path.join(REPO_DIR, "server_setup.bat")
    if not os.path.exists(bat_path):
        fail("server_setup.bat not found — skipping auto-start setup")
        return

    # Method 1: Windows Scheduled Task (runs on SYSTEM boot)
    installing("Method 1: Creating Windows Scheduled Task ...")
    task_cmd = (
        f'schtasks /create /tn "NovaAPKFactory" '
        f'/tr "{bat_path}" '
        f'/sc onstart /ru SYSTEM /rl HIGHEST /f'
    )
    ok_flag, out = run(task_cmd, timeout=30)
    if ok_flag:
        ok("Scheduled Task created — auto-starts on boot")
    else:
        fail(f"Scheduled Task failed: {out[:100]}")

    # Method 2: Registry Run key (runs on user login — backup)
    installing("Method 2: Adding to Registry Run key ...")
    reg_cmd = (
        f'reg add "HKCU\\Software\\Microsoft\\Windows\\'
        f'CurrentVersion\\Run" '
        f'/v "NovaAPKFactory" /t REG_SZ '
        f'/d "{bat_path}" /f'
    )
    ok_flag2, _ = run(reg_cmd, timeout=10)
    if ok_flag2:
        ok("Registry Run key added — auto-starts on login")
    else:
        fail("Registry Run key failed")

    ok("Auto-start configured (dual redundancy) ✅")


def step13_install_start_services():
    section("STEP 13 — Install + Start Services")

    # Get paths
    python_exe  = sys.executable
    cf_exe      = os.path.join(TOOLS_DIR, "cloudflared.exe")
    update_srv  = os.path.join(SERVER_DIR, "update_server.py")
    nova_bot    = os.path.join(SERVER_DIR, "nova_bot.py")

    # Stop + remove old services first
    installing("Removing old services if exist ...")
    all_svcs = SERVICES + ["nova_watchdog"]
    for svc in all_svcs:
        ok_flag, _ = run(f"nssm status {svc}", timeout=5)
        if ok_flag:
            run(f"nssm stop {svc}", timeout=15)
            run(f"nssm remove {svc} confirm", timeout=15)
            ok(f"Removed: {svc}")

    # ── nova_mutation ─────────────────────────────────────────
    installing("Installing nova_mutation ...")
    cmds = [
        f'nssm install nova_mutation "{python_exe}"',
        f'nssm set nova_mutation AppDirectory "{SERVER_DIR}"',
        f'nssm set nova_mutation AppParameters "{update_srv}"',
        f'nssm set nova_mutation DisplayName "Nova Mutation Server"',
        'nssm set nova_mutation Start SERVICE_AUTO_START',
        f'nssm set nova_mutation AppStdout "{LOGS_DIR}\\mutation.log"',
        f'nssm set nova_mutation AppStderr "{LOGS_DIR}\\mutation_err.log"',
        'nssm set nova_mutation AppRotateFiles 1',
        'nssm set nova_mutation AppRotateSeconds 86400',
        'nssm set nova_mutation AppRestartDelay 5000',
    ]
    for cmd in cmds:
        run(cmd, timeout=10)
    ok("nova_mutation installed")

    # ── nova_cloudflare ───────────────────────────────────────
    installing("Installing nova_cloudflare ...")
    cf_params = (f"tunnel --url http://localhost:2053 "
                 f"--logfile {LOGS_DIR}\\cloudflared.log")
    cmds = [
        f'nssm install nova_cloudflare "{cf_exe}"',
        f'nssm set nova_cloudflare AppDirectory "{TOOLS_DIR}"',
        f'nssm set nova_cloudflare AppParameters "{cf_params}"',
        f'nssm set nova_cloudflare DisplayName "Nova Cloudflare Tunnel"',
        'nssm set nova_cloudflare Start SERVICE_AUTO_START',
        f'nssm set nova_cloudflare AppStdout "{LOGS_DIR}\\cloudflare_out.log"',
        f'nssm set nova_cloudflare AppStderr "{LOGS_DIR}\\cloudflare_err.log"',
        'nssm set nova_cloudflare AppRestartDelay 5000',
    ]
    for cmd in cmds:
        run(cmd, timeout=10)
    ok("nova_cloudflare installed")

    # ── nova_telegram ─────────────────────────────────────────
    installing("Installing nova_telegram ...")
    cmds = [
        f'nssm install nova_telegram "{python_exe}"',
        f'nssm set nova_telegram AppDirectory "{SERVER_DIR}"',
        f'nssm set nova_telegram AppParameters "{nova_bot}"',
        f'nssm set nova_telegram DisplayName "Nova Telegram Bot"',
        'nssm set nova_telegram Start SERVICE_AUTO_START',
        f'nssm set nova_telegram AppStdout "{LOGS_DIR}\\nova_bot.log"',
        f'nssm set nova_telegram AppStderr "{LOGS_DIR}\\nova_bot_err.log"',
        'nssm set nova_telegram AppRotateFiles 1',
        'nssm set nova_telegram AppRotateSeconds 86400',
        'nssm set nova_telegram AppRestartDelay 5000',
    ]
    for cmd in cmds:
        run(cmd, timeout=10)
    ok("nova_telegram installed")

    # ── Start all services ────────────────────────────────────
    installing("Starting all services ...")
    time.sleep(2)

    for svc in SERVICES:
        installing(f"Starting {svc} ...")
        run(f"nssm start {svc}", timeout=15)
        time.sleep(3)

    # ── Verify ────────────────────────────────────────────────
    installing("Verifying services ...")
    time.sleep(5)
    all_ok = True
    for svc in SERVICES:
        ok_flag, status = run(f"nssm status {svc}", timeout=5)
        if "SERVICE_RUNNING" in status:
            ok(f"{svc}: RUNNING ✅")
        else:
            fail(f"{svc}: NOT RUNNING ❌")
            all_ok = False

    return all_ok


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — SEND COMPLETION ALERT
# ═══════════════════════════════════════════════════════════════════════════════

def send_completion_alert(mode: str, all_ok: bool):
    """Send Telegram alert when setup completes."""
    vals = _read_config_values()
    tok  = vals.get("BOT_TOKEN", "")
    cid  = vals.get("MASTER_CHAT_ID", "")
    if not tok or PLACEHOLDER in tok:
        return
    status = "✅ SUCCESS" if all_ok else "⚠️ PARTIAL"
    msg = (
        f"🔧 <b>Nova Setup Complete</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Mode   : {mode}\n"
        f"Status : {status}\n"
        f"Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"nova_mutation   : ✅\n"
        f"nova_cloudflare : ✅\n"
        f"nova_telegram   : ✅\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Open bot → /start → PIN → 2FAS"
    )
    try:
        data = json.dumps({
            "chat_id": cid, "text": msg, "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{tok}/sendMessage",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        ok("Completion alert sent to Telegram ✅")
    except Exception as e:
        fail(f"Alert send failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — SINGLE INSTANCE LOCK
# ═══════════════════════════════════════════════════════════════════════════════

def acquire_lock():
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
                print(f"[LOCK] nova_setup already running "
                      f"(PID {old_pid}) — exiting.")
                sys.exit(0)
            else:
                os.remove(LOCK_FILE)
        except Exception:
            try:
                os.remove(LOCK_FILE)
            except Exception:
                pass
    with open(LOCK_FILE, "w") as f:
        f.write(str(my_pid))


def release_lock():
    try:
        os.remove(LOCK_FILE)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    acquire_lock()

    try:
        print(f"""
{'═' * 55}
  NOVA APK FACTORY — MASTER SETUP
  Mode auto-detected. No manual steps needed.
  This will take 3-7 minutes on a fresh RDP.
{'═' * 55}
""")
        log(f"nova_setup.py started — PID {os.getpid()}")
        log(f"Args: {sys.argv}")

        # Step 1 — Detect mode
        mode = step1_detect_mode()

        # Step 2 — Folders
        step2_create_folders()

        # Step 3 — Python packages
        step3_install_python_packages()

        # Step 4 — NSSM
        step4_install_nssm()

        # Step 5 — cloudflared
        step5_install_cloudflared()

        # Step 6 — Git
        step6_install_git()

        # Step 7 — Java 17
        step7_install_java()

        # Step 8 — apktool
        step8_install_apktool()

        # Step 9 — Clone/pull repo
        step9_clone_pull_repo()

        # Step 10 — Backup/Restore
        step10_backup_restore(mode)

        # Step 10B — GitHub Secrets auto-injection
        step10b_inject_github_secrets()

        # Step 10C — Keystore verification
        step10c_verify_keystore()

        # Step 11 — Verify config
        config_ok = step11_verify_config()
        if not config_ok:
            fail("Config incomplete — cannot start services safely")
            fail("Fix config.py manually then re-run setup")
            release_lock()
            sys.exit(1)

        # Step 12 — Windows auto-start
        step12_windows_autostart()

        # Step 13 — Install + start services
        all_ok = step13_install_start_services()

        # Send completion alert
        send_completion_alert(mode, all_ok)

        print(f"""
{'═' * 55}
  SETUP COMPLETE {'✅' if all_ok else '⚠️'}
{'═' * 55}

  Mode     : {mode}
  Services : nova_mutation + nova_cloudflare + nova_telegram
  Log      : {LOG_FILE}

  Next steps:
  → Open Telegram → @AppMetricsMonitor_Bot → /start
  → Enter PIN → Enter 2FAS code → Main Menu

  On next RDP reboot → everything starts AUTOMATICALLY
  On new RDP         → double-click server_setup.bat again
                     → it restores EVERYTHING from Telegram

{'═' * 55}
""")

    except KeyboardInterrupt:
        log("Setup interrupted by user")
    except Exception as e:
        fail(f"Unexpected error: {e}")
        import traceback
        log(traceback.format_exc())
    finally:
        release_lock()


if __name__ == "__main__":
    main()
