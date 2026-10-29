#!/usr/bin/env python3
"""
commit_notify.py
─────────────────────────────────────────────────────────────────────────────
Called by notify.yml on every GitHub push.
Sends rich commit alert to Telegram.
Runs on GitHub servers — works even when RDP is OFF.

Triple fallback token resolution:
  Priority 1: --token argument (GitHub Secret)
  Priority 2: TELEGRAM_BOT_TOKEN env var
  Priority 3: BOT_TOKEN env var
─────────────────────────────────────────────────────────────────────────────
"""

import argparse
import json
import os
import sys
import time
import urllib.request


# ── Template emoji map ────────────────────────────────────────────────────────
FILE_EMOJI_MAP = {
    ".py":     "🐍",
    ".kt":     "🤖",
    ".java":   "☕",
    ".yml":    "⚙️",
    ".yaml":   "⚙️",
    ".gradle": "🔧",
    ".json":   "📋",
    ".xml":    "📄",
    ".sh":     "💻",
    ".bat":    "💻",
    ".md":     "📝",
    ".txt":    "📝",
    ".apk":    "📦",
    ".so":     "🔩",
    ".c":      "⚡",
    ".cpp":    "⚡",
    ".h":      "⚡",
}


def get_file_emoji(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return FILE_EMOJI_MAP.get(ext, "📁")


def resolve_token(token_arg: str) -> str:
    """Triple fallback token resolution."""
    PLACEHOLDER = "YOUR_BOT_TOKEN_HERE"

    # Priority 1: argument
    if token_arg and token_arg != PLACEHOLDER and ":" in token_arg:
        return token_arg

    # Priority 2: TELEGRAM_BOT_TOKEN env
    env1 = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if env1 and env1 != PLACEHOLDER and ":" in env1:
        return env1

    # Priority 3: BOT_TOKEN env
    env2 = os.environ.get("BOT_TOKEN", "")
    if env2 and env2 != PLACEHOLDER and ":" in env2:
        return env2

    return ""


def resolve_chat_id(chat_id_arg: str) -> str:
    """Triple fallback chat_id resolution."""
    if chat_id_arg and chat_id_arg not in ("0", "", "YOUR_CHAT_ID_HERE"):
        return chat_id_arg

    env1 = os.environ.get("TELEGRAM_CHAT_ID", "")
    if env1 and env1 not in ("0", ""):
        return env1

    env2 = os.environ.get("BUILD_CHAT_ID", "")
    if env2 and env2 not in ("0", ""):
        return env2

    return ""


def send_message(token: str, chat_id: str,
                 text: str, retries: int = 3) -> bool:
    """Send Telegram message with retry."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for attempt in range(retries):
        try:
            payload = json.dumps({
                "chat_id":    chat_id,
                "text":       text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            }).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                result = json.loads(r.read().decode())
                if result.get("ok"):
                    return True
                print(
                    f"[commit_notify] Telegram error: "
                    f"{result.get('description', '')}",
                    file=sys.stderr
                )
        except Exception as e:
            print(
                f"[commit_notify] Attempt {attempt + 1}/{retries} "
                f"failed: {e}",
                file=sys.stderr
            )
            if attempt < retries - 1:
                time.sleep(3)
    return False


def build_commit_message(args) -> str:
    """Build rich commit alert message."""

    # Format files list
    files_list = ""
    if args.files:
        files = [f.strip() for f in args.files.split(",") if f.strip()]
        file_lines = []
        for f in files[:8]:  # max 8 files shown
            emoji = get_file_emoji(f)
            # Show only filename not full path if too long
            display = f if len(f) <= 40 else "..." + f[-37:]
            file_lines.append(f"  {emoji} <code>{display}</code>")
        if len(files) > 8:
            file_lines.append(
                f"  📁 ...and {len(files) - 8} more files")
        files_list = "\n".join(file_lines)

    # Stats line
    stats = ""
    added   = args.added or "0"
    deleted = args.deleted or "0"
    if added != "0" or deleted != "0":
        stats = f"+{added} / -{deleted} lines"

    # RDP status hint
    rdp_hint = (
        "🖥 RDP sync will follow when online"
        if True else ""
    )

    # Repo short name
    repo_name = args.repo.split("/")[-1] if args.repo else "repo"

    # Commit URL
    commit_url = (
        f"https://github.com/{args.repo}/commit/{args.sha}"
        if args.repo and args.sha else ""
    )

    lines = [
        f"📦 <b>New Commit — {repo_name}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        f"📝 <b>Message</b> : {args.msg or 'No message'}",
        f"👤 <b>Author</b>  : {args.author or 'Unknown'}",
        f"🔀 <b>Commit</b>  : <code>{args.sha or '?'}</code>",
        f"🌿 <b>Branch</b>  : {args.branch or 'main'}",
        f"🕐 <b>UTC</b>     : {args.date or ''}",
    ]

    if stats:
        lines.append(f"📊 <b>Changes</b> : {stats}")

    if args.count and args.count != "0":
        lines.append(
            f"📁 <b>Files</b>   : {args.count} file(s) changed")

    if files_list:
        lines.append("━━━━━━━━━━━━━━━━━━━━")
        lines.append(files_list)

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append(rdp_hint)

    if commit_url:
        lines.append(f"🔗 <a href='{commit_url}'>View on GitHub</a>")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token",    default="")
    parser.add_argument("--chat-id",  default="", dest="chat_id")
    parser.add_argument("--sha",      default="")
    parser.add_argument("--msg",      default="")
    parser.add_argument("--author",   default="")
    parser.add_argument("--date",     default="")
    parser.add_argument("--branch",   default="main")
    parser.add_argument("--files",    default="")
    parser.add_argument("--count",    default="0")
    parser.add_argument("--added",    default="0")
    parser.add_argument("--deleted",  default="0")
    parser.add_argument("--repo",     default="")
    parser.add_argument("--run-id",   default="", dest="run_id")
    args = parser.parse_args()

    # Triple fallback resolution
    token   = resolve_token(args.token)
    chat_id = resolve_chat_id(args.chat_id)

    if not token or not chat_id:
        print(
            "[commit_notify] No token or chat_id — skipping",
            file=sys.stderr
        )
        sys.exit(0)

    text = build_commit_message(args)
    ok   = send_message(token, chat_id, text)

    if ok:
        print(
            f"[commit_notify] Alert sent ✅ "
            f"commit={args.sha} files={args.count}"
        )
        sys.exit(0)
    else:
        print("[commit_notify] Failed to send alert", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
