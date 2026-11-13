#!/usr/bin/env python3
"""
crash_reporter.py
-----------------
Standalone crash reporting for the VaultGuard build pipeline.

Usage (from build_module.py):
    from crash_reporter import crash_guard
    with crash_guard():
        main_logic()

On any unhandled exception inside the with-block:
  1. Writes a human-readable crash report  →  crash_report.txt
  2. Sends the report as a Telegram message (text, no file size limit issue)
  3. Sends the crash report file as a Telegram document
  4. Re-raises the exception so the CI step still fails (exit != 0)
"""

import os
import sys
import traceback
import datetime
import inspect
import struct
import contextlib


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def _env(key, default=""):
    return os.environ.get(key, default)


def _send_telegram_text(bot_token, chat_id, text):
    """Send a plain text message to Telegram (truncated to 4096 chars)."""
    import urllib.request, urllib.parse, json
    text = text[:4096]
    data = urllib.parse.urlencode({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "HTML",
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        data=data,
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        return json.loads(resp.read())
    except Exception as e:
        print(f"  [CRASH_REPORTER] Telegram text send failed: {e}", file=sys.stderr)
        return None


def _send_telegram_document(bot_token, chat_id, file_path, caption=""):
    """Send a file as a Telegram document."""
    import urllib.request, http.client
    if not os.path.exists(file_path):
        return None

    # Build multipart form manually (no external deps)
    boundary = "----PythonCrashReporterBoundary7f3a9c"
    body_parts = []

    # chat_id field
    body_parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
        f"{chat_id}\r\n"
    )

    # caption field
    if caption:
        body_parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="caption"\r\n\r\n'
            f"{caption[:1024]}\r\n"
        )

    # document file
    with open(file_path, "rb") as f:
        file_data = f.read()

    fname = os.path.basename(file_path)
    body_parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="document"; filename="{fname}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )

    body = "".join(body_parts).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode()

    try:
        conn = http.client.HTTPSConnection("api.telegram.org", timeout=60)
        conn.request(
            "POST",
            f"/bot{bot_token}/sendDocument",
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        resp = conn.getresponse()
        return resp.read()
    except Exception as e:
        print(f"  [CRASH_REPORTER] Telegram document send failed: {e}", file=sys.stderr)
        return None


# ── Core crash report builder ────────────────────────────────────────────────

def build_crash_report(exc_type, exc_value, exc_tb):
    """
    Returns a detailed crash report string.

    Covers:
      - Exact exception type + message
      - Full traceback with file path, line number, function name, source line
      - Every frame in the call stack (innermost last)
      - Build environment snapshot
    """
    lines = []
    sep = "=" * 72

    lines.append(sep)
    lines.append("  ❌  BUILD CRASH REPORT")
    lines.append(f"  Time      : {_now()}")
    lines.append(f"  Run       : #{_env('GITHUB_RUN_NUMBER', 'local')}")
    lines.append(f"  Commit    : {_env('GITHUB_SHA', 'unknown')[:12]}")
    lines.append(f"  Workflow  : {_env('GITHUB_WORKFLOW', 'unknown')}")
    lines.append(sep)

    # ── Exception summary ──────────────────────────────────────────────────
    lines.append("")
    lines.append("  EXCEPTION")
    lines.append(f"  Type    : {exc_type.__name__}")
    lines.append(f"  Message : {exc_value}")
    lines.append("")

    # ── Full traceback ─────────────────────────────────────────────────────
    lines.append("  FULL TRACEBACK (most recent call last)")
    lines.append("  " + "-" * 68)

    tb_entries = traceback.extract_tb(exc_tb)
    for i, frame in enumerate(tb_entries):
        rel_path = frame.filename
        # Make path relative to workspace if possible
        ws = _env("GITHUB_WORKSPACE", "")
        if ws and rel_path.startswith(ws):
            rel_path = rel_path[len(ws):].lstrip("/")

        lines.append(f"  [{i+1:02d}] File : {rel_path}")
        lines.append(f"       Line : {frame.lineno}")
        lines.append(f"       Func : {frame.name}")
        if frame.line:
            lines.append(f"       Code : {frame.line.strip()}")
        lines.append("")

    # ── Crash location summary (innermost frame) ───────────────────────────
    if tb_entries:
        last = tb_entries[-1]
        rel_path = last.filename
        ws = _env("GITHUB_WORKSPACE", "")
        if ws and rel_path.startswith(ws):
            rel_path = rel_path[len(ws):].lstrip("/")

        lines.append("  CRASH LOCATION SUMMARY")
        lines.append(f"  File     : {rel_path}")
        lines.append(f"  Line     : {last.lineno}")
        lines.append(f"  Function : {last.name}")
        lines.append(f"  Code     : {last.line.strip() if last.line else '(unavailable)'}")
        lines.append(f"  Reason   : {exc_type.__name__}: {exc_value}")
        lines.append("")

    # ── Chained exceptions ─────────────────────────────────────────────────
    cause = exc_value.__cause__ or exc_value.__context__
    depth = 0
    while cause and depth < 5:
        depth += 1
        lines.append(f"  CAUSED BY (depth {depth})")
        lines.append(f"  Type    : {type(cause).__name__}")
        lines.append(f"  Message : {cause}")
        cause_tb = cause.__traceback__
        if cause_tb:
            cause_frames = traceback.extract_tb(cause_tb)
            if cause_frames:
                cf = cause_frames[-1]
                lines.append(f"  At      : {cf.filename}:{cf.lineno} in {cf.name}")
                if cf.line:
                    lines.append(f"  Code    : {cf.line.strip()}")
        lines.append("")
        cause = cause.__cause__ or cause.__context__

    # ── Environment snapshot ───────────────────────────────────────────────
    lines.append("  ENVIRONMENT")
    env_keys = [
        "GITHUB_WORKFLOW", "GITHUB_RUN_NUMBER", "GITHUB_SHA",
        "GITHUB_ACTOR", "GITHUB_REF", "RUNNER_OS",
        "TEMPLATE", "CLIENT_ID", "MODULE_ASSET",
        "NEW_MOD_PKG", "INSTALLER_PKG", "ANDROID_SDK_ROOT",
    ]
    for key in env_keys:
        val = _env(key)
        if val:
            lines.append(f"  {key:28s} = {val}")
    lines.append("")

    lines.append(sep)
    lines.append("  END OF CRASH REPORT")
    lines.append(sep)

    return "\n".join(lines)


# ── Context manager ───────────────────────────────────────────────────────────

@contextlib.contextmanager
def crash_guard(report_path="crash_report.txt"):
    """
    Wraps a block of code. On any unhandled exception:
      1. Writes crash_report.txt
      2. Sends text summary to Telegram
      3. Sends crash_report.txt as Telegram document
      4. Re-raises so the process exits non-zero
    """
    try:
        yield
    except SystemExit:
        raise
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()

        # Build report
        report = build_crash_report(exc_type, exc_value, exc_tb)

        # Always print to stdout/stderr so it appears in CI logs
        print("\n" + report, file=sys.stderr)

        # Write to file
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"\n  [CRASH_REPORTER] Report written → {report_path}", file=sys.stderr)
        except Exception as write_err:
            print(f"  [CRASH_REPORTER] Failed to write report file: {write_err}", file=sys.stderr)

        # Send to Telegram
        bot_token = _env("BOT_TOKEN") or _env("TELEGRAM_BOT_TOKEN")
        chat_id   = _env("CHAT_ID")   or _env("TELEGRAM_CHAT_ID")

        if bot_token and chat_id:
            # Text summary (first 4096 chars of report)
            run_num = _env("GITHUB_RUN_NUMBER", "local")
            short_summary = (
                f"❌ <b>Build #{run_num} CRASHED</b>\n"
                f"<b>Type:</b> {exc_type.__name__}\n"
                f"<b>Message:</b> {str(exc_value)[:300]}\n"
            )
            if exc_tb:
                frames = traceback.extract_tb(exc_tb)
                if frames:
                    last = frames[-1]
                    ws = _env("GITHUB_WORKSPACE", "")
                    fp = last.filename
                    if ws and fp.startswith(ws):
                        fp = fp[len(ws):].lstrip("/")
                    short_summary += (
                        f"<b>File:</b> {fp}\n"
                        f"<b>Line:</b> {last.lineno}\n"
                        f"<b>Function:</b> {last.name}\n"
                        f"<b>Code:</b> <code>{last.line.strip() if last.line else '?'}</code>\n"
                    )

            print(f"  [CRASH_REPORTER] Sending text summary to Telegram...", file=sys.stderr)
            _send_telegram_text(bot_token, chat_id, short_summary)

            if os.path.exists(report_path):
                caption = f"❌ Build #{run_num} crash report — full details inside"
                print(f"  [CRASH_REPORTER] Sending report file to Telegram...", file=sys.stderr)
                _send_telegram_document(bot_token, chat_id, report_path, caption)
        else:
            print("  [CRASH_REPORTER] No Telegram credentials — skipping Telegram send", file=sys.stderr)

        raise  # Re-raise so CI marks the step as failed
