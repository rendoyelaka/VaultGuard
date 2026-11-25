#!/usr/bin/env python3
"""
apk_signer.py — Auto APK signer for Berlin App

Signing flow:
  1. Locate apksigner (Android build-tools or PATH)
  2. Use platform.jks (bundled in repo at keys/platform.jks)
  3. Password from env var KS_PASS — if not set or wrong → skip, warn
  4. V1 + V2 signing
  5. If signing fails for any reason → skip, output unsigned APK

Usage:
    python3 scripts/apk_signer.py <input_apk> [output_apk]
    If output_apk omitted → signs in-place.

Env vars:
    KS_PASS     — keystore password (optional — skip signing if absent)
    ANDROID_SDK_ROOT — path to Android SDK (optional)
"""

import glob
import os
import shutil
import subprocess
import sys

# ── Constants ─────────────────────────────────────────────────────────────────
KEY_ALIAS   = "platform"
KS_FILENAME = "platform.jks"
_KS_PASS    = "android"
_KEY_PASS   = "android"

# Locations to search for the keystore (relative to repo root / script dir)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT  = os.path.dirname(_SCRIPT_DIR)

KS_SEARCH_PATHS = [
    os.path.join(_REPO_ROOT, "berlin", "keys", KS_FILENAME),
    os.path.join(_SCRIPT_DIR, "..", "keys", KS_FILENAME),
    os.path.join(_REPO_ROOT, "keys", KS_FILENAME),
]


def _find_apksigner() -> str | None:
    """Find apksigner binary — SDK build-tools or PATH."""
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")
    if android_sdk:
        candidates = sorted(glob.glob(
            os.path.join(android_sdk, "build-tools", "*", "apksigner")
        ))
        if candidates:
            return candidates[-1]  # newest build-tools version

    # Try PATH
    found = shutil.which("apksigner")
    return found


def _find_keystore() -> str | None:
    """Find platform.jks in known locations."""
    for path in KS_SEARCH_PATHS:
        if os.path.exists(path):
            return path
    return None


def sign(input_apk: str, output_apk: str = None) -> bool:
    """
    Sign APK. Returns True on success, False if skipped/failed.
    If output_apk is None → sign in-place.
    """
    in_place = output_apk is None
    if in_place:
        output_apk = input_apk

    print(f"\n[apk_signer] ── Signing ───────────────────────────────────────")
    print(f"[apk_signer] Input:  {input_apk}")
    print(f"[apk_signer] Output: {output_apk}")

    # 1. Find apksigner
    apksigner = _find_apksigner()
    if not apksigner:
        print(f"[apk_signer] ⚠ apksigner not found — skipping signing")
        if not in_place and input_apk != output_apk:
            shutil.copy2(input_apk, output_apk)
        return False

    # 2. Find keystore
    ks_path = _find_keystore()
    if not ks_path:
        print(f"[apk_signer] ⚠ {KS_FILENAME} not found in: {KS_SEARCH_PATHS}")
        print(f"[apk_signer] ⚠ Skipping signing — place {KS_FILENAME} in keys/ folder")
        if not in_place and input_apk != output_apk:
            shutil.copy2(input_apk, output_apk)
        return False

    # 3. Password — hardcoded (no env var required)
    ks_pass = os.environ.get("KS_PASS", _KS_PASS)  # env override allowed

    # 4. Copy to output if not in-place
    if not in_place and input_apk != output_apk:
        shutil.copy2(input_apk, output_apk)
        target = output_apk
    else:
        target = input_apk

    # 5. Sign
    print(f"[apk_signer] Keystore: {ks_path}")
    print(f"[apk_signer] Alias:    {KEY_ALIAS}")
    print(f"[apk_signer] Tool:     {apksigner}")

    cmd = [
        apksigner, "sign",
        "--ks",              ks_path,
        "--ks-pass",         f"pass:{ks_pass}",
        "--ks-key-alias",    KEY_ALIAS,
        "--key-pass",        f"pass:{_KEY_PASS}",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        target,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[apk_signer] ⚠ apksigner failed (exit {result.returncode}):")
            print(f"[apk_signer]   {result.stderr.strip()}")
            print(f"[apk_signer] ⚠ Skipping signing — unsigned APK at {target}")
            return False

        print(f"[apk_signer] ✅ Signed OK → {target}")
        return True

    except Exception as e:
        print(f"[apk_signer] ⚠ Signing exception: {e}")
        print(f"[apk_signer] ⚠ Skipping signing — unsigned APK at {target}")
        return False


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apk_signer.py <input_apk> [output_apk]")
        sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None

    ok = sign(inp, out)
    sys.exit(0 if ok else 1)
