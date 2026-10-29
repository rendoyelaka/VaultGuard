#!/usr/bin/env python3
"""
folder_nester.py  —  Step 10 [COMPANION]
-----------------------------------------------
Injects the module data into an 11-level deep unicode folder path
inside the APK ZIP, using interleaved Arabic RTL chars and Korean hangul
filler (U+3164) as folder names.

Folder structure (example):
    ۦ/ㅤ/ۖ/ㅤ/۫/ㅤ/ۦ/ㅤ/ۖ/ㅤ/۫/<payload_filename>

Primary chars  : Arabic RTL  ۦ (U+06E6)  ۖ (U+0596)  ۫ (U+06EB)
Secondary chars: Korean hangul filler ㅤ (U+3164)

The interleaved pattern ensures tools that handle one charset but not
the other will fail to parse the full path.

Usage (standalone):
    python3 scripts/folder_nester.py \
        --apk companion_renamed_unsigned.apk \
        --payload <path_to_payload_bytes> \
        --ext .bin \
        --build-hash a3f9c2

Usage (called from build_module.py):
    from folder_nester import inject_unicode_nest
    nest_path = inject_unicode_nest(apk_path, payload_bytes, build_hash, ext=".bin")
"""

import os
import sys
import random
import secrets
import zipfile
import argparse

# ── Unicode character pools ───────────────────────────────────────────────────

# PRIMARY: Arabic RTL presentation/combining chars that are valid Unicode
# but cause RTL parsers and most APK tools to misinterpret path boundaries.
ARABIC_RTL = [
    "\u06E6",   # ARABIC SMALL YEH       ۦ
    "\u0596",   # HEBREW ACCENT TIPEHA   ۖ  (RTL, used here as confusion char)
    "\u06EB",   # ARABIC SMALL HIGH THREE DOTS  ۫
    "\u200F",   # RIGHT-TO-LEFT MARK (invisible, zero-width)
    "\u06DD",   # ARABIC END OF AYAH     ۝
]

# SECONDARY: Korean hangul filler — looks like whitespace but is a full char.
HANGUL_FILLER = "\u3164"   # ㅤ

# Depth is fixed at 11 levels per spec.
NEST_DEPTH = 11


# ── Path generator ────────────────────────────────────────────────────────────

def generate_nest_path(build_hash: str, filename: str) -> str:
    """
    Build an 11-level interleaved unicode folder path.

    Pattern: arabic / hangul / arabic / hangul / ... / filename
    Each arabic level picks a random char from ARABIC_RTL pool.
    The hangul level is always U+3164.

    Returns the full ZIP entry path string (e.g. "ۦ/ㅤ/ۖ/ㅤ/.../payload.bin").
    """
    # Use build_hash to seed per-build determinism (same hash → same path).
    rng = random.Random(build_hash)
    parts = []
    for level in range(NEST_DEPTH):
        if level % 2 == 0:
            # Even levels: pick from Arabic RTL pool
            parts.append(rng.choice(ARABIC_RTL))
        else:
            # Odd levels: Korean hangul filler
            parts.append(HANGUL_FILLER)
    parts.append(filename)
    return "/".join(parts)


# ── APK injector ─────────────────────────────────────────────────────────────

def inject_unicode_nest(
    apk_path: str,
    payload_bytes: bytes,
    build_hash: str,
    ext: str = ".bin",
) -> str:
    """
    Injects payload_bytes into apk_path under an 11-level unicode nested path.

    - apk_path     : path to the APK (modified in-place)
    - payload_bytes: raw bytes of the module data to embed
    - build_hash   : hex string used as RNG seed (per-build determinism)
    - ext          : file extension for the payload entry (default .bin)

    Returns the full ZIP entry path of the injected payload.
    """
    # Build the payload filename: build_hash + extension
    payload_filename = build_hash[:8] + ext
    nest_path = generate_nest_path(build_hash, payload_filename)

    print(f"\n── Step 10: Unicode folder nesting (Companion)")
    print(f"  Depth     : {NEST_DEPTH} levels")
    print(f"  Path      : {repr(nest_path)}")
    print(f"  Payload   : {len(payload_bytes)} bytes  ext={ext}")

    tmp_path = apk_path + ".nest_tmp"

    with zipfile.ZipFile(apk_path, "r") as zin:
        with zipfile.ZipFile(tmp_path, "w", allowZip64=False) as zout:
            # Copy all existing entries unchanged
            for item in zin.infolist():
                data = zin.read(item.filename)
                zout.writestr(item, data)

            # Inject the unicode-nested payload entry
            nest_info = zipfile.ZipInfo(nest_path)
            nest_info.compress_type = zipfile.ZIP_STORED
            # CRITICAL: Set UTF-8 EFS flag (bit 11) so apksigner reads the
            # unicode filename correctly and doesn't produce mojibake in
            # MANIFEST.MF → prevents v1 signature verification failure.
            nest_info.flag_bits |= 0x800
            zout.writestr(nest_info, payload_bytes)

    os.replace(tmp_path, apk_path)

    size_kb = os.path.getsize(apk_path) // 1024
    print(f"  ✅ Injected into APK  ({size_kb} KB total)")
    print(f"  ✅ Entry: {repr(nest_path)}")
    return nest_path


# ── Path printer (debug / verification) ──────────────────────────────────────

def print_nest_path(build_hash: str, ext: str = ".bin") -> None:
    """Print the unicode path that would be generated for a given build hash."""
    filename = build_hash[:8] + ext
    path = generate_nest_path(build_hash, filename)
    print(f"Build hash : {build_hash}")
    print(f"Nest path  : {repr(path)}")
    print(f"Levels     : {path.count('/') } folder separators  ({NEST_DEPTH} levels)")
    print("\nLevel breakdown:")
    parts = path.split("/")
    for i, part in enumerate(parts[:-1]):
        kind = "Arabic RTL" if i % 2 == 0 else "Korean hangul (U+3164)"
        print(f"  Level {i+1:2d}  U+{ord(part):04X}  {kind}")
    print(f"  Payload : {parts[-1]}")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Step 10 — Inject companion payload into unicode nested folder"
    )
    sub = parser.add_subparsers(dest="cmd")

    # inject sub-command
    inj = sub.add_parser("inject", help="Inject payload into APK")
    inj.add_argument("--apk",          required=True, help="APK file to modify in-place")
    inj.add_argument("--payload",      required=True, help="Path to payload file")
    inj.add_argument("--build-hash",   required=True, help="Build hash (hex) for path seed")
    inj.add_argument("--ext",          default=".bin", help="Payload file extension (default: .bin)")

    # show sub-command (dry run — just print the path)
    show = sub.add_parser("show", help="Print the unicode path without modifying any file")
    show.add_argument("--build-hash",  required=True, help="Build hash (hex) for path seed")
    show.add_argument("--ext",         default=".bin", help="Payload file extension (default: .bin)")

    args = parser.parse_args()

    if args.cmd == "inject":
        if not os.path.isfile(args.apk):
            print(f"[X] APK not found: {args.apk}")
            sys.exit(1)
        if not os.path.isfile(args.payload):
            print(f"[X] Payload not found: {args.payload}")
            sys.exit(1)
        with open(args.payload, "rb") as f:
            payload_bytes = f.read()
        inject_unicode_nest(args.apk, payload_bytes, args.build_hash, ext=args.ext)

    elif args.cmd == "show":
        print_nest_path(args.build_hash, ext=args.ext)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
