#!/usr/bin/env python3
"""
build_stub_dex.py

Builds the Berlin installer stub classes.dex from BerlinStubLoader.java.
Pure Java — zero Kotlin stdlib dependency. No kotlinc required.
Patches BERLIN_DEX_ASSET and BERLIN_DEX_KEY directly into the DEX byte arrays.

Flow:
  1. Compile BerlinStubLoader.java → .class using javac
  2. Convert .class → classes.dex using d8
  3. Patch asset name  (marker: 32 × 0xAB) with actual BERLIN_DEX_ASSET
  4. Patch AES-256 key (marker: 64 × 0xCD) with actual BERLIN_DEX_KEY hex
  5. Write patched classes.dex to output path

Usage:
    python3 build_stub_dex.py \\
        <stub_java_path>       path to BerlinStubLoader.java
        <output_dex_path>      where to write patched classes.dex
        <berlin_dex_asset>     e.g. "d4f9a2c1.bin"  (≤31 chars)
        <berlin_dex_key_hex>   64-char hex AES-256 key
        <android_jar_path>     path to android.jar (e.g. $ANDROID_HOME/platforms/android-34/android.jar)
        [d8_path]              optional: path to d8 binary (default: auto-detect from $ANDROID_HOME)
"""

import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path


ASSET_MARKER = bytes([0xAB] * 32)   # 32 × 0xAB — asset name placeholder
KEY_MARKER   = bytes([0xCD] * 64)   # 64 × 0xCD — AES key hex placeholder


def find_d8(android_home: str) -> str:
    candidates = [
        os.path.join(android_home, "build-tools", "34.0.0", "d8"),
        os.path.join(android_home, "build-tools", "33.0.2", "d8"),
        os.path.join(android_home, "build-tools", "33.0.0", "d8"),
    ]
    # Try all build-tools versions
    bt_root = os.path.join(android_home, "build-tools")
    if os.path.isdir(bt_root):
        for ver in sorted(os.listdir(bt_root), reverse=True):
            candidates.insert(0, os.path.join(bt_root, ver, "d8"))
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    # Fallback: d8 on PATH
    d8 = shutil.which("d8")
    if d8:
        return d8
    sys.exit("ERROR: d8 not found. Pass d8_path or ensure ANDROID_HOME/build-tools/*/d8 exists.")


def find_javac() -> str:
    # Prefer JAVA_HOME/bin/javac, then PATH
    java_home = os.environ.get("JAVA_HOME", "")
    if java_home:
        candidate = os.path.join(java_home, "bin", "javac")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    jc = shutil.which("javac")
    if jc:
        return jc
    sys.exit("ERROR: javac not found. Ensure JDK is installed and on PATH or JAVA_HOME is set.")


def patch_marker(dex: bytes, marker: bytes, value: bytes, label: str) -> bytes:
    idx = dex.find(marker)
    if idx == -1:
        sys.exit(f"ERROR: Marker {label} not found in DEX. Was BerlinStubLoader.java compiled correctly?")
    if len(value) > len(marker):
        sys.exit(f"ERROR: {label} value ({len(value)} bytes) exceeds marker size ({len(marker)} bytes).")
    # Patch: write value bytes, pad remainder with 0x00
    patched = bytearray(dex)
    for i, b in enumerate(value):
        patched[idx + i] = b
    for i in range(len(value), len(marker)):
        patched[idx + i] = 0x00   # null terminator — scanner in BerlinStubLoader.kt stops at 0x00
    return bytes(patched)


def fix_dex_checksum(dex: bytes) -> bytes:
    """Fix Adler-32 checksum at bytes 8..11 (covers bytes 12..end)."""
    import zlib
    checksum = zlib.adler32(dex[12:]) & 0xFFFFFFFF
    return dex[:8] + checksum.to_bytes(4, 'little') + dex[12:]


def main():
    if len(sys.argv) < 6:
        sys.exit(
            f"Usage: {sys.argv[0]} "
            "<stub_java_path> <output_dex_path> <berlin_dex_asset> "
            "<berlin_dex_key_hex> <android_jar_path> [d8_path]"
        )

    stub_java     = Path(sys.argv[1])
    output_dex    = Path(sys.argv[2])
    asset_name    = sys.argv[3].strip()
    key_hex       = sys.argv[4].strip()
    android_jar   = sys.argv[5].strip()
    d8_path       = sys.argv[6] if len(sys.argv) > 6 else None

    # Validate
    if not stub_java.exists():
        sys.exit(f"ERROR: Stub Java file not found: {stub_java}")
    if not os.path.isfile(android_jar):
        sys.exit(f"ERROR: android.jar not found: {android_jar}")
    if len(key_hex) != 64:
        sys.exit(f"ERROR: berlin_dex_key_hex must be 64 chars. Got {len(key_hex)}.")
    asset_bytes = asset_name.encode("utf-8")
    if len(asset_bytes) > 31:
        sys.exit(f"ERROR: asset_name too long ({len(asset_bytes)} bytes, max 31).")
    key_bytes_utf8 = key_hex.encode("utf-8")  # 64 ASCII chars = 64 bytes

    javac = find_javac()
    d8    = find_d8(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", ""))) \
            if not d8_path else d8_path

    print(f"[build_stub_dex] javac         : {javac}")
    print(f"[build_stub_dex] d8            : {d8}")
    print(f"[build_stub_dex] android.jar   : {android_jar}")
    print(f"[build_stub_dex] Asset name    : {asset_name}")
    print(f"[build_stub_dex] Key           : {key_hex[:16]}...")
    print(f"[build_stub_dex] Stub source   : {stub_java}")
    print(f"[build_stub_dex] Output DEX    : {output_dex}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        classes_dir = tmp / "stub_classes"
        classes_dir.mkdir()
        dex_dir = tmp / "dex_out"
        dex_dir.mkdir()

        # Step 1: javac → .class files
        # Pure Java — zero Kotlin stdlib. No runtime library needed beyond android.jar.
        print("[build_stub_dex] Compiling Java → .class ...")
        result = subprocess.run(
            [
                javac,
                "-source", "8",
                "-target", "8",
                "-classpath", android_jar,
                "-d", str(classes_dir),
                str(stub_java),
            ],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            sys.exit(f"ERROR: javac failed (exit {result.returncode})")

        # Collect all .class files produced
        extracted = [str(f) for f in classes_dir.rglob("*.class")]
        stub_classes = [f for f in extracted if "BerlinAppEntry" in f]
        if not stub_classes:
            sys.exit("ERROR: BerlinAppEntry.class not found after javac. Check class name in BerlinStubLoader.java.")
        print(f"[build_stub_dex] Compiled {len(extracted)} class file(s) for DEX compilation")

        # Step 2: d8 → classes.dex (only stub class files, NOT the full JAR)
        print("[build_stub_dex] Converting stub classes → DEX ...")
        result = subprocess.run(
            [
                d8,
                *extracted,
                "--release",
                "--min-api", "26",
                "--lib", android_jar,
                "--output", str(dex_dir),
            ],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr)
            sys.exit(f"ERROR: d8 failed (exit {result.returncode})")

        dex_file = dex_dir / "classes.dex"
        if not dex_file.exists():
            sys.exit(f"ERROR: d8 did not produce classes.dex in {dex_dir}")
        dex_size = dex_file.stat().st_size
        print(f"[build_stub_dex] DEX built     : {dex_file} ({dex_size:,} bytes)")
        if dex_size > 200_000:
            sys.exit(f"ERROR: Stub DEX too large ({dex_size:,} bytes, max 200KB). Check BerlinStubLoader.java for unexpected dependencies.")

        # Step 3: Patch asset name marker (32 × 0xAB)
        dex = dex_file.read_bytes()
        print(f"[build_stub_dex] Patching asset name marker ...")
        dex = patch_marker(dex, ASSET_MARKER, asset_bytes, "ASSET_MARKER(0xAB×32)")

        # Step 4: Patch AES key marker (64 × 0xCD)
        print(f"[build_stub_dex] Patching AES key marker ...")
        dex = patch_marker(dex, KEY_MARKER, key_bytes_utf8, "KEY_MARKER(0xCD×64)")

        # Step 5: Fix Adler-32 checksum after patching
        dex = fix_dex_checksum(dex)

        # Write output
        output_dex.parent.mkdir(parents=True, exist_ok=True)
        output_dex.write_bytes(dex)
        print(f"[build_stub_dex] Patched DEX   : {output_dex} ({len(dex):,} bytes)")
        print(f"[build_stub_dex] Done.")


if __name__ == "__main__":
    main()
