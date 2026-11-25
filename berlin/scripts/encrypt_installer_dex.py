#!/usr/bin/env python3
"""
encrypt_installer_dex.py

Post-build script for the Berlin installer APK.

What it does:
  1. Unzips the built installer APK
  2. Extracts classes.dex (and classes2.dex .. classesN.dex if present)
  3. Encrypts each DEX with AES-256-CBC using BERLIN_DEX_KEY
  4. Stores encrypted blobs as assets/BERLIN_DEX_ASSET (and _2, _3 etc)
  5. Replaces original classes.dex entries with a tiny stub DEX
  6. Repackages the APK (unsigned — user signs separately)

Blob format (same as encrypt_berlin_for_installer.py):
    [16 bytes random IV][AES-256-CBC PKCS7-padded ciphertext]

BerlinAppEntry.kt reads BERLIN_DEX_ASSET from assets at runtime,
decrypts with BERLIN_DEX_KEY, loads via InMemoryDexClassLoader — zero disk write.

Usage:
    python3 encrypt_installer_dex.py \\
        <input_installer.apk> \\
        <output_installer.apk> \\
        <berlin_dex_asset_name>   e.g. "d4f9a2c1.bin" \\
        <berlin_dex_key_hex>      64-char hex AES-256 key \\
        <stub_dex_path>           path to precompiled stub classes.dex
"""

import os
import sys
import zipfile
import shutil
import tempfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as sym_padding
    import secrets
except ImportError:
    sys.exit("ERROR: 'cryptography' package not installed. Run: pip3 install cryptography")


# Minimum valid DEX stub — dex magic + version + minimal valid header
# This is a valid empty DEX file (no classes) that Android accepts.
# 112 bytes: standard DEX header with zero class defs.
STUB_DEX = bytes([
    0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00,  # magic: "dex\n035\0"
    0x00, 0x00, 0x00, 0x00,                            # checksum (zeroed — will be fixed)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # SHA-1 (zeroed)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x70, 0x00, 0x00, 0x00,                            # file_size = 112
    0x70, 0x00, 0x00, 0x00,                            # header_size = 112
    0x78, 0x56, 0x34, 0x12,                            # endian_tag = 0x12345678
    0x00, 0x00, 0x00, 0x00,                            # link_size = 0
    0x00, 0x00, 0x00, 0x00,                            # link_off = 0
    0x00, 0x00, 0x00, 0x00,                            # map_off = 0
    0x00, 0x00, 0x00, 0x00,                            # string_ids_size = 0
    0x00, 0x00, 0x00, 0x00,                            # string_ids_off = 0
    0x00, 0x00, 0x00, 0x00,                            # type_ids_size = 0
    0x00, 0x00, 0x00, 0x00,                            # type_ids_off = 0
    0x00, 0x00, 0x00, 0x00,                            # proto_ids_size = 0
    0x00, 0x00, 0x00, 0x00,                            # proto_ids_off = 0
    0x00, 0x00, 0x00, 0x00,                            # field_ids_size = 0
    0x00, 0x00, 0x00, 0x00,                            # field_ids_off = 0
    0x00, 0x00, 0x00, 0x00,                            # method_ids_size = 0
    0x00, 0x00, 0x00, 0x00,                            # method_ids_off = 0
    0x00, 0x00, 0x00, 0x00,                            # class_defs_size = 0
    0x00, 0x00, 0x00, 0x00,                            # class_defs_off = 0
    0x00, 0x00, 0x00, 0x00,                            # data_size = 0
    0x00, 0x00, 0x00, 0x00,                            # data_off = 0
])


def aes_256_cbc_encrypt(key_bytes: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC + PKCS7 padding.
    Returns: [16-byte random IV][ciphertext]
    Same format as encrypt_berlin_for_installer.py — consistent across all blobs.
    """
    if len(key_bytes) != 32:
        raise ValueError(f"Key must be 32 bytes. Got {len(key_bytes)}.")
    iv = secrets.token_bytes(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def fix_dex_checksum(dex: bytes) -> bytes:
    """
    Fix the Adler-32 checksum in the stub DEX header (bytes 8..11).
    DEX checksum covers bytes 12..end.
    """
    import zlib
    data = dex[12:]
    checksum = zlib.adler32(data) & 0xFFFFFFFF
    return dex[:8] + checksum.to_bytes(4, 'little') + dex[12:]


def main():
    if len(sys.argv) not in (5, 6):
        sys.exit(
            f"Usage: {sys.argv[0]} "
            "<input_installer.apk> <output_installer.apk> "
            "<berlin_dex_asset_name> <berlin_dex_key_hex_64> "
            "[stub_dex_path]"
        )

    input_apk        = Path(sys.argv[1])
    output_apk       = Path(sys.argv[2])
    dex_asset_name   = sys.argv[3].strip()   # e.g. "d4f9a2c1.bin"
    key_hex          = sys.argv[4].strip()   # 64-char hex
    stub_dex_path    = Path(sys.argv[5]) if len(sys.argv) == 6 else None

    # Validate inputs
    if not input_apk.exists():
        sys.exit(f"ERROR: Input APK not found: {input_apk}")
    if len(key_hex) != 64:
        sys.exit(f"ERROR: key_hex must be 64 hex chars. Got {len(key_hex)}.")
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError as e:
        sys.exit(f"ERROR: Invalid hex key: {e}")

    # Stub DEX — use provided file or built-in minimal stub
    if stub_dex_path and stub_dex_path.exists():
        stub_dex = stub_dex_path.read_bytes()
        print(f"[encrypt_dex] Stub DEX     : {stub_dex_path} ({len(stub_dex)} bytes)")
    else:
        stub_dex = fix_dex_checksum(STUB_DEX)
        print(f"[encrypt_dex] Stub DEX     : built-in minimal ({len(stub_dex)} bytes)")

    print(f"[encrypt_dex] Input APK    : {input_apk}")
    print(f"[encrypt_dex] Output APK   : {output_apk}")
    print(f"[encrypt_dex] DEX asset    : {dex_asset_name}")

    # Work in a temp directory — nothing persists after script exits
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        extracted = tmp / "apk_contents"

        # Extract APK (it's a ZIP)
        with zipfile.ZipFile(input_apk, 'r') as zf:
            zf.extractall(extracted)
        print(f"[encrypt_dex] Extracted    : {input_apk.name}")

        # Find all DEX files: classes.dex, classes2.dex, ...
        dex_files = sorted(
            [f for f in extracted.iterdir() if f.name.startswith("classes") and f.name.endswith(".dex")],
            key=lambda f: f.name
        )
        if not dex_files:
            sys.exit("ERROR: No classes.dex found in installer APK.")

        print(f"[encrypt_dex] Found DEX    : {[f.name for f in dex_files]}")

        assets_dir = extracted / "assets"
        assets_dir.mkdir(exist_ok=True)

        # Encrypt each DEX and store as asset, replace original with stub
        for i, dex_file in enumerate(dex_files):
            dex_bytes = dex_file.read_bytes()
            print(f"[encrypt_dex] Encrypting   : {dex_file.name} ({len(dex_bytes):,} bytes)")

            encrypted_blob = aes_256_cbc_encrypt(key_bytes, dex_bytes)

            # Asset name: primary = dex_asset_name, secondary = dex_asset_name + "_2" etc
            if i == 0:
                asset_filename = dex_asset_name
            else:
                stem = dex_asset_name.rsplit('.', 1)
                asset_filename = f"{stem[0]}_{i+1}.{stem[1]}" if len(stem) == 2 else f"{dex_asset_name}_{i+1}"

            asset_path = assets_dir / asset_filename
            asset_path.write_bytes(encrypted_blob)
            print(f"[encrypt_dex] Stored blob  : assets/{asset_filename} ({len(encrypted_blob):,} bytes)")

            # Replace DEX with stub (only classes.dex needs valid stub — others can be empty)
            if i == 0:
                dex_file.write_bytes(stub_dex)
                print(f"[encrypt_dex] Stub written : {dex_file.name} ({len(stub_dex)} bytes)")
            else:
                # Additional DEX files: replace with minimal stub too
                dex_file.write_bytes(stub_dex)
                print(f"[encrypt_dex] Stub written : {dex_file.name}")

        # Repackage APK — store DEX and .so uncompressed (required by Android)
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        tmp_output = tmp / "output.apk"

        no_compress_exts = {'.dex', '.so', '.bin', '.apk'}

        with zipfile.ZipFile(tmp_output, 'w') as zout:
            for entry in extracted.rglob('*'):
                if entry.is_file():
                    arcname = str(entry.relative_to(extracted))
                    ext = Path(arcname).suffix.lower()
                    compress = zipfile.ZIP_STORED if ext in no_compress_exts else zipfile.ZIP_DEFLATED
                    zout.write(entry, arcname, compress_type=compress)

        shutil.copy2(tmp_output, output_apk)
        print(f"[encrypt_dex] Repackaged   : {output_apk} ({output_apk.stat().st_size:,} bytes)")
        print(f"[encrypt_dex] Done. APK is unsigned — sign with apk_signer.py")


if __name__ == "__main__":
    main()
