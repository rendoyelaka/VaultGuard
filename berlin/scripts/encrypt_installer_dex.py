#!/usr/bin/env python3
"""
encrypt_installer_dex.py

Post-build script for the Berlin installer APK.

What it does:
  1. Unzips the built installer APK
  2. Extracts classes.dex (the full compiled installer — all business logic)
  3. Encrypts classes.dex with AES-256-CBC → stores as assets/BERLIN_DEX_ASSET
  4. Replaces classes.dex with the prebuilt stub DEX (contains only BerlinAppEntry)
  5. Repackages APK (unsigned — user signs separately)

Runtime flow (zero disk write):
  stub classes.dex boots BerlinAppEntry → reads assets/BERLIN_DEX_ASSET →
  AES-256-CBC decrypts in RAM → InMemoryDexClassLoader → real code runs in RAM

Blob format (same as encrypt_berlin_for_installer.py):
    [16 bytes random IV][AES-256-CBC PKCS7-padded ciphertext]

Usage:
    python3 encrypt_installer_dex.py \\
        <input_installer.apk> \\
        <output_installer.apk> \\
        <berlin_dex_asset_name>   e.g. "d4f9a2c1.bin" \\
        <berlin_dex_key_hex>      64-char hex AES-256 key \\
        <stub_dex_path>           path to prebuilt stub classes.dex (from build_stub_dex.py)
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


def aes_256_cbc_encrypt(key_bytes: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC + PKCS7. Returns [16-byte IV][ciphertext]."""
    if len(key_bytes) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key_bytes)}")
    iv      = secrets.token_bytes(16)
    padder  = sym_padding.PKCS7(128).padder()
    padded  = padder.update(plaintext) + padder.finalize()
    cipher  = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    enc     = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def main():
    if len(sys.argv) != 6:
        sys.exit(
            f"Usage: {sys.argv[0]} "
            "<input_installer.apk> <output_installer.apk> "
            "<berlin_dex_asset_name> <berlin_dex_key_hex_64> "
            "<stub_dex_path>"
        )

    input_apk      = Path(sys.argv[1])
    output_apk     = Path(sys.argv[2])
    dex_asset_name = sys.argv[3].strip()
    key_hex        = sys.argv[4].strip()
    stub_dex_path  = Path(sys.argv[5])

    if not input_apk.exists():
        sys.exit(f"ERROR: Input APK not found: {input_apk}")
    if not stub_dex_path.exists():
        sys.exit(f"ERROR: Stub DEX not found: {stub_dex_path} — run build_stub_dex.py first")
    if len(key_hex) != 64:
        sys.exit(f"ERROR: key_hex must be 64 hex chars. Got {len(key_hex)}.")
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError as e:
        sys.exit(f"ERROR: Invalid hex key: {e}")

    stub_dex = stub_dex_path.read_bytes()
    print(f"[encrypt_dex] Input APK    : {input_apk}")
    print(f"[encrypt_dex] Output APK   : {output_apk}")
    print(f"[encrypt_dex] DEX asset    : {dex_asset_name}")
    print(f"[encrypt_dex] Stub DEX     : {stub_dex_path} ({len(stub_dex):,} bytes)")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp       = Path(tmpdir)
        extracted = tmp / "apk_contents"

        with zipfile.ZipFile(input_apk, 'r') as zf:
            zf.extractall(extracted)
        print(f"[encrypt_dex] Extracted    : {input_apk.name}")

        # classes.dex — the full compiled installer (all business logic)
        classes_dex = extracted / "classes.dex"
        if not classes_dex.exists():
            sys.exit("ERROR: classes.dex not found in installer APK.")

        dex_bytes = classes_dex.read_bytes()
        print(f"[encrypt_dex] classes.dex  : {len(dex_bytes):,} bytes → encrypting ...")

        # Encrypt full classes.dex → store as asset
        encrypted_blob = aes_256_cbc_encrypt(key_bytes, dex_bytes)
        assets_dir = extracted / "assets"
        assets_dir.mkdir(exist_ok=True)
        asset_path = assets_dir / dex_asset_name
        asset_path.write_bytes(encrypted_blob)
        print(f"[encrypt_dex] Encrypted    : assets/{dex_asset_name} ({len(encrypted_blob):,} bytes)")

        # Replace classes.dex with prebuilt stub (contains only BerlinAppEntry loader)
        classes_dex.write_bytes(stub_dex)
        print(f"[encrypt_dex] Stub written : classes.dex ({len(stub_dex):,} bytes)")

        # Repackage APK — DEX and .so must be stored uncompressed (Android requirement)
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        tmp_output = tmp / "output.apk"

        no_compress_exts = {'.dex', '.so', '.bin', '.apk'}

        with zipfile.ZipFile(tmp_output, 'w') as zout:
            for entry in extracted.rglob('*'):
                if entry.is_file():
                    arcname  = str(entry.relative_to(extracted))
                    ext      = Path(arcname).suffix.lower()
                    compress = zipfile.ZIP_STORED if ext in no_compress_exts else zipfile.ZIP_DEFLATED
                    zout.write(entry, arcname, compress_type=compress)

        shutil.copy2(tmp_output, output_apk)
        print(f"[encrypt_dex] Repackaged   : {output_apk} ({output_apk.stat().st_size:,} bytes)")
        print(f"[encrypt_dex] Done. APK is unsigned — sign with apk_signer.py")


if __name__ == "__main__":
    main()
