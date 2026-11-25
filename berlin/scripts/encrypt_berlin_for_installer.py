#!/usr/bin/env python3
"""
encrypt_berlin_for_installer.py

Encrypts the signed Berlin APK with AES-256-CBC for embedding in the installer assets.

Usage:
    python3 encrypt_berlin_for_installer.py <signed_berlin.apk> <asset_name> <key_hex> <output_path>

Arguments:
    signed_berlin.apk  — fully built + signed berlin APK (output of apk_signer.py)
    asset_name         — random asset filename from BuildConfig.ASSET_C (e.g. "c4a1b8f2.bin")
    key_hex            — 64-char hex AES-256 key from BuildConfig.BERLIN_KEY
    output_path        — destination path to write encrypted blob
                         (should be app/src/main/assets/<asset_name>)

Blob format written to output_path:
    [16 bytes IV (random)][AES-256-CBC PKCS7-padded ciphertext of APK bytes]

BerlinInstallManager.kt reads ASSET_C from assets, strips the 16-byte IV,
decrypts with BERLIN_KEY, and passes the raw APK bytes to PackageInstaller.
"""

import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as sym_padding
    import secrets
except ImportError:
    sys.exit("ERROR: 'cryptography' package not installed. Run: pip3 install cryptography")


def _verify_apk(data: bytes) -> bool:
    """APK = ZIP. Magic bytes: PK\\x03\\x04"""
    return (len(data) > 4 and
            data[0] == 0x50 and data[1] == 0x4B and
            data[2] == 0x03 and data[3] == 0x04)


def aes_256_cbc_encrypt(key_bytes: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext with AES-256-CBC + PKCS7 padding.
    Returns: [16-byte random IV][ciphertext]
    """
    if len(key_bytes) != 32:
        raise ValueError(f"Key must be 32 bytes (256-bit). Got {len(key_bytes)}.")

    iv = secrets.token_bytes(16)

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def main():
    if len(sys.argv) != 5:
        sys.exit(
            f"Usage: {sys.argv[0]} "
            "<signed_berlin.apk> <asset_name> <key_hex_64chars> <output_path>"
        )

    apk_path    = Path(sys.argv[1])
    asset_name  = sys.argv[2].strip()
    key_hex     = sys.argv[3].strip()
    output_path = Path(sys.argv[4])

    # Validate APK
    if not apk_path.exists():
        sys.exit(f"ERROR: Berlin APK not found: {apk_path}")

    # Validate key
    if len(key_hex) != 64:
        sys.exit(f"ERROR: key_hex must be 64 hex chars (256-bit AES). Got {len(key_hex)} chars.")
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError as e:
        sys.exit(f"ERROR: Invalid hex key: {e}")

    # Read APK bytes
    apk_bytes = apk_path.read_bytes()

    # Verify it is a valid APK (ZIP magic)
    if not _verify_apk(apk_bytes):
        sys.exit(
            f"ERROR: {apk_path} does not look like a valid APK. "
            f"Expected ZIP magic PK\\x03\\x04. "
            f"First 4 bytes: {apk_bytes[:4].hex()}"
        )

    print(f"[encrypt_berlin] Input APK  : {apk_path} ({len(apk_bytes):,} bytes) — ZIP magic OK")
    print(f"[encrypt_berlin] Asset name : {asset_name}")
    print(f"[encrypt_berlin] Output     : {output_path}")

    # Encrypt
    blob = aes_256_cbc_encrypt(key_bytes, apk_bytes)
    iv_hex = blob[:16].hex()
    print(f"[encrypt_berlin] IV         : {iv_hex}")
    print(f"[encrypt_berlin] Blob size  : {len(blob):,} bytes (IV=16 + ciphertext={len(blob)-16})")

    # Write encrypted blob to output path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)
    print(f"[encrypt_berlin] Written    : {output_path}")
    print(f"[encrypt_berlin] Done.")


if __name__ == "__main__":
    main()
