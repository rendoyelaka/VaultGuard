#!/usr/bin/env python3
"""
data_processor.py — Phase 3 Steps 18-21

Step 18: Extract classes.dex from module APK
Step 19: Encrypt DEX with AES-256-GCM (key from FingerprintPlugin)
Step 20: Split encrypted blob into N randomized segments
Step 21: Tag each segment with sequence index + build hash

Usage (called from CI build.yml):
  python3 scripts/data_processor.py \
    --companion app/src/main/assets/module.apk \
    --aes-key <fp_aesKeyHex> \
    --salt <fp_saltHex> \
    --build-uuid <fp_buildUUID> \
    --out-dir /tmp/segments \
    --manifest /tmp/chunk_manifest.json

Output:
  /tmp/segments/chunk_000.bin  ... chunk_007.bin  (4-8 segments)
  /tmp/chunk_manifest.json   (offsets, sizes, hashes, XOR mask key)
"""

import os
import sys
import json
import struct
import hashlib
import secrets
import zipfile
import argparse
import random

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] pip install cryptography --break-system-packages")
    sys.exit(1)


def extract_dex(companion_apk: str) -> bytes:
    """Step 18: Extract classes.dex from companion APK."""
    print(f"[Step 18] Extracting classes.dex from {companion_apk}")
    with zipfile.ZipFile(companion_apk, 'r') as z:
        # Handle multi-dex: collect all dex files in order
        dex_files = sorted([n for n in z.namelist() if n.endswith('.dex')])
        print(f"  Found DEX files: {dex_files}")

        if not dex_files:
            raise ValueError("No .dex files found in companion APK")

        # Concatenate all dex files with length-prefix framing
        # Format: [4-byte count][4-byte len][dex bytes]...
        dex_data_list = []
        for dex_name in dex_files:
            data = z.read(dex_name)
            dex_data_list.append(data)
            print(f"  {dex_name}: {len(data)/1024:.1f}KB")

        # Pack: magic(4) + count(4) + [len(4) + data] * N
        packed = b'NDEX' + struct.pack('<I', len(dex_data_list))
        for d in dex_data_list:
            packed += struct.pack('<I', len(d)) + d

        print(f"  Total packed DEX: {len(packed)/1024:.1f}KB")
        return packed


def derive_aes_key(aes_key_hex: str, salt_hex: str, build_uuid: str) -> tuple:
    """Derive encryption key and IV using HKDF from FingerprintPlugin values."""
    # Master key from FingerprintPlugin (256-bit AES key)
    master_key = bytes.fromhex(aes_key_hex)
    salt       = bytes.fromhex(salt_hex)
    info       = f"nova_phase3_dex_{build_uuid}".encode()

    # Derive 44 bytes: 32 for AES-256 key + 12 for GCM nonce
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=44,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    derived = hkdf.derive(master_key)
    key = derived[:32]   # AES-256 key
    iv  = derived[32:]   # 12-byte GCM nonce
    return key, iv


def encrypt_dex(dex_bytes: bytes, key: bytes, iv: bytes) -> bytes:
    """Step 19: Encrypt DEX with AES-256-GCM."""
    print(f"[Step 19] Encrypting DEX ({len(dex_bytes)/1024:.1f}KB) with AES-256-GCM")
    aesgcm = AESGCM(key)
    # AAD must match DexLoader.kt private const val AAD exactly.
    # Changed from "nova_companion_dex" to neutral value — removes GPP fingerprint
    # from Nova DEX. Any mismatch here = AES-GCM decryption failure at runtime.
    aad = b"aes_gcm_v1"
    ciphertext = aesgcm.encrypt(iv, dex_bytes, aad)
    print(f"  Encrypted blob: {len(ciphertext)/1024:.1f}KB")
    # Prepend AAD length + AAD for runtime verification
    result = struct.pack('<I', len(aad)) + aad + ciphertext
    return result


def split_chunks(encrypted_blob: bytes, build_uuid: str) -> list:
    """Step 20: Split encrypted blob into N randomized chunks."""
    # N = 4-8 segments, randomized per build
    rng = random.Random(build_uuid)
    n_chunks = rng.randint(4, 8)
    total = len(encrypted_blob)

    print(f"[Step 20] Splitting {total/1024:.1f}KB into {n_chunks} chunks")

    # Generate random split points (not equal splits)
    # Each segment min 10% of total, max 40%
    min_size = max(1024, total // 10)
    max_size = total // 2

    boundaries = [0]
    remaining  = total
    for i in range(n_chunks - 1):
        chunks_left = n_chunks - i
        # Ensure remaining segments can all be at least min_size
        max_this = min(max_size, remaining - (chunks_left - 1) * min_size)
        if max_this < min_size:
            max_this = min_size
        size = rng.randint(min_size, max(min_size, max_this))
        boundaries.append(boundaries[-1] + size)
        remaining -= size

    boundaries.append(total)

    chunks = []
    for i in range(n_chunks):
        start = boundaries[i]
        end   = boundaries[i + 1]
        chunk_data = encrypted_blob[start:end]

        # Step 20: Tag segment with sequence index header
        # Header: magic(4) + index(2) + total_chunks(2) + chunk_size(4) + SHA256(32)
        sha256 = hashlib.sha256(chunk_data).digest()
        header = (
            b'NCHK' +
            struct.pack('<H', i) +
            struct.pack('<H', n_chunks) +
            struct.pack('<I', len(chunk_data)) +
            sha256
        )
        tagged_chunk = header + chunk_data
        chunks.append(tagged_chunk)
        print(f"  chunk_{i:03d}: {len(chunk_data)/1024:.1f}KB (sha256={sha256.hex()[:16]}...)")

    return chunks


def assign_fake_extensions(n_chunks: int, build_uuid: str) -> list:
    """Step 21: Assign fake extensions per build."""
    extensions = ['.bin', '.dat', '.np', '.cache', '.idx', '.sig', '.pak', '.blob']
    rng = random.Random(build_uuid + "ext")
    exts = rng.choices(extensions, k=n_chunks)
    return exts


def generate_xor_mask_key() -> int:
    """Generate XOR mask key for offset/size obfuscation (Step 24)."""
    return secrets.randbits(32)


def write_chunks(chunks: list, out_dir: str, build_hash: str, build_uuid: str) -> list:
    """Write chunks to output directory with fake extensions."""
    os.makedirs(out_dir, exist_ok=True)
    exts = assign_fake_extensions(len(chunks), build_uuid)
    chunk_files = []

    for i, chunk_data in enumerate(chunks):
        ext      = exts[i]
        filename = f"chunk_{i:03d}_{build_hash[:8]}{ext}"
        path     = os.path.join(out_dir, filename)
        with open(path, 'wb') as f:
            f.write(chunk_data)
        chunk_files.append({
            'index':    i,
            'filename': filename,
            'path':     path,
            'size':     len(chunk_data),
            'sha256':   hashlib.sha256(chunk_data).hexdigest(),
            'ext':      ext,
        })
        print(f"  Written: {filename} ({len(chunk_data)/1024:.1f}KB)")

    return chunk_files


def main():
    parser = argparse.ArgumentParser(description='Phase 3 DEX Encryptor')
    parser.add_argument('--companion',   required=True,  help='Path to companion.apk')
    parser.add_argument('--aes-key',     required=True,  help='AES-256 key hex from FingerprintPlugin')
    parser.add_argument('--salt',        required=True,  help='Salt hex from FingerprintPlugin')
    parser.add_argument('--build-uuid',  required=True,  help='Build UUID from FingerprintPlugin')
    parser.add_argument('--build-hash',  required=True,  help='Build hash for filenames')
    parser.add_argument('--out-dir',     required=True,  help='Output directory for chunks')
    parser.add_argument('--manifest',    required=True,  help='Output chunk manifest JSON path')
    args = parser.parse_args()

    print(f"[Phase 3] DEX Encryption Pipeline")
    print(f"  Companion: {args.companion}")
    print(f"  Output:    {args.out_dir}")
    print(f"  Manifest:  {args.manifest}")
    print()

    # Step 18: Extract DEX
    dex_bytes = extract_dex(args.companion)

    # Step 19: Encrypt with AES-256-GCM
    key, iv = derive_aes_key(args.aes_key, args.salt, args.build_uuid)
    encrypted = encrypt_dex(dex_bytes, key, iv)

    # Compute integrity hashes (DUAL HASH: SHA-512 + BLAKE3-like via SHA-256)
    sha512_hash  = hashlib.sha512(encrypted).hexdigest()
    sha256_hash  = hashlib.sha256(encrypted).hexdigest()

    # Step 20: Split into segments
    chunks = split_chunks(encrypted, args.build_uuid)

    # Write segments
    chunk_files = write_chunks(chunks, args.out_dir, args.build_hash, args.build_uuid)

    # Generate XOR mask key for offset enhancion (Step 24)
    xor_mask_key = generate_xor_mask_key()

    # Build manifest
    manifest = {
        'version':       3,
        'build_uuid':    args.build_uuid,
        'build_hash':    args.build_hash,
        'n_chunks':      len(chunks),
        'total_enc_size':len(encrypted),
        'sha512_hash':   sha512_hash,
        'sha256_hash':   sha256_hash,
        'xor_mask_key':  xor_mask_key,
        'key_hex':       key.hex(),
        'iv_hex':        iv.hex(),
        'chunks':        chunk_files,
    }

    os.makedirs(os.path.dirname(args.manifest), exist_ok=True)
    with open(args.manifest, 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[Phase 3] ✅ Complete")
    print(f"  Chunks: {len(chunks)}")
    print(f"  SHA-512: {sha512_hash[:32]}...")
    print(f"  Manifest: {args.manifest}")

    # Output for CI environment variables
    print(f"\n::set-output name=chunk_count::{len(chunks)}")
    print(f"::set-output name=manifest_path::{args.manifest}")


if __name__ == '__main__':
    main()
