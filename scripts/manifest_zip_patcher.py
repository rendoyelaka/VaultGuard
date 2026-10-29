#!/usr/bin/env python3
"""
manifest_zip_patcher.py — Steps 7 / 17D / 17E / 17F

Step 7  — Manifest compression: stored(0) → deflate(8) to match IRT.apk

Step 17D — Binary manifest AES-256-GCM string encryption
    Selected non-critical string values inside the binary AndroidManifest.xml
    (AXML format) are encrypted with AES-256-GCM using a per-build key.
    The encrypted blobs replace the original string bytes in the AXML string pool.
    The native layer decrypts them before manifest parsing at runtime.
    NOTE: Only signal/non-essential strings are encrypted — package name,
    activity names and permissions are left intact so Android can install/run.

Step 17E — Fake encrypted blocks injection in manifest
    Non-functional binary blocks that look like AES-GCM ciphertext
    (random nonce + random bytes) are injected into the AXML string pool
    after the real strings. Confuses RE tools and automated manifest parsers.

Step 17F — Random manifest binary padding
    Random-length binary padding is appended to the AXML file data inside
    the APK. Each build produces a different manifest binary size.
    Defeats manifest-based APK fingerprinting.

Usage:
    python3 scripts/manifest_zip_patcher.py <apk_in> <apk_out> <aes_key_hex>

    aes_key_hex : 64-char hex string (32 bytes = AES-256 key) from fingerprint generator.

Re-sign after running:
    zipalign -f 4 apk_out apk_aligned.apk
    apksigner sign --ks ... apk_aligned.apk
"""

import sys
import os
import struct
import secrets
import zipfile
import random

try:
    from Crypto.Cipher import AES
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# ── AXML constants ─────────────────────────────────────────────────────────────
AXML_MAGIC        = b'\x03\x00\x08\x00'   # AXML file header type + headerSize
STRING_POOL_TYPE  = 0x0001
UTF8_FLAG         = 1 << 8

# Strings we MUST NOT encrypt (Android needs them to parse the manifest)
PROTECTED_STRINGS = {
    'android', 'package', 'android.permission',
    'activity', 'service', 'receiver', 'provider',
    'uses-permission', 'application', 'manifest',
    'http://schemas.android.com/apk/res/android',
}

# Fake encrypted block marker (Step 17E)
FAKE_BLOCK_MARKER = b'\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE'

# Padding bounds for Step 17F (bytes)
PAD_MIN = 64
PAD_MAX = 512


# ── AES-256-GCM encrypt / decrypt ─────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Returns nonce(12) + ciphertext + tag(16)."""
    if HAS_PYCRYPTODOME:
        nonce  = secrets.token_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + ct + tag
    else:
        # Fallback: XOR with key-derived stream (no PyCryptodome)
        # Still confuses parsers; not real GCM but structurally similar.
        nonce  = secrets.token_bytes(12)
        stream = bytearray()
        for i in range(0, len(plaintext) + 16, 32):
            stream.extend((k ^ (i & 0xFF)) for k in key)
        ct  = bytes(p ^ s for p, s in zip(plaintext, stream))
        tag = secrets.token_bytes(16)
        return nonce + ct + tag


def fake_gcm_block(min_len=16, max_len=128) -> bytes:
    """Step 17E — generate a fake AXML segment with unknown type.
    Uses a valid segment header so Android's AXML parser can skip it correctly.
    chunk_type = 0x00FF (unknown, not used by Android)
    header_size = 8 (standard minimum)
    chunk_size = 8 + payload_length (total including header)
    Android skips unknown segments by advancing chunk_size bytes.
    Random payload looks like AES-GCM ciphertext to confuse static scanners.
    """
    payload_len = random.randint(min_len, max_len)
    # Align payload to 4 bytes
    payload_len = (payload_len + 3) & ~3
    chunk_size  = 8 + payload_len
    header = struct.pack('<HHI', 0x00FF, 8, chunk_size)
    payload = secrets.token_bytes(payload_len)
    return header + payload


# ── AXML string pool parser / patcher ─────────────────────────────────────────

def patch_axml(axml_data: bytes, aes_key: bytes, skip_17d: bool = False) -> bytes:
    """
    Patches the AXML binary string pool:
      - Step 17D: encrypts selected non-critical string values
                  (skipped when skip_17d=True — requires Phase 4 native decryptor)
      - Step 17E: injects fake encrypted blocks (always applied)
      - Step 17F: appends random padding (always applied)
    Returns modified AXML bytes.
    """
    if len(axml_data) < 8:
        return axml_data

    data = bytearray(axml_data)

    # ── Locate string pool segment ──────────────────────────────────────────────
    # AXML layout: [file header 8 bytes][string pool segment][xml tree segments...]
    SP = 8
    if len(data) < SP + 28:
        return bytes(data)

    sp_type       = struct.unpack_from('<H', data, SP)[0]
    sp_hdr_size   = struct.unpack_from('<H', data, SP + 2)[0]
    sp_chunk_size = struct.unpack_from('<I', data, SP + 4)[0]
    str_count     = struct.unpack_from('<I', data, SP + 8)[0]
    style_count   = struct.unpack_from('<I', data, SP + 12)[0]
    flags         = struct.unpack_from('<I', data, SP + 16)[0]
    strings_start = struct.unpack_from('<I', data, SP + 20)[0]
    styles_start  = struct.unpack_from('<I', data, SP + 24)[0]

    if sp_type != STRING_POOL_TYPE or str_count == 0:
        return bytes(data)

    is_utf8 = bool(flags & UTF8_FLAG)

    str_data_base = SP + strings_start
    offsets_base  = SP + sp_hdr_size

    # Read string offsets
    offsets = [
        struct.unpack_from('<I', data, offsets_base + i * 4)[0]
        for i in range(str_count)
    ]

    # Read strings (UTF-8 pool only — UTF-16 left untouched)
    strings = []
    if is_utf8:
        for off in offsets:
            pos = str_data_base + off
            if pos >= len(data):
                strings.append(None)
                continue
            b0 = data[pos]; pos += 1
            char_len = ((b0 & 0x7F) << 8) | data[pos] if b0 & 0x80 else b0
            if b0 & 0x80: pos += 1
            b1 = data[pos]; pos += 1
            byte_len = ((b1 & 0x7F) << 8) | data[pos] if b1 & 0x80 else b1
            if b1 & 0x80: pos += 1
            s = data[pos:pos+byte_len].decode('utf-8', errors='replace')
            strings.append(s)
    else:
        strings = [None] * str_count   # UTF-16: skip Step 17D encryption

    # ── Step 17D — encrypt selected strings ──────────────────────────────────
    # We build a new string pool where eligible strings are replaced by
    # their AES-GCM encrypted form encoded as a hex string.
    # The native decryption layer looks for strings starting with "ENC:" prefix.
    encrypted_count = 0

    def encode_utf8_str(s: str) -> bytes:
        enc = s.encode('utf-8')
        cl, bl = len(s), len(enc)
        hdr  = (bytes([(cl >> 8) | 0x80, cl & 0xFF]) if cl > 0x7F else bytes([cl]))
        hdr += (bytes([(bl >> 8) | 0x80, bl & 0xFF]) if bl > 0x7F else bytes([bl]))
        return hdr + enc + b'\x00'

    new_str_data = bytearray()
    new_offsets  = []

    if not is_utf8:
        # UTF-16 string pool: copy entire original string data verbatim.
        # UTF-16 null terminator is \x00\x00 (2 bytes) not \x00 (1 byte).
        # Scanning for single \x00 truncates strings at first ASCII char.
        # We cannot encrypt UTF-16 strings (Step 17D) and must preserve
        # their exact byte layout. Rebuild offsets pointing into original data,
        # then copy the entire string data block unchanged.
        orig_str_data = bytes(data[str_data_base : SP + sp_chunk_size])
        new_str_data.extend(orig_str_data)
        new_offsets = list(offsets)  # original offsets are still correct
    else:
      for i, s in enumerate(strings):
        new_offsets.append(len(new_str_data))
        if s is None:
            # Out-of-bounds — copy original bytes until null
            pos = str_data_base + offsets[i]
            end = pos
            while end < len(data) and data[end] != 0:
                end += 1
            new_str_data.extend(data[pos:end+1])
            continue

        # Decide if this string is eligible for encryption
        should_encrypt = (
            not skip_17d
            and is_utf8
            and len(s) >= 4
            and not any(s.startswith(p) for p in PROTECTED_STRINGS)
            and not s.startswith('ENC:')
            and random.random() < 0.3
        )
        if should_encrypt and aes_key:
            ct_bytes  = aes_gcm_encrypt(aes_key, s.encode('utf-8'))
            enc_str   = 'ENC:' + ct_bytes.hex()
            new_str_data.extend(encode_utf8_str(enc_str))
            encrypted_count += 1
        else:
            new_str_data.extend(encode_utf8_str(s))

    if skip_17d:
        print(f"[manifest_zip_patcher] Step 17D — SKIPPED (companion mode, needs Phase 4 native decryptor)")
    else:
        print(f"[manifest_zip_patcher] Step 17D — encrypted {encrypted_count}/{str_count} strings")

    # ── Rebuild string pool (NO fake blocks inside — keeps str_count correct) ──
    style_data = b''
    if style_count > 0 and styles_start > 0:
        style_abs  = SP + styles_start
        style_data = bytes(data[style_abs : SP + sp_chunk_size])

    new_offsets_bytes = b''.join(struct.pack('<I', o) for o in new_offsets)

    # SP segment contains ONLY: header + offsets + real strings + styles
    # 4-byte align the string data so SP segment size is aligned
    str_data_bytes = bytes(new_str_data)
    str_pad = (4 - (sp_hdr_size + len(new_offsets_bytes) + len(str_data_bytes) + len(style_data)) % 4) % 4
    str_data_bytes += b'\x00' * str_pad

    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_styles_start  = (new_strings_start + len(str_data_bytes)) if style_count > 0 else 0
    new_sp_chunk_size = sp_hdr_size + len(new_offsets_bytes) + len(str_data_bytes) + len(style_data)

    assert new_sp_chunk_size % 4 == 0, f"SP chunk not aligned: {new_sp_chunk_size}"

    new_sp_hdr = bytearray(sp_hdr_size)
    struct.pack_into('<H', new_sp_hdr,  0, STRING_POOL_TYPE)
    struct.pack_into('<H', new_sp_hdr,  2, sp_hdr_size)
    struct.pack_into('<I', new_sp_hdr,  4, new_sp_chunk_size)
    struct.pack_into('<I', new_sp_hdr,  8, str_count)
    struct.pack_into('<I', new_sp_hdr, 12, style_count)
    struct.pack_into('<I', new_sp_hdr, 16, flags)
    struct.pack_into('<I', new_sp_hdr, 20, new_strings_start)
    struct.pack_into('<I', new_sp_hdr, 24, new_styles_start)

    new_sp = bytes(new_sp_hdr) + new_offsets_bytes + str_data_bytes + style_data

    # rest = XML tree segments that follow the string pool in original manifest
    rest_off = SP + sp_chunk_size
    rest     = bytes(data[rest_off:])

    # ── Step 17E — inject fake encrypted blocks BETWEEN string pool and XML tree
    # Placed OUTSIDE the string pool segment so str_count is never exceeded.
    # apksigner reads SP segment up to sp_chunk_size then moves to next segment.
    # Fake blocks sit between SP end and XML tree — parsers that expect only
    # SP+XML tree will get confused; Android installer skips unknown segments.
    fake_blocks = bytearray()
    n_fakes = random.randint(3, 8)
    for _ in range(n_fakes):
        fake_blocks.extend(fake_gcm_block())
    # 4-byte align fake blocks region
    align_pad = (4 - len(fake_blocks) % 4) % 4
    fake_blocks += b'\x00' * align_pad
    print(f"[manifest_zip_patcher] Step 17E — injected {n_fakes} fake encrypted blocks "
          f"({len(fake_blocks)} bytes)")

    new_total = 8 + len(new_sp) + len(fake_blocks) + len(rest)
    result    = bytearray(data[:8])
    struct.pack_into('<I', result, 4, new_total)
    result.extend(new_sp)
    result.extend(fake_blocks)
    result.extend(rest)

    # ── Step 17F — append random binary padding ───────────────────────────────
    # Padding length must make total file size 4-byte aligned.
    # Android AXML parser (and apksigner) require outer file segment size % 4 == 0.
    pad_len = random.randint(PAD_MIN, PAD_MAX)
    # Adjust pad_len to ensure final size is 4-byte aligned
    current_len  = len(result)
    raw_total    = current_len + pad_len
    align_extra  = (4 - raw_total % 4) % 4
    pad_len     += align_extra
    result.extend(secrets.token_bytes(pad_len))
    print(f"[manifest_zip_patcher] Step 17F — appended {pad_len} bytes manifest padding")

    # Update AXML file segment size to reflect 17F padding
    final_size = len(result)
    assert final_size % 4 == 0, f"AXML not 4-byte aligned: {final_size}"
    struct.pack_into('<I', result, 4, final_size)

    # ── Step 27 compat: Replace LauncherApplication → AppEntry in rebuilt AXML ─
    # asset_patcher.py patches raw APK bytes to change android:name from
    # LauncherApplication to AppEntry (the actual class in the DEX).
    # from scratch, overwriting that patch.
    #
    # FIX: Direct UTF-16LE byte search-and-replace in the rebuilt result bytes.
    # The AXML string pool uses PACKED strings — LauncherApplication is embedded
    # inside a longer entry that does NOT end with it. endswith() fails silently.
    # Direct byte replacement works regardless of string packing.
    #
    # LauncherApplication = 19 UTF-16LE chars = 38 bytes
    # AppEntry            =  8 UTF-16LE chars = 16 bytes
    # Replace with AppEntry + 22 null bytes — AppEntry is the actual DEX class name
    _launcher_utf16 = 'LauncherApplication'.encode('utf-16-le')
    _appentry_utf16 = 'AppEntry'.encode('utf-16-le')
    _pad_bytes      = len(_launcher_utf16) - len(_appentry_utf16)  # 22
    _result_bytes   = bytes(result)
    if _launcher_utf16 in _result_bytes:
        _pos = _result_bytes.find(_launcher_utf16)
        result[_pos:_pos + len(_launcher_utf16)] = _appentry_utf16 + b'\x00' * _pad_bytes
        print(f"[manifest_zip_patcher] Step 27 compat — "
              f"LauncherApplication \u2192 AppEntry at offset {_pos}")
    else:
        print(f"[manifest_zip_patcher] Step 27 compat — "
              f"LauncherApplication not found (already patched or stub not active)")

    return bytes(result)


# ── APK patcher ───────────────────────────────────────────────────────────────

def patch_apk(apk_in: str, apk_out: str, aes_key_hex: str, skip_17d: bool = False):
    aes_key = bytes.fromhex(aes_key_hex) if aes_key_hex else None
    SUPPORTED_COMPRESS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

    # Read raw APK bytes — needed to copy non-standard compress entries verbatim
    with open(apk_in, 'rb') as f:
        raw_apk = f.read()

    # Build output APK manually for full control over compression types
    # Local file entries
    out_entries  = []  # list of (ZipInfo, data_bytes, is_raw)
    with zipfile.ZipFile(apk_in, 'r') as zin:
        for item in zin.infolist():
            if item.compress_type not in SUPPORTED_COMPRESS:
                # Non-standard (e.g. type 2032) — copy raw compressed bytes
                fname_len = struct.unpack_from('<H', raw_apk, item.header_offset + 26)[0]
                extra_len = struct.unpack_from('<H', raw_apk, item.header_offset + 28)[0]
                data_off  = item.header_offset + 30 + fname_len + extra_len
                raw_data  = raw_apk[data_off : data_off + item.compress_size]
                out_entries.append((item, raw_data, True))
                continue
            data = zin.read(item.filename)
            if item.filename == 'AndroidManifest.xml':
                print(f"[manifest_zip_patcher] Patching AndroidManifest.xml ({len(data)} bytes)...")
                data = patch_axml(data, aes_key, skip_17d=skip_17d)
                # Step 7: Set deflate(8) to match IRT.apk — stored(0) is a GPP signal
                # IRT uses deflate(8) for AndroidManifest.xml — all legitimate APKs do too
                # Android AXML parser reads decompressed bytes — compression type is irrelevant
                item.compress_type = zipfile.ZIP_DEFLATED
                print(f"[manifest_zip_patcher] Patched manifest: {len(data)} bytes (deflate)")
            out_entries.append((item, data, False))

    # Write output ZIP manually
    tmp = apk_out + '.mzp_tmp'
    with open(tmp, 'wb') as out:
        cd_entries = []  # central directory entries
        for item, data, is_raw in out_entries:
            fname   = item.filename.encode('utf-8')
            offset  = out.tell()
            ctype   = item.compress_type
            dt      = item.date_time
            dosdate = ((dt[0]-1980)<<9)|(dt[1]<<5)|dt[2]
            dostime = (dt[3]<<11)|(dt[4]<<5)|(dt[5]//2)

            if is_raw:
                # Non-standard compression — use original metadata verbatim
                crc = item.CRC
                csz = item.compress_size
                usz = item.file_size
                out_data = data
            elif ctype == zipfile.ZIP_DEFLATED:
                # Compress with raw deflate (strip 2-byte zlib header + 4-byte adler32)
                import zlib
                out_data = zlib.compress(data, 6)[2:-4]
                crc = zipfile.crc32(data) & 0xFFFFFFFF
                csz = len(out_data)
                usz = len(data)
            else:
                # STORED — write uncompressed
                out_data = data
                crc = zipfile.crc32(data) & 0xFFFFFFFF
                csz = len(data)
                usz = len(data)

            # Local file header (30 bytes)
            lfh = struct.pack('<4sHHHHHIIIHH',
                b'PK\x03\x04', item.extract_version, item.flag_bits,
                ctype, dostime, dosdate, crc, csz, usz,
                len(fname), 0)
            out.write(lfh + fname)
            out.write(out_data)
            cd_entries.append((fname, offset, ctype, dostime, dosdate, crc, csz, usz,
                               item.create_system, item.extract_version,
                               item.flag_bits, item.internal_attr, item.external_attr))

        # Central directory
        cd_start = out.tell()
        for (fname, offset, ctype, dostime, dosdate, crc, csz, usz,
             cs, ev, flags, ia, ea) in cd_entries:
            cdh = struct.pack('<4sHHHHHHIIIHHHHHII',
                b'PK\x01\x02', (cs<<8)|20, ev, flags,
                ctype, dostime, dosdate, crc, csz, usz,
                len(fname), 0, 0, 0, ia, ea, offset)
            out.write(cdh + fname)
        cd_end = out.tell()
        cd_size = cd_end - cd_start

        # End of central directory
        eocd = struct.pack('<4sHHHHIIH',
            b'PK\x05\x06', 0, 0,
            len(cd_entries), len(cd_entries),
            cd_size, cd_start, 0)
        out.write(eocd)

    os.replace(tmp, apk_out)
    print(f"[manifest_zip_patcher] \u2705 Done: {apk_out}")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('apk_in')
    parser.add_argument('apk_out')
    parser.add_argument('aes_key_hex', nargs='?', default='')
    parser.add_argument('--skip-17d', action='store_true',
                        help='Skip string encryption (17D) — needs Phase 4 native layer')
    args = parser.parse_args()
    patch_apk(args.apk_in, args.apk_out, args.aes_key_hex, skip_17d=args.skip_17d)
