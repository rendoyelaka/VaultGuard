#!/usr/bin/env python3
"""
strip_fingerprint_files.py — Steps 5 + 7

Step 5: Strips GPP fingerprint files from signed APK.
Step 7: Recompresses manifest + .bin assets to deflate(8) to match IRT.apk.
        Injects META-INF/services/r8 fake R8 compiler marker (IRT technique).

CRITICAL: Preserves ghost entries (flag 0x0801) by reading raw LFH bytes.
Ghost entries cannot be read by zipfile.ZipFile — this script reads them
directly from raw bytes and writes them verbatim into the output ZIP.

Usage:
  python3 scripts/strip_fingerprint_files.py <apk_in> <apk_out>

Must re-sign after:
  python3 scripts/phase2_resign.py <apk_out>
"""

import sys
import os
import struct
import zlib
import zipfile

# ── Entries to strip — exact match ───────────────────────────────────────────
STRIP_EXACT = {
    'assets/dexopt/baseline.prof',
    'assets/dexopt/baseline.profm',
    'META-INF/com/android/build/gradle/app-metadata.properties',
    'kotlin-tooling-metadata.json',
}

# ── Prefix patterns to strip ─────────────────────────────────────────────────
STRIP_PREFIXES = (
    'META-INF/services/kotlinx.',
    'META-INF/androidx.',
    'META-INF/kotlinx_',
    'META-INF/com/android/build/',
)

# ── Suffix patterns to strip ─────────────────────────────────────────────────
STRIP_SUFFIXES = (
    '.kotlin_builtins',
    'baseline.prof',
    'baseline.profm',
)

# ── Entries to force deflate(8) — Step 7 — match IRT.apk ────────────────────
FORCE_DEFLATE_EXACT = {
    'AndroidManifest.xml',
}

# ── Entries that must stay stored(0) — Android requirement ───────────────────
FORCE_STORED = {
    'resources.arsc',
}


def should_strip(name: str) -> bool:
    if name in STRIP_EXACT:
        return True
    for p in STRIP_PREFIXES:
        if name.startswith(p):
            return True
    for s in STRIP_SUFFIXES:
        if name.endswith(s):
            return True
    return False


def should_force_deflate(name: str) -> bool:
    if name in FORCE_DEFLATE_EXACT:
        return True
    # All .bin assets under assets/ → deflate(8) to match IRT
    if name.startswith('assets/') and name.endswith('.bin'):
        return True
    return False


def read_raw_entries(apk_path: str) -> list:
    """
    Parse ALL local file headers from raw APK bytes.
    Returns list of dicts with all LFH fields including ghost entries (flag 0x0801).
    """
    entries = []
    with open(apk_path, 'rb') as f:
        raw = f.read()

    pos = 0
    while pos < len(raw) - 4:
        sig = struct.unpack_from('<I', raw, pos)[0]
        if sig == 0x04034b50:
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
            fname_bytes = raw[pos+30:pos+30+fname_len]
            data_off    = pos + 30 + fname_len + extra_len
            comp_data   = raw[data_off:data_off+comp_size]
            try:
                fname_str = fname_bytes.decode('utf-8', 'replace')
            except Exception:
                fname_str = fname_bytes.decode('latin-1', 'replace')

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
                'is_ghost':    bool(flags & 0x0001),
                'lhf_pos':     pos,
            })
            pos = data_off + comp_size
        elif sig == 0x02014b50:
            break
        else:
            pos += 1

    return entries


def inject_r8_decoy(raw_entries: list) -> list:
    """
    Step 7: Add META-INF/services/r8 fake R8 compiler marker entry.
    Matches IRT.apk exactly: 72B content, flag=0x0801, compress=8.
    """
    R8_NAME    = 'META-INF/services/r8'
    R8_CONTENT = b'<manifest>ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWX</resources>'
    R8_FLAG    = 0x0801
    R8_COMPRESS = 8
    # Fixed timestamp matching IRT ghost entries: 2026-08-23 06:31:48
    R8_TIME = (6 << 11) | (31 << 5) | (48 // 2)
    R8_DATE = ((2026-1980) << 9) | (8 << 5) | 23

    # Check if already present
    if any(e['name'] == R8_NAME for e in raw_entries):
        print(f"[strip_fingerprint_files] META-INF/services/r8 already present")
        return raw_entries

    r8_comp = zlib.compress(R8_CONTENT, 6)[2:-4]
    r8_crc  = zlib.crc32(R8_CONTENT) & 0xFFFFFFFF

    new_entry = {
        'name':        R8_NAME,
        'fname_bytes': R8_NAME.encode('utf-8'),
        'version':     0x0014,
        'flags':       R8_FLAG,
        'compress':    R8_COMPRESS,
        'mod_time':    R8_TIME,
        'mod_date':    R8_DATE,
        'crc32':       r8_crc,
        'comp_size':   len(r8_comp),
        'uncomp_size': len(R8_CONTENT),
        'comp_data':   r8_comp,
        'is_ghost':    True,  # flag 0x0801 has ENCRYPTED bit set
        'lhf_pos':     -1,
    }

    print(f"[strip_fingerprint_files] Injecting META-INF/services/r8 (72B, flag=0x0801)")
    return raw_entries + [new_entry]


def strip_apk(apk_in: str, apk_out: str) -> None:
    """
    Main function: strip fingerprint files, recompress, inject r8 decoy,
    and PRESERVE all ghost entries (flag 0x0801) by raw byte copy.
    """
    stripped     = []
    kept_real    = 0
    kept_ghost   = 0
    recompressed = []

    # Parse ALL entries including ghosts from raw bytes
    raw_entries = read_raw_entries(apk_in)
    print(f"[strip_fingerprint_files] Read {len(raw_entries)} entries from raw bytes")

    # Inject r8 decoy
    raw_entries = inject_r8_decoy(raw_entries)

    tmp = apk_out + '.strip_tmp'

    with open(tmp, 'wb') as fout:
        local_offsets = {}

        for entry in raw_entries:
            name      = entry['name']
            fname_b   = entry['fname_bytes']
            flags     = entry['flags']
            compress  = entry['compress']
            mod_time  = entry['mod_time']
            mod_date  = entry['mod_date']
            crc32     = entry['crc32']
            comp_size = entry['comp_size']
            uncomp    = entry['uncomp_size']
            comp_data = entry['comp_data']
            version   = entry['version']
            is_ghost  = entry['is_ghost']

            # Strip check
            if should_strip(name):
                stripped.append(name)
                continue

            local_offsets[name] = fout.tell()

            if is_ghost:
                # Write ghost verbatim — preserves flag 0x0801 exactly
                lfh = struct.pack('<4sHHHHHIIIHH',
                    b'PK\x03\x04', version, flags, compress,
                    mod_time, mod_date, crc32, comp_size, uncomp,
                    len(fname_b), 0)
                fout.write(lfh + fname_b + comp_data)
                kept_ghost += 1

            elif should_force_deflate(name) and compress != 8:
                # Decompress from stored, recompress as deflate(8)
                try:
                    raw_data = comp_data  # stored = raw
                    new_comp = zlib.compress(raw_data, 6)[2:-4]
                    new_crc  = zlib.crc32(raw_data) & 0xFFFFFFFF
                    clean_flags = flags & ~0x0008
                    lfh = struct.pack('<4sHHHHHIIIHH',
                        b'PK\x03\x04', version, clean_flags, 8,
                        mod_time, mod_date, new_crc,
                        len(new_comp), len(raw_data), len(fname_b), 0)
                    fout.write(lfh + fname_b + new_comp)
                    # Update entry for CD
                    entry['compress']   = 8
                    entry['crc32']      = new_crc
                    entry['comp_size']  = len(new_comp)
                    entry['flags']      = clean_flags
                    recompressed.append(f"{name} stored→deflate({len(raw_data)}→{len(new_comp)}B)")
                    kept_real += 1
                except Exception as e:
                    # Fallback verbatim
                    lfh = struct.pack('<4sHHHHHIIIHH',
                        b'PK\x03\x04', version, flags, compress,
                        mod_time, mod_date, crc32, comp_size, uncomp, len(fname_b), 0)
                    fout.write(lfh + fname_b + comp_data)
                    kept_real += 1

            elif name in FORCE_STORED and compress != 0:
                # Must stay stored
                try:
                    raw_data = zlib.decompress(comp_data, -15) if compress==8 else comp_data
                    new_crc  = zlib.crc32(raw_data) & 0xFFFFFFFF
                    lfh = struct.pack('<4sHHHHHIIIHH',
                        b'PK\x03\x04', version, flags & ~0x0008, 0,
                        mod_time, mod_date, new_crc,
                        len(raw_data), len(raw_data), len(fname_b), 0)
                    fout.write(lfh + fname_b + raw_data)
                    kept_real += 1
                except Exception:
                    lfh = struct.pack('<4sHHHHHIIIHH',
                        b'PK\x03\x04', version, flags, compress,
                        mod_time, mod_date, crc32, comp_size, uncomp, len(fname_b), 0)
                    fout.write(lfh + fname_b + comp_data)
                    kept_real += 1

            else:
                # Write verbatim
                lfh = struct.pack('<4sHHHHHIIIHH',
                    b'PK\x03\x04', version, flags, compress,
                    mod_time, mod_date, crc32, comp_size, uncomp, len(fname_b), 0)
                fout.write(lfh + fname_b + comp_data)
                kept_real += 1

        # Write Central Directory
        cd_start = fout.tell()
        cd_count = 0

        for entry in raw_entries:
            name = entry['name']
            if name in stripped or name not in local_offsets:
                continue

            fname_b  = entry['fname_bytes']
            ext_attr = 0

            cde = struct.pack('<4sHHHHHHIIIHHHHHII',
                b'PK\x01\x02',
                0x0314,            # version made by
                entry['version'],  # version needed
                entry['flags'],
                entry['compress'],
                entry['mod_time'],
                entry['mod_date'],
                entry['crc32'],
                entry['comp_size'],
                entry['uncomp_size'],
                len(fname_b),
                0, 0,              # extra, comment
                0, 0,              # disk start, internal attrs
                ext_attr,
                local_offsets[name],
            ) + fname_b
            fout.write(cde)
            cd_count += 1

        cd_end  = fout.tell()
        cd_size = cd_end - cd_start

        # EOCD
        eocd = struct.pack('<4sHHHHIIH',
            b'PK\x05\x06',
            0, 0,
            cd_count, cd_count,
            cd_size, cd_start,
            0)
        fout.write(eocd)

    os.replace(tmp, apk_out)

    total = kept_real + kept_ghost
    print(f"[strip_fingerprint_files] Done: stripped={len(stripped)} real={kept_real} ghost={kept_ghost} total={total}")
    for s in stripped:
        print(f"  Stripped: {s}")
    if recompressed:
        print(f"  Recompressed {len(recompressed)} entries to deflate(8):")
        for r in recompressed:
            print(f"    {r}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <apk_in> <apk_out>")
        sys.exit(1)
    apk_in, apk_out = sys.argv[1], sys.argv[2]
    if not os.path.isfile(apk_in):
        print(f"[ERROR] APK not found: {apk_in}")
        sys.exit(1)
    strip_apk(apk_in, apk_out)
