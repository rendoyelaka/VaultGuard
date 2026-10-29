#!/usr/bin/env python3
"""
signing_block_patcher.py — IRT Technique #1
Injects custom non-standard APK signing block ID 0x00000603.

Correct APK Signing Block structure (Android source verified):
  [size_field1: 8 bytes]   ← value = len(pairs) + 8
  [pairs...]               ← ID-value pairs (V2, V3, etc)
  [size_field2: 8 bytes]   ← same value as size_field1
  [magic: 16 bytes]        ← "APK Sig Block 42"
  [Central Directory]

Strategy:
  1. Find magic, read size_field2 (8 bytes before magic)
  2. Locate pairs region: pairs_end = size_field2_off, pairs_len = size_value - 8
  3. Append custom pair AFTER existing pairs (preserves all existing pairs exactly)
  4. Update both size fields
  5. Update EOCD CD offset
"""

import sys, os, struct, secrets

MAGIC     = b'APK Sig Block 42'
CUSTOM_ID = 0x00000603

def patch(apk_path: str) -> None:
    with open(apk_path, 'rb') as f:
        raw = bytearray(f.read())

    # ── 1. Find magic ─────────────────────────────────────────────────────────
    magic_off = bytes(raw).rfind(MAGIC)
    if magic_off < 0:
        raise RuntimeError("APK Sig Block magic not found")

    # ── 2. Read size_field2 (8 bytes immediately before magic) ───────────────
    sf2_off    = magic_off - 8
    size_value = struct.unpack_from('<Q', raw, sf2_off)[0]
    # size_value = len(pairs) + 8  (includes sf2 itself, excludes sf1 and magic)

    # ── 3. Locate pairs region ────────────────────────────────────────────────
    pairs_end   = sf2_off                    # pairs end just before sf2
    pairs_len   = size_value - 8            # subtract sf2 itself
    pairs_start = pairs_end - pairs_len      # pairs start
    sf1_off     = pairs_start - 8            # sf1 is 8 bytes before pairs

    pairs = bytes(raw[pairs_start:pairs_end])

    print(f"[sbp] APK size:      {len(raw):,}")
    print(f"[sbp] Magic at:      {magic_off}")
    print(f"[sbp] size_value:    {size_value}")
    print(f"[sbp] pairs region:  {pairs_start}..{pairs_end} ({pairs_len} bytes)")

    # ── 4. Scan for V2 block and check custom already present ─────────────────
    # Use raw search (don't try to parse — pipeline may have injected malformed entries)
    v2_id_bytes     = struct.pack('<I', 0x7109871a)
    custom_id_bytes = struct.pack('<I', CUSTOM_ID)

    if v2_id_bytes not in pairs:
        raise RuntimeError("V2 signing block (0x7109871a) not found — APK not V2 signed")

    if custom_id_bytes in pairs:
        print(f"[sbp] Custom block 0x{CUSTOM_ID:08x} already present — skip")
        return

    # ── 5. Build custom pair ──────────────────────────────────────────────────
    custom_value   = secrets.token_bytes(16)
    pair_len_val   = 4 + len(custom_value)          # ID(4) + value
    custom_pair    = (struct.pack('<Q', pair_len_val)
                      + struct.pack('<I', CUSTOM_ID)
                      + custom_value)                # total: 8+4+16 = 28 bytes

    print(f"[sbp] Injecting 0x{CUSTOM_ID:08x} ({len(custom_pair)} bytes)")

    # ── 6. New size value ─────────────────────────────────────────────────────
    new_size_value  = size_value + len(custom_pair)
    new_sf          = struct.pack('<Q', new_size_value)

    # ── 7. Reconstruct APK ────────────────────────────────────────────────────
    # [before sf1][new sf1][old pairs][custom pair][new sf2][magic][CD+EOCD]
    cd_start_old   = magic_off + 16
    cd_and_after   = bytes(raw[cd_start_old:])

    new_apk = bytearray(
        bytes(raw[:sf1_off])  # everything before signing block
        + new_sf               # sf1 (updated)
        + pairs                # original pairs (untouched)
        + custom_pair          # new custom pair appended
        + new_sf               # sf2 (updated)
        + MAGIC                # magic (unchanged)
        + cd_and_after         # CD + EOCD
    )

    # ── 8. Update EOCD CD offset ──────────────────────────────────────────────
    shift       = len(custom_pair)
    eocd_off    = bytes(new_apk).rfind(b'PK\x05\x06')
    old_cd_off  = struct.unpack_from('<I', new_apk, eocd_off + 16)[0]
    new_cd_off  = old_cd_off + shift
    struct.pack_into('<I', new_apk, eocd_off + 16, new_cd_off)
    print(f"[sbp] CD offset:     {old_cd_off} → {new_cd_off}")

    # ── 9. Verify ─────────────────────────────────────────────────────────────
    new_magic_off  = bytes(new_apk).rfind(MAGIC)
    new_sf2_off    = new_magic_off - 8
    new_sv         = struct.unpack_from('<Q', new_apk, new_sf2_off)[0]
    new_pairs_data = bytes(new_apk[new_sf2_off - (new_sv - 8): new_sf2_off])

    assert v2_id_bytes in new_pairs_data,     "❌ V2 block missing after patch"
    assert custom_id_bytes in new_pairs_data, "❌ Custom block missing after patch"

    new_cd_bytes = bytes(new_apk[new_cd_off:new_cd_off + 4])
    assert new_cd_bytes == b'PK\x01\x02', \
        f"❌ CD not at {new_cd_off}: {new_cd_bytes.hex()}"

    with open(apk_path, 'wb') as f:
        f.write(new_apk)

    print(f"[sbp] ✅ V2 block preserved")
    print(f"[sbp] ✅ Custom 0x{CUSTOM_ID:08x} injected")
    print(f"[sbp] ✅ New APK size: {len(new_apk):,}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <apk_path>"); sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        print(f"❌ Not found: {sys.argv[1]}"); sys.exit(1)
    try:
        patch(sys.argv[1])
    except Exception as e:
        print(f"[sbp] ❌ {e}"); sys.exit(1)
