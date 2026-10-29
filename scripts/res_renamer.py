#!/usr/bin/env python3
"""
res_renamer.py — Step 17H

Step 17H — Inject fake/decoy string resources into res/values/strings.xml
    inside the APK. Fake entries use random names and values different per
    build. Increases noise so real strings are harder to identify in static
    analysis. Applied after signing (post-build).

Usage:
    python3 scripts/res_renamer.py <apk_in> <apk_out> [--count N]

    --count N : number of fake string entries to inject (default: 30)

Re-sign after running:
    zipalign -f 4 apk_out apk_aligned.apk
    apksigner sign --ks ... apk_aligned.apk
"""

import sys
import os
import random
import secrets
import string
import zipfile
import argparse
import xml.etree.ElementTree as ET


# ── Random name/value generators ──────────────────────────────────────────────

_CHARS = string.ascii_lowercase + string.digits + '_'

def rand_name(min_len=5, max_len=14) -> str:
    """Generate a valid Android resource name (starts with letter)."""
    first = random.choice(string.ascii_lowercase)
    rest  = ''.join(random.choices(_CHARS, k=random.randint(min_len - 1, max_len - 1)))
    return first + rest

_WORD_POOL = [
    "initialize", "configure", "validate", "authenticate", "synchronize",
    "dispatch", "intercept", "propagate", "transform", "serialize",
    "deserialize", "bootstrap", "provision", "allocate", "deallocate",
    "encrypt", "decrypt", "compress", "decompress", "aggregate",
    "reconcile", "arbitrate", "orchestrate", "delegate", "enumerate",
    "navigate", "annotate", "register", "unregister", "broadcast",
    "subscribe", "publish", "consume", "produce", "terminate",
]

def rand_value() -> str:
    """Generate a plausible-looking decoy string value."""
    kind = random.randint(0, 3)
    if kind == 0:
        # Looks like a URL/endpoint
        segments = random.randint(2, 4)
        parts = [random.choice(_WORD_POOL) for _ in range(segments)]
        return 'https://api.' + '.'.join(parts[:2]) + '.com/' + '/'.join(parts[2:])
    elif kind == 1:
        # Looks like a config key
        return '_'.join(random.choices(_WORD_POOL, k=random.randint(2, 4))).upper()
    elif kind == 2:
        # Looks like a UUID token
        return secrets.token_hex(16)
    else:
        # Plain English-looking phrase
        return ' '.join(random.choices(_WORD_POOL, k=random.randint(3, 7))).capitalize() + '.'


# ── Inject into strings.xml ───────────────────────────────────────────────────

def inject_fake_strings(xml_bytes: bytes, count: int) -> bytes:
    """
    Parse strings.xml, inject `count` fake <string> entries, return new XML bytes.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        # If binary/broken XML just return unchanged
        return xml_bytes

    # Collect existing names to avoid collision
    existing = {child.get('name', '') for child in root if child.tag == 'string'}

    added = 0
    attempts = 0
    while added < count and attempts < count * 10:
        attempts += 1
        name = rand_name()
        if name in existing:
            continue
        existing.add(name)
        elem      = ET.SubElement(root, 'string')
        elem.set('name', name)
        elem.text = rand_value()
        added += 1

    # Serialize back — ET.tostring gives bytes
    ET.indent(root, space='    ')
    xml_out = b'<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding='unicode').encode('utf-8')
    return xml_out


# ── APK patcher ───────────────────────────────────────────────────────────────

STRINGS_XML_PATH = 'res/values/strings.xml'

def patch_apk(apk_in: str, apk_out: str, count: int):
    tmp = apk_out + '.rr_tmp'

    found = False
    with zipfile.ZipFile(apk_in, 'r') as zin,          zipfile.ZipFile(tmp, 'w', allowZip64=False) as zout:
        for item in zin.infolist():
            if item.filename == STRINGS_XML_PATH:
                found  = True
                data   = zin.read(item.filename)
                before = len(data)
                data   = inject_fake_strings(data, count)
                # Store strings.xml as ZIP_STORED (uncompressed).
                # Using deflate risks producing compressed data that Java's
                # apksigner inflater rejects with DataFormatException.
                # ZIP_STORED is safe — apksigner reads raw bytes directly.
                new_item = zipfile.ZipInfo(item.filename)
                new_item.compress_type = zipfile.ZIP_STORED
                new_item.date_time     = item.date_time
                new_item.flag_bits     = item.flag_bits
                zout.writestr(new_item, data)
                print(f"[res_renamer] Step 17H — strings.xml: {before} → {len(data)} bytes "
                      f"({count} fake entries injected, stored uncompressed)")
            else:
                # Copy other entries: decompress with read(), recompress with writestr().
                # CRITICAL: do NOT copy file_size, compress_size, or CRC to new_item.
                # writestr() re-deflates the data producing a new compressed size.
                # If LFH declares old compress_size but actual data has new size,
                # apksigner reads wrong number of bytes = truncated deflate = corrupt.
                # Let zipfile calculate file_size, compress_size, CRC fresh.
                raw = zin.read(item.filename)
                new_item = zipfile.ZipInfo(item.filename)
                new_item.compress_type = item.compress_type
                new_item.date_time     = item.date_time
                new_item.flag_bits     = item.flag_bits
                # file_size, compress_size, CRC intentionally NOT copied
                zout.writestr(new_item, raw)

    if not found:
        # strings.xml not present — create it as STORED
        print(f"[res_renamer] Step 17H — strings.xml not found; creating with {count} fake entries")
        xml_bytes = inject_fake_strings(b'<resources/>', count)
        with zipfile.ZipFile(apk_in, 'r') as zin,              zipfile.ZipFile(tmp, 'w', allowZip64=False) as zout:
            for item in zin.infolist():
                raw = zin.read(item.filename)
                new_item = zipfile.ZipInfo(item.filename)
                new_item.compress_type = item.compress_type
                new_item.date_time     = item.date_time
                new_item.flag_bits     = item.flag_bits
                # file_size, compress_size, CRC intentionally NOT copied
                zout.writestr(new_item, raw)
            # Add strings.xml as STORED
            si = zipfile.ZipInfo(STRINGS_XML_PATH)
            si.compress_type = zipfile.ZIP_STORED
            zout.writestr(si, xml_bytes)

    os.replace(tmp, apk_out)
    print(f"[res_renamer] ✅ Done: {apk_out}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Step 17H — inject fake string resources')
    parser.add_argument('apk_in',  help='Input APK path')
    parser.add_argument('apk_out', help='Output APK path')
    parser.add_argument('--count', type=int, default=30, help='Number of fake strings to inject (default 30)')
    args = parser.parse_args()
    patch_apk(args.apk_in, args.apk_out, args.count)
