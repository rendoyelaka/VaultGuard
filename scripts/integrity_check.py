#!/usr/bin/env python3
"""
integrity_check.py — Step 11
Verifies every APK pair in a batch output directory is unique.
- Computes MD5, SHA-1, SHA-256, SHA-512 of every APK
- Rejects any duplicates across the batch (zero tolerance)
- Prints a full integrity report
- Exits 1 if any duplicates found, 0 if all unique

Usage:
    python3 integrity_check.py <batch_output_dir>
    python3 integrity_check.py ./batch_output
"""

import sys
import os
import hashlib
from pathlib import Path
from collections import defaultdict


def hash_file(path: Path) -> dict:
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(path, 'rb') as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        'md5':    md5.hexdigest(),
        'sha1':   sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
        'sha512': sha512.hexdigest(),
        'size':   path.stat().st_size,
    }


def run(batch_dir: str):
    root = Path(batch_dir)
    if not root.exists() or not root.is_dir():
        print(f"[ERROR] Directory not found: {batch_dir}")
        sys.exit(1)

    # Collect all APKs recursively
    apks = sorted(root.rglob("*.apk"))
    if not apks:
        print(f"[ERROR] No APKs found in {batch_dir}")
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"  Batch Integrity Check — {len(apks)} APK(s) found in {batch_dir}")
    print(f"{'='*70}\n")

    records = []
    for apk in apks:
        rel = apk.relative_to(root)
        print(f"  Hashing: {rel} ...", end=' ', flush=True)
        h = hash_file(apk)
        h['path'] = str(rel)
        records.append(h)
        print(f"OK  [{h['sha256'][:16]}...]")

    # Check for duplicates across every hash algorithm
    duplicates_found = False
    for algo in ('md5', 'sha1', 'sha256', 'sha512'):
        seen = defaultdict(list)
        for r in records:
            seen[r[algo]].append(r['path'])

        dupes = {h: paths for h, paths in seen.items() if len(paths) > 1}
        if dupes:
            duplicates_found = True
            print(f"\n  ❌ DUPLICATE {algo.upper()} HASHES DETECTED:")
            for h, paths in dupes.items():
                print(f"     Hash : {h}")
                for p in paths:
                    print(f"       → {p}")

    # Full report table
    print(f"\n{'─'*70}")
    print(f"  {'APK':<35} {'MD5':>10} {'SHA256':>16} {'SIZE':>10}")
    print(f"{'─'*70}")
    for r in records:
        name = Path(r['path']).name[:34]
        print(f"  {name:<35} {r['md5'][:8]:>10} {r['sha256'][:14]:>16} {r['size']:>10,}")

    print(f"\n{'='*70}")
    if duplicates_found:
        print(f"  ❌ RESULT: DUPLICATES FOUND — batch is NOT valid for delivery")
        print(f"{'='*70}\n")
        sys.exit(1)
    else:
        print(f"  ✅ RESULT: All {len(apks)} APK(s) are unique — batch is valid")
        print(f"{'='*70}\n")
        sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 integrity_check.py <batch_output_dir>")
        sys.exit(1)
    run(sys.argv[1])
