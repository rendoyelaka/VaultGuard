#!/usr/bin/env bash
# =============================================================================
# key_wipe.sh — Step 6: Cryptographic multi-pass wipe of key material
# Usage: ./key_wipe.sh <directory>
# Wipes all .jks, .keystore, .properties files with 3-pass overwrite + delete
# =============================================================================

set -euo pipefail

TARGET_DIR="${1:-}"

if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then
    echo "[key_wipe] Usage: ./key_wipe.sh <directory>"
    exit 1
fi

WIPED=0
FAILED=0

secure_wipe() {
    local file="$1"
    local size
    size=$(wc -c < "$file")

    if [ "$size" -gt 0 ]; then
        # Pass 1 — zeros
        dd if=/dev/zero of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null
        # Pass 2 — ones (0xFF)
        tr '\000' '\377' < /dev/zero | dd of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null
        # Pass 3 — random
        dd if=/dev/urandom of="$file" bs=1 count="$size" conv=notrunc 2>/dev/null
    fi

    rm -f "$file"
    echo "[key_wipe] 🔒 Secure wiped (3-pass): $(basename "$file")"
}

for ext in jks keystore properties; do
    while IFS= read -r -d '' f; do
        if secure_wipe "$f"; then
            WIPED=$((WIPED + 1))
        else
            echo "[key_wipe] ⚠️  Failed to wipe: $f"
            rm -f "$f"
            FAILED=$((FAILED + 1))
        fi
    done < <(find "$TARGET_DIR" -maxdepth 2 -name "*.${ext}" -print0 2>/dev/null)
done

echo "[key_wipe] ✅ Wiped: ${WIPED} | Failed: ${FAILED}"
exit 0
