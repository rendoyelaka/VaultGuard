#!/usr/bin/env python3
"""
Pre-build static checks — runs BEFORE Gradle build.
Fails immediately with exact file + line if anything is wrong.
"""
import sys, os, re

ERRORS = []

def fail(msg):
    ERRORS.append(msg)
    print(f"::error::{msg}")

def check_file(path, label):
    if not os.path.exists(path):
        fail(f"{label}: FILE NOT FOUND: {path}")
        return None
    return open(path).read()

BASE = "app/src/main/java"

# ── Find actual package dir (renamed by CI) ──────────────────────────────────
kt_files = []
for root, dirs, files in os.walk(BASE):
    for f in files:
        if f.endswith('.kt'):
            kt_files.append(os.path.join(root, f))

def find_kt(name):
    matches = [f for f in kt_files if os.path.basename(f) == name]
    return matches[0] if matches else None

install_activity  = find_kt('InstallActivity.kt')
install_receiver  = find_kt('InstallReceiver.kt')
launcher_app      = find_kt('LauncherApplication.kt')
launcher_service  = find_kt('LauncherService.kt')
mutation_engine   = find_kt('MutationEngine.kt')
manifest          = 'app/src/main/AndroidManifest.xml'
build_gradle      = 'app/build.gradle'

print("=" * 60)
print("PRE-BUILD STATIC CHECKS")
print("=" * 60)

# ── CHECK 1: USER_ACTION_NOT_REQUIRED must NOT be set as code ────────────────
print("\n[1] USER_ACTION_NOT_REQUIRED must not be called...")
if install_activity:
    ia = open(install_activity).read()
    lines = ia.split('\n')
    for i, line in enumerate(lines, 1):
        if 'USER_ACTION_NOT_REQUIRED' in line and not line.strip().startswith('//'):
            fail(f"InstallActivity.kt line {i}: USER_ACTION_NOT_REQUIRED is set — "
                 f"causes STATUS_FAILURE_BLOCKED glitch loop. Remove it.")
    print("  ✅ USER_ACTION_NOT_REQUIRED not set as code")
else:
    fail("InstallActivity.kt not found")

# ── CHECK 2: SESSION_ACTION in manifest must use applicationId placeholder ────
print("\n[2] SESSION_ACTION must use ${applicationId}...")
if os.path.exists(manifest):
    mf = open(manifest).read()
    # Find SESSION_ACTION line
    for i, line in enumerate(mf.split('\n'), 1):
        if 'SESSION_ACTION' in line:
            if '${applicationId}' not in line and 'applicationId' not in line:
                # Check it's not hardcoded to a specific package
                hardcoded = re.search(r'com\.[a-z]+\.[a-z]+\.SESSION_ACTION', line)
                if hardcoded:
                    fail(f"AndroidManifest.xml line {i}: SESSION_ACTION hardcoded to "
                         f"'{hardcoded.group()}' — must use ${{applicationId}}.SESSION_ACTION. "
                         f"When CI renames package, receiver never gets the broadcast → no dialog.")
            else:
                print(f"  ✅ SESSION_ACTION uses applicationId placeholder")
            break
    else:
        fail("AndroidManifest.xml: SESSION_ACTION not found in manifest at all")
else:
    fail("AndroidManifest.xml not found")

# ── CHECK 3: LauncherService must have NO coroutines ─────────────────────────
print("\n[3] LauncherService must have no coroutines...")
if launcher_service:
    ls = open(launcher_service).read()
    lines = ls.split('\n')
    coro_keywords = ['CoroutineScope', 'SupervisorJob', 'runBlocking',
                     'withContext', 'withTimeout', 'launch {', 'kotlinx.coroutines']
    for i, line in enumerate(lines, 1):
        for kw in coro_keywords:
            if kw in line and not line.strip().startswith('//'):
                fail(f"LauncherService.kt line {i}: '{kw}' found — "
                     f"coroutines in Service cause 'DefaultExecutor was shut down' crash. "
                     f"LauncherApplication handles mutation via plain Thread.")
    print("  ✅ LauncherService has no coroutines")
else:
    fail("LauncherService.kt not found")

# ── CHECK 4: LauncherApplication must start processing on plain Thread ──────────
print("\n[4] LauncherApplication must use plain Thread for mutation...")
if launcher_app:
    la = open(launcher_app).read()
    lines = la.split('\n')
    # Must have Thread { and MutationEngine
    has_thread = any('Thread {' in l or 'Thread(' in l for l in lines)
    has_engine = any('MutationEngine' in l for l in lines)
    has_scope  = any('CoroutineScope' in l and not l.strip().startswith('//')
                     for l in lines)
    if not has_thread:
        fail("LauncherApplication.kt: No plain Thread found — "
             "mutation must run on Thread { isDaemon=true }")
    if not has_engine:
        fail("LauncherApplication.kt: MutationEngine not called — "
             "mc.tmp will never be written → getCompanionBytes() always falls back")
    if has_scope:
        for i, l in enumerate(lines, 1):
            if 'CoroutineScope' in l and not l.strip().startswith('//'):
                fail(f"LauncherApplication.kt line {i}: CoroutineScope found — "
                     f"causes NoClassDefFoundError/DefaultExecutor crash at app launch")
    if has_thread and has_engine and not has_scope:
        print("  ✅ LauncherApplication uses plain Thread + MutationEngine")
else:
    fail("LauncherApplication.kt not found")

# ── CHECK 5: MutationEngine must have no suspend/runBlocking/coroutines ───────
print("\n[5] MutationEngine must have no coroutine calls...")
if mutation_engine:
    me = open(mutation_engine).read()
    lines = me.split('\n')
    bad = ['runBlocking', 'withContext', 'withTimeout', 'suspend fun getMutated',
           'CoroutineScope', 'kotlinx.coroutines.run']
    for i, line in enumerate(lines, 1):
        for kw in bad:
            if kw in line and not line.strip().startswith('//'):
                fail(f"MutationEngine.kt line {i}: '{kw}' found — "
                     f"causes DefaultExecutor crash when called from daemon Thread")
    print("  ✅ MutationEngine has no coroutine calls")
else:
    fail("MutationEngine.kt not found")

# ── CHECK 6: getCompanionBytes must be in InstallActivity ────────────────────
print("\n[6] InstallActivity must have getCompanionBytes()...")
if install_activity:
    ia = open(install_activity).read()
    if 'getCompanionBytes' not in ia:
        fail("InstallActivity.kt: getCompanionBytes() method missing — "
             "startDownload() cannot read mc.tmp → always falls back to assets directly")
    else:
        print("  ✅ getCompanionBytes() present in InstallActivity")

# ── CHECK 7: InstallActivity must poll mc.tmp ─────────────────────────────────
print("\n[7] InstallActivity must poll mc.tmp for mutated APK...")
if install_activity:
    ia = open(install_activity).read()
    has_mctmp = 'mc.tmp' in ia or 'MUTATED_APK_NAME' in ia or 'getMutatedApkFile' in ia
    if not has_mctmp:
        fail("InstallActivity.kt: mc.tmp polling not found — "
             "MutationEngine output never read → always installs base companion")
    else:
        print("  ✅ mc.tmp polling present in InstallActivity")

# ── CHECK 8: module.apk must exist in assets ───────────────────────────────
print("\n[8] assets/companion.apk must exist...")
comp_path = 'app/src/main/assets/companion.apk'
if not os.path.exists(comp_path):
    fail(f"assets/companion.apk NOT FOUND — Tier 3 fallback will fail → empty APK → crash")
else:
    import zipfile
    try:
        with zipfile.ZipFile(comp_path) as z:
            has_dex = 'classes.dex' in z.namelist()
            has_mf  = 'AndroidManifest.xml' in z.namelist()
        if not (has_dex and has_mf):
            fail(f"assets/companion.apk is not a valid APK (missing dex or manifest)")
        else:
            size = os.path.getsize(comp_path) / 1024 / 1024
            print(f"  ✅ companion.apk valid ({size:.2f}MB)")
    except Exception as e:
        fail(f"assets/companion.apk is corrupt: {e}")

# ── CHECK 9: InstallReceiver must call startActivity for PENDING_USER_ACTION ──
print("\n[9] InstallReceiver must handle STATUS_PENDING_USER_ACTION...")
if install_receiver:
    ir = open(install_receiver).read()
    has_pending = ('STATUS_PENDING_USER_ACTION' in ir or
                   'PENDING_USER_ACTION' in ir)
    has_start   = 'startActivity' in ir
    has_extra   = 'EXTRA_INTENT' in ir or 'extra.INTENT' in ir or 'getParcelableExtra' in ir
    if not has_pending:
        fail("InstallReceiver.kt: STATUS_PENDING_USER_ACTION not handled — "
             "PackageInstaller fires this to show the install dialog; "
             "if not handled, no dialog ever appears")
    if not has_start:
        fail("InstallReceiver.kt: startActivity not called — "
             "install dialog can never be shown")
    if not has_extra:
        fail("InstallReceiver.kt: EXTRA_INTENT / getParcelableExtra missing — "
             "user intent for install dialog never extracted")
    if has_pending and has_start and has_extra:
        print("  ✅ InstallReceiver correctly handles STATUS_PENDING_USER_ACTION")
else:
    fail("InstallReceiver.kt not found")

# ── RESULT ────────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
if ERRORS:
    print(f"❌ PRE-BUILD CHECKS FAILED — {len(ERRORS)} error(s):")
    for i, e in enumerate(ERRORS, 1):
        print(f"  {i}. {e}")
    sys.exit(1)
else:
    print("✅ ALL PRE-BUILD CHECKS PASSED")
    sys.exit(0)
