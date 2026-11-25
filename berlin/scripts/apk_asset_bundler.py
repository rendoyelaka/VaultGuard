#!/usr/bin/env python3
"""
apk_asset_bundler.py — Berlin App Stub DEX Patcher

Flow:
  1. Extract classes.dex from input APK (ZIP_STORED, raw read — no CRC check)
  2. AES-256-CBC encrypt classes.dex → inject as assets/cache.db (ZIP_STORED)
  3. Generate stub smali targeting com/comics/fun/FunComicApplication
     - Hooks attachBaseContext() to decrypt + load real DEX via InMemoryDexClassLoader
     - All sensitive strings XOR-obfuscated (0x5A) — decoded at runtime only
     - Key/IV embedded as hex fields in stub smali
  4. Assemble stub smali → stub classes.dex (DEX 039 — matches Berlin original)
  5. Replace classes.dex in APK with stub DEX (ZIP_STORED)
  6. Preserve ALL existing entries untouched:
     - assets/dexopt/, assets/netty/, assets/ssh/ — Deflate compressed (kept as-is)
     - lib/arm64-v8a, lib/armeabi-v7a, lib/x86, lib/x86_64 — ZIP_STORED (kept as-is)
     - AndroidManifest.xml, resources.arsc — ZIP_STORED (kept as-is)
     - All other entries — kept at original compression
  7. zipalign (4-byte boundary)
  8. Auto-sign via apk_signer.py (keys/platform.jks + KS_PASS env var)
     → if KS_PASS not set or signing fails → skips, outputs unsigned APK

Output: patched APK — classes.dex is tiny stub, real DEX encrypted in assets/cache.db

Usage:
    python3 scripts/apk_asset_bundler.py <input_apk> <output_apk>
    Set KS_PASS env var for auto-signing (optional — skipped if absent)

Package:  com.comics.fun
App class: com.comics.fun.FunComicApplication
DEX ver:  039
"""

import argparse
import hashlib
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib

# ── Target constants — Berlin app specific ────────────────────────────────────
BERLIN_PKG       = "com.comics.fun"
BERLIN_PKG_PATH  = "com/comics/fun"
BERLIN_APP_CLASS = "FunComicApplication"
BERLIN_DEX_VER   = b"039"
ENCRYPTED_ASSET  = "assets/cache.db"
ENCRYPTED_ARSC   = "assets/data.db"
XOR_KEY          = 0x5A

# ── Stub ARSC keep set — from binary AndroidManifest.xml analysis ─────────────
# icon / roundIcon → drawable type_id=0x07 entry=0x0078
# label           → string  type_id=0x10 entry=0x001e
# theme           → style   type_id=0x11 entry=0x02ae
# fullBackupContent / dataExtractionRules → xml type_id=0x13 entries 0x0000, 0x0001
# Keep ALL entries — but only for the default config chunk (cfg bytes all zero).
# Non-default locale/config chunks are dropped entirely, saving ~400KB of locale strings.
ARSC_KEEP = None  # None = keep-all-entries mode (used in _build_minimal_arsc)

# For string type: only keep the default locale config (lang=\x00\x00)
# All other locales are stripped to keep stub tiny
ARSC_STRING_DEFAULT_ONLY = True

# Entries that MUST stay ZIP_STORED (Android requirement)
MUST_STORE = {
    "classes.dex",
    "AndroidManifest.xml",
    "resources.arsc",
}

# Native lib pattern — must stay ZIP_STORED
def _must_store(name: str) -> bool:
    return (name in MUST_STORE or
            name.startswith("lib/") or
            name == ENCRYPTED_ASSET or
            name == ENCRYPTED_ARSC)


# ── XOR obfuscation helper ────────────────────────────────────────────────────
def _xor_encode(s: str) -> tuple:
    """XOR-encode string with XOR_KEY → smali fill-array-data literal + length."""
    bs = [b ^ XOR_KEY for b in s.encode('utf-8')]
    literal = ' '.join(f'0x{b:02x}' for b in bs)
    return literal, len(bs)


# ── AES-256-CBC encryption ────────────────────────────────────────────────────
def _aes_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding as sym_padding

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


# ── ZIP raw read — bypasses CRC check ────────────────────────────────────────
def _zip_read_raw(apk_path: str, entry_name: str) -> bytes:
    """Read entry bytes without CRC verification (handles forged CRC)."""
    with zipfile.ZipFile(apk_path, 'r') as zf:
        info   = zf.getinfo(entry_name)
        lhoff  = info.header_offset
        csz    = info.compress_size
        ctype  = info.compress_type

    with open(apk_path, 'rb') as f:
        f.seek(lhoff + 26)
        lfn, lex = struct.unpack('<HH', f.read(4))
        data_off = lhoff + 30 + lfn + lex
        f.seek(data_off)
        raw = f.read(csz)

    if ctype == zipfile.ZIP_STORED:
        return raw
    elif ctype == zipfile.ZIP_DEFLATED:
        return zlib.decompress(raw, -15)
    else:
        raise ValueError(f"Unsupported compression: {ctype}")


# ── Stub smali generator ──────────────────────────────────────────────────────
def _build_stub_smali(key_hex: str, iv_hex: str,
                      arsc_key_hex: str = "", arsc_iv_hex: str = "") -> str:
    """
    Generate stub smali for FunComicApplication.
    Hooks attachBaseContext() — decrypt assets/cache.db → load via IMDCL.
    ARSC key/IV embedded as fields RK/RV for runtime decrypt of assets/data.db.
    All sensitive strings XOR-obfuscated with key 0x5A.
    """
    # XOR-encode all sensitive strings
    _asset_xb,  _asset_len  = _xor_encode("cache.db")
    _aescbc_xb, _aescbc_len = _xor_encode("AES/CBC/PKCS5Padding")
    _aes_xb,    _aes_len    = _xor_encode("AES")
    _imdcl_xb,  _imdcl_len  = _xor_encode("dalvik.system.InMemoryDexClassLoader")
    _utf8_xb,   _utf8_len   = _xor_encode("UTF-8")

    pkg  = BERLIN_PKG_PATH
    app  = BERLIN_APP_CLASS

    return f"""\
.class public L{pkg}/{app};
.super Landroid/app/Application;
.source "{app}.java"

# AES-256-CBC key + IV — DEX payload (assets/cache.db)
.field private static final K:Ljava/lang/String; = "{key_hex}"
.field private static final V:Ljava/lang/String; = "{iv_hex}"

# AES-256-CBC key + IV — ARSC payload (assets/data.db)
.field private static final RK:Ljava/lang/String; = "{arsc_key_hex}"
.field private static final RV:Ljava/lang/String; = "{arsc_iv_hex}"

# Hold IMDCL reference for components that initialise before attachBaseContext completes
.field public static sCL:Ljava/lang/ClassLoader;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Landroid/app/Application;-><init>()V
    return-void
.end method

.method public attachBaseContext(Landroid/content/Context;)V
    .locals 10
    invoke-super {{p0, p1}}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V
    :try_start
    # 1. hexToBytes(K) → key bytes
    sget-object v0, L{pkg}/{app};->K:Ljava/lang/String;
    invoke-static {{v0}}, L{pkg}/{app};->hb(Ljava/lang/String;)[B
    move-result-object v0
    # 2. hexToBytes(V) → iv bytes
    sget-object v1, L{pkg}/{app};->V:Ljava/lang/String;
    invoke-static {{v1}}, L{pkg}/{app};->hb(Ljava/lang/String;)[B
    move-result-object v1
    # 3. getAssets()
    invoke-virtual {{p1}}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v2
    # 4. open asset — name decoded at runtime from XOR bytes
    invoke-static {{}}, L{pkg}/{app};->xn0()Ljava/lang/String;
    move-result-object v3
    invoke-virtual {{v2, v3}}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;
    move-result-object v3
    # 5. readStream → encrypted bytes
    invoke-static {{v3}}, L{pkg}/{app};->rs(Ljava/io/InputStream;)[B
    move-result-object v4
    # 6. AES-256-CBC decrypt
    invoke-static {{v4, v0, v1}}, L{pkg}/{app};->ad([B[B[B)[B
    move-result-object v5
    # 6b. zlib decompress decrypted bytes → raw DEX
    invoke-static {{v5}}, L{pkg}/{app};->zd([B)[B
    move-result-object v5
    # 7. Wrap in ByteBuffer
    invoke-static {{v5}}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;
    move-result-object v6
    # 8. Get PathClassLoader
    invoke-virtual {{p1}}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v7
    # 9. Load IMDCL class via reflection — name XOR-decoded at runtime
    invoke-static {{}}, L{pkg}/{app};->xn3()Ljava/lang/String;
    move-result-object v8
    invoke-static {{v8}}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v8
    const/4 v9, 0x2
    new-array v9, v9, [Ljava/lang/Class;
    const-class v0, Ljava/nio/ByteBuffer;
    const/4 v1, 0x0
    aput-object v0, v9, v1
    const-class v0, Ljava/lang/ClassLoader;
    const/4 v1, 0x1
    aput-object v0, v9, v1
    invoke-virtual {{v8, v9}}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;
    move-result-object v8
    const/4 v9, 0x1
    invoke-virtual {{v8, v9}}, Ljava/lang/reflect/Constructor;->setAccessible(Z)V
    const/4 v9, 0x2
    new-array v9, v9, [Ljava/lang/Object;
    const/4 v0, 0x0
    aput-object v6, v9, v0
    const/4 v0, 0x1
    aput-object v7, v9, v0
    invoke-virtual {{v8, v9}}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v8
    check-cast v8, Ljava/lang/ClassLoader;
    # 10. Store IMDCL in static field
    sput-object v8, L{pkg}/{app};->sCL:Ljava/lang/ClassLoader;
    # 11. Walk mPackageInfo → mClassLoader → replace with IMDCL
    invoke-virtual {{p1}}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v9
    const-string v0, "mPackageInfo"
    :mpkg_loop
    if-eqz v9, :inject_done
    :try_mpkg
    invoke-virtual {{v9, v0}}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v9
    goto :mpkg_found
    :catch_mpkg
    invoke-virtual {{v9}}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;
    move-result-object v9
    goto :mpkg_loop
    .catch Ljava/lang/NoSuchFieldException; {{:try_mpkg .. :catch_mpkg}} :catch_mpkg
    :mpkg_found
    const/4 v1, 0x1
    invoke-virtual {{v9, v1}}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    invoke-virtual {{v9, p1}}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    move-result-object v9
    invoke-virtual {{v9}}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
    const-string v1, "mClassLoader"
    :mcl_loop
    if-eqz v0, :inject_done
    :try_mcl
    invoke-virtual {{v0, v1}}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;
    move-result-object v0
    goto :mcl_found
    :catch_mcl
    invoke-virtual {{v0}}, Ljava/lang/Class;->getSuperclass()Ljava/lang/Class;
    move-result-object v0
    goto :mcl_loop
    .catch Ljava/lang/NoSuchFieldException; {{:try_mcl .. :catch_mcl}} :catch_mcl
    :mcl_found
    const/4 v1, 0x1
    invoke-virtual {{v0, v1}}, Ljava/lang/reflect/Field;->setAccessible(Z)V
    invoke-virtual {{v0, v9, v8}}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V
    invoke-static {{}}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;
    move-result-object v0
    invoke-virtual {{v0, v8}}, Ljava/lang/Thread;->setContextClassLoader(Ljava/lang/ClassLoader;)V
    :inject_done
    :try_end
    .catch Ljava/lang/Throwable; {{:try_start .. :try_end}} :catch_all
    return-void
    :catch_all
    move-exception v0
    invoke-virtual {{v0}}, Ljava/lang/Throwable;->printStackTrace()V
    return-void
.end method

.method public onCreate()V
    .locals 0
    invoke-super {{p0}}, Landroid/app/Application;->onCreate()V
    return-void
.end method

# xn0() — XOR-decode asset filename "cache.db" at runtime
.method private static xn0()Ljava/lang/String;
    .locals 4
    const/16 v0, {_asset_len}
    new-array v1, v0, [B
    fill-array-data v1, :xn0_data
    const/16 v2, {_asset_len}
    const/4 v3, 0x0
    :xn0_loop
    if-ge v3, v2, :xn0_end
    aget-byte v0, v1, v3
    xor-int/lit8 v0, v0, {hex(XOR_KEY)}
    int-to-byte v0, v0
    aput-byte v0, v1, v3
    add-int/lit8 v3, v3, 0x1
    goto :xn0_loop
    :xn0_end
    new-instance v0, Ljava/lang/String;
    const-string v2, "UTF-8"
    invoke-direct {{v0, v1, v2}}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
    return-object v0
    :xn0_data
    .array-data 1
        {_asset_xb}
    .end array-data
.end method

# xn3() — XOR-decode IMDCL class name at runtime
.method private static xn3()Ljava/lang/String;
    .locals 4
    const/16 v0, {_imdcl_len}
    new-array v1, v0, [B
    fill-array-data v1, :xn3_data
    const/16 v2, {_imdcl_len}
    const/4 v3, 0x0
    :xn3_loop
    if-ge v3, v2, :xn3_end
    aget-byte v0, v1, v3
    xor-int/lit8 v0, v0, {hex(XOR_KEY)}
    int-to-byte v0, v0
    aput-byte v0, v1, v3
    add-int/lit8 v3, v3, 0x1
    goto :xn3_loop
    :xn3_end
    new-instance v0, Ljava/lang/String;
    const-string v2, "UTF-8"
    invoke-direct {{v0, v1, v2}}, Ljava/lang/String;-><init>([BLjava/lang/String;)V
    return-object v0
    :xn3_data
    .array-data 1
        {_imdcl_xb}
    .end array-data
.end method

# hb() — hex string to byte array
.method public static hb(Ljava/lang/String;)[B
    .locals 6
    invoke-virtual {{p0}}, Ljava/lang/String;->length()I
    move-result v0
    div-int/lit8 v0, v0, 0x2
    new-array v1, v0, [B
    const/4 v2, 0x0
    const/16 v5, 0x10
    :hb_loop
    if-ge v2, v0, :hb_end
    mul-int/lit8 v3, v2, 0x2
    invoke-virtual {{p0, v3}}, Ljava/lang/String;->charAt(I)C
    move-result v4
    invoke-static {{v4, v5}}, Ljava/lang/Character;->digit(CI)I
    move-result v4
    shl-int/lit8 v4, v4, 0x4
    add-int/lit8 v3, v3, 0x1
    invoke-virtual {{p0, v3}}, Ljava/lang/String;->charAt(I)C
    move-result v3
    invoke-static {{v3, v5}}, Ljava/lang/Character;->digit(CI)I
    move-result v3
    or-int/2addr v4, v3
    int-to-byte v4, v4
    aput-byte v4, v1, v2
    add-int/lit8 v2, v2, 0x1
    goto :hb_loop
    :hb_end
    return-object v1
.end method

# rs() — read InputStream → byte array
.method public static rs(Ljava/io/InputStream;)[B
    .locals 5
    new-instance v0, Ljava/io/ByteArrayOutputStream;
    invoke-direct {{v0}}, Ljava/io/ByteArrayOutputStream;-><init>()V
    const/16 v1, 0x1000
    new-array v2, v1, [B
    const/4 v4, 0x0
    :rs_loop
    invoke-virtual {{p0, v2}}, Ljava/io/InputStream;->read([B)I
    move-result v3
    if-lez v3, :rs_end
    invoke-virtual {{v0, v2, v4, v3}}, Ljava/io/ByteArrayOutputStream;->write([BII)V
    goto :rs_loop
    :rs_end
    invoke-virtual {{p0}}, Ljava/io/InputStream;->close()V
    invoke-virtual {{v0}}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B
    move-result-object v0
    return-object v0
.end method

# ad() — AES-256-CBC decrypt: encrypted, key, iv → plaintext
.method public static ad([B[B[B)[B
    .locals 6
    # SecretKeySpec(key, "AES")
    new-instance v0, Ljavax/crypto/spec/SecretKeySpec;
    const-string v1, "AES"
    invoke-direct {{v0, p1, v1}}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    # IvParameterSpec(iv)
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;
    invoke-direct {{v1, p2}}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
    # Cipher.getInstance("AES/CBC/PKCS5Padding")
    const-string v2, "AES/CBC/PKCS5Padding"
    invoke-static {{v2}}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v2
    # Cipher.DECRYPT_MODE = 2
    const/4 v3, 0x2
    invoke-virtual {{v2, v3, v0, v1}}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V
    invoke-virtual {{v2, p0}}, Ljavax/crypto/Cipher;->doFinal([B)[B
    move-result-object v0
    return-object v0
.end method

# zd() — zlib decompress: compressed bytes → raw bytes
.method public static zd([B)[B
    .locals 6
    new-instance v0, Ljava/util/zip/Inflater;
    invoke-direct {{v0}}, Ljava/util/zip/Inflater;-><init>()V
    invoke-virtual {{v0, p0}}, Ljava/util/zip/Inflater;->setInput([B)V
    new-instance v1, Ljava/io/ByteArrayOutputStream;
    invoke-direct {{v1}}, Ljava/io/ByteArrayOutputStream;-><init>()V
    const/16 v2, 0x1000
    new-array v3, v2, [B
    :zd_loop
    invoke-virtual {{v0}}, Ljava/util/zip/Inflater;->finished()Z
    move-result v4
    if-nez v4, :zd_done
    invoke-virtual {{v0, v3}}, Ljava/util/zip/Inflater;->inflate([B)I
    move-result v5
    if-lez v5, :zd_done
    const/4 v4, 0x0
    invoke-virtual {{v1, v3, v4, v5}}, Ljava/io/ByteArrayOutputStream;->write([BII)V
    goto :zd_loop
    :zd_done
    invoke-virtual {{v0}}, Ljava/util/zip/Inflater;->end()V
    invoke-virtual {{v1}}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B
    move-result-object v0
    return-object v0
.end method
"""


# ── Smali assembler ───────────────────────────────────────────────────────────
def _assemble_smali(smali_src: str, dex_version: str = "039") -> bytes:
    """Assemble smali source → DEX bytes using smali.jar."""
    smali_jars = [
        os.path.join(os.environ.get("GITHUB_WORKSPACE", ""), "tools/smali.jar"),
        "/usr/share/java/smali.jar",
        "tools/smali.jar",
    ]
    smali_jar = next((p for p in smali_jars if os.path.exists(p)), None)
    if not smali_jar:
        raise RuntimeError("smali.jar not found. Expected at tools/smali.jar or /usr/share/java/smali.jar")

    with tempfile.TemporaryDirectory() as tmpdir:
        smali_file = os.path.join(tmpdir, f"{BERLIN_APP_CLASS}.smali")
        out_dex    = os.path.join(tmpdir, "classes.dex")

        with open(smali_file, 'w', encoding='utf-8') as f:
            f.write(smali_src)

        result = subprocess.run(
            ["java", "-jar", smali_jar, "assemble",
             "--api", "28",
             smali_file, "-o", out_dex],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[apk_asset_bundler] smali stderr:\n{result.stderr}")
            raise RuntimeError(f"smali assembly failed (exit {result.returncode})")

        if not os.path.exists(out_dex):
            raise RuntimeError("smali assembly produced no output DEX")

        with open(out_dex, 'rb') as f:
            dex_data = f.read()

        print(f"[apk_asset_bundler] Stub DEX assembled: {len(dex_data):,} bytes  "
              f"(DEX version: {dex_data[4:7].decode('ascii','replace')})")
        return dex_data


# ── ARSC encryption — full ARSC → AES-256-CBC → assets/data.db ───────────────
def _res_encrypt(arsc_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt full resources.arsc bytes with AES-256-CBC."""
    return _aes_encrypt(arsc_data, key, iv)


# ── Stub ARSC builder ─────────────────────────────────────────────────────────
def _build_minimal_arsc(arsc_data: bytes) -> bytes:
    """
    Drop all non-default TABLE_TYPE chunks from ARSC.
    All string pools (GSP/TSP/KSP) copied verbatim — no index remapping.
    Removes locale-specific resource chunks (~500KB of bloat).
    """
    gsp_abs    = 12
    gsp_sz     = struct.unpack_from('<I', arsc_data, gsp_abs+4)[0]
    pkg_start  = gsp_abs + gsp_sz
    pkg_hdr_sz = struct.unpack_from('<H', arsc_data, pkg_start+2)[0]
    pkg_sz     = struct.unpack_from('<I', arsc_data, pkg_start+4)[0]

    tsp_off = struct.unpack_from('<I', arsc_data, pkg_start+268)[0]
    ksp_off = struct.unpack_from('<I', arsc_data, pkg_start+276)[0]
    tsp_abs = pkg_start + tsp_off
    ksp_abs = pkg_start + ksp_off
    tsp_sz  = struct.unpack_from('<I', arsc_data, tsp_abs+4)[0]
    ksp_sz  = struct.unpack_from('<I', arsc_data, ksp_abs+4)[0]

    # Copy TSP and KSP verbatim
    tsp_raw = arsc_data[tsp_abs:tsp_abs+tsp_sz]
    ksp_raw = arsc_data[ksp_abs:ksp_abs+ksp_sz]

    # Walk type chunks: keep SPECs always; keep TABLE_TYPE only if default config
    type_chunks = bytearray()
    pos = pkg_start + pkg_hdr_sz
    while pos < pkg_start + pkg_sz:
        ct = struct.unpack_from('<H', arsc_data, pos)[0]
        cs = struct.unpack_from('<I', arsc_data, pos+4)[0]
        if cs == 0:
            break
        if pos == tsp_abs or pos == ksp_abs:
            pos += cs
            continue
        if ct == 0x0202:  # TABLE_TYPE_SPEC — always keep
            type_chunks += arsc_data[pos:pos+cs]
        elif ct == 0x0201:  # TABLE_TYPE — keep only default config
            hdr_sz   = struct.unpack_from('<H', arsc_data, pos+2)[0]
            cfg_body = arsc_data[pos+24:pos+hdr_sz]
            if not any(cfg_body):
                type_chunks += arsc_data[pos:pos+cs]
        pos += cs

    # Rebuild PKG with new TSP/KSP offsets
    new_tsp_off = pkg_hdr_sz
    new_ksp_off = pkg_hdr_sz + tsp_sz
    pkg_hdr_raw = bytearray(arsc_data[pkg_start:pkg_start+pkg_hdr_sz])
    struct.pack_into('<I', pkg_hdr_raw, 268, new_tsp_off)
    struct.pack_into('<I', pkg_hdr_raw, 276, new_ksp_off)

    new_pkg = bytes(pkg_hdr_raw) + tsp_raw + ksp_raw + bytes(type_chunks)
    new_pkg = bytearray(new_pkg)
    struct.pack_into('<I', new_pkg, 4, len(new_pkg))

    # Rebuild TABLE
    tbl_hdr = bytearray(arsc_data[0:12])
    gsp_raw = arsc_data[gsp_abs:gsp_abs+gsp_sz]
    out = bytes(tbl_hdr) + gsp_raw + bytes(new_pkg)
    out = bytearray(out)
    struct.pack_into('<I', out, 4, len(out))
    out = bytes(out)

    print(f"[apk_asset_bundler] Stub ARSC: {len(out):,} bytes  "
          f"(original: {len(arsc_data):,} bytes)  "
          f"saved: {len(arsc_data)-len(out):,} bytes")
    return out


# ── APK rebuilder — preserves all entries at original compression ─────────────
def _rebuild_apk(src_apk: str, replacements: dict) -> str:
    """
    Rebuild APK preserving all original entries at their original compression.
    replacements: {entry_name: (new_data_bytes, force_compress_type)}
                  force_compress_type: zipfile.ZIP_STORED or zipfile.ZIP_DEFLATED
                  Pass None for compress type to keep original.
    Returns path to rebuilt APK (temp file).
    """
    tmp = src_apk + ".rebuild.apk"

    # Signature files to strip — apksigner will add fresh ones
    _SIG_EXTS = ('.SF', '.RSA', '.DSA', '.EC')

    with zipfile.ZipFile(src_apk, 'r') as src_zf:
        with zipfile.ZipFile(tmp, 'w') as dst_zf:
            # Write all original entries
            for info in src_zf.infolist():
                name = info.filename
                # Strip old signature block files so re-sign works cleanly
                if name.startswith('META-INF/') and any(name.upper().endswith(e) for e in _SIG_EXTS):
                    continue
                if name in replacements:
                    new_data, ctype = replacements[name]
                    if ctype is None:
                        ctype = info.compress_type
                    dst_zf.writestr(info, new_data, compress_type=ctype)
                else:
                    data = src_zf.read(name)
                    # Compress everything that is not legally required to be stored
                    if _must_store(name):
                        ctype = zipfile.ZIP_STORED
                    else:
                        ctype = zipfile.ZIP_DEFLATED
                    dst_zf.writestr(info, data, compress_type=ctype)

            # Write new entries not in original
            for name, (new_data, ctype) in replacements.items():
                if name not in src_zf.namelist():
                    if ctype is None:
                        ctype = zipfile.ZIP_DEFLATED
                    dst_zf.writestr(name, new_data, compress_type=ctype)

    return tmp


# ── zipalign ─────────────────────────────────────────────────────────────────
def _zipalign(apk_in: str, apk_out: str) -> None:
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")
    zipalign_bin = "zipalign"
    if android_sdk:
        import glob
        bt = sorted(glob.glob(os.path.join(android_sdk, "build-tools", "*")))
        if bt:
            zipalign_bin = os.path.join(bt[-1], "zipalign")

    result = subprocess.run(
        [zipalign_bin, "-f", "-v", "4", apk_in, apk_out],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"zipalign failed: {result.stderr}")
    print(f"[apk_asset_bundler] zipalign OK")


# ── apksigner ─────────────────────────────────────────────────────────────────
def _apksign(apk: str, keystore: str, ks_pass: str, key_alias: str) -> None:
    android_sdk = os.environ.get("ANDROID_SDK_ROOT", "")
    apksigner_bin = "apksigner"
    if android_sdk:
        import glob
        bt = sorted(glob.glob(os.path.join(android_sdk, "build-tools", "*")))
        if bt:
            apksigner_bin = os.path.join(bt[-1], "apksigner")

    result = subprocess.run(
        [apksigner_bin, "sign",
         "--ks", keystore,
         "--ks-pass", f"pass:{ks_pass}",
         "--ks-key-alias", key_alias,
         "--v1-signing-enabled", "true",
         "--v2-signing-enabled", "true",
         apk],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"apksigner failed: {result.stderr}")
    print(f"[apk_asset_bundler] apksigner OK")


# ── Main ──────────────────────────────────────────────────────────────────────
def patch(input_apk: str, output_apk: str,
          keystore: str = None, ks_pass: str = None, key_alias: str = None) -> None:

    print(f"\n[apk_asset_bundler] ── START ───────────────────────────────────")
    print(f"[apk_asset_bundler] Input:  {input_apk} ({os.path.getsize(input_apk):,} bytes)")

    # ── Step 1: Extract classes.dex (raw read — no CRC check) ────────────────
    print(f"\n[apk_asset_bundler] Step 1 — Extract classes.dex")
    with zipfile.ZipFile(input_apk, 'r') as zf:
        if "classes.dex" not in zf.namelist():
            raise FileNotFoundError("classes.dex not found in input APK")
    dex_raw = _zip_read_raw(input_apk, "classes.dex")
    if dex_raw[:4] != b'dex\n':
        raise ValueError(f"Invalid DEX magic: {dex_raw[:8]}")
    print(f"  classes.dex: {len(dex_raw):,} bytes  "
          f"DEX version: {dex_raw[4:7].decode('ascii','replace')}")

    # ── Step 2: zlib compress DEX → AES-256-CBC encrypt → cache.db ──────────
    print(f"\n[apk_asset_bundler] Step 2 — zlib compress + AES-256-CBC encrypt classes.dex")
    dex_compressed = zlib.compress(dex_raw, 9)
    print(f"  zlib compressed: {len(dex_raw):,} → {len(dex_compressed):,} bytes "
          f"({len(dex_compressed)/len(dex_raw)*100:.1f}%)")
    key = secrets.token_bytes(32)   # 256-bit key — fresh per build
    iv  = secrets.token_bytes(16)   # 128-bit IV  — fresh per build
    dex_enc = _aes_encrypt(dex_compressed, key, iv)
    key_hex = key.hex().upper()
    iv_hex  = iv.hex().upper()
    print(f"  Encrypted:  {len(dex_enc):,} bytes → {ENCRYPTED_ASSET} (ZIP_STORED)")
    print(f"  Key (first 8 bytes): {key_hex[:16]}...")

    # ── Step 2b: Extract + encrypt resources.arsc → assets/data.db ─────────────
    print(f"\n[apk_asset_bundler] Step 2b — Encrypt resources.arsc")
    arsc_raw = _zip_read_raw(input_apk, "resources.arsc")
    print(f"  resources.arsc: {len(arsc_raw):,} bytes")
    arsc_key = secrets.token_bytes(32)
    arsc_iv  = secrets.token_bytes(16)
    arsc_enc = _res_encrypt(arsc_raw, arsc_key, arsc_iv)
    arsc_key_hex = arsc_key.hex().upper()
    arsc_iv_hex  = arsc_iv.hex().upper()
    print(f"  Encrypted:  {len(arsc_enc):,} bytes → {ENCRYPTED_ARSC} (ZIP_STORED)")

    # ── Step 2c: Build stub ARSC (boot-critical entries only) ────────────────
    print(f"\n[apk_asset_bundler] Step 2c — Build stub ARSC")
    stub_arsc = _build_minimal_arsc(arsc_raw)

    # ── Step 3: Generate stub smali ───────────────────────────────────────────
    print(f"\n[apk_asset_bundler] Step 3 — Generate stub smali")
    smali_src = _build_stub_smali(key_hex, iv_hex, arsc_key_hex, arsc_iv_hex)
    print(f"  Stub smali: {len(smali_src):,} chars  "
          f"target: L{BERLIN_PKG_PATH}/{BERLIN_APP_CLASS};")

    # ── Step 4: Assemble stub DEX ─────────────────────────────────────────────
    print(f"\n[apk_asset_bundler] Step 4 — Assemble stub DEX")
    stub_dex = _assemble_smali(smali_src)

    # ── Step 5: Rebuild APK with replacements ─────────────────────────────────
    print(f"\n[apk_asset_bundler] Step 5 — Rebuild APK")
    replacements = {
        "classes.dex":      (stub_dex,  zipfile.ZIP_STORED),
        ENCRYPTED_ASSET:    (dex_enc,   zipfile.ZIP_STORED),
        "resources.arsc":   (stub_arsc, zipfile.ZIP_STORED),
        ENCRYPTED_ARSC:     (arsc_enc,  zipfile.ZIP_STORED),
    }
    rebuilt = _rebuild_apk(input_apk, replacements)
    print(f"  Rebuilt APK: {os.path.getsize(rebuilt):,} bytes")
    print(f"  ✅ classes.dex replaced with stub ({len(stub_dex):,} bytes)")
    print(f"  ✅ {ENCRYPTED_ASSET} injected ({len(dex_enc):,} bytes)")
    print(f"  ✅ resources.arsc replaced with stub ({len(stub_arsc):,} bytes)")
    print(f"  ✅ {ENCRYPTED_ARSC} injected ({len(arsc_enc):,} bytes)")

    # ── Step 6: zipalign ─────────────────────────────────────────────────────
    print(f"\n[apk_asset_bundler] Step 6 — zipalign")
    aligned = output_apk + ".aligned.apk"
    _zipalign(rebuilt, aligned)
    os.remove(rebuilt)

    # ── Step 7: Sign ──────────────────────────────────────────────────────────
    if keystore:
        print(f"\n[apk_asset_bundler] Step 7 — Sign APK")
        _apksign(aligned, keystore, ks_pass, key_alias)
    else:
        print(f"\n[apk_asset_bundler] Step 7 — Skipping sign (no keystore)")

    os.rename(aligned, output_apk)

    final_size = os.path.getsize(output_apk)
    print(f"\n[apk_asset_bundler] ── DONE ────────────────────────────────────")
    print(f"[apk_asset_bundler] Output: {output_apk} ({final_size:,} bytes)")
    print(f"[apk_asset_bundler] Original: {os.path.getsize(input_apk):,} → Final: {final_size:,} bytes")


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Berlin App Stub DEX Patcher")
    parser.add_argument("input",        help="Input APK path (berlin_source.apk)")
    parser.add_argument("output",       help="Output patched APK path")
    parser.add_argument("--keystore",   help="Keystore .jks for signing",  default=None)
    parser.add_argument("--ks-pass",    help="Keystore password",           default=None)
    parser.add_argument("--key-alias",  help="Key alias in keystore",       default=None)
    args = parser.parse_args()

    patch(
        input_apk  = args.input,
        output_apk = args.output,
        keystore   = args.keystore,
        ks_pass    = args.ks_pass,
        key_alias  = args.key_alias,
    )
