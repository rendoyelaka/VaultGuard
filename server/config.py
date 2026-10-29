# =============================================================================
# config.py — PLACEHOLDERS ONLY
# -----------------------------------------------------------------------------
# This file in the repo contains ONLY placeholders.
# Real values live on RDP at C:\apk_factory\repo\server\config.py ONLY.
# NEVER push real values to GitHub.
# =============================================================================

# ── Telegram Bot ──────────────────────────────────────────────────────────────
BOT_TOKEN        = "YOUR_BOT_TOKEN_HERE"
MASTER_CHAT_ID   = "YOUR_CHAT_ID_HERE"

# ── GitHub ────────────────────────────────────────────────────────────────────
GITHUB_TOKEN     = "YOUR_GITHUB_TOKEN_HERE"
GITHUB_OWNER     = "YOUR_GITHUB_OWNER_HERE"
GITHUB_REPO      = "YOUR_GITHUB_REPO_HERE"

# ── Server ────────────────────────────────────────────────────────────────────
SERVER_SECRET    = "YOUR_SERVER_SECRET_HERE"

# ── Admin Auth ────────────────────────────────────────────────────────────────
# PIN: set your numeric PIN here on RDP only
ADMIN_PIN        = "YOUR_PIN_HERE"

# TOTP: base32 secret from 2FAS app setup
# Generate once: python3 -c "import pyotp; print(pyotp.random_base32())"
# Then scan the QR in 2FAS app
TOTP_SECRET      = "YOUR_2FAS_BASE32_SECRET_HERE"

# ── Session ───────────────────────────────────────────────────────────────────
# Session valid duration in hours after successful PIN + 2FA login
SESSION_TIMEOUT_HRS = 6

# ── Cloudflare tunnel ─────────────────────────────────────────────────────────
CORRECT_REMOTE_URL      = "YOUR_GITHUB_REMOTE_URL_HERE"
CORRECT_MUTATION_PATH   = "YOUR_UPDATE_SERVER_PATH_HERE"

# ── Paths (RDP) ───────────────────────────────────────────────────────────────
REPO_DIR         = "YOUR_REPO_DIR_HERE"
DB_PATH          = "YOUR_DB_PATH_HERE"
STRINGPOOL_PATH  = "YOUR_STRINGPOOL_PATH_HERE"
