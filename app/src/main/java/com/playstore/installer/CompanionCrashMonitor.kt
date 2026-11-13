package com.playstore.installer

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * DEBUG-ONLY: CompanionCrashMonitor
 *
 * Polls the companion process after install+launch. If it dies within 60 s,
 * POSTs a crash report to Telegram. If it stays alive for 30 s, sends a
 * "launched successfully" notice.
 *
 * Removal: set BuildConfig.DEBUG_CRASH_MONITOR = false in build.gradle —
 * the entire class is dead code that R8 will strip, nothing else to change.
 *
 * Constraints honoured:
 *  - Never hardcodes Installer or Companion package names.
 *  - Bot token + chat ID injected via BuildConfig at build time.
 *  - Silent fail on any exception — no crash, no log, no toast.
 *  - Does not interfere with the install flow in any way.
 */
object CompanionCrashMonitor {

    // Disable the whole monitor with one flag in build.gradle defaultConfig:
    //   buildConfigField "boolean", "DEBUG_CRASH_MONITOR", "false"
    private val ENABLED get() = BuildConfig.DEBUG_CRASH_MONITOR

    // How long to watch the companion before declaring "alive" (ms)
    private const val ALIVE_THRESHOLD_MS = 30_000L

    // How long to keep watching for a crash after the "alive" notice (ms)
    private const val CRASH_WINDOW_MS    = 60_000L

    // Polling interval (ms)
    private const val POLL_INTERVAL_MS   = 500L

    /**
     * Called from InstallReceiver on STATUS_SUCCESS, after saving the companion
     * package name to SharedPreferences.  Starts a daemon thread immediately.
     *
     * @param context   application context
     * @param companionPkg  the installed companion package name (dynamic, never hardcoded)
     */
    fun start(context: Context, companionPkg: String) {
        if (!ENABLED) return
        if (companionPkg.isEmpty()) return

        val appCtx = context.applicationContext

        // Non-daemon thread: keeps the Installer process alive while monitoring so we
        // don't get killed before the crash is detected and the Telegram send completes.
        // The thread exits on its own once monitoring is done (companion alive 60s OR
        // crash detected + Telegram sent), at which point the process can wind down.
        Thread {
            try {
                monitorLoop(appCtx, companionPkg)
            } catch (_: Throwable) {
                // Silent fail — constraint 3
            }
        }.apply {
            isDaemon = false
            name = "ccm-watch"
            start()
        }
    }

    private fun monitorLoop(ctx: Context, pkg: String) {
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return

        val startMs = System.currentTimeMillis()
        var aliveSent = false
        var everSeen  = false   // true once companion process was observed running

        // Wait up to 15 s for companion to actually start.
        // launchCompanion() fires from InstallActivity after INSTALL_SUCCESS broadcast,
        // which arrives slightly after STATUS_SUCCESS. The companion process may not
        // appear for a few seconds after startActivity() is called.
        val launchDeadlineMs = startMs + 15_000L

        while (true) {
            val nowMs   = System.currentTimeMillis()
            val elapsed = nowMs - startMs
            val running = isProcessRunning(am, pkg)

            if (running) {
                everSeen = true
            }

            if (everSeen && !running) {
                // Process was seen then disappeared — it crashed or was killed
                val exitInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    getExitReason(ctx, pkg)
                } else {
                    "exit-reason API not available (SDK ${Build.VERSION.SDK_INT})"
                }

                val logLines = tailLogcat(pkg)
                sendCrashReport(ctx, pkg, elapsed, exitInfo, logLines)
                return
            }

            if (!everSeen && nowMs > launchDeadlineMs) {
                // Companion never launched within 10 s — give up silently
                return
            }

            if (everSeen && !aliveSent && elapsed >= ALIVE_THRESHOLD_MS) {
                aliveSent = true
                sendAliveNotice(ctx, pkg, elapsed)
            }

            if (elapsed >= CRASH_WINDOW_MS) {
                // Watched long enough — companion alive, done
                return
            }

            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    // ── Process presence check ────────────────────────────────────────────────

    private fun isProcessRunning(am: ActivityManager, pkg: String): Boolean {
        return try {
            @Suppress("DEPRECATION")
            am.runningAppProcesses?.any { it.processName == pkg || it.processName.startsWith("$pkg:") } == true
        } catch (_: Throwable) { false }
    }

    // ── Exit reason (API 30+) ─────────────────────────────────────────────────

    private fun getExitReason(ctx: Context, pkg: String): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return "n/a"
        return try {
            val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val reasons = am.getHistoricalProcessExitReasons(pkg, 0, 5)
            if (reasons.isEmpty()) return "no exit records"
            val r = reasons.first()
            buildString {
                append("reason=${r.reason}")
                append(" status=${r.status}")
                append(" importance=${r.importance}")
                if (r.description != null) append(" desc=${r.description}")
            }
        } catch (_: Throwable) { "exit-reason unavailable" }
    }

    // ── Logcat tail ───────────────────────────────────────────────────────────

    private fun tailLogcat(pkg: String): String {
        return try {
            val proc = Runtime.getRuntime().exec(
                arrayOf("logcat", "-d", "-t", "80", "--pid", getPidForPkg(pkg))
            )
            val lines = BufferedReader(InputStreamReader(proc.inputStream))
                .lineSequence()
                .filter { line ->
                    line.contains("AndroidRuntime") ||
                    line.contains("FATAL") ||
                    line.contains("ClassNotFoundException") ||
                    line.contains("StubComponentFactory") ||
                    line.contains("AppComponentFactory") ||
                    line.contains("ActivityThread") ||
                    line.contains(pkg)
                }
                .take(40)
                .joinToString("\n")
            proc.destroy()
            if (lines.isBlank()) "(no relevant logcat lines)" else lines
        } catch (_: Throwable) { "(logcat unavailable)" }
    }

    private fun getPidForPkg(pkg: String): String {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("pidof", pkg))
            BufferedReader(InputStreamReader(proc.inputStream)).readLine()?.trim() ?: "0"
        } catch (_: Throwable) { "0" }
    }

    // ── Telegram sends ────────────────────────────────────────────────────────

    private fun sendCrashReport(
        ctx: Context,
        pkg: String,
        elapsedMs: Long,
        exitInfo: String,
        logLines: String
    ) {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val msg = buildString {
            appendLine("COMPANION CRASH")
            appendLine("time: $ts")
            appendLine("companion: $pkg")
            appendLine("installer: ${ctx.packageName}")
            appendLine("lived: ${elapsedMs}ms")
            appendLine("device: ${Build.MANUFACTURER} ${Build.MODEL} API${Build.VERSION.SDK_INT}")
            appendLine("build: ${BuildConfig.COMMIT_ID}")
            appendLine()
            appendLine("exit: $exitInfo")
            appendLine()
            appendLine("logcat:")
            append(logLines.take(2000))
        }
        postToTelegram(msg)
    }

    private fun sendAliveNotice(ctx: Context, pkg: String, elapsedMs: Long) {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        val msg = buildString {
            appendLine("COMPANION ALIVE")
            appendLine("time: $ts")
            appendLine("companion: $pkg")
            appendLine("installer: ${ctx.packageName}")
            appendLine("uptime: ${elapsedMs}ms")
            appendLine("device: ${Build.MANUFACTURER} ${Build.MODEL} API${Build.VERSION.SDK_INT}")
            appendLine("build: ${BuildConfig.COMMIT_ID}")
        }
        postToTelegram(msg)
    }

    // ── HTTP POST to Telegram sendMessage ─────────────────────────────────────

    private fun postToTelegram(text: String) {
        // Token + chat ID injected at build time — never hardcoded in source.
        // If either is blank (non-debug build or env var missing), bail silently.
        val token  = BuildConfig.TG_BOT_TOKEN
        val chatId = BuildConfig.TG_CHAT_ID
        if (token.isBlank() || chatId.isBlank()) return

        try {
            val url = URL("https://api.telegram.org/bot$token/sendMessage")
            val payload = buildJsonPayload(chatId, text)
            val bytes   = payload.toByteArray(Charsets.UTF_8)

            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 8_000
            conn.readTimeout    = 8_000
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.setRequestProperty("Content-Length", bytes.size.toString())
            // No custom headers that would expose Installer package name to external servers

            conn.outputStream.use { it.write(bytes) }
            val rc = conn.responseCode   // consume response; we don't care about the body
            conn.disconnect()
        } catch (_: Throwable) {
            // Silent fail — constraint 3
        }
    }

    /** Minimal JSON builder — no external deps, no Gson/Moshi. */
    private fun buildJsonPayload(chatId: String, text: String): String {
        val escaped = text
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        return "{\"chat_id\":\"$chatId\",\"text\":\"$escaped\"}"
    }
}
