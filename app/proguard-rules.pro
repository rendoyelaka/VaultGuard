# ============================================================
# Nova Launcher — ProGuard / R8 Rules (Step 70)
# Shrink only — no obfuscation.
# Step 8A: All native code removed — pure Kotlin only.
# ============================================================

# ── Disable obfuscation entirely ────────────────────────────
-dontobfuscate

# ── Strip: SourceFile + LineNumberTable annotations ──────────
-renamesourcefileattribute ""
-keepattributes !SourceFile,!LineNumberTable

# ── Keep: Android framework base classes ────────────────────
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# ── Keep: Nova entry point class names ──────────────────────
-keep class **.MainActivity
-keep class **.SecondActivity
-keep class **.InstallActivity
-keep class **.LauncherApplication
-keep class **.InstallReceiver
-keep class **.service.LauncherService

# ── Keep: Critical constants ─────────────────────────────────
-keepclassmembers class **.InstallActivity {
    public static final java.lang.String INSTALL_SUCCESS_ACTION;
}

# Keep StringPool object
-keep class **.StringPool { *; }
-keepclassmembers class **.StringPool {
    public static *** d(java.lang.String);
    public static *** loadReviews(android.content.Context, java.lang.String);
}

-keepclassmembers class **.MainActivity {
    public static boolean isUninstalling;
}

# ── Keep: android:onClick XML handler methods ────────────────
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# ── Keep: Android lifecycle method signatures ────────────────
-keepclassmembers class * {
    public void onCreate(android.os.Bundle);
    public void onStart();
    public void onResume();
    public void onPause();
    public void onStop();
    public void onDestroy();
    public android.os.IBinder onBind(android.content.Intent);
    public int onStartCommand(android.content.Intent, int, int);
    public void onReceive(android.content.Context, android.content.Intent);
    public void onActivityResult(int, int, android.content.Intent);
    public void onRequestPermissionsResult(int, java.lang.String[], int[]);
}

# ── Keep: Parcelable ─────────────────────────────────────────
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# ── Keep: Enum values ────────────────────────────────────────
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── Keep: BuildConfig fields ─────────────────────────────────
-keep class **.BuildConfig { *; }

# ── Keep: Annotations ────────────────────────────────────────
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes Exceptions

# ── Strip: All debug logging ─────────────────────────────────
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}

# ── Strip: Kotlin metadata ────────────────────────────────────
-dontwarn kotlin.Metadata
-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
    public static void checkNotNullParameter(...);
    public static void checkNotNullExpressionValue(...);
}

# ── Suppress warnings ─────────────────────────────────────────
-dontwarn **
-ignorewarnings

# ── Aggressive: Repackage all classes into root ───────────────
-repackageclasses ''

# ── Aggressive: Broaden access modifiers ─────────────────────
-allowaccessmodification

# ── Aggressive: Overload method names ────────────────────────
-overloadaggressively

# ── Keep: MutationEngine + DexLoader ─────────────────────────
# Step 8A: All native code removed — pure Kotlin only.
# NativeProtect, ChunkConstants, all .so files permanently deleted.

-keep class **.MutationEngine {
    public <init>(android.content.Context);
}

-keep class **.DexLoader {
    public static *** loadCompanionDex(android.content.Context);
}

-keepclassmembers class **.LauncherApplication {
    public static *** instance;
    public static *** getMutatedApkFile(android.app.Application);
}

# ── Note: shrinkResources true is set in build.gradle ────────
# companion.apk in assets/ protected via res/raw/keep.xml
