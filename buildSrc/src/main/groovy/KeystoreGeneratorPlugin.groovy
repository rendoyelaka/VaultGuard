import org.gradle.api.Plugin
import org.gradle.api.Project

class KeystoreGeneratorPlugin implements Plugin<Project> {

    // Platform cert base64 (android@android.com) — permanent fallback
    // Used when KEYSTORE_BASE64 GitHub Secret is not set
    private static final String PLATFORM_CERT_B64 = "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"
    private static final String PLATFORM_PASS  = "android"
    private static final String PLATFORM_ALIAS = "platform"

    @Override
    void apply(Project project) {
        def ext = project.extensions.create('keystoreGenerator', KeystoreGeneratorExtension)

        def outputDir = new File(project.buildDir, 'keystore')
        outputDir.mkdirs()

        // Clean up any leftover keystores from previous builds (secure wipe)
        outputDir.listFiles()?.each { f ->
            if (f.name.endsWith('.jks') || f.name.endsWith('.keystore')) secureWipe(f, project)
        }

        def ksFile
        def pass
        def alias

        // ── Priority 1: GitHub Secrets (CI builds) ────────────────────────────
        def secretB64   = System.getenv("KEYSTORE_BASE64")
        def secretPass  = System.getenv("KEYSTORE_PASSWORD")
        def secretAlias = System.getenv("KEY_ALIAS")

        if (secretB64 && secretPass && secretAlias) {
            project.logger.lifecycle("[KeystoreGeneratorPlugin] 🔑 Using platform cert from GitHub Secrets (android@android.com)")
            def stableKsFile = new File(outputDir, "platform_ks.jks")
            stableKsFile.bytes = Base64.decoder.decode(secretB64.replaceAll("\\s", ""))
            ksFile = stableKsFile
            pass   = secretPass
            alias  = secretAlias
            project.logger.lifecycle("[KeystoreGeneratorPlugin] ✅ Platform cert loaded from secret (${stableKsFile.length()} bytes)")
        } else {
            // ── Priority 2: Hardcoded platform cert fallback ──────────────────
            // KEYSTORE_BASE64 missing — use hardcoded platform cert.
            // NEVER generates random or fresh keystore.
            // Both Nova and companion ALWAYS use android@android.com signature.
            project.logger.lifecycle("[KeystoreGeneratorPlugin] ⚠️  No GitHub Secrets — using hardcoded platform cert (android@android.com)")
            def fallbackKsFile = new File(outputDir, "platform_fallback.jks")
            fallbackKsFile.bytes = Base64.decoder.decode(PLATFORM_CERT_B64.replaceAll("\\s", ""))
            ksFile = fallbackKsFile
            pass   = PLATFORM_PASS
            alias  = PLATFORM_ALIAS
            project.logger.lifecycle("[KeystoreGeneratorPlugin] ✅ Platform cert fallback loaded (android@android.com)")
        }

        project.ext.ks_storeFile = ksFile
        project.ext.ks_storePass = pass
        project.ext.ks_keyAlias  = alias
        project.ext.ks_keyPass   = pass

        def credsFile = new File(outputDir, "ks_creds_${project.name}.properties")
        credsFile.text = """ks_file=${ksFile.absolutePath}
ks_pass=${pass}
ks_alias=${alias}
"""
        project.ext.ks_credsFile = credsFile.absolutePath
        project.logger.lifecycle("[KeystoreGeneratorPlugin] 📝 Credentials written: ${credsFile.name}")
        project.logger.lifecycle("[KeystoreGeneratorPlugin] ℹ️  Keystore wipe deferred to generate_batch.sh post-resign")
    }

    /**
     * Step 6: Multi-pass secure wipe.
     * Pass 1: overwrite with 0x00
     * Pass 2: overwrite with 0xFF
     * Pass 3: overwrite with random bytes
     * Then delete.
     */
    static void secureWipe(File file, Project project) {
        if (!file.exists()) return
        try {
            long len = file.length()
            if (len > 0) {
                def rng = new java.security.SecureRandom()
                // Pass 1 — zeros
                file.withOutputStream { os ->
                    def zeros = new byte[4096]
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        os.write(zeros, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }
                // Pass 2 — 0xFF
                file.withOutputStream { os ->
                    def ones = new byte[4096]
                    java.util.Arrays.fill(ones, (byte) 0xFF)
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        os.write(ones, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }
                // Pass 3 — random
                file.withOutputStream { os ->
                    def buf = new byte[4096]
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        rng.nextBytes(buf)
                        os.write(buf, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }
            }
            file.delete()
            project.logger.lifecycle("[KeystoreGeneratorPlugin] 🔒 Secure wiped (3-pass): ${file.name}")
        } catch (Exception e) {
            file.delete()
            project.logger.warn("[KeystoreGeneratorPlugin] ⚠️ Wipe failed, deleted: ${file.name} — ${e.message}")
        }
    }
}

class KeystoreGeneratorExtension {
    File   outputDir
    String label
}
