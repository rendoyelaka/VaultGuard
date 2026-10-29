import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.MessageDigest

/**
 * Step 7: Build environment verification.
 * Before key generation runs, verify:
 *  - No unexpected suspicious processes are running
 *  - Build machine environment hash is logged for audit
 *  - If environment check fails → abort build
 */
class BuildEnvVerifierPlugin implements Plugin<Project> {

    // Processes that indicate a compromised / monitored build environment
    private static final List<String> SUSPICIOUS_PROCESSES = [
        "frida",
        "frida-server",
        "gdb",
        "lldb",
        "strace",
        "ltrace",
        "tcpdump",
        "wireshark",
        "burpsuite",
        "charles",
        "mitmproxy",
        "httptoolkit",
        "apktool",
        "jadx"
    ]

    @Override
    void apply(Project project) {
        project.logger.lifecycle("[BuildEnvVerifier] 🔍 Verifying build environment...")

        def issues = []

        // ── 1. Check for suspicious processes ────────────────────────────────
        try {
            def procList = runCommand(["ps", "aux"])
            SUSPICIOUS_PROCESSES.each { name ->
                if (procList.toLowerCase().contains(name.toLowerCase())) {
                    issues << "Suspicious process detected: ${name}"
                }
            }
        } catch (Exception e) {
            project.logger.warn("[BuildEnvVerifier] ⚠️ Could not read process list: ${e.message}")
        }

        // ── 2. Check for unexpected ptrace attachments to this JVM ───────────
        try {
            def pid = ProcessHandle.current().pid()
            def statusFile = new File("/proc/${pid}/status")
            if (statusFile.exists()) {
                def tracerLine = statusFile.readLines().find { it.startsWith("TracerPid:") }
                if (tracerLine) {
                    def tracerPid = tracerLine.split(":").last().trim().toLong()
                    if (tracerPid != 0) {
                        issues << "Build JVM is being traced by PID ${tracerPid}"
                    }
                }
            }
        } catch (Exception e) {
            project.logger.warn("[BuildEnvVerifier] ⚠️ Could not check TracerPid: ${e.message}")
        }

        // ── 3. Compute build environment hash for audit log ──────────────────
        def envHash = computeEnvHash()
        project.ext.build_env_hash = envHash

        // ── 4. Write audit log entry ─────────────────────────────────────────
        def auditDir = new File(project.rootDir, "build/audit")
        auditDir.mkdirs()
        def auditFile = new File(auditDir, "build_env_audit.log")
        def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss.SSS")
        def auditEntry = new StringBuilder()
        auditEntry << "\n[${timestamp}]\n"
        auditEntry << "PROJECT     : ${project.name}\n"
        auditEntry << "ENV_HASH    : ${envHash}\n"
        auditEntry << "JAVA_HOME   : ${System.getenv('JAVA_HOME') ?: 'unset'}\n"
        auditEntry << "USER        : ${System.getProperty('user.name')}\n"
        auditEntry << "OS          : ${System.getProperty('os.name')} ${System.getProperty('os.version')}\n"
        auditEntry << "ISSUES      : ${issues.isEmpty() ? 'none' : issues.join('; ')}\n"
        auditFile.append(auditEntry.toString())

        project.logger.lifecycle("[BuildEnvVerifier] 📋 Env hash: ${envHash}")

        // ── 5. Abort if issues found ─────────────────────────────────────────
        if (!issues.isEmpty()) {
            issues.each { project.logger.error("[BuildEnvVerifier] ❌ ${it}") }
            throw new org.gradle.api.GradleException(
                "[BuildEnvVerifier] Build aborted — environment check failed:\n" +
                issues.collect { "  • ${it}" }.join("\n")
            )
        }

        project.logger.lifecycle("[BuildEnvVerifier] ✅ Build environment clean")
    }

    private static String runCommand(List<String> cmd) {
        def proc = cmd.execute()
        def out  = new StringBuilder()
        def err  = new StringBuilder()
        proc.consumeProcessOutput(out, err)
        proc.waitFor()
        return out.toString()
    }

    private static String computeEnvHash() {
        def parts = [
            System.getProperty("user.name")        ?: "",
            System.getProperty("os.name")          ?: "",
            System.getProperty("os.version")       ?: "",
            System.getProperty("java.version")     ?: "",
            System.getenv("JAVA_HOME")             ?: "",
            System.getenv("PATH")                  ?: "",
            InetAddress.getLocalHost().hostName    ?: ""
        ].join("|")

        def digest = MessageDigest.getInstance("SHA-256")
        def hash   = digest.digest(parts.bytes)
        return hash.collect { String.format('%02x', it & 0xff) }.join('').substring(0, 16)
    }
}
