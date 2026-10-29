import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * ResRenamerPlugin — DISABLED (Fix 2)
 *
 * Previously renamed res/ filenames to 2-4 random chars per build.
 * This created an obfuscator tool fingerprint that GPP detects:
 *   - 353 obfuscated resource files in APK (IRT target: 6)
 *   - resources.arsc 215KB (IRT target: 4KB)
 *   - 176 stored entries (IRT target: 4)
 *
 * IRT.apk uses real resource names — looks like a legitimate app.
 * Plugin removed from app/build.gradle plugins block.
 * This file kept as no-op so buildSrc compiles cleanly.
 */
class ResRenamerPlugin implements Plugin<Project> {
    @Override
    void apply(Project project) {
        project.logger.lifecycle("[ResRenamerPlugin] Disabled — real resource names preserved (Fix 2)")
    }
}
