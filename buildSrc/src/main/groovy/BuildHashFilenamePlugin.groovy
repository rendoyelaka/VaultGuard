import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom

class BuildHashFilenamePlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        def ext = project.extensions.create('buildHashFilename', BuildHashFilenameExtension)

        // Must run at configuration time, NOT afterEvaluate
        // AGP 8.x locks outputFileName after evaluation
        project.plugins.withId('com.android.application') {
            project.android.applicationVariants.all { variant ->
                if (variant.buildType.name == 'release') {
                    def prefix    = ext.prefix ?: project.name
                    def buildHash = generateBuildHash()
                    def newName   = "${prefix}_${buildHash}.apk"

                    variant.outputs.all { output ->
                        output.outputFileName = newName
                        project.logger.lifecycle("[BuildHashFilenamePlugin] ✅ APK: ${newName}")
                    }
                }
            }
        }
    }

    private static String generateBuildHash() {
        def rng   = new SecureRandom()
        def bytes = new byte[3]
        rng.nextBytes(bytes)
        return bytes.collect { String.format('%02x', it & 0xff) }.join('')
    }
}

class BuildHashFilenameExtension {
    String prefix
}
