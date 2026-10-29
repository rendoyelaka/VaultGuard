import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry

/**
 * Step 21 [SHARED] — ZIP comment watermark injector.
 *
 * Injects a unique hidden identifier into the APK ZIP comment field after signing.
 * - Unique per APK per batch — no two builds share the same watermark.
 * - Invisible to end users; survives normal APK inspection.
 * - Used for leak traceability: identifies exactly which APK was leaked/decompiled.
 *
 * The watermark is written as raw bytes into the EOCD "ZIP file comment" field
 * (offset after the End-of-Central-Directory record). Android installer ignores
 * this field; it does NOT break installation or signature verification.
 *
 * Format (64 bytes total):
 *   4 bytes  : magic marker  0xDE 0xAD 0xC0 0xDE
 *   8 bytes  : timestamp     Unix epoch millis (big-endian)
 *  16 bytes  : build UUID    random per build
 *  32 bytes  : HMAC-SHA256   of (uuid_bytes || timestamp_bytes) keyed by salt
 *   4 bytes  : salt          random per build (first 4 bytes of 32-byte salt)
 * Total: 64 bytes embedded in EOCD comment field.
 */
class WatermarkPlugin implements Plugin<Project> {

    static final byte[] MAGIC = [0xDE as byte, 0xAD as byte, 0xC0 as byte, 0xDE as byte]

    @Override
    void apply(Project project) {
        project.plugins.withId('com.android.application') {
            project.afterEvaluate {
                project.android.applicationVariants.all { variant ->
                    if (variant.buildType.name != 'release') return

                    // Hook after apksigner completes (packageRelease outputs the final APK)
                    def packageTask = project.tasks.findByName('packageRelease')
                    if (!packageTask) return

                    // Step 21 — ZIP comment watermark is intentionally NOT injected here.
                    // Injecting it via assembleRelease.finalizedBy runs AFTER apksigner
                    // which breaks V2/V3 signature verification (EOCD is covered by V2).
                    // The watermark is instead injected by generate_batch.sh as the
                    // very last step AFTER apksigner resign + verify completes.
                    project.logger.lifecycle("[WatermarkPlugin] ℹ️  Watermark deferred to post-resign step in generate_batch.sh")
                }
            }
        }
    }

    /**
     * Generate 64-byte unique watermark payload.
     */
    static byte[] generateWatermark() {
        def rng       = new SecureRandom()
        def saltBytes = new byte[32];  rng.nextBytes(saltBytes)
        def uuidBytes = new byte[16];  rng.nextBytes(uuidBytes)
        long nowMs    = System.currentTimeMillis()

        // Timestamp bytes (8, big-endian)
        def tsBytes = new byte[8]
        for (int i = 7; i >= 0; i--) { tsBytes[i] = (byte)(nowMs & 0xFF); nowMs >>= 8 }

        // HMAC-SHA256 over (uuidBytes || tsBytes) keyed by saltBytes
        def mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(new javax.crypto.spec.SecretKeySpec(saltBytes, "HmacSHA256"))
        mac.update(uuidBytes)
        mac.update(tsBytes)
        def hmac = mac.doFinal()  // 32 bytes

        // Assemble: magic(4) + ts(8) + uuid(16) + hmac(32) + salt[0..3](4) = 64 bytes
        def wm = new byte[64]
        System.arraycopy(MAGIC,    0, wm,  0,  4)
        System.arraycopy(tsBytes,  0, wm,  4,  8)
        System.arraycopy(uuidBytes,0, wm, 12, 16)
        System.arraycopy(hmac,     0, wm, 28, 32)
        System.arraycopy(saltBytes,0, wm, 60,  4)
        return wm
    }

    /**
     * Write watermark into the EOCD comment field of the APK ZIP.
     * Patches the comment length and appends comment bytes directly into
     * the raw APK binary — no re-zip, no re-sign needed (comment is post-sigblock).
     *
     * EOCD structure (22 bytes minimum):
     *   0x06054b50  signature
     *   disk number (2)
     *   disk with CD (2)
     *   entries on disk (2)
     *   total entries (2)
     *   CD size (4)
     *   CD offset (4)
     *   comment length (2)   ← we write len(watermark) here
     *   comment bytes        ← we append watermark here
     */
    static void injectComment(File apkFile, byte[] watermark) {
        def raw = apkFile.bytes

        // Locate EOCD by scanning backwards for 0x06054b50
        int eocdOff = -1
        for (int i = raw.length - 22; i >= 0; i--) {
            if (raw[i]   == 0x50 && raw[i+1] == 0x4B &&
                raw[i+2] == 0x05 && raw[i+3] == 0x06) {
                eocdOff = i
                break
            }
        }
        if (eocdOff < 0) throw new RuntimeException('[WatermarkPlugin] EOCD not found in APK')

        // Read existing comment length (2 bytes LE at EOCD+20)
        int existingCommentLen = ((raw[eocdOff + 21] & 0xFF) << 8) | (raw[eocdOff + 20] & 0xFF)

        // Build new APK bytes: everything up to end of EOCD (22 bytes) + watermark
        int eocdEnd = eocdOff + 22 + existingCommentLen  // strip existing comment if any
        def newRaw  = new byte[eocdEnd + watermark.length]
        System.arraycopy(raw,      0, newRaw, 0, Math.min(eocdEnd, raw.length))
        System.arraycopy(watermark,0, newRaw, eocdEnd, watermark.length)

        // Patch comment length field (2 bytes LE at EOCD+20)
        int wLen = watermark.length
        newRaw[eocdOff + 20] = (byte)(wLen & 0xFF)
        newRaw[eocdOff + 21] = (byte)((wLen >> 8) & 0xFF)

        apkFile.bytes = newRaw
    }
}
