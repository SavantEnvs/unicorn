#!/usr/bin/env bash
#
# mayhem/build.sh — build unicorn's fuzz harnesses (tests/fuzz/fuzz_emu_*.c), a standalone
# run-once reproducer for each, AND unicorn's own unit-test suite (which mayhem/test.sh RUNS).
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) exports the build contract: CC/CXX, LIB_FUZZING_ENGINE,
# SANITIZER_FLAGS, DEBUG_FLAGS, STANDALONE_FUZZ_MAIN, SRC.
#
# Layout produced:
#   /mayhem/fuzz_emu_<arch>              libFuzzer target      (Mayhemfile cmd)
#   /mayhem/fuzz_emu_<arch>-standalone   run-once reproducer   (one input file, natural crash)
#   /mayhem/build-fuzz/libunicorn.a      sanitized+instrumented unicorn (fuzzed code)
#   /mayhem/build-tests/test_*           unicorn's acutest unit tests, NORMAL flags (the oracle)
#
# ── Why the build looks the way it does ──────────────────────────────────────────────────────
# 1. UNICORN_FUZZ=ON is required even though we link the harnesses ourselves: it is the ONLY
#    switch that forwards ${CMAKE_C_FLAGS} into the bundled-QEMU sub-configure
#    (`--extra-cflags=`, CMakeLists.txt:323). Without it the emulator core — i.e. the code we
#    are actually fuzzing — is built WITHOUT sanitizers and without coverage instrumentation.
# 2. -fsanitize=fuzzer-no-link on the library build: $SANITIZER_FLAGS is ASan+UBSan only and
#    carries no SanitizerCoverage, so without this libFuzzer runs blind over libunicorn.a
#    (targets execute but record edges=0 forever). It is a per-TU COMPILE flag; the `-fsanitize=fuzzer`
#    at link only supplies the runtime.
# 3. UBSan relaxations — three checks are disabled for the QEMU-derived code, everything else in
#    ASan+UBSan stays ON and HALTING (-fno-sanitize-recover=all):
#      * function          — MANDATORY, not cosmetic. QEMU's TCG calls JIT-generated code through a
#                            function pointer; the `function` check reads a type signature stored
#                            *before* the callee, and the JIT buffer has no such prologue, so the
#                            check itself SEGVs at (code_gen_buffer - 8) inside cpu_tb_exec() on the
#                            very FIRST input of every target. Also fires benignly on glib_compat's
#                            GDestroyNotify casts (glib_compat.c:816 -> flatview_unref_*).
#      * pointer-overflow  — fires on the first input of all 13 targets on QEMU's idiomatic
#                            "offset from a NULL base" arithmetic (softmmu/memory.c:1465 zero offset,
#                            include/tcg/tcg.h:987 non-zero offset 120). Nothing memory-unsafe.
#      * shift-base        — QEMU's translators left-shift negative/large ints as a matter of course
#                            (target/{arm,mips,sparc,s390x}/translate.c, fpu/softfloat.h). Measured:
#                            this alone killed 7 of 13 targets within seconds of campaign start.
#                            NOTE only the *base* operand check is relaxed — `shift-exponent`
#                            (shifting by >= the type width) stays halting, as do
#                            signed-integer-overflow, alignment, bounds, divide-by-zero, null, etc.
#    Rationale matches the porting skill's "UBSan checks that flood on benign patterns may be
#    selectively relaxed"; upstream OSS-Fuzz builds unicorn with SANITIZER=address only (no UBSan).
#    The relaxations are appended only when $SANITIZER_FLAGS actually enables UBSan, so an explicit
#    `--build-arg SANITIZER_FLAGS=` (no-sanitizer repro build) is unaffected.
# 4. Standalone reproducers use unicorn's OWN file-input driver tests/fuzz/onefile.c (the project
#    ships one, so per the porting skill we use it instead of $STANDALONE_FUZZ_MAIN).
# 4b. HARNESS OVERRIDES: the target set and target NAMES come from tests/fuzz/fuzz_emu_*.c
#    (OSS-Fuzz parity), but if mayhem/<name>.c exists it is compiled INSTEAD of the upstream
#    file for that target. `mayhem` is purely additive, so a harness upstream got wrong is fixed
#    by adding a corrected copy here rather than by editing tests/fuzz/. Two overrides exist
#    today, each with the evidence in its own header, and each announced in the build log:
#      * mayhem/fuzz_emu_x86_16.c — upstream's x86_16 harness is a copy of the x86_32 one and
#        keeps ADDRESS 0x1000000, which real mode cannot fetch from (EIP truncates to 16 bits ->
#        linear 0, unmapped), so uc_emu_start() returned UC_ERR_FETCH_UNMAPPED on every input and
#        the target covered 0 edges.
#      * mayhem/fuzz_emu_m68k_be.c — uc_open() leaves env->cc_op at the translator-only
#        CC_OP_DYNAMIC sentinel (m68k_cpu_reset() is unreachable from uc_open()), so the first
#        guest instruction that touches the condition codes hits COMPUTE_CCR()'s
#        `default: cpu_abort(...)` and abort()s. 16 of the 106 cases in the target's own Mayhem
#        testsuite did that, which is what kept failing Mayhem's 5-iteration smoke test. The
#        override writes UC_M68K_REG_SR (0) after uc_open(), which installs CC_OP_FLAGS.
# 5. The build is INCREMENTAL on purpose (no rm -rf): re-running build.sh in the already-built
#    image is a near no-op, which is what the idempotent + air-gapped re-run gate wants. Nothing
#    here touches the network — CMake + the bundled QEMU configure only, no FetchContent/pkg fetch.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FUZZ_BUILD="$SRC/build-fuzz"
TEST_BUILD="$SRC/build-tests"

# UBSan relaxations (see note 3) — only when UBSan is actually on.
UBSAN_RELAX=""
case "$SANITIZER_FLAGS" in
  *undefined*) UBSAN_RELAX="-fno-sanitize=function,pointer-overflow,shift-base" ;;
esac

# SanitizerCoverage for libFuzzer (see note 2). Dropped when the caller explicitly asks for a
# sanitizer-free build: nothing would then define the __sanitizer_cov_* callbacks the instrumented
# objects call, and the standalone reproducers (which link no fuzzing runtime) would not link.
FUZZ_COV="-fsanitize=fuzzer-no-link"
[ -n "${SANITIZER_FLAGS// /}" ] || FUZZ_COV=""

FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $FUZZ_COV"

# ── 1) unicorn itself, sanitized + coverage-instrumented (this is the fuzzed code) ────────────
cmake -S "$SRC" -B "$FUZZ_BUILD" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER="$CC" \
  -DBUILD_SHARED_LIBS=OFF \
  -DUNICORN_FUZZ=ON \
  -DUNICORN_BUILD_TESTS=OFF \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS"
# `unicorn_archive` is the bundled static lib (libunicorn.a: unicorn + every *-softmmu + common).
# Building just it skips CMake's own 13 fuzz_emu executables, which link the project's directory
# driver (onedir.c) and are not the binaries Mayhem runs.
cmake --build "$FUZZ_BUILD" --target unicorn_archive -j"$MAYHEM_JOBS"

UCLIB="$FUZZ_BUILD/libunicorn.a"
[ -f "$UCLIB" ] || { echo "build.sh: $UCLIB was not produced" >&2; exit 1; }

# Build-time LSan-off hook (SPEC.md 6.1, mayhem/lsan_off.c). Replaces a forbidden runtime ASan
# options override; linked into every sanitized binary below so the hook is actually resolved.
LSAN_OBJ="$FUZZ_BUILD/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$LSAN_OBJ"

# ── 2) one libFuzzer binary + one standalone reproducer per harness ───────────────────────────
n=0
for src in "$SRC"/tests/fuzz/fuzz_emu_*.c; do
  t="$(basename "$src" .c)"
  n=$((n + 1))
  # Harness override (see note 4b): mayhem/<target>.c wins over the upstream file, same name.
  if [ -f "$SRC/mayhem/$t.c" ]; then
    echo "build.sh: $t -> using harness override mayhem/$t.c (upstream tests/fuzz/$t.c is not built)"
    src="$SRC/mayhem/$t.c"
  fi
  # libFuzzer target
  $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      -I"$SRC/include" "$src" "$LSAN_OBJ" "$UCLIB" -lpthread -lrt -lm \
      -o "/mayhem/$t"
  # standalone run-once reproducer (unicorn's own tests/fuzz/onefile.c driver: argv[1] = input file)
  $CC $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS \
      -I"$SRC/include" "$src" "$SRC/tests/fuzz/onefile.c" "$LSAN_OBJ" "$UCLIB" -lpthread -lrt -lm \
      -o "/mayhem/$t-standalone"
done
[ "$n" -eq 13 ] || { echo "build.sh: expected 13 fuzz_emu harnesses, built $n" >&2; exit 1; }

# ── 3) unicorn's own unit tests, NORMAL flags — a separate, clean build (the honest oracle) ────
# mayhem/test.sh only RUNS these; it must never compile.
cmake -S "$SRC" -B "$TEST_BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DBUILD_SHARED_LIBS=OFF \
  -DUNICORN_FUZZ=OFF \
  -DUNICORN_BUILD_TESTS=ON \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS"
cmake --build "$TEST_BUILD" -j"$MAYHEM_JOBS"

ntests=0
for b in "$TEST_BUILD"/test_*; do [ -x "$b" ] && [ -f "$b" ] && ntests=$((ntests + 1)); done
[ "$ntests" -ge 12 ] || { echo "build.sh: expected >=12 unit-test binaries, found $ntests" >&2; exit 1; }

echo "build.sh: OK — $n fuzz targets (+ standalone reproducers), $ntests unit-test binaries"
