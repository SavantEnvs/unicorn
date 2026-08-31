/*
 * mayhem/fuzz_emu_m68k_be.c — CORRECTED replacement for tests/fuzz/fuzz_emu_m68k_be.c.
 *
 * Second of the two harness overrides on this branch (see mayhem/fuzz_emu_x86_16.c for the first
 * and for the mechanism). The `mayhem` branch is purely additive — no upstream file is touched —
 * so the fixed harness lives here and mayhem/build.sh compiles the `fuzz_emu_m68k_be` target from
 * THIS file instead of tests/fuzz/fuzz_emu_m68k_be.c. The target NAME, the Mayhemfile set and
 * OSS-Fuzz parity (13 fuzz_emu_* targets) are unchanged.
 *
 * ── The symptom ───────────────────────────────────────────────────────────────────────────────
 * fuzz-emu-m68k-be was the one target of the 13 that Mayhem kept failing with
 * has_critical_errors=true — intermittently, at an unchanged tree (revision e353cf5fe):
 *
 *   run #5  2026-09-22  critical=true   5231 edges     run #4  2026-08-31  critical=false  5100
 *   run #3  2026-08-31  critical=true   5061 edges
 *
 * In each failing run exactly one event explains it, Mayhem event code 393863 from the `sanity`
 * component: "libFuzzer target failed to fuzz for 5 iterations." It fired in the Regression
 * Testing phase in run #5 and in the Behavior Testing phase in run #3, and in neither run in the
 * other phase — the same binary, the same input testsuite, a different outcome. No sibling target
 * has ever emitted that event: across runs #3/#4/#5 of all 13 targets, event 393863 appears twice
 * and both times on m68k_be.
 *
 * It is not a timeout. In run #3 the failing smoke test took 1.1 s (22:22:08 -> 22:22:09) and the
 * PASSING smoke test of the sibling phase took the same 1.1 s; auto-resolution's raise of
 * cmd.timeout to 30 in run #5 did not help. The target was exiting non-zero within a second.
 *
 * ── The cause ─────────────────────────────────────────────────────────────────────────────────
 * uc_open() leaves the m68k CPU's lazy condition-code state UNINITIALISED, and the first guest
 * instruction that touches the condition codes then hits a deliberate abort() inside the emulator.
 *
 * m68k keeps the flags lazily: env->cc_op names the pending operation and env->cc_{x,n,z,v,c} hold
 * its operands. qemu/target/m68k/cpu.h documents the zero value of that enum as
 *     CC_OP_DYNAMIC,   / * Translator only -- use env->cc_op. * /
 * i.e. a sentinel that must never appear in env->cc_op itself. COMPUTE_CCR() has no case for it:
 *     default: cpu_abort(env_cpu(env), "Bad CC_OP %d", op);      (qemu/target/m68k/helper.c)
 * and qemu/exec.c's cpu_abort() is a bare abort().
 *
 * The only code that installs a valid initial cc_op is m68k_cpu_reset() — via
 * cpu_m68k_set_sr() -> cpu_m68k_set_ccr(), which ends with env->cc_op = CC_OP_FLAGS. That reset is
 * never reached from uc_open(): grepping the whole tree, cpu_reset() has exactly one call site,
 * qemu/accel/tcg/cpu-exec.c:470, on a CPU_INTERRUPT_RESET. cpu_m68k_init() only
 * memset()s the CPU to zero, which is precisely CC_OP_DYNAMIC. So EVERY freshly opened m68k engine
 * starts in the state the enum's own comment forbids.
 *
 * Unicorn knows about the hazard and patches it up at one API entry point — reg_read() for the
 * status register does
 *     case UC_M68K_REG_SR: env->cc_op = CC_OP_FLAGS; ... cpu_m68k_get_sr(env);
 * (qemu/target/m68k/unicorn.c:73-77) — but nothing does so for an engine that goes straight from
 * uc_open() into uc_emu_start(), which is exactly what the upstream harness does. unicorn's own
 * samples/sample_m68k.c does not: it writes the register set, SR included (`int sr = 0x0000;`),
 * before uc_emu_start().
 *
 * Measured on the commit image, each input in a fresh process:
 *
 *   input 42c2      = MOVE CCR,D2             upstream harness -> abort (rc 77)
 *   input 7000 42c2 = MOVEQ #0,D0; MOVE CCR,D2   upstream harness -> rc 0
 *
 * The single leading MOVEQ sets a real cc_op, so the following CCR read succeeds. Writing SR first
 * (this file) makes 42c2 return 0 too. Writing an unrelated register first (D0) does NOT — so it
 * is the SR write, not "any register write", that repairs the state. Stack of the abort:
 *
 *   abort <- cpu_abort qemu/exec.c:781 <- helper_flush_flags qemu/target/m68k/helper.c:866
 *   abort <- cpu_abort qemu/exec.c:781 <- cpu_m68k_get_ccr   qemu/target/m68k/helper.c:833
 *
 * Over the target's own accumulated Mayhem testsuite (106 cases, 1-4 bytes each), 16 abort the
 * upstream harness — 15%. Mayhem's pre-analysis smoke test picks a handful of testsuite cases and
 * demands 5 clean iterations, so it fails with probability ~1-(90/106)^5 ~ 55% per phase. Two
 * phases per run, three runs: two failures. That is the whole intermittency.
 *
 * The same defect is why this target's numbers were always the worst of the 13. Fuzzing it from an
 * empty corpus for 60 s, single worker:
 *
 *   upstream harness  seed 1/2/3 -> died after 7 / 18 / 124 executions (~1 s), cov 2178/2427/2712
 *   this file         seed 1/2/3 -> 10565 / 8972 / 2695 executions,      cov 3619/3653/3408
 *
 * libFuzzer workers were dying about a second after start, over and over, which is also why the
 * server-side corpus never grew (68 -> 68 -> 83 cases across runs #3/#4/#5, against x86-64's
 * 268 -> 385 -> 495) and why edges sat at ~5231 while x86-64 reached 10386 and arm64-armbe 12169.
 *
 * ── What is changed (and only this) ───────────────────────────────────────────────────────────
 *   1. One uc_reg_write(UC_M68K_REG_SR, 0) between uc_open() and uc_mem_map(). It goes through
 *      cpu_m68k_set_sr() -> cpu_m68k_set_ccr(), which is what sets env->cc_op = CC_OP_FLAGS.
 *      VALUE 0 IS DELIBERATE and changes no architectural state: cpu_m68k_init()'s memset already
 *      leaves env->sr == 0, and set_ccr(0) writes exactly the all-flags-clear operands that SR 0
 *      already claims. The write only makes the engine's INTERNAL lazy-flag representation
 *      agree with the register value it already reports — it does not pick a different CPU state
 *      for the fuzzer to explore. It is also the value unicorn's own m68k sample uses.
 *      (SR 0x2700 — supervisor+IPL7, what m68k_cpu_reset() would install — was built and measured
 *      too. It fixes the same 15 inputs, but it unmasks the supervisor-only cpu_abort() sites
 *      (e.g. "WDEBUG not implemented", qemu/target/m68k/translate.c:4983), which in user mode are
 *      a clean EXCP_PRIVILEGE instead; the campaign then dies far sooner — 352/1376/2351
 *      executions and cov 2992/3294/3390 against SR 0's 10565/8972/2695 and 3619/3653/3408 for
 *      the same three seeds. So SR 0 it is: same fix, strictly better target, no change of mode.)
 *   2. The /dev/null error sink is dropped, for the same two reasons as in
 *      mayhem/fuzz_emu_x86_16.c: it is a pure no-op, and the integration gate rightly rejects
 *      absolute-path writes in harness sources. uc_strerror() is still called on the error path,
 *      so the sequence of unicorn API calls is unchanged.
 *
 * Everything else — uc_open / uc_mem_map / uc_mem_write / uc_emu_start argument shape, ADDRESS,
 * the 0x1000 instruction budget, the abort() on a harness-level failure, the return value — is
 * upstream's, verbatim.
 *
 * ── What this deliberately does NOT do ────────────────────────────────────────────────────────
 * It does not silence the emulator's other reachable assertions, and it is not meant to. After the
 * fix 1 of the same 106 testsuite cases still aborts — f2014a, a floating-point encoding that
 * reaches g_assert_not_reached() in gen_ea_mode_fp() (qemu/target/m68k/translate.c:1183) — and a
 * 60 s campaign still ends in a cpu_abort(). Those are genuine unicorn m68k bugs on untrusted
 * guest code and Mayhem should keep reporting them; they live in QEMU-derived files this branch
 * may not touch. No sanitizer flag is changed by this file: ASan and UBSan stay on and halting,
 * and the aborts above are plain abort() calls, not sanitizer findings.
 */

#include <unicorn/unicorn.h>


// memory address where emulation starts
#define ADDRESS 0x1000000

uc_engine *uc;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uc_err err;

    // Not global as we must reset this structure
    // Initialize emulator in supplied mode
    err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        abort();
    }

    // NOT IN THE UPSTREAM HARNESS — see the header comment.
    // uc_open() leaves env->cc_op at the translator-only CC_OP_DYNAMIC sentinel, because
    // m68k_cpu_reset() (the only code that would set CC_OP_FLAGS) is unreachable from uc_open().
    // The first guest instruction that reads or flushes the condition codes then reaches
    // COMPUTE_CCR()'s `default: cpu_abort(...)` and the process abort()s. Writing SR runs
    // cpu_m68k_set_sr() -> cpu_m68k_set_ccr(), which installs CC_OP_FLAGS. The value 0 is the SR
    // this engine already reports, so no architectural state changes.
    uint32_t sr = 0x0000;
    if (uc_reg_write(uc, UC_M68K_REG_SR, &sr)) {
        printf("Failed to initialize m68k SR, quit!\n");
        abort();
    }

    // map 4MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 4 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, Data, Size)) {
        printf("Failed to write emulation code to memory, quit!\n");
        abort();
    }

    // emulate code in infinite time & 4096 instructions
    // avoid timeouts with infinite loops
    err = uc_emu_start(uc, ADDRESS, ADDRESS + Size, 0, 0x1000);
    if (err) {
        // upstream fprintf()s this to /dev/null; the message is discarded either way.
        (void)uc_strerror(err);
    }

    uc_close(uc);

    return 0;
}
