/*
 * mayhem/fuzz_emu_x86_16.c — CORRECTED replacement for tests/fuzz/fuzz_emu_x86_16.c.
 *
 * One of the two harnesses Mayhem does not take verbatim from upstream (the other is
 * mayhem/fuzz_emu_m68k_be.c), and the deviation is deliberate. The `mayhem` branch must stay
 * purely additive (no upstream file is touched), so the
 * fixed harness lives here and mayhem/build.sh compiles the `fuzz_emu_x86_16` target from THIS
 * file instead of tests/fuzz/fuzz_emu_x86_16.c. The target NAME, the Mayhemfile set and OSS-Fuzz
 * parity (13 fuzz_emu_* targets) are unchanged.
 *
 * ── What upstream does ────────────────────────────────────────────────────────────────────────
 * tests/fuzz/fuzz_emu_x86_16.c is byte-identical to tests/fuzz/fuzz_emu_x86_32.c except for
 * `uc_open(UC_ARCH_X86, UC_MODE_16, &uc)` (32 -> 16). It keeps the 32-bit file's
 *     #define ADDRESS 0x1000000            // 16 MB
 * and does uc_mem_map(ADDRESS, 4MB) / uc_mem_write(ADDRESS, Data, Size) /
 * uc_emu_start(ADDRESS, ADDRESS + Size, 0, 0x1000).
 *
 * ── Why that covers nothing ───────────────────────────────────────────────────────────────────
 * x86 16-bit is real mode: EIP is truncated to 16 bits and the fetch address is CS.base + IP.
 * With CS.base = 0, starting at 0x1000000 fetches from linear (0x1000000 & 0xFFFF) == 0, which is
 * NOT mapped — the only mapping is at 16 MB. uc_emu_start() therefore fails immediately, on
 * EVERY input, before a single guest instruction is translated. Measured against this tree with a
 * UC_HOOK_CODE instruction counter:
 *
 *   MODE_16, map+write+start 0x1000000 (upstream)  -> err=8 UC_ERR_FETCH_UNMAPPED, insns=0
 *   MODE_32, map+write+start 0x1000000 (x86_32)    -> err=0 UC_ERR_OK,             insns=4
 *   MODE_16, map+write+start 0x1000   (this file)  -> err=0 UC_ERR_OK,             insns=6
 * and, proving 16-bit truncation is the mechanism, MODE_16 started at 0x11000 with the code
 * written at 0x1000 executes that code: the first hooked PC is 0x1000, not 0x11000.
 *
 * The upstream harness catches the error, prints it to a /dev/null FILE* and returns 0, so the
 * target runs "successfully" forever while never entering the emulator core. On Mayhem, runs #1
 * and #2 both ended cleanly after ~104,000 tests with edges_covered = 0, while the other 12
 * targets from the same build reported 2,630-9,430 edges. A seed corpus cannot help: no byte of
 * any input is ever decoded. Confirmed with libFuzzer on the commit image — the upstream harness
 * does 100,000 executions with `cov: 1555 ft: 1556` unchanged from the first pulse to the last
 * and `new_units_added: 0`. It is pinned to uc_emu_start()'s error return forever.
 *
 * ── What is changed (and only this) ───────────────────────────────────────────────────────────
 *   1. ADDRESS 0x1000000 -> 0x1000: an entry point real mode can actually fetch from. This is the
 *      whole fix; every uc_* call keeps upstream's argument shape, uc_mem_map() included, so the
 *      4 MB mapping still sits AT ADDRESS.
 *      (Mapping from 0 instead — so the full real-mode address space is backed — was tried and
 *      rejected. It makes low memory writable, so an input that runs off its own end into zero
 *      bytes keeps executing `add [bx+si],al` against mapped memory for the whole 0x1000
 *      instruction budget instead of faulting: measured 2151 emulated instructions per execution
 *      at 40 exec/s, against 63 instructions at 405 exec/s with the mapping left at ADDRESS
 *      (x86_32, for scale: 22 instructions, 727 exec/s). Same code paths, ten times the
 *      throughput, so the mapping stays exactly where upstream puts it.)
 *   2. The /dev/null error sink is dropped. It is a pure no-op — the message goes nowhere — and
 *      the integration gate rightly rejects absolute-path writes in harness sources. uc_strerror()
 *      is still called on the error path, so the sequence of unicorn API calls is unchanged.
 * Everything else — uc_open / uc_mem_map / uc_mem_write / uc_emu_start argument shape, the 0x1000
 * instruction budget, the abort() on a harness-level failure, the return value — is upstream's,
 * verbatim.
 */

#include <unicorn/unicorn.h>


// memory address where emulation starts.
// UPSTREAM USES 0x1000000 (16 MB), which real mode cannot fetch from — see the header comment.
#define ADDRESS 0x1000

uc_engine *uc;


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uc_err err;

    // Not global as we must reset this structure
    // Initialize emulator in supplied mode
    err = uc_open(UC_ARCH_X86, UC_MODE_16, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
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
