#!/usr/bin/env bash
#
# mayhem/test.sh — RUN unicorn's own unit-test suite (built by mayhem/build.sh into
# $SRC/build-tests with the project's NORMAL flags). Never compiles anything.
#
# Oracle design (§6.3, anti-reward-hacking):
#   The suites are acutest binaries (tests/unit/*.c). We run each with `--tap`, which emits a TAP
#   plan line `1..N` followed by one `ok N - name` / `not ok N - name` per assertion-checked unit
#   test. We assert the OUTPUT: every binary must emit a plan AND exactly as many result lines as
#   the plan promises, and every result must be `ok`. A program neutered to exit(0) emits no TAP at
#   all, so each binary is scored as a failure and this script exits non-zero — which is exactly
#   what the sabotage check requires. `ctest` alone would NOT do: it only inspects exit codes, so a
#   no-op binary would still be reported as 12/12 passing.
#
# Emits a CTRF (https://ctrf.io) summary line — counts are per acutest UNIT TEST (~170), not per
# binary.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TEST_BUILD="$SRC/build-tests"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$TEST_BUILD" ]; then
  echo "test.sh: $TEST_BUILD missing — mayhem/build.sh did not build the unit tests" >&2
  emit_ctrf "acutest" 0 1
  exit 1
fi

shopt -s nullglob
bins=( "$TEST_BUILD"/test_* )
nbin=0
for b in "${bins[@]}"; do [ -f "$b" ] && [ -x "$b" ] && nbin=$((nbin + 1)); done
if [ "$nbin" -lt 12 ]; then
  echo "test.sh: expected >=12 unit-test binaries in $TEST_BUILD, found $nbin — build.sh bug" >&2
  emit_ctrf "acutest" 0 1
  exit 1
fi

passed=0
failed=0

for b in "${bins[@]}"; do
  [ -f "$b" ] && [ -x "$b" ] || continue
  name="$(basename "$b")"
  out="$("$b" --tap 2>&1)"
  rc=$?
  plan="$(printf '%s\n' "$out" | sed -nE 's/^1\.\.([0-9]+)[[:space:]]*$/\1/p' | head -1)"
  ok="$(printf '%s\n' "$out" | grep -cE '^ok [0-9]+ -' )"
  notok="$(printf '%s\n' "$out" | grep -cE '^not ok [0-9]+ -' )"

  if [ -z "$plan" ]; then
    # No TAP plan: the binary produced no asserted output at all (crashed, was neutered, or is not
    # the runner we expect). Score the whole binary as one failure.
    echo "FAIL $name: emitted no TAP plan (rc=$rc)" >&2
    printf '%s\n' "$out" | tail -3 >&2
    failed=$((failed + 1))
    continue
  fi
  if [ "$((ok + notok))" -ne "$plan" ]; then
    echo "FAIL $name: TAP plan promised $plan results, got $((ok + notok)) (rc=$rc) — suite aborted mid-run" >&2
    passed=$((passed + ok))
    failed=$((failed + notok + (plan - ok - notok)))
    continue
  fi
  if [ "$notok" -ne 0 ]; then
    echo "FAIL $name: $notok/$plan unit tests failed" >&2
    printf '%s\n' "$out" | grep -E '^not ok ' >&2
  elif [ "$rc" -ne 0 ]; then
    # Every promised result said "ok" yet the runner still exited non-zero — count it as a failure
    # rather than trusting the TAP body alone.
    echo "FAIL $name: all $plan results were ok but the runner exited $rc" >&2
    failed=$((failed + 1))
  fi
  passed=$((passed + ok))
  failed=$((failed + notok))
done

emit_ctrf "acutest" "$passed" "$failed"
