#!/usr/bin/env bash

set -euo pipefail

source_root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
source_root="$(cd "$source_root" && pwd -P)"
analysis_script="$source_root/tests/static_analysis_regression.sh"
work_root="$(mktemp -d)"
trap 'rm -rf -- "$work_root"' EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

cat >"$work_root/jscpd" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if test "${1:-}" = "--version"; then
    printf '%s\n' '4.0.7'
    exit 0
fi
printf '%s\n' "$@" >"$FAKE_JSCPD_ARGS"
printf '%s\n' 'fake jscpd diagnostic'
exit "${FAKE_JSCPD_STATUS:-0}"
EOF

cat >"$work_root/lizard" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if test "${1:-}" = "--version"; then
    printf '%s\n' '1.23.0'
    exit 0
fi
printf '%s\n' "$@" >"$FAKE_LIZARD_ARGS"
exit "${FAKE_LIZARD_STATUS:-0}"
EOF
chmod +x "$work_root/jscpd" "$work_root/lizard"

fake_jscpd_args="$work_root/jscpd.args"
fake_lizard_args="$work_root/lizard.args"
success_output=$(
    FAKE_JSCPD_ARGS="$fake_jscpd_args" \
    FAKE_LIZARD_ARGS="$fake_lizard_args" \
    JSCPD="$work_root/jscpd" \
    LIZARD="$work_root/lizard" \
    bash "$analysis_script" "$source_root"
)
grep -Fq 'PASS static analysis' <<<"$success_output" ||
    fail "fake analyzer success did not produce the PASS receipt"

expect_argument_pair() {
    local path="$1"
    local option="$2"
    local value="$3"

    awk -v option="$option" -v value="$value" '
        $0 == option {
            if (getline > 0 && $0 == value) {
                found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    ' "$path" || fail "missing analyzer argument pair: $option $value"
}

expect_argument_pair "$fake_jscpd_args" --min-lines 20
expect_argument_pair "$fake_jscpd_args" --min-tokens 200
expect_argument_pair "$fake_jscpd_args" --max-lines 5000
expect_argument_pair "$fake_jscpd_args" --threshold 0.34
grep -Fxq 'src' "$fake_jscpd_args" || fail "jscpd source boundary is missing"
expect_argument_pair "$fake_lizard_args" -C 15
expect_argument_pair "$fake_lizard_args" -L 1000
expect_argument_pair "$fake_lizard_args" -a 10
expect_argument_pair "$fake_lizard_args" -i 171
grep -Fxq 'src' "$fake_lizard_args" || fail "lizard source boundary is missing"

missing_stderr="$work_root/missing.stderr"
if JSCPD="$work_root/missing-jscpd" LIZARD="$work_root/lizard" \
    bash "$analysis_script" "$source_root" >/dev/null 2>"$missing_stderr"; then
    fail "missing jscpd was accepted"
fi
grep -Fq 'required static-analysis tool is unavailable' "$missing_stderr" ||
    fail "missing jscpd diagnostic is absent"
if JSCPD="$work_root/jscpd" LIZARD="$work_root/missing-lizard" \
    bash "$analysis_script" "$source_root" >/dev/null 2>"$missing_stderr"; then
    fail "missing lizard was accepted"
fi
grep -Fq 'required static-analysis tool is unavailable' "$missing_stderr" ||
    fail "missing lizard diagnostic is absent"

failure_stderr="$work_root/failure.stderr"
if FAKE_JSCPD_ARGS="$fake_jscpd_args" \
    FAKE_LIZARD_ARGS="$fake_lizard_args" \
    FAKE_JSCPD_STATUS=1 \
    JSCPD="$work_root/jscpd" \
    LIZARD="$work_root/lizard" \
    bash "$analysis_script" "$source_root" >/dev/null 2>"$failure_stderr"; then
    fail "jscpd failure was accepted"
fi
grep -Fq 'fake jscpd diagnostic' "$failure_stderr" ||
    fail "jscpd failure details were suppressed"
grep -Fq 'jscpd duplication ceiling exceeded or analysis failed' "$failure_stderr" ||
    fail "jscpd failure summary is absent"

printf 'PASS static analysis contract regression\n'
