#!/usr/bin/env bash

set -euo pipefail

source_root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
source_root="$(cd "$source_root" && pwd -P)"
jscpd_bin="${JSCPD:-jscpd}"
lizard_bin="${LIZARD:-lizard}"
jscpd_expected_version="${JSCPD_EXPECTED_VERSION:-4.0.7}"
lizard_expected_version="${LIZARD_EXPECTED_VERSION:-1.23.0}"
jscpd_duplication_limit="0.34"
lizard_warning_budget=171
analysis_paths=(
    src
    bindings/go/secdat
    bindings/node/src
    bindings/python/secdat_sdk.py
    bindings/rust/src
)

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

require_tool() {
    local tool="$1"

    command -v "$tool" >/dev/null 2>&1 ||
        fail "required static-analysis tool is unavailable: $tool"
}

require_tool "$jscpd_bin"
require_tool "$lizard_bin"

jscpd_version="$($jscpd_bin --version)"
lizard_version="$($lizard_bin --version)"
test "$jscpd_version" = "$jscpd_expected_version" ||
    fail "jscpd version is $jscpd_version, expected $jscpd_expected_version"
test "$lizard_version" = "$lizard_expected_version" ||
    fail "lizard version is $lizard_version, expected $lizard_expected_version"

cd "$source_root"

if ! jscpd_output=$(
    "$jscpd_bin" \
        --min-lines 20 \
        --min-tokens 200 \
        --max-lines 5000 \
        --max-size 1mb \
        --threshold "$jscpd_duplication_limit" \
        --reporters console \
        --mode strict \
        --noSymlinks \
        "${analysis_paths[@]}" 2>&1
); then
    printf '%s\n' "$jscpd_output" >&2
    fail "jscpd duplication ceiling exceeded or analysis failed"
fi

if ! lizard_output=$(
    "$lizard_bin" \
        -C 15 \
        -L 1000 \
        -a 10 \
        -i "$lizard_warning_budget" \
        -w \
        "${analysis_paths[@]}" 2>&1
); then
    printf '%s\n' "$lizard_output" >&2
    fail "lizard warning budget exceeded or analysis failed"
fi

lizard_warning_count=$(
    printf '%s\n' "$lizard_output" | grep -c ': warning:' || true
)
test "$lizard_warning_count" -le "$lizard_warning_budget" ||
    fail "lizard emitted $lizard_warning_count warnings, budget is $lizard_warning_budget"

printf 'PASS static analysis (jscpd=%s duplication<%s%%; lizard=%s warnings=%s/%s)\n' \
    "$jscpd_version" \
    "$jscpd_duplication_limit" \
    "$lizard_version" \
    "$lizard_warning_count" \
    "$lizard_warning_budget"
