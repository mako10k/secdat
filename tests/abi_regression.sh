#!/usr/bin/env bash

set -euo pipefail

# GNU binutils localizes human-readable labels such as readelf's SONAME
# description. Keep every tool-output parser in this regression deterministic.
export LC_ALL=C
export LANGUAGE=C

library_path="${1:-}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

test -n "$library_path" || fail "libsecdat path is required"
test -f "$library_path" || fail "libsecdat not found at $library_path"
command -v nm >/dev/null 2>&1 || fail "nm is required"
command -v readelf >/dev/null 2>&1 || fail "readelf is required"

symbols=$(nm -D --defined-only "$library_path" | awk '{ print $3 }')
required_symbols='
secdat_sdk_classify_exec_json_field
secdat_sdk_collect_status
secdat_sdk_cp
secdat_sdk_describe_redaction_class
secdat_sdk_exec_plan_json
secdat_sdk_exists
secdat_sdk_free
secdat_sdk_get
secdat_sdk_list_domains
secdat_sdk_list_keys
secdat_sdk_list_keys_with_patterns
secdat_sdk_list_stores
secdat_sdk_lock
secdat_sdk_mask
secdat_sdk_mv
secdat_sdk_redaction_class_name
secdat_sdk_redaction_display_label
secdat_sdk_redaction_policy_name
secdat_sdk_redaction_value_allowed
secdat_sdk_relation_suggest_refresh
secdat_sdk_resize_preserve_attrs
secdat_sdk_rm
secdat_sdk_set
secdat_sdk_set_preserve_attrs
secdat_sdk_unlock
secdat_sdk_unmask
secdat_sdk_wait_unlock
secdat_sdk_write_at_preserve_attrs
'

while IFS= read -r symbol; do
    test -z "$symbol" && continue
    printf '%s\n' "$symbols" | grep -Fxq "$symbol" || fail "missing ABI symbol $symbol"
done <<<"$required_symbols"

readelf -d "$library_path" | grep -Fq 'Library soname: [libsecdat.so.0]' ||
    fail "libsecdat SONAME is not libsecdat.so.0"

resolved_library=$(readlink -f "$library_path")
test "$(basename "$resolved_library")" = "libsecdat.so.0.1.0" ||
    fail "libsecdat artifact is $(basename "$resolved_library"), expected libsecdat.so.0.1.0"

printf 'PASS ABI regression (libsecdat.so.0 -> libsecdat.so.0.1.0)\n'
