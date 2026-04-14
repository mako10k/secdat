#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_eq() {
    if [[ "$1" != "$2" ]]; then
        fail "$3: expected [$2], got [$1]"
    fi
}

assert_contains_line() {
    local haystack="$1"
    local needle="$2"

    if ! printf '%s\n' "$haystack" | grep -Fx -- "$needle" >/dev/null; then
        fail "missing line [$needle] in [$haystack]"
    fi
}

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

export XDG_DATA_HOME="$work_root/xdg"
export SECDAT_MASTER_KEY='test-master-key'

root="$work_root/work/root"
child="$root/child"
mkdir -p "$root" "$child" "$XDG_DATA_HOME"

"$bin_path" --dir "$root" domain create >/dev/null
"$bin_path" --dir "$child" domain create >/dev/null
"$bin_path" --dir "$root" store create team >/dev/null
"$bin_path" --dir "$root" store create temp >/dev/null

"$bin_path" --dir "$root" set prefix_one one >/dev/null
"$bin_path" --dir "$root" set prefix_two two >/dev/null
"$bin_path" --dir "$root" set other_key other >/dev/null

ls_output="$("$bin_path" --dir "$root" ls 'prefix_*')"
assert_contains_line "$ls_output" 'prefix_one'
assert_contains_line "$ls_output" 'prefix_two'

"$bin_path" set "$root"/explicit_key:team explicit_value >/dev/null
explicit_value="$("$bin_path" get "$root"/explicit_key:team --stdout)"
assert_eq "$explicit_value" 'explicit_value' 'KEYREF set/get'

if "$bin_path" get explicit_key/"$root":team --stdout >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'old KEYREF syntax still accepted'
fi

canonical_output="$("$bin_path" --dir "$root" ls --canonical)"
assert_contains_line "$canonical_output" "$root/other_key:default"

team_canonical_output="$("$bin_path" --dir "$root" --store team ls --canonical)"
assert_contains_line "$team_canonical_output" "$root/explicit_key:team"

canonical_domain_output="$("$bin_path" --dir "$root" ls --canonical-domain)"
assert_contains_line "$canonical_domain_output" "$root/other_key"

canonical_store_output="$("$bin_path" --dir "$root" --store team ls --canonical-store)"
assert_contains_line "$canonical_store_output" 'explicit_key:team'

"$bin_path" cp "$root"/explicit_key:team "$child"/copied_key:temp >/dev/null
copied_value="$("$bin_path" get "$child"/copied_key:temp --stdout)"
assert_eq "$copied_value" 'explicit_value' 'KEYREF cp'

"$bin_path" mv "$child"/copied_key:temp "$root"/moved_key:team >/dev/null
moved_value="$("$bin_path" get "$root"/moved_key:team --stdout)"
assert_eq "$moved_value" 'explicit_value' 'KEYREF mv'

if "$bin_path" get "$child"/copied_key:temp --stdout >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'moved source still visible'
fi

store_output="$("$bin_path" --dir "$root" store ls 'te*')"
assert_contains_line "$store_output" 'team'
assert_contains_line "$store_output" 'temp'

domain_output="$("$bin_path" domain ls "$root*")"
assert_contains_line "$domain_output" "$root"
assert_contains_line "$domain_output" "$child"

printf 'PASS keyref regression\n'