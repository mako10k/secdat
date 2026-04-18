#!/usr/bin/env bash

set -euo pipefail

bin_path="$(realpath "${1:-./src/secdat}")"

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
export LC_ALL=C
export LANGUAGE=C

root="$work_root/work/root"
child="$root/child"
sibling="$work_root/work/sibling"
unregistered="$work_root/work/unregistered"
mkdir -p "$root" "$child" "$XDG_DATA_HOME"
mkdir -p "$sibling"
mkdir -p "$unregistered"

"$bin_path" --dir "$root" domain create >/dev/null
"$bin_path" --dir "$child" domain create >/dev/null
"$bin_path" --dir "$sibling" domain create >/dev/null
"$bin_path" --dir "$root" store create team >/dev/null
"$bin_path" --dir "$root" store create temp >/dev/null

"$bin_path" --dir "$root" set prefix_one one >/dev/null
"$bin_path" --dir "$root" set prefix_two two >/dev/null
"$bin_path" --dir "$root" set other_key other >/dev/null
"$bin_path" --dir "$root" set shared_key shared >/dev/null
"$bin_path" --dir "$root" set override_key parent >/dev/null
"$bin_path" --dir "$child" set override_key child >/dev/null

domain_status_output="$(LANGUAGE=C "$bin_path" --dir "$child" domain status)"
assert_contains_line "$domain_status_output" "resolved domain: $child"
assert_contains_line "$domain_status_output" 'resolution source: --dir'
assert_contains_line "$domain_status_output" 'store count: 1'
assert_contains_line "$domain_status_output" 'visible key count: 5'
assert_contains_line "$domain_status_output" 'key source: environment'
assert_contains_line "$domain_status_output" 'effective state: unlocked'
assert_contains_line "$domain_status_output" 'effective source: environment'
assert_contains_line "$domain_status_output" 'wrapped master key: absent'

domain_status_quiet="$(LANGUAGE=C "$bin_path" --dir "$child" domain status --quiet)"
assert_eq "$domain_status_quiet" "$child" 'domain status --quiet'

domain_status_cwd="$(cd "$child" && LANGUAGE=C "$bin_path" domain status)"
assert_contains_line "$domain_status_cwd" "resolved domain: $child"
assert_contains_line "$domain_status_cwd" 'resolution source: current working directory'

domain_status_exact="$(LANGUAGE=C "$bin_path" --domain "$root" domain status)"
assert_contains_line "$domain_status_exact" "resolved domain: $root"
assert_contains_line "$domain_status_exact" 'resolution source: --domain'

exact_override_value="$(cd "$child" && "$bin_path" --domain "$root" get override_key --stdout)"
assert_eq "$exact_override_value" 'parent' '--domain exact root get'

if "$bin_path" --domain "$work_root/work" status --quiet >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail '--domain accepted a non-domain root'
fi

if "$bin_path" --dir "$root" --domain "$child" status --quiet >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail '--dir and --domain were accepted together'
fi

domain_long_output="$(LANGUAGE=C "$bin_path" --dir "$work_root/work" domain ls -l)"
assert_contains_line "$domain_long_output" $'DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED'
assert_contains_line "$domain_long_output" "$root"$'\tenvironment\tunlocked\tenvironment\t3\t5\tabsent'
assert_contains_line "$domain_long_output" "$child"$'\tenvironment\tunlocked\tenvironment\t1\t5\tabsent'
assert_contains_line "$domain_long_output" "$sibling"$'\tenvironment\tunlocked\tenvironment\t1\t0\tabsent'

domain_inherited_output="$(LANGUAGE=C "$bin_path" --dir "$child" domain ls -la --descendants)"
assert_contains_line "$domain_inherited_output" $'DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED'
assert_contains_line "$domain_inherited_output" "$root"$'\tenvironment\tunlocked\tenvironment\t3\t5\tabsent'
assert_contains_line "$domain_inherited_output" "$child"$'\tenvironment\tunlocked\tenvironment\t1\t5\tabsent'
assert_contains_line "$domain_inherited_output" '*default*'$'\tenvironment\tunlocked\tenvironment\t0\t0\tabsent'

if ! "$bin_path" --dir "$root" exists prefix_one >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'exists did not report an existing key'
fi
if "$bin_path" --dir "$root" exists missing_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'exists reported success for a missing key'
fi
if ! "$bin_path" --dir "$child" exists shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'child did not inherit shared_key before mask'
fi

ls_output="$("$bin_path" --dir "$root" ls 'prefix_*')"
assert_contains_line "$ls_output" 'prefix_one'
assert_contains_line "$ls_output" 'prefix_two'

ls_multi_output="$($bin_path --dir "$root" ls --pattern 'prefix_*' --pattern 'other_*' --pattern-exclude 'prefix_two')"
assert_contains_line "$ls_multi_output" 'prefix_one'
assert_contains_line "$ls_multi_output" 'other_key'
if printf '%s\n' "$ls_multi_output" | grep -Fx -- 'prefix_two' >/dev/null; then
    fail 'ls --pattern-exclude still returned excluded key'
fi

"$bin_path" set "$root"/explicit_key:team explicit_value >/dev/null
explicit_value="$($bin_path get "$root"/explicit_key:team --stdout)"
assert_eq "$explicit_value" 'explicit_value' 'KEYREF set/get'

if "$bin_path" --dir "$unregistered" set stray_key stray >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'set unexpectedly wrote to the default domain'
fi
assert_contains_line "$(cat /tmp/secdat-keyref-test.err)" 'writes to the default domain are not supported'

if "$bin_path" get explicit_key/"$root":team --stdout >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'old KEYREF syntax still accepted'
fi

if ! "$bin_path" exists "$root"/explicit_key:team >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'exists KEYREF did not resolve explicit domain/store key'
fi

if "$bin_path" cp "$root"/explicit_key:team "$unregistered"/default_copy:team >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'cp unexpectedly wrote to the default domain'
fi
assert_contains_line "$(cat /tmp/secdat-keyref-test.err)" 'writes to the default domain are not supported'

canonical_output="$($bin_path --dir "$root" ls --canonical)"
assert_contains_line "$canonical_output" "$root/other_key:default"

team_canonical_output="$($bin_path --dir "$root" --store team ls --canonical)"
assert_contains_line "$team_canonical_output" "$root/explicit_key:team"

canonical_domain_output="$($bin_path --dir "$root" ls --canonical-domain)"
assert_contains_line "$canonical_domain_output" "$root/other_key"

canonical_store_output="$($bin_path --dir "$root" --store team ls --canonical-store)"
assert_contains_line "$canonical_store_output" 'explicit_key:team'

"$bin_path" cp "$root"/explicit_key:team "$child"/copied_key:temp >/dev/null
copied_value="$($bin_path get "$child"/copied_key:temp --stdout)"
assert_eq "$copied_value" 'explicit_value' 'KEYREF cp'

"$bin_path" mv "$child"/copied_key:temp "$root"/moved_key:team >/dev/null
moved_value="$($bin_path get "$root"/moved_key:team --stdout)"
assert_eq "$moved_value" 'explicit_value' 'KEYREF mv'

if "$bin_path" get "$child"/copied_key:temp --stdout >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'moved source still visible'
fi

if ! "$bin_path" --dir "$root" rm --ignore-missing missing_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'rm --ignore-missing failed for a missing key'
fi

if ! "$bin_path" --dir "$root" rm --ignore-missing prefix_one >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'rm --ignore-missing failed for an existing key'
fi
if "$bin_path" --dir "$root" exists prefix_one >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'rm --ignore-missing did not remove an existing key'
fi

if "$bin_path" --dir "$unregistered" rm missing_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'rm unexpectedly targeted the default domain'
fi
assert_contains_line "$(cat /tmp/secdat-keyref-test.err)" 'writes to the default domain are not supported'

overridden_output="$($bin_path --dir "$child" list --overridden)"
assert_contains_line "$overridden_output" 'override_key'

if ! "$bin_path" --dir "$child" mask shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'mask failed for inherited key'
fi
masked_output="$($bin_path --dir "$child" list --masked)"
assert_contains_line "$masked_output" 'shared_key'
if "$bin_path" --dir "$child" exists shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'mask did not hide inherited key'
fi

if ! "$bin_path" --dir "$root" rm shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'failed to remove parent shared_key for orphaned tombstone test'
fi
orphaned_output="$($bin_path --dir "$child" list --orphaned)"
assert_contains_line "$orphaned_output" 'shared_key'

if ! "$bin_path" --dir "$child" unmask shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'unmask failed for masked key'
fi
if "$bin_path" --dir "$child" exists shared_key >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'unmask restored visibility after parent key was removed'
fi

store_output="$($bin_path --dir "$root" store ls 'te*')"
assert_contains_line "$store_output" 'team'
assert_contains_line "$store_output" 'temp'

if "$bin_path" --dir "$unregistered" store create scratch >/tmp/secdat-keyref-test.out 2>/tmp/secdat-keyref-test.err; then
    fail 'store create unexpectedly targeted the default domain'
fi
assert_contains_line "$(cat /tmp/secdat-keyref-test.err)" 'writes to the default domain are not supported'

domain_output="$($bin_path --dir "$work_root/work" domain ls "$root*")"
assert_contains_line "$domain_output" "$root"
assert_contains_line "$domain_output" "$child"

domain_default_output="$(cd "$root" && "$bin_path" domain ls)"
assert_contains_line "$domain_default_output" "$root"
assert_contains_line "$domain_default_output" "$child"
if printf '%s\n' "$domain_default_output" | grep -Fx -- "$sibling" >/dev/null; then
    fail 'domain ls default scope included sibling domain'
fi

domain_ancestors_output="$($bin_path --dir "$child" domain ls --ancestors)"
assert_contains_line "$domain_ancestors_output" "$root"
assert_contains_line "$domain_ancestors_output" "$child"
if printf '%s\n' "$domain_ancestors_output" | grep -Fx -- "$sibling" >/dev/null; then
    fail 'domain ls --ancestors included sibling domain'
fi

domain_descendants_output="$($bin_path --dir "$root" domain ls --descendants)"
assert_contains_line "$domain_descendants_output" "$root"
assert_contains_line "$domain_descendants_output" "$child"
if printf '%s\n' "$domain_descendants_output" | grep -Fx -- "$sibling" >/dev/null; then
    fail 'domain ls --descendants included sibling domain'
fi

domain_scoped_output="$($bin_path --dir "$work_root/work" domain ls)"
assert_contains_line "$domain_scoped_output" "$root"
assert_contains_line "$domain_scoped_output" "$child"
assert_contains_line "$domain_scoped_output" "$sibling"

printf 'PASS keyref regression\n'