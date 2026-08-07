#!/usr/bin/env bash

set -euo pipefail

source_root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
source_root="$(cd "$source_root" && pwd -P)"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

project_version=$(sed -n \
    's/^AC_INIT(\[secdat\], \[\([^]]*\)\].*/\1/p' \
    "$source_root/configure.ac")
test -n "$project_version" || fail "could not read project version from configure.ac"

work_root=$(mktemp -d "${TMPDIR:-/tmp}/secdat-gettext-regression.XXXXXX")
trap 'rm -rf -- "$work_root"' EXIT
fresh_pot="$work_root/secdat.pot"
merged_po="$work_root/ja.po"
tracked_pot_normalized="$work_root/secdat.tracked.normalized.pot"
fresh_pot_normalized="$work_root/secdat.fresh.normalized.pot"
tracked_normalized="$work_root/ja.tracked.normalized.po"
merged_normalized="$work_root/ja.merged.normalized.po"

xgettext \
    --default-domain=secdat \
    --directory="$source_root" \
    --add-comments=TRANSLATORS: \
    --files-from="$source_root/po/POTFILES.in" \
    --copyright-holder='secdat contributors' \
    --package-name=secdat \
    --package-version="$project_version" \
    --msgid-bugs-address=noreply@example.invalid \
    --keyword=_ \
    --output="$fresh_pot"

msgmerge --quiet --lang=ja --previous \
    --output-file="$merged_po" \
    "$source_root/po/ja.po" \
    "$fresh_pot"

normalize_pot_creation_date() {
    sed -E \
        's/^"POT-Creation-Date: .*\\n"$/"POT-Creation-Date: normalized\\n"/' \
        "$1" >"$2"
}

test -f "$source_root/po/secdat.pot" ||
    fail "po/secdat.pot is missing; the reviewed template must be tracked"
normalize_pot_creation_date \
    "$source_root/po/secdat.pot" \
    "$tracked_pot_normalized"
normalize_pot_creation_date "$fresh_pot" "$fresh_pot_normalized"
if ! cmp -s "$tracked_pot_normalized" "$fresh_pot_normalized"; then
    diff -u "$tracked_pot_normalized" "$fresh_pot_normalized" |
        sed -n '1,160p' >&2 || :
    fail "po/secdat.pot is stale; force gettext regeneration before freezing the candidate"
fi

normalize_pot_creation_date "$source_root/po/ja.po" "$tracked_normalized"
normalize_pot_creation_date "$merged_po" "$merged_normalized"

if ! cmp -s "$tracked_normalized" "$merged_normalized"; then
    diff -u "$tracked_normalized" "$merged_normalized" | sed -n '1,160p' >&2 || :
    fail "po/ja.po is stale; force gettext regeneration before freezing the candidate"
fi

printf 'PASS gettext catalog regression (%s)\n' "$project_version"
