#!/usr/bin/env bash

set -euo pipefail

build_root="${1:-.}"
src_build="$build_root/src"
makefile="$src_build/Makefile"
library="$src_build/libsecdat.la"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

test -f "$makefile" || fail "generated src/Makefile not found"
test -f "$library" || fail "libsecdat.la not found"

touch "$makefile"
set +e
make -q -C "$src_build" libsecdat.la >/dev/null 2>&1
query_status=$?
set -e
if test "$query_status" -ne 1; then
    fail "libsecdat.la did not become out of date after its generated link rules changed"
fi

make -C "$src_build" libsecdat.la >/dev/null
test "$library" -nt "$makefile" || fail "libsecdat.la was not relinked after src/Makefile changed"
grep -Fxq 'current=1' "$library" || fail "libsecdat.la current is not 1"
grep -Fxq 'age=1' "$library" || fail "libsecdat.la age is not 1"
grep -Fxq 'revision=0' "$library" || fail "libsecdat.la revision is not 0"

printf 'PASS libtool relink regression\n'
