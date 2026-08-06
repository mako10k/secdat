#!/usr/bin/env bash

set -euo pipefail

source_root="${1:-.}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT
repo="$work_root/repo"
install_root="$work_root/install"
mkdir -p "$repo" "$install_root"

(
    cd "$source_root"
    git ls-files -z | tar --null -T - -cf -
) | tar -C "$repo" -xf -
if test ! -f "$repo/tests/build_id_regression.sh"; then
    cp "$source_root/tests/build_id_regression.sh" "$repo/tests/build_id_regression.sh"
fi

(
    cd "$repo"
    autoreconf -fi >/dev/null 2>&1
    git init -q
    git config user.name 'secdat build-id regression'
    git config user.email 'build-id-regression@example.invalid'
    git config commit.gpgsign false
    git add -A
    git commit -qm 'baseline'
    ./configure --enable-fuse >/dev/null
)

expected_build_id() {
    local hash
    hash="$(git -C "$repo" rev-parse --short=12 HEAD)"
    if test -n "$(git -C "$repo" status --porcelain --untracked-files=normal)"; then
        printf '%s-dirty\n' "$hash"
    else
        printf '%s\n' "$hash"
    fi
}

reported_cli_build_id() {
    "$repo/src/secdat" --version | sed -n 's/^Build: //p'
}

reported_fuse_build_id() {
    "$repo/src/secdat-fuse" --version | sed -n 's/^.*(\([^()]\+\))$/\1/p'
}

assert_build_id() {
    local context="$1"
    local expected
    local cli_actual
    local fuse_actual
    expected="$(expected_build_id)"
    cli_actual="$(reported_cli_build_id)"
    fuse_actual="$(reported_fuse_build_id)"
    if test "$cli_actual" != "$expected"; then
        fail "$context CLI Build ID mismatch: expected=$expected actual=$cli_actual"
    fi
    if test "$fuse_actual" != "$expected"; then
        fail "$context FUSE Build ID mismatch: expected=$expected actual=$fuse_actual"
    fi
}

make -C "$repo" -j2 >/dev/null
assert_build_id 'initial clean build'

git -C "$repo" commit --allow-empty -qm 'HEAD transition'
make -C "$repo" -j2 >/dev/null
assert_build_id 'HEAD transition'

printf '\n' >> "$repo/README.md"
make -C "$repo" -j2 >/dev/null
assert_build_id 'clean-to-dirty transition'

git -C "$repo" checkout -- README.md
make -C "$repo" -j2 >/dev/null
assert_build_id 'dirty-to-clean transition'

git -C "$repo" commit --allow-empty -qm 'install transition'
make -C "$repo" install DESTDIR="$install_root" >/dev/null
installed_cli="$install_root/usr/local/bin/secdat"
installed_fuse="$install_root/usr/local/bin/secdat-fuse"
installed_library_path="$install_root/usr/local/lib"
expected="$(expected_build_id)"
cli_actual="$(LD_LIBRARY_PATH="$installed_library_path" "$installed_cli" --version | sed -n 's/^Build: //p')"
fuse_actual="$(LD_LIBRARY_PATH="$installed_library_path" "$installed_fuse" --version | sed -n 's/^.*(\([^()]\+\))$/\1/p')"
if test "$cli_actual" != "$expected" || test "$fuse_actual" != "$expected"; then
    fail "installed Build ID mismatch: expected=$expected cli=$cli_actual fuse=$fuse_actual"
fi

mv "$repo/.git" "$work_root/git-metadata"
make -C "$repo" -j2 >/dev/null
if test -n "$(reported_cli_build_id)"; then
    fail 'git-less CLI build unexpectedly reported a Build ID'
fi
if test -n "$(reported_fuse_build_id)"; then
    fail 'git-less FUSE build unexpectedly reported a Build ID'
fi

printf 'PASS build ID regression\n'
