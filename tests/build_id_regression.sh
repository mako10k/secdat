#!/usr/bin/env bash

set -euo pipefail

source_root="${1:-.}"
source_root_abs="$(cd "$source_root" && pwd -P)"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

assert_repo_clean() {
    local context="$1"
    local status
    status="$(git -C "$repo" status --porcelain --untracked-files=normal)"
    if test -n "$status"; then
        printf 'unexpected repository status:\n%s\n' "$status" >&2
        fail "$context fixture is not clean"
    fi
}

assert_only_readme_dirty() {
    local context="$1"
    local status
    status="$(git -C "$repo" status --porcelain --untracked-files=normal)"
    if test "$status" != ' M README.md'; then
        printf 'unexpected repository status:\n%s\n' "$status" >&2
        fail "$context fixture is not dirty only in README.md"
    fi
}

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT
repo="$work_root/repo"
install_root="$work_root/install"
mkdir -p "$repo" "$install_root"

git_root="$(git -C "$source_root_abs" rev-parse --show-toplevel 2>/dev/null || :)"
if test -n "$git_root"; then
    git_root="$(cd "$git_root" && pwd -P)"
fi
if test "$git_root" = "$source_root_abs"; then
    (
        cd "$source_root_abs"
        git ls-files -z | tar --null -T - -cf -
    ) | tar -C "$repo" -xf -
else
    (
        cd "$source_root_abs"
        tar \
            --exclude='./.git' \
            --exclude='./_build' \
            --exclude='./_inst' \
            -cf - .
    ) | tar -C "$repo" -xf -
fi

chmod -R u+w "$repo"
for required_file in .gitignore configure.ac Makefile.am src/Makefile.am src/main.c tests/build_id_regression.sh; do
    test -f "$repo/$required_file" || fail "fixture source is missing $required_file"
done

(
    cd "$repo"
    autoreconf -fi >/dev/null 2>&1
    ./configure --enable-fuse >/dev/null
    git init -q
    git config user.name 'secdat build-id regression'
    git config user.email 'build-id-regression@example.invalid'
    git config commit.gpgsign false
    git add -A
    git commit -qm 'baseline'
)
assert_repo_clean 'configured baseline'

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
assert_repo_clean 'initial build'
assert_build_id 'initial clean build'

git -C "$repo" commit --allow-empty -qm 'HEAD transition'
make -C "$repo" -j2 >/dev/null
assert_repo_clean 'HEAD transition'
assert_build_id 'HEAD transition'

printf '\n' >> "$repo/README.md"
assert_only_readme_dirty 'clean-to-dirty transition before build'
make -C "$repo" -j2 >/dev/null
assert_only_readme_dirty 'clean-to-dirty transition after build'
assert_build_id 'clean-to-dirty transition'

git -C "$repo" checkout -- README.md
assert_repo_clean 'dirty-to-clean transition before build'
make -C "$repo" -j2 >/dev/null
assert_repo_clean 'dirty-to-clean transition after build'
assert_build_id 'dirty-to-clean transition'

git -C "$repo" commit --allow-empty -qm 'install transition'
make -C "$repo" install DESTDIR="$install_root" >/dev/null
assert_repo_clean 'install transition'
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
