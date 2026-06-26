#!/usr/bin/env bash

set -euo pipefail

build_root="${1:-.}"
source_root="${2:-$build_root}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

install_prefix="/opt/secdat-install-regression"
install_exec_prefix="$install_prefix"
install_libexecdir="$install_exec_prefix/libexec"
default_dest="$work_root/default-dest"
helper_dest="$work_root/helper-dest"
default_helper="$default_dest$install_libexecdir/secdat/secdat-askpass"
installed_helper="$helper_dest$install_libexecdir/secdat/secdat-askpass"
source_helper="$source_root/contrib/secdat-askpass"
make_install_vars=(
    "prefix=$install_prefix"
    "exec_prefix=$install_exec_prefix"
    "libexecdir=$install_libexecdir"
)

mkdir -p "$default_dest" "$helper_dest"

make -C "$build_root" install DESTDIR="$default_dest" "${make_install_vars[@]}" >/dev/null
if test -e "$default_helper"; then
    fail "default make install installed the optional askpass helper"
fi

make -C "$build_root" install-askpass-helper DESTDIR="$helper_dest" "${make_install_vars[@]}" >/dev/null
if test ! -x "$installed_helper"; then
    fail "install-askpass-helper did not install an executable helper"
fi
if ! cmp -s "$source_helper" "$installed_helper"; then
    fail "installed askpass helper differs from source helper"
fi

make -C "$build_root" uninstall-askpass-helper DESTDIR="$helper_dest" "${make_install_vars[@]}" >/dev/null
if test -e "$installed_helper"; then
    fail "uninstall-askpass-helper left the helper installed"
fi

printf 'PASS install regression\n'
