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

configured_prefix=$(
    make -s --no-print-directory -C "$build_root" -f Makefile -f - print-prefix <<'MAKE_EOF'
print-prefix:
	@printf '%s\n' '$(prefix)'
MAKE_EOF
)
configured_localedir=$(
    make -s --no-print-directory -C "$build_root" -f Makefile -f - print-localedir <<'MAKE_EOF'
print-localedir:
	@printf '%s\n' '$(localedir)'
MAKE_EOF
)

if ! locale -a 2>/dev/null | grep -Eqi '^ja_JP\.utf-?8$'; then
    printf 'SKIP installed locale smoke: ja_JP.UTF-8 locale is unavailable\n'
elif test -z "$configured_prefix" || test -z "$configured_localedir"; then
    printf 'SKIP installed locale smoke: configured prefix/localedir is unavailable\n'
elif test "${configured_prefix#/tmp/}" = "$configured_prefix"; then
    printf 'SKIP installed locale smoke: configured prefix is not under /tmp (%s)\n' "$configured_prefix"
else
    make -C "$build_root" install >/dev/null
    runtime_secdat="$configured_prefix/bin/secdat"
    if test ! -x "$runtime_secdat"; then
        fail "runtime install did not install the secdat binary"
    fi
    runtime_output=$(
        cd "$work_root"
        LD_LIBRARY_PATH="$configured_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
            LANGUAGE=ja LANG=ja_JP.UTF-8 LC_ALL= "$runtime_secdat" --help
    )
    if ! printf '%s\n' "$runtime_output" | grep -q '使い方:'; then
        fail "installed secdat did not use the installed Japanese locale catalog from $configured_localedir"
    fi
fi

printf 'PASS install regression\n'
