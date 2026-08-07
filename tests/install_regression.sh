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
sdk_dest="$work_root/sdk-dest"
default_helper="$default_dest$install_libexecdir/secdat/secdat-askpass"
installed_helper="$helper_dest$install_libexecdir/secdat/secdat-askpass"
source_helper="$source_root/contrib/secdat-askpass"
make_install_vars=(
    "prefix=$install_prefix"
    "exec_prefix=$install_exec_prefix"
    "libexecdir=$install_libexecdir"
)

mapfile -t configured_paths < <(
    make -s --no-print-directory -C "$build_root" -f Makefile -f - \
        print-configured-paths <<'MAKE_EOF'
print-configured-paths:
	@printf '%s\n' '$(prefix)' '$(bindir)' '$(libdir)' '$(includedir)' '$(localedir)'
MAKE_EOF
)
if test "${#configured_paths[@]}" -ne 5; then
    fail "could not resolve configured install paths"
fi
configured_prefix="${configured_paths[0]}"
configured_bindir="${configured_paths[1]}"
configured_libdir="${configured_paths[2]}"
configured_includedir="${configured_paths[3]}"
configured_localedir="${configured_paths[4]}"
for configured_path in "$configured_prefix" "$configured_bindir" \
    "$configured_libdir" "$configured_includedir" "$configured_localedir"; do
    case "$configured_path" in
        /*) ;;
        *) fail "configured install path is not absolute: $configured_path" ;;
    esac
done
installed_pkg_config_dir="$sdk_dest$configured_libdir/pkgconfig"
installed_include_dir="$sdk_dest$configured_includedir"
installed_library_dir="$sdk_dest$configured_libdir"
installed_shared_library="$installed_library_dir/libsecdat.so"
installed_static_library="$installed_library_dir/libsecdat.a"

mkdir -p "$default_dest" "$helper_dest" "$sdk_dest"

make -C "$build_root" install DESTDIR="$default_dest" "${make_install_vars[@]}" >/dev/null
if test -e "$default_helper"; then
    fail "default make install installed the optional askpass helper"
fi

make -C "$build_root" install DESTDIR="$sdk_dest" >/dev/null
test -f "$installed_pkg_config_dir/libsecdat.pc" ||
    fail "make install did not install libsecdat.pc"
test -f "$installed_include_dir/secdat-sdk.h" ||
    fail "make install did not install secdat-sdk.h"
cat >"$work_root/installed-consumer.c" <<'C_EOF'
#include <secdat-sdk.h>

int main(void)
{
    secdat_sdk_free(0);
    return 0;
}
C_EOF
pkg_config_args=(--cflags --libs libsecdat)
if test -e "$installed_shared_library"; then
    test -f "$installed_static_library" ||
        fail "shared install did not include the configured static library"
elif test -f "$installed_static_library"; then
    pkg_config_args=(--static --cflags --libs libsecdat)
else
    fail "make install did not install libsecdat"
fi
if ! installed_consumer_flags_text=$(
    PKG_CONFIG_SYSROOT_DIR="$sdk_dest" \
        PKG_CONFIG_LIBDIR="$installed_pkg_config_dir" \
        pkg-config "${pkg_config_args[@]}"
); then
    fail "pkg-config could not resolve the installed C consumer contract"
fi
case " $installed_consumer_flags_text " in
    *" -I$installed_include_dir "*) ;;
    *) fail "installed pkg-config Cflags do not select the staged include directory" ;;
esac
case " $installed_consumer_flags_text " in
    *" -L$installed_library_dir "*) ;;
    *) fail "installed pkg-config Libs do not select the staged library directory" ;;
esac
read -r -a installed_consumer_flags <<<"$installed_consumer_flags_text"
cc "$work_root/installed-consumer.c" "${installed_consumer_flags[@]}" \
    -o "$work_root/installed-consumer"
if test ! -e "$installed_shared_library"; then
    if readelf -d "$work_root/installed-consumer" 2>/dev/null |
        grep -Fq 'Shared library: [libsecdat.so'; then
        fail "static-only installed consumer depends on libsecdat.so"
    fi
fi
LD_LIBRARY_PATH="$installed_library_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    "$work_root/installed-consumer"

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

if ! locale -a 2>/dev/null | grep -Eqi '^ja_JP\.utf-?8$'; then
    printf 'SKIP installed locale smoke: ja_JP.UTF-8 locale is unavailable\n'
elif test -z "$configured_prefix" || test -z "$configured_localedir"; then
    printf 'SKIP installed locale smoke: configured prefix/localedir is unavailable\n'
elif test "${configured_prefix#/tmp/}" = "$configured_prefix"; then
    printf 'SKIP installed locale smoke: configured prefix is not under /tmp (%s)\n' "$configured_prefix"
else
    make -C "$build_root" install >/dev/null
    runtime_secdat="$configured_bindir/secdat"
    if test ! -x "$runtime_secdat"; then
        fail "runtime install did not install the secdat binary"
    fi
    runtime_output=$(
        cd "$work_root"
        LD_LIBRARY_PATH="$configured_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
            LANGUAGE=ja LANG=ja_JP.UTF-8 LC_ALL='' "$runtime_secdat" --help
    )
    if ! printf '%s\n' "$runtime_output" | grep -q '使い方:'; then
        fail "installed secdat did not use the installed Japanese locale catalog from $configured_localedir"
    fi
fi

printf 'PASS install regression\n'
