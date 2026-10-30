#!/usr/bin/env bash
set -euo pipefail
EVIDENCE_DIR=/home/katsumata-m/secdat-release-evidence/v0.11.0
work="$EVIDENCE_DIR/installed-consumers-work"
SHARED_PREFIX="$EVIDENCE_DIR/prefix-shared"
STATIC_PREFIX="$EVIDENCE_DIR/prefix-static"
unset PKG_CONFIG_SYSROOT_DIR
export PKG_CONFIG_PATH=
export GOCACHE="$work/go-cache"
test ! -e "$work/go-shared"
test ! -e "$work/go-static"
for shape in shared static; do
 if test "$shape" = shared; then stage_prefix="$SHARED_PREFIX"; tag_args=(); else stage_prefix="$STATIC_PREFIX"; tag_args=(-tags secdat_static); fi
 export PKG_CONFIG_LIBDIR="$stage_prefix/lib/pkgconfig"
 export LD_LIBRARY_PATH="$stage_prefix/lib"
 test "$(pkg-config --variable=pcfiledir libsecdat)" = "$PKG_CONFIG_LIBDIR"
 test "$(pkg-config --variable=prefix libsecdat)" = "$stage_prefix"
 test "$(pkg-config --modversion libsecdat)" = 0.11.0
 if test "$shape" = static; then test -f "$stage_prefix/lib/libsecdat.a"; test ! -e "$stage_prefix/lib/libsecdat.so"; fi
 # Distributed sources have archive receipts, not a VCS checkout. An unrelated
 # empty HOME/.git makes Go's ancestor detection fail; stamp no VCS data here.
 (cd "$work/bindings/go" && go build -buildvcs=false "${tag_args[@]}" ./...)
 (cd "$work/go-consumer" && go build -buildvcs=false "${tag_args[@]}" -o "$work/go-$shape" .)
 readelf -d "$work/go-$shape" > "$work/go-$shape.dynamic"
 if test "$shape" = static; then
  if grep -Fq 'Shared library: [libsecdat.so' "$work/go-$shape.dynamic"; then exit 1; fi
 else
  grep -Fq 'Shared library: [libsecdat.so.0]' "$work/go-$shape.dynamic"
  ldd "$work/go-$shape" > "$work/go-$shape.ldd"
  grep -F "$stage_prefix/lib/libsecdat.so.0" "$work/go-$shape.ldd"
 fi
 "$work/go-$shape"
 printf 'PASS installed Go %s consumer\n' "$shape"
done
