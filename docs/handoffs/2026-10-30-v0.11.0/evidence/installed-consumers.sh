#!/usr/bin/env bash
# Executed only by the release gate owner; writes exclusively into EVIDENCE_DIR.
set -euo pipefail
: "${RELEASE_SOURCE:?}" "${SHARED_PREFIX:?}" "${STATIC_PREFIX:?}" "${EVIDENCE_DIR:?}"
RELEASE_SOURCE=$(realpath "$RELEASE_SOURCE")
SHARED_PREFIX=$(realpath "$SHARED_PREFIX")
STATIC_PREFIX=$(realpath "$STATIC_PREFIX")
mkdir -p "$EVIDENCE_DIR"
EVIDENCE_DIR=$(realpath "$EVIDENCE_DIR")
work="$EVIDENCE_DIR/installed-consumers-work"
# Never reuse stale output or overwrite an earlier receipt.
mkdir "$work"
cp -a "$RELEASE_SOURCE/bindings" "$work/bindings"
export PYTHONDONTWRITEBYTECODE=1
unset PKG_CONFIG_SYSROOT_DIR
export PKG_CONFIG_PATH=
export LD_LIBRARY_PATH="$SHARED_PREFIX/lib"
export SECDAT_SDK_LIBRARY="$SHARED_PREFIX/lib/libsecdat.so"
export CARGO_TARGET_DIR="$work/rust-target"
export GOCACHE="$work/go-cache"
export npm_config_cache="$work/npm-cache"
export npm_config_devdir="$work/node-headers"
export npm_config_audit=false npm_config_fund=false
version=$(python3 - "$work/bindings/python/pyproject.toml" <<'PY'
import sys,tomllib
with open(sys.argv[1],'rb') as f: print(tomllib.load(f)['project']['version'])
PY
)
test "$version" = 0.11.0
select_prefix() {
    local prefix=$1
    export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
    test "$(pkg-config --variable=pcfiledir libsecdat)" = "$PKG_CONFIG_LIBDIR"
    test "$(pkg-config --variable=prefix libsecdat)" = "$prefix"
    test "$(pkg-config --modversion libsecdat)" = "$version"
}
select_prefix "$SHARED_PREFIX"
test -f "$SECDAT_SDK_LIBRARY"
# Thin source wrapper and packaged wheel are distinct runtime consumers.
cat > "$work/python-runtime.py" <<'PY'
import os,pathlib
import secdat_sdk
from secdat_sdk import Secdat,RedactionFieldClass
assert Secdat().redaction_class_name(RedactionFieldClass.PUBLIC_TEXT) == 'public_text'
print('Python runtime:', pathlib.Path(secdat_sdk.__file__).resolve())
PY
PYTHONPATH="$work/bindings/python" python3 "$work/python-runtime.py"
python3 -m pip wheel "$work/bindings/python" --no-deps -w "$work/wheels"
python3 -m venv "$work/python-venv"
mapfile -t wheels < <(find "$work/wheels" -maxdepth 1 -name '*.whl' -type f)
test "${#wheels[@]}" -eq 1
"$work/python-venv/bin/python" -m pip install --no-index --no-deps "${wheels[0]}"
PYTHONPATH= "$work/python-venv/bin/python" - "$version" "$work/python-venv" <<'PY'
import sys,pathlib,importlib.metadata
import secdat_sdk
from secdat_sdk import Secdat,RedactionFieldClass
assert importlib.metadata.version('secdat-sdk') == sys.argv[1]
assert pathlib.Path(secdat_sdk.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[2]).resolve())
assert Secdat().redaction_class_name(RedactionFieldClass.PUBLIC_TEXT) == 'public_text'
print('Installed wheel runtime/version PASS')
PY
(cd "$work/bindings/rust" && cargo check --locked && cargo package --locked --allow-dirty)
# npm supplies node-gyp in lifecycle PATH; use bundled executable if unavailable.
if ! command -v node-gyp >/dev/null; then
    npm_root=$(npm root -g)
    bundled="$npm_root/npm/node_modules/node-gyp/bin"
    test -f "$bundled/node-gyp.js"
    mkdir "$work/node-bin"
    ln -s "$bundled/node-gyp.js" "$work/node-bin/node-gyp"
    export PATH="$work/node-bin:$PATH"
fi
(cd "$work/bindings/node" && npm ci && npm run build && npm pack --dry-run && npm pack --pack-destination "$work")
mapfile -t node_packages < <(find "$work" -maxdepth 1 -name '*.tgz' -type f)
test "${#node_packages[@]}" -eq 1
mkdir "$work/node-consumer"
(cd "$work/node-consumer" && npm init -y && npm install "${node_packages[0]}" && node - "$version" <<'JS'
const assert = require('node:assert/strict');
const sdk = require('secdat-sdk-node');
assert.equal(require('secdat-sdk-node/package.json').version, process.argv[2]);
for (const name of ['get','set','exists','rm','mv','cp','mask','unmask','unlock','lock','collectStatus','listKeys','listStores','listDomains','waitUnlock']) {
  assert.equal(typeof sdk[name], 'function', name);
}
console.log('External Node tarball consumer/version/functions PASS');
JS
)
mkdir "$work/go-consumer"
cat > "$work/go-consumer/go.mod" <<EOF
module release-consumer

go 1.21
require github.com/mako10k/secdat/bindings/go v0.0.0
replace github.com/mako10k/secdat/bindings/go => "$work/bindings/go"
EOF
cat > "$work/go-consumer/main.go" <<'GO'
package main
import (
 "fmt"
 "github.com/mako10k/secdat/bindings/go/secdat"
)
func main() {
 name,err := secdat.RedactionClassName(secdat.RedactionPublicText)
 if err != nil || name != "public_text" { panic(fmt.Sprintf("redaction name=%q err=%v",name,err)) }
 fmt.Println("Go linked C runtime PASS:",name)
}
GO
(cd "$work/bindings/go" && go build ./...)
(cd "$work/go-consumer" && go build -o "$work/go-shared" .)
readelf -d "$work/go-shared" > "$work/go-shared.dynamic"
grep -Fq 'Shared library: [libsecdat.so' "$work/go-shared.dynamic"
LD_LIBRARY_PATH="$SHARED_PREFIX/lib" "$work/go-shared"
select_prefix "$STATIC_PREFIX"
test -f "$STATIC_PREFIX/lib/libsecdat.a"
test ! -e "$STATIC_PREFIX/lib/libsecdat.so"
(cd "$work/bindings/go" && go build -tags secdat_static ./...)
(cd "$work/go-consumer" && go build -tags secdat_static -o "$work/go-static" .)
readelf -d "$work/go-static" > "$work/go-static.dynamic"
if grep -Fq 'Shared library: [libsecdat.so' "$work/go-static.dynamic"; then
    echo 'Static Go consumer unexpectedly links shared libsecdat' >&2
    exit 1
fi
LD_LIBRARY_PATH="$STATIC_PREFIX/lib" "$work/go-static"
printf 'Installed bindings matrix PASS version=%s\n' "$version"
