# secdat Release Workflow

This document captures the concrete steps for cutting a release tag and preparing distributable artifacts for `libsecdat` and the language bindings.

## Scope

- the core C project version is still sourced from `configure.ac`
- binding package versions currently track the same version as the core project
- release tags should use the form `vX.Y.Z`

## Before tagging

1. update the version in `configure.ac` and the binding manifests that carry an explicit version:
   - `bindings/node/package.json`
   - `bindings/python/pyproject.toml`
   - `bindings/rust/Cargo.toml`
2. regenerate build metadata when the autotools inputs changed:
   - `autoreconf -fi`
   - `./configure`
3. run the project validation:
   - `make check`
4. run installed-consumer validation for published artifacts:
   - `PKG_CONFIG_PATH=$PWD pkg-config --cflags --libs libsecdat`
   - `(cd bindings/python && python3 -m pip wheel . --no-deps -w /tmp/secdat-python-wheel)`
   - `prefix=$(mktemp -d) && ./configure --prefix="$prefix" && make && make install`
   - `LD_LIBRARY_PATH="$prefix/lib" SECDAT_SDK_LIBRARY="$prefix/lib/libsecdat.so" PYTHONPATH="$PWD/bindings/python" python3 -c 'from secdat_sdk import Secdat; Secdat()'`
   - `(cd bindings/rust && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" cargo check)`
   - `(cd bindings/node && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" npm run build)`
   - `node_pkg=$(cd bindings/node && npm pack --silent) && tmp_consumer=$(mktemp -d) && cp "bindings/node/$node_pkg" "$tmp_consumer/" && (cd "$tmp_consumer" && npm init -y && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" LD_LIBRARY_PATH="$prefix/lib" npm install "./$node_pkg" && node -e "require('secdat-sdk-node')")`
   - `(cd bindings/go && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" go build ./...)`
   - `(cd bindings/node && npm pack --dry-run)`
   - `(cd bindings/rust && cargo package --allow-dirty)`

## Tagging

After the tree is clean and the release contents are committed:

```sh
git tag -a vX.Y.Z -m "secdat vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

If the tag should point at a release-specific commit, create and verify that commit before tagging.

## C SDK packaging

For installable native consumers, the release should provide:

- the `libsecdat` shared library
- the installed public header `secdat-sdk.h`
- the generated `libsecdat.pc` pkg-config file

Local release verification from a clean checkout:

```sh
./autogen.sh
./configure --prefix=/tmp/secdat-prefix
make
make install
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig pkg-config --cflags --libs libsecdat
```

## Binding publication notes

### Python

Build the wheel from `bindings/python`:

```sh
python3 -m pip wheel . --no-deps -w dist
```

The package is a thin wrapper around an installed `libsecdat` shared library. Runtime users may need `SECDAT_SDK_LIBRARY` when the loader cannot locate `libsecdat` automatically.

### Rust

Check and package from `bindings/rust`:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig cargo check
cargo package --allow-dirty
```

The crate now uses `pkg-config` in `build.rs`, so the target environment must expose `libsecdat.pc` during builds.

### Node

Build and inspect the package from `bindings/node`:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig npm run build
npm pack --dry-run
```

The current package assumes the target system can build the N-API addon against an installed `libsecdat` exposed through `pkg-config`.

### Go

The Go binding is distributed as a module rooted at `bindings/go` and validated with:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig go build ./...
```

If a public module release is needed, publish tags that are valid for the `bindings/go` submodule path before documenting a `go get` flow.

## Release checklist

- versions updated consistently
- tree clean after validation
- `make check` passed
- package-shape checks passed
- tag created and pushed
- release notes mention C SDK changes and binding/API additions