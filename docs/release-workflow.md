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
4. run package-shape validation for published artifacts:
   - `PKG_CONFIG_PATH=$PWD pkg-config --cflags --libs libsecdat`
   - `cd bindings/python && python3 -m pip wheel . --no-deps -w /tmp/secdat-python-wheel`
   - `cd bindings/rust && cargo package --allow-dirty --no-verify`
   - `cd bindings/node && npm pack --dry-run`
   - `cd bindings/go && go build ./...`

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

For a narrower release-like container build, you can also use the build-only recipe introduced for reproducible environments:

```sh
docker build -f .devcontainer/Dockerfile.build --build-arg BASE_IMAGE=debian:bookworm-slim .
docker build -f .devcontainer/Dockerfile.build --build-arg BASE_IMAGE=amazonlinux:2023 .
```

## Binding publication notes

### Python

Build the wheel from `bindings/python`:

```sh
python3 -m pip wheel . --no-deps -w dist
```

The package is a thin wrapper around an installed `libsecdat` shared library. Runtime users may need `SECDAT_SDK_LIBRARY` when the loader cannot locate `libsecdat` automatically.

### Rust

Dry-run or package from `bindings/rust`:

```sh
cargo package --allow-dirty --no-verify
```

When publishing becomes desirable, add any remaining metadata required by crates.io such as license fields before `cargo publish`.

### Node

Inspect the package from `bindings/node`:

```sh
npm pack --dry-run
```

The current package assumes the target system can build the N-API addon against an installed `libsecdat`.

### Go

The Go binding is distributed as a module rooted at `bindings/go` and validated with:

```sh
go build ./...
```

If a public module release is needed, the repository tag should align with the module versioning plan before publishing documentation for `go get` consumers.

## Release checklist

- versions updated consistently
- tree clean after validation
- `make check` passed
- package-shape checks passed
- tag created and pushed
- release notes mention C SDK changes and binding/API additions