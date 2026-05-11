# secdat Bindings

This directory contains thin bindings over `libsecdat`.

- `python/` uses `ctypes`
- `go/` uses `cgo`
- `rust/` uses `extern "C"`
- `node/` uses a small N-API addon

All bindings currently target the initial C ABI in [src/secdat-sdk.h](../src/secdat-sdk.h) and intentionally keep the same semantics as the CLI for domain resolution, unlocking, and stderr diagnostics.

Packaging notes:

- C consumers can use `pkg-config --cflags --libs libsecdat` after `make install`.
- Python can build a wheel or local editable install from `bindings/python/` via `python -m build` or `pip install -e .`.
- Rust packaging metadata lives in `bindings/rust/Cargo.toml` and keeps the crate as a thin FFI layer over the installed `libsecdat`.
- Node packaging metadata lives in `bindings/node/package.json`; publishing still assumes the target system can build the addon against `libsecdat`.
- Go uses the module path declared in `bindings/go/go.mod` and links through cgo against the installed library.

During local development, point your runtime loader at the build-tree shared library if you have not run `make install` yet:

```sh
export LD_LIBRARY_PATH="$PWD/src/.libs:${LD_LIBRARY_PATH:-}"
```