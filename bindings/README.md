# secdat Bindings

This directory contains thin bindings over `libsecdat`.

- `python/` uses `ctypes`
- `go/` uses `cgo`
- `rust/` uses `extern "C"`
- `node/` uses a small N-API addon

All bindings currently target the initial C ABI in [src/secdat-sdk.h](../src/secdat-sdk.h) and intentionally keep the same semantics as the CLI for domain resolution, unlocking, and stderr diagnostics.

During local development, point your runtime loader at the build-tree shared library if you have not run `make install` yet:

```sh
export LD_LIBRARY_PATH="$PWD/src/.libs:${LD_LIBRARY_PATH:-}"
```