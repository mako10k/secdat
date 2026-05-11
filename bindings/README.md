# secdat Bindings

This directory contains thin bindings over `libsecdat`.

- `python/` uses `ctypes`
- `go/` uses `cgo`
- `rust/` uses `extern "C"`
- `node/` uses a small N-API addon

Per-binding usage notes and examples live here:

- [Python](python/README.md)
- [Go](go/README.md)
- [Rust](rust/README.md)
- [Node](node/README.md)

All bindings currently target the initial C ABI in [src/secdat-sdk.h](../src/secdat-sdk.h) and intentionally keep the same semantics as the CLI for domain resolution, unlocking, and stderr diagnostics.

The current binding surface covers `get`, `set`, `exists`, `collect_status`, `rm`, `mv`, `cp`, `mask`, `unmask`, `unlock`, and `lock`.

Typical workflow shape across all bindings:

1. initialize the target domain and store once with the CLI
2. load the binding and pass `dir`, `domain`, and `store` through binding-specific options
3. call `unlock` before mutating or reading encrypted data unless `SECDAT_MASTER_KEY` already provides the key
4. use `mask` and `unmask` from a child domain only for inherited keys, not for keys that already exist locally

For example, a root domain can create a secret and a child domain can mask the inherited value:

```sh
./src/secdat --dir /tmp/example/root domain create
./src/secdat --dir /tmp/example/root/child domain create
./src/secdat --dir /tmp/example/root store create team
export SECDAT_MASTER_KEY='example-master-key'
```

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