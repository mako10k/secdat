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

All bindings currently target the C ABI in [src/secdat-sdk.h](../src/secdat-sdk.h) and intentionally keep the same semantics as the CLI for domain resolution, unlocking, and stderr diagnostics.

The current binding surface covers `get`, `set`, `exists`, `collect_status`, `rm`, `mv`, `cp`, `mask`, `unmask`, `unlock`, and `lock`.

Typical workflow shape across all bindings:

1. initialize the target domain and store once with the CLI
2. load the binding and pass `dir`, `domain`, and `store` through binding-specific options
3. call `unlock` before mutating or reading encrypted data unless `SECDAT_MASTER_KEY` already provides the key
4. use `mask` and `unmask` from a child domain only for inherited keys, not for keys that already exist locally

For example, after installing the `secdat` CLI, bootstrap the root domain and child domain once before using any binding:

```sh
secdat --dir /tmp/example/root domain create
secdat --dir /tmp/example/root/child domain create
secdat --dir /tmp/example/root store create team
secdat --dir /tmp/example/root unlock
```

For explicit non-interactive unlock flows, set `SECDAT_MASTER_KEY_PASSPHRASE` before calling `unlock`. If you instead provide `SECDAT_MASTER_KEY`, reads and writes can bypass the session-agent path without calling `unlock`.

Packaging notes:

- C consumers can use `pkg-config --cflags --libs libsecdat` after `make install`.
- Python can build a wheel or local editable install from `bindings/python/` via `python -m build` or `pip install -e .`, but runtime still needs an installed `libsecdat` shared library. Set `SECDAT_SDK_LIBRARY` when the loader cannot resolve it.
- Rust uses `pkg-config` during build to find an installed `libsecdat`. Ensure `PKG_CONFIG_PATH` includes the target prefix when `libsecdat` is not installed in a default system path.
- Node uses `pkg-config` during `npm install` or `npm run build` to find the installed header and linker flags for `libsecdat`.
- Go uses the module path declared in `bindings/go/go.mod` and resolves compiler and linker flags through `pkg-config --cflags --libs libsecdat`.

During local development, point your runtime loader at the build-tree shared library if you have not run `make install` yet:

```sh
export LD_LIBRARY_PATH="$PWD/src/.libs:${LD_LIBRARY_PATH:-}"
```