# secdat Rust Binding

This crate is a thin FFI layer over the installed `libsecdat` shared library.

After installing the `secdat` CLI, create the target domain and store once before using the binding:

```sh
secdat --dir /tmp/example/root domain create
secdat --dir /tmp/example/root/child domain create
secdat --dir /tmp/example/root store create team
secdat --dir /tmp/example/root unlock
```

For non-interactive unlock flows, export `SECDAT_MASTER_KEY_PASSPHRASE` before `secdat unlock`. If you provide `SECDAT_MASTER_KEY`, the binding can use that explicit key source without a session unlock.

## Surface

The crate currently exposes:

- `get`
- `set`
- `exists`
- `collect_status`
- `list_keys`
- `list_stores`
- `list_domains`
- `wait_unlock`
- `remove`
- `mv`
- `cp`
- `mask`
- `unmask`
- `unlock`
- `lock`

`list_keys` returns metadata such as key name, store, canonical keyref, source domain, source type, storage mode, and non-secret attributes. It does not return plaintext secret values.

## Example

```rust
use secdat_sdk::{cp, lock, mask, remove, set, unlock, unmask, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Options {
        dir: Some("/tmp/example/root".into()),
        domain: None,
        store: Some("team".into()),
    };
    let child = Options {
        dir: Some("/tmp/example/root/child".into()),
        domain: None,
        store: Some("team".into()),
    };

    unlock(&root)?;
    set(&root, "API_TOKEN", b"token-123", false)?;
    cp(&root, "API_TOKEN", "API_TOKEN_BACKUP")?;
    mask(&child, "API_TOKEN")?;
    unmask(&child, "API_TOKEN")?;
    remove(&root, "API_TOKEN_BACKUP", false)?;
    lock(&root)?;
    Ok(())
}
```

The crate does not bootstrap domains or stores on its own. When `libsecdat` is installed outside a default prefix, export `PKG_CONFIG_PATH` before `cargo build` so the build script can find `libsecdat.pc`. At runtime, ensure the loader can resolve `libsecdat`, for example with `LD_LIBRARY_PATH` when needed.
