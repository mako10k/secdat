# secdat Rust Binding

This crate is a thin FFI layer over the installed `libsecdat` shared library.

## Surface

The crate currently exposes:

- `get`
- `set`
- `exists`
- `collect_status`
- `remove`
- `mv`
- `cp`
- `mask`
- `unmask`
- `unlock`
- `lock`

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

The crate does not bootstrap domains or stores on its own. Create those once with the CLI before using the binding.