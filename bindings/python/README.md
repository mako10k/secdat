# secdat Python Binding

This package provides a thin `ctypes` wrapper around the installed `libsecdat` shared library.

Set `SECDAT_SDK_LIBRARY` when the runtime loader cannot find `libsecdat` automatically.

After installing the `secdat` CLI, create the target domain and store once before using the binding:

```sh
secdat --dir /tmp/example/root domain create
secdat --dir /tmp/example/root/child domain create
secdat --dir /tmp/example/root store create team
secdat --dir /tmp/example/root unlock
```

For non-interactive unlock flows, export `SECDAT_MASTER_KEY_PASSPHRASE` before `secdat unlock`. If you provide `SECDAT_MASTER_KEY`, the binding can use that explicit key source without a session unlock.

## Surface

`Secdat` currently exposes these methods:

- `get`
- `set`
- `exists`
- `collect_status`
- `list_keys`
- `list_stores`
- `list_domains`
- `wait_unlock`
- `rm`
- `mv`
- `cp`
- `mask`
- `unmask`
- `unlock`
- `lock`

`list_keys` returns metadata such as key name, store, canonical keyref, source domain, source type, storage mode, and non-secret attributes. It does not return plaintext secret values.

## Example

```python
from secdat_sdk import Secdat

sdk = Secdat()
sdk.unlock(dir="/tmp/example/root", store="team")
sdk.set("API_TOKEN", b"token-123", dir="/tmp/example/root", store="team")
sdk.cp("API_TOKEN", "API_TOKEN_BACKUP", dir="/tmp/example/root", store="team")

value, unsafe_store = sdk.get("API_TOKEN_BACKUP", dir="/tmp/example/root", store="team")
assert value == b"token-123"
assert unsafe_store is False

sdk.mask("API_TOKEN", dir="/tmp/example/root/child", store="team")
sdk.unmask("API_TOKEN", dir="/tmp/example/root/child", store="team")
sdk.rm("API_TOKEN_BACKUP", dir="/tmp/example/root", store="team")
sdk.lock(dir="/tmp/example/root", store="team")
```

The constructor accepts an optional shared-library path, not a domain path. Domain selection is done per call with `dir=`, `domain=`, and `store=`.
