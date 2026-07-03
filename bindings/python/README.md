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
- `exec_plan_json`
- `redaction_class_name`
- `redaction_policy_name`
- `redaction_display_label`
- `redaction_value_allowed`
- `describe_redaction_class`
- `classify_exec_json_field`
- `relation_suggest_refresh`

`list_keys` returns metadata such as key name, store, canonical keyref, source domain, source type, storage mode, and non-secret attributes. It does not return plaintext secret values.

`exec_plan_json` returns the same secret-safe JSON shape as `secdat exec --dry-run --json` without launching a child process. It accepts `argv`, repeated `inject_rules`, optional `inject_files`, `bulk_gate`, and `command_resolution`. If the plan is invalid but a JSON report is available, the method still returns that report with `"ok": false`.

The redaction helpers expose shared class, policy, display, and value-allowed metadata for secdat-originated output. `classify_exec_json_field` fails closed for unknown exec plan field paths.

`relation_suggest_refresh` returns `RelationRefreshSuggestion` rows equivalent to `secdat relation suggest-refresh KEYREF`. The rows include severity, relation id, leaked role, refresh role, refresh KEYREF, and reason, but never plaintext secret values.

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

Exec-planner and relation-refresh helpers use the same per-call domain options:

```python
from secdat_sdk import RedactionFieldClass, Secdat

sdk = Secdat()
plan_json = sdk.exec_plan_json(
    ["python3", "-c", "pass"],
    dir="/tmp/example/root",
    store="team",
    inject_rules=["secret:only=API_TOKEN", "route:prefer=secret"],
    command_resolution="direct",
)

classification = sdk.describe_redaction_class(RedactionFieldClass.SECRET_VALUE)
assert classification.policy_name == "redact"

refreshes = sdk.relation_suggest_refresh("API_TOKEN", dir="/tmp/example/root", store="team")
for item in refreshes:
    print(item.refresh_keyref, item.reason)
```

The constructor accepts an optional shared-library path, not a domain path. Domain selection is done per call with `dir=`, `domain=`, and `store=`.
