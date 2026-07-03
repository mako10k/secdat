# secdat Go Binding

This package exposes thin cgo wrappers around `libsecdat`.

After installing the `secdat` CLI, create the target domain and store once before using the binding:

```sh
secdat --dir /tmp/example/root domain create
secdat --dir /tmp/example/root/child domain create
secdat --dir /tmp/example/root store create team
secdat --dir /tmp/example/root unlock
```

For non-interactive unlock flows, export `SECDAT_MASTER_KEY_PASSPHRASE` before `secdat unlock`. If you provide `SECDAT_MASTER_KEY` instead, the binding can use that explicit key source without a session unlock.

## Surface

The package currently exports:

- `Get`
- `Set`
- `Exists`
- `CollectStatus`
- `ListKeys`
- `ListStores`
- `ListDomains`
- `WaitUnlock`
- `Remove`
- `Move`
- `Copy`
- `Mask`
- `Unmask`
- `Unlock`
- `Lock`
- `ExecPlanJSON`
- `RedactionClassName`
- `RedactionPolicyName`
- `RedactionDisplayLabel`
- `RedactionValueAllowed`
- `DescribeRedactionClass`
- `ClassifyExecJSONField`
- `RelationSuggestRefresh`

`ListKeys` returns metadata such as key name, store, canonical keyref, source domain, source type, storage mode, and non-secret attributes. It does not return plaintext secret values.

`ExecPlanJSON` returns the same secret-safe JSON shape as `secdat exec --dry-run --json` without launching a child process. It accepts counted argv, repeated inject rules, optional inject policy files, bulk gate, and command resolution. If the plan is invalid but a JSON report is available, the function still returns that report with `"ok": false`.

The redaction helpers expose shared class, policy, display, and value-allowed metadata for secdat-originated output. `ClassifyExecJSONField` fails closed for unknown exec plan field paths.

`RelationSuggestRefresh` returns `RelationRefreshSuggestion` rows equivalent to `secdat relation suggest-refresh KEYREF`. The rows include severity, relation id, leaked role, refresh role, refresh KEYREF, and reason, but never plaintext secret values.

## Example

```go
package main

import (
	"log"

	"github.com/mako10k/secdat/bindings/go/secdat"
)

func main() {
	options := secdat.Options{Dir: "/tmp/example/root", Store: "team"}
	child := secdat.Options{Dir: "/tmp/example/root/child", Store: "team"}

	if err := secdat.Unlock(options); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Set(options, "API_TOKEN", []byte("token-123"), false); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Copy(options, "API_TOKEN", "API_TOKEN_BACKUP"); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Mask(child, "API_TOKEN"); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Unmask(child, "API_TOKEN"); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Remove(options, "API_TOKEN_BACKUP", false); err != nil {
		log.Fatal(err)
	}
	if err := secdat.Lock(options); err != nil {
		log.Fatal(err)
	}
}
```

Exec-planner and relation-refresh helpers use the same `Options` struct:

```go
package main

import (
	"log"

	"github.com/mako10k/secdat/bindings/go/secdat"
)

func main() {
	options := secdat.Options{Dir: "/tmp/example/root", Store: "team"}

	planJSON, err := secdat.ExecPlanJSON(options, secdat.ExecPlanOptions{
		Argv:              []string{"python3", "-c", "pass"},
		InjectRules:       []string{"secret:only=API_TOKEN", "route:prefer=secret"},
		CommandResolution: "direct",
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = planJSON

	classification, err := secdat.DescribeRedactionClass(secdat.RedactionSecretValue)
	if err != nil {
		log.Fatal(err)
	}
	if classification.PolicyName != "redact" {
		log.Fatal("unexpected redaction policy")
	}

	refreshes, err := secdat.RelationSuggestRefresh(options, "API_TOKEN")
	if err != nil {
		log.Fatal(err)
	}
	for _, item := range refreshes {
		log.Printf("%s %s", item.RefreshKeyref, item.Reason)
	}
}
```

For local development, ensure `LD_LIBRARY_PATH` includes the build-tree `src/.libs` directory or install `libsecdat` first.

For installed-library builds, export `PKG_CONFIG_PATH` when `libsecdat.pc` lives outside the default search path.

The module path is `github.com/mako10k/secdat/bindings/go`. Keep repository tags compatible with that submodule path before documenting a `go get` release flow.
