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
- `Remove`
- `Move`
- `Copy`
- `Mask`
- `Unmask`
- `Unlock`
- `Lock`

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

For local development, ensure `LD_LIBRARY_PATH` includes the build-tree `src/.libs` directory or install `libsecdat` first.

For installed-library builds, export `PKG_CONFIG_PATH` when `libsecdat.pc` lives outside the default search path.

The module path is `github.com/mako10k/secdat/bindings/go`. Keep repository tags compatible with that submodule path before documenting a `go get` release flow.