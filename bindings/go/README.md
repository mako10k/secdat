# secdat Go Binding

This package exposes thin cgo wrappers around `libsecdat`.

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