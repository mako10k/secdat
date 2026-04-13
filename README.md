# secdat

Minimal C scaffold for the `secdat` secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- the CLI scaffold recognizes global options and command families
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- command execution logic is not implemented yet

## Bootstrap

```sh
./autogen.sh
./configure
make
```

## Run

```sh
./src/secdat --help
LANGUAGE=ja ./src/secdat --help
```

## Next implementation steps

1. Implement domain resolution and registry handling.
2. Implement encrypted storage primitives.
3. Implement `set`, `get`, `rm`, `ls`, `mv`, `cp`, and `exec`.

