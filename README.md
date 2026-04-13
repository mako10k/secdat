# secdat

Minimal C implementation of the secdat secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- `ls`, `get`, `set`, `rm`, `mv`, `cp`, and `exec` are implemented with encrypted local storage
- `domain create`, `domain delete`, and `domain ls` are implemented
- `store create`, `store delete`, and `store ls` are implemented
- normal store commands resolve the current domain from `--dir` or the working directory and fall back through parent domains
- stores are domain-local namespaces, not global objects shared across all domains
- encryption currently requires `SECDAT_MASTER_KEY` to be set in the environment

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

## First use

Set a master secret in your shell before calling `secdat`:

```sh
export SECDAT_MASTER_KEY='change-me'
```

For a less guessable test value, you can generate one instead of typing it manually:

```sh
export SECDAT_MASTER_KEY="$(openssl rand -hex 32)"
```

Then you can store and read values:

```sh
./src/secdat set HOGE 100
./src/secdat ls
./src/secdat get HOGE --stdout
```

You can also create a domain for a project directory and manage per-domain stores:

```sh
mkdir -p ~/example/project
./src/secdat --dir ~/example/project domain create
./src/secdat --dir ~/example/project store create app
./src/secdat --dir ~/example/project --store app set API_TOKEN --value token-123
./src/secdat --dir ~/example/project store ls
```

To avoid writing secrets to your shell history, prefer stdin for sensitive values:

```sh
printf '%s' 'super-secret-value' | ./src/secdat set API_TOKEN --stdin
./src/secdat get API_TOKEN --stdout
```

## Persistent shell setup

If you want to use `secdat` regularly, add the export to your shell startup file and reload it:

```sh
printf "\nexport SECDAT_MASTER_KEY='%s'\n" "$(openssl rand -hex 32)" >> ~/.bashrc
. ~/.bashrc
```

Treat this key like any other secret. Anyone who can read your shell startup file can decrypt your stored values.

## Next implementation steps

1. Implement domain resolution and registry handling.
2. Harden edge cases and translations around `exec`, domain/store lifecycle commands, and key moves/copies.
3. Add broader behavioral test coverage for inheritance, tombstones, and command execution.

