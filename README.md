# secdat

Minimal C implementation of the secdat secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- `ls`, `get`, `set`, `rm`, `mv`, `cp`, and `exec` are implemented with encrypted local storage
- `domain create`, `domain delete`, and `domain ls` are implemented
- `store create`, `store delete`, and `store ls` are implemented
- `unlock`, `lock`, and `status` are implemented with a session agent and a wrapped persistent master key
- normal store commands resolve the current domain from `--dir` or the working directory and fall back through parent domains
- stores are domain-local namespaces, not global objects shared across all domains
- encryption currently uses `SECDAT_MASTER_KEY` or an active `secdat unlock` session

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

Initialize `secdat` once with a shell-provided master secret, then switch to passphrase-based `unlock`:

```sh
export SECDAT_MASTER_KEY='change-me'
./src/secdat unlock
```

The first interactive `unlock` stores a wrapped copy of the current master key under `XDG_DATA_HOME` and starts the session agent. After that, you can unset `SECDAT_MASTER_KEY` and unlock later with only your passphrase.

For a less guessable test value, you can generate one instead of typing it manually:

```sh
export SECDAT_MASTER_KEY="$(openssl rand -hex 32)"
```

Then you can store and read values:

```sh
./src/secdat set HOGE 100
./src/secdat ls
./src/secdat ls 'HO*'
./src/secdat ls --canonical
./src/secdat get HOGE --stdout
```

Key arguments also accept an explicit domain/store suffix as `KEY[/ABSOLUTE/DOMAIN][:STORE]`.
If the suffixes are omitted, `--dir`, `--store`, and then the current defaults are used.

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

## Session commands

You can keep the active master key in a login-session-scoped session agent and avoid exporting it for every command:

```sh
./src/secdat status
./src/secdat status --quiet
./src/secdat unlock
./src/secdat lock
```

If `SECDAT_MASTER_KEY` is already set, `unlock` reuses it and can bootstrap the persistent wrapped key. Otherwise it prompts on the terminal with echo disabled and unwraps the stored master key into the session agent.

Help is also available per command:

```sh
./src/secdat --help status
./src/secdat status --help
./src/secdat store --help
```

## Next implementation steps

1. Add pinentry or askpass support for non-terminal passphrase entry.
2. Add passphrase rotation for the wrapped master key without re-encrypting stored values.
3. Expose more structured status output for scripts if a machine-readable mode becomes necessary.

