# secdat

Minimal C implementation of the secdat secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- `ls`, `get`, `set`, and `rm` are implemented with encrypted local storage
- the current runtime uses the fallback `default` domain only
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
2. Implement inherited-domain lookup and tombstone behavior.
3. Implement `mv`, `cp`, `exec`, and `domain` subcommands.

