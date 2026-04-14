# secdat

Minimal C implementation of the secdat secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- repository-local coding workflow and project rules are documented in `.github/copilot-instructions.md`
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- `ls`, `get`, `set`, `rm`, `mv`, `cp`, and `exec` are implemented with encrypted local storage
- `export` is implemented for shell-friendly setup without embedding raw secret values
- `save` and `load` are implemented for passphrase-protected secret bundles scoped to the current view
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

Initialize `secdat` once directly with a passphrase:

```sh
./src/secdat unlock
```

The first interactive `unlock` generates a fresh master key, stores a wrapped copy under `XDG_DATA_HOME`, and starts the session agent. After that, later `unlock` calls need only your passphrase.

For explicit non-interactive use, `SECDAT_MASTER_KEY_PASSPHRASE` can provide the current wrapped-key passphrase to `unlock`. This is an override path rather than the default recommendation, because environment variables are easier to expose than terminal prompts.

If you already have a master key to migrate or explicitly override with, `SECDAT_MASTER_KEY` still works:

```sh
export SECDAT_MASTER_KEY='change-me'
./src/secdat unlock
```

For a less guessable test value, you can generate one instead of typing it manually:

```sh
export SECDAT_MASTER_KEY="$(openssl rand -hex 32)"
```

Then you can store and read values:

```sh
./src/secdat set HOGE 100
./src/secdat ls
./src/secdat ls 'HO*'
./src/secdat ls --pattern 'HO*' --pattern 'API_*' --pattern-exclude 'HOGE'
./src/secdat ls --canonical
./src/secdat exists HOGE
./src/secdat get HOGE --stdout
```

For shell branching without printing secret material, use `exists` and check the exit status:

```sh
if ./src/secdat --dir ~/example/project --store app exists API_TOKEN; then
	echo present
else
	echo missing
fi
```

If you explicitly need a value to remain readable while `secdat` is locked, `set --unsafe` stores it in plaintext on disk:

```sh
./src/secdat set PUBLIC_ENDPOINT --unsafe --value https://example.invalid/api
./src/secdat get PUBLIC_ENDPOINT --stdout
```

`--unsafe` is intentionally outside the normal secret workflow. It does not require the master key, remains readable while locked, and should only be used for values you accept storing in plaintext.

Key arguments also accept an explicit domain/store qualifier as `[/ABSOLUTE/DOMAIN/]KEY[:STORE]`.
When a raw domain is present, the trailing slash before `KEY` is required. If the qualifier is omitted, `--dir`, `--store`, and then the current defaults are used.

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
./src/secdat get API_TOKEN --shellescaped
```

For shell setup, you can emit bash-oriented export lines that defer the real secret read to `secdat get`:

```sh
./src/secdat --dir ~/example/project --store app export
eval "$(./src/secdat --dir ~/example/project --store app export)"
source <(./src/secdat --dir ~/example/project --store app export)
```

The output is shell-ready text such as `eval "export API_TOKEN=$(./src/secdat ... get API_TOKEN --shellescaped)"`; it does not print raw secret values directly. `get --shellescaped` emits a single-quoted shell literal for one secret value, and `export` reuses that path. In bash, you can either `eval "$(...)"` or source it with process substitution as `source <(...)` / `. <(...)`. Plain `. $(...)` is not valid here because `.` expects a file path, not command text. The current implementation is bash-oriented, single-quote escapes command arguments, and rejects keys that are not valid shell identifiers.

For command injection into a child process, `exec` now accepts repeated `--pattern` and `--pattern-exclude` filters. Include patterns are ORed together, and exclude patterns are applied afterward.

Bash completion source is in `completions/secdat.bash`, and `make install` installs it for automatic loading as `secdat` under the system bash-completion directory. `make install` also installs the command reference into the system manpath from `docs/secdat.1`.

You can also save the currently visible secrets from one view and load them into another domain/store context:

```sh
./src/secdat --dir ~/example/project --store app save ~/backup/app.secdat
./src/secdat --dir ~/example/restore --store app load ~/backup/app.secdat
```

Both commands require a passphrase on a terminal. `save` exports only the secrets visible from the current `--dir` and `--store` view, writes a passphrase-encrypted bundle, and refuses to overwrite an existing bundle file. `load` imports that bundle into the current domain/store context, overwriting matching local keys but leaving unspecified keys untouched.

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

If `SECDAT_MASTER_KEY` is already set, `unlock` reuses it as an explicit override or migration source and can bootstrap the persistent wrapped key from it. Otherwise, the first terminal `unlock` generates and wraps a fresh master key, and later unlocks unwrap the stored master key into the session agent.

You can rotate the wrapped-master-key passphrase without changing stored secret payloads:

```sh
./src/secdat passwd
SECDAT_MASTER_KEY_PASSPHRASE='current-passphrase' ./src/secdat passwd
```

`passwd` unwraps the persistent master key with the current passphrase and re-wraps it with the new one.

There is no supported raw master-key retrieval command in the normal workflow. The intended design keeps the generated master key internal to the wrapped-key and session-agent path unless an explicit future recovery/export flow is added.

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

