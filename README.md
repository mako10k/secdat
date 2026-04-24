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
- `domain create`, `domain delete`, `domain ls`, and `domain status` are implemented
- `store create`, `store delete`, and `store ls` are implemented
- `unlock`, `lock`, and `status` are implemented with domain-scoped session agents and a wrapped persistent master key
- normal store commands resolve the current domain from `--dir` or the working directory and fall back through parent domains
- stores are domain-local namespaces, not global objects shared across all domains
- encryption currently uses `SECDAT_MASTER_KEY` or an active `secdat unlock` session

## Security scope

`secdat` is intended for local single-user use on one host, primarily for developer workflows under the same OS account.

The current design does not try to support shared hosts, shared containers, multi-user collaboration, root compromise, or forwarded/multiplexed session edge cases as first-class deployment targets.

The session-agent path relies on normal OS user separation and private XDG runtime/data locations. If those assumptions do not hold in your environment, treat that deployment as unsupported.

## Bootstrap

```sh
./autogen.sh
./configure
make
```

## Run

```sh
./src/secdat --help
./src/secdat --version
./src/secdat help usecases
./src/secdat help concepts
LANGUAGE=ja ./src/secdat --help
```

The CLI help now has two extra documentation-oriented topics. `help usecases` shows short workflow examples such as bootstrapping a domain, exporting shell variables, and waiting for another terminal to unlock. `help concepts` explains the core model behind domains, stores, inheritance, local locks, local unlocks, and `KEYREF` resolution. Individual command help such as `help get` and `help export` also includes a short `Use cases:` section.

When built from a Git worktree, `--version` also prints a short build identifier derived from the current commit hash and appends `-dirty` when the tree has uncommitted changes. Release or tarball builds keep the plain package version when Git metadata is unavailable.

## First use

Initialize `secdat` once directly with a passphrase in the target domain:

```sh
./src/secdat --dir ~/example/project unlock
```

The first interactive `unlock` generates a fresh master key, stores a wrapped copy under `XDG_DATA_HOME`, and starts a session agent scoped to the current domain. Use `unlock --duration TTL` for relative expiry values: plain numbers mean minutes, suffix forms such as `1h30m` are accepted, and `PT1H30M` style ISO 8601 durations work. Use `unlock --until TIME` for an absolute RFC 3339 expiry timestamp. Running `unlock` again while the current domain is already unlocked refreshes the current domain without asking for the passphrase again.

When a domain is shadowed by a local lock, `unlock --inherit` removes that local lock after checking that the resulting effective state would become unlocked. If no local lock is present but the current domain has its own local unlock, `unlock --inherit` clears that local unlock instead and falls back to inherited state when the checked result would still be unlocked. Symmetrically, `lock --inherit` still removes only the local lock after checking that the resulting effective state would stay locked. Plain `lock` is now a no-op success when the current domain is already locked. If you need to remove the local lock, or clear a local unlock when no lock is present, without that safety check, use `inherit`.

When a branch still contains local-lock shadows, `unlock --descendants` performs an explicit subtree unlock: it keeps those local locks in place, but creates local descendant unlocks so the current domain and blocked descendants become available for the lifetime of those unlocks. Because that broadens access beyond the current domain, the command asks for confirmation unless you pass `--yes` for non-interactive use.

Before prompting, `unlock` now prints the resolved domain it is about to unlock so the current scope is visible even when you launched the command from the wrong directory by mistake. When no registered domain applies, that output uses the presentation label `*default*` to mean "no registered domain resolved; the top-level inherited fallback scope is active".

If some descendants under the unlocked branch remain shadowed by local locks, plain `unlock` now says so and prints follow-up commands for `domain ls -l --descendants`, `domain status`, and a descendant-specific `unlock` using the correct `--dir` values. Descendants that can already reuse the unlocked session are summarized count-only; only descendants that remain locked are listed explicitly.

If a secret read fails while `secdat` is still locked, the error now reports the resolved domain context and suggests the matching `domain status` and `unlock` command so you do not keep retrying from the wrong directory.

For `get` only, `--on-demand-unlock` can wait for another terminal to unlock the resolved domain instead of failing immediately. The wait notice is written to standard error and includes the matching `unlock` command to run elsewhere. Use `--unlock-timeout SECONDS` to fail after a bounded wait, or set `SECDAT_GET_ON_DEMAND_UNLOCK=1` to make this the default behavior for `get`. `SECDAT_GET_UNLOCK_TIMEOUT_SECONDS` sets the default timeout for that wait path.

For script orchestration that should block before a later secret read or secret-injecting command, `wait-unlock` provides the same wait behavior without reading any secret value itself. `secdat --dir ~/example/project wait-unlock --timeout 900` waits until the resolved domain becomes unlocked, returns success immediately when it is already unlocked, and otherwise fails after the timeout.

If you want that behavior by default in interactive shells without changing the product default for scripts and non-interactive callers, prefer shell startup configuration guarded by an interactive-shell check:

```sh
if [[ $- == *i* ]]; then
	export SECDAT_GET_ON_DEMAND_UNLOCK=1
	export SECDAT_GET_UNLOCK_TIMEOUT_SECONDS=90
fi
```

That keeps plain `get` fail-fast in automation while making interactive terminal use wait up to 90 seconds for another terminal to run `secdat unlock`.

For explicit non-interactive use, `SECDAT_MASTER_KEY_PASSPHRASE` can provide the current wrapped-key passphrase to `unlock`. This is an override path rather than the default recommendation, because environment variables are easier to expose than terminal prompts.

For a non-mutating session, `unlock --volatile` keeps subsequent `set`, `rm`, `mask`, `unmask`, `cp`, `mv`, `load`, and read-side resolution changes in the session agent's memory instead of writing through to the real store files. `lock` clears that overlay, and `lock --save` first writes the local volatile overlay into the real store files before locking. This is intended for dry-run validation and read-only filesystems.

When no wrapped master key exists yet, `unlock --volatile` can still start by generating an ephemeral in-memory master key without writing the wrapped-key file. Current volatile sessions can remove only tombstones created in the same volatile overlay; persisted tombstones still require a normal writable session.

For a read-only session with the real persisted data, `unlock --readonly` reuses an existing master key but rejects mutating commands such as `set`, `rm`, `mask`, `unmask`, `cp`, `mv`, `load`, `store create`, `store delete`, and domain create/delete. `--readonly` and `--volatile` are mutually exclusive.

If you already have a master key to migrate or explicitly override with, `SECDAT_MASTER_KEY` still works:

```sh
export SECDAT_MASTER_KEY='change-me'
./src/secdat --dir ~/example/project unlock
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
./src/secdat ls --unsafe
./src/secdat ls --safe
./src/secdat ls --canonical
./src/secdat exists HOGE
./src/secdat get HOGE --stdout
./src/secdat get --on-demand-unlock --unlock-timeout 30 HOGE --stdout
```

Most command-local long options also accept unique abbreviations and `--option=value` forms.
For commands with positional operands, command-local options are generally accepted before or after those operands.
Use `--` to stop command-local option parsing explicitly when you need a literal operand that starts with `-`:

```sh
./src/secdat get HOGE --std
./src/secdat --dir ~/example/project rm OLD_API_TOKEN -f
./src/secdat set DASHED_VALUE -- --starts-with-dash
./src/secdat --dir ~/example/project API_TOKEN=token-123 API_ENDPOINT=https://example.invalid/api
./src/secdat --dir ~/example/project set API_TOKEN=token-123 API_ENDPOINT=https://example.invalid/api
./src/secdat exec --pattern 'APP_*' -- python3 -c 'import os; print(os.environ["APP_TOKEN"])'
./src/secdat exec --env-map-sed 's/^MY_REDMINE_\(.*\)$/SPV_REDMINE_\1/' -- env | grep '^SPV_REDMINE_'
```

For shell branching without printing secret material, use `exists` and check the exit status:

```sh
if ./src/secdat --dir ~/example/project --store app exists API_TOKEN; then
	echo present
else
	echo missing
fi
```

To hide an inherited key in a child domain without touching the parent value, use `mask`. To remove that local tombstone later, use `unmask`:

```sh
./src/secdat --dir ~/example/project/child mask API_TOKEN
./src/secdat --dir ~/example/project/child unmask API_TOKEN
```

For current-domain state inspection, `list` can show active tombstones, orphaned tombstones, and local overrides:

```sh
./src/secdat --dir ~/example/project/child list --masked
./src/secdat --dir ~/example/project/child list --orphaned
./src/secdat --dir ~/example/project/child list --overridden
./src/secdat --dir ~/example/project/child list --unsafe
./src/secdat --dir ~/example/project/child list --safe
```

For idempotent cleanup in shell automation, `rm --ignore-missing` treats an absent key as a successful no-op:

```sh
./src/secdat --dir ~/example/project --store app rm --ignore-missing OLD_API_TOKEN
```

If you explicitly need a value to remain readable while `secdat` is locked, `set --unsafe` stores it in plaintext on disk:

```sh
./src/secdat set PUBLIC_ENDPOINT --unsafe --value https://example.invalid/api
./src/secdat get PUBLIC_ENDPOINT --stdout
```

`--unsafe` is intentionally outside the normal secret workflow. It does not require the master key, remains readable while locked, and should only be used for values you accept storing in plaintext.
Unsafe values may also be entered from or written to a terminal. Safe values keep the existing terminal I/O refusal.
Copying or moving a `--unsafe` key preserves that plaintext-at-rest storage mode.
For simple shell-style assignment input, you can also use `KEY=VALUE` operands directly. `secdat KEY=VALUE ...` is treated as repeated `set`, and `secdat set KEY=VALUE ...` does the same. The split happens on the first `=`, so later `=` characters stay in the stored value.
Key names are restricted to shell/environment identifier syntax: they must start with a letter or `_`, and the remaining characters may contain only letters, digits, or `_`. `exec --env-map-sed` applies the same rule to generated environment variable names, so empty results or names with unsuitable characters are rejected.

Key arguments also accept an explicit domain/store qualifier as `[/ABSOLUTE/DOMAIN/]KEY[:STORE]`.
When a raw domain is present, the trailing slash before `KEY` is required. If the qualifier is omitted, `--domain`, then `--dir`, then `--store`, and finally the current defaults are used.
Write commands must still resolve to a registered domain. If resolution would fall back to the implicit `*default*` scope, the command fails instead of creating unreachable local state there.

Use `--domain /exact/domain/root` when you want one exact registered domain root instead of normal ancestor-based discovery. Unlike `--dir`, it fails unless the supplied path is itself a registered domain root.

You can also create a domain for a project directory and manage per-domain stores:

```sh
mkdir -p ~/example/project
./src/secdat --dir ~/example/project domain create
./src/secdat --dir ~/example/project store create app
./src/secdat --dir ~/example/project --store app set API_TOKEN --value token-123
./src/secdat --dir ~/example/project store ls
```

`domain ls` is scoped by directory. Without `--dir`, it behaves like `--dir .`, so it lists only ancestor/self/descendant domains around the current working directory. Use `--ancestors` to keep only the current domain and its ancestor side, `--descendants` to keep only the current domain and its descendant side, `-a` or `--inherited` to add the effective inherited parent chain for the current scope, and `-l` or `--long` to add the `domain status` summary columns for each listed domain. When that inherited chain reaches the user-global fallback scope, `domain ls -a` includes a presentation row labeled `*default*`. A wider base such as `--dir ~` gives you a broader registered-domain listing. The long format now includes `EFFECTIVE`, `REMAINING`, and `STATE_SOURCE` so shadowed descendants can be distinguished from local unlocks, inherited unlocks, local locks, and inherited locks. `REMAINING` shows a session lifetime such as `1h59m` or `1m32s`, and `-` when no runtime session is active.

When `domain ls -l` writes to a terminal, it now groups rows under their shared parent directory and wraps very long domain labels onto a separate line before the status columns. Non-terminal output keeps the existing tab-separated full-path layout.

`domain status` shows which domain normal commands resolve to for the current context, whether that context came from `--dir` or the working directory, and a compact summary of visible keys, stores, key source state, remaining unlock time, and the effective access state (`environment`, `local unlock`, `inherited unlock`, `local lock`, or `inherited lock`).

When no registered domain applies, user-facing `unlock` and `domain status` output show an emphasized `*default*` label for the user-global fallback scope. In other words, no registered domain resolved and commands are operating against the top-level inherited fallback scope. That label is presentation only; the implementation no longer stores or resolves that case through a domain string sentinel.

```sh
./src/secdat --dir ~/example/project/child domain status
./src/secdat --domain ~/example/project domain status
./src/secdat domain status --quiet
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

The output is shell-ready text such as `eval "export API_TOKEN=$(./src/secdat ... get API_TOKEN --shellescaped)"`; it does not print raw secret values directly. `get --shellescaped` emits a single-quoted shell literal for one secret value, and `export` reuses that path. In bash, you can either `eval "$(...)"` or source it with process substitution as `source <(...)` / `. <(...)`. Plain `. $(...)` is not valid here because `.` expects a file path, not command text. The current implementation is bash-oriented, single-quote escapes command arguments, and key names already follow shell-identifier syntax.

For command injection into a child process, `exec` accepts repeated `--pattern` and `--pattern-exclude` filters. Include patterns are ORed together, and exclude patterns are applied afterward. `--env-map-sed EXPR` adds one sed-style environment-name remapping rule for `exec`; when present, only keys matched by the substitution are injected, and the replacement text becomes the environment variable name. The current minimal subset accepts one `s///` expression, with an optional leading `/ADDRESS/` filter, and supports `&` plus `\1` through `\9` in the replacement. As with sed, the delimiter after `s` may be any non-alphanumeric, non-backslash character, so forms like `s|...|...|` and `s#...#...#` also work. Use `--` before `CMD` when the command itself or its first argument starts with `-`.

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

You can keep the active master key in a domain-scoped session agent and avoid exporting it for every command:

```sh
./src/secdat status
./src/secdat status --quiet
./src/secdat --dir ~/example/project wait-unlock --timeout 900
./src/secdat --dir ~/example/project unlock
./src/secdat --dir ~/example/project unlock --inherit
./src/secdat --dir ~/example/project inherit
./src/secdat lock
```

If `SECDAT_MASTER_KEY` is already set, `unlock` reuses it as an explicit override or migration source and can bootstrap the persistent wrapped key from it. Otherwise, the first terminal `unlock` generates and wraps a fresh master key, and later unlocks unwrap the stored master key into the current domain's session agent.

You can rotate the wrapped-master-key passphrase without changing stored secret payloads:

```sh
./src/secdat passwd
SECDAT_MASTER_KEY_PASSPHRASE='current-passphrase' ./src/secdat passwd
```

`passwd` unwraps the persistent master key with the current passphrase and re-wraps it with the new one.

For the current single-user local scope, the wrapped-key passphrase protection remains on the current KDF cost. Future hardening may revisit that cost or make it more configurable, but compatibility with existing wrapped keys must be preserved.

There is no supported raw master-key retrieval command in the normal workflow. The intended design keeps the generated master key internal to the wrapped-key and session-agent path unless an explicit future recovery/export flow is added.

Help is also available per command:

```sh
./src/secdat --help status
./src/secdat status --help
./src/secdat store --help
```

## Next implementation steps

1. Add pinentry or askpass support for non-terminal passphrase entry.
2. Revisit wrapped-key passphrase KDF cost and configurability while keeping compatibility with existing wrapped keys.
3. Expose more structured status output for scripts if a machine-readable mode becomes necessary.

