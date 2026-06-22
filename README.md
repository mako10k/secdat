# secdat

Minimal C implementation of the secdat secure local secret store.

Current status:

- requirements and design are documented in `docs/secdat-spec.md`
- release and publish workflow is documented in `docs/release-workflow.md`
- repository-local coding workflow and project rules are documented in `.github/copilot-instructions.md`
- autotools support is available through `configure.ac` and `Makefile.am`
- gettext-based localization is wired in for user-facing CLI messages
- `ls`, `get`, `set`, `rm`, `mv`, `cp`, and `exec` are implemented with encrypted local storage
- `attr` is implemented for per-secret metadata such as value access and sandbox injection eligibility
- `fsck` is implemented for non-destructive v1/v2 store metadata checks used by the v2 migration path
- `gc` is implemented for explicit v2 orphaned/dangling graph cleanup after review
- `secret status` is implemented for read-only v2 secret-object metadata inspection by UUID
- `export` is implemented for shell-friendly setup without embedding raw secret values
- `save` and `load` are implemented for passphrase-protected secret bundles scoped to the current view
- `domain create`, `domain delete`, `domain ls`, and `domain status` are implemented
- `store create`, `store delete`, `store ls`, `store migrate`, and `store finalize-migration` are implemented
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
./autogen.sh --profile build
./configure
make
```

For a fuller local setup, including language-binding toolchains and debugging/search tools, install the `dev` profile once:

```sh
sudo ./scripts/bootstrap-system.sh --profile dev --install --assume-yes
./autogen.sh --profile dev --configure
```

The bootstrap helper supports Debian-family and Amazon Linux-family systems and can print or install either the narrow `build` profile or the fuller `dev` profile. The repository also ships a VS Code devcontainer and a separate build-only container recipe. See [docs/development-environment.md](docs/development-environment.md) for host setup, devcontainer usage, production-style container builds, and the recommended AI-assisted development tools.

The build now also produces `src/.libs/libsecdat.so` and installs the public C header `src/secdat-sdk.h` as `secdat-sdk.h`.

## SDK

`libsecdat` exposes a small C ABI for embedding the existing secret-store behavior without shelling out through the CLI parser.

The first SDK surface is intentionally small:

- `secdat_sdk_get()` for binary-safe reads
- `secdat_sdk_set()` for binary-safe writes
- `secdat_sdk_rm()` for deletes with optional ignore-missing behavior
- `secdat_sdk_mv()` and `secdat_sdk_cp()` for key moves and copies
- `secdat_sdk_mask()` and `secdat_sdk_unmask()` for domain-local tombstones
- `secdat_sdk_unlock()` and `secdat_sdk_lock()` for session control
- `secdat_sdk_exists()` for presence checks
- `secdat_sdk_collect_status()` for the current domain summary
- `secdat_sdk_free()` for buffers returned by the library

The public header is [src/secdat-sdk.h](src/secdat-sdk.h). Minimal bindings live under [bindings](bindings): Python uses `ctypes`, Go uses `cgo`, Rust uses `extern "C"`, and Node uses a small N-API addon.
Release tagging and package publication steps are captured in [docs/release-workflow.md](docs/release-workflow.md).

Typical native consumers can compile and run against the build tree directly during development:

```sh
cc -I./src example.c -L./src/.libs -lsecdat -Wl,-rpath,"$PWD/src/.libs"
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

The first prompt-based `unlock` generates a fresh master key, stores a wrapped copy under `XDG_DATA_HOME`, and starts a session agent scoped to the current domain. Use `unlock --duration TTL` for relative expiry values: plain numbers mean minutes, suffix forms such as `1h30m` are accepted, and `PT1H30M` style ISO 8601 durations work. Use `unlock --until TIME` for an absolute RFC 3339 expiry timestamp. Running `unlock` again while the current domain is already unlocked refreshes the current domain without asking for the passphrase again.

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

For explicit non-interactive use, `SECDAT_MASTER_KEY_PASSPHRASE` can provide the current wrapped-key passphrase to `unlock`. This is an override path rather than the default recommendation, because environment variables are easier to expose than terminal prompts. When standard input is not a terminal and no passphrase override is set, `unlock --askpass /path/to/helper` or `passwd --askpass /path/to/helper` can choose an executable askpass helper for that command. Without `--askpass`, `SECDAT_ASKPASS` is used, or `SSH_ASKPASS` when `SECDAT_ASKPASS` is unset. The helper receives the prompt text as its first argument and must print the passphrase on stdout. TTY input remains the default whenever a terminal is available.

For a session that does not write through unless explicitly saved, `unlock --volatile` keeps subsequent `set`, `rm`, `mask`, `unmask`, `cp`, `mv`, `load`, and read-side resolution changes in the session agent's memory instead of writing through to the real store files. `ln` is a persisted v2 graph operation and is not supported in a volatile overlay. `lock` clears that overlay, and `lock --save` first writes supported overlay changes into the real store files before locking. This is intended for dry-run validation and read-only filesystems.

When no wrapped master key exists yet, `unlock --volatile` can still start by generating an ephemeral in-memory master key without writing the wrapped-key file. Current volatile sessions can remove only tombstones created in the same volatile overlay; persisted tombstones and v2 local-entry deletions still require a normal writable session.

For a read-only session with the real persisted data, `unlock --readonly` reuses an existing master key but rejects mutating commands such as `set`, `rm`, `mask`, `unmask`, `cp`, `mv`, `ln`, `gc`, `load`, `fsck --repair`, `store migrate` without `--dry-run`, `store create`, `store delete`, `store finalize-migration` without `--dry-run`, and domain create/delete. `--readonly` and `--volatile` are mutually exclusive.

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

`--unsafe` is intentionally outside the normal secret workflow. It does not require the master key, remains readable while locked, and should only be used for values you accept storing in plaintext. The clearer alias is `--public-value`; encrypted values use `value_access=unlocked`.
Unsafe values may also be entered from or written to a terminal. Safe values keep the existing terminal I/O refusal.
Copying or moving a `--unsafe` key preserves that plaintext-at-rest storage mode.
For simple shell-style assignment input, you can also use `KEY=VALUE` operands directly. `secdat KEY=VALUE ...` is treated as repeated `set`, and `secdat set KEY=VALUE ...` does the same. The split happens on the first `=`, so later `=` characters stay in the stored value.
If the first operand is not a known subcommand and is not an assignment, `secdat KEY` falls back to `secdat get KEY`.
When a key lookup fails, diagnostics print close visible key candidates when available. Because `secdat KEY` is valid syntax, a bare first operand that cannot be used as a key or looks like a misspelled command reports command candidates separately as "if this was meant as a command"; unknown group subcommands such as `store migarte` likewise report close subcommand candidates.
Key names are restricted to shell/environment identifier syntax: they must start with a letter or `_`, and the remaining characters may contain only letters, digits, or `_`. `exec --env-map-sed` applies the same rule to generated environment variable names, so empty results or names with unsuitable characters are rejected.

Secret entries now have metadata attributes:

```text
key_visibility = always | unlocked
value_access   = unlocked | always
sandbox_inject = never | explicit | bulk
```

The v1 storage layout keeps key names visible on disk, so `key_visibility=unlocked` is rejected there. The v2 graph layout reads and writes split domain-entry/secret-object attributes, including hidden key names: `key_visibility=always` stores a plaintext domain-entry key name, while `key_visibility=unlocked` stores the key name as an encrypted `encrypted_key` field and requires the master key or an active session to list or resolve that key. `value_access=unlocked` is the normal encrypted-at-rest mode; `value_access=always` is the public/plaintext-at-rest mode used by `--unsafe` and `--public-value`. `sandbox_inject` marks whether `--sandbox-injectable` selection may include the key: `never` and `explicit` exclude it from that bulk policy gate, while `bulk` allows it. Plain `exec --pattern` and `export --pattern` select visible keys directly unless `--sandbox-injectable` is also present. v2 enforces this as a split check: a domain entry must allow selection and the secret object must allow the value to leave the store.

Use `attr` to inspect or update attributes:

```sh
./src/secdat set API_TOKEN --value token-123 --sandbox-inject explicit
./src/secdat attr API_TOKEN
./src/secdat attr API_TOKEN --sandbox-inject bulk
./src/secdat set PUBLIC_ENDPOINT --public-value --value https://example.invalid/api
./src/secdat attr PUBLIC_ENDPOINT --value-access unlocked
./src/secdat ls --metadata
./src/secdat ls --sandbox-injectable
```

The storage v2 layout moves from one domain-local file per key to a directory/inode-like split between domain entries and secret objects. Domain entries own key names and key visibility; secret objects own values and value access. The current v2 path includes linked secrets (`ln`) across v2 domains/stores, secret UUID references, object address metadata, object-owned payloads for new or rewritten v2 values, refcount/orphan checks, cached refcount repair, and a migration-first compatibility path from the current v1 store. Direct source-object links such as `ln @UUID DST_KEYREF` are supported only when the current context can authorize the UUID through an existing visible or unlocked domain entry; `@UUID` is a source operand, not a destination. See [docs/secdat-spec.md](docs/secdat-spec.md#510-store-v2-domain-entries-and-secret-objects).

For migration preparation and v2 cache maintenance, `fsck` checks the current domain/store without decrypting secret values:

```sh
./src/secdat fsck
./src/secdat fsck --orphaned
./src/secdat fsck --dangling
./src/secdat fsck --refcount
./src/secdat fsck --format v2 --refcount --repair
./src/secdat gc --format v2 --dry-run
./src/secdat gc --format v2 --orphaned
./src/secdat secret status UUID
./src/secdat store migrate default --to-format v2 --dry-run
./src/secdat store migrate default --to-format v2
./src/secdat store finalize-migration default --from-format v1 --dry-run
./src/secdat store finalize-migration default --from-format v1
```

Clean output is `ok`. v1 issues are tab-separated rows such as `orphaned-metadata	KEY	missing-entry`, `orphaned-tombstone	KEY	missing-parent`, `dangling-entry	KEY	invalid-entry`, or `dangling-metadata	KEY	invalid-metadata`. `--refcount` is currently a clean no-op for v1 because secret objects and hard links arrive with store v2. Stores marked with the v2 format marker can also be checked with `fsck --format v2`, which reports domain-entry/object graph issues such as `orphaned-secret	UUID	missing-entry`, `orphaned-value	UUID	missing-secret`, `dangling-entry	ENTRY_ID	missing-secret`, `dangling-value	UUID	missing-secret`, `duplicate-key	KEY	multiple-entries`, and `refcount-mismatch	SECRET_ID	expected=N actual=M`. `fsck --format v2 --refcount --repair` rewrites only rebuildable cached object refcounts and emits `repaired-refcount	SECRET_ID	expected=N actual=M`; it does not delete orphaned secrets, dangling entries, values, or tombstones.
`gc --format v2 --dry-run` reports v2 graph artifacts that would be removed as `would-remove-*` rows. Without `--dry-run`, `gc` removes orphaned secret object artifacts, standalone object value sidecars, and dangling v2 domain-entry/object artifacts, but does not touch legacy v1 key/value fallback files.
`secret status UUID` prints one v2 secret object's non-secret metadata, cached and actual refcounts, orphaned state, object payload presence, and legacy sidecar presence without reading the secret value. UUID lookup is scoped to the current domain/store object view; when following a cross-domain link, use the object-owning domain/store context for direct UUID status.
`store migrate STORE --to-format v2 --dry-run` validates the selected v1 store and prints the number of domain entries, secret objects, metadata sidecars, tombstones, public values, encrypted values, and bulk-injectable entries that would be created or preserved by the v2 migration path. Without `--dry-run`, migration writes side-by-side v2 domain-entry/object graph files, verifies them with `fsck --format v2`, marks the store as v2, and leaves the v1 value files in place for compatibility.
`store finalize-migration STORE --from-format v1 --dry-run` inspects the legacy v1 fallback files left after migration. It reports v1 entry files that still block finalization because their v2 objects do not yet have valid object-owned value payloads or valid legacy object value sidecars, and reports legacy entry/metadata files that would be removable after values have been rewritten or removed. Without `--dry-run`, it removes only those legacy entry/metadata files when no blockers remain; if any blocker exists, it reports the blockers and removes nothing.
The safe migration sequence is: dry-run migrate, migrate, `fsck --format v2`, rewrite or remove fallback-backed values, dry-run finalize, then finalize. A migrated value blocks finalization until it has object-owned v2 value material. Today that happens when the value is set again, removed, or rewritten through a value-access change; if it is already in the intended mode, change it once and change it back or set the same secret value again.
For stores marked as v2, `ls`, `exists`, `attr`, `set`, `get`, `rm`, `cp`, `mv`, `ln`, and `id KEYREF` use the v2 domain-entry/object graph. Hidden keys are visible to those commands only while unlocked; writes that could create a new v2 entry require unlock when hidden entries make absence impossible to prove. `ln SRC DST` creates another v2 domain entry pointing to the same secret object, including across explicit source/destination KEYREF domains and stores, so updates through either key affect both. `ln @UUID DST_KEYREF` uses a secret object UUID as the source only after the current context authorizes that UUID through an existing visible or unlocked entry; `@UUID` is rejected as a destination. New or rewritten v2 values are stored as a binary payload inside the secret object's `.sec` file; encrypted values use the object data key. Legacy `.value` sidecars and `SECDAT1` value payloads remain readable for migration compatibility. Domain entries record the object domain/store separately from the entry domain/store. `id` prints the resolved `secret_id` without reading the value. Migrated stores keep their preserved v1 value files as a fallback until a value is rewritten into v2 object-owned storage. v2-only errors print a migration dry-run hint; set `SECDAT_SUPPRESS_MIGRATION_HINTS=1` to hide those hints.

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
./src/secdat --dir ~/example/project store ls --json
./src/secdat --dir ~/example/project store migrate app --to-format v2 --dry-run
```

`ls --json` prints key metadata without secret values, including key name, store name, source domain, canonical key reference, safe/unsafe storage mode, and non-secret key attributes. `store ls --json` prints the resolved domain, store list, and store count.

`domain ls` is scoped by directory. Without `--dir`, it behaves like `--dir .`, so it lists only ancestor/self/descendant domains around the current working directory. Use `--ancestors` to keep only the current domain and its ancestor side, `--descendants` to keep only the current domain and its descendant side, `-a` or `--inherited` to add the effective inherited parent chain for the current scope, and `-l` or `--long` to add the `domain status` summary columns for each listed domain. When that inherited chain reaches the user-global fallback scope, `domain ls -a` includes a presentation row labeled `*default*`. A wider base such as `--dir ~` gives you a broader registered-domain listing. The long format now includes `EFFECTIVE`, `REMAINING`, and `STATE_SOURCE` so shadowed descendants can be distinguished from local unlocks, inherited unlocks, local locks, inherited locks, and orphaned registered domains whose root directories have already been removed. `REMAINING` shows a session lifetime such as `1h59m` or `1m32s`, and `-` when no runtime session is active. Use `domain ls --json` for stable domain rows with effective source/state, related domain, expiry, remaining seconds, store count, visible key count, orphaned-domain state, and wrapped-key presence.

When `domain ls -l` writes to a terminal, it now groups rows under their shared parent directory and wraps very long domain labels onto a separate line before the status columns. Non-terminal output keeps the existing tab-separated full-path layout.

`domain status` shows which domain normal commands resolve to for the current context, whether that context came from `--dir` or the working directory, and a compact summary of visible keys, stores, key source state, remaining unlock time, and the effective access state (`environment`, `local unlock`, `inherited unlock`, `local lock`, or `inherited lock`). Use `status --json` or `domain status --json` when scripts need the same state as stable JSON fields.

When no registered domain applies, user-facing `unlock` and `domain status` output show an emphasized `*default*` label for the user-global fallback scope. In other words, no registered domain resolved and commands are operating against the top-level inherited fallback scope. That label is presentation only; the implementation no longer stores or resolves that case through a domain string sentinel.

```sh
./src/secdat --dir ~/example/project/child domain status
./src/secdat --domain ~/example/project domain status
./src/secdat domain status --quiet
./src/secdat domain status --json
./src/secdat domain ls --json --long --inherited
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

For command injection into a child process, `exec` accepts repeated `--pattern` and `--pattern-exclude` filters. Include patterns are ORed together, and exclude patterns are applied afterward. `--sandbox-injectable` further restricts `exec` to keys whose effective `sandbox_inject` allows bulk selection. `export --sandbox-injectable` applies the same bulk-selection filter to emitted shell setup lines. A key with `sandbox_inject=explicit` is excluded by `--sandbox-injectable`; plain `--pattern` remains a direct visible-key selector unless that policy gate is also present. `--env-map-sed EXPR` adds one sed-style environment-name remapping rule for `exec`; when present, only keys matched by the substitution are injected, and the replacement text becomes the environment variable name. The current minimal subset accepts one `s///` expression, with an optional leading `/ADDRESS/` filter, and supports `&` plus `\1` through `\9` in the replacement. As with sed, the delimiter after `s` may be any non-alphanumeric, non-backslash character, so forms like `s|...|...|` and `s#...#...#` also work. Use `--` before `CMD` when the command itself or its first argument starts with `-`.

Bash completion source is in `completions/secdat.bash`, and `make install` installs it as `secdat` under the system bash-completion directory when bash-completion is installed and loaded by the shell. The script now asks `secdat __completion --bash` for the current command surface instead of hardcoding command tables, which keeps completion aligned with new commands and options as the CLI evolves while preserving the normal fallback that treats unknown leading operands as keys. Completion still depends on being able to execute `secdat`, so in-tree or custom-prefix testing needs the binary to resolve `libsecdat`. `make install` also installs the command reference into the system manpath from `docs/secdat.1`. For direct system installs into standard library directories such as `/usr/local/lib`, the install step also refreshes the dynamic linker cache with `ldconfig` when available so the installed `secdat` binary can resolve `libsecdat` immediately.

You can also save the currently visible secrets from one view and load them into another domain/store context:

```sh
./src/secdat --dir ~/example/project --store app save ~/backup/app.secdat
./src/secdat --dir ~/example/restore --store app load ~/backup/app.secdat
```

Both commands require a passphrase from a terminal or askpass helper. `save` exports only the secrets visible from the current `--dir` and `--store` view, writes a passphrase-encrypted bundle, and refuses to overwrite an existing bundle file. `load` imports that bundle into the current domain/store context, overwriting matching local keys but leaving unspecified keys untouched.

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
./src/secdat status --json
./src/secdat --dir ~/example/project wait-unlock --timeout 900
./src/secdat --dir ~/example/project unlock
./src/secdat --dir ~/example/project unlock --inherit
./src/secdat --dir ~/example/project inherit
./src/secdat lock
```

If `SECDAT_MASTER_KEY` is already set, `unlock` reuses it as an explicit override or migration source and can bootstrap the persistent wrapped key from it. Otherwise, the first prompt-based `unlock` generates and wraps a fresh master key, and later unlocks unwrap the stored master key into the current domain's session agent.

You can rotate the wrapped-master-key passphrase without changing stored secret payloads:

```sh
./src/secdat passwd
./src/secdat passwd --askpass /path/to/helper
SECDAT_MASTER_KEY_PASSPHRASE='current-passphrase' ./src/secdat passwd
```

`passwd` unwraps the persistent master key with the current passphrase and re-wraps it with the new one.

New wrapped master-key writes use PBKDF2 with 200000 iterations by default. Set `SECDAT_MASTER_KEY_PBKDF2_ITERATIONS` to an integer from 200000 through 10000000 before `unlock` bootstrap or `passwd` to choose the cost for the new wrapped-key file. Existing wrapped keys keep their stored iteration count when they are read, so changing the environment does not break older keys or silently rewrite them.

There is no supported raw master-key retrieval command in the normal workflow. The intended design keeps the generated master key internal to the wrapped-key and session-agent path unless an explicit future recovery/export flow is added.

Help is also available per command:

```sh
./src/secdat --help status
./src/secdat status --help
./src/secdat store --help
```

## Next implementation steps

1. Run a focused v2 architecture review against the current migrated store behavior.
