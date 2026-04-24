# secdat Requirements, Specification, and Design

## 1. Purpose

`secdat` is a simple local data store for managing sensitive data securely through a minimal CLI.

Its main use cases are:

- storing secrets such as API tokens and passwords
- injecting secrets into subprocess environments at runtime
- updating secrets from the CLI without editing files directly

This document consolidates the initial requirements, defines the product and security requirements, and proposes a C-based implementation design.

## 2. Requirement Summary

### 2.1 Target CLI

The intended command set is:

```text
secdat [--dir DIR] [--store STORE] ls [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]... [-x GLOBPATTERN|--pattern-exclude GLOBPATTERN]... [-e|--safe] [-u|--unsafe] [--canonical|--canonical-domain|--canonical-store]

secdat [--dir DIR] [--store STORE] list [-m|--masked] [-o|--overridden] [-O|--orphaned] [-e|--safe] [-u|--unsafe]

secdat [--dir DIR] [--store STORE] exists KEYREF

secdat [--dir DIR] [--store STORE] mask KEYREF
secdat [--dir DIR] [--store STORE] unmask KEYREF

secdat [--dir DIR] [--store STORE] get KEYREF
secdat [--dir DIR] [--store STORE] get KEYREF --stdout
secdat [--dir DIR] [--store STORE] get KEYREF [--stdout|-o]
secdat [--dir DIR] [--store STORE] get KEYREF [--shellescaped|-e]
secdat [--dir DIR] [--store STORE] get [-w|--on-demand-unlock] [-t SECONDS|--unlock-timeout SECONDS] KEYREF [--stdout|-o|--shellescaped|-e]

secdat [--dir DIR] [--store STORE] set KEYREF
secdat [--dir DIR] [--store STORE] set KEYREF VALUE
secdat [--dir DIR] [--store STORE] set KEYREF [-u|--unsafe] VALUE
secdat [--dir DIR] [--store STORE] set KEYREF [--stdin|-i]
secdat [--dir DIR] [--store STORE] set KEYREF [--env|-e] ENVNAME
secdat [--dir DIR] [--store STORE] set KEYREF [--value|-v] VALUE

secdat [--dir DIR] [--store STORE] rm [-f|--ignore-missing] KEYREF
secdat [--dir DIR] [--store STORE] mv SRC_KEYREF DST_KEYREF
secdat [--dir DIR] [--store STORE] cp SRC_KEYREF DST_KEYREF

secdat [--dir DIR] [--store STORE] exec [-p GLOBPATTERN|--pattern GLOBPATTERN]... [-x GLOBPATTERN|--pattern-exclude GLOBPATTERN]... [--] CMD [ARGS...]

secdat [--dir DIR] unlock [-i|--inherit] [-v|--volatile|-r|--readonly] [-d|--descendants] [-y|--yes]
secdat [--dir DIR] inherit
secdat passwd
secdat [--dir DIR] lock [-i|--inherit] [-s|--save]
secdat [--dir DIR] status [--quiet]
secdat [--dir DIR] wait-unlock [-t SECONDS|--timeout SECONDS] [-q|--quiet]

secdat [--dir DIR] store create STORE
secdat [--dir DIR] store delete STORE
secdat [--dir DIR] store ls [GLOBPATTERN]

secdat [--dir DIR] domain create
secdat [--dir DIR] domain delete
secdat [--dir DIR] domain ls [-l|--long] [-a|--inherited] [-A|--ancestors] [-R|--descendants] [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]
secdat [--dir DIR|--domain DIR] domain status [--quiet]

secdat [--dir DIR] [--store STORE] save FILE
secdat [--dir DIR] [--store STORE] load FILE
secdat [--dir DIR] [--store STORE] export [--pattern GLOBPATTERN]
```

### 2.2 Explicitly Stated Requirements

- displaying or interactively entering secret values through a terminal must be rejected
- stored values must always be encrypted at rest, except for an explicit `set --unsafe` plaintext path
- the implementation language is C
- the design should remain simple
- domains are isolated per OS user

### 2.3 Clarified Interpretations

To make the requested behavior implementable, the following are treated as normative:

- `get KEYREF` is equivalent to `get KEYREF --stdout`
- if the first operand is not a known subcommand and is not an assignment, `secdat KEYREF` falls back to `get KEYREF`
- `get KEYREF --shellescaped` emits a shell-escaped single-value representation suitable for `eval`-style shell assignment
- `set KEYREF VALUE` is equivalent to `set KEYREF --value VALUE`
- `set KEYREF` is equivalent to `set KEYREF --stdin`
- `set KEYREF --unsafe ...` explicitly opts into plaintext-at-rest storage that remains readable while locked
- `exec` injects matched keys into the child process environment
- `secdat --help SUBCOMMAND` and `secdat SUBCOMMAND --help` are equivalent for command-local usage output
- unique long-option abbreviations are accepted when they resolve unambiguously within the current command
- required option values accept both `--option VALUE` and `--option=VALUE`
- `--` stops command-local option parsing and leaves the remaining tokens untouched as operands
- except for `exec`, command-local options should generally be accepted before or after positional operands
- `secdat help usecases` prints workflow-oriented examples across multiple commands
- `secdat help concepts` prints detailed explanations of domains, stores, inheritance, explicit locks, sessions, and `KEYREF` resolution
- `unlock` caches the current master key in a domain-scoped runtime location
- `SECDAT_MASTER_KEY_PASSPHRASE` may provide the current wrapped-key passphrase as an explicit override for non-interactive `unlock` and `passwd` flows
- `status` reports whether a master-key session is active for the current domain scope
- `lock` clears the current domain's local master-key session
- `wait-unlock` waits until the current domain scope becomes unlocked without reading any secret value
- values are modeled as arbitrary byte strings internally
- domains are resolved from a directory context
- `--dir` is a global option that overrides the directory context used for domain resolution
- stores are domain-local namespaces, not global objects shared across domains
- reads fall back from the current domain to parent domains
- writes and deletes apply to the current domain only
- hiding a value inherited from a parent domain is represented by a tombstone

## 3. Requirements Definition

### 3.1 In Scope

- a local secret store for a single host
- single-user local workflows under one OS account
- simple CRUD operations and listing
- runtime injection into external commands
- encryption at rest
- directory-based domain separation

### 3.2 Out of Scope

- network sharing
- ACLs and multi-user collaboration
- shared-host and shared-container hardening beyond normal OS user separation
- root compromise and other host-compromise scenarios
- forwarded or multiplexed session boundary guarantees across unrelated login contexts
- automated key rotation
- secret versioning
- tamper-proof audit logs

### 3.3 Terms

- Store: a logical grouping of secrets selected with `--store`
- Store metadata and entries live inside exactly one resolved domain
- Domain: a configuration boundary associated with a directory path
- Key: the logical name of a stored value
- Key reference (`KEYREF`): `[/ABSOLUTE/DOMAIN/]KEY[:STORE]`
- `KEY` must be a valid environment-variable identifier: it starts with a letter or `_`, and the remaining characters are limited to letters, digits, or `_`
- the `/ABSOLUTE/DOMAIN/` qualifier is optional, must begin with `/`, and must include the trailing slash before `KEY`
- the `:STORE` qualifier is optional
- if the domain qualifier is omitted, the command falls back to `--domain DIR`, then `--dir DIR`, and then the current working directory
- if the store qualifier is omitted, the command falls back to `--store STORE` and then the default store
- if a write command would resolve to the implicit user-global default scope instead of a registered domain, it fails
- Value: secret plaintext
- Master key: key material used to encrypt and decrypt values
- Session: a temporary login-scoped cache of the active master key
- Tombstone: a delete marker in the current domain that hides an inherited key

### 3.4 Functional Requirements

#### FR-1 Key Listing

- `secdat ls` lists the effective keys visible from the current domain view
- `secdat ls PATTERN` and `secdat ls --pattern PATTERN` are equivalent
- `secdat ls --canonical` prints `KEYREF` with both canonical domain and canonical store suffixes
- `secdat ls --canonical-domain` prints `KEYREF` with the canonical domain suffix only
- `secdat ls --canonical-store` prints `KEYREF` with the canonical store suffix only
- output is sorted lexicographically
- output format is one key per line

#### FR-2 Value Retrieval

- `secdat get KEYREF` is equivalent to `secdat get KEYREF --stdout`
- if the first operand is not a known subcommand and is not an assignment, `secdat KEYREF` falls back to `secdat get KEYREF`
- the resolved plaintext value is written to standard output unchanged
- no trailing newline is added automatically
- it is an error if the key is not found in the effective domain view
- `get --on-demand-unlock` waits for another terminal to unlock the resolved domain scope before retrying the read
- `get --unlock-timeout SECONDS` bounds that wait and fails when the timeout expires
- `SECDAT_GET_ON_DEMAND_UNLOCK` may enable `get --on-demand-unlock` by default for one process environment
- `SECDAT_GET_UNLOCK_TIMEOUT_SECONDS` may provide the default timeout used by that wait path

#### FR-3 Value Storage

- `secdat set KEYREF` is equivalent to `secdat set KEYREF --stdin`
- `secdat set KEYREF VALUE` is equivalent to `secdat set KEYREF --value VALUE`
- `secdat set KEYREF --unsafe ...` stores the value in plaintext and does not require the master key
- `--stdin` reads bytes from standard input until EOF
- `--env ENVNAME` stores the value of the named environment variable
- `--value VALUE` stores the literal argument value
- `set` overwrites an existing key in the current domain
- `get`, `ls`, and other read paths must continue to resolve `--unsafe` entries while the runtime is locked

#### FR-3a Key Existence Query

- `secdat exists KEYREF` checks whether the resolved key is visible in the current effective domain/store view
- the command exits with status 0 when the key exists
- the command exits with a non-zero status when the key does not exist or the lookup context is invalid
- the command is intended for shell-friendly branching and should not print secret values

#### FR-3aa Local-State Listing

- `secdat list --masked` lists keys hidden by active local tombstones in the resolved current domain
- `secdat list --orphaned` lists keys with local tombstones whose parent-visible value no longer exists
- `secdat list --overridden` lists keys stored locally that also remain visible from a parent domain
- `list` operates on current-domain local state rather than the effective visible view returned by `ls`
- `list` requires at least one state filter in the initial implementation

#### FR-3b Tombstone Operations

- `secdat mask KEYREF` creates a local tombstone in the resolved current domain to hide one inherited key
- `mask` is an error when the key already exists locally in the current domain
- `mask` is an error when the key is not inherited and visible from a parent domain
- `secdat unmask KEYREF` removes one local tombstone from the resolved current domain
- `unmask` is an error when no local tombstone exists for that key

#### FR-4 Key Removal

- `secdat rm KEYREF` applies deletion in the resolved target domain and store
- `secdat rm --ignore-missing KEYREF` treats an absent key as a successful no-op
- if the key exists as a concrete entry in the current domain, that entry is removed
- if the key is only inherited from a parent domain, a tombstone is created in the current domain
- it is an error if the key does not exist in the effective domain view

#### FR-5 Key Rename

- `secdat mv SRC_KEYREF DST_KEYREF` moves a key between resolved source and destination locations
- it is an error if `DST_KEYREF` already exists in the effective destination view
- it is an error if `SRC_KEYREF` and `DST_KEYREF` are identical textually
- if `SRC_KEYREF` is inherited from a parent domain, the source name is hidden with a tombstone in the resolved source current domain after the destination is materialized
- `mv` preserves the source entry storage mode, including plaintext-at-rest entries created with `set --unsafe`

#### FR-6 Key Copy

- `secdat cp SRC_KEYREF DST_KEYREF` copies the resolved plaintext value of `SRC_KEYREF` into `DST_KEYREF`
- it is an error if `DST_KEYREF` already exists in the effective destination view
- the copied value must be re-encrypted with a new nonce
- `cp` preserves the source entry storage mode, including plaintext-at-rest entries created with `set --unsafe`

#### FR-7 Runtime Injection

- `secdat exec CMD [ARGS...]` injects the effective visible keys into a child process environment and executes the command
- repeated `--pattern GLOBPATTERN` options widen the include set for both `ls` and `exec`
- repeated `--pattern-exclude GLOBPATTERN` options remove matches from the include set for both `ls` and `exec`
- `--env-map-sed EXPR` for `exec` applies one sed-style key-to-environment-name mapping after pattern filtering; when present, only keys matched by the substitution are injected
- mapped environment variable names must remain valid identifiers; empty or otherwise invalid results are rejected
- `secdat ls --safe` lists only effective keys whose resolved entry is stored encrypted at rest
- `secdat ls --unsafe` lists only effective keys whose resolved entry is stored plaintext at rest
- `secdat exec --pattern GLOBPATTERN CMD [ARGS...]` injects only matched keys
- the initial `--env-map-sed` subset accepts a single `s///` expression with an optional leading `/ADDRESS/` filter and supports `&` plus `\1` through `\9` in the replacement text
- the delimiter after `s` may be any non-alphanumeric, non-backslash character, so `s|...|...|` and `s#...#...#` are accepted
- the parent process environment is not modified
- resolved values are decrypted and passed through an `execve`-style API

#### FR-7e Local State Inspection

- `secdat list --masked` lists current-domain tombstones that still hide a visible parent key
- `secdat list --orphaned` lists current-domain tombstones whose parent key is no longer visible
- `secdat list --overridden` lists current-domain concrete entries that override a visible parent key
- `secdat list --safe` lists current-domain concrete entries stored encrypted at rest
- `secdat list --unsafe` lists current-domain concrete entries stored plaintext at rest
- combining multiple `list` filters returns the union of the selected current-domain categories

#### FR-7c Shell Export

- `secdat export` emits bash-oriented `export ...` lines for the currently visible keys in the current `--dir` and `--store` view
- emitted lines must reference `secdat get ... --shellescaped` command substitutions rather than embedding raw secret values directly
- `secdat export --pattern GLOBPATTERN` limits output to matched keys
- emitted lines use `eval "export ...=$(...)"` so the `--shellescaped` payload is interpreted as shell syntax at assignment time
- output uses shell quoting for the command path and arguments, and currently requires keys to already be valid shell identifiers
- keys that are not valid shell identifiers cause the command to fail rather than guessing a normalization rule

#### FR-7a Session Control

- `secdat [--dir DIR] status` returns success and reports an unlocked state when `SECDAT_MASTER_KEY` is set or a valid runtime session exists in the current domain scope
- `secdat status` returns non-zero and reports `locked` when no active master-key source exists
- `secdat [--dir DIR] status --quiet` suppresses output and reports state only through the exit code
- `status` without `--quiet` reports the active source and whether a wrapped persistent master key is present
- `secdat [--dir DIR] unlock [--duration TTL] [--until TIME] [--inherit] [--volatile|--readonly] [--descendants] [--yes]` creates or refreshes a domain-scoped cache of the current master key
- `secdat [--dir DIR] wait-unlock [--timeout SECONDS] [--quiet]` waits for the current effective domain scope to become unlocked and is intended for scripts that handle external notifications separately
- `wait-unlock` exits successfully immediately when the scope is already unlocked, returns non-zero on timeout, and prints unlock guidance to standard error unless `--quiet` is used
- if no wrapped persistent master key exists, `unlock` prompts twice on a terminal, generates a fresh master key by default, stores a wrapped copy of it, and loads it into the session agent
- `unlock --volatile` redirects subsequent secret writes, deletes, and tombstone changes to a session-agent memory overlay that is cleared by `lock`
- `lock --save` persists the local volatile overlay into the real store files before clearing that local session; it must fail for non-volatile sessions
- reads, listing, export-like operations, and bundle save/load must prefer the active volatile overlay before consulting persisted store files
- when no wrapped persistent master key exists, `unlock --volatile` may generate an ephemeral in-memory master key without writing the wrapped-key file
- the current implementation removes only tombstones created in the active volatile overlay; removing persisted tombstones still requires a normal writable session
- `unlock --readonly` reuses an existing master key but must reject mutating commands while keeping reads, listing, export-like operations, and status available
- `--readonly` and `--volatile` are mutually exclusive, and neither may be combined with `unlock --inherit`
- if `SECDAT_MASTER_KEY` is already set, `unlock` may reuse it as an explicit override or migration source instead of the generated bootstrap key
- `SECDAT_MASTER_KEY_PASSPHRASE` may provide the current wrapped-key passphrase as an explicit non-interactive override for `unlock`
- otherwise `unlock` prompts on a terminal with echo disabled and unwraps the stored master key into the session agent
- `unlock --duration TTL` sets the remaining unlock time for the session being created or refreshed
- plain numeric `TTL` values are interpreted as minutes
- suffixed `TTL` values accept combined components such as `1h`, `1h30m`, `1h30m56s`, `30m`, and `56s`, including common variants like `hr`, `hour`, `min`, and `sec`
- ISO 8601 duration forms such as `PT1H30M` are accepted as relative TTL values
- `unlock --until TIME` accepts RFC 3339 absolute timestamps such as `2026-04-21T15:04:05Z` and interprets them as the target expiry time
- `--duration` and `--until` are mutually exclusive
- before prompting, `unlock` reports the resolved domain it is about to unlock
- unlocking one domain must not unlock sibling domains
- descendant domains may reuse an unlocked ancestor session without an extra `unlock`
- when the current domain is already unlocked, plain `unlock` refreshes that current domain without asking for the passphrase again
- `unlock --inherit` must not create a local unlock; it removes the current domain's local lock when present, otherwise it clears the current domain's local unlock, and succeeds only when the resulting effective state would become unlocked
- `unlock --inherit` is an error when no current-domain local lock or local unlock exists, or when the checked result would remain locked
- `unlock --descendants` applies only to the resolved target domain plus registered descendants rooted beneath it; it must never affect ancestors, siblings, or unregistered directories
- `unlock --descendants` must keep local locks intact and instead create or refresh local descendant unlocks where needed so blocked descendants become effectively unlocked for the current session lifetime
- when `unlock --descendants` would broaden access beyond the current domain, it must print the affected descendant count, warn that local locks remain in force, and require confirmation unless `--yes` is present
- when `unlock` succeeds for one domain while descendant domains remain effectively locked because of local-lock shadow state, the command must say so explicitly and print follow-up inspection/unlock commands using the correct `--dir` targets
- when a secret read fails because no active session is available, the error must report the resolved domain context and print matching `domain status` / `unlock` follow-up commands so users can unlock the correct domain
- `secdat [--dir DIR] lock [--inherit]` clears the current domain's local unlock state
- plain `lock` is a no-op success when the current domain is already locked
- when the resolved domain has a registered parent and `--inherit` is not present, `lock` must persist a local lock after clearing the local unlock
- `lock --inherit` must not clear or create local unlocks; it removes only the current domain's local lock and succeeds only when the resulting effective state would remain locked
- `lock --inherit` is an error when no current-domain local lock exists or when the checked result would become unlocked
- `secdat [--dir DIR] inherit` removes the current domain's local lock when present, otherwise clears the current domain's local unlock, without checking the resulting effective state
- the current implementation refreshes the idle timeout when the agent serves the cached key
- no raw master-key retrieval path is required for normal operation; the generated key remains internal unless a separate future recovery/export flow is introduced
- safe values still refuse terminal-based stdin/stdout for `set` and `get`
- plaintext-at-rest values created with `set --unsafe` may be read from or written to a terminal with `get` and `set`

#### FR-7d Wrapped-Key Passphrase Rotation

- `secdat passwd` re-wraps the persistent master key under a new passphrase without changing stored secret payloads
- `secdat passwd` requires an initialized wrapped master key and fails clearly if bootstrap has not happened yet
- `SECDAT_MASTER_KEY_PASSPHRASE` may provide the current wrapped-key passphrase as an explicit non-interactive override for `passwd`
- for the current single-user local scope, the wrapped-key passphrase KDF cost remains at the current setting unless a future review justifies a change
- any future increase or configurability change for the wrapped-key KDF must preserve compatibility with existing wrapped-key files

#### FR-7b Secret Bundle Save/Load

- `secdat save FILE` exports the currently visible secrets from the current `--dir` and `--store` view into a passphrase-protected bundle file
- `secdat load FILE` imports a previously saved bundle into the current `--dir` and `--store` context
- both commands require terminal-based passphrase entry; `save` asks for confirmation and `load` asks once
- the saved bundle format is a PBKDF2 + AES-256-GCM encrypted binary payload containing key/value entries from the current visible view only
- `save` refuses to overwrite an existing bundle file
- `load` overwrites matching keys in the current domain/store and leaves keys not mentioned by the bundle untouched

#### FR-8 Store Selection

- `secdat --store STORE ...` selects the target store within the resolved domain
- if `--store` is omitted, the default store is used
- stores are domain-local, so the same store name may exist independently in multiple domains

#### FR-9 Store Management

- `secdat [--dir DIR] store create STORE` creates an empty store in the resolved current domain
- creating a store that already exists in the current domain is an error
- `secdat [--dir DIR] store delete STORE` deletes a store from the resolved current domain
- deleting a store fails if the store still contains local entries or tombstones
- `secdat [--dir DIR] store ls` lists store names defined in the resolved current domain
- `secdat [--dir DIR] store ls PATTERN` and `secdat [--dir DIR] store ls --pattern PATTERN` are equivalent
- `store` management never creates, deletes, or lists stores in parent or child domains

#### FR-10 Domain Management

- `secdat [--dir DIR] domain create` creates a domain rooted at the target directory
- if `--dir` is omitted, the target directory is the current working directory
- creating a domain for a directory that already has a domain is an error
- `secdat [--dir DIR] domain delete` deletes the domain definition for the target directory
- `domain delete` does not modify parent-domain data
- `secdat domain ls` without `--dir` uses the current working directory as the listing scope
- `secdat domain ls PATTERN` and `secdat domain ls --pattern PATTERN` are equivalent
- `secdat --dir DIR domain ls` restricts the listing scope to ancestor domains of `DIR`, the domain rooted at `DIR` itself, and descendant domains under `DIR`
- sibling directories of `DIR` and their descendants are excluded from that restricted listing
- `secdat [--dir DIR] domain ls --ancestors` limits that listing to the current domain and its ancestor side
- `secdat [--dir DIR] domain ls --descendants` limits that listing to the current domain and its descendant side
- `secdat [--dir DIR] domain ls -a` / `--inherited` augments that listing with the effective inherited parent chain for the current scope, including an emphasized fallback row such as `*default*` when the chain reaches the user-global fallback scope
- combining `--ancestors` and `--descendants` is equivalent to the default `domain ls` behavior
- when `domain ls -l` writes to a terminal, it may render a human-oriented grouped view that lifts the shared parent directory into a heading and wraps long domain labels before the metadata columns
- non-terminal `domain ls -l` output must keep the tab-separated full-path rows so scripts can continue to consume the current layout
- `secdat [--dir DIR] domain ls -l` adds the key source, effective state, remaining unlock time, effective-state source, current-domain store count, visible key count, and wrapped-master-key presence for each listed domain
- the long-format effective-state source must distinguish `local-unlock`, `inherited-unlock-from:DOMAIN`, `local-lock`, `inherited-lock-from:DOMAIN`, and plain `locked`
- `secdat [--dir DIR] domain status` reports the resolved current domain used by normal store commands
- `secdat [--domain DIR] ...` uses that exact registered domain root as the current domain context
- `domain status` reports whether that resolution came from `--dir` or the current working directory
- `domain status` summarizes the visible key count, current-domain store count, key source, remaining unlock time, wrapped-master-key presence, and the effective access state for that resolved domain
- `secdat [--dir DIR] domain status --quiet` prints only the resolved domain root, or an emphasized fallback label such as `*default*` when no registered domain applies; that label means no registered domain resolved and the top-level inherited fallback scope is active

#### FR-11 Domain Resolution

- all commands accept `--dir` as a global option
- for normal store commands and `store` management commands, the current domain is resolved from the nearest ancestor domain of the base directory
- the base directory is `DIR` when `--dir DIR` is provided, otherwise it is the current working directory
- if no ancestor domain exists, commands that need fallback session context use an explicit per-user global scope instead of a domain string sentinel
- `get`, `ls`, and `exec` resolve values from the current domain and then fall back through parent domains
- `set`, `mv`, `cp`, and `rm` apply changes to the current domain only
- `store create`, `store delete`, and `store ls` apply to the current domain only
- for `domain create` and `domain delete`, `--dir` identifies the target directory
- for `domain ls`, `--dir` identifies the directory that constrains the listing scope; when omitted, that scope starts at the current working directory

#### FR-12 Inheritance and Tombstones

- if a key does not exist in the current domain, the parent domain chain may satisfy the lookup
- setting a key in the current domain shadows the same key inherited from a parent
- removing an inherited key creates a tombstone instead of deleting the parent entry
- a key hidden by a tombstone is excluded from `get`, `ls`, and `exec` in that domain and its descendants unless overridden again locally
- removing a concrete key in the current domain deletes that concrete entry
- removing a key that exists nowhere in the effective view is an error

### 3.5 Security Requirements

#### SR-1 No Direct Terminal Secret I/O

- `get` must fail if standard output is a TTY
- `set --stdin` must fail if standard input is a TTY
- the same rule applies to their default forms
- this prevents accidental screen display and interactive terminal entry of secrets

#### SR-2 Encryption at Rest

- values must always be persisted in encrypted form
- plaintext must never be written to storage files
- an AEAD construction must be used so tampering is detectable

#### SR-3 File Permission Control

- store and domain directories are created with mode 0700
- data files are created with mode 0600
- permission mismatches should be detected and treated as warnings or errors

#### SR-4 Minimize Plaintext Lifetime

- plaintext should live only in minimal in-memory buffers
- plaintext buffers must be explicitly wiped after use
- plaintext must never appear in debug logs

#### SR-5 Safe Updates

- writes must go to a temporary file first
- after `fsync`, the temporary file must replace the target atomically via `rename`
- interrupted writes should not leave partially written ciphertext as the active value

#### SR-6 Key Acquisition Separation

- master key acquisition must be abstracted from storage logic
- the implementation should provide a `key_provider` abstraction
- failure to obtain key material must cause immediate failure

#### SR-7 Per-User Isolation

- domain definitions and stored data are isolated per OS user
- no shared cross-user registry is provided
- persistent storage must stay inside a private area under the user's home or XDG data directory
- runtime session handling assumes the OS preserves privacy for the user's XDG runtime area and related local process boundaries

### 3.6 Non-Functional Requirements

#### NFR-1 Simplicity

- prefer a single binary
- do not depend on a database server
- use a file-based storage design

#### NFR-2 Practical Dependencies

- external dependencies should be limited to cryptographic libraries
- preferred candidates are libsodium or OpenSSL EVP

#### NFR-3 Portability

- Linux is the primary target platform
- the implementation assumes POSIX APIs

#### NFR-4 Operational Clarity

- error reasons should be concise and written to standard error
- exit codes should be meaningful for automation

### 3.7 Data Requirements

- key names should avoid UTF-8-sensitive semantics and remain ASCII-based
- the recommended key syntax is `[A-Za-z0-9._/-]+`
- leading `/`, trailing `/`, and `..` path segments are forbidden
- values are modeled internally as arbitrary byte strings
- `--value` and `--env` cannot carry NUL bytes

## 4. CLI Specification

### 4.1 Common Syntax

```text
secdat [--dir DIR] [--store STORE] <command> [options] [args]
```

- the default store name is `default`
- `--dir` is a global option for all commands
- `--version` prints the package version and, when Git metadata is available at build time, a short build identifier with `-dirty` appended for uncommitted worktrees
- for store commands, `--dir` changes the directory context used for domain resolution
- for `domain create` and `domain delete`, `--dir` selects the target directory
- for `domain ls`, `--dir` constrains the visible domain listing to ancestors, self, and descendants of the specified directory
- if `--dir` is omitted, domain resolution starts from the current working directory
- `--store` must appear before the command name

Examples:

```sh
printf %s "$TOKEN" | secdat set api/token
printf %s "$TOKEN" | secdat --dir /work/app set api/token
secdat get api/token > token.txt
secdat ls --pattern 'api/*'
secdat exec --pattern 'aws/*' env
secdat --dir /work/app domain ls --pattern '/work/*'
```

### 4.2 `ls`

```text
secdat [--dir DIR] [--store STORE] ls [--pattern GLOBPATTERN]... [--pattern-exclude GLOBPATTERN]...
```

- lists the effective visible keys for the resolved current domain
- without `--pattern`, all visible keys are listed
- repeated `--pattern` options are ORed together
- repeated `--pattern-exclude` options subtract matches after include filtering
- glob semantics follow `fnmatch(3)`

### 4.2aa `list`

```text
secdat [--dir DIR] [--store STORE] list [--masked] [--overridden] [--orphaned]
```

- lists current-domain local state selected by one or more state filters
- `--masked` shows tombstones that still hide an inherited parent value
- `--orphaned` shows tombstones whose parent-visible value is already gone
- `--overridden` shows local keys that still shadow a parent-visible key
- the initial implementation requires at least one filter

### 4.2a `exists`

```text
secdat [--dir DIR] [--store STORE] exists KEYREF
```

- exits with status 0 when the resolved key exists
- exits with a non-zero status when the resolved key does not exist
- writes no secret value to standard output

### 4.2b `mask`

```text
secdat [--dir DIR] [--store STORE] mask KEYREF
```

- creates a local tombstone in the current domain
- hides one inherited key from the effective visible view
- fails when the key already exists locally

### 4.2c `unmask`

```text
secdat [--dir DIR] [--store STORE] unmask KEYREF
```

- removes one local tombstone from the current domain
- restores inherited visibility when a parent still provides the key
- fails when no local tombstone exists

### 4.3 `get`

```text
secdat [--dir DIR] [--store STORE] get KEY [--stdout]
```

- fails if standard output is a TTY
- writes the raw resolved value to standard output

### 4.4 `set`

```text
secdat [--dir DIR] [--store STORE] KEY=VALUE [KEY=VALUE]...
secdat [--dir DIR] [--store STORE] set KEY
secdat [--dir DIR] [--store STORE] set KEY VALUE
secdat [--dir DIR] [--store STORE] set KEY=VALUE [KEY=VALUE]...
secdat [--dir DIR] [--store STORE] set KEY --stdin
secdat [--dir DIR] [--store STORE] set KEY --env ENVNAME
secdat [--dir DIR] [--store STORE] set KEY --value VALUE
```

- these modes are mutually exclusive
- `set KEY` means `--stdin`
- `set KEY VALUE` means `--value VALUE`
- `secdat KEY=VALUE ...` behaves like repeating `set KEY VALUE`
- `secdat set KEY=VALUE ...` behaves like repeating `set KEY VALUE`
- shorthand assignment splits on the first `=` and keeps any later `=` in the stored value
- `--stdin` fails if standard input is a TTY

### 4.5 `rm`

```text
secdat [--dir DIR] [--store STORE] rm [--ignore-missing] KEY
```

- `--ignore-missing` converts a missing-key case into a successful no-op

### 4.6 `mv`

```text
secdat [--dir DIR] [--store STORE] mv SRC_KEY DST_KEY
```

### 4.7 `cp`

```text
secdat [--dir DIR] [--store STORE] cp SRC_KEY DST_KEY
```

### 4.8 `exec`

```text
secdat [--dir DIR] [--store STORE] exec [--pattern GLOBPATTERN]... [--pattern-exclude GLOBPATTERN]... [--env-map-sed EXPR] CMD [ARGS...]
```

- without `--pattern`, all effective visible keys are injected
- repeated `--pattern` options are ORed together
- repeated `--pattern-exclude` options subtract matches after include filtering
- `--env-map-sed EXPR` accepts one sed-style substitution for exec-time environment names; when present, only matched keys are injected
- the initial subset accepts `s/REGEX/REPLACEMENT/` with an optional leading `/ADDRESS/`; replacement supports `&` and `\1` through `\9`, and the delimiter after `s` may be any non-alphanumeric, non-backslash character
- the parent process environment is unchanged

Environment variable mapping:

- uppercase the key
- replace each non-alphanumeric character with `_`
- prefix the result with `SECDAT_`
- fail on collisions after normalization

Examples:

- `api/token` -> `SECDAT_API_TOKEN`
- `db.password` -> `SECDAT_DB_PASSWORD`

### 4.9 `domain`

```text
secdat [--dir DIR] domain create
secdat [--dir DIR] domain delete
secdat [--dir DIR] domain ls [-l|--long] [-a|--inherited] [--ancestors] [--descendants] [--pattern GLOBPATTERN]
secdat [--dir DIR] domain status [--quiet]
```

- `create` registers a domain rooted at the target directory
- `delete` removes the domain definition for the target directory
- `ls` without `--dir` uses the current working directory as the listing scope
- `domain ls --pattern` filters domain roots using a glob pattern
- `domain ls -a` / `--inherited` adds the inherited parent chain for the current scope and may include a `*default*` fallback row when the user-global fallback scope participates in that chain
- `domain ls -l` prints one tab-separated summary row per listed domain using the same effective-state fields as `domain status`
- output format is one domain root per line
- with no `--dir`, the listing behaves the same as `--dir .`
- with `--dir /a/b`, the listing may contain domains rooted at `/a`, `/a/b`, and `/a/b/...`
- with `--dir /a/b`, the listing must not include `/a/c` or descendants of `/a/c`
- `status` reports the resolved current domain for normal store commands and a compact summary of stores, visible keys, key-source state, and effective access state
- `status --quiet` prints only the resolved domain root, or an emphasized fallback label such as `*default*` when no registered domain applies; that label means no registered domain resolved and the top-level inherited fallback scope is active

### 4.10 Domain Resolution Rules

When resolving the current domain for store commands:

1. start from `DIR` if `--dir DIR` is provided; otherwise start from the current working directory
2. walk upward through parent directories until the nearest matching domain root is found
3. if none is found, use the per-user default domain

Example:

```text
/work                  <- domain A
/work/app              <- domain B
/work/app/service      <- execution location
```

In this case, running from `/work/app/service` resolves domain B as the current domain. If domain B does not provide a key, reads may fall back to domain A.

## 5. Design

### 5.1 Design Principles

- keep the system file-based and simple
- store one logical key per file
- encrypt each value independently
- resolve domains by directory ancestry
- treat stores as logical namespaces inside a domain
- separate key acquisition from storage logic

### 5.2 Recommended Directory Layout

```text
$XDG_DATA_HOME/secdat/
  domains/
    registry
    by-id/
      default/
        meta
        stores/
          default/
            entries/
              api%2Ftoken.sec
            tombstones/
              db%2Fpassword.tomb
      6f1b.../
        meta
        stores/
          default/
            entries/
              db%2Fpassword.sec
            tombstones/
              api%2Ftoken.tomb
```

If `XDG_DATA_HOME` is not set, use `~/.local/share`.

Notes:

- `registry` maps absolute domain-root paths to domain IDs
- `default` is the per-user fallback domain that is not bound to any directory path
- key names are escaped before being used as file names
- `entries` remains flat for implementation simplicity
- `tombstones` contains only delete markers that hide inherited keys
- this layout can later evolve into a hierarchical on-disk structure if needed

### 5.3 File Formats

Each secret entry is stored in a single binary file.

```text
struct entry_file {
  char magic[8];          // "SECDAT1\0"
  uint8_t version;        // 1
  uint8_t algorithm;      // 1 = XChaCha20-Poly1305, 2 = AES-256-GCM
  uint8_t nonce_len;
  uint8_t reserved;
  uint32_t ciphertext_len;
  uint8_t nonce[nonce_len];
  uint8_t ciphertext[ciphertext_len];
}
```

Design rationale:

- keep a magic number and version for forward compatibility
- use an AEAD format so authentication data is bound to the ciphertext payload
- keep plaintext key names out of the encrypted entry file body

A tombstone may be an empty file, but a tiny structured format is preferable for forward compatibility.

```text
struct tombstone_file {
  char magic[8];      // "SECTOMB\0"
  uint8_t version;    // 1
}
```

### 5.4 Cryptography Design

#### Preferred Choice

- prefer libsodium
- prefer XChaCha20-Poly1305

Reasons:

- the API is comparatively simple and harder to misuse in C
- the nonce space is large enough for per-write random generation
- authenticated encryption is directly available

#### Alternative

- OpenSSL EVP with AES-256-GCM

#### Key Derivation

- this document assumes a master key can be obtained securely
- per-store or per-domain subkeys may be derived with HKDF or a similar KDF
- persistence and delivery of the master key remain out of scope here

### 5.5 Proposed Modules

```text
src/
  main.c
  cli.c
  cli.h
  domain.c
  domain.h
  store.c
  store.h
  crypto.c
  crypto.h
  key_provider.c
  key_provider.h
  fsutil.c
  fsutil.h
  exec_env.c
  exec_env.h
```

Responsibilities:

- `main.c`: entry point and exit-code handling
- `cli.c`: argument parsing and command dispatch
- `domain.c`: domain registration, deletion, listing, and resolution
- `store.c`: key listing, reads, writes, removal, rename, and copy
- `crypto.c`: encryption, decryption, and memory wiping
- `key_provider.c`: master key acquisition abstraction
- `fsutil.c`: path resolution, permission handling, and atomic writes
- `exec_env.c`: environment construction for `exec`

### 5.6 Internal Command Flow

#### `domain create`

1. canonicalize the target directory to an absolute path
2. verify that no domain is already registered for that path
3. allocate a new domain ID
4. create the registry entry and `by-id/<id>` state atomically

#### `domain delete`

1. look up the domain ID for the target directory
2. check whether child domains exist
3. if allowed, remove the registry entry
4. remove the corresponding on-disk state

#### `domain ls`

1. load the registry
2. keep only domains that are ancestors of the base directory, equal to it, or descendants beneath it
3. if `--ancestors` is present, drop descendant-only matches
4. if `--descendants` is present, drop ancestor-only matches
5. if `-a` or `--inherited` is present, union in the inherited parent chain for the current scope and append an emphasized fallback row such as `*default*` when that chain reaches the user-global fallback scope
6. if `--pattern` is provided, apply glob filtering
7. if `-l` or `--long` is provided, compute the same summary fields used by `domain status` for each listed domain and print one tab-separated row per domain
8. otherwise, print one path per line

#### `domain status`

1. resolve the current domain from `--dir` or the current working directory using the same rule as normal store commands
2. compute the resolved domain root path, or an emphasized fallback label such as `*default*` when no registered domain applies; that label means no registered domain resolved and the top-level inherited fallback scope is active
3. count current-domain stores and currently visible keys for that context
4. report whether key material currently comes from the environment, a session agent, or neither
5. report whether effective access is unlocked via environment, local session, inherited session, or locked due to default locking, an explicit lock, or an explicit-lock block higher in the domain chain
6. in `--quiet` mode, print only the resolved domain root identifier

#### `unlock`

1. resolve the current domain from `--dir` or the current working directory
2. print the resolved domain before any terminal prompt so the user sees the target scope
3. if `--inherit` is present, verify that removing the current domain's local explicit-lock marker, or clearing the current domain's local session when no marker is present, would make the resulting effective state unlocked, then apply only that local fallback change without creating a local session
4. otherwise, initialize or refresh the local session for that resolved domain
5. when `--descendants` is present, compute the affected registered descendant subtree, require confirmation for any broader-scope unlock unless `--yes` is present, and create or refresh local descendant sessions without removing explicit-lock markers
6. if `--descendants` was not requested and descendant domains under the unlocked domain remain effectively locked because they are explicit-lock roots or blocked below one, print a short summary and next-step commands for descendant inspection and descendant-specific unlocks; descendants that can already reuse the unlocked session may be summarized count-only, while descendants that remain locked are the ones listed explicitly
7. otherwise, if descendant domains exist under that branch, summarize that they can now reuse the refreshed session

#### `lock`

1. resolve the current domain from `--dir` or the current working directory
2. if `--inherit` is present, verify that removing the current domain's local explicit-lock marker would leave the resulting effective state locked, then remove only that marker without clearing a session
3. otherwise, clear the current domain's local session state
4. if the resolved domain has a registered parent and `--inherit` was not requested, persist a local explicit-lock marker

#### `inherit`

1. resolve the current domain from `--dir` or the current working directory
2. require that the resolved domain has a current-domain explicit-lock marker or local session
3. remove the local explicit-lock marker when present; otherwise clear the local session, without checking the resulting effective state

#### `ls`

1. resolve the current domain and its parent chain
2. walk `entries` and `tombstones` in precedence order
3. build the effective visible key set, favoring nearer domains
4. apply glob filtering and print lexicographically
5. when long format is written to a terminal, render the listed rows under their shared parent directory and wrap labels that would make the metadata columns unreadable

#### `get`

1. reject the request if `isatty(STDOUT_FILENO)` is true
2. resolve the key through the current domain and parent chain
3. treat a tombstone as hiding the key
4. load the encrypted entry
5. obtain the master key
6. decrypt the value
7. write plaintext bytes to standard output unchanged
8. wipe plaintext buffers

#### `set --stdin`

1. reject the request if `isatty(STDIN_FILENO)` is true
2. read standard input until EOF
3. remove any current-domain tombstone for the key if present
4. obtain the master key
5. encrypt with a fresh nonce
6. write via a temporary file and atomic rename
7. wipe plaintext buffers

#### `set --value`

1. obtain the value from the command-line argument
2. remove any current-domain tombstone for the key if present
3. encrypt and store it in the current domain
4. wipe any mutable plaintext copies if created

#### `set --env`

1. look up the environment variable with `getenv`
2. fail if the variable is undefined
3. remove any current-domain tombstone for the key if present
4. encrypt and store it in the current domain

#### `rm`

1. check whether the key exists concretely in the current domain
2. if it does, unlink the concrete entry
3. otherwise, if it is inherited from a parent domain, create a tombstone in the current domain
4. if it exists nowhere, fail

#### `mv`

1. resolve the effective source value and where it comes from
2. verify that the destination key is unused in the effective current-domain view
3. if the source is concrete in the current domain, rename it locally
4. if the source is inherited, copy it into the current domain under the new name and create a tombstone for the old inherited name

#### `cp`

1. resolve and decrypt the source value
2. re-encrypt with a fresh nonce
3. store the new entry in the current domain
4. wipe plaintext buffers

#### `exec`

1. resolve the effective visible key set
2. decrypt each value
3. map keys to environment variable names
4. detect collisions after normalization
5. launch the child with `fork` plus `execve` or an equivalent API
6. return the child's exit status from the parent

### 5.7 Error Handling

Suggested exit codes:

- `0`: success
- `1`: general error
- `2`: argument error
- `3`: key not found
- `4`: destination already exists
- `5`: security policy violation
- `6`: decrypt failure or integrity failure
- `7`: key acquisition failure

Representative error messages:

- `stdout is a terminal; refusing to print secret`
- `stdin is a terminal; refusing to read secret`
- `key not found: api/token`
- `destination key already exists: dst`
- `failed to decrypt entry: db/password`

### 5.8 Concurrency and Consistency

- concurrent `set` operations on the same key resolve to last successful atomic rename wins
- concurrent `set` and `rm` in the same domain resolve to whichever atomic state change lands last
- explicit file locking such as `flock` can be added later if needed
- the first version should prioritize atomic replacement over mandatory locking

### 5.9 Logging Policy

- by default, neither plaintext nor ciphertext is logged
- if needed, `SECDAT_DEBUG=1` may enable minimal debug logging
- even in debug mode, logs must stop at key names and never include values

## 6. Security Notes

- `set --value` can leak through shell history and process listings, so `--stdin` is operationally preferred
- `set --env` assumes the secret already exists in the parent environment and therefore carries the caller's exposure model
- `exec` places plaintext values into the child environment, so process-level observability must be considered
- deleting a domain removes local overrides and tombstones in that domain, which can cause inherited parent values to become visible again
- swap, core dumps, and similar OS-level exposures should be mitigated with host configuration

## 7. Recommended Implementation Order

1. path resolution and domain initialization
2. `set`, `get`, `rm`, and `ls`
3. encrypted persistence and decryption
4. `mv` and `cp`
5. `exec`
6. exit-code cleanup and error-message refinement

## 8. Open Questions

The following should be fixed before implementation is finalized:

1. how master key material is provided
2. whether the proposed environment variable normalization for `exec` is final
3. whether libsodium or OpenSSL is the initial dependency choice
4. whether binary-value support is officially in scope for v1
5. whether explicit locking such as `flock` should be part of v1
6. whether `domain delete` should fail when child domains exist, or whether forced recursive deletion should be a separate command

## 9. Recommended Direction

The recommended initial implementation direction is:

- file-based storage with one file per key
- directory-based domains with parent-domain inheritance
- Linux-oriented POSIX implementation
- libsodium-based AEAD encryption
- mandatory TTY rejection for `get` and `set --stdin`
- `exec` injection via `SECDAT_`-prefixed environment variables
- key acquisition abstracted behind an interface, with persistence deferred

This approach keeps the system simple enough for a C implementation while preserving the requested security properties and the intended domain semantics.
