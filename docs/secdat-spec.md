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
secdat [--dir DIR] [--store STORE] ls [GLOBPATTERN] [--canonical|--canonical-domain|--canonical-store]

secdat [--dir DIR] [--store STORE] get KEYREF
secdat [--dir DIR] [--store STORE] get KEYREF --stdout

secdat [--dir DIR] [--store STORE] set KEYREF
secdat [--dir DIR] [--store STORE] set KEYREF VALUE
secdat [--dir DIR] [--store STORE] set KEYREF --stdin
secdat [--dir DIR] [--store STORE] set KEYREF --env ENVNAME
secdat [--dir DIR] [--store STORE] set KEYREF --value VALUE

secdat [--dir DIR] [--store STORE] rm KEYREF
secdat [--dir DIR] [--store STORE] mv SRC_KEYREF DST_KEYREF
secdat [--dir DIR] [--store STORE] cp SRC_KEYREF DST_KEYREF

secdat [--dir DIR] [--store STORE] exec [--pattern GLOBPATTERN] CMD [ARGS...]

secdat unlock
secdat lock
secdat status [--quiet]

secdat [--dir DIR] store create STORE
secdat [--dir DIR] store delete STORE
secdat [--dir DIR] store ls [GLOBPATTERN]

secdat [--dir DIR] domain create
secdat [--dir DIR] domain delete
secdat [--dir DIR] domain ls [GLOBPATTERN]
```

### 2.2 Explicitly Stated Requirements

- displaying or interactively entering secret values through a terminal must be rejected
- stored values must always be encrypted at rest
- the implementation language is C
- the design should remain simple
- domains are isolated per OS user

### 2.3 Clarified Interpretations

To make the requested behavior implementable, the following are treated as normative:

- `get KEYREF` is equivalent to `get KEYREF --stdout`
- `set KEYREF VALUE` is equivalent to `set KEYREF --value VALUE`
- `set KEYREF` is equivalent to `set KEYREF --stdin`
- `exec` injects matched keys into the child process environment
- `secdat --help SUBCOMMAND` and `secdat SUBCOMMAND --help` are equivalent for command-local usage output
- `unlock` caches the current master key in a session-scoped runtime location
- `status` reports whether a master-key session is active
- `lock` clears the active master-key session
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
- simple CRUD operations and listing
- runtime injection into external commands
- encryption at rest
- directory-based domain separation

### 3.2 Out of Scope

- network sharing
- ACLs and multi-user collaboration
- automated key rotation
- secret versioning
- tamper-proof audit logs

### 3.3 Terms

- Store: a logical grouping of secrets selected with `--store`
- Store metadata and entries live inside exactly one resolved domain
- Domain: a configuration boundary associated with a directory path
- Key: the logical name of a stored value
- Key reference (`KEYREF`): `KEY[/ABSOLUTE/DOMAIN][:STORE]`
- the `/ABSOLUTE/DOMAIN` suffix is optional and must begin with `/`
- the `:STORE` suffix is optional
- if the domain suffix is omitted, the command falls back to `--dir DIR` and then the current working directory
- if the store suffix is omitted, the command falls back to `--store STORE` and then the default store
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
- the resolved plaintext value is written to standard output unchanged
- no trailing newline is added automatically
- it is an error if the key is not found in the effective domain view

#### FR-3 Value Storage

- `secdat set KEYREF` is equivalent to `secdat set KEYREF --stdin`
- `secdat set KEYREF VALUE` is equivalent to `secdat set KEYREF --value VALUE`
- `--stdin` reads bytes from standard input until EOF
- `--env ENVNAME` stores the value of the named environment variable
- `--value VALUE` stores the literal argument value
- `set` overwrites an existing key in the current domain

#### FR-4 Key Removal

- `secdat rm KEYREF` applies deletion in the resolved target domain and store
- if the key exists as a concrete entry in the current domain, that entry is removed
- if the key is only inherited from a parent domain, a tombstone is created in the current domain
- it is an error if the key does not exist in the effective domain view

#### FR-5 Key Rename

- `secdat mv SRC_KEYREF DST_KEYREF` moves a key between resolved source and destination locations
- it is an error if `DST_KEYREF` already exists in the effective destination view
- it is an error if `SRC_KEYREF` and `DST_KEYREF` are identical textually
- if `SRC_KEYREF` is inherited from a parent domain, the source name is hidden with a tombstone in the resolved source current domain after the destination is materialized

#### FR-6 Key Copy

- `secdat cp SRC_KEYREF DST_KEYREF` copies the resolved plaintext value of `SRC_KEYREF` into `DST_KEYREF`
- it is an error if `DST_KEYREF` already exists in the effective destination view
- the copied value must be re-encrypted with a new nonce

#### FR-7 Runtime Injection

- `secdat exec CMD [ARGS...]` injects the effective visible keys into a child process environment and executes the command
- `secdat exec --pattern GLOBPATTERN CMD [ARGS...]` injects only matched keys
- the parent process environment is not modified
- resolved values are decrypted and passed through an `execve`-style API

#### FR-7a Session Control

- `secdat status` returns success and reports an unlocked state when `SECDAT_MASTER_KEY` is set or a valid runtime session exists
- `secdat status` returns non-zero and reports `locked` when no active master-key source exists
- `secdat status --quiet` suppresses output and reports state only through the exit code
- `status` without `--quiet` reports the active source and whether a wrapped persistent master key is present
- `secdat unlock` creates or refreshes a session-scoped cache of the current master key
- if `SECDAT_MASTER_KEY` is already set, `unlock` may reuse it without prompting
- if no wrapped persistent master key exists and `SECDAT_MASTER_KEY` is set on a terminal, `unlock` prompts twice and stores a wrapped copy of that master key
- otherwise `unlock` prompts on a terminal with echo disabled and unwraps the stored master key into the session agent
- `secdat lock` removes the active agent-backed session state
- the current implementation refreshes the idle timeout when the agent serves the cached key

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
- `secdat domain ls` without `--dir` lists all domains owned by the current OS user
- `secdat domain ls PATTERN` and `secdat domain ls --pattern PATTERN` are equivalent
- `secdat --dir DIR domain ls` restricts the listing scope to ancestor domains of `DIR`, the domain rooted at `DIR` itself, and descendant domains under `DIR`
- sibling directories of `DIR` and their descendants are excluded from that restricted listing

#### FR-11 Domain Resolution

- all commands accept `--dir` as a global option
- for normal store commands and `store` management commands, the current domain is resolved from the nearest ancestor domain of the base directory
- the base directory is `DIR` when `--dir DIR` is provided, otherwise it is the current working directory
- if no ancestor domain exists, the per-user default domain is used
- `get`, `ls`, and `exec` resolve values from the current domain and then fall back through parent domains
- `set`, `mv`, `cp`, and `rm` apply changes to the current domain only
- `store create`, `store delete`, and `store ls` apply to the current domain only
- for `domain create` and `domain delete`, `--dir` identifies the target directory
- for `domain ls`, `--dir` identifies the directory that constrains the listing scope

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
secdat [--dir DIR] [--store STORE] ls [--pattern GLOBPATTERN]
```

- lists the effective visible keys for the resolved current domain
- without `--pattern`, all visible keys are listed
- glob semantics follow `fnmatch(3)`

### 4.3 `get`

```text
secdat [--dir DIR] [--store STORE] get KEY [--stdout]
```

- fails if standard output is a TTY
- writes the raw resolved value to standard output

### 4.4 `set`

```text
secdat [--dir DIR] [--store STORE] set KEY
secdat [--dir DIR] [--store STORE] set KEY VALUE
secdat [--dir DIR] [--store STORE] set KEY --stdin
secdat [--dir DIR] [--store STORE] set KEY --env ENVNAME
secdat [--dir DIR] [--store STORE] set KEY --value VALUE
```

- these modes are mutually exclusive
- `set KEY` means `--stdin`
- `set KEY VALUE` means `--value VALUE`
- `--stdin` fails if standard input is a TTY

### 4.5 `rm`

```text
secdat [--dir DIR] [--store STORE] rm KEY
```

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
secdat [--dir DIR] [--store STORE] exec [--pattern GLOBPATTERN] CMD [ARGS...]
```

- without `--pattern`, all effective visible keys are injected
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
secdat [--dir DIR] domain ls [--pattern GLOBPATTERN]
```

- `create` registers a domain rooted at the target directory
- `delete` removes the domain definition for the target directory
- `ls` without `--dir` lists all domain roots owned by the current OS user
- `domain ls --pattern` filters domain roots using a glob pattern
- output format is one domain root per line
- with `--dir /a/b`, the listing may contain domains rooted at `/a`, `/a/b`, and `/a/b/...`
- with `--dir /a/b`, the listing must not include `/a/c` or descendants of `/a/c`

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
2. if `--dir` is provided, keep only domains that are ancestors of the base directory, equal to it, or descendants beneath it
3. if `--pattern` is provided, apply glob filtering
4. sort lexicographically and print one path per line

#### `ls`

1. resolve the current domain and its parent chain
2. walk `entries` and `tombstones` in precedence order
3. build the effective visible key set, favoring nearer domains
4. apply glob filtering and print lexicographically

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
