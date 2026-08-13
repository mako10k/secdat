# ADR 0007: Identity-scoped lifecycle timestamps and opt-in list display

## Status

Accepted (2026-08-13).

Tracks [issue #232](https://github.com/mako10k/secdat/issues/232) under
[issue #231](https://github.com/mako10k/secdat/issues/231). This record is a
design contract only. It does not authorize implementation, release, or
publication.

Static review covered operation symmetry, old/new reader behavior, CLI default
stability, C ABI layout, transaction replay, migration/bundle boundaries, and
unrelated-domain isolation. It produced the implementation-order correction in
this record; no implementation has been reviewed or authorized by this ADR.

## Context

Persisted v2 separates a key binding (`entry_id`) from a shared value object
(`secret_id`). `ln` creates a new binding to an existing object, while `cp`
creates both a new binding and a new object. Searchable key metadata is local to
the binding name. These are different lifecycle owners and one undifferentiated
`updated_at` would be misleading.

The current store does not maintain semantic creation or update timestamps.
Filesystem `mtime` and `ctime` reflect rewrites such as refcount repair,
reencryption, transaction recovery, and migration, so they are not lifecycle
authority.

Current v2 domain-entry and secret-object parsers reject unknown fields, and
their writers reconstruct the complete record. Adding optional fields inline
would therefore be rejected by older readers and would require every existing
writer to preserve the new fields. A full record/store-format bump would make a
metadata-only feature the compatibility boundary for every v2 operation.

The top-level `ls` default text and JSON forms are documented stable surfaces.
The installed C SDK also has a public fixed-layout metadata structure under
SONAME 0; growing that structure would change array stride for existing
callers.

## Decision

### 1. Keep six timestamps with explicit owners

Lifecycle timestamps are system-owned, read-only metadata:

| Field | Owner | Meaning |
| --- | --- | --- |
| `entry_created_at` | domain entry | The binding identity was created |
| `entry_updated_at` | domain entry | The binding name/address or entry-owned policy was last intentionally mutated |
| `metadata_updated_at` | domain entry | Searchable user metadata for this binding was last intentionally mutated |
| `object_created_at` | secret object | The shared secret object identity was created |
| `value_updated_at` | secret object | `set` last intentionally wrote the logical secret value |
| `object_metadata_updated_at` | secret object | Object-owned policy was last intentionally mutated |

`entry_updated_at` does not absorb searchable-metadata changes, and
`object_metadata_updated_at` does not absorb cached-refcount or GC maintenance.
No aggregate `updated_at` is persisted because it would erase those ownership
boundaries.

GC queue timestamps such as `gc_candidate_at`, `gc_checked_at`, and retry time
belong to the deferred-GC record designed by the next task. Mask lifecycle and
refcount-repair audit time are also outside these six semantic fields.

### 2. Store lifecycle data in identity-keyed sidecars

Core DENT1 and secret-object records and user `.kmeta` files remain unchanged.
Lifecycle records are adjacent identity-keyed sidecars:

```text
domain-ent/<entry-id>.life
objects/secret/<secret-id>.life
```

The entry record is:

```text
SECDATENTRYLIFE1
entry_id=<uuid>
entry_created_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
entry_updated_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
metadata_updated_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
```

The object record is:

```text
SECDATOBJECTLIFE1
secret_id=<uuid>
object_created_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
value_updated_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
object_metadata_updated_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
```

The file name and embedded identity must match. Each field occurs exactly once;
unknown fields, duplicates, malformed integers, and values outside signed
64-bit range are corruption. `-` means an explicitly unknown legacy value. A
missing sidecar is valid and means every field is unknown.

Writers obtain one event time from `CLOCK_REALTIME` per logical transaction and
reuse that nanosecond value for every affected field. Recovery replays that
captured value and never creates a new time. The timestamps are display and
audit hints, not transaction ordering, authorization, TTL, or conflict
authority. Clock correction may therefore make them equal or non-monotonic;
code must not compare them to decide correctness.

Sidecars are ordinary transaction `STATE_FILE` targets. A mutation that changes
a semantic facet commits its core record, lifecycle sidecar, and searchable
metadata together. An invalid existing sidecar fails a mutation touching that
identity rather than silently replacing history. Reads that did not request
timestamps need not open sidecars.

This representation keeps lifecycle concerns out of the core record parsers
and prevents core refcount rewrites from accidentally changing semantic time.
Older binaries can read the unchanged core records, but writes by an older
binary do not update lifecycle sidecars and are unsupported after lifecycle
tracking has been used. The new binary cannot prove that an old writer did not
run, so downgrade-write compatibility is explicitly not claimed.

### 3. Define lifecycle transitions by identity effect

All timestamps below use the transaction's single event time. "Preserve"
includes preserving unknown.

| Operation | Entry lifecycle | Object lifecycle | Searchable metadata |
| --- | --- | --- | --- |
| New persisted v2 `set` | create entry; set created and updated | create object; set created, value-updated, and object-metadata-updated | unknown |
| `set` existing v2 binding | preserve entry fields unless entry-owned policy also changes | preserve object-created; set value-updated on the shared object | preserve |
| `set` over an inherited/absent binding | create a local entry and object as for new `set` | create as for new `set` | unknown |
| `ln` | create destination entry; set entry created and updated | preserve all source object fields | destination metadata unknown; source preserved |
| `ln --replace` | delete old destination binding and create a new destination entry | preserve linked source object; old object lifecycle remains until GC | preserve destination key metadata content; set the new entry's metadata-updated if content exists |
| `cp` | create destination entry; set entry created and updated | create independent destination object; set all object fields | copied metadata, when present, gets destination metadata-updated at copy time |
| Identity-preserving v2 `mv` | preserve entry-created; set entry-updated | preserve all object fields | move content and preserve metadata-updated |
| Inherited-source materialization | create destination entry; set entry created and updated | preserve shared object fields | copied destination metadata gets the materialization time |
| Entry-owned `attr` mutation | preserve entry-created; set entry-updated | preserve | preserve |
| Object-owned `attr` mutation | preserve entry fields | preserve object-created and value-updated; set object-metadata-updated | preserve |
| `meta set`, `meta unset`, `meta mark-leaked` | preserve entry created/updated | preserve | set metadata-updated after a successful requested mutation, including a same-value request |
| `rm` | entry sidecar is removed with the binding | preserve object fields while the object is a GC candidate | remove binding metadata |
| `mask`, `unmask` | preserve | preserve | preserve |
| Refcount increment/decrement/repair | preserve | preserve every semantic field | preserve |
| `fsck`, GC check, transaction replay | preserve | preserve | preserve |
| v1-to-v2 migration or pre-feature v2 data | do not create history sidecars; report unknown and never infer creation from migration or filesystem time | do not create history sidecars; report unknown | unknown unless a later user mutation establishes it |
| Bundle save | no change; timestamps are not exported | no change | no change |
| Bundle load | create destination entries at one load event time | create destination objects at that time while preserving sharing inside the bundle | imported/copied metadata, if bundle support is added, gets destination time |

An operation that combines facets updates each applicable timestamp with the
same event time. Changing value storage/encryption through object attributes is
an object-metadata mutation, not a logical value mutation. A successful `set`
updates `value_updated_at` even if the supplied bytes equal the previous value;
the timestamp records user-intent writes without requiring a secret comparison.

The table is identity-based so it remains valid across implementation paths.
If an operation cannot preserve an identity (for example a v1 path), the new
identity gets creation time rather than inheriting the source identity's time.
Until the accepted UUID-stable v2 `mv` contract in ADR 0006 is implemented, the
current copy-and-delete path therefore creates fresh destination entry/object
lifecycle and removes the source lifecycle. It must not pretend to preserve
creation history merely because its command name is `mv`.

### 4. Make timestamp display opt-in

Default `ls`, `ls --metadata`, and `ls --json` output remain byte-for-byte
compatible. Add these options:

- `--timestamps`: append the six named lifecycle fields;
- `-l`, `--long`: a formatting alias for `--metadata --timestamps`.

Text uses UTC RFC 3339 with exactly nine fractional digits and `Z`; unknown is
`-`. Named tab-separated fields avoid ambiguous positional columns and compose
with canonical key output:

```text
APP_TOKEN\tentry_created_at=2026-08-13T02:03:04.123456789Z\tentry_updated_at=2026-08-13T02:03:04.123456789Z\tmetadata_updated_at=-\tobject_created_at=2026-08-13T02:03:04.123456789Z\tvalue_updated_at=2026-08-13T02:03:04.123456789Z\tobject_metadata_updated_at=2026-08-13T02:03:04.123456789Z
```

`ls --json --timestamps` adds one nested object per key; default JSON omits it:

```json
"timestamps": {
  "entry_created_at": "2026-08-13T02:03:04.123456789Z",
  "entry_updated_at": "2026-08-13T02:03:04.123456789Z",
  "metadata_updated_at": null,
  "object_created_at": "2026-08-13T02:03:04.123456789Z",
  "value_updated_at": "2026-08-13T02:03:04.123456789Z",
  "object_metadata_updated_at": "2026-08-13T02:03:04.123456789Z"
}
```

`--timestamps` and `--long` compose with include/exclude, safe/unsafe,
bulk-gate, and canonical options. They do not add sorting or filtering.
`--metadata` remains the user-facing entry/object policy view and does not
silently acquire lifecycle fields.

Within one timestamp-list invocation, object lifecycle records are cached by
the resolved `(object_domain, object_store, secret_id)` tuple so `ln` aliases do
not repeatedly open the same sidecar. The lookup still follows only the
effective entry's resolved chain and explicit object address.

For v1 and ephemeral entries the first implementation returns six unknowns.
Session-local ephemeral lifecycle tracking requires a separately versioned
agent protocol and is not inferred from agent-process time.

### 5. Extend the SDK without changing existing structure layout

Existing `secdat_sdk_key_metadata`, list functions, and their result layout stay
unchanged. Add a new structure containing six `(known, unix_ns)` pairs and a
new detail-list API that embeds the existing metadata structure plus lifecycle
data. The exact public names are:

```c
struct secdat_sdk_timestamp {
    int known;
    int64_t unix_ns;
};

struct secdat_sdk_key_lifecycle {
    struct secdat_sdk_timestamp entry_created_at;
    struct secdat_sdk_timestamp entry_updated_at;
    struct secdat_sdk_timestamp metadata_updated_at;
    struct secdat_sdk_timestamp object_created_at;
    struct secdat_sdk_timestamp value_updated_at;
    struct secdat_sdk_timestamp object_metadata_updated_at;
};

struct secdat_sdk_key_detail {
    struct secdat_sdk_key_metadata metadata;
    struct secdat_sdk_key_lifecycle lifecycle;
};
```

`secdat_sdk_list_key_details()` and
`secdat_sdk_list_key_details_with_patterns()` mirror the existing list filters
and allocation/free contract. They are additive symbols under the existing
SONAME. Numeric nanoseconds avoid locale and `time_t` width ambiguity; the CLI
alone formats RFC 3339.

FUSE continues using the existing list API. The first implementation does not
project lifecycle values into virtual `mtime`, `ctime`, or birth time: those
POSIX fields have different semantics, and exposing them would make stat-like
reads another timestamp contract.

### 6. Treat missing history and lifecycle garbage explicitly

- Missing sidecar: valid unknown history, not an fsck failure.
- Invalid sidecar for a live identity: fsck issue and fail-closed timestamp
  read/mutation for that identity.
- Entry lifecycle without its `.dent`: `orphaned-entry-lifecycle`.
- Object lifecycle without its `.sec`: `orphaned-object-lifecycle`.
- `fsck --repair` may remove confirmed orphan lifecycle files but must never
  invent creation/update times.
- Deferred GC removes the object lifecycle sidecar only when it authoritatively
  deletes the object. Candidate enqueue, cancellation, or refcount repair does
  not alter semantic lifecycle fields.

## Compatibility and sequencing consequences

The sidecars add up to two files per key/object. Until whole-state mutation
clone/diff is removed, that would amplify the currently diagnosed `set`
latency. Therefore all three design tasks may complete first, but scoped
mutation traversal must be implemented before lifecycle sidecars are enabled
by normal writers. The PERT implementation order must be corrected to reflect
that dependency.

Positive consequences:

- linked bindings and shared values have honest, separate histories;
- refcount/fsck/GC maintenance cannot masquerade as a value update;
- missing legacy history is represented without false inference;
- default CLI JSON and existing SDK ABI remain stable;
- timestamp reads stay within the already resolved child-to-parent domain
  chain and object address, with no registered-domain scan.

Costs and limitations:

- timestamp listing adds at most one entry-sidecar and one object-sidecar read
  per emitted key;
- lifecycle orphans require fsck/GC coverage;
- downgrade writes are unsupported and can leave apparently known sidecars
  stale because old binaries do not understand them;
- wall-clock timestamps are not a cryptographic audit log or total order.

### Alternatives rejected

- Inline optional DENT1/object fields: current readers reject unknown fields,
  and every complete-record writer, including refcount repair, would have to
  preserve the fields correctly in one cutover.
- New DENT/object magic or store v3: this would make every old binary reject
  the store for nullable inspection metadata and would expand migration,
  bundle, fsck, and rollback scope unnecessarily.
- User `.kmeta`: it is name-keyed, user-controlled, and removed when empty, so
  it cannot own system or identity lifecycle.
- One consolidated store-wide lifecycle index: it creates a shared rewrite
  hotspot and couples unrelated keys, which conflicts with scoped mutation and
  crash-isolation goals.
- A new `lifecycle/` directory tree: valid but more distant from the owning
  identity. Adjacent suffix-specific sidecars reuse existing identity paths,
  are ignored by old `.dent`/`.sec` enumerators, and make deletion pairing
  explicit. Old store deletion remains safely blocked until those files are
  understood or removed.

## Acceptance criteria for implementation

1. All six operation owners and transitions above have focused v2 tests,
   including shared-link `set`, independent `cp`, identity-preserving `mv`,
   metadata copy/move, refcount repair, and recovery replay.
2. Legacy v1/DENT1/object data reports null/`-`; no test uses filesystem time as
   expected lifecycle data.
3. Default text/JSON and existing SDK ABI regression fixtures remain unchanged.
4. `--timestamps`, `--long`, completion, help, man page, spec, README, Japanese
   catalog, and new SDK symbols have focused coverage.
5. Sidecars are transaction targets, unrelated domains are not opened, and
   timestamp output never reads secret plaintext.
6. Bundle round trips establish destination time and preserve link grouping,
   rather than claiming source history.
7. Optional FUSE builds and existing FUSE metadata behavior remain unchanged.

## Non-goals

- A tamper-evident audit/event log.
- Ordering mutations by wall-clock time.
- Timestamp sorting/filtering in `ls`.
- v1 or ephemeral lifecycle persistence.
- Mask lifecycle display.
- GC queue design or implementation.
- Scoped mutation implementation itself.

## Evidence checked

- `src/store.c`: v2 entry/object parsers and complete-record writers; effective
  key resolution; `ls` text/JSON; searchable `.kmeta`; set/cp/ln/mv/rm;
  migration; bundle load/save; refcount/fsck/GC paths.
- `src/secdat-sdk.h`, `src/Makefile.am`, `tests/abi_regression.sh`: public SDK
  layouts, symbols, and SONAME contract.
- `docs/adr/0006-uuid-stable-mv-and-identity-linked-masks.md`: entry/object
  identity and move/link/copy semantics.
