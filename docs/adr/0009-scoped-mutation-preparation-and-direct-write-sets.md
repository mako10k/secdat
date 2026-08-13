# ADR 0009: Scoped mutation preparation and direct transaction write sets

## Status

Accepted (2026-08-13).

Tracks [issue #234](https://github.com/mako10k/secdat/issues/234) under
[issue #231](https://github.com/mako10k/secdat/issues/231). This record is a
design contract only. It does not authorize implementation, release, or
publication.

Static review covered the complete operation matrix, recovery-before-prepare,
guard/write manifest separation, dependency-index generation publication,
hidden-name transitions, descendant masks, relation and domain-move closure,
load overwrite, container publication/deletion and recovery, migration,
ADR 0007/0008 integration, legacy-stage cleanup, resource bounds, and
structural/performance acceptance. No blocking or major finding remains. No
implementation or dynamic fault-injection result is accepted by this record.

## Context

Persisted v2 `set`, `cp`, `ln`, `rm`, and `load` currently enter the generic
planned-mutation path. `secdat_run_planned_mutation()` creates a staging data
home, `secdat_mutation_clone_tree()` copies nearly the complete secdat data
tree into it, the ordinary command writes into that clone, and
`secdat_mutation_append_state_diff()` recursively enumerates and reads both
`domains` trees to infer transaction targets. The staging tree is then removed.

This makes a single-key `set` proportional to unrelated persisted state even
though ordinary key resolution needs only the destination domain chain from
child to parent and the explicitly addressed object. In an isolated
measurement, increasing unrelated v2 domains from 2 to 22 increased median
`set` latency from about 500 ms to about 1.5 s, while v1 remained about 37 ms.
At 12 domains, v2 made about 773 `openat`, 666 `getdents`, and 146 `fsync`
calls, compared with 75, 4, and 2 for v1. A real 55-domain, 595-file data home
took about 4.57 s for one `set`.

The stage is serving three different purposes at once:

1. it gives existing imperative writers somewhere safe to mutate;
2. it lets later items in a batch observe earlier planned writes;
3. it discovers the final transaction write set by whole-tree comparison.

None of those purposes requires a physical copy of unrelated state. The
transaction journal already accepts exact before/after file images and replays
them after a crash. Canonical mask and unmask paths already demonstrate the
smaller pattern: resolve and validate state, construct exact targets, prepare
the journal, then commit those targets.

A second global cost exists in destructive v2 entry paths. Current `rm` and
replacement logic scans every registered domain to prove the actual secret
object reference count before deleting the object. ADR 0008 deliberately
moves that proof and physical deletion to deferred GC. Until that implementation
lands, this scan is a temporary destructive-path compatibility cost; it is not
allowed in ordinary `set`, independent `cp`, or non-replacing `ln`.

ADR 0006 also requires identity-linked masks to follow a renamed or removed
target entry. That dependency can live in descendant domains and therefore is
not discoverable from only the source domain's parent chain. Scanning all
registered domains is not an acceptable foreground solution. The dependency
must instead be directly addressable by target identity.

## Decision

### 1. Replace physical staging with one immutable prepared operation

Every covered mutation has one operation-specific prepare builder. The builder
reads through a bounded projected-state view and returns one immutable
`secdat_prepared_operation`. Dry-run and commit consume that same result; commit
must not dispatch the command a second time.

The logical interface is:

```c
struct secdat_prepared_operation;
struct secdat_prepared_state_view;

int secdat_prepare_operation(
    const struct secdat_normalized_request *request,
    const struct secdat_prepare_inputs *captured_inputs,
    struct secdat_prepared_operation **out);

int secdat_render_prepared_operation(
    const struct secdat_prepared_operation *prepared,
    enum secdat_output_mode mode);

int secdat_commit_prepared_operation(
    const struct secdat_prepared_operation *prepared);
```

The names are illustrative; the following contents and boundaries are
normative:

- one normalized request containing command, source/destination addresses,
  store selection, mask policy, and output policy;
- one operation time where ADR 0007 requires it;
- UUIDs, nonces, encrypted payloads, and other nondeterministic material
  generated exactly once;
- an observation/guard set recording every exact file and typed directory
  inventory whose state affected the decision;
- a path-coalesced write set containing canonical relative path, semantic role,
  exact before/after existence and bytes, digests, and a sensitive-data flag;
- complete mask-impact rows and other result facts used by both text and JSON;
- post-commit notifications, such as ADR 0008 `GCWAKE`, which are not part of
  durable correctness.

After construction the prepared operation is immutable. All sensitive input,
plaintext, keys, and before/after payloads are securely cleared when the result
is released, whether preparation, dry-run, commit, or rendering fails.

Input that can safely block, including reading a bundle and acquiring its
passphrase, is captured before the global mutation lock. It is bounded and
parsed for gross format errors there. The mandatory execution order is:

```text
capture bounded external input
-> acquire the global mutation/transaction lock
-> recover every older transaction
-> perform authoritative resolution and preparation
-> persist PREPARED
-> revalidate guards and write before-images
-> persist COMMITTING
-> roll forward exact writes
```

Decryption that depends on live domain/session state, preparation, and commit
occur under that one lock acquisition. Dry-run also recovers before its
authoritative preparation, then renders without creating its own transaction.
A builder is never allowed to inspect a mixed frontier left by an older
`COMMITTING` transaction. No persistent-state write other than required older
transaction recovery occurs during preparation.

### 2. Use a narrow projected-state view, not a virtual filesystem

`secdat_prepared_state_view` supports only the queries needed by mutation
builders:

- exact-file lookup, consulting the current write overlay before live state;
- typed directory inventory for one explicit domain/store directory, merging
  live records with planned creates, replacements, and deletes;
- effective-key and inherited-key resolution over an explicit child-to-parent
  domain chain;
- canonical-mask resolution in an explicit current domain/store plus the
  target entries reached through its explicit parent chain;
- explicit object lookup by `(owner_domain_id, owner_store, secret_id)`;
- exact reverse-dependency lookup by stable identity where section 4 requires
  it.

It is not a generic POSIX interception layer and must not accept an arbitrary
data-root path or recursively copy a directory. Each builder has to name a
typed query and its permitted scope. This makes an accidental return to
whole-tree traversal visible in review and tests.

An exact-file guard records existence, size, and digest. A typed directory
guard records a canonical sorted inventory of only the record
kinds relevant to the decision, including names and digests where content was
examined. Absence derived from an inventory is valid only while that inventory
guard still matches. Commit revalidates guards and all write before-images
while holding the mutation lock. A mismatch fails with
`changed since plan`; preparation is not silently repeated inside commit.

Hidden-key storage may require enumerating all typed entries in one relevant
domain/store because a name cannot be indexed without its key. That is a
legitimate fail-closed chain-local inventory. It does not authorize sibling,
descendant, or registered-domain traversal.

### 3. Coalesce exact writes before constructing transaction targets

The overlay is keyed by canonical relative path. Its first mutation captures
the live before-image and every later mutation reads the current planned
after-image. Coalescing follows these rules:

| Sequence on one path | Final write-set entry |
| --- | --- |
| create, then update | absent to final bytes |
| create, then delete | no target |
| update one or more times | original bytes to final bytes |
| delete, then recreate | original bytes to replacement bytes |
| same before and after | no target |

Two builders assigning incompatible semantic ownership to one path is an
internal planning error, not last-writer-wins behavior. Targets carry a fixed
application phase and are sorted by `(phase, canonical relative path)` before
journal construction. The normative dependency-update order is reference epoch
when required, immutable dependency nodes, affected primary mask/relation or
entry records, then `dependency-state` active-root publication. The active root
has a dedicated phase and is never ordered by its pathname. For creation, a
complete container precedes the registry/root
pointer that publishes it. For deletion, the registry pointer is removed before
the empty container. Move publishes a validated destination before removing
the source pointer. Recovery uses the identical operation-specific order.
`changed_file_count` counts only non-no-op write targets, never read guards.

The transaction manifest advances to version 2 and separates validation-only
`guards` from replayable `writes`. The new loader remains backward-compatible
with version 1; an old strict loader is not expected to read version 2. Existing
validation-only `DOMAIN_ENTRY` targets are the precedent; the new guard model
also represents typed directory inventories without pretending that a
directory digest is a file after-image. A guard stores no semantic after-image
and is never applied. The loader continues to recover older version-1
manifests before starting a new compatible mutation. Unknown future versions
remain fail-closed.

The transaction record remains the recovery authority. After the outer
recovery-before-prepare sequence, commit:

1. persists the bounded guard/write manifest and exact write blobs as
   `PREPARED`;
2. revalidates every guard and write before-image immediately before the
   commit point;
3. advances the durable state to `COMMITTING`;
4. applies the sorted exact after-images;
5. completes using the existing roll-forward recovery contract;
6. releases the mutation lock and only then sends best-effort wakeups.

Recovery never reruns a builder, obtains a new clock value or UUID, decrypts a
value again, or recomputes mask/refcount decisions. Directory creation needed
for a planned file is performed by the transaction target applier with its
existing secure component validation and parent-directory fsync rules. Empty
directories left by deletion are harmless.

The `STATE_FILE` target allowlist remains deny-by-default. It is extended only
for the exact ADR 0007 lifecycle paths, ADR 0008 reference epoch and candidate
paths, and the dependency records in section 4. Arbitrary top-level paths and
symlinked/non-canonical components remain invalid.

Recovery of `STAGING` or `PREPARED` cleans the unpublished operation exactly as
today. Recovery of `COMMITTING` validates only the replayable write frontier:
each write must still match either its before- or after-image, after which all
remaining after-images are rolled forward. Guards are not re-evaluated after
the durable commit point. `COMMITTED` verification likewise checks write
after-images only.

Preparation enforces all of these first-version resource limits before making
an operation directory:

- at most 4096 guards plus writes;
- at most 4096 records and 16 MiB of canonical encoded data in any one typed
  directory guard;
- at most 64 MiB for the complete manifest plus guard encodings;
- at most 256 MiB total before/after blob bytes, including a `CONTAINER_TREE`;
- existing per-record limits remain independently enforced.

Limit overflow fails closed and writes nothing; automatic transaction chunking
is forbidden because it would weaken batch/container atomicity. Directory
guards persist only canonical storage record type, filename or stable ID, size,
and content digest. They never persist a decrypted logical hidden name. Raising
any bound requires separate transaction memory/disk exhaustion review.

### 4. Make cross-descendant dependencies directly addressable

Ordinary `set` and mask evaluation read the current domain and its explicit
parent chain. They do not enumerate registered domains. The same rule applies
to destination absence checks for `cp`, `ln`, and `load`.

The bounded exceptions are operations that must mutate records outside those
chains because an existing record names the identity being moved or removed:

- identity masks keyed by `target_entry_id`;
- name-based relation members affected by an ADR 0006 move.

Compatible v2 writers maintain one copy-on-write reverse index whose paths are
hash-authenticated relative to a guarded active root:

```text
indexes/dependency-state
indexes/dependencies/nodes/<first-two-hex>/<node-sha256>.idx
```

The active root is a persistent Merkle-radix map. Content-addressed immutable
branch and leaf nodes are strict `SECDATDEPNODE1` records, are at most 16 KiB,
and have mode `0600` below `0700` directories. Their canonical bytes hash to
their filename; child hashes commit the complete subtree. The top map uses three
key spaces:

- `M || target_entry_id` maps to a second hash-committed edge set containing
  every identity mask for that entry;
- `R || SHA256(length-prefixed canonical KEYREF)` maps to a second hash-committed
  edge set containing every relation that references that KEYREF.
- `D || referenced_domain_id` maps to relation-member dependencies whose
  canonical KEYREF embeds that registered domain root.

A mask edge contains target entry ID, exact mask domain/store and record ID,
and the primary mask-record digest. A relation-member dependency contains only
the KEYREF hash, referenced domain ID, exact relation domain/store and relation
ID, and the primary relation-record digest. It never contains the plaintext
KEYREF. The same dependency is indexed under both its `R` and `D` lookup keys.
A relation has one dependency per distinct referenced KEYREF regardless of how
many member roles use it. Paths, embedded identities, primary digests, node
hashes, sorted radix slots, and referenced primary records must all agree.
Unknown or duplicate fields, non-canonical addresses, invalid hashes, oversized
nodes, missing child nodes, and primary mismatches are corruption.

The hash-authenticated path supplies both inclusion and absence proof relative
to the guarded active root without
enumerating unrelated dependency keys. Updating a dependency writes new
immutable nodes only along its affected radix paths and changes the small active-root record
in the same transaction as the primary record. Old unreachable nodes are not
deleted in foreground; explicit index maintenance may collect them later.

The strict root record is:

```text
SECDATDEPSTATE1
schema_version=1
writer_contract=indexed-mutations-v1
state=<building|complete>
build_id=<uuid>
active_root=<lowercase-sha256-or-dash>
building_generation=<uuid-or-dash>
```

Each field occurs exactly once; unknown fields and trailing data are rejected.
`complete` requires an active root (including the canonical empty-tree root)
and `building_generation=-`. `building` requires a generation UUID and may
retain the prior active root for diagnostics, but every reverse-dependent
mutation fails closed while that state is present. Missing or malformed state
is incomplete, never an empty index.

Rebuild and first activation use this publication protocol while holding the
global mutation lock:

1. recover older transactions;
2. durably replace the state with `building`, a new `build_id` and generation
   before creating or changing any index artifact;
3. scan the complete primary mask/relation scope, write content-addressed nodes
   for a new root, and fsync every node and directory;
4. rescan and verify every primary-to-edge and edge-to-primary mapping, hidden
   visibility rule, node hash, and the resulting root;
5. atomically publish `complete`, the validated root and the same `build_id`,
   then fsync the index directory;
6. leave old or crash-orphaned nodes for explicit maintenance.

A crash before step 5 leaves `building`; ordinary reverse-dependent mutation
remains blocked until explicit rebuild restarts with a new generation. A crash
after the atomic publication has a complete durable root. Lookup guards both
`dependency-state` and every hash-committed node it traverses. Normal compatible
mask, unmask, rebind, relation, migration, import, domain/store inventory, and
deletion writers update primary records, new index nodes, and the active root
in one transaction. Bulk activation that would exceed the transaction limit
uses the building/publication protocol and cannot make its primary inventory
visible while coverage is incomplete.

Current relation creation rejects hidden v2 key names. This prohibition remains
part of `indexed-mutations-v1`: neither relation edges, node keys, guards,
journals, plan JSON, effect digests, nor diagnostics persist a hidden logical
name. A future relation format that permits hidden members needs a separate
encrypted/keyed lookup design before this writer contract can change.

An entry-owned `key_visibility` transition has an additional mask dependency
closure. Preparation reads the complete `M || entry_id` set and every named
mask primary. A visible-to-hidden transition rewrites all plaintext last-known
name material into the ADR 0006 mask-domain-key encryption, then writes the
mask primaries, replacement dependency nodes/root and entry record in one
prepared transaction. Any relation dependency rejects the transition as today.
Missing coverage or inability to unlock, validate, decrypt or re-encrypt one
affected mask fails before mutation. Hidden-to-visible follows the accepted
ADR 0006 representation policy through the same complete set; it never exposes
a name merely as a convenience side effect.

The index is authoritative planning state, not a deletion authority. Missing,
building, corrupt, or unverifiable coverage fails reverse-dependent mutation
with `fsck --dependency-index` repair guidance; it never falls back to a
registered-domain scan. `fsck --dependency-index` may explicitly perform the
full validation/rebuild protocol.

For an identity-preserving `mv`, the builder enumerates only the reverse edges
for the preserved `entry_id`, then reads the named mask records and the
explicit child-to-parent chain of each affected mask domain when fallback
analysis is needed. For `rm`, it does the same before orphan/fallback
continuation planning. Relation consequence reporting reads only the reverse
edges for the exact moved source key reference. Work may scale with actual
dependencies of the changed entry, never the total registered-domain count.

For `domain move`, the builder reads `D || moved_domain_id`, then the named
relation primaries. It rewrites every member canonical KEYREF from the validated
old root to the new root and replaces the corresponding `R` and `D`
dependencies and active root in the same bounded transaction as domain
metadata/registry changes. This covers local and inherited KEYREFs without
enumerating keys or unrelated relations. If any named relation is inaccessible,
ambiguous or over the transaction bounds, the move fails before publication.

This section narrows ADR 0006 section 12: “every affected registered domain”
means domains named by complete reverse dependencies for an identity-changing
operation, not enumeration of all registered domains. Derived visibility-state
changes in other descendants that require no persistent rewrite are recomputed
when those domains are read and are not mutation targets. The mask safety,
last-known-name, fallback-remasking, propagation, ambiguity, and fail-closed
requirements of ADR 0006 remain unchanged.

Old binaries or direct-disk writers cannot maintain this index and are not
compatible writers after indexed mutation is enabled. Downgrade reads may
remain possible, but downgrade writes require a subsequent explicit index
validation/rebuild before reverse-dependent mutation is allowed.

### 5. Fix each operation's dependency closure

Common preparation may read current domain identity, its explicit parent
chain, selected store-format markers, writable authorization/session state,
and transaction recovery state. It may inventory typed records only in the
operation scopes below.

| Operation | Bounded reads and validation | Exact planned writes |
| --- | --- | --- |
| `set`, existing local binding | Destination child-to-parent chain; local entry; its explicitly addressed owner object and legacy value if present; current-domain masks/tombstone. An entry-visibility change additionally reads the complete reverse mask set and exact relation dependencies | Shared owner object after-image; entry only if its representation/policy changes; legacy value deletion; current-domain mask/tombstone reconciliation. Visible-to-hidden also re-encrypts every affected mask primary and replaces dependency nodes/root; any relation dependency rejects. Later ADR 0007 sidecars and stale ADR 0008 candidate cancellation join the same writes. No reference-epoch rotation when the binding is unchanged |
| `set`, absent or inherited-only key | Destination chain and chain-local absence/ambiguity/masks | New local entry and independent object; tombstone reconciliation; ADR 0007 creation sidecars; one reference-epoch rotation |
| `rm`, local v2 entry | Destination chain; local entry and metadata; explicitly addressed object; current-domain masks; complete reverse mask dependencies for that entry and only their named fallback chains | Entry, metadata and entry-lifecycle deletion; fallback mask continuation/reconciliation; ADR 0008 candidate enqueue, cached-refcount hint delta, and one reference-epoch rotation. Object/value deletion is deferred after ADR 0008 |
| `rm`, inherited key | Destination chain plus current-domain canonical mask/tombstone state | Canonical mask and rollback-compatible tombstone only; no reference or object change |
| `cp` | Source child-to-parent chain, resolved entry/object/value/attrs and copyable metadata; destination chain and chain-local absence/masks | New independent destination object and entry; copied metadata as new destination state; ADR 0007 creation times; one ADR 0008 reference-epoch rotation; destination tombstone reconciliation |
| `ln` | Source chain or explicit object address; destination chain and absence/masks; when replacing, old local destination entry/object/metadata and its reverse mask dependencies; optional same-value comparison reads only the two addressed objects | New destination entry sharing the source object; cached-refcount hint and candidate cancellation; destination lifecycle; one reference-epoch rotation. Replacement also removes the old entry state and enqueues its old object in the same transaction |
| `mv`, local concrete source in one domain/store | Exact source/destination slots in that chain; source entry/object address; destination absence/masks; source metadata; reverse mask dependencies for the source `entry_id`; reverse relation dependencies for the source key reference | ADR 0006 rename of the same `.dent` identity, metadata/lifecycle name move, affected masks and index root; preserve object, candidate, refcount and reference epoch. It never falls back to plaintext `cp` plus `rm` |
| `mv`, local concrete source across namespaces | Exact source/destination chains; source entry/object address; destination absence/masks; source metadata; the same reverse dependencies | Preserve `entry_id`/`secret_id`, move/re-wrap the entry and metadata/lifecycle, update affected masks and index root, preserve candidate/refcount, and rotate the reference epoch once because the physical reference address changes |
| `mv`, inherited source | Exact source/destination chains; inherited entry and owner object; source-view and destination masks; pre-existing reverse mask dependencies selected by ADR 0006 propagation policy; reverse relation edges for the source key reference | A new destination entry referring to the same object, new entry lifecycle, source-view mask/fallback records and dependency edges, cached-refcount hint increment, candidate cancellation, and one reference-epoch rotation. The inherited source entry remains |
| `load` and multi-key mutation | Bundle/input captured once; one explicit destination chain per addressed namespace; typed chain-local inventories and masks; overlay results of prior items. `reject` fails on the first projected conflict, `skip` records no effect for that item, and `overwrite` additionally reads the old entry/object/metadata/lifecycle and reverse mask dependencies | One coalesced transaction. First accepted label for an SDB2 object creates a fresh destination object; later labels share that projected object. Overwrite removes old entry state, plans required mask continuations, enqueues the old object, creates no candidate action for the fresh object, and coalesces per-object refcount deltas. One operation time and at most one reference-epoch rotation |
| `mask`, `unmask`, `mask --rebind` | Current domain/store masks and tombstones; explicit inherited target chain; selected chain records; for rebind, the exact fallback chain | Canonical masks, compatibility tombstones, and mask reverse edges atomically. These paths migrate from their existing direct plans to the common prepared-operation representation |
| `attr` | Resolved entry and addressed object. An entry-visibility change additionally reads the complete reverse mask set and exact relation dependencies | Exact entry/object policy records and corresponding ADR 0007 lifecycle sidecars atomically. Visible-to-hidden re-encrypts affected mask primaries and replaces dependency nodes/root; any relation dependency rejects. Never a global reference scan |
| `meta set/unset`, `mark-leaked` | Resolved local entry/name metadata; `mark-leaked` prepares its later suggestions from the exact relation reverse lookup before commit | `.kmeta` and entry lifecycle sidecar atomically; no object or global scan. Suggestions render from prepared result facts after commit and are not mutation targets |
| relation mutation | Addressed relation record and exact member key references/chains | Relation record and relation reverse edges atomically; suggestion/list scans are not part of mutation |
| `store create` | Exact target-domain store inventory and absence; bounded canonical empty skeleton | Rotate the reference epoch durably, then publish one exact empty `CONTAINER_TREE`; no candidate, lifecycle, or dependency edge |
| `store delete` | Exact known-empty store skeleton; dependency-index absence; ADR 0008 owner/store candidate and quarantine shards must be empty | Rotate the reference epoch before unpublishing the exact empty `CONTAINER_TREE`. It never discards candidate, quarantine, object, entry, lifecycle, or unknown artifacts |
| `domain create/register` | Canonical root identity; registry absence; parent relationship; bounded empty domain/default-store skeleton | Rotate the reference epoch before atomically publishing the exact by-id container and registry/root metadata. No data-bearing tree is adopted implicitly |
| `domain move` | For a changed root: exact source/destination registry slots, root identities, child-domain constraints and domain metadata; complete `D || domain_id` dependencies and their named relation primaries. `--allow-same-root` needs only exact root-identity metadata | Changed root rewrites canonical old-root KEYREF members, their `R`/`D` dependencies and index root; updates root/identity metadata and explicitly ordered registry targets; rotates the reference epoch before destination visibility. The by-id entry/object tree stays in place; an over-limit or inaccessible relation closure rejects the move. Same-root refresh changes only root-identity metadata: no registry target, dependency update, or epoch rotation |
| `domain delete` | Child-domain registry guard; exact known-empty domain skeleton; no owned entries/objects/migration artifacts; owner candidate and quarantine shards empty; no foreign dependency/object-owner edge | Rotate the reference epoch, unpublish registry state, then remove only the exact empty `CONTAINER_TREE`. Data-bearing or unknown state fails closed |
| `store migrate` | Complete selected legacy store and rollback/mask scope only; destination target count/byte bounds; complete dependency rebuild inputs | One atomic bounded conversion, one reference-epoch rotation, cancellation of candidates for identities it creates/references, no new candidates, lifecycle history left unknown, and dependency coverage published only through section 4. Unrelated stores/domains are not read |
| `store finalize-migration` | Selected store's validated migration backup and canonical v2 state | Delete only the validated migration backup. Do not rotate the epoch or change candidates, objects, entries, lifecycle, or dependency coverage |
| `fsck`, `gc` | Their explicitly requested maintenance scope | Their accepted repair/collection writes; excluded from foreground key latency |

`CONTAINER_TREE` is a new, narrowly allowlisted transaction artifact, not an
arbitrary recursive tree target. Its manifest lists every permitted relative
directory and administrative file, mode, size and digest; symlinks, devices,
unknown names, value-bearing records and an over-limit tree are invalid. Create
builds and fsyncs the exact after-tree inside the operation journal, then the
COMMITTING applier revalidates an absent destination and uses fd-relative
no-replace rename to its canonical destination, then fsyncs the parent. Delete
is allowed only after immediately revalidating a manifest-matching empty
skeleton; the applier atomically renames it into the operation journal before
reporting the live after-state as absent. The removed tree stays recoverable
until COMMITTED cleanup. This artifact cannot migrate, delete, or stage a
data-bearing store.

The initial schemas are exact:

| Schema | Required tree | Optional empty compatibility tree | Forbidden |
| --- | --- | --- | --- |
| `empty-store-v1` | root, `entries/`, `tombstones/`, all mode `0700` | `key-meta/`, `relations/`; strict `format` may be absent or have exact bytes `SECDATSTORE1\nformat=v1\nstate=ready\n` | every other name and every nonempty data directory |
| `empty-store-v2` | root, `entries/`, `tombstones/`, `domain-ent/`, `objects/secret/`, `key-meta/`, `relations/`, exact `format` bytes `SECDATSTORE1\nformat=v2\nstate=ready\n`; directories mode `0700`, file mode `0600` | empty `masks/` and empty format-version-declared future lifecycle directories only after their schema revision is accepted | entries, objects, masks, lifecycle records, migration backup, unknown artifacts |
| `empty-domain-v1` | root, `meta/root`, `meta/root-identity`, `stores/default/` matching `empty-store-v1`; directories `0700`, metadata files `0600` | additional named stores only when each independently matches an accepted empty-store schema | owned data, unknown metadata, sessions/locks, migration artifacts, unrecognized store schemas |

One tree has at most 64 directories plus administrative files; nested depth is
at most four below its canonical root. Optional directories are named by the
selected schema and must be empty. A future lifecycle or store-format revision
must revise this table before container deletion accepts its directory names.

Recovery enumerates these states without recursive rediscovery beyond the
bounded manifest. For create, PREPARED has one journal after-tree and an absent
live destination, so cleanup deletes only the journal tree; COMMITTING has
exactly one verified after-tree at journal or live location and rolls it to
live; COMMITTED requires the verified live tree and removes journal metadata.
For delete, PREPARED leaves the verified before-tree live; COMMITTING has it at
exactly one live or journal location and rolls it into the journal; COMMITTED
requires live absence and then deletes the journal-held before-tree. Both
locations present, neither location present, identity/mode drift, a symlink or
manifest mismatch is corruption and never licenses recursive removal.

Registry files and reference epoch remain ordinary exact file targets in the
same transaction. Phase ordering makes the epoch durable first, a created
container complete before registry publication, and registry unpublication
complete before container deletion. A crash at any later target is completed
by normal COMMITTING recovery. Operations larger than the bounds in section 8
fail before creating either a file target or a container tree.

The role phases are fixed as follows:

```text
store create:          epoch -> container
domain create:         epoch -> by-id container including metadata -> registry
store delete:          epoch -> container removal
domain delete:         epoch -> registry removal -> container removal
domain move:           epoch -> dependency nodes -> relation primaries
                       -> dependency root -> root metadata
                       -> destination registry -> source registry removal
domain same-root:      root-identity metadata only
```

`set` through any `ln` alias updates the one shared addressed object and does not
enumerate the other aliases. `cp` always creates an independent object. `ln`
always shares the addressed object. These object semantics are determined from
the resolved entry/object tuple, not from a graph scan.

If a legacy v2 object lacks canonical direct object-key material, preparation
may use material already carried by the resolved entry but must not search all
sibling `.dent` records for a usable key. Explicit migration/fsck normalizes
that legacy state. A normal scoped mutation fails closed with repair guidance
when neither the addressed object nor resolved entry is sufficient.

Before ADR 0008 is implemented, only local `rm` and destination replacement may
retain the current synchronous actual-reference scan and foreground object
delete. That temporary compatibility branch is named in code and tests, never
called by value-only `set`, non-replacing `ln`, or independent `cp`, and is
removed—not merely bypassed—when ADR 0008 routes those operations.

### 6. Give batches sequential projected semantics and one atomic commit

A batch is prepared in input order against the overlay. Item N therefore sees
the final planned result of items 1 through N-1 without any disk mutation.
Destination conflicts, duplicate keys, link aliases, mask transitions, object
hint deltas, lifecycle transitions, and candidate enqueue/cancel effects use
that projected state.

Failure of any item discards the complete prepared operation. One path has one
first before-image and one final after-image, object candidate effects are
coalesced by canonical owner tuple, and reference topology changes rotate the
ADR 0008 epoch once. One ADR 0007 event time applies to the complete logical
operation. The transaction target limit is checked after coalescing and before
journal preparation.

SDB2 import preserves current sharing semantics within the batch: the first
accepted label materializes a fresh destination object and subsequent labels
for that bundle object reference its projected object. Skipped items do not
leave writes. A conflict or malformed item after a valid earlier item leaves
the persisted store unchanged.

For a general operation that removes and recreates a reference to the same
existing object, the net cached-refcount delta is zero and the final candidate
effect is cancel: the object is still referenced. Repointing between existing
objects enqueues the old tuple and cancels the new tuple. SDB2 import does
neither: overwrite removes the old binding and creates a fresh bundle object,
so it enqueues only the old tuple and treats any UUID collision as an error.
Intermediate per-item actions never escape the coalesced transaction.

### 7. Keep dry-run and commit on the same semantic path

The same builder and prepared result produce rejection diagnostics, dry-run
text/JSON, and committed effects. `--dry-run` renders the result, performs no
transaction write, clears it, and exits. A committing invocation renders
warnings/results only from the prepared facts that it actually commits.

The existing public mutation-plan schema and ordering remain stable. This ADR
does not add a public plan hash. Tests may compute an internal effect digest
over normalized semantic facts and sorted write roles. With a frozen clock and
deterministic randomness, dry-run and commit preparation must produce the same
effect digest. Separate real invocations naturally have different UUIDs,
nonces, and ciphertext and are not required to be byte-identical.

`--mask-action=reject` still returns the complete authorized impact plan but
never constructs or commits a partial transaction. Warning suppression changes
only presentation, never prepared decisions or writes.

## Invariants

1. Foreground `set` never calls registered-domain collection, actual-reference
   counting, data-root clone, recursive data-root diff, or staging-home setup.
2. A normal key mutation visits only explicit source/destination parent chains,
   explicitly addressed object owners, current-scope mask state, and strict
   reverse dependencies named by the changed identity.
3. Absence is accepted only from a complete typed inventory of the relevant
   domain/store or an equally authoritative exact index. Inaccessible, hidden,
   ambiguous, corrupt, or changed relevant state fails before a write.
4. No fail-closed mask behavior is weakened. Bounded lookup changes discovery,
   not the required mask transition.
5. Every committed path was present with exact before/after images in the one
   prepared operation; recovery applies those images without semantic replay.
6. Shared-link value update, independent copy, shared link creation, and
   UUID-stable move retain the identities defined by ADR 0006.
7. Refcount fields, GC candidates, and reverse edges never authorize secret
   deletion. Only ADR 0008's stable-epoch authoritative scan does so.
8. Compatible foreground cost is independent of unrelated registered-domain
   and file count. It may scale with explicit chain length, batch size, value
   size, and the actual reverse dependencies of identities being changed.

## Migration and rollout

Implementation is split at the causal cut point rather than by command-local
optimizations:

1. add the prepared-operation, projected-view, guard, path-coalescing,
   and exact-target framework behind no command route;
2. add/rebuild/validate the strict hash-committed dependency index and
   normalize legacy object-key material through an
   explicit migration/fsck path; do not mark dependency coverage complete
   until primary records, guarded root and dependencies agree;
3. route persisted v2 `set` first, preserving the existing public plan output,
   and prove it has no stage/global traversal;
4. route `cp`, non-replacing `ln`, `rm`, replacement, `load`, multi-key, and the
   ADR 0006-compliant `mv`; retain the named temporary destructive reference
   scan only until ADR 0008 is active;
5. adapt mask/unmask/rebind and multi-file attr/metadata/relation changes to the
   common exact-target helpers;
6. remove generic stage creation, clone/diff, and staging `XDG_DATA_HOME`
   mutation after every formerly routed command uses direct preparation;
7. implement ADR 0008 on the bounded write-set foundation and remove the
   synchronous reference scan/object delete from all foreground paths;
8. implement ADR 0007 lifecycle sidecars and display on the same target model;
9. run combined lifecycle, GC, mask, recovery, and scale acceptance before any
   release decision.

Legacy `.secdat-stage.<uuid>` cleanup remains a recovery-compatibility reader
after new stage creation stops. Such trees may contain complete secret-state
copies. Under the mutation lock it accepts only the existing canonical stage
name/ownership/mode/symlink checks, removes one verified abandoned tree, fsyncs
the parent, and is fault-tested independently. It is retired only after a
separately accepted migration proves no supported prior writer can leave a
stage and one full compatibility release has provided explicit cleanup. The
new prepared writer never creates a legacy stage.

The scoped-traversal implementation task is not complete while any generic
planned mutation still clones or diffs the data tree. A feature flag may route
individual commands during development, but release acceptance requires one
authoritative route per command and no silent fallback to global staging.

## Acceptance criteria

### Structural scope

- Instrumented wrappers prove `set`, independent `cp`, non-replacing `ln`,
  `load` without overwrite, `attr`, `meta`, relation mutation, and chain-local
  mask operations call clone-tree, stage creation, whole-domain diff,
  registered-domain collection, visible-key whole collection, and global
  actual-reference count zero times.
- Before ADR 0008, only `rm`, destination replacement, and overwrite items may
  call the named temporary actual-reference collector; one batch traversal
  counts all affected old objects. After ADR 0008, those paths also call it zero
  times and foreground object deletion is absent.
- A normal direct path never changes `XDG_DATA_HOME`, creates a
  `.secdat-stage.*` directory, or recursively opens the data root.
- An unreadable/atime-audited unrelated-domain sentinel is untouched by every
  operation in the preceding two bullets, plus `rm`, replacement, overwrite
  `load`, multi-set and both `mv` forms once ADR 0008/indexed writers are active.
- Visit counters report only explicit chain records, addressed objects, and
  actual reverse-dependency edges. Target count equals the non-no-op prepared
  write count.
- Plain `ls` remains outside this mutation design and ADR 0007 guarantees it
  does not read lifecycle sidecars without the timestamp option.

### Semantics and safety

- Existing-local and absent/inherited `set`, hidden names, inaccessible chain
  state, legacy ambiguous tombstones, mask preserve/propagate/reject, and
  fallback-remasking have focused tests.
- Setting through either of two aliases changes their one shared object;
  `cp` produces a distinct object; `ln` shares; `mv` preserves identities as
  required by ADR 0006.
- Cross-domain object owners, source/destination chains, foreign links, and
  reverse-index corruption fail or commit exactly as specified.
- Dependency tests cover zero, one and N actual dependents with 100 unrelated
  domains held constant; `mv`/`rm` visit only the guarded hash paths and N
  named primary records/chains. Missing/extra/wrong-primary edges, node/hash
  corruption, a crash in each rebuild step, and building/missing coverage all
  fail closed until a complete generation is published.
- Every transaction fault boundary is injected. Recovery yields the complete
  exact before-state or accepted roll-forward after-state, including mask,
  dependency node/root, candidate/epoch, container and lifecycle targets.
- Recovery runs before every authoritative builder. A PREPARED guard mismatch
  discards the unpublished transaction; after COMMITTING, recovery never reads
  guards and rolls forward only writes.
- A direct external relevant-file or inventory change between preparation and
  the pre-`COMMITTING` validation produces `changed since plan` and no command
  effects.
- Sensitive captured and prepared bytes are cleared on every success and
  failure path.
- Hidden logical names are absent from index filenames/nodes, guard and journal
  bytes, plan text/JSON, stderr, and internal effect digests. Current hidden-key
  relation creation remains rejected.
- With descendant masks present, both `set --key-visibility unlocked` and the
  equivalent `attr` transition leave the entry and every mask either all-old or
  all-new after recovery completes at every injected fault boundary; the new
  mask primaries/index/journal contain no plaintext last-known name. An
  inaccessible mask fails before the entry change.
- Moving a domain referenced by relations removes old-root `R` dependencies,
  rewrites the named primary members, preserves its `D` dependency, and makes
  new-root lookup and `mark-leaked` suggestions agree after recovery.
- Store/domain create/move/delete, migrate, finalize, dependency activation and
  legacy-stage cleanup have fault tests for the exact phase/guard ordering and
  ADR 0008 container invariants. Migration may traverse its selected store but
  never opens an unrelated store or domain.

### Batch and dry-run

- Item-N failure leaves no earlier disk effect; duplicate-path coalescing,
  create/delete no-op, delete/recreate, candidate cancellation, and one epoch
  rotation are covered.
- SDB2 repeated labels share the one projected object without a physical stage.
- `reject`, `skip`, and SDB2 fresh-object `overwrite` cover reverse masks,
  metadata/lifecycle, old-object candidate enqueue, no fresh-object candidate,
  net refcount deltas, and the one epoch rotation. General same-existing-object
  replacement has separate cancel/net-zero coverage.
- Frozen clock/randomness tests give dry-run and commit builders the same
  internal effect digest and authorized mask rows; dry-run performs zero state
  writes.
- Existing text and JSON plan fixtures remain exact unless a separately
  accepted schema change says otherwise.

### Performance

- A fixed single-key `set` benchmark with 1 and 100 unrelated domains has the
  same visited-record, directory-open and write-target counts. These structural
  counts are the required CI gate.
- A separate same-host performance receipt reports at least 20 measured runs
  after warm-up and targets a 100-domain/1-domain median latency ratio no larger
  than 1.20. Filesystem noise alone does not fail the structural CI gate, but a
  missed target blocks the combined performance acceptance pending explanation.
- Increasing only the explicit parent-chain length may increase lookup work
  linearly; the benchmark reports this separately from unrelated-domain count.
- `strace` or equivalent proves no unrelated-domain directory is opened and no
  full-tree copy/delete/fsync burst remains.
- Combined acceptance is measured again after ADR 0007 sidecars and ADR 0008
  queue/epoch records are enabled, because those records must add only bounded
  targets, not restore tree-wide work.

## Alternatives rejected

### Keep the stage but clone fewer directories

A scoped physical clone still routes correctness through environment mutation
and recursive filesystem inference. Batch observation, hidden-state copying,
cross-owner objects, and new ADR 0007/0008 files would keep expanding the clone
boundary. It shortens one walk without cutting the cause.

### Intercept every filesystem call with a generic copy-on-write layer

This preserves imperative writers but creates a second filesystem with path,
directory, symlink, permission, and crash semantics that must match the real
one. Typed projected queries are smaller and make dependency scope reviewable.

### Diff only directories that existing writers happened to touch

Discovering touches after mutation still cannot prove which reads justified
absence or mask decisions, and requires write interception. Explicit builders
produce both observations and writes before mutation.

### Use cached refcounts or GC candidates as deletion proof

Both are hints and can be stale. ADR 0008's stable-epoch graph scan remains the
only physical object-deletion authority.

### Scan all domains only for `mv` and `rm`

That preserves semantics but leaves foreground latency and availability tied
to unrelated domains. Strict reverse dependencies cut the cross-descendant
causal edge without weakening ADR 0006.

## Consequences and residual risks

Operation builders become explicit and initially duplicate some parsing and
serialization responsibilities now hidden inside imperative writers. Shared
typed serializers and target helpers should be extracted, but builders must
not call a writer that mutates disk during preparation.

The reverse dependency index adds cross-record invariants and a migration/fsck
surface. This is deliberate: ADR 0006 already makes those dependencies part of
correct mutation; the index makes their cost proportional to real dependents.
Index completeness is guaranteed only for compatible writers. Old binaries and
direct-disk changes can invalidate it and require explicit validation/rebuild.
Merkle hashes detect inconsistency relative to the guarded active root; they
are not a MAC or trust anchor against an attacker that can rewrite both root
and nodes. Such direct writers are outside the compatible-writer threat model.

The global mutation lock continues to serialize preparation and commit. This
ADR removes work under that lock but does not introduce concurrent foreground
writers. Very large batches or an entry with many actual dependent masks may
still hold the lock longer; later chunking cannot weaken batch atomicity.

Filesystem directory inventories do not provide a portable kernel generation
number. Digest revalidation catches relevant changes made outside compatible
writers but costs one repeated chain-local inventory. It never expands the
scope to unrelated domains.

Until ADR 0008 is implemented, destructive entry removal and replacement still
have a deliberately isolated synchronous graph scan. Therefore the immediate
`set` improvement is real, while complete foreground independence from global
reference topology is accepted only after the deferred-GC rollout step.
