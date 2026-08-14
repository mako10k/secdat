# ADR 0008: Persistent session-agent deferred secret-object GC

## Status

Accepted (2026-08-13).

Tracks [issue #233](https://github.com/mako10k/secdat/issues/233) under
[issue #231](https://github.com/mako10k/secdat/issues/231). This record is a
design contract only. It does not authorize implementation, release, or
publication.

Static review covered queue survivability and discovery scope, reference-scan
races in both commit orders, epoch rotation coverage, batch and poll bounds,
agent session inheritance/expiry/handover, transaction recovery, explicit GC
and fsck symmetry, destructive store/domain paths, cross-domain links,
corruption recovery, and ADR 0007 lifecycle deletion. No blocking or major
finding remained; no implementation has been reviewed or authorized by this
ADR.

## Context

Persisted v2 separates a domain entry from its possibly shared secret object.
The current `rm`, destination replacement, and link paths synchronously scan
every registered domain and v2 store to calculate the actual object reference
count. When the last reference is removed, the foreground command also deletes
the object and legacy value sidecar. This makes foreground latency depend on
the entire registered graph rather than the source and destination operation.

The cached refcount in a secret-object record is not sufficient deletion
authority. It can be missing or stale, repair is explicitly supported, and a
crash or older writer may have left it inconsistent. Conversely, a durable GC
queue entry means only that a reference was removed; another reference may
still exist or may be created before collection. Cached refcount and queue state
are therefore scheduling hints, not proofs.

The existing session agent already owns the persistent unlocked-session
lifetime, but its loop blocks indefinitely in `accept()` and has no timer or
background-work protocol. Mutation recovery has a global transaction lock and
can replay exact before/after images. Extending its strict target allowlist for
a fixed GC subtree is enough for durable candidate records and atomic object
deletion, but an actual reference scan must not hold the global mutation lock
for its full duration.

Cross-domain links mean that the authoritative reference scope is wider than
the object's owner domain. A safe collector must also compose with agent
restart and handover, explicit `gc`, refcount repair, store/domain deletion,
and the object lifecycle sidecar defined by ADR 0007.

## Decision

### 1. Persist one globally durable, owner-sharded candidate per object

Candidate discovery is scoped to the agent's owner domain but is stored outside
that domain tree, so an unsafe or interrupted domain/store deletion cannot also
erase the cleanup intent. A candidate lives at:

```text
gc/candidates/by-owner/<owner-domain-id>/<escaped-store>/<tuple-sha256>.gc
```

The store component uses the store directory's canonical escaping.
`tuple-sha256` is lowercase SHA-256 over the canonical length-prefixed
`(owner-domain-id, effective-store, secret-id)` tuple: each canonical byte
string is encoded as an unsigned 32-bit big-endian length followed by exactly
that many bytes. Directories are mode `0700`; candidate files are mode `0600`.
The record contains object addresses and scheduling state but never secret
value bytes:

```text
SECDATGCCAND1
owner_domain_id=<canonical-32-lowercase-hex-domain-id>
owner_store=<escaped-canonical-store>
secret_id=<uuid>
enqueue_id=<uuid>
enqueued_at_ns=<signed-decimal-unix-nanoseconds>
attempt_count=<unsigned-decimal-32-bit>
last_attempt_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
next_attempt_at_ns=<signed-decimal-unix-nanoseconds-or-dash>
last_error=<none|scan-incomplete|io-error|owner-missing|invalid-object|unknown-artifact>
manual_required=<0|1>
```

The path and embedded owner, store, and object identity must match. Each field
occurs exactly once. Unknown fields, duplicate fields, invalid identities,
non-canonical store escaping, invalid integers, values outside their stated
range, tuple-hash mismatch, and files larger than 4096 bytes are corruption.

Add one global reference-graph generation record:

```text
gc/reference-epoch
```

with strict content:

```text
SECDATREFEPOCH1
reference_epoch=<uuid>
```

Every entry-reference graph mutation rotates this UUID in the same transaction
as its other effects. A multi-key transaction rotates it once. Domain/store
inventory changes durably rotate the epoch under the mutation lock before their
directory visibility changes; an extra rotation after a crash is harmless.
Value-only and metadata-only writes, candidate retry, candidate cancellation
after a stable scan, cached-refcount repair, and object deletion do not rotate
it. Missing or corrupt epoch state disables automatic deletion until explicit
repair initializes a sound baseline.
The first compatible reference-graph mutation may create a missing epoch in
the same transaction; in particular, the first candidate cannot commit without
also establishing the epoch. A candidate with no valid epoch is corruption and
is retained.

Transaction `STATE_FILE` validation is extended only for
`gc/reference-epoch` and canonical files below `gc/candidates/by-owner/` in
addition to the existing `domains/` subtree. Arbitrary top-level paths remain
invalid transaction targets.

Every foreground removal or rebind that drops a v2 object reference writes a
fresh `enqueue_id`, resets retry state, and uses the logical transaction's one
event time for `enqueued_at_ns` and `next_attempt_at_ns`. Replacing an existing
candidate is intentional: it is the observable generation change that fences
a concurrent scan. Worker retry updates preserve `enqueue_id` and
`enqueued_at_ns`. Candidate times are maintenance scheduling data, not the
semantic lifecycle timestamps from ADR 0007 and not correctness clocks.

The on-disk states are:

```text
absent -> pending -> absent
                  \-> retry-pending
                  \-> manual-required
```

`scanning` is memory-only. A crash during a scan leaves the persisted pending
state and makes restart naturally retry it. `manual-required` retains both the
candidate and object until an explicit repair or a new foreground enqueue
resets the candidate generation.

The strict parser derives state only from these valid field combinations:

| Derived state | `manual_required` | `attempt_count` | `last_attempt_at_ns` | `next_attempt_at_ns` | `last_error` |
| --- | --- | --- | --- | --- | --- |
| `pending` | `0` | `0` | `-` | integer | `none` |
| `retry-pending` | `0` | `1..UINT32_MAX` | integer | integer | `scan-incomplete` or `io-error` |
| `manual-required` | `1` | `1..UINT32_MAX` | integer | `-` | `owner-missing`, `invalid-object`, or `unknown-artifact` |

Any other combination is corrupt. Foreground enqueue writes `pending`. A
failed authoritative attempt increments `attempt_count` with saturation,
captures one attempt time, and writes either a scheduled retry or
manual-required state. Lock contention and epoch/generation changes are not
attempts: they change only an in-memory 250-millisecond retry deadline. A
stable reference cancels the candidate; stable zero deletes it with the object.

### 2. Move reference topology maintenance out of foreground graph scans

The following changes are part of the same recoverable transaction as the
namespace change:

| Topology effect | Candidate effect | Cached refcount effect |
| --- | --- | --- |
| Remove or replace a concrete v2 entry | Enqueue the old owner object with a fresh generation | Apply a saturating best-effort decrement when the cache is valid |
| Create or repoint a v2 entry to an existing object | Cancel that owner object's candidate | Apply a best-effort increment when the cache is valid |
| Create an independent object (`set`/`cp`) | No candidate exists | Initialize the cache from the references created in that transaction |
| Update a value through an existing binding | Cancel a stale candidate if present | Preserve the cache |
| Identity-preserving `mv` | Preserve candidate state | Preserve the cache |
| Remove an inherited name by creating a mask | No object reference was removed; do not enqueue | Preserve the cache |

Multi-entry `load`, replacement, and future batch operations coalesce effects
per object. A removal always enqueues even when the cached count remains above
zero. This makes eventual cleanup independent of a prior fsck repair; the cache
may still be used to delay low-priority scans but cannot cancel a candidate or
authorize deletion.

A new candidate whose valid post-delta cached count is above zero is first due
after one hour; a missing or zero cached count is first due after the one-second
debounce. Every later removal replaces the candidate and recomputes that hint.
Thus a stale-high cache can delay, but never permanently suppress, an
authoritative check.

If the namespace change and required enqueue/cancel state cannot be committed
together, the foreground operation fails. Once that transaction commits, the
foreground command succeeds whether or not an agent is running. Notification
failure never rolls back the committed mutation.

This contract applies to every reference-topology writer, including
cross-domain `ln`, `ln --replace`, current copy/delete `mv`, the accepted
identity-preserving `mv`, bundle load, migration writers, and repair paths. A
cross-domain writer targets the candidate directory in the object's owner shard
in the same transaction. These paths, domain/store create/delete, and any
dangling-entry repair also rotate the common reference epoch through one graph
mutation helper. A writer that does not maintain both invariants is not
compatible with automatic GC.

### 3. Use one batched, epoch- and generation-fenced delete proof

The worker never deletes from the candidate or cached count alone. It processes
a bounded batch with this two-fence algorithm:

1. Try to acquire the global worker lease and mutation lock without blocking.
   Under the mutation lock, run transaction recovery, strictly read reference
   epoch `R0`, then snapshot and validate at most eight due candidate generations
   `E[0..n)`, owner addresses, and object identities from one owner shard. Release
   the mutation lock.
2. Outside the lock, enumerate all physically present v2 domain-entry records
   below the current data home's `domains/by-id` tree once. Build counts only
   for the batch's object tuples. A valid found reference establishes
   `REFERENCED` for that tuple even if a later unrelated record is corrupt. Any
   unreadable directory, invalid entry that could hide a reference,
   path/identity mismatch, or incomplete scope makes every still-unreferenced
   tuple `INDETERMINATE` and fail closed.
3. Try to reacquire the global mutation lock without blocking and run recovery
   again. Reread the epoch and every candidate. If the epoch is not `R0`, abandon
   the complete batch. Drop an individual result if its candidate is absent,
   invalid, or its `enqueue_id` is not the matching `E[i]`.
4. While retaining the mutation lock, build and commit one bounded transaction
   for all remaining stable results. For a nonzero actual count, cancel the
   candidate and reconcile a present cached refcount. For zero, delete the
   secret object, legacy `.value`, ADR 0007 object `.life`, and candidate.
   Release the mutation lock only after commit or recovery completes.

```text
short lock                    no lock                  final locked commit
recover/read R0,E[] -> one entry-tree traversal -> recover/re-read R0,E[]
                                                       | changed: abandon
                                                       | refs > 0: cancel
                                                       ` refs = 0: delete
```

All reference creation cancels the candidate, and all reference removal writes
a fresh generation. The common epoch additionally covers graph inventory and
repair changes that cannot safely identify one candidate. Therefore any graph
mutation during the unlocked scan changes the final epoch, while a mutation of
this object's references also makes the candidate generation absent or
different. The short first fence prevents starting from an unrecovered partial
transaction; the final fence and recovery prevent committing a deletion against
an incomplete topology change.

The opposite worker/reference-creation ordering is also explicit. Every writer
holds the same mutation lock through its commit and revalidates the exact object
path, embedded identity, and value-artifact requirements immediately before it
adds or repoints an entry. If the worker committed deletion first, the writer
fails without creating the entry. If the writer commits first, it rotates the
epoch and cancels the candidate before the worker's final fence. There is no
ordering in which a new reference commits to an already deleted object.

The physical `domains/by-id` tree, not only the live registry, is scanned so a
recoverable but temporarily unregistered domain cannot hide a reference.
Non-domain entries and unknown store formats fail the candidate attempt closed;
they are maintenance issues, not permission to erase an object. A future
authoritative reverse index may replace this scan, but is not required by this
ADR.

The zero-reference deletion transaction contains exact before/after images for
all known object-owned artifacts and the candidate. If any unknown object-owned
artifact is present, the worker records `unknown-artifact` and requires manual
review rather than partially deleting the identity. Directory removal is
best-effort cleanup after the transaction and has no correctness role.

### 4. Run collection only in a persistent writable session agent

The agent run loop changes from an indefinitely blocking `accept()` to a
`poll()` loop over the command socket and the next due GC time. The spawning
path passes the canonical owner domain ID into the run loop. Automatic GC is
enabled only when the object-owner domain's exact local agent holds that
domain's persistent, non-readonly, non-volatile unlocked session. An inherited
ancestor or user-global session does not make a descendant owner shard eligible;
the descendant needs its own agent, or manual GC handles its candidates.
Readonly, volatile, expired, or locked state does not mutate the persistent
queue.

On startup, successful persistent-session configuration, and handover, the
agent enumerates only `gc/candidates/by-owner/<its-domain-id>`. It never
enumerates registered domains merely to discover work. Queue state is already
persistent, so the handover snapshot does not duplicate it; the successor
rediscovers the queue after accepting the persistent session. A 30-second
rescan deadline guarantees eventual discovery if every best-effort wake is
lost.

Add the additive `GC_WORKER_V1` capability and `GCWAKE` request to agent
protocol v1. A foreground mutation sends a best-effort wake to the object
owner's agent after commit. Unsupported protocol, absent agent, socket failure,
and lost wake are all harmless because startup and the timer discover durable
work.
The wire exchange is exactly `GCWAKE\n` followed by `OK\n`. Its handler is an
O(1) in-memory schedule notification: it does not enumerate the queue, take the
worker or mutation lock, mutate disk, or refresh session expiry.
After an upgrade, a client that finds a same-protocol agent lacking
`GC_WORKER_V1` must attempt one existing `HANDOVER_V1` replacement when that
capability is available. Failure retains the queue, emits one actionable
diagnostic, and disables automatic collection rather than weakening the delete
proof.

Only one process holds `transactions/gc-worker.lock` while building and
committing a proof; this coordination flock file is excluded from mutation
state and added as one exact allowed transaction-root entry during recovery.
The lease is nonblocking and released after each bounded batch. No process waits
for the mutation lock while holding the worker lease: if the initial/final
try-lock fails, it releases the lease and reschedules. Explicit GC acquires the
worker lease before entering the short-fence mutation-lock protocol instead of
using the current whole-command generic pre-lock.

The long reference walk is incremental: after 256 entry records or 25
milliseconds, whichever comes first, the agent returns to the poll loop and
services ready client work before continuing the in-memory scan. Mutations
served between chunks merely rotate the epoch and cause the final proof to be
discarded. Queue discovery and the reference-tree walk retain open `DIR *`
cursors across chunks and accept filesystem enumeration order; they must not
pre-collect or sort a complete directory. A restart or directory mutation may
discard a cursor, and the 30-second full rescan supplies eventual discovery.

The poll deadline includes session expiry even when no client connects. The
agent re-evaluates expiry and exact-local persistent/writable eligibility before
each discovery or scan chunk and again while holding the final mutation lock.
If it becomes ineligible, the agent abandons the in-memory scan, writes no
retry/candidate state, releases the worker lease, and returns to normal session
handling.

Scheduling uses these fixed first-version bounds:

- new candidates are debounced for one second;
- only one authoritative reference scan runs across all agents;
- the agent services ready socket work between scan chunks and candidates;
- owner-shard queue discovery is itself resumable and yields after 256 directory
  entries or 25 milliseconds, retaining its open enumeration cursor;
- one GC slice snapshots at most eight due candidates and verifies them with
  one reference-tree traversal; it starts no new batch after 100 milliseconds;
- lock contention reschedules after 250 milliseconds without incrementing
  `attempt_count`;
- scan/I/O failures back off at 1 second, 5 seconds, 30 seconds, 5 minutes, then
  1 hour, capped at 1 hour with no retry-count deletion threshold;
- invalid object structure, owner disappearance, and unknown artifacts become
  `manual-required` and are never auto-deleted; an invalid candidate cannot be
  safely rewritten and remains untouched while GC status reports it as corrupt.

At graceful shutdown the agent starts no new scan. An unlocked scan may be
abandoned because it owns no persistent intermediate state. A transaction that
has reached commit/recovery is completed by the ordinary recovery contract.
Retaining encrypted object data and its candidate indefinitely is the safe
outcome whenever the worker cannot prove zero references.

### 5. Reuse one collector contract for manual GC and fsck

Existing `gc --format v2` default behavior and text output remain compatible.
Extend the flat option surface without changing its default selectors:

```text
secdat gc [--orphaned] [--dangling] [--queued] [--dry-run] [--format v2]
secdat gc --status [--errors] [--json] [--format v2]
secdat gc --owner DOMAIN_ID [--store STORE] [--queued|--status] [--json]
secdat gc --repair-epoch [--dry-run]
secdat gc --quarantine-candidate HANDLE [--dry-run]
secdat gc --drop-quarantine HANDLE [--dry-run]
```

With no selector, the existing `--orphaned --dangling` default remains. An
explicit `--queued` alone selects only queued work; it may be combined with the
two existing selectors. `--status` is read-only and mutually exclusive with
`--orphaned`, `--dangling`, `--queued`, and `--dry-run`. Its `--json` is status
output, so this form bypasses the mutation-plan wrapper that currently owns
mutation `--json`.

`--owner DOMAIN_ID` is the explicit administrator/recovery address for an owner
shard that no longer has a registered root or live exact-local agent. It never
changes the caller's domain resolution. Mutating `--owner DOMAIN_ID --queued`
requires writable authorization for that exact owner when it is registered;
authorization may come from its persistent writable agent session or an owner
master key already accepted by ordinary mutable commands. An unregistered
owner is read-only status until domain recovery or
an explicit future orphan-owner purge contract. This avoids converting a
missing registry entry into delete authority. `--owner` without `--queued` or
`--status`, and `--owner` with orphan/dangling full sweep, are invalid.

`HANDLE` is the candidate's 64-character tuple hash, not a secret UUID.
`--status --errors` is the only aggregate form that lists handles. Text adds
one named line per non-ready record. JSON changes to schema
`secdat.gc-status-errors.v1` and adds an `errors` array of
`{handle,state,last_error}` objects; it does not add embedded object identities.

`--repair-epoch` acquires the global mutation lock, runs recovery, and replaces
a missing or malformed reference epoch with one new UUID. It does not modify
candidates, entries, objects, or cached counts. This is safe because no old
epoch is accepted as proof after replacement; every candidate must still pass
a complete later scan against the new epoch. A non-dry-run repair requires an
exact-local persistent writable session for the current registered domain.

`--quarantine-candidate HANDLE` is available only when `--status --errors`
identified that exact file as structurally corrupt. Under the mutation lock it
requires secure regular-file and parent-directory ownership/modes, then
atomically renames the unchanged file to
`gc/quarantine/by-owner/<owner>/<escaped-store>/<handle>.candidate-corrupt` and
fsyncs both directories. Rename, rather than parsing the bytes into a journal,
also bounds memory use for an oversized corrupt file. A crash before or after
the rename leaves exactly one work record; recovery/status recognizes both
locations. The command never deletes or rewrites an object. Quarantine remains
visible to status and continues blocking owner/store deletion.
`--drop-quarantine HANDLE` is a separate explicit acknowledgement that unlinks
and fsyncs only the quarantined work record after the operator has run the
full-store orphan/dangling inspection; it never deletes an object. Both mutating
forms require the same exact-owner authorization as queued GC, so an
unregistered owner must first be recovered. Dry-run changes nothing.

The quarantine subtree uses canonical owner/store components, mode `0700` for
every directory and `0600` for regular files. Creation fsyncs each new child
directory and its parent. Status and mutation reject symlinks, non-regular
files, insecure modes/owners, noncanonical handles, and owner/store path
mismatches; such unknown artifacts continue blocking destructive container
operations until explicit filesystem repair.

Without `--owner`, `--queued` processes candidates in the selected
current-domain owner shard and store with the same validation,
epoch/generation fences, and transactional delete helper as the agent. It does
not enumerate unrelated owner shards.
`--dry-run --queued` performs the authoritative check but writes neither retry
state nor object state. A non-dry-run explicit queued pass ignores debounce and
backoff and revalidates a structurally valid `manual-required` candidate after
the operator has repaired its reported cause.

The existing orphan/dangling full sweep remains the explicit recovery path for
legacy unqueued objects. Object removal by that path also uses the authoritative
zero-reference gate, stable epoch plus candidate-absence fence, and one
transactional artifact deletion. Explicit
`--dangling` may remove invalid entry/value artifacts as today, but an invalid
secret object with a valid identity is retained when a possible reference
cannot be excluded.

`fsck --refcount` remains read-only. `fsck --refcount --repair` retains its
narrow responsibility: it repairs a present cached count from an authoritative
scan but neither enqueues, cancels, nor deletes candidate/object state. It
reports candidate inconsistency for a later queued/manual GC pass. Repair does
not update `value_updated_at` or other semantic lifecycle fields.
The stable diagnostic is
`gc-candidate-inconsistency<TAB>SECRET_ID<TAB>missing-zero-reference` when a
valid zero-reference object has no candidate, or the same kind with
`invalid-record` when its canonical candidate path is present but invalid.
A valid delayed candidate for an object that still has references is expected
work, not an fsck inconsistency. Here `<TAB>` denotes one literal tab in CLI
output.

`gc --status` reads candidate records without an actual graph scan or unlocked
session. Text reports only aggregate counts and times. `--json` emits this exact
top-level shape, with RFC 3339 nanosecond strings or `null` for absent times:

```json
{
  "schema_version": "secdat.gc-status.v1",
  "domain_id": "<canonical-32-lowercase-hex-domain-id>",
  "store": "default",
  "pending": 0,
  "ready": 0,
  "retrying": 0,
  "manual_required": 0,
  "corrupt": 0,
  "quarantined": 0,
  "oldest_enqueued_at": null,
  "next_attempt_at": null
}
```

The complete error-detail shape is:

```json
{
  "schema_version": "secdat.gc-status-errors.v1",
  "domain_id": "<canonical-32-lowercase-hex-domain-id>",
  "store": "default",
  "pending": 0,
  "ready": 0,
  "retrying": 0,
  "manual_required": 1,
  "corrupt": 0,
  "quarantined": 0,
  "oldest_enqueued_at": "2026-08-13T02:03:04.123456789Z",
  "next_attempt_at": null,
  "errors": [
    {
      "handle": "<64-lowercase-hex>",
      "state": "manual-required",
      "last_error": "invalid-object"
    }
  ]
}
```

It does not list object UUIDs. Add the opt-in object inspection form
`secret status --gc UUID`. Existing `secret status UUID` output remains exact.
The opt-in form appends named `gc_candidate`, `gc_enqueued_at`,
`gc_last_attempt_at`, `gc_next_attempt_at`, `gc_attempt_count`, and
`gc_last_error` lines, using the same state names and RFC 3339 nanosecond or `-`
conventions. It never prints the internal `enqueue_id`. Default top-level agent
`status` output remains unchanged.

### 6. Make destructive container operations preserve the invariant

`store delete` must additionally require that the corresponding global
owner/store candidate shard is empty. A missing-object candidate is cleared
only by the collector/manual repair path, not silently discarded by store
deletion.

Before automatic GC is enabled, `domain delete` must stop recursively deleting
a data-bearing domain tree. Apart from the known empty store skeleton and
administrative identity metadata, it rejects a domain containing v1/v2
entries, owned objects, migration artifacts, or other store data, and it
rejects any candidate or quarantine record in that domain's global owner shard,
in addition to its existing child-domain check. Operators remove bindings and drain/repair GC
first. This closes the current path that could remove an owner object while a
foreign entry still references it and preserves the epoch/generation invariant
without inventing a mass-delete transaction.

Migration creates entries and objects but no candidates, rotates the reference
epoch, and cancels any candidate for an identity it references. Migration
finalization may remove only its migration backup after normal validation and
does not discard candidates or object artifacts. A cross-domain link is always
counted from its entry domain while its candidate is owned and processed by the
object-domain agent.

Older binaries neither cancel nor regenerate candidates when changing entry
topology. As with ADR 0007 lifecycle sidecars, older-binary writes are
unsupported after this feature has been enabled. Read-only downgrade access
remains possible because core DENT1 and secret-object records do not change.
A store-format bump is the only complete way to make old writers reject the
store; that larger compatibility boundary is not introduced here.

## Required operation sequences

Foreground reference removal or replacement has one durable commit boundary:

```text
CLI -> mutation lock/recovery: establish current state
CLI -> planner: coalesce net entry-reference deltas by object tuple
CLI -> transaction: entry/life/metadata change + refcount hint
                   + fresh candidate/cancellation + reference epoch rotation
transaction -> disk: prepare, commit, fsync, recover if interrupted
CLI -> owner agent: best-effort GCWAKE after commit
CLI -> caller: success is independent of wake or worker availability
```

The automatic worker sequence is:

```text
agent poll -> owner shard: select due candidate
agent -> worker lease + mutation lock: recover and snapshot R0,E[0..8)
agent -> persisted entry tree: one incremental traversal for the tuple batch
agent -> mutation lock: recover and verify R0,E[] unchanged
agent -> one transaction: cancel/delete/retry stable batch results
agent -> poll loop: release lease and service clients
```

Explicit GC uses the same proof rather than a second delete implementation:

```text
gc CLI -> authorization/lock: require writable owner authorization unless dry-run/status
gc CLI -> queued shard or explicit full-store inventory: select object
gc CLI -> common collector: run epoch/generation-fenced proof
gc CLI -> common transaction helper: cancel/delete/retry (no writes in dry-run)
gc CLI -> report: preserve existing default text; opt-in status has v1 JSON
```

For an unregistered owner, `gc --owner DOMAIN_ID --status` remains available but
`--queued` stops before proof/deletion and reports domain recovery as required.

Refcount fsck remains separate from object lifetime:

```text
fsck -> persisted entry tree: calculate actual count
fsck (no --repair) -> report: no writes
fsck --repair -> object record: transactionally repair cached hint only
fsck -> candidate/object lifecycle: report inconsistency; preserve both
```

## Recovery and idempotency

The required outcomes at each persistence boundary are:

| Interruption point | Recovery outcome |
| --- | --- |
| Foreground transaction is staging/prepared | Discard incomplete state; neither entry topology nor candidate generation changes |
| Foreground transaction is committing | Roll forward exact entry and candidate after-images |
| Foreground commit completed before wake | Mutation remains successful; timer/startup later discovers the candidate |
| Worker before/during reference scan | Object and candidate remain; retry from the persisted generation |
| Topology changes during scan | Final epoch and/or generation check fails; abandon stale result |
| Retry-state transaction is interrupted | Ordinary recovery selects the exact old or new retry record |
| Candidate cancellation is interrupted | Ordinary recovery rolls candidate removal and cache reconciliation forward together |
| Object deletion is interrupted | Ordinary recovery rolls object, value, lifecycle, and candidate removal forward together |
| Agent handover/restart | Successor rediscovers the durable global owner shard; no in-memory work claim is required |

Recovery replays stored candidate timestamps and generations. It never obtains
a new clock value or creates a replacement enqueue generation.

## Safeguards and acceptance criteria

Implementation is accepted only with tests or structural checks for all of the
following:

- foreground `rm`, replacement, and reference creation do not call the global
  domain/reference collector and their visited scope is independent of
  unrelated domain count;
- entry removal plus fresh enqueue, and entry creation plus cancellation, are
  atomic under injected failures at staging, prepared, committing, and each
  target application;
- every graph mutation surface uses the common helper to rotate the epoch, and
  a reference created, removed, or replaced during an unlocked worker scan
  changes the epoch/generation and prevents stale deletion;
- cross-domain links keep the owner object alive, including when the referencing
  domain is physically present but temporarily absent from the registry;
- cache values that are missing, stale high, stale low, or malformed never
  authorize deletion;
- agent startup, wake loss, handover, expiry, readonly/volatile modes, shutdown,
  exact-local versus inherited/global session eligibility, retry/backoff, and
  manual-required records preserve durable work correctly;
- a worker enumerates only its global owner shard during discovery and services
  socket work between bounded reference-scan chunks and candidates;
- worker/manual zero-reference deletion removes object, `.value`, ADR 0007
  object lifecycle, and candidate atomically without changing semantic times;
- `fsck --refcount --repair`, full manual GC, queued dry-run, queue status text,
  error handles, epoch repair, candidate quarantine/drop, and exact JSON shapes
  follow the contracts above;
- store and domain deletion cannot silently discard a candidate or strand a
  foreign reference;
- owner-directed status can inspect an unregistered shard but no owner-missing
  path converts it into deletion authority;
- corrupted entry/object/candidate records and incomplete traversal retain the
  object and produce actionable diagnostics; traversal/discovery tests prove no
  complete directory is pre-collected before the configured yield bound.

Final performance acceptance is measured only after ADR 0008 is combined with
the scoped mutation traversal design: adding candidate files to the current
whole-tree clone/diff implementation would otherwise make foreground writes
slower even though the synchronous refcount scan moved away.

## Consequences

- Foreground cleanup cost becomes the bounded enqueue/cancel write set and no
  longer grows with registered-domain count.
- Actual all-domain reference verification still exists, but only in agent or
  explicitly requested maintenance work.
- Every reference removal may cause a later scan even when other aliases still
  exist. Debounce, one-candidate coalescing, and the cached-count scheduling
  hint control this cost without weakening deletion safety.
- With no eligible agent and no manual GC, encrypted unreferenced objects remain
  on disk indefinitely. This is the explicit residual secret-retention policy;
  namespace deletion does not wait for collection.
- A corrupt or incomplete graph also retains objects indefinitely until repair.
  Storage leakage is preferred to deleting a possibly referenced secret.
- Queue paths add files to mutation state, so scoped direct transaction targets
  must be implemented before automatic candidate writes are enabled.

## Residual risks

- The live-reference-wins proof applies only to compatible writers that hold
  the mutation lock and rotate `reference_epoch`. An older binary or direct
  disk writer can change an entry without rotating the epoch. Downgrade writes
  remain unsupported, and automatic GC must not be presented as safe in a
  mixed-writer deployment.
- Continuous graph mutation can repeatedly invalidate a batch and starve
  collection. This retains data safely; an explicit maintenance window remains
  the recovery path.
- A missing exact-local persistent session, corrupt graph, unregistered owner,
  or unresolved quarantine can retain encrypted object data indefinitely. This
  is preferable to treating partial knowledge as deletion authority.

## Alternatives rejected

### Delete when cached refcount reaches zero

This is fast but treats repairable cached state as deletion authority. A stale
low value can delete a live shared object. The cache remains useful for
scheduling and fsck diagnostics only.

### Hold the global transaction lock during the complete reference scan

This gives a simple snapshot but moves the original whole-graph delay into lock
contention: foreground operations would wait behind the agent. Epoch and
candidate-generation fences provide deletion safety while keeping the long scan
outside the lock.

### Keep the queue only in the runtime directory or agent memory

That loses cleanup intent on logout, reboot, handover, or agent crash. The
foreground namespace mutation would succeed without a durable route to eventual
collection.

### Discover work by scanning every registered store

That repeats global work at each agent wake and startup. A global owner shard
gives bounded discovery; only the authoritative deletion proof is global.

### Store the queue inside each owner domain

This bounds discovery but couples the only durable cleanup intent to domain
tree deletion. The global owner shard keeps discovery bounded while surviving
container-tree mistakes and interrupted administrative cleanup.

### Put candidates beside each secret object

Adjacent files make transaction targeting possible but force the owner agent to
enumerate every store/object directory to discover work. The separate queue
keeps object identity and store address explicit and leaves store trees free of
work-scheduling records.
