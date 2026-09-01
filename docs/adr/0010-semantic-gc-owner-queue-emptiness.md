# ADR 0010: Semantic GC owner-queue emptiness for container deletion

## Status

Accepted (2026-09-01).

This record clarifies the deletion contracts in
[ADR 0008](0008-persistent-session-agent-deferred-gc.md) and
[ADR 0009](0009-scoped-mutation-preparation-and-direct-write-sets.md). It is a
design contract only. It does not authorize implementation, release,
publication, or deletion of user data. Implementation requires its own issue
scope, focused validation, and review before a non-WIP commit.

A non-persistent LLMThink audit of the decision candidate reported no fatal,
error, or warning finding. Its one informational item preserves the unknown
whether a particular user's domain contains additional owned artifacts. The
audit therefore accepts the general defect and decision boundary; it does not
prove that GC shard residue is the only blocker in any uninspected data home.

## Context

ADR 0008 stores deferred-GC work outside the domain container, below global
owner- and store-sharded candidate and quarantine trees. It requires store and
domain deletion to retain any candidate or quarantined record. ADR 0009 in turn
allows `domain delete` only for an exact known-empty domain skeleton whose
owner candidate and quarantine shards are empty. It also states that empty
directories left by deletion are harmless.

The current owner-level predicate does not implement that semantic boundary.
`secdat_gc_owner_queue_is_empty()` calls
`secdat_gc_directory_is_secure_and_empty()` on each owner directory itself:

```text
gc/candidates/by-owner/<owner-domain-id>/
gc/quarantine/by-owner/<owner-domain-id>/
```

The owner directory contains one directory per escaped store. Consequently an
empty, secure store shard makes the owner directory physically non-empty even
when it contains no candidate or quarantine record. The collector removes the
record and secret-object artifacts but intentionally does not make correctness
depend on pruning these structural directories.

An isolated current-main reproduction established this sequence:

```text
remove the final entry
-> one GC candidate is pending
-> run queued GC successfully
-> zero candidates remain
-> an empty owner/store candidate directory remains
-> domain delete still reports "domain is not empty"
```

The store-level predicate already has the correct shape: it checks the leaf
candidate and quarantine shards for the addressed owner/store pair. The defect
is the different meaning assigned by the owner-level predicate.

Orphan-domain inspection is a related usability problem, but it is not the
mechanism that creates this false non-empty state. Normal key enumeration still
requires a matching registered root, and an actual domain may also contain
entries, objects, migration artifacts, dependency edges, quarantined records,
or unknown files. Those states must not be collapsed into this correction.

## Causal classification

- **Root cause:** the owner-level predicate applies physical directory
  emptiness at the owner root even though its immediate children are
  non-semantic store-shard topology. It therefore equates an empty store shard
  with pending GC work.
- **Contributing cause:** collector and quarantine operations correctly remove
  records without making empty-directory pruning authoritative, so the flawed
  predicate's false-negative state persists after successful cleanup.
- **Escape or detection cause:** existing tests cover GC record removal and
  fresh empty-domain deletion separately but do not join the lifecycle through
  final-entry removal, queued collection, retained empty shard, and domain
  deletion.
- **Corrective action:** make the owner predicate enumerate canonical secure
  leaf shards and decide emptiness from their contents while failing closed on
  every unknown structure.
- **Recurrence-prevention action:** add the joined lifecycle regression and its
  corrupt/unknown structural counterparts required below.

## Decision

### 1. Define queue emptiness by records, not shard topology

For container deletion, an owner GC queue is empty exactly when both of these
conditions hold:

1. every canonical store shard below that owner's candidate subtree contains
   no directory entry other than `.` and `..`; and
2. every canonical store shard below that owner's quarantine subtree contains
   no directory entry other than `.` and `..`.

A missing owner subtree is empty. A present, secure, canonical store-shard
directory that contains no records is also empty and may remain on disk.

The predicate is intentionally conservative. A candidate, quarantined record,
unknown entry, non-canonical store component, symlink, wrong object type,
wrong mode or owner, traversal error, or a path that changes during validation
does not count as empty. It rejects deletion or returns an inspection error; it
never converts an unrecognized artifact into deletion authority.

### 2. Traverse the bounded owner shards with existing safety rules

The owner-level check enumerates only the two exact owner subtrees. It first
opens each owner subtree with the existing no-follow, user-owned, mode-`0700`
directory check; absence is empty and any other open or validation failure is
not empty. For each child it:

1. ignores only `.` and `..`;
2. validates the child name using the same unescape/re-escape canonical store
   rule used by GC discovery;
3. opens the child as the effective user with no symlink following and requires
   a user-owned mode-`0700` directory; and
4. checks that leaf directory with the existing secure empty-directory helper.

The implementation should share or extract the existing canonical shard
enumeration logic rather than introduce a looser path parser. The work is
bounded by the number of shards owned by the one domain being deleted; it does
not scan registered domains, object records, or unrelated owners.

### 3. Do not make producer-side directory pruning authoritative

Candidate collection and explicit quarantine removal may remove newly empty
store and owner directories as best-effort hygiene, but successful pruning is
not a precondition for semantic emptiness. The delete predicate remains correct
if cleanup is interrupted, if two compatible operations create or remove work
around the same shard, or if a compatible older writer leaves directories
behind.

This preserves ADR 0008's separation between record lifetime and discovery
topology. It also avoids replacing the false-negative bug with correctness
that depends on a race-prone `rmdir` chain.

### 4. Preserve all other domain-delete guards

This decision changes only the meaning of candidate/quarantine queue emptiness.
`domain delete` must still validate every ADR 0009 guard, including the child
domain guard, exact known-empty domain skeleton, owned-artifact absence,
foreign dependency/object-owner absence, reference-epoch ordering, and exact
container transaction.

The command must never recursively discard a non-empty or unknown GC shard.
The existing generic `domain is not empty` diagnostic may be improved by a
separate usability change, but diagnostic quality does not alter deletion
authority.

### 5. Require a joined lifecycle regression

Acceptance requires an end-to-end regression that exercises the previously
unjoined state transition:

```text
create a v2 key in a domain
-> remove its final entry
-> observe one queued candidate
-> collect it with `gc --queued`
-> observe zero pending/quarantined records
-> retain the empty owner/store shard directory
-> delete the otherwise-empty domain successfully
```

The regression must also prove the fail-closed counterparts:

- a candidate record blocks domain deletion;
- a quarantined record blocks domain deletion;
- an unknown entry in a shard blocks domain deletion;
- a non-canonical shard, symlink, non-directory child, insecure mode, or wrong
  owner blocks deletion or produces an inspection error;
- multiple empty canonical store shards count as empty; and
- store deletion retains the same semantic treatment through its existing
  owner/store predicate.

## Claim, evidence, and action traceability

### C-001: Empty structural shards are not pending GC work

- **Evidence E-001:** The isolated lifecycle reproduction reaches zero queued
  records but leaves an empty candidate store directory and still fails
  `domain delete`.
- **Evidence E-002:** `secdat_gc_owner_queue_is_empty()` tests the owner
  directory for physical child absence, while
  `secdat_gc_owner_store_queue_is_empty()` tests the candidate and quarantine
  leaf shards.
- **Action A-001:** Replace the owner-level topology test with bounded,
  safety-checked enumeration of semantic leaf contents.
- **Confidence:** High for the reproduced general defect; unknown for whether
  this is the sole blocker in any uninspected user domain.

### C-002: Semantic emptiness can be corrected without weakening deletion

- **Evidence E-003:** ADR 0008 gives candidate and quarantine records—not their
  parent directories—the retention meaning and explicitly requires corruption
  to fail closed.
- **Evidence E-004:** ADR 0009 requires record-bearing or unknown state to fail
  closed while treating empty directories as harmless container residue.
- **Action A-002:** Accept empty canonical secure shards, reject every record or
  unrecognized structural condition, and retain all non-GC domain guards.
- **Confidence:** High.

### C-003: Orphan inspection and destructive draining are separate changes

- **Evidence E-005:** Orphaned domains cannot use normal root-bound key
  enumeration, but the false non-empty result remains reproducible after
  rebind, entry removal, and successful GC.
- **Evidence E-006:** Domain ownership spans more than GC candidates: entries,
  objects, migrations, dependencies, quarantine, and unknown artifacts have
  different retention and authorization rules.
- **Action A-003:** Keep artifact inventory, `domain drain`, or an explicit
  destructive `domain delete --discard` contract in a separately reviewed ADR
  or issue.
- **Confidence:** High for separation of concerns; the final command design is
  undecided.

## Alternatives rejected

### Remove all empty directories after every GC action

This improves hygiene but does not define correctness. An interrupted or racing
cleanup can still leave a harmless directory and recreate the false-negative
state.

### Treat every owner directory as empty after `gc --queued` reports zero

Status output is an observation, not a transaction guard. It can omit a newly
created record or be unable to classify corrupt state. Deletion must validate
the durable shards under its own mutation/recovery boundary.

### Recursively delete the owner queue with the domain

This violates ADR 0008 by allowing domain cleanup to erase durable candidates
or quarantined evidence. It also turns unknown artifacts into implicit discard.

### Add orphan artifact listing and forced deletion in the same change

That would combine a narrow predicate defect with new enumeration,
authorization, presentation, and destructive-data semantics. The larger
surface is valuable but is not required to cut the causal chain producing the
current false non-empty result.

## Consequences

- A successfully collected domain can be deleted even when harmless GC shard
  directories remain.
- Candidate, quarantine, corrupt, and unknown state continue to block
  deletion.
- Domain deletion performs bounded work proportional to that owner's store
  shards rather than unrelated repository state.
- Empty-shard pruning becomes optional maintenance and can be added without
  changing the deletion contract.
- Users may still need a separate inspection/drain workflow when a genuinely
  non-empty orphan domain cannot be enumerated through the normal root-bound
  interface.

## Dependency and review record

Normative direct dependencies:

- ADR 0008 defines the persistent candidate/quarantine safety and fail-closed
  rules refined here.
- ADR 0009 defines the domain-delete guard and exact empty-container transaction
  refined here.

The repository's Sealgraph records these direct Cause links. Its historical
chain also records ADR 0007 as a cause of ADR 0008, ADR 0006 as a cause of ADR
0007, and ADR 0006/0007/0008 as causes of ADR 0009. Sealgraph seals exact ADR
content and dependency edges; it does not authorize implementation or prove
runtime behavior.

The pre-decision LLMThink audit was non-persistent and produced no fatal,
error, or warning finding. Readability hints and possible shared-reference
candidates did not identify a contradictory decision. The one informational
unknown concerning actual user data remains explicit in C-001.

## Follow-ups

1. Create an implementation issue for A-001/A-002 with the regression matrix
   above before changing code.
2. Separately design owner-scoped artifact inventory and an orphan-domain
   inspection/drain workflow, preserving explicit discard authority.
3. Keep issue #242's orphan-domain move diagnostics separate unless its
   acceptance criteria are deliberately expanded and re-reviewed.
