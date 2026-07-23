# ADR 0006: UUID-stable move and identity-linked masks

## Status

Accepted (2026-07-23)

Tracks [issue #160](https://github.com/mako10k/secdat/issues/160).
Implementation is sequenced by
[`plans/adr-0006-implementation.pert`](../../plans/adr-0006-implementation.pert)
and issues
[#161](https://github.com/mako10k/secdat/issues/161) through
[#169](https://github.com/mako10k/secdat/issues/169).

## Design review

Reviewed on 2026-07-23 from both consistency/symmetry and non-expert user
perspectives. The final review has no unresolved Blocker or High findings.
The review resulted in these material clarifications:

- an orphaned identity mask is a fail-closed last-known-name barrier, and
  target removal atomically masks a same-name fallback;
- hidden last-known names are mandatory encrypted metadata rather than
  optional hints;
- fallback continuations form one removable mask chain, while a name-only
  `unmask` cannot remove a chain that has spread across multiple key names;
- chain-qualified removal has mandatory dry-run/JSON visibility and reports
  any mask that still controls the requested name;
- legacy rollback compatibility, batch atomicity, and cross-owner deletion
  guards are explicit preconditions rather than implementation follow-ups.

The maintainer authorized implementation on 2026-07-23. Each implementation
slice still requires its own issue scope, focused validation, and review before
its non-WIP commit.

## Context

Store v2 separates a key binding from its value:

- a domain entry owns `entry_id`, the key name, key visibility, and link-side
  policy;
- a secret object owns `secret_id`, the value, value access, and object-side
  policy.

`secdat id KEYREF` exposes `secret_id`. `ln` creates another domain entry that
points to the same secret object, while `cp` creates an independent secret
object.

The current v2 `mv` does not use that identity model. It reads plaintext and
attributes, stores a new destination key, and then removes the source. An
absent v2 destination receives a new `entry_id` and a new `secret_id`.
Consequently:

- `id` changes across `mv`;
- a moved key is detached from existing `ln` aliases;
- a move unnecessarily decrypts and rewrites value material;
- rollback must reconstruct state that a domain-entry rename would not have
  disturbed.

Current masks are empty, name-indexed tombstones:

```text
domain/store/tombstones/<escaped-key>.tomb
```

They do not record the inherited domain entry or secret object they hide.
This produces two opposite rename hazards:

1. if a parent renames `A` to `B`, a child `mask A` becomes orphaned and the
   same secret becomes visible as `B`;
2. if an old or orphaned `mask B` exists, an unrelated entry renamed to `B`
   is hidden by that stale name mask, and `unmask B` cannot distinguish the
   old and new mask intents.

A destination tombstone is also treated as effective key absence. Current
`set`, `cp`, and `mv` destination writes remove that tombstone silently.
This loses a negative inheritance override and can expose the inherited entry
later when the local entry is removed.

The desired user model is:

- successful v2 `mv` preserves the UUID printed by `id`;
- normal users do not need to reason about tombstone files;
- masks survive local overrides and renames safely;
- operations report mask impact by default, including direct hits on dormant
  masks;
- mask mutation behavior and mask-warning policy are independently
  configurable;
- ambiguous legacy state fails closed rather than being hidden by warning
  suppression.

## Decision

### 1. Keep secret identity, entry identity, and mask identity separate

The following identities have different meanings:

| Identity | Owner | Meaning |
| --- | --- | --- |
| `secret_id` | secret object | Identity of shared value material; printed by `secdat id` |
| `entry_id` | domain entry | Identity of one name/binding to a secret object |
| mask record | current domain/store | Negative inheritance override targeting one inherited `entry_id` |

Normal `mask KEYREF` targets the resolved inherited **domain entry**, not the
whole secret object. It does not deny every `ln` alias that shares the same
`secret_id`.

An object-wide denial by `secret_id`, if added later, is a separate feature and
must not reuse `mask` semantics.

### 2. Define UUID-stable v2 move

For every successful persisted v2-to-v2 `mv`:

- the destination refers to the same `secret_id` as the source;
- value bytes are not decrypted and copied merely to rename or move the
  binding;
- existing `ln` aliases remain aliases of the moved destination;
- cached refcounts are updated only when the number of entries changes;
- the operation preserves source attributes according to their v2 owner:
  entry-owned fields move with the entry, and object-owned fields remain on
  the object.

`cp` remains deliberately different: it creates a new `entry_id` and a new
`secret_id`.

An effective visible destination entry remains a hard destination-exists
error. A canonical active, dormant, or orphan-barrier mask is not a visible
destination entry: the write may proceed under `preserve` while retaining the
mask and reporting its impact. A legacy-ambiguous name mask blocks the write.

#### 2.1 Local concrete rename in the same domain/store

If the effective source is a local concrete v2 entry and the destination is in
the same domain/store:

- preserve both `entry_id` and `secret_id`;
- rewrite only domain-entry name material and name-indexed auxiliary metadata;
- do not change object refcount;
- do not create a second entry as an intermediate visible state.

Masks in descendant domains that target the preserved `entry_id` continue to
target it after the name changes. This is intrinsic identity preservation, not
optional mask propagation.

#### 2.2 Local concrete move across v2 domain/store namespaces

The final contract is:

- preserve `secret_id`;
- preserve `entry_id` for a true move of a locally owned binding;
- rewrap the object data key for the destination domain entry when required;
- keep the secret object at its current object-domain/store address unless a
  separate object-relocation transaction is explicitly designed;
- remove the source entry only after the destination entry is durable.

Cross-domain/store move must not be enabled until all object-owner destructive
paths reject removal that would leave foreign entries dangling. This includes
`domain delete`, `store delete`, migration finalization, and GC; each must
check foreign entries against the object domain/store/secret tuple.

#### 2.3 Inherited source move

An inherited source entry is not owned by the resolved current source domain.
`mv` therefore materializes a new destination binding:

- preserve `secret_id`;
- create a new destination `entry_id`;
- retain the parent source entry;
- create or retain a mask targeting the original inherited source entry so the
  source name is absent from the source effective view after the move.

This is a link-like materialization followed by a source-view negative
override, not physical movement of the parent entry.

Only masks that existed before the operation are candidates for explicit
cross-entry propagation. The source mask created by `mv` itself is not
propagated to the destination entry.

#### 2.4 Unsupported identity boundaries

The UUID-stability guarantee applies only to persisted v2-to-v2 operations.

- v1 has no `secret_id`; v1-to-v1 behavior remains legacy behavior until a
  separate migration decision.
- v1/v2 mixed-format move must not silently claim UUID preservation.
- volatile overlays do not currently store v2 graph identity; identity-stable
  `mv` must either be rejected in volatile mode or wait for an identity-aware
  overlay design.
- a v2 source must never silently fall back to plaintext copy merely because
  the requested destination cannot preserve identity.

### 3. Replace name-only v2 tombstones with identity-linked mask records

A canonical v2 mask record targets exactly one inherited domain entry. Its
authoritative matching field is `target_entry_id`.

The persisted record must contain enough information to:

- identify `target_entry_id`;
- retain `target_secret_id` as a consistency check, not as matching authority;
- retain a `mask_chain_id` shared by fallback-continuation records;
- retain an optional predecessor target for a fallback continuation;
- retain the last known target domain/store address for audit, rollback, and
  orphan-barrier classification;
- retain a stable mask-record version;
- present the last known key name without weakening `key_visibility`;
- distinguish canonical identity masks from legacy name-only tombstones.

The exact binary/text encoding is an implementation decision, but canonical
writes must not index the record only by key name. A suitable logical shape is:

```text
version
mask_chain_id
target_entry_id
target_secret_id
predecessor_entry_id (optional)
last_known_target_domain
last_known_target_store
last_known_key or encrypted_last_known_key
```

For `key_visibility=unlocked`, neither the file name nor a public record field
may reveal the key name. The last-known name is mandatory for the orphan
barrier and must be encrypted with a mask-domain-derived key under the same
visibility boundary as the target domain entry. If it cannot be stored and
later recovered safely, mask creation, migration, or move fails.

At most one canonical mask per current domain/store may target the same
`entry_id`. Repeating `mask` for the same target is idempotent and retains the
existing chain.

Each explicit `mask` that actually creates a new canonical mask starts a new
`mask_chain_id`. A fallback mask created to prevent re-exposure keeps that
chain ID and records its predecessor. This makes the original mask and every
same-name safety continuation one logical policy that can later be removed
atomically. `propagate` creates a fresh destination chain rather than joining
source and destination names into one removal unit.

When a target entry is moved or renamed, canonical masks update last-known
metadata according to post-move reachability:

- if the target remains in the mask domain's inheritance scope, update to the
  destination address/name in the same transaction;
- if the target leaves that scope, retain the source address/name as the last
  authorized barrier and atomically mask any same-name fallback;
- `propagate` may separately create a destination-scope mask chain where the
  destination binding becomes inherited.

These fields are not allowed to become stale hints because the orphan barrier
relies on them after target loss. If an affected hidden-name mask cannot be
read and rewritten under its domain key, the move fails before mutation.

### 4. Allow local entries and masks to coexist

A mask targets an inherited entry, not the local key-name slot. Therefore a
nearer local entry and a mask may coexist.

Resolution order is:

1. a nearer visible/unlocked local entry wins;
2. when considering an inherited candidate, a current-scope mask targeting
   that candidate's `entry_id` hides it;
3. masks targeting other entries with the same current or last-known name do
   not hide the candidate while their own target remains reachable;
4. if a masked target disappears or leaves scope, its orphaned mask becomes a
   fail-closed barrier at the last authorized name until the mask is rebound or
   explicitly removed.

`set`, `cp`, `mv`, `ln`, `load`, and similar writes must not silently delete a
canonical mask merely because they create or update a local entry with the
same name.

Removing a local entry can reactivate a preserved mask. The underlying
inherited entry must remain hidden after that reactivation.

If the masked target disappears and another same-name ancestor would otherwise
become effective, `preserve` must prevent re-exposure:

- a secdat mutation that removes/moves the target atomically creates a new
  mask for the next inherited candidate and retains the old mask as orphaned;
- a read that observes an out-of-band missing target applies the orphan
  barrier and does not expose the fallback;
- if the fallback cannot be identified or masked safely, the mutation fails
  before changing data.

This automatic safety continuation is reported as `fallback-remasked`. It does
not mean that an unrelated, still-reachable mask for another entry hides the
new candidate.

#### 4.1 `mask` and `unmask` with a local override

When local `B` exists, `mask B` does not hide that local value. It resolves the
nearest inherited `B` below the local entry and creates a dormant mask for that
entry. It fails if no inherited target exists or the target is ambiguous.

`unmask B` first resolves the one logical mask chain that controls `B`. If
every active, dormant, and orphan-barrier record in that chain protects the
same authorized key name `B`, it atomically removes the chain in the current
domain/store. This is the ordinary inverse of automatic `fallback-remasked`:
users do not have to discover and remove each same-name safety continuation.

When local `B` exists, the local value remains visible after `unmask B`.
Because a later `rm B` can then reveal the inherited value, `unmask` emits a
deferred exposure warning by default. Warning suppression remains
behavior-neutral.

Name-only `unmask B` fails without removing anything if there is no unique
controlling chain **or** that chain has come to protect another authorized key
name after a target rename. It points to `list --all-masks --long` and an
`unmask --dry-run --mask-chain ...` inspection. The current, supported explicit
chain-removal surface is:

```text
secdat unmask --dry-run --mask-chain MASK_CHAIN_UUID B
secdat unmask --mask-chain MASK_CHAIN_UUID B
```

The selected chain must contain a record whose current or last-known
authorized name matches `B`; the option cannot remove an unrelated chain by
UUID alone. The explicit qualifier authorizes atomic removal of the entire
chain, including records protecting other names; dry-run/JSON must list every
record and authorized key slot that would stop being protected before the
user retries without `--dry-run`. This qualifier is also required when
independent canonical chains compete at the same name. A legacy-ambiguous
barrier must first be repaired with `mask --rebind B`; warning suppression
never turns ambiguity into an unmask.

After removal, `unmask` re-resolves `B`. If another independent chain or
barrier still masks it, the operation succeeds but the default warning says,
for example, `removed mask chain; B remains masked by 1 other chain`. JSON
always reports the remaining chain/barrier count and resulting effective
state, even when warnings are disabled.

### 5. Define mask state, record kind, and resolution separately

Mask state is derived from the current domain/store view:

| State | Meaning |
| --- | --- |
| `active` | The target entry is reachable through inheritance and the mask currently suppresses it |
| `dormant` | The target entry still exists in the inheritance chain, but a nearer local entry/binding currently shadows it |
| `orphaned` | The target entry is missing or no longer reachable; the record remains a fail-closed barrier at its last authorized name |

`orphaned` output must include a non-secret reason such as `missing-entry` or
`out-of-scope` when that distinction is known.

Dormancy is valid preserved state, not corruption. `fsck` must not report a
canonical dormant mask as an error.

Legacy/canonical representation and resolution are orthogonal fields:

| Field | Values |
| --- | --- |
| `record_kind` | `canonical`, `legacy` |
| `resolution` | `bound`, `ambiguous` |
| `state` | `active`, `dormant`, `orphaned` |

A legacy record may therefore be `legacy + ambiguous + orphaned`, while an
unambiguous migrated record is `canonical + bound + active|dormant|orphaned`.
`list` filters select by state; long/JSON output separately reports record kind
and resolution. Ambiguous resolution is an error precondition when an
operation would touch that mask, not a fourth state.

### 6. Expose active, dormant, and orphaned masks

Extend local-state inspection:

```text
secdat list --masked
secdat list --dormant
secdat list --orphaned
secdat list --all-masks
secdat list --masked --dormant --orphaned --long
secdat list --all-masks --json
```

- `--masked` continues to mean active masks only.
- `--dormant` lists preserved masks shadowed by nearer local entries.
- `--orphaned` lists masks whose target binding is no longer inherited.
- `--all-masks` is equivalent to all three state filters.
- filters may be combined.

Long and JSON output must expose, subject to key visibility:

- mask state;
- current/display key when allowed;
- current domain and store;
- target entry ID;
- target secret ID only when the same context would authorize observing that
  object identity;
- `mask_chain_id`, so an authorized operator can pass the displayed value to
  `unmask --mask-chain`;
- orphan reason;
- whether the record is canonical or legacy.

Locked-mode inspection must not reveal a hidden key name or a secret UUID that
the equivalent locked key view would not authorize.

### 7. Keep mask action and warning policy orthogonal

Mutation commands that can affect masks use two independent policy axes.

#### 7.1 Mask action

```text
--mask-action=preserve|propagate|reject
```

`preserve`:

- is the default action;
- never deletes a canonical mask as a side effect of a key write;
- permits active masks to become dormant and dormant masks to reactivate;
- permits intrinsic following when a move preserves the target `entry_id`;
- does not copy mask intent to a newly created `entry_id`;
- creates a source mask when moving a local override would otherwise reveal a
  same-name inherited entry;
- atomically masks a same-name fallback when removing a masked target would
  otherwise expose that fallback.

`propagate`:

- includes all `preserve` behavior;
- is accepted initially only by `mv`;
- when an inherited-source move creates a new destination `entry_id`, copies
  pre-existing applicable source mask intent to that destination binding;
- retains the original mask because the inherited source binding still exists;
- preflights every affected registered domain before writing any mask.

For each pre-existing source mask, propagation occurs only when the
destination binding will be in that mask domain's effective inheritance scope.
It must not create out-of-scope mask records.

Normal local rename does not require `propagate`: masks follow automatically
because the same `entry_id` is retained. Command help must describe
`propagate` as a broader operation that may create destination masks in other
registered descendant domains, and dry-run must list those domains.

`reject`:

- fails before mutation if the command has a direct mask hit, would transition
  any canonical mask state, create a source/fallback mask, or propagate a mask;
- reports the blocking impact as an error;
- is suitable for scripts that require zero mask interaction.

Commands for which `propagate` has no defined meaning, including `set` and
`cp`, must reject `--mask-action=propagate` as invalid rather than silently
lowering it to `preserve`. Each affected command's help lists only the action
values it accepts, its effective warning default, and `--no-warn-mask`.

#### 7.2 Mask warnings

```text
--mask-warnings=default|on|off
--warn-mask
--no-warn-mask
```

`--warn-mask` is an alias for `--mask-warnings=on`.
`--no-warn-mask` is an alias for `--mask-warnings=off`.
Conflicting forms are an argument error.

Warning policy never changes:

- persisted state;
- mask action;
- command success/failure;
- exit status;
- dry-run or JSON impact data.

Action modes may choose different warning defaults:

| Mask action | Default warning policy |
| --- | --- |
| `preserve` | on |
| `propagate` | on |
| `reject` | off, because detected impact is reported as an error |

`--mask-warnings=off` suppresses only warnings. It cannot suppress invalid
arguments, ambiguous legacy-state errors, failed preconditions, or a
`--mask-action=reject` failure.

### 8. Define mask-impact events

Every relevant mutation performs one common, read-only mask-impact analysis
before writing.

The normalized event vocabulary is:

| Event | Meaning |
| --- | --- |
| `direct-hit` | The command directly creates, updates, moves, links, or removes a local binding whose domain/store/key has a canonical active, dormant, or orphan-barrier mask |
| `became-dormant` | An active mask is now shadowed by a nearer local binding |
| `reactivated` | Removing/moving a local binding makes a dormant mask active |
| `followed` | A preserved `entry_id` changed name/location and its existing mask still targets it |
| `propagated` | `--mask-action=propagate` created a mask for a newly created destination `entry_id` |
| `source-mask-created` | `rm` or `mv` created a mask to keep an inherited source name absent |
| `fallback-remasked` | Target removal would expose a same-name lower ancestor, so that fallback was masked atomically |
| `orphaned` | The operation made a mask target missing or out of scope |
| `legacy-ambiguous` | A name-only mask cannot be assigned safely to one target |

A `direct-hit` is reported even when the mask remains dormant and no state
transition occurs. This makes repeated `set`, `cp`, `mv`, or `ln` activity over
a dormant mask observable.

Updating only the value of a target entry, without directly touching the mask's
local name slot and without changing mask state or binding identity, is not a
mask impact. In particular, a parent `set` must not warn merely because some
descendant has an unchanged active mask for that entry.

`reject` treats every event in this table, including mask creation, as a
blocking interaction except a pre-existing unrelated orphan that the command
neither reads nor changes.

### 9. Apply impact analysis consistently across mutation commands

| Command shape | Required mask behavior |
| --- | --- |
| `set B` | Preserve an active/dormant mask at local `B`; active becomes dormant; warn on direct hit |
| `cp A B` | Create independent secret/entry identities; preserve destination masks; warn on direct hit and dormancy |
| `mv A B` | Preserve secret identity; preserve/propagate entry masks per move kind and action; report source and destination impacts |
| `ln A B` / `ln @UUID B` | Preserve destination masks; warn on direct hit and dormancy |
| `rm B` | Preserve masks; warn when removal reactivates a dormant mask or creates a fallback mask |
| `load` / multi-key `set` | Preflight the whole batch and emit one aggregate impact result |
| `unmask B` | Warn when a local override keeps the immediate result unchanged but its later removal can expose inheritance |

Other key-creating or key-removing surfaces, including FUSE writes and SDK
entry points, must use the same analyzer rather than reimplementing partial
rules.

The final CLI support matrix is:

| Command | Accepted actions | Warning controls | Dry-run/JSON |
| --- | --- | --- | --- |
| `set`, `cp`, `ln`, `rm` | `preserve`, `reject` | all warning modes | required |
| `mv` | `preserve`, `propagate`, `reject` | all warning modes | required |
| `load`, multi-key `set` | `preserve`, `reject` | all warning modes | required for the whole batch |
| `mask`, `unmask`, `mask --rebind` | explicit mask operation; no action selector | all warning modes where deferred exposure exists | required |
| FUSE mutation | fixed `preserve`; no CLI selector | structured daemon/audit impact, not per-write terminal spam | plan internally before commit |

Help for each command shows only its accepted actions, resolved default, and
warning controls. It must not advertise `propagate` on commands that reject it.

### 10. Warning and error presentation

Warnings are written to standard error only after the mutation commits
successfully. Failed operations must not emit wording that implies a mask
transition occurred.

Default output is one aggregate warning line per command, not one line per
affected domain. Human stderr uses plain language and omits zero-count facts;
normalized event tokens are reserved for JSON/SDK output.

```text
warning: mv: preserved 1 dormant mask and carried 2 masks with the renamed entry; inspect with 'secdat --dir DIR list --all-masks --long'
```

For a single-key direct hit, a concise form is allowed:

```text
warning: set: API_TOKEN preserves a dormant mask; removing the local key will not reveal the inherited value
```

Warnings must not print secret values. Hidden key names must follow the same
redaction/authorization rules as `list`.

### 11. Dry-run, JSON, and SDK observation

Mutation commands covered by this ADR use one reusable impact plan and expose
the dry-run support in the command matrix above. For example:

```text
secdat mv --dry-run [--json] \
  [--mask-action=preserve|propagate|reject] \
  [--mask-warnings=default|on|off] SRC DST
```

Dry-run does not mutate data and reports the planned identity and mask effects.
JSON includes:

```text
plan_schema_version
ok
source_secret_id
destination_secret_id
source_entry_id
destination_entry_id
entry_id_preserved
secret_id_preserved
mask_action
mask_warnings_requested
mask_warnings_effective
mask_impact_counts
mask_impact_rows
```

Each impact row includes non-secret domain/store context, event, state before,
state after, and authorized target identifiers. Runtime warning suppression
does not remove rows from JSON.

For `unmask`, the plan/result additionally includes the removed
`mask_chain_id`, every affected authorized key slot, record count,
`remaining_mask_chain_count`, remaining legacy-barrier count, and the effective
state of the requested key after removal. These fields are present in dry-run
and committed JSON results.

With `--mask-action=reject`, an impact produces `ok=false`, non-zero status, and
the complete non-secret plan in JSON. Warning policy cannot remove the plan or
turn the rejection into success.

Existing ABI-stable SDK mutation functions retain their signatures and use
`preserve` behavior with terminal warnings disabled. New versioned `_ex` or
plan APIs accept requested action/warning policy and return an SDK-owned,
schema-versioned impact result that callers release with `secdat_sdk_free()`.
A library operation must not require callers to scrape localized stderr
warnings.

### 12. Treat planning and mutation as one transaction boundary

Before mutation:

1. resolve source and destination entries authoritatively;
2. snapshot relevant entry/object IDs, mask records, metadata, and refcounts;
3. enumerate every affected registered domain for propagation/transition
   analysis;
4. reject affected inaccessible or ambiguous state that cannot be preserved or
   rebound, and reject changed-since-plan state;
5. enforce `mask-action`.

A pre-existing orphaned mask unrelated to the command does not block it. A mask
that the command would newly orphan may commit only if no same-name fallback
can appear or the fallback is atomically masked. An inaccessible affected
domain or an unsafe fallback is a pre-mutation error.

The mutation must be all-or-nothing from later command views. In particular:

- a destination mask must not disappear if source removal fails;
- source and destination must not both remain visible after a failed local
  rename;
- refcount cache changes must not claim an entry update that did not commit;
- warnings must describe committed effects only.

Same-domain/store rename should use atomic replacement of the existing domain
entry as its namespace commit point. Updating descendant mask last-known
metadata still makes the full operation multi-file. Multi-file and cross-domain
operations require a recoverable operation journal or an equivalent staged
commit protocol; best-effort rollback alone is not the final contract.

`load` and multi-key mutation parse and validate the complete input, decrypt
required values, build the complete mask-impact plan, and stage every write
before committing any key. A failure at item N, a mixed `reject` impact, or
process restart during commit must not leave items 1 through N-1 partially
applied; journal recovery completes or rolls back the batch.

### 13. Migrate legacy name-only tombstones conservatively

v1 name tombstones remain v1 behavior.

While a migrated store still promises v1 rollback, canonical v2 mask changes
must preserve the equivalent v1 effective view:

- retain or dual-write the v1 name tombstone for every representable masked v1
  key;
- update that compatibility tombstone when an identity-following rename
  changes the protected name;
- remove compatibility tombstones only during explicit migration finalization,
  after canonical mask validation;
- reject a pre-finalization mask/move when hidden-name or orphan state cannot be
  projected safely back to v1 and rollback would expose a value.

Rollback reads the retained name tombstones. It must never silently discard a
canonical-only mask and expose the parent value.

For a v2 store, a legacy name-only tombstone may be converted automatically
only when migration can resolve exactly one inherited target entry while
ignoring that tombstone:

- write a canonical identity mask for that `entry_id`;
- preserve key visibility;
- retain the legacy tombstone through the v1 rollback window;
- after finalization, remove the legacy tombstone only after the canonical
  record is durable and verified.

An orphaned or otherwise ambiguous legacy tombstone remains a
`record_kind=legacy`, `resolution=ambiguous` record:

- readers retain fail-closed name masking for compatibility;
- writes that directly hit that name fail rather than deleting or rebinding
  the tombstone;
- warning suppression cannot bypass the failure;
- guidance offers `secdat mask --rebind KEY`.

`mask --rebind KEY` is an atomic repair operation for either a
legacy-ambiguous name barrier or a canonical orphan barrier whose target was
lost out of band. It resolves the current inherited target while retaining the
old barrier and stages a canonical mask for that target:

- a legacy-ambiguous barrier starts a new `mask_chain_id`; the legacy record is
  removed after migration finalization or demoted to rollback-only
  compatibility state only when the canonical record is durable;
- a canonical orphan barrier adds the new target as a fallback continuation
  in the existing `mask_chain_id`, records the orphan target as predecessor,
  and retains the old record as the chain's fail-closed history/barrier.

Rebind fails without changing state or exposing inheritance if no unique
target exists. Users are not instructed to repair ambiguity with a non-atomic
`unmask KEY`/`mask KEY` sequence.

A newly appearing same-name entry must not automatically become the permanent
identity target of an old orphaned tombstone.

### 14. Source-name and relation consequences

After successful `mv`, the source must be absent from the resolved source
effective view. If moving a local override would reveal a same-name parent
entry, `mv` creates a source mask for that parent entry. This is a deliberate
behavior change from simple local-entry deletion.

Searchable key metadata remains name-indexed and moves with a renamed local
entry. Metadata movement participates in the same transaction.

Relation members currently store canonical name-based KEYREFs. This ADR does
not silently redefine relation identity. Automatic relation rewrite or
entry-ID relation members require a separate decision. Until then, move
planning must detect affected relation members and report the existing
name-based consequence separately from mask-impact warnings.

## State-transition examples

### Parent rename followed by a child mask

Initial state:

```text
parent: A(entry=X, secret=S)
child:  mask(target=X) active
```

After parent `mv A B`:

```text
parent: B(entry=X, secret=S)
child:  mask(target=X) active; B remains hidden
```

The mask follows because `entry_id=X` was preserved.

### Unrelated orphan mask at the destination name

Initial state:

```text
parent: A(entry=X, secret=S)
child:  legacy/canonical mask formerly displayed as B, targeting Y
```

After parent `mv A B`, a canonical mask targeting `Y` does not hide `X`.
If `Y` is orphaned and its last authorized name is `B`, its fail-closed barrier
keeps the child from exposing `X`, but it is not silently rebound to `X`; the
move reports the orphan barrier and requires an explicit later rebind or
unmask. A legacy ambiguous `B` mask blocks the move until atomically rebound.

### Child move over an inherited destination mask

Initial state:

```text
parent: A(entry=X, secret=S1), B(entry=Y, secret=S2)
child:  mask(target=Y) active
```

After child `mv A B --mask-action=preserve`:

```text
parent: A(entry=X, secret=S1), B(entry=Y, secret=S2)
child:  B(entry=Z, secret=S1)
        mask(target=X) active for source-name absence
        mask(target=Y) dormant behind local B
```

Removing child `B(entry=Z)` reactivates `mask(target=Y)`, so parent `B` remains
hidden. Creation of `mask(target=X)` is reported as `source-mask-created`.

### Masked target deletion with a lower same-name fallback

Initial state:

```text
grandparent: B(entry=Y)
parent:      B(entry=X)
child:       mask(target=X) active
```

If a secdat operation removes `X`, `preserve` retains the mask for `X` as
orphaned and atomically creates a mask for fallback `Y` in the same mask chain.
`Y` is never visible between those steps. A later `unmask B` atomically removes
the entire chain, including both the orphan barrier for `X` and the active mask
for `Y`. If `X` disappears out of band, the orphan barrier blocks `B` until
`mask --rebind B` can attach safely to `Y`.

### Linked alias

Initial state:

```text
A(entry=X, secret=S)
C(entry=Z, secret=S)
child mask(target=X)
```

Renaming `A` does not make the mask hide `C`; the mask targets entry `X`, not
secret `S`.

## Consequences

### Positive

- `mv` matches the v2 directory-entry/inode model.
- UUID and `ln` alias identity survive move.
- rename-following masks do not become object-wide alias denials.
- destination writes no longer destroy negative inheritance policy.
- dormant mask hits are observable without forcing users to manage tombstone
  files.
- strict automation can reject all mask interaction, while warning suppression
  remains behavior-neutral.
- legacy ambiguity fails closed.

### Negative

- canonical mask lookup becomes graph/identity based rather than a single
  name-path check.
- local entry and mask coexistence changes `set`, `rm`, `cp`, `mv`, `ln`,
  `load`, FUSE, list, fsck, SDK, and migration assumptions.
- cross-domain propagation requires registered-descendant enumeration and a
  recoverable multi-file transaction.
- keeping the object at its original owner creates a lifecycle dependency on
  domain/store deletion guards.
- source-effective-absence semantics can break scripts that relied on a parent
  value reappearing after moving a local override.
- relation KEYREFs remain a separate name-identity problem.

## Non-goals

- Object-wide denial by `secret_id`.
- Automatic rewrite of relation records.
- Making v1 entries acquire UUIDs without store migration.
- Silently preserving old plaintext-copy `mv` as a fallback for v2.
- Treating warning suppression as authorization.
- Garbage-collecting orphaned or legacy masks during ordinary writes.
- Finalizing the on-disk binary encoding in this ADR.

## Implementation sequence

1. Add read-only canonical/legacy mask parsing and mask-state/impact
   classification.
2. Add `list --dormant`, long/JSON observation, and migration dry-run.
3. Add rollback-safe canonical identity-mask writes with legacy dual-write
   compatibility until finalization.
4. Change destination writes to preserve masks and report direct hits/state
   transitions.
5. Implement same-domain/store local v2 rename with stable `entry_id` and
   `secret_id`.
6. Add source-effective-absence handling for local overrides.
7. Add inherited-source v2 move and explicit `propagate` behavior.
8. Add cross-domain/store move only after object-owner deletion guards and a
   recoverable transaction are available.
9. Extend SDK/FUSE/batch surfaces and remove legacy write paths only after
   migration coverage is complete.

Each implementation slice requires its own issue scope and review. This ADR
does not authorize implementation.

## Required regression matrix

- local v2 `mv` preserves `secret_id` and `entry_id`;
- a moved entry stays linked to all existing `ln` aliases;
- `cp` still creates independent entry and secret IDs;
- a visible destination entry remains a destination-exists error;
- parent rename keeps a child identity mask active under the new name;
- a reachable canonical mask for a different target entry does not mask the
  moved entry, while an orphan barrier remains fail closed;
- target deletion/out-of-scope with a lower same-name ancestor atomically masks
  that fallback or fails before mutation;
- `unmask` after one or more fallback continuations removes the unique mask
  chain atomically, while ambiguous name-only lookup removes nothing and
  requires `--mask-chain`;
- name-only `unmask` refuses a chain that protects more than one authorized key
  name; chain-qualified dry-run lists all affected names before explicit
  whole-chain removal;
- long/JSON mask listing returns the authorized `mask_chain_id`, and using that
  value disambiguates only a chain that also matches the requested key;
- successful chain-qualified removal reports when another chain or legacy
  barrier still masks the requested key;
- out-of-band target loss does not expose a lower same-name ancestor;
- `mask B` under local `B` creates a dormant mask for the nearest inherited
  target, and ambiguous `unmask B` fails with inspection guidance;
- a local write over an active mask preserves it as dormant;
- repeated `set`, `cp`, `mv`, and `ln` direct hits on dormant masks warn even
  without another state transition;
- warning suppression changes neither state nor exit status;
- `reject` fails before every direct hit, transition, propagation, source-mask
  creation, or fallback mask creation;
- `propagate` copies only pre-existing applicable masks to a new destination
  entry and retains original masks;
- removal of a local override reactivates the dormant mask;
- source-name parent fallback remains hidden after `mv`;
- hidden-key mask records and warning/list output do not reveal key names while
  locked;
- unambiguous legacy masks migrate to entry identity;
- ambiguous legacy masks block direct writes and survive warning suppression;
- `mask --rebind` replaces an ambiguous barrier atomically without an exposure
  window;
- `mask --rebind` extends a canonical out-of-band orphan's existing chain
  without an exposure window;
- migration, canonical mask creation, and canonical mask conversion all retain
  equivalent v1 tombstones until finalization, and rollback never exposes a
  masked key;
- failed move restores source, destination, masks, metadata, and refcounts;
- dry-run/JSON includes schema version and requested/effective policy, and SDK
  impact counts match committed CLI behavior;
- batch set/load failure at item N, reject/legacy ambiguity in a later item, and
  restart during commit leave no partial batch after journal recovery;
- hidden target rename updates encrypted last-known mask metadata atomically or
  fails while an affected descendant is inaccessible;
- `domain delete`, `store delete`, migration finalization, and GC each refuse
  to strand moved/linked foreign entries owned by the target domain/store.

## References

- [Issue #160](https://github.com/mako10k/secdat/issues/160)
- [Store v2 domain entries and secret objects](../secdat-spec.md#510-store-v2-domain-entries-and-secret-objects)
- `docs/secdat-spec.md` FR-3b, FR-5, and FR-6
- `src/store.c` v2 entry lookup/write, `secdat_command_mv`, mask resolution,
  and link/refcount helpers
- `tests/v2_fsck_regression.sh`
- `tests/migrate_regression.sh`
