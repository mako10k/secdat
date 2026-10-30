# secdat v0.11.0 Release Notes

## Highlights

- New persistent stores use format v2: new-domain default stores, explicit
  `store create`, and supported implicit creation through CLI writes, qualified
  destinations, SDK setters, and volatile-overlay save. Existing marked and
  markerless v1 stores keep their format and normal read/write behavior.
- `fsck` detects the selected local store's format when `--format` is omitted.
  Explicit `--format v1|v2` continues to enforce that format.
- Bash completion suggests existing store names in the command's namespace:
  effective inherited stores for `--store`/`-s`, and local stores for delete,
  migrate, and finalize-migration operands. Completion does not unlock stores,
  read secret values, initialize stores, or migrate existing data.
- Local v2 `mv` within the same domain/store preserves secret and entry identity,
  including linked-value identity and mask planning. Broader move modes remain
  outside this release's completed scope.
- Local overrides remain visible to listing, completion, export, and exec when
  they coexist with a dormant inherited-entry mask. Removing the override
  reactivates the retained mask rather than exposing the parent value.

## Compatibility and operator actions

- No automatic v1 migration or public option for creating a new v1 store is
  added. Existing v1 conversion remains an explicit operator choice. Review
  `store migrate STORE --to-format v2 --dry-run` before running the migration;
  migration finalization is also explicit.
- Read-only operations, completion, dry-runs, rejected precommit checks, and
  writes with no effective changes do not initialize an absent store. Once a
  transaction enters COMMITTING, interrupted writes retain a recoverable journal.
- Existing v2 identity, dependency-index, and mask guards remain enabled.
  New-store creation does not rebuild the global dependency index. Operations
  such as identity-preserving `mv` and hidden-name transitions may require an
  explicit `fsck --dependency-index --repair` when coverage is incomplete.
- A v2 child masking an existing v1 parent's key can retain a legacy-ambiguous
  mask. Ordinary unmask is refused until the operator explicitly migrates the
  parent, prepares the dependency index where required, and runs child
  `mask --rebind` before unmask. This release does not migrate the parent or
  relax that ambiguity guard.
- Volatile overlays do not provide persisted v2 graph identity. Removing a local
  persisted v2 entry requires a normal writable session; overlay-only removals
  and inherited masks retain their supported behavior.
- The public C SDK ABI and `libsecdat.so.0` SONAME are unchanged from v0.10.0.
  Python, Rust, and Node package versions track `0.11.0`; the Rust binding requires
  `libsecdat >= 0.11.0` through `pkg-config`.

## Known limitations

- [#221](https://github.com/mako10k/secdat/issues/221): an ordinary client command
  does not trigger lossless handover from a same-protocol capable session agent.
  The regression remains a known XFAIL; forced handover tests prove protocol
  transfer, not the production trigger. There is no supported manual lossless
  same-protocol handover. `lock` followed by `unlock` restarts the session and
  clears volatile and per-key ephemeral state.
- [#242](https://github.com/mako10k/secdat/issues/242): moving an orphaned domain
  after its directory was renamed has been reported to exit 1 with no diagnostic,
  leaving the old registration orphaned and the destination unregistered. The
  cause and a general recovery procedure remain unresolved. This release does
  not claim a fix; retain the existing domain data and registration for diagnosis.
- The remaining ADR 0006 work in
  [#166](https://github.com/mako10k/secdat/issues/166),
  [#167](https://github.com/mako10k/secdat/issues/167),
  [#168](https://github.com/mako10k/secdat/issues/168), and
  [#169](https://github.com/mako10k/secdat/issues/169) is not declared complete:
  source absence for moves of local overrides, inherited-source propagation,
  guarded cross-namespace moves, and the remaining SDK/FUSE/finalization surfaces
  retain their documented boundaries.

## Validation

The release candidate must complete the repository's receipt-driven release
matrix before tagging: fresh gettext and release metadata checks, FUSE-enabled
`make check`, default/shared-only/static-only FUSE-enabled `make distcheck`, and
installed C/Python/Rust/Node/Go consumer and package checks. Results and residual
limitations are reported separately against the frozen candidate commit and tree;
this checklist is not itself a claim that those gates have passed.
