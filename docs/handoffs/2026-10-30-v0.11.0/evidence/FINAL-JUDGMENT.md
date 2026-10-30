# v0.11.0 release preparation — final judgment

Decision: **GO for publication of the exact reviewed candidate with the known limitations below.** This is a preparation/verification result, not publication authorization. No tags, release-branch push, main push, GitHub Release, registry publication, or production installation were performed.

## Candidate and publication boundary

- Branch: `codex/release-0.11.0` (local, one commit ahead of remote main).
- Candidate: `0e4eb24eba841a901dd6b320cbb3eb71ddf37f97`.
- Tree: `704a660340df464f159b500591eb2edd7edf581f`.
- Verified remote main: `c465ab9e05a15a1b8054f52a402e93cfe006366d`.
- Working tree is clean. Final remote reads found no v0.11.0 tag; the latest listed release remains v0.10.0.
- Prepared publication inputs are frozen in `publication-inputs.json`: tag/title `v0.11.0` / `secdat v0.11.0`, exact candidate target and committed release-note body, zero explicit assets under the repository workflow.
- Before any later publication, obtain the owner's decision, revalidate these exact identities and remote state, publish/read back this exact commit to main, then follow the annotated-tag and release write/readback procedure. A new commit or tree invalidates these receipts; do not transfer them to a new merge or edited candidate.

## Required validation coverage

| Axis | Result | Evidence |
| --- | --- | --- |
| Build; fresh gettext; release metadata | PASS | 01, 02, 03 receipts |
| FUSE-enabled make check, prefix under /tmp | PASS | 04; real mount read/write/readback; installed Japanese locale covered |
| FUSE-enabled default distcheck | PASS | 05b |
| FUSE-enabled shared-only distcheck | PASS | 06 |
| FUSE-enabled static-only distcheck | PASS | 07 |
| Distribution provenance | PASS | 117 tracked shipped files match candidate Git blobs; archive-provenance.json |
| Installed C shared/static linkage and runtime | PASS | 08; exact staged pkg-config; shared path readback; static excludes shared libsecdat |
| Python source wrapper and wheel | PASS | Completed axes in 09: wheel build + isolated installed runtime/version + C API call |
| Rust check and package verification | PASS | Completed axes in 09; locked check and package verification |
| Node build/pack/external tarball consumer | PASS | Completed axes in 09; native addon load, package version and exported functions |
| Installed Go shared/static build/link/runtime | PASS | 10; exact staged library and C API runtime |
| Build-tree pkg-config | PASS | 11 |

Gate09 is retained as overall FAIL: its later Go VCS-stamping step failed. Python/Rust/Node completed successfully before that failure, as supported by the hashed ordered set-e script and explicit completion output. Gate10 completes the remaining Go axes. It would be inaccurate to relabel09 as a passing gate.

## Failed attempts and environment controls

- Failed05 used parallel `make -j2 distcheck`; inherited jobserver flags polluted the install-test path query with directory banners. The documented serial05b passes. No product/test-source change was made. The harness weakness is tracked by [#248](https://github.com/mako10k/secdat/issues/248). Failed log/receipt and extracted tree are preserved.
- Gate09 Go failure was caused by an unrelated empty HOME/.git marker confusing Go's ancestor VCS detection. Gate10 uses command-local `-buildvcs=false` for archive-derived consumer binaries. HOME and global Go settings were not changed; source provenance is provided by the candidate/archive comparison.
- Original01–04 checker/environment hashes are a retrospective inventory, explicitly not represented as execution-time hashes. Later receipts bind execution-time checker/environment/candidate/direct-script input hashes.
- Nonfatal Rust license-metadata and npm configuration/install-script warnings remain in09's raw log. Package verification and the external native addon consumer passed. Registry publication is outside this preparation.

## Known product limits

The committed release notes explicitly disclose:

- [#221](https://github.com/mako10k/secdat/issues/221): ordinary same-protocol session-agent handover remains a known XFAIL. Forced handover coverage is not trigger coverage; lock/unlock clears volatile and per-key ephemeral state.
- [#242](https://github.com/mako10k/secdat/issues/242): orphaned renamed-domain move may exit1 without a diagnostic; cause/general recovery unresolved. No fix is claimed.
- ADR0006 work #166–#169 is not declared complete.
- Existing v1 is preserved; no automatic migration or new-v1 creation option. Mixed v1-parent/v2-child masks retain the ambiguity guard, with operator-selected migration/index repair/rebind required before unmask.
- Existing v2 dependency-index and volatile-overlay identity restrictions remain.

Distcheck prefix conditions skip installed-locale smoke;04 covers it under /tmp. Static-only skips shared ABI and Python runtime; shared profiles and the isolated wheel consumer cover those axes.

## Final acceptance and measured resources

The independent final reviewer verified the clean candidate, all12 receipt log/resource hashes and recorded inputs,18 artifact hashes,117 source comparisons, and exact release-note blob/body. No remaining acceptance blocker was found. No gate was rerun by the reviewer.

All recorded gate attempts, including failures: 4431.30 seconds elapsed (73m51s),2821.20 seconds CPU (47m01s),487188KiB peak RSS. These are gate resource totals, not total task elapsed time or person effort; preparation and diagnostic work are separate.

See matrix-summary.json for receipt mapping, commands/configuration, artifact hashes and limitations; publication-inputs.json for the frozen future publication payload. Final preparation is tracked by [#247](https://github.com/mako10k/secdat/issues/247).
