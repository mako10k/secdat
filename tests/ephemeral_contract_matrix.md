# Per-key ephemeral contract matrix

This matrix names the automated checks that protect the per-key ephemeral
contract. The quoted labels are stable failure-message fragments in the
listed regression script; they are more durable anchors than line numbers.

## Read and selection surfaces

| Contract cell | Automated check |
| --- | --- |
| CLI `get`, `exists`, `ls`, JSON metadata, and `attr` | `session_regression.sh`: `ephemeral shadow get`, `child tombstone ephemeral exists`, `ephemeral ls --json metadata`, `ephemeral attr read` |
| CLI `list --bulk-gate` and `ls --bulk-gate` for exclude/named/include | `session_regression.sh`: `list ephemeral bulk-select matrix`, `ls ephemeral bulk-select matrix` |
| CLI `export` and explicit/bulk-gated `exec` | `session_regression.sh`: `child tombstone ephemeral bulk export`, `explicit ephemeral exec injection`, `bulk-gated ephemeral exec injection` |
| SDK get/list with hidden backing and an unrelated process key | `sdk_regression.sh`: `SDK get did not read`, `SDK list returned wrong`, `SDK ephemeral enumeration harness` |
| FUSE selection and read | `fuse_regression.sh`: `ephemeral FUSE dry-run selection`, `ephemeral FUSE read` |
| Bundle and `lock --save` exclusion | `session_regression.sh`: `save did not reject tombstone-shadowing ephemeral`, `lock --save persisted an ephemeral key` |

## Mutation refusal surfaces

| Contract cell | Automated check |
| --- | --- |
| CLI plain `set`/`rm`; `cp`/`mv` source and destination | `session_regression.sh`: table ending in `ambiguous ephemeral operation should fail` plus `refused destination mutation changed ephemeral value` |
| CLI v2 `ln` source and destination | `session_regression.sh`: `v2 ephemeral link refusal mismatch` |
| CLI `mask`, `unmask`, `attr`, metadata set/unset/mark-leaked, relation, and save | `session_regression.sh`: table ending in `ambiguous ephemeral operation should fail` |
| SDK set, atomic write, and atomic resize | `sdk_regression.sh`: `SDK write unexpectedly persisted`, `SDK atomic write unexpectedly updated`, `SDK atomic resize unexpectedly updated` |
| SDK rm, mv/cp source and destination, mask, and unmask | `sdk_regression.sh`: `refusal_cases` table plus `rejected SDK destination mutation changed` |
| Live FUSE write and truncate | `fuse_regression.sh`: `ephemeral FUSE write did not fail closed`, `ephemeral FUSE truncate did not fail closed` |
| FUSE fallback without a live mount | `sdk_regression.sh`: the always-run SDK atomic write/resize checks used by the FUSE implementation |

## Lifecycle surfaces

| Contract cell | Automated check |
| --- | --- |
| Replace an existing ephemeral item | `session_regression.sh`: `existing ephemeral replacement`, `ephemeral replacement value mismatch` |
| Remove and ignore a missing item | `session_regression.sh`: `ephemeral shadow removal`, `missing ephemeral ignore-missing` |
| Setter process exits while the agent remains active | `session_regression.sh`: `ephemeral value did not survive setter process exit` |
| Session agent process exits and clears its memory | `session_regression.sh`: `ephemeral key survived session agent process exit`, `session agent socket survived process exit` |
| Same-master refresh preserves items | `session_regression.sh`: `same-master owner refresh lost ephemeral key` |
| Local and inherited-agent locks purge only the target domain | `session_regression.sh`: `child ephemeral reappeared after lock`, `child lock cleared unrelated ephemeral key`, `ancestor-owned same-master child ephemeral reappeared` |
| Different-master child replacement clears the target domain | `session_regression.sh`: `replaced child session retained ancestor-owned ephemeral key`, `different-key replacement ephemeral reappeared` |
| Different-master owner replacement clears every item owned by that agent | `session_regression.sh`: `different-master owner replacement retained ephemeral key` |
| Expiry clears the item | `session_regression.sh`: `ephemeral key survived session expiry` |

## Payload and protocol compatibility

| Contract cell | Automated check |
| --- | --- |
| Large payload | `session_regression.sh`: `large ephemeral set/get/cleanup` |
| Binary stdin payload containing NUL bytes | `session_regression.sh`: `binary ephemeral round trip` |
| Old-agent `EPLOOKUP` and `EPLIST` unsupported-command fallback | `session_regression.sh`: `old-agent EPLOOKUP compatibility`, `old-agent EPLIST compatibility` |
| Unexpected old-agent lookup/list errors fail closed | `session_regression.sh`: `unexpected EPLOOKUP errors`, `unexpected EPLIST errors` |

## Session-agent negotiation and handover

| Contract cell | Automated check |
| --- | --- |
| Legacy persistent fallback and legacy volatile fail-closed behavior | `session_regression.sh`: old-agent `OVLIST` EOF mode matrix |
| Advertised capability, malformed protocol, and incomplete overlay failures remain fail-closed | `session_regression.sh`: failed `CAPS`, malformed `proto`, capability-advertised EOF, and persistent/readonly write guards |
| Abandoned, truncated, malformed-length, unsupported-version, or rejected import preserves the old authoritative process and state | `session_regression.sh`: abandoned handover plus checksum/frame/version/candidate fault matrix |
| Stalled coordinator/candidate rolls back within the phase deadline and queued clients resume | `session_regression.sh`: stalled raw coordinator and `stall-after-ready` candidate |
| Bulk snapshot preserves binary, empty, large, tombstone, attribute, child-domain, and multi-store items | `session_regression.sh`: `HANDOVER_*` value/attribute/tombstone matrix |
| Successful activation changes the serving PID without extending absolute expiry | `session_regression.sh`: capability/PID and `session_expires_at` comparison |
| Volatile, persistent, and readonly session modes survive handover | `session_regression.sh`: forced handover mode matrix |
| `lock --save` persists volatile changes but never imported ephemeral entries | `session_regression.sh`: post-handover save and default/alternate-store absence checks |
