#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
work_root="$(mktemp -d)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env.update(LC_ALL="C", LANGUAGE="C", SECDAT_MASTER_KEY="mv-transaction-master-key")
root = work_root / "root"
child = root / "child"
destination = work_root / "destination"
legacy = work_root / "legacy"
for path in (root, child, destination, legacy):
    path.mkdir(parents=True, exist_ok=True)
state_root = Path(env["XDG_DATA_HOME"]) / "secdat"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(*args, extra_env=None):
    command_env = env if extra_env is None else {**env, **extra_env}
    return subprocess.run(
        [bin_path, *args], text=True, capture_output=True,
        env=command_env, check=False,
    )


def require_ok(result, label, stdout=""):
    if (
        result.returncode != 0
        or result.stderr
        or (stdout is not None and result.stdout != stdout)
    ):
        fail(
            f"{label}: rc={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


def pending_transactions():
    return sorted(
        path for path in (state_root / "transactions").iterdir()
        if path.name != "lock"
    )


def domain_id(path):
    by_id = state_root / "domains/by-id"
    before = set(by_id.iterdir()) if by_id.exists() else set()
    require_ok(run("--dir", str(path), "domain", "create"), f"create {path}")
    created = set(by_id.iterdir()) - before
    if len(created) != 1:
        fail(f"could not identify domain id for {path}: {created!r}")
    return created.pop().name


def migrate(path):
    require_ok(
        run("--dir", str(path), "store", "migrate", "default", "--to-format", "v2"),
        f"migrate {path}",
        stdout=None,
    )


def set_key(path, key, value):
    require_ok(run("--dir", str(path), "set", key, "--value", value), f"set {key}")


def secret_id(path, key):
    result = run("--dir", str(path), "id", key)
    require_ok(result, f"id {key}", stdout=None)
    return result.stdout.strip()


def entry_id(owner_id, secret, key=None):
    entry_dir = state_root / "domains/by-id" / owner_id / "stores/default/domain-ent"
    matches = [
        path.stem for path in entry_dir.glob("*.dent")
        if (
            f"secret_id={secret}\n" in path.read_text(encoding="utf-8")
            and (
                key is None
                or f"key={key}\n" in path.read_text(encoding="utf-8")
            )
        )
    ]
    if len(matches) != 1:
        fail(f"expected one entry for {secret} key={key!r}, found {matches!r}")
    return matches[0]


def secret_status(path, secret):
    result = run("--dir", str(path), "secret", "status", secret)
    require_ok(result, f"secret status {secret}", stdout=None)
    return dict(
        line.split("=", 1)
        for line in result.stdout.splitlines()
        if "=" in line
    )


def require_missing(path, key, label):
    result = run("--dir", str(path), "exists", key)
    if result.returncode == 0:
        fail(f"{label}: key still exists: {key}")


def state_snapshot():
    snapshot = {}
    for path in sorted(state_root.rglob("*")):
        relative = path.relative_to(state_root)
        if path.is_file() and "transactions" not in relative.parts:
            snapshot[str(relative)] = path.read_bytes()
    return snapshot


def manifest_changed_write_count(manifest):
    return sum(
        item.get("before") != item.get("after")
        for item in manifest.get("writes", [])
    )


root_id = domain_id(root)
child_id = domain_id(child)
destination_id = domain_id(destination)
domain_id(legacy)
for path in (root, child, destination):
    migrate(path)

for key, value in (
    ("MOVE_MASK", "masked-value"),
    ("OTHER", "other-value"),
    ("PREPARED_MOVE", "prepared-value"),
    ("CRASH_MOVE", "crash-value"),
    ("CROSS_MOVE", "cross-value"),
    ("HIDDEN_MOVE", "hidden-value"),
    ("INACCESSIBLE_MOVE", "inaccessible-value"),
    ("WARNING_MOVE", "warning-value"),
    ("FALLBACK_MOVE", "parent-fallback-value"),
    ("DESTINATION_MASK", "destination-fallback-value"),
    ("INHERITED_BOUNDARY", "inherited-boundary-value"),
    ("CROSS_BOUNDARY", "cross-boundary-value"),
):
    set_key(root, key, value)
set_key(child, "FALLBACK_MOVE", "child-override-value")
set_key(child, "DESTINATION_SOURCE", "destination-source-value")
set_key(legacy, "V1_MOVE", "v1-move-value")

require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"),
    "dependency rebuild",
    stdout=None,
)
require_ok(
    run(
        "--dir", str(root), "attr", "HIDDEN_MOVE",
        "--key-visibility", "unlocked",
    ),
    "hide move source",
)
require_ok(
    run("--dir", str(root), "ln", "MOVE_MASK", "MOVE_ALIAS"),
    "move alias setup",
)
require_ok(
    run("--dir", str(root), "ln", "CRASH_MOVE", "CRASH_ALIAS"),
    "crash move alias setup",
)

require_ok(
    run(
        "--dir", str(root), "relation", "set", "move-pair",
        "--member", "first=MOVE_MASK", "--member", "second=OTHER",
    ),
    "relation setup",
)
require_ok(
    run(
        "--dir", str(root), "relation", "set", "crash-pair",
        "--member", "first=CRASH_MOVE", "--member", "second=OTHER",
    ),
    "crash relation setup",
)
require_ok(
    run(
        "--dir", str(root), "relation", "set", "inaccessible-pair",
        "--member", "first=INACCESSIBLE_MOVE", "--member", "second=OTHER",
    ),
    "inaccessible relation setup",
)
require_ok(run("--dir", str(child), "mask", "MOVE_MASK"), "mask setup")
require_ok(run("--dir", str(child), "mask", "CRASH_MOVE"), "crash mask setup")
require_ok(run("--dir", str(child), "mask", "HIDDEN_MOVE"), "hidden mask setup")
require_ok(run("--dir", str(child), "mask", "WARNING_MOVE"), "warning mask setup")
require_ok(
    run("--dir", str(child), "mask", "INACCESSIBLE_MOVE"),
    "inaccessible mask setup",
)
require_ok(
    run("--dir", str(child), "mask", "DESTINATION_MASK"),
    "destination mask setup",
)

fallback_secret = secret_id(child, "FALLBACK_MOVE")
fallback_before = state_snapshot()
fallback_reject = run(
    "--dir", str(child), "mv", "--mask-action=reject", "--json",
    "FALLBACK_MOVE", "FALLBACK_MOVED",
)
if fallback_reject.returncode == 0 or fallback_reject.stderr:
    fail(f"source fallback mv reject mismatch: {fallback_reject}")
fallback_report = json.loads(fallback_reject.stdout)
fallback_rows = [
    row for row in fallback_report["mask_impact_rows"]
    if row.get("event") == "source-mask-created"
]
if (
    fallback_report.get("ok")
    or fallback_report.get("committed")
    or fallback_report["mask_impact_counts"].get("source-mask-created") != 1
    or len(fallback_rows) != 1
    or fallback_rows[0].get("key") != "FALLBACK_MOVE"
    or secret_id(child, "FALLBACK_MOVE") != fallback_secret
    or state_snapshot() != fallback_before
):
    fail(f"source fallback mv plan mismatch: {fallback_report!r}")
require_missing(child, "FALLBACK_MOVED", "source fallback rejected mv")

destination_source_secret = secret_id(child, "DESTINATION_SOURCE")
destination_before = state_snapshot()
destination_dry = run(
    "--dir", str(child), "mv", "--dry-run", "--json",
    "DESTINATION_SOURCE", "DESTINATION_MASK",
)
require_ok(destination_dry, "destination mask mv dry-run", stdout=None)
destination_dry_report = json.loads(destination_dry.stdout)
destination_direct_rows = [
    row for row in destination_dry_report["mask_impact_rows"]
    if row.get("event") == "direct-hit"
]
if (
    destination_dry_report["mask_impact_counts"].get("direct-hit") != 1
    or destination_dry_report["mask_impact_counts"].get("became-dormant") != 1
    or len(destination_direct_rows) != 1
    or destination_direct_rows[0].get("key") != "DESTINATION_MASK"
    or destination_direct_rows[0].get("state_before") != "active"
    or destination_direct_rows[0].get("state_after") != "dormant"
    or secret_id(child, "DESTINATION_SOURCE") != destination_source_secret
    or state_snapshot() != destination_before
):
    fail(f"destination mask mv dry-run mismatch: {destination_dry_report!r}")
require_missing(child, "DESTINATION_MASK", "destination mask dry-run")

destination_reject = run(
    "--dir", str(child), "mv", "--mask-action=reject", "--json",
    "DESTINATION_SOURCE", "DESTINATION_MASK",
)
if destination_reject.returncode == 0 or destination_reject.stderr:
    fail(f"destination mask mv reject mismatch: {destination_reject}")
destination_reject_report = json.loads(destination_reject.stdout)
if (
    destination_reject_report["mask_impact_rows"]
    != destination_dry_report["mask_impact_rows"]
    or secret_id(child, "DESTINATION_SOURCE") != destination_source_secret
    or state_snapshot() != destination_before
):
    fail(f"destination mask mv reject plan mismatch: {destination_reject_report!r}")
require_missing(child, "DESTINATION_MASK", "destination mask rejected mv")

destination_commit = run(
    "--dir", str(child), "mv", "--no-warn-mask", "--json",
    "DESTINATION_SOURCE", "DESTINATION_MASK",
)
require_ok(destination_commit, "destination mask mv commit", stdout=None)
destination_commit_report = json.loads(destination_commit.stdout)
if (
    destination_commit_report["mask_impact_rows"]
    != destination_dry_report["mask_impact_rows"]
    or secret_id(child, "DESTINATION_MASK") != destination_source_secret
):
    fail(f"destination mask mv commit plan mismatch: {destination_commit_report!r}")
require_missing(child, "DESTINATION_SOURCE", "destination mask committed mv")

warning_move = run(
    "--dir", str(root), "mv", "--json",
    "WARNING_MOVE", "WARNING_MOVED",
)
expected_warning = (
    "warning: mv: 1 mask(s) followed preserved entry identity; "
    "inspect with 'secdat --dir DIR list --all-masks --long'\n"
)
if warning_move.returncode != 0 or warning_move.stderr != expected_warning:
    fail(f"followed mask warning mismatch: {warning_move}")
warning_report = json.loads(warning_move.stdout)
if warning_report["mask_impact_counts"].get("followed") != 1:
    fail(f"followed mask warning plan mismatch: {warning_report!r}")

move_secret = secret_id(root, "MOVE_MASK")
move_entry = entry_id(root_id, move_secret, "MOVE_MASK")
alias_entry = entry_id(root_id, move_secret, "MOVE_ALIAS")
move_status_before = secret_status(root, move_secret)
refcount_before_move = (
    move_status_before["refcount_cached"],
    move_status_before["refcount_actual"],
)
epoch_path = state_root / "gc/reference-epoch"
epoch_before_same = epoch_path.read_bytes()

human_dry_run = run(
    "--dir", str(root), "mv", "--dry-run",
    "MOVE_MASK", "MOVE_MASKED",
)
require_ok(human_dry_run, "dependent mv human dry-run", stdout=None)
expected_human_row = (
    f"mask_impact_row={child_id}:default:MOVE_MASK:MOVE_MASKED:"
    "followed:active:active\n"
)
if expected_human_row not in human_dry_run.stdout:
    fail(f"dependent mv human row mismatch: {human_dry_run.stdout!r}")

dry_run = run(
    "--dir", str(root), "mv", "--dry-run", "--json",
    "MOVE_MASK", "MOVE_MASKED",
)
require_ok(dry_run, "dependent mv dry-run", stdout=None)
dry_report = json.loads(dry_run.stdout)
followed_rows = [
    row for row in dry_report["mask_impact_rows"]
    if row.get("event") == "followed"
]
relation_rows = dry_report["relation_consequence_rows"]
if (
    dry_report.get("operation") != "mv"
    or not dry_report.get("ok")
    or not dry_report.get("dry_run")
    or dry_report.get("committed")
    or dry_report.get("source_secret_id") != move_secret
    or dry_report.get("destination_secret_id") != move_secret
    or dry_report.get("source_entry_id") != move_entry
    or dry_report.get("destination_entry_id") != move_entry
    or dry_report.get("entry_id_preserved") is not True
    or dry_report.get("secret_id_preserved") is not True
    or dry_report["mask_impact_counts"].get("followed") != 1
    or len(followed_rows) != 1
    or followed_rows[0].get("key") != "MOVE_MASK"
    or followed_rows[0].get("key_after") != "MOVE_MASKED"
    or dry_report.get("relation_consequence_count") != 1
    or len(relation_rows) != 1
    or relation_rows[0].get("relation_id") != "move-pair"
    or relation_rows[0].get("action") != "rewrite-keyref"
    or relation_rows[0].get("rewritten_member_count") != 1
):
    fail(f"dependent mv dry-run report mismatch: {dry_report!r}")
if secret_id(root, "MOVE_MASK") != move_secret:
    fail("mv dry-run changed the source identity")
require_missing(root, "MOVE_MASKED", "mv dry-run")
if secret_id(root, "MOVE_ALIAS") != move_secret:
    fail("mv dry-run changed the linked alias")

dependent_prepared = run(
    "--dir", str(root), "mv", "MOVE_MASK", "MOVE_MASKED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if dependent_prepared.returncode != 86:
    fail(f"dependent mv did not stop at PREPARED: {dependent_prepared}")
operations = pending_transactions()
if len(operations) != 1:
    fail(f"expected one dependent PREPARED mv transaction: {operations!r}")
dependent_manifest = json.loads(
    (operations[0] / "journal").read_text(encoding="utf-8").splitlines()[1]
)
if (
    dry_report.get("changed_file_count")
    != manifest_changed_write_count(dependent_manifest)
):
    fail(
        "dependent mv dry-run write count does not match final manifest: "
        f"{dry_report!r} {dependent_manifest!r}"
    )
require_ok(run("--dir", str(root), "status", "--quiet"), "dependent PREPARED cleanup")
if secret_id(root, "MOVE_MASK") != move_secret:
    fail("dependent PREPARED cleanup changed the source identity")
require_missing(root, "MOVE_MASKED", "dependent PREPARED cleanup")

rejected = run(
    "--dir", str(root), "mv", "--mask-action=reject", "--json",
    "MOVE_MASK", "MOVE_MASKED",
)
if rejected.returncode == 0 or rejected.stderr:
    fail(f"dependent mv reject mismatch: {rejected}")
reject_report = json.loads(rejected.stdout)
if reject_report.get("ok") or reject_report.get("committed"):
    fail(f"dependent mv reject report mismatch: {reject_report!r}")
if secret_id(root, "MOVE_MASK") != move_secret:
    fail("rejected mv changed the source identity")
require_missing(root, "MOVE_MASKED", "rejected mv")

committed = run(
    "--dir", str(root), "mv", "--no-warn-mask", "--json",
    "MOVE_MASK", "MOVE_MASKED",
)
require_ok(committed, "dependent mv", stdout=None)
commit_report = json.loads(committed.stdout)
if not commit_report.get("committed") or not commit_report.get("ok"):
    fail(f"dependent mv commit report mismatch: {commit_report!r}")
if commit_report.get("changed_file_count") != dry_report.get("changed_file_count"):
    fail(f"dependent mv dry-run/commit write count mismatch: {commit_report!r}")
if secret_id(root, "MOVE_MASKED") != move_secret or entry_id(root_id, move_secret, "MOVE_MASKED") != move_entry:
    fail("same-namespace mv did not preserve entry and secret UUIDs")
if secret_id(root, "MOVE_ALIAS") != move_secret or entry_id(root_id, move_secret, "MOVE_ALIAS") != alias_entry:
    fail("same-namespace mv changed the linked alias identity")
move_status_after = secret_status(root, move_secret)
if (
    move_status_after["refcount_cached"],
    move_status_after["refcount_actual"],
) != refcount_before_move:
    fail("same-namespace mv changed the linked secret refcount")
if epoch_path.read_bytes() != epoch_before_same:
    fail("same-namespace mv rotated the reference epoch")
relation = run("--dir", str(root), "relation", "show", "move-pair")
require_ok(relation, "moved relation", stdout=None)
if "/MOVE_MASK:default" in relation.stdout or "/MOVE_MASKED:default" not in relation.stdout:
    fail(f"mv did not rewrite the relation member: {relation.stdout!r}")
masked = run("--dir", str(child), "get", "MOVE_MASKED")
if masked.returncode == 0:
    fail("identity mask did not follow the moved entry")
require_ok(
    run("--dir", str(root), "set", "MOVE_ALIAS", "--value", "linked-update"),
    "linked alias update after mv",
)
require_ok(
    run("--dir", str(root), "get", "MOVE_MASKED"),
    "moved entry after linked alias update",
    "linked-update",
)
require_ok(run("--dir", str(child), "unmask", "MOVE_MASKED"), "unmask moved entry")
require_ok(run("--dir", str(child), "get", "MOVE_MASKED"), "unmasked moved value", "linked-update")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "dependency validation after dependent mv",
    "ok\n",
)

inaccessible_secret = secret_id(root, "INACCESSIBLE_MOVE")
inaccessible_entry = entry_id(
    root_id,
    inaccessible_secret,
    "INACCESSIBLE_MOVE",
)
inaccessible_mask = (
    state_root
    / "domains/by-id"
    / child_id
    / "stores/default/masks"
    / f"{inaccessible_entry}.mask"
)
inaccessible_mask_before = inaccessible_mask.read_bytes()
inaccessible_mask_mode = inaccessible_mask.stat().st_mode & 0o777
inaccessible_relation_before = run(
    "--dir", str(root), "relation", "show", "inaccessible-pair",
)
require_ok(
    inaccessible_relation_before,
    "inaccessible relation before rejected mv",
    stdout=None,
)
inaccessible_mask.chmod(0)
try:
    inaccessible_move = run(
        "--dir", str(root), "mv",
        "INACCESSIBLE_MOVE", "INACCESSIBLE_MOVED",
    )
finally:
    inaccessible_mask.chmod(inaccessible_mask_mode)
if inaccessible_move.returncode != 1:
    fail(f"inaccessible descendant mv was not rejected safely: {inaccessible_move}")
if secret_id(root, "INACCESSIBLE_MOVE") != inaccessible_secret:
    fail("inaccessible descendant mv changed the source identity")
if entry_id(root_id, inaccessible_secret, "INACCESSIBLE_MOVE") != inaccessible_entry:
    fail("inaccessible descendant mv changed the source entry")
require_missing(root, "INACCESSIBLE_MOVED", "inaccessible descendant mv")
if inaccessible_mask.read_bytes() != inaccessible_mask_before:
    fail("inaccessible descendant mv changed the affected mask")
inaccessible_relation_after = run(
    "--dir", str(root), "relation", "show", "inaccessible-pair",
)
require_ok(
    inaccessible_relation_after,
    "inaccessible relation after rejected mv",
    stdout=inaccessible_relation_before.stdout,
)
if run("--dir", str(child), "get", "INACCESSIBLE_MOVE").returncode == 0:
    fail("inaccessible descendant mv lost the original identity mask")

hidden_secret = secret_id(root, "HIDDEN_MOVE")
hidden_entry = entry_id(root_id, hidden_secret)
hidden_move = run(
    "--dir", str(root), "mv", "HIDDEN_MOVE", "HIDDEN_MOVED",
    extra_env={"SECDAT_MASTER_KEY": ""},
)
if hidden_move.returncode == 0:
    fail(f"locked hidden mv unexpectedly succeeded: {hidden_move}")
if entry_id(root_id, hidden_secret) != hidden_entry:
    fail("locked hidden mv changed the source entry")
require_missing(root, "HIDDEN_MOVED", "locked hidden mv")

prepared_secret = secret_id(root, "PREPARED_MOVE")
prepared_entry = entry_id(root_id, prepared_secret)
prepared_dry = run(
    "--dir", str(root), "mv", "--dry-run", "--json",
    "PREPARED_MOVE", "PREPARED_MOVED",
)
require_ok(prepared_dry, "PREPARED mv dry-run", stdout=None)
prepared_dry_report = json.loads(prepared_dry.stdout)
prepared = run(
    "--dir", str(root), "mv", "PREPARED_MOVE", "PREPARED_MOVED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if prepared.returncode != 86:
    fail(f"mv did not stop at PREPARED: {prepared}")
operations = pending_transactions()
if len(operations) != 1:
    fail(f"expected one PREPARED mv transaction: {operations!r}")
manifest = json.loads((operations[0] / "journal").read_text(encoding="utf-8").splitlines()[1])
if manifest.get("command") != "mv" or manifest.get("state") != "prepared":
    fail(f"invalid PREPARED mv manifest: {manifest!r}")
if (
    prepared_dry_report.get("changed_file_count")
    != manifest_changed_write_count(manifest)
):
    fail(
        "PREPARED mv dry-run write count does not match final manifest: "
        f"{prepared_dry_report!r} {manifest!r}"
    )
require_ok(run("--dir", str(root), "status", "--quiet"), "PREPARED mv cleanup")
if pending_transactions() or secret_id(root, "PREPARED_MOVE") != prepared_secret:
    fail("PREPARED mv cleanup changed the source")
if entry_id(root_id, prepared_secret) != prepared_entry:
    fail("PREPARED mv cleanup changed the source entry UUID")

crash_secret = secret_id(root, "CRASH_MOVE")
crash_entry = entry_id(root_id, crash_secret, "CRASH_MOVE")
crash_alias_entry = entry_id(root_id, crash_secret, "CRASH_ALIAS")
crash_status_before = secret_status(root, crash_secret)
crash_refcount_before = (
    crash_status_before["refcount_cached"],
    crash_status_before["refcount_actual"],
)
committing = run(
    "--dir", str(root), "mv", "CRASH_MOVE", "CRASH_MOVED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1"},
)
if committing.returncode != 86:
    fail(f"mv did not stop at target-1: {committing}")
require_ok(run("--dir", str(root), "status", "--quiet"), "target-1 mv recovery")
if secret_id(root, "CRASH_MOVED") != crash_secret or entry_id(root_id, crash_secret, "CRASH_MOVED") != crash_entry:
    fail("same-namespace target recovery did not preserve UUIDs")
if secret_id(root, "CRASH_ALIAS") != crash_secret or entry_id(root_id, crash_secret, "CRASH_ALIAS") != crash_alias_entry:
    fail("same-namespace target recovery changed the linked alias identity")
crash_status_after = secret_status(root, crash_secret)
if (
    crash_status_after["refcount_cached"],
    crash_status_after["refcount_actual"],
) != crash_refcount_before:
    fail("same-namespace target recovery changed the linked secret refcount")
crash_relation = run("--dir", str(root), "relation", "show", "crash-pair")
require_ok(crash_relation, "recovered moved relation", stdout=None)
if "/CRASH_MOVE:default" in crash_relation.stdout or "/CRASH_MOVED:default" not in crash_relation.stdout:
    fail(f"same-namespace target recovery did not rewrite relation: {crash_relation.stdout!r}")
if run("--dir", str(child), "get", "CRASH_MOVED").returncode == 0:
    fail("same-namespace target recovery lost the descendant identity mask")
require_missing(root, "CRASH_MOVE", "same-namespace target recovery")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "dependency validation after recovered dependent mv",
    "ok\n",
)

cross_secret = secret_id(root, "CROSS_MOVE")
cross_entry = entry_id(root_id, cross_secret)
epoch_before_cross = epoch_path.read_bytes()
cross_prepared = run(
    "mv", f"{root}/CROSS_MOVE", f"{destination}/CROSS_MOVED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if cross_prepared.returncode != 86:
    fail(f"cross-domain mv did not stop at PREPARED: {cross_prepared}")
operations = pending_transactions()
manifest = json.loads((operations[0] / "journal").read_text(encoding="utf-8").splitlines()[1])
role_phases = {(item.get("role"), item.get("phase")) for item in manifest["writes"]}
if not {
    ("reference-epoch", 10),
    ("primary-record", 30),
    ("source-removal", 31),
}.issubset(role_phases):
    fail(f"cross-domain mv phase ordering mismatch: {manifest!r}")
require_ok(run("--dir", str(root), "status", "--quiet"), "cross PREPARED cleanup")
if epoch_path.read_bytes() != epoch_before_cross or secret_id(root, "CROSS_MOVE") != cross_secret:
    fail("cross PREPARED cleanup changed the source or epoch")

cross_committing = run(
    "mv", f"{root}/CROSS_MOVE", f"{destination}/CROSS_MOVED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1"},
)
if cross_committing.returncode != 86:
    fail(f"cross-domain mv did not stop at target-1: {cross_committing}")
require_ok(run("--dir", str(destination), "status", "--quiet"), "cross mv recovery")
if epoch_path.read_bytes() == epoch_before_cross:
    fail("cross-domain mv did not rotate the reference epoch")
if secret_id(destination, "CROSS_MOVED") != cross_secret:
    fail("cross-domain mv changed the secret UUID")
if entry_id(destination_id, cross_secret) != cross_entry:
    fail("cross-domain mv changed the entry UUID")
missing_source = run("--dir", str(root), "exists", "CROSS_MOVE")
if missing_source.returncode == 0:
    fail("cross-domain mv recovery retained the source")
require_ok(
    run("--dir", str(destination), "fsck", "--format", "v2", "--dependency-index"),
    "dependency validation after cross mv",
    "ok\n",
)

unsupported_cases = (
    ("inherited", lambda options: run(
        "--dir", str(child), "mv", *options,
        "INHERITED_BOUNDARY", "INHERITED_MOVED",
    )),
    ("cross-domain", lambda options: run(
        "mv", *options,
        f"{root}/CROSS_BOUNDARY", f"{destination}/CROSS_BOUNDARY_MOVED",
    )),
    ("v1", lambda options: run(
        "--dir", str(legacy), "mv", *options,
        "V1_MOVE", "V1_MOVED",
    )),
)
for boundary, invoke in unsupported_cases:
    for options in (("--dry-run",), ("--json",), ("--mask-action=reject",)):
        before = state_snapshot()
        unsupported = invoke(options)
        if unsupported.returncode == 0 or state_snapshot() != before:
            fail(
                f"unsupported {boundary} mv planning was not all-before "
                f"for {options}: {unsupported}"
            )

print("PASS mv transaction regression")
PY
