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
for path in (root, child, destination):
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


def entry_id(owner_id, secret):
    entry_dir = state_root / "domains/by-id" / owner_id / "stores/default/domain-ent"
    matches = [
        path.stem for path in entry_dir.glob("*.dent")
        if f"secret_id={secret}\n" in path.read_text(encoding="utf-8")
    ]
    if len(matches) != 1:
        fail(f"expected one entry for {secret}, found {matches!r}")
    return matches[0]


root_id = domain_id(root)
child_id = domain_id(child)
destination_id = domain_id(destination)
for path in (root, child, destination):
    migrate(path)

for key, value in (
    ("MOVE_MASK", "masked-value"),
    ("OTHER", "other-value"),
    ("PREPARED_MOVE", "prepared-value"),
    ("CRASH_MOVE", "crash-value"),
    ("CROSS_MOVE", "cross-value"),
):
    set_key(root, key, value)

require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"),
    "dependency rebuild",
    stdout=None,
)
require_ok(
    run(
        "--dir", str(root), "relation", "set", "move-pair",
        "--member", "first=MOVE_MASK", "--member", "second=OTHER",
    ),
    "relation setup",
)
require_ok(run("--dir", str(child), "mask", "MOVE_MASK"), "mask setup")

move_secret = secret_id(root, "MOVE_MASK")
move_entry = entry_id(root_id, move_secret)
epoch_path = state_root / "gc/reference-epoch"
epoch_before_same = epoch_path.read_bytes()
require_ok(run("--dir", str(root), "mv", "MOVE_MASK", "MOVE_MASKED"), "dependent mv")
if secret_id(root, "MOVE_MASKED") != move_secret or entry_id(root_id, move_secret) != move_entry:
    fail("same-namespace mv did not preserve entry and secret UUIDs")
if epoch_path.read_bytes() != epoch_before_same:
    fail("same-namespace mv rotated the reference epoch")
relation = run("--dir", str(root), "relation", "show", "move-pair")
require_ok(relation, "moved relation", stdout=None)
if "/MOVE_MASK:default" in relation.stdout or "/MOVE_MASKED:default" not in relation.stdout:
    fail(f"mv did not rewrite the relation member: {relation.stdout!r}")
masked = run("--dir", str(child), "get", "MOVE_MASKED")
if masked.returncode == 0:
    fail("identity mask did not follow the moved entry")
require_ok(run("--dir", str(child), "unmask", "MOVE_MASKED"), "unmask moved entry")
require_ok(run("--dir", str(child), "get", "MOVE_MASKED"), "unmasked moved value", "masked-value")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "dependency validation after dependent mv",
    "ok\n",
)

prepared_secret = secret_id(root, "PREPARED_MOVE")
prepared_entry = entry_id(root_id, prepared_secret)
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
require_ok(run("--dir", str(root), "status", "--quiet"), "PREPARED mv cleanup")
if pending_transactions() or secret_id(root, "PREPARED_MOVE") != prepared_secret:
    fail("PREPARED mv cleanup changed the source")
if entry_id(root_id, prepared_secret) != prepared_entry:
    fail("PREPARED mv cleanup changed the source entry UUID")

crash_secret = secret_id(root, "CRASH_MOVE")
crash_entry = entry_id(root_id, crash_secret)
committing = run(
    "--dir", str(root), "mv", "CRASH_MOVE", "CRASH_MOVED",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1"},
)
if committing.returncode != 86:
    fail(f"mv did not stop at target-1: {committing}")
require_ok(run("--dir", str(root), "status", "--quiet"), "target-1 mv recovery")
if secret_id(root, "CRASH_MOVED") != crash_secret or entry_id(root_id, crash_secret) != crash_entry:
    fail("same-namespace target recovery did not preserve UUIDs")

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

print("PASS mv transaction regression")
PY
