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
env.update(
    LC_ALL="C",
    LANGUAGE="C",
    SECDAT_MASTER_KEY="dependency-index-master-key",
)
root = work_root / "root"
child = root / "child"
child2 = root / "child2"
root.mkdir(parents=True)
child.mkdir(parents=True)
child2.mkdir(parents=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(*args):
    return subprocess.run(
        [bin_path, *args], text=True, capture_output=True, env=env, check=False
    )


def require_ok(result, label, stdout=None):
    if result.returncode != 0 or result.stderr or (stdout is not None and result.stdout != stdout):
        fail(
            f"{label}: rc={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


for domain in (root, child, child2):
    require_ok(run("--dir", str(domain), "domain", "create"), f"create {domain}", "")
    require_ok(run("--dir", str(domain), "store", "create", "app"), f"store {domain}", "")

for key, value in (("ALPHA", "one"), ("BETA", "two")):
    require_ok(
        run("--dir", str(root), "--store", "app", "set", key, "--value", value),
        f"set {key}",
        "",
    )

require_ok(
    run("--dir", str(root), "store", "migrate", "app", "--to-format", "v2"),
    "migrate root",
)
require_ok(
    run("--dir", str(child), "store", "migrate", "app", "--to-format", "v2"),
    "migrate child",
)
require_ok(
    run("--dir", str(child2), "store", "migrate", "app", "--to-format", "v2"),
    "migrate child2",
)

missing = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if missing.returncode != 1 or missing.stdout != (
    "dependency-index\tglobal\tmissing-building-corrupt-or-stale\n"
):
    fail(f"missing index did not fail closed: {missing}")
wrong_format = run("--dir", str(root), "fsck", "--dependency-index")
if wrong_format.returncode != 2 or "requires --format v2" not in wrong_format.stderr:
    fail(f"dependency index accepted v1 format: {wrong_format}")
combined = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--orphaned"
)
if combined.returncode != 2 or "cannot be combined with store checks" not in combined.stderr:
    fail(f"dependency index accepted combined store checks: {combined}")

empty = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
require_ok(empty, "empty rebuild")
if empty.stdout != "rebuilt-dependency-index\tglobal\tlookups=0 edges=0\n":
    fail(f"empty rebuild receipt mismatch: {empty.stdout!r}")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "empty validate",
    "ok\n",
)

state_path = Path(env["XDG_DATA_HOME"]) / "secdat/indexes/dependency-state"
require_ok(
    run(
        "--dir", str(root), "--store", "app", "relation", "set", "pair",
        "--member", "first=ALPHA", "--member", "second=ALPHA",
    ),
    "relation set",
    "",
)
relation_only = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
require_ok(relation_only, "relation-only rebuild")
if relation_only.stdout != "rebuilt-dependency-index\tglobal\tlookups=2 edges=2\n":
    fail(f"R/D coverage or duplicate member coalescing mismatch: {relation_only.stdout!r}")
relation_blocked = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
)
if (
    relation_blocked.returncode == 0
    or "relation references key: ALPHA (pair)" not in relation_blocked.stderr
):
    fail(f"exact R lookup did not block hidden transition: {relation_blocked}")

relation_path = next(
    path
    for path in (Path(env["XDG_DATA_HOME"]) / "secdat").rglob("pair.rel")
    if "transactions" not in path.parts
)
relation_bytes = relation_path.read_bytes()
relation_path.write_bytes(relation_bytes + b"note=changed-outside-writer\n")
stale_primary = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if stale_primary.returncode != 1 or "dependency-index\tglobal\t" not in stale_primary.stdout:
    fail(f"changed relation primary was accepted: {stale_primary}")
stale_lookup = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
)
if stale_lookup.returncode == 0 or "dependency index is corrupt" not in stale_lookup.stderr:
    fail(f"exact R lookup accepted changed relation primary: {stale_lookup}")
relation_path.write_bytes(relation_bytes)
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "validate restored relation primary",
    "ok\n",
)

require_ok(
    run("--dir", str(child), "--store", "app", "mask", "ALPHA"),
    "canonical mask",
    "",
)
if "state=complete\n" not in state_path.read_text(encoding="utf-8"):
    fail("mask writer did not preserve a complete dependency index")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental mask dependency update",
    "ok\n",
)
require_ok(
    run("--dir", str(child2), "--store", "app", "mask", "ALPHA"),
    "second canonical mask for one entry",
    "",
)
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental multi-edge mask update",
    "ok\n",
)
require_ok(
    run("--dir", str(child2), "--store", "app", "unmask", "ALPHA"),
    "remove one mask edge while preserving another",
    "",
)
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental multi-edge mask removal",
    "ok\n",
)

# A complete index is updated in the same recovery authority as the mask
# primary. The manifest guards every old Merkle node that was traversed and
# publishes new nodes before the primary and the replacement active root.
crash_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
crashed_mask = subprocess.run(
    [bin_path, "--dir", str(child), "--store", "app", "mask", "BETA"],
    text=True,
    capture_output=True,
    env=crash_env,
    check=False,
)
if crashed_mask.returncode != 86:
    fail(f"indexed mask did not stop at committing: {crashed_mask}")
transactions_root = Path(env["XDG_DATA_HOME"]) / "secdat/transactions"
pending = [path for path in transactions_root.iterdir() if path.name != "lock"]
if len(pending) != 1:
    fail(f"expected one indexed mask transaction: {pending!r}")
envelope = (pending[0] / "journal").read_text(encoding="utf-8").splitlines()
if len(envelope) != 2:
    fail(f"invalid indexed mask journal envelope: {envelope!r}")
manifest = json.loads(envelope[1])
guards = manifest.get("guards", [])
writes = manifest.get("writes", [])
phases = {write.get("phase") for write in writes}
if (
    manifest.get("version") != 2
    or manifest.get("state") != "committing"
    or not guards
    or any(
        guard.get("type") != "exact-file"
        or guard.get("role") != "exact-file"
        for guard in guards
    )
    or not {20, 30, 40}.issubset(phases)
    or not any(write.get("role") == "dependency-node" for write in writes)
    or not any(write.get("role") == "primary-record" for write in writes)
    or not any(write.get("role") == "dependency-root" for write in writes)
):
    fail(f"indexed mask transaction ordering/guards mismatch: {manifest!r}")
require_ok(run("--dir", str(child), "status", "--quiet"), "indexed mask recovery", "")
if "state=complete\n" not in state_path.read_text(encoding="utf-8"):
    fail("indexed mask recovery did not publish a complete root")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "indexed mask recovery validation",
    "ok\n",
)
require_ok(
    run("--dir", str(child), "--store", "app", "unmask", "BETA"),
    "remove recovered indexed mask",
    "",
)
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental recovered-mask removal",
    "ok\n",
)

indexes_root = Path(env["XDG_DATA_HOME"]) / "secdat/indexes"
node_bytes = b"".join(path.read_bytes() for path in sorted(indexes_root.rglob("*.idx")))
if b"ALPHA" in node_bytes:
    fail("plaintext logical key leaked into dependency nodes")

active_root = next(
    line.split("=", 1)[1]
    for line in state_path.read_text(encoding="utf-8").splitlines()
    if line.startswith("active_root=")
)
root_node = indexes_root / "dependencies/nodes" / active_root[:2] / f"{active_root}.idx"
root_shard = root_node.parent
real_root_shard = root_shard.with_name(f"{root_shard.name}.real")
root_shard.rename(real_root_shard)
root_shard.symlink_to(real_root_shard, target_is_directory=True)
symlinked = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if symlinked.returncode != 1 or "dependency-index\tglobal\t" not in symlinked.stdout:
    fail(f"symlinked dependency shard was accepted: {symlinked}")
root_shard.unlink()
real_root_shard.rename(root_shard)

root_node.write_bytes(root_node.read_bytes() + b"\n")
corrupt = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if corrupt.returncode != 1 or "dependency-index\tglobal\t" not in corrupt.stdout:
    fail(f"node content/hash corruption was accepted: {corrupt}")
require_ok(
    run(
        "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
    ),
    "repair corrupt node",
)
repaired_root = next(
    line.split("=", 1)[1]
    for line in state_path.read_text(encoding="utf-8").splitlines()
    if line.startswith("active_root=")
)
if repaired_root != active_root:
    fail(f"deterministic dependency root changed: {active_root} != {repaired_root}")

require_ok(
    run("--dir", str(root), "--store", "app", "relation", "rm", "pair"),
    "relation rm",
    "",
)
if "state=complete\n" not in state_path.read_text(encoding="utf-8"):
    fail("relation rm writer did not preserve a complete dependency index")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental relation dependency removal",
    "ok\n",
)
mask_blocked = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
)
if (
    mask_blocked.returncode == 0
    or "hidden-name transition cannot preserve v1 rollback mask state: ALPHA"
    not in mask_blocked.stderr
):
    fail(f"v1 rollback state did not block hidden transition: {mask_blocked}")

# Finalized v2 state has no plaintext compatibility tombstone. In that state,
# the complete M lookup rewrites every named mask record in the same transaction
# as the entry and dependency root instead of rejecting the transition.
alpha_tombstones = [
    path
    for path in (Path(env["XDG_DATA_HOME"]) / "secdat").rglob("ALPHA.tomb")
    if "transactions" not in path.parts
]
if len(alpha_tombstones) != 1:
    fail(f"expected one ALPHA compatibility tombstone: {alpha_tombstones!r}")
alpha_tombstones[0].unlink()
require_ok(
    run(
        "--dir", str(root), "--store", "app", "attr",
        "--key-visibility", "unlocked", "ALPHA",
    ),
    "hidden transition with exact mask closure",
    "",
)
alpha_masks = [
    path
    for path in (Path(env["XDG_DATA_HOME"]) / "secdat").rglob("*.mask")
    if "transactions" not in path.parts and b"ALPHA" in path.read_bytes()
]
if alpha_masks:
    fail(f"hidden transition retained plaintext mask names: {alpha_masks!r}")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "hidden transition dependency closure",
    "ok\n",
)

require_ok(
    run("--dir", str(child), "--store", "app", "unmask", "ALPHA"),
    "unmask",
    "",
)
if "state=complete\n" not in state_path.read_text(encoding="utf-8"):
    fail("unmask writer did not preserve a complete dependency index")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "incremental unmask dependency update",
    "ok\n",
)
require_ok(
    run(
        "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
    ),
    "already-hidden transition after exact absence proof",
    "",
)

original_state = state_path.read_text(encoding="utf-8")
state_path.write_text(original_state + "\n", encoding="utf-8")
trailing = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if trailing.returncode != 1 or "dependency-index\tglobal\t" not in trailing.stdout:
    fail(f"trailing state data was accepted: {trailing}")
state_path.write_text(original_state + "unknown=field\n", encoding="utf-8")
strict = run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index")
if strict.returncode != 1 or "dependency-index\tglobal\t" not in strict.stdout:
    fail(f"unknown state field was accepted: {strict}")
corrupt_writer = run(
    "--dir", str(child2), "--store", "app", "mask", "BETA"
)
if (
    corrupt_writer.returncode == 0
    or "dependency index is corrupt" not in corrupt_writer.stderr
):
    fail(f"mask writer accepted malformed dependency state: {corrupt_writer}")

state_path.write_text(original_state, encoding="utf-8")
require_ok(
    run(
        "--dir", str(root), "--store", "app", "set", "GAMMA",
        "--value", "three", "--key-visibility", "unlocked",
    ),
    "create hidden key",
    "",
)
require_ok(
    run("--dir", str(child), "--store", "app", "mask", "GAMMA"),
    "mask hidden key",
    "",
)
require_ok(
    run(
        "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
    ),
    "hidden-mask rebuild",
)
require_ok(
    run(
        "--dir", str(root), "--store", "app", "set", "GAMMA",
        "--value", "updated", "--key-visibility", "unlocked",
    ),
    "update already-hidden masked key",
    "",
)
require_ok(
    run("--dir", str(root), "--store", "app", "get", "GAMMA"),
    "read updated hidden key",
    "updated",
)
require_ok(
    run(
        "--dir", str(root), "--store", "app", "attr",
        "--key-visibility", "always", "GAMMA",
    ),
    "visible transition with exact mask closure",
    "",
)
gamma_masks = [
    path
    for path in (Path(env["XDG_DATA_HOME"]) / "secdat").rglob("*.mask")
    if "transactions" not in path.parts and b"GAMMA" in path.read_bytes()
]
gamma_tombstones = [
    path
    for path in (Path(env["XDG_DATA_HOME"]) / "secdat").rglob("GAMMA.tomb")
    if "transactions" not in path.parts
]
if len(gamma_masks) != 1 or len(gamma_tombstones) != 1:
    fail(
        "visible transition did not restore canonical rollback state: "
        f"masks={gamma_masks!r} tombstones={gamma_tombstones!r}"
    )
gamma_tombstones[0].unlink()
require_ok(
    run(
        "--dir", str(root), "--store", "app", "attr",
        "--key-visibility", "unlocked", "GAMMA",
    ),
    "restore hidden state after finalized rollback removal",
    "",
)
if b"GAMMA" in gamma_masks[0].read_bytes():
    fail("restored hidden transition retained plaintext mask name")
require_ok(
    run("--dir", str(root), "fsck", "--format", "v2", "--dependency-index"),
    "bidirectional visibility dependency closure",
    "ok\n",
)

hidden_relation_path = relation_path.parent / "hidden-direct.rel"
hidden_relation_path.write_bytes(
    relation_bytes.replace(b"relation_id=pair", b"relation_id=hidden-direct").replace(
        b"ALPHA", b"GAMMA"
    )
)
hidden_relation_path.chmod(0o600)
hidden_relation = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
if (
    hidden_relation.returncode != 1
    or "cannot index a relation dependency that references a hidden v2 key"
    not in hidden_relation.stderr
):
    fail(f"dependency rebuild accepted a hidden relation member: {hidden_relation}")
hidden_relation_path.unlink()
require_ok(
    run(
        "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
    ),
    "rebuild after hidden relation removal",
)

noncanonical_path = relation_path.parent / "noncanonical.rel"
noncanonical_path.write_text(
    "SECDATREL1\n"
    "relation_id=noncanonical\n"
    "kind=dependency\n"
    "member=first\tALPHA\n"
    "member=second\tBETA\n",
    encoding="utf-8",
)
noncanonical_path.chmod(0o600)
noncanonical = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
if noncanonical.returncode != 1 or "cannot index relation dependency" not in noncanonical.stderr:
    fail(f"dependency rebuild accepted non-canonical relation members: {noncanonical}")
noncanonical_path.unlink()
require_ok(
    run(
        "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
    ),
    "rebuild after non-canonical relation removal",
)
final_node_bytes = b"".join(
    path.read_bytes() for path in sorted(indexes_root.rglob("*.idx"))
)
if b"GAMMA" in final_node_bytes:
    fail("hidden logical key leaked into rebuilt dependency nodes")

print("PASS dependency index regression")
PY
