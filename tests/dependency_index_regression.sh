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
root.mkdir(parents=True)
child.mkdir(parents=True)


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


for domain in (root, child):
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
if "state=building\n" not in state_path.read_text(encoding="utf-8"):
    fail("mask writer did not invalidate complete dependency index")

rebuilt = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
require_ok(rebuilt, "dependency rebuild")
if rebuilt.stdout != "rebuilt-dependency-index\tglobal\tlookups=3 edges=3\n":
    fail(f"M/R/D coverage or duplicate member coalescing mismatch: {rebuilt.stdout!r}")

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
incomplete = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
)
if incomplete.returncode == 0 or "dependency index is incomplete" not in incomplete.stderr:
    fail(f"building state did not fail hidden transition closed: {incomplete}")

mask_only_rebuild = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
require_ok(mask_only_rebuild, "mask-only rebuild")
if mask_only_rebuild.stdout != "rebuilt-dependency-index\tglobal\tlookups=1 edges=1\n":
    fail(f"mask-only dependency index mismatch: {mask_only_rebuild.stdout!r}")
mask_blocked = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
)
if (
    mask_blocked.returncode == 0
    or "identity masks reference entry: ALPHA" not in mask_blocked.stderr
):
    fail(f"exact M lookup did not block hidden transition: {mask_blocked}")

require_ok(
    run("--dir", str(child), "--store", "app", "unmask", "ALPHA"),
    "unmask",
    "",
)
final_rebuild = run(
    "--dir", str(root), "fsck", "--format", "v2", "--dependency-index", "--repair"
)
require_ok(final_rebuild, "final rebuild")
if final_rebuild.stdout != "rebuilt-dependency-index\tglobal\tlookups=0 edges=0\n":
    fail(f"removed primaries remain indexed: {final_rebuild.stdout!r}")
require_ok(
    run(
        "--dir", str(root), "--store", "app", "attr", "--key-visibility", "unlocked", "ALPHA"
    ),
    "hidden transition after exact absence proof",
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
visible_blocked = run(
    "--dir", str(root), "--store", "app", "attr", "--key-visibility", "always", "GAMMA"
)
if (
    visible_blocked.returncode == 0
    or "key_visibility=always cannot be used while identity masks reference entry: GAMMA"
    not in visible_blocked.stderr
):
    fail(f"exact M lookup did not block hidden-to-visible transition: {visible_blocked}")

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
