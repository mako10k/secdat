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
env.update(LC_ALL="C", LANGUAGE="C", SECDAT_MASTER_KEY="domain-move-master-key")
source = work_root / "source"
destination = work_root / "destination"
source.mkdir()
destination.mkdir()
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


def pending():
    return sorted(
        path for path in (state_root / "transactions").iterdir()
        if path.name != "lock"
    )


def relation_text(root):
    result = run(
        "--dir", str(root), "--store", "app", "relation", "show", "pair"
    )
    if result.returncode != 0 or result.stderr:
        fail(f"relation show failed: {result}")
    return result.stdout


require_ok(run("--dir", str(source), "domain", "create"), "domain create")
require_ok(run("--dir", str(source), "store", "create", "app"), "store create")
for key, value in (("ALPHA", "one"), ("BETA", "two")):
    require_ok(
        run("--dir", str(source), "--store", "app", "set", key, "--value", value),
        f"set {key}",
    )
require_ok(
    run("--dir", str(source), "store", "migrate", "app", "--to-format", "v2"),
    "migrate",
    stdout=None,
)
require_ok(
    run(
        "--dir", str(source), "--store", "app", "relation", "set", "pair",
        "--member", "first=ALPHA", "--member", "second=BETA",
    ),
    "relation set",
)
rebuilt = run(
    "--dir", str(source), "fsck", "--format", "v2",
    "--dependency-index", "--repair",
)
if rebuilt.returncode != 0 or rebuilt.stderr:
    fail(f"dependency rebuild failed: {rebuilt}")

prepared = run(
    "domain", "move", "--from", str(source), "--to", str(destination),
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if prepared.returncode != 86:
    fail(f"domain move did not stop at PREPARED: {prepared}")
operations = pending()
if len(operations) != 1:
    fail(f"expected one prepared domain move: {operations!r}")
lines = (operations[0] / "journal").read_text(encoding="utf-8").splitlines()
manifest = json.loads(lines[1])
role_phases = {(item.get("role"), item.get("phase")) for item in manifest["writes"]}
required = {
    ("reference-epoch", 10),
    ("dependency-node", 20),
    ("primary-record", 30),
    ("dependency-root", 40),
    ("root-metadata", 50),
    ("destination-registry", 60),
    ("source-registry", 70),
}
if (
    manifest.get("command") != "domain-move"
    or manifest.get("state") != "prepared"
    or not required.issubset(role_phases)
):
    fail(f"domain move phase ordering mismatch: {manifest!r}")
if str(source) not in relation_text(source) or str(destination) in relation_text(source):
    fail("PREPARED move changed the relation primary")
require_ok(run("--dir", str(source), "status", "--quiet"), "prepared recovery")
if pending() or str(source) not in relation_text(source):
    fail("PREPARED recovery did not preserve the source state")

committing = run(
    "domain", "move", "--from", str(source), "--to", str(destination),
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if committing.returncode != 86:
    fail(f"domain move did not stop at COMMITTING: {committing}")
require_ok(
    run("--dir", str(destination), "status", "--quiet"),
    "committing recovery",
)
moved_relation = relation_text(destination)
if str(source) in moved_relation or moved_relation.count(str(destination)) != 2:
    fail(f"relation KEYREFs were not rewritten exactly: {moved_relation!r}")
require_ok(
    run("--dir", str(destination), "fsck", "--format", "v2", "--dependency-index"),
    "moved dependency index",
    "ok\n",
)
require_ok(
    run("--dir", str(destination), "--store", "app", "get", "ALPHA"),
    "moved value",
    "one",
)

epoch_path = state_root / "gc/reference-epoch"
epoch_before = epoch_path.read_bytes()
require_ok(
    run(
        "--dir", str(destination), "domain", "move", "--from", str(destination),
        "--allow-same-root",
    ),
    "same-root no-op refresh",
)
if epoch_path.read_bytes() != epoch_before:
    fail("same-root refresh rotated the reference epoch")

print("PASS domain move transaction regression")
PY
