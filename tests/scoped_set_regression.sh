#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

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
env = {
    **os.environ,
    "LC_ALL": "C",
    "LANGUAGE": "C",
    "SECDAT_MASTER_KEY": "scoped-set-regression-master-key",
}
target = work_root / "workspace" / "target"
unrelated = work_root / "workspace" / "unrelated"
target.mkdir(parents=True)
unrelated.mkdir(parents=True)
domains_by_id = Path(env["XDG_DATA_HOME"]) / "secdat" / "domains" / "by-id"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(args, extra_env=None):
    command_env = env if extra_env is None else {**env, **extra_env}
    return subprocess.run(
        args,
        text=True,
        capture_output=True,
        env=command_env,
        check=False,
    )


def expect_ok(args):
    completed = run(args)
    if completed.returncode != 0 or completed.stderr != "":
        fail(
            f"command failed: {args!r}: rc={completed.returncode} "
            f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
        )
    return completed.stdout


def create_v2_domain(path):
    before = set(domains_by_id.iterdir()) if domains_by_id.exists() else set()
    expect_ok([bin_path, "--dir", str(path), "domain", "create"])
    expect_ok(
        [
            bin_path,
            "--dir",
            str(path),
            "store",
            "migrate",
            "default",
            "--to-format",
            "v2",
        ]
    )
    created = set(domains_by_id.iterdir()) - before
    if len(created) != 1:
        fail(f"could not identify created domain: {created!r}")
    return created.pop()


target_state = create_v2_domain(target)
unrelated_state = create_v2_domain(unrelated)

# A whole-tree staging clone rejects this non-regular artifact. A scoped set
# must not inspect it because it is outside the selected domain chain.
sentinel = unrelated_state / "scope-sentinel"
os.mkfifo(sentinel, 0o600)
try:
    expect_ok(
        [
            bin_path,
            "--dir",
            str(target),
            "set",
            "SCOPED",
            "--value",
            "one",
        ]
    )
finally:
    sentinel.unlink()

if expect_ok([bin_path, "--dir", str(target), "get", "SCOPED"]) != "one":
    fail("scoped set value mismatch")

# Repeated operands in one command observe earlier projected after-images and
# preserve one entry identity while the final value wins.
expect_ok(
    [
        bin_path,
        "--dir",
        str(target),
        "set",
        "BATCH=first",
        "BATCH=second",
    ]
)
if expect_ok([bin_path, "--dir", str(target), "get", "BATCH"]) != "second":
    fail("projected batch value mismatch")
entry_count = len(list((target_state / "stores" / "default" / "domain-ent").glob("*.dent")))
if entry_count != 2:
    fail(f"repeated set created extra entry identities: {entry_count}")

# The direct write set retains the existing transaction recovery guarantee.
crashed = run(
    [
        bin_path,
        "--dir",
        str(target),
        "set",
        "SCOPED",
        "--value",
        "recovered",
    ],
    {"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1"},
)
if crashed.returncode != 86:
    fail(
        f"transaction fault injection did not crash at target-1: "
        f"rc={crashed.returncode} stdout={crashed.stdout!r} "
        f"stderr={crashed.stderr!r}"
    )
transaction_root = Path(env["XDG_DATA_HOME"]) / "secdat" / "transactions"
pending = sorted(path for path in transaction_root.iterdir() if path.name != "lock")
if len(pending) != 1:
    fail(f"expected one pending scoped transaction: {pending!r}")
journal_lines = (pending[0] / "journal").read_text(encoding="utf-8").splitlines()
if len(journal_lines) != 2:
    fail(f"invalid scoped transaction envelope: {journal_lines!r}")
manifest = json.loads(journal_lines[1])
writes = manifest.get("writes")
if (
    manifest.get("version") != 2
    or manifest.get("guards") != []
    or not isinstance(writes, list)
    or not writes
    or [(write.get("phase"), write.get("name")) for write in writes]
    != sorted((write.get("phase"), write.get("name")) for write in writes)
    or any(
        write.get("phase") != 30
        or write.get("role") != "primary-record"
        or write.get("sensitive") is not True
        for write in writes
    )
):
    fail(f"scoped set did not persist canonical phased writes: {manifest!r}")
if expect_ok([bin_path, "--dir", str(target), "get", "SCOPED"]) != "recovered":
    fail("scoped set recovery did not roll forward")

leftovers = sorted(path.name for path in transaction_root.iterdir() if path.name != "lock")
if leftovers:
    fail(f"transaction recovery left artifacts: {leftovers!r}")

print("PASS scoped set regression")
PY
