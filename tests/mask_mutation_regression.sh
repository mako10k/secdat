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
    "SECDAT_MASTER_KEY": "mask-mutation-regression-master-key",
}

root = work_root / "workspace" / "root"
parent = root / "parent"
child = parent / "child"
bundle_source = work_root / "workspace" / "bundle-source"
for domain in (root, parent, child, bundle_source):
    domain.mkdir(parents=True, exist_ok=True)

askpass_path = work_root / "askpass.py"
bundle_path = work_root / "load.secdat"
askpass_path.write_text(
    "#!/usr/bin/env python3\n"
    "import os\n"
    "print(os.environ['SECDAT_TEST_ASKPASS_VALUE'])\n",
    encoding="utf-8",
)
askpass_path.chmod(0o700)
askpass_env = {
    **env,
    "SECDAT_ASKPASS": str(askpass_path),
    "SECDAT_TEST_ASKPASS_VALUE": "bundle-passphrase",
}


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(args, run_env=None):
    completed = subprocess.run(
        args,
        text=True,
        capture_output=True,
        env=env if run_env is None else run_env,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def expect_ok(args, run_env=None, expected_stderr=""):
    rc, stdout, stderr = run(args, run_env)
    if rc != 0 or stderr != expected_stderr:
        fail(
            f"command failed: {args!r}: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    return stdout


def expect_failure(args, run_env=None):
    rc, stdout, stderr = run(args, run_env)
    if rc == 0:
        fail(f"command unexpectedly succeeded: {args!r}")
    return rc, stdout, stderr


def parse_json(stdout, context):
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        fail(f"{context} did not return JSON: {error}: {stdout!r}")


def create_v2_domain(domain):
    expect_ok([bin_path, "--dir", str(domain), "domain", "create"])
    migrated = expect_ok(
        [
            bin_path,
            "--dir",
            str(domain),
            "store",
            "migrate",
            "default",
            "--to-format",
            "v2",
        ]
    )
    if "verified=yes\n" not in migrated:
        fail(f"migration was not verified for {domain}: {migrated!r}")


def set_key(domain, key, value=None, hidden=False):
    args = [bin_path, "--dir", str(domain), "set", key]
    if hidden:
        args.extend(["--key-visibility", "unlocked"])
    args.extend(["--value", key.lower() if value is None else value])
    expect_ok(args)


def mask_key(key):
    expect_ok([bin_path, "--dir", str(child), "mask", key])


def mask_rows():
    return parse_json(
        expect_ok(
            [
                bin_path,
                "--dir",
                str(child),
                "list",
                "--all-masks",
                "--json",
            ]
        ),
        "mask list",
    )["masks"]


def mask_state(key):
    matches = [row for row in mask_rows() if row.get("key") == key]
    if len(matches) != 1:
        fail(f"expected one mask row for {key}, got {matches!r}")
    return matches[0]["state"]


def key_exists(domain, key):
    rc, _, _ = run([bin_path, "--dir", str(domain), "exists", key])
    return rc == 0


def domain_store(domain):
    resolved = str(domain.resolve())
    for root_path in Path(env["XDG_DATA_HOME"]).glob(
        "secdat/domains/by-id/*/meta/root"
    ):
        if root_path.read_text(encoding="utf-8") == resolved:
            return (
                root_path.parent.parent.name,
                root_path.parent.parent / "stores" / "default",
            )
    fail(f"domain store not found for {domain}")


for domain in (root, parent, child, bundle_source):
    create_v2_domain(domain)

parent_keys = [
    "SET_ACTIVE",
    "SET_REJECT",
    "SET_DRY",
    "CP_DEST",
    "CP_SOURCE",
    "LN_DEST",
    "LN_SOURCE",
    "RM_REACTIVATE",
    "RM_SOURCE_MASK",
    "BATCH_ONE",
    "BATCH_TWO",
    "LOAD_ONE",
    "LOAD_TWO",
    "FAULT_SET",
    "ORPHAN_SET",
    "LEGACY_AMBIGUOUS",
    "LOCKED_OTHER",
]
for key in parent_keys:
    set_key(parent, key, f"parent-{key}")
set_key(root, "LEGACY_AMBIGUOUS", "root-legacy")
set_key(parent, "HIDDEN_LOCKED", "hidden", hidden=True)

for key in [
    "SET_ACTIVE",
    "SET_REJECT",
    "SET_DRY",
    "CP_DEST",
    "LN_DEST",
    "RM_REACTIVATE",
    "BATCH_ONE",
    "BATCH_TWO",
    "LOAD_ONE",
    "LOAD_TWO",
    "FAULT_SET",
    "ORPHAN_SET",
    "HIDDEN_LOCKED",
]:
    mask_key(key)

# preserve defaults warn after commit and keep the canonical mask dormant.
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "SET_ACTIVE",
        "--value",
        "local",
    ]
)
if (
    rc != 0
    or stdout != ""
    or "warning: set:" not in stderr
    or "1 directly affected masked key slot(s)" not in stderr
    or "1 mask(s) became dormant" not in stderr
):
    fail(f"default set warning mismatch: rc={rc} out={stdout!r} err={stderr!r}")
if mask_state("SET_ACTIVE") != "dormant":
    fail("set did not preserve the active mask as dormant")

# A repeated dormant direct hit remains observable; warning suppression changes
# neither the result nor the JSON impact rows.
report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "set",
            "SET_ACTIVE",
            "--value",
            "local-2",
            "--no-warn-mask",
            "--json",
        ]
    ),
    "dormant direct-hit set",
)
if (
    not report.get("ok")
    or not report.get("committed")
    or report.get("mask_warnings_requested") != "off"
    or report.get("mask_warnings_effective")
    or report["mask_impact_counts"].get("direct-hit") != 1
    or report["mask_impact_counts"].get("became-dormant") != 0
):
    fail(f"dormant direct-hit report mismatch: {report!r}")
direct_rows = [
    row
    for row in report["mask_impact_rows"]
    if row.get("event") == "direct-hit"
]
if (
    len(direct_rows) != 1
    or direct_rows[0].get("state_before") != "dormant"
    or direct_rows[0].get("state_after") != "dormant"
):
    fail(f"dormant direct-hit row mismatch: {direct_rows!r}")

# reject and dry-run both use the complete plan and leave live state untouched.
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "SET_REJECT",
        "--value",
        "rejected",
        "--mask-action=reject",
        "--json",
    ]
)
reject_report = parse_json(stdout, "reject set")
if (
    rc != 1
    or stderr != ""
    or reject_report.get("ok")
    or reject_report.get("committed")
    or reject_report.get("mask_warnings_effective")
    or reject_report["mask_impact_counts"].get("direct-hit") != 1
    or key_exists(child, "SET_REJECT")
    or mask_state("SET_REJECT") != "active"
):
    fail(f"reject contract mismatch: {reject_report!r} stderr={stderr!r}")

dry_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "set",
            "SET_DRY",
            "--value",
            "dry",
            "--dry-run",
            "--json",
        ]
    ),
    "dry-run set",
)
if (
    not dry_report.get("ok")
    or dry_report.get("committed")
    or not dry_report.get("dry_run")
    or dry_report["mask_impact_counts"].get("direct-hit") != 1
    or key_exists(child, "SET_DRY")
    or mask_state("SET_DRY") != "active"
):
    fail(f"dry-run contract mismatch: {dry_report!r}")

# cp and ln use the same destination plan and do not delete its mask.
for command, source, destination in [
    ("cp", "CP_SOURCE", "CP_DEST"),
    ("ln", "LN_SOURCE", "LN_DEST"),
]:
    report = parse_json(
        expect_ok(
            [
                bin_path,
                "--dir",
                str(child),
                command,
                source,
                destination,
                "--no-warn-mask",
                "--json",
            ]
        ),
        f"{command} destination plan",
    )
    if (
        not report.get("committed")
        or report["mask_impact_counts"].get("direct-hit") != 1
        or report["mask_impact_counts"].get("became-dormant") != 1
        or mask_state(destination) != "dormant"
    ):
        fail(f"{command} mask result mismatch: {report!r}")

# rm reactivates a preserved dormant mask. Removing an inherited key creates
# one source mask, which reject can also stop before mutation.
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "RM_REACTIVATE",
        "--value",
        "local-rm",
        "--no-warn-mask",
    ]
)
rm_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "rm",
            "RM_REACTIVATE",
            "--no-warn-mask",
            "--json",
        ]
    ),
    "rm reactivation",
)
if (
    rm_report["mask_impact_counts"].get("direct-hit") != 1
    or rm_report["mask_impact_counts"].get("reactivated") != 1
    or mask_state("RM_REACTIVATE") != "active"
):
    fail(f"rm reactivation mismatch: {rm_report!r}")

rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "rm",
        "RM_SOURCE_MASK",
        "--mask-action=reject",
        "--json",
    ]
)
source_reject = parse_json(stdout, "rm source-mask reject")
if (
    rc != 1
    or stderr != ""
    or source_reject["mask_impact_counts"].get("source-mask-created") != 1
    or not key_exists(child, "RM_SOURCE_MASK")
):
    fail(f"rm source-mask reject mismatch: {source_reject!r}")

# Multi-set plans and commits as one aggregate batch.
batch_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "set",
            "BATCH_ONE=one",
            "BATCH_TWO=two",
            "--no-warn-mask",
            "--json",
        ]
    ),
    "multi-set aggregate",
)
if (
    batch_report["mask_impact_counts"].get("direct-hit") != 2
    or batch_report["mask_impact_counts"].get("became-dormant") != 2
    or mask_state("BATCH_ONE") != "dormant"
    or mask_state("BATCH_TWO") != "dormant"
):
    fail(f"multi-set aggregate mismatch: {batch_report!r}")

# A later operand failure cannot leak an earlier staged assignment.
expect_failure(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "ATOMIC_GOOD=one",
        "BAD-NAME=two",
    ]
)
if key_exists(child, "ATOMIC_GOOD"):
    fail("failed multi-set leaked its earlier assignment")

# load uses one plan for every key in the bundle.
set_key(bundle_source, "LOAD_ONE", "loaded-one")
set_key(bundle_source, "LOAD_TWO", "loaded-two")
expect_ok(
    [
        bin_path,
        "--dir",
        str(bundle_source),
        "save",
        str(bundle_path),
    ],
    askpass_env,
)
load_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "load",
            str(bundle_path),
            "--no-warn-mask",
            "--json",
        ],
        askpass_env,
    ),
    "load aggregate",
)
if (
    load_report["mask_impact_counts"].get("direct-hit") != 2
    or load_report["mask_impact_counts"].get("became-dormant") != 2
    or mask_state("LOAD_ONE") != "dormant"
    or mask_state("LOAD_TWO") != "dormant"
):
    fail(f"load aggregate mismatch: {load_report!r}")

# A standalone ambiguous legacy tombstone is a hard precondition even with
# warnings disabled, and its complete JSON result remains available.
child_id, child_store = domain_store(child)
legacy_tombstone = child_store / "tombstones" / "LEGACY_AMBIGUOUS.tomb"
legacy_tombstone.parent.mkdir(parents=True, exist_ok=True)
legacy_tombstone.write_bytes(b"")
legacy_tombstone.chmod(0o600)
rc, stdout, stderr = expect_failure(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "LEGACY_AMBIGUOUS",
        "--value",
        "local",
        "--no-warn-mask",
        "--json",
    ]
)
legacy_report = parse_json(stdout, "legacy ambiguous set")
if (
    rc != 1
    or stderr != ""
    or legacy_report["mask_impact_counts"].get("legacy-ambiguous") != 1
    or not legacy_tombstone.exists()
):
    fail(f"legacy ambiguity contract mismatch: {legacy_report!r}")

# When hidden mask names cannot be read, require_complete fails closed before
# an otherwise public inherited rm can create a tombstone.
locked_env = {**env}
locked_env.pop("SECDAT_MASTER_KEY", None)
locked_runtime = work_root / "locked-runtime"
locked_runtime.mkdir(mode=0o700)
locked_env["XDG_RUNTIME_DIR"] = str(locked_runtime)
locked_list = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "list",
            "--all-masks",
            "--json",
        ],
        locked_env,
    ),
    "locked mask list",
)
if locked_list.get("redacted_mask_count", 0) < 1:
    fail(f"hidden mask was not redacted while locked: {locked_list!r}")
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "rm",
        "LOCKED_OTHER",
        "--mask-warnings=off",
    ],
    locked_env,
)
if rc == 0:
    fail(
        "locked hidden-mask mutation unexpectedly succeeded: "
        f"stdout={stdout!r} stderr={stderr!r}"
    )
locked_other_tombstone = child_store / "tombstones" / "LOCKED_OTHER.tomb"
if (
    rc != 1
    or stdout != ""
    or "cannot analyze mask impact while hidden mask names are locked"
        not in stderr
    or locked_other_tombstone.exists()
):
    fail(f"locked hidden-mask preflight mismatch: {stderr!r}")

# Fault recovery rolls a multi-file mutation forward before the next command.
fault_env = {
    **env,
    "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1",
}
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "FAULT_SET",
        "--value",
        "faulted",
        "--no-warn-mask",
    ],
    fault_env,
)
if rc != 86:
    fail(
        "state-file transaction fault did not stop at target-1: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
if not key_exists(child, "FAULT_SET") or mask_state("FAULT_SET") != "dormant":
    fail("state-file transaction recovery did not restore all-after state")

# Commands without propagate semantics reject it as an argument, independently
# of warning selection.
rc, _, stderr = expect_failure(
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "NO_PROPAGATE",
        "--value",
        "value",
        "--mask-action=propagate",
        "--no-warn-mask",
    ]
)
if rc != 2 or "invalid mask action: propagate" not in stderr:
    fail(f"invalid propagate handling mismatch: rc={rc} stderr={stderr!r}")

print("mask mutation regression tests passed")
PY
