#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

work_root="$(mktemp -d)"
if [[ "${SECDAT_TEST_KEEP_WORK_ROOT:-0}" == "1" ]]; then
    trap 'printf "kept work root: %s\n" "$work_root" >&2' EXIT
else
    trap 'rm -rf "$work_root"' EXIT
fi

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = {
    **os.environ,
    "LC_ALL": "C",
    "LANGUAGE": "C",
    "SECDAT_MASTER_KEY": "mask-transaction-regression-master-key",
}

root = work_root / "root"
parent = root / "parent"
child = parent / "child"
for domain in (root, parent, child):
    domain.mkdir(parents=True, exist_ok=True)


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


def expect_ok(args, expected_stderr=""):
    rc, stdout, stderr = run(args)
    if rc != 0 or stderr != expected_stderr:
        fail(
            f"command failed: {args!r}: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    return stdout


def run_while_mask_plan_paused(planned_args, concurrent_args, context):
    controller, worker_socket = socket.socketpair()
    lock_controller, lock_worker_socket = socket.socketpair()
    planned_env = {
        **env,
        "SECDAT_TEST_MASK_PLAN_SYNC_FD": str(worker_socket.fileno()),
    }
    planned = subprocess.Popen(
        planned_args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=planned_env,
        pass_fds=(worker_socket.fileno(),),
    )
    worker_socket.close()
    controller.settimeout(10)
    if controller.recv(1) != b"R":
        planned.kill()
        fail(f"{context} did not reach its prepared plan")
    concurrent_env = {
        **env,
        "SECDAT_TEST_TRANSACTION_LOCK_ATTEMPT_FD": str(
            lock_worker_socket.fileno()
        ),
    }
    concurrent = subprocess.Popen(
        concurrent_args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=concurrent_env,
        pass_fds=(lock_worker_socket.fileno(),),
    )
    lock_worker_socket.close()
    lock_controller.settimeout(10)
    lock_result = lock_controller.recv(1)
    if lock_result != b"B":
        planned.kill()
        concurrent.kill()
        fail(
            f"{context} concurrent writer did not observe the held "
            f"transaction lock: {lock_result!r}"
        )
    lock_controller.close()
    if concurrent.poll() is not None:
        planned.kill()
        fail(f"{context} concurrent writer bypassed the transaction lock")
    controller.sendall(b"G")
    controller.close()
    planned_stdout, planned_stderr = planned.communicate(timeout=10)
    concurrent_stdout, concurrent_stderr = concurrent.communicate(timeout=10)
    if (
        planned.returncode != 0
        or planned_stdout != ""
        or planned_stderr != ""
        or concurrent.returncode != 0
        or concurrent_stdout != ""
        or concurrent_stderr != ""
    ):
        fail(
            f"{context} did not serialize cleanly: "
            f"planned=({planned.returncode}, {planned_stdout!r}, "
            f"{planned_stderr!r}) concurrent=({concurrent.returncode}, "
            f"{concurrent_stdout!r}, {concurrent_stderr!r})"
        )


def create_domain(domain):
    expect_ok([bin_path, "--dir", str(domain), "domain", "create"])


def domain_store(domain):
    resolved = str(domain.resolve())
    for root_file in Path(env["XDG_DATA_HOME"]).glob(
        "secdat/domains/by-id/*/meta/root"
    ):
        if root_file.read_text(encoding="utf-8") == resolved:
            return root_file.parent.parent.name, root_file.parent.parent / "stores" / "default"
    fail(f"domain store not found for {domain}")


def migrate(domain):
    stdout = expect_ok(
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
    if "verified=yes\n" not in stdout:
        fail(f"migration was not verified for {domain}: {stdout!r}")


def set_key(domain, key, value="value", hidden=False):
    args = [bin_path, "--dir", str(domain), "set", key]
    if hidden:
        args.extend(["--key-visibility", "unlocked"])
    args.extend(["--value", value])
    expect_ok(args)


def parse_json(stdout, context):
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as error:
        fail(f"{context} did not return JSON: {error}: {stdout!r}")


def entry_for_key(store, key):
    for path in (store / "domain-ent").glob("*.dent"):
        fields = dict(
            line.split("=", 1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line
        )
        if fields.get("key") == key:
            return path.stem
    fail(f"entry not found for {key}")


def available_fixture_entry_id(store, high):
    used = {path.stem for path in (store / "domain-ent").glob("*.dent")}
    for offset in range(len(used) + 1):
        suffix = (0xFFFFFFFFFFFF - offset) if high else offset
        if high:
            candidate = f"ffffffff-ffff-4fff-bfff-{suffix:012x}"
        else:
            candidate = f"00000000-0000-4000-8000-{suffix:012x}"
        if candidate not in used:
            return candidate
    fail("could not allocate deterministic fixture entry ID")


def reidentify_entry(store, current_entry_id, replacement_entry_id):
    current_path = store / "domain-ent" / f"{current_entry_id}.dent"
    replacement_path = store / "domain-ent" / f"{replacement_entry_id}.dent"
    if replacement_path.exists():
        fail(f"fixture entry ID already exists: {replacement_entry_id}")
    current_text = current_path.read_text(encoding="utf-8")
    current_field = f"entry_id={current_entry_id}\n"
    if current_text.count(current_field) != 1:
        fail(f"fixture entry ID field is invalid: {current_entry_id}")
    current_path.write_text(
        current_text.replace(
            current_field,
            f"entry_id={replacement_entry_id}\n",
            1,
        ),
        encoding="utf-8",
    )
    current_path.rename(replacement_path)
    return replacement_entry_id


def mask_paths(child_store, target_entry_id, key):
    return (
        child_store / "masks" / f"{target_entry_id}.mask",
        child_store / "tombstones" / f"{key}.tomb",
    )


def assert_mask_state(mask_path, tombstone_path, expected, context):
    actual = (mask_path.exists(), tombstone_path.exists())
    if actual != expected:
        fail(f"{context}: expected mask/tombstone {expected!r}, got {actual!r}")


create_domain(root)
create_domain(parent)
create_domain(child)

keys = [
    "PUBLIC",
    "FAULT_PREPARED",
    "FAULT_COMMITTING",
    "FAULT_TARGET",
    "FAULT_COMMITTED",
    "FAULT_DEPENDENCY",
    "FAULT_DEPENDENCY_V1",
    "FAULT_UNMASK",
    "FAULT_TAMPER",
    "FAULT_NUL",
    "FAULT_PHASE",
    "CONCURRENT_MASK",
    "CONCURRENT_UNMASK",
    "REBIND",
    "CHAIN_A",
    "CHAIN_B",
    "WARN_DEFAULT",
    "WARN_QUIET",
    "LEGACY_REBIND",
    "LEGACY_UNMASK",
    "LEGACY_AMBIG",
]
for key in keys:
    set_key(parent, key)
set_key(root, "LEGACY_AMBIG", "root-ambiguous")
set_key(root, "MIXED_REMAINING", "root-visible")
set_key(parent, "HIDDEN_ROLLBACK")
set_key(child, "WARN_DEFAULT", "local-default")
set_key(child, "WARN_QUIET", "local-quiet")

migrate(root)
migrate(parent)
migrate(child)
expect_ok(
    [
        bin_path,
        "--dir",
        str(parent),
        "attr",
        "HIDDEN_ROLLBACK",
        "--key-visibility",
        "unlocked",
    ]
)
set_key(parent, "HIDDEN", hidden=True)
set_key(parent, "MIXED_REMAINING", "parent-hidden", hidden=True)
root_id, root_store = domain_store(root)
parent_id, parent_store = domain_store(parent)
child_id, child_store = domain_store(child)

# Canonical creation, dual-write compatibility, stable plan schema, and
# idempotent repeat.
public_entry = entry_for_key(parent_store, "PUBLIC")
public_mask, public_tombstone = mask_paths(
    child_store, public_entry, "PUBLIC"
)
dry_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--dry-run",
            "--json",
            "PUBLIC",
        ]
    ),
    "mask dry-run",
)
if (
    dry_report.get("plan_schema_version")
    != "secdat.mask-operation-plan.v1"
    or dry_report.get("operation") != "mask"
    or dry_report.get("dry_run") is not True
    or dry_report.get("committed") is not False
):
    fail(f"unexpected mask dry-run plan: {dry_report!r}")
assert_mask_state(public_mask, public_tombstone, (False, False), "mask dry-run")

created_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--json",
            "PUBLIC",
        ]
    ),
    "mask commit",
)
chain_id = created_report.get("mask_chain_id")
if (
    not created_report.get("committed")
    or created_report.get("target_entry_id") != public_entry
    or not isinstance(chain_id, str)
):
    fail(f"unexpected committed mask plan: {created_report!r}")
assert_mask_state(public_mask, public_tombstone, (True, True), "mask commit")
tombstone_text = public_tombstone.read_text(encoding="utf-8")
if tombstone_text != (
    "SECDATMASKCOMPAT1\n"
    "version=1\n"
    f"target_entry_id={public_entry}\n"
):
    fail(f"unexpected compatibility tombstone: {tombstone_text!r}")

repeat_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--json",
            "PUBLIC",
        ]
    ),
    "repeated mask",
)
if (
    repeat_report.get("mask_chain_id") != chain_id
    or repeat_report.get("no_op") is not True
    or repeat_report.get("write_mask") is not False
    or repeat_report.get("write_legacy_tombstone") is not False
):
    fail(f"repeated mask was not idempotent: {repeat_report!r}")
list_report = parse_json(
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
    "mask list after dual-write",
)
public_rows = [
    row for row in list_report["masks"] if row.get("key") == "PUBLIC"
]
if (
    len(public_rows) != 1
    or public_rows[0].get("record_kind") != "canonical"
):
    fail(f"compatibility tombstone became a second logical mask: {public_rows!r}")

unmask_dry = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "unmask",
            "--dry-run",
            "--json",
            "PUBLIC",
        ]
    ),
    "unmask dry-run",
)
if (
    unmask_dry.get("plan_schema_version")
    != "secdat.mask-operation-plan.v1"
    or unmask_dry.get("mask_chain_id") != chain_id
    or unmask_dry.get("record_count") != 1
    or unmask_dry.get("affected_key_slots")
    != [{"key": "PUBLIC", "record_count": 1}]
    or unmask_dry.get("resulting_effective_state") != "inherited"
):
    fail(f"unexpected unmask dry-run: {unmask_dry!r}")
assert_mask_state(
    public_mask, public_tombstone, (True, True), "unmask dry-run"
)
unmask_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "unmask",
            "--json",
            "PUBLIC",
        ]
    ),
    "unmask commit",
)
if not unmask_report.get("committed"):
    fail(f"unmask did not report commit: {unmask_report!r}")
assert_mask_state(
    public_mask, public_tombstone, (False, False), "unmask commit"
)

# Commit-boundary crashes recover to all-before or all-after.
fault_cases = [
    ("prepared", "FAULT_PREPARED", (False, False), (False, False)),
    ("committing", "FAULT_COMMITTING", (False, False), (True, True)),
    ("target-1", "FAULT_TARGET", (True, False), (True, True)),
    ("committed", "FAULT_COMMITTED", (True, True), (True, True)),
]
for boundary, key, crash_state, recovered_state in fault_cases:
    target_entry = entry_for_key(parent_store, key)
    mask_path, tombstone_path = mask_paths(child_store, target_entry, key)
    fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": boundary}
    rc, stdout, stderr = run(
        [bin_path, "--dir", str(child), "mask", key],
        run_env=fault_env,
    )
    if rc != 86:
        fail(
            f"fault boundary {boundary} did not exit at injection: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    assert_mask_state(
        mask_path,
        tombstone_path,
        crash_state,
        f"{boundary} crash state",
    )
    if boundary == "committing":
        pending = [
            path
            for path in (
                Path(env["XDG_DATA_HOME"]) / "secdat" / "transactions"
            ).iterdir()
            if path.name != "lock"
        ]
        if len(pending) != 1:
            fail(f"expected one pending transaction: {pending!r}")
        temporary = pending[0] / ".tmp.interrupted-atomic-write"
        temporary.write_bytes(b"partial")
        temporary.chmod(0o600)
    committed_dependency = None
    if boundary == "committed":
        committed_dependency = (
            parent_store / "domain-ent" / f"{target_entry}.dent"
        )
        committed_text = committed_dependency.read_text(encoding="utf-8")
        committed_dependency.write_text(
            committed_text.replace(
                "bulk_select_entry=exclude\n",
                "bulk_select_entry=include\n",
            ),
            encoding="utf-8",
        )
        committed_dependency.chmod(0o600)
    expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
    assert_mask_state(
        mask_path,
        tombstone_path,
        recovered_state,
        f"{boundary} recovered state",
    )
    if (
        committed_dependency is not None
        and "bulk_select_entry=include\n"
        not in committed_dependency.read_text(encoding="utf-8")
    ):
        fail("committed recovery reverted a validation-only dependency")

transactions_root = Path(env["XDG_DATA_HOME"]) / "secdat" / "transactions"
if sorted(path.name for path in transactions_root.iterdir()) != ["lock"]:
    fail(f"completed transactions were not cleaned: {list(transactions_root.iterdir())!r}")

# Manifest v2 persists source observations as validation-only guards, separate
# from replayable writes. COMMITTING recovery does not reevaluate those guards;
# it rolls the exact write frontier forward and preserves later guard changes.
dependency_entry = entry_for_key(parent_store, "FAULT_DEPENDENCY")
dependency_path = parent_store / "domain-ent" / f"{dependency_entry}.dent"
dependency_mask, dependency_tombstone = mask_paths(
    child_store, dependency_entry, "FAULT_DEPENDENCY"
)
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "FAULT_DEPENDENCY"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "validation dependency setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
pending = [path for path in transactions_root.iterdir() if path.name != "lock"]
if len(pending) != 1:
    fail(f"expected one v2 dependency transaction: {pending!r}")
dependency_journal = pending[0] / "journal"
dependency_payload = dependency_journal.read_text(encoding="utf-8").splitlines()
if len(dependency_payload) != 2:
    fail(f"invalid v2 dependency journal envelope: {dependency_payload!r}")
dependency_manifest = json.loads(dependency_payload[1])
if (
    dependency_manifest.get("version") != 2
    or set(dependency_manifest) != {
        "version",
        "operation_id",
        "command",
        "owner_domain_id",
        "owner_store",
        "state",
        "guards",
        "writes",
    }
    or len(dependency_manifest["guards"]) != 1
    or dependency_manifest["guards"][0].get("type") != "exact-file"
    or dependency_manifest["guards"][0].get("role") != "exact-file"
    or not dependency_manifest["writes"]
    or any(write.get("phase") != 30 for write in dependency_manifest["writes"])
):
    fail(f"v2 guard/write manifest was not canonical: {dependency_manifest!r}")
dependency_original = dependency_path.read_text(encoding="utf-8")
dependency_path.write_text(
    dependency_original.replace(
        "bulk_select_entry=exclude\n",
        "bulk_select_entry=include\n",
    ),
    encoding="utf-8",
)
dependency_path.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc != 0
    or stdout != ""
    or stderr != ""
    or not dependency_mask.exists()
    or not dependency_tombstone.exists()
    or "bulk_select_entry=include\n"
    not in dependency_path.read_text(encoding="utf-8")
):
    fail(
        "v2 recovery reevaluated a guard after COMMITTING: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
dependency_path.write_text(dependency_original, encoding="utf-8")
dependency_path.chmod(0o600)
assert_mask_state(
    dependency_mask,
    dependency_tombstone,
    (True, True),
    "v2 committed dependency recovery",
)

# A version-1 journal remains recoverable with its legacy validation target
# semantics. Changing that target after COMMITTING blocks every write until the
# exact before-image is restored.
legacy_dependency_entry = entry_for_key(parent_store, "FAULT_DEPENDENCY_V1")
legacy_dependency_path = (
    parent_store / "domain-ent" / f"{legacy_dependency_entry}.dent"
)
legacy_dependency_mask, legacy_dependency_tombstone = mask_paths(
    child_store, legacy_dependency_entry, "FAULT_DEPENDENCY_V1"
)
fault_env = {
    **env,
    "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing",
    "SECDAT_TEST_TRANSACTION_MANIFEST_VERSION": "1",
}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "FAULT_DEPENDENCY_V1"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "v1 compatibility setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
pending = [path for path in transactions_root.iterdir() if path.name != "lock"]
if len(pending) != 1:
    fail(f"expected one v1 dependency transaction: {pending!r}")
legacy_payload = (pending[0] / "journal").read_text(encoding="utf-8").splitlines()
legacy_manifest = json.loads(legacy_payload[1])
if legacy_manifest.get("version") != 1 or "targets" not in legacy_manifest:
    fail(f"legacy v1 journal was not emitted: {legacy_manifest!r}")
legacy_dependency_original = legacy_dependency_path.read_text(encoding="utf-8")
legacy_dependency_path.write_text(
    legacy_dependency_original.replace(
        "bulk_select_entry=exclude\n",
        "bulk_select_entry=include\n",
    ),
    encoding="utf-8",
)
legacy_dependency_path.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc == 0
    or "transaction target changed during recovery" not in stderr
    or legacy_dependency_mask.exists()
    or legacy_dependency_tombstone.exists()
):
    fail(
        "v1 validation target compatibility did not fail closed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
legacy_dependency_path.write_text(legacy_dependency_original, encoding="utf-8")
legacy_dependency_path.chmod(0o600)
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
assert_mask_state(
    legacy_dependency_mask,
    legacy_dependency_tombstone,
    (True, True),
    "restored v1 validation dependency recovery",
)

# Unmask uses the same journal. A crash after removing the canonical record
# rolls forward the compatibility tombstone removal on restart.
unmask_entry = entry_for_key(parent_store, "FAULT_UNMASK")
unmask_mask, unmask_tombstone = mask_paths(
    child_store, unmask_entry, "FAULT_UNMASK"
)
expect_ok([bin_path, "--dir", str(child), "mask", "FAULT_UNMASK"])
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "target-1"}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "unmask", "FAULT_UNMASK"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "unmask target fault did not exit: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
assert_mask_state(
    unmask_mask,
    unmask_tombstone,
    (False, True),
    "unmask crash state",
)
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
assert_mask_state(
    unmask_mask,
    unmask_tombstone,
    (False, False),
    "unmask recovered state",
)

# The command-wide transaction lock keeps every mutating writer outside the
# interval between an immutable mask/unmask plan and its commit.
concurrent_mask_entry = entry_for_key(parent_store, "CONCURRENT_MASK")
concurrent_mask, concurrent_mask_tombstone = mask_paths(
    child_store, concurrent_mask_entry, "CONCURRENT_MASK"
)
run_while_mask_plan_paused(
    [bin_path, "--dir", str(child), "mask", "CONCURRENT_MASK"],
    [bin_path, "--dir", str(parent), "rm", "CONCURRENT_MASK"],
    "mask plan serialization",
)
assert_mask_state(
    concurrent_mask,
    concurrent_mask_tombstone,
    (True, True),
    "serialized mask plan",
)

concurrent_unmask_entry = entry_for_key(
    parent_store, "CONCURRENT_UNMASK"
)
concurrent_unmask, concurrent_unmask_tombstone = mask_paths(
    child_store, concurrent_unmask_entry, "CONCURRENT_UNMASK"
)
expect_ok([bin_path, "--dir", str(child), "mask", "CONCURRENT_UNMASK"])
run_while_mask_plan_paused(
    [bin_path, "--dir", str(child), "unmask", "CONCURRENT_UNMASK"],
    [
        bin_path,
        "--dir",
        str(child),
        "set",
        "CONCURRENT_UNMASK",
        "--value",
        "local-after-unmask",
    ],
    "unmask plan serialization",
)
assert_mask_state(
    concurrent_unmask,
    concurrent_unmask_tombstone,
    (False, False),
    "serialized unmask plan",
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "get", "--stdout", "CONCURRENT_UNMASK"]
)
if rc != 0 or stdout != "local-after-unmask" or stderr != "":
    fail(
        "serialized post-unmask writer produced the wrong effective value: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

# Hidden-name canonical records round-trip while unlocked and authenticate all
# bound identity/address fields plus ciphertext and tag.
hidden_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--json",
            "HIDDEN",
        ]
    ),
    "hidden mask commit",
)
hidden_entry = hidden_report["target_entry_id"]
hidden_mask, hidden_tombstone = mask_paths(
    child_store, hidden_entry, "HIDDEN"
)
hidden_original = hidden_mask.read_text(encoding="utf-8")
if (
    "key_visibility=unlocked\n" not in hidden_original
    or "encrypted_last_known_key=" not in hidden_original
    or "last_known_key=HIDDEN" in hidden_original
    or hidden_tombstone.exists()
    or hidden_report.get("write_legacy_tombstone") is not False
):
    fail(
        "hidden canonical mask leaked its name or was not encrypted: "
        f"{hidden_original!r}"
    )
hidden_rows = [
    row
    for row in parse_json(
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
        "hidden mask list",
    )["masks"]
    if row.get("key") == "HIDDEN"
]
if len(hidden_rows) != 1 or hidden_rows[0]["target_entry_id"] != hidden_entry:
    fail(f"hidden mask did not round-trip while unlocked: {hidden_rows!r}")


def expect_tamper_failure(text, context, path=hidden_mask):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    rc, stdout, stderr = run(
        [
            bin_path,
            "--dir",
            str(child),
            "list",
            "--all-masks",
            "--json",
        ]
    )
    if rc == 0 or "HIDDEN" in stdout:
        fail(
            f"{context} was accepted or leaked the key: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    path.write_text(hidden_original, encoding="utf-8")
    path.chmod(0o600)


expect_tamper_failure(
    hidden_original.replace(
        f"mask_chain_id={hidden_report['mask_chain_id']}",
        "mask_chain_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ),
    "mask chain AAD tamper",
)
expect_tamper_failure(
    hidden_original.replace(
        f"target_secret_id={hidden_report['target_secret_id']}",
        "target_secret_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaac",
    ),
    "target secret AAD tamper",
)
expect_tamper_failure(
    hidden_original.replace(
        f"target_secret_id={hidden_report['target_secret_id']}\n",
        (
            f"target_secret_id={hidden_report['target_secret_id']}\n"
            "predecessor_entry_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaad\n"
        ),
    ),
    "predecessor AAD tamper",
)
expect_tamper_failure(
    hidden_original.replace(
        f"last_known_target_domain={parent_id}",
        f"last_known_target_domain={child_id}",
    ),
    "target domain AAD tamper",
)
expect_tamper_failure(
    hidden_original.replace(
        "last_known_target_store=default",
        "last_known_target_store=other",
    ),
    "target store AAD tamper",
)
encrypted_line = next(
    line
    for line in hidden_original.splitlines()
    if line.startswith("encrypted_last_known_key=")
)
encrypted_hex = encrypted_line.split("=", 1)[1]
cipher_index = 24
tampered_cipher = (
    encrypted_hex[:cipher_index]
    + ("0" if encrypted_hex[cipher_index] != "0" else "1")
    + encrypted_hex[cipher_index + 1 :]
)
expect_tamper_failure(
    hidden_original.replace(encrypted_hex, tampered_cipher),
    "ciphertext tamper",
)
tampered_tag = encrypted_hex[:-1] + (
    "0" if encrypted_hex[-1] != "0" else "1"
)
expect_tamper_failure(
    hidden_original.replace(encrypted_hex, tampered_tag),
    "tag tamper",
)

changed_entry = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab"
changed_path = hidden_mask.with_name(f"{changed_entry}.mask")
changed_text = hidden_original.replace(
    f"target_entry_id={hidden_entry}",
    f"target_entry_id={changed_entry}",
)
hidden_mask.rename(changed_path)
expect_tamper_failure(changed_text, "target entry AAD tamper", changed_path)
changed_path.rename(hidden_mask)
hidden_mask.write_text(hidden_original, encoding="utf-8")
hidden_mask.chmod(0o600)

# A migrated hidden v1 fallback cannot acquire a name tombstone without
# disclosing the hidden name, so the operation fails before mutation.
hidden_rollback_masks_before = {
    path.name for path in (child_store / "masks").glob("*.mask")
}
hidden_rollback_tombstone = (
    child_store / "tombstones" / "HIDDEN_ROLLBACK.tomb"
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "HIDDEN_ROLLBACK"]
)
if (
    rc == 0
    or stdout != ""
    or "cannot be projected to v1 rollback state" not in stderr
    or {
        path.name for path in (child_store / "masks").glob("*.mask")
    } != hidden_rollback_masks_before
    or hidden_rollback_tombstone.exists()
):
    fail(
        "hidden rollback projection did not fail closed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

# If an explicit unmask leaves multiple same-name chains, a visible chain
# anywhere in the remaining set owns the v1 rollback projection. A hidden
# orphan sorting first must not make the result depend on directory order.
mixed_hidden_probe = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--dry-run",
            "--json",
            "MIXED_REMAINING",
        ]
    ),
    "mixed hidden mask fixture probe",
)
mixed_hidden_entry = reidentify_entry(
    parent_store,
    mixed_hidden_probe["target_entry_id"],
    available_fixture_entry_id(parent_store, high=False),
)
mixed_visible_entry = reidentify_entry(
    root_store,
    entry_for_key(root_store, "MIXED_REMAINING"),
    available_fixture_entry_id(root_store, high=True),
)
if not mixed_hidden_entry < mixed_visible_entry:
    fail("deterministic hidden-first canonical mask ordering is invalid")
mixed_hidden_report = parse_json(
    expect_ok(
        [bin_path, "--dir", str(child), "mask", "--json", "MIXED_REMAINING"]
    ),
    "mixed hidden mask",
)
if mixed_hidden_report["target_entry_id"] != mixed_hidden_entry:
    fail(f"mixed hidden mask selected wrong target: {mixed_hidden_report!r}")
mixed_hidden_mask, mixed_tombstone = mask_paths(
    child_store, mixed_hidden_entry, "MIXED_REMAINING"
)
mixed_hidden_stash = work_root / "mixed-hidden.mask"
mixed_hidden_mask.rename(mixed_hidden_stash)
(parent_store / "domain-ent" / f"{mixed_hidden_entry}.dent").unlink()

mixed_visible_report = parse_json(
    expect_ok(
        [bin_path, "--dir", str(child), "mask", "--json", "MIXED_REMAINING"]
    ),
    "mixed visible mask",
)
if mixed_visible_report["target_entry_id"] != mixed_visible_entry:
    fail(f"mixed visible mask selected wrong target: {mixed_visible_report!r}")
mixed_visible_mask, mixed_tombstone = mask_paths(
    child_store, mixed_visible_entry, "MIXED_REMAINING"
)
mixed_visible_stash = work_root / "mixed-visible.mask"
mixed_visible_mask.rename(mixed_visible_stash)
mixed_tombstone.unlink()

set_key(parent, "MIXED_REMAINING", "selected-visible")
mixed_selected_report = parse_json(
    expect_ok(
        [bin_path, "--dir", str(child), "mask", "--json", "MIXED_REMAINING"]
    ),
    "mixed selected mask",
)
mixed_selected_entry = mixed_selected_report["target_entry_id"]
mixed_selected_mask, mixed_tombstone = mask_paths(
    child_store, mixed_selected_entry, "MIXED_REMAINING"
)
mixed_hidden_stash.rename(mixed_hidden_mask)
mixed_visible_stash.rename(mixed_visible_mask)
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "unmask",
        "--no-warn-mask",
        "--mask-chain",
        mixed_selected_report["mask_chain_id"],
        "MIXED_REMAINING",
    ]
)
if (
    mixed_selected_mask.exists()
    or not mixed_hidden_mask.exists()
    or not mixed_visible_mask.exists()
    or mixed_tombstone.read_text(encoding="utf-8")
    != (
        "SECDATMASKCOMPAT1\n"
        "version=1\n"
        f"target_entry_id={mixed_visible_entry}\n"
    )
):
    fail("unmask did not retain the visible remaining chain projection")

# The same remaining visible chain restores a missing rollback tombstone rather
# than depending on a before-image that happens to exist.
mixed_hidden_stash = work_root / "mixed-hidden-second.mask"
mixed_visible_stash = work_root / "mixed-visible-second.mask"
mixed_hidden_mask.rename(mixed_hidden_stash)
mixed_visible_mask.rename(mixed_visible_stash)
mixed_tombstone.unlink()
mixed_second_selected_report = parse_json(
    expect_ok(
        [bin_path, "--dir", str(child), "mask", "--json", "MIXED_REMAINING"]
    ),
    "mixed second selected mask",
)
mixed_second_selected_mask, mixed_tombstone = mask_paths(
    child_store,
    mixed_second_selected_report["target_entry_id"],
    "MIXED_REMAINING",
)
mixed_hidden_stash.rename(mixed_hidden_mask)
mixed_visible_stash.rename(mixed_visible_mask)
mixed_tombstone.unlink()
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "unmask",
        "--no-warn-mask",
        "--mask-chain",
        mixed_second_selected_report["mask_chain_id"],
        "MIXED_REMAINING",
    ]
)
if (
    mixed_second_selected_mask.exists()
    or not mixed_tombstone.exists()
    or mixed_tombstone.read_text(encoding="utf-8")
    != (
        "SECDATMASKCOMPAT1\n"
        "version=1\n"
        f"target_entry_id={mixed_visible_entry}\n"
    )
):
    fail("unmask did not recreate a missing visible-chain projection")

# Rebinding an orphan retains the old barrier and extends the same chain.
rebind_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--json",
            "REBIND",
        ]
    ),
    "initial rebind mask",
)
old_rebind_entry = rebind_report["target_entry_id"]
rebind_chain = rebind_report["mask_chain_id"]
(parent_store / "domain-ent" / f"{old_rebind_entry}.dent").unlink()
set_key(parent, "REBIND", "replacement")
new_rebind_entry = entry_for_key(parent_store, "REBIND")
if new_rebind_entry == old_rebind_entry:
    fail("replacement entry unexpectedly reused the orphan identity")
rebind_dry = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--rebind",
            "--dry-run",
            "--json",
            "REBIND",
        ]
    ),
    "rebind dry-run",
)
if (
    rebind_dry.get("mask_chain_id") != rebind_chain
    or rebind_dry.get("target_entry_id") != new_rebind_entry
    or rebind_dry.get("predecessor_entry_id") != old_rebind_entry
):
    fail(f"rebind did not retain the chain/predecessor: {rebind_dry!r}")
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "mask",
        "--rebind",
        "REBIND",
    ]
)
rebind_rows = [
    row
    for row in parse_json(
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
        "rebound mask list",
    )["masks"]
    if row.get("key") == "REBIND"
]
if (
    len(rebind_rows) != 2
    or {row["mask_chain_id"] for row in rebind_rows} != {rebind_chain}
    or {row["state"] for row in rebind_rows} != {"active", "orphaned"}
):
    fail(f"rebind did not preserve an atomic fallback chain: {rebind_rows!r}")
(parent_store / "domain-ent" / f"{new_rebind_entry}.dent").unlink()
set_key(parent, "REBIND", "second replacement")
third_rebind_entry = entry_for_key(parent_store, "REBIND")
second_rebind = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--rebind",
            "--json",
            "REBIND",
        ]
    ),
    "continued rebind",
)
if (
    second_rebind.get("mask_chain_id") != rebind_chain
    or second_rebind.get("target_entry_id") != third_rebind_entry
    or second_rebind.get("predecessor_entry_id") != new_rebind_entry
):
    fail(f"continued rebind did not extend the chain tail: {second_rebind!r}")
expect_ok([bin_path, "--dir", str(child), "unmask", "REBIND"])
for target_entry in (
    old_rebind_entry,
    new_rebind_entry,
    third_rebind_entry,
):
    if (child_store / "masks" / f"{target_entry}.mask").exists():
        fail("name-only unmask did not remove the one-name fallback chain")
if (child_store / "tombstones" / "REBIND.tomb").exists():
    fail("name-only unmask left fallback compatibility state")

# Name-only removal refuses a chain spanning multiple authorized names, while
# explicit chain dry-run exposes every slot and explicit commit removes all.
chain_reports = {}
for key in ("CHAIN_A", "CHAIN_B"):
    chain_reports[key] = parse_json(
        expect_ok(
            [bin_path, "--dir", str(child), "mask", "--json", key]
        ),
        f"{key} mask",
    )
chain_a_id = chain_reports["CHAIN_A"]["mask_chain_id"]
chain_b_path = (
    child_store
    / "masks"
    / f"{chain_reports['CHAIN_B']['target_entry_id']}.mask"
)
chain_b_text = chain_b_path.read_text(encoding="utf-8")
chain_b_path.write_text(
    chain_b_text.replace(
        f"mask_chain_id={chain_reports['CHAIN_B']['mask_chain_id']}",
        f"mask_chain_id={chain_a_id}",
    ),
    encoding="utf-8",
)
chain_b_path.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "unmask", "CHAIN_A"]
)
if (
    rc == 0
    or "mask chain protects multiple key names" not in stderr
    or not chain_b_path.exists()
):
    fail(
        "name-only unmask removed or accepted a multi-name chain: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
explicit_dry = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "unmask",
            "--dry-run",
            "--json",
            "--mask-chain",
            chain_a_id,
            "CHAIN_A",
        ]
    ),
    "explicit chain dry-run",
)
if (
    explicit_dry.get("record_count") != 2
    or {row["key"] for row in explicit_dry["affected_key_slots"]}
    != {"CHAIN_A", "CHAIN_B"}
):
    fail(f"explicit chain dry-run omitted affected names: {explicit_dry!r}")
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "unmask",
        "--mask-chain",
        chain_a_id,
        "CHAIN_A",
    ]
)
for key in ("CHAIN_A", "CHAIN_B"):
    target_entry = chain_reports[key]["target_entry_id"]
    mask_path, tombstone_path = mask_paths(child_store, target_entry, key)
    assert_mask_state(
        mask_path,
        tombstone_path,
        (False, False),
        "explicit multi-name unmask",
    )

# A local override and dormant mask coexist. Warning policy changes only
# stderr, never the plan, persisted removal, or exit status.
for key in ("WARN_DEFAULT", "WARN_QUIET"):
    report = parse_json(
        expect_ok(
            [bin_path, "--dir", str(child), "mask", "--json", key]
        ),
        f"{key} dormant mask",
    )
    rows = [
        row
        for row in parse_json(
            expect_ok(
                [
                    bin_path,
                    "--dir",
                    str(child),
                    "list",
                    "--dormant",
                    "--json",
                ]
            ),
            f"{key} dormant list",
        )["masks"]
        if row.get("key") == key
    ]
    if len(rows) != 1 or rows[0].get("state") != "dormant":
        fail(f"local override did not preserve a dormant mask: {rows!r}")
    if report.get("target_entry_id") != entry_for_key(parent_store, key):
        fail(f"dormant mask selected the wrong inherited entry: {report!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "unmask", "WARN_DEFAULT"]
)
if (
    rc != 0
    or stdout != ""
    or stderr
    != (
        "warning: unmask: WARN_DEFAULT remains local; "
        "removing it later may expose the inherited value\n"
    )
):
    fail(
        "default deferred-exposure warning mismatch: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
quiet_dry = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "unmask",
            "--dry-run",
            "--json",
            "--no-warn-mask",
            "WARN_QUIET",
        ]
    ),
    "quiet unmask dry-run",
)
if (
    quiet_dry.get("mask_warnings_requested") != "off"
    or quiet_dry.get("mask_warnings_effective") is not False
    or quiet_dry.get("resulting_effective_state") != "local"
):
    fail(f"warning suppression changed the plan: {quiet_dry!r}")
expect_ok(
    [
        bin_path,
        "--dir",
        str(child),
        "unmask",
        "--no-warn-mask",
        "WARN_QUIET",
    ]
)
for key in ("WARN_DEFAULT", "WARN_QUIET"):
    rc, stdout, stderr = run(
        [bin_path, "--dir", str(child), "get", "--stdout", key]
    )
    if rc != 0 or stdout not in ("local-default", "local-quiet"):
        fail(f"unmask changed the local override for {key}: {stdout!r}")

# A unique legacy barrier can be rebound explicitly, while an ambiguous
# same-name barrier remains fail-closed. A name-only unmask can remove a
# uniquely bound standalone legacy barrier.
legacy_rebind_tombstone = (
    child_store / "tombstones" / "LEGACY_REBIND.tomb"
)
legacy_rebind_tombstone.write_bytes(b"")
legacy_rebind_tombstone.chmod(0o600)
legacy_rebind_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "mask",
            "--rebind",
            "--json",
            "LEGACY_REBIND",
        ]
    ),
    "legacy rebind",
)
legacy_rebind_entry = entry_for_key(parent_store, "LEGACY_REBIND")
legacy_rebind_mask, _ = mask_paths(
    child_store, legacy_rebind_entry, "LEGACY_REBIND"
)
if (
    legacy_rebind_report.get("operation") != "rebind"
    or legacy_rebind_report.get("target_entry_id") != legacy_rebind_entry
    or not legacy_rebind_mask.exists()
):
    fail(f"legacy barrier was not rebound canonically: {legacy_rebind_report!r}")

legacy_unmask_tombstone = (
    child_store / "tombstones" / "LEGACY_UNMASK.tomb"
)
legacy_unmask_tombstone.write_bytes(b"")
legacy_unmask_tombstone.chmod(0o600)
legacy_unmask_report = parse_json(
    expect_ok(
        [
            bin_path,
            "--dir",
            str(child),
            "unmask",
            "--json",
            "LEGACY_UNMASK",
        ]
    ),
    "bound legacy unmask",
)
if (
    legacy_unmask_report.get("record_count") != 1
    or legacy_unmask_tombstone.exists()
):
    fail(f"bound legacy barrier was not removed: {legacy_unmask_report!r}")

legacy_ambig_tombstone = (
    child_store / "tombstones" / "LEGACY_AMBIG.tomb"
)
legacy_ambig_tombstone.write_bytes(b"")
legacy_ambig_tombstone.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "LEGACY_AMBIG"]
)
if (
    rc == 0
    or stdout != ""
    or "ambiguous legacy mask blocks this write" not in stderr
    or not legacy_ambig_tombstone.exists()
):
    fail(
        "ambiguous legacy barrier did not block implicit binding: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "mask",
        "--rebind",
        "LEGACY_AMBIG",
    ]
)
if (
    rc == 0
    or stdout != ""
    or "mask rebind found no unique inherited v2 target" not in stderr
    or not legacy_ambig_tombstone.exists()
):
    fail(
        "ambiguous legacy rebind did not remain fail-closed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

# Conflicting warning forms are rejected without changing mask state.
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "unmask",
        "--warn-mask",
        "--no-warn-mask",
        "LEGACY_REBIND",
    ]
)
if rc != 2 or stdout != "" or "invalid arguments for unmask" not in stderr:
    fail(
        "conflicting warning controls were not rejected: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

# A structurally valid compatibility marker may not borrow another
# canonical mask's target identity to hide a conflicting name barrier.
legacy_rebind_original = legacy_rebind_tombstone.read_text(encoding="utf-8")
legacy_rebind_tombstone.write_text(
    (
        "SECDATMASKCOMPAT1\n"
        "version=1\n"
        f"target_entry_id={hidden_entry}\n"
    ),
    encoding="utf-8",
)
legacy_rebind_tombstone.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "LEGACY_REBIND"]
)
if (
    rc == 0
    or stdout != ""
    or "compatibility tombstone does not match its canonical mask" not in stderr
):
    fail(
        "repeated mask accepted a cross-name compatibility collision: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"]
)
if (
    rc == 0
    or stdout != ""
    or "compatibility tombstone does not match its canonical mask" not in stderr
):
    fail(
        "cross-name compatibility collision was hidden: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
legacy_rebind_tombstone.write_text(
    legacy_rebind_original,
    encoding="utf-8",
)
legacy_rebind_tombstone.chmod(0o600)

# Embedded NULs cannot turn noncanonical journal strings into accepted C
# strings. Recovery retains the journal fail-closed until its exact bytes are
# restored.
nul_entry = entry_for_key(parent_store, "FAULT_NUL")
nul_mask, nul_tombstone = mask_paths(child_store, nul_entry, "FAULT_NUL")
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "FAULT_NUL"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "embedded-NUL setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
pending = [
    path
    for path in transactions_root.iterdir()
    if path.name != "lock"
]
if len(pending) != 1:
    fail(f"expected one NUL-test transaction: {pending!r}")
nul_journal = pending[0] / "journal"
nul_original = nul_journal.read_text(encoding="utf-8")
nul_journal.write_text(
    nul_original.replace(
        '"command":"mask"',
        '"command":"mask\\u0000suffix"',
    ),
    encoding="utf-8",
)
nul_journal.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc == 0
    or "invalid transaction journal" not in stderr
    or nul_mask.exists()
    or nul_tombstone.exists()
):
    fail(
        "embedded-NUL journal string was accepted: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
nul_journal.write_text(nul_original, encoding="utf-8")
nul_journal.chmod(0o600)
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
assert_mask_state(
    nul_mask,
    nul_tombstone,
    (True, True),
    "embedded-NUL journal restored recovery",
)

# A journal cannot relabel a primary record into the dependency-root phase.
# Recovery rejects role/phase drift before applying any replayable write.
phase_entry = entry_for_key(parent_store, "FAULT_PHASE")
phase_mask, phase_tombstone = mask_paths(child_store, phase_entry, "FAULT_PHASE")
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "FAULT_PHASE"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "phase validation setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
pending = [path for path in transactions_root.iterdir() if path.name != "lock"]
if len(pending) != 1:
    fail(f"expected one phase-test transaction: {pending!r}")
phase_journal = pending[0] / "journal"
phase_original = phase_journal.read_text(encoding="utf-8")
phase_journal.write_text(
    phase_original.replace('"phase":30', '"phase":40', 1),
    encoding="utf-8",
)
phase_journal.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc == 0
    or "invalid transaction journal" not in stderr
    or phase_mask.exists()
    or phase_tombstone.exists()
):
    fail(
        "transaction role/phase drift was accepted: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
phase_journal.write_text(phase_original, encoding="utf-8")
phase_journal.chmod(0o600)
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
assert_mask_state(
    phase_mask,
    phase_tombstone,
    (True, True),
    "role/phase journal restored recovery",
)

# Recovery resolves every target below the trusted state root with
# fd-relative no-symlink traversal. Replacing a target directory after the
# committing journal is durable must not redirect a write outside the store.
for domain in (parent, child):
    expect_ok(
        [bin_path, "--dir", str(domain), "store", "create", "symlink"]
    )
expect_ok(
    [
        bin_path,
        "--dir",
        str(parent),
        "--store",
        "symlink",
        "set",
        "SYMLINK_TARGET",
        "--value",
        "value",
    ]
)
for domain in (parent, child):
    stdout = expect_ok(
        [
            bin_path,
            "--dir",
            str(domain),
            "store",
            "migrate",
            "symlink",
            "--to-format",
            "v2",
        ]
    )
    if "verified=yes\n" not in stdout:
        fail(f"symlink store migration was not verified: {stdout!r}")
parent_symlink_store = parent_store.parent / "symlink"
child_symlink_store = child_store.parent / "symlink"
symlink_entry = entry_for_key(parent_symlink_store, "SYMLINK_TARGET")
symlink_mask = child_symlink_store / "masks" / f"{symlink_entry}.mask"
outside_masks = work_root / "outside-masks"
outside_masks.mkdir()
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "--store",
        "symlink",
        "mask",
        "SYMLINK_TARGET",
    ],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "symlink recovery setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_symlink_store / "masks").rmdir()
(child_symlink_store / "masks").symlink_to(
    outside_masks,
    target_is_directory=True,
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc == 0
    or "invalid transaction target directory" not in stderr
    or any(outside_masks.iterdir())
):
    fail(
        "recovery followed a replaced target directory: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_symlink_store / "masks").unlink()
(child_symlink_store / "masks").mkdir(mode=0o700)
expect_ok([bin_path, "--dir", str(child), "status", "--quiet"])
if not symlink_mask.exists() or any(outside_masks.iterdir()):
    fail("restored recovery did not commit inside the store")

# Recovery validates every target before rolling any target forward. An
# out-of-band change at a later target therefore fails closed without applying
# the earlier canonical-mask target or deleting the journal.
tamper_entry = entry_for_key(parent_store, "FAULT_TAMPER")
tamper_mask, tamper_tombstone = mask_paths(
    child_store, tamper_entry, "FAULT_TAMPER"
)
fault_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"}
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "mask", "FAULT_TAMPER"],
    run_env=fault_env,
)
if rc != 86:
    fail(
        "tamper recovery setup did not stop at committing: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
tamper_tombstone.write_text("tampered\n", encoding="utf-8")
tamper_tombstone.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "status", "--quiet"]
)
if (
    rc == 0
    or "transaction target changed during recovery" not in stderr
    or "failed to recover pending transactions" not in stderr
    or tamper_mask.exists()
    or tamper_tombstone.read_text(encoding="utf-8") != "tampered\n"
    or len([path for path in transactions_root.iterdir() if path.name != "lock"])
    != 1
):
    fail(
        "tampered recovery did not fail closed before all target writes: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

print("ok")
PY
