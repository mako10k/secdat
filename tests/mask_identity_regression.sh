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
import hashlib
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
    "SECDAT_MASTER_KEY": "mask-identity-regression-master-key",
}

root = work_root / "root"
parent = root / "parent"
child = parent / "child"
outside = work_root / "outside"
for domain in (root, parent, child, outside):
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


def create_domain(domain):
    before = set(Path(env["XDG_DATA_HOME"]).rglob("entries"))
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
    if rc != 0 or stdout != "" or stderr != "":
        fail(
            f"domain create failed for {domain}: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    after = set(Path(env["XDG_DATA_HOME"]).rglob("entries"))
    created = after - before
    if len(created) != 1:
        fail(f"expected one new entries directory for {domain}, found {created!r}")
    store_root = created.pop().parent
    domain_id = store_root.parents[1].name
    (store_root / "domain-ent").mkdir(parents=True)
    (store_root / "objects" / "secret").mkdir(parents=True)
    (store_root / "masks").mkdir(parents=True)
    (store_root / "masks").chmod(0o700)
    (store_root / "format").write_text(
        "SECDATSTORE1\nformat=v2\nstate=ready\n",
        encoding="utf-8",
    )
    return domain_id, store_root


def write_entry(store_root, entry_id, secret_id, key, visibility="always"):
    fields = [
        "SECDATDENT1",
        f"entry_id={entry_id}",
        f"secret_id={secret_id}",
        f"key_visibility={visibility}",
    ]
    if visibility == "always":
        fields.append(f"key={key}")
    else:
        fields.append(f"encrypted_key={'00' * 32}")
    fields.append("bulk_select_entry=named")
    (store_root / "domain-ent" / f"{entry_id}.dent").write_text(
        "\n".join(fields) + "\n",
        encoding="utf-8",
    )
    (store_root / "objects" / "secret" / f"{secret_id}.sec").write_text(
        "\n".join(
            [
                "SECDATSECOBJ1",
                f"secret_id={secret_id}",
                "value_access=unlocked",
                "bulk_select_value=include",
                "refcount=1",
                "",
            ]
        ),
        encoding="utf-8",
    )


def write_mask(
    store_root,
    chain_id,
    target_entry_id,
    target_secret_id,
    target_domain_id,
    key,
    visibility="always",
):
    fields = [
        "SECDATMASK1",
        "version=1",
        f"mask_chain_id={chain_id}",
        f"target_entry_id={target_entry_id}",
        f"target_secret_id={target_secret_id}",
        f"last_known_target_domain={target_domain_id}",
        "last_known_target_store=default",
        f"key_visibility={visibility}",
    ]
    if visibility == "always":
        fields.append(f"last_known_key={key}")
    else:
        fields.extend(
            [
                "key_encryption=aes-256-gcm-mask-name-v1",
                f"encrypted_last_known_key={'00' * 28}",
            ]
        )
    path = store_root / "masks" / f"{target_entry_id}.mask"
    path.write_text(
        "\n".join(fields) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


root_id, root_store = create_domain(root)
parent_id, parent_store = create_domain(parent)
child_id, child_store = create_domain(child)
outside_id, outside_store = create_domain(outside)

active_entry = "11111111-1111-4111-8111-111111111111"
active_secret = "21111111-1111-4111-8111-111111111111"
dormant_entry = "12222222-2222-4222-8222-222222222222"
dormant_secret = "22222222-2222-4222-8222-222222222222"
dormant_local_entry = "13333333-3333-4333-8333-333333333333"
dormant_local_secret = "23333333-3333-4333-8333-333333333333"
alias_entry = "14444444-4444-4444-8444-444444444444"
legacy_one_entry = "15555555-5555-4555-8555-555555555555"
legacy_one_secret = "25555555-5555-4555-8555-555555555555"
legacy_multi_parent_entry = "16666666-6666-4666-8666-666666666666"
legacy_multi_parent_secret = "26666666-6666-4666-8666-666666666666"
legacy_multi_root_entry = "17777777-7777-4777-8777-777777777777"
legacy_multi_root_secret = "27777777-7777-4777-8777-777777777777"
legacy_local_missing_entry = "1eeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
legacy_local_missing_secret = "2eeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
legacy_blocked_entry = "1fffffff-ffff-4fff-8fff-ffffffffffff"
legacy_blocked_secret = "2fffffff-ffff-4fff-8fff-ffffffffffff"
local_safe_entry = "1abababa-baba-4aba-8aba-abababababab"
local_safe_secret = "2abababa-baba-4aba-8aba-abababababab"
orphan_entry = "18888888-8888-4888-8888-888888888888"
orphan_secret = "28888888-8888-4888-8888-888888888888"
outside_entry = "1bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
outside_secret = "2bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

write_entry(parent_store, active_entry, active_secret, "ACTIVE")
write_entry(parent_store, alias_entry, active_secret, "ACTIVE_ALIAS")
write_entry(parent_store, dormant_entry, dormant_secret, "DORMANT")
write_entry(child_store, dormant_local_entry, dormant_local_secret, "DORMANT")
write_entry(parent_store, legacy_one_entry, legacy_one_secret, "LEGACY_ONE")
write_entry(
    parent_store,
    legacy_multi_parent_entry,
    legacy_multi_parent_secret,
    "LEGACY_MULTI",
)
write_entry(
    root_store,
    legacy_multi_root_entry,
    legacy_multi_root_secret,
    "LEGACY_MULTI",
)
write_entry(
    child_store,
    legacy_local_missing_entry,
    legacy_local_missing_secret,
    "LEGACY_LOCAL_MISSING",
)
write_entry(
    root_store,
    legacy_blocked_entry,
    legacy_blocked_secret,
    "LEGACY_BLOCKED",
)
write_entry(child_store, local_safe_entry, local_safe_secret, "LOCAL_SAFE")
write_entry(outside_store, outside_entry, outside_secret, "OUT_OF_SCOPE")

write_mask(
    child_store,
    "31111111-1111-4111-8111-111111111111",
    active_entry,
    active_secret,
    parent_id,
    "ACTIVE",
)
write_mask(
    child_store,
    "32222222-2222-4222-8222-222222222222",
    dormant_entry,
    dormant_secret,
    parent_id,
    "DORMANT",
)
write_mask(
    child_store,
    "33333333-3333-4333-8333-333333333333",
    orphan_entry,
    orphan_secret,
    parent_id,
    "ORPHAN",
)
write_mask(
    child_store,
    "3bbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    outside_entry,
    outside_secret,
    outside_id,
    "OUT_OF_SCOPE",
)

tombstones = child_store / "tombstones"
tombstones.mkdir(parents=True, exist_ok=True)
for key in (
    "LEGACY_ONE",
    "LEGACY_MULTI",
    "LEGACY_MISSING",
    "LEGACY_LOCAL_MISSING",
    "LEGACY_BLOCKED",
):
    (tombstones / f"{key}.tomb").write_bytes(b"")
parent_tombstones = parent_store / "tombstones"
parent_tombstones.mkdir(parents=True, exist_ok=True)
(parent_tombstones / "LEGACY_BLOCKED.tomb").write_bytes(b"")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"]
)
if rc != 0 or stderr != "":
    fail(
        "mask JSON inspection failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
try:
    report = json.loads(stdout)
except json.JSONDecodeError as error:
    fail(f"mask JSON is invalid: {error}: {stdout!r}")
if report.get("schema_version") != "secdat.mask-list.v2":
    fail(f"unexpected mask JSON schema: {report!r}")
if report.get("domain_id") != child_id or report.get("store") != "default":
    fail(f"unexpected mask JSON scope: {report!r}")
if (
    report.get("mask_count") != 9
    or report.get("visible_mask_count") != 9
    or report.get("redacted_mask_count") != 0
    or report.get("visible_state_unknown_count") != 0
    or report.get("redacted_state_unknown_count") != 0
    or report.get("state_unknown_count") != 0
    or report.get("state_filter_complete") is not True
):
    fail(f"unexpected mask counts: {report!r}")

rows = {row["key"]: row for row in report["masks"]}
expected_keys = {
    "ACTIVE",
    "DORMANT",
    "ORPHAN",
    "LEGACY_ONE",
    "LEGACY_MULTI",
    "LEGACY_MISSING",
    "LEGACY_LOCAL_MISSING",
    "LEGACY_BLOCKED",
    "OUT_OF_SCOPE",
}
if set(rows) != expected_keys:
    fail(f"unexpected mask keys: {rows!r}")
expected = {
    "ACTIVE": ("active", "canonical", "bound"),
    "DORMANT": ("dormant", "canonical", "bound"),
    "ORPHAN": ("orphaned", "canonical", "bound"),
    "LEGACY_ONE": ("active", "legacy", "bound"),
    "LEGACY_MULTI": ("active", "legacy", "ambiguous"),
    "LEGACY_MISSING": ("orphaned", "legacy", "ambiguous"),
    "LEGACY_LOCAL_MISSING": ("orphaned", "legacy", "ambiguous"),
    "LEGACY_BLOCKED": ("dormant", "legacy", "bound"),
    "OUT_OF_SCOPE": ("orphaned", "canonical", "bound"),
}
for key, classification in expected.items():
    row = rows[key]
    actual = (row["state"], row["record_kind"], row["resolution"])
    if actual != classification:
        fail(f"unexpected classification for {key}: {row!r}")
    if row.get("state_complete") is not True:
        fail(f"unlocked mask state must be complete for {key}: {row!r}")
if rows["ACTIVE"]["target_entry_id"] != active_entry:
    fail(f"canonical target identity was not exposed: {rows['ACTIVE']!r}")
if rows["LEGACY_ONE"]["target_entry_id"] != legacy_one_entry:
    fail(f"unique legacy target was not bound: {rows['LEGACY_ONE']!r}")
if rows["LEGACY_MULTI"]["target_entry_id"] is not None:
    fail(f"ambiguous legacy target must not be guessed: {rows['LEGACY_MULTI']!r}")
if "ACTIVE_ALIAS" in rows:
    fail(f"entry alias must not become a separate mask: {rows!r}")
if rows["ORPHAN"]["orphan_reason"] != "missing-entry":
    fail(f"canonical orphan reason missing: {rows['ORPHAN']!r}")
if rows["OUT_OF_SCOPE"]["orphan_reason"] != "out-of-scope":
    fail(f"canonical out-of-scope reason missing: {rows['OUT_OF_SCOPE']!r}")
if (
    rows["ORPHAN"]["target_secret_id"] is not None
    or rows["OUT_OF_SCOPE"]["target_secret_id"] is not None
):
    fail(f"unreachable target secret identity must not be exposed: {rows!r}")

state_filters = {
    "--masked": {"ACTIVE", "LEGACY_ONE", "LEGACY_MULTI"},
    "--dormant": {"DORMANT", "LEGACY_BLOCKED"},
    "--orphaned": {
        "ORPHAN",
        "OUT_OF_SCOPE",
        "LEGACY_MISSING",
        "LEGACY_LOCAL_MISSING",
    },
}
for state_filter, expected_state_keys in state_filters.items():
    rc, stdout, stderr = run(
        [
            bin_path,
            "--dir",
            str(child),
            "list",
            state_filter,
            "--json",
        ]
    )
    if rc != 0 or stderr != "":
        fail(
            f"mask state filter {state_filter} failed: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    state_report = json.loads(stdout)
    actual_state_keys = {row["key"] for row in state_report["masks"]}
    if actual_state_keys != expected_state_keys:
        fail(
            f"mask state filter {state_filter} mismatch: "
            f"{actual_state_keys!r}"
        )
    if (
        state_report["mask_count"] != len(expected_state_keys)
        or state_report["visible_mask_count"] != len(expected_state_keys)
        or state_report["redacted_mask_count"] != 0
        or state_report["visible_state_unknown_count"] != 0
        or state_report["redacted_state_unknown_count"] != 0
        or state_report["state_unknown_count"] != 0
        or state_report["state_filter_complete"] is not True
    ):
        fail(f"mask state filter counts mismatch: {state_report!r}")

rc, stdout, stderr = run(
    [
        bin_path,
        "--dir",
        str(child),
        "list",
        "--masked",
        "--dormant",
        "--long",
    ]
)
if rc != 0 or stderr != "":
    fail(
        "combined mask long inspection failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
long_rows = stdout.splitlines()
if len(long_rows) != 5:
    fail(f"combined mask long row count mismatch: {long_rows!r}")
for expected_fragment in (
    f"ACTIVE\tdomain_id={child_id}\tstore=default\tstate=active\tstate_complete=yes\tstate_candidates=-\trecord_kind=canonical\tresolution=bound",
    f"DORMANT\tdomain_id={child_id}\tstore=default\tstate=dormant\tstate_complete=yes\tstate_candidates=-\trecord_kind=canonical\tresolution=bound",
    f"LEGACY_MULTI\tdomain_id={child_id}\tstore=default\tstate=active\tstate_complete=yes\tstate_candidates=-\trecord_kind=legacy\tresolution=ambiguous",
):
    if not any(row.startswith(expected_fragment) for row in long_rows):
        fail(f"combined mask long output missing {expected_fragment!r}: {long_rows!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child), "list", "--all-masks"])
if rc != 0 or stderr != "":
    fail(
        "mask text inspection failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
if stdout.splitlines() != sorted(expected_keys):
    fail(f"mask text output was not stable and sorted: {stdout!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--dormant", "--safe"]
)
if (
    rc != 0
    or stderr != ""
    or stdout.splitlines()
    != ["DORMANT", "LEGACY_BLOCKED", "LEGACY_LOCAL_MISSING", "LOCAL_SAFE"]
):
    fail(
        "mixed mask/local list filters must return a deduplicated union: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--safe"]
)
if (
    rc != 0
    or stderr != ""
    or stdout.splitlines() != sorted(expected_keys | {"LOCAL_SAFE"})
):
    fail(
        "--all-masks must be equivalent to all three short state filters: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

rc, stdout, stderr = run([bin_path, "--dir", str(child), "list", "--json"])
if rc != 2 or stdout != "" or "invalid arguments for list\n" not in stderr:
    fail(
        "list --json without --all-masks must be rejected: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--long", "--json"]
)
if rc != 2 or stdout != "" or "invalid arguments for list\n" not in stderr:
    fail(
        "list --long and --json together must be rejected: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

hidden_entry = "19999999-9999-4999-8999-999999999999"
hidden_secret = "29999999-9999-4999-8999-999999999999"
write_entry(
    parent_store,
    hidden_entry,
    hidden_secret,
    "LOCKED_HIDDEN_NAME",
    visibility="unlocked",
)
write_mask(
    child_store,
    "39999999-9999-4999-8999-999999999999",
    hidden_entry,
    hidden_secret,
    parent_id,
    "LOCKED_HIDDEN_NAME",
    visibility="unlocked",
)
locked_env = env.copy()
locked_env.pop("SECDAT_MASTER_KEY", None)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"],
    run_env=locked_env,
)
if rc != 0 or stderr != "":
    fail(
        "locked hidden mask inspection failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
locked_report = json.loads(stdout)
if (
    locked_report["mask_count"] != 10
    or locked_report["visible_mask_count"] != 9
    or locked_report["redacted_mask_count"] != 1
    or locked_report["visible_state_unknown_count"] != 3
    or locked_report["redacted_state_unknown_count"] != 1
    or locked_report["state_unknown_count"] != 4
    or locked_report["state_filter_complete"] is not False
    or "LOCKED_HIDDEN_NAME" in stdout
):
    fail(f"locked hidden mask leaked or was not counted: {locked_report!r}")
locked_rows = {row["key"]: row for row in locked_report["masks"]}
if (
    locked_rows["LEGACY_MISSING"].get("state") is not None
    or locked_rows["LEGACY_MISSING"].get("state_complete") is not False
    or locked_rows["LEGACY_MISSING"].get("state_candidates")
    != ["active", "dormant", "orphaned"]
):
    fail(f"locked legacy uncertainty was not exposed: {locked_rows!r}")
if locked_rows["LEGACY_ONE"].get("state_complete") is not True:
    fail(f"visible inherited target must keep a complete state: {locked_rows!r}")
if locked_rows["LEGACY_BLOCKED"].get("state_candidates") != ["active", "dormant"]:
    fail(f"locked parent barrier candidates were not narrowed: {locked_rows!r}")
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--long"],
    run_env=locked_env,
)
locked_long_rows = {
    line.split("\t", 1)[0]: line
    for line in stdout.splitlines()
    if "\t" in line
}
if (
    rc != 0
    or stderr
    != (
        "1 hidden mask(s) omitted; unlock the affected domains or use --json for counts\n"
        "4 mask state(s) are incomplete while ancestor key names are locked; "
        "unlock the affected domains or use --json for counts\n"
    )
    or "LEGACY_MISSING" not in locked_long_rows
    or "\tstate=unknown\tstate_complete=no\tstate_candidates=active,dormant,orphaned\t"
    not in locked_long_rows.get("LEGACY_MISSING", "")
    or "LEGACY_BLOCKED" not in locked_long_rows
    or "\tstate=unknown\tstate_complete=no\tstate_candidates=active,dormant\t"
    not in locked_long_rows.get("LEGACY_BLOCKED", "")
    or "LOCKED_HIDDEN_NAME" in stdout
    or hidden_entry in stdout
    or hidden_secret in stdout
):
    fail(
        "locked long inspection must expose uncertainty without hidden identity: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
locked_filter_expectations = {
    "--masked": (
        {"ACTIVE", "LEGACY_ONE", "LEGACY_MULTI", "LEGACY_MISSING", "LEGACY_BLOCKED"},
        1,
        3,
    ),
    "--dormant": (
        {"DORMANT", "LEGACY_BLOCKED", "LEGACY_MISSING", "LEGACY_LOCAL_MISSING"},
        1,
        4,
    ),
    "--orphaned": (
        {"ORPHAN", "OUT_OF_SCOPE", "LEGACY_MISSING", "LEGACY_LOCAL_MISSING"},
        0,
        2,
    ),
}
for state_filter, (
    expected_locked_keys,
    expected_redacted_count,
    expected_unknown_count,
) in locked_filter_expectations.items():
    rc, stdout, stderr = run(
        [bin_path, "--dir", str(child), "list", state_filter, "--json"],
        run_env=locked_env,
    )
    if rc != 0 or stderr != "":
        fail(
            f"locked state filter {state_filter} failed: "
            f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
        )
    filtered_report = json.loads(stdout)
    filtered_keys = {row["key"] for row in filtered_report["masks"]}
    if (
        filtered_keys != expected_locked_keys
        or filtered_report["redacted_mask_count"] != expected_redacted_count
        or filtered_report["state_unknown_count"] != expected_unknown_count
        or filtered_report["state_filter_complete"] is not False
    ):
        fail(
            f"locked state filter {state_filter} did not honor candidates: "
            f"{filtered_report!r}"
        )

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--orphaned", "--json"],
    run_env=locked_env,
)
if rc != 0 or stderr != "":
    fail(
        "locked orphan filter failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
locked_orphan_report = json.loads(stdout)
if (
    locked_orphan_report["mask_count"] != 4
    or locked_orphan_report["visible_mask_count"] != 4
    or locked_orphan_report["redacted_mask_count"] != 0
    or locked_orphan_report["visible_state_unknown_count"] != 2
    or locked_orphan_report["redacted_state_unknown_count"] != 0
    or locked_orphan_report["state_unknown_count"] != 2
    or locked_orphan_report["state_filter_complete"] is not False
):
    fail(f"locked reachable mask must not inflate orphan count: {locked_orphan_report!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks"],
    run_env=locked_env,
)
if (
    rc != 0
    or "LOCKED_HIDDEN_NAME" in stdout
    or stderr
    != (
        "1 hidden mask(s) omitted; unlock the affected domains or use --json for counts\n"
        "4 mask state(s) are incomplete while ancestor key names are locked; "
        "unlock the affected domains or use --json for counts\n"
    )
):
    fail(
        "locked hidden text inspection must warn about omitted rows: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--orphaned"],
    run_env=locked_env,
)
if (
    rc != 1
    or stderr != ""
    or "incomplete-mask-state\tLEGACY_MISSING\tlocked-ancestor\n" not in stdout
    or "incomplete-mask-state\tLEGACY_BLOCKED\tlocked-ancestor\n" in stdout
    or "LOCKED_HIDDEN_NAME" in stdout
    or hidden_entry in stdout
    or hidden_secret in stdout
):
    fail(
        "locked fsck must report incomplete legacy state without leaking hidden identity: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_store / "masks" / f"{hidden_entry}.mask").unlink()
(parent_store / "domain-ent" / f"{hidden_entry}.dent").unlink()
(parent_store / "objects" / "secret" / f"{hidden_secret}.sec").unlink()

hidden_orphan_entry = "1ccccccc-cccc-4ccc-8ccc-cccccccccccc"
hidden_orphan_secret = "2ccccccc-cccc-4ccc-8ccc-cccccccccccc"
write_mask(
    child_store,
    "3ccccccc-cccc-4ccc-8ccc-cccccccccccc",
    hidden_orphan_entry,
    hidden_orphan_secret,
    parent_id,
    "PARTIALLY_UNLOCKED_HIDDEN_ORPHAN",
    visibility="unlocked",
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "unlock", "--volatile"]
)
if rc != 0:
    fail(
        "child-only unlock for hidden orphan regression failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"],
    run_env=locked_env,
)
if rc != 0 or stderr != "":
    fail(
        "partially unlocked hidden orphan inspection failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
partial_report = json.loads(stdout)
if (
    partial_report["mask_count"] != 10
    or partial_report["visible_mask_count"] != 9
    or partial_report["redacted_mask_count"] != 1
    or partial_report["visible_state_unknown_count"] != 0
    or partial_report["redacted_state_unknown_count"] != 0
    or partial_report["state_unknown_count"] != 0
    or partial_report["state_filter_complete"] is not True
    or "PARTIALLY_UNLOCKED_HIDDEN_ORPHAN" in stdout
    or hidden_orphan_entry in stdout
    or hidden_orphan_secret in stdout
):
    fail(f"partially unlocked hidden orphan leaked identity: {partial_report!r}")
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--orphaned"],
    run_env=locked_env,
)
if (
    rc != 1
    or stderr != ""
    or "orphaned-mask\t<redacted>\tmissing-entry\n" not in stdout
    or "PARTIALLY_UNLOCKED_HIDDEN_ORPHAN" in stdout
    or hidden_orphan_entry in stdout
    or hidden_orphan_secret in stdout
):
    fail(
        "locked fsck must report a hidden orphan without leaking identity: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_store / "masks" / f"{hidden_orphan_entry}.mask").unlink()

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--orphaned"]
)
if rc != 1 or stderr != "":
    fail(
        "v2 fsck orphaned mask classification failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
for expected_row in (
    "orphaned-mask\tORPHAN\tmissing-entry\n",
    "orphaned-mask\tOUT_OF_SCOPE\tout-of-scope\n",
    "orphaned-mask\tLEGACY_MISSING\tmissing-entry\n",
):
    if expected_row not in stdout:
        fail(f"v2 fsck missing mask classification {expected_row!r}: {stdout!r}")
if "DORMANT" in stdout:
    fail(f"canonical dormant mask must not be an fsck error: {stdout!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--dangling"]
)
if (
    rc != 1
    or stderr != ""
    or "ambiguous-mask\tLEGACY_MULTI\tunresolved-target\n" not in stdout
    or "DORMANT" in stdout
):
    fail(
        "v2 fsck legacy ambiguity classification failed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

invalid_target_secret = "2ddddddd-dddd-4ddd-8ddd-dddddddddddd"
write_mask(
    child_store,
    "3ddddddd-dddd-4ddd-8ddd-dddddddddddd",
    legacy_one_entry,
    invalid_target_secret,
    parent_id,
    "LEGACY_ONE",
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--dangling"]
)
invalid_target_handle = (
    "record-sha256:"
    + hashlib.sha256(legacy_one_entry.encode("utf-8")).hexdigest()[:16]
)
if (
    rc != 1
    or stderr != ""
    or f"dangling-mask\t{invalid_target_handle}\tinvalid-target\n" not in stdout
    or legacy_one_entry in stdout
    or invalid_target_secret in stdout
    or "LEGACY_ONE" in stdout
):
    fail(
        "v2 fsck must classify target-inconsistent canonical masks without leakage: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_store / "masks" / f"{legacy_one_entry}.mask").unlink()

invalid_domain_entry = "1ddddddd-dddd-4ddd-8ddd-dddddddddddd"
write_mask(
    child_store,
    "3ddddddd-dddd-4ddd-8ddd-dddddddddddd",
    invalid_domain_entry,
    "2ddddddd-dddd-4ddd-8ddd-dddddddddddd",
    "garbage",
    "INVALID_DOMAIN",
)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"]
)
if (
    rc != 1
    or stdout != ""
    or (
        "invalid v2 mask record: <redacted>; "
        "run fsck --format v2 --dangling for a diagnostic handle\n"
    )
    not in stderr
):
    fail(
        "malformed canonical target domain must fail before path lookup: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
(child_store / "masks" / f"{invalid_domain_entry}.mask").unlink()

malformed_entry = "1aaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
malformed_path = child_store / "masks" / f"{malformed_entry}.mask"
malformed_path.write_text(
    "SECDATMASK1\nversion=1\n",
    encoding="utf-8",
)
malformed_path.chmod(0o600)
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "list", "--all-masks", "--json"]
)
if (
    rc != 1
    or stdout != ""
    or (
        "invalid v2 mask record: <redacted>; "
        "run fsck --format v2 --dangling for a diagnostic handle\n"
    )
    not in stderr
):
    fail(
        "malformed canonical mask must fail closed: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )
rc, stdout, stderr = run(
    [bin_path, "--dir", str(child), "fsck", "--format", "v2", "--dangling"]
)
malformed_handle = (
    "record-sha256:"
    + hashlib.sha256(malformed_entry.encode("utf-8")).hexdigest()[:16]
)
if (
    rc != 1
    or stderr != ""
    or f"dangling-mask\t{malformed_handle}\tinvalid-record\n" not in stdout
    or malformed_entry in stdout
):
    fail(
        "v2 fsck must classify malformed canonical masks: "
        f"rc={rc} stdout={stdout!r} stderr={stderr!r}"
    )

print("mask identity regression tests passed")
PY
