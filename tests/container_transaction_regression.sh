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
import shutil
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env.update(LC_ALL="C", LANGUAGE="C", SECDAT_MASTER_KEY="container-master-key")
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
    if result.returncode != 0 or result.stderr or result.stdout != stdout:
        fail(
            f"{label}: rc={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


def pending_transactions():
    root = state_root / "transactions"
    return sorted(path for path in root.iterdir() if path.name != "lock")


def registry_files():
    root = state_root / "domains/registry/by-root"
    return [] if not root.exists() else sorted(path for path in root.iterdir())


def journal_manifest(path):
    lines = (path / "journal").read_text(encoding="utf-8").splitlines()
    if len(lines) != 2 or lines[0] != "SECDATTXN1":
        fail(f"invalid transaction envelope: {lines!r}")
    return json.loads(lines[1])


root = work_root / "prepared-root"
root.mkdir()
prepared = run(
    "--dir", str(root), "domain", "create",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if prepared.returncode != 86:
    fail(f"domain create did not stop at PREPARED: {prepared}")
pending = pending_transactions()
if len(pending) != 1 or registry_files():
    fail(f"PREPARED create was published: pending={pending!r}")
manifest = journal_manifest(pending[0])
writes = manifest.get("writes", [])
role_phases = {(item.get("role"), item.get("phase")) for item in writes}
if (
    manifest.get("version") != 2
    or manifest.get("command") != "domain-create"
    or manifest.get("state") != "prepared"
    or ("reference-epoch", 10) not in role_phases
    or ("container-publish", 50) not in role_phases
    or ("registry-publish", 60) not in role_phases
    or not any(item.get("kind") == "container-tree" for item in writes)
    or len(list(pending[0].glob("tree.after.*"))) != 1
):
    fail(f"domain create ordering/artifact mismatch: {manifest!r}")
require_ok(run("--dir", str(root), "status", "--quiet"), "PREPARED cleanup")
if pending_transactions() or registry_files():
    fail("PREPARED cleanup published or retained the container")

committing = run(
    "--dir", str(root), "domain", "create",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if committing.returncode != 86:
    fail(f"domain create did not stop at COMMITTING: {committing}")
require_ok(run("--dir", str(root), "status", "--quiet"), "COMMITTING roll-forward")
if len(registry_files()) != 1 or pending_transactions():
    fail("COMMITTING create did not roll forward exactly once")
domain_id = registry_files()[0].read_text(encoding="utf-8")
domain_data = state_root / "domains/by-id" / domain_id
if not domain_data.is_dir():
    fail("rolled-forward domain container is absent")

require_ok(run("--dir", str(root), "store", "create", "app"), "store create")
epoch_path = state_root / "gc/reference-epoch"
epoch_before = epoch_path.read_bytes()
unknown = domain_data / "stores/app/unknown"
unknown.write_text("unexpected", encoding="utf-8")
unknown.chmod(0o600)
blocked_store = run("--dir", str(root), "store", "delete", "app")
if (
    blocked_store.returncode == 0
    or "store is not empty: app" not in blocked_store.stderr
    or epoch_path.read_bytes() != epoch_before
    or not unknown.exists()
):
    fail(f"unknown store artifact was not rejected before mutation: {blocked_store}")
unknown.unlink()
require_ok(run("--dir", str(root), "store", "delete", "app"), "store delete")

# Canonical escaped store names remain usable, while noncanonical aliases fail
# closed before listing or deletion can reinterpret them as another store.
require_ok(
    run("--dir", str(root), "store", "create", "ops/team"),
    "escaped store create",
)
require_ok(
    run("--dir", str(root), "store", "ls"),
    "escaped store list",
    "default\nops/team\n",
)
require_ok(
    run("--dir", str(root), "store", "delete", "ops/team"),
    "escaped store delete",
)
noncanonical_store = domain_data / "stores/%41pp"
shutil.copytree(domain_data / "stores/default", noncanonical_store)
noncanonical_store_list = run("--dir", str(root), "store", "ls")
if (
    noncanonical_store_list.returncode == 0
    or "invalid path: %41pp" not in noncanonical_store_list.stderr
    or noncanonical_store_list.stdout
    or not noncanonical_store.is_dir()
):
    fail(f"noncanonical store alias was accepted: {noncanonical_store_list}")
noncanonical_store_delete = run("--dir", str(root), "domain", "delete")
if (
    noncanonical_store_delete.returncode == 0
    or "domain is not empty:" not in noncanonical_store_delete.stderr
    or not noncanonical_store.is_dir()
    or not domain_data.is_dir()
    or len(registry_files()) != 1
):
    fail(
        "noncanonical store alias was deleted or treated as empty: "
        f"{noncanonical_store_delete}"
    )
shutil.rmtree(noncanonical_store)

# Registry aliases must not be decoded to a canonical root and then left
# behind after the canonical registration is removed.
canonical_registry = registry_files()[0]
noncanonical_registry_name = canonical_registry.name.replace("%2F", "%2f", 1)
if noncanonical_registry_name == canonical_registry.name:
    fail(f"registry path did not contain a canonical escape: {canonical_registry}")
noncanonical_registry = canonical_registry.with_name(noncanonical_registry_name)
noncanonical_registry.write_bytes(canonical_registry.read_bytes())
noncanonical_registry.chmod(0o600)
noncanonical_domain_list = run("--dir", str(root), "domain", "ls", "--json")
if (
    noncanonical_domain_list.returncode == 0
    or f"invalid path: {noncanonical_registry_name}" not in noncanonical_domain_list.stderr
    or not noncanonical_registry.is_file()
):
    fail(f"noncanonical registry alias was accepted: {noncanonical_domain_list}")
noncanonical_registry_delete = run("--dir", str(root), "domain", "delete")
if (
    noncanonical_registry_delete.returncode == 0
    or f"invalid path: {noncanonical_registry_name}" not in noncanonical_registry_delete.stderr
    or not domain_data.is_dir()
    or len(registry_files()) != 2
):
    fail(
        "noncanonical registry alias was orphaned by deletion: "
        f"{noncanonical_registry_delete}"
    )
noncanonical_registry.unlink()

# Persisted v1 key components also require exact canonical bytes. A redundant
# escape must neither produce a phantom key nor be removed as a canonical key.
require_ok(run("--dir", str(root), "set", "AB", "--value", "alias"), "key alias seed")
canonical_entry = domain_data / "stores/default/entries/AB.sec"
noncanonical_entry = canonical_entry.with_name("%41B.sec")
canonical_entry.rename(noncanonical_entry)
noncanonical_key_list = run("--dir", str(root), "ls")
if (
    noncanonical_key_list.returncode == 0
    or "invalid path: %41B.sec" not in noncanonical_key_list.stderr
    or noncanonical_key_list.stdout
    or not noncanonical_entry.is_file()
):
    fail(f"noncanonical key alias was accepted: {noncanonical_key_list}")
canonical_entry_get = run("--dir", str(root), "get", "AB")
if canonical_entry_get.returncode == 0 or not noncanonical_entry.is_file():
    fail(f"canonical key lookup consumed its alias: {canonical_entry_get}")
noncanonical_entry.rename(canonical_entry)
require_ok(run("--dir", str(root), "rm", "AB"), "key alias cleanup")

epoch_before = epoch_path.read_bytes()
unknown = domain_data / "unknown"
unknown.write_text("unexpected", encoding="utf-8")
unknown.chmod(0o600)
blocked_domain = run("--dir", str(root), "domain", "delete")
if (
    blocked_domain.returncode == 0
    or "domain is not empty:" not in blocked_domain.stderr
    or epoch_path.read_bytes() != epoch_before
    or len(registry_files()) != 1
):
    fail(f"unknown domain artifact was not rejected before mutation: {blocked_domain}")
unknown.unlink()

prepared_delete = run(
    "--dir", str(root), "domain", "delete",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if prepared_delete.returncode != 86:
    fail(f"domain delete did not stop at PREPARED: {prepared_delete}")
pending = pending_transactions()
manifest = journal_manifest(pending[0])
role_phases = {
    (item.get("role"), item.get("phase"))
    for item in manifest.get("writes", [])
}
if (
    ("reference-epoch", 10) not in role_phases
    or ("registry-removal", 50) not in role_phases
    or ("container-removal", 60) not in role_phases
    or list(pending[0].glob("tree.before.*"))
    or not domain_data.is_dir()
    or len(registry_files()) != 1
):
    fail(f"PREPARED delete changed live state: {manifest!r}")
require_ok(run("--dir", str(root), "status", "--quiet"), "PREPARED delete cleanup")
if not domain_data.is_dir() or len(registry_files()) != 1:
    fail("PREPARED delete cleanup did not preserve live state")

committing_delete = run(
    "--dir", str(root), "domain", "delete",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if committing_delete.returncode != 86:
    fail(f"domain delete did not stop at COMMITTING: {committing_delete}")
require_ok(run("--dir", str(root), "status", "--quiet"), "delete roll-forward")
if domain_data.exists() or registry_files() or pending_transactions():
    fail("COMMITTING delete did not roll forward and clean the journal tree")

print("PASS container transaction regression")
PY
