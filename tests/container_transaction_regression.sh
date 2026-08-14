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
