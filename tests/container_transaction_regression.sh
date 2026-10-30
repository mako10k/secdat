#!/usr/bin/env bash
# R: Verify container publication, legacy journal recovery and deletion boundaries.

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


def record_legacy_v1_container(journal_dir):
    """Replace a paused create with a valid pre-default v1 staged artifact.

    The recorded inventory, digest and staged tree are explicit fixture data;
    recovery must consume that record rather than today's creation template.
    No older checkout, binary or production format-selection switch is used.
    """
    manifest = journal_manifest(journal_dir)
    containers = [
        (index, item) for index, item in enumerate(manifest["writes"])
        if item.get("kind") == "container-tree"
    ]
    if len(containers) != 1 or manifest["state"] != "committing":
        fail(f"invalid paused legacy container fixture: {manifest!r}")
    write_index, target = containers[0]
    target_index = len(manifest["guards"]) + write_index
    staged = journal_dir / f"tree.after.{target_index:04d}"
    if target["name"] == "empty-domain-v1":
        legacy_store = staged / "stores" / "default"
    elif target["name"] == "empty-store-v2":
        target["name"] = "empty-store-v1"
        legacy_store = staged
    else:
        fail(f"unexpected current container schema: {target!r}")
    shutil.rmtree(legacy_store)
    legacy_store.mkdir(mode=0o700)
    for name in ("entries", "tombstones"):
        (legacy_store / name).mkdir(mode=0o700)
    inventory = [f"SECDATCONTAINERTREE1\nschema={target['name']}\n"]
    items = [(".", staged), *[(path.relative_to(staged).as_posix(), path) for path in staged.rglob("*")]]
    for relative, path in sorted(items):
        if path.is_dir():
            if path.stat().st_mode & 0o7777 != 0o700:
                fail(f"legacy fixture directory is not private: {path}")
            inventory.append(f"dir={relative}\t0700\n")
        elif path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            if path.stat().st_mode & 0o7777 != 0o600:
                fail(f"legacy fixture file is not private: {path}")
            inventory.append(f"file={relative}\t0600\t{len(data)}\t{hashlib.sha256(data).hexdigest()}\n")
        else:
            fail(f"unknown legacy fixture artifact: {path}")
    payload = "".join(inventory).encode("utf-8")
    target["after"] = hashlib.sha256(payload).hexdigest()
    blob = journal_dir / f"after.{target_index:04d}"
    blob.write_bytes(payload)
    blob.chmod(0o600)
    (journal_dir / "journal").write_text(
        "SECDATTXN1\n" + json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def require_recovered_v1(domain, store, store_path):
    if (store_path / "format").exists() or set(path.name for path in store_path.iterdir()) != {"entries", "tombstones"}:
        fail(f"legacy recorded v1 skeleton was regenerated with a different format: {store_path}")
    require_ok(run("--dir", str(domain), "--store", store, "fsck"), "recorded v1 automatic fsck", "ok\n")
    require_ok(run("--dir", str(domain), "--store", store, "fsck", "--format", "v1"), "recorded v1 explicit fsck", "ok\n")
    mismatch = run("--dir", str(domain), "--store", store, "fsck", "--format", "v2")
    if mismatch.returncode != 2 or "store format is v1" not in mismatch.stderr:
        fail(f"recorded legacy v1 format was not retained: {mismatch}")


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

# Simulate a valid pending journal written by the pre-v2-default version.
# Both the store schema and the reused domain schema must preserve their
# recorded markerless default store instead of rebuilding a new v2 template.
legacy_create = run(
    "--dir", str(root), "store", "create", "legacy-pending",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if legacy_create.returncode != 86:
    fail(f"legacy store journal fixture did not pause: {legacy_create}")
pending = pending_transactions()
if len(pending) != 1:
    fail(f"expected one paused legacy store journal: {pending!r}")
record_legacy_v1_container(pending[0])
require_ok(run("--dir", str(root), "status", "--quiet"), "legacy store journal recovery")
require_recovered_v1(root, "legacy-pending", domain_data / "stores" / "legacy-pending")
require_ok(run("--dir", str(root), "store", "delete", "legacy-pending"), "delete recovered legacy store")

legacy_domain = work_root / "legacy-pending-domain"
legacy_domain.mkdir()
legacy_create = run(
    "--dir", str(legacy_domain), "domain", "create",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if legacy_create.returncode != 86:
    fail(f"legacy domain journal fixture did not pause: {legacy_create}")
pending = pending_transactions()
if len(pending) != 1:
    fail(f"expected one paused legacy domain journal: {pending!r}")
legacy_target = record_legacy_v1_container(pending[0])
require_ok(run("--dir", str(legacy_domain), "status", "--quiet"), "legacy domain journal recovery")
legacy_domain_data = state_root / "domains" / "by-id" / legacy_target["domain_id"]
require_recovered_v1(legacy_domain, "default", legacy_domain_data / "stores" / "default")
require_ok(run("--dir", str(legacy_domain), "domain", "delete"), "delete recovered legacy domain")
if pending_transactions() or len(registry_files()) != 1:
    fail("legacy journal recovery/cleanup changed unrelated domain state")

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
