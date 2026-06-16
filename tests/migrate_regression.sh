#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

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
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "migrate-master-key"

domain = work_root / "project"
domain.mkdir(parents=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args):
    completed = subprocess.run(args, text=True, capture_output=True, env=env)
    return completed.returncode, completed.stdout, completed.stderr


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "create", "app"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "--store", "app", "set", "APP_TOKEN",
    "--value", "secret-token", "--sandbox-inject", "explicit",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set APP_TOKEN failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "--store", "app", "set", "APP_PUBLIC",
    "--public-value", "--value", "public-value",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set APP_PUBLIC failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 0 or stderr != "":
    fail(f"store migrate dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in [
    "format=v1\n",
    "target_format=v2\n",
    "dry_run=yes\n",
    "store=app\n",
    "domain_entries=2\n",
    "secret_objects=2\n",
    "metadata_sidecars=1\n",
    "tombstones=0\n",
    "public_values=1\n",
    "encrypted_values=1\n",
    "injectable_entries=1\n",
    "issues=0\n",
]:
    assert_contains(stdout, expected, "store migrate dry-run output")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2"])
if rc != 2 or "store migrate currently requires --dry-run" not in stderr:
    fail(f"store migrate without dry-run should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v3", "--dry-run"])
if rc != 2 or "invalid migration target format: v3" not in stderr:
    fail(f"store migrate invalid target should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 2 or "--store is not valid with store commands" not in stderr:
    fail(f"store migrate should reject global --store: rc={rc} stdout={stdout!r} stderr={stderr!r}")

entry_files = list(Path(env["XDG_DATA_HOME"]).rglob("APP_TOKEN.sec"))
if len(entry_files) != 1:
    fail(f"expected one APP_TOKEN.sec, found {entry_files!r}")
entries_dir = entry_files[0].parent
(entries_dir / "BROKEN.sec").write_bytes(b"not-a-secdat-entry")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 1 or stderr != "":
    fail(f"store migrate should report corrupt v1 entries: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "cannot-migrate\tdangling-entry\tBROKEN\tinvalid-entry\n", "store migrate corrupt entry")
assert_contains(stdout, "issues=1\n", "store migrate issue count")

print("PASS migrate regression")
PY
