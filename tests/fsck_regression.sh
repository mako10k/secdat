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
env["SECDAT_MASTER_KEY"] = "fsck-master-key"

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

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "GOOD", "--value", "good"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set GOOD failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"clean fsck failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--refcount"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"v1 refcount fsck should be a clean no-op: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 2 or "store format is v1; use --format v1" not in stderr:
    fail(f"v2 fsck should be rejected for now: rc={rc} stdout={stdout!r} stderr={stderr!r}")

entry_files = list(Path(env["XDG_DATA_HOME"]).rglob("GOOD.sec"))
if len(entry_files) != 1:
    fail(f"expected one GOOD.sec, found {entry_files!r}")
entries_dir = entry_files[0].parent
tombstones_dir = entries_dir.parent / "tombstones"
tombstones_dir.mkdir(parents=True, exist_ok=True)

(entries_dir / "ORPHAN.meta").write_text(
    "SECDATATTR1\nkey_visibility=always\nvalue_access=unlocked\nsandbox_inject=explicit\n",
    encoding="utf-8",
)
(entries_dir / "BROKEN.sec").write_bytes(b"not-a-secdat-entry")
(tombstones_dir / "STALE.tomb").write_bytes(b"")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "BADMETA", "--value", "bad", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set BADMETA failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
(entries_dir / "BADMETA.meta").write_text(
    "SECDATATTR1\nkey_visibility=unlocked\nvalue_access=unlocked\nsandbox_inject=explicit\n",
    encoding="utf-8",
)

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--orphaned"])
if rc != 1 or stderr != "":
    fail(f"orphaned fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "orphaned-metadata\tORPHAN\tmissing-entry\n", "orphaned metadata")
assert_contains(stdout, "orphaned-tombstone\tSTALE\tmissing-parent\n", "orphaned tombstone")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--dangling"])
if rc != 1 or stderr != "":
    fail(f"dangling fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "dangling-entry\tBROKEN\tinvalid-entry\n", "dangling entry")
assert_contains(stdout, "dangling-metadata\tBADMETA\tinvalid-metadata\n", "dangling metadata")

print("PASS fsck regression")
PY
