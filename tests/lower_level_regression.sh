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

python3 - "$bin_path" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "lower-level-test-master-key"
env["SECDAT_MASTER_KEY_PASSPHRASE"] = "lower-level-test-passphrase"

work_root = Path(env["XDG_RUNTIME_DIR"]).parent
root_domain = work_root / "root-domain"
child_domain = root_domain / "child-domain"
grandchild_domain = child_domain / "grandchild-domain"
sibling_domain = work_root / "sibling-domain"

for path in (root_domain, child_domain, grandchild_domain, sibling_domain):
    path.mkdir(parents=True, exist_ok=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def assert_contains(text, fragment, label):
    if fragment not in text:
        fail(f"{label}: missing {fragment!r} in {text!r}")


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected {expected!r}, got {actual!r}")


def scoped(args, domain=root_domain):
    return [bin_path, "--dir", str(domain), *args]


for domain in (root_domain, child_domain, grandchild_domain, sibling_domain):
    rc, stdout, stderr = run(scoped(["domain", "create"], domain))
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"domain create failed for {domain}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["store", "create", "team"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain))
if rc != 0 or "session unlocked from environment\n" not in stdout:
    fail(f"root unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

env.pop("SECDAT_MASTER_KEY", None)

rc, stdout, stderr = run([bin_path, "set", f"{root_domain}/API_TOKEN:team", "-v", "team-token"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit keyref set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "get", f"{root_domain}/API_TOKEN:team", "-o"])
if rc != 0 or stderr != "":
    fail(f"explicit keyref get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "team-token", "explicit keyref value")

for bad_ref, expected in [
    (f"{root_domain}/API_TOKEN:", "invalid key reference"),
    (f"API_TOKEN/{root_domain}:team", "invalid key reference"),
    ("nested/API_TOKEN", "invalid key reference"),
    (f"{root_domain}/", "invalid key reference"),
]:
    rc, stdout, stderr = run([bin_path, "exists", bad_ref])
    if rc == 0 or expected not in stderr:
        fail(f"bad keyref {bad_ref!r} unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child did not inherit root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly inherited root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: explicit lock\n", "child explicit lock state")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: blocked by explicit lock\n", "grandchild blocked state")
assert_contains(stdout, f"blocked by: {child_domain}\n", "grandchild blocked source")

rc, stdout, stderr = run([bin_path, "--dir", str(child_domain), "--store", "team", "get", "API_TOKEN", "-o"])
if rc == 0 or "missing SECDAT_MASTER_KEY and no active secdat session" not in stderr:
    fail(f"child blocked read unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "blocked read resolved domain")
assert_contains(stderr, f"unlock current domain: secdat --dir {child_domain} unlock\n", "blocked read unlock guidance")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session unlocked\nnote: 1 descendant domains can now reuse this session":
    fail(f"child unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "child unlock resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild inherited status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited session\n", "grandchild inherited state")
assert_contains(stdout, f"inherited from: {child_domain}\n", "grandchild inherited source")
PY

printf 'PASS lower-level regression\n'