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
import pty
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
passphrase = "e2e-passphrase"

project_root = work_root / "workspace" / "root"
service_dir = project_root / "service"
ops_dir = project_root / "ops"
for path in [project_root, service_dir, ops_dir]:
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


def run_pty(args, prompts, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)

    pid, fd = pty.fork()
    if pid == 0:
        os.execve(args[0], args, run_env)

    chunks = []
    try:
        for expected, reply in prompts:
            collected = ""
            while expected not in collected:
                data = os.read(fd, 4096)
                if not data:
                    break
                text = data.decode(errors="replace")
                chunks.append(text)
                collected += text
            if expected not in collected:
                fail(f"missing prompt [{expected}] in [{''.join(chunks)}]")
            os.write(fd, reply.encode() + b"\n")

        while True:
            data = os.read(fd, 4096)
            if not data:
                break
            chunks.append(data.decode(errors="replace"))
    except OSError:
        pass
    finally:
        _, status = os.waitpid(pid, 0)

    return os.waitstatus_to_exitcode(status), "".join(chunks)


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected [{expected}], got [{actual}]")


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


# Scenario 1: bootstrap session unlock and operate on a project store without env master key.
rc, transcript = run_pty(
    [bin_path, "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {"SECDAT_MASTER_KEY": "e2e-master-key"},
)
if rc != 0 or "persistent master key initialized; session unlocked from environment" not in transcript:
    fail(f"bootstrap unlock failed: rc={rc} transcript={transcript!r}")

env.pop("SECDAT_MASTER_KEY", None)

rc, stdout, stderr = run([bin_path, "status"])
if rc != 0 or stderr != "":
    fail(f"status after bootstrap failed: rc={rc} stderr={stderr!r}")
assert_contains(stdout, "source: session agent", "session-backed status")

rc, _, stderr = run([bin_path, "--dir", str(project_root), "domain", "create"])
if rc != 0 or stderr != "":
    fail(f"project domain create failed: rc={rc} stderr={stderr!r}")
rc, _, stderr = run([bin_path, "--dir", str(service_dir), "domain", "create"])
if rc != 0 or stderr != "":
    fail(f"service domain create failed: rc={rc} stderr={stderr!r}")
rc, _, stderr = run([bin_path, "--dir", str(project_root), "store", "create", "app"])
if rc != 0 or stderr != "":
    fail(f"app store create failed: rc={rc} stderr={stderr!r}")
rc, _, stderr = run([bin_path, "--dir", str(project_root), "store", "create", "ops"])
if rc != 0 or stderr != "":
    fail(f"ops store create failed: rc={rc} stderr={stderr!r}")

rc, _, stderr = run([bin_path, "--dir", str(project_root), "--store", "app", "set", "API_TOKEN", "-v", "app-token"])
if rc != 0 or stderr != "":
    fail(f"set API_TOKEN in app store failed: rc={rc} stderr={stderr!r}")
rc, _, stderr = run([bin_path, "--dir", str(project_root), "--store", "ops", "set", "API_TOKEN", "-v", "ops-token"])
if rc != 0 or stderr != "":
    fail(f"set API_TOKEN in ops store failed: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(project_root), "--store", "app", "get", "API_TOKEN", "-o"])
if rc != 0 or stderr != "":
    fail(f"get API_TOKEN from app store failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "app-token", "app store value")

rc, stdout, stderr = run([bin_path, "--dir", str(project_root), "--store", "ops", "get", "API_TOKEN", "-o"])
if rc != 0 or stderr != "":
    fail(f"get API_TOKEN from ops store failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "ops-token", "ops store value")

rc, stdout, stderr = run([
    bin_path,
    "--dir",
    str(project_root),
    "--store",
    "app",
    "exec",
    "python3",
    "-c",
    "import os,sys; sys.stdout.write(os.environ.get('API_TOKEN', 'missing'))",
])
if rc != 0 or stderr != "":
    fail(f"exec app store failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "app-token", "exec app store value")


# Scenario 2: inherited secrets can be hidden with a tombstone and overridden locally.
rc, _, stderr = run([bin_path, "--dir", str(project_root), "set", "SHARED_KEY", "-v", "root-secret"])
if rc != 0 or stderr != "":
    fail(f"set inherited key failed: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "get", "SHARED_KEY", "-o"])
if rc != 0 or stderr != "":
    fail(f"get inherited key in child failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "root-secret", "child inherited key")

rc, _, stderr = run([bin_path, "--dir", str(service_dir), "rm", "SHARED_KEY"])
if rc != 0 or stderr != "":
    fail(f"rm inherited key in child failed: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "ls"])
if rc != 0 or stderr != "":
    fail(f"ls in child after tombstone failed: rc={rc} stderr={stderr!r}")
if "SHARED_KEY" in stdout.splitlines():
    fail(f"tombstoned key still listed: {stdout!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "get", "SHARED_KEY", "-o"])
if rc == 0:
    fail("tombstoned key was still readable")

rc, stdout, stderr = run([
    bin_path,
    "--dir",
    str(service_dir),
    "exec",
    "python3",
    "-c",
    "import os,sys; sys.stdout.write('present' if 'SHARED_KEY' in os.environ else 'missing')",
])
if rc != 0 or stderr != "":
    fail(f"exec after tombstone failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "missing", "tombstoned key hidden from exec")

rc, _, stderr = run([bin_path, "--dir", str(service_dir), "set", "SHARED_KEY", "-v", "child-secret"])
if rc != 0 or stderr != "":
    fail(f"override child key failed: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "get", "SHARED_KEY", "-o"])
if rc != 0 or stderr != "":
    fail(f"get overridden child key failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "child-secret", "child override value")

rc, stdout, stderr = run([
    bin_path,
    "--dir",
    str(service_dir),
    "exec",
    "--pattern",
    "SHARED_*",
    "python3",
    "-c",
    "import os,sys; sys.stdout.write(os.environ.get('SHARED_KEY', 'missing'))",
])
if rc != 0 or stderr != "":
    fail(f"exec overridden child key failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "child-secret", "exec overridden child key")


# Scenario 3: locking clears the session-backed workflow.
rc, stdout, stderr = run([bin_path, "lock"])
if rc != 0 or stderr != "":
    fail(f"lock after e2e scenarios failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout.strip(), "session locked", "session lock output")

rc, stdout, stderr = run([bin_path, "--dir", str(project_root), "--store", "app", "get", "API_TOKEN", "-o"])
if rc == 0:
    fail("get unexpectedly succeeded after lock")
assert_contains(stderr, "missing SECDAT_MASTER_KEY and no active secdat session", "locked get error")

print("PASS e2e regression")
PY