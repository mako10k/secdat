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
export SECDAT_MASTER_KEY='save-load-master-key'
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import os
import pty
import re
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
bundle_passphrase = "bundle-passphrase"

root_dir = work_root / "workspace" / "root"
child_dir = root_dir / "child"
restore_dir = work_root / "workspace" / "restore"
bundle_path = work_root / "backup" / "app.secdat"
bundle_path.parent.mkdir(parents=True, exist_ok=True)
for path in [root_dir, child_dir, restore_dir]:
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


def normalize_spaces(text):
    return re.sub(r"[ \t]+", " ", text)


for args, marker in [
    ([bin_path, "help", "save"], "save FILE"),
    ([bin_path, "load", "--help"], "load FILE"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 0 or marker not in normalize_spaces(output) or "passphrase-protected bundle" not in output:
        fail(f"save/load help check failed for {args}: rc={rc} output={output!r}")

for path in [root_dir, child_dir, restore_dir]:
    rc, stdout, stderr = run([bin_path, "--dir", str(path), "domain", "create"])
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"domain create failed for {path}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(root_dir), "store", "create", "app"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create app failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for args in [
    [bin_path, "--dir", str(root_dir), "--store", "app", "set", "INHERITED_APP", "-v", "root-app"],
    [bin_path, "--dir", str(child_dir), "--store", "app", "set", "LOCAL_APP", "-v", "child-app"],
    [bin_path, "--dir", str(child_dir), "set", "DEFAULT_ONLY", "-v", "default-value"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup set failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)])
output = stdout + stderr
if rc == 0 or "this command requires a terminal for passphrase input" not in output:
    fail(f"non-tty save should require passphrase terminal: rc={rc} output={output!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)],
    [("Create secdat bundle passphrase:", bundle_passphrase), ("Confirm secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"save command failed: rc={rc} transcript={transcript!r}")
if not bundle_path.is_file() or bundle_path.stat().st_size == 0:
    fail("save did not create a non-empty bundle file")

rc, transcript = run_pty(
    [bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)],
    [("Create secdat bundle passphrase:", bundle_passphrase), ("Confirm secdat bundle passphrase:", bundle_passphrase)],
)
if rc == 0 or "bundle file already exists" not in transcript:
    fail(f"save overwrite semantics failed: rc={rc} transcript={transcript!r}")

for args in [
    [bin_path, "--dir", str(restore_dir), "--store", "app", "set", "LOCAL_APP", "-v", "old-value"],
    [bin_path, "--dir", str(restore_dir), "--store", "app", "set", "EXTRA_APP", "-v", "keep-me"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"restore setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(bundle_path)])
output = stdout + stderr
if rc == 0 or "this command requires a terminal for passphrase input" not in output:
    fail(f"non-tty load should require passphrase terminal: rc={rc} output={output!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(bundle_path)],
    [("Enter secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"load command failed: rc={rc} transcript={transcript!r}")

for args, expected, label in [
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "INHERITED_APP", "-o"], "root-app", "inherited app key"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "LOCAL_APP", "-o"], "child-app", "overwritten local app key"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "EXTRA_APP", "-o"], "keep-me", "unspecified key preserved"),
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stderr != "":
        fail(f"post-load get failed for {label}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    assert_eq(stdout, expected, label)

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "DEFAULT_ONLY", "-o"])
if rc == 0:
    fail("save unexpectedly included default-store key in app-store bundle")
assert_contains(stdout + stderr, "key not found: DEFAULT_ONLY", "store-scoped save/load")

print("PASS save/load regression")
PY