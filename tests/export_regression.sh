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
export SECDAT_MASTER_KEY='export-master-key'
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import os
import shlex
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"

root_dir = work_root / "workspace" / "root"
child_dir = root_dir / "child"
invalid_dir = work_root / "workspace" / "invalid"
for path in [root_dir, child_dir, invalid_dir]:
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


def assert_contains(text, expected, label):
    if expected not in text:
        fail(f"{label}: missing [{expected}] in [{text}]")


for args, marker in [
    ([bin_path, "help", "export"], "export [-p GLOBPATTERN|--pattern GLOBPATTERN]"),
    ([bin_path, "export", "--help"], "emit shell-ready export lines"),
    ([bin_path, "help", "get"], "get KEYREF [-o|--stdout|--shellescaped]"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 0 or marker not in output:
        fail(f"export help check failed for {args}: rc={rc} output={output!r}")

for path in [root_dir, child_dir, invalid_dir]:
    rc, stdout, stderr = run([bin_path, "--dir", str(path), "domain", "create"])
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"domain create failed for {path}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(root_dir), "store", "create", "app"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for args in [
    [bin_path, "--dir", str(root_dir), "set", "ROOT_TOKEN", "root-secret"],
    [bin_path, "--dir", str(child_dir), "set", "CHILD_TOKEN", "child secret's value"],
    [bin_path, "--dir", str(root_dir), "--store", "app", "set", "APP_TOKEN", "app-secret"],
    [bin_path, "--dir", str(invalid_dir), "set", "BAD-KEY", "bad-secret"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup set failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "export"])
if rc != 0 or stderr != "":
    fail(f"export current view failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, 'eval "export CHILD_TOKEN=$(', "child export command")
quoted_paths = {shlex.quote(bin_path), shlex.quote(str(Path(bin_path).resolve()))}
if not any(candidate in stdout for candidate in quoted_paths):
    fail(f"quoted command path: missing one of {sorted(quoted_paths)!r} in [{stdout}]")
assert_contains(stdout, "get 'CHILD_TOKEN' --shellescaped)\"", "child local key line")
assert_contains(stdout, "get 'ROOT_TOKEN' --shellescaped)\"", "child inherited key line")
if "child secret's value" in stdout or "root-secret" in stdout:
    fail(f"export leaked raw secrets: {stdout!r}")

cmd = stdout + "python3 -c \"import os; print(os.environ['CHILD_TOKEN']); print(os.environ['ROOT_TOKEN'])\""
rc, eval_stdout, eval_stderr = run(["bash", "-lc", cmd])
if rc != 0 or eval_stderr != "" or eval_stdout.splitlines() != ["child secret's value", "root-secret"]:
    fail(f"evaluated export failed: rc={rc} stdout={eval_stdout!r} stderr={eval_stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "get", "CHILD_TOKEN", "--shellescaped"])
if rc != 0 or stderr != "":
    fail(f"shellescaped get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if stdout != "'child secret'\\''s value'":
    fail(f"unexpected shellescaped output: {stdout!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(root_dir), "--store", "app", "export"])
if rc != 0 or stderr != "":
    fail(f"store export failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "--store 'app'", "store option present")
assert_contains(stdout, "get 'APP_TOKEN' --shellescaped)\"", "store key present")
if "ROOT_TOKEN" in stdout:
    fail(f"store export unexpectedly included default-store key: {stdout!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "export", "--pattern", "ROOT_*"])
if rc != 0 or stderr != "":
    fail(f"pattern export failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "ROOT_TOKEN", "pattern export keeps match")
if "CHILD_TOKEN" in stdout:
    fail(f"pattern export unexpectedly included unmatched key: {stdout!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(invalid_dir), "export"])
if rc == 0 or "key is not a valid shell identifier: BAD-KEY" not in stderr:
    fail(f"invalid shell identifier check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS export regression")
PY