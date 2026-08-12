#!/usr/bin/env bash
set -euo pipefail

bin_path="${1:-./src/secdat}"
work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT
export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
export SECDAT_MASTER_KEY='generate-regression-master-key'
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME" "$work_root/domain"

python3 - "$bin_path" "$work_root/domain" <<'PY'
import os, re, subprocess, sys
binary, domain = sys.argv[1:]
env = os.environ | {"LC_ALL": "C", "LANGUAGE": "C"}
def run(*args):
    p = subprocess.run([binary, "--dir", domain, *args], text=True, capture_output=True, env=env)
    return p.returncode, p.stdout, p.stderr
def fail(message): raise SystemExit(f"FAIL: {message}")
if run("domain", "create") != (0, "", ""): fail("domain create")
rc, stdout, stderr = run("set", "PASSWORD", "--generate", "--length", "48", "--charset", "lower,upper,digit,symbol", "--require-each-class")
if (rc, stdout, stderr) != (0, "", ""): fail(f"generated set: {rc=} {stdout=!r} {stderr=!r}")
rc, value, stderr = run("get", "PASSWORD", "--stdout")
if rc or stderr or len(value) != 48: fail("generated value readback")
if not re.fullmatch(r"[A-Za-z0-9!#$%&()*+,.\-/:<=>?@\[\]^_{|}~]{48}", value): fail("unexpected charset")
for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[!#$%&()*+,.\-/:<=>?@\[\]^_{|}~]"):
    if not re.search(pattern, value): fail(f"required class absent: {pattern}")
for args, expected in [
    (("set", "TOO_SHORT", "--generate", "--length", "2", "--charset", "lower,upper,digit", "--require-each-class"), "generated secret length is too short"),
    (("set", "BAD_CHARSET", "--generate", "--length", "8", "--charset", "lower,unknown"), "invalid generated secret charset"),
    (("set", "MISSING_LENGTH", "--generate", "--charset", "lower"), "invalid arguments for generated set"),
    (("set", "MIXED_INPUT", "--generate", "--length", "8", "--charset", "lower", "--value", "plaintext"), "invalid arguments for generated set"),
    (("set", "NO_GENERATE", "--length", "8", "--charset", "lower", "value"), "require --generate"),
]:
    rc, stdout, stderr = run(*args)
    if rc == 0 or stdout or expected not in stderr: fail(f"invalid invocation accepted: {args!r}")
print("PASS generate regression")
PY
