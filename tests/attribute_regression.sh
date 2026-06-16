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
env["SECDAT_MASTER_KEY"] = "attribute-master-key"

domain = work_root / "project"
child = domain / "child"
domain.mkdir(parents=True)
child.mkdir(parents=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected [{expected}], got [{actual}]")


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "set", "API_TOKEN",
    "--value", "token", "--sandbox-inject", "explicit",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set explicit inject failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "API_TOKEN"])
if rc != 0 or stderr != "":
    fail(f"attr API_TOKEN failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "key_visibility=always\n", "attr key visibility")
assert_contains(stdout, "value_access=unlocked\n", "attr value access")
assert_contains(stdout, "sandbox_inject=explicit\n", "attr inject")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--metadata"])
if rc != 0 or stderr != "":
    fail(f"ls --metadata failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "API_TOKEN\tkey_visibility=always\tvalue_access=unlocked\tsandbox_inject=explicit\n", "ls metadata")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--sandbox-injectable"])
if rc != 0 or stderr != "":
    fail(f"ls --sandbox-injectable failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "API_TOKEN\n", "sandbox-injectable list")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "NO_INJECT", "--value", "nope"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set non-inject failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--sandbox-injectable"])
if rc != 0 or stderr != "":
    fail(f"ls sandbox-injectable after non-inject failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "API_TOKEN\n", "non-inject key excluded")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "NO_INJECT", "--sandbox-inject", "bulk"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"attr bulk failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "list", "--sandbox-injectable"])
if rc != 0 or stderr != "":
    fail(f"list sandbox-injectable failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "API_TOKEN\n", "list includes explicit key")
assert_contains(stdout, "NO_INJECT\n", "list includes bulk key")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "NO_INJECT", "--sandbox-inject", "allow"])
if rc == 0 or "invalid sandbox inject policy: allow" not in stderr:
    fail(f"legacy allow CLI input should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

legacy_meta_files = list(Path(env["XDG_DATA_HOME"]).rglob("NO_INJECT.meta"))
if len(legacy_meta_files) != 1:
    fail(f"expected one NO_INJECT.meta, found {legacy_meta_files!r}")
legacy_meta_files[0].write_text(
    "SECDATATTR1\nkey_visibility=always\nvalue_access=unlocked\nsandbox_inject=allow\n",
    encoding="utf-8",
)
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "NO_INJECT"])
if rc != 0 or stderr != "":
    fail(f"legacy allow metadata readback failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "sandbox_inject=bulk\n", "legacy allow metadata normalizes to bulk")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "PUBLIC_ENDPOINT", "--public-value", "--value", "https://example.invalid"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set public value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "PUBLIC_ENDPOINT"])
if rc != 0 or stderr != "":
    fail(f"attr public value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "value_access=always\n", "public value access")

locked_env = {"SECDAT_MASTER_KEY": ""}
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "PUBLIC_ENDPOINT", "--stdout"], locked_env)
if rc != 0 or stderr != "":
    fail(f"locked public get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "https://example.invalid", "locked public get")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "PUBLIC_ENDPOINT", "--value-access", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"attr value-access unlocked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "PUBLIC_ENDPOINT"])
if rc != 0 or stderr != "":
    fail(f"attr relocked public failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "value_access=unlocked\n", "relocked value access")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "PUBLIC_ENDPOINT", "--stdout"], locked_env)
if rc == 0 or "missing SECDAT_MASTER_KEY" not in stderr:
    fail(f"locked secret get should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "cp", "API_TOKEN", "API_TOKEN_COPY"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cp with attrs failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "API_TOKEN_COPY"])
if rc != 0 or stderr != "":
    fail(f"attr copied key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "sandbox_inject=explicit\n", "copy preserves inject attr")

rc, stdout, stderr = run([bin_path, "--dir", str(child), "attr", "API_TOKEN", "--sandbox-inject", "never"])
if rc == 0 or "cannot update inherited key attributes" not in stderr:
    fail(f"inherited attr update should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "HIDDEN_KEY", "--key-visibility", "unlocked", "--value", "secret"])
if rc == 0 or "key_visibility=unlocked requires store format v2" not in stderr:
    fail(f"hidden key should be rejected for v1 storage: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS attribute regression")
PY
