#!/usr/bin/env bash

# R: Verify command-aware completion candidates and their Bash insertion contract.
set -euo pipefail

bin_path="${1:-./src/secdat}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
completion_script="$source_root/completions/secdat.bash"

# The bash wrapper checks exec command completion with compgen -c.  Limit its
# command search to the Linux toolchain so WSL-mounted Windows directories do
# not make this secdat regression depend on host filesystem enumeration.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

python3 - "$bin_path" "$completion_script" "$script_dir" <<'PY'
import hashlib
import os
import pty
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import time

bin_path = os.path.abspath(sys.argv[1])
completion_script = sys.argv[2]
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])
from store_fixture import create_v1_store


def parse_completion_lines(lines, label):
    if not lines or not lines[0].startswith("__secdat_completion_mode="):
        raise SystemExit(f"FAIL: missing completion mode header for {label}: {lines!r}")
    mode = lines[0].split("=", 1)[1]
    offset = None
    start = 1
    if len(lines) > start and lines[start].startswith("__secdat_completion_offset="):
        offset = int(lines[start].split("=", 1)[1])
        start += 1
    values = lines[start:]
    if mode == "store":
        try:
            values = [bytes.fromhex(value).decode("utf-8") for value in values]
        except (ValueError, UnicodeDecodeError) as error:
            raise SystemExit(f"FAIL: invalid encoded store candidate for {label}: {error}")
    return mode, values, offset


def run_completion(*words):
    completed = subprocess.run(
        [bin_path, "__completion", "--bash", *words],
        text=True,
        capture_output=True,
        env={**os.environ, "LC_ALL": "C", "LANGUAGE": "C"},
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"FAIL: __completion failed for {words!r}: rc={completed.returncode} stderr={completed.stderr!r}")
    return parse_completion_lines(completed.stdout.splitlines(), words)


def assert_contains(values, expected, label):
    if expected not in values:
        raise SystemExit(f"FAIL: {label}: missing {expected!r} in {values!r}")


def assert_not_contains(values, unexpected, label):
    if unexpected in values:
        raise SystemExit(f"FAIL: {label}: unexpected {unexpected!r} in {values!r}")


mode, values, _ = run_completion("")
if mode != "plain":
    raise SystemExit(f"FAIL: top-level completion mode mismatch: {mode!r}")
for expected in ["wait-unlock", "inherit", "store", "meta", "relation", "secret", "domain", "unlock", "attr", "fsck", "gc", "id", "ln", "version", "--dir", "--domain", "--store", "--help", "--version"]:
    assert_contains(values, expected, "top-level commands")

mode, values, _ = run_completion("help", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help completion mode mismatch: {mode!r}")
for expected in ["usecases", "concepts", "wait-unlock", "store", "meta", "relation", "secret", "domain", "gc", "id"]:
    assert_contains(values, expected, "help targets")

mode, values, _ = run_completion("help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "help store subcommands")
assert_not_contains(values, "get", "help store subcommands")

mode, values, _ = run_completion("help", "meta", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help meta completion mode mismatch: {mode!r}")
for expected in ["get", "set", "unset", "search", "mark-leaked"]:
    assert_contains(values, expected, "help meta subcommands")
assert_not_contains(values, "create", "help meta subcommands")

mode, values, _ = run_completion("help", "relation", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help relation completion mode mismatch: {mode!r}")
for expected in ["set", "ls", "search", "suggest-refresh", "suggest-link", "show", "rm"]:
    assert_contains(values, expected, "help relation subcommands")
assert_not_contains(values, "create", "help relation subcommands")

mode, values, _ = run_completion("help", "domain", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help domain completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "status"]:
    assert_contains(values, expected, "help domain subcommands")
assert_not_contains(values, "get", "help domain subcommands")

mode, values, _ = run_completion("help", "secret", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help secret completion mode mismatch: {mode!r}")
for expected in ["status"]:
    assert_contains(values, expected, "help secret subcommands")
assert_not_contains(values, "get", "help secret subcommands")

mode, values, _ = run_completion("help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("--help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: --help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "--help store subcommands")
assert_not_contains(values, "get", "--help store subcommands")

mode, values, _ = run_completion("--help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: --help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("--help", "store", "migrate", "--")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: --help store migrate option completion should stay in help target mode: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("set", "help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: operand help token completion mode mismatch: {mode!r}")
assert_not_contains(values, "create", "operand help token should not enter help target completion")

mode, values, _ = run_completion("--dir", "/tmp", "help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: scoped help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "scoped help store subcommands")
assert_not_contains(values, "get", "scoped help store subcommands")

mode, values, _ = run_completion("--dir", "/tmp", "help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: scoped help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("domain", "")
if mode != "plain":
    raise SystemExit(f"FAIL: domain completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "status"]:
    assert_contains(values, expected, "domain subcommands")

mode, values, _ = run_completion("store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "store subcommands")

mode, values, _ = run_completion("meta", "")
if mode != "plain":
    raise SystemExit(f"FAIL: meta completion mode mismatch: {mode!r}")
for expected in ["get", "set", "unset", "search", "mark-leaked"]:
    assert_contains(values, expected, "meta subcommands")

mode, values, _ = run_completion("relation", "")
if mode != "plain":
    raise SystemExit(f"FAIL: relation completion mode mismatch: {mode!r}")
for expected in ["set", "ls", "search", "suggest-refresh", "show", "rm"]:
    assert_contains(values, expected, "relation subcommands")

mode, values, _ = run_completion("secret", "")
if mode != "plain":
    raise SystemExit(f"FAIL: secret completion mode mismatch: {mode!r}")
for expected in ["status"]:
    assert_contains(values, expected, "secret subcommands")

mode, values, _ = run_completion("ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: ls option completion mode mismatch: {mode!r}")
for expected in ["--pattern-exclude", "--canonical-store", "--safe", "--unsafe", "--metadata", "--bulk-gate", "--public-value", "--secret-value", "--json"]:
    assert_contains(values, expected, "ls options")
for unexpected in ["--bulk-select", "--inject", "--inject-file", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable"]:
    assert_not_contains(values, unexpected, "ls options must not suggest attr/exec/legacy flags")

mode, values, _ = run_completion("list", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: list option completion mode mismatch: {mode!r}")
for expected in ["--masked", "--dormant", "--safe", "--unsafe", "--bulk-gate", "--public-value", "--secret-value", "--all-masks", "--long", "--json"]:
    assert_contains(values, expected, "list options")
for unexpected in ["--bulk-select", "--inject", "--inject-file", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable"]:
    assert_not_contains(values, unexpected, "list options must not suggest attr/exec/legacy flags")

mode, values, _ = run_completion("mask", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: mask option completion mode mismatch: {mode!r}")
for expected in ["--rebind", "--dry-run", "--json"]:
    assert_contains(values, expected, "mask options")
for unexpected in ["--mask-chain", "--mask-warnings", "--no-warn-mask"]:
    assert_not_contains(values, unexpected, "mask options must not suggest unmask-only flags")

mode, values, _ = run_completion("unmask", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: unmask option completion mode mismatch: {mode!r}")
for expected in [
    "--dry-run",
    "--json",
    "--mask-chain",
    "--mask-warnings",
    "--warn-mask",
    "--no-warn-mask",
]:
    assert_contains(values, expected, "unmask options")

mode, values, _ = run_completion("unmask", "--mask-chain", "")
if mode != "none" or values:
    raise SystemExit(
        "FAIL: unmask --mask-chain completion should not expose UUIDs: "
        f"mode={mode!r} values={values!r}"
    )

mode, values, _ = run_completion("unmask", "--mask-warnings", "")
if mode != "none" or values:
    raise SystemExit(
        "FAIL: unmask --mask-warnings completion should stay silent: "
        f"mode={mode!r} values={values!r}"
    )

mode, values, _ = run_completion("unlock", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: unlock option completion mode mismatch: {mode!r}")
for expected in ["--duration", "--until", "--descendants", "--yes", "--askpass", "--gui"]:
    assert_contains(values, expected, "unlock options")

mode, values, _ = run_completion("unlock", "--askpass", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: unlock --askpass completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("passwd", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: passwd option completion mode mismatch: {mode!r}")
assert_contains(values, "--askpass", "passwd options")

mode, values, _ = run_completion("passwd", "--askpass", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: passwd --askpass completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("attr", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: attr option completion mode mismatch: {mode!r}")
for expected in ["--key-visibility", "--value-access", "--bulk-select"]:
    assert_contains(values, expected, "attr options")
for unexpected in ["--inject", "--bulk-gate", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable", "--sandbox-inject", "--inject-bulk"]:
    assert_not_contains(values, unexpected, "attr options must not suggest exec/legacy flags")

mode, values, _ = run_completion("attr", "--bulk-select", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: attr --bulk-select completion should not suggest token values: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("attr", "--key-visibility", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: attr --key-visibility completion should not suggest token values: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("attr", "API_TOKEN", "--inject", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: attr mistaken --inject value completion should stay silent: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("relation", "set", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: relation set option completion mode mismatch: {mode!r}")
for expected in ["--kind", "--member", "--security", "--exposure", "--impact", "--note"]:
    assert_contains(values, expected, "relation set options")

mode, values, _ = run_completion("relation", "set", "--member", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: relation set --member completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("fsck", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: fsck option completion mode mismatch: {mode!r}")
for expected in ["--orphaned", "--dangling", "--refcount", "--dependency-index", "--repair", "--format"]:
    assert_contains(values, expected, "fsck options")

mode, values, _ = run_completion("gc", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: gc option completion mode mismatch: {mode!r}")
for expected in ["--orphaned", "--dangling", "--dry-run", "--format"]:
    assert_contains(values, expected, "gc options")

mode, values, _ = run_completion("store", "migrate", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store migrate option completion mode mismatch: {mode!r}")
for expected in ["--to-format", "--dry-run"]:
    assert_contains(values, expected, "store migrate options")

mode, values, _ = run_completion("store", "ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store ls option completion mode mismatch: {mode!r}")
for expected in ["--pattern", "--json"]:
    assert_contains(values, expected, "store ls options")

mode, values, _ = run_completion("domain", "ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: domain ls option completion mode mismatch: {mode!r}")
for expected in ["--long", "--inherited", "--descendants", "--pattern", "--json"]:
    assert_contains(values, expected, "domain ls options")

mode, values, _ = run_completion("store", "migrate", "--to-format", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: store migrate --to-format completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("store", "finalize-migration", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store finalize-migration option completion mode mismatch: {mode!r}")
for expected in ["--from-format", "--dry-run"]:
    assert_contains(values, expected, "store finalize-migration options")

mode, values, _ = run_completion("store", "finalize-migration", "--from-format", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: store finalize-migration --from-format completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("set", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: set option completion mode mismatch: {mode!r}")
for expected in ["--ephemeral", "--public-value", "--secret-value", "--key-visibility", "--value-access", "--bulk-select"]:
    assert_contains(values, expected, "set options")
for unexpected in ["--inject", "--bulk-gate", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable", "--sandbox-inject", "--inject-bulk"]:
    assert_not_contains(values, unexpected, "set options must not suggest exec/legacy flags")

mode, values, _ = run_completion("set", "--bulk-select", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: set --bulk-select completion should not suggest token values: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("rm", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: rm option completion mode mismatch: {mode!r}")
for expected in ["--ephemeral", "--ignore-missing"]:
    assert_contains(values, expected, "rm options")

mode, values, _ = run_completion("exec", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: exec option completion mode mismatch: {mode!r}")
for expected in ["--inject", "--inject-file", "--bulk-gate", "--command-resolution", "--dry-run", "--json", "--json-summary"]:
    assert_contains(values, expected, "exec options")
for unexpected in ["--bulk-select", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable", "--sandbox-inject", "--inject-bulk"]:
    assert_not_contains(values, unexpected, "exec options must not suggest attr/legacy flags")

mode, values, _ = run_completion("exec", "--inject", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: exec --inject completion should not suggest rule values: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("exec", "--inject-file", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: exec --inject-file completion should enter file mode: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("exec", "--bulk-gate", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: exec --bulk-gate completion should not suggest values: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("exec", "--command-resolution", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: exec --command-resolution completion should not suggest token values: mode={mode!r} values={values!r}")

mode, values, offset = run_completion("exec", "")
if mode != "command" or values or offset is not None:
    raise SystemExit(f"FAIL: exec CMD completion should enter command mode: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("exec", "--", "")
if mode != "command" or values or offset is not None:
    raise SystemExit(f"FAIL: exec after -- should enter command mode: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("exec", "--inject", "secret:only=APP_", "--", "")
if mode != "command" or values or offset is not None:
    raise SystemExit(f"FAIL: exec after options and -- should enter command mode: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("exec", "--inject", "secret:only=APP_", "")
if mode != "command" or values or offset is not None:
    raise SystemExit(f"FAIL: exec after options should enter command mode: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("exec", "--inject", "secret:only=APP_", "--", "python", "")
if mode != "delegate" or values or offset != 5:
    raise SystemExit(f"FAIL: exec child-arg completion should delegate: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("--dir", "/tmp", "exec", "--bulk-gate", "--", "python", "")
if mode != "delegate" or values or offset != 6:
    raise SystemExit(f"FAIL: scoped exec child-arg completion should delegate: mode={mode!r} values={values!r} offset={offset!r}")

mode, values, offset = run_completion("exec", "--inject", "secret:only=APP_", "--", "python", "-c")
if mode != "delegate" or values or offset != 5:
    raise SystemExit(f"FAIL: exec child option completion should delegate: mode={mode!r} values={values!r} offset={offset!r}")

for words, expected_offset in [
    (["-d/tmp", "exec", "--", "printf", ""], 4),
    (["--dir=/tmp", "exec", "--", "printf", ""], 4),
    (["--domain=/tmp", "exec", "--", "printf", ""], 4),
    (["-sdefault", "exec", "--", "printf", ""], 4),
    (["--store=default", "exec", "--", "printf", ""], 4),
    (["-d/tmp", "-sdefault", "exec", "--", "printf", ""], 5),
    (["-d/tmp", "exec", "--", "printf", "foo", "=", "bar", ""], 4),
    (["-d/tmp", "exec", "--", "printf", "foo", ":", "bar", ""], 4),
]:
    mode, values, offset = run_completion(*words)
    if mode != "delegate" or values or offset != expected_offset:
        raise SystemExit(
            f"FAIL: attached global option changed child offset for {words!r}: "
            f"mode={mode!r} values={values!r} offset={offset!r} expected={expected_offset}"
        )

for unexpected in ["--inject", "--bulk-gate", "--dry-run"]:
    mode, values, offset = run_completion("exec", "--inject", "secret:only=APP_", "--", "")
    if unexpected in values:
        raise SystemExit(f"FAIL: exec command phase should not suggest secdat flags: {unexpected!r} in {values!r}")

mode, values, _ = run_completion("export", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: export option completion mode mismatch: {mode!r}")
for expected in ["--pattern", "--bulk-gate"]:
    assert_contains(values, expected, "export options")
for unexpected in ["--bulk-select", "--inject", "--inject-file", "--inject-gate", "--inject-bulk-gate", "--sandbox-injectable"]:
    assert_not_contains(values, unexpected, "export options must not suggest attr/exec/legacy flags")

mode, values, _ = run_completion("cp", "")
if mode != "plain":
    raise SystemExit(f"FAIL: cp completion mode mismatch: {mode!r}")

mode, values, _ = run_completion("mv", "")
if mode != "plain":
    raise SystemExit(f"FAIL: mv completion mode mismatch: {mode!r}")
for expected in [
    "--mask-action", "--mask-warnings", "--warn-mask", "--no-warn-mask",
    "--dry-run", "--json",
]:
    assert_contains(values, expected, "mv options")

mode, values, _ = run_completion("ln", "")
if mode != "plain":
    raise SystemExit(f"FAIL: ln completion mode mismatch: {mode!r}")
for expected in ["--replace", "--skip-same-value-check"]:
    assert_contains(values, expected, "ln options")

mode, values, _ = run_completion("relation", "suggest-link", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: relation suggest-link option completion mode mismatch: {mode!r}")
assert_contains(values, "--cluster-field", "relation suggest-link options")

mode, values, _ = run_completion("unlock", "--")
for expected in ["--duration", "--until", "--descendants", "--yes", "--readonly"]:
    assert_contains(values, expected, "unlock options")

mode, values, _ = run_completion("wait-unlock", "--")
for expected in ["--timeout", "--quiet"]:
    assert_contains(values, expected, "wait-unlock options")

mode, values, _ = run_completion("--dir", "")
if mode != "dir" or values:
    raise SystemExit(f"FAIL: --dir completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("--domain", "")
if mode != "dir" or values:
    raise SystemExit(f"FAIL: --domain completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("--store", "")
if mode != "store":
    raise SystemExit(f"FAIL: --store completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("save", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: save completion mode mismatch: mode={mode!r} values={values!r}")

mode, values, _ = run_completion("save", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: save option completion mode mismatch: {mode!r}")
assert_contains(values, "--key", "save long options")

mode, values, _ = run_completion("save", "-")
if mode != "plain":
    raise SystemExit(f"FAIL: save short option completion mode mismatch: {mode!r}")
assert_contains(values, "-k", "save short options")

mode, values, _ = run_completion("save", "--key", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: save --key completion should not suggest values: mode={mode!r} values={values!r}")

work_root = tempfile.mkdtemp(prefix="secdat-completion-")
env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "XDG_RUNTIME_DIR": os.path.join(work_root, "runtime"), "XDG_DATA_HOME": os.path.join(work_root, "data"), "SECDAT_MASTER_KEY": "completion-test-key"}
os.makedirs(env["XDG_RUNTIME_DIR"], exist_ok=True)
os.makedirs(env["XDG_DATA_HOME"], exist_ok=True)

literal_dir = os.path.join(work_root, "literal")
literal_child = os.path.join(literal_dir, "child")
space_domain = os.path.join(work_root, "space domain")
os.makedirs(literal_dir, exist_ok=True)
os.makedirs(literal_child, exist_ok=True)
os.makedirs(space_domain, exist_ok=True)
subprocess.run([bin_path, "--dir", literal_dir, "domain", "create"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_child, "domain", "create"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", space_domain, "domain", "create"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "set", "__completion", "literal-value"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "set", "COMPLETION_ALPHA", "alpha-value"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_child, "set", "COMPLETION_CHILD", "child-value"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "store", "create", "team"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "--store", "team", "set", "COMPLETION_TEAM", "team-value"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", space_domain, "set", "COMPLETION_SPACE", "space-value"], check=True, capture_output=True, text=True, env=env)
literal_get = subprocess.run([bin_path, "--dir", literal_dir, "__completion"], check=False, capture_output=True, text=True, env=env)
if literal_get.returncode != 0 or literal_get.stdout != "literal-value":
    raise SystemExit(f"FAIL: bare __completion no longer falls back to get: rc={literal_get.returncode} stdout={literal_get.stdout!r} stderr={literal_get.stderr!r}")

def run_scoped_completion(*words, environment=None, cwd=None):
    completed = subprocess.run(
        [bin_path, "__completion", "--bash", *words],
        text=True,
        capture_output=True,
        env=env if environment is None else environment,
        cwd=cwd,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"FAIL: scoped __completion failed for {words!r}: rc={completed.returncode} stderr={completed.stderr!r}")
    return parse_completion_lines(completed.stdout.splitlines(), words)


# Store candidates are namespace metadata. Keep inherited/local scopes
# distinct, and exercise the real shell wrapper as well as its wire protocol.
def create_store(directory, name):
    subprocess.run(
        [bin_path, "--dir", directory, "store", "create", name],
        check=True, capture_output=True, text=True, env=env,
    )


parent_stores = ["cstore-parent", "cstore-shared"]
child_stores = ["cstore-child", "cstore-shared", "cstore-empty", "cstore-v1", "cstore-v2"]
shell_eval_marker = os.path.join(work_root, "completion-evaluated")
special_stores = [
    "cstore-space name", "cstore-日本語", "cstore-slash/name",
    "cstore-new\nline", "cstore-trailing\n", "cstore-tab\tname",
    "cstore-quote'\"\\name", f"cstore-$(touch {shell_eval_marker});*?[]",
    "cstore-colon:name", "cstore-equals=name",
    "cstore-ansi'quote\nend", "cstore-control\x01end",
]
for name in parent_stores:
    create_store(literal_dir, name)
for name in child_stores + special_stores:
    create_store(literal_child, name)
create_store(literal_child, "-cstore-dash")
create_store(space_domain, "cstore-unrelated")
create_v1_store(env["XDG_DATA_HOME"], literal_child, "cstore-v1")

local_store_names = sorted(set(child_stores + special_stores))
effective_store_names = sorted(set(local_store_names + parent_stores))


def assert_store_candidates(words, expected, *, environment=None, cwd=None):
    mode, values, _ = run_scoped_completion(*words, environment=environment, cwd=cwd)
    if mode != "store" or values != expected:
        raise SystemExit(
            f"FAIL: store completion for {words!r}: mode={mode!r} "
            f"values={values!r} expected={expected!r}"
        )


for scope in [
    ["--dir", literal_child], ["-d", literal_child], ["--domain", literal_child],
    [f"--dir={literal_child}"], [f"-d{literal_child}"], [f"--domain={literal_child}"],
]:
    for option in ["--store", "-s"]:
        assert_store_candidates([*scope, option, "cstore-"], effective_store_names)
    assert_store_candidates(
        [*scope, "--store=cstore-"], [f"--store={name}" for name in effective_store_names]
    )
    assert_store_candidates([*scope, "-scstore-"], [f"-s{name}" for name in effective_store_names])
    for command in ["delete", "migrate", "finalize-migration"]:
        assert_store_candidates([*scope, "store", command, "cstore-"], local_store_names)

assert_store_candidates(["--store", "cstore-"], effective_store_names, cwd=literal_child)
unregistered_child = os.path.join(literal_child, "unregistered-child")
os.makedirs(unregistered_child)
assert_store_candidates(["--dir", unregistered_child, "--store", "cstore-"], effective_store_names)
assert_store_candidates(
    ["--dir", unregistered_child, "store", "delete", "cstore-"], local_store_names
)
assert_store_candidates(["--dir", work_root, "--store", "cstore-"], [])
assert_store_candidates(["--dir", literal_child, "--store", "cstore-ch"], ["cstore-child"])
assert_store_candidates(["--dir", literal_child, "--store", "absent-"], [])
assert_store_candidates(["--dir", literal_child, "store", "delete", "-cstore-"], ["-cstore-dash"])
assert_store_candidates(["--dir", os.path.join(work_root, "missing"), "--store", "cstore-"], [])
assert_store_candidates(["--dir", literal_child, "--domain", literal_dir, "--store", "cstore-"], [])
assert_store_candidates(
    ["--dir", space_domain, "--store", "cstore-"], ["cstore-unrelated"]
)

for command, option, value in [
    ("migrate", "--to-format", "v2"),
    ("finalize-migration", "--from-format", "v1"),
]:
    for options in [[option, value], [f"{option}={value}"], ["--dry-run", option, value]]:
        assert_store_candidates(
            ["--dir", literal_child, "store", command, *options, "cstore-"], local_store_names
        )
    mode, values, _ = run_scoped_completion("--dir", literal_child, "store", command, option, "")
    if mode == "store" or any(value.startswith("cstore-") for value in values):
        raise SystemExit(f"FAIL: {option} value mistaken for store operand: {mode!r} {values!r}")

for words in [
    ["store", "create", "cstore-"], ["store", "ls", "cstore-"],
    ["store", "delete", "cstore-child", "cstore-"],
    ["store", "migrate", "cstore-child", "--to-format", "v2", "cstore-"],
    ["store", "finalize-migration", "cstore-child", "--from-format", "v1", "cstore-"],
    ["get", "--store", "cstore-"], ["set", "KEY", "--store", "cstore-"],
    ["help", "store", "delete", "cstore-"],
    ["exec", "--", "printf", "--store", "cstore-"],
]:
    mode, values, _ = run_scoped_completion("--dir", literal_child, *words)
    if mode == "store" or any(value.startswith("cstore-") for value in values):
        raise SystemExit(f"FAIL: store candidates escaped operand boundary for {words!r}: {mode!r} {values!r}")


def shell_quote_candidates(values):
    completed = subprocess.run(
        ["bash", "--noprofile", "--norc", "-c", 'printf "%q\\0" "$@"', "quote-test", *values],
        capture_output=True, check=True, env=env,
    )
    return [value.decode("utf-8") for value in completed.stdout.split(b"\0")[:-1]]


def bash_store_candidates(words, *, cword=None, cwd=None, environment=None, line=None, point=None):
    # Pass words as positional parameters instead of embedding shell syntax.
    # NUL output preserves names containing whitespace, newlines and quotes.
    completed = subprocess.run(
        [
            "bash", "--noprofile", "--norc", "-c",
            'source "$1"; export SECDAT_COMPLETION_BIN="$2"; '
            'COMP_CWORD=$3; COMP_LINE=$4; COMP_POINT=$5; '
            'if [[ $COMP_LINE ]]; then COMP_POINT=${COMP_POINT:-${#COMP_LINE}}; else unset COMP_LINE COMP_POINT; fi; '
            'shift 5; COMP_WORDS=("$@"); '
            '_comp_command_offset() { COMPREPLY=("delegate-offset:$1"); }; '
            '_secdat_complete; '
            'if ((${#COMPREPLY[@]})); then printf "%s\\0" "${COMPREPLY[@]}"; fi',
            "completion-test", completion_script, bin_path,
            str(len(words) - 1 if cword is None else cword), "" if line is None else line,
            "" if point is None else str(point), *words,
        ],
        capture_output=True, env=env if environment is None else environment, cwd=cwd,
    )
    if completed.returncode != 0:
        raise SystemExit(f"FAIL: Bash store completion failed for {words!r}: {completed.stderr!r}")
    return [value.decode("utf-8") for value in completed.stdout.split(b"\0")[:-1]]


for option in ["--store", "-s"]:
    words = ["secdat", "--dir", literal_child, option, "cstore-"]
    values = bash_store_candidates(words)
    if values != shell_quote_candidates(effective_store_names):
        raise SystemExit(f"FAIL: Bash {option} store candidates: {values!r}")
    # A later token must not change the target or turn the cursor into a
    # different operand. This also protects completion during line editing.
    values = bash_store_candidates([*words, "--dir", space_domain, "get", "KEY"], cword=4)
    if values != shell_quote_candidates(effective_store_names):
        raise SystemExit(f"FAIL: Bash cursor-middle {option} completion: {values!r}")

middle_line = f"secdat --dir {literal_child} --store cstore-chsuffix get KEY"
middle_prefix = f"secdat --dir {literal_child} --store cstore-ch"
values = bash_store_candidates(
    ["secdat", "--dir", literal_child, "--store", "cstore-chsuffix", "get", "KEY"],
    cword=4, line=middle_line, point=len(middle_prefix),
)
if values != shell_quote_candidates(["cstore-child"]):
    raise SystemExit(f"FAIL: Bash completion consumed the suffix after the cursor: {values!r}")

# Bash normally puts '=' in COMP_WORDBREAKS. Cover both its split words and
# the unsplit representation used when users customize that variable.
for words, expected, suffix in [
    (["--store", "=", "cstore-"], effective_store_names, "--store=cstore-"),
    (["--store", "=", ""], ["-cstore-dash", "default", *effective_store_names, "team"], "--store="),
    (["--store=cstore-"], [f"--store={name}" for name in effective_store_names], "--store=cstore-"),
    (["-scstore-"], [f"-s{name}" for name in effective_store_names], "-scstore-"),
]:
    values = bash_store_candidates(
        ["secdat", "--dir", literal_child, *words],
        line=f"secdat --dir {literal_child} {suffix}",
    )
    if values != shell_quote_candidates(sorted(expected)):
        raise SystemExit(f"FAIL: Bash attached option {words!r}: {values!r} expected={sorted(expected)!r}")

for words in [
    ["secdat", "--dir", "=", literal_child, "--store", "cstore-"],
    ["secdat", "--domain", "=", literal_child, "--store", "cstore-"],
]:
    option = words[1]
    values = bash_store_candidates(words, line=f"secdat {option}={literal_child} --store cstore-")
    if values != shell_quote_candidates(effective_store_names):
        raise SystemExit(f"FAIL: Bash split context option {words!r}: {values!r}")

values = bash_store_candidates(
    ["secdat", "--dir", literal_child, "--store", "=", "cstore-"],
    line=f"secdat --dir {literal_child} --store = cstore-",
)
if values:
    raise SystemExit(f"FAIL: Bash whitespace-separated equals was treated as attached syntax: {values!r}")

for name in special_stores:
    values = bash_store_candidates(["secdat", "--dir", literal_child, "store", "delete", name])
    if values != shell_quote_candidates([name]):
        raise SystemExit(f"FAIL: Bash special store name was changed: {name!r} -> {values!r}")

values = bash_store_candidates(["secdat", "--dir", literal_child, "store", "delete", "-cstore-"])
if values != shell_quote_candidates(["-cstore-dash"]):
    raise SystemExit(f"FAIL: Bash leading-dash store name was mistaken for an option: {values!r}")

for suffix, line_suffix in [
    ([""], ""),
    (["foo", "=", "bar", ""], "foo=bar "),
    (["foo", ":", "bar", ""], "foo:bar "),
]:
    words = ["secdat", f"-d{literal_child}", "exec", "--", "printf", *suffix]
    values = bash_store_candidates(words, line=f"secdat -d{literal_child} exec -- printf {line_suffix}")
    if values != ["delegate-offset:4"]:
        raise SystemExit(f"FAIL: Bash normalization changed child delegation offset: {words!r} -> {values!r}")

# A slash in a store name is not a request for filesystem directory
# completion. Deliberately provide a matching real directory as a trap.
os.makedirs(os.path.join(work_root, "cstore-slash", "not-a-store"))
os.makedirs(os.path.join(work_root, "cstore-slash", "name"))
os.makedirs(os.path.join(work_root, "cstore-child"))
values = bash_store_candidates(
    ["secdat", "--dir", literal_child, "--store", "cstore-slash/"], cwd=work_root
)
if values != shell_quote_candidates(["cstore-slash/name"]):
    raise SystemExit(f"FAIL: Bash store completion mixed filesystem paths: {values!r}")
if os.path.exists(shell_eval_marker):
    raise SystemExit("FAIL: a store name was evaluated as shell code")


def check_readline_insertion():
    # COMPREPLY alone cannot prove that Readline inserts one literal argument:
    # quoting, word breaks and filename mode all affect the executed argv.
    prompt = b"__SECDAT_COMPLETION_PROMPT__ "
    result_path = os.path.join(work_root, "readline-argv")
    interactive_env = {
        **env, "PS1": prompt.decode("ascii"), "TERM": "xterm",
        "SECDAT_COMPLETION_BIN": bin_path,
    }
    interactive_env.pop("PROMPT_COMMAND", None)
    child, terminal = pty.fork()
    if child == 0:
        os.chdir(work_root)
        os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"], interactive_env)

    case_label = "shell startup"

    def read_prompt():
        output = b""
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.1)[0]:
                try:
                    chunk = os.read(terminal, 65536)
                except OSError as error:
                    raise SystemExit(f"FAIL: Readline shell exited: {output!r}: {error}")
                if not chunk:
                    break
                output += chunk
                if output.endswith(prompt):
                    return output
        raise SystemExit(f"FAIL: timed out waiting for Readline prompt ({case_label}): {output!r}")

    def send_line(line):
        os.write(terminal, line)
        return read_prompt()

    cases = [
        ("--store cstore-ch", ["--store", "cstore-child"]),
        ("--store cstore-space", ["--store", "cstore-space name"]),
        ("--store cstore-quote", ["--store", "cstore-quote'\"\\name"]),
        ("--store cstore-colon:na", ["--store", "cstore-colon:name"]),
        ("--store cstore-equals=na", ["--store", "cstore-equals=name"]),
        ("--store cstore-trailing", ["--store", "cstore-trailing\n"]),
        ("--store cstore-slash/na", ["--store", "cstore-slash/name"]),
        ("--store 'cstore-space", ["--store", "cstore-space name"]),
        ('--store "cstore-space', ["--store", "cstore-space name"]),
        ("--store 'cstore-quote", ["--store", "cstore-quote'\"\\name"]),
        ('--store "cstore-quote', ["--store", "cstore-quote'\"\\name"]),
        ("--store=cstore-ch", ["--store=cstore-child"]),
        ("-scstore-ch", ["-scstore-child"]),
        ("store delete -cstore-da", ["store", "delete", "-cstore-dash"]),
        ("--store cstore-\\$", ["--store", special_stores[7]]),
        ("--store $'cstore-spa'", ["--store", "cstore-space name"]),
        ("--store $'cstore-\\x73pa'", ["--store", "cstore-space name"]),
        ("--store $'cstore-\\163pa'", ["--store", "cstore-space name"]),
        ("--store $'cstore-spa", ["--store", "cstore-space name"]),
        ("--store cstore-ansi", ["--store", "cstore-ansi'quote\nend"]),
        ("--store $'cstore-ansi\\'quote\\n'", ["--store", "cstore-ansi'quote\nend"]),
        ("--store $'cstore-control\\cA'", ["--store", "cstore-control\x01end"]),
        (
            "--store " + shell_quote_candidates(["cstore-ansi'quote\nend"])[0],
            ["--store", "cstore-ansi'quote\nend"],
        ),
    ]
    try:
        read_prompt()
        setup = (
            f"source {shlex.quote(completion_script)}; "
            f"secdat() {{ printf '%s\\0' \"$@\" > {shlex.quote(result_path)}; }}; "
            "bind 'set bell-style none'"
        )
        send_line(setup.encode("utf-8") + b"\n")
        helper_path = "/usr/share/bash-completion/bash_completion"
        for with_helper in [False, True] if os.path.isfile(helper_path) else [False]:
            if with_helper:
                send_line(f"source {shlex.quote(helper_path)}\n".encode("utf-8"))
            for typed, expected in cases:
                case_label = f"helper={with_helper}, input={typed!r}"
                if os.path.exists(result_path):
                    os.unlink(result_path)
                command = f"secdat --dir {shlex.quote(literal_child)} {typed}"
                rendered = send_line(command.encode("utf-8") + b"\t\n")
                if os.path.exists(result_path):
                    with open(result_path, "rb") as stream:
                        actual = stream.read().split(b"\0")[:-1]
                else:
                    actual = []
                expected_bytes = [value.encode("utf-8") for value in ["--dir", literal_child, *expected]]
                if actual != expected_bytes:
                    raise SystemExit(
                        f"FAIL: Readline store insertion (helper={with_helper}) for {typed!r}: "
                        f"argv={actual!r} expected={expected_bytes!r} terminal={rendered!r}"
                    )
    finally:
        # Never leave the interactive child behind after an assertion/timeout.
        try:
            os.kill(child, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            exited, _ = os.waitpid(child, os.WNOHANG)
            if exited:
                break
            time.sleep(0.05)
        else:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        os.close(terminal)
    if os.path.exists(shell_eval_marker):
        raise SystemExit("FAIL: Readline completion executed a store name")


check_readline_insertion()


def tree_contents(root):
    snapshot = []
    for directory, directories, files in os.walk(root):
        directories.sort()
        for name in sorted(directories + files):
            path = os.path.join(directory, name)
            info = os.lstat(path)
            digest = None
            if os.path.isfile(path) and not os.path.islink(path):
                with open(path, "rb") as stream:
                    digest = hashlib.sha256(stream.read()).hexdigest()
            snapshot.append((os.path.relpath(path, root), info.st_mode, digest))
    return snapshot


locked_env = {key: value for key, value in env.items() if key != "SECDAT_MASTER_KEY"}
before_data = tree_contents(env["XDG_DATA_HOME"])
before_runtime = tree_contents(env["XDG_RUNTIME_DIR"])
assert_store_candidates(
    ["--dir", literal_child, "--store", "cstore-"], effective_store_names, environment=locked_env
)
for command in ["delete", "migrate", "finalize-migration"]:
    assert_store_candidates(
        ["--dir", literal_child, "store", command, "cstore-"], local_store_names,
        environment=locked_env,
    )
values = bash_store_candidates(
    ["secdat", "--dir", literal_child, "--store", "cstore-"], environment=locked_env
)
if values != shell_quote_candidates(effective_store_names):
    raise SystemExit(f"FAIL: Bash locked store metadata completion: {values!r}")
if tree_contents(env["XDG_DATA_HOME"]) != before_data or tree_contents(env["XDG_RUNTIME_DIR"]) != before_runtime:
    raise SystemExit("FAIL: store completion changed persistent data or session state")

mode, values, _ = run_scoped_completion("--dir", literal_dir, "COMPLETION_")
if mode != "plain":
    raise SystemExit(f"FAIL: scoped top-level key completion mode mismatch: {mode!r}")
assert_contains(values, "COMPLETION_ALPHA", "top-level key completions")
assert_contains(values, "COMPLETION_ALPHA=", "top-level assignment completions")

for command in ["get", "exists", "attr", "rm", "mask", "unmask", "set", "cp", "mv", "ln"]:
    mode, values, _ = run_scoped_completion("--dir", literal_dir, command, "COMPLETION_")
    if mode != "plain":
        raise SystemExit(f"FAIL: {command} key completion mode mismatch: {mode!r}")
    assert_contains(values, "COMPLETION_ALPHA", f"{command} key completions")
    if "COMPLETION_ALPHA=" in values:
        raise SystemExit(f"FAIL: {command} key completion should not emit assignment candidates: {values!r}")

for command in ["cp", "mv", "ln"]:
    mode, values, _ = run_scoped_completion("--dir", literal_dir, command, "COMPLETION_ALPHA", "")
    if "COMPLETION_ALPHA" in values:
        raise SystemExit(f"FAIL: {command} destination completion should not reuse existing key candidates: {values!r}")

mode, values, _ = run_scoped_completion("--dir", literal_child, "get", "../COMPLETION_")
assert_contains(values, "../COMPLETION_ALPHA", "relative parent KEYREF completion")
if "../COMPLETION_CHILD" in values:
    raise SystemExit(f"FAIL: relative parent completion leaked a child-local key: {values!r}")

mode, values, _ = run_scoped_completion("--domain", literal_child, "get", "../COMPLETION_")
assert_contains(values, "../COMPLETION_ALPHA", "--domain relative KEYREF completion")

mode, values, _ = run_scoped_completion("--dir", literal_child, "get", "./COMPLETION_")
assert_contains(values, "./COMPLETION_CHILD", "relative local KEYREF completion")
if "./COMPLETION_ALPHA" in values:
    raise SystemExit(f"FAIL: exact-local completion inherited a parent key: {values!r}")

absolute_prefix = f"{literal_dir}/COMPLETION_"
mode, values, _ = run_scoped_completion("get", absolute_prefix)
assert_contains(values, f"{literal_dir}/COMPLETION_ALPHA", "absolute KEYREF completion")

mode, values, _ = run_scoped_completion("--dir", literal_child, "get", "../COMPLETION_T:t")
assert_contains(values, "../COMPLETION_TEAM:team", "qualified KEYREF store completion")

mode, values, _ = run_scoped_completion(
    "--dir", literal_child, "mv", "../COMPLETION_ALPHA", "./COMPLETION_"
)
assert_contains(values, "./COMPLETION_ALPHA", "relative mv destination completion")

bash_qualified_test = subprocess.run(
    [
        "bash",
        "-lc",
        (
            f"source {completion_script!r}; "
            f"export SECDAT_COMPLETION_BIN={bin_path!r}; "
            f"COMP_WORDS=(secdat --dir {literal_child!r} get '../COMPLETION_'); "
            "COMP_CWORD=4; "
            "_secdat_complete; "
            "printf '%s\n' \"${COMPREPLY[@]}\""
        ),
    ],
    text=True,
    capture_output=True,
    env=env,
    check=False,
)
if bash_qualified_test.returncode != 0:
    raise SystemExit(
        f"FAIL: bash qualified KEYREF completion failed: "
        f"rc={bash_qualified_test.returncode} stderr={bash_qualified_test.stderr!r}"
    )
assert_contains(
    [line for line in bash_qualified_test.stdout.splitlines() if line],
    "../COMPLETION_ALPHA",
    "bash relative KEYREF completion",
)

bash_space_test = subprocess.run(
    [
        "bash",
        "-lc",
        (
            f"source {completion_script!r}; "
            f"export SECDAT_COMPLETION_BIN={bin_path!r}; "
            f"COMP_WORDS=(secdat get {space_domain + '/COMPLETION_'!r}); "
            "COMP_CWORD=2; "
            "_secdat_complete; "
            "printf '<%s>\n' \"${COMPREPLY[@]}\""
        ),
    ],
    text=True,
    capture_output=True,
    env=env,
    check=False,
)
if bash_space_test.returncode != 0 or bash_space_test.stdout != f"<{space_domain}/COMPLETION_SPACE>\n":
    raise SystemExit(
        f"FAIL: bash qualified completion did not preserve spaces: "
        f"rc={bash_space_test.returncode} stdout={bash_space_test.stdout!r} "
        f"stderr={bash_space_test.stderr!r}"
    )

bash_test = subprocess.run(
    [
        "bash",
        "-lc",
        (
            f"source {completion_script!r}; "
            f"export SECDAT_COMPLETION_BIN={bin_path!r}; "
            "COMP_WORDS=(secdat domain ''); "
            "COMP_CWORD=2; "
            "_secdat_complete; "
            "printf '%s\n' \"${COMPREPLY[@]}\""
        ),
    ],
    text=True,
    capture_output=True,
    env=env,
    check=False,
)
if bash_test.returncode != 0:
    raise SystemExit(f"FAIL: bash completion wrapper failed: rc={bash_test.returncode} stderr={bash_test.stderr!r}")
bash_values = [line for line in bash_test.stdout.splitlines() if line]
for expected in ["create", "delete", "ls", "status"]:
    assert_contains(bash_values, expected, "bash wrapper domain completions")

bash_exec_test = subprocess.run(
    [
        "bash",
        "-lc",
        (
            f"source {completion_script!r}; "
            f"export SECDAT_COMPLETION_BIN={bin_path!r}; "
            "COMP_WORDS=(secdat exec --inject secret:only=APP_ -- ''); "
            "COMP_CWORD=6; "
            "_secdat_complete; "
            "printf '%s\n' \"${COMPREPLY[@]}\""
        ),
    ],
    text=True,
    capture_output=True,
    env=env,
    check=False,
)
if bash_exec_test.returncode != 0:
    raise SystemExit(f"FAIL: bash exec command completion failed: rc={bash_exec_test.returncode} stderr={bash_exec_test.stderr!r}")
bash_exec_values = [line for line in bash_exec_test.stdout.splitlines() if line]
if "--inject" in bash_exec_values or "--bulk-gate" in bash_exec_values:
    raise SystemExit(f"FAIL: bash exec command completion should not suggest secdat flags: {bash_exec_values!r}")
if bash_exec_values and not any(value.startswith("py") for value in bash_exec_values):
    raise SystemExit(f"FAIL: bash exec command completion should suggest PATH commands: {bash_exec_values!r}")

print("PASS completion regression")
PY
