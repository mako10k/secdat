#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_root="$(CDPATH= cd -- "$script_dir/.." && pwd)"
completion_script="$source_root/completions/secdat.bash"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

python3 - "$bin_path" "$completion_script" <<'PY'
import os
import subprocess
import sys
import tempfile

bin_path = sys.argv[1]
completion_script = sys.argv[2]


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
    lines = completed.stdout.splitlines()
    if not lines or not lines[0].startswith("__secdat_completion_mode="):
        raise SystemExit(f"FAIL: missing completion mode header for {words!r}: {completed.stdout!r}")
    return lines[0].split("=", 1)[1], lines[1:]


def assert_contains(values, expected, label):
    if expected not in values:
        raise SystemExit(f"FAIL: {label}: missing {expected!r} in {values!r}")


def assert_not_contains(values, unexpected, label):
    if unexpected in values:
        raise SystemExit(f"FAIL: {label}: unexpected {unexpected!r} in {values!r}")


mode, values = run_completion("")
if mode != "plain":
    raise SystemExit(f"FAIL: top-level completion mode mismatch: {mode!r}")
for expected in ["wait-unlock", "inherit", "store", "meta", "relation", "secret", "domain", "unlock", "attr", "fsck", "gc", "id", "ln", "version", "--dir", "--domain", "--store", "--help", "--version"]:
    assert_contains(values, expected, "top-level commands")

mode, values = run_completion("help", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help completion mode mismatch: {mode!r}")
for expected in ["usecases", "concepts", "wait-unlock", "store", "meta", "relation", "secret", "domain", "gc", "id"]:
    assert_contains(values, expected, "help targets")

mode, values = run_completion("help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "help store subcommands")
assert_not_contains(values, "get", "help store subcommands")

mode, values = run_completion("help", "meta", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help meta completion mode mismatch: {mode!r}")
for expected in ["get", "set", "unset", "search", "mark-leaked"]:
    assert_contains(values, expected, "help meta subcommands")
assert_not_contains(values, "create", "help meta subcommands")

mode, values = run_completion("help", "relation", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help relation completion mode mismatch: {mode!r}")
for expected in ["set", "ls", "search", "suggest-refresh", "show", "rm"]:
    assert_contains(values, expected, "help relation subcommands")
assert_not_contains(values, "create", "help relation subcommands")

mode, values = run_completion("help", "domain", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help domain completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "status"]:
    assert_contains(values, expected, "help domain subcommands")
assert_not_contains(values, "get", "help domain subcommands")

mode, values = run_completion("help", "secret", "")
if mode != "plain":
    raise SystemExit(f"FAIL: help secret completion mode mismatch: {mode!r}")
for expected in ["status"]:
    assert_contains(values, expected, "help secret subcommands")
assert_not_contains(values, "get", "help secret subcommands")

mode, values = run_completion("help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values = run_completion("--help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: --help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "--help store subcommands")
assert_not_contains(values, "get", "--help store subcommands")

mode, values = run_completion("--help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: --help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values = run_completion("--help", "store", "migrate", "--")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: --help store migrate option completion should stay in help target mode: mode={mode!r} values={values!r}")

mode, values = run_completion("set", "help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: operand help token completion mode mismatch: {mode!r}")
assert_not_contains(values, "create", "operand help token should not enter help target completion")

mode, values = run_completion("--dir", "/tmp", "help", "store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: scoped help store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "scoped help store subcommands")
assert_not_contains(values, "get", "scoped help store subcommands")

mode, values = run_completion("--dir", "/tmp", "help", "store", "migrate", "")
if mode != "plain" or values:
    raise SystemExit(f"FAIL: scoped help store migrate completion should not suggest deeper targets: mode={mode!r} values={values!r}")

mode, values = run_completion("domain", "")
if mode != "plain":
    raise SystemExit(f"FAIL: domain completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "status"]:
    assert_contains(values, expected, "domain subcommands")

mode, values = run_completion("store", "")
if mode != "plain":
    raise SystemExit(f"FAIL: store completion mode mismatch: {mode!r}")
for expected in ["create", "delete", "ls", "migrate", "finalize-migration"]:
    assert_contains(values, expected, "store subcommands")

mode, values = run_completion("meta", "")
if mode != "plain":
    raise SystemExit(f"FAIL: meta completion mode mismatch: {mode!r}")
for expected in ["get", "set", "unset", "search", "mark-leaked"]:
    assert_contains(values, expected, "meta subcommands")

mode, values = run_completion("relation", "")
if mode != "plain":
    raise SystemExit(f"FAIL: relation completion mode mismatch: {mode!r}")
for expected in ["set", "ls", "search", "suggest-refresh", "show", "rm"]:
    assert_contains(values, expected, "relation subcommands")

mode, values = run_completion("secret", "")
if mode != "plain":
    raise SystemExit(f"FAIL: secret completion mode mismatch: {mode!r}")
for expected in ["status"]:
    assert_contains(values, expected, "secret subcommands")

mode, values = run_completion("ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: ls option completion mode mismatch: {mode!r}")
for expected in ["--pattern-exclude", "--canonical-store", "--safe", "--unsafe", "--metadata", "--bulk-gate", "--public-value", "--secret-value", "--json"]:
    assert_contains(values, expected, "ls options")

mode, values = run_completion("list", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: list option completion mode mismatch: {mode!r}")
for expected in ["--masked", "--safe", "--unsafe", "--bulk-gate", "--public-value", "--secret-value"]:
    assert_contains(values, expected, "list options")

mode, values = run_completion("unlock", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: unlock option completion mode mismatch: {mode!r}")
for expected in ["--duration", "--until", "--descendants", "--yes", "--askpass", "--gui"]:
    assert_contains(values, expected, "unlock options")

mode, values = run_completion("unlock", "--askpass", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: unlock --askpass completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("passwd", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: passwd option completion mode mismatch: {mode!r}")
assert_contains(values, "--askpass", "passwd options")

mode, values = run_completion("passwd", "--askpass", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: passwd --askpass completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("attr", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: attr option completion mode mismatch: {mode!r}")
for expected in ["--key-visibility", "--value-access", "--bulk-select", "--inject"]:
    assert_contains(values, expected, "attr options")

mode, values = run_completion("relation", "set", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: relation set option completion mode mismatch: {mode!r}")
for expected in ["--kind", "--member", "--security", "--exposure", "--impact", "--note"]:
    assert_contains(values, expected, "relation set options")

mode, values = run_completion("relation", "set", "--member", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: relation set --member completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("fsck", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: fsck option completion mode mismatch: {mode!r}")
for expected in ["--orphaned", "--dangling", "--refcount", "--repair", "--format"]:
    assert_contains(values, expected, "fsck options")

mode, values = run_completion("gc", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: gc option completion mode mismatch: {mode!r}")
for expected in ["--orphaned", "--dangling", "--dry-run", "--format"]:
    assert_contains(values, expected, "gc options")

mode, values = run_completion("store", "migrate", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store migrate option completion mode mismatch: {mode!r}")
for expected in ["--to-format", "--dry-run"]:
    assert_contains(values, expected, "store migrate options")

mode, values = run_completion("store", "ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store ls option completion mode mismatch: {mode!r}")
for expected in ["--pattern", "--json"]:
    assert_contains(values, expected, "store ls options")

mode, values = run_completion("domain", "ls", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: domain ls option completion mode mismatch: {mode!r}")
for expected in ["--long", "--inherited", "--descendants", "--pattern", "--json"]:
    assert_contains(values, expected, "domain ls options")

mode, values = run_completion("store", "migrate", "--to-format", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: store migrate --to-format completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("store", "finalize-migration", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: store finalize-migration option completion mode mismatch: {mode!r}")
for expected in ["--from-format", "--dry-run"]:
    assert_contains(values, expected, "store finalize-migration options")

mode, values = run_completion("store", "finalize-migration", "--from-format", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: store finalize-migration --from-format completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("set", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: set option completion mode mismatch: {mode!r}")
for expected in ["--public-value", "--secret-value", "--key-visibility", "--value-access", "--bulk-select", "--inject"]:
    assert_contains(values, expected, "set options")

mode, values = run_completion("exec", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: exec option completion mode mismatch: {mode!r}")
for expected in ["--inject", "--inject-file", "--bulk-gate", "--dry-run", "--json", "--json-summary"]:
    assert_contains(values, expected, "exec options")

mode, values = run_completion("export", "--")
if mode != "plain":
    raise SystemExit(f"FAIL: export option completion mode mismatch: {mode!r}")
for expected in ["--pattern", "--bulk-gate"]:
    assert_contains(values, expected, "export options")

mode, values = run_completion("cp", "")
if mode != "plain":
    raise SystemExit(f"FAIL: cp completion mode mismatch: {mode!r}")

mode, values = run_completion("mv", "")
if mode != "plain":
    raise SystemExit(f"FAIL: mv completion mode mismatch: {mode!r}")

mode, values = run_completion("ln", "")
if mode != "plain":
    raise SystemExit(f"FAIL: ln completion mode mismatch: {mode!r}")

mode, values = run_completion("unlock", "--")
for expected in ["--duration", "--until", "--descendants", "--yes", "--readonly"]:
    assert_contains(values, expected, "unlock options")

mode, values = run_completion("wait-unlock", "--")
for expected in ["--timeout", "--quiet"]:
    assert_contains(values, expected, "wait-unlock options")

mode, values = run_completion("--dir", "")
if mode != "dir" or values:
    raise SystemExit(f"FAIL: --dir completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("--domain", "")
if mode != "dir" or values:
    raise SystemExit(f"FAIL: --domain completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("--store", "")
if mode != "none" or values:
    raise SystemExit(f"FAIL: --store completion mode mismatch: mode={mode!r} values={values!r}")

mode, values = run_completion("save", "")
if mode != "file" or values:
    raise SystemExit(f"FAIL: save completion mode mismatch: mode={mode!r} values={values!r}")

work_root = tempfile.mkdtemp(prefix="secdat-completion-")
env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "XDG_RUNTIME_DIR": os.path.join(work_root, "runtime"), "XDG_DATA_HOME": os.path.join(work_root, "data"), "SECDAT_MASTER_KEY": "completion-test-key"}
os.makedirs(env["XDG_RUNTIME_DIR"], exist_ok=True)
os.makedirs(env["XDG_DATA_HOME"], exist_ok=True)

literal_dir = os.path.join(work_root, "literal")
os.makedirs(literal_dir, exist_ok=True)
subprocess.run([bin_path, "--dir", literal_dir, "domain", "create"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "set", "__completion", "literal-value"], check=True, capture_output=True, text=True, env=env)
subprocess.run([bin_path, "--dir", literal_dir, "set", "COMPLETION_ALPHA", "alpha-value"], check=True, capture_output=True, text=True, env=env)
literal_get = subprocess.run([bin_path, "--dir", literal_dir, "__completion"], check=False, capture_output=True, text=True, env=env)
if literal_get.returncode != 0 or literal_get.stdout != "literal-value":
    raise SystemExit(f"FAIL: bare __completion no longer falls back to get: rc={literal_get.returncode} stdout={literal_get.stdout!r} stderr={literal_get.stderr!r}")

def run_scoped_completion(*words):
    completed = subprocess.run(
        [bin_path, "__completion", "--bash", *words],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"FAIL: scoped __completion failed for {words!r}: rc={completed.returncode} stderr={completed.stderr!r}")
    lines = completed.stdout.splitlines()
    if not lines or not lines[0].startswith("__secdat_completion_mode="):
        raise SystemExit(f"FAIL: missing scoped completion mode header for {words!r}: {completed.stdout!r}")
    return lines[0].split("=", 1)[1], lines[1:]

mode, values = run_scoped_completion("--dir", literal_dir, "COMPLETION_")
if mode != "plain":
    raise SystemExit(f"FAIL: scoped top-level key completion mode mismatch: {mode!r}")
assert_contains(values, "COMPLETION_ALPHA", "top-level key completions")
assert_contains(values, "COMPLETION_ALPHA=", "top-level assignment completions")

for command in ["get", "exists", "attr", "rm", "mask", "unmask", "set", "cp", "mv", "ln"]:
    mode, values = run_scoped_completion("--dir", literal_dir, command, "COMPLETION_")
    if mode != "plain":
        raise SystemExit(f"FAIL: {command} key completion mode mismatch: {mode!r}")
    assert_contains(values, "COMPLETION_ALPHA", f"{command} key completions")
    if "COMPLETION_ALPHA=" in values:
        raise SystemExit(f"FAIL: {command} key completion should not emit assignment candidates: {values!r}")

for command in ["cp", "mv", "ln"]:
    mode, values = run_scoped_completion("--dir", literal_dir, command, "COMPLETION_ALPHA", "")
    if "COMPLETION_ALPHA" in values:
        raise SystemExit(f"FAIL: {command} destination completion should not reuse existing key candidates: {values!r}")

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

print("PASS completion regression")
PY
