#!/usr/bin/env bash

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

python3 - "$bin_path" "$completion_script" <<'PY'
import os
import subprocess
import sys
import tempfile

bin_path = sys.argv[1]
completion_script = sys.argv[2]


def parse_completion_lines(lines, label):
    if not lines or not lines[0].startswith("__secdat_completion_mode="):
        raise SystemExit(f"FAIL: missing completion mode header for {label}: {lines!r}")
    mode = lines[0].split("=", 1)[1]
    offset = None
    start = 1
    if len(lines) > start and lines[start].startswith("__secdat_completion_offset="):
        offset = int(lines[start].split("=", 1)[1])
        start += 1
    return mode, lines[start:], offset


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
if mode != "none" or values:
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
    return parse_completion_lines(completed.stdout.splitlines(), words)

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
