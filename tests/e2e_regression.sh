#!/usr/bin/env bash
# R: Verify session-backed cross-domain secret workflows with persisted v2 defaults.

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

work_root="$(mktemp -d)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import os
import json
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
bundle_passphrase = "e2e-bundle-passphrase"

project_root = work_root / "workspace" / "root"
service_dir = project_root / "service"
ops_dir = project_root / "ops"
restore_dir = work_root / "workspace" / "restore"
bundle_path = work_root / "backup" / "service-app.secdat"
bundle_path.parent.mkdir(parents=True, exist_ok=True)
for path in [project_root, service_dir, ops_dir, restore_dir]:
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


def exec_stderr_ok(stderr):
    for line in stderr.splitlines():
        if line and not line.startswith("warning: exec:"):
            return False
    return True


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
rc, _, stderr = run([bin_path, "--dir", str(restore_dir), "domain", "create"])
if rc != 0 or stderr != "":
    fail(f"restore domain create failed: rc={rc} stderr={stderr!r}")
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

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "rm", "SHARED_KEY"])
expected_mask_warning = "warning: rm: 1 source mask(s) created; inspect with 'secdat --dir DIR list --all-masks --long'\n"
if rc != 0 or stdout != "" or stderr != expected_mask_warning:
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

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "set", "SHARED_KEY", "-v", "child-secret"])
expected_override_warning = "warning: set: 1 directly affected masked key slot(s); 1 mask(s) became dormant; inspect with 'secdat --dir DIR list --all-masks --long'\n"
if rc != 0 or stdout != "" or stderr != expected_override_warning:
    fail(f"override child key failed: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "get", "SHARED_KEY", "-o"])
if rc != 0 or stderr != "":
    fail(f"get overridden child key failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "child-secret", "child override value")

rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "ls", "--json"])
if rc != 0 or stderr:
    fail(f"list overridden child key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
listed = json.loads(stdout)
if listed["key_count"] != 1 or [item["key"] for item in listed["keys"]] != ["SHARED_KEY"]:
    fail(f"list/get disagreed on the local override under a dormant mask: {listed!r}")
rc, stdout, stderr = run([bin_path, "__completion", "--bash", "--dir", str(service_dir), "get", "SHARED_"])
if rc != 0 or stderr or stdout != "__secdat_completion_mode=plain\nSHARED_KEY\n":
    fail(f"completion hid local override under dormant mask: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, exports, stderr = run([bin_path, "--dir", str(service_dir), "export", "--pattern", "SHARED_*"])
if rc != 0 or stderr:
    fail(f"export overridden child key failed: rc={rc} stderr={stderr!r}")
rc, stdout, stderr = run(["bash", "--noprofile", "--norc", "-c", exports + 'printf %s "${SHARED_KEY-missing}"'])
if rc != 0 or stderr or stdout != "child-secret":
    fail(f"export/get disagreed on local override: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([
    bin_path, "--dir", str(service_dir), "exec", "--inject", "secret:only=SHARED_*",
    "--dry-run", "--json", "--", "python3", "-c", "pass",
])
if rc != 0 or stderr:
    fail(f"exec plan for overridden child key failed: rc={rc} stderr={stderr!r}")
plan = json.loads(stdout)
if plan["supply"]["secret"]["contributed"] != ["SHARED_KEY"] or plan["injected_key_count"] != 1:
    fail(f"exec plan hid local override under dormant mask: {plan!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "list", "--all-masks", "--long"])
mask_rows = [line for line in stdout.splitlines() if line.startswith("SHARED_KEY\t")]
if rc != 0 or stderr or len(mask_rows) != 1 or "\tstate=dormant\t" not in mask_rows[0]:
    fail(f"local override did not retain its dormant barrier: rc={rc} stdout={stdout!r} stderr={stderr!r}")
mask_before = dict(field.split("=", 1) for field in mask_rows[0].split("\t")[1:])

rc, stdout, stderr = run([
    bin_path,
    "--dir",
    str(service_dir),
    "exec",
    "--inject", "secret:only=SHARED_*",
    "python3",
    "-c",
    "import os,sys; sys.stdout.write(os.environ.get('SHARED_KEY', 'missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"exec overridden child key failed: rc={rc} stderr={stderr!r}")
assert_eq(stdout, "child-secret", "exec overridden child key")

# Removing the local entry must reactivate the retained inheritance barrier,
# rather than fixing enumeration by discarding the mask during override.
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "fsck", "--dependency-index", "--repair"])
if rc != 0 or stderr or not stdout.startswith("rebuilt-dependency-index\tglobal\t"):
    fail(f"override removal coverage setup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "rm", "SHARED_KEY"])
expected_reactivated_warning = "warning: rm: 1 directly affected masked key slot(s); 1 dormant mask(s) reactivated; inspect with 'secdat --dir DIR list --all-masks --long'\n"
if rc != 0 or stdout or stderr != expected_reactivated_warning:
    fail(f"remove local override failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "get", "SHARED_KEY", "-o"])
if rc != 1 or stdout or "key not found: SHARED_KEY" not in stderr:
    fail(f"removing override exposed parent through retained barrier: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "ls"])
if rc != 0 or stderr or "SHARED_KEY" in stdout.splitlines():
    fail(f"listing exposed reactivated masked source: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(service_dir), "list", "--all-masks", "--long"])
mask_rows = [line for line in stdout.splitlines() if line.startswith("SHARED_KEY\t")]
if rc != 0 or stderr or len(mask_rows) != 1 or "\tstate=active\t" not in mask_rows[0]:
    fail(f"retained mask did not reactivate: rc={rc} stdout={stdout!r} stderr={stderr!r}")
mask_after = dict(field.split("=", 1) for field in mask_rows[0].split("\t")[1:])
for field in ("record_kind", "mask_chain_id", "target_entry_id", "target_secret_id", "target_domain_id"):
    assert_eq(mask_after[field], mask_before[field], f"reactivated mask preserves {field}")


# Scenario 3: save/load/export supports app-store migration into a new domain.
rc, _, stderr = run([bin_path, "--dir", str(service_dir), "--store", "app", "set", "SERVICE_TOKEN", "-v", "service-token"])
if rc != 0 or stderr != "":
    fail(f"set service app token failed: rc={rc} stderr={stderr!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(service_dir), "--store", "app", "save", str(bundle_path)],
    [("Create secdat bundle passphrase:", bundle_passphrase), ("Confirm secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"save bundle failed: rc={rc} transcript={transcript!r}")
if not bundle_path.is_file() or bundle_path.stat().st_size == 0:
    fail("save bundle did not create a non-empty file")

rc, _, stderr = run([bin_path, "--dir", str(restore_dir), "store", "create", "app"])
if rc != 0 or stderr != "":
    fail(f"restore app store create failed: rc={rc} stderr={stderr!r}")
rc, _, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "set", "EXTRA_TOKEN", "-v", "keep-me"])
if rc != 0 or stderr != "":
    fail(f"set restore extra token failed: rc={rc} stderr={stderr!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(bundle_path)],
    [("Enter secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"load bundle failed: rc={rc} transcript={transcript!r}")

for args, expected, label in [
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "API_TOKEN", "-o"], "app-token", "restored inherited app token"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "SERVICE_TOKEN", "-o"], "service-token", "restored local service token"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "EXTRA_TOKEN", "-o"], "keep-me", "preserved extra token"),
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stderr != "":
        fail(f"post-load get failed for {label}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    assert_eq(stdout, expected, label)

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "export"])
if rc != 0 or stderr != "":
    fail(f"restore export failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "API_TOKEN", "restore export API_TOKEN")
assert_contains(stdout, "SERVICE_TOKEN", "restore export SERVICE_TOKEN")
assert_contains(stdout, "EXTRA_TOKEN", "restore export EXTRA_TOKEN")

rc, stdout, stderr = run([
    "bash",
    "-lc",
    stdout + "python3 -c \"import os; print(os.environ['API_TOKEN']); print(os.environ['SERVICE_TOKEN']); print(os.environ['EXTRA_TOKEN'])\"",
])
if rc != 0 or stderr != "":
    fail(f"evaluated restore export failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "app-token\nservice-token\nkeep-me\n", "evaluated restore export values")


# Scenario 4: locking clears the session-backed workflow.
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
