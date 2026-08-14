#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
work_root="$(mktemp -d)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

python3 - "$bin_path" "$work_root" <<'PY'
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

bin_path = str(Path(sys.argv[1]).resolve())
work_root = Path(sys.argv[2])
data_root = work_root / "data"
runtime_root = work_root / "runtime"
workspace = work_root / "workspace"
for path in (data_root, runtime_root, workspace):
    path.mkdir(parents=True, exist_ok=True)

base_env = {
    **os.environ,
    "LC_ALL": "C",
    "LANGUAGE": "C",
    "XDG_DATA_HOME": str(data_root),
    "XDG_RUNTIME_DIR": str(runtime_root),
    "SECDAT_MASTER_KEY": "deferred-gc-master-key",
}


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(domain, *args, extra_env=None):
    env = base_env.copy()
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [bin_path, "--dir", str(domain), *args],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def require_ok(result, label, stdout=None):
    if result.returncode != 0 or result.stderr or (
        stdout is not None and result.stdout != stdout
    ):
        fail(
            f"{label}: rc={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


def create_v2_domain(name):
    domain = workspace / name
    domain.mkdir()
    before = set(by_id.iterdir()) if by_id.exists() else set()
    require_ok(run(domain, "domain", "create"), f"create {name}", "")
    require_ok(
        run(domain, "store", "migrate", "default", "--to-format", "v2"),
        f"migrate {name}",
    )
    created = set(by_id.iterdir()) - before
    if len(created) != 1:
        fail(f"could not identify {name} domain state: {created!r}")
    return domain, created.pop()


def status(domain, errors=False):
    args = ["gc", "--status"]
    if errors:
        args.append("--errors")
    args.append("--json")
    result = run(domain, *args)
    require_ok(result, "GC status")
    return json.loads(result.stdout)


def candidate_files(owner_state):
    root = data_root / "secdat/gc/candidates/by-owner" / owner_state.name
    return sorted(root.rglob("*.gc")) if root.exists() else []


def object_path(owner_state, secret_id):
    return owner_state / "stores/default/objects/secret" / f"{secret_id}.sec"


state_root = data_root / "secdat"
by_id = state_root / "domains/by-id"
owner, owner_state = create_v2_domain("owner")

# A PREPARED crash must retain both the reference and candidate absence.
require_ok(run(owner, "set", "FAULT_KEY", "--value", "fault"), "fault seed", "")
fault_id = run(owner, "id", "FAULT_KEY").stdout.strip()
prepared = run(
    owner,
    "rm",
    "FAULT_KEY",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"},
)
if prepared.returncode != 86:
    fail(f"prepared fault did not stop transaction: {prepared}")
require_ok(run(owner, "status", "--quiet"), "prepared recovery", "")
if run(owner, "exists", "FAULT_KEY").returncode != 0:
    fail("PREPARED recovery removed the reference")
if candidate_files(owner_state):
    fail("PREPARED recovery retained a GC candidate")

# A COMMITTING crash must roll the namespace and candidate generation forward.
committing = run(
    owner,
    "rm",
    "FAULT_KEY",
    extra_env={"SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if committing.returncode != 86:
    fail(f"committing fault did not stop transaction: {committing}")
require_ok(run(owner, "status", "--quiet"), "committing recovery", "")
if run(owner, "exists", "FAULT_KEY").returncode == 0:
    fail("COMMITTING recovery retained the removed reference")
files = candidate_files(owner_state)
if len(files) != 1 or not object_path(owner_state, fault_id).is_file():
    fail("COMMITTING recovery did not retain object plus candidate")
require_ok(run(owner, "gc", "--queued"), "fault candidate collection")

# Foreground rm retains the object and writes one canonical candidate generation.
require_ok(run(owner, "set", "ONE", "--value", "one"), "single seed", "")
single_id_result = run(owner, "id", "ONE")
require_ok(single_id_result, "single id")
single_id = single_id_result.stdout.strip()
require_ok(run(owner, "rm", "ONE"), "single rm", "")
files = candidate_files(owner_state)
if len(files) != 1 or not object_path(owner_state, single_id).is_file():
    fail("foreground rm did not retain object plus one candidate")
candidate = files[0]
record = dict(
    line.split("=", 1)
    for line in candidate.read_text(encoding="utf-8").splitlines()[1:]
)
tuple_bytes = b"".join(
    len(value).to_bytes(4, "big") + value
    for value in (
        owner_state.name.encode(),
        b"default",
        single_id.encode(),
    )
)
if candidate.stem != hashlib.sha256(tuple_bytes).hexdigest():
    fail("candidate tuple handle is not canonical")
if record["attempt_count"] != "0" or record["manual_required"] != "0":
    fail(f"foreground candidate state is not pending: {record!r}")
single_status = status(owner)
expected_status_keys = {
    "schema_version", "domain_id", "store", "pending", "ready",
    "retrying", "manual_required", "corrupt", "quarantined",
    "oldest_enqueued_at", "next_attempt_at",
}
if set(single_status) != expected_status_keys:
    fail(f"GC status shape changed: {single_status!r}")
secret_status = run(owner, "secret", "status", "--gc", single_id)
require_ok(secret_status, "secret GC status")
if "gc_candidate=pending\n" not in secret_status.stdout:
    fail(f"secret GC status omitted pending state: {secret_status.stdout!r}")
dry_run = run(owner, "gc", "--queued", "--dry-run")
require_ok(dry_run, "queued dry-run")
if not object_path(owner_state, single_id).is_file() or not candidate.is_file():
    fail("queued dry-run mutated object or candidate")
collected = run(owner, "gc", "--queued")
require_ok(collected, "queued collection")
if object_path(owner_state, single_id).exists() or candidate.exists():
    fail("queued collection did not atomically remove object and candidate")

# Refcount fsck diagnoses lifecycle inconsistency but never manufactures or
# deletes candidate/object state, including in repair mode.
require_ok(run(owner, "set", "FSCK_GC", "--value", "fsck"), "fsck GC seed", "")
fsck_gc_id = run(owner, "id", "FSCK_GC").stdout.strip()
require_ok(run(owner, "rm", "FSCK_GC"), "fsck GC removal", "")
fsck_candidate = candidate_files(owner_state)[0]
fsck_candidate.unlink()
expected_fsck_gc = (
    f"gc-candidate-inconsistency\t{fsck_gc_id}\tmissing-zero-reference\n"
)
for repair_args in ((), ("--repair",)):
    fsck_gc = run(
        owner,
        "fsck",
        "--format",
        "v2",
        "--refcount",
        *repair_args,
    )
    if (
        fsck_gc.returncode != 1
        or fsck_gc.stdout != expected_fsck_gc
        or fsck_gc.stderr != ""
    ):
        fail(f"fsck GC lifecycle diagnostic changed: {fsck_gc!r}")
    if not object_path(owner_state, fsck_gc_id).is_file() or candidate_files(owner_state):
        fail("fsck refcount changed candidate/object lifecycle state")
require_ok(run(owner, "gc", "--orphaned"), "fsck GC cleanup")
if object_path(owner_state, fsck_gc_id).exists():
    fail("manual orphan GC did not clean the fsck-diagnosed object")

# A cached positive count only delays the proof; forced queued GC finds the alias.
require_ok(run(owner, "set", "LINK_A", "--value", "linked"), "link seed", "")
link_id = run(owner, "id", "LINK_A").stdout.strip()
require_ok(run(owner, "ln", "LINK_A", "LINK_B"), "link alias", "")
require_ok(run(owner, "rm", "LINK_A"), "link removal", "")
files = candidate_files(owner_state)
if len(files) != 1:
    fail("shared removal did not write one candidate")
shared_record = dict(
    line.split("=", 1)
    for line in files[0].read_text(encoding="utf-8").splitlines()[1:]
)
delay = int(shared_record["next_attempt_at_ns"]) - int(shared_record["enqueued_at_ns"])
if delay != 3_600_000_000_000:
    fail(f"shared candidate did not use one-hour hint: {delay}")
shared_gc = run(owner, "gc", "--queued")
require_ok(shared_gc, "shared candidate proof")
if "\treferenced\n" not in shared_gc.stdout or not object_path(owner_state, link_id).is_file():
    fail(f"shared candidate proof deleted a referenced object: {shared_gc.stdout!r}")
if candidate_files(owner_state):
    fail("shared candidate proof did not cancel the candidate")
require_ok(run(owner, "rm", "LINK_B"), "link cleanup", "")
require_ok(run(owner, "gc", "--queued"), "link cleanup GC")

# A physically present but unregistered domain still protects a cross-domain link.
consumer, consumer_state = create_v2_domain("consumer")
require_ok(run(owner, "set", "REMOTE", "--value", "remote"), "remote seed", "")
remote_id = run(owner, "id", "REMOTE").stdout.strip()
require_ok(
    run(owner, "ln", "REMOTE", f"{consumer}/REMOTE_LINK"),
    "cross-domain link",
    "",
)
require_ok(run(owner, "rm", "REMOTE"), "cross-domain owner removal", "")
registry_root = state_root / "domains/registry/by-root"
registry_entry = next(
    path for path in registry_root.iterdir()
    if path.read_text(encoding="utf-8") == consumer_state.name
)
offline_registry = work_root / "consumer.registry.offline"
registry_entry.rename(offline_registry)
protected = run(owner, "gc", "--queued")
require_ok(protected, "physical unregistered reference proof")
if "\treferenced\n" not in protected.stdout or not object_path(owner_state, remote_id).is_file():
    fail("physical unregistered reference did not protect the owner object")
offline_registry.rename(registry_entry)
require_ok(run(consumer, "rm", "REMOTE_LINK"), "remote link cleanup", "")
require_ok(run(owner, "gc", "--queued"), "remote object cleanup")

# Corrupt work can be quarantined and explicitly dropped without deleting data.
require_ok(run(owner, "set", "CORRUPT", "--value", "retain"), "corrupt seed", "")
corrupt_id = run(owner, "id", "CORRUPT").stdout.strip()
require_ok(run(owner, "rm", "CORRUPT"), "corrupt removal", "")
corrupt_candidate = candidate_files(owner_state)[0]
handle = corrupt_candidate.stem
payload = corrupt_candidate.read_text(encoding="utf-8")
corrupt_candidate.write_text(payload.replace("SECDATGCCAND1", "BROKEN-GC", 1), encoding="utf-8")
corrupt_candidate.chmod(0o600)
corrupt_fsck = run(owner, "fsck", "--format", "v2", "--refcount")
expected_corrupt_fsck = (
    f"gc-candidate-inconsistency\t{corrupt_id}\tinvalid-record\n"
)
if (
    corrupt_fsck.returncode != 1
    or corrupt_fsck.stdout != expected_corrupt_fsck
    or corrupt_fsck.stderr != ""
):
    fail(f"corrupt candidate fsck diagnostic changed: {corrupt_fsck!r}")
error_status = status(owner, errors=True)
if error_status["corrupt"] != 1 or error_status["errors"][0]["handle"] != handle:
    fail(f"corrupt candidate was not addressable by handle: {error_status!r}")
require_ok(
    run(owner, "gc", "--quarantine-candidate", handle),
    "candidate quarantine",
)
if status(owner)["quarantined"] != 1 or not object_path(owner_state, corrupt_id).is_file():
    fail("candidate quarantine discarded object state")
require_ok(run(owner, "gc", "--drop-quarantine", handle), "drop quarantine")
if status(owner)["quarantined"] != 0 or not object_path(owner_state, corrupt_id).is_file():
    fail("drop quarantine deleted object state")

# A same-protocol owner agent without GC_WORKER_V1 triggers one handover
# attempt. Failure is diagnostic only; the foreground commit and queue remain.
handover_domain, handover_state = create_v2_domain("handover")
require_ok(run(handover_domain, "set", "HANDOVER_GC", "--value", "retain"), "handover seed", "")
handover_id = run(handover_domain, "id", "HANDOVER_GC").stdout.strip()
socket_dir = runtime_root / "secdat"
socket_dir.mkdir(mode=0o700, exist_ok=True)
socket_digest = hashlib.sha256(handover_state.name.encode()).hexdigest()[:32]
handover_socket_path = socket_dir / f"agent-{socket_digest}.sock"
fake_agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
fake_agent.bind(str(handover_socket_path))
fake_agent.listen()
fake_agent.settimeout(0.1)
fake_commands = []
fake_stop = threading.Event()


def serve_missing_gc_agent():
    while not fake_stop.is_set():
        try:
            connection, _ = fake_agent.accept()
        except socket.timeout:
            continue
        with connection:
            with connection.makefile("rwb") as stream:
                command = stream.readline().decode().strip()
                fake_commands.append(command)
                if command == "CAPS":
                    stream.write(b"OK 1 4 pid=0\n")
                else:
                    stream.write(b"INVALID-HANDOVER!")
                stream.flush()


fake_thread = threading.Thread(target=serve_missing_gc_agent, daemon=True)
fake_thread.start()
handover_rm = run(handover_domain, "rm", "HANDOVER_GC")
fake_stop.set()
fake_thread.join(timeout=3)
fake_agent.close()
handover_socket_path.unlink(missing_ok=True)
if (
    handover_rm.returncode != 0
    or handover_rm.stdout != ""
    or "owner agent could not be upgraded" not in handover_rm.stderr
    or fake_commands.count("CAPS") != 1
    or fake_commands.count("HANDOVER") != 1
):
    fail(
        "missing GC capability did not attempt one safe handover: "
        f"result={handover_rm} commands={fake_commands!r}"
    )
if not object_path(handover_state, handover_id).is_file() or not candidate_files(handover_state):
    fail("failed GC-agent handover discarded durable work")
require_ok(run(handover_domain, "gc", "--queued"), "handover retained work cleanup")

# An exact-local persistent writable agent discovers durable work after debounce.
agent, agent_state = create_v2_domain("agent")
unlock = run(
    agent,
    "unlock",
    "--duration",
    "PT2M",
    extra_env={"SECDAT_MASTER_KEY_PASSPHRASE": "deferred-gc-passphrase"},
)
if unlock.returncode != 0 or "session unlocked" not in unlock.stdout:
    fail(f"persistent agent unlock failed: {unlock}")
without_env = {"SECDAT_MASTER_KEY": "", "SECDAT_MASTER_KEY_PASSPHRASE": ""}
require_ok(run(agent, "set", "AUTO", "--value", "auto", extra_env=without_env), "auto seed", "")
auto_id = run(agent, "id", "AUTO", extra_env=without_env).stdout.strip()
require_ok(run(agent, "rm", "AUTO", extra_env=without_env), "auto removal", "")
deadline = time.monotonic() + 6
while time.monotonic() < deadline and object_path(agent_state, auto_id).exists():
    time.sleep(0.2)
if object_path(agent_state, auto_id).exists() or candidate_files(agent_state):
    fail("persistent exact-local agent did not collect deferred work")
require_ok(run(agent, "lock", extra_env=without_env), "agent lock")

# The agent services socket work between bounded reference-scan chunks.
responsive, responsive_state = create_v2_domain("responsive")
for index in range(80):
    require_ok(
        run(responsive, "set", f"BULK_{index:03d}", "--value", "bulk"),
        f"responsive bulk seed {index}",
        "",
    )
require_ok(run(responsive, "set", "RESPONSIVE", "--value", "target"), "responsive target", "")
responsive_id = run(responsive, "id", "RESPONSIVE").stdout.strip()
scan_signal = work_root / "gc-scan-started"
responsive_unlock = run(
    responsive,
    "unlock",
    "--duration",
    "PT2M",
    extra_env={
        "SECDAT_MASTER_KEY_PASSPHRASE": "deferred-gc-passphrase",
        "SECDAT_TEST_GC_SCAN_ENTRY_DELAY_US": "5000",
        "SECDAT_TEST_GC_SCAN_SIGNAL_PATH": str(scan_signal),
    },
)
if responsive_unlock.returncode != 0:
    fail(f"responsive agent unlock failed: {responsive_unlock}")
require_ok(
    run(responsive, "rm", "RESPONSIVE", extra_env=without_env),
    "responsive removal",
    "",
)
signal_deadline = time.monotonic() + 6
while time.monotonic() < signal_deadline and not scan_signal.exists():
    time.sleep(0.01)
if not scan_signal.exists():
    fail("agent reference scan did not reach a checkpoint")
request_started = time.monotonic()
require_ok(
    run(responsive, "status", "--quiet", extra_env=without_env),
    "status during GC scan",
    "",
)
request_elapsed = time.monotonic() - request_started
if request_elapsed >= 0.30:
    fail(f"agent did not service socket work between scan chunks: {request_elapsed:.3f}s")
responsive_deadline = time.monotonic() + 8
while time.monotonic() < responsive_deadline and object_path(responsive_state, responsive_id).exists():
    time.sleep(0.1)
if object_path(responsive_state, responsive_id).exists():
    fail("bounded agent scan did not eventually collect the target")
require_ok(run(responsive, "lock", extra_env=without_env), "responsive agent lock")

# Readonly and volatile exact-local agents retain durable work until an eligible
# persistent session or an explicit manual pass becomes available.
mode_domain, mode_state = create_v2_domain("agent-modes")
require_ok(run(mode_domain, "set", "READONLY_GC", "--value", "retain"), "readonly seed", "")
readonly_id = run(mode_domain, "id", "READONLY_GC").stdout.strip()
require_ok(run(mode_domain, "rm", "READONLY_GC"), "readonly candidate", "")
readonly_unlock = run(
    mode_domain,
    "unlock",
    "--readonly",
    "--duration",
    "PT2M",
    extra_env={"SECDAT_MASTER_KEY_PASSPHRASE": "deferred-gc-passphrase"},
)
if readonly_unlock.returncode != 0:
    fail(f"readonly agent unlock failed: {readonly_unlock}")
time.sleep(2)
if not object_path(mode_state, readonly_id).exists() or not candidate_files(mode_state):
    fail("readonly agent mutated deferred GC work")
persistent_unlock = run(
    mode_domain,
    "unlock",
    "--duration",
    "PT2M",
    extra_env={"SECDAT_MASTER_KEY_PASSPHRASE": "deferred-gc-passphrase"},
)
if persistent_unlock.returncode != 0:
    fail(f"persistent mode replacement failed: {persistent_unlock}")
mode_deadline = time.monotonic() + 15
while time.monotonic() < mode_deadline and object_path(mode_state, readonly_id).exists():
    time.sleep(0.1)
if object_path(mode_state, readonly_id).exists() or candidate_files(mode_state):
    mode_session = run(mode_domain, "status", extra_env=without_env)
    mode_secret = run(
        mode_domain,
        "secret",
        "status",
        "--gc",
        readonly_id,
        extra_env=without_env,
    )
    reference_files = []
    for entry_file in by_id.rglob("*.dent"):
        if readonly_id.encode() in entry_file.read_bytes():
            reference_files.append(str(entry_file.relative_to(by_id)))
    mode_gc_status = status(mode_domain, errors=True)
    # The asynchronous delete can commit between the deadline read and these
    # diagnostics. Re-read both filesystem surfaces before declaring failure.
    if object_path(mode_state, readonly_id).exists() or candidate_files(mode_state):
        fail(
            "persistent mode did not resume readonly deferred work: "
            f"session={mode_session!r} secret={mode_secret!r} "
            f"gc={mode_gc_status!r} refs={reference_files!r}"
        )
require_ok(run(mode_domain, "lock", extra_env=without_env), "mode persistent lock")

require_ok(run(mode_domain, "set", "VOLATILE_GC", "--value", "retain"), "volatile seed", "")
volatile_id = run(mode_domain, "id", "VOLATILE_GC").stdout.strip()
require_ok(run(mode_domain, "rm", "VOLATILE_GC"), "volatile candidate", "")
volatile_unlock = run(
    mode_domain,
    "unlock",
    "--volatile",
    "--duration",
    "PT2M",
    extra_env={"SECDAT_MASTER_KEY_PASSPHRASE": "deferred-gc-passphrase"},
)
if volatile_unlock.returncode != 0:
    fail(f"volatile agent unlock failed: {volatile_unlock}")
time.sleep(2)
if not object_path(mode_state, volatile_id).exists() or not candidate_files(mode_state):
    fail("volatile agent mutated deferred GC work")
require_ok(run(mode_domain, "lock", extra_env=without_env), "volatile agent lock")
require_ok(run(mode_domain, "gc", "--queued"), "volatile manual collection")
if object_path(mode_state, volatile_id).exists() or candidate_files(mode_state):
    fail("manual GC did not drain work retained by a volatile agent")

print("PASS deferred GC regression")
PY
