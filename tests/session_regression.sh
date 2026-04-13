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

python3 - "$bin_path" <<'PY'
import os
import pty
import subprocess
import sys
import time
from pathlib import Path

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
passphrase = "passphrase-for-session-test"
wrapped_path = Path(env["XDG_DATA_HOME"]) / "secdat" / "master-key.bin"
socket_path = Path(env["XDG_RUNTIME_DIR"]) / "secdat" / "agent.sock"
isolated_root = Path(env["XDG_RUNTIME_DIR"]).parent

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
                fail(f"missing prompt [{expected}] in [{' '.join(chunks)}]")
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

rc, _, _ = run([bin_path, "status", "--quiet"])
if rc != 1:
    fail(f"status --quiet while locked returned {rc}")

for args, marker in [
    ([bin_path, "help", "status"], "status [-q|--quiet]"),
    ([bin_path, "--help", "status"], "status [-q|--quiet]"),
    ([bin_path, "-h", "status"], "status [-q|--quiet]"),
    ([bin_path, "status", "--help"], "status [-q|--quiet]"),
    ([bin_path, "status", "-h"], "status [-q|--quiet]"),
    ([bin_path, "help", "export"], "bash load current shell vars: source <("),
    ([bin_path, "store", "--help"], "store create STORE"),
    ([bin_path, "store", "-h"], "store create STORE"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if (
        rc != 0
        or marker not in output
        or "Help:" not in output
        or "Semantics:" not in output
        or "Meaning:" not in output
        or "DIR:" not in output
        or "DOMAIN:" not in output
        or "STORE:" not in output
        or "KEY / KEYREF:" not in output
    ):
        fail(f"help check failed for {args}: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "help"])
output = stdout + stderr
if rc != 0 or "[options] subcommand ..." not in output or "Options:" not in output or "Commands:" not in output or "help: show global help" not in output or "version: print the secdat version" not in output:
    fail(f"help subcommand check failed: rc={rc} output={output!r}")

for args, expected in [
    ([bin_path, "unlock", "--bad"], f"Try: {bin_path} help unlock"),
    ([bin_path, "status", "--dir", "/tmp"], f"Try: {bin_path} help status"),
    ([bin_path, "store", "create"], f"Try: {bin_path} help store"),
    ([bin_path, "get", "KEY", "--bad"], f"Try: {bin_path} help get"),
    ([bin_path, "set", "KEY", "--bad"], f"Try: {bin_path} help set"),
    ([bin_path, "cp", "ONLY_ONE"], f"Try: {bin_path} help cp"),
    ([bin_path, "mv", "ONLY_ONE"], f"Try: {bin_path} help mv"),
    ([bin_path, "rm"], f"Try: {bin_path} help rm"),
    ([bin_path, "exec"], f"Try: {bin_path} help exec"),
    ([bin_path, "lock", "--bad"], f"Try: {bin_path} help lock"),
    ([bin_path, "store", "bogus"], f"Try: {bin_path} help store"),
    ([bin_path, "domain", "bogus"], f"Try: {bin_path} help domain"),
    ([bin_path, "bogus"], f"Try: {bin_path} help"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 2 or expected not in output:
        fail(f"recovery hint check failed for {args}: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "store", "create"])
output = stdout + stderr
if rc != 2 or "missing store name for store create" not in output:
    fail(f"missing operand check failed for store create: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help"])
output = stdout + stderr
if rc != 0 or "[options] subcommand ..." not in output or "Options:" not in output or "-d, --dir DIR" not in output or "Commands:" not in output or "Groups:" not in output or "--help COMMAND" not in output or "COMMAND --help" not in output or "--version" not in output:
    fail(f"global help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--version"])
if rc != 0 or not (stdout + stderr).startswith("secdat "):
    fail(f"--version failed: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "version"])
if rc != 0 or not (stdout + stderr).startswith("secdat "):
    fail(f"version failed: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "-V"])
if rc != 0 or not (stdout + stderr).startswith("secdat "):
    fail(f"-V failed: rc={rc} output={(stdout + stderr)!r}")

rc, transcript = run_pty(
    [bin_path, "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
)
if rc != 0 or "persistent master key initialized; session unlocked" not in transcript:
    fail(f"bootstrap unlock failed: rc={rc} transcript={transcript!r}")
if not wrapped_path.is_file():
    fail("wrapped master key was not created")

rc, stdout, _ = run([bin_path, "status"])
if rc != 0 or "source: session agent" not in stdout or "wrapped master key: present" not in stdout:
    fail(f"status after bootstrap unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, _ = run([bin_path, "status", "-q"])
if rc != 0 or stdout != "":
    fail(f"status -q after unlock unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, stderr = run([bin_path, "lock"])
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock before reconnect check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

socket_path.parent.mkdir(parents=True, exist_ok=True)
socket_path.write_text("stale")
rc, stdout, stderr = run([bin_path, "unlock"], {"SECDAT_MASTER_KEY": "session-test-key"})
if rc != 0 or stdout.strip() != "session unlocked from environment":
    fail(f"stale socket unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "status"])
if rc != 0 or "source: session agent" not in stdout or stderr != "":
    fail(f"status after reconnect unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "lock"])
if rc != 0 or stdout.strip() != "session locked":
    fail(f"second lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, _ = run([bin_path, "status", "-q"])
if rc != 1 or stdout != "":
    fail(f"status -q after lock unexpected: rc={rc} stdout={stdout!r}")

rc, transcript = run_pty([bin_path, "unlock"], [("Enter secdat passphrase:", passphrase)])
if rc != 0 or "session unlocked" not in transcript:
    fail(f"passphrase unlock failed: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run([bin_path, "set", "SESSION_KEY", "-v", "value"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "get", "MISSING_KEY", "-o"])
output = stdout + stderr
if rc == 0 or "key not found: MISSING_KEY" not in output or "Hint: check secdat status, --dir, and --store" not in output:
    fail(f"missing key guidance failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "get", "SESSION_KEY", "-o"])
if rc != 0 or stdout != "value" or stderr != "":
    fail(f"get after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "lock"])
if rc != 0 or stdout.strip() != "session locked" or stderr != "":
    fail(f"lock before expiry check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "unlock"], {"SECDAT_MASTER_KEY": "session-test-key", "SECDAT_SESSION_IDLE_SECONDS": "1"})
if rc != 0 or "session unlocked from environment" not in stdout:
    fail(f"short-timeout unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

time.sleep(5)

rc, stdout, stderr = run([bin_path, "status", "-q"])
if rc != 1 or stdout != "" or stderr != "":
    fail(f"status -q after expiry unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "get", "SESSION_KEY", "-o"])
if rc == 0 or "missing SECDAT_MASTER_KEY and no active secdat session" not in stderr:
    fail(f"expired session get unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(
    [bin_path, "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {"SECDAT_MASTER_KEY": "migration-master-key"},
)
if rc != 0 or "session unlocked from environment" not in transcript:
    fail(f"environment override failed: rc={rc} transcript={transcript!r}")

fresh_runtime = isolated_root / "runtime-migrate"
fresh_data = isolated_root / "data-migrate"
fresh_runtime.mkdir(parents=True, exist_ok=True)
fresh_data.mkdir(parents=True, exist_ok=True)
fresh_wrapped = fresh_data / "secdat" / "master-key.bin"

rc, transcript = run_pty(
    [bin_path, "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {
        "XDG_RUNTIME_DIR": str(fresh_runtime),
        "XDG_DATA_HOME": str(fresh_data),
        "SECDAT_MASTER_KEY": "migration-master-key",
    },
)
if rc != 0 or "persistent master key initialized; session unlocked from environment" not in transcript:
    fail(f"environment migration bootstrap failed: rc={rc} transcript={transcript!r}")
if not fresh_wrapped.is_file():
    fail("environment migration bootstrap did not create wrapped master key")
PY

printf 'PASS session regression\n'