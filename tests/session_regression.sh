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
import shutil
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
passphrase = "passphrase-for-session-test"
wrapped_path = Path(env["XDG_DATA_HOME"]) / "secdat" / "master-key.bin"

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
    ([bin_path, "--help", "status"], "status [-q|--quiet]"),
    ([bin_path, "-h", "status"], "status [-q|--quiet]"),
    ([bin_path, "status", "--help"], "status [-q|--quiet]"),
    ([bin_path, "status", "-h"], "status [-q|--quiet]"),
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

rc, stdout, stderr = run([bin_path, "--help"])
output = stdout + stderr
if rc != 0 or "[options] subcommand ..." not in output or "Options:" not in output or "-d, --dir DIR" not in output or "Commands:" not in output or "Groups:" not in output or "--help COMMAND" not in output or "COMMAND --help" not in output or "--version" not in output:
    fail(f"global help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--version"])
if rc != 0 or not (stdout + stderr).startswith("secdat "):
    fail(f"--version failed: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "-V"])
if rc != 0 or not (stdout + stderr).startswith("secdat "):
    fail(f"-V failed: rc={rc} output={(stdout + stderr)!r}")

rc, transcript = run_pty(
    [bin_path, "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {"SECDAT_MASTER_KEY": "session-test-key"},
)
if rc != 0 or "persistent master key initialized; session unlocked from environment" not in transcript:
    fail(f"bootstrap unlock failed: rc={rc} transcript={transcript!r}")
if not wrapped_path.is_file():
    fail("wrapped master key was not created")

env.pop("SECDAT_MASTER_KEY", None)
rc, stdout, _ = run([bin_path, "status"])
if rc != 0 or "source: session agent" not in stdout or "wrapped master key: present" not in stdout:
    fail(f"status after bootstrap unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, _ = run([bin_path, "status", "-q"])
if rc != 0 or stdout != "":
    fail(f"status -q after unlock unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, _ = run([bin_path, "lock"])
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock failed: rc={rc} stdout={stdout!r}")

rc, stdout, _ = run([bin_path, "status", "-q"])
if rc != 1 or stdout != "":
    fail(f"status -q after lock unexpected: rc={rc} stdout={stdout!r}")

rc, transcript = run_pty([bin_path, "unlock"], [("Enter secdat passphrase:", passphrase)])
if rc != 0 or "session unlocked" not in transcript:
    fail(f"passphrase unlock failed: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run([bin_path, "set", "SESSION_KEY", "-v", "value"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "get", "SESSION_KEY", "-o"])
if rc != 0 or stdout != "value" or stderr != "":
    fail(f"get after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
PY

printf 'PASS session regression\n'