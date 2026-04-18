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
import re
import subprocess
import sys
import time
from pathlib import Path
import hashlib

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
for variable_name in (
    "SECDAT_MASTER_KEY",
    "SECDAT_MASTER_KEY_PASSPHRASE",
    "SECDAT_GET_ON_DEMAND_UNLOCK",
    "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS",
):
    env.pop(variable_name, None)
passphrase = "passphrase-for-session-test"
wrapped_path = Path(env["XDG_DATA_HOME"]) / "secdat" / "master-key.bin"
isolated_root = Path(env["XDG_RUNTIME_DIR"]).parent
root_domain = isolated_root / "domain-root"
child_domain = root_domain / "child-domain"
grandchild_domain = child_domain / "grandchild-domain"
sibling_domain = isolated_root / "sibling-domain"

def scoped(args, domain=root_domain):
    return [bin_path, "--dir", str(domain), *args]

def socket_path_for(domain):
    digest = hashlib.sha256(str(domain).encode()).hexdigest()[:32]
    return Path(env["XDG_RUNTIME_DIR"]) / "secdat" / f"agent-{digest}.sock"

def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)

def assert_contains(output, fragment, context):
    if fragment not in output:
        fail(f"{context}: missing fragment {fragment!r} in {output!r}")

def normalize_spaces(text):
    return re.sub(r"[ \t]+", " ", text)

def description_column(output, label):
    prefix = f"  {label}"
    for line in output.splitlines():
        if line.startswith(prefix):
            suffix = line[len(prefix):]
            stripped = suffix.lstrip(" ")
            if stripped == "":
                fail(f"missing description after label {label!r} in line {line!r}")
            return len(line) - len(stripped)
    fail(f"missing line for label {label!r} in output {output!r}")

def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr

def run_background(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    return subprocess.Popen(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run_env)

def run_pty(args, prompts, extra_env=None, eof_after_prompts=False):
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

        if eof_after_prompts:
            os.write(fd, b"\x04")

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

for domain in (root_domain, child_domain, grandchild_domain, sibling_domain):
    domain.mkdir(parents=True, exist_ok=True)

rc, stdout, stderr = run(scoped(["domain", "create"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"root domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "create"], child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "create"], grandchild_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"grandchild domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "create"], sibling_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"sibling domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, _, _ = run(scoped(["status", "--quiet"]))
if rc != 1:
    fail(f"status --quiet while locked returned {rc}")

rc, stdout, stderr = run(scoped(["set", "UNSAFE_VISIBLE_KEY", "--unsafe", "--value", "visible-while-locked"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set --unsafe while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "SAFE_HIDDEN_KEY", "--value", "hidden-while-locked"]))
if rc == 0 or "no active secdat session" not in stderr:
    fail(f"safe set while locked unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_VISIBLE_KEY", "-o"]))
if rc != 0 or stdout != "visible-while-locked" or stderr != "":
    fail(f"get unsafe key while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["ls", "--unsafe"]))
if rc != 0 or stdout != "UNSAFE_VISIBLE_KEY\n" or stderr != "":
    fail(f"ls --unsafe while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["ls", "--safe"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"ls --safe while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["list", "--unsafe"]))
if rc != 0 or stdout != "UNSAFE_VISIBLE_KEY\n" or stderr != "":
    fail(f"list --unsafe while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["list", "--safe"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"list --safe while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(scoped(["set", "UNSAFE_TTY_KEY", "--unsafe"]), [("", "typed-on-tty")], eof_after_prompts=True)
if rc != 0 or "refusing to read secret from a terminal" in transcript:
    fail(f"unsafe tty set failed unexpectedly: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_TTY_KEY", "-o"]))
if rc != 0 or stdout != "typed-on-tty\n" or stderr != "":
    fail(f"unsafe tty set should store terminal input: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(scoped(["get", "UNSAFE_VISIBLE_KEY", "-o"]), [])
if rc != 0 or "visible-while-locked" not in transcript or "refusing to write secret to a terminal" in transcript:
    fail(f"unsafe tty get failed unexpectedly: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["cp", "UNSAFE_VISIBLE_KEY", "UNSAFE_COPIED_KEY"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cp unsafe key while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_COPIED_KEY", "-o"]))
if rc != 0 or stdout != "visible-while-locked" or stderr != "":
    fail(f"get copied unsafe key while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["mv", "UNSAFE_COPIED_KEY", "UNSAFE_MOVED_KEY"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"mv unsafe key while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_MOVED_KEY", "-o"]))
if rc != 0 or stdout != "visible-while-locked" or stderr != "":
    fail(f"get moved unsafe key while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_COPIED_KEY", "-o"]))
if rc == 0 or "key not found: UNSAFE_COPIED_KEY" not in stderr:
    fail(f"moved unsafe source still visible while locked: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "VOLATILE_TOMBSTONE_KEY", "--unsafe", "--value", "persistent-value"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"persistent unsafe seed for volatile rm failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

volatile_env = {"SECDAT_MASTER_KEY": "volatile-master-key-for-tests"}

rc, stdout, stderr = run(scoped(["unlock", "--volatile"]), extra_env=volatile_env)
if rc != 0 or "volatile session unlocked from environment" not in stdout or "resolved domain:" not in stderr:
    fail(f"volatile unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"]))
if rc != 0 or "overlay: volatile\n" not in stdout or stderr != "":
    fail(f"volatile status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "VOLATILE_ONLY_KEY", "--value", "volatile-value"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "VOLATILE_ONLY_KEY", "-o"]))
if rc != 0 or stdout != "volatile-value" or stderr != "":
    fail(f"volatile get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["rm", "VOLATILE_TOMBSTONE_KEY"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile rm failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "VOLATILE_TOMBSTONE_KEY", "-o"]))
if rc == 0 or "key not found: VOLATILE_TOMBSTONE_KEY" not in stderr:
    fail(f"volatile tombstone should hide persistent key: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--volatile"], domain=child_domain), extra_env=volatile_env)
if rc != 0 or "volatile session unlocked from environment" not in stdout:
    fail(f"child volatile unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["mask", "UNSAFE_VISIBLE_KEY"], domain=child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile mask failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_VISIBLE_KEY", "-o"], domain=child_domain))
if rc == 0 or "key not found: UNSAFE_VISIBLE_KEY" not in stderr:
    fail(f"volatile mask should hide inherited key: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unmask", "UNSAFE_VISIBLE_KEY"], domain=child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile unmask failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_VISIBLE_KEY", "-o"], domain=child_domain))
if rc != 0 or stdout != "visible-while-locked" or stderr != "":
    fail(f"volatile unmask should restore inherited key: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"]))
if rc != 0 or stdout != "session locked\n" or stderr != "":
    fail(f"lock after volatile root session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["exists", "VOLATILE_ONLY_KEY"]))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"volatile-only key leaked after lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "VOLATILE_TOMBSTONE_KEY", "-o"]))
if rc != 0 or stdout != "persistent-value" or stderr != "":
    fail(f"persistent key should reappear after volatile lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], domain=child_domain))
if rc != 0 or stdout != "session locked\n" or stderr != "":
    fail(f"child lock after volatile session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "UNSAFE_VISIBLE_KEY", "-o"], domain=child_domain))
if rc != 0 or stdout != "visible-while-locked" or stderr != "":
    fail(f"inherited key should remain visible after child volatile lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")

readonly_env = {"SECDAT_MASTER_KEY": "readonly-master-key-for-tests"}

rc, stdout, stderr = run(scoped(["unlock", "--readonly"]), extra_env=readonly_env)
if rc != 0 or "readonly session unlocked from environment" not in stdout or "resolved domain:" not in stderr:
    fail(f"readonly unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"]))
if rc != 0 or "access: readonly\n" not in stdout or stderr != "":
    fail(f"readonly status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "READONLY_BLOCKED_KEY", "--value", "blocked"]))
if rc == 0 or "current session is readonly and cannot run set" not in stderr or f"unlock writable session: secdat --dir {root_domain} unlock" not in stderr:
    fail(f"readonly set should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock", "--save"]))
if rc == 0 or "lock --save requires a local volatile session" not in stderr:
    fail(f"lock --save should reject readonly session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"]))
if rc != 0 or stdout != "session locked\n" or stderr != "":
    fail(f"lock after readonly session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--volatile"]), extra_env=volatile_env)
if rc != 0 or "volatile session unlocked from environment" not in stdout or "resolved domain:" not in stderr:
    fail(f"volatile unlock for save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "SAVE_PERSISTED_KEY", "--unsafe", "--value", "persisted-after-save"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile unsafe set for save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["rm", "VOLATILE_TOMBSTONE_KEY"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"volatile rm for save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock", "--save"]))
if rc != 0 or stdout != "volatile session saved and locked\n" or stderr != "":
    fail(f"lock --save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "SAVE_PERSISTED_KEY", "-o"]))
if rc != 0 or stdout != "persisted-after-save" or stderr != "":
    fail(f"saved volatile key should persist after lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "VOLATILE_TOMBSTONE_KEY", "-o"]))
if rc == 0 or "key not found: VOLATILE_TOMBSTONE_KEY" not in stderr:
    fail(f"saved volatile tombstone should persist after lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for args, marker in [
    ([bin_path, "help", "status"], "[-d DIR|--dir DIR] status [-q|--quiet]"),
    ([bin_path, "--help", "status"], "[-d DIR|--dir DIR] status [-q|--quiet]"),
    ([bin_path, "-h", "status"], "[-d DIR|--dir DIR] status [-q|--quiet]"),
    ([bin_path, "status", "--help"], "[-d DIR|--dir DIR] status [-q|--quiet]"),
    ([bin_path, "status", "-h"], "[-d DIR|--dir DIR] status [-q|--quiet]"),
    ([bin_path, "help", "unlock"], "unlock [--inherit] [--volatile|--readonly] [--descendants] [--yes]"),
    ([bin_path, "help", "inherit"], "[-d DIR|--dir DIR] inherit"),
    ([bin_path, "help", "lock"], "[-d DIR|--dir DIR] lock [--inherit] [--save]"),
    ([bin_path, "help", "list"], "list [--masked] [--overridden] [--orphaned] [--safe] [--unsafe]"),
    ([bin_path, "help", "mask"], "mask KEYREF"),
    ([bin_path, "help", "unmask"], "unmask KEYREF"),
    ([bin_path, "help", "exists"], "exists KEYREF"),
    ([bin_path, "help", "ls"], "[--safe|--unsafe]"),
    ([bin_path, "help", "get"], "[--on-demand-unlock] [--unlock-timeout SECONDS] KEYREF"),
    ([bin_path, "help", "wait-unlock"], "wait-unlock [--timeout SECONDS] [-q|--quiet]"),
    ([bin_path, "help", "exec"], "--pattern-exclude GLOBPATTERN"),
    ([bin_path, "help", "rm"], "rm [--ignore-missing] KEYREF"),
    ([bin_path, "help", "set"], "set KEYREF [--unsafe]"),
    ([bin_path, "help", "export"], "export [-p GLOBPATTERN|--pattern GLOBPATTERN]"),
    ([bin_path, "help", "passwd"], "passwd"),
    ([bin_path, "help", "domain"], "domain ls [-l|--long] [-a|--inherited]"),
    ([bin_path, "store", "--help"], "store create STORE"),
    ([bin_path, "store", "-h"], "store create STORE"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    normalized_output = normalize_spaces(output)
    if (
        rc != 0
        or marker not in normalized_output
        or "Help:" not in output
        or "Support:" not in output
        or "issues: https://github.com/mako10k/secdat/issues" not in normalized_output
        or "author: Makoto Katsumata <mako10k@mk10.org>" not in normalized_output
        or "Semantics:" not in output
        or "Meaning:" not in output
        or "DIR:" not in normalized_output
        or "DOMAIN:" not in normalized_output
        or "STORE:" not in normalized_output
        or "KEY / KEYREF:" not in normalized_output
    ):
        fail(f"help check failed for {args}: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "help", "get"])
output = stdout + stderr
if rc != 0 or "Use cases:" not in output or "read one value to stdout:" not in output or "wait for another terminal to unlock before reading:" not in output:
    fail(f"get use cases help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help", "usecases"])
output = stdout + stderr
if rc != 0 or "Meaning:" not in output or "Use cases:" not in output or "bootstrap a new project domain:" not in output or "block automation until a human unlocks the domain elsewhere:" not in output:
    fail(f"usecases topic help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help", "concepts"])
output = stdout + stderr
if rc != 0 or "Meaning:" not in output or "Concepts:" not in output or "explicit lock:" not in output or "KEYREF:" not in output:
    fail(f"concepts topic help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help"])
output = stdout + stderr
normalized_output = normalize_spaces(output)
if rc != 0 or "[options] subcommand ..." not in normalized_output or "Options:" not in output or "Commands:" not in output or "Topics:" not in output or "Support:" not in output or "issues: https://github.com/mako10k/secdat/issues" not in normalized_output or "help: show global help" not in normalized_output or "version: print the secdat version" not in normalized_output:
    fail(f"help subcommand check failed: rc={rc} output={output!r}")

for args, expected in [
    ([bin_path, "unlock", "--bad"], f"Try: {bin_path} help unlock"),
    ([bin_path, "unlock", "--volatile", "--readonly"], f"Try: {bin_path} help unlock"),
    ([bin_path, "--store", "default", "status"], f"Try: {bin_path} help status"),
    ([bin_path, "store", "create"], f"Try: {bin_path} help store"),
    ([bin_path, "get", "KEY", "--bad"], f"Try: {bin_path} help get"),
    ([bin_path, "get", "--unlock-timeout", "1", "KEY"], "--unlock-timeout requires --on-demand-unlock or SECDAT_GET_ON_DEMAND_UNLOCK"),
    ([bin_path, "wait-unlock", "--bad"], f"Try: {bin_path} help wait-unlock"),
    ([bin_path, "set", "KEY", "--bad"], f"Try: {bin_path} help set"),
    ([bin_path, "cp", "ONLY_ONE"], f"Try: {bin_path} help cp"),
    ([bin_path, "mv", "ONLY_ONE"], f"Try: {bin_path} help mv"),
    ([bin_path, "rm"], f"Try: {bin_path} help rm"),
    ([bin_path, "exec"], f"Try: {bin_path} help exec"),
    ([bin_path, "passwd", "--bad"], f"Try: {bin_path} help passwd"),
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
normalized_output = normalize_spaces(output)
if rc != 0 or "[options] subcommand ..." not in normalized_output or "Options:" not in output or "-d, --dir DIR" not in normalized_output or "Commands:" not in output or "Topics:" not in output or "Groups:" not in output or "Support:" not in output or "repository: https://github.com/mako10k/secdat" not in normalized_output or "help usecases" not in normalized_output or "help concepts" not in normalized_output or "--help COMMAND" not in normalized_output or "COMMAND --help" not in normalized_output or "--version" not in normalized_output:
    fail(f"global help check failed: rc={rc} output={output!r}")

help_column = description_column(output, "help:")
get_column = description_column(output, "get:")
wait_unlock_column = description_column(output, "wait-unlock:")
if help_column != get_column or get_column != wait_unlock_column:
    fail(f"command help alignment mismatch: help={help_column} get={get_column} wait-unlock={wait_unlock_column} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help"], {"LANGUAGE": "ja", "LC_ALL": ""})
output = stdout + stderr
if rc != 0 or "トピック:" not in output or "show global help, or combine with COMMAND or TOPIC for detailed help" in output or "decrypt one resolved key and write it to standard output; --on-demand-unlock waits for another terminal to unlock" in output or "explain domains, stores, inheritance, sessions, and KEYREF resolution" in output:
    fail(f"japanese global help translation check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help", "get"], {"LANGUAGE": "ja", "LC_ALL": ""})
output = stdout + stderr
if rc != 0 or "利用例:" not in output or "意味:" not in output or "read one value to stdout:" in output or "wait for another terminal to unlock before reading:" in output:
    fail(f"japanese get help translation check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--version"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Issues: https://github.com/mako10k/secdat/issues" not in output or "Author: Makoto Katsumata <mako10k@mk10.org>" not in output:
    fail(f"--version failed: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "version"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Repository: https://github.com/mako10k/secdat" not in output:
    fail(f"version failed: rc={rc} output={(stdout + stderr)!r}")

rc, stdout, stderr = run([bin_path, "-V"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Issues: https://github.com/mako10k/secdat/issues" not in output:
    fail(f"-V failed: rc={rc} output={(stdout + stderr)!r}")

rc, transcript = run_pty(
    scoped(["unlock"]),
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
)
if rc != 0 or f"resolved domain: {root_domain}" not in transcript or "persistent master key initialized; session unlocked" not in transcript:
    fail(f"bootstrap unlock failed: rc={rc} transcript={transcript!r}")
if "note: 2 descendant domains remain locked under this branch" not in transcript:
    fail(f"bootstrap unlock coverage summary missing: transcript={transcript!r}")
if not wrapped_path.is_file():
    fail("wrapped master key was not created")

rc, stdout, _ = run(scoped(["status"], root_domain))
if rc != 0 or "source: session agent" not in stdout or "wrapped master key: present" not in stdout:
    fail(f"status after bootstrap unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, _ = run(scoped(["status", "-q"], child_domain))
if rc != 1 or stdout != "":
    fail(f"status -q in child after parent unlock unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly unlocked by ancestor child path: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock before reconnect check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout or "note: 2 descendant domains remain locked under this branch\n" not in stdout:
    fail(f"root unlock before shadow check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"root unlock prompt context missing: stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "PARENT_UNLOCK_VISIBLE", "-v", "visible-from-parent"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"root set for explicit-lock coverage failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], child_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"child status after explicit lock unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], grandchild_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"grandchild status after parent explicit lock unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"domain status after explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective state: locked\n", "domain status explicit lock")
assert_contains(stdout, "effective source: explicit lock\n", "domain status explicit lock")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after parent explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: blocked by explicit lock\n", "grandchild blocked status")
assert_contains(stdout, f"blocked by: {child_domain}\n", "grandchild blocked status")

rc, stdout, stderr = run(scoped(["domain", "ls", "-l", "--descendants"], root_domain))
if rc != 0 or stderr != "":
    fail(f"domain ls -l after explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "domain ls -l header")
assert_contains(stdout, f"{child_domain}\tlocked\tlocked\texplicit-lock", "domain ls explicit-lock row")
assert_contains(stdout, f"{grandchild_domain}\tlocked\tlocked\tblocked:{child_domain}", "domain ls blocked row")

rc, stdout, stderr = run(scoped(["get", "PARENT_UNLOCK_VISIBLE", "-o"], child_domain))
if rc == 0 or "no active secdat session" not in stderr:
    fail(f"child unexpectedly reused ancestor session after explicit lock: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "locked read resolved domain guidance")
assert_contains(stderr, f"inspect current domain: secdat --dir {child_domain} domain status\n", "locked read status guidance")
assert_contains(stderr, f"unlock current domain: secdat --dir {child_domain} unlock\n", "locked read unlock guidance")

pending = run_background(scoped(["wait-unlock", "--timeout", "5"], child_domain))
time.sleep(0.5)
if pending.poll() is not None:
    fail("wait-unlock exited before unlock arrived")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"child unlock for wait-unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

stdout, stderr = pending.communicate(timeout=5)
if pending.returncode != 0 or stdout != "" or f"waiting for another terminal to unlock resolved domain: {child_domain}\n" not in stderr or f"unlock from another terminal: secdat --dir {child_domain} unlock\n" not in stderr or "wait-unlock timeout: 5 seconds\n" not in stderr:
    fail(f"wait-unlock failed: rc={pending.returncode} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock after wait-unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["wait-unlock", "--timeout", "1"], child_domain))
if rc == 0 or stdout != "" or f"waiting for another terminal to unlock resolved domain: {child_domain}\n" not in stderr or "timed out waiting for another terminal to unlock resolved domain after 1 seconds\n" not in stderr:
    fail(f"wait-unlock timeout failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

pending = run_background(scoped(["wait-unlock", "--timeout", "5", "--quiet"], child_domain))
time.sleep(0.5)
if pending.poll() is not None:
    fail("quiet wait-unlock exited before unlock arrived")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"child unlock for quiet wait-unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

stdout, stderr = pending.communicate(timeout=5)
if pending.returncode != 0 or stdout != "" or stderr != "":
    fail(f"quiet wait-unlock failed: rc={pending.returncode} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock after quiet wait-unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

pending = run_background(scoped(["get", "--on-demand-unlock", "--unlock-timeout", "5", "PARENT_UNLOCK_VISIBLE", "-o"], child_domain))
time.sleep(0.5)
if pending.poll() is not None:
    fail("on-demand unlock get exited before unlock arrived")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"child unlock for on-demand get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

stdout, stderr = pending.communicate(timeout=5)
if pending.returncode != 0 or stdout != "visible-from-parent" or f"waiting for another terminal to unlock secrets for resolved domain: {child_domain}\n" not in stderr or f"unlock from another terminal: secdat --dir {child_domain} unlock\n" not in stderr or "unlock wait timeout: 5 seconds\n" not in stderr:
    fail(f"on-demand unlock get failed: rc={pending.returncode} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock after on-demand get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "--on-demand-unlock", "--unlock-timeout", "1", "PARENT_UNLOCK_VISIBLE", "-o"], child_domain))
if rc == 0 or stdout != "" or f"waiting for another terminal to unlock secrets for resolved domain: {child_domain}\n" not in stderr or "timed out waiting for another terminal to unlock secrets after 1 seconds\n" not in stderr:
    fail(f"on-demand timeout get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

pending = run_background(
    scoped(["get", "PARENT_UNLOCK_VISIBLE", "-o"], child_domain),
    {"SECDAT_GET_ON_DEMAND_UNLOCK": "1", "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS": "5"},
)
time.sleep(0.5)
if pending.poll() is not None:
    fail("env-default on-demand get exited before unlock arrived")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"child unlock for env-default on-demand get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

stdout, stderr = pending.communicate(timeout=5)
if pending.returncode != 0 or stdout != "visible-from-parent" or "unlock wait timeout: 5 seconds\n" not in stderr:
    fail(f"env-default on-demand get failed: rc={pending.returncode} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock after env-default on-demand get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(
    scoped(["get", "PARENT_UNLOCK_VISIBLE", "-o"], child_domain),
    {"SECDAT_GET_ON_DEMAND_UNLOCK": "1", "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS": "1"},
)
if rc == 0 or stdout != "" or "timed out waiting for another terminal to unlock secrets after 1 seconds\n" not in stderr:
    fail(f"env-default on-demand timeout get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout or "note: 1 descendant domains can now reuse this session\n" not in stdout:
    fail(f"env passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {child_domain}\n" not in stderr:
    fail(f"child unlock prompt context missing: stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock before descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--descendants"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc == 0 or "unlock --descendants requires confirmation on a terminal or rerun with --yes\n" not in stderr:
    fail(f"non-interactive descendant unlock without --yes should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(
    scoped(["unlock", "--descendants"], root_domain),
    [
        ("unlock descendant domains in this subtree? explicit lock markers will remain [y/N]: ", "y"),
        ("Enter secdat passphrase:", passphrase),
    ],
)
if rc != 0 or f"resolved domain: {root_domain}" not in transcript or "this will unlock 2 descendant domains in the current subtree" not in transcript:
    fail(f"interactive descendant unlock failed: rc={rc} transcript={transcript!r}")
if "note: unlocked 2 descendant domains in this subtree; explicit lock markers remain" not in transcript:
    fail(f"interactive descendant unlock summary missing: transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local session\n", "child local session after descendant unlock")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local session\n", "grandchild local session after descendant unlock")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock before --yes descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--descendants", "--yes"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "note: unlocked 1 descendant domains in this subtree; explicit lock markers remain\n" not in stdout:
    fail(f"descendant unlock with --yes failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "unlock descendant domains in this subtree? explicit lock markers will remain [y/N]: " in stderr:
    fail(f"--yes descendant unlock should not prompt: stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child status after descendant unlock unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], grandchild_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"grandchild status after descendant unlock unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local session\n", "child local status after descendant unlock")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local session\n", "grandchild local status after descendant unlock")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly unlocked by child session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

new_passphrase = "rotated-passphrase-for-session-test"
rc, transcript = run_pty(
    [bin_path, "passwd"],
    [("Create new secdat passphrase:", new_passphrase), ("Confirm new secdat passphrase:", new_passphrase)],
    {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase},
)
if rc != 0 or "persistent master key passphrase updated" not in transcript:
    fail(f"passwd rotation failed: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock after passwd rotation failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": new_passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"unlock with rotated env passphrase failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"rotated unlock prompt context missing: stderr={stderr!r}")
assert_contains(stdout, f"note: 1 descendant domains remain locked under this branch\n", "guided unlock count")
assert_contains(stdout, "affected descendants:\n", "guided unlock header")
assert_contains(stdout, f"  {child_domain}\n", "guided unlock child descendant")
assert_contains(stdout, f"inspect descendants: secdat --dir {root_domain} domain ls -l --descendants\n", "guided unlock descendants command")
assert_contains(stdout, f"inspect one descendant: secdat --dir {child_domain} domain status\n", "guided unlock status command")
assert_contains(stdout, f"unlock one descendant: secdat --dir {child_domain} unlock\n", "guided unlock unlock command")

socket_path = socket_path_for(root_domain)
socket_path.parent.mkdir(parents=True, exist_ok=True)
if socket_path.exists() or socket_path.is_socket():
    socket_path.unlink()
socket_path.write_text("stale")
rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY": "session-test-key"})
if rc != 0 or "session unlocked from environment\n" not in stdout or f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"stale socket unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "note: 2 descendant domains can now reuse this session\n" not in stdout:
    fail(f"stale socket unlock guidance missing: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"], root_domain))
if rc != 0 or "source: session agent" not in stdout or stderr != "":
    fail(f"status after reconnect unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"second lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, _ = run(scoped(["status", "-q"], root_domain))
if rc != 1 or stdout != "":
    fail(f"status -q after lock unexpected: rc={rc} stdout={stdout!r}")

rc, transcript = run_pty(scoped(["unlock"], root_domain), [("Enter secdat passphrase:", new_passphrase)])
if rc != 0 or f"resolved domain: {root_domain}" not in transcript or "session unlocked" not in transcript:
    fail(f"passphrase unlock failed: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["set", "SESSION_KEY", "-v", "value"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "MISSING_KEY", "-o"], root_domain))
output = stdout + stderr
if rc == 0 or "key not found: MISSING_KEY" not in output or "Hint: check secdat status, --dir, and --store" not in output:
    fail(f"missing key guidance failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["get", "SESSION_KEY", "-o"], root_domain))
if rc != 0 or stdout != "value" or stderr != "":
    fail(f"get after passphrase unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked" or stderr != "":
    fail(f"lock before expiry check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY": "session-test-key", "SECDAT_SESSION_IDLE_SECONDS": "1"})
if rc != 0 or "session unlocked from environment" not in stdout:
    fail(f"short-timeout unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

time.sleep(5)

rc, stdout, stderr = run(scoped(["status", "-q"], root_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"status -q after expiry unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["get", "SESSION_KEY", "-o"], root_domain))
if rc == 0 or "missing SECDAT_MASTER_KEY and no active secdat session" not in stderr:
    fail(f"expired session get unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(
    scoped(["unlock"], root_domain),
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {"SECDAT_MASTER_KEY": "migration-master-key"},
)
if rc != 0 or "session unlocked from environment" not in transcript:
    fail(f"environment override failed: rc={rc} transcript={transcript!r}")

fresh_runtime = isolated_root / "runtime-migrate"
fresh_data = isolated_root / "data-migrate"
fresh_domain = isolated_root / "domain-migrate"
fresh_runtime.mkdir(parents=True, exist_ok=True)
fresh_data.mkdir(parents=True, exist_ok=True)
fresh_domain.mkdir(parents=True, exist_ok=True)
fresh_wrapped = fresh_data / "secdat" / "master-key.bin"

rc, stdout, stderr = run([bin_path, "--dir", str(fresh_domain), "domain", "create"], {"XDG_RUNTIME_DIR": str(fresh_runtime), "XDG_DATA_HOME": str(fresh_data)})
if rc != 0 or stdout != "" or stderr != "":
    fail(f"fresh domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(fresh_domain), "unlock"],
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

default_runtime = isolated_root / "runtime-default"
default_data = isolated_root / "data-default"
default_scope = isolated_root / "default-scope"
default_runtime.mkdir(parents=True, exist_ok=True)
default_data.mkdir(parents=True, exist_ok=True)
default_scope.mkdir(parents=True, exist_ok=True)

rc, transcript = run_pty(
    [bin_path, "--dir", str(default_scope), "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {
        "XDG_RUNTIME_DIR": str(default_runtime),
        "XDG_DATA_HOME": str(default_data),
    },
)
if rc != 0 or "resolved domain: *default*" not in transcript or "persistent master key initialized; session unlocked" not in transcript:
    fail(f"default-domain bootstrap unlock failed: rc={rc} transcript={transcript!r}")
if "failed to resolve directory:" in transcript:
    fail(f"default-domain unlock emitted spurious guidance error: transcript={transcript!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "domain", "status"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-scope domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "resolved domain: *default*\n", "default-scope domain status label")
assert_contains(stdout, "key source: session agent\n", "default-scope domain status key source")
assert_contains(stdout, "effective source: local session\n", "default-scope domain status local session")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "domain", "ls", "-la"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-scope domain ls -la failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "default-scope domain ls -la header")
assert_contains(stdout, "*default*\tsession\tunlocked\tlocal-session\t0\t0\tpresent\n", "default-scope domain ls -la fallback row")
PY

printf 'PASS session regression\n'