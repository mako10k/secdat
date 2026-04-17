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
import unicodedata
from pathlib import Path

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "lower-level-test-master-key"
env["SECDAT_MASTER_KEY_PASSPHRASE"] = "lower-level-test-passphrase"

work_root = Path(env["XDG_RUNTIME_DIR"]).parent
root_domain = work_root / "root-domain"
child_domain = root_domain / "child-domain"
grandchild_domain = child_domain / "grandchild-domain"
sibling_domain = work_root / "sibling-domain"
long_named_domain = work_root / "domain-with-an-extremely-long-name-for-terminal-layout-check"

for path in (root_domain, child_domain, grandchild_domain, sibling_domain, long_named_domain):
    path.mkdir(parents=True, exist_ok=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        for key, value in extra_env.items():
            if value is None:
                run_env.pop(key, None)
            else:
                run_env[key] = value
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def run_pty(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        for key, value in extra_env.items():
            if value is None:
                run_env.pop(key, None)
            else:
                run_env[key] = value

    pid, fd = pty.fork()
    if pid == 0:
        os.execve(args[0], args, run_env)

    chunks = []
    try:
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


def assert_contains(text, fragment, label):
    if fragment not in text:
        fail(f"{label}: missing {fragment!r} in {text!r}")


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected {expected!r}, got {actual!r}")


def display_width(text):
    width = 0
    for character in text:
        if character in "\r\n":
            continue
        width += 2 if unicodedata.east_asian_width(character) in ("F", "W") else 1
    return width


def display_index(text, needle):
    byte_index = text.find(needle)
    if byte_index < 0:
        fail(f"display_index missing {needle!r} in {text!r}")
    return display_width(text[:byte_index])


def scoped(args, domain=root_domain):
    return [bin_path, "--dir", str(domain), *args]


for domain in (root_domain, child_domain, grandchild_domain, sibling_domain, long_named_domain):
    rc, stdout, stderr = run(scoped(["domain", "create"], domain))
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"domain create failed for {domain}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["store", "create", "team"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain))
if rc != 0 or "session unlocked from environment\n" not in stdout:
    fail(f"root unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l"])
if rc != 0 or stderr != "":
    fail(f"non-tty domain ls -l failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "non-tty domain ls header")
assert_contains(stdout, f"{long_named_domain}\t", "non-tty domain retains full path")

rc, transcript = run_pty([bin_path, "--dir", str(work_root), "domain", "ls", "-l"])
if rc != 0:
    fail(f"tty domain ls -l failed: rc={rc} transcript={transcript!r}")
assert_contains(transcript, f"{work_root}/\r\n", "tty grouped parent heading")
assert_contains(transcript, "  sibling-domain", "tty relative sibling label")
assert_contains(transcript, f"  {long_named_domain.name}\r\n", "tty wrapped long domain label")
assert_contains(transcript, "environment  unlocked", "tty metadata line present")

rc, transcript = run_pty(
    [bin_path, "--dir", str(work_root), "domain", "ls", "-l"],
    {"LC_ALL": None, "LANGUAGE": "ja"},
)
if rc != 0:
    fail(f"localized tty domain ls -l failed: rc={rc} transcript={transcript!r}")
assert_contains(transcript, "アンロック済み", "localized effective label present")
assert_contains(transcript, "あり", "localized wrapped label present")

localized_lines = transcript.splitlines()
header_line = next((line for line in localized_lines if "KEY_SOURCE" in line and "EFFECTIVE" in line), None)
row_line = next((line for line in localized_lines if "  root-domain" in line and "environment" in line), None)
if header_line is None or row_line is None:
    fail(f"localized tty lines missing: header={header_line!r} row={row_line!r} transcript={transcript!r}")
assert_eq(display_index(row_line, "environment"), display_index(header_line, "KEY_SOURCE"), "localized key-source column alignment")
assert_eq(display_index(row_line, "アンロック済み"), display_index(header_line, "EFFECTIVE"), "localized effective column alignment")

env.pop("SECDAT_MASTER_KEY", None)

rc, stdout, stderr = run([bin_path, "set", f"{root_domain}/API_TOKEN:team", "-v", "team-token"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit keyref set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "get", f"{root_domain}/API_TOKEN:team", "-o"])
if rc != 0 or stderr != "":
    fail(f"explicit keyref get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "team-token", "explicit keyref value")

for bad_ref, expected in [
    (f"{root_domain}/API_TOKEN:", "invalid key reference"),
    (f"API_TOKEN/{root_domain}:team", "invalid key reference"),
    ("nested/API_TOKEN", "invalid key reference"),
    (f"{root_domain}/", "invalid key reference"),
]:
    rc, stdout, stderr = run([bin_path, "exists", bad_ref])
    if rc == 0 or expected not in stderr:
        fail(f"bad keyref {bad_ref!r} unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child did not inherit root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly inherited root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls -l plain locked state failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"{sibling_domain}\tlocked\tlocked\tno-session", "domain ls plain locked row")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session unlocked\nnote: 1 descendant domains can now reuse this session":
    fail(f"child local unlock before inherit checks failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "child local unlock resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local session\n", "child local status before checked inherit")

rc, stdout, stderr = run(scoped(["unlock", "--inherit"], child_domain))
if rc != 0 or stdout.strip() != "local session cleared; resulting state: unlocked":
    fail(f"unlock --inherit from local session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "unlock --inherit local-session resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local-session unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited session\n", "child inherited status after local-session unlock --inherit")
assert_contains(stdout, f"inherited from: {root_domain}\n", "child inherited source after local-session unlock --inherit")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session unlocked\nnote: 1 descendant domains can now reuse this session":
    fail(f"child second local unlock before unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["inherit"], child_domain))
if rc != 0 or stdout.strip() != "local session cleared":
    fail(f"unchecked inherit from local session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local-session inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited session\n", "child inherited status after local-session inherit")
assert_contains(stdout, f"inherited from: {root_domain}\n", "child inherited source after local-session inherit")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: explicit lock\n", "child explicit lock state")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: blocked by explicit lock\n", "grandchild blocked state")
assert_contains(stdout, f"blocked by: {child_domain}\n", "grandchild blocked source")

rc, stdout, stderr = run([bin_path, "--dir", str(child_domain), "--store", "team", "get", "API_TOKEN", "-o"])
if rc == 0 or "missing SECDAT_MASTER_KEY and no active secdat session" not in stderr:
    fail(f"child blocked read unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "blocked read resolved domain")
assert_contains(stderr, f"unlock current domain: secdat --dir {child_domain} unlock\n", "blocked read unlock guidance")

rc, stdout, stderr = run(scoped(["lock", "--inherit"], child_domain))
if rc == 0:
    fail(f"lock --inherit unexpectedly succeeded while parent session would unlock child: stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"refusing to remove local explicit lock for: {child_domain}\n", "lock --inherit refusal")
assert_contains(stderr, "expected resulting state: locked\n", "lock --inherit expected state")
assert_contains(stderr, "actual resulting state after removing local explicit lock: unlocked\n", "lock --inherit actual state")

rc, stdout, stderr = run(scoped(["unlock", "--inherit"], child_domain))
if rc != 0 or stdout.strip() != "local explicit lock removed; resulting state: unlocked":
    fail(f"unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "unlock --inherit resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited session\n", "child inherited status after unlock --inherit")
assert_contains(stdout, f"inherited from: {root_domain}\n", "child inherited source after unlock --inherit")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock before failed checked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"root lock before failed checked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--inherit"], child_domain))
if rc == 0:
    fail(f"unlock --inherit unexpectedly succeeded without an inherited unlock source: stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "failed unlock --inherit resolved domain")
assert_contains(stderr, f"refusing to remove local explicit lock for: {child_domain}\n", "unlock --inherit refusal")
assert_contains(stderr, "expected resulting state: unlocked\n", "unlock --inherit expected state")
assert_contains(stderr, "actual resulting state after removing local explicit lock: locked\n", "unlock --inherit actual state")

rc, stdout, stderr = run(scoped(["inherit"], child_domain))
if rc != 0 or stdout.strip() != "local explicit lock removed":
    fail(f"unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: locked\n", "child locked status after unchecked inherit")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": env["SECDAT_MASTER_KEY_PASSPHRASE"]})
if rc != 0 or stdout.strip() != "session unlocked\nnote: 2 descendant domains can now reuse this session":
    fail(f"root unlock after unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock after unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session unlocked\nnote: 1 descendant domains can now reuse this session":
    fail(f"child unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "child unlock resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild inherited status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited session\n", "grandchild inherited state")
assert_contains(stdout, f"inherited from: {child_domain}\n", "grandchild inherited source")
PY

printf 'PASS lower-level regression\n'