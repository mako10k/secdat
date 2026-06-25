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
import json
import subprocess
import sys
import unicodedata
from pathlib import Path

bin_path = str(Path(sys.argv[1]).resolve())
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "lower-level-test-master-key"
env["SECDAT_MASTER_KEY_PASSPHRASE"] = "lower-level-test-passphrase"
japanese_env = {
    "LC_ALL": "",
    "LC_MESSAGES": "ja_JP.UTF-8",
    "LANG": "ja_JP.UTF-8",
    "LANGUAGE": "ja",
}

work_root = Path(env["XDG_RUNTIME_DIR"]).parent
root_domain = work_root / "root-domain"
child_domain = root_domain / "child-domain"
grandchild_domain = child_domain / "grandchild-domain"
sibling_domain = work_root / "sibling-domain"
orphaned_domain = work_root / "orphaned-domain"
long_named_domain = work_root / "domain-with-an-extremely-long-name-for-terminal-layout-check"

for path in (root_domain, child_domain, grandchild_domain, sibling_domain, orphaned_domain, long_named_domain):
    path.mkdir(parents=True, exist_ok=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None, cwd=None):
    run_env = env.copy()
    if extra_env:
        for key, value in extra_env.items():
            if value is None:
                run_env.pop(key, None)
            else:
                run_env[key] = value
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env, cwd=cwd)
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


for domain in (root_domain, child_domain, grandchild_domain, sibling_domain, orphaned_domain, long_named_domain):
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
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tREMAINING\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "non-tty domain ls header")
assert_contains(stdout, f"{long_named_domain}\t", "non-tty domain retains full path")

rc, stdout, stderr = run(scoped(["set", "ORPHANED_KEY", "orphaned-value"], orphaned_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"orphaned-domain set before orphaning failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

orphaned_domain.rmdir()

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls -l with orphaned root failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"{orphaned_domain}\torphaned\torphaned\t-\torphaned-domain\t1\t1\tpresent", "domain ls orphaned row")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "--json", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls --json with orphaned root failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
domain_rows = json.loads(stdout)["domains"]
orphaned_rows = [row for row in domain_rows if row["root"] == str(orphaned_domain)]
if len(orphaned_rows) != 1:
    fail(f"domain ls --json orphaned row count mismatch: {domain_rows!r}")
orphaned_row = orphaned_rows[0]
if orphaned_row["unlocked"]:
    fail(f"orphaned domain JSON row must not be unlocked: {orphaned_row!r}")
assert_eq(orphaned_row["key_source"], "orphaned", "orphaned domain JSON key source")
assert_eq(orphaned_row["effective_state"], "orphaned", "orphaned domain JSON effective state")
assert_eq(orphaned_row["effective_source"], "orphaned_domain", "orphaned domain JSON effective source")
if orphaned_row["session_expires_at"] is not None or orphaned_row["remaining_seconds"] is not None or orphaned_row["related_domain"] is not None:
    fail(f"orphaned domain JSON row must not expose session inheritance: {orphaned_row!r}")

rc, transcript = run_pty([bin_path, "--dir", str(work_root), "domain", "ls", "-l"])
if rc != 0:
    fail(f"tty domain ls -l failed: rc={rc} transcript={transcript!r}")
assert_contains(transcript, f"{work_root}/\r\n", "tty grouped parent heading")
assert_contains(transcript, "  sibling-domain", "tty relative sibling label")
assert_contains(transcript, f"  {long_named_domain.name}\r\n", "tty wrapped long domain label")
assert_contains(transcript, "environment  unlocked", "tty metadata line present")

rc, transcript = run_pty(
    [bin_path, "--dir", str(work_root), "domain", "ls", "-l"],
    japanese_env,
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

rc, stdout, stderr = run(scoped(["set", "BAD-KEY", "bad-value"]))
if rc == 0 or "key is not a valid environment variable name: BAD-KEY" not in stderr:
    fail(f"invalid key-name unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], child_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child did not inherit root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly inherited root session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls -l plain locked state failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"{sibling_domain}\tlocked\tlocked\t-\tlocked", "domain ls plain locked row")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session refreshed\nnote: 1 descendant domains can now reuse this session":
    fail(f"child local unlock before inherit checks failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "child local unlock resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local unlock\n", "child local status before checked inherit")

rc, stdout, stderr = run(scoped(["unlock", "--inherit"], child_domain))
if rc != 0 or stdout.strip() != "local unlock cleared; resulting state: unlocked":
    fail(f"unlock --inherit from local session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "unlock --inherit local-session resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local-session unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited unlock\n", "child inherited status after local-session unlock --inherit")
assert_contains(stdout, f"inherited from: {root_domain}\n", "child inherited source after local-session unlock --inherit")

rc, stdout, stderr = run(scoped(["unlock"], child_domain))
if rc != 0 or stdout.strip() != "session refreshed\nnote: 1 descendant domains can now reuse this session":
    fail(f"child second local unlock before unchecked inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["inherit"], child_domain))
if rc != 0 or stdout.strip() != "local unlock cleared":
    fail(f"unchecked inherit from local session failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after local-session inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited unlock\n", "child inherited status after local-session inherit")
assert_contains(stdout, f"inherited from: {root_domain}\n", "child inherited source after local-session inherit")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local lock\n", "child explicit lock state")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited lock\n", "grandchild blocked state")
assert_contains(stdout, f"inherited from: {child_domain}\n", "grandchild blocked source")

rc, stdout, stderr = run([bin_path, "--dir", str(child_domain), "--store", "team", "get", "API_TOKEN", "-o"])
if rc == 0 or "missing SECDAT_MASTER_KEY and no active secdat session" not in stderr:
    fail(f"child blocked read unexpectedly succeeded: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "blocked read resolved domain")
assert_contains(stderr, f"unlock current domain: secdat --dir {child_domain} unlock\n", "blocked read unlock guidance")

rc, stdout, stderr = run(scoped(["lock", "--inherit"], child_domain))
if rc == 0:
    fail(f"lock --inherit unexpectedly succeeded while parent session would unlock child: stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"refusing to remove local lock for: {child_domain}\n", "lock --inherit refusal")
assert_contains(stderr, "expected resulting state: locked\n", "lock --inherit expected state")
assert_contains(stderr, "actual resulting state after removing local lock: unlocked\n", "lock --inherit actual state")

rc, stdout, stderr = run(scoped(["unlock", "--inherit"], child_domain))
if rc != 0 or stdout.strip() != "local lock removed; resulting state: unlocked":
    fail(f"unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {child_domain}\n", "unlock --inherit resolved domain")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited unlock\n", "child inherited status after unlock --inherit")
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
assert_contains(stderr, f"refusing to remove local lock for: {child_domain}\n", "unlock --inherit refusal")
assert_contains(stderr, "expected resulting state: unlocked\n", "unlock --inherit expected state")
assert_contains(stderr, "actual resulting state after removing local lock: locked\n", "unlock --inherit actual state")

rc, stdout, stderr = run(scoped(["inherit"], child_domain))
if rc != 0 or stdout.strip() != "local lock removed":
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
assert_contains(stdout, "effective source: inherited unlock\n", "grandchild inherited state")
assert_contains(stdout, f"inherited from: {child_domain}\n", "grandchild inherited source")

mismatch_domain = work_root / "identity-mismatch-domain"
mismatch_moved_domain = work_root / "identity-mismatch-domain-moved"
mismatch_domain.mkdir()
rc, stdout, stderr = run(
    scoped(["domain", "create"], mismatch_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"identity mismatch domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

mismatch_domain.rename(mismatch_moved_domain)
mismatch_domain.mkdir()
rc, stdout, stderr = run(scoped(["domain", "status", "--quiet"], mismatch_domain))
if rc == 0 or stdout != "" or f"domain root identity mismatch for: {mismatch_domain}\n" not in stderr:
    fail(f"replacement domain did not fail closed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "--json"], mismatch_domain))
if rc == 0 or f"domain root identity mismatch for: {mismatch_domain}\n" not in stderr:
    fail(f"status --json did not fail closed on identity mismatch: rc={rc} stdout={stdout!r} stderr={stderr!r}")
mismatch_status = json.loads(stdout)
if mismatch_status["unlocked"] or mismatch_status["resolution_error"] != "domain_resolution_failed" or mismatch_status["resolved_domain"] is not None:
    fail(f"status --json did not expose resolution failure: {mismatch_status!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls with identity mismatch failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"{mismatch_domain}\torphaned\torphaned\t-\torphaned-domain", "domain ls identity mismatch row")

rc, stdout, stderr = run(scoped(["domain", "delete"], mismatch_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"identity mismatch domain delete failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(
    scoped(["domain", "create"], mismatch_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"identity mismatch replacement create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

symlink_domain = work_root / "identity-symlink-domain"
symlink_moved_domain = work_root / "identity-symlink-domain-moved"
symlink_domain.mkdir()
rc, stdout, stderr = run(
    scoped(["domain", "create"], symlink_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"identity symlink domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

symlink_domain.rename(symlink_moved_domain)
symlink_domain.symlink_to(symlink_moved_domain, target_is_directory=True)
rc, stdout, stderr = run(scoped(["domain", "status", "--quiet"], symlink_domain))
if rc == 0 or stdout != "" or f"domain root identity mismatch for: {symlink_domain}\n" not in stderr:
    fail(f"symlink replacement did not fail closed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(
    [bin_path, "domain", "status", "--quiet"],
    {"PWD": str(symlink_domain)},
    cwd=symlink_domain,
)
if rc == 0 or stdout != "" or f"domain root identity mismatch for: {symlink_domain}\n" not in stderr:
    fail(f"symlink cwd replacement did not fail closed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(work_root), "domain", "ls", "-l", "--descendants"])
if rc != 0 or stderr != "":
    fail(f"domain ls with symlink identity mismatch failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"{symlink_domain}\torphaned\torphaned\t-\torphaned-domain", "domain ls symlink identity mismatch row")

rc, stdout, stderr = run(scoped(["domain", "delete"], symlink_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"symlink identity mismatch domain delete failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

move_source_domain = work_root / "move-source-domain"
move_destination_domain = work_root / "move-destination-domain"
move_source_domain.mkdir()
move_destination_domain.mkdir()
rc, stdout, stderr = run(
    scoped(["domain", "create"], move_source_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"move source domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["set", "MOVED_KEY", "moved-secret"], move_source_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"move source set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
move_source_domain.rmdir()

rc, stdout, stderr = run([bin_path, "--dir", str(move_destination_domain), "domain", "move", "--from", str(move_source_domain)])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"missing-root domain move failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(scoped(["domain", "status", "--quiet"], move_destination_domain))
if rc != 0 or stdout != f"{move_destination_domain}\n" or stderr != "":
    fail(f"moved domain status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["get", "MOVED_KEY", "--stdout"], move_destination_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "moved-secret" or stderr != "":
    fail(f"moved domain did not preserve secret: rc={rc} stdout={stdout!r} stderr={stderr!r}")

move_to_source_domain = work_root / "move-to-source-domain"
move_to_destination_domain = work_root / "move-to-destination-domain"
move_to_source_domain.mkdir()
move_to_destination_domain.mkdir()
rc, stdout, stderr = run(
    scoped(["domain", "create"], move_to_source_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit-to source domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["set", "EXPLICIT_MOVED_KEY", "explicit-moved-secret"], move_to_source_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit-to source set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
move_to_source_domain.rmdir()

rc, stdout, stderr = run([bin_path, "domain", "move", "--from", str(move_to_source_domain), "--to", str(move_to_destination_domain)])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit-to domain move failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["get", "EXPLICIT_MOVED_KEY", "--stdout"], move_to_destination_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "explicit-moved-secret" or stderr != "":
    fail(f"explicit-to domain move did not preserve secret: rc={rc} stdout={stdout!r} stderr={stderr!r}")

move_collision_source_domain = work_root / "move-collision-source-domain"
move_collision_destination_domain = work_root / "move-collision-destination-domain"
move_collision_source_domain.mkdir()
move_collision_destination_domain.mkdir()
for collision_domain in (move_collision_source_domain, move_collision_destination_domain):
    rc, stdout, stderr = run(
        scoped(["domain", "create"], collision_domain),
        {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
    )
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"collision domain create failed for {collision_domain}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
move_collision_source_domain.rmdir()

rc, stdout, stderr = run([bin_path, "domain", "move", "--from", str(move_collision_source_domain), "--to", str(move_collision_destination_domain)])
if rc == 0 or stdout != "" or f"domain already exists for: {move_collision_destination_domain}\n" not in stderr:
    fail(f"domain move accepted registered destination: rc={rc} stdout={stdout!r} stderr={stderr!r}")

move_same_domain = work_root / "move-same-domain"
move_same_domain.mkdir()
rc, stdout, stderr = run(
    scoped(["domain", "create"], move_same_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"same-root move domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["set", "SAME_MOVED_KEY", "same-moved-secret"], move_same_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"same-root move set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
move_same_domain.rmdir()
move_same_domain.mkdir()

rc, stdout, stderr = run([bin_path, "--dir", str(move_same_domain), "domain", "move", "--from", str(move_same_domain)])
if rc == 0 or stdout != "" or "source and destination domain roots are the same; use --allow-same-root\n" not in stderr:
    fail(f"same-root domain move without explicit allow did not fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(move_same_domain), "domain", "move", "--from", str(move_same_domain), "--allow-same-root"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"same-root domain move failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    scoped(["get", "SAME_MOVED_KEY", "--stdout"], move_same_domain),
    {"SECDAT_MASTER_KEY": "lower-level-test-master-key"},
)
if rc != 0 or stdout != "same-moved-secret" or stderr != "":
    fail(f"same-root domain move did not preserve secret: rc={rc} stdout={stdout!r} stderr={stderr!r}")
PY

printf 'PASS lower-level regression\n'
