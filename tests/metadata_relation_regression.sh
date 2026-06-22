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

python3 - "$bin_path" "$work_root" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "metadata-relation-master-key"

domain = work_root / "project"
child = domain / "child"
domain.mkdir(parents=True)
child.mkdir(parents=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        for name, value in extra_env.items():
            if value is None:
                run_env.pop(name, None)
            else:
                run_env[name] = value
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected [{expected}], got [{actual}]")


def assert_not_contains(output, unexpected, label):
    if unexpected in output:
        fail(f"{label}: unexpected [{unexpected}] in [{output}]")


rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(child), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"child domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for key, value in [
    ("BILLING_ID", "user@example.invalid"),
    ("BILLING_PASSWORD", "password-value"),
    ("BILLING_SALT", "salt-value"),
]:
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", key, "--value", value])
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"set {key} failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "set", "BILLING_ID", "service", "billing"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"meta set service failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "set", "BILLING_ID", "meaning", "public identifier"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"meta set meaning failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "get", "BILLING_ID"])
if rc != 0 or stderr != "":
    fail(f"meta get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "service=billing\n", "meta get service")
assert_contains(stdout, "meaning=public identifier\n", "meta get meaning")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "search", "service=bill*"])
if rc != 0 or stderr != "":
    fail(f"meta search service failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "BILLING_ID\n", "meta search service")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "search", "meaning"])
if rc != 0 or stderr != "":
    fail(f"meta search presence failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "BILLING_ID\n", "meta search presence")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "set", "BILLING_ID", "oversized", "x" * 32768])
if rc == 0 or "metadata is too large" not in stderr:
    fail(f"oversized metadata should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child), "meta", "set", "BILLING_ID", "child", "blocked"])
if rc == 0 or "cannot update inherited key metadata: BILLING_ID" not in stderr:
    fail(f"inherited metadata update should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "cp", "BILLING_ID", "BILLING_ID_COPY"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cp metadata key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "get", "BILLING_ID_COPY"])
if rc != 0 or stderr != "":
    fail(f"copied metadata read failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "service=billing\n", "copy preserves service metadata")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "mv", "BILLING_ID_COPY", "BILLING_ID_RENAMED"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"mv metadata key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "get", "BILLING_ID_RENAMED"])
if rc != 0 or stderr != "":
    fail(f"renamed metadata read failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "service=billing\n", "mv preserves service metadata")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "meta", "get", "BILLING_ID_COPY"])
if rc == 0 or "key not found: BILLING_ID_COPY" not in stderr:
    fail(f"old moved metadata key should be absent: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "relation", "set", "billing-login",
    "--kind", "credential",
    "--member", "id=BILLING_ID",
    "--member", "password=BILLING_PASSWORD",
    "--security", "combination-sensitive",
    "--exposure", "id may be public; password must remain secret",
    "--impact", "account takeover",
    "--note", "id alone is low sensitivity",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"relation set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "show", "billing-login"])
if rc != 0 or stderr != "":
    fail(f"relation show failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "relation_id=billing-login\n", "relation id")
assert_contains(stdout, "kind=credential\n", "relation kind")
assert_contains(stdout, f"member=id\t{domain}/BILLING_ID:default\n", "relation id member")
assert_contains(stdout, f"member=password\t{domain}/BILLING_PASSWORD:default\n", "relation password member")
assert_contains(stdout, "security=combination-sensitive\n", "relation security")
assert_contains(stdout, "exposure=id may be public; password must remain secret\n", "relation exposure")
assert_contains(stdout, "impact=account takeover\n", "relation impact")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "ls"])
if rc != 0 or stderr != "":
    fail(f"relation ls failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "billing-login\n", "relation ls")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "ls", "BILLING_PASSWORD"])
if rc != 0 or stderr != "":
    fail(f"relation ls by key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "billing-login\n", "relation ls by key")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "unlock", "--readonly"])
if rc != 0 or "readonly session unlocked from environment" not in stdout:
    fail(f"readonly unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
readonly_env = {"SECDAT_MASTER_KEY": None}
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "show", "billing-login"], extra_env=readonly_env)
if rc != 0 or stderr != "":
    fail(f"relation show should work in readonly session: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "security=combination-sensitive\n", "readonly relation show")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "ls"], extra_env=readonly_env)
if rc != 0 or stderr != "":
    fail(f"relation ls should work in readonly session: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(stdout, "billing-login\n", "readonly relation ls")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "relation", "set", "readonly-blocked", "--member", "id=BILLING_ID", "--member", "password=BILLING_PASSWORD"], extra_env=readonly_env)
if rc == 0 or "current session is readonly and cannot run relation set" not in stderr:
    fail(f"relation set should be blocked in readonly session: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "lock"], extra_env=readonly_env)
if rc != 0 or stdout != "session locked\n" or stderr != "":
    fail(f"lock after readonly relation checks failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "relation", "set", "bad-relation",
    "--member", "id=BILLING_ID",
    "--member", "password=NO_SUCH_KEY",
])
if rc == 0 or "key not found: NO_SUCH_KEY" not in stderr:
    fail(f"relation set should reject missing member: rc={rc} stdout={stdout!r} stderr={stderr!r}")

hidden_domain = work_root / "hidden-project"
hidden_domain.mkdir(parents=True)
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"hidden domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for key, value in [
    ("PUBLIC_ID", "public-id"),
    ("HIDDEN_TOKEN", "hidden-value"),
    ("BLOCKED_BY_META", "meta-value"),
    ("CRED_ID", "credential-id"),
    ("CRED_SECRET", "credential-secret"),
]:
    rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "set", key, "--value", value])
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"hidden-domain set {key} failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "store", "migrate", "default", "--to-format", "v2"])
if rc != 0 or stderr != "":
    fail(f"hidden-domain v2 migration failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "HIDDEN_TOKEN", "--key-visibility", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"hidden key visibility update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "meta", "set", "HIDDEN_TOKEN", "service", "hidden"])
if rc == 0 or stdout != "" or "key metadata cannot be set for hidden v2 key: HIDDEN_TOKEN" not in stderr:
    fail(f"meta set should reject hidden v2 key: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if list(Path(env["XDG_DATA_HOME"]).rglob("HIDDEN_TOKEN.kmeta")):
    fail("meta set for hidden v2 key leaked plaintext key metadata filename")
rc, stdout, stderr = run([
    bin_path, "--dir", str(hidden_domain), "relation", "set", "hidden-login",
    "--member", "id=PUBLIC_ID",
    "--member", "secret=HIDDEN_TOKEN",
])
if rc == 0 or stdout != "" or "relation member cannot reference hidden v2 key: HIDDEN_TOKEN" not in stderr:
    fail(f"relation set should reject hidden v2 member: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if list(Path(env["XDG_DATA_HOME"]).rglob("hidden-login.rel")):
    fail("relation set for hidden v2 key wrote a plaintext relation file")

rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "meta", "set", "BLOCKED_BY_META", "service", "billing"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"visible metadata before hiding failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "BLOCKED_BY_META", "--key-visibility", "unlocked"])
if rc == 0 or stdout != "" or "key_visibility=unlocked cannot be used while key metadata exists: BLOCKED_BY_META" not in stderr:
    fail(f"hidden visibility should reject existing metadata: rc={rc} stdout={stdout!r} stderr={stderr!r}")
hidden_meta_dirs = [
    path for path in Path(env["XDG_DATA_HOME"]).rglob("key-meta")
    if (path / "BLOCKED_BY_META.kmeta").exists()
]
if len(hidden_meta_dirs) != 1:
    fail(f"expected hidden-domain key-meta directory, found {hidden_meta_dirs!r}")
(hidden_meta_dirs[0] / "HIDDEN_TOKEN.kmeta").write_text("SECDATKMETA1\nservice=legacy\n", encoding="utf-8")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "cp", "HIDDEN_TOKEN", "HIDDEN_COPY"])
if rc == 0 or stdout != "" or "key metadata cannot be preserved for hidden v2 key: HIDDEN_COPY" not in stderr:
    fail(f"cp should reject metadata-preserving hidden v2 key copy: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if (hidden_meta_dirs[0] / "HIDDEN_COPY.kmeta").exists():
    fail("cp wrote metadata for a hidden v2 destination key")
(hidden_meta_dirs[0] / "HIDDEN_TOKEN.kmeta").unlink()
(hidden_meta_dirs[0] / "LINKED_HIDDEN.kmeta").write_text("SECDATKMETA1\nservice=legacy\n", encoding="utf-8")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "ln", "HIDDEN_TOKEN", "LINKED_HIDDEN"])
if rc == 0 or stdout != "" or "key_visibility=unlocked cannot be used while key metadata exists: LINKED_HIDDEN" not in stderr:
    fail(f"ln should reject hidden v2 destination with metadata path: rc={rc} stdout={stdout!r} stderr={stderr!r}")
(hidden_meta_dirs[0] / "LINKED_HIDDEN.kmeta").unlink()
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "meta", "unset", "BLOCKED_BY_META", "service"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"metadata cleanup before hiding failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "BLOCKED_BY_META", "--key-visibility", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"hidden visibility after metadata cleanup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(hidden_domain), "relation", "set", "credential-pair",
    "--member", "id=CRED_ID",
    "--member", "secret=CRED_SECRET",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"visible relation before hiding failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "CRED_SECRET", "--key-visibility", "unlocked"])
if rc == 0 or stdout != "" or "key_visibility=unlocked cannot be used while relation references key: CRED_SECRET (credential-pair)" not in stderr:
    fail(f"hidden visibility should reject existing relation: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "relation", "rm", "credential-pair"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"relation cleanup before hiding failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "CRED_SECRET", "--key-visibility", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"hidden visibility after relation cleanup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

consumer_domain = work_root / "relation-consumer"
consumer_domain.mkdir(parents=True)
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"relation consumer domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "set", "REMOTE_ID", "--value", "remote-id"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"relation consumer id set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([
    bin_path, "--dir", str(consumer_domain), "relation", "set", "remote-credential",
    "--member", "id=REMOTE_ID",
    "--member", f"secret={hidden_domain}/PUBLIC_ID",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain relation set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "PUBLIC_ID", "--key-visibility", "unlocked"])
if rc == 0 or stdout != "" or "key_visibility=unlocked cannot be used while relation references key: PUBLIC_ID (remote-credential)" not in stderr:
    fail(f"hidden visibility should reject cross-domain relation: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "relation", "rm", "remote-credential"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain relation cleanup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "attr", "PUBLIC_ID", "--key-visibility", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"hidden visibility after cross-domain cleanup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(hidden_domain), "ls", "--metadata"], extra_env={"SECDAT_MASTER_KEY": ""})
if rc != 0 or stderr != "":
    fail(f"locked v2 metadata list after hidden guards failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_not_contains(stdout, "HIDDEN_TOKEN", "locked list after hidden metadata guard")
assert_not_contains(stdout, "BLOCKED_BY_META", "locked list after hidden metadata cleanup")
assert_not_contains(stdout, "CRED_SECRET", "locked list after hidden relation cleanup")

key_meta_dirs = [
    path for path in Path(env["XDG_DATA_HOME"]).rglob("key-meta")
    if (path / "BILLING_ID.kmeta").exists()
]
if len(key_meta_dirs) != 1:
    fail(f"expected one key-meta directory, found {key_meta_dirs!r}")
(key_meta_dirs[0] / "ORPHAN.kmeta").write_text("SECDATKMETA1\nservice=orphan\n", encoding="utf-8")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck"])
if rc != 1 or stderr != "":
    fail(f"fsck should report orphan key metadata: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "orphaned-key-metadata\tORPHAN\tmissing-entry\n", "orphan key metadata fsck")
(key_meta_dirs[0] / "ORPHAN.kmeta").unlink()

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "rm", "BILLING_PASSWORD"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"rm relation member failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck"])
if rc != 1 or stderr != "":
    fail(f"fsck should report relation missing member: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "dangling-relation\tbilling-login\tmissing-key:password\n", "relation missing key fsck")

print("PASS metadata/relation regression")
PY
