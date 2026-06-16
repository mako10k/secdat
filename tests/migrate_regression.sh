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
env["SECDAT_MASTER_KEY"] = "migrate-master-key"

domain = work_root / "project"
domain.mkdir(parents=True)


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


def domain_entries_for_secret(store_root, sid):
    return [
        path.read_text(encoding="utf-8")
        for path in (store_root / "domain-ent").glob("*.dent")
        if f"secret_id={sid}\n" in path.read_text(encoding="utf-8")
    ]


def assert_object_payload_magic(path, magic, label):
    data = path.read_bytes()
    separator = data.find(b"\n\n")
    if separator < 0:
        fail(f"{label}: missing object payload separator")
    header = data[:separator].decode("utf-8")
    payload = data[separator + 2 :]
    if f"payload_length={len(payload)}\n" not in header + "\n":
        fail(f"{label}: object payload length metadata mismatch")
    if not payload.startswith(magic):
        fail(f"{label}: expected object payload magic {magic!r}, found {payload[:8]!r}")


rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "create", "app"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "--store", "app", "set", "APP_TOKEN",
    "--value", "secret-token", "--sandbox-inject", "explicit",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set APP_TOKEN failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "--store", "app", "set", "APP_PUBLIC",
    "--public-value", "--value", "public-value",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set APP_PUBLIC failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 0 or stderr != "":
    fail(f"store migrate dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in [
    "format=v1\n",
    "target_format=v2\n",
    "dry_run=yes\n",
    "store=app\n",
    "domain_entries=2\n",
    "secret_objects=2\n",
    "metadata_sidecars=1\n",
    "tombstones=0\n",
    "public_values=1\n",
    "encrypted_values=1\n",
    "injectable_entries=0\n",
    "issues=0\n",
]:
    assert_contains(stdout, expected, "store migrate dry-run output")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "id", "APP_TOKEN"])
if rc != 1 or stdout != "" or "secret id is available only for store format v2\n" not in stderr or "store migrate app --to-format v2 --dry-run" not in stderr:
    fail(f"v1 id should include migration hint: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(
    [bin_path, "--dir", str(domain), "--store", "app", "id", "APP_TOKEN"],
    {"SECDAT_SUPPRESS_MIGRATION_HINTS": "1"},
)
if rc != 1 or stdout != "" or "secret id is available only for store format v2\n" not in stderr or "store migrate app --to-format v2 --dry-run" in stderr:
    fail(f"migration hint suppression failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "--store", "app", "secret", "status",
    "11111111-1111-4111-8111-111111111111",
])
if rc != 1 or stdout != "" or "secret status is available only for store format v2\n" not in stderr or "store migrate app --to-format v2 --dry-run" not in stderr:
    fail(f"v1 secret status should include migration hint: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "finalize-migration", "app", "--from-format", "v1", "--dry-run"])
if rc != 2 or stdout != "" or "store format is v1; finalize-migration requires a migrated v2 store\n" not in stderr:
    fail(f"v1 finalize-migration should require migrated v2 store: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v3", "--dry-run"])
if rc != 2 or "invalid migration target format: v3" not in stderr:
    fail(f"store migrate invalid target should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "finalize-migration", "app", "--from-format", "v2", "--dry-run"])
if rc != 2 or "invalid migration source format: v2" not in stderr:
    fail(f"store finalize-migration invalid source should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 2 or "--store is not valid with store commands" not in stderr:
    fail(f"store migrate should reject global --store: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "create", "broken"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"broken store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "broken", "set", "BROKEN_TOKEN", "--value", "bad"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set BROKEN_TOKEN failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
entry_files = list(Path(env["XDG_DATA_HOME"]).rglob("BROKEN_TOKEN.sec"))
if len(entry_files) != 1:
    fail(f"expected one BROKEN_TOKEN.sec, found {entry_files!r}")
entries_dir = entry_files[0].parent
(entries_dir / "BROKEN.sec").write_bytes(b"not-a-secdat-entry")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "broken", "--to-format", "v2", "--dry-run"])
if rc != 1 or stderr != "":
    fail(f"store migrate should report corrupt v1 entries: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "cannot-migrate\tdangling-entry\tBROKEN\tinvalid-entry\n", "store migrate corrupt entry")
assert_contains(stdout, "issues=1\n", "store migrate issue count")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "create", "artifact"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"artifact store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "artifact", "set", "ARTIFACT_TOKEN", "--value", "artifact"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"set ARTIFACT_TOKEN failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
artifact_files = list(Path(env["XDG_DATA_HOME"]).rglob("ARTIFACT_TOKEN.sec"))
if len(artifact_files) != 1:
    fail(f"expected one ARTIFACT_TOKEN.sec, found {artifact_files!r}")
artifact_root = artifact_files[0].parent.parent
(artifact_root / "domain-ent").mkdir()
(artifact_root / "domain-ent" / "leftover.dent").write_text("leftover\n", encoding="utf-8")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "artifact", "--to-format", "v2"])
if rc != 1 or stdout != "" or "v2 migration artifacts already exist" not in stderr:
    fail(f"store migrate should reject existing v2 artifacts: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2"])
if rc != 0 or stderr != "":
    fail(f"store migrate write failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in [
    "format=v1\n",
    "target_format=v2\n",
    "dry_run=no\n",
    "store=app\n",
    "domain_entries=2\n",
    "secret_objects=2\n",
    "metadata_sidecars=1\n",
    "tombstones=0\n",
    "public_values=1\n",
    "encrypted_values=1\n",
    "injectable_entries=0\n",
    "issues=0\n",
    "verified=yes\n",
]:
    assert_contains(stdout, expected, "store migrate write output")

app_token_files = list(Path(env["XDG_DATA_HOME"]).rglob("APP_TOKEN.sec"))
if len(app_token_files) != 1:
    fail(f"expected v1 APP_TOKEN.sec to remain, found {app_token_files!r}")
store_root = app_token_files[0].parent.parent
if (store_root / "format").read_text(encoding="utf-8") != "SECDATSTORE1\nformat=v2\nstate=ready\n":
    fail("store format marker was not updated to v2")
if len(list((store_root / "domain-ent").glob("*.dent"))) != 2:
    fail("expected two v2 domain entries")
if len(list((store_root / "objects" / "secret").glob("*.sec"))) != 2:
    fail("expected two v2 secret objects")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"migrated v2 fsck failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "finalize-migration", "app", "--from-format", "v1"])
if rc != 2 or stdout != "" or "store finalize-migration currently requires --dry-run\n" not in stderr:
    fail(f"store finalize-migration write should be gated: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "finalize-migration", "app", "--from-format", "v1", "--dry-run"])
if rc != 1 or stderr != "":
    fail(f"initial finalize-migration dry-run should report blocking fallback: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in [
    "cannot-finalize\tlegacy-entry\tAPP_PUBLIC\tmissing-object-payload\n",
    "cannot-finalize\tlegacy-entry\tAPP_TOKEN\tmissing-object-payload\n",
    "would-remove-legacy-metadata\tAPP_TOKEN\tv2-metadata\n",
    "format=v2\n",
    "from_format=v1\n",
    "dry_run=yes\n",
    "store=app\n",
    "legacy_entries=2\n",
    "metadata_sidecars=1\n",
    "removable_legacy_entries=0\n",
    "removable_metadata_sidecars=1\n",
    "blocking_legacy_entries=2\n",
    "blocking_metadata_sidecars=0\n",
    "issues=2\n",
]:
    assert_contains(stdout, expected, "initial finalize-migration dry-run")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "ls", "--metadata"])
if rc != 0 or stderr != "":
    fail(f"migrated v2 ls metadata failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "APP_TOKEN\tkey_visibility=always\tvalue_access=unlocked\tsandbox_inject=explicit\n", "migrated APP_TOKEN metadata")
assert_contains(stdout, "APP_PUBLIC\tkey_visibility=always\tvalue_access=always\tsandbox_inject=never\n", "migrated APP_PUBLIC metadata")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "id", "APP_TOKEN"])
if rc != 0 or stderr != "":
    fail(f"migrated v2 id failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if len(stdout.strip()) != 36 or stdout.count("\n") != 1:
    fail(f"migrated v2 id did not print one UUID: {stdout!r}")
app_token_secret_id = stdout.strip()
app_token_object_path = store_root / "objects" / "secret" / f"{app_token_secret_id}.sec"
app_token_entry_texts = domain_entries_for_secret(store_root, app_token_secret_id)
if len(app_token_entry_texts) != 1 or "wrapped_object_key=" not in app_token_entry_texts[0]:
    fail("migrated encrypted APP_TOKEN domain entry did not include wrapped_object_key")
if "object_domain=" not in app_token_entry_texts[0] or "object_store=app\n" not in app_token_entry_texts[0]:
    fail("migrated encrypted APP_TOKEN domain entry did not include object location")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "id", "APP_PUBLIC"])
if rc != 0 or stderr != "":
    fail(f"migrated v2 public id failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
app_public_entry_texts = domain_entries_for_secret(store_root, stdout.strip())
if len(app_public_entry_texts) != 1:
    fail(f"expected one APP_PUBLIC domain entry, found {len(app_public_entry_texts)}")
if "wrapped_object_key=" in app_public_entry_texts[0]:
    fail("migrated public APP_PUBLIC domain entry should not include wrapped_object_key")
if "object_domain=" not in app_public_entry_texts[0] or "object_store=app\n" not in app_public_entry_texts[0]:
    fail("migrated public APP_PUBLIC domain entry did not include object location")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_PUBLIC"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=always\nsandbox_inject=never\n" or stderr != "":
    fail(f"migrated v2 attr failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN", "--sandbox-inject", "bulk"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 attr inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=bulk\n" or stderr != "":
    fail(f"migrated v2 attr after inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "ls", "--sandbox-injectable"])
if rc != 0 or stdout != "APP_TOKEN\n" or stderr != "":
    fail(f"migrated v2 sandbox injectable list failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"migrated v2 fsck after attr update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN", "--value-access", "always"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 value_access public update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=always\nsandbox_inject=bulk\n" or stderr != "":
    fail(f"migrated v2 attr after value_access public update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "get", "APP_TOKEN"], {"SECDAT_MASTER_KEY": ""})
if rc != 0 or stdout != "secret-token" or stderr != "":
    fail(f"migrated v2 public get while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
value_files = list((store_root / "objects" / "secret").glob("*.value"))
if value_files:
    fail(f"migrated v2 value rewrite should not create object value sidecars: {value_files!r}")
assert_object_payload_magic(app_token_object_path, b"SECDAT1\0", "migrated public value")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN", "--value-access", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 value_access encrypted update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_object_payload_magic(app_token_object_path, b"SECDOBJ2", "migrated encrypted value")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "get", "APP_TOKEN"], {"SECDAT_MASTER_KEY": ""})
if rc == 0 or stdout != "" or "missing SECDAT_MASTER_KEY" not in stderr:
    fail(f"migrated v2 encrypted get while locked should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN", "--key-visibility", "unlocked"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 key_visibility hidden update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=unlocked\nvalue_access=unlocked\nsandbox_inject=bulk\n" or stderr != "":
    fail(f"migrated v2 attr after key_visibility hidden update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
app_token_entry_texts = [
    path.read_text(encoding="utf-8")
    for path in (store_root / "domain-ent").glob("*.dent")
    if f"secret_id={app_token_secret_id}\n" in path.read_text(encoding="utf-8")
]
if len(app_token_entry_texts) != 1:
    fail(f"expected one APP_TOKEN domain entry after hiding key, found {len(app_token_entry_texts)}")
if "APP_TOKEN" in app_token_entry_texts[0] or "encrypted_key=" not in app_token_entry_texts[0]:
    fail("migrated v2 hidden key update did not hide APP_TOKEN in the domain entry")
if "wrapped_object_key=" not in app_token_entry_texts[0]:
    fail("migrated v2 hidden key update did not preserve wrapped_object_key")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "ls", "--metadata"], {"SECDAT_MASTER_KEY": ""})
if rc != 0 or stderr != "":
    fail(f"migrated v2 locked metadata list after hidden key update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "APP_TOKEN" in stdout:
    fail(f"migrated v2 locked metadata list should hide APP_TOKEN: {stdout!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "get", "APP_TOKEN"], {"SECDAT_MASTER_KEY": ""})
if rc == 0 or stdout != "":
    fail(f"migrated v2 locked hidden key get should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN", "--key-visibility", "always"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 key_visibility visible restore failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=bulk\n" or stderr != "":
    fail(f"migrated v2 attr after key_visibility visible restore failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
app_token_entry_texts = [
    path.read_text(encoding="utf-8")
    for path in (store_root / "domain-ent").glob("*.dent")
    if f"secret_id={app_token_secret_id}\n" in path.read_text(encoding="utf-8")
]
if len(app_token_entry_texts) != 1:
    fail(f"expected one APP_TOKEN domain entry after visible restore, found {len(app_token_entry_texts)}")
if "key=APP_TOKEN\n" not in app_token_entry_texts[0] or "encrypted_key=" in app_token_entry_texts[0]:
    fail("migrated v2 key_visibility visible restore did not write a plaintext key entry")
if "wrapped_object_key=" not in app_token_entry_texts[0]:
    fail("migrated v2 key_visibility visible restore did not preserve wrapped_object_key")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "get", "APP_TOKEN"])
if rc != 0 or stdout != "secret-token" or stderr != "":
    fail(f"v1 read compatibility after migration failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

app_public_files = list(Path(env["XDG_DATA_HOME"]).rglob("APP_PUBLIC.sec"))
if len(app_public_files) != 1:
    fail(f"expected v1 APP_PUBLIC.sec to remain before rm, found {app_public_files!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "rm", "APP_PUBLIC"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"migrated v2 rm failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "exists", "APP_PUBLIC"])
if rc == 0:
    fail("migrated v2 rm should remove APP_PUBLIC")
if app_public_files[0].exists():
    fail("migrated v2 rm did not remove the legacy v1 value file")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "--store", "app", "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"migrated v2 fsck after rm failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "finalize-migration", "app", "--from-format", "v1", "--dry-run"])
if rc != 0 or stderr != "":
    fail(f"final finalize-migration dry-run should be clean: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in [
    "would-remove-legacy-entry\tAPP_TOKEN\tobject-payload\n",
    "would-remove-legacy-metadata\tAPP_TOKEN\tv2-metadata\n",
    "legacy_entries=1\n",
    "metadata_sidecars=1\n",
    "removable_legacy_entries=1\n",
    "removable_metadata_sidecars=1\n",
    "blocking_legacy_entries=0\n",
    "blocking_metadata_sidecars=0\n",
    "issues=0\n",
]:
    assert_contains(stdout, expected, "final finalize-migration dry-run")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "app", "--to-format", "v2", "--dry-run"])
if rc != 2 or "store format is v2; migration is not needed" not in stderr:
    fail(f"already migrated store should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS migrate regression")
PY
