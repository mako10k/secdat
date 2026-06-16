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
env["SECDAT_MASTER_KEY"] = "v2-fsck-master-key"

domain = work_root / "project"
domain.mkdir(parents=True)

entry_id = "11111111-1111-4111-8111-111111111111"
secret_id = "22222222-2222-4222-8222-222222222222"
missing_entry_id = "33333333-3333-4333-8333-333333333333"
missing_secret_id = "44444444-4444-4444-8444-444444444444"
orphan_secret_id = "55555555-5555-4555-8555-555555555555"


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


def write_entry(path, eid, sid, key):
    path.write_text(
        f"SECDATDENT1\nentry_id={eid}\nsecret_id={sid}\nkey_visibility=always\nkey={key}\nentry_inject=explicit\n",
        encoding="utf-8",
    )


def write_object(path, sid, refcount):
    path.write_text(
        f"SECDATSECOBJ1\nsecret_id={sid}\nvalue_access=unlocked\nsecret_inject=allow\nrefcount={refcount}\n",
        encoding="utf-8",
    )


def domain_entries_for_secret(sid):
    return [
        path.read_text(encoding="utf-8")
        for path in domain_entries_dir.glob("*.dent")
        if f"secret_id={sid}\n" in path.read_text(encoding="utf-8")
    ]


def assert_wrapped_object_key_count(sid, expected_count, label):
    entry_texts = domain_entries_for_secret(sid)
    if len(entry_texts) != expected_count:
        fail(f"{label}: expected {expected_count} domain entries, found {len(entry_texts)}")
    for entry_text in entry_texts:
        if "wrapped_object_key=" not in entry_text:
            fail(f"{label}: missing wrapped_object_key")


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


def read_object_header_text(path):
    data = path.read_bytes()
    separator = data.find(b"\n\n")
    if separator >= 0:
        return data[:separator].decode("utf-8") + "\n"
    return data.decode("utf-8")


def replace_object_header_text(path, old, new):
    data = path.read_bytes()
    separator = data.find(b"\n\n")
    if separator >= 0:
        header = data[:separator].decode("utf-8")
        path.write_bytes(header.replace(old, new).encode("utf-8") + data[separator:])
        return
    path.write_text(data.decode("utf-8").replace(old, new), encoding="utf-8")


def read_field(text, field):
    prefix = f"{field}="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    fail(f"missing field: {field}")


rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

entries_dirs = list(Path(env["XDG_DATA_HOME"]).rglob("entries"))
if len(entries_dirs) != 1:
    fail(f"expected one v1 entries dir from domain create, found {entries_dirs!r}")
store_root = entries_dirs[0].parent
domain_entries_dir = store_root / "domain-ent"
secret_objects_dir = store_root / "objects" / "secret"
domain_entries_dir.mkdir(parents=True)
secret_objects_dir.mkdir(parents=True)
(store_root / "format").write_text("SECDATSTORE1\nformat=v2\nstate=ready\n", encoding="utf-8")

write_entry(domain_entries_dir / f"{entry_id}.dent", entry_id, secret_id, "APP_TOKEN")
write_object(secret_objects_dir / f"{secret_id}.sec", secret_id, 1)

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"clean v2 fsck failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--metadata"])
if rc != 0 or stdout != "APP_TOKEN\tkey_visibility=always\tvalue_access=unlocked\tsandbox_inject=explicit\n" or stderr != "":
    fail(f"clean v2 ls metadata failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "exists", "APP_TOKEN"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"clean v2 exists failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_TOKEN"])
if rc != 0 or stdout != f"{secret_id}\n" or stderr != "":
    fail(f"clean v2 id failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "secret", "status", secret_id])
if rc != 0 or stderr != "":
    fail(f"clean v2 secret status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in (
    f"secret_id={secret_id}\n",
    "object_domain=",
    "object_store=default\n",
    "value_access=unlocked\n",
    "secret_inject=allow\n",
    "refcount_cached=1\n",
    "refcount_actual=1\n",
    "orphaned=no\n",
    "object_payload=no\n",
    "object_payload_length=0\n",
    "legacy_value_sidecar=no\n",
):
    assert_contains(stdout, expected, "clean v2 secret status")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "secret", "status", "not-a-uuid"])
if rc != 2 or stdout != "" or "invalid UUID for secret status: not-a-uuid\n" not in stderr:
    fail(f"secret status invalid UUID should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=explicit\n" or stderr != "":
    fail(f"clean v2 attr failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--sandbox-injectable"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"explicit v2 key should be excluded from bulk sandbox-injectable list: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN", "--sandbox-inject", "never"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"clean v2 attr inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=never\n" or stderr != "":
    fail(f"clean v2 attr after inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
entry_text = (domain_entries_dir / f"{entry_id}.dent").read_text(encoding="utf-8")
object_text = read_object_header_text(secret_objects_dir / f"{secret_id}.sec")
if "entry_inject=never\n" not in entry_text:
    fail("clean v2 attr did not update domain entry inject policy")
if "object_domain=" not in entry_text or "object_store=default\n" not in entry_text:
    fail("clean v2 attr did not write object location metadata")
if "wrapped_object_key=" not in entry_text:
    fail("clean v2 attr did not backfill the wrapped object key")
if "secret_inject=never\n" not in object_text or "refcount=1\n" not in object_text:
    fail("clean v2 attr did not preserve secret object metadata")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN", "--sandbox-inject", "bulk"])
if rc == 0 or "secret object forbids sandbox injection: APP_TOKEN" not in stderr:
    fail(f"object-level inject deny should reject bulk re-enable: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=never\n" or stderr != "":
    fail(f"v2 attr after rejected bulk re-enable failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"clean v2 fsck after attr update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_TOKEN"])
if rc != 1 or stdout != "" or "v2 secret value storage is not implemented yet" not in stderr:
    fail(f"pure v2 get should reject missing value storage: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "APP_TOKEN", "--public-value", "--value", "public-token"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 set existing public value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_TOKEN"])
if rc != 0 or stdout != f"{secret_id}\n" or stderr != "":
    fail(f"pure v2 set should preserve existing secret id: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=always\nsandbox_inject=never\n" or stderr != "":
    fail(f"pure v2 attr after public set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_TOKEN"], {"SECDAT_MASTER_KEY": ""})
if rc != 0 or stdout != "public-token" or stderr != "":
    fail(f"pure v2 public get while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if (secret_objects_dir / f"{secret_id}.value").exists():
    fail("pure v2 set should not create object value sidecar")
assert_object_payload_magic(secret_objects_dir / f"{secret_id}.sec", b"SECDAT1\0", "pure v2 public value")

source_entry_text = (domain_entries_dir / f"{entry_id}.dent").read_text(encoding="utf-8")
source_object_domain = read_field(source_entry_text, "object_domain")
source_object_store = read_field(source_entry_text, "object_store")
consumer_domain = work_root / "consumer"
consumer_domain.mkdir(parents=True)
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "domain", "create"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"consumer domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
consumer_entries_dirs = [path for path in Path(env["XDG_DATA_HOME"]).rglob("entries") if path != entries_dirs[0]]
if len(consumer_entries_dirs) != 1:
    fail(f"expected one consumer entries dir, found {consumer_entries_dirs!r}")
consumer_store_root = consumer_entries_dirs[0].parent
consumer_domain_entries_dir = consumer_store_root / "domain-ent"
consumer_secret_objects_dir = consumer_store_root / "objects" / "secret"
consumer_domain_entries_dir.mkdir(parents=True)
consumer_secret_objects_dir.mkdir(parents=True)
(consumer_store_root / "format").write_text("SECDATSTORE1\nformat=v2\nstate=ready\n", encoding="utf-8")
remote_entry_id = "66666666-6666-4666-8666-666666666666"
(consumer_domain_entries_dir / f"{remote_entry_id}.dent").write_text(
    "SECDATDENT1\n"
    f"entry_id={remote_entry_id}\n"
    f"secret_id={secret_id}\n"
    f"object_domain={source_object_domain}\n"
    f"object_store={source_object_store}\n"
    "key_visibility=always\n"
    "key=REMOTE_PUBLIC\n"
    "entry_inject=explicit\n",
    encoding="utf-8",
)
source_public_object_path = secret_objects_dir / f"{secret_id}.sec"
replace_object_header_text(source_public_object_path, "refcount=1\n", "refcount=2\n")
replace_object_header_text(source_public_object_path, "refcount=2\n", "refcount=5\n")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--refcount", "--repair"])
if rc != 0 or stderr != "":
    fail(f"v2 refcount repair should fix a payload object: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"repaired-refcount\t{secret_id}\texpected=5 actual=2\n", "v2 refcount payload repair")
assert_object_payload_magic(source_public_object_path, b"SECDAT1\0", "v2 refcount repair payload preservation")
source_public_object_text = read_object_header_text(source_public_object_path)
if "refcount=2\n" not in source_public_object_text:
    fail("v2 refcount repair did not update the payload object's cached refcount")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"remote object v2 fsck failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "get", "REMOTE_PUBLIC"], {"SECDAT_MASTER_KEY": ""})
if rc != 0 or stdout != "public-token" or stderr != "":
    fail(f"remote public object get while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "APP_SECRET", "--value", "secret-value", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 set new encrypted value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET"])
if rc != 0 or stdout != "secret-value" or stderr != "":
    fail(f"pure v2 encrypted get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if (entries_dirs[0] / "APP_SECRET.sec").exists():
    fail("pure v2 set should not create a v1 value file")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_SECRET"])
if rc != 0 or stderr != "":
    fail(f"pure v2 id for APP_SECRET failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
app_secret_id = stdout.strip()
assert_wrapped_object_key_count(app_secret_id, 1, "pure v2 encrypted set")
if (secret_objects_dir / f"{app_secret_id}.value").exists():
    fail("pure v2 encrypted set should not create object value sidecar")
assert_object_payload_magic(secret_objects_dir / f"{app_secret_id}.sec", b"SECDOBJ2", "pure v2 encrypted value")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET"], {"SECDAT_MASTER_KEY": ""})
if rc == 0 or stdout != "" or "missing SECDAT_MASTER_KEY" not in stderr:
    fail(f"pure v2 encrypted object-key get while locked should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ln", "APP_SECRET", "APP_SECRET_LINK"], {"SECDAT_MASTER_KEY": ""})
if rc == 0 or stdout != "" or "missing SECDAT_MASTER_KEY" not in stderr:
    fail(f"pure v2 locked ln should require unlock: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ln", "APP_SECRET", "APP_SECRET_LINK"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 ln failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "secret", "status", app_secret_id])
if rc != 0 or stderr != "":
    fail(f"linked v2 secret status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
for expected in (
    f"secret_id={app_secret_id}\n",
    "object_domain=",
    "object_store=default\n",
    "value_access=unlocked\n",
    "secret_inject=allow\n",
    "refcount_cached=2\n",
    "refcount_actual=2\n",
    "orphaned=no\n",
    "object_payload=yes\n",
    "legacy_value_sidecar=no\n",
):
    assert_contains(stdout, expected, "linked v2 secret status")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_SECRET_LINK"])
if rc != 0 or stdout.strip() != app_secret_id or stderr != "":
    fail(f"pure v2 linked key should share secret id: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET_LINK"])
if rc != 0 or stdout != "secret-value" or stderr != "":
    fail(f"pure v2 linked get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
link_object_text = read_object_header_text(secret_objects_dir / f"{app_secret_id}.sec")
if "refcount=2\n" not in link_object_text:
    fail("pure v2 ln did not increment the linked secret refcount")
assert_wrapped_object_key_count(app_secret_id, 2, "pure v2 ln")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"pure v2 fsck after ln failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "APP_SECRET_LINK", "--value", "linked-value", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 set through linked key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET"])
if rc != 0 or stdout != "linked-value" or stderr != "":
    fail(f"pure v2 linked set should update original key: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "APP_SECRET", "--value", "secret-value", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 restore original linked value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "rm", "APP_SECRET_LINK"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 rm linked key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "exists", "APP_SECRET_LINK"])
if rc == 0:
    fail("pure v2 rm should remove only the linked key")
if not (secret_objects_dir / f"{app_secret_id}.sec").exists() or (secret_objects_dir / f"{app_secret_id}.value").exists():
    fail("pure v2 rm linked key should keep the shared secret object")
link_object_text = read_object_header_text(secret_objects_dir / f"{app_secret_id}.sec")
if "refcount=1\n" not in link_object_text:
    fail("pure v2 rm linked key did not decrement the linked secret refcount")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "secret", "status", app_secret_id])
if rc != 0 or stderr != "":
    fail(f"unlinked v2 secret status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "refcount_cached=1\n", "unlinked v2 secret status cached refcount")
assert_contains(stdout, "refcount_actual=1\n", "unlinked v2 secret status actual refcount")

remote_secret_keyref = f"{consumer_domain}/REMOTE_SECRET"
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ln", "APP_SECRET", remote_secret_keyref])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain v2 ln failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "id", "REMOTE_SECRET"])
if rc != 0 or stdout.strip() != app_secret_id or stderr != "":
    fail(f"cross-domain linked key should share secret id: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "get", "REMOTE_SECRET"])
if rc != 0 or stdout != "secret-value" or stderr != "":
    fail(f"cross-domain linked get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
remote_secret_entries = [
    path.read_text(encoding="utf-8")
    for path in consumer_domain_entries_dir.glob("*.dent")
    if f"secret_id={app_secret_id}\n" in path.read_text(encoding="utf-8")
]
if len(remote_secret_entries) != 1:
    fail(f"expected one cross-domain secret entry, found {len(remote_secret_entries)}")
if "wrapped_object_key=" not in remote_secret_entries[0]:
    fail("cross-domain v2 ln did not rewrap the object key into the destination entry")
link_object_text = read_object_header_text(secret_objects_dir / f"{app_secret_id}.sec")
if "refcount=2\n" not in link_object_text:
    fail("cross-domain v2 ln did not increment the source secret refcount")
for fsck_domain, label in ((domain, "source"), (consumer_domain, "consumer")):
    rc, stdout, stderr = run([bin_path, "--dir", str(fsck_domain), "fsck", "--format", "v2"])
    if rc != 0 or stdout != "ok\n" or stderr != "":
        fail(f"cross-domain v2 fsck failed for {label}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "set", "REMOTE_SECRET", "--value", "remote-linked-value", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain v2 set through linked key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET"])
if rc != 0 or stdout != "remote-linked-value" or stderr != "":
    fail(f"cross-domain v2 linked set should update original key: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "set", "APP_SECRET", "--value", "secret-value", "--sandbox-inject", "explicit"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain v2 restore original value failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "rm", "REMOTE_SECRET"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"cross-domain v2 rm linked key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(consumer_domain), "exists", "REMOTE_SECRET"])
if rc == 0:
    fail("cross-domain v2 rm should remove the destination link")
if not (secret_objects_dir / f"{app_secret_id}.sec").exists() or (secret_objects_dir / f"{app_secret_id}.value").exists():
    fail("cross-domain v2 rm should keep the source object while the source key remains")
link_object_text = read_object_header_text(secret_objects_dir / f"{app_secret_id}.sec")
if "refcount=1\n" not in link_object_text:
    fail("cross-domain v2 rm did not decrement the source secret refcount")
for fsck_domain, label in ((domain, "source"), (consumer_domain, "consumer")):
    rc, stdout, stderr = run([bin_path, "--dir", str(fsck_domain), "fsck", "--format", "v2"])
    if rc != 0 or stdout != "ok\n" or stderr != "":
        fail(f"cross-domain v2 fsck after rm failed for {label}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "cp", "APP_SECRET", "APP_SECRET_COPY"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 cp failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET_COPY"])
if rc != 0 or stdout != "secret-value" or stderr != "":
    fail(f"pure v2 copied get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_SECRET_COPY"])
if rc != 0 or stderr != "":
    fail(f"pure v2 id for copied key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if stdout.strip() == app_secret_id:
    fail("pure v2 cp should create an independent secret object")
assert_wrapped_object_key_count(stdout.strip(), 1, "pure v2 cp")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "mv", "APP_SECRET_COPY", "APP_SECRET_MOVED"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 mv failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "exists", "APP_SECRET_COPY"])
if rc == 0:
    fail("pure v2 mv should remove the source key")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "APP_SECRET_MOVED"])
if rc != 0 or stdout != "secret-value" or stderr != "":
    fail(f"pure v2 moved get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "APP_SECRET_MOVED"])
if rc != 0 or stderr != "":
    fail(f"pure v2 id for moved key failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
moved_secret_id = stdout.strip()

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "rm", "APP_SECRET_MOVED"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 rm failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "exists", "APP_SECRET_MOVED"])
if rc == 0:
    fail("pure v2 rm should remove the moved key")
if (secret_objects_dir / f"{moved_secret_id}.sec").exists() or (secret_objects_dir / f"{moved_secret_id}.value").exists():
    fail("pure v2 rm did not remove the unreferenced secret object")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"pure v2 fsck after value writes failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "set", "HIDDEN_TOKEN",
    "--key-visibility", "unlocked", "--value", "hidden-value", "--sandbox-inject", "explicit",
])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 hidden key set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "id", "HIDDEN_TOKEN"])
if rc != 0 or stderr != "":
    fail(f"pure v2 hidden key id failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
hidden_secret_id = stdout.strip()
hidden_entry_texts = [
    path.read_text(encoding="utf-8")
    for path in domain_entries_dir.glob("*.dent")
    if f"secret_id={hidden_secret_id}\n" in path.read_text(encoding="utf-8")
]
if len(hidden_entry_texts) != 1:
    fail(f"expected one hidden key domain entry, found {len(hidden_entry_texts)}")
hidden_entry_text = hidden_entry_texts[0]
if "key_visibility=unlocked\n" not in hidden_entry_text or "encrypted_key=" not in hidden_entry_text:
    fail("pure v2 hidden key domain entry did not use encrypted_key")
if "wrapped_object_key=" not in hidden_entry_text:
    fail("pure v2 hidden key domain entry did not include wrapped_object_key")
if "HIDDEN_TOKEN" in hidden_entry_text or "key=HIDDEN_TOKEN" in hidden_entry_text:
    fail("pure v2 hidden key leaked the key name in the domain entry")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "HIDDEN_TOKEN"])
if rc != 0 or stdout != "hidden-value" or stderr != "":
    fail(f"pure v2 hidden key get failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "HIDDEN_TOKEN"])
if rc != 0 or stdout != "key_visibility=unlocked\nvalue_access=unlocked\nsandbox_inject=explicit\n" or stderr != "":
    fail(f"pure v2 hidden key attr failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--metadata"])
if rc != 0 or stderr != "":
    fail(f"pure v2 hidden key metadata list failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "HIDDEN_TOKEN\tkey_visibility=unlocked\tvalue_access=unlocked\tsandbox_inject=explicit\n", "hidden key metadata")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "ls", "--metadata"], {"SECDAT_MASTER_KEY": ""})
if rc != 0 or stderr != "":
    fail(f"pure v2 locked metadata list failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "HIDDEN_TOKEN" in stdout:
    fail(f"pure v2 locked metadata list should hide hidden key: {stdout!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "HIDDEN_TOKEN"], {"SECDAT_MASTER_KEY": ""})
if rc == 0 or stdout != "":
    fail(f"pure v2 locked hidden key get should fail: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "HIDDEN_TOKEN", "--key-visibility", "always"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"pure v2 hidden key visibility restore failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
hidden_entry_texts = [
    path.read_text(encoding="utf-8")
    for path in domain_entries_dir.glob("*.dent")
    if f"secret_id={hidden_secret_id}\n" in path.read_text(encoding="utf-8")
]
if len(hidden_entry_texts) != 1:
    fail(f"expected one restored hidden key domain entry, found {len(hidden_entry_texts)}")
hidden_entry_text = hidden_entry_texts[0]
if "key_visibility=always\n" not in hidden_entry_text or "key=HIDDEN_TOKEN\n" not in hidden_entry_text or "encrypted_key=" in hidden_entry_text:
    fail("pure v2 hidden key visibility restore did not write a plaintext key entry")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"pure v2 fsck after hidden key operations failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck"])
if rc != 2 or "store format is v2; use --format v2" not in stderr:
    fail(f"v1 fsck should reject v2 marker: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "default", "--to-format", "v2", "--dry-run"])
if rc != 2 or "store format is v2; migration is not needed" not in stderr:
    fail(f"v2 store migrate should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

(store_root / "format").write_text("not-a-store-format\n", encoding="utf-8")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2"])
if rc != 1 or "invalid store format marker" not in stderr:
    fail(f"invalid format marker should be rejected by fsck: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "store", "migrate", "default", "--to-format", "v2", "--dry-run"])
if rc != 1 or "invalid store format marker" not in stderr:
    fail(f"invalid format marker should be rejected by migration: rc={rc} stdout={stdout!r} stderr={stderr!r}")
(store_root / "format").write_text("SECDATSTORE1\nformat=v2\nstate=ready\n", encoding="utf-8")

write_entry(domain_entries_dir / f"{missing_entry_id}.dent", missing_entry_id, missing_secret_id, "MISSING")
(domain_entries_dir / "BROKEN.dent").write_text("not-a-domain-entry\n", encoding="utf-8")
(secret_objects_dir / "BAD.sec").write_text("not-a-secret-object\n", encoding="utf-8")
(secret_objects_dir / "BAD.value").write_text("bad-sidecar\n", encoding="utf-8")
write_object(secret_objects_dir / f"{secret_id}.sec", secret_id, 3)
write_object(secret_objects_dir / f"{orphan_secret_id}.sec", orphan_secret_id, 0)
(secret_objects_dir / f"{orphan_secret_id}.value").write_text("orphan-sidecar\n", encoding="utf-8")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--dangling"])
if rc != 1 or stderr != "":
    fail(f"v2 dangling fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "dangling-entry\tBROKEN\tinvalid-entry\n", "v2 invalid entry")
assert_contains(stdout, f"dangling-entry\t{missing_entry_id}\tmissing-secret\n", "v2 missing secret")
assert_contains(stdout, "dangling-secret\tBAD\tinvalid-secret\n", "v2 invalid secret")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--orphaned"])
if rc != 1 or stderr != "":
    fail(f"v2 orphaned fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"orphaned-secret\t{orphan_secret_id}\tmissing-entry\n", "v2 orphaned secret")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--refcount"])
if rc != 1 or stderr != "":
    fail(f"v2 refcount fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"refcount-mismatch\t{secret_id}\texpected=3 actual=2\n", "v2 refcount mismatch")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--refcount", "--repair"])
if rc != 0 or stderr != "":
    fail(f"v2 refcount repair should report repaired rows: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"repaired-refcount\t{secret_id}\texpected=3 actual=2\n", "v2 refcount repair")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--refcount"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"v2 refcount fsck should be clean after repair: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--orphaned"])
if rc != 1 or stderr != "":
    fail(f"v2 refcount repair should not remove orphans: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"orphaned-secret\t{orphan_secret_id}\tmissing-entry\n", "v2 orphaned secret after repair")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "gc", "--format", "v2", "--dangling", "--dry-run"])
if rc != 0 or stderr != "":
    fail(f"v2 dangling gc dry-run should succeed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "would-remove-dangling-entry\tBROKEN\tinvalid-entry\n", "v2 gc dry-run invalid entry")
assert_contains(stdout, f"would-remove-dangling-entry\t{missing_entry_id}\tmissing-secret\n", "v2 gc dry-run missing secret")
assert_contains(stdout, "would-remove-dangling-secret\tBAD\tinvalid-secret\n", "v2 gc dry-run invalid secret")
if (not (domain_entries_dir / "BROKEN.dent").exists()
        or not (domain_entries_dir / f"{missing_entry_id}.dent").exists()
        or not (secret_objects_dir / "BAD.sec").exists()
        or not (secret_objects_dir / "BAD.value").exists()):
    fail("v2 gc dry-run should not remove dangling artifacts")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "gc", "--format", "v2", "--dangling"])
if rc != 0 or stderr != "":
    fail(f"v2 dangling gc should remove entries: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "removed-dangling-entry\tBROKEN\tinvalid-entry\n", "v2 gc invalid entry removal")
assert_contains(stdout, f"removed-dangling-entry\t{missing_entry_id}\tmissing-secret\n", "v2 gc missing secret removal")
assert_contains(stdout, "removed-dangling-secret\tBAD\tinvalid-secret\n", "v2 gc invalid secret removal")
if ((domain_entries_dir / "BROKEN.dent").exists()
        or (domain_entries_dir / f"{missing_entry_id}.dent").exists()
        or (secret_objects_dir / "BAD.sec").exists()
        or (secret_objects_dir / "BAD.value").exists()):
    fail("v2 gc did not remove dangling artifacts")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--dangling"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"v2 dangling fsck should be clean after gc: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "gc", "--format", "v2", "--orphaned", "--dry-run"])
if rc != 0 or stderr != "":
    fail(f"v2 orphaned gc dry-run should succeed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"would-remove-orphaned-secret\t{orphan_secret_id}\tmissing-entry\n", "v2 gc dry-run orphan")
if not (secret_objects_dir / f"{orphan_secret_id}.sec").exists() or not (secret_objects_dir / f"{orphan_secret_id}.value").exists():
    fail("v2 gc dry-run should not remove orphaned secret artifacts")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "gc", "--format", "v2", "--orphaned"])
if rc != 0 or stderr != "":
    fail(f"v2 orphaned gc should remove artifacts: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"removed-orphaned-secret\t{orphan_secret_id}\tmissing-entry\n", "v2 gc orphan removal")
if (secret_objects_dir / f"{orphan_secret_id}.sec").exists() or (secret_objects_dir / f"{orphan_secret_id}.value").exists():
    fail("v2 gc did not remove orphaned secret artifacts")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--orphaned"])
if rc != 0 or stdout != "ok\n" or stderr != "":
    fail(f"v2 orphaned fsck should be clean after gc: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS v2 fsck regression")
PY
