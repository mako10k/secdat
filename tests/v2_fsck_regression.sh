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

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=explicit\n" or stderr != "":
    fail(f"clean v2 attr failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN", "--sandbox-inject", "never"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"clean v2 attr inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "APP_TOKEN"])
if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nsandbox_inject=never\n" or stderr != "":
    fail(f"clean v2 attr after inject update failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
entry_text = (domain_entries_dir / f"{entry_id}.dent").read_text(encoding="utf-8")
object_text = (secret_objects_dir / f"{secret_id}.sec").read_text(encoding="utf-8")
if "entry_inject=never\n" not in entry_text:
    fail("clean v2 attr did not update domain entry inject policy")
if "secret_inject=never\n" not in object_text or "refcount=1\n" not in object_text:
    fail("clean v2 attr did not preserve secret object metadata")
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
if not (secret_objects_dir / f"{secret_id}.value").exists():
    fail("pure v2 set did not create object value storage")

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
write_object(secret_objects_dir / f"{secret_id}.sec", secret_id, 2)
write_object(secret_objects_dir / f"{orphan_secret_id}.sec", orphan_secret_id, 0)

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--dangling"])
if rc != 1 or stderr != "":
    fail(f"v2 dangling fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "dangling-entry\tBROKEN\tinvalid-entry\n", "v2 invalid entry")
assert_contains(stdout, f"dangling-entry\t{missing_entry_id}\tmissing-secret\n", "v2 missing secret")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--orphaned"])
if rc != 1 or stderr != "":
    fail(f"v2 orphaned fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"orphaned-secret\t{orphan_secret_id}\tmissing-entry\n", "v2 orphaned secret")

rc, stdout, stderr = run([bin_path, "--dir", str(domain), "fsck", "--format", "v2", "--refcount"])
if rc != 1 or stderr != "":
    fail(f"v2 refcount fsck should report issues: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, f"refcount-mismatch\t{secret_id}\texpected=2 actual=1\n", "v2 refcount mismatch")

print("PASS v2 fsck regression")
PY
