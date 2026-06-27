#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
fuse_bin="${2:-./src/secdat-fuse}"

if [ ! -x "$fuse_bin" ]; then
	printf 'SKIP fuse regression (secdat-fuse not built)\n'
	exit 0
fi

work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
export SECDAT_MASTER_KEY='fuse-regression-master-key'
export LC_ALL=C
export LANGUAGE=C
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$fuse_bin" "$work_root" <<'PY'
import os
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

bin_path = str(Path(sys.argv[1]).resolve())
fuse_bin = str(Path(sys.argv[2]).resolve())
work_root = Path(sys.argv[3])
env = os.environ.copy()


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, cwd=None):
    completed = subprocess.run(args, text=True, capture_output=True, env=env, cwd=cwd)
    return completed.returncode, completed.stdout, completed.stderr


def run_bytes(args, cwd=None):
    completed = subprocess.run(args, capture_output=True, env=env, cwd=cwd)
    return completed.returncode, completed.stdout, completed.stderr


def corrupt_entry(key):
    entries_root = Path(env["XDG_DATA_HOME"]) / "secdat" / "domains" / "by-id"
    matches = list(entries_root.glob(f"*/stores/default/entries/{key}.sec"))
    if len(matches) != 1:
        fail(f"could not find one stored entry for {key}: {matches!r}")
    matches[0].write_text("broken", encoding="utf-8")


rc, stdout, stderr = run([fuse_bin, "--help"])
if rc != 0 or "Mount selected secdat keys as files." not in stdout or stderr != "":
    fail(f"secdat-fuse help failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([fuse_bin, "--version"])
if rc != 0 or not stdout.startswith("secdat-fuse ") or stderr != "":
    fail(f"secdat-fuse version failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

domain = work_root / "domain"
mountpoint = work_root / "mount"
domain.mkdir()
mountpoint.mkdir()

for args in [
    [bin_path, "--dir", str(domain), "domain", "create"],
    [bin_path, "--dir", str(domain), "set", "FUSE_TOKEN", "--value", "fuse-secret"],
    [bin_path, "--dir", str(domain), "set", "FUSE_SKIP", "--value", "skip-secret"],
    [bin_path, "--dir", str(domain), "set", "OTHER_TOKEN", "--value", "other-secret"],
    [bin_path, "--dir", str(domain), "set", "ALT_TOKEN", "--value", "alt-secret"],
    [bin_path, "--dir", str(domain), "set", "BULK_TOKEN", "--bulk-select", "include", "--value", "bulk-secret"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup command failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

corrupt_entry("OTHER_TOKEN")
corrupt_entry("ALT_TOKEN")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    str(domain),
    "--pattern",
    "FUSE_*",
    "--pattern-exclude",
    "FUSE_SKIP",
    "--dry-run",
    str(mountpoint),
])
if rc != 0 or stderr != "":
    fail(f"secdat-fuse dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"mountpoint: {mountpoint}\n" not in stdout or "file_count: 1\n" not in stdout or "FUSE_TOKEN\n" not in stdout:
    fail(f"secdat-fuse dry-run missing expected file: {stdout!r}")
if "FUSE_SKIP" in stdout or "OTHER_TOKEN" in stdout:
    fail(f"secdat-fuse dry-run did not apply filters: {stdout!r}")
if "fuse-secret" in stdout or "skip-secret" in stdout or "other-secret" in stdout:
    fail(f"secdat-fuse dry-run leaked secret value: {stdout!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    str(domain),
    "--pattern",
    "FUSE_*",
    "--pattern",
    "ALT_*",
    "--pattern-exclude",
    "FUSE_SKIP",
    "--pattern-exclude",
    "ALT_*",
    "--require-key",
    "FUSE_TOKEN",
    "--dry-run",
    str(mountpoint),
])
if rc != 0 or stderr != "":
    fail(f"secdat-fuse repeated filters failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "file_count: 1\n" not in stdout or "FUSE_TOKEN\n" not in stdout:
    fail(f"secdat-fuse repeated filters missing expected key: {stdout!r}")
if "FUSE_SKIP" in stdout or "ALT_TOKEN" in stdout or "OTHER_TOKEN" in stdout:
    fail(f"secdat-fuse repeated filters exposed excluded key: {stdout!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    str(domain),
    "--pattern",
    "FUSE_*",
    "--require-key",
    "OTHER_TOKEN",
    "--dry-run",
    str(mountpoint),
])
if rc == 0 or stdout != "" or "required key is not selected for secdat-fuse mount: OTHER_TOKEN" not in stderr:
    fail(f"secdat-fuse missing required key did not fail safely: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    str(domain),
    "--pattern",
    "FUSE_*",
    "--pattern-exclude",
    "FUSE_SKIP",
    "--require-key",
    "FUSE_TOKEN",
    "--dry-run",
    "--json",
    str(mountpoint),
])
if rc != 0 or stderr != "":
    fail(f"secdat-fuse JSON dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
report = json.loads(stdout)
if report != {
    "ok": True,
    "mountpoint": str(mountpoint),
    "file_count": 1,
    "files": ["FUSE_TOKEN"],
    "include_patterns": ["FUSE_*"],
    "exclude_patterns": ["FUSE_SKIP"],
    "bulk_gate": False,
    "required_keys": ["FUSE_TOKEN"],
    "missing_required_keys": [],
}:
    fail(f"secdat-fuse JSON dry-run payload mismatch: {report!r}")
if "fuse-secret" in stdout or "skip-secret" in stdout or "other-secret" in stdout or "alt-secret" in stdout:
    fail(f"secdat-fuse JSON dry-run leaked secret value: {stdout!r}")

rc, stdout_bytes, stderr_bytes = run_bytes([
    os.fsencode(fuse_bin),
    b"--dir",
    os.fsencode(domain),
    b"--pattern",
    b"\xff",
    b"--dry-run",
    b"--json",
    os.fsencode(mountpoint),
])
if rc != 0 or stderr_bytes != b"":
    fail(f"secdat-fuse JSON invalid UTF-8 dry-run failed: rc={rc} stdout={stdout_bytes!r} stderr={stderr_bytes!r}")
if b"\xff" in stdout_bytes:
    fail(f"secdat-fuse JSON dry-run emitted raw invalid UTF-8: {stdout_bytes!r}")
report = json.loads(stdout_bytes)
if report["include_patterns"] != [chr(0xff)]:
    fail(f"secdat-fuse JSON invalid UTF-8 pattern was not escaped consistently: {report!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    str(domain),
    "--pattern",
    "FUSE_*",
    "--require-key",
    "OTHER_TOKEN",
    "--dry-run",
    "--json",
    str(mountpoint),
])
if rc == 0 or stderr != "":
    fail(f"secdat-fuse JSON missing required key did not fail as JSON: rc={rc} stdout={stdout!r} stderr={stderr!r}")
report = json.loads(stdout)
if report["ok"] is not False or report["files"] != [] or report["file_count"] != 0 or report["missing_required_keys"] != ["OTHER_TOKEN"]:
    fail(f"secdat-fuse JSON missing required payload mismatch: {report!r}")
if "FUSE_TOKEN" in stdout or "FUSE_SKIP" in stdout:
    fail(f"secdat-fuse JSON missing required exposed selected files: {stdout!r}")

rc, stdout, stderr = run([fuse_bin, "--json", str(mountpoint)])
if rc == 0 or "--json requires --dry-run" not in stderr:
    fail(f"secdat-fuse --json without --dry-run did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([fuse_bin, "--dir", str(domain), "--dry-run", str(mountpoint), "--", "true"])
if rc == 0 or stdout != "" or "invalid arguments" not in stderr:
    fail(f"secdat-fuse dry-run command mode did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--domain",
    str(domain),
    "--pattern",
    "FUSE_TOKEN",
    "--dry-run",
    str(mountpoint),
])
if rc != 0 or stderr != "" or "file_count: 1\n" not in stdout or "FUSE_TOKEN\n" not in stdout:
    fail(f"secdat-fuse --domain dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

child_domain = domain / "child"
child_domain.mkdir()
rc, stdout, stderr = run([
    fuse_bin,
    "--domain",
    str(child_domain),
    "--dry-run",
    str(mountpoint),
])
if rc == 0 or stdout != "" or "domain not found for:" not in stderr:
    fail(f"secdat-fuse --domain accepted an unregistered child: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    fuse_bin,
    "--dir",
    ".",
    "--pattern",
    "FUSE_TOKEN",
    "--dry-run",
    str(mountpoint),
], cwd=domain)
if rc != 0 or stderr != "" or "file_count: 1\n" not in stdout or "FUSE_TOKEN\n" not in stdout:
    fail(f"secdat-fuse relative --dir dry-run failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

live_mount_available = False
if Path("/dev/fuse").exists() and shutil.which("fusermount3") is not None:
    process = subprocess.Popen(
        [
            fuse_bin,
            "--dir",
            str(domain),
            "--pattern",
            "FUSE_*",
            "--pattern-exclude",
            "FUSE_SKIP",
            "--foreground",
            str(mountpoint),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        mounted_file = mountpoint / "FUSE_TOKEN"
        for _ in range(50):
            if mounted_file.exists() or process.poll() is not None:
                break
            time.sleep(0.1)
        if process.poll() is None and mounted_file.exists():
            if mounted_file.stat().st_size != 0:
                fail("mounted FUSE_TOKEN reported nonzero size without --size-metadata")
            if mounted_file.read_text() != "fuse-secret":
                fail("mounted FUSE_TOKEN did not expose expected value")
            mounted_file.write_text("fuse-updated")
            rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "FUSE_TOKEN", "-o"])
            if rc != 0 or stdout != "fuse-updated" or stderr != "":
                fail(f"mounted FUSE_TOKEN write did not update the store: rc={rc} stdout={stdout!r} stderr={stderr!r}")
            if mounted_file.read_text() != "fuse-updated":
                fail("mounted FUSE_TOKEN did not expose the updated value")
            live_mount_available = True
            try:
                (mountpoint / "OTHER_TOKEN").read_text()
                fail("mounted filesystem exposed a key outside the filters")
            except FileNotFoundError:
                pass
            except OSError as error:
                if error.errno != 2:
                    fail(f"unexpected error for filtered key: {error!r}")
        else:
            if process.poll() is None:
                process.terminate()
            try:
                stdout_data, stderr_data = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_data, stderr_data = process.communicate()
            print(f"SKIP fuse mount smoke: helper did not stay mounted: {stdout_data!r} {stderr_data!r}")
    finally:
        subprocess.run(["fusermount3", "-u", str(mountpoint)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

if live_mount_available:
    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "FUSE_TOKEN",
        str(mountpoint),
        "--",
        "python3",
        "-c",
        "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text(), end='')",
        str(mountpoint / "FUSE_TOKEN"),
    ])
    if rc != 0 or stdout != "fuse-updated":
        fail(f"secdat-fuse command mode failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    if (mountpoint / "FUSE_TOKEN").exists():
        fail("secdat-fuse command mode left the mount active after command exit")

    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "FUSE_TOKEN",
        str(mountpoint),
        "--",
        "python3",
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('command-updated')",
        str(mountpoint / "FUSE_TOKEN"),
    ])
    if rc != 0 or stdout != "":
        fail(f"secdat-fuse command mode write failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "FUSE_TOKEN", "-o"])
    if rc != 0 or stdout != "command-updated" or stderr != "":
        fail(f"secdat-fuse command mode write did not persist: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    if (mountpoint / "FUSE_TOKEN").exists():
        fail("secdat-fuse command mode write left the mount active after command exit")

    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "FUSE_TOKEN",
        str(mountpoint),
        "--",
        "python3",
        "-c",
        "from pathlib import Path; import sys\nwith Path(sys.argv[1]).open('a') as stream:\n    stream.write('-tail')",
        str(mountpoint / "FUSE_TOKEN"),
    ])
    if rc != 0 or stdout != "":
        fail(f"secdat-fuse append write failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "FUSE_TOKEN", "-o"])
    if rc != 0 or stdout != "command-updated-tail" or stderr != "":
        fail(f"secdat-fuse append write did not persist: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    if (mountpoint / "FUSE_TOKEN").exists():
        fail("secdat-fuse append write left the mount active after command exit")

    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "BULK_*",
        "--bulk-gate",
        str(mountpoint),
        "--",
        "python3",
        "-c",
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('bulk-updated')",
        str(mountpoint / "BULK_TOKEN"),
    ])
    if rc != 0 or stdout != "":
        fail(f"secdat-fuse bulk-gate write failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "get", "BULK_TOKEN", "-o"])
    if rc != 0 or stdout != "bulk-updated" or stderr != "":
        fail(f"secdat-fuse bulk-gate write did not persist: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "attr", "BULK_TOKEN"])
    if rc != 0 or stdout != "key_visibility=always\nvalue_access=unlocked\nbulk_select=include\n" or stderr != "":
        fail(f"secdat-fuse bulk-gate write did not preserve attributes: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "BULK_*",
        "--bulk-gate",
        "--dry-run",
        str(mountpoint),
    ])
    if rc != 0 or "BULK_TOKEN\n" not in stdout or stderr != "":
        fail(f"secdat-fuse bulk-gate write removed key from selection: rc={rc} stdout={stdout!r} stderr={stderr!r}")

    rc, stdout, stderr = run([
        fuse_bin,
        "--dir",
        str(domain),
        "--pattern",
        "FUSE_TOKEN",
        "--size-metadata",
        str(mountpoint),
        "--",
        "python3",
        "-c",
        "from pathlib import Path; import sys; print(Path(sys.argv[1]).stat().st_size, end='')",
        str(mountpoint / "FUSE_TOKEN"),
    ])
    if rc != 0 or stdout != str(len("command-updated-tail")):
        fail(f"secdat-fuse size metadata mode failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    if (mountpoint / "FUSE_TOKEN").exists():
        fail("secdat-fuse size metadata command mode left the mount active after command exit")

rc, stdout, stderr = run([fuse_bin, "--dry-run"])
if rc == 0 or "missing mountpoint" not in stderr:
    fail(f"secdat-fuse missing mountpoint did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([fuse_bin, "--unknown", str(mountpoint)])
if rc == 0 or "unknown option:" not in stderr:
    fail(f"secdat-fuse unknown option did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS fuse regression")
PY
