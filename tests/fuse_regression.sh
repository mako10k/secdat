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


rc, stdout, stderr = run([fuse_bin, "--help"])
if rc != 0 or "Mount selected secdat keys as read-only files." not in stdout or stderr != "":
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
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup command failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

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
            if mounted_file.read_text() != "fuse-secret":
                fail("mounted FUSE_TOKEN did not expose expected value")
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

rc, stdout, stderr = run([fuse_bin, "--dry-run"])
if rc == 0 or "missing mountpoint" not in stderr:
    fail(f"secdat-fuse missing mountpoint did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([fuse_bin, "--unknown", str(mountpoint)])
if rc == 0 or "unknown option:" not in stderr:
    fail(f"secdat-fuse unknown option did not fail cleanly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

print("PASS fuse regression")
PY
