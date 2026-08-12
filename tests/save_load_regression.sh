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
export SECDAT_MASTER_KEY='save-load-master-key'
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import os
import pty
import re
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
for variable_name in ("SECDAT_ASKPASS", "SSH_ASKPASS"):
    env.pop(variable_name, None)
bundle_passphrase = "bundle-passphrase"

root_dir = work_root / "workspace" / "root"
child_dir = root_dir / "child"
restore_dir = work_root / "workspace" / "restore"
askpass_restore_dir = work_root / "workspace" / "askpass-restore"
selected_restore_dir = work_root / "workspace" / "selected-restore"
legacy_restore_dir = work_root / "workspace" / "legacy-restore"
malformed_restore_dir = work_root / "workspace" / "malformed-restore"
bundle_path = work_root / "backup" / "app.secdat"
tampered_bundle_path = work_root / "backup" / "app-tampered.secdat"
selected_bundle_path = work_root / "backup" / "app-selected.secdat"
legacy_bundle_path = work_root / "backup" / "legacy-v1.secdat"
malformed_bundle_path = work_root / "backup" / "malformed-v2.secdat"
askpass_bundle_path = work_root / "backup" / "askpass.secdat"
askpass_path = work_root / "askpass.py"
askpass_log = work_root / "askpass.log"
bundle_path.parent.mkdir(parents=True, exist_ok=True)
for path in [root_dir, child_dir, restore_dir, askpass_restore_dir, selected_restore_dir, legacy_restore_dir, malformed_restore_dir]:
    path.mkdir(parents=True, exist_ok=True)

askpass_path.write_text(
    "#!/usr/bin/env python3\n"
    "import os\n"
    "import sys\n"
    "with open(os.environ['SECDAT_TEST_ASKPASS_LOG'], 'a', encoding='utf-8') as stream:\n"
    "    stream.write((sys.argv[1] if len(sys.argv) > 1 else '') + '\\n')\n"
    "print(os.environ['SECDAT_TEST_ASKPASS_VALUE'])\n"
)
askpass_path.chmod(0o700)
askpass_env = {
    "SECDAT_ASKPASS": str(askpass_path),
    "SECDAT_TEST_ASKPASS_LOG": str(askpass_log),
    "SECDAT_TEST_ASKPASS_VALUE": bundle_passphrase,
}


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
                fail(f"missing prompt [{expected}] in [{''.join(chunks)}]")
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


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected [{expected}], got [{actual}]")


def assert_contains(output, expected, label):
    if expected not in output:
        fail(f"{label}: missing [{expected}] in [{output}]")


def normalize_spaces(text):
    return re.sub(r"[ \t]+", " ", text)


for args, marker in [
    ([bin_path, "help", "save"], "save [--key KEY]... FILE"),
    (
        [bin_path, "load", "--help"],
        "load [--mask-action=preserve|reject] "
        "[--mask-warnings=default|on|off] [--warn-mask|--no-warn-mask] "
        "[--dry-run] [--json] FILE",
    ),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 0 or marker not in normalize_spaces(output) or "passphrase-protected bundle" not in output:
        fail(f"save/load help check failed for {args}: rc={rc} output={output!r}")

for path in [root_dir, child_dir, restore_dir, askpass_restore_dir, selected_restore_dir, legacy_restore_dir, malformed_restore_dir]:
    rc, stdout, stderr = run([bin_path, "--dir", str(path), "domain", "create"])
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"domain create failed for {path}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(root_dir), "store", "create", "app"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"store create app failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for args in [
    [bin_path, "--dir", str(root_dir), "--store", "app", "set", "INHERITED_APP", "-v", "root-app"],
    [bin_path, "--dir", str(child_dir), "--store", "app", "set", "LOCAL_APP", "-v", "child-app"],
    [bin_path, "--dir", str(child_dir), "--store", "app", "set", "UNSELECTED_APP", "-v", "not-saved"],
    [bin_path, "--dir", str(child_dir), "set", "DEFAULT_ONLY", "-v", "default-value"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup set failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)])
output = stdout + stderr
if rc == 0 or "this command requires a terminal for passphrase input" not in output:
    fail(f"non-tty save should require passphrase terminal: rc={rc} output={output!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(child_dir), "--store", "app", "save",
    "--key", "LOCAL_APP", "--key", "INHERITED_APP", str(selected_bundle_path),
], askpass_env)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"selected save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if not selected_bundle_path.is_file() or selected_bundle_path.stat().st_size == 0:
    fail("selected save did not create a non-empty bundle file")

rc, stdout, stderr = run([
    bin_path, "--dir", str(child_dir), "--store", "app", "save",
    "--key", "MISSING_APP", str(work_root / "backup" / "missing.secdat"),
], askpass_env)
if rc == 0 or "key not found: MISSING_APP" not in stdout + stderr or (work_root / "backup" / "missing.secdat").exists():
    fail(f"selected save missing-key preflight failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

askpass_log.write_text("")
rc, stdout, stderr = run([bin_path, "--dir", str(child_dir), "--store", "app", "save", str(askpass_bundle_path)], askpass_env)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"askpass save failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if not askpass_bundle_path.is_file() or askpass_bundle_path.stat().st_size == 0:
    fail("askpass save did not create a non-empty bundle file")
askpass_prompts = askpass_log.read_text()
assert_contains(askpass_prompts, "Create secdat bundle passphrase:", "askpass save create prompt")
assert_contains(askpass_prompts, "Confirm secdat bundle passphrase:", "askpass save confirm prompt")

rc, transcript = run_pty(
    [bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)],
    [("Create secdat bundle passphrase:", bundle_passphrase), ("Confirm secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"save command failed: rc={rc} transcript={transcript!r}")
if not bundle_path.is_file() or bundle_path.stat().st_size == 0:
    fail("save did not create a non-empty bundle file")
bundle_bytes = bundle_path.read_bytes()
if len(bundle_bytes) < 20 or bundle_bytes[8] != 2:
    fail("save did not write a version 2 bundle")
tampered_bytes = bytearray(bundle_bytes)
tampered_bytes[15] ^= 1
tampered_bundle_path.write_bytes(tampered_bytes)

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(tampered_bundle_path)], askpass_env)
if rc == 0:
    fail("tampered v2 bundle unexpectedly loaded")

malformed_bundle_path.write_bytes(bytes.fromhex(
    "53454344424e444c02100c0000030d4000000029000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1bd7fed30ee540450a4767b6a227498038d0c8c1701629849a"
    "95bb1f7fc54f06441220c77fc17c575c51"
))
rc, stdout, stderr = run([bin_path, "--dir", str(malformed_restore_dir), "--store", "app", "set", "EXISTING", "-v", "keep"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"malformed restore setup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(malformed_restore_dir), "--store", "app", "load", str(malformed_bundle_path)], askpass_env)
if rc == 0 or "invalid secret bundle" not in stdout + stderr:
    fail(f"malformed v2 bundle unexpectedly loaded: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(malformed_restore_dir), "--store", "app", "get", "EXISTING"])
if rc != 0 or stdout != "keep" or stderr != "":
    fail(f"malformed v2 bundle changed destination: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# v1 used the same envelope without authenticated header metadata and stored
# key/value pairs directly.  Keep its reader compatibility independent of the
# current v2 writer.
legacy_bundle_path.write_bytes(bytes.fromhex(
    "53454344424e444c01100c0000030d4000000032000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b84ba913de54045014767b6af330cc77992919e3b5370e8ff"
    "f25f396293219f311876ae8e432358478470a2931ef914c8c61f"
))

rc, stdout, stderr = run([bin_path, "--dir", str(legacy_restore_dir), "--store", "app", "set", "EXISTING", "-v", "keep"])
if rc != 0 or stdout != "" or stderr != "":
    fail(f"legacy restore setup failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(legacy_restore_dir), "--store", "app", "load", str(legacy_bundle_path)], askpass_env)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"legacy v1 load failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run([bin_path, "--dir", str(legacy_restore_dir), "--store", "app", "get", "LEGACY_KEY"])
if rc != 0 or stdout != "legacy-value" or stderr != "":
    fail(f"legacy v1 value mismatch: rc={rc} stdout={stdout!r} stderr={stderr!r}")


rc, transcript = run_pty(
    [bin_path, "--dir", str(child_dir), "--store", "app", "save", str(bundle_path)],
    [("Create secdat bundle passphrase:", bundle_passphrase), ("Confirm secdat bundle passphrase:", bundle_passphrase)],
)
if rc == 0 or "bundle file already exists" not in transcript:
    fail(f"save overwrite semantics failed: rc={rc} transcript={transcript!r}")

for args in [
    [bin_path, "--dir", str(restore_dir), "--store", "app", "set", "LOCAL_APP", "-v", "old-value"],
    [bin_path, "--dir", str(restore_dir), "--store", "app", "set", "EXTRA_APP", "-v", "keep-me"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"restore setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(bundle_path)])
output = stdout + stderr
if rc == 0 or "this command requires a terminal for passphrase input" not in output:
    fail(f"non-tty load should require passphrase terminal: rc={rc} output={output!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(restore_dir), "--store", "app", "load", str(bundle_path)],
    [("Enter secdat bundle passphrase:", bundle_passphrase)],
)
if rc != 0:
    fail(f"load command failed: rc={rc} transcript={transcript!r}")

for args in [
    [bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "set", "LOCAL_APP", "-v", "old-value"],
    [bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "set", "EXTRA_APP", "-v", "keep-me"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"askpass restore setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

for args in [
    [bin_path, "--dir", str(selected_restore_dir), "--store", "app", "set", "LOCAL_APP", "-v", "old-value"],
    [bin_path, "--dir", str(selected_restore_dir), "--store", "app", "set", "UNSELECTED_APP", "-v", "keep-me"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"selected restore setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(selected_restore_dir), "--store", "app", "load", str(selected_bundle_path)], askpass_env)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"selected load failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

askpass_log.write_text("")
rc, stdout, stderr = run([bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "load", str(askpass_bundle_path)], askpass_env)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"askpass load failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(askpass_log.read_text(), "Enter secdat bundle passphrase:", "askpass load prompt")

for args, expected, label in [
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "INHERITED_APP", "-o"], "root-app", "inherited app key"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "LOCAL_APP", "-o"], "child-app", "overwritten local app key"),
    ([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "EXTRA_APP", "-o"], "keep-me", "unspecified key preserved"),
    ([bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "get", "INHERITED_APP", "-o"], "root-app", "askpass inherited app key"),
    ([bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "get", "LOCAL_APP", "-o"], "child-app", "askpass overwritten local app key"),
    ([bin_path, "--dir", str(askpass_restore_dir), "--store", "app", "get", "EXTRA_APP", "-o"], "keep-me", "askpass unspecified key preserved"),
    ([bin_path, "--dir", str(selected_restore_dir), "--store", "app", "get", "INHERITED_APP", "-o"], "root-app", "selected inherited app key"),
    ([bin_path, "--dir", str(selected_restore_dir), "--store", "app", "get", "LOCAL_APP", "-o"], "child-app", "selected local app key"),
    ([bin_path, "--dir", str(selected_restore_dir), "--store", "app", "get", "UNSELECTED_APP", "-o"], "keep-me", "selected bundle excludes unselected key"),
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stderr != "":
        fail(f"post-load get failed for {label}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
    assert_eq(stdout, expected, label)

rc, stdout, stderr = run([bin_path, "--dir", str(restore_dir), "--store", "app", "get", "DEFAULT_ONLY", "-o"])
if rc == 0:
    fail("save unexpectedly included default-store key in app-store bundle")
assert_contains(stdout + stderr, "key not found: DEFAULT_ONLY", "store-scoped save/load")

print("PASS save/load regression")
PY
