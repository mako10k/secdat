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
import unicodedata
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib

bin_path = sys.argv[1]
env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
japanese_env = {
    "LC_ALL": "",
    "LC_MESSAGES": "ja_JP.UTF-8",
    "LANG": "ja_JP.UTF-8",
    "LANGUAGE": "ja",
}
for variable_name in (
    "SECDAT_MASTER_KEY",
    "SECDAT_MASTER_KEY_PASSPHRASE",
    "SECDAT_MASTER_KEY_PBKDF2_ITERATIONS",
    "SECDAT_ASKPASS",
    "SECDAT_GET_ON_DEMAND_UNLOCK",
    "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS",
    "SSH_ASKPASS",
):
    env.pop(variable_name, None)
passphrase = "passphrase-for-session-test"
wrapped_path = Path(env["XDG_DATA_HOME"]) / "secdat" / "master-key.bin"
isolated_root = Path(env["XDG_RUNTIME_DIR"]).parent
root_domain = isolated_root / "domain-root"
child_domain = root_domain / "child-domain"
grandchild_domain = child_domain / "grandchild-domain"
sibling_domain = isolated_root / "sibling-domain"
askpass_path = isolated_root / "askpass.py"
cancel_askpass_path = isolated_root / "cancel-askpass.py"
unsupported_askpass_path = isolated_root / "unsupported-askpass.py"
askpass_log = isolated_root / "askpass.log"

askpass_path.write_text(
    "#!/usr/bin/env python3\n"
    "import os\n"
    "import sys\n"
    "with open(os.environ['SECDAT_TEST_ASKPASS_LOG'], 'a', encoding='utf-8') as stream:\n"
    "    stream.write((sys.argv[1] if len(sys.argv) > 1 else '') + '\\n')\n"
    "print(os.environ['SECDAT_TEST_ASKPASS_VALUE'])\n"
)
askpass_path.chmod(0o700)
cancel_askpass_path.write_text(
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "sys.exit(1)\n"
)
cancel_askpass_path.chmod(0o700)
unsupported_askpass_path.write_text("#!/usr/bin/env python3\nprint('unused')\n")
askpass_env = {
    "SECDAT_ASKPASS": str(askpass_path),
    "SECDAT_TEST_ASKPASS_LOG": str(askpass_log),
    "SECDAT_TEST_ASKPASS_VALUE": passphrase,
}
askpass_value_env = {
    "SECDAT_TEST_ASKPASS_LOG": str(askpass_log),
    "SECDAT_TEST_ASKPASS_VALUE": passphrase,
}
read_compat_env = askpass_env.copy()
read_compat_env["SECDAT_MASTER_KEY_PBKDF2_ITERATIONS"] = "250000"

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


def assert_contains_any(output, fragments, context):
    if any(fragment in output for fragment in fragments):
        return
    fail(f"{context}: missing any of {fragments!r} in {output!r}")

def read_wrapped_iterations(path=wrapped_path):
    data = path.read_bytes()
    if len(data) < 20 or data[:8] != b"SECDWRP\0":
        fail(f"invalid wrapped key header in {path}")
    return int.from_bytes(data[12:16], "big")

def normalize_spaces(text):
    return re.sub(r"[ \t]+", " ", text)

def display_width(text):
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        if unicodedata.east_asian_width(char) in ("W", "F"):
            width += 2
        else:
            width += 1
    return width

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

def description_display_column(output, label):
    prefix = f"  {label}"
    for line in output.splitlines():
        if line.startswith(prefix):
            suffix = line[len(prefix):]
            stripped = suffix.lstrip(" ")
            if stripped == "":
                fail(f"missing description after label {label!r} in line {line!r}")
            return display_width(line[: len(line) - len(stripped)])
    fail(f"missing line for label {label!r} in output {output!r}")

def usage_command_column(output, command):
    in_usage = False
    for line in output.splitlines():
        if line == "Usage:":
            in_usage = True
            continue
        if not in_usage:
            continue
        if line == "":
            break
        if not line.startswith("  "):
            continue
        program_end = line.find(" ", 2)
        if program_end < 0:
            continue
        column = line.find(command, program_end + 1)
        if column >= 0:
            return column
    fail(f"missing usage command {command!r} in output {output!r}")

def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr

def run_bytes(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr

def run_background(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    return subprocess.Popen(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run_env)

def assert_pot_is_up_to_date():
    repo_root = Path(bin_path).resolve().parent.parent
    po_dir = repo_root / "po"
    pot_path = po_dir / "secdat.pot"
    ignore_check = subprocess.run(
        ["git", "-C", str(repo_root), "check-ignore", "-q", "po/secdat.pot"],
        text=True,
        capture_output=True,
        env=env,
    )
    if ignore_check.returncode == 0:
        return
    if not pot_path.exists():
        return
    original = pot_path.read_text(encoding="utf-8")
    try:
        completed = subprocess.run(
            ["make", "-C", str(po_dir), "secdat.pot-update"],
            text=True,
            capture_output=True,
            env=env,
        )
        if completed.returncode != 0:
            fail(
                "secdat.pot update failed: "
                f"rc={completed.returncode} stdout={completed.stdout!r} stderr={completed.stderr!r}"
            )
        updated = pot_path.read_text(encoding="utf-8")
        if updated != original:
            fail("po/secdat.pot is stale; regenerate it after changing translatable strings")
    finally:
        pot_path.write_text(original, encoding="utf-8")

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

invalid_utf8_domain_bytes = os.fsencode(isolated_root) + b"/invalid-json-\xff"
os.mkdir(invalid_utf8_domain_bytes)
invalid_utf8_domain = os.fsdecode(invalid_utf8_domain_bytes)
rc, stdout, stderr = run_bytes([bin_path, "--dir", invalid_utf8_domain, "domain", "create"])
if rc != 0 or stdout != b"" or stderr != b"":
    fail(f"invalid-utf8 domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run_bytes([bin_path, "--dir", invalid_utf8_domain, "domain", "status", "--json"])
if rc != 0 or stderr != b"":
    fail(f"invalid-utf8 domain status --json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
invalid_utf8_status = json.loads(stdout)
if invalid_utf8_status["resolved_domain"].endswith("invalid-json-ÿ") is False:
    fail(f"invalid-utf8 domain status --json returned unexpected path: {invalid_utf8_status!r}")

rc, _, _ = run(scoped(["status", "--quiet"]))
if rc != 1:
    fail(f"status --quiet while locked returned {rc}")

rc, stdout, stderr = run(scoped(["status", "--json"]))
if rc != 1 or stderr != "":
    fail(f"status --json while locked failed unexpectedly: rc={rc} stdout={stdout!r} stderr={stderr!r}")
locked_status = json.loads(stdout)
if locked_status["unlocked"] or locked_status["key_source"] != "locked" or locked_status["effective_source"] != "locked" or locked_status["wrapped_master_key_present"]:
    fail(f"status --json while locked returned unexpected state: {locked_status!r}")
if locked_status["resolved_domain"] != str(root_domain) or locked_status["store_count"] != 1 or locked_status["visible_key_count"] != 0:
    fail(f"status --json while locked returned unexpected metadata: {locked_status!r}")

rc, stdout, stderr = run(scoped(["status", "--quiet", "--json"]))
if rc != 2 or stdout != "" or "invalid arguments for status" not in stderr:
    fail(f"status --quiet --json should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

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

rc, stdout, stderr = run(scoped(["ls", "--json", "--canonical-domain", "--canonical-store", "--unsafe"]))
if rc != 0 or stderr != "":
    fail(f"ls --json while locked failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "visible-while-locked" in stdout:
    fail(f"ls --json leaked secret value: {stdout!r}")
ls_metadata = json.loads(stdout)
if ls_metadata["key_count"] != 1 or len(ls_metadata["keys"]) != 1:
    fail(f"ls --json returned unexpected key count: {ls_metadata!r}")
json_key = ls_metadata["keys"][0]
if (
    json_key["key"] != "UNSAFE_VISIBLE_KEY"
    or json_key["store"] != "default"
    or json_key["source_domain"] != str(root_domain)
    or json_key["canonical_keyref"] != f"{root_domain}/UNSAFE_VISIBLE_KEY:default"
    or json_key["storage_mode"] != "unsafe"
    or not json_key["unsafe_store"]
):
    fail(f"ls --json returned unexpected key metadata: {ls_metadata!r}")

rc, stdout, stderr = run(scoped(["store", "ls", "--json"]))
if rc != 0 or stderr != "":
    fail(f"store ls --json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
store_listing = json.loads(stdout)
if store_listing["resolved_domain"] != str(root_domain) or store_listing["store_count"] != 1 or [item["name"] for item in store_listing["stores"]] != ["default"]:
    fail(f"store ls --json returned unexpected metadata: {store_listing!r}")

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

rc, stdout, stderr = run(scoped(["status", "--json"]))
if rc != 0 or stderr != "":
    fail(f"volatile status json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
volatile_status = json.loads(stdout)
if not volatile_status["unlocked"] or volatile_status["key_source"] != "session" or volatile_status["effective_source"] != "local_unlock" or volatile_status["session_mode"] != "volatile" or volatile_status["remaining_seconds"] is None:
    fail(f"volatile status json unexpected: {volatile_status!r}")

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

repair_guard_store = "repairguard"
rc, stdout, stderr = run(scoped(["store", "create", repair_guard_store]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"readonly repair guard store create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(scoped(["--store", repair_guard_store, "set", "REPAIR_GUARD_KEY", "--unsafe", "--value", "repair-guard-value"]))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"readonly repair guard set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(scoped(["store", "migrate", repair_guard_store, "--to-format", "v2"]))
if rc != 0 or stderr != "":
    fail(f"readonly repair guard migrate failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
rc, stdout, stderr = run(scoped(["--store", repair_guard_store, "id", "REPAIR_GUARD_KEY"]))
if rc != 0 or stderr != "":
    fail(f"readonly repair guard id failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
repair_guard_secret_id = stdout.strip()
repair_guard_object_paths = list(Path(env["XDG_DATA_HOME"]).rglob(f"{repair_guard_secret_id}.sec"))
if len(repair_guard_object_paths) != 1:
    fail(f"expected one repair guard object, found {repair_guard_object_paths!r}")
repair_guard_object_path = repair_guard_object_paths[0]
repair_guard_object_path.write_text(
    repair_guard_object_path.read_text(encoding="utf-8").replace("refcount=1\n", "refcount=5\n"),
    encoding="utf-8",
)

readonly_env = {"SECDAT_MASTER_KEY": "readonly-master-key-for-tests"}

rc, stdout, stderr = run(scoped(["unlock", "--readonly"]), extra_env=readonly_env)
if rc != 0 or "readonly session unlocked from environment" not in stdout or "resolved domain:" not in stderr:
    fail(f"readonly unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"]))
if rc != 0 or "access: readonly\n" not in stdout or stderr != "":
    fail(f"readonly status failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status", "--json"]))
if rc != 0 or stderr != "":
    fail(f"readonly status json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
readonly_status = json.loads(stdout)
if not readonly_status["unlocked"] or readonly_status["session_mode"] != "readonly" or readonly_status["effective_state"] != "unlocked":
    fail(f"readonly status json unexpected: {readonly_status!r}")

rc, stdout, stderr = run(scoped(["set", "READONLY_BLOCKED_KEY", "--value", "blocked"]))
if rc == 0 or "current session is readonly and cannot run set" not in stderr or f"unlock writable session: secdat --dir {root_domain} unlock" not in stderr:
    fail(f"readonly set should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["store", "migrate", "default", "--to-format", "v2"]))
if rc == 0 or stdout != "" or "current session is readonly and cannot run store migrate" not in stderr or f"unlock writable session: secdat --dir {root_domain} unlock" not in stderr:
    fail(f"readonly store migrate should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["--store", repair_guard_store, "fsck", "--format", "v2", "--refcount", "--repair"]))
if rc == 0 or stdout != "" or "current session is readonly and cannot run fsck --repair" not in stderr or f"unlock writable session: secdat --dir {root_domain} unlock" not in stderr:
    fail(f"readonly fsck repair should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "refcount=5\n" not in repair_guard_object_path.read_text(encoding="utf-8"):
    fail("readonly fsck repair mutated cached refcount")

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
    ([bin_path, "help", "status"], "[-d DIR|--dir DIR] status [-q|--quiet|--json]"),
    ([bin_path, "--help", "status"], "[-d DIR|--dir DIR] status [-q|--quiet|--json]"),
    ([bin_path, "-h", "status"], "[-d DIR|--dir DIR] status [-q|--quiet|--json]"),
    ([bin_path, "status", "--help"], "[-d DIR|--dir DIR] status [-q|--quiet|--json]"),
    ([bin_path, "status", "-h"], "[-d DIR|--dir DIR] status [-q|--quiet|--json]"),
    ([bin_path, "help", "unlock"], "unlock [-t TTL|--duration TTL] [--until TIME] [-i|--inherit] [-v|--volatile|-r|--readonly] [-d|--descendants] [-y|--yes] [--askpass PATH]"),
    ([bin_path, "help", "inherit"], "[-d DIR|--dir DIR] inherit"),
    ([bin_path, "help", "lock"], "[-d DIR|--dir DIR] lock [-i|--inherit] [-s|--save]"),
    ([bin_path, "help", "list"], "list [-m|--masked] [-o|--overridden] [-O|--orphaned] [-e|--safe|--secret-value] [-u|--unsafe|--public-value] [--sandbox-injectable]"),
    ([bin_path, "help", "attr"], "attr KEYREF [--key-visibility always|unlocked] [--value-access unlocked|always] [--sandbox-inject never|explicit|bulk]"),
    ([bin_path, "help", "fsck"], "fsck [--orphaned] [--dangling] [--refcount] [--repair] [--format v1|v2]"),
    ([bin_path, "help", "gc"], "gc [--orphaned] [--dangling] [--dry-run] [--format v2]"),
    ([bin_path, "help", "mask"], "mask KEYREF"),
    ([bin_path, "help", "unmask"], "unmask KEYREF"),
    ([bin_path, "help", "exists"], "exists KEYREF"),
    ([bin_path, "help", "id"], "id KEYREF"),
    ([bin_path, "help", "ls"], "[-x GLOBPATTERN|--pattern-exclude GLOBPATTERN] [-e|--safe|--secret-value] [-u|--unsafe|--public-value] [--metadata] [--sandbox-injectable]"),
    ([bin_path, "help", "get"], "[-w|--on-demand-unlock] [-t SECONDS|--unlock-timeout SECONDS] KEYREF"),
    ([bin_path, "help", "wait-unlock"], "wait-unlock [-t SECONDS|--timeout SECONDS] [-q|--quiet]"),
    ([bin_path, "help", "exec"], "[-x GLOBPATTERN|--pattern-exclude GLOBPATTERN] [--env-map-sed EXPR] [--sandbox-injectable] [--] CMD [ARGS...]"),
    ([bin_path, "help", "rm"], "rm [-f|--ignore-missing] KEYREF"),
    ([bin_path, "help", "ln"], "ln SRC_KEYREF|@UUID DST_KEYREF"),
    ([bin_path, "help", "set"], "set KEYREF [-u|--unsafe|--public-value|--secret-value]"),
    ([bin_path, "help", "export"], "export [-p GLOBPATTERN|--pattern GLOBPATTERN] [--sandbox-injectable]"),
    ([bin_path, "help", "passwd"], "passwd [--askpass PATH]"),
    ([bin_path, "help", "store"], "store migrate STORE --to-format v2 [--dry-run]"),
    ([bin_path, "help", "store", "migrate"], "store migrate STORE --to-format v2 [--dry-run]"),
    ([bin_path, "--help", "store", "migrate"], "store migrate STORE --to-format v2 [--dry-run]"),
    ([bin_path, "store", "migrate", "--help"], "store migrate STORE --to-format v2 [--dry-run]"),
    ([bin_path, "help", "store", "finalize-migration"], "store finalize-migration STORE --from-format v1 [--dry-run]"),
    ([bin_path, "--help", "store", "finalize-migration"], "store finalize-migration STORE --from-format v1 [--dry-run]"),
    ([bin_path, "store", "finalize-migration", "--help"], "store finalize-migration STORE --from-format v1 [--dry-run]"),
    ([bin_path, "help", "secret"], "secret status UUID"),
    ([bin_path, "help", "secret", "status"], "secret status UUID"),
    ([bin_path, "--help", "secret", "status"], "secret status UUID"),
    ([bin_path, "secret", "status", "--help"], "secret status UUID"),
    ([bin_path, "help", "domain"], "domain ls [-l|--long] [-a|--inherited] [-A|--ancestors] [-R|--descendants]"),
    ([bin_path, "help", "domain", "status"], "domain status [-q|--quiet|--json]"),
    ([bin_path, "domain", "status", "--help"], "domain status [-q|--quiet|--json]"),
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

usage_alignment_targets = [
    ([bin_path, "help", "help"], ["help"]),
    ([bin_path, "help", "version"], ["version"]),
    ([bin_path, "help", "ls"], ["ls"]),
    ([bin_path, "help", "rm"], ["rm"]),
    ([bin_path, "help", "cp"], ["cp"]),
    ([bin_path, "help", "get"], ["get"]),
    ([bin_path, "help", "unlock"], ["unlock"]),
    ([bin_path, "help", "wait-unlock"], ["wait-unlock"]),
    ([bin_path, "help", "secret"], ["secret status"]),
    ([bin_path, "help", "store"], [
        "store create",
        "store delete",
        "store ls",
        "store migrate",
        "store finalize-migration",
    ]),
    ([bin_path, "help", "domain"], [
        "domain create",
        "domain delete",
        "domain ls",
        "domain status",
    ]),
]
usage_columns = {}
for args, commands in usage_alignment_targets:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 0:
        fail(f"usage alignment help failed for {args}: rc={rc} output={output!r}")
    for command in commands:
        usage_columns[command] = usage_command_column(output, command)

expected_usage_column = usage_columns["ls"]
misaligned_usage_columns = {
    command: column
    for command, column in usage_columns.items()
    if column != expected_usage_column
}
if misaligned_usage_columns:
    fail(f"usage command column mismatch: expected={expected_usage_column} columns={usage_columns!r}")

for args, fragments in [
    (
        [bin_path, "help", "store", "migrate"],
        [
            "store migrate: validate one v1 store;",
            "leave v1 fallback files in place",
            "write the v2 graph after reviewing the dry-run output:",
        ],
    ),
    (
        [bin_path, "store", "migrate", "--help"],
        [
            "store migrate: validate one v1 store;",
            "leave v1 fallback files in place",
            "write the v2 graph after reviewing the dry-run output:",
        ],
    ),
    (
        [bin_path, "help", "store", "finalize-migration"],
        [
            "store finalize-migration:",
            "inspect legacy v1 fallback files;",
            "refuse to remove anything while blockers remain",
            "typical order is migrate dry-run, migrate, fsck --format v2",
            "remove removable legacy fallback files only after blockers are gone:",
        ],
    ),
    (
        [bin_path, "help", "unlock"],
        [
            "--volatile keeps writes, deletes, tombstones",
            "lock --save persists supported overlay changes before locking",
            "v2 local-entry deletions still require a normal writable session",
        ],
    ),
    (
        [bin_path, "help", "secret", "status"],
        [
            "secret status: print one v2 secret object's non-secret metadata and reference counts",
            "UUID lookup is scoped to the current domain/store object view",
            "inspect one v2 secret object by UUID without reading its value:",
        ],
    ),
    (
        [bin_path, "help", "attr"],
        [
            "value_access=always stores a public/plaintext-at-rest value",
            "sandbox_inject controls export/exec eligibility",
            "--sandbox-injectable is used",
            "secret object's secret_inject policy",
        ],
    ),
    (
        [bin_path, "help", "fsck"],
        [
            "with no filters, fsck runs orphaned, dangling, and refcount checks",
            "--repair only rebuilds cached v2 refcounts",
        ],
    ),
    (
        [bin_path, "help", "gc"],
        [
            "--dry-run previews selected v2 graph files",
            "without --dry-run it permanently removes the selected graph files",
        ],
    ),
    (
        [bin_path, "help", "ln"],
        [
            "value writes through either linked key affect the shared object",
            "domain-entry attributes remain per link",
        ],
    ),
    (
        [bin_path, "help", "id"],
        [
            "id: print the v2 secret object UUID for one resolved key",
            "the UUID is an address, not authority",
            "resolve one key to its v2 secret object UUID without reading it:",
        ],
    ),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if rc != 0:
        fail(f"detailed help marker check failed for {args}: rc={rc} output={output!r}")
    for fragment in fragments:
        if fragment not in normalize_spaces(output):
            fail(f"detailed help marker check failed for {args}: missing {fragment!r} in {output!r}")

rc, stdout, stderr = run([bin_path, "help", "get"])
output = stdout + stderr
if rc != 0 or "Use cases:" not in output or "read one value to stdout:" not in output or "wait for another terminal to unlock before reading:" not in output:
    fail(f"get use cases help check failed: rc={rc} output={output!r}")

for args, marker in [
    ([bin_path, "get", "KEY", "--help"], " KEYREF "),
    ([bin_path, "set", "KEY", "--help"], "set KEYREF"),
    ([bin_path, "domain", "ls", "ROOT", "--help"], "domain ls [-l|--long]"),
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or marker not in normalize_spaces(stdout) or stderr != "":
        fail(f"explicit help stdout check failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "help", "usecases"])
output = stdout + stderr
if rc != 0 or "Meaning:" not in output or "Use cases:" not in output or "bootstrap a new project domain:" not in output or "block automation until a human unlocks the domain elsewhere:" not in output:
    fail(f"usecases topic help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help", "concepts"])
output = stdout + stderr
if rc != 0 or "Meaning:" not in output or "Concepts:" not in output or "local lock:" not in output or "local unlock:" not in output or "KEYREF:" not in output:
    fail(f"concepts topic help check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help"])
output = stdout + stderr
normalized_output = normalize_spaces(output)
if rc != 0 or "[options] subcommand ..." not in normalized_output or "Options:" not in output or "Commands:" not in output or "Topics:" not in output or "Support:" not in output or "issues: https://github.com/mako10k/secdat/issues" not in normalized_output or "help: show global help" not in normalized_output or "version: print the secdat version" not in normalized_output:
    fail(f"help subcommand check failed: rc={rc} output={output!r}")

for args, expected in [
    ([bin_path, "unlock", "--bad"], f"Try: {bin_path} help unlock"),
    ([bin_path, "unlock", "--volatile", "--readonly"], f"Try: {bin_path} help unlock"),
    ([bin_path, "unlock", "--duration", "15", "--until", "2026-04-21T15:04:05Z"], "--duration and --until cannot be combined"),
    ([bin_path, "unlock", "--duration", "bad", "--until", "2026-04-21T15:04:05Z"], "--duration and --until cannot be combined"),
    ([bin_path, "unlock", "--until", "not-a-date", "--duration", "bad"], "--duration and --until cannot be combined"),
    ([bin_path, "--store", "default", "status"], f"Try: {bin_path} help status"),
    ([bin_path, "store", "create"], f"Try: {bin_path} help store"),
    ([bin_path, "get", "KEY", "--bad"], f"Try: {bin_path} help get"),
    ([bin_path, "get", "--unlock-timeout", "1", "KEY"], "--unlock-timeout requires --on-demand-unlock or SECDAT_GET_ON_DEMAND_UNLOCK"),
    ([bin_path, "wait-unlock", "--bad"], f"Try: {bin_path} help wait-unlock"),
    ([bin_path, "set", "KEY", "--bad"], f"Try: {bin_path} help set"),
    ([bin_path, "cp", "ONLY_ONE"], f"Try: {bin_path} help cp"),
    ([bin_path, "mv", "ONLY_ONE"], f"Try: {bin_path} help mv"),
    ([bin_path, "ln", "ONLY_ONE"], f"Try: {bin_path} help ln"),
    ([bin_path, "rm"], f"Try: {bin_path} help rm"),
    ([bin_path, "exec"], f"Try: {bin_path} help exec"),
    ([bin_path, "passwd", "--bad"], f"Try: {bin_path} help passwd"),
    ([bin_path, "lock", "--bad"], f"Try: {bin_path} help lock"),
    ([bin_path, "store", "bogus"], f"Try: {bin_path} help store"),
    ([bin_path, "domain", "bogus"], f"Try: {bin_path} help domain"),
    ([bin_path, "bogus", "extra"], f"Try: {bin_path} help get"),
]:
    rc, stdout, stderr = run(args)
    output = stdout + stderr
    if expected.startswith(f"Try: {bin_path} help "):
        expected_variants = [expected]
        relative_bin_path = os.path.relpath(bin_path, Path.cwd())
        if not relative_bin_path.startswith("."):
            relative_bin_path = f"./{relative_bin_path}"
        expected_variants.append(expected.replace(bin_path, relative_bin_path, 1))
    else:
        expected_variants = [expected]

    if rc != 2:
        fail(f"recovery hint check failed for {args}: rc={rc} output={output!r}")
    assert_contains_any(output, expected_variants, f"recovery hint check failed for {args}")

rc, stdout, stderr = run([bin_path, "store", "create"])
output = stdout + stderr
if rc != 2 or "missing store name for store create" not in output:
    fail(f"missing operand check failed for store create: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help"])
output = stdout + stderr
normalized_output = normalize_spaces(output)
if rc != 0 or "[options] subcommand ..." not in normalized_output or "Options:" not in output or "-d, --dir DIR" not in normalized_output or "Commands:" not in output or "Topics:" not in output or "Groups:" not in output or "Support:" not in output or "repository: https://github.com/mako10k/secdat" not in normalized_output or "help usecases" not in normalized_output or "help concepts" not in normalized_output or "--help COMMAND" not in normalized_output or "COMMAND --help" not in normalized_output or "--version" not in normalized_output or "store migrate:" not in normalized_output or "store finalize-migration:" not in normalized_output:
    fail(f"global help check failed: rc={rc} output={output!r}")

help_column = description_column(output, "help:")
get_column = description_column(output, "get:")
wait_unlock_column = description_column(output, "wait-unlock:")
if help_column != get_column or get_column != wait_unlock_column:
    fail(f"command help alignment mismatch: help={help_column} get={get_column} wait-unlock={wait_unlock_column} output={output!r}")

rc, stdout, stderr = run([bin_path, "--help"], japanese_env)
output = stdout + stderr
if rc != 0 or "トピック:" not in output or "show global help, or combine with COMMAND or TOPIC for detailed help" in output or "decrypt one resolved key and write it to standard output; --on-demand-unlock waits for another terminal to unlock" in output or "explain domains, stores, inheritance, sessions, and KEYREF resolution" in output or "local unlock" not in output or "local lock" not in output:
    fail(f"japanese global help translation check failed: rc={rc} output={output!r}")
if "全体 help を表示します。\n                        COMMAND または TOPIC と組み合わせると詳細 help を表示します" not in output:
    fail(f"japanese global help wrap check failed: rc={rc} output={output!r}")

issues_column = description_display_column(output, "issue 報告先:")
repository_column = description_display_column(output, "repository:")
if issues_column != repository_column:
    fail(f"japanese help alignment mismatch: issues={issues_column} repository={repository_column} output={output!r}")

rc, stdout, stderr = run([bin_path, "help", "get"], japanese_env)
output = stdout + stderr
if rc != 0 or "利用例:" not in output or "意味:" not in output or "read one value to stdout:" in output or "wait for another terminal to unlock before reading:" in output:
    fail(f"japanese get help translation check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help", "unlock"], japanese_env)
output = stdout + stderr
if rc != 0 or "local unlock" not in output or "local override" not in output or "authenticated secret session" in output:
    fail(f"japanese unlock help translation check failed: rc={rc} output={output!r}")
if "現在の domain 用の local unlock を開始または更新します。\n                        --duration" not in output or "3339 timestamp を受け付けます。\n                        --inherit" not in output:
    fail(f"japanese unlock help wrap check failed: rc={rc} output={output!r}")

rc, stdout, stderr = run([bin_path, "help", "lock"], japanese_env)
output = stdout + stderr
if rc != 0 or "ローカルなロック状態へ戻し" not in output or "clear the current domain's direct secret session" in output:
    fail(f"japanese lock help translation check failed: rc={rc} output={output!r}")

assert_pot_is_up_to_date()

rc, stdout, stderr = run([bin_path, "--version"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Issues: https://github.com/mako10k/secdat/issues" not in output or "Author: Makoto Katsumata <mako10k@mk10.org>" not in output:
    fail(f"--version failed: rc={rc} output={(stdout + stderr)!r}")
source_root = Path(bin_path).resolve().parent.parent
build_line = next((line for line in output.splitlines() if line.startswith("Build: ")), "")
if build_line and not re.fullmatch(r"Build: [0-9a-f]{7,40}(?:-dirty)?", build_line):
    fail(f"--version build line format failed: output={output!r}")
if (source_root / ".git").exists() and build_line == "":
    fail(f"--version missing build line in git worktree: output={output!r}")

rc, stdout, stderr = run([bin_path, "version"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Repository: https://github.com/mako10k/secdat" not in output:
    fail(f"version failed: rc={rc} output={(stdout + stderr)!r}")
build_line = next((line for line in output.splitlines() if line.startswith("Build: ")), "")
if build_line and not re.fullmatch(r"Build: [0-9a-f]{7,40}(?:-dirty)?", build_line):
    fail(f"version build line format failed: output={output!r}")
if (source_root / ".git").exists() and build_line == "":
    fail(f"version missing build line in git worktree: output={output!r}")

rc, stdout, stderr = run([bin_path, "-V"])
output = stdout + stderr
if rc != 0 or not output.startswith("secdat ") or "Issues: https://github.com/mako10k/secdat/issues" not in output:
    fail(f"-V failed: rc={rc} output={(stdout + stderr)!r}")
build_line = next((line for line in output.splitlines() if line.startswith("Build: ")), "")
if build_line and not re.fullmatch(r"Build: [0-9a-f]{7,40}(?:-dirty)?", build_line):
    fail(f"-V build line format failed: output={output!r}")
if (source_root / ".git").exists() and build_line == "":
    fail(f"-V missing build line in git worktree: output={output!r}")

invalid_kdf_runtime = isolated_root / "invalid-kdf-runtime"
invalid_kdf_data = isolated_root / "invalid-kdf-data"
invalid_kdf_runtime.mkdir(parents=True, exist_ok=True)
invalid_kdf_data.mkdir(parents=True, exist_ok=True)
invalid_kdf_wrapped = invalid_kdf_data / "secdat" / "master-key.bin"
rc, transcript = run_pty(
    scoped(["unlock"], root_domain),
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {
        "XDG_RUNTIME_DIR": str(invalid_kdf_runtime),
        "XDG_DATA_HOME": str(invalid_kdf_data),
        "SECDAT_MASTER_KEY_PBKDF2_ITERATIONS": "199999",
    },
)
if rc == 0 or "SECDAT_MASTER_KEY_PBKDF2_ITERATIONS must be an integer between 200000 and 10000000" not in transcript:
    fail(f"invalid PBKDF2 iteration count should fail: rc={rc} transcript={transcript!r}")
if invalid_kdf_wrapped.exists():
    fail("invalid PBKDF2 iteration count created a wrapped master key")

rc, transcript = run_pty(
    scoped(["unlock", "--duration", "2"]),
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
)
if rc != 0 or f"resolved domain: {root_domain}" not in transcript or "persistent master key initialized; session unlocked" not in transcript:
    fail(f"bootstrap unlock failed: rc={rc} transcript={transcript!r}")
if "note: 2 descendant domains remain locked under this branch" not in transcript:
    fail(f"bootstrap unlock coverage summary missing: transcript={transcript!r}")
if not wrapped_path.is_file():
    fail("wrapped master key was not created")
if read_wrapped_iterations() != 200000:
    fail(f"default wrapped master key iterations unexpected: {read_wrapped_iterations()}")

rc, stdout, _ = run(scoped(["status"], root_domain))
if rc != 0 or "source: session agent" not in stdout or "wrapped master key: present" not in stdout or re.search(r"expires in: \d+ seconds", stdout) or not re.search(r"expires in: (1m\d\ds|2m00s)\n", stdout):
    fail(f"status after bootstrap unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, stderr = run(scoped(["status", "--json"], root_domain))
if rc != 0 or stderr != "":
    fail(f"status --json after bootstrap failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
bootstrap_status = json.loads(stdout)
if not bootstrap_status["unlocked"] or bootstrap_status["session_mode"] != "persistent" or not bootstrap_status["wrapped_master_key_present"] or bootstrap_status["remaining_seconds"] is None:
    fail(f"status --json after bootstrap unexpected: {bootstrap_status!r}")

rc, stdout, stderr = run(scoped(["unlock", "--duration", "PT95S"], root_domain))
if rc != 0 or "session refreshed\n" not in stdout or stderr != f"resolved domain: {root_domain}\n":
    fail(f"refresh unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "note: 2 descendant domains remain locked under this branch\n" not in stdout:
    fail(f"refresh unlock guidance missing: stdout={stdout!r}")

rc, stdout, stderr = run(scoped(["status"], root_domain))
if rc != 0 or not re.search(r"expires in: 1m\d\ds\n", stdout):
    fail(f"status after refresh unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--duration", "1hr30min"], root_domain))
if rc != 0 or "session refreshed\n" not in stdout:
    fail(f"suffix duration refresh failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"], root_domain))
if rc != 0 or not re.search(r"expires in: 1h(29|30)m\n", stdout):
    fail(f"status after suffix refresh unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

absolute_deadline = (datetime.now(timezone.utc) + timedelta(seconds=95)).strftime("%Y-%m-%dT%H:%M:%SZ")
rc, stdout, stderr = run(scoped(["unlock", "--until", absolute_deadline], root_domain))
if rc != 0 or "session refreshed\n" not in stdout:
    fail(f"absolute duration refresh failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["status"], root_domain))
if rc != 0 or not re.search(r"expires in: 1m\d\ds\n", stdout):
    fail(f"status after absolute refresh unexpected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, _ = run(scoped(["status", "-q"], child_domain))
if rc != 1 or stdout != "":
    fail(f"status -q in child after parent unlock unexpected: rc={rc} stdout={stdout!r}")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly unlocked by ancestor child path: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock before reconnect check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "already locked":
    fail(f"second lock noop failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

askpass_log.write_text("")
rc, stdout, stderr = run(scoped(["unlock"], root_domain), read_compat_env)
if rc != 0 or "session unlocked\n" not in stdout or "note: 2 descendant domains remain locked under this branch\n" not in stdout:
    fail(f"askpass unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"askpass unlock prompt context missing: stderr={stderr!r}")
assert_contains(askpass_log.read_text(), "Enter secdat passphrase:", "askpass unlock prompt")
if read_wrapped_iterations() != 200000:
    fail("reading an existing wrapped key must not rewrite iterations from the environment")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock after askpass unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain))
if rc == 0 or stdout != "" or "missing askpass provider; this command requires a terminal for passphrase input" not in stderr:
    fail(f"non-tty unlock without askpass should distinguish missing provider: rc={rc} stdout={stdout!r} stderr={stderr!r}")

missing_askpass_path = isolated_root / "missing-askpass.py"
rc, stdout, stderr = run(scoped(["unlock", "--askpass", str(missing_askpass_path)], root_domain), askpass_value_env)
if rc == 0 or stdout != "" or f"missing askpass provider: {missing_askpass_path}" not in stderr:
    fail(f"unlock --askpass missing provider failed unexpectedly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--askpass", str(unsupported_askpass_path)], root_domain), askpass_value_env)
if rc == 0 or stdout != "" or f"unsupported askpass provider: {unsupported_askpass_path}" not in stderr:
    fail(f"unlock --askpass unsupported provider failed unexpectedly: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--askpass", str(cancel_askpass_path)], root_domain), askpass_value_env)
if rc == 0 or stdout != "" or "askpass prompt cancelled" not in stderr:
    fail(f"unlock --askpass cancellation should be distinct: rc={rc} stdout={stdout!r} stderr={stderr!r}")

bad_askpass_env = askpass_value_env.copy()
bad_askpass_env["SECDAT_TEST_ASKPASS_VALUE"] = "wrong-passphrase"
askpass_log.write_text("")
rc, stdout, stderr = run(scoped(["unlock", "--askpass", str(askpass_path)], root_domain), bad_askpass_env)
if rc == 0 or stdout != "" or "failed to unlock persistent master key" not in stderr:
    fail(f"unlock --askpass bad passphrase should be distinct: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(askpass_log.read_text(), "Enter secdat passphrase:", "bad askpass unlock prompt")

askpass_log.write_text("")
rc, stdout, stderr = run(scoped(["unlock", "--askpass", str(askpass_path)], root_domain), askpass_value_env)
if rc != 0 or "session unlocked\n" not in stdout or "note: 2 descendant domains remain locked under this branch\n" not in stdout:
    fail(f"unlock --askpass failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"unlock --askpass prompt context missing: stderr={stderr!r}")
assert_contains(askpass_log.read_text(), "Enter secdat passphrase:", "unlock --askpass prompt")

rc, stdout, stderr = run(scoped(["status", "--json"], root_domain))
if rc != 0 or stderr != "":
    fail(f"status --json after unlock --askpass failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
askpass_status = json.loads(stdout)
if not askpass_status["unlocked"] or askpass_status["key_source"] != "session" or askpass_status["effective_source"] != "local_unlock":
    fail(f"status --json after unlock --askpass unexpected: {askpass_status!r}")

askpass_log.write_text("")
rc, stdout, stderr = run([bin_path, "passwd", "--askpass", str(askpass_path)], askpass_value_env)
if rc != 0 or stdout != "persistent master key passphrase updated\n" or stderr != "":
    fail(f"passwd --askpass failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
passwd_askpass_prompts = askpass_log.read_text()
assert_contains(passwd_askpass_prompts, "Enter secdat passphrase:", "passwd --askpass current prompt")
assert_contains(passwd_askpass_prompts, "Create new secdat passphrase:", "passwd --askpass create prompt")
assert_contains(passwd_askpass_prompts, "Confirm new secdat passphrase:", "passwd --askpass confirm prompt")

rc, stdout, stderr = run(scoped(["lock"], root_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock after explicit askpass unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout or "note: 2 descendant domains remain locked under this branch\n" not in stdout:
    fail(f"root unlock before shadow check failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if f"resolved domain: {root_domain}\n" not in stderr:
    fail(f"root unlock prompt context missing: stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["set", "PARENT_UNLOCK_VISIBLE", "-v", "visible-from-parent"], root_domain))
if rc != 0 or stdout != "" or stderr != "":
    fail(f"root set for explicit-lock coverage failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], child_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "session unlocked\n" not in stdout:
    fail(f"child local unlock before explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

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
assert_contains(stdout, "effective source: local lock\n", "domain status explicit lock")

rc, stdout, stderr = run(scoped(["domain", "status", "--json"], child_domain))
if rc != 0 or stderr != "":
    fail(f"domain status --json after explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
child_domain_status = json.loads(stdout)
if child_domain_status["unlocked"] or child_domain_status["resolved_domain"] != str(child_domain) or child_domain_status["effective_source"] != "local_lock" or child_domain_status["related_domain"] is not None:
    fail(f"domain status --json after explicit lock unexpected: {child_domain_status!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after parent explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited lock\n", "grandchild blocked status")
assert_contains(stdout, f"inherited from: {child_domain}\n", "grandchild blocked status")

rc, stdout, stderr = run(scoped(["domain", "status", "--json"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status --json after parent explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
grandchild_domain_status = json.loads(stdout)
if grandchild_domain_status["unlocked"] or grandchild_domain_status["effective_source"] != "inherited_lock" or grandchild_domain_status["related_domain"] != str(child_domain):
    fail(f"grandchild domain status --json after parent explicit lock unexpected: {grandchild_domain_status!r}")

rc, stdout, stderr = run(scoped(["domain", "ls", "-l", "--descendants"], root_domain))
if rc != 0 or stderr != "":
    fail(f"domain ls -l after explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tREMAINING\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "domain ls -l header")
assert_contains(stdout, f"{child_domain}\tlocked\tlocked\t-\tlocal-lock", "domain ls explicit-lock row")
assert_contains(stdout, f"{grandchild_domain}\tlocked\tlocked\t-\tinherited-lock-from:{child_domain}", "domain ls blocked row")

rc, stdout, stderr = run(scoped(["domain", "ls", "--json", "--long", "--descendants"], root_domain))
if rc != 0 or stderr != "":
    fail(f"domain ls --json after explicit lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "visible-from-parent" in stdout:
    fail(f"domain ls --json leaked secret value: {stdout!r}")
domain_listing = json.loads(stdout)
domain_rows = {item["root"]: item for item in domain_listing["domains"]}
if domain_listing["domain_count"] < 3 or str(child_domain) not in domain_rows or str(grandchild_domain) not in domain_rows:
    fail(f"domain ls --json returned missing rows: {domain_listing!r}")
if domain_rows[str(child_domain)]["effective_source"] != "local_lock" or domain_rows[str(child_domain)]["related_domain"] is not None:
    fail(f"domain ls --json returned unexpected child row: {domain_rows[str(child_domain)]!r}")
if domain_rows[str(grandchild_domain)]["effective_source"] != "inherited_lock" or domain_rows[str(grandchild_domain)]["related_domain"] != str(child_domain):
    fail(f"domain ls --json returned unexpected grandchild row: {domain_rows[str(grandchild_domain)]!r}")

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
        ("unlock descendant domains in this subtree? local locks will remain [y/N]: ", "y"),
        ("Enter secdat passphrase:", passphrase),
    ],
)
if rc != 0 or f"resolved domain: {root_domain}" not in transcript or "this will unlock 2 descendant domains in the current subtree" not in transcript:
    fail(f"interactive descendant unlock failed: rc={rc} transcript={transcript!r}")
if "note: unlocked 2 descendant domains in this subtree; local locks remain" not in transcript:
    fail(f"interactive descendant unlock summary missing: transcript={transcript!r}")

rc, stdout, stderr = run(scoped(["domain", "status"], child_domain))
if rc != 0 or stderr != "":
    fail(f"child domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local unlock\n", "child local session after descendant unlock")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local unlock\n", "grandchild local session after descendant unlock")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"child relock before --yes descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock", "--descendants", "--yes"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": passphrase})
if rc != 0 or "note: unlocked 1 descendant domains in this subtree; local locks remain\n" not in stdout:
    fail(f"descendant unlock with --yes failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
if "unlock descendant domains in this subtree? local locks will remain [y/N]: " in stderr:
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
assert_contains(stdout, "effective source: local unlock\n", "child local status after descendant unlock")

rc, stdout, stderr = run(scoped(["domain", "status"], grandchild_domain))
if rc != 0 or stderr != "":
    fail(f"grandchild domain status after descendant unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: local unlock\n", "grandchild local status after descendant unlock")

rc, stdout, stderr = run(scoped(["status", "-q"], sibling_domain))
if rc != 1 or stdout != "" or stderr != "":
    fail(f"sibling unexpectedly unlocked by child session: rc={rc} stdout={stdout!r} stderr={stderr!r}")

new_passphrase = "rotated-passphrase-for-session-test"
rc, transcript = run_pty(
    [bin_path, "passwd"],
    [("Create new secdat passphrase:", new_passphrase), ("Confirm new secdat passphrase:", new_passphrase)],
    {
        "SECDAT_MASTER_KEY_PASSPHRASE": passphrase,
        "SECDAT_MASTER_KEY_PBKDF2_ITERATIONS": "250000",
    },
)
if rc != 0 or "persistent master key passphrase updated" not in transcript:
    fail(f"passwd rotation failed: rc={rc} transcript={transcript!r}")
if read_wrapped_iterations() != 250000:
    fail(f"passwd did not rewrite wrapped key iterations: {read_wrapped_iterations()}")

rc, stdout, stderr = run(scoped(["lock"], child_domain))
if rc != 0 or stdout.strip() != "session locked":
    fail(f"lock after passwd rotation failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(scoped(["unlock"], root_domain), {"SECDAT_MASTER_KEY_PASSPHRASE": new_passphrase})
if rc != 0 or ("session refreshed\n" not in stdout and "session unlocked\n" not in stdout):
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

rc, stdout, stderr = run(scoped(["get", "SESSOIN_KEY", "-o"], root_domain))
output = stdout + stderr
if rc == 0 or "key not found: SESSOIN_KEY" not in output or "Key candidates:" not in output or "  SESSION_KEY\n" not in output:
    fail(f"missing key suggestion failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["stauts"], root_domain))
output = stdout + stderr
if (
    rc == 0
    or "key not found: stauts" not in output
    or "treated as a key for get" not in output
    or "Command candidates" not in output
    or "  status\n" not in output
):
    fail(f"default-get command suggestion failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["DEFINITELY_MISSING_KEY"], root_domain))
output = stdout + stderr
if (
    rc == 0
    or "key not found: DEFINITELY_MISSING_KEY" not in output
    or "treated as a key for get" in output
    or "Command candidates" in output
):
    fail(f"default-get no-command-suggestion noise failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["sotre", "ls"], root_domain))
output = stdout + stderr
if (
    rc == 0
    or "invalid arguments for get" not in output
    or "treated as a key for get" not in output
    or "Command candidates" not in output
    or "  store\n" not in output
):
    fail(f"default-get invalid-argument command suggestion failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["stauts", "--quiet"], root_domain))
output = stdout + stderr
if (
    rc == 0
    or "invalid arguments for get" not in output
    or "treated as a key for get" not in output
    or "Command candidates" not in output
    or "  status\n" not in output
):
    fail(f"default-get option-error command suggestion failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["wait-unlok"], root_domain))
output = stdout + stderr
if (
    rc == 0
    or "key is not a valid environment variable name: wait-unlok" not in output
    or "treated as a key for get" not in output
    or "Command candidates" not in output
    or "  wait-unlock\n" not in output
):
    fail(f"default-get invalid-key command suggestion failed: rc={rc} output={output!r}")

rc, stdout, stderr = run(scoped(["store", "migarte"], root_domain))
output = stdout + stderr
if rc == 0 or "unknown store subcommand: migarte" not in output or "Subcommand candidates:" not in output or "  migrate\n" not in output:
    fail(f"subcommand suggestion failed: rc={rc} output={output!r}")

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

mismatch_runtime = isolated_root / "runtime-mismatch"
mismatch_data = isolated_root / "data-mismatch"
mismatch_parent = isolated_root / "domain-mismatch-parent"
mismatch_child = mismatch_parent / "child-domain"
mismatch_runtime.mkdir(parents=True, exist_ok=True)
mismatch_data.mkdir(parents=True, exist_ok=True)
mismatch_child.mkdir(parents=True, exist_ok=True)
mismatch_env = {
    "XDG_RUNTIME_DIR": str(mismatch_runtime),
    "XDG_DATA_HOME": str(mismatch_data),
}

for domain in (mismatch_parent, mismatch_child):
    rc, stdout, stderr = run([bin_path, "--dir", str(domain), "domain", "create"], mismatch_env)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"mismatch domain create failed for {domain}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, transcript = run_pty(
    [bin_path, "--dir", str(mismatch_parent), "unlock"],
    [("Create secdat passphrase:", passphrase), ("Confirm secdat passphrase:", passphrase)],
    {
        **mismatch_env,
        "SECDAT_MASTER_KEY": "mismatch-parent-master",
    },
)
if rc != 0 or "persistent master key initialized; session unlocked from environment" not in transcript:
    fail(f"mismatch bootstrap unlock failed: rc={rc} transcript={transcript!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(mismatch_parent), "set", "PARENT_KEY", "-v", "parent-secret"],
    mismatch_env,
)
if rc != 0 or stdout != "" or stderr != "":
    fail(f"mismatch parent set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(mismatch_parent), "lock"], mismatch_env)
if rc != 0 or stdout.strip() != "session locked":
    fail(f"mismatch parent lock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run(
    [bin_path, "--dir", str(mismatch_child), "unlock"],
    {
        **mismatch_env,
        "SECDAT_MASTER_KEY": "mismatch-child-master",
    },
)
if rc != 0 or "session unlocked from environment\n" not in stdout:
    fail(f"mismatch child unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(mismatch_child), "get", "PARENT_KEY", "-o"], mismatch_env)
if rc == 0 or stdout != "" or "failed to authenticate encrypted value\n" in stderr or "no active secdat session" not in stderr:
    fail(f"ancestor read with mismatched child session should request ancestor unlock: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stderr, f"resolved domain: {mismatch_parent}\n", "mismatch ancestor read resolved domain guidance")
assert_contains(stderr, f"inspect current domain: secdat --dir {mismatch_parent} domain status\n", "mismatch ancestor read status guidance")
assert_contains(stderr, f"unlock current domain: secdat --dir {mismatch_parent} unlock\n", "mismatch ancestor read unlock guidance")

default_runtime = isolated_root / "runtime-default"
default_data = isolated_root / "data-default"
default_scope = isolated_root / "default-scope"
default_child = isolated_root / "default-child-domain"
default_runtime.mkdir(parents=True, exist_ok=True)
default_data.mkdir(parents=True, exist_ok=True)
default_scope.mkdir(parents=True, exist_ok=True)
default_child.mkdir(parents=True, exist_ok=True)

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
assert_contains(stdout, "effective source: local unlock\n", "default-scope domain status local session")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "domain", "status", "--json"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-scope domain status --json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
default_domain_status = json.loads(stdout)
if default_domain_status["resolved_domain"] != "*default*" or not default_domain_status["unlocked"] or default_domain_status["effective_source"] != "local_unlock":
    fail(f"default-scope domain status --json unexpected: {default_domain_status!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "domain", "ls", "-la"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-scope domain ls -la failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "DOMAIN\tKEY_SOURCE\tEFFECTIVE\tREMAINING\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n", "default-scope domain ls -la header")
assert_contains(stdout, "*default*\tsession\tunlocked\t", "default-scope domain ls -la fallback row prefix")
assert_contains(stdout, "\tlocal-unlock\t0\t0\tpresent\n", "default-scope domain ls -la fallback row suffix")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "domain", "ls", "--json", "--long", "--inherited"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-scope domain ls --json failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
default_domain_listing = json.loads(stdout)
default_rows = {item["root"]: item for item in default_domain_listing["domains"]}
if "*default*" not in default_rows or default_rows["*default*"]["effective_source"] != "local_unlock":
    fail(f"default-scope domain ls --json unexpected: {default_domain_listing!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "domain", "create"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stdout != "" or stderr != "":
    fail(f"default-child domain create failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "set", "DEFAULT_CHILD_KEY", "-v", "default-child-value"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
    "SECDAT_MASTER_KEY_PASSPHRASE": passphrase,
})
if rc != 0 or stdout != "" or stderr != "":
    fail(f"default-child set failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "unlock"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
    "SECDAT_MASTER_KEY_PASSPHRASE": passphrase,
})
if rc != 0 or stdout != "session refreshed\n" or stderr != f"resolved domain: {default_child}\n":
    fail(f"default-child local unlock failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_scope), "unlock"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
    "SECDAT_MASTER_KEY_PASSPHRASE": passphrase,
})
if rc != 0 or stdout not in ("session unlocked\n", "session refreshed\n") or stderr != "resolved domain: *default*\n":
    fail(f"default-scope refresh before inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "unlock", "--inherit"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stdout != "local unlock cleared; resulting state: unlocked\n" or stderr != f"resolved domain: {default_child}\n":
    fail(f"default-child unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "domain", "status"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stderr != "":
    fail(f"default-child status after unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_contains(stdout, "effective source: inherited unlock\n", "default-child inherited status after unlock --inherit")
assert_contains(stdout, "inherited from: *default*\n", "default-child inherited source after unlock --inherit")

rc, stdout, stderr = run([bin_path, "--dir", str(default_child), "get", "DEFAULT_CHILD_KEY", "-o"], {
    "XDG_RUNTIME_DIR": str(default_runtime),
    "XDG_DATA_HOME": str(default_data),
})
if rc != 0 or stdout != "default-child-value" or stderr != "":
    fail(f"default-child get after unlock --inherit failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
PY

printf 'PASS session regression\n'
