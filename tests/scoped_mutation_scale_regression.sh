#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
command -v strace >/dev/null 2>&1 || {
    printf 'FAIL: strace is required for scoped mutation structural counts\n' >&2
    exit 1
}

work_root="$(mktemp -d)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

python3 - "$bin_path" "$work_root" <<'PY'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

bin_path = str(Path(sys.argv[1]).resolve())
work_root = Path(sys.argv[2])


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(env, *args, extra_env=None):
    command_env = env if extra_env is None else {**env, **extra_env}
    return subprocess.run(
        [bin_path, *args], text=True, capture_output=True,
        env=command_env, check=False,
    )


def require_ok(result, label, stdout=None):
    if result.returncode != 0 or result.stderr or (
        stdout is not None and result.stdout != stdout
    ):
        fail(
            f"{label}: rc={result.returncode} stdout={result.stdout!r} "
            f"stderr={result.stderr!r}"
        )


def create_v2_domain(env, path):
    state_root = Path(env["XDG_DATA_HOME"]) / "secdat"
    by_id = state_root / "domains/by-id"
    before = set(by_id.iterdir()) if by_id.exists() else set()
    require_ok(run(env, "--dir", str(path), "domain", "create"), f"create {path}", "")
    require_ok(
        run(env, "--dir", str(path), "store", "migrate", "default", "--to-format", "v2"),
        f"migrate {path}",
    )
    created = set(by_id.iterdir()) - before
    if len(created) != 1:
        fail(f"could not identify created domain for {path}: {created!r}")
    return created.pop()


def structural_case(domain_count):
    case_root = work_root / f"case-{domain_count}"
    data_root = case_root / "data"
    runtime_root = case_root / "runtime"
    workspace = case_root / "workspace"
    data_root.mkdir(parents=True)
    runtime_root.mkdir()
    workspace.mkdir()
    env = {
        **os.environ,
        "LC_ALL": "C",
        "LANGUAGE": "C",
        "SECDAT_MASTER_KEY": "scoped-scale-master-key",
        "XDG_DATA_HOME": str(data_root),
        "XDG_RUNTIME_DIR": str(runtime_root),
    }
    states = []
    domains = []
    for index in range(domain_count):
        domain = workspace / f"domain-{index:03d}"
        domain.mkdir()
        domains.append(domain)
        states.append(create_v2_domain(env, domain))

    sentinel = None
    if domain_count > 1:
        sentinel = states[-1] / "unrelated-scope-sentinel"
        os.mkfifo(sentinel, 0o600)

    trace_path = case_root / "trace"
    traced_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "prepared"}
    completed = subprocess.run(
        [
            "strace", "-f", "-qq", "-e", "trace=openat,getdents64",
            "-o", str(trace_path), bin_path, "--dir", str(domains[0]),
            "set", "SCALE_KEY", "--value", "scale-value",
        ],
        text=True,
        capture_output=True,
        env=traced_env,
        check=False,
    )
    if completed.returncode != 86:
        fail(f"traced set did not stop at PREPARED: {completed}")

    trace = trace_path.read_text(encoding="utf-8")
    if ".secdat-stage." in trace:
        fail("scoped set opened a legacy stage path")
    for unrelated in states[1:]:
        if str(unrelated) in trace:
            fail(f"scoped set opened unrelated domain state: {unrelated}")
    if sentinel is not None and str(sentinel) in trace:
        fail("scoped set touched the unrelated sentinel")

    state_root = Path(env["XDG_DATA_HOME"]) / "secdat"
    operations = sorted(
        path for path in (state_root / "transactions").iterdir()
        if path.name != "lock"
    )
    if len(operations) != 1:
        fail(f"expected one structural transaction: {operations!r}")
    manifest = json.loads(
        (operations[0] / "journal").read_text(encoding="utf-8").splitlines()[1]
    )
    counts = {
        "openat": len(re.findall(r"\bopenat\(", trace)),
        "getdents64": len(re.findall(r"\bgetdents64\(", trace)),
        "guards": len(manifest.get("guards", [])),
        "writes": len(manifest.get("writes", [])),
    }
    require_ok(run(env, "--dir", str(domains[0]), "status", "--quiet"), "cleanup", "")
    if sentinel is not None:
        sentinel.unlink()
    return counts


one = structural_case(1)
hundred = structural_case(100)
if one != hundred:
    fail(f"unrelated-domain structural counts changed: one={one!r} hundred={hundred!r}")
print(
    "PASS scoped mutation scale regression "
    f"(openat={one['openat']} getdents64={one['getdents64']} "
    f"guards={one['guards']} writes={one['writes']})"
)
PY
