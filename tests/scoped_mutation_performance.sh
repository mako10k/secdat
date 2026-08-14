#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"
work_root="$(mktemp -d)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

python3 - "$bin_path" "$work_root" <<'PY'
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

bin_path = str(Path(sys.argv[1]).resolve())
work_root = Path(sys.argv[2])


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(env, *args):
    started = time.perf_counter()
    result = subprocess.run(
        [bin_path, *args], text=True, capture_output=True,
        env=env, check=False,
    )
    elapsed = time.perf_counter() - started
    if result.returncode != 0 or result.stderr:
        fail(
            f"command failed: {args!r}: rc={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return elapsed


def prepare_case(domain_count):
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
        "SECDAT_MASTER_KEY": "scoped-performance-master-key",
        "XDG_DATA_HOME": str(data_root),
        "XDG_RUNTIME_DIR": str(runtime_root),
    }
    domains = []
    for index in range(domain_count):
        domain = workspace / f"domain-{index:03d}"
        domain.mkdir()
        domains.append(domain)
        run(env, "--dir", str(domain), "domain", "create")
        run(
            env,
            "--dir", str(domain), "store", "migrate", "default",
            "--to-format", "v2",
        )
    run(env, "--dir", str(domains[0]), "set", "PERF_KEY", "--value", "initial")
    return env, domains[0]


one_env, one_domain = prepare_case(1)
hundred_env, hundred_domain = prepare_case(100)
cases = {
    "one": (one_env, one_domain),
    "hundred": (hundred_env, hundred_domain),
}

for index in range(8):
    for label in (("one", "hundred") if index % 2 == 0 else ("hundred", "one")):
        env, domain = cases[label]
        run(env, "--dir", str(domain), "set", "PERF_KEY", "--value", f"warm-{index}-{label}")

samples = {"one": [], "hundred": []}
for index in range(20):
    order = ("one", "hundred") if index % 2 == 0 else ("hundred", "one")
    for label in order:
        env, domain = cases[label]
        samples[label].append(
            run(
                env,
                "--dir", str(domain), "set", "PERF_KEY",
                "--value", f"sample-{index}-{label}",
            )
        )

one_median = statistics.median(samples["one"])
hundred_median = statistics.median(samples["hundred"])
ratio = hundred_median / one_median
if ratio > 1.20:
    fail(
        "100-domain/1-domain median ratio exceeds 1.20: "
        f"one={one_median * 1000:.1f}ms "
        f"hundred={hundred_median * 1000:.1f}ms ratio={ratio:.3f}"
    )
print(
    "PASS scoped mutation performance "
    f"(runs=20 one_p50={one_median * 1000:.1f}ms "
    f"one_mean={statistics.mean(samples['one']) * 1000:.1f}ms "
    f"hundred_p50={hundred_median * 1000:.1f}ms "
    f"hundred_mean={statistics.mean(samples['hundred']) * 1000:.1f}ms "
    f"ratio={ratio:.3f})"
)
PY
