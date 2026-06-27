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
export SECDAT_MASTER_KEY='inject-regression-master-key'
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

python3 - "$bin_path" "$work_root" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

bin_path = sys.argv[1]
work_root = Path(sys.argv[2])
domain = work_root / "project"

env = os.environ.copy()
env["LC_ALL"] = "C"
env["LANGUAGE"] = "C"
env["SECDAT_MASTER_KEY"] = "inject-regression-master-key"
env["MY_TOKEN"] = "ambient-token"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, extra_env=None):
    run_env = env.copy()
    if extra_env:
        run_env.update(extra_env)
    completed = subprocess.run(args, text=True, capture_output=True, env=run_env)
    return completed.returncode, completed.stdout, completed.stderr


def exec_stderr_ok(stderr):
    for line in stderr.splitlines():
        if line and not line.startswith("warning: exec:"):
            return False
    return True


def exec_stderr_json(stderr):
    payload = "\n".join(
        line for line in stderr.splitlines()
        if line and not line.startswith("warning: exec:")
    )
    start = payload.find("{")
    if start < 0:
        fail(f"exec stderr missing JSON summary: {stderr!r}")
    return json.loads(payload[start:])


def assert_eq(actual, expected, label):
    if actual != expected:
        fail(f"{label}: expected {expected!r}, got {actual!r}")


domain.mkdir(parents=True)

for args in [
    [bin_path, "--dir", str(domain), "domain", "create"],
    [bin_path, "--dir", str(domain), "store", "create", "app"],
    [bin_path, "--dir", str(domain), "set", "APP_TOKEN", "--value", "app-secret"],
    [bin_path, "--dir", str(domain), "set", "APP_DEBUG", "--value", "debug-secret"],
    [bin_path, "--dir", str(domain), "set", "ROOT_TOKEN", "--value", "root-secret"],
    [bin_path, "--dir", str(domain), "set", "ADMIN_TOKEN", "--value", "admin-secret"],
    [bin_path, "--dir", str(domain), "set", "MY_TOKEN", "--value", "secret-token"],
    [bin_path, "--dir", str(domain), "set", "OTHER_TOKEN", "--value", "other-secret"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# Baseline dry-run: default ambient + secret supply, route prefer secret.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"baseline dry-run failed: rc={rc} stderr={stderr!r}")
plan = json.loads(stdout)
if plan["ok"] is not True:
    fail(f"baseline dry-run not ok: {plan!r}")
if plan["supply"]["ambient"]["mode"] != "default" or plan["supply"]["secret"]["mode"] != "default":
    fail(f"baseline supply modes unexpected: {plan['supply']!r}")
if plan["route"]["prefer"] != "secret":
    fail(f"baseline route prefer unexpected: {plan['route']!r}")
if "APP_TOKEN" not in plan["supply"]["secret"]["contributed"]:
    fail(f"baseline secret contributed missing APP_TOKEN: {plan['supply']['secret']!r}")
if "PATH" not in plan["supply"]["ambient"]["contributed"]:
    fail(f"baseline ambient contributed missing PATH: {plan['supply']['ambient']!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "route:prefer=secret",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"explicit route dry-run failed: rc={rc} stderr={stderr!r}")
explicit = json.loads(stdout)
if explicit["route"]["prefer"] != "secret":
    fail(f"explicit route prefer mismatch: {explicit['route']!r}")

# §7.3 CI-style policy: APP secrets only, PATH from ambient on collision, omit/reject SECDAT_*.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:omit=SECDAT_*",
    "--inject", "secret:only=APP_*",
    "--inject", "secret:require=APP_TOKEN",
    "--inject", "route:PATH=ambient",
    "--inject", "route:prefer=secret",
    "--inject", "final:reject=SECDAT_*",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"ci policy dry-run failed: rc={rc} stderr={stderr!r}")
ci = json.loads(stdout)
if ci["supply"]["secret"]["mode"] != "only":
    fail(f"ci secret mode unexpected: {ci['supply']['secret']!r}")
if ci["supply"]["secret"]["contributed"] != ["APP_DEBUG", "APP_TOKEN"]:
    fail(f"ci secret contributed unexpected: {ci['supply']['secret']['contributed']!r}")
if "SECDAT_MASTER_KEY" in ci["final"]["present"]:
    fail(f"ci final present leaked SECDAT_MASTER_KEY: {ci['final']['present']!r}")
if "APP_TOKEN" not in ci["final"]["present"]:
    fail(f"ci final missing APP_TOKEN: {ci['final']['present']!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:omit=SECDAT_*",
    "--inject", "secret:only=APP_*",
    "--inject", "secret:require=APP_TOKEN",
    "--inject", "route:PATH=ambient",
    "--inject", "final:reject=SECDAT_*",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ[k] for k in sorted(k for k in os.environ if k.startswith('APP_'))}, sort_keys=True))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"ci policy exec failed: rc={rc} stderr={stderr!r}")
assert_eq(
    json.loads(stdout),
    {"APP_DEBUG": "debug-secret", "APP_TOKEN": "app-secret"},
    "ci policy exec payload",
)
if "SECDAT_MASTER_KEY" in stdout:
    fail(f"ci policy exec leaked SECDAT_MASTER_KEY: {stdout!r}")

# §7.3 secret:reject with colon-separated selectors.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:reject=ROOT_TOKEN:ADMIN_*",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject reject matched present entry: ROOT_TOKEN" not in stderr:
    fail(f"secret reject dry-run did not fail cleanly: rc={rc} stderr={stderr!r}")
reject_plan = json.loads(stdout)
if reject_plan["ok"] is not False:
    fail(f"secret reject dry-run ok flag unexpected: {reject_plan!r}")
if sorted(reject_plan["supply"]["secret"]["rejected_present"]) != ["ADMIN_TOKEN", "ROOT_TOKEN"]:
    fail(f"secret reject rejected_present unexpected: {reject_plan!r}")

# §7.3 strict final allowlist (selectors are colon-separated per §7.1).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:only=PATH:HOME",
    "--inject", "secret:only=APP_TOKEN",
    "--inject", "final:only=PATH:HOME:APP_TOKEN",
    "python3", "-c",
    "import json, os; print(json.dumps(sorted(k for k in os.environ if k in ('PATH','HOME','APP_TOKEN','APP_DEBUG','MY_TOKEN'))))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"final only exec failed: rc={rc} stderr={stderr!r}")
final_keys = json.loads(stdout)
if final_keys != ["APP_TOKEN", "HOME", "PATH"]:
    fail(f"final only child env unexpected: {final_keys!r}")

# Route collision: default prefer secret.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=MY_TOKEN",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"collision dry-run failed: rc={rc} stderr={stderr!r}")
collision = json.loads(stdout)
if collision["route"]["collisions"] != [{"name": "MY_TOKEN", "picked": "secret"}]:
    fail(f"collision route unexpected: {collision['route']!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=MY_TOKEN",
    "python3", "-c", "import os,sys; sys.stdout.write(os.environ.get('MY_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "secret-token":
    fail(f"collision secret pick failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=MY_TOKEN",
    "--inject", "route:MY_TOKEN=ambient",
    "python3", "-c", "import os,sys; sys.stdout.write(os.environ.get('MY_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "ambient-token":
    fail(f"collision ambient override failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# §7.3 route:prefer=error on collision.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=MY_TOKEN",
    "--inject", "route:prefer=error",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "ambient/secret collision on environment variable: MY_TOKEN" not in stderr:
    fail(f"route error collision did not fail: rc={rc} stderr={stderr!r}")
error_plan = json.loads(stdout)
if error_plan["ok"] is not False:
    fail(f"route error ok flag unexpected: {error_plan!r}")

# secret:rename via native --inject (BRE capture group).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=OTHER_*",
    "--inject", r"secret:rename=s/^OTHER_\(.*\)/RENAMED_\1/",
    "python3", "-c",
    "import os,sys; sys.stdout.write(os.environ.get('RENAMED_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "other-secret":
    fail(f"secret rename exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# §9 final:reject when a forbidden variable survives into the final plan.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:reject=SECDAT_*",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject final reject matched present entry: SECDAT_MASTER_KEY" not in stderr:
    fail(f"final reject present did not fail: rc={rc} stderr={stderr!r}")

# §15.6 legacy + inject on different concerns.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--pattern", "APP_*",
    "--inject", "route:MY_TOKEN=ambient",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('APP_TOKEN','MY_TOKEN')}, sort_keys=True))",
])
if rc != 0 or "warning: exec: --pattern is deprecated" not in stderr:
    fail(f"legacy+inject combo failed: rc={rc} stderr={stderr!r}")
combo = json.loads(stdout)
if combo["APP_TOKEN"] != "app-secret" or combo["MY_TOKEN"] != "ambient-token":
    fail(f"legacy+inject combo payload unexpected: {combo!r}")

# §15.6 legacy + inject conflict on same pentad kind.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--pattern", "APP_*",
    "--inject", "secret:only=OTHER_*",
    "python3", "-c", "pass",
])
if rc != 2 or "exec: --pattern conflicts with --inject secret:only" not in stderr:
    fail(f"legacy conflict did not fail: rc={rc} stderr={stderr!r}")

# Native --inject secret:only equivalence to legacy --pattern.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ[k] for k in sorted(k for k in os.environ if k.startswith('APP_'))}, sort_keys=True))",
])
if rc != 0 or stderr != "":
    fail(f"inject secret only exec failed: rc={rc} stderr={stderr!r}")
assert_eq(
    json.loads(stdout),
    {"APP_DEBUG": "debug-secret", "APP_TOKEN": "app-secret"},
    "inject secret only payload",
)

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "secret:omit=APP_DEBUG",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ[k] for k in sorted(k for k in os.environ if k.startswith('APP_'))}, sort_keys=True))",
])
if rc != 0 or stderr != "":
    fail(f"inject secret omit failed: rc={rc} stderr={stderr!r}")
assert_eq(json.loads(stdout), {"APP_TOKEN": "app-secret"}, "inject secret omit payload")

# §9 pentad contract conflict.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:require=APP_TOKEN",
    "--inject", "secret:omit=APP_TOKEN",
    "python3", "-c", "pass",
])
if rc != 2 or "exec inject contract conflict: require and omit overlap: APP_TOKEN" not in stderr:
    fail(f"pentad conflict did not fail: rc={rc} stderr={stderr!r}")

# §9 final:require missing.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:require=MISSING_ENV",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject required entry missing: MISSING_ENV" not in stderr:
    fail(f"final require missing did not fail: rc={rc} stderr={stderr!r}")
final_req = json.loads(stdout)
if final_req["final"]["missing_required"] != ["MISSING_ENV"]:
    fail(f"final require missing plan unexpected: {final_req!r}")

# json-summary with native --inject.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_TOKEN",
    "--json-summary",
    "python3", "-c", "import sys; sys.stdout.write('summary-ok'); sys.exit(4)",
])
if rc != 4 or stdout != "summary-ok":
    fail(f"json-summary exec failed: rc={rc} stdout={stdout!r}")
summary = exec_stderr_json(stderr)
if summary["ok"] is not True or summary["exit_status"] != 4:
    fail(f"json-summary payload unexpected: {summary!r}")
if summary["injected_keys"] != [{"key": "APP_TOKEN", "env_name": "APP_TOKEN"}]:
    fail(f"json-summary injected keys unexpected: {summary!r}")

print("PASS inject regression")
PY