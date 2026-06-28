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
    [bin_path, "--dir", str(domain), "set", "BULK_TOKEN", "--value", "bulk-secret", "--bulk-select", "include"],
    [bin_path, "--dir", str(domain), "set", "EXPLICIT_TOKEN", "--value", "explicit-secret", "--bulk-select", "named"],
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
if plan.get("bulk_gate"):
    fail(f"baseline bulk_gate unexpected: {plan!r}")
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
if rc == 0 or "exec inject secret key must not be present: ROOT_TOKEN" not in stderr:
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

# secret:rename non-match keeps env_name = key (design §6 Phase 1).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*:OTHER_*",
    "--inject", r"secret:rename=s/^OTHER_\(.*\)/RENAMED_\1/",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('APP_TOKEN', 'RENAMED_TOKEN')}, sort_keys=True))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"secret rename identity fallback exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(
    json.loads(stdout),
    {"APP_TOKEN": "app-secret", "RENAMED_TOKEN": "other-secret"},
    "secret rename identity fallback payload",
)

# secret:only matches mapped env_name after rename (design §6 Phase 1).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=RENAMED_*",
    "--inject", r"secret:rename=s/^OTHER_\(.*\)/RENAMED_\1/",
    "python3", "-c",
    "import os,sys; sys.stdout.write(os.environ.get('RENAMED_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "other-secret":
    fail(f"secret only env_name match failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# secret:omit matches mapped env_name after rename.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*:OTHER_*",
    "--inject", "secret:omit=RENAMED_*",
    "--inject", r"secret:rename=s/^OTHER_\(.*\)/RENAMED_\1/",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('APP_TOKEN', 'RENAMED_TOKEN')}, sort_keys=True))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"secret omit env_name match failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(
    json.loads(stdout),
    {"APP_TOKEN": "app-secret", "RENAMED_TOKEN": None},
    "secret omit env_name payload",
)

# ambient:require missing surfaces in JSON supply.ambient.missing_required.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:require=MISSING_AMBIENT_VAR",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject required ambient variable not available: MISSING_AMBIENT_VAR" not in stderr:
    fail(f"ambient require missing did not fail: rc={rc} stderr={stderr!r}")
ambient_req = json.loads(stdout)
if ambient_req["supply"]["ambient"]["missing_required"] != ["MISSING_AMBIENT_VAR"]:
    fail(f"ambient require missing JSON unexpected: {ambient_req!r}")

# route:prefer may be specified at most once.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "route:prefer=secret",
    "--inject", "route:prefer=ambient",
    "python3", "-c", "pass",
])
if rc != 2 or "route:prefer may be specified at most once" not in stderr:
    fail(f"duplicate route prefer did not fail: rc={rc} stderr={stderr!r}")

# --inject-file loads policy; later --inject overrides file entries.
policy_file = work_root / "exec.env.yaml"
policy_file.write_text(
    "supply:\n"
    "  secret:\n"
    "    only: [\"APP_*\"]\n"
    "route:\n"
    "  prefer: secret\n",
    encoding="utf-8",
)
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-file", str(policy_file),
    "--inject", "secret:only=OTHER_*",
    "python3", "-c",
    "import os,sys; sys.stdout.write(os.environ.get('OTHER_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "other-secret":
    fail(f"inject-file override failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# secret:rename duplicate env_name is a plan error (design §6 Phase 1).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*:OTHER_*",
    "--inject", r"secret:rename=s/^.*$/DUP_ENV/",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "duplicate environment variable name from secret rename: DUP_ENV" not in stderr:
    fail(f"secret rename duplicate env_name did not fail: rc={rc} stderr={stderr!r}")
dup_plan = json.loads(stdout)
if dup_plan["ok"] is not False:
    fail(f"secret rename duplicate env_name ok flag unexpected: {dup_plan!r}")

# §9 final:reject when a forbidden variable survives into the final plan.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:reject=SECDAT_*",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject forbidden variable in final child env: SECDAT_MASTER_KEY" not in stderr:
    fail(f"final reject present did not fail: rc={rc} stderr={stderr!r}")

# §15.8 Phase 3: removed legacy exec flags fail with replacement hints.
for legacy_args, expected in [
    (["--pattern", "APP_*"], "exec: --pattern (-p) is no longer supported; use --inject secret:only=GLOB"),
    (["--pattern-exclude", "APP_DEBUG"], "exec: --pattern-exclude (-x) is no longer supported; use --inject secret:omit=GLOB"),
    (["--require-key", "APP_TOKEN"], "exec: --require-key is no longer supported; use --inject secret:require=KEY"),
    (["--env-map-sed", "s/^.*$/RENAMED/"], "exec: --env-map-sed is no longer supported; use --inject secret:rename=EXPR"),
    (["--sandbox-injectable"], "exec: --sandbox-injectable is no longer supported; use --bulk-gate"),
]:
    rc, stdout, stderr = run([
        bin_path, "--dir", str(domain), "exec",
        *legacy_args,
        "python3", "-c", "pass",
    ])
    if rc != 2 or expected not in stderr:
        fail(f"legacy removal failed for {legacy_args}: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-gate", "sandbox",
    "python3", "-c", "pass",
])
if rc != 2 or "invalid --inject-gate value: sandbox; use --bulk-gate" not in stderr:
    fail(f"legacy --inject-gate=sandbox should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-gate", "bulk",
    "python3", "-c", "pass",
])
if rc != 2 or "exec: --inject-gate is no longer supported; use --bulk-gate" not in stderr:
    fail(f"legacy --inject-gate=bulk should be rejected: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# Native --inject secret:only.
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

# §9 pentad contract conflicts (require/omit, require/reject, omit/reject per layer).
pentad_conflict_cases = [
    ("secret", ["--inject", "secret:require=APP_TOKEN", "--inject", "secret:omit=APP_TOKEN"],
     "exec inject secret pentad conflict: require and omit overlap: APP_TOKEN"),
    ("secret", ["--inject", "secret:require=APP_TOKEN", "--inject", "secret:reject=APP_*"],
     "exec inject secret pentad conflict: require and reject overlap: APP_TOKEN"),
    ("secret", ["--inject", "secret:omit=APP_DEBUG", "--inject", "secret:reject=APP_*"],
     "exec inject secret pentad conflict: omit and reject overlap: APP_DEBUG"),
    ("ambient", ["--inject", "ambient:require=PATH", "--inject", "ambient:omit=PATH"],
     "exec inject ambient pentad conflict: require and omit overlap: PATH"),
    ("ambient", ["--inject", "ambient:require=PATH", "--inject", "ambient:reject=PATH"],
     "exec inject ambient pentad conflict: require and reject overlap: PATH"),
    ("ambient", ["--inject", "ambient:omit=PATH", "--inject", "ambient:reject=PATH"],
     "exec inject ambient pentad conflict: omit and reject overlap: PATH"),
    ("final", ["--inject", "final:require=APP_TOKEN", "--inject", "final:omit=APP_TOKEN"],
     "exec inject final pentad conflict: require and omit overlap: APP_TOKEN"),
    ("final", ["--inject", "final:require=APP_TOKEN", "--inject", "final:reject=APP_*"],
     "exec inject final pentad conflict: require and reject overlap: APP_TOKEN"),
    ("final", ["--inject", "final:omit=APP_TOKEN", "--inject", "final:reject=APP_*"],
     "exec inject final pentad conflict: omit and reject overlap: APP_TOKEN"),
]
for layer, inject_args, expected in pentad_conflict_cases:
    rc, stdout, stderr = run([
        bin_path, "--dir", str(domain), "exec",
        *inject_args,
        "python3", "-c", "pass",
    ])
    if rc != 2 or expected not in stderr:
        fail(f"{layer} pentad conflict did not fail: rc={rc} stderr={stderr!r}")

# §9 final:require missing.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:require=MISSING_ENV",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject required variable missing from final child env: MISSING_ENV" not in stderr:
    fail(f"final require missing did not fail: rc={rc} stderr={stderr!r}")
final_req = json.loads(stdout)
if final_req["final"]["missing_required"] != ["MISSING_ENV"]:
    fail(f"final require missing plan unexpected: {final_req!r}")

# --inject-file bulk_gate: true applies the same pre-filter as --bulk-gate (§7.4).
gate_policy_file = work_root / "exec.gate.yaml"
gate_policy_file.write_text(
    "bulk_gate: true\n"
    "supply:\n"
    "  secret:\n"
    "    only: [\"BULK_TOKEN\", \"EXPLICIT_TOKEN\", \"APP_TOKEN\"]\n",
    encoding="utf-8",
)
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-file", str(gate_policy_file),
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ[k] for k in sorted(k for k in os.environ if k in ('BULK_TOKEN', 'EXPLICIT_TOKEN', 'APP_TOKEN'))}, sort_keys=True))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"inject-file gate bulk-gate exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(json.loads(stdout), {"BULK_TOKEN": "bulk-secret"}, "inject-file gate bulk payload")

bad_gate_file = work_root / "bad.gate.yaml"
bad_gate_file.write_text("gate: invalid\n", encoding="utf-8")
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-file", str(bad_gate_file),
    "python3", "-c", "pass",
])
if rc != 2 or "gate: is no longer supported; use bulk_gate: true" not in stderr:
    fail(f"inject-file legacy gate did not fail: rc={rc} stderr={stderr!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject-file", str(gate_policy_file),
    "--bulk-gate",
    "python3", "-c", "pass",
])
if rc != 2 or "--bulk-gate may be specified at most once" not in stderr:
    fail(f"inject-file gate duplicate did not fail: rc={rc} stderr={stderr!r}")

# --bulk-gate applies bulk_select include pre-filter (§10).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--bulk-gate",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"bulk-gate dry-run failed: rc={rc} stderr={stderr!r}")
gate_plan = json.loads(stdout)
if gate_plan.get("bulk_gate") is not True:
    fail(f"bulk-gate JSON unexpected: {gate_plan!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--bulk-gate",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ[k] for k in sorted(k for k in os.environ if k in ('BULK_TOKEN', 'EXPLICIT_TOKEN', 'APP_TOKEN'))}, sort_keys=True))",
])
if rc != 0 or stderr != "":
    fail(f"bulk-gate exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(json.loads(stdout), {"BULK_TOKEN": "bulk-secret"}, "bulk-gate payload")

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

# §7.3 baseline exec (implicit default policy: ambient + secret, secret wins on collision).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "python3", "-c",
    "import os,sys; sys.stdout.write(os.environ.get('APP_TOKEN','missing'))",
])
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "app-secret":
    fail(f"baseline exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# §7.3 route glob rule on collision (route:APP_*=ambient).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "route:APP_*=ambient",
    "python3", "-c",
    "import os,sys; sys.stdout.write(os.environ.get('APP_TOKEN','missing'))",
], extra_env={"APP_TOKEN": "ambient-override"})
if rc != 0 or not exec_stderr_ok(stderr) or stdout != "ambient-override":
    fail(f"route glob ambient pick failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")

# §7.3 ambient supply modes in JSON (only vs default+omit).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:only=PATH:HOME",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"ambient only dry-run failed: rc={rc} stderr={stderr!r}")
ambient_only = json.loads(stdout)
if ambient_only["supply"]["ambient"]["mode"] != "only":
    fail(f"ambient only mode unexpected: {ambient_only['supply']['ambient']!r}")

rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:omit=SECDAT_*",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"ambient omit dry-run failed: rc={rc} stderr={stderr!r}")
ambient_omit = json.loads(stdout)
if ambient_omit["supply"]["ambient"]["mode"] != "default":
    fail(f"ambient omit mode unexpected: {ambient_omit['supply']['ambient']!r}")
if "SECDAT_MASTER_KEY" in ambient_omit["supply"]["ambient"]["contributed"]:
    fail(f"ambient omit leaked SECDAT_MASTER_KEY: {ambient_omit['supply']['ambient']!r}")

# §7.3 secret:require success path.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "secret:require=APP_TOKEN",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc != 0 or stderr != "":
    fail(f"secret require success dry-run failed: rc={rc} stderr={stderr!r}")
secret_req_ok = json.loads(stdout)
if secret_req_ok["supply"]["secret"]["missing_required"] != []:
    fail(f"secret require success missing_required unexpected: {secret_req_ok!r}")
if "APP_TOKEN" not in secret_req_ok["supply"]["secret"]["contributed"]:
    fail(f"secret require success contributed unexpected: {secret_req_ok!r}")

# §7.3 final:omit exec.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:omit=APP_DEBUG",
    "python3", "-c",
    "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('APP_TOKEN', 'APP_DEBUG')}, sort_keys=True))",
])
if rc != 0 or not exec_stderr_ok(stderr):
    fail(f"final omit exec failed: rc={rc} stdout={stdout!r} stderr={stderr!r}")
assert_eq(
    json.loads(stdout),
    {"APP_DEBUG": None, "APP_TOKEN": "app-secret"},
    "final omit payload",
)

# §9 ambient:reject when a forbidden ambient variable is present.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "ambient:reject=MY_TOKEN",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject ambient variable must not be present: MY_TOKEN" not in stderr:
    fail(f"ambient reject dry-run did not fail: rc={rc} stderr={stderr!r}")
ambient_reject = json.loads(stdout)
if ambient_reject["supply"]["ambient"]["rejected_present"] != ["MY_TOKEN"]:
    fail(f"ambient reject JSON unexpected: {ambient_reject!r}")

# §9 secret:require missing.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:require=MISSING_SECRET_KEY",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject required secret key not available for injection: MISSING_SECRET_KEY" not in stderr:
    fail(f"secret require missing did not fail: rc={rc} stderr={stderr!r}")
secret_missing = json.loads(stdout)
if secret_missing["supply"]["secret"]["missing_required"] != ["MISSING_SECRET_KEY"]:
    fail(f"secret require missing JSON unexpected: {secret_missing!r}")

# §9 secret:reject exec path (design §7.3 forbid dangerous store keys).
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:reject=ROOT_TOKEN:ADMIN_*",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject secret key must not be present: ROOT_TOKEN" not in stderr:
    fail(f"secret reject exec did not fail: rc={rc} stderr={stderr!r}")

# §9 final:reject exec path.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=APP_*",
    "--inject", "final:reject=SECDAT_*",
    "python3", "-c", "pass",
])
if rc == 0 or "exec inject forbidden variable in final child env: SECDAT_MASTER_KEY" not in stderr:
    fail(f"final reject exec did not fail: rc={rc} stderr={stderr!r}")

# §9 invalid rename env name.
rc, stdout, stderr = run([
    bin_path, "--dir", str(domain), "exec",
    "--inject", "secret:only=OTHER_*",
    "--inject", r"secret:rename=s/^OTHER_\(.*\)/BAD-NAME/",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "invalid environment variable name from secret rename: BAD-NAME" not in stderr:
    fail(f"invalid rename env name did not fail: rc={rc} stderr={stderr!r}")

# §9 invalid store key as environment variable name (legacy artifact).
invalid_key_domain = work_root / "invalid-key-domain"
invalid_key_domain.mkdir(parents=True)
for args in [
    [bin_path, "--dir", str(invalid_key_domain), "domain", "create"],
    [bin_path, "--dir", str(invalid_key_domain), "store", "create", "app"],
    [bin_path, "--dir", str(invalid_key_domain), "set", "LEGACY_SOURCE", "--value", "legacy-secret"],
]:
    rc, stdout, stderr = run(args)
    if rc != 0 or stdout != "" or stderr != "":
        fail(f"invalid-key setup failed for {args}: rc={rc} stdout={stdout!r} stderr={stderr!r}")
source_files = list(Path(env["XDG_DATA_HOME"]).rglob("LEGACY_SOURCE.sec"))
if len(source_files) != 1:
    fail(f"expected one LEGACY_SOURCE.sec, found {source_files!r}")
legacy_invalid_entry = source_files[0].parent / "ZZZ-BAD.sec"
legacy_invalid_entry.write_bytes(source_files[0].read_bytes())
rc, stdout, stderr = run([
    bin_path, "--dir", str(invalid_key_domain), "exec",
    "--dry-run", "--json",
    "python3", "-c", "pass",
])
if rc == 0 or "key is not a valid environment variable name: ZZZ-BAD" not in stderr:
    fail(f"invalid store key env name did not fail: rc={rc} stderr={stderr!r}")

# §15.10 parser and at-most-once limits (post–Phase 3).
for bad_args, expected in [
    (["--inject", "not-a-valid-token"], "invalid --inject token: not-a-valid-token"),
    (["--inject", "bogus:only=FOO"], "invalid --inject layer: bogus"),
    (["--inject", "route:FOO=ambinet"], "invalid route pick: ambinet"),
    ([
        "--inject", r"secret:rename=s/^APP_\(.*\)/RENAMED_\1/",
        "--inject", r"secret:rename=s/^OTHER_\(.*\)/ALT_\1/",
    ], "secret rename may be specified at most once"),
    (["--bulk-gate", "--bulk-gate"], "--bulk-gate may be specified at most once"),
]:
    rc, stdout, stderr = run([
        bin_path, "--dir", str(domain), "exec",
        *bad_args,
        "python3", "-c", "pass",
    ])
    if rc != 2 or expected not in stderr:
        fail(f"parser limit failed for {bad_args}: rc={rc} stderr={stderr!r}")

print("PASS inject regression")
PY
