#!/usr/bin/env bash
# R: Verify new-store v2 defaults and preservation of explicit legacy v1 fixtures.
set -euo pipefail
umask 077
bin_path="${1:-./src/secdat}"
script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work_root="$(mktemp -d)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"
export XDG_DATA_HOME="$work_root/data" XDG_RUNTIME_DIR="$work_root/runtime"
mkdir -p "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
python3 - "$bin_path" "$work_root" "$script_dir" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])
from store_fixture import create_v1_store, store_root, V1_MARKER, V2_MARKER

bin_path = os.path.abspath(sys.argv[1])
work_root = Path(sys.argv[2])
env = {**os.environ, "LC_ALL": "C", "LANGUAGE": "C", "SECDAT_MASTER_KEY": "default-format-test-key"}
for variable in ("SECDAT_ASKPASS", "SSH_ASKPASS"):
    env.pop(variable, None)
data_home = Path(env["XDG_DATA_HOME"])
parent = work_root / "parent"
child = parent / "child"
for domain in (parent, child):
    domain.mkdir(parents=True, exist_ok=True)


def run(domain, *args, environment=None):
    return subprocess.run(
        [bin_path, "--dir", str(domain), *args], text=True, capture_output=True,
        env=env if environment is None else environment, check=False,
    )


def require_ok(result, label, stdout=""):
    if result.returncode != 0 or result.stderr or (stdout is not None and result.stdout != stdout):
        raise SystemExit(f"FAIL: {label}: rc={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")


def root(domain, store="default"):
    return store_root(data_home, domain, store)


def require_v2(domain, store="default"):
    target = root(domain, store)
    if (target / "format").read_bytes() != V2_MARKER:
        raise SystemExit(f"FAIL: new store is not v2: {target}")
    if (target / "format").stat().st_mode & 0o777 != 0o600:
        raise SystemExit(f"FAIL: new format marker is not private: {target}")
    require_ok(run(domain, "--store", store, "fsck"), f"automatic v2 fsck {store}", "ok\n")
    require_ok(run(domain, "--store", store, "fsck", "--format", "v2"), f"explicit v2 fsck {store}", "ok\n")


def snapshot():
    result = []
    for path in sorted(data_home.rglob("*")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        result.append((path.relative_to(data_home).as_posix(), path.stat().st_mode, digest))
    return result


for domain in (parent, child):
    require_ok(run(domain, "domain", "create"), "domain create")
    require_v2(domain)
require_ok(run(parent, "store", "create", "named"), "named store create")
require_v2(parent, "named")

# New v2 capabilities need no preliminary migration.
require_ok(run(parent, "set", "SOURCE", "--value", "source-value"), "source set")
require_ok(run(parent, "ln", "SOURCE", "ALIAS"), "new default store link")
a = run(parent, "id", "SOURCE")
b = run(parent, "id", "ALIAS")
if a.returncode or b.returncode or not a.stdout.strip() or a.stdout != b.stdout:
    raise SystemExit(f"FAIL: new v2 link identity: {a} {b}")
# Hidden-name writes retain the existing dependency-index coverage preflight.
rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
if rebuilt.returncode or rebuilt.stderr or not rebuilt.stdout.startswith("rebuilt-dependency-index\tglobal\t"):
    raise SystemExit(f"FAIL: new v2 dependency index preflight: {rebuilt}")
require_ok(run(parent, "set", "HIDDEN", "--key-visibility", "unlocked", "--value", "hidden-value"), "new v2 hidden key")
locked = {key: value for key, value in env.items() if key != "SECDAT_MASTER_KEY"}
listing = run(parent, "ls", environment=locked)
if listing.returncode or "HIDDEN" in listing.stdout or "hidden-value" in listing.stdout + listing.stderr:
    raise SystemExit(f"FAIL: hidden key exposed while locked: {listing}")

# Every implicit destination chooses its own newly created v2 namespace.
require_ok(run(parent, "set", "NEW:implicit-set", "--value", "set-value"), "implicit set")
require_ok(run(parent, "cp", "SOURCE", "COPY:implicit-cp"), "implicit cp")
require_ok(run(parent, "set", "MOVE_SOURCE", "--value", "move-value"), "move seed")
require_ok(run(parent, "mv", "MOVE_SOURCE", "MOVED:implicit-mv"), "implicit mv")
require_ok(run(parent, "ln", "SOURCE", "LINK:implicit-ln"), "implicit ln")
for store in ("implicit-set", "implicit-cp", "implicit-mv", "implicit-ln"):
    require_v2(parent, store)
for keyref, expected in (("NEW:implicit-set", "set-value"), ("COPY:implicit-cp", "source-value"), ("MOVED:implicit-mv", "move-value"), ("LINK:implicit-ln", "source-value")):
    require_ok(run(parent, "get", keyref), f"implicit value {keyref}", expected)

# Relation metadata can create a namespace even when every member belongs to
# another explicitly qualified store/domain.
require_ok(run(parent, "set", "REL_OTHER", "--value", "relation-other"), "relation member seed")
require_ok(run(
    child, "--store", "relation-created", "relation", "set", "pair",
    "--member", f"left={parent}/SOURCE:default",
    "--member", f"right={parent}/REL_OTHER:default",
), "implicit relation store")
require_v2(child, "relation-created")
before = snapshot()
invalid_relation = run(
    child, "--store", "relation-invalid", "relation", "set", "pair",
    "--member", f"left={parent}/SOURCE:default",
    "--member", f"right={parent}/MISSING:default",
)
if invalid_relation.returncode == 0 or root(child, "relation-invalid").exists() or snapshot() != before:
    raise SystemExit(f"FAIL: invalid relation input materialized a target store: {invalid_relation}")

# Bundle load into a missing target store follows the same v2 default.
askpass = work_root / "askpass.sh"
askpass.write_text("#!/bin/sh\nprintf '%s\\n' fixture-bundle-passphrase\n", encoding="utf-8")
askpass.chmod(0o700)
bundle_env = {**env, "SECDAT_ASKPASS": str(askpass)}
require_ok(run(parent, "set", "BUNDLE:bundle-source", "--value", "bundle-value"), "bundle seed")
bundle = work_root / "fixture.secdat"
require_ok(run(parent, "--store", "bundle-source", "save", str(bundle), environment=bundle_env), "bundle save")
require_ok(run(parent, "--store", "implicit-load", "load", str(bundle), environment=bundle_env), "implicit load")
require_v2(parent, "implicit-load")
require_ok(run(parent, "get", "BUNDLE:implicit-load"), "implicit load value", "bundle-value")
before = snapshot()
skipped = run(child, "--store", "bundle-source", "load", "--conflict", "skip", str(bundle), environment=bundle_env)
if skipped.returncode or skipped.stdout or skipped.stderr or root(child, "bundle-source").exists() or snapshot() != before:
    raise SystemExit(f"FAIL: all-skipped inherited load initialized a store or changed state: {skipped}")
require_ok(run(parent, "store", "create", "empty-bundle-source"), "empty bundle source")
empty_bundle = work_root / "empty.secdat"
require_ok(run(parent, "--store", "empty-bundle-source", "save", str(empty_bundle), environment=bundle_env), "save empty view")
before = snapshot()
empty_load = run(child, "--store", "empty-import", "load", str(empty_bundle), environment=bundle_env)
if empty_load.returncode or empty_load.stdout or empty_load.stderr or root(child, "empty-import").exists() or snapshot() != before:
    raise SystemExit(f"FAIL: empty bundle load initialized a store or changed state: {empty_load}")

# Planning, reads, rejected input and failed locked writes do not instantiate a store.
for store, args, success in [
    ("dry-set", ["set", "DRY:dry-set", "--value", "dry", "--dry-run", "--json"], True),
    ("dry-copy", ["cp", "SOURCE", "DRY:dry-copy", "--dry-run", "--json"], True),
    ("dry-link", ["ln", "SOURCE", "DRY:dry-link", "--dry-run", "--json"], True),
    # Cross-store mv planning retains its existing explicit rejection boundary.
    ("dry-move", ["mv", "SOURCE", "DRY:dry-move", "--dry-run", "--json"], False),
    ("missing-read", ["get", "MISSING:missing-read"], False),
    ("missing-list", ["--store", "missing-list", "ls"], True),
    ("missing-exists", ["exists", "MISSING:missing-exists"], False),
    ("missing-rm", ["rm", "MISSING:missing-rm", "--ignore-missing"], True),
    ("bad-input", ["set", "BAD-KEY:bad-input", "--value", "bad"], False),
]:
    before = snapshot()
    result = run(parent, *args)
    if (result.returncode == 0) != success or root(parent, store).exists() or snapshot() != before:
        raise SystemExit(f"FAIL: non-writing missing-store operation {args!r}: {result}")
before = snapshot()
result = run(parent, "set", "LOCKED:locked-missing", "--value", "secret", environment=locked)
if result.returncode == 0 or root(parent, "locked-missing").exists() or snapshot() != before:
    raise SystemExit(f"FAIL: locked write materialized missing store: {result}")

# Explicit legacy fixtures exercise both historical markerless and marked v1.
for store, marked in (("legacy-markerless", False), ("legacy-marked", True)):
    legacy = create_v1_store(data_home, parent, store, marked=marked)
    require_ok(run(parent, "set", f"OLD:{store}", "--value", "old-value"), "legacy set")
    require_ok(run(parent, "get", f"OLD:{store}"), "legacy get", "old-value")
    require_ok(run(parent, "cp", f"OLD:{store}", f"COPY:{store}"), "legacy cp")
    require_ok(run(parent, "mv", f"COPY:{store}", f"MOVED:{store}"), "legacy mv")
    require_ok(run(parent, "--store", store, "fsck"), "legacy automatic fsck", "ok\n")
    require_ok(run(parent, "--store", store, "fsck", "--format", "v1"), "legacy explicit fsck", "ok\n")
    marker = legacy / "format"
    if marker.exists() != marked or (marked and marker.read_bytes() != V1_MARKER) or (legacy / "domain-ent").exists():
        raise SystemExit(f"FAIL: ordinary operations changed legacy format: {legacy}")
    mismatch = run(parent, "--store", store, "fsck", "--format", "v2")
    if mismatch.returncode != 2 or "store format is v1" not in mismatch.stderr:
        raise SystemExit(f"FAIL: explicit v2 mismatch on legacy store: {mismatch}")
require_ok(run(parent, "cp", "OLD:legacy-markerless", "IMPORTED:from-v1"), "legacy source to new v2 destination")
require_v2(parent, "from-v1")
require_ok(run(parent, "get", "IMPORTED:from-v1"), "legacy-to-v2 copy value", "old-value")

# An inherited v1 source never determines the format of a new local namespace.
legacy_parent = create_v1_store(data_home, parent, "mixed")
require_ok(run(parent, "set", "PARENT_ONLY:mixed", "--value", "parent-v1"), "mixed parent set")
require_ok(run(child, "get", "PARENT_ONLY:mixed"), "mixed inherited v1 read", "parent-v1")
if root(child, "mixed").exists():
    raise SystemExit("FAIL: inherited read instantiated a child store")
require_ok(run(child, "set", "CHILD_ONLY:mixed", "--value", "child-v2"), "mixed child set")
require_v2(child, "mixed")
require_ok(run(child, "get", "PARENT_ONLY:mixed"), "mixed inherited read after child creation", "parent-v1")
require_ok(run(child, "set", "PARENT_ONLY:mixed", "--value", "mixed-local-v2"), "mixed local v2 override")
require_ok(run(child, "get", "PARENT_ONLY:mixed"), "mixed local override read", "mixed-local-v2")
require_ok(run(parent, "get", "PARENT_ONLY:mixed"), "mixed parent preserved", "parent-v1")
mixed_rows = run(child, "--store", "mixed", "ls", "--json")
require_ok(mixed_rows, "mixed v1/v2 local listing", stdout=None)
mixed_listing = json.loads(mixed_rows.stdout)
if mixed_listing["key_count"] != 2 or sorted(item["key"] for item in mixed_listing["keys"]) != ["CHILD_ONLY", "PARENT_ONLY"]:
    raise SystemExit(f"FAIL: mixed v1/v2 listing/get precedence differs: {mixed_listing!r}")
if (legacy_parent / "format").exists() or (legacy_parent / "domain-ent").exists():
    raise SystemExit("FAIL: creating child store migrated parent v1")
require_ok(run(parent, "set", "PARENT:reverse-mixed", "--value", "parent-v2"), "reverse mixed parent")
legacy_child = create_v1_store(data_home, child, "reverse-mixed", marked=True)
require_ok(run(child, "set", "CHILD:reverse-mixed", "--value", "child-v1"), "reverse mixed child")
require_ok(run(child, "get", "PARENT:reverse-mixed"), "reverse inherited v2 read", "parent-v2")
require_ok(run(child, "get", "CHILD:reverse-mixed"), "reverse local v1 read", "child-v1")
require_ok(run(child, "set", "PARENT:reverse-mixed", "--value", "reverse-local-v1"), "reverse local v1 override")
require_ok(run(child, "get", "PARENT:reverse-mixed"), "reverse local override read", "reverse-local-v1")
require_ok(run(parent, "get", "PARENT:reverse-mixed"), "reverse parent preserved", "parent-v2")
mixed_rows = run(child, "--store", "reverse-mixed", "ls", "--json")
require_ok(mixed_rows, "reverse mixed local listing", stdout=None)
mixed_listing = json.loads(mixed_rows.stdout)
if mixed_listing["key_count"] != 2 or sorted(item["key"] for item in mixed_listing["keys"]) != ["CHILD", "PARENT"]:
    raise SystemExit(f"FAIL: reverse v2/v1 listing/get precedence differs: {mixed_listing!r}")
if (legacy_child / "format").read_bytes() != V1_MARKER:
    raise SystemExit("FAIL: inherited v2 source changed existing child v1 format")
require_v2(parent, "reverse-mixed")

# Both canonical v2 masks and legacy v1-source masks can initialize an absent
# local namespace without converting the inherited source namespace.
require_ok(run(parent, "set", "MASK_SOURCE:mask-created", "--value", "mask-value"), "mask source")
rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
if rebuilt.returncode or rebuilt.stderr:
    raise SystemExit(f"FAIL: mask dependency coverage: {rebuilt}")
before = snapshot()
planned = run(child, "mask", "MASK_SOURCE:mask-created", "--dry-run", "--json")
if planned.returncode or root(child, "mask-created").exists() or snapshot() != before:
    raise SystemExit(f"FAIL: missing-store mask dry-run wrote state: {planned}")
require_ok(run(child, "mask", "MASK_SOURCE:mask-created"), "implicit canonical mask")
require_v2(child, "mask-created")
if run(child, "get", "MASK_SOURCE:mask-created").returncode != 1:
    raise SystemExit("FAIL: newly initialized canonical mask did not hide source")
require_ok(run(child, "unmask", "MASK_SOURCE:mask-created"), "canonical unmask")
require_ok(run(child, "get", "MASK_SOURCE:mask-created"), "canonical source restored", "mask-value")
legacy_mask_source = create_v1_store(data_home, parent, "legacy-mask")
require_ok(run(parent, "set", "LEGACY_MASK:legacy-mask", "--value", "legacy-mask-value"), "legacy mask source")
require_ok(run(child, "mask", "LEGACY_MASK:legacy-mask"), "implicit legacy-source mask")
if (root(child, "legacy-mask") / "format").read_bytes() != V2_MARKER:
    raise SystemExit("FAIL: legacy-source mask did not initialize a v2 child store")
# A v1 source has no stable entry UUID. Preserve its legacy ambiguity instead
# of inventing a canonical identity or automatically migrating the source.
for format_args in ((), ("--format", "v2")):
    report = run(child, "--store", "legacy-mask", "fsck", *format_args)
    if report.returncode != 1 or report.stderr or report.stdout != "ambiguous-mask\tLEGACY_MASK\tunresolved-target\n":
        raise SystemExit(f"FAIL: legacy-source ambiguity report changed: {report}")
if run(child, "get", "LEGACY_MASK:legacy-mask").returncode != 1:
    raise SystemExit("FAIL: new local v2 store did not mask inherited v1 source")
if (legacy_mask_source / "format").exists() or (legacy_mask_source / "domain-ent").exists():
    raise SystemExit("FAIL: masking an inherited v1 source migrated it")
before = snapshot()
refused = run(child, "unmask", "LEGACY_MASK:legacy-mask")
if refused.returncode != 1 or "ambiguous legacy mask requires mask --rebind before unmask" not in refused.stderr or snapshot() != before:
    raise SystemExit(f"FAIL: ambiguous legacy unmask did not retain its guard: {refused}")
if (legacy_mask_source / "format").exists() or (legacy_mask_source / "domain-ent").exists():
    raise SystemExit("FAIL: refused legacy unmask migrated its source")
# Owner-selected compatibility boundary: preserve the v2 ambiguity guard and
# require an explicit source migration plus reviewed rebind before unmask.
require_ok(run(parent, "store", "migrate", "legacy-mask", "--to-format", "v2"), "manual legacy mask source migration", stdout=None)
rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
if rebuilt.returncode or rebuilt.stderr:
    raise SystemExit(f"FAIL: manual legacy mask dependency coverage: {rebuilt}")
require_ok(run(child, "mask", "--rebind", "LEGACY_MASK:legacy-mask"), "manual legacy mask rebind")
require_ok(run(child, "unmask", "LEGACY_MASK:legacy-mask"), "manual legacy-source unmask")
require_ok(run(child, "get", "LEGACY_MASK:legacy-mask"), "legacy mask source restored", "legacy-mask-value")
require_v2(child, "legacy-mask")

# A volatile session may defer namespace creation until its explicit save.
volatile = work_root / "volatile"
volatile.mkdir()
require_ok(run(volatile, "domain", "create"), "volatile domain")
unlocked = run(volatile, "unlock", "--volatile")
if unlocked.returncode or "session unlocked" not in unlocked.stdout:
    raise SystemExit(f"FAIL: volatile unlock: {unlocked}")
require_ok(run(volatile, "set", "VOL:save-created", "--value", "volatile-value", environment=locked), "volatile missing-store set")
if root(volatile, "save-created").exists():
    raise SystemExit("FAIL: volatile set instantiated persistent namespace before save")
saved = run(volatile, "lock", "--save", environment=locked)
if saved.returncode or saved.stdout != "volatile session saved and locked\n" or saved.stderr:
    raise SystemExit(f"FAIL: volatile lock --save: {saved}")
require_v2(volatile, "save-created")
require_ok(run(volatile, "get", "VOL:save-created"), "saved volatile v2 value", "volatile-value")
for source_format in ("v2", "v1"):
    store = "overlay-mask-" + source_format
    if source_format == "v1":
        create_v1_store(data_home, parent, store)
    require_ok(run(parent, "set", f"OVERLAY_SOURCE:{store}", "--value", "overlay-value"), "overlay mask source")
    unlocked = run(child, "unlock", "--volatile")
    if unlocked.returncode or "session unlocked" not in unlocked.stdout:
        raise SystemExit(f"FAIL: child volatile unlock: {unlocked}")
    require_ok(run(child, "mask", f"OVERLAY_SOURCE:{store}", environment=locked), "volatile overlay mask")
    if root(child, store).exists():
        raise SystemExit("FAIL: volatile mask instantiated persistent namespace before save")
    saved = run(child, "lock", "--save", environment=locked)
    if saved.returncode or saved.stdout != "volatile session saved and locked\n" or saved.stderr:
        raise SystemExit(f"FAIL: overlay tombstone lock --save: {saved}")
    if (root(child, store) / "format").read_bytes() != V2_MARKER:
        raise SystemExit("FAIL: saved overlay tombstone did not initialize a v2 store")
    if run(child, "get", f"OVERLAY_SOURCE:{store}").returncode != 1:
        raise SystemExit("FAIL: saved overlay mask did not hide inherited source")
    if source_format == "v1":
        before = snapshot()
        overlay_report = run(child, "--store", store, "fsck")
        explicit_report = run(child, "--store", store, "fsck", "--format", "v2")
        expected = "ambiguous-mask\tOVERLAY_SOURCE\tunresolved-target\n"
        if overlay_report.returncode != 1 or overlay_report.stderr or overlay_report.stdout != expected or explicit_report.returncode != 1 or explicit_report.stdout != expected:
            raise SystemExit(f"FAIL: saved legacy overlay diagnostics: {overlay_report} {explicit_report}")
        refused = run(child, "unmask", f"OVERLAY_SOURCE:{store}")
        if refused.returncode != 1 or "ambiguous legacy mask requires mask --rebind before unmask" not in refused.stderr or snapshot() != before:
            raise SystemExit(f"FAIL: saved legacy overlay unmask guard: {refused}")
        if (root(parent, store) / "format").exists():
            raise SystemExit("FAIL: overlay save or refused unmask migrated its parent")
        require_ok(run(parent, "store", "migrate", store, "--to-format", "v2"), "manual saved overlay source migration", stdout=None)
        rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
        if rebuilt.returncode or rebuilt.stderr:
            raise SystemExit(f"FAIL: saved overlay dependency coverage: {rebuilt}")
        require_ok(run(child, "mask", "--rebind", f"OVERLAY_SOURCE:{store}"), "saved overlay rebind")
    else:
        require_v2(child, store)
    require_ok(run(child, "unmask", f"OVERLAY_SOURCE:{store}"), "saved overlay unmask")
    require_ok(run(child, "get", f"OVERLAY_SOURCE:{store}"), "saved overlay source restored", "overlay-value")
    require_v2(child, store)

# Recovery can stop before or immediately after namespace initialization;
# staged initialization must precede the value/entry writes in the journal.
transaction_root = data_home / "secdat" / "transactions"
for boundary in ("prepared", "committing", "target-2", "committing-partial"):
    store = "recovery-" + boundary
    crash_boundary = "committing" if boundary == "committing-partial" else boundary
    crash_env = {**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": crash_boundary}
    crashed = run(parent, "set", f"RECOVER:{store}", "--value", "recovered-value", environment=crash_env)
    if crashed.returncode != 86:
        raise SystemExit(f"FAIL: missing-store crash at {boundary}: {crashed}")
    pending = [path for path in transaction_root.iterdir() if path.name != "lock"]
    if len(pending) != 1:
        raise SystemExit(f"FAIL: expected one recovery journal at {boundary}: {pending!r}")
    lines = (pending[0] / "journal").read_text(encoding="utf-8").splitlines()
    manifest = json.loads(lines[1])
    writes = manifest.get("writes", [])
    initializers = [item for item in writes if item.get("role") == "store-initialization"]
    if len(initializers) != 1 or initializers[0].get("phase") != 15 or len(writes) < 3 or writes[1] != initializers[0]:
        raise SystemExit(f"FAIL: namespace initialization ordering at {boundary}: {writes!r}")
    if boundary != "target-2" and root(parent, store).exists():
        raise SystemExit(f"FAIL: namespace published before commit application at {boundary}")
    if boundary == "target-2" and (root(parent, store) / "format").read_bytes() != V2_MARKER:
        raise SystemExit("FAIL: initialization target did not materialize v2 before interruption")
    if boundary == "committing-partial":
        # A legitimate interrupted mkdir sequence may leave only part of the
        # known empty skeleton, with no published marker or user payload.
        (root(parent, store) / "entries").mkdir(parents=True, mode=0o700)
        root(parent, store).chmod(0o700)
    require_ok(run(parent, "status", "--quiet"), f"recover {boundary}")
    if [path for path in transaction_root.iterdir() if path.name != "lock"]:
        raise SystemExit(f"FAIL: pending recovery journal remained at {boundary}")
    if boundary == "prepared":
        if root(parent, store).exists():
            raise SystemExit("FAIL: discarded PREPARED operation created a store")
    else:
        require_v2(parent, store)
        require_ok(run(parent, "get", f"RECOVER:{store}"), f"recovered value {boundary}", "recovered-value")

# Typed mask/tombstone before-image reads must also tolerate a verified pending
# initialization whose legitimate partial skeleton lacks their parent dirs.
for source_format in ("v2", "v1"):
    store = "recovery-mask-" + source_format
    if source_format == "v1":
        create_v1_store(data_home, parent, store)
    require_ok(run(parent, "set", f"SOURCE:{store}", "--value", "source-value"), "recovery mask seed")
    rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
    if rebuilt.returncode or rebuilt.stderr:
        raise SystemExit(f"FAIL: recovery mask dependency coverage: {rebuilt}")
    crashed = run(
        child, "mask", f"SOURCE:{store}",
        environment={**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
    )
    if crashed.returncode != 86 or root(child, store).exists():
        raise SystemExit(f"FAIL: typed-mask recovery fixture {source_format}: {crashed}")
    (root(child, store) / "entries").mkdir(parents=True, mode=0o700)
    root(child, store).chmod(0o700)
    require_ok(run(child, "status", "--quiet"), f"recover partial typed mask {source_format}")
    if (root(child, store) / "format").read_bytes() != V2_MARKER:
        raise SystemExit(f"FAIL: partial typed-mask recovery did not initialize v2: {source_format}")
    if run(child, "get", f"SOURCE:{store}").returncode != 1:
        raise SystemExit(f"FAIL: recovered typed mask did not hide source: {source_format}")
    require_ok(run(parent, "get", f"SOURCE:{store}"), "typed-mask recovery preserved parent", "source-value")
    if source_format == "v1":
        before = snapshot()
        refused = run(child, "unmask", f"SOURCE:{store}")
        if refused.returncode != 1 or "ambiguous legacy mask requires mask --rebind before unmask" not in refused.stderr or snapshot() != before:
            raise SystemExit(f"FAIL: recovered ambiguous legacy unmask guard: {refused}")
        if (root(parent, store) / "format").exists():
            raise SystemExit("FAIL: recovering a legacy mask migrated its parent")
        require_ok(run(parent, "store", "migrate", store, "--to-format", "v2"), "manual recovered mask source migration", stdout=None)
        rebuilt = run(parent, "fsck", "--dependency-index", "--repair")
        if rebuilt.returncode or rebuilt.stderr:
            raise SystemExit(f"FAIL: recovered legacy dependency coverage: {rebuilt}")
        require_ok(run(child, "mask", "--rebind", f"SOURCE:{store}"), "manual recovered mask rebind")
    require_ok(run(child, "unmask", f"SOURCE:{store}"), "typed-mask recovery unmask")
    require_v2(child, store)

# Invalid markers are errors, not a reason to reinterpret or recreate a store.
require_ok(run(parent, "store", "create", "invalid-marker"), "invalid marker fixture")
marker = root(parent, "invalid-marker") / "format"
marker.write_bytes(b"not-a-format\n")
before = snapshot()
for args in (("--store", "invalid-marker", "fsck"), ("get", "MISSING:invalid-marker"), ("set", "NEW:invalid-marker", "--value", "new")):
    result = run(parent, *args)
    diagnostic = "cannot determine store format for fsck" if args[-1] == "fsck" else "invalid store format marker"
    if result.returncode == 0 or diagnostic not in result.stderr or snapshot() != before:
        raise SystemExit(f"FAIL: invalid marker was not preserved: {args!r}: {result}")
marker.write_bytes(V2_MARKER)
mismatch = run(parent, "fsck", "--format", "v1")
if mismatch.returncode != 2 or "store format is v2" not in mismatch.stderr:
    raise SystemExit(f"FAIL: explicit v1 mismatch on new v2 store: {mismatch}")

# Recovery must never stamp v2 over foreign/v1 data inserted before its marker.
# Keep this unresolved journal last: subsequent commands must also fail closed.
store = "recovery-foreign-payload"
crashed = run(
    parent, "set", f"RECOVER:{store}", "--value", "intended-value",
    environment={**env, "SECDAT_TEST_TRANSACTION_CRASH_AFTER": "committing"},
)
if crashed.returncode != 86 or root(parent, store).exists():
    raise SystemExit(f"FAIL: foreign-payload recovery fixture: {crashed}")
foreign = root(parent, store) / "entries" / "OLD.sec"
foreign.parent.mkdir(parents=True, mode=0o700)
root(parent, store).chmod(0o700)
foreign.write_bytes(b"preserve-this-legacy-or-foreign-payload")
foreign.chmod(0o600)
foreign_before = foreign.read_bytes()
blocked = run(parent, "status", "--quiet")
if blocked.returncode == 0 or not foreign.exists() or foreign.read_bytes() != foreign_before or (root(parent, store) / "format").exists():
    raise SystemExit(f"FAIL: recovery accepted or changed foreign payload: {blocked}")
if not [path for path in transaction_root.iterdir() if path.name != "lock"]:
    raise SystemExit("FAIL: blocked foreign-payload recovery discarded its journal")

print("PASS store default format regression")
PY
