#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

build_root="$(cd "$(dirname "$bin_path")/.." && pwd)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(cd "$script_dir/.." && pwd)"
work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
export LC_ALL=C
export LANGUAGE=C
export SECDAT_MASTER_KEY="sdk-regression-master-key"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

root_domain="$work_root/root"
child_domain="$root_domain/child"
orphaned_child_domain="$root_domain/orphaned-child"
refresh_domain="$work_root/refresh"
long_role="$(printf '%*s' 5000 '' | tr ' ' r)"
mkdir -p "$root_domain" "$child_domain" "$orphaned_child_domain" "$refresh_domain"

run_secdat() {
    local stdout_path="$work_root/stdout"
    local stderr_path="$work_root/stderr"

    if ! "$bin_path" "$@" >"$stdout_path" 2>"$stderr_path"; then
        printf 'stdout:\n%s\nstderr:\n%s\n' "$(cat "$stdout_path")" "$(cat "$stderr_path")" >&2
        fail "secdat command failed: $*"
    fi
    if test -s "$stderr_path"; then
        printf 'stderr:\n%s\n' "$(cat "$stderr_path")" >&2
        fail "unexpected stderr from secdat command: $*"
    fi
}

run_secdat --dir "$root_domain" domain create
run_secdat --dir "$child_domain" domain create
run_secdat --dir "$orphaned_child_domain" domain create
run_secdat --dir "$refresh_domain" domain create
run_secdat --dir "$root_domain" store create team
run_secdat --dir "$root_domain" --store team set API_TOKEN --value sdk-secret-value
run_secdat --dir "$root_domain" --store team set PUBLIC_URL --unsafe --value public-secret-value
run_secdat --dir "$root_domain" --store team set BULK_TOKEN --bulk-select include --value bulk-secret-value
run_secdat --dir "$root_domain" --store team set LONG_PRIMARY --value long-primary-value
run_secdat --dir "$root_domain" --store team set LONG_SECONDARY --value long-secondary-value
run_secdat --dir "$refresh_domain" set CONSUMER_TOKEN --value consumer-token
run_secdat --dir "$root_domain" --store team relation set sdk-refresh \
    --member token=API_TOKEN \
    --member bulk_token=BULK_TOKEN \
    --member account=PUBLIC_URL \
    --security combination-sensitive
run_secdat --dir "$refresh_domain" relation set sdk-cross-refresh \
    --member "token=$root_domain/API_TOKEN:team" \
    --member refresh_token=CONSUMER_TOKEN \
    --security combination-sensitive
run_secdat --dir "$root_domain" --store team relation set sdk-long-refresh \
    --member "$long_role=LONG_PRIMARY" \
    --member secondary=LONG_SECONDARY \
    --security combination-sensitive
run_secdat --dir "$orphaned_child_domain" set ORPHANED_SDK_KEY --value orphaned-sdk-value
rmdir "$orphaned_child_domain"

cat >"$work_root/sdk_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int string_has_secret(const char *value)
{
    return strstr(value, "sdk-secret-value") != NULL
        || strstr(value, "public-secret-value") != NULL
        || strstr(value, "bulk-secret-value") != NULL
        || strstr(value, "bulk-updated-value") != NULL
        || strstr(value, "long-primary-value") != NULL
        || strstr(value, "long-secondary-value") != NULL
        || strstr(value, "consumer-token") != NULL;
}

static void assert_no_key_value(const struct secdat_sdk_key_metadata *item)
{
    if (string_has_secret(item->key)
        || string_has_secret(item->store)
        || string_has_secret(item->canonical_keyref)
        || string_has_secret(item->source_domain)
        || string_has_secret(item->source_type)
        || string_has_secret(item->storage_mode)
        || string_has_secret(item->key_visibility)
        || string_has_secret(item->value_access)
        || string_has_secret(item->bulk_select)) {
        fail("key metadata exposed a secret value");
    }
}

static const struct secdat_sdk_key_metadata *find_key(
    const struct secdat_sdk_key_metadata_list *list,
    const char *key
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].key, key) == 0) {
            return &list->items[index];
        }
    }
    return NULL;
}

static int contains_store(const struct secdat_sdk_store_metadata_list *list, const char *name)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int contains_domain(const struct secdat_sdk_domain_metadata_list *list, const char *root)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].root, root) == 0) {
            return 1;
        }
    }
    return 0;
}

static const struct secdat_sdk_domain_metadata *find_domain(
    const struct secdat_sdk_domain_metadata_list *list,
    const char *root
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].root, root) == 0) {
            return &list->items[index];
        }
    }
    return NULL;
}

static const struct secdat_sdk_relation_refresh_suggestion *find_refresh_suggestion(
    const struct secdat_sdk_relation_refresh_suggestion_list *list,
    const char *relation_id,
    const char *leaked_role,
    const char *refresh_role,
    const char *refresh_keyref,
    const char *reason
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        const struct secdat_sdk_relation_refresh_suggestion *item = &list->items[index];

        if (strcmp(item->severity, "high") == 0
            && strcmp(item->relation_id, relation_id) == 0
            && strcmp(item->leaked_role, leaked_role) == 0
            && strcmp(item->refresh_role, refresh_role) == 0
            && strcmp(item->refresh_keyref, refresh_keyref) == 0
            && strcmp(item->reason, reason) == 0) {
            return item;
        }
    }
    return NULL;
}

static void assert_no_refresh_secret(const struct secdat_sdk_relation_refresh_suggestion *item)
{
    if (string_has_secret(item->severity)
        || string_has_secret(item->relation_id)
        || string_has_secret(item->leaked_role)
        || string_has_secret(item->refresh_role)
        || string_has_secret(item->refresh_keyref)
        || string_has_secret(item->reason)) {
        fail("relation refresh suggestion exposed a secret value");
    }
}

static void format_expected_keyref(char *buffer, size_t size, const char *domain, const char *keyref)
{
    int written = snprintf(buffer, size, "%s/%s", domain, keyref);

    if (written < 0 || (size_t)written >= size) {
        fail("expected keyref path was too long");
    }
}

int main(int argc, char **argv)
{
    const char *root;
    const char *child;
    const char *orphaned_child;
    const char *refresh_domain;
    const char *long_role;
    struct secdat_sdk_options root_options = {0};
    struct secdat_sdk_options child_options = {0};
    struct secdat_sdk_list_filters public_filter = {0};
    struct secdat_sdk_list_filters bulk_filter = {0};
    struct secdat_sdk_domain_filters domain_filters = {0};
    struct secdat_sdk_key_metadata_list keys = {0};
    struct secdat_sdk_key_metadata_list public_keys = {0};
    struct secdat_sdk_key_metadata_list bulk_keys = {0};
    struct secdat_sdk_key_metadata_list child_keys = {0};
    struct secdat_sdk_store_metadata_list stores = {0};
    struct secdat_sdk_domain_metadata_list domains = {0};
    struct secdat_sdk_relation_refresh_suggestion_list refreshes = {0};
    struct secdat_sdk_relation_refresh_suggestion_list public_refreshes = {0};
    struct secdat_sdk_relation_refresh_suggestion_list long_refreshes = {0};
    const struct secdat_sdk_key_metadata *api_token;
    const struct secdat_sdk_key_metadata *public_url;
    const struct secdat_sdk_key_metadata *bulk_token;
    const struct secdat_sdk_domain_metadata *orphaned_domain;
    char expected_api_keyref[PATH_MAX * 2];
    char expected_bulk_keyref[PATH_MAX * 2];
    char expected_consumer_keyref[PATH_MAX * 2];
    char expected_long_primary_keyref[PATH_MAX * 2];
    char expected_long_secondary_keyref[PATH_MAX * 2];
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    size_t index;

    if (argc != 6) {
        fail("expected root, child, orphaned child, refresh domain, and long role");
    }
    root = argv[1];
    child = argv[2];
    orphaned_child = argv[3];
    refresh_domain = argv[4];
    long_role = argv[5];
    root_options.dir = root;
    root_options.store = "team";
    child_options.dir = child;
    child_options.store = "team";

    if (secdat_sdk_list_stores(&root_options, &stores) != 0) {
        fail("secdat_sdk_list_stores failed");
    }
    if (!contains_store(&stores, "team")) {
        fail("store metadata did not include team");
    }
    secdat_sdk_free(stores.items);

    if (secdat_sdk_list_keys(&root_options, NULL, &keys) != 0) {
        fail("secdat_sdk_list_keys failed");
    }
    for (index = 0; index < keys.count; index += 1) {
        assert_no_key_value(&keys.items[index]);
    }
    api_token = find_key(&keys, "API_TOKEN");
    public_url = find_key(&keys, "PUBLIC_URL");
    bulk_token = find_key(&keys, "BULK_TOKEN");
    if (api_token == NULL || public_url == NULL || bulk_token == NULL) {
        fail("key metadata did not include expected keys");
    }
    if (strcmp(api_token->storage_mode, "safe") != 0 || api_token->unsafe_store) {
        fail("safe key metadata had wrong storage mode");
    }
    if (strcmp(public_url->storage_mode, "unsafe") != 0 || !public_url->unsafe_store) {
        fail("unsafe key metadata had wrong storage mode");
    }
    if (!api_token->local || api_token->inherited || strcmp(api_token->source_type, "local") != 0) {
        fail("local source metadata was wrong");
    }
    if (strcmp(bulk_token->bulk_select, "include") != 0) {
        fail("bulk key metadata had wrong inject bulk policy");
    }
    secdat_sdk_free(keys.items);

    if (secdat_sdk_set_preserve_attrs(
            &root_options,
            "BULK_TOKEN",
            (const unsigned char *)"bulk-updated-value",
            strlen("bulk-updated-value")) != 0) {
        fail("secdat_sdk_set_preserve_attrs failed");
    }
    if (secdat_sdk_get(&root_options, "BULK_TOKEN", &value, &value_length, &unsafe_store) != 0) {
        fail("secdat_sdk_get after preserve attrs failed");
    }
    if (unsafe_store || value_length != strlen("bulk-updated-value")
        || memcmp(value, "bulk-updated-value", value_length) != 0) {
        fail("secdat_sdk_set_preserve_attrs wrote the wrong value or storage mode");
    }
    secdat_sdk_free(value);
    value = NULL;
    value_length = 0;

    bulk_filter.include_pattern = "BULK_*";
    bulk_filter.bulk_gate = 1;
    if (secdat_sdk_list_keys(&root_options, &bulk_filter, &bulk_keys) != 0) {
        fail("bulk filtered secdat_sdk_list_keys failed");
    }
    if (bulk_keys.count != 1
        || strcmp(bulk_keys.items[0].key, "BULK_TOKEN") != 0
        || strcmp(bulk_keys.items[0].bulk_select, "include") != 0) {
        fail("secdat_sdk_set_preserve_attrs did not preserve inject bulk metadata");
    }
    secdat_sdk_free(bulk_keys.items);

    public_filter.include_pattern = "PUBLIC_*";
    public_filter.unsafe_store = 1;
    if (secdat_sdk_list_keys(&root_options, &public_filter, &public_keys) != 0) {
        fail("filtered secdat_sdk_list_keys failed");
    }
    if (public_keys.count != 1 || strcmp(public_keys.items[0].key, "PUBLIC_URL") != 0) {
        fail("key metadata filters returned wrong keys");
    }
    assert_no_key_value(&public_keys.items[0]);
    secdat_sdk_free(public_keys.items);

    if (secdat_sdk_list_keys(&child_options, NULL, &child_keys) != 0) {
        fail("child secdat_sdk_list_keys failed");
    }
    api_token = find_key(&child_keys, "API_TOKEN");
    if (api_token == NULL || !api_token->inherited || api_token->local || strcmp(api_token->source_type, "inherited") != 0) {
        fail("inherited source metadata was wrong");
    }
    secdat_sdk_free(child_keys.items);

    format_expected_keyref(expected_api_keyref, sizeof(expected_api_keyref), root, "API_TOKEN:team");
    format_expected_keyref(expected_bulk_keyref, sizeof(expected_bulk_keyref), root, "BULK_TOKEN:team");
    format_expected_keyref(expected_consumer_keyref, sizeof(expected_consumer_keyref), refresh_domain, "CONSUMER_TOKEN:default");
    format_expected_keyref(expected_long_primary_keyref, sizeof(expected_long_primary_keyref), root, "LONG_PRIMARY:team");
    format_expected_keyref(expected_long_secondary_keyref, sizeof(expected_long_secondary_keyref), root, "LONG_SECONDARY:team");
    if (secdat_sdk_relation_suggest_refresh(&root_options, "API_TOKEN", &refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh failed");
    }
    if (refreshes.count != 4) {
        fail("relation refresh suggestion count mismatch");
    }
    for (index = 0; index < refreshes.count; index += 1) {
        assert_no_refresh_secret(&refreshes.items[index]);
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-refresh",
            "token",
            "token",
            expected_api_keyref,
            "leaked-secret-member") == NULL) {
        fail("missing SDK self refresh suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-refresh",
            "token",
            "bulk_token",
            expected_bulk_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK local related refresh suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-cross-refresh",
            "token",
            "token",
            expected_api_keyref,
            "leaked-secret-member") == NULL) {
        fail("missing SDK cross-domain leaked member suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-cross-refresh",
            "token",
            "refresh_token",
            expected_consumer_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK cross-domain refresh target suggestion");
    }
    secdat_sdk_free(refreshes.items);
    if (secdat_sdk_relation_suggest_refresh(&root_options, "PUBLIC_URL", &public_refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh public role failed");
    }
    if (public_refreshes.count != 0) {
        fail("public relation role should not produce high-risk refresh suggestions");
    }
    secdat_sdk_free(public_refreshes.items);
    if (secdat_sdk_relation_suggest_refresh(&root_options, "LONG_PRIMARY", &long_refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh long role failed");
    }
    if (long_refreshes.count != 2) {
        fail("long role relation refresh suggestion count mismatch");
    }
    for (index = 0; index < long_refreshes.count; index += 1) {
        assert_no_refresh_secret(&long_refreshes.items[index]);
    }
    if (find_refresh_suggestion(
            &long_refreshes,
            "sdk-long-refresh",
            long_role,
            long_role,
            expected_long_primary_keyref,
            "leaked-relation-member") == NULL) {
        fail("missing SDK long role self suggestion");
    }
    if (find_refresh_suggestion(
            &long_refreshes,
            "sdk-long-refresh",
            long_role,
            "secondary",
            expected_long_secondary_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK long role related suggestion");
    }
    secdat_sdk_free(long_refreshes.items);

    if (secdat_sdk_wait_unlock(&root_options, 1) != 0) {
        fail("secdat_sdk_wait_unlock did not accept SECDAT_MASTER_KEY");
    }

    domain_filters.include_descendants = 1;
    if (secdat_sdk_list_domains(&root_options, &domain_filters, &domains) != 0) {
        fail("secdat_sdk_list_domains failed");
    }
    if (!contains_domain(&domains, root) || !contains_domain(&domains, child)) {
        fail("domain metadata did not include root and child");
    }
    orphaned_domain = find_domain(&domains, orphaned_child);
    if (orphaned_domain == NULL) {
        fail("domain metadata did not include orphaned child");
    }
    if (!orphaned_domain->orphaned_domain
        || orphaned_domain->unlocked
        || orphaned_domain->key_source != SECDAT_SDK_KEY_SOURCE_ORPHANED
        || orphaned_domain->effective_source != SECDAT_SDK_EFFECTIVE_SOURCE_ORPHANED
        || orphaned_domain->session_expires_at != 0
        || orphaned_domain->remaining_seconds != 0
        || orphaned_domain->related_domain_root[0] != '\0') {
        fail("orphaned domain metadata exposed unlock state");
    }
    secdat_sdk_free(domains.items);

    unsetenv("SECDAT_MASTER_KEY");
    if (secdat_sdk_wait_unlock(&root_options, 1) == 0) {
        fail("secdat_sdk_wait_unlock succeeded while locked");
    }

    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_harness.c" \
    -L"$build_root/src/.libs" -lsecdat -lssl -lcrypto \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_harness"

"$work_root/sdk_harness" "$root_domain" "$child_domain" "$orphaned_child_domain" "$refresh_domain" "$long_role"

cli_plan="$work_root/cli-plan.json"
cli_plan_stderr="$work_root/cli-plan.stderr"
sdk_plan="$work_root/sdk-plan.json"
sdk_plan_stderr="$work_root/sdk-plan.stderr"

if ! "$bin_path" --dir "$root_domain" --store team exec \
        --inject "ambient:only=__SDK_NO_AMBIENT__" \
        --inject "secret:only=API_TOKEN:BULK_TOKEN" \
        --inject "route:prefer=secret" \
        --command-resolution direct \
        --dry-run --json \
        python3 -c pass >"$cli_plan" 2>"$cli_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$cli_plan_stderr")" >&2
    fail "CLI exec dry-run JSON plan failed"
fi
if test -s "$cli_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$cli_plan_stderr")" >&2
    fail "unexpected stderr from CLI exec dry-run JSON plan"
fi

cat >"$work_root/sdk_plan_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    struct secdat_sdk_exec_plan_options plan_options = {0};
    const char *inject_rules[] = {
        "ambient:only=__SDK_NO_AMBIENT__",
        "secret:only=API_TOKEN:BULK_TOKEN",
        "route:prefer=secret",
    };
    const char *command_argv[] = {"python3", "-c", "pass"};
    char *json = NULL;

    if (argc != 2) {
        fail("expected root domain path");
    }
    options.dir = argv[1];
    options.store = "team";
    plan_options.inject_rules = inject_rules;
    plan_options.inject_rule_count = sizeof(inject_rules) / sizeof(inject_rules[0]);
    plan_options.command_resolution = "direct";
    plan_options.argv = command_argv;
    plan_options.argv_count = sizeof(command_argv) / sizeof(command_argv[0]);

    if (secdat_sdk_exec_plan_json(&options, &plan_options, &json) != 0 || json == NULL) {
        fail("secdat_sdk_exec_plan_json failed");
    }
    fputs(json, stdout);
    fputc('\n', stdout);
    secdat_sdk_free(json);
    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_plan_harness.c" \
    -L"$build_root/src/.libs" -lsecdat -lssl -lcrypto \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_plan_harness"

if ! "$work_root/sdk_plan_harness" "$root_domain" >"$sdk_plan" 2>"$sdk_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_plan_stderr")" >&2
    fail "SDK exec JSON plan harness failed"
fi
if test -s "$sdk_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_plan_stderr")" >&2
    fail "unexpected stderr from SDK exec JSON plan harness"
fi

python3 - "$cli_plan" "$sdk_plan" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    cli_plan = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    sdk_plan = json.load(handle)

if sdk_plan != cli_plan:
    raise SystemExit(f"FAIL: SDK exec plan JSON differed from CLI dry-run\nCLI={cli_plan!r}\nSDK={sdk_plan!r}")
if sdk_plan.get("ok") is not True:
    raise SystemExit(f"FAIL: SDK exec plan should be ok: {sdk_plan!r}")
if sdk_plan.get("command_resolution") != "direct":
    raise SystemExit(f"FAIL: SDK exec plan command resolution mismatch: {sdk_plan!r}")
if sdk_plan.get("argv") != ["python3", "-c", "pass"]:
    raise SystemExit(f"FAIL: SDK exec plan argv mismatch: {sdk_plan!r}")
if sdk_plan.get("supply", {}).get("ambient", {}).get("contributed") != []:
    raise SystemExit(f"FAIL: SDK exec plan ambient selection should be empty: {sdk_plan!r}")
if {item["key"] for item in sdk_plan.get("injected_keys", [])} != {"API_TOKEN", "BULK_TOKEN"}:
    raise SystemExit(f"FAIL: SDK exec plan injected keys mismatch: {sdk_plan!r}")

serialized = json.dumps(sdk_plan, sort_keys=True)
for secret in ["sdk-secret-value", "public-secret-value", "bulk-secret-value", "bulk-updated-value"]:
    if secret in serialized:
        raise SystemExit(f"FAIL: SDK exec plan exposed a secret value: {secret!r}")
PY

PYTHONPATH="$source_root/bindings/python" SECDAT_SDK_LIBRARY="$build_root/src/.libs/libsecdat.so" \
python3 - "$root_domain" "$refresh_domain" "$long_role" "$cli_plan" <<'PY'
import json
import os
import sys
import tempfile

from secdat_sdk import RedactionFieldClass, Secdat, SecdatError

root = sys.argv[1]
refresh_domain = sys.argv[2]
long_role = sys.argv[3]
cli_plan_path = sys.argv[4]
secret_values = [
    "sdk-secret-value",
    "public-secret-value",
    "bulk-secret-value",
    "bulk-updated-value",
    "long-primary-value",
    "long-secondary-value",
    "consumer-token",
]


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def assert_no_secret_text(value, label):
    for secret in secret_values:
        if secret in value:
            fail(f"{label} exposed a secret value: {secret!r}")


def find_refresh_suggestion(suggestions, relation_id, leaked_role, refresh_role, refresh_keyref, reason):
    for item in suggestions:
        if (
            item.severity == "high"
            and item.relation_id == relation_id
            and item.leaked_role == leaked_role
            and item.refresh_role == refresh_role
            and item.refresh_keyref == refresh_keyref
            and item.reason == reason
        ):
            return item
    return None


def call_with_c_stderr_suppressed(callback):
    saved_stderr = os.dup(2)
    try:
        with tempfile.TemporaryFile() as captured:
            os.dup2(captured.fileno(), 2)
            try:
                return callback()
            finally:
                os.dup2(saved_stderr, 2)
    finally:
        os.close(saved_stderr)


sdk = Secdat()
plan_json = sdk.exec_plan_json(
    ["python3", "-c", "pass"],
    dir=root,
    store="team",
    inject_rules=[
        "ambient:only=__SDK_NO_AMBIENT__",
        "secret:only=API_TOKEN:BULK_TOKEN",
        "route:prefer=secret",
    ],
    command_resolution="direct",
)
with open(cli_plan_path, encoding="utf-8") as handle:
    cli_plan = json.load(handle)
python_plan = json.loads(plan_json)
if python_plan != cli_plan:
    fail(f"Python SDK exec plan JSON differed from CLI dry-run\nCLI={cli_plan!r}\nPython={python_plan!r}")
assert_no_secret_text(json.dumps(python_plan, sort_keys=True), "Python SDK exec plan")

if sdk.redaction_class_name(RedactionFieldClass.SECRET_VALUE) != "secret_value":
    fail("Python SDK redaction class name mismatch")
if sdk.redaction_policy_name(RedactionFieldClass.SECRET_VALUE) != "redact":
    fail("Python SDK redaction policy mismatch")
if sdk.redaction_display_label(RedactionFieldClass.SECRET_VALUE) != "secret value":
    fail("Python SDK redaction display label mismatch")
if sdk.redaction_value_allowed(RedactionFieldClass.SECRET_VALUE):
    fail("Python SDK redaction should not allow secret values")
classification = sdk.describe_redaction_class(RedactionFieldClass.SECRET_DERIVED_IDENTIFIER)
if (
    classification.field_class != RedactionFieldClass.SECRET_DERIVED_IDENTIFIER
    or classification.class_name != "secret_derived_identifier"
    or classification.policy_name != "label-only"
    or not classification.value_allowed
):
    fail(f"Python SDK redaction classification mismatch: {classification!r}")
field_classification = sdk.classify_exec_json_field("injected_keys.key")
if field_classification.field_class != RedactionFieldClass.SECRET_DERIVED_IDENTIFIER:
    fail(f"Python SDK exec JSON field classification mismatch: {field_classification!r}")
try:
    sdk.classify_exec_json_field("unknown.field")
except SecdatError:
    pass
else:
    fail("Python SDK unknown exec JSON field should fail closed")
invalid_plan_json = call_with_c_stderr_suppressed(
    lambda: sdk.exec_plan_json(
        ["env"],
        dir=root,
        store="team",
        inject_rules=["secret:require=MISSING_SDK_TOKEN"],
        command_resolution="direct",
    )
)
invalid_plan = json.loads(invalid_plan_json)
missing_required = invalid_plan.get("supply", {}).get("secret", {}).get("missing_required", [])
if invalid_plan.get("ok") is not False or "MISSING_SDK_TOKEN" not in missing_required:
    fail(f"Python SDK invalid exec plan did not return failure JSON: {invalid_plan!r}")
assert_no_secret_text(json.dumps(invalid_plan, sort_keys=True), "Python SDK invalid exec plan")
for text in [
    classification.class_name,
    classification.policy_name,
    classification.display_label,
    field_classification.class_name,
    field_classification.policy_name,
    field_classification.display_label,
]:
    assert_no_secret_text(text, "Python SDK redaction metadata")

api_keyref = f"{root}/API_TOKEN:team"
bulk_keyref = f"{root}/BULK_TOKEN:team"
consumer_keyref = f"{refresh_domain}/CONSUMER_TOKEN:default"
long_primary_keyref = f"{root}/LONG_PRIMARY:team"
long_secondary_keyref = f"{root}/LONG_SECONDARY:team"

refreshes = sdk.relation_suggest_refresh("API_TOKEN", dir=root, store="team")
if len(refreshes) != 4:
    fail(f"Python SDK relation refresh count mismatch: {refreshes!r}")
for item in refreshes:
    assert_no_secret_text(json.dumps(vars(item), sort_keys=True), "Python SDK relation refresh")
if find_refresh_suggestion(refreshes, "sdk-refresh", "token", "token", api_keyref, "leaked-secret-member") is None:
    fail("missing Python SDK self refresh suggestion")
if find_refresh_suggestion(refreshes, "sdk-refresh", "token", "bulk_token", bulk_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK local related refresh suggestion")
if find_refresh_suggestion(refreshes, "sdk-cross-refresh", "token", "token", api_keyref, "leaked-secret-member") is None:
    fail("missing Python SDK cross-domain leaked member suggestion")
if find_refresh_suggestion(refreshes, "sdk-cross-refresh", "token", "refresh_token", consumer_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK cross-domain refresh target suggestion")

public_refreshes = sdk.relation_suggest_refresh("PUBLIC_URL", dir=root, store="team")
if public_refreshes:
    fail(f"Python SDK public role should not produce refresh suggestions: {public_refreshes!r}")

long_refreshes = sdk.relation_suggest_refresh("LONG_PRIMARY", dir=root, store="team")
if len(long_refreshes) != 2:
    fail(f"Python SDK long role refresh count mismatch: {long_refreshes!r}")
if find_refresh_suggestion(long_refreshes, "sdk-long-refresh", long_role, long_role, long_primary_keyref, "leaked-relation-member") is None:
    fail("missing Python SDK long role self suggestion")
if find_refresh_suggestion(long_refreshes, "sdk-long-refresh", long_role, "secondary", long_secondary_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK long role related suggestion")
for item in long_refreshes:
    assert_no_secret_text(json.dumps(vars(item), sort_keys=True), "Python SDK long relation refresh")
PY

printf 'PASS SDK exec plan regression\n'
