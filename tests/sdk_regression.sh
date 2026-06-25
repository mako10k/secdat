#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

repo_root="$(cd "$(dirname "$bin_path")/.." && pwd)"
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
mkdir -p "$root_domain" "$child_domain" "$orphaned_child_domain"

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
run_secdat --dir "$root_domain" store create team
run_secdat --dir "$root_domain" --store team set API_TOKEN --value sdk-secret-value
run_secdat --dir "$root_domain" --store team set PUBLIC_URL --unsafe --value public-secret-value
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
    return strstr(value, "sdk-secret-value") != NULL || strstr(value, "public-secret-value") != NULL;
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
        || string_has_secret(item->sandbox_inject)) {
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

int main(int argc, char **argv)
{
    const char *root;
    const char *child;
    const char *orphaned_child;
    struct secdat_sdk_options root_options = {0};
    struct secdat_sdk_options child_options = {0};
    struct secdat_sdk_list_filters public_filter = {0};
    struct secdat_sdk_domain_filters domain_filters = {0};
    struct secdat_sdk_key_metadata_list keys = {0};
    struct secdat_sdk_key_metadata_list public_keys = {0};
    struct secdat_sdk_key_metadata_list child_keys = {0};
    struct secdat_sdk_store_metadata_list stores = {0};
    struct secdat_sdk_domain_metadata_list domains = {0};
    const struct secdat_sdk_key_metadata *api_token;
    const struct secdat_sdk_key_metadata *public_url;
    const struct secdat_sdk_domain_metadata *orphaned_domain;
    size_t index;

    if (argc != 4) {
        fail("expected root, child, and orphaned child paths");
    }
    root = argv[1];
    child = argv[2];
    orphaned_child = argv[3];
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
    if (api_token == NULL || public_url == NULL) {
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
    secdat_sdk_free(keys.items);

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

cc -I"$repo_root/src" "$work_root/sdk_harness.c" \
    -L"$repo_root/src/.libs" -lsecdat -lssl -lcrypto \
    -Wl,-rpath,"$repo_root/src/.libs" \
    -o "$work_root/sdk_harness"

"$work_root/sdk_harness" "$root_domain" "$child_domain" "$orphaned_child_domain"
