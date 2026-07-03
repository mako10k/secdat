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

cat >"$work_root/redaction_harness.c" <<'C'
#include "redaction.h"
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void assert_string(const char *actual, const char *expected, const char *label)
{
    if (actual == NULL || strcmp(actual, expected) != 0) {
        fprintf(stderr, "FAIL: %s: expected %s, got %s\n", label, expected, actual == NULL ? "(null)" : actual);
        exit(1);
    }
}

static void assert_no_secret_hint(const char *value, const char *sample_secret, const char *sample_length)
{
    if (value == NULL) {
        fail("redaction helper returned null text");
    }
    if (strstr(value, sample_secret) != NULL || strstr(value, sample_length) != NULL) {
        fail("redaction helper exposed a secret value or plaintext length");
    }
}

static void assert_sdk_classification(
    const struct secdat_sdk_redaction_classification *classification,
    enum secdat_sdk_redaction_field_class expected_class,
    const char *expected_class_name,
    const char *expected_policy_name,
    int expected_value_allowed,
    const char *label
)
{
    if (classification->field_class != expected_class) {
        fprintf(stderr, "FAIL: %s: unexpected class id\n", label);
        exit(1);
    }
    assert_string(classification->class_name, expected_class_name, label);
    assert_string(classification->policy_name, expected_policy_name, label);
    if (classification->value_allowed != expected_value_allowed) {
        fprintf(stderr, "FAIL: %s: unexpected value_allowed\n", label);
        exit(1);
    }
}

int main(void)
{
    const char *sample_secret = "redaction-secret-sentinel";
    const char *sample_length = "25";
    static const struct secdat_redaction_field_rule rules[] = {
        {"secret.payload", SECDAT_REDACTION_SECRET_VALUE},
        {"secret.id", SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER},
        {"metadata.owner", SECDAT_REDACTION_NON_SECRET_METADATA},
        {"argv", SECDAT_REDACTION_COMMAND_ARGV},
        {"domain", SECDAT_REDACTION_PATH_DOMAIN_LABEL},
        {"message", SECDAT_REDACTION_PUBLIC_TEXT},
        {NULL, SECDAT_REDACTION_PUBLIC_TEXT},
    };
    const struct secdat_redaction_field_rule *rule;
    enum secdat_redaction_field_class classes[] = {
        SECDAT_REDACTION_SECRET_VALUE,
        SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER,
        SECDAT_REDACTION_NON_SECRET_METADATA,
        SECDAT_REDACTION_COMMAND_ARGV,
        SECDAT_REDACTION_PATH_DOMAIN_LABEL,
        SECDAT_REDACTION_PUBLIC_TEXT,
    };
    enum secdat_sdk_redaction_field_class sdk_classes[] = {
        SECDAT_SDK_REDACTION_SECRET_VALUE,
        SECDAT_SDK_REDACTION_SECRET_DERIVED_IDENTIFIER,
        SECDAT_SDK_REDACTION_NON_SECRET_METADATA,
        SECDAT_SDK_REDACTION_COMMAND_ARGV,
        SECDAT_SDK_REDACTION_PATH_DOMAIN_LABEL,
        SECDAT_SDK_REDACTION_PUBLIC_TEXT,
    };
    struct secdat_sdk_redaction_classification classification = {0};
    size_t index;

    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_SECRET_VALUE), "secret_value", "secret class");
    assert_string(secdat_redaction_policy_name(SECDAT_REDACTION_SECRET_VALUE), "redact", "secret policy");
    assert_string(secdat_redaction_display_label(SECDAT_REDACTION_SECRET_VALUE), "secret value", "secret label");
    if (secdat_redaction_value_allowed(SECDAT_REDACTION_SECRET_VALUE)) {
        fail("secret values should not be display-allowed");
    }

    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER), "secret_derived_identifier", "identifier class");
    assert_string(secdat_redaction_policy_name(SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER), "label-only", "identifier policy");
    if (!secdat_redaction_value_allowed(SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER)) {
        fail("secret-derived identifiers should be label-allowed");
    }

    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_NON_SECRET_METADATA), "non_secret_metadata", "metadata class");
    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_COMMAND_ARGV), "command_argv", "argv class");
    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_PATH_DOMAIN_LABEL), "path_domain_label", "path class");
    assert_string(secdat_redaction_class_name(SECDAT_REDACTION_PUBLIC_TEXT), "public_text", "public class");

    for (index = 0; index < sizeof(classes) / sizeof(classes[0]); index += 1) {
        assert_no_secret_hint(secdat_redaction_class_name(classes[index]), sample_secret, sample_length);
        assert_no_secret_hint(secdat_redaction_policy_name(classes[index]), sample_secret, sample_length);
        assert_no_secret_hint(secdat_redaction_display_label(classes[index]), sample_secret, sample_length);
    }
    for (index = 0; index < sizeof(sdk_classes) / sizeof(sdk_classes[0]); index += 1) {
        assert_no_secret_hint(secdat_sdk_redaction_class_name(sdk_classes[index]), sample_secret, sample_length);
        assert_no_secret_hint(secdat_sdk_redaction_policy_name(sdk_classes[index]), sample_secret, sample_length);
        assert_no_secret_hint(secdat_sdk_redaction_display_label(sdk_classes[index]), sample_secret, sample_length);
    }
    if (secdat_sdk_redaction_class_name((enum secdat_sdk_redaction_field_class)999) != NULL
            || secdat_sdk_redaction_policy_name((enum secdat_sdk_redaction_field_class)999) != NULL
            || secdat_sdk_redaction_display_label((enum secdat_sdk_redaction_field_class)999) != NULL
            || secdat_sdk_redaction_value_allowed((enum secdat_sdk_redaction_field_class)999)
            || secdat_sdk_describe_redaction_class((enum secdat_sdk_redaction_field_class)999, &classification) == 0) {
        fail("invalid SDK redaction class should fail closed");
    }

    if (secdat_sdk_describe_redaction_class(SECDAT_SDK_REDACTION_SECRET_VALUE, &classification) != 0) {
        fail("SDK secret redaction classification failed");
    }
    assert_sdk_classification(
        &classification,
        SECDAT_SDK_REDACTION_SECRET_VALUE,
        "secret_value",
        "redact",
        0,
        "sdk secret classification"
    );
    assert_string(classification.display_label, "secret value", "sdk secret display label");

    if (secdat_sdk_classify_exec_json_field("injected_keys.key", &classification) != 0) {
        fail("SDK exec JSON key field classification failed");
    }
    assert_sdk_classification(
        &classification,
        SECDAT_SDK_REDACTION_SECRET_DERIVED_IDENTIFIER,
        "secret_derived_identifier",
        "label-only",
        1,
        "sdk exec key field classification"
    );
    if (secdat_sdk_classify_exec_json_field("domain", &classification) != 0) {
        fail("SDK exec JSON domain field classification failed");
    }
    assert_sdk_classification(
        &classification,
        SECDAT_SDK_REDACTION_PATH_DOMAIN_LABEL,
        "path_domain_label",
        "allow",
        1,
        "sdk exec domain field classification"
    );
    if (secdat_sdk_classify_exec_json_field("argv", &classification) != 0) {
        fail("SDK exec JSON argv field classification failed");
    }
    assert_sdk_classification(
        &classification,
        SECDAT_SDK_REDACTION_COMMAND_ARGV,
        "command_argv",
        "allow",
        1,
        "sdk exec argv field classification"
    );
    if (secdat_sdk_classify_exec_json_field("unknown.field", &classification) == 0
            || classification.class_name != NULL
            || classification.policy_name != NULL
            || classification.display_label != NULL
            || classification.value_allowed != 0) {
        fail("unknown SDK exec JSON field should fail closed");
    }

    rule = secdat_redaction_find_field_rule(rules, "secret.payload");
    if (rule == NULL || rule->field_class != SECDAT_REDACTION_SECRET_VALUE) {
        fail("secret payload rule lookup failed");
    }
    rule = secdat_redaction_find_field_rule(rules, "domain");
    if (rule == NULL || rule->field_class != SECDAT_REDACTION_PATH_DOMAIN_LABEL) {
        fail("domain rule lookup failed");
    }
    if (secdat_redaction_find_field_rule(rules, "missing") != NULL) {
        fail("missing rule lookup should return null");
    }

    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/redaction_harness.c" \
    -L"$build_root/src/.libs" -lsecdat -lssl -lcrypto \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/redaction_harness"

"$work_root/redaction_harness"

printf 'PASS redaction regression\n'
