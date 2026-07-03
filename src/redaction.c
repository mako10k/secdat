#define _GNU_SOURCE

#include "redaction.h"
#include "secdat-sdk.h"

#include <stddef.h>
#include <string.h>

static int secdat_sdk_redaction_to_internal(
    enum secdat_sdk_redaction_field_class field_class,
    enum secdat_redaction_field_class *internal_out
)
{
    if (internal_out == NULL) {
        return 1;
    }
    switch (field_class) {
    case SECDAT_SDK_REDACTION_SECRET_VALUE:
        *internal_out = SECDAT_REDACTION_SECRET_VALUE;
        return 0;
    case SECDAT_SDK_REDACTION_SECRET_DERIVED_IDENTIFIER:
        *internal_out = SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER;
        return 0;
    case SECDAT_SDK_REDACTION_NON_SECRET_METADATA:
        *internal_out = SECDAT_REDACTION_NON_SECRET_METADATA;
        return 0;
    case SECDAT_SDK_REDACTION_COMMAND_ARGV:
        *internal_out = SECDAT_REDACTION_COMMAND_ARGV;
        return 0;
    case SECDAT_SDK_REDACTION_PATH_DOMAIN_LABEL:
        *internal_out = SECDAT_REDACTION_PATH_DOMAIN_LABEL;
        return 0;
    case SECDAT_SDK_REDACTION_PUBLIC_TEXT:
        *internal_out = SECDAT_REDACTION_PUBLIC_TEXT;
        return 0;
    default:
        return 1;
    }
}

const char *secdat_redaction_class_name(enum secdat_redaction_field_class field_class)
{
    switch (field_class) {
    case SECDAT_REDACTION_SECRET_VALUE:
        return "secret_value";
    case SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER:
        return "secret_derived_identifier";
    case SECDAT_REDACTION_NON_SECRET_METADATA:
        return "non_secret_metadata";
    case SECDAT_REDACTION_COMMAND_ARGV:
        return "command_argv";
    case SECDAT_REDACTION_PATH_DOMAIN_LABEL:
        return "path_domain_label";
    case SECDAT_REDACTION_PUBLIC_TEXT:
    default:
        return "public_text";
    }
}

const char *secdat_redaction_policy_name(enum secdat_redaction_field_class field_class)
{
    switch (field_class) {
    case SECDAT_REDACTION_SECRET_VALUE:
        return "redact";
    case SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER:
        return "label-only";
    case SECDAT_REDACTION_NON_SECRET_METADATA:
    case SECDAT_REDACTION_COMMAND_ARGV:
    case SECDAT_REDACTION_PATH_DOMAIN_LABEL:
    case SECDAT_REDACTION_PUBLIC_TEXT:
    default:
        return "allow";
    }
}

const char *secdat_redaction_display_label(enum secdat_redaction_field_class field_class)
{
    switch (field_class) {
    case SECDAT_REDACTION_SECRET_VALUE:
        return "secret value";
    case SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER:
        return "secret-derived identifier";
    case SECDAT_REDACTION_NON_SECRET_METADATA:
        return "non-secret metadata";
    case SECDAT_REDACTION_COMMAND_ARGV:
        return "command argv";
    case SECDAT_REDACTION_PATH_DOMAIN_LABEL:
        return "path/domain label";
    case SECDAT_REDACTION_PUBLIC_TEXT:
    default:
        return "public text";
    }
}

int secdat_redaction_value_allowed(enum secdat_redaction_field_class field_class)
{
    return field_class != SECDAT_REDACTION_SECRET_VALUE;
}

const struct secdat_redaction_field_rule *secdat_redaction_find_field_rule(
    const struct secdat_redaction_field_rule *rules,
    const char *field_path
)
{
    size_t index;

    if (rules == NULL || field_path == NULL) {
        return NULL;
    }
    for (index = 0; rules[index].field_path != NULL; index += 1) {
        if (strcmp(rules[index].field_path, field_path) == 0) {
            return &rules[index];
        }
    }
    return NULL;
}

const char *secdat_sdk_redaction_class_name(enum secdat_sdk_redaction_field_class field_class)
{
    enum secdat_redaction_field_class internal;

    if (secdat_sdk_redaction_to_internal(field_class, &internal) != 0) {
        return NULL;
    }
    return secdat_redaction_class_name(internal);
}

const char *secdat_sdk_redaction_policy_name(enum secdat_sdk_redaction_field_class field_class)
{
    enum secdat_redaction_field_class internal;

    if (secdat_sdk_redaction_to_internal(field_class, &internal) != 0) {
        return NULL;
    }
    return secdat_redaction_policy_name(internal);
}

const char *secdat_sdk_redaction_display_label(enum secdat_sdk_redaction_field_class field_class)
{
    enum secdat_redaction_field_class internal;

    if (secdat_sdk_redaction_to_internal(field_class, &internal) != 0) {
        return NULL;
    }
    return secdat_redaction_display_label(internal);
}

int secdat_sdk_redaction_value_allowed(enum secdat_sdk_redaction_field_class field_class)
{
    enum secdat_redaction_field_class internal;

    if (secdat_sdk_redaction_to_internal(field_class, &internal) != 0) {
        return 0;
    }
    return secdat_redaction_value_allowed(internal);
}

int secdat_sdk_describe_redaction_class(
    enum secdat_sdk_redaction_field_class field_class,
    struct secdat_sdk_redaction_classification *classification_out
)
{
    if (classification_out == NULL) {
        return 1;
    }
    classification_out->field_class = field_class;
    classification_out->class_name = secdat_sdk_redaction_class_name(field_class);
    classification_out->policy_name = secdat_sdk_redaction_policy_name(field_class);
    classification_out->display_label = secdat_sdk_redaction_display_label(field_class);
    classification_out->value_allowed = secdat_sdk_redaction_value_allowed(field_class);
    if (classification_out->class_name == NULL
            || classification_out->policy_name == NULL
            || classification_out->display_label == NULL) {
        memset(classification_out, 0, sizeof(*classification_out));
        return 1;
    }
    return 0;
}
