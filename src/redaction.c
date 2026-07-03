#define _GNU_SOURCE

#include "redaction.h"

#include <stddef.h>
#include <string.h>

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
