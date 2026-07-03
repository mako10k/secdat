#ifndef SECDAT_REDACTION_H
#define SECDAT_REDACTION_H

enum secdat_redaction_field_class {
    SECDAT_REDACTION_SECRET_VALUE = 0,
    SECDAT_REDACTION_SECRET_DERIVED_IDENTIFIER,
    SECDAT_REDACTION_NON_SECRET_METADATA,
    SECDAT_REDACTION_COMMAND_ARGV,
    SECDAT_REDACTION_PATH_DOMAIN_LABEL,
    SECDAT_REDACTION_PUBLIC_TEXT,
};

struct secdat_redaction_field_rule {
    const char *field_path;
    enum secdat_redaction_field_class field_class;
};

const char *secdat_redaction_class_name(enum secdat_redaction_field_class field_class);
const char *secdat_redaction_policy_name(enum secdat_redaction_field_class field_class);
const char *secdat_redaction_display_label(enum secdat_redaction_field_class field_class);
int secdat_redaction_value_allowed(enum secdat_redaction_field_class field_class);
const struct secdat_redaction_field_rule *secdat_redaction_find_field_rule(
    const struct secdat_redaction_field_rule *rules,
    const char *field_path
);

#endif
