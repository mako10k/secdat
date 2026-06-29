#define _GNU_SOURCE

#include "exec_inject.h"

#include "domain.h"
#include "i18n.h"
#include "json_util.h"
#include "store.h"
#include "store_exec_port.h"

#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

struct secdat_exec_inject_policy;

int secdat_exec_apply_inject_policy_file(struct secdat_exec_inject_policy *policy, const char *path);

struct secdat_exec_selector_list {
    char **items;
    size_t count;
};

struct secdat_exec_pentad {
    struct secdat_exec_selector_list only;
    struct secdat_exec_selector_list omit;
    struct secdat_exec_selector_list require;
    struct secdat_exec_selector_list reject;
};

enum secdat_exec_route_pick {
    SECDAT_EXEC_ROUTE_SECRET = 0,
    SECDAT_EXEC_ROUTE_AMBIENT,
    SECDAT_EXEC_ROUTE_ERROR,
};

enum secdat_exec_command_resolution {
    SECDAT_EXEC_COMMAND_RESOLUTION_CALLER_PATH = 0,
    SECDAT_EXEC_COMMAND_RESOLUTION_CHILD_PATH,
    SECDAT_EXEC_COMMAND_RESOLUTION_DIRECT,
};

struct secdat_exec_route_rule {
    char *match;
    enum secdat_exec_route_pick pick;
    int from_cli;
};

struct secdat_exec_secret_rename {
    regex_t address_regex;
    regex_t match_regex;
    char *replacement;
    int configured;
    int has_address;
};

struct secdat_exec_inject_policy {
    struct secdat_exec_pentad ambient;
    struct secdat_exec_pentad secret;
    struct secdat_exec_secret_rename secret_rename;
    enum secdat_exec_route_pick route_prefer;
    struct secdat_exec_route_rule *route_rules;
    size_t route_rule_count;
    struct secdat_exec_pentad final;
    int bulk_gate;
    int explicit_bulk_gate;
    int explicit_secret_only;
    int explicit_secret_omit;
    int explicit_secret_require;
    int explicit_secret_reject;
    int explicit_secret_rename;
    int explicit_ambient_only;
    int explicit_ambient_omit;
    int explicit_ambient_require;
    int explicit_ambient_reject;
    int explicit_final_only;
    int explicit_final_omit;
    int explicit_final_require;
    int explicit_final_reject;
    int explicit_route_prefer;
};

struct secdat_exec_options {
    struct secdat_exec_inject_policy policy;
    int dry_run;
    int json;
    int json_summary;
    enum secdat_exec_command_resolution command_resolution;
    size_t command_index;
};

enum secdat_exec_value_source {
    SECDAT_EXEC_VALUE_AMBIENT = 0,
    SECDAT_EXEC_VALUE_SECRET,
};

enum secdat_exec_pentad_layer {
    SECDAT_EXEC_PENTAD_AMBIENT = 0,
    SECDAT_EXEC_PENTAD_SECRET,
    SECDAT_EXEC_PENTAD_FINAL,
};

struct secdat_exec_plan_entry {
    char *env_name;
    char *secret_key;
    enum secdat_exec_value_source value_source;
};

struct secdat_exec_collision {
    char *name;
    enum secdat_exec_route_pick picked;
};

struct secdat_exec_plan {
    struct secdat_exec_plan_entry *final_entries;
    size_t final_count;
    struct secdat_exec_collision *collisions;
    size_t collision_count;
    char **ambient_contributed;
    size_t ambient_contributed_count;
    char **secret_contributed;
    size_t secret_contributed_count;
    char **secret_contributed_env_names;
    size_t secret_contributed_env_names_count;
    char **missing_secret_required;
    size_t missing_secret_required_count;
    char **missing_ambient_required;
    size_t missing_ambient_required_count;
    char **rejected_secret_present;
    size_t rejected_secret_present_count;
    char **rejected_ambient_present;
    size_t rejected_ambient_present_count;
    char **missing_final_required;
    size_t missing_final_required_count;
    char **rejected_final_present;
    size_t rejected_final_present_count;
    int ambient_mode_only;
    int secret_mode_only;
    int final_mode_only;
};

static void secdat_exec_selector_list_free(struct secdat_exec_selector_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->count; index += 1) {
        free(list->items[index]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static void secdat_exec_pentad_free(struct secdat_exec_pentad *pentad)
{
    if (pentad == NULL) {
        return;
    }
    secdat_exec_selector_list_free(&pentad->only);
    secdat_exec_selector_list_free(&pentad->omit);
    secdat_exec_selector_list_free(&pentad->require);
    secdat_exec_selector_list_free(&pentad->reject);
}

static void secdat_exec_secret_rename_free(struct secdat_exec_secret_rename *rename)
{
    if (rename == NULL) {
        return;
    }
    if (rename->configured) {
        regfree(&rename->match_regex);
        if (rename->has_address) {
            regfree(&rename->address_regex);
        }
    }
    free(rename->replacement);
    memset(rename, 0, sizeof(*rename));
}

static void secdat_exec_policy_free(struct secdat_exec_inject_policy *policy)
{
    size_t index;

    if (policy == NULL) {
        return;
    }
    secdat_exec_pentad_free(&policy->ambient);
    secdat_exec_pentad_free(&policy->secret);
    secdat_exec_secret_rename_free(&policy->secret_rename);
    for (index = 0; index < policy->route_rule_count; index += 1) {
        free(policy->route_rules[index].match);
    }
    free(policy->route_rules);
    secdat_exec_pentad_free(&policy->final);
    memset(policy, 0, sizeof(*policy));
}

static void secdat_exec_options_free(struct secdat_exec_options *options)
{
    if (options == NULL) {
        return;
    }
    secdat_exec_policy_free(&options->policy);
    memset(options, 0, sizeof(*options));
}

static void secdat_exec_string_list_free(char **items, size_t count)
{
    size_t index;

    for (index = 0; index < count; index += 1) {
        free(items[index]);
    }
    free(items);
}

static void secdat_exec_plan_free(struct secdat_exec_plan *plan)
{
    size_t index;

    if (plan == NULL) {
        return;
    }
    for (index = 0; index < plan->final_count; index += 1) {
        free(plan->final_entries[index].env_name);
        free(plan->final_entries[index].secret_key);
    }
    free(plan->final_entries);
    for (index = 0; index < plan->collision_count; index += 1) {
        free(plan->collisions[index].name);
    }
    free(plan->collisions);
    secdat_exec_string_list_free(plan->ambient_contributed, plan->ambient_contributed_count);
    secdat_exec_string_list_free(plan->secret_contributed, plan->secret_contributed_count);
    secdat_exec_string_list_free(plan->secret_contributed_env_names, plan->secret_contributed_env_names_count);
    secdat_exec_string_list_free(plan->missing_secret_required, plan->missing_secret_required_count);
    secdat_exec_string_list_free(plan->missing_ambient_required, plan->missing_ambient_required_count);
    secdat_exec_string_list_free(plan->rejected_secret_present, plan->rejected_secret_present_count);
    secdat_exec_string_list_free(plan->rejected_ambient_present, plan->rejected_ambient_present_count);
    secdat_exec_string_list_free(plan->missing_final_required, plan->missing_final_required_count);
    secdat_exec_string_list_free(plan->rejected_final_present, plan->rejected_final_present_count);
    memset(plan, 0, sizeof(*plan));
}

static int secdat_exec_selector_list_append(struct secdat_exec_selector_list *list, const char *value)
{
    char **items;
    char *copy;
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index], value) == 0) {
            return 0;
        }
    }
    copy = strdup(value);
    if (copy == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    items = realloc(list->items, (list->count + 1) * sizeof(*items));
    if (items == NULL) {
        free(copy);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    list->items = items;
    list->items[list->count] = copy;
    list->count += 1;
    return 0;
}

static int secdat_exec_string_list_append(char ***items_out, size_t *count_out, const char *value)
{
    char **items;
    char *copy;

    copy = strdup(value);
    if (copy == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    items = realloc(*items_out, (*count_out + 1) * sizeof(*items));
    if (items == NULL) {
        free(copy);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    *items_out = items;
    items[*count_out] = copy;
    *count_out += 1;
    return 0;
}

static int secdat_exec_selector_matches(const char *selector, const char *value)
{
    if (strchr(selector, '*') != NULL || strchr(selector, '?') != NULL || strchr(selector, '[') != NULL) {
        return fnmatch(selector, value, 0) == 0;
    }
    return strcmp(selector, value) == 0;
}

static int secdat_exec_selector_list_matches(const struct secdat_exec_selector_list *list, const char *value)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (secdat_exec_selector_matches(list->items[index], value)) {
            return 1;
        }
    }
    return 0;
}

static int secdat_exec_selector_matches_primary_or_alternate(
    const char *selector,
    const char *primary,
    const char *alternate
)
{
    if (secdat_exec_selector_matches(selector, primary)) {
        return 1;
    }
    if (alternate != NULL && secdat_exec_selector_matches(selector, alternate)) {
        return 1;
    }
    return 0;
}

static int secdat_exec_selector_list_matches_primary_or_alternate(
    const struct secdat_exec_selector_list *list,
    const char *primary,
    const char *alternate
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (secdat_exec_selector_matches_primary_or_alternate(list->items[index], primary, alternate)) {
            return 1;
        }
    }
    return 0;
}

static const char *secdat_exec_pentad_layer_name(enum secdat_exec_pentad_layer layer)
{
    switch (layer) {
    case SECDAT_EXEC_PENTAD_AMBIENT:
        return "ambient";
    case SECDAT_EXEC_PENTAD_SECRET:
        return "secret";
    case SECDAT_EXEC_PENTAD_FINAL:
    default:
        return "final";
    }
}

static void secdat_exec_print_reject_present(enum secdat_exec_pentad_layer layer, const char *name)
{
    switch (layer) {
    case SECDAT_EXEC_PENTAD_AMBIENT:
        fprintf(stderr, _("exec inject ambient variable must not be present: %s\n"), name);
        return;
    case SECDAT_EXEC_PENTAD_SECRET:
    default:
        fprintf(stderr, _("exec inject secret key must not be present: %s\n"), name);
        return;
    }
}

static void secdat_exec_print_required_missing(enum secdat_exec_pentad_layer layer, const char *name)
{
    switch (layer) {
    case SECDAT_EXEC_PENTAD_AMBIENT:
        fprintf(stderr, _("exec inject required ambient variable not available: %s\n"), name);
        return;
    case SECDAT_EXEC_PENTAD_SECRET:
    default:
        fprintf(stderr, _("exec inject required secret key not available for injection: %s\n"), name);
        return;
    }
}

static int secdat_exec_pentad_conflicts(
    const struct secdat_exec_pentad *pentad,
    enum secdat_exec_pentad_layer layer
)
{
    size_t require_index;
    size_t other_index;
    const char *layer_name = secdat_exec_pentad_layer_name(layer);

    for (require_index = 0; require_index < pentad->require.count; require_index += 1) {
        const char *required = pentad->require.items[require_index];

        if (secdat_exec_selector_list_matches(&pentad->omit, required)) {
            fprintf(stderr, _("exec inject %s pentad conflict: require and omit overlap: %s\n"), layer_name, required);
            return 1;
        }
        if (secdat_exec_selector_list_matches(&pentad->reject, required)) {
            fprintf(stderr, _("exec inject %s pentad conflict: require and reject overlap: %s\n"), layer_name, required);
            return 1;
        }
    }
    for (other_index = 0; other_index < pentad->omit.count; other_index += 1) {
        const char *omitted = pentad->omit.items[other_index];

        if (secdat_exec_selector_list_matches(&pentad->reject, omitted)) {
            fprintf(stderr, _("exec inject %s pentad conflict: omit and reject overlap: %s\n"), layer_name, omitted);
            return 1;
        }
    }
    return 0;
}

static int secdat_exec_is_valid_env_name(const char *value)
{
    size_t index;

    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (!(isalpha((unsigned char)value[0]) || value[0] == '_')) {
        return 0;
    }
    for (index = 1; value[index] != '\0'; index += 1) {
        if (!(isalnum((unsigned char)value[index]) || value[index] == '_')) {
            return 0;
        }
    }
    return 1;
}

static int secdat_exec_parse_route_pick(const char *value, enum secdat_exec_route_pick *pick_out)
{
    if (strcmp(value, "secret") == 0) {
        *pick_out = SECDAT_EXEC_ROUTE_SECRET;
        return 0;
    }
    if (strcmp(value, "ambient") == 0) {
        *pick_out = SECDAT_EXEC_ROUTE_AMBIENT;
        return 0;
    }
    if (strcmp(value, "error") == 0) {
        *pick_out = SECDAT_EXEC_ROUTE_ERROR;
        return 0;
    }
    fprintf(stderr, _("invalid route pick: %s\n"), value);
    return 2;
}

static const char *secdat_exec_route_pick_name(enum secdat_exec_route_pick pick)
{
    switch (pick) {
    case SECDAT_EXEC_ROUTE_AMBIENT:
        return "ambient";
    case SECDAT_EXEC_ROUTE_ERROR:
        return "error";
    case SECDAT_EXEC_ROUTE_SECRET:
    default:
        return "secret";
    }
}

static int secdat_exec_parse_command_resolution(
    const char *value,
    enum secdat_exec_command_resolution *resolution_out
)
{
    if (strcmp(value, "caller-path") == 0) {
        *resolution_out = SECDAT_EXEC_COMMAND_RESOLUTION_CALLER_PATH;
        return 0;
    }
    if (strcmp(value, "child-path") == 0) {
        *resolution_out = SECDAT_EXEC_COMMAND_RESOLUTION_CHILD_PATH;
        return 0;
    }
    if (strcmp(value, "direct") == 0) {
        *resolution_out = SECDAT_EXEC_COMMAND_RESOLUTION_DIRECT;
        return 0;
    }
    fprintf(stderr, _("invalid command resolution: %s\n"), value);
    return 2;
}

static int secdat_exec_parse_rename_expression(const char *expression, struct secdat_exec_secret_rename *rename)
{
    const char *cursor = expression;
    const char *segment_start;
    char *address_pattern = NULL;
    char *match_pattern = NULL;
    char *replacement = NULL;
    char regex_error[256];
    size_t length;
    char delimiter;
    int reg_status;

    if (rename->configured) {
        fprintf(stderr, _("secret rename may be specified at most once\n"));
        return 2;
    }

    if (*cursor == '/') {
        const char *address_end = cursor + 1;

        while (*address_end != '\0') {
            size_t backslash_count = 0;
            const char *backtrack = address_end;

            if (*address_end == '/') {
                while (backtrack > cursor + 1 && backtrack[-1] == '\\') {
                    backslash_count += 1;
                    backtrack -= 1;
                }
                if ((backslash_count % 2) == 0) {
                    break;
                }
            }
            address_end += 1;
        }
        if (*address_end != '/') {
            fprintf(stderr, _("invalid secret rename expression\n"));
            return 2;
        }
        length = (size_t)(address_end - (cursor + 1));
        address_pattern = malloc(length + 1);
        if (address_pattern == NULL) {
            return 1;
        }
        memcpy(address_pattern, cursor + 1, length);
        address_pattern[length] = '\0';
        reg_status = regcomp(&rename->address_regex, address_pattern, 0);
        if (reg_status != 0) {
            regerror(reg_status, &rename->address_regex, regex_error, sizeof(regex_error));
            fprintf(stderr, _("invalid secret rename regex: %s\n"), regex_error);
            free(address_pattern);
            return 2;
        }
        rename->has_address = 1;
        free(address_pattern);
        cursor = address_end + 1;
    }

    if (*cursor != 's') {
        fprintf(stderr, _("invalid secret rename expression\n"));
        return 2;
    }
    cursor += 1;
    delimiter = *cursor;
    if (delimiter == '\0' || delimiter == '\\' || isalnum((unsigned char)delimiter)) {
        fprintf(stderr, _("invalid secret rename expression\n"));
        return 2;
    }

    segment_start = cursor + 1;
    while (*cursor != '\0') {
        size_t backslash_count = 0;
        const char *backtrack;

        cursor += 1;
        if (*cursor == '\0') {
            break;
        }
        if (*cursor != delimiter) {
            continue;
        }
        backtrack = cursor;
        while (backtrack > segment_start && backtrack[-1] == '\\') {
            backslash_count += 1;
            backtrack -= 1;
        }
        if ((backslash_count % 2) == 0) {
            break;
        }
    }
    if (*cursor != delimiter) {
        fprintf(stderr, _("invalid secret rename expression\n"));
        return 2;
    }
    length = (size_t)(cursor - segment_start);
    match_pattern = malloc(length + 1);
    if (match_pattern == NULL) {
        return 1;
    }
    memcpy(match_pattern, segment_start, length);
    match_pattern[length] = '\0';

    segment_start = cursor + 1;
    while (*cursor != '\0') {
        size_t backslash_count = 0;
        const char *backtrack;

        cursor += 1;
        if (*cursor == '\0') {
            break;
        }
        if (*cursor != delimiter) {
            continue;
        }
        backtrack = cursor;
        while (backtrack > segment_start && backtrack[-1] == '\\') {
            backslash_count += 1;
            backtrack -= 1;
        }
        if ((backslash_count % 2) == 0) {
            break;
        }
    }
    if (*cursor != delimiter || cursor[1] != '\0') {
        free(match_pattern);
        fprintf(stderr, _("invalid secret rename expression\n"));
        return 2;
    }
    length = (size_t)(cursor - segment_start);
    replacement = malloc(length + 1);
    if (replacement == NULL) {
        free(match_pattern);
        return 1;
    }
    memcpy(replacement, segment_start, length);
    replacement[length] = '\0';

    reg_status = regcomp(&rename->match_regex, match_pattern, 0);
    free(match_pattern);
    if (reg_status != 0) {
        regerror(reg_status, &rename->match_regex, regex_error, sizeof(regex_error));
        fprintf(stderr, _("invalid secret rename regex: %s\n"), regex_error);
        free(replacement);
        return 2;
    }

    rename->replacement = replacement;
    rename->configured = 1;
    return 0;
}

static int secdat_exec_env_name_identity(const char *key, char **env_name_out)
{
    char *env_name;

    *env_name_out = NULL;
    if (!secdat_exec_is_valid_env_name(key)) {
        fprintf(stderr, _("key is not a valid environment variable name: %s\n"), key);
        return 1;
    }
    env_name = strdup(key);
    if (env_name == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    *env_name_out = env_name;
    return 0;
}

static int secdat_exec_env_name_from_key(
    const struct secdat_exec_secret_rename *rename,
    const char *key,
    char **env_name_out
)
{
    regmatch_t matches[10];
    char *env_name;
    size_t total_length = 0;
    size_t replacement_index;
    int reg_status;

    *env_name_out = NULL;

    if (!rename->configured) {
        return secdat_exec_env_name_identity(key, env_name_out);
    }

    if (rename->has_address) {
        reg_status = regexec(&rename->address_regex, key, 0, NULL, 0);
        if (reg_status == REG_NOMATCH) {
            return secdat_exec_env_name_identity(key, env_name_out);
        }
        if (reg_status != 0) {
            fprintf(stderr, _("failed to match secret rename against key: %s\n"), key);
            return 1;
        }
    }

    reg_status = regexec(&rename->match_regex, key, (int)(sizeof(matches) / sizeof(matches[0])), matches, 0);
    if (reg_status == REG_NOMATCH) {
        return secdat_exec_env_name_identity(key, env_name_out);
    }
    if (reg_status != 0) {
        fprintf(stderr, _("failed to match secret rename against key: %s\n"), key);
        return 1;
    }

    for (replacement_index = 0; rename->replacement[replacement_index] != '\0'; replacement_index += 1) {
        char current = rename->replacement[replacement_index];

        if (current == '&') {
            total_length += (size_t)(matches[0].rm_eo - matches[0].rm_so);
            continue;
        }
        if (current == '\\' && isdigit((unsigned char)rename->replacement[replacement_index + 1])) {
            int capture_index = rename->replacement[replacement_index + 1] - '0';

            if (capture_index < (int)(sizeof(matches) / sizeof(matches[0])) && matches[capture_index].rm_so >= 0) {
                total_length += (size_t)(matches[capture_index].rm_eo - matches[capture_index].rm_so);
            }
            replacement_index += 1;
            continue;
        }
        if (current == '\\' && rename->replacement[replacement_index + 1] != '\0') {
            replacement_index += 1;
        }
        total_length += 1;
    }

    env_name = malloc(total_length + 1);
    if (env_name == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    total_length = 0;
    for (replacement_index = 0; rename->replacement[replacement_index] != '\0'; replacement_index += 1) {
        char current = rename->replacement[replacement_index];

        if (current == '&') {
            size_t capture_length = (size_t)(matches[0].rm_eo - matches[0].rm_so);

            memcpy(env_name + total_length, key + matches[0].rm_so, capture_length);
            total_length += capture_length;
            continue;
        }
        if (current == '\\' && isdigit((unsigned char)rename->replacement[replacement_index + 1])) {
            int capture_index = rename->replacement[replacement_index + 1] - '0';

            if (capture_index < (int)(sizeof(matches) / sizeof(matches[0])) && matches[capture_index].rm_so >= 0) {
                size_t capture_length = (size_t)(matches[capture_index].rm_eo - matches[capture_index].rm_so);

                memcpy(env_name + total_length, key + matches[capture_index].rm_so, capture_length);
                total_length += capture_length;
            }
            replacement_index += 1;
            continue;
        }
        if (current == '\\' && rename->replacement[replacement_index + 1] != '\0') {
            replacement_index += 1;
            current = rename->replacement[replacement_index];
        }
        env_name[total_length] = current;
        total_length += 1;
    }
    env_name[total_length] = '\0';

    if (!secdat_exec_is_valid_env_name(env_name)) {
        fprintf(stderr, _("invalid environment variable name from secret rename: %s\n"), env_name);
        free(env_name);
        return 1;
    }

    *env_name_out = env_name;
    return 0;
}

static int secdat_exec_append_inject_selectors(
    struct secdat_exec_pentad *pentad,
    const char *kind,
    const char *selectors
)
{
    char *buffer;
    char *cursor;
    char *token;

    buffer = strdup(selectors);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    cursor = buffer;
    while ((token = strsep(&cursor, ":")) != NULL) {
        struct secdat_exec_selector_list *target = NULL;

        if (token[0] == '\0') {
            continue;
        }
        if (strcmp(kind, "only") == 0) {
            target = &pentad->only;
        } else if (strcmp(kind, "omit") == 0) {
            target = &pentad->omit;
        } else if (strcmp(kind, "require") == 0) {
            target = &pentad->require;
        } else if (strcmp(kind, "reject") == 0) {
            target = &pentad->reject;
        } else {
            fprintf(stderr, _("invalid exec inject kind: %s\n"), kind);
            free(buffer);
            return 2;
        }
        if (secdat_exec_selector_list_append(target, token) != 0) {
            free(buffer);
            return 1;
        }
    }

    free(buffer);
    return 0;
}

static struct secdat_exec_selector_list *secdat_exec_pentad_selector_list(
    struct secdat_exec_pentad *pentad,
    const char *kind
)
{
    if (strcmp(kind, "only") == 0) {
        return &pentad->only;
    }
    if (strcmp(kind, "omit") == 0) {
        return &pentad->omit;
    }
    if (strcmp(kind, "require") == 0) {
        return &pentad->require;
    }
    if (strcmp(kind, "reject") == 0) {
        return &pentad->reject;
    }
    return NULL;
}

static int *secdat_exec_pentad_explicit_flag(struct secdat_exec_inject_policy *policy, const char *layer, const char *kind)
{
    if (strcmp(layer, "ambient") == 0) {
        if (strcmp(kind, "only") == 0) {
            return &policy->explicit_ambient_only;
        }
        if (strcmp(kind, "omit") == 0) {
            return &policy->explicit_ambient_omit;
        }
        if (strcmp(kind, "require") == 0) {
            return &policy->explicit_ambient_require;
        }
        if (strcmp(kind, "reject") == 0) {
            return &policy->explicit_ambient_reject;
        }
    }
    if (strcmp(layer, "secret") == 0) {
        if (strcmp(kind, "only") == 0) {
            return &policy->explicit_secret_only;
        }
        if (strcmp(kind, "omit") == 0) {
            return &policy->explicit_secret_omit;
        }
        if (strcmp(kind, "require") == 0) {
            return &policy->explicit_secret_require;
        }
        if (strcmp(kind, "reject") == 0) {
            return &policy->explicit_secret_reject;
        }
    }
    if (strcmp(layer, "final") == 0) {
        if (strcmp(kind, "only") == 0) {
            return &policy->explicit_final_only;
        }
        if (strcmp(kind, "omit") == 0) {
            return &policy->explicit_final_omit;
        }
        if (strcmp(kind, "require") == 0) {
            return &policy->explicit_final_require;
        }
        if (strcmp(kind, "reject") == 0) {
            return &policy->explicit_final_reject;
        }
    }
    return NULL;
}

static void secdat_exec_prepare_cli_pentad_override(
    struct secdat_exec_inject_policy *policy,
    const char *layer,
    struct secdat_exec_pentad *pentad,
    const char *kind
)
{
    int *explicit_flag = secdat_exec_pentad_explicit_flag(policy, layer, kind);
    struct secdat_exec_selector_list *list = secdat_exec_pentad_selector_list(pentad, kind);

    if (explicit_flag != NULL && list != NULL && !*explicit_flag) {
        secdat_exec_selector_list_free(list);
        *explicit_flag = 1;
    }
}

static void secdat_exec_remove_file_route_rules(struct secdat_exec_inject_policy *policy, const char *match)
{
    size_t read_index;
    size_t write_index = 0;

    for (read_index = 0; read_index < policy->route_rule_count; read_index += 1) {
        if (!policy->route_rules[read_index].from_cli && strcmp(policy->route_rules[read_index].match, match) == 0) {
            free(policy->route_rules[read_index].match);
            continue;
        }
        if (write_index != read_index) {
            policy->route_rules[write_index] = policy->route_rules[read_index];
        }
        write_index += 1;
    }
    policy->route_rule_count = write_index;
}

static int secdat_exec_reject_removed_legacy_flag(const char *flag, const char *replacement)
{
    fprintf(stderr, _("exec: %s is no longer supported; use %s\n"), flag, replacement);
    return 2;
}

static int secdat_exec_enable_bulk_gate(struct secdat_exec_inject_policy *policy)
{
    if (policy->explicit_bulk_gate) {
        fprintf(stderr, _("--bulk-gate may be specified at most once\n"));
        return 2;
    }
    policy->explicit_bulk_gate = 1;
    policy->bulk_gate = 1;
    return 0;
}

int secdat_exec_apply_bulk_gate_yaml(struct secdat_exec_inject_policy *policy, const char *value)
{
    if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0) {
        return secdat_exec_enable_bulk_gate(policy);
    }
    if (strcmp(value, "bulk") == 0 || strcmp(value, "sandbox") == 0) {
        fprintf(stderr, _("gate: %s is no longer supported; use bulk_gate: true\n"), value);
        return 2;
    }
    fprintf(stderr, _("invalid bulk_gate value: %s; use bulk_gate: true\n"), value);
    return 2;
}

static int secdat_exec_reject_legacy_inject_gate(const char *value)
{
    if (value != NULL && strcmp(value, "sandbox") == 0) {
        fprintf(stderr, _("invalid --inject-gate value: %s; use --bulk-gate\n"), value);
        return 2;
    }
    fprintf(stderr, _("exec: --inject-gate is no longer supported; use --bulk-gate\n"));
    return 2;
}

int secdat_exec_apply_inject_token(struct secdat_exec_inject_policy *policy, const char *token, int from_cli)
{
    const char *separator = strchr(token, ':');
    char layer[32];
    char *rest;
    char *kind;
    char *value;
    size_t layer_length;

    if (separator == NULL) {
        fprintf(stderr, _("invalid --inject token: %s\n"), token);
        return 2;
    }

    layer_length = (size_t)(separator - token);
    if (layer_length >= sizeof(layer)) {
        fprintf(stderr, _("invalid --inject token: %s\n"), token);
        return 2;
    }
    memcpy(layer, token, layer_length);
    layer[layer_length] = '\0';
    rest = strdup(separator + 1);
    if (rest == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    kind = rest;
    value = strchr(kind, '=');
    if (value == NULL) {
        fprintf(stderr, _("invalid --inject token: %s\n"), token);
        free(rest);
        return 2;
    }
    *value = '\0';
    value += 1;
    if (value[0] == '\0') {
        fprintf(stderr, _("invalid --inject token: %s\n"), token);
        free(rest);
        return 2;
    }

    if (strcmp(layer, "ambient") == 0) {
        if (from_cli) {
            secdat_exec_prepare_cli_pentad_override(policy, layer, &policy->ambient, kind);
        }
        if (secdat_exec_append_inject_selectors(&policy->ambient, kind, value) != 0) {
            free(rest);
            return 1;
        }
        free(rest);
        return 0;
    }
    if (strcmp(layer, "secret") == 0) {
        if (strcmp(kind, "rename") == 0) {
            if (from_cli && policy->explicit_secret_rename) {
                fprintf(stderr, _("secret rename may be specified at most once\n"));
                free(rest);
                return 2;
            }
            if (from_cli) {
                if (!policy->explicit_secret_rename && policy->secret_rename.configured) {
                    secdat_exec_secret_rename_free(&policy->secret_rename);
                }
                policy->explicit_secret_rename = 1;
            }
            if (!from_cli && policy->secret_rename.configured) {
                fprintf(stderr, _("secret rename may be specified at most once\n"));
                free(rest);
                return 2;
            }
            if (secdat_exec_parse_rename_expression(value, &policy->secret_rename) != 0) {
                free(rest);
                return 1;
            }
            free(rest);
            return 0;
        }
        if (from_cli) {
            secdat_exec_prepare_cli_pentad_override(policy, layer, &policy->secret, kind);
        }
        if (secdat_exec_append_inject_selectors(&policy->secret, kind, value) != 0) {
            free(rest);
            return 1;
        }
        free(rest);
        return 0;
    }
    if (strcmp(layer, "route") == 0) {
        if (strcmp(kind, "prefer") == 0) {
            if (from_cli && policy->explicit_route_prefer) {
                fprintf(stderr, _("route:prefer may be specified at most once\n"));
                free(rest);
                return 2;
            }
            if (from_cli) {
                policy->explicit_route_prefer = 1;
            }
            if (secdat_exec_parse_route_pick(value, &policy->route_prefer) != 0) {
                free(rest);
                return 2;
            }
            free(rest);
            return 0;
        }
        {
            struct secdat_exec_route_rule *rules;
            struct secdat_exec_route_rule rule;
            enum secdat_exec_route_pick pick;

            if (secdat_exec_parse_route_pick(value, &pick) != 0) {
                free(rest);
                return 2;
            }
            if (from_cli) {
                secdat_exec_remove_file_route_rules(policy, kind);
            }

            rule.match = strdup(kind);
            if (rule.match == NULL) {
                free(rest);
                fprintf(stderr, _("out of memory\n"));
                return 1;
            }
            rule.pick = pick;
            rule.from_cli = from_cli;
            rules = realloc(policy->route_rules, (policy->route_rule_count + 1) * sizeof(*rules));
            if (rules == NULL) {
                free(rule.match);
                free(rest);
                fprintf(stderr, _("out of memory\n"));
                return 1;
            }
            policy->route_rules = rules;
            policy->route_rules[policy->route_rule_count] = rule;
            policy->route_rule_count += 1;
        }
        free(rest);
        return 0;
    }
    if (strcmp(layer, "final") == 0) {
        if (from_cli) {
            secdat_exec_prepare_cli_pentad_override(policy, layer, &policy->final, kind);
        }
        if (secdat_exec_append_inject_selectors(&policy->final, kind, value) != 0) {
            free(rest);
            return 1;
        }
        free(rest);
        return 0;
    }

    fprintf(stderr, _("invalid --inject layer: %s\n"), layer);
    free(rest);
    return 2;
}

static int secdat_exec_completion_is_global_option(const char *token)
{
    return token != NULL
        && (strcmp(token, "--dir") == 0 || strcmp(token, "-d") == 0
            || strcmp(token, "--domain") == 0
            || strcmp(token, "--store") == 0 || strcmp(token, "-s") == 0);
}

static int secdat_exec_completion_option_takes_argument(const char *token)
{
    return token != NULL
        && (strcmp(token, "--inject") == 0
            || strcmp(token, "--inject-file") == 0
            || strcmp(token, "--inject-gate") == 0
            || strcmp(token, "--command-resolution") == 0
            || strcmp(token, "--pattern") == 0 || strcmp(token, "-p") == 0
            || strcmp(token, "--pattern-exclude") == 0 || strcmp(token, "-x") == 0
            || strcmp(token, "--env-map-sed") == 0
            || strcmp(token, "--require-key") == 0);
}

int secdat_exec_completion_command_index(int argc, char **argv)
{
    int exec_index = -1;
    int index;

    for (index = 0; index + 1 < argc; index += 1) {
        const char *token = argv[index];

        if (secdat_exec_completion_is_global_option(token)) {
            index += 1;
            continue;
        }
        if (strcmp(token, "--help") == 0 || strcmp(token, "-h") == 0
            || strcmp(token, "--version") == 0 || strcmp(token, "-V") == 0) {
            continue;
        }
        if (strcmp(token, "exec") == 0) {
            exec_index = index;
            break;
        }
        break;
    }

    if (exec_index < 0) {
        return -1;
    }

    index = exec_index + 1;
    while (index < argc - 1) {
        const char *token = argv[index];

        if (strcmp(token, "--") == 0) {
            return index + 1;
        }
        if (token[0] == '-') {
            if (secdat_exec_completion_option_takes_argument(token)) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        return index;
    }

    return argc - 1;
}

static void secdat_prepare_exec_option_argv(const struct secdat_cli *cli, int *argc_out, char **argv_out)
{
    size_t index;

    argv_out[0] = (char *)cli->program_name;
    for (index = 0; index < cli->argc; index += 1) {
        argv_out[index + 1] = cli->argv[index];
    }
    argv_out[cli->argc + 1] = NULL;
    *argc_out = (int)cli->argc + 1;
}

static void secdat_exec_reset_getopt_state(void)
{
    opterr = 0;
    optind = 0;
}

static int secdat_exec_parse_options(
    const struct secdat_cli *cli,
    struct secdat_exec_options *options,
    const char **help_target_out
)
{
    static const struct option long_options[] = {
        {"inject", required_argument, NULL, 1000},
        {"inject-file", required_argument, NULL, 1007},
        {"bulk-gate", no_argument, NULL, 1009},
        {"inject-gate", required_argument, NULL, 9008},
        {"pattern", required_argument, NULL, 'p'},
        {"pattern-exclude", required_argument, NULL, 'x'},
        {"env-map-sed", required_argument, NULL, 1001},
        {"sandbox-injectable", no_argument, NULL, 1002},
        {"dry-run", no_argument, NULL, 1003},
        {"json", no_argument, NULL, 1004},
        {"json-summary", no_argument, NULL, 1005},
        {"require-key", required_argument, NULL, 1006},
        {"command-resolution", required_argument, NULL, 1010},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;
    int status;

    memset(options, 0, sizeof(*options));
    options->policy.route_prefer = SECDAT_EXEC_ROUTE_SECRET;
    options->command_resolution = SECDAT_EXEC_COMMAND_RESOLUTION_CALLER_PATH;
    if (help_target_out != NULL) {
        *help_target_out = "exec";
    }

    secdat_prepare_exec_option_argv(cli, &argc, argv);
    secdat_exec_reset_getopt_state();
    while ((option = getopt_long(argc, argv, "+p:x:", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            status = secdat_exec_apply_inject_token(&options->policy, optarg, 1);
            if (status != 0) {
                secdat_exec_options_free(options);
                if (help_target_out != NULL) {
                    *help_target_out = "inject";
                }
                return status;
            }
            break;
        case 1007:
            status = secdat_exec_apply_inject_policy_file(&options->policy, optarg);
            if (status != 0) {
                secdat_exec_options_free(options);
                if (help_target_out != NULL) {
                    *help_target_out = "inject";
                }
                return status;
            }
            break;
        case 'p':
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_removed_legacy_flag("--pattern (-p)", "--inject secret:only=GLOB");
        case 'x':
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_removed_legacy_flag("--pattern-exclude (-x)", "--inject secret:omit=GLOB");
        case 1001:
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_removed_legacy_flag("--env-map-sed", "--inject secret:rename=EXPR");
        case 1009:
            status = secdat_exec_enable_bulk_gate(&options->policy);
            if (status != 0) {
                secdat_exec_options_free(options);
                return status;
            }
            break;
        case 9008:
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_legacy_inject_gate(optarg);
        case 1002:
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_removed_legacy_flag("--sandbox-injectable", "--bulk-gate");
        case 1003:
            options->dry_run = 1;
            break;
        case 1004:
            options->json = 1;
            break;
        case 1005:
            options->json_summary = 1;
            break;
        case 1006:
            secdat_exec_options_free(options);
            if (help_target_out != NULL) {
                *help_target_out = "inject";
            }
            return secdat_exec_reject_removed_legacy_flag("--require-key", "--inject secret:require=KEY");
        case 1010:
            status = secdat_exec_parse_command_resolution(optarg, &options->command_resolution);
            if (status != 0) {
                secdat_exec_options_free(options);
                return status;
            }
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for exec\n"));
            secdat_exec_options_free(options);
            return 2;
        }
    }

    options->command_index = (size_t)(optind - 1);
    if (optind >= argc) {
        fprintf(stderr, _("invalid arguments for exec\n"));
        secdat_exec_options_free(options);
        return 2;
    }
    if (options->json && !options->dry_run) {
        fprintf(stderr, _("--json requires --dry-run for exec; use --json-summary for real executions\n"));
        secdat_exec_options_free(options);
        return 2;
    }
    if (options->dry_run && options->json_summary) {
        fprintf(stderr, _("--json-summary cannot be combined with --dry-run; use --dry-run --json for preflight JSON\n"));
        secdat_exec_options_free(options);
        return 2;
    }

    if (secdat_exec_pentad_conflicts(&options->policy.ambient, SECDAT_EXEC_PENTAD_AMBIENT) != 0
        || secdat_exec_pentad_conflicts(&options->policy.secret, SECDAT_EXEC_PENTAD_SECRET) != 0
        || secdat_exec_pentad_conflicts(&options->policy.final, SECDAT_EXEC_PENTAD_FINAL) != 0) {
        secdat_exec_options_free(options);
        if (help_target_out != NULL) {
            *help_target_out = "inject";
        }
        return 2;
    }

    return 0;
}

struct secdat_exec_name_value {
    char *name;
    char *value;
};

struct secdat_exec_name_value_list {
    struct secdat_exec_name_value *items;
    size_t count;
};

static void secdat_exec_name_value_list_free(struct secdat_exec_name_value_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->count; index += 1) {
        free(list->items[index].name);
        free(list->items[index].value);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
}

static int secdat_exec_name_value_list_append(
    struct secdat_exec_name_value_list *list,
    const char *name,
    const char *value
)
{
    struct secdat_exec_name_value *items;
    char *name_copy;
    char *value_copy;

    name_copy = strdup(name);
    value_copy = strdup(value);
    if (name_copy == NULL || value_copy == NULL) {
        free(name_copy);
        free(value_copy);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    items = realloc(list->items, (list->count + 1) * sizeof(*items));
    if (items == NULL) {
        free(name_copy);
        free(value_copy);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    list->items = items;
    list->items[list->count].name = name_copy;
    list->items[list->count].value = value_copy;
    list->count += 1;
    return 0;
}

static int secdat_exec_snapshot_ambient(struct secdat_exec_name_value_list *ambient_out)
{
    char **cursor;

    memset(ambient_out, 0, sizeof(*ambient_out));
    for (cursor = environ; cursor != NULL && *cursor != NULL; cursor += 1) {
        char *equals = strchr(*cursor, '=');

        if (equals == NULL || equals == *cursor) {
            continue;
        }
        {
            char name_buffer[PATH_MAX];
            size_t name_length = (size_t)(equals - *cursor);

            if (name_length >= sizeof(name_buffer)) {
                continue;
            }
            memcpy(name_buffer, *cursor, name_length);
            name_buffer[name_length] = '\0';
            if (secdat_exec_name_value_list_append(ambient_out, name_buffer, equals + 1) != 0) {
                secdat_exec_name_value_list_free(ambient_out);
                return 1;
            }
        }
    }
    return 0;
}

static int secdat_exec_pentad_select_names(
    const struct secdat_exec_pentad *pentad,
    enum secdat_exec_pentad_layer layer,
    const char **available,
    size_t available_count,
    const char **alternate_names,
    char ***selected_out,
    size_t *selected_count_out,
    char ***rejected_present_out,
    size_t *rejected_present_count_out,
    char ***missing_required_out,
    size_t *missing_required_count_out,
    int *mode_only_out
)
{
    char **selected = NULL;
    size_t selected_count = 0;
    size_t available_index;
    size_t selector_index;

    *selected_out = NULL;
    *selected_count_out = 0;
    *rejected_present_out = NULL;
    *rejected_present_count_out = 0;
    if (missing_required_out != NULL) {
        *missing_required_out = NULL;
    }
    if (missing_required_count_out != NULL) {
        *missing_required_count_out = 0;
    }
    *mode_only_out = pentad->only.count > 0;

    for (selector_index = 0; selector_index < pentad->reject.count; selector_index += 1) {
        for (available_index = 0; available_index < available_count; available_index += 1) {
            if (!secdat_exec_selector_matches(pentad->reject.items[selector_index], available[available_index])) {
                continue;
            }
            secdat_exec_print_reject_present(layer, available[available_index]);
            if (secdat_exec_string_list_append(rejected_present_out, rejected_present_count_out, available[available_index]) != 0) {
                secdat_exec_string_list_free(selected, selected_count);
                return 1;
            }
        }
    }
    if (*rejected_present_count_out > 0) {
        return 1;
    }

    for (available_index = 0; available_index < available_count; available_index += 1) {
        const char *name = available[available_index];
        const char *alternate = alternate_names != NULL ? alternate_names[available_index] : NULL;
        int include = *mode_only_out == 0;

        if (*mode_only_out) {
            if (alternate_names != NULL) {
                include = secdat_exec_selector_list_matches_primary_or_alternate(&pentad->only, name, alternate);
            } else if (secdat_exec_selector_list_matches(&pentad->only, name)) {
                include = 1;
            }
        }
        if (include) {
            if (alternate_names != NULL) {
                if (secdat_exec_selector_list_matches_primary_or_alternate(&pentad->omit, name, alternate)) {
                    include = 0;
                }
            } else if (secdat_exec_selector_list_matches(&pentad->omit, name)) {
                include = 0;
            }
        }
        if (!include) {
            continue;
        }
        if (secdat_exec_string_list_append(&selected, &selected_count, name) != 0) {
            return 1;
        }
    }

    for (selector_index = 0; selector_index < pentad->require.count; selector_index += 1) {
        const char *required = pentad->require.items[selector_index];
        int found = 0;
        size_t selected_index;

        for (selected_index = 0; selected_index < selected_count; selected_index += 1) {
            if (secdat_exec_selector_matches(required, selected[selected_index])) {
                found = 1;
                break;
            }
        }
        if (!found) {
            secdat_exec_print_required_missing(layer, required);
            if (missing_required_out != NULL
                && missing_required_count_out != NULL
                && secdat_exec_string_list_append(missing_required_out, missing_required_count_out, required) != 0) {
                secdat_exec_string_list_free(selected, selected_count);
                return 1;
            }
            if (missing_required_out == NULL || missing_required_count_out == NULL) {
                secdat_exec_string_list_free(selected, selected_count);
                return 1;
            }
        }
    }
    *selected_out = selected;
    *selected_count_out = selected_count;
    if (missing_required_count_out != NULL && *missing_required_count_out > 0) {
        return 1;
    }
    return 0;
}

static int secdat_exec_find_name_value(
    const struct secdat_exec_name_value_list *list,
    const char *name,
    const char **value_out
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].name, name) == 0) {
            *value_out = list->items[index].value;
            return 1;
        }
    }
    return 0;
}

static enum secdat_exec_route_pick secdat_exec_resolve_collision(
    const struct secdat_exec_inject_policy *policy,
    const char *name
)
{
    size_t index;

    for (index = 0; index < policy->route_rule_count; index += 1) {
        if (!policy->route_rules[index].from_cli) {
            continue;
        }
        if (secdat_exec_selector_matches(policy->route_rules[index].match, name)) {
            return policy->route_rules[index].pick;
        }
    }
    for (index = 0; index < policy->route_rule_count; index += 1) {
        if (policy->route_rules[index].from_cli) {
            continue;
        }
        if (secdat_exec_selector_matches(policy->route_rules[index].match, name)) {
            return policy->route_rules[index].pick;
        }
    }
    return policy->route_prefer;
}

static int secdat_exec_build_plan(
    const struct secdat_exec_inject_policy *policy,
    const struct secdat_domain_chain *chain,
    const char *store_name,
    char **visible_keys,
    size_t visible_key_count,
    struct secdat_exec_plan *plan_out
)
{
    struct secdat_exec_name_value_list ambient_snapshot = {0};
    struct secdat_exec_name_value_list ambient_bundle = {0};
    struct secdat_exec_name_value_list secret_bundle = {0};
    char **ambient_available = NULL;
    char **ambient_selected = NULL;
    size_t ambient_available_count = 0;
    size_t ambient_selected_count = 0;
    char **secret_available = NULL;
    char **secret_selected = NULL;
    char **secret_env_names = NULL;
    size_t secret_available_count = 0;
    size_t secret_selected_count = 0;
    char **merged_names = NULL;
    size_t merged_count = 0;
    size_t key_index;
    size_t index;
    int status = 0;

    memset(plan_out, 0, sizeof(*plan_out));

    if (secdat_exec_snapshot_ambient(&ambient_snapshot) != 0) {
        return 1;
    }

    ambient_available = calloc(ambient_snapshot.count, sizeof(*ambient_available));
    if (ambient_available == NULL && ambient_snapshot.count > 0) {
        fprintf(stderr, _("out of memory\n"));
        secdat_exec_name_value_list_free(&ambient_snapshot);
        return 1;
    }
    for (index = 0; index < ambient_snapshot.count; index += 1) {
        ambient_available[index] = ambient_snapshot.items[index].name;
    }
    ambient_available_count = ambient_snapshot.count;

    if (secdat_exec_pentad_select_names(
            &policy->ambient,
            SECDAT_EXEC_PENTAD_AMBIENT,
            (const char **)ambient_available,
            ambient_available_count,
            NULL,
            &ambient_selected,
            &ambient_selected_count,
            &plan_out->rejected_ambient_present,
            &plan_out->rejected_ambient_present_count,
            &plan_out->missing_ambient_required,
            &plan_out->missing_ambient_required_count,
            &plan_out->ambient_mode_only) != 0) {
        status = 1;
        goto cleanup;
    }

    for (index = 0; index < ambient_selected_count; index += 1) {
        const char *value = NULL;

        if (!secdat_exec_find_name_value(&ambient_snapshot, ambient_selected[index], &value)) {
            continue;
        }
        if (secdat_exec_name_value_list_append(&ambient_bundle, ambient_selected[index], value) != 0) {
            status = 1;
            goto cleanup;
        }
        if (secdat_exec_string_list_append(&plan_out->ambient_contributed, &plan_out->ambient_contributed_count, ambient_selected[index]) != 0) {
            status = 1;
            goto cleanup;
        }
    }

    secret_available = calloc(visible_key_count, sizeof(*secret_available));
    secret_env_names = calloc(visible_key_count, sizeof(*secret_env_names));
    if ((secret_available == NULL || secret_env_names == NULL) && visible_key_count > 0) {
        fprintf(stderr, _("out of memory\n"));
        status = 1;
        goto cleanup;
    }

    for (key_index = 0; key_index < visible_key_count; key_index += 1) {
        const char *key = visible_keys[key_index];
        char *env_name = NULL;
        int map_status;

        if (policy->bulk_gate) {
            int allowed = 0;

            if (secdat_exec_port_key_allows_bulk_select(chain, store_name, key, &allowed) != 0) {
                status = 1;
                goto cleanup;
            }
            if (!allowed) {
                continue;
            }
        }

        map_status = secdat_exec_env_name_from_key(&policy->secret_rename, key, &env_name);
        if (map_status != 0) {
            status = 1;
            goto cleanup;
        }

        if (secret_available_count > 0) {
            size_t prior_index;

            for (prior_index = 0; prior_index < secret_available_count; prior_index += 1) {
                if (strcmp(secret_env_names[prior_index], env_name) == 0) {
                    fprintf(stderr, _("duplicate environment variable name from secret rename: %s\n"), env_name);
                    free(env_name);
                    status = 1;
                    goto cleanup;
                }
            }
        }

        secret_available[secret_available_count] = strdup(key);
        secret_env_names[secret_available_count] = env_name;
        if (secret_available[secret_available_count] == NULL) {
            fprintf(stderr, _("out of memory\n"));
            status = 1;
            goto cleanup;
        }
        secret_available_count += 1;
    }

    if (secdat_exec_pentad_select_names(
            &policy->secret,
            SECDAT_EXEC_PENTAD_SECRET,
            (const char **)secret_available,
            secret_available_count,
            (const char **)secret_env_names,
            &secret_selected,
            &secret_selected_count,
            &plan_out->rejected_secret_present,
            &plan_out->rejected_secret_present_count,
            &plan_out->missing_secret_required,
            &plan_out->missing_secret_required_count,
            &plan_out->secret_mode_only) != 0) {
        status = 1;
    }

    for (index = 0; index < secret_selected_count; index += 1) {
        const char *key = secret_selected[index];
        const char *env_name = NULL;
        size_t key_lookup;

        for (key_lookup = 0; key_lookup < secret_available_count; key_lookup += 1) {
            if (strcmp(secret_available[key_lookup], key) == 0) {
                env_name = secret_env_names[key_lookup];
                break;
            }
        }
        if (env_name == NULL) {
            continue;
        }
        if (secdat_exec_name_value_list_append(&secret_bundle, env_name, key) != 0) {
            status = 1;
            goto cleanup;
        }
        if (secdat_exec_string_list_append(&plan_out->secret_contributed, &plan_out->secret_contributed_count, key) != 0) {
            status = 1;
            goto cleanup;
        }
        if (secdat_exec_string_list_append(
                &plan_out->secret_contributed_env_names,
                &plan_out->secret_contributed_env_names_count,
                env_name) != 0) {
            status = 1;
            goto cleanup;
        }
    }

    for (index = 0; index < ambient_bundle.count; index += 1) {
        if (secdat_exec_string_list_append(&merged_names, &merged_count, ambient_bundle.items[index].name) != 0) {
            status = 1;
            goto cleanup;
        }
    }
    for (index = 0; index < secret_bundle.count; index += 1) {
        size_t prior;

        for (prior = 0; prior < merged_count; prior += 1) {
            if (strcmp(merged_names[prior], secret_bundle.items[index].name) == 0) {
                break;
            }
        }
        if (prior == merged_count) {
            if (secdat_exec_string_list_append(&merged_names, &merged_count, secret_bundle.items[index].name) != 0) {
                status = 1;
                goto cleanup;
            }
        }
    }

    for (index = 0; index < merged_count; index += 1) {
        const char *name = merged_names[index];
        const char *ambient_value = NULL;
        const char *secret_key = NULL;
        int has_ambient = secdat_exec_find_name_value(&ambient_bundle, name, &ambient_value);
        int has_secret = secdat_exec_find_name_value(&secret_bundle, name, &secret_key);
        enum secdat_exec_route_pick pick;
        enum secdat_exec_value_source source;
        struct secdat_exec_plan_entry entry = {0};
        struct secdat_exec_plan_entry *entries;

        if (has_ambient && has_secret) {
            pick = secdat_exec_resolve_collision(policy, name);
            if (pick == SECDAT_EXEC_ROUTE_ERROR) {
                fprintf(stderr, _("ambient/secret collision on environment variable: %s\n"), name);
                status = 1;
                goto cleanup;
            }
            {
                struct secdat_exec_collision *collisions;
                struct secdat_exec_collision collision;

                collision.name = strdup(name);
                collision.picked = pick;
                if (collision.name == NULL) {
                    fprintf(stderr, _("out of memory\n"));
                    status = 1;
                    goto cleanup;
                }
                collisions = realloc(plan_out->collisions, (plan_out->collision_count + 1) * sizeof(*collisions));
                if (collisions == NULL) {
                    free(collision.name);
                    fprintf(stderr, _("out of memory\n"));
                    status = 1;
                    goto cleanup;
                }
                plan_out->collisions = collisions;
                plan_out->collisions[plan_out->collision_count] = collision;
                plan_out->collision_count += 1;
            }
            source = pick == SECDAT_EXEC_ROUTE_AMBIENT ? SECDAT_EXEC_VALUE_AMBIENT : SECDAT_EXEC_VALUE_SECRET;
        } else if (has_secret) {
            source = SECDAT_EXEC_VALUE_SECRET;
        } else {
            source = SECDAT_EXEC_VALUE_AMBIENT;
        }

        entry.env_name = strdup(name);
        if (entry.env_name == NULL) {
            fprintf(stderr, _("out of memory\n"));
            status = 1;
            goto cleanup;
        }
        if (source == SECDAT_EXEC_VALUE_SECRET) {
            entry.secret_key = strdup(secret_key);
            if (entry.secret_key == NULL) {
                free(entry.env_name);
                fprintf(stderr, _("out of memory\n"));
                status = 1;
                goto cleanup;
            }
        }
        entry.value_source = source;

        entries = realloc(plan_out->final_entries, (plan_out->final_count + 1) * sizeof(*entries));
        if (entries == NULL) {
            free(entry.env_name);
            free(entry.secret_key);
            fprintf(stderr, _("out of memory\n"));
            status = 1;
            goto cleanup;
        }
        plan_out->final_entries = entries;
        plan_out->final_entries[plan_out->final_count] = entry;
        plan_out->final_count += 1;
    }

    plan_out->final_mode_only = policy->final.only.count > 0;

    for (index = 0; index < plan_out->final_count; index += 1) {
        const char *name = plan_out->final_entries[index].env_name;

        if (!secdat_exec_selector_list_matches(&policy->final.reject, name)) {
            continue;
        }
        fprintf(stderr, _("exec inject forbidden variable in final child env: %s\n"), name);
        if (secdat_exec_string_list_append(&plan_out->rejected_final_present, &plan_out->rejected_final_present_count, name) != 0) {
            status = 1;
            goto cleanup;
        }
    }
    if (plan_out->rejected_final_present_count > 0) {
        status = 1;
        goto cleanup;
    }

    {
        struct secdat_exec_plan_entry *filtered = NULL;
        size_t filtered_count = 0;
        size_t selector_index;

        for (index = 0; index < plan_out->final_count; index += 1) {
            const char *name = plan_out->final_entries[index].env_name;
            int keep = plan_out->final_mode_only == 0
                || secdat_exec_selector_list_matches(&policy->final.only, name);

            if (keep && secdat_exec_selector_list_matches(&policy->final.omit, name)) {
                keep = 0;
            }
            if (!keep) {
                free(plan_out->final_entries[index].env_name);
                free(plan_out->final_entries[index].secret_key);
                continue;
            }
            {
                struct secdat_exec_plan_entry *entries;

                entries = realloc(filtered, (filtered_count + 1) * sizeof(*entries));
                if (entries == NULL) {
                    free(filtered);
                    fprintf(stderr, _("out of memory\n"));
                    status = 1;
                    goto cleanup;
                }
                filtered = entries;
                filtered[filtered_count] = plan_out->final_entries[index];
                filtered_count += 1;
            }
        }
        free(plan_out->final_entries);
        plan_out->final_entries = filtered;
        plan_out->final_count = filtered_count;

        for (selector_index = 0; selector_index < policy->final.require.count; selector_index += 1) {
            const char *required = policy->final.require.items[selector_index];
            int found = 0;
            size_t filtered_index;

            for (filtered_index = 0; filtered_index < filtered_count; filtered_index += 1) {
                if (secdat_exec_selector_matches(required, filtered[filtered_index].env_name)) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, _("exec inject required variable missing from final child env: %s\n"), required);
                if (secdat_exec_string_list_append(
                        &plan_out->missing_final_required,
                        &plan_out->missing_final_required_count,
                        required) != 0) {
                    status = 1;
                    goto cleanup;
                }
            }
        }
        if (plan_out->missing_final_required_count > 0) {
            status = 1;
            goto cleanup;
        }
    }

cleanup:
    secdat_exec_name_value_list_free(&ambient_snapshot);
    secdat_exec_name_value_list_free(&ambient_bundle);
    secdat_exec_name_value_list_free(&secret_bundle);
    free(ambient_available);
    secdat_exec_string_list_free(ambient_selected, ambient_selected_count);
    for (index = 0; index < secret_available_count; index += 1) {
        free(secret_available[index]);
        free(secret_env_names[index]);
    }
    free(secret_available);
    free(secret_env_names);
    secdat_exec_string_list_free(secret_selected, secret_selected_count);
    secdat_exec_string_list_free(merged_names, merged_count);
    return status;
}

static long long secdat_exec_monotonic_millis(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (long long)now.tv_sec * 1000 + (long long)(now.tv_nsec / 1000000);
}

static json_t *secdat_exec_json_supply_pentad(
    const char *mode,
    char **contributed,
    size_t contributed_count,
    char **rejected_present,
    size_t rejected_present_count,
    char **missing_required,
    size_t missing_required_count
)
{
    json_t *pentad = json_object();

    if (pentad == NULL) {
        return NULL;
    }
    if (json_object_set_new(pentad, "mode", json_string(mode)) != 0
            || json_object_set_new(pentad, "contributed", secdat_json_string_array(contributed, contributed_count)) != 0
            || json_object_set_new(pentad, "rejected_present", secdat_json_string_array(rejected_present, rejected_present_count)) != 0
            || json_object_set_new(pentad, "missing_required", secdat_json_string_array(missing_required, missing_required_count)) != 0) {
        json_decref(pentad);
        return NULL;
    }
    return pentad;
}

static json_t *secdat_exec_build_json_report(
    const struct secdat_domain_chain *chain,
    const struct secdat_cli *cli,
    const struct secdat_exec_options *options,
    const struct secdat_exec_plan *plan,
    char **command_argv,
    int ok,
    int dry_run,
    int exit_status,
    int term_signal,
    long long duration_ms
)
{
    char domain_label[PATH_MAX];
    json_t *root = json_object();
    json_t *supply = json_object();
    json_t *ambient = NULL;
    json_t *secret = NULL;
    json_t *route = json_object();
    json_t *collisions = json_array();
    json_t *final = json_object();
    json_t *present = NULL;
    json_t *injected_keys = json_array();
    json_t *argv = json_array();
    char **present_names = NULL;
    size_t present_count = 0;
    size_t index;
    size_t injected_key_count = 0;

    if (root == NULL || supply == NULL || route == NULL || collisions == NULL || final == NULL || injected_keys == NULL || argv == NULL) {
        goto fail;
    }

    if (secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], domain_label, sizeof(domain_label)) != 0) {
        domain_label[0] = '\0';
    }

    ambient = secdat_exec_json_supply_pentad(
        plan->ambient_mode_only ? "only" : "default",
        plan->ambient_contributed,
        plan->ambient_contributed_count,
        plan->rejected_ambient_present,
        plan->rejected_ambient_present_count,
        plan->missing_ambient_required,
        plan->missing_ambient_required_count
    );
    secret = secdat_exec_json_supply_pentad(
        plan->secret_mode_only ? "only" : "default",
        plan->secret_contributed,
        plan->secret_contributed_count,
        plan->rejected_secret_present,
        plan->rejected_secret_present_count,
        plan->missing_secret_required,
        plan->missing_secret_required_count
    );
    if (ambient == NULL || secret == NULL) {
        json_decref(ambient);
        json_decref(secret);
        goto fail;
    }

    for (index = 0; index < plan->collision_count; index += 1) {
        json_t *collision = json_object();

        if (collision == NULL
                || json_object_set_new(collision, "name", json_string(plan->collisions[index].name)) != 0
                || json_object_set_new(collision, "picked", json_string(secdat_exec_route_pick_name(plan->collisions[index].picked))) != 0
                || json_array_append_new(collisions, collision) != 0) {
            json_decref(collision);
            goto fail;
        }
    }

    for (index = 0; index < plan->final_count; index += 1) {
        if (secdat_exec_string_list_append(&present_names, &present_count, plan->final_entries[index].env_name) != 0) {
            goto fail;
        }
    }
    present = secdat_json_string_array(present_names, present_count);
    if (present == NULL) {
        goto fail;
    }

    for (index = 0; index < plan->final_count; index += 1) {
        if (plan->final_entries[index].secret_key == NULL) {
            continue;
        }
        json_t *entry = json_object();

        injected_key_count += 1;
        if (entry == NULL
                || json_object_set_new(entry, "key", json_string(plan->final_entries[index].secret_key)) != 0
                || json_object_set_new(entry, "env_name", json_string(plan->final_entries[index].env_name)) != 0
                || json_array_append_new(injected_keys, entry) != 0) {
            json_decref(entry);
            goto fail;
        }
    }

    for (index = 0; command_argv != NULL && command_argv[index] != NULL; index += 1) {
        if (json_array_append_new(argv, json_string(command_argv[index])) != 0) {
            goto fail;
        }
    }

    if (json_object_set_new(supply, "ambient", ambient) != 0) {
        goto fail;
    }
    ambient = NULL;
    if (json_object_set_new(supply, "secret", secret) != 0) {
        goto fail;
    }
    secret = NULL;
    if (json_object_set_new(route, "prefer", json_string(secdat_exec_route_pick_name(options->policy.route_prefer))) != 0
            || json_object_set_new(route, "collisions", collisions) != 0) {
        goto fail;
    }
    collisions = NULL;
    if (json_object_set_new(final, "mode", json_string(plan->final_mode_only ? "only" : "default")) != 0
            || json_object_set_new(final, "present", present) != 0) {
        goto fail;
    }
    present = NULL;
    if (json_object_set_new(final, "missing_required", secdat_json_string_array(plan->missing_final_required, plan->missing_final_required_count)) != 0
            || json_object_set_new(final, "rejected_present", secdat_json_string_array(plan->rejected_final_present, plan->rejected_final_present_count)) != 0
            || json_object_set_new(root, "ok", json_boolean(ok)) != 0
            || json_object_set_new(root, "domain", json_string(domain_label)) != 0
            || json_object_set_new(root, "store", json_string(secdat_exec_port_effective_store_name(cli->store))) != 0
            || json_object_set_new(root, "dry_run", json_boolean(dry_run)) != 0
            || json_object_set_new(root, "bulk_gate", json_boolean(options->policy.bulk_gate)) != 0
            || json_object_set_new(root, "supply", supply) != 0
            || json_object_set_new(root, "route", route) != 0
            || json_object_set_new(root, "final", final) != 0
            || json_object_set_new(root, "injected_key_count", json_integer((json_int_t)injected_key_count)) != 0
            || json_object_set_new(root, "injected_keys", injected_keys) != 0
            || json_object_set_new(root, "argv", argv) != 0
            || json_object_set_new(root, "exit_status", exit_status >= 0 ? json_integer(exit_status) : json_null()) != 0
            || json_object_set_new(root, "term_signal", term_signal >= 0 ? json_integer(term_signal) : json_null()) != 0
            || json_object_set_new(root, "duration_ms", duration_ms >= 0 ? json_integer(duration_ms) : json_null()) != 0) {
        goto fail;
    }
    supply = NULL;
    route = NULL;
    final = NULL;
    injected_keys = NULL;
    argv = NULL;

    secdat_exec_string_list_free(present_names, present_count);
    return root;

fail:
    secdat_exec_string_list_free(present_names, present_count);
    json_decref(ambient);
    json_decref(secret);
    json_decref(present);
    json_decref(collisions);
    json_decref(injected_keys);
    json_decref(argv);
    json_decref(final);
    json_decref(route);
    json_decref(supply);
    json_decref(root);
    return NULL;
}

static void secdat_exec_write_json_report(
    FILE *stream,
    const struct secdat_domain_chain *chain,
    const struct secdat_cli *cli,
    const struct secdat_exec_options *options,
    const struct secdat_exec_plan *plan,
    char **command_argv,
    int ok,
    int dry_run,
    int exit_status,
    int term_signal,
    long long duration_ms
)
{
    json_t *root = secdat_exec_build_json_report(
        chain,
        cli,
        options,
        plan,
        command_argv,
        ok,
        dry_run,
        exit_status,
        term_signal,
        duration_ms
    );

    if (root == NULL) {
        fputs("{}\n", stream);
        return;
    }
    secdat_json_dump(stream, root);
    json_decref(root);
}

static void secdat_exec_print_text_preflight(
    const struct secdat_domain_chain *chain,
    const struct secdat_cli *cli,
    const struct secdat_exec_plan *plan,
    char **command_argv
)
{
    char domain_label[PATH_MAX];
    size_t index;
    size_t injected_key_count = 0;

    if (secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], domain_label, sizeof(domain_label)) != 0) {
        domain_label[0] = '\0';
    }

    for (index = 0; index < plan->final_count; index += 1) {
        if (plan->final_entries[index].secret_key != NULL) {
            injected_key_count += 1;
        }
    }

    printf("domain: %s\n", domain_label);
    printf("store: %s\n", secdat_exec_port_effective_store_name(cli->store));
    fputs("argv:", stdout);
    for (index = 0; command_argv != NULL && command_argv[index] != NULL; index += 1) {
        fputc(' ', stdout);
        fputs(command_argv[index], stdout);
    }
    fputc('\n', stdout);
    printf("injected_key_count: %zu\n", injected_key_count);
    for (index = 0; index < plan->final_count; index += 1) {
        if (plan->final_entries[index].secret_key == NULL) {
            printf("%s\t<ambient>\n", plan->final_entries[index].env_name);
        } else {
            printf("%s\t%s\n", plan->final_entries[index].secret_key, plan->final_entries[index].env_name);
        }
    }
}

static int secdat_exec_build_child_environ(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_exec_plan *plan,
    const struct secdat_exec_name_value_list *ambient_snapshot,
    char ***environ_out,
    size_t *environ_count_out
)
{
    char **environ_entries = NULL;
    size_t environ_count = 0;
    size_t index;

    for (index = 0; index < plan->final_count; index += 1) {
        const struct secdat_exec_plan_entry *entry = &plan->final_entries[index];
        char *assignment = NULL;
        const char *value = NULL;
        char *owned_value = NULL;
        size_t assignment_length;

        if (entry->value_source == SECDAT_EXEC_VALUE_AMBIENT) {
            if (!secdat_exec_find_name_value(ambient_snapshot, entry->env_name, &value)) {
                fprintf(stderr, _("ambient variable missing during exec: %s\n"), entry->env_name);
                goto fail;
            }
        } else {
            unsigned char *plaintext = NULL;
            size_t plaintext_length = 0;

            if (secdat_exec_port_load_plaintext(chain, store_name, entry->secret_key, &plaintext, &plaintext_length) != 0) {
                goto fail;
            }
            if (secdat_exec_port_plaintext_to_env_value(entry->secret_key, plaintext, plaintext_length, &owned_value) != 0) {
                secdat_exec_port_secure_clear(plaintext, plaintext_length);
                free(plaintext);
                goto fail;
            }
            secdat_exec_port_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            value = owned_value;
        }

        assignment_length = strlen(entry->env_name) + 1 + strlen(value);
        assignment = malloc(assignment_length + 1);
        if (assignment == NULL) {
            fprintf(stderr, _("out of memory\n"));
            free(owned_value);
            goto fail;
        }
        snprintf(assignment, assignment_length + 1, "%s=%s", entry->env_name, value);
        free(owned_value);

        {
            char **items = realloc(environ_entries, (environ_count + 1) * sizeof(*items));
            if (items == NULL) {
                free(assignment);
                fprintf(stderr, _("out of memory\n"));
                goto fail;
            }
            environ_entries = items;
            environ_entries[environ_count] = assignment;
            environ_count += 1;
        }
    }

    {
        char **items = realloc(environ_entries, (environ_count + 1) * sizeof(*items));
        if (items == NULL) {
            fprintf(stderr, _("out of memory\n"));
            goto fail;
        }
        environ_entries = items;
        environ_entries[environ_count] = NULL;
    }

    *environ_out = environ_entries;
    *environ_count_out = environ_count;
    return 0;

fail:
    for (index = 0; index < environ_count; index += 1) {
        secdat_exec_port_secure_clear(environ_entries[index], strlen(environ_entries[index]));
        free(environ_entries[index]);
    }
    free(environ_entries);
    return 1;
}

static void secdat_exec_free_child_environ(char **environ_entries, size_t environ_count)
{
    size_t index;

    for (index = 0; index < environ_count; index += 1) {
        if (environ_entries[index] != NULL) {
            secdat_exec_port_secure_clear(environ_entries[index], strlen(environ_entries[index]));
            free(environ_entries[index]);
        }
    }
    free(environ_entries);
}

static const char *secdat_exec_child_environ_get(char **environ_entries, const char *name)
{
    size_t name_length = strlen(name);
    size_t index;

    for (index = 0; environ_entries != NULL && environ_entries[index] != NULL; index += 1) {
        if (strncmp(environ_entries[index], name, name_length) == 0 && environ_entries[index][name_length] == '=') {
            return environ_entries[index] + name_length + 1;
        }
    }
    return NULL;
}

static int secdat_exec_command_has_slash(const char *command)
{
    return strchr(command, '/') != NULL;
}

static void secdat_exec_try_child_path(char **command_argv, char **child_environ)
{
    const char *path = secdat_exec_child_environ_get(child_environ, "PATH");
    const char *cursor;
    const char *command = command_argv[0];
    size_t command_length = strlen(command);
    int saved_errno = ENOENT;

    if (secdat_exec_command_has_slash(command)) {
        execve(command, command_argv, child_environ);
        return;
    }
    if (path == NULL) {
        errno = ENOENT;
        return;
    }

    cursor = path;
    while (1) {
        const char *separator = strchr(cursor, ':');
        size_t directory_length = separator == NULL ? strlen(cursor) : (size_t)(separator - cursor);
        size_t candidate_length = (directory_length == 0 ? 2 : directory_length + 1) + command_length;
        char *candidate;

        if (directory_length > (size_t)INT_MAX || candidate_length < command_length) {
            errno = ENAMETOOLONG;
            return;
        }
        candidate = malloc(candidate_length + 1);
        if (candidate == NULL) {
            errno = ENOMEM;
            return;
        }
        if (directory_length == 0) {
            snprintf(candidate, candidate_length + 1, "./%s", command);
        } else {
            snprintf(candidate, candidate_length + 1, "%.*s/%s", (int)directory_length, cursor, command);
        }
        execve(candidate, command_argv, child_environ);
        if (errno != ENOENT && errno != ENOTDIR) {
            saved_errno = errno;
        }
        free(candidate);
        if (separator == NULL) {
            break;
        }
        cursor = separator + 1;
    }
    errno = saved_errno;
}

static int secdat_exec_run_child(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_exec_plan *plan,
    char **command_argv,
    enum secdat_exec_command_resolution command_resolution,
    int *exit_status_out,
    int *term_signal_out
)
{
    struct secdat_exec_name_value_list ambient_snapshot = {0};
    char **child_environ = NULL;
    size_t child_environ_count = 0;
    pid_t child_pid;
    int wait_status = 0;

    *exit_status_out = -1;
    *term_signal_out = -1;

    if (secdat_exec_snapshot_ambient(&ambient_snapshot) != 0) {
        return 1;
    }
    if (secdat_exec_build_child_environ(chain, store_name, plan, &ambient_snapshot, &child_environ, &child_environ_count) != 0) {
        secdat_exec_name_value_list_free(&ambient_snapshot);
        return 1;
    }
    secdat_exec_name_value_list_free(&ambient_snapshot);

    child_pid = fork();
    if (child_pid < 0) {
        secdat_exec_free_child_environ(child_environ, child_environ_count);
        fprintf(stderr, _("failed to execute command: %s\n"), command_argv[0]);
        return 1;
    }
    if (child_pid == 0) {
        if (command_resolution == SECDAT_EXEC_COMMAND_RESOLUTION_DIRECT
                && !secdat_exec_command_has_slash(command_argv[0])) {
            fprintf(stderr, _("command resolution direct requires slash-qualified command: %s\n"), command_argv[0]);
            _exit(127);
        }
        if (command_resolution == SECDAT_EXEC_COMMAND_RESOLUTION_CALLER_PATH) {
            execvpe(command_argv[0], command_argv, child_environ);
        } else if (command_resolution == SECDAT_EXEC_COMMAND_RESOLUTION_CHILD_PATH) {
            secdat_exec_try_child_path(command_argv, child_environ);
        } else {
            execve(command_argv[0], command_argv, child_environ);
        }
        fprintf(stderr, _("failed to execute command: %s\n"), command_argv[0]);
        _exit(127);
    }

    while (waitpid(child_pid, &wait_status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        secdat_exec_free_child_environ(child_environ, child_environ_count);
        fprintf(stderr, _("failed to execute command: %s\n"), command_argv[0]);
        return 1;
    }

    secdat_exec_free_child_environ(child_environ, child_environ_count);

    if (WIFEXITED(wait_status)) {
        *exit_status_out = WEXITSTATUS(wait_status);
    } else if (WIFSIGNALED(wait_status)) {
        *term_signal_out = WTERMSIG(wait_status);
    }
    return 0;
}

int secdat_exec_command(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_exec_options options;
    struct secdat_exec_plan plan = {0};
    char **visible_keys = NULL;
    size_t visible_key_count = 0;
    char **command_argv;
    const char *parse_help_target = "exec";
    int status;

    status = secdat_exec_parse_options(cli, &options, &parse_help_target);
    if (status != 0) {
        secdat_cli_print_try_help(cli, parse_help_target);
        return status;
    }

    if (secdat_domain_resolve_chain(cli->domain != NULL ? cli->domain : cli->dir, &chain) != 0) {
        secdat_exec_options_free(&options);
        return 1;
    }
    if (secdat_exec_port_collect_visible_keys(&chain, cli->store, &visible_keys, &visible_key_count) != 0) {
        secdat_exec_options_free(&options);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    command_argv = &cli->argv[options.command_index];
    status = secdat_exec_build_plan(&options.policy, &chain, cli->store, visible_keys, visible_key_count, &plan);
    if (status != 0) {
        if (options.dry_run && options.json) {
            secdat_exec_write_json_report(
                stdout,
                &chain,
                cli,
                &options,
                &plan,
                command_argv,
                0,
                1,
                -1,
                -1,
                -1
            );
        } else if (options.json_summary) {
            secdat_exec_write_json_report(
                stderr,
                &chain,
                cli,
                &options,
                &plan,
                command_argv,
                0,
                0,
                -1,
                -1,
                -1
            );
        }
        secdat_exec_plan_free(&plan);
        secdat_exec_port_free_keys(visible_keys, visible_key_count);
        secdat_exec_options_free(&options);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (options.dry_run) {
        if (options.json) {
            secdat_exec_write_json_report(stdout, &chain, cli, &options, &plan, command_argv, 1, 1, -1, -1, -1);
        } else {
            secdat_exec_print_text_preflight(&chain, cli, &plan, command_argv);
        }
        secdat_exec_plan_free(&plan);
        secdat_exec_port_free_keys(visible_keys, visible_key_count);
        secdat_exec_options_free(&options);
        secdat_domain_chain_free(&chain);
        return 0;
    }

    if (options.json_summary) {
        long long started_ms = secdat_exec_monotonic_millis();
        long long ended_ms;
        int exit_status = -1;
        int term_signal = -1;

        status = secdat_exec_run_child(
            &chain,
            cli->store,
            &plan,
            command_argv,
            options.command_resolution,
            &exit_status,
            &term_signal
        );
        ended_ms = secdat_exec_monotonic_millis();
        if (status != 0) {
            secdat_exec_plan_free(&plan);
            secdat_exec_port_free_keys(visible_keys, visible_key_count);
            secdat_exec_options_free(&options);
            secdat_domain_chain_free(&chain);
            return 1;
        }
        secdat_exec_write_json_report(
            stderr,
            &chain,
            cli,
            &options,
            &plan,
            command_argv,
            1,
            0,
            exit_status,
            term_signal,
            started_ms >= 0 && ended_ms >= started_ms ? ended_ms - started_ms : -1
        );
        secdat_exec_plan_free(&plan);
        secdat_exec_port_free_keys(visible_keys, visible_key_count);
        secdat_exec_options_free(&options);
        secdat_domain_chain_free(&chain);
        if (exit_status >= 0) {
            return exit_status;
        }
        if (term_signal >= 0) {
            return 128 + term_signal;
        }
        return 1;
    }

    {
        int exit_status = -1;
        int term_signal = -1;

        status = secdat_exec_run_child(
            &chain,
            cli->store,
            &plan,
            command_argv,
            options.command_resolution,
            &exit_status,
            &term_signal
        );
        secdat_exec_plan_free(&plan);
        secdat_exec_port_free_keys(visible_keys, visible_key_count);
        secdat_exec_options_free(&options);
        secdat_domain_chain_free(&chain);
        if (status != 0) {
            return 1;
        }
        if (exit_status >= 0) {
            return exit_status;
        }
        if (term_signal >= 0) {
            return 128 + term_signal;
        }
        return 1;
    }
}
