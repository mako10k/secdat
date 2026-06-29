#define _GNU_SOURCE

#include "i18n.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct secdat_exec_inject_policy;
struct secdat_exec_inject_profile;

extern int secdat_exec_apply_bulk_gate_yaml(struct secdat_exec_inject_policy *policy, const char *value);
extern int secdat_exec_apply_inject_token(struct secdat_exec_inject_policy *policy, const char *token, int from_cli);
extern int secdat_exec_apply_profile_required_yaml(struct secdat_exec_inject_policy *policy, const char *value);
extern int secdat_exec_policy_add_profile(
    struct secdat_exec_inject_policy *policy,
    const char *name,
    struct secdat_exec_inject_profile **profile_out
);
extern int secdat_exec_profile_set_command(struct secdat_exec_inject_profile *profile, const char *command);
extern int secdat_exec_profile_append_argv_prefix(struct secdat_exec_inject_profile *profile, const char *argument);
extern int secdat_exec_profile_add_inject_token(struct secdat_exec_inject_profile *profile, const char *token);

struct secdat_exec_yaml_string_list {
    char **items;
    size_t count;
};

static void secdat_exec_yaml_string_list_free(struct secdat_exec_yaml_string_list *list)
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

static int secdat_exec_yaml_string_list_append(struct secdat_exec_yaml_string_list *list, const char *value)
{
    char **items;
    char *copy;

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

static const char *secdat_exec_yaml_skip_spaces(const char *cursor)
{
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
        cursor += 1;
    }
    return cursor;
}

static int secdat_exec_yaml_unquote_scalar(const char *input, char **output)
{
    const char *cursor = input;
    char *result;
    size_t length = 0;
    size_t index = 0;

    *output = NULL;
    cursor = secdat_exec_yaml_skip_spaces(cursor);
    if (*cursor == '"' || *cursor == '\'') {
        char quote = *cursor;

        cursor += 1;
        while (cursor[length] != '\0' && cursor[length] != quote) {
            if (cursor[length] == '\\' && cursor[length + 1] != '\0') {
                length += 2;
                continue;
            }
            length += 1;
        }
        if (cursor[length] != quote) {
            return 2;
        }
        result = malloc(length + 1);
        if (result == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        while (index < length) {
            if (cursor[index] == '\\' && cursor[index + 1] != '\0') {
                result[index] = cursor[index + 1];
                index += 2;
                continue;
            }
            result[index] = cursor[index];
            index += 1;
        }
        result[length] = '\0';
        *output = result;
        return 0;
    }

    length = strlen(cursor);
    while (length > 0 && isspace((unsigned char)cursor[length - 1])) {
        length -= 1;
    }
    result = malloc(length + 1);
    if (result == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(result, cursor, length);
    result[length] = '\0';
    *output = result;
    return 0;
}

static int secdat_exec_yaml_inline_array_item_end(const char *cursor, const char **end_out)
{
    const char *end;

    *end_out = NULL;
    if (*cursor == '"' || *cursor == '\'') {
        char quote = *cursor;

        end = cursor + 1;
        while (*end != '\0') {
            if (*end == '\\' && end[1] != '\0') {
                end += 2;
                continue;
            }
            if (*end == quote) {
                end += 1;
                end = secdat_exec_yaml_skip_spaces(end);
                if (*end == ',' || *end == ']') {
                    *end_out = end;
                    return 0;
                }
                return 2;
            }
            end += 1;
        }
        return 2;
    }

    end = cursor + strcspn(cursor, ",]");
    *end_out = end;
    return 0;
}

static int secdat_exec_yaml_parse_inline_array(const char *input, struct secdat_exec_yaml_string_list *list)
{
    const char *cursor = input;
    char *item = NULL;
    int status;

    cursor = secdat_exec_yaml_skip_spaces(cursor);
    if (*cursor != '[') {
        return 2;
    }
    cursor += 1;
    while (*cursor != '\0') {
        cursor = secdat_exec_yaml_skip_spaces(cursor);
        if (*cursor == ']') {
            return 0;
        }
        if (*cursor == ',') {
            cursor += 1;
            continue;
        }
        {
            const char *item_end;
            char *raw_item;
            size_t raw_length;

            status = secdat_exec_yaml_inline_array_item_end(cursor, &item_end);
            if (status != 0) {
                return status;
            }
            raw_length = (size_t)(item_end - cursor);
            raw_item = malloc(raw_length + 1);
            if (raw_item == NULL) {
                fprintf(stderr, _("out of memory\n"));
                return 1;
            }
            memcpy(raw_item, cursor, raw_length);
            raw_item[raw_length] = '\0';
            status = secdat_exec_yaml_unquote_scalar(raw_item, &item);
            free(raw_item);
            if (status != 0) {
                return status;
            }
            cursor = item_end;
        }
        if (secdat_exec_yaml_string_list_append(list, item) != 0) {
            free(item);
            return 1;
        }
        free(item);
        item = NULL;
        if (*cursor == ',') {
            cursor += 1;
        }
    }
    return 2;
}

static int secdat_exec_yaml_join_selectors(
    const struct secdat_exec_yaml_string_list *list,
    char **joined_out
)
{
    size_t total_length = 0;
    size_t index;
    char *joined;

    *joined_out = NULL;
    for (index = 0; index < list->count; index += 1) {
        total_length += strlen(list->items[index]);
        if (index + 1 < list->count) {
            total_length += 1;
        }
    }
    joined = malloc(total_length + 1);
    if (joined == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    joined[0] = '\0';
    for (index = 0; index < list->count; index += 1) {
        if (index > 0) {
            strcat(joined, ":");
        }
        strcat(joined, list->items[index]);
    }
    *joined_out = joined;
    return 0;
}

static int secdat_exec_yaml_build_token(
    char **token_out,
    const char *layer,
    const char *kind,
    const char *value
)
{
    char *token;
    int written;
    size_t layer_length = strlen(layer);
    size_t kind_length = strlen(kind);
    size_t value_length = strlen(value);
    size_t token_length;

    *token_out = NULL;
    if (layer_length > SIZE_MAX - kind_length
            || layer_length + kind_length > SIZE_MAX - value_length
            || layer_length + kind_length + value_length > SIZE_MAX - 2) {
        fprintf(stderr, _("inject policy token is too large\n"));
        return 2;
    }
    token_length = layer_length + 1 + kind_length + 1 + value_length;
    token = malloc(token_length + 1);
    if (token == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    written = snprintf(token, token_length + 1, "%s:%s=%s", layer, kind, value);
    if (written < 0 || (size_t)written != token_length) {
        free(token);
        fprintf(stderr, _("failed to build inject policy token\n"));
        return 1;
    }
    *token_out = token;
    return 0;
}

static int secdat_exec_yaml_apply_pentad_tokens(
    struct secdat_exec_inject_policy *policy,
    const char *layer,
    const char *kind,
    const struct secdat_exec_yaml_string_list *selectors
)
{
    char *joined = NULL;
    char *token = NULL;
    int status;

    if (selectors->count == 0) {
        return 0;
    }
    status = secdat_exec_yaml_join_selectors(selectors, &joined);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_yaml_build_token(&token, layer, kind, joined);
    if (status != 0) {
        free(joined);
        return status;
    }
    status = secdat_exec_apply_inject_token(policy, token, 0);
    free(token);
    free(joined);
    return status;
}

static int secdat_exec_yaml_apply_scalar_token(
    struct secdat_exec_inject_policy *policy,
    const char *layer,
    const char *kind,
    const char *value
)
{
    char *token = NULL;
    int status;

    status = secdat_exec_yaml_build_token(&token, layer, kind, value);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_apply_inject_token(policy, token, 0);
    free(token);
    return status;
}

static int secdat_exec_yaml_apply_route_tokens(
    struct secdat_exec_inject_policy *policy,
    const char *key,
    const char *value
)
{
    char *token = NULL;
    int status;

    status = secdat_exec_yaml_build_token(&token, "route", key, value);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_apply_inject_token(policy, token, 0);
    free(token);
    return status;
}

static int secdat_exec_yaml_store_profile_pentad_tokens(
    struct secdat_exec_inject_profile *profile,
    const char *layer,
    const char *kind,
    const struct secdat_exec_yaml_string_list *selectors
)
{
    char *joined = NULL;
    char *token = NULL;
    int status;

    if (selectors->count == 0) {
        return 0;
    }
    status = secdat_exec_yaml_join_selectors(selectors, &joined);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_yaml_build_token(&token, layer, kind, joined);
    if (status != 0) {
        free(joined);
        return status;
    }
    status = secdat_exec_profile_add_inject_token(profile, token);
    free(token);
    free(joined);
    return status;
}

static int secdat_exec_yaml_store_profile_scalar_token(
    struct secdat_exec_inject_profile *profile,
    const char *layer,
    const char *kind,
    const char *value
)
{
    char *token = NULL;
    int status;

    status = secdat_exec_yaml_build_token(&token, layer, kind, value);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_profile_add_inject_token(profile, token);
    free(token);
    return status;
}

static int secdat_exec_yaml_store_profile_route_tokens(
    struct secdat_exec_inject_profile *profile,
    const char *key,
    const char *value
)
{
    char *token = NULL;
    int status;

    status = secdat_exec_yaml_build_token(&token, "route", key, value);
    if (status != 0) {
        return status;
    }
    status = secdat_exec_profile_add_inject_token(profile, token);
    free(token);
    return status;
}

static int secdat_exec_yaml_apply_profile_argv_prefix(
    struct secdat_exec_inject_profile *profile,
    const struct secdat_exec_yaml_string_list *arguments
)
{
    size_t index;

    for (index = 0; index < arguments->count; index += 1) {
        if (secdat_exec_profile_append_argv_prefix(profile, arguments->items[index]) != 0) {
            return 1;
        }
    }
    return 0;
}

static int secdat_exec_yaml_count_indent(const char *line)
{
    size_t index = 0;

    while (line[index] == ' ') {
        index += 1;
    }
    if (line[index] == '\t') {
        return -1;
    }
    return (int)index;
}

static int secdat_exec_yaml_split_key_value(const char *line, char **key_out, char **value_out)
{
    char *key;
    char *value;
    const char *cursor;
    size_t key_length;

    *key_out = NULL;
    *value_out = NULL;
    cursor = secdat_exec_yaml_skip_spaces(line);
    if (*cursor == '\0' || *cursor == '#') {
        return 2;
    }
    key_length = strcspn(cursor, ":");
    if (cursor[key_length] != ':') {
        return 2;
    }
    key = malloc(key_length + 1);
    if (key == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(key, cursor, key_length);
    key[key_length] = '\0';
    {
        size_t trim = key_length;

        while (trim > 0 && isspace((unsigned char)key[trim - 1])) {
            trim -= 1;
        }
        key[trim] = '\0';
    }
    if (secdat_exec_yaml_unquote_scalar(cursor + key_length + 1, &value) != 0) {
        free(key);
        return 2;
    }
    *key_out = key;
    *value_out = value;
    return 0;
}

static int secdat_exec_yaml_block_list_item(const char *line, const char **item_out)
{
    const char *item;
    size_t index;

    *item_out = NULL;
    if (line[0] != '-') {
        return 0;
    }
    if (line[1] != '\0' && !isspace((unsigned char)line[1])) {
        return 0;
    }
    item = secdat_exec_yaml_skip_spaces(line + 1);
    if (item[0] == '"' || item[0] == '\'') {
        char quote = item[0];
        const char *cursor = item + 1;

        while (*cursor != '\0') {
            if (*cursor == '\\' && cursor[1] != '\0') {
                cursor += 2;
                continue;
            }
            if (*cursor == quote) {
                cursor += 1;
                cursor = secdat_exec_yaml_skip_spaces(cursor);
                if (*cursor == '\0' || *cursor == '#') {
                    *item_out = item;
                    return 1;
                }
                return -1;
            }
            cursor += 1;
        }
        *item_out = item;
        return 1;
    }
    for (index = 0; item[index] != '\0'; index += 1) {
        if (item[index] == ':' && (item[index + 1] == '\0' || isspace((unsigned char)item[index + 1]))) {
            return -1;
        }
    }
    *item_out = item;
    return 1;
}

enum secdat_exec_yaml_pending_target {
    SECDAT_EXEC_YAML_PENDING_NONE = 0,
    SECDAT_EXEC_YAML_PENDING_BASE_PENTAD,
    SECDAT_EXEC_YAML_PENDING_PROFILE_PENTAD,
    SECDAT_EXEC_YAML_PENDING_PROFILE_ARGV_PREFIX,
};

static int secdat_exec_yaml_flush_pending(
    struct secdat_exec_inject_policy *policy,
    struct secdat_exec_inject_profile *pending_profile,
    enum secdat_exec_yaml_pending_target pending_target,
    int pending_subsection,
    const char *pending_kind,
    const struct secdat_exec_yaml_string_list *pending
)
{
    const char *layer;

    if (pending_target == SECDAT_EXEC_YAML_PENDING_NONE) {
        return 0;
    }
    if (pending_target == SECDAT_EXEC_YAML_PENDING_PROFILE_ARGV_PREFIX) {
        return secdat_exec_yaml_apply_profile_argv_prefix(pending_profile, pending);
    }
    layer = pending_subsection == 1 ? "ambient" : pending_subsection == 2 ? "secret" : "final";
    if (pending_target == SECDAT_EXEC_YAML_PENDING_PROFILE_PENTAD) {
        return secdat_exec_yaml_store_profile_pentad_tokens(pending_profile, layer, pending_kind, pending);
    }
    return secdat_exec_yaml_apply_pentad_tokens(policy, layer, pending_kind, pending);
}

int secdat_exec_apply_inject_policy_file(struct secdat_exec_inject_policy *policy, const char *path)
{
    FILE *stream;
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    int section = 0;
    int subsection = 0;
    int profile_section = 0;
    int profile_subsection = 0;
    struct secdat_exec_inject_profile *current_profile = NULL;
    struct secdat_exec_yaml_string_list pending = {0};
    char *pending_kind = NULL;
    enum secdat_exec_yaml_pending_target pending_target = SECDAT_EXEC_YAML_PENDING_NONE;
    int pending_subsection = 0;
    struct secdat_exec_inject_profile *pending_profile = NULL;
    int status = 0;

    stream = fopen(path, "r");
    if (stream == NULL) {
        fprintf(stderr, _("failed to open inject policy file: %s\n"), path);
        return 1;
    }

    while ((line_length = getline(&line, &line_capacity, stream)) >= 0) {
        char *key = NULL;
        char *value = NULL;
        int indent;
        char *trimmed = line;
        const char *content;

        (void)line_length;
        while (*trimmed != '\0' && (*trimmed == '\r' || *trimmed == '\n')) {
            trimmed += 1;
        }
        {
            size_t end = strlen(trimmed);

            while (end > 0 && (trimmed[end - 1] == '\n' || trimmed[end - 1] == '\r')) {
                trimmed[end - 1] = '\0';
                end -= 1;
            }
        }
        indent = secdat_exec_yaml_count_indent(trimmed);
        if (indent < 0) {
            fprintf(stderr, _("invalid inject policy file indentation: %s\n"), path);
            status = 2;
            goto cleanup;
        }
        content = secdat_exec_yaml_skip_spaces(trimmed);
        if (content[0] == '\0' || content[0] == '#') {
            continue;
        }
        trimmed = (char *)content;

        if (pending_target != SECDAT_EXEC_YAML_PENDING_NONE && indent > 0) {
            const char *item = NULL;
            int list_item = secdat_exec_yaml_block_list_item(trimmed, &item);

            if (list_item < 0) {
                fprintf(stderr, _("invalid inject policy file list entry: %s\n"), path);
                status = 2;
                goto cleanup;
            }
            if (list_item == 0) {
                goto flush_pending;
            }
            {
                char *scalar = NULL;

                if (secdat_exec_yaml_unquote_scalar(item, &scalar) != 0) {
                    fprintf(stderr, _("invalid inject policy file list entry: %s\n"), path);
                    status = 2;
                    goto cleanup;
                }
                if (secdat_exec_yaml_string_list_append(&pending, scalar) != 0) {
                    free(scalar);
                    status = 1;
                    goto cleanup;
                }
                free(scalar);
            }
            continue;
        }

flush_pending:
        if (pending_target != SECDAT_EXEC_YAML_PENDING_NONE) {
            status = secdat_exec_yaml_flush_pending(
                policy,
                pending_profile,
                pending_target,
                pending_subsection,
                pending_kind,
                &pending);
            if (status != 0) {
                goto cleanup;
            }
            secdat_exec_yaml_string_list_free(&pending);
            free(pending_kind);
            pending_kind = NULL;
            pending_target = SECDAT_EXEC_YAML_PENDING_NONE;
            pending_subsection = 0;
            pending_profile = NULL;
        }

        if (secdat_exec_yaml_split_key_value(trimmed, &key, &value) != 0) {
            fprintf(stderr, _("invalid inject policy file line: %s\n"), trimmed);
            status = 2;
            goto cleanup;
        }

        if (indent == 0) {
            subsection = 0;
            profile_section = 0;
            profile_subsection = 0;
            current_profile = NULL;
            if (strcmp(key, "supply") == 0) {
                section = 1;
                free(key);
                free(value);
            } else if (strcmp(key, "route") == 0) {
                section = 2;
                free(key);
                free(value);
            } else if (strcmp(key, "demand") == 0) {
                section = 3;
                free(key);
                free(value);
            } else if (strcmp(key, "profiles") == 0) {
                section = 4;
                free(key);
                free(value);
            } else if (strcmp(key, "profile_required") == 0) {
                section = 0;
                status = secdat_exec_apply_profile_required_yaml(policy, value);
                free(key);
                free(value);
                if (status != 0) {
                    goto cleanup;
                }
            } else if (strcmp(key, "bulk_gate") == 0) {
                section = 0;
                status = secdat_exec_apply_bulk_gate_yaml(policy, value);
                free(key);
                free(value);
                if (status != 0) {
                    goto cleanup;
                }
            } else if (strcmp(key, "gate") == 0) {
                section = 0;
                fprintf(stderr, _("gate: is no longer supported; use bulk_gate: true\n"));
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            } else {
                fprintf(stderr, _("unknown inject policy file section: %s\n"), key);
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            }
            continue;
        }

        if (section == 4 && indent == 2) {
            status = secdat_exec_policy_add_profile(policy, key, &current_profile);
            profile_section = 0;
            profile_subsection = 0;
            free(key);
            free(value);
            if (status != 0) {
                goto cleanup;
            }
            continue;
        }

        if (section == 4) {
            if (current_profile == NULL) {
                fprintf(stderr, _("invalid inject policy file line: %s\n"), trimmed);
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            }
            if (indent == 4) {
                profile_subsection = 0;
                if (strcmp(key, "match") == 0) {
                    profile_section = 1;
                } else if (strcmp(key, "supply") == 0) {
                    profile_section = 2;
                } else if (strcmp(key, "route") == 0) {
                    profile_section = 3;
                } else if (strcmp(key, "demand") == 0) {
                    profile_section = 4;
                } else {
                    fprintf(stderr, _("unknown inject profile section: %s\n"), key);
                    status = 2;
                    free(key);
                    free(value);
                    goto cleanup;
                }
                free(key);
                free(value);
                continue;
            }
            if (profile_section == 1 && indent == 6) {
                if (strcmp(key, "command") == 0) {
                    status = secdat_exec_profile_set_command(current_profile, value);
                    free(key);
                    free(value);
                    if (status != 0) {
                        goto cleanup;
                    }
                    continue;
                }
                if (strcmp(key, "argv_prefix") == 0) {
                    if (value[0] == '[') {
                        struct secdat_exec_yaml_string_list arguments = {0};

                        status = secdat_exec_yaml_parse_inline_array(value, &arguments);
                        free(key);
                        free(value);
                        if (status != 0) {
                            secdat_exec_yaml_string_list_free(&arguments);
                            fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                            status = 2;
                            goto cleanup;
                        }
                        status = secdat_exec_yaml_apply_profile_argv_prefix(current_profile, &arguments);
                        secdat_exec_yaml_string_list_free(&arguments);
                        if (status != 0) {
                            goto cleanup;
                        }
                        continue;
                    }
                    pending_kind = key;
                    key = NULL;
                    pending_target = SECDAT_EXEC_YAML_PENDING_PROFILE_ARGV_PREFIX;
                    pending_subsection = 0;
                    pending_profile = current_profile;
                    if (value[0] == '\0') {
                        free(value);
                        continue;
                    }
                    status = secdat_exec_yaml_parse_inline_array(value, &pending);
                    free(value);
                    if (status != 0) {
                        fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                        status = 2;
                        goto cleanup;
                    }
                    continue;
                }
                fprintf(stderr, _("unknown inject profile match key: %s\n"), key);
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            }
            if (profile_section == 2 && indent == 6) {
                if (strcmp(key, "ambient") == 0) {
                    profile_subsection = 1;
                } else if (strcmp(key, "secret") == 0) {
                    profile_subsection = 2;
                } else {
                    fprintf(stderr, _("unknown inject policy supply section: %s\n"), key);
                    status = 2;
                    free(key);
                    free(value);
                    goto cleanup;
                }
                free(key);
                free(value);
                continue;
            }
            if (profile_section == 4 && indent == 6 && strcmp(key, "final") == 0) {
                profile_subsection = 3;
                free(key);
                free(value);
                continue;
            }
            if (profile_section == 2 && (profile_subsection == 1 || profile_subsection == 2) && indent == 8) {
                const char *layer = profile_subsection == 1 ? "ambient" : "secret";

                if (strcmp(key, "rename") == 0) {
                    status = secdat_exec_yaml_store_profile_scalar_token(current_profile, layer, "rename", value);
                    free(key);
                    free(value);
                    if (status != 0) {
                        goto cleanup;
                    }
                    continue;
                }
                if (value[0] == '[') {
                    struct secdat_exec_yaml_string_list selectors = {0};
                    char *kind = key;

                    status = secdat_exec_yaml_parse_inline_array(value, &selectors);
                    free(value);
                    if (status != 0) {
                        free(kind);
                        fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                        status = 2;
                        goto cleanup;
                    }
                    status = secdat_exec_yaml_store_profile_pentad_tokens(current_profile, layer, kind, &selectors);
                    free(kind);
                    secdat_exec_yaml_string_list_free(&selectors);
                    if (status != 0) {
                        goto cleanup;
                    }
                    continue;
                }
                pending_kind = key;
                key = NULL;
                pending_target = SECDAT_EXEC_YAML_PENDING_PROFILE_PENTAD;
                pending_subsection = profile_subsection;
                pending_profile = current_profile;
                if (value[0] == '\0') {
                    free(value);
                    continue;
                }
                status = secdat_exec_yaml_parse_inline_array(value, &pending);
                free(value);
                if (status != 0) {
                    fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                    status = 2;
                    goto cleanup;
                }
                continue;
            }
            if (profile_section == 4 && profile_subsection == 3 && indent == 8) {
                if (value[0] == '[') {
                    struct secdat_exec_yaml_string_list selectors = {0};
                    char *kind = key;

                    status = secdat_exec_yaml_parse_inline_array(value, &selectors);
                    free(value);
                    if (status != 0) {
                        free(kind);
                        fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                        status = 2;
                        goto cleanup;
                    }
                    status = secdat_exec_yaml_store_profile_pentad_tokens(current_profile, "final", kind, &selectors);
                    free(kind);
                    secdat_exec_yaml_string_list_free(&selectors);
                    if (status != 0) {
                        goto cleanup;
                    }
                    continue;
                }
                pending_kind = key;
                key = NULL;
                pending_target = SECDAT_EXEC_YAML_PENDING_PROFILE_PENTAD;
                pending_subsection = 3;
                pending_profile = current_profile;
                if (value[0] == '\0') {
                    free(value);
                    continue;
                }
                status = secdat_exec_yaml_parse_inline_array(value, &pending);
                free(value);
                if (status != 0) {
                    fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                    status = 2;
                    goto cleanup;
                }
                continue;
            }
            if (profile_section == 3 && indent == 6) {
                status = secdat_exec_yaml_store_profile_route_tokens(current_profile, key, value);
                free(key);
                free(value);
                if (status != 0) {
                    goto cleanup;
                }
                continue;
            }
            fprintf(stderr, _("invalid inject policy file line: %s\n"), trimmed);
            status = 2;
            free(key);
            free(value);
            goto cleanup;
        }

        if (section == 1 && indent == 2) {
            if (strcmp(key, "ambient") == 0) {
                subsection = 1;
            } else if (strcmp(key, "secret") == 0) {
                subsection = 2;
            } else {
                fprintf(stderr, _("unknown inject policy supply section: %s\n"), key);
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            }
            free(key);
            free(value);
            continue;
        }

        if (section == 3 && indent == 2 && strcmp(key, "final") == 0) {
            subsection = 3;
            free(key);
            free(value);
            continue;
        }

        if (section == 1 && (subsection == 1 || subsection == 2) && indent == 4) {
            const char *layer = subsection == 1 ? "ambient" : "secret";

            if (strcmp(key, "rename") == 0) {
                status = secdat_exec_yaml_apply_scalar_token(policy, layer, "rename", value);
                free(key);
                free(value);
                if (status != 0) {
                    goto cleanup;
                }
                continue;
            }
            if (value[0] == '[') {
                struct secdat_exec_yaml_string_list selectors = {0};
                char *kind = key;

                status = secdat_exec_yaml_parse_inline_array(value, &selectors);
                free(value);
                if (status != 0) {
                    free(kind);
                    fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                    status = 2;
                    goto cleanup;
                }
                status = secdat_exec_yaml_apply_pentad_tokens(policy, layer, kind, &selectors);
                free(kind);
                secdat_exec_yaml_string_list_free(&selectors);
                if (status != 0) {
                    goto cleanup;
                }
                continue;
            }
            pending_kind = key;
            key = NULL;
            pending_target = SECDAT_EXEC_YAML_PENDING_BASE_PENTAD;
            pending_subsection = subsection;
            pending_profile = NULL;
            if (value[0] == '\0') {
                free(value);
                continue;
            }
            status = secdat_exec_yaml_parse_inline_array(value, &pending);
            free(value);
            if (status != 0) {
                fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                status = 2;
                goto cleanup;
            }
            continue;
        }

        if (section == 3 && subsection == 3 && indent == 4) {
            if (value[0] == '[') {
                struct secdat_exec_yaml_string_list selectors = {0};
                char *kind = key;

                status = secdat_exec_yaml_parse_inline_array(value, &selectors);
                free(value);
                if (status != 0) {
                    free(kind);
                    fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                    status = 2;
                    goto cleanup;
                }
                status = secdat_exec_yaml_apply_pentad_tokens(policy, "final", kind, &selectors);
                free(kind);
                secdat_exec_yaml_string_list_free(&selectors);
                if (status != 0) {
                    goto cleanup;
                }
                continue;
            }
            pending_kind = key;
            key = NULL;
            pending_target = SECDAT_EXEC_YAML_PENDING_BASE_PENTAD;
            pending_subsection = 3;
            pending_profile = NULL;
            if (value[0] == '\0') {
                free(value);
                continue;
            }
            status = secdat_exec_yaml_parse_inline_array(value, &pending);
            free(value);
            if (status != 0) {
                fprintf(stderr, _("invalid inject policy file selector list: %s\n"), path);
                status = 2;
                goto cleanup;
            }
            continue;
        }

        if (section == 2 && indent == 2) {
            status = secdat_exec_yaml_apply_route_tokens(policy, key, value);
            free(key);
            free(value);
            if (status != 0) {
                goto cleanup;
            }
            continue;
        }

        fprintf(stderr, _("invalid inject policy file line: %s\n"), trimmed);
        status = 2;
        free(key);
        free(value);
        goto cleanup;
    }

    if (pending_target != SECDAT_EXEC_YAML_PENDING_NONE) {
        status = secdat_exec_yaml_flush_pending(
            policy,
            pending_profile,
            pending_target,
            pending_subsection,
            pending_kind,
            &pending);
        if (status != 0) {
            goto cleanup;
        }
    }

cleanup:
    free(line);
    secdat_exec_yaml_string_list_free(&pending);
    free(pending_kind);
    fclose(stream);
    return status;
}
