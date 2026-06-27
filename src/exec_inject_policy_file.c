#define _GNU_SOURCE

#include "i18n.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct secdat_exec_inject_policy;

extern int secdat_exec_apply_inject_gate(struct secdat_exec_inject_policy *policy, const char *value);
extern int secdat_exec_apply_inject_token(struct secdat_exec_inject_policy *policy, const char *token);

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
        status = secdat_exec_yaml_unquote_scalar(cursor, &item);
        if (status != 0) {
            return status;
        }
        if (secdat_exec_yaml_string_list_append(list, item) != 0) {
            free(item);
            return 1;
        }
        free(item);
        item = NULL;
        cursor += strcspn(cursor, ",]");
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

static int secdat_exec_yaml_apply_pentad_tokens(
    struct secdat_exec_inject_policy *policy,
    const char *layer,
    const char *kind,
    const struct secdat_exec_yaml_string_list *selectors
)
{
    char *joined = NULL;
    char token[4096];
    int status;

    if (selectors->count == 0) {
        return 0;
    }
    status = secdat_exec_yaml_join_selectors(selectors, &joined);
    if (status != 0) {
        return status;
    }
    snprintf(token, sizeof(token), "%s:%s=%s", layer, kind, joined);
    status = secdat_exec_apply_inject_token(policy, token);
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
    char token[4096];

    snprintf(token, sizeof(token), "%s:%s=%s", layer, kind, value);
    return secdat_exec_apply_inject_token(policy, token);
}

static int secdat_exec_yaml_apply_route_tokens(
    struct secdat_exec_inject_policy *policy,
    const char *key,
    const char *value
)
{
    char token[4096];

    snprintf(token, sizeof(token), "route:%s=%s", key, value);
    return secdat_exec_apply_inject_token(policy, token);
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

int secdat_exec_apply_inject_policy_file(struct secdat_exec_inject_policy *policy, const char *path)
{
    FILE *stream;
    char line[4096];
    int section = 0;
    int subsection = 0;
    struct secdat_exec_yaml_string_list pending = {0};
    char *pending_kind = NULL;
    int status = 0;

    stream = fopen(path, "r");
    if (stream == NULL) {
        fprintf(stderr, _("failed to open inject policy file: %s\n"), path);
        return 1;
    }

    while (fgets(line, sizeof(line), stream) != NULL) {
        char *key = NULL;
        char *value = NULL;
        int indent;
        char *trimmed = line;
        const char *content;

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

        if (pending_kind != NULL && indent > 0 && strchr(trimmed, ':') == NULL && trimmed[0] == '-') {
            const char *item = trimmed + 1;

            item = secdat_exec_yaml_skip_spaces(item);
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

        if (pending_kind != NULL) {
            if (secdat_exec_yaml_apply_pentad_tokens(policy, subsection == 1 ? "ambient" : subsection == 2 ? "secret" : "final", pending_kind, &pending) != 0) {
                status = 1;
                goto cleanup;
            }
            secdat_exec_yaml_string_list_free(&pending);
            free(pending_kind);
            pending_kind = NULL;
        }

        if (secdat_exec_yaml_split_key_value(trimmed, &key, &value) != 0) {
            fprintf(stderr, _("invalid inject policy file line: %s\n"), trimmed);
            status = 2;
            goto cleanup;
        }

        if (indent == 0) {
            subsection = 0;
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
            } else if (strcmp(key, "gate") == 0) {
                section = 0;
                status = secdat_exec_apply_inject_gate(policy, value);
                free(key);
                free(value);
                if (status != 0) {
                    goto cleanup;
                }
            } else {
                fprintf(stderr, _("unknown inject policy file section: %s\n"), key);
                status = 2;
                free(key);
                free(value);
                goto cleanup;
            }
            continue;
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

    if (pending_kind != NULL) {
        if (secdat_exec_yaml_apply_pentad_tokens(
                policy,
                subsection == 1 ? "ambient" : subsection == 2 ? "secret" : "final",
                pending_kind,
                &pending) != 0) {
            status = 1;
            goto cleanup;
        }
    }

cleanup:
    secdat_exec_yaml_string_list_free(&pending);
    free(pending_kind);
    fclose(stream);
    return status;
}