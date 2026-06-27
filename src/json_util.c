#define _GNU_SOURCE

#include "json_util.h"

#include <stdio.h>
#include <stdlib.h>

static size_t secdat_json_valid_utf8_sequence_length(const unsigned char *cursor)
{
    unsigned char first = cursor[0];

    if (first < 0x80) {
        return 1;
    }
    if (first >= 0xc2 && first <= 0xdf) {
        return (cursor[1] & 0xc0) == 0x80 ? 2 : 0;
    }
    if (first == 0xe0) {
        return cursor[1] >= 0xa0 && cursor[1] <= 0xbf
                && (cursor[2] & 0xc0) == 0x80
            ? 3
            : 0;
    }
    if (first >= 0xe1 && first <= 0xec) {
        return (cursor[1] & 0xc0) == 0x80 && (cursor[2] & 0xc0) == 0x80 ? 3 : 0;
    }
    if (first == 0xed) {
        return cursor[1] >= 0x80 && cursor[1] <= 0x9f
                && (cursor[2] & 0xc0) == 0x80
            ? 3
            : 0;
    }
    if (first >= 0xee && first <= 0xef) {
        return (cursor[1] & 0xc0) == 0x80 && (cursor[2] & 0xc0) == 0x80 ? 3 : 0;
    }
    if (first == 0xf0) {
        return cursor[1] >= 0x90 && cursor[1] <= 0xbf
                && (cursor[2] & 0xc0) == 0x80
                && (cursor[3] & 0xc0) == 0x80
            ? 4
            : 0;
    }
    if (first >= 0xf1 && first <= 0xf3) {
        return (cursor[1] & 0xc0) == 0x80
                && (cursor[2] & 0xc0) == 0x80
                && (cursor[3] & 0xc0) == 0x80
            ? 4
            : 0;
    }
    if (first == 0xf4) {
        return cursor[1] >= 0x80 && cursor[1] <= 0x8f
                && (cursor[2] & 0xc0) == 0x80
                && (cursor[3] & 0xc0) == 0x80
            ? 4
            : 0;
    }

    return 0;
}

static void secdat_write_json_string_fallback(FILE *stream, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)(value != NULL ? value : "");

    fputc('"', stream);
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"':
            fputs("\\\"", stream);
            break;
        case '\\':
            fputs("\\\\", stream);
            break;
        case '\b':
            fputs("\\b", stream);
            break;
        case '\f':
            fputs("\\f", stream);
            break;
        case '\n':
            fputs("\\n", stream);
            break;
        case '\r':
            fputs("\\r", stream);
            break;
        case '\t':
            fputs("\\t", stream);
            break;
        default:
            if (*cursor < 0x20) {
                fprintf(stream, "\\u%04x", (unsigned int)*cursor);
            } else {
                size_t sequence_length = secdat_json_valid_utf8_sequence_length(cursor);

                if (sequence_length == 0) {
                    fprintf(stream, "\\u%04x", (unsigned int)*cursor);
                } else {
                    fwrite(cursor, 1, sequence_length, stream);
                    cursor += sequence_length - 1;
                }
            }
            break;
        }
        cursor += 1;
    }
    fputc('"', stream);
}

void secdat_write_json_string(FILE *stream, const char *value)
{
    json_t *string;
    char *encoded;

    string = json_string(value != NULL ? value : "");
    if (string == NULL) {
        secdat_write_json_string_fallback(stream, value != NULL ? value : "");
        return;
    }
    encoded = json_dumps(string, JSON_ENCODE_ANY | JSON_COMPACT);
    json_decref(string);
    if (encoded == NULL) {
        secdat_write_json_string_fallback(stream, value != NULL ? value : "");
        return;
    }
    fputs(encoded, stream);
    free(encoded);
}

int secdat_json_dump(FILE *stream, json_t *root)
{
    if (root == NULL) {
        return -1;
    }
    if (json_dumpf(root, stream, JSON_INDENT(2)) != 0) {
        return -1;
    }
    fputc('\n', stream);
    return 0;
}

json_t *secdat_json_string_array(char **items, size_t count)
{
    json_t *array = json_array();
    size_t index;

    if (array == NULL) {
        return NULL;
    }
    for (index = 0; index < count; index += 1) {
        if (json_array_append_new(array, json_string(items[index])) != 0) {
            json_decref(array);
            return NULL;
        }
    }
    return array;
}