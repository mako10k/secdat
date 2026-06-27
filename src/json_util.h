#ifndef SECDAT_JSON_UTIL_H
#define SECDAT_JSON_UTIL_H

#include <jansson.h>
#include <stdio.h>

void secdat_write_json_string(FILE *stream, const char *value);
int secdat_json_dump(FILE *stream, json_t *root);
json_t *secdat_json_string_array(char **items, size_t count);

#endif