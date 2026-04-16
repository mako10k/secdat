#include "domain.h"

#include "i18n.h"

#include "store.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SECDAT_DOMAIN_ID_LEN 32

struct secdat_string_list {
    char **items;
    size_t count;
    size_t capacity;
};

static int secdat_compare_strings(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;

    return strcmp(*left_string, *right_string);
}

static void secdat_string_list_free(struct secdat_string_list *list)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        free(list->items[index]);
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int secdat_string_list_contains(const struct secdat_string_list *list, const char *value)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index], value) == 0) {
            return 1;
        }
    }

    return 0;
}

static int secdat_string_list_append(struct secdat_string_list *list, const char *value)
{
    char **new_items;
    size_t new_capacity;

    if (secdat_string_list_contains(list, value)) {
        return 0;
    }

    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        new_items = realloc(list->items, sizeof(*new_items) * new_capacity);
        if (new_items == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count] = strdup(value);
    if (list->items[list->count] == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    list->count += 1;
    return 0;
}

static int secdat_is_unreserved(unsigned char character)
{
    return isalnum(character) || character == '-' || character == '_' || character == '.';
}

static int secdat_escape_component(const char *input, char **output)
{
    size_t index;
    size_t extra = 0;
    size_t length = strlen(input);
    char *result;
    char *cursor;

    for (index = 0; index < length; index += 1) {
        if (!secdat_is_unreserved((unsigned char)input[index])) {
            extra += 2;
        }
    }

    result = malloc(length + extra + 1);
    if (result == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    cursor = result;
    for (index = 0; index < length; index += 1) {
        if (secdat_is_unreserved((unsigned char)input[index])) {
            *cursor++ = input[index];
            continue;
        }

        snprintf(cursor, 4, "%%%02X", (unsigned char)input[index]);
        cursor += 3;
    }

    *cursor = '\0';
    *output = result;
    return 0;
}

static int secdat_hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int secdat_unescape_component(const char *input, char **output)
{
    size_t length = strlen(input);
    char *result;
    size_t read_index;
    size_t write_index;
    int high;
    int low;

    result = malloc(length + 1);
    if (result == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    read_index = 0;
    write_index = 0;
    while (read_index < length) {
        if (input[read_index] == '%' && read_index + 2 < length) {
            high = secdat_hex_value(input[read_index + 1]);
            low = secdat_hex_value(input[read_index + 2]);
            if (high >= 0 && low >= 0) {
                result[write_index++] = (char)((high << 4) | low);
                read_index += 3;
                continue;
            }
        }

        result[write_index++] = input[read_index++];
    }

    result[write_index] = '\0';
    *output = result;
    return 0;
}

static int secdat_join_path(char *buffer, size_t size, const char *left, const char *right)
{
    int written;

    written = snprintf(buffer, size, "%s/%s", left, right);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_data_home(char *buffer, size_t size)
{
    const char *xdg_data_home = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    int written;

    if (xdg_data_home != NULL && xdg_data_home[0] != '\0') {
        written = snprintf(buffer, size, "%s", xdg_data_home);
    } else if (home != NULL && home[0] != '\0') {
        written = snprintf(buffer, size, "%s/.local/share", home);
    } else {
        fprintf(stderr, _("HOME is not set\n"));
        return 1;
    }

    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_domains_root(char *buffer, size_t size)
{
    char data_home[PATH_MAX];

    if (secdat_data_home(data_home, sizeof(data_home)) != 0) {
        return 1;
    }

    return snprintf(buffer, size, "%s/secdat/domains", data_home) >= (int)size ? 1 : 0;
}

static int secdat_registry_dir(char *buffer, size_t size)
{
    char domains_root[PATH_MAX];

    if (secdat_domains_root(domains_root, sizeof(domains_root)) != 0) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return secdat_join_path(buffer, size, domains_root, "registry/by-root");
}

static int secdat_by_id_root(char *buffer, size_t size)
{
    char domains_root[PATH_MAX];

    if (secdat_domains_root(domains_root, sizeof(domains_root)) != 0) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return secdat_join_path(buffer, size, domains_root, "by-id");
}

static int secdat_registry_path_for_root(const char *root_path, char *buffer, size_t size)
{
    char registry_dir[PATH_MAX];
    char *escaped_root = NULL;
    int status;
    int written;

    status = secdat_registry_dir(registry_dir, sizeof(registry_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(root_path, &escaped_root);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s", registry_dir, escaped_root);
    free(escaped_root);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_domain_root_for_id(const char *domain_id, char *buffer, size_t size)
{
    char by_id_root[PATH_MAX];
    int status;
    int written;

    status = secdat_by_id_root(by_id_root, sizeof(by_id_root));
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s", by_id_root, domain_id);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_ensure_directory(const char *path, mode_t mode)
{
    struct stat status;
    char partial[PATH_MAX];
    size_t index;
    size_t length;

    length = strlen(path);
    if (length == 0 || length >= sizeof(partial)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(partial, path, length + 1);
    for (index = 1; index < length; index += 1) {
        if (partial[index] != '/') {
            continue;
        }

        partial[index] = '\0';
        if (mkdir(partial, mode) != 0 && errno != EEXIST) {
            fprintf(stderr, _("failed to create directory: %s\n"), partial);
            return 1;
        }
        partial[index] = '/';
    }

    if (mkdir(partial, mode) != 0 && errno != EEXIST) {
        fprintf(stderr, _("failed to create directory: %s\n"), partial);
        return 1;
    }

    if (stat(path, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, _("not a directory: %s\n"), path);
        return 1;
    }

    return 0;
}

static int secdat_read_text_file(const char *path, char *buffer, size_t size)
{
    FILE *stream;
    size_t length;

    stream = fopen(path, "rb");
    if (stream == NULL) {
        if (errno == ENOENT) {
            return 1;
        }
        fprintf(stderr, _("failed to open file: %s\n"), path);
        return 2;
    }

    if (fgets(buffer, (int)size, stream) == NULL) {
        fclose(stream);
        fprintf(stderr, _("failed to read file: %s\n"), path);
        return 2;
    }

    fclose(stream);
    length = strlen(buffer);
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r')) {
        buffer[length - 1] = '\0';
        length -= 1;
    }

    return 0;
}

static int secdat_atomic_write_text_file(const char *path, const char *value)
{
    char temporary_path[PATH_MAX];
    int file_descriptor;
    FILE *stream;
    char *slash;
    size_t prefix_length;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        fprintf(stderr, _("invalid path: %s\n"), path);
        return 1;
    }

    prefix_length = (size_t)(slash - path);
    if (prefix_length + strlen("/.tmp.XXXXXX") + 1 >= sizeof(temporary_path)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(temporary_path, path, prefix_length);
    temporary_path[prefix_length] = '\0';
    strcat(temporary_path, "/.tmp.XXXXXX");

    file_descriptor = mkstemp(temporary_path);
    if (file_descriptor < 0) {
        fprintf(stderr, _("failed to create temporary file for: %s\n"), path);
        return 1;
    }

    if (fchmod(file_descriptor, 0600) != 0) {
        fprintf(stderr, _("failed to set permissions on: %s\n"), temporary_path);
        close(file_descriptor);
        unlink(temporary_path);
        return 1;
    }

    stream = fdopen(file_descriptor, "wb");
    if (stream == NULL) {
        close(file_descriptor);
        unlink(temporary_path);
        fprintf(stderr, _("failed to open temporary stream for: %s\n"), path);
        return 1;
    }

    if (fputs(value, stream) == EOF || fflush(stream) != 0 || fsync(file_descriptor) != 0) {
        fclose(stream);
        unlink(temporary_path);
        fprintf(stderr, _("failed to write file: %s\n"), path);
        return 1;
    }

    if (fclose(stream) != 0) {
        unlink(temporary_path);
        fprintf(stderr, _("failed to close file: %s\n"), path);
        return 1;
    }

    if (rename(temporary_path, path) != 0) {
        unlink(temporary_path);
        fprintf(stderr, _("failed to rename file into place: %s\n"), path);
        return 1;
    }

    return 0;
}

static int secdat_canonicalize_directory(const char *input, char *buffer, size_t size)
{
    const char *resolved_input = input == NULL ? "." : input;
    struct stat status;

    if (realpath(resolved_input, buffer) == NULL) {
        fprintf(stderr, _("failed to resolve directory: %s\n"), resolved_input);
        return 1;
    }

    if (strlen(buffer) >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    if (stat(buffer, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fprintf(stderr, _("not a directory: %s\n"), buffer);
        return 1;
    }

    return 0;
}

static void secdat_parent_path(char *path)
{
    char *slash;

    if (strcmp(path, "/") == 0) {
        return;
    }

    slash = strrchr(path, '/');
    if (slash == NULL) {
        strcpy(path, "/");
        return;
    }

    if (slash == path) {
        path[1] = '\0';
    } else {
        *slash = '\0';
    }
}

static int secdat_lookup_domain_id_for_root(const char *root_path, char *buffer, size_t size)
{
    char registry_path[PATH_MAX];
    int status;

    status = secdat_registry_path_for_root(root_path, registry_path, sizeof(registry_path));
    if (status != 0) {
        return status;
    }

    status = secdat_read_text_file(registry_path, buffer, size);
    if (status == 1) {
        return 1;
    }

    return status == 0 ? 0 : 2;
}

int secdat_domain_validate_root(const char *domain_root, char *buffer, size_t size)
{
    char domain_id[PATH_MAX];
    int lookup_status;

    if (secdat_canonicalize_directory(domain_root, buffer, size) != 0) {
        return 1;
    }

    lookup_status = secdat_lookup_domain_id_for_root(buffer, domain_id, sizeof(domain_id));
    if (lookup_status == 0) {
        return 0;
    }
    if (lookup_status == 1) {
        fprintf(stderr, _("domain not found for: %s\n"), buffer);
    }
    return 1;
}

static int secdat_path_is_ancestor_or_same(const char *candidate, const char *base)
{
    size_t candidate_length;

    if (strcmp(candidate, "/") == 0) {
        return 1;
    }

    candidate_length = strlen(candidate);
    if (strncmp(candidate, base, candidate_length) != 0) {
        return 0;
    }

    return base[candidate_length] == '\0' || base[candidate_length] == '/';
}

static int secdat_path_is_descendant_or_same(const char *candidate, const char *base)
{
    size_t base_length;

    if (strcmp(base, "/") == 0) {
        return 1;
    }

    base_length = strlen(base);
    if (strncmp(base, candidate, base_length) != 0) {
        return 0;
    }

    return candidate[base_length] == '\0' || candidate[base_length] == '/';
}

static int secdat_generate_domain_id(char *buffer, size_t size)
{
    unsigned char raw[SECDAT_DOMAIN_ID_LEN / 2];
    size_t index;

    if (size < SECDAT_DOMAIN_ID_LEN + 1) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        fprintf(stderr, _("failed to generate domain id\n"));
        return 1;
    }

    for (index = 0; index < sizeof(raw); index += 1) {
        snprintf(buffer + (index * 2), 3, "%02x", raw[index]);
    }
    buffer[SECDAT_DOMAIN_ID_LEN] = '\0';
    return 0;
}

static int secdat_directory_is_empty(const char *path)
{
    DIR *directory;
    struct dirent *entry;

    directory = opendir(path);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 1;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), path);
        return 0;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            closedir(directory);
            return 0;
        }
    }

    closedir(directory);
    return 1;
}

static int secdat_remove_tree(const char *path)
{
    DIR *directory;
    struct dirent *entry;
    char child_path[PATH_MAX];
    struct stat status;

    directory = opendir(path);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), path);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name) >= (int)sizeof(child_path)) {
            closedir(directory);
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }

        if (lstat(child_path, &status) != 0) {
            closedir(directory);
            fprintf(stderr, _("failed to stat path: %s\n"), child_path);
            return 1;
        }

        if (S_ISDIR(status.st_mode)) {
            if (secdat_remove_tree(child_path) != 0) {
                closedir(directory);
                return 1;
            }
        } else if (unlink(child_path) != 0) {
            closedir(directory);
            fprintf(stderr, _("failed to remove file: %s\n"), child_path);
            return 1;
        }
    }

    closedir(directory);
    if (rmdir(path) != 0) {
        fprintf(stderr, _("failed to remove directory: %s\n"), path);
        return 1;
    }

    return 0;
}

static int secdat_collect_registered_roots(struct secdat_string_list *roots)
{
    DIR *directory;
    struct dirent *entry;
    char registry_dir[PATH_MAX];
    char *decoded_root = NULL;
    int status;

    status = secdat_registry_dir(registry_dir, sizeof(registry_dir));
    if (status != 0) {
        return status;
    }

    directory = opendir(registry_dir);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), registry_dir);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (secdat_unescape_component(entry->d_name, &decoded_root) != 0) {
            closedir(directory);
            return 1;
        }

        if (secdat_string_list_append(roots, decoded_root) != 0) {
            free(decoded_root);
            closedir(directory);
            return 1;
        }

        free(decoded_root);
        decoded_root = NULL;
    }

    closedir(directory);
    qsort(roots->items, roots->count, sizeof(*roots->items), secdat_compare_strings);
    return 0;
}

void secdat_domain_chain_free(struct secdat_domain_chain *chain)
{
    size_t index;

    for (index = 0; index < chain->count; index += 1) {
        free(chain->ids[index]);
    }

    free(chain->ids);
    chain->ids = NULL;
    chain->count = 0;
}

void secdat_domain_root_list_free(struct secdat_domain_root_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }

    for (index = 0; index < list->count; index += 1) {
        free(list->roots[index]);
    }
    free(list->roots);
    list->roots = NULL;
    list->count = 0;
}

int secdat_domain_resolve_current(const char *dir_override, char *buffer, size_t size)
{
    struct secdat_domain_chain chain = {0};
    int status;

    status = secdat_domain_resolve_chain(dir_override, &chain);
    if (status != 0) {
        return status;
    }

    if (chain.count == 0 || strlen(chain.ids[0]) >= size) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    strcpy(buffer, chain.ids[0]);
    secdat_domain_chain_free(&chain);
    return 0;
}

int secdat_domain_resolve_chain(const char *dir_override, struct secdat_domain_chain *chain)
{
    char current_path[PATH_MAX];
    char domain_id[PATH_MAX];
    struct secdat_string_list ids = {0};
    int lookup_status;

    chain->ids = NULL;
    chain->count = 0;

    if (secdat_canonicalize_directory(dir_override, current_path, sizeof(current_path)) != 0) {
        return 1;
    }

    for (;;) {
        lookup_status = secdat_lookup_domain_id_for_root(current_path, domain_id, sizeof(domain_id));
        if (lookup_status == 0) {
            if (secdat_string_list_append(&ids, domain_id) != 0) {
                secdat_string_list_free(&ids);
                return 1;
            }
        } else if (lookup_status != 1) {
            secdat_string_list_free(&ids);
            return 1;
        }

        if (strcmp(current_path, "/") == 0) {
            break;
        }
        secdat_parent_path(current_path);
    }

    if (secdat_string_list_append(&ids, "default") != 0) {
        secdat_string_list_free(&ids);
        return 1;
    }

    chain->ids = ids.items;
    chain->count = ids.count;
    return 0;
}

int secdat_domain_root_path(const char *domain_id, char *buffer, size_t size)
{
    char domain_root[PATH_MAX];
    char meta_dir[PATH_MAX];
    char root_file[PATH_MAX];
    int status;

    if (strcmp(domain_id, "default") == 0) {
        if (size == 0) {
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }
        buffer[0] = '\0';
        return 0;
    }

    status = secdat_domain_root_for_id(domain_id, domain_root, sizeof(domain_root));
    if (status != 0) {
        return status;
    }
    if (secdat_join_path(meta_dir, sizeof(meta_dir), domain_root, "meta") != 0) {
        return 1;
    }
    if (secdat_join_path(root_file, sizeof(root_file), meta_dir, "root") != 0) {
        return 1;
    }

    status = secdat_read_text_file(root_file, buffer, size);
    if (status != 0) {
        fprintf(stderr, _("failed to read file: %s\n"), root_file);
        return 1;
    }

    return 0;
}

int secdat_collect_descendant_domain_roots(const char *root_path, struct secdat_domain_root_list *list)
{
    struct secdat_string_list roots = {0};
    struct secdat_string_list descendants = {0};
    char canonical_root[PATH_MAX];
    size_t index;

    list->roots = NULL;
    list->count = 0;

    if (secdat_canonicalize_directory(root_path, canonical_root, sizeof(canonical_root)) != 0) {
        return 1;
    }
    if (secdat_collect_registered_roots(&roots) != 0) {
        secdat_string_list_free(&roots);
        return 1;
    }

    for (index = 0; index < roots.count; index += 1) {
        if (!secdat_path_is_descendant_or_same(roots.items[index], canonical_root)) {
            continue;
        }
        if (secdat_string_list_append(&descendants, roots.items[index]) != 0) {
            secdat_string_list_free(&roots);
            secdat_string_list_free(&descendants);
            return 1;
        }
    }

    secdat_string_list_free(&roots);
    list->roots = descendants.items;
    list->count = descendants.count;
    return 0;
}

int secdat_domain_data_root(const char *domain_id, char *buffer, size_t size)
{
    if (strcmp(domain_id, "default") == 0) {
        if (size == 0) {
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }
        buffer[0] = '\0';
        return 0;
    }

    return secdat_domain_root_for_id(domain_id, buffer, size);
}

int secdat_domain_store_root(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char domain_root[PATH_MAX];
    char *escaped_store = NULL;
    const char *resolved_store = store_name == NULL ? "default" : store_name;
    int status;
    int written;

    status = secdat_domain_root_for_id(domain_id, domain_root, sizeof(domain_root));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(resolved_store, &escaped_store);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/stores/%s", domain_root, escaped_store);
    free(escaped_store);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_domain_create_default_store(const char *domain_id)
{
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];

    if (secdat_domain_store_root(domain_id, NULL, store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    if (secdat_join_path(entries_dir, sizeof(entries_dir), store_root, "entries") != 0) {
        return 1;
    }
    if (secdat_join_path(tombstones_dir, sizeof(tombstones_dir), store_root, "tombstones") != 0) {
        return 1;
    }

    if (secdat_ensure_directory(entries_dir, 0700) != 0) {
        return 1;
    }
    return secdat_ensure_directory(tombstones_dir, 0700);
}

static int secdat_domain_command_create(const struct secdat_cli *cli)
{
    char root_path[PATH_MAX];
    char registry_dir[PATH_MAX];
    char registry_path[PATH_MAX];
    char domain_id[SECDAT_DOMAIN_ID_LEN + 1];
    char domain_root[PATH_MAX];
    char meta_dir[PATH_MAX];
    char root_file[PATH_MAX];
    char existing_id[PATH_MAX];
    int lookup_status;

    if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for domain create\n"));
        secdat_cli_print_try_help(cli, "domain");
        return 2;
    }

    if (secdat_canonicalize_directory(cli->domain != NULL ? cli->domain : cli->dir, root_path, sizeof(root_path)) != 0) {
        return 1;
    }

    lookup_status = secdat_lookup_domain_id_for_root(root_path, existing_id, sizeof(existing_id));
    if (lookup_status == 0) {
        fprintf(stderr, _("domain already exists for: %s\n"), root_path);
        return 1;
    }
    if (lookup_status != 1) {
        return 1;
    }

    if (secdat_generate_domain_id(domain_id, sizeof(domain_id)) != 0) {
        return 1;
    }
    if (secdat_registry_path_for_root(root_path, registry_path, sizeof(registry_path)) != 0) {
        return 1;
    }
    if (secdat_registry_dir(registry_dir, sizeof(registry_dir)) != 0) {
        return 1;
    }
    if (secdat_domain_root_for_id(domain_id, domain_root, sizeof(domain_root)) != 0) {
        return 1;
    }
    if (secdat_join_path(meta_dir, sizeof(meta_dir), domain_root, "meta") != 0) {
        return 1;
    }
    if (secdat_join_path(root_file, sizeof(root_file), meta_dir, "root") != 0) {
        return 1;
    }

    if (secdat_ensure_directory(registry_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_ensure_directory(meta_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_domain_create_default_store(domain_id) != 0) {
        return 1;
    }
    if (secdat_atomic_write_text_file(root_file, root_path) != 0) {
        return 1;
    }
    return secdat_atomic_write_text_file(registry_path, domain_id);
}

static int secdat_domain_command_delete(const struct secdat_cli *cli)
{
    char root_path[PATH_MAX];
    char domain_id[PATH_MAX];
    char registry_path[PATH_MAX];
    char domain_root[PATH_MAX];
    struct secdat_string_list roots = {0};
    size_t index;

    if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for domain delete\n"));
        secdat_cli_print_try_help(cli, "domain");
        return 2;
    }

    if (secdat_canonicalize_directory(cli->domain != NULL ? cli->domain : cli->dir, root_path, sizeof(root_path)) != 0) {
        return 1;
    }

    if (secdat_lookup_domain_id_for_root(root_path, domain_id, sizeof(domain_id)) != 0) {
        fprintf(stderr, _("domain not found for: %s\n"), root_path);
        return 1;
    }

    if (secdat_collect_registered_roots(&roots) != 0) {
        secdat_string_list_free(&roots);
        return 1;
    }

    for (index = 0; index < roots.count; index += 1) {
        if (strcmp(roots.items[index], root_path) != 0 && secdat_path_is_descendant_or_same(roots.items[index], root_path)) {
            fprintf(stderr, _("cannot delete domain with child domains: %s\n"), root_path);
            secdat_string_list_free(&roots);
            return 1;
        }
    }
    secdat_string_list_free(&roots);

    if (secdat_registry_path_for_root(root_path, registry_path, sizeof(registry_path)) != 0) {
        return 1;
    }
    if (unlink(registry_path) != 0) {
        fprintf(stderr, _("failed to remove file: %s\n"), registry_path);
        return 1;
    }

    if (secdat_domain_root_for_id(domain_id, domain_root, sizeof(domain_root)) != 0) {
        return 1;
    }

    return secdat_remove_tree(domain_root);
}

static int secdat_domain_command_ls(const struct secdat_cli *cli)
{
    struct secdat_string_list roots = {0};
    struct secdat_domain_status_summary summary;
    const char *pattern = NULL;
    const char *key_source;
    const char *state_source;
    char scope_base[PATH_MAX];
    char *state_source_owned = NULL;
    size_t index;
    int include_ancestors = 0;
    int include_descendants = 0;
    int long_format = 0;

    for (index = 0; index < (size_t)cli->argc; index += 1) {
        if (strcmp(cli->argv[index], "-l") == 0 || strcmp(cli->argv[index], "--long") == 0) {
            long_format = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--ancestors") == 0) {
            include_ancestors = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--descendants") == 0) {
            include_descendants = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--pattern") == 0) {
            if (index + 1 >= (size_t)cli->argc) {
                fprintf(stderr, _("invalid arguments for domain ls\n"));
                secdat_cli_print_try_help(cli, "domain");
                return 2;
            }
            pattern = cli->argv[index + 1];
            index += 1;
            continue;
        }
        if (cli->argv[index][0] != '-' && pattern == NULL) {
            pattern = cli->argv[index];
            continue;
        }

        fprintf(stderr, _("invalid arguments for domain ls\n"));
        secdat_cli_print_try_help(cli, "domain");
        return 2;
    }

    if (!include_ancestors && !include_descendants) {
        include_ancestors = 1;
        include_descendants = 1;
    }

    if (secdat_canonicalize_directory(cli->domain != NULL ? cli->domain : cli->dir, scope_base, sizeof(scope_base)) != 0) {
        return 1;
    }

    if (secdat_collect_registered_roots(&roots) != 0) {
        secdat_string_list_free(&roots);
        return 1;
    }

    if (long_format) {
        printf(_("DOMAIN\tKEY_SOURCE\tEFFECTIVE\tSTATE_SOURCE\tSTORES\tVISIBLE\tWRAPPED\n"));
    }

    for (index = 0; index < roots.count; index += 1) {
        int matches_ancestor = secdat_path_is_ancestor_or_same(roots.items[index], scope_base);
        int matches_descendant = secdat_path_is_descendant_or_same(roots.items[index], scope_base);

        if ((include_ancestors == 0 || matches_ancestor == 0)
            && (include_descendants == 0 || matches_descendant == 0)) {
            continue;
        }
        if (pattern != NULL && fnmatch(pattern, roots.items[index], 0) != 0) {
            continue;
        }

        if (!long_format) {
            puts(roots.items[index]);
            continue;
        }

        if (secdat_collect_domain_status_summary(roots.items[index], &summary) != 0) {
            secdat_string_list_free(&roots);
            return 1;
        }

        switch (summary.key_source) {
        case SECDAT_KEY_SOURCE_ENVIRONMENT:
            key_source = _("environment");
            break;
        case SECDAT_KEY_SOURCE_SESSION:
            key_source = _("session");
            break;
        default:
            key_source = _("locked");
            break;
        }
        switch (summary.effective_source) {
        case SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT:
            state_source = _("environment");
            break;
        case SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION:
            state_source = _("local-session");
            break;
        case SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION:
            state_source_owned = malloc(strlen("inherited:") + strlen(summary.related_domain_root) + 1);
            if (state_source_owned == NULL) {
                fprintf(stderr, _("out of memory\n"));
                secdat_string_list_free(&roots);
                return 1;
            }
            sprintf(state_source_owned, "inherited:%s", summary.related_domain_root);
            state_source = state_source_owned;
            break;
        case SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK:
            state_source = _("explicit-lock");
            break;
        case SECDAT_EFFECTIVE_SOURCE_BLOCKED:
            state_source_owned = malloc(strlen("blocked:") + strlen(summary.related_domain_root) + 1);
            if (state_source_owned == NULL) {
                fprintf(stderr, _("out of memory\n"));
                secdat_string_list_free(&roots);
                return 1;
            }
            sprintf(state_source_owned, "blocked:%s", summary.related_domain_root);
            state_source = state_source_owned;
            break;
        default:
            state_source = _("locked");
            break;
        }
        printf("%s\t%s\t%s\t%s\t%zu\t%zu\t%s\n",
            roots.items[index],
            key_source,
            summary.effective_source == SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK
                || summary.effective_source == SECDAT_EFFECTIVE_SOURCE_BLOCKED
                || summary.effective_source == SECDAT_EFFECTIVE_SOURCE_LOCKED
                ? _("locked")
                : _("unlocked"),
            state_source,
            summary.store_count,
            summary.visible_key_count,
            summary.wrapped_master_key_present ? _("present") : _("absent"));
            free(state_source_owned);
            state_source_owned = NULL;
    }

    secdat_string_list_free(&roots);
    return 0;
}

static int secdat_domain_command_status(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_domain_status_summary summary;
    char domain_root[PATH_MAX];
    int quiet = 0;

    if (cli->argc == 1 && (strcmp(cli->argv[0], "--quiet") == 0 || strcmp(cli->argv[0], "-q") == 0)) {
        quiet = 1;
    } else if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for domain status\n"));
        secdat_cli_print_try_help(cli, "domain");
        return 2;
    }

    if (secdat_domain_resolve_chain(cli->domain != NULL ? cli->domain : cli->dir, &chain) != 0) {
        return 1;
    }
    if (chain.count == 0) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    if (secdat_domain_root_path(chain.ids[0], domain_root, sizeof(domain_root)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    secdat_domain_chain_free(&chain);

    if (secdat_collect_domain_status_summary(cli->domain != NULL ? cli->domain : cli->dir, &summary) != 0) {
        return 1;
    }

    if (quiet) {
        puts(domain_root[0] != '\0' ? domain_root : "default");
        return 0;
    }

    printf(_("resolved domain: %s\n"), domain_root[0] != '\0' ? domain_root : "default");
    printf(_("resolution source: %s\n"), cli->domain != NULL ? "--domain" : (cli->dir != NULL ? "--dir" : "current working directory"));
    printf(_("store count: %zu\n"), summary.store_count);
    printf(_("visible key count: %zu\n"), summary.visible_key_count);
    switch (summary.key_source) {
    case SECDAT_KEY_SOURCE_ENVIRONMENT:
        puts(_("key source: environment"));
        break;
    case SECDAT_KEY_SOURCE_SESSION:
        puts(_("key source: session agent"));
        printf(_("expires in: %lld seconds\n"), (long long)(summary.session_expires_at - time(NULL)));
        break;
    default:
        puts(_("key source: locked"));
        break;
    }
    switch (summary.effective_source) {
    case SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT:
        puts(_("effective state: unlocked"));
        puts(_("effective source: environment"));
        break;
    case SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION:
        puts(_("effective state: unlocked"));
        puts(_("effective source: local session"));
        break;
    case SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION:
        puts(_("effective state: unlocked"));
        puts(_("effective source: inherited session"));
        printf(_("inherited from: %s\n"), summary.related_domain_root);
        break;
    case SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK:
        puts(_("effective state: locked"));
        puts(_("effective source: explicit lock"));
        break;
    case SECDAT_EFFECTIVE_SOURCE_BLOCKED:
        puts(_("effective state: locked"));
        puts(_("effective source: blocked by explicit lock"));
        printf(_("blocked by: %s\n"), summary.related_domain_root);
        break;
    default:
        puts(_("effective state: locked"));
        puts(_("effective source: locked"));
        break;
    }
    puts(summary.wrapped_master_key_present ? _("wrapped master key: present") : _("wrapped master key: absent"));
    return 0;
}

int secdat_handle_domain_command(const struct secdat_cli *cli)
{
    switch (cli->command) {
    case SECDAT_COMMAND_DOMAIN_CREATE:
        return secdat_domain_command_create(cli);
    case SECDAT_COMMAND_DOMAIN_DELETE:
        return secdat_domain_command_delete(cli);
    case SECDAT_COMMAND_DOMAIN_LS:
        return secdat_domain_command_ls(cli);
    case SECDAT_COMMAND_DOMAIN_STATUS:
        return secdat_domain_command_status(cli);
    default:
        fprintf(stderr, _("command not implemented yet: %s\n"), secdat_cli_command_name(cli->command));
        return 1;
    }
}