#include "store.h"

#include "domain.h"

#include "i18n.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SECDAT_ENTRY_VERSION 1
#define SECDAT_ENTRY_ALGORITHM_PLAINTEXT 1
#define SECDAT_ENTRY_ALGORITHM_AES_256_GCM 2
#define SECDAT_NONCE_LEN 12
#define SECDAT_TAG_LEN 16
#define SECDAT_HEADER_LEN 16
#define SECDAT_BUNDLE_HEADER_LEN 20
#define SECDAT_MASTER_KEY_RANDOM_BYTES 32
#define SECDAT_SESSION_IDLE_SECONDS 1800
#define SECDAT_WRAP_SALT_LEN 16
#define SECDAT_WRAP_HEADER_LEN 20
#define SECDAT_WRAP_PBKDF2_ITERATIONS 200000
#define SECDAT_AGENT_CONNECT_RETRIES 50
#define SECDAT_SESSION_IDLE_ENV "SECDAT_SESSION_IDLE_SECONDS"

static const unsigned char secdat_entry_magic[8] = {'S', 'E', 'C', 'D', 'A', 'T', '1', '\0'};
static const unsigned char secdat_wrapped_key_magic[8] = {'S', 'E', 'C', 'D', 'W', 'R', 'P', '\0'};
static const unsigned char secdat_bundle_magic[8] = {'S', 'E', 'C', 'D', 'B', 'N', 'D', 'L'};

struct secdat_key_list {
    char **items;
    size_t count;
    size_t capacity;
};

struct secdat_key_reference {
    char key[PATH_MAX];
    char domain[PATH_MAX];
    char store[PATH_MAX];
    const char *domain_value;
    const char *store_value;
};

struct secdat_ls_options {
    struct secdat_key_list include_patterns;
    struct secdat_key_list exclude_patterns;
    int canonical_domain;
    int canonical_store;
};

struct secdat_exec_options {
    struct secdat_key_list include_patterns;
    struct secdat_key_list exclude_patterns;
    size_t command_index;
};

struct secdat_list_options {
    int masked;
    int overridden;
    int orphaned;
};

struct secdat_session_record {
    char master_key[512];
    time_t expires_at;
};

struct secdat_wrapped_master_key {
    uint32_t iterations;
    unsigned char salt[SECDAT_WRAP_SALT_LEN];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char *ciphertext;
    size_t ciphertext_length;
};

struct secdat_secret_bundle {
    uint32_t iterations;
    unsigned char salt[SECDAT_WRAP_SALT_LEN];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char *ciphertext;
    size_t ciphertext_length;
};

static void secdat_write_be32(unsigned char *buffer, uint32_t value);
static uint32_t secdat_read_be32(const unsigned char *buffer);
static int secdat_collect_visible_keys(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_key_list *include_patterns,
    const struct secdat_key_list *exclude_patterns,
    struct secdat_key_list *visible_keys
);
static int secdat_load_resolved_plaintext(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    unsigned char **plaintext,
    size_t *plaintext_length,
    size_t *resolved_index,
    int *unsafe_store
);

static void secdat_secure_clear(void *buffer, size_t length)
{
    if (buffer != NULL && length > 0) {
        OPENSSL_cleanse(buffer, length);
    }
}

static void secdat_key_list_free(struct secdat_key_list *list)
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
    list->capacity = 0;
}

static int secdat_key_list_contains(const struct secdat_key_list *list, const char *value)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index], value) == 0) {
            return 1;
        }
    }

    return 0;
}

static int secdat_key_list_append(struct secdat_key_list *list, const char *value)
{
    char **new_items;
    size_t new_capacity;

    if (secdat_key_list_contains(list, value)) {
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

static int secdat_compare_strings(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;

    return strcmp(*left_string, *right_string);
}

static int secdat_copy_string(char *buffer, size_t size, const char *value)
{
    size_t length = strlen(value);

    if (length >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(buffer, value, length + 1);
    return 0;
}

static int secdat_canonicalize_directory_path(const char *input, char *buffer, size_t size)
{
    const char *resolved_input = input == NULL ? "." : input;

    if (realpath(resolved_input, buffer) == NULL) {
        fprintf(stderr, _("failed to resolve directory: %s\n"), resolved_input);
        return 1;
    }

    if (strlen(buffer) >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_parse_key_reference(
    const char *raw,
    const char *fallback_dir,
    const char *fallback_store,
    struct secdat_key_reference *reference
)
{
    const char *store_separator;
    const char *key_separator;
    size_t base_length;
    size_t key_length;

    memset(reference, 0, sizeof(*reference));
    reference->domain_value = fallback_dir;
    reference->store_value = fallback_store;

    store_separator = strrchr(raw, ':');
    if (store_separator != NULL) {
        if (store_separator[1] == '\0') {
            fprintf(stderr, _("invalid key reference: %s\n"), raw);
            return 1;
        }
        if (secdat_copy_string(reference->store, sizeof(reference->store), store_separator + 1) != 0) {
            return 1;
        }
        reference->store_value = reference->store;
        base_length = (size_t)(store_separator - raw);
    } else {
        base_length = strlen(raw);
    }

    if (raw[0] == '/') {
        key_separator = raw;
        while (key_separator != NULL) {
            const char *next_separator = memchr(key_separator + 1, '/', base_length - (size_t)(key_separator + 1 - raw));

            if (next_separator == NULL) {
                break;
            }
            key_separator = next_separator;
        }

        if (key_separator == raw || (size_t)(key_separator - raw) >= base_length) {
            fprintf(stderr, _("invalid key reference: %s\n"), raw);
            return 1;
        }

        key_length = base_length - (size_t)(key_separator + 1 - raw);
        if ((size_t)(key_separator - raw) >= sizeof(reference->domain)) {
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }

        memcpy(reference->domain, raw, (size_t)(key_separator - raw));
        reference->domain[key_separator - raw] = '\0';
        reference->domain_value = reference->domain;

        memcpy(reference->key, key_separator + 1, key_length);
        reference->key[key_length] = '\0';
    } else {
        if (memchr(raw, '/', base_length) != NULL) {
            fprintf(stderr, _("invalid key reference: %s\n"), raw);
            return 1;
        }
        key_length = base_length;
        memcpy(reference->key, raw, key_length);
        reference->key[key_length] = '\0';
    }

    if (key_length == 0 || key_length >= sizeof(reference->key)) {
        fprintf(stderr, _("invalid key reference: %s\n"), raw);
        return 1;
    }
    return 0;
}

static const char *secdat_effective_store_name(const char *store_name)
{
    return store_name == NULL ? "default" : store_name;
}

static int secdat_parse_ls_options(const struct secdat_cli *cli, struct secdat_ls_options *options)
{
    int index;

    memset(options, 0, sizeof(*options));

    for (index = 0; index < cli->argc; index += 1) {
        if (strcmp(cli->argv[index], "--pattern") == 0 || strcmp(cli->argv[index], "-p") == 0) {
            if (index + 1 >= cli->argc) {
                fprintf(stderr, _("invalid arguments for ls\n"));
                return 2;
            }
            if (secdat_key_list_append(&options->include_patterns, cli->argv[index + 1]) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            index += 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--pattern-exclude") == 0) {
            if (index + 1 >= cli->argc) {
                fprintf(stderr, _("invalid arguments for ls\n"));
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 2;
            }
            if (secdat_key_list_append(&options->exclude_patterns, cli->argv[index + 1]) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            index += 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--canonical") == 0 || strcmp(cli->argv[index], "-c") == 0) {
            options->canonical_domain = 1;
            options->canonical_store = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--canonical-domain") == 0 || strcmp(cli->argv[index], "-D") == 0) {
            options->canonical_domain = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--canonical-store") == 0 || strcmp(cli->argv[index], "-S") == 0) {
            options->canonical_store = 1;
            continue;
        }
        if (cli->argv[index][0] == '-') {
            fprintf(stderr, _("invalid arguments for ls\n"));
            secdat_key_list_free(&options->include_patterns);
            secdat_key_list_free(&options->exclude_patterns);
            return 2;
        }
        if (secdat_key_list_append(&options->include_patterns, cli->argv[index]) != 0) {
            secdat_key_list_free(&options->include_patterns);
            secdat_key_list_free(&options->exclude_patterns);
            return 1;
        }
    }

    return 0;
}

static int secdat_parse_exec_options(const struct secdat_cli *cli, struct secdat_exec_options *options)
{
    size_t index;

    memset(options, 0, sizeof(*options));

    for (index = 0; index < (size_t)cli->argc; ) {
        if (strcmp(cli->argv[index], "--pattern") == 0 || strcmp(cli->argv[index], "-p") == 0) {
            if (index + 1 >= (size_t)cli->argc) {
                fprintf(stderr, _("invalid arguments for exec\n"));
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 2;
            }
            if (secdat_key_list_append(&options->include_patterns, cli->argv[index + 1]) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            index += 2;
            continue;
        }
        if (strcmp(cli->argv[index], "--pattern-exclude") == 0) {
            if (index + 1 >= (size_t)cli->argc) {
                fprintf(stderr, _("invalid arguments for exec\n"));
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 2;
            }
            if (secdat_key_list_append(&options->exclude_patterns, cli->argv[index + 1]) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            index += 2;
            continue;
        }
        break;
    }

    options->command_index = index;
    if (options->command_index >= (size_t)cli->argc) {
        fprintf(stderr, _("invalid arguments for exec\n"));
        secdat_key_list_free(&options->include_patterns);
        secdat_key_list_free(&options->exclude_patterns);
        return 2;
    }

    return 0;
}

static int secdat_parse_list_options(const struct secdat_cli *cli, struct secdat_list_options *options)
{
    size_t index;

    memset(options, 0, sizeof(*options));
    for (index = 0; index < (size_t)cli->argc; index += 1) {
        if (strcmp(cli->argv[index], "--masked") == 0) {
            options->masked = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--overridden") == 0) {
            options->overridden = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--orphaned") == 0) {
            options->orphaned = 1;
            continue;
        }
        fprintf(stderr, _("invalid arguments for list\n"));
        secdat_cli_print_try_help(cli, "list");
        return 2;
    }

    if (!options->masked && !options->overridden && !options->orphaned) {
        fprintf(stderr, _("missing state filter for list\n"));
        secdat_cli_print_try_help(cli, "list");
        return 2;
    }

    return 0;
}

static int secdat_parse_simple_ls_pattern(const struct secdat_cli *cli, const char *command_name, const char **pattern)
{
    if (cli->argc == 2 && (strcmp(cli->argv[0], "--pattern") == 0 || strcmp(cli->argv[0], "-p") == 0)) {
        *pattern = cli->argv[1];
        return 0;
    }
    if (cli->argc == 1 && cli->argv[0][0] != '-') {
        *pattern = cli->argv[0];
        return 0;
    }
    if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for %s\n"), command_name);
        return 2;
    }

    *pattern = NULL;
    return 0;
}

static int secdat_format_canonical_key(
    char *buffer,
    size_t size,
    const char *key,
    const char *domain,
    const char *store,
    int include_domain,
    int include_store
)
{
    int written;
    const char *domain_separator = "";

    if (include_domain && domain != NULL && domain[0] != '\0' && domain[strlen(domain) - 1] != '/') {
        domain_separator = "/";
    }

    written = snprintf(
        buffer,
        size,
        "%s%s%s%s%s",
        include_domain && domain != NULL && domain[0] != '\0' ? domain : "",
        include_domain && domain != NULL && domain[0] != '\0' ? domain_separator : "",
        key,
        include_store ? ":" : "",
        include_store ? store : ""
    );
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

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

static int secdat_store_root(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    return secdat_domain_store_root(domain_id, store_name, buffer, size);
}

static int secdat_store_entries_dir(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];
    int status;

    status = secdat_store_root(domain_id, store_name, store_root, sizeof(store_root));
    if (status != 0) {
        return status;
    }

    return secdat_join_path(buffer, size, store_root, "entries");
}

static int secdat_store_tombstones_dir(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];
    int status;

    status = secdat_store_root(domain_id, store_name, store_root, sizeof(store_root));
    if (status != 0) {
        return status;
    }

    return secdat_join_path(buffer, size, store_root, "tombstones");
}

static int secdat_build_entry_path(const char *domain_id, const char *store_name, const char *key, char *buffer, size_t size)
{
    char entries_dir[PATH_MAX];
    char *escaped_key = NULL;
    int status;
    int written;

    status = secdat_store_entries_dir(domain_id, store_name, entries_dir, sizeof(entries_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(key, &escaped_key);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s.sec", entries_dir, escaped_key);
    free(escaped_key);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_build_tombstone_path(const char *domain_id, const char *store_name, const char *key, char *buffer, size_t size)
{
    char tombstones_dir[PATH_MAX];
    char *escaped_key = NULL;
    int status;
    int written;

    status = secdat_store_tombstones_dir(domain_id, store_name, tombstones_dir, sizeof(tombstones_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_escape_component(key, &escaped_key);
    if (status != 0) {
        return status;
    }

    written = snprintf(buffer, size, "%s/%s.tomb", tombstones_dir, escaped_key);
    free(escaped_key);
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

static int secdat_ensure_store_dirs(const char *domain_id, const char *store_name)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    int status;

    status = secdat_store_entries_dir(domain_id, store_name, entries_dir, sizeof(entries_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_store_tombstones_dir(domain_id, store_name, tombstones_dir, sizeof(tombstones_dir));
    if (status != 0) {
        return status;
    }

    status = secdat_ensure_directory(entries_dir, 0700);
    if (status != 0) {
        return status;
    }

    return secdat_ensure_directory(tombstones_dir, 0700);
}

static int secdat_file_exists(const char *path)
{
    struct stat status;

    return stat(path, &status) == 0 && S_ISREG(status.st_mode);
}

static int secdat_remove_if_exists(const char *path)
{
    if (unlink(path) == 0 || errno == ENOENT) {
        return 0;
    }

    fprintf(stderr, _("failed to remove file: %s\n"), path);
    return 1;
}

static int secdat_atomic_write_file(const char *path, const unsigned char *data, size_t length)
{
    char temporary_path[PATH_MAX];
    int file_descriptor;
    size_t offset;
    ssize_t written;
    char *slash;

    slash = strrchr(path, '/');
    if (slash == NULL) {
        fprintf(stderr, _("invalid path: %s\n"), path);
        return 1;
    }

    if ((size_t)(slash - path) + strlen("/.tmp.XXXXXX") + 1 >= sizeof(temporary_path)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    memcpy(temporary_path, path, (size_t)(slash - path));
    temporary_path[slash - path] = '\0';
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

    offset = 0;
    while (offset < length) {
        written = write(file_descriptor, data + offset, length - offset);
        if (written <= 0) {
            fprintf(stderr, _("failed to write file: %s\n"), temporary_path);
            close(file_descriptor);
            unlink(temporary_path);
            return 1;
        }
        offset += (size_t)written;
    }

    if (fsync(file_descriptor) != 0) {
        fprintf(stderr, _("failed to fsync file: %s\n"), temporary_path);
        close(file_descriptor);
        unlink(temporary_path);
        return 1;
    }

    if (close(file_descriptor) != 0) {
        fprintf(stderr, _("failed to close file: %s\n"), temporary_path);
        unlink(temporary_path);
        return 1;
    }

    if (rename(temporary_path, path) != 0) {
        fprintf(stderr, _("failed to rename file into place: %s\n"), path);
        unlink(temporary_path);
        return 1;
    }

    return 0;
}

static int secdat_read_file(const char *path, unsigned char **data, size_t *length)
{
    FILE *stream;
    long size;
    unsigned char *buffer;

    stream = fopen(path, "rb");
    if (stream == NULL) {
        fprintf(stderr, _("failed to open file: %s\n"), path);
        return 1;
    }

    if (fseek(stream, 0, SEEK_END) != 0) {
        fclose(stream);
        fprintf(stderr, _("failed to seek file: %s\n"), path);
        return 1;
    }

    size = ftell(stream);
    if (size < 0) {
        fclose(stream);
        fprintf(stderr, _("failed to determine file size: %s\n"), path);
        return 1;
    }

    if (fseek(stream, 0, SEEK_SET) != 0) {
        fclose(stream);
        fprintf(stderr, _("failed to seek file: %s\n"), path);
        return 1;
    }

    buffer = malloc((size_t)size);
    if (buffer == NULL && size > 0) {
        fclose(stream);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    if (size > 0 && fread(buffer, 1, (size_t)size, stream) != (size_t)size) {
        fclose(stream);
        free(buffer);
        fprintf(stderr, _("failed to read file: %s\n"), path);
        return 1;
    }

    fclose(stream);
    *data = buffer;
    *length = (size_t)size;
    return 0;
}

static int secdat_runtime_dir(char *buffer, size_t size)
{
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *tmp_dir = getenv("TMPDIR");
    int written;

    if (runtime_dir != NULL && runtime_dir[0] != '\0') {
        written = snprintf(buffer, size, "%s/secdat", runtime_dir);
    } else if (tmp_dir != NULL && tmp_dir[0] != '\0') {
        written = snprintf(buffer, size, "%s/secdat-%ld", tmp_dir, (long)getuid());
    } else {
        written = snprintf(buffer, size, "/tmp/secdat-%ld", (long)getuid());
    }

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

static int secdat_state_dir(char *buffer, size_t size)
{
    char data_home[PATH_MAX];

    if (secdat_data_home(data_home, sizeof(data_home)) != 0) {
        return 1;
    }

    if (snprintf(buffer, size, "%s/secdat", data_home) >= (int)size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static int secdat_session_agent_path(char *buffer, size_t size)
{
    char runtime_dir[PATH_MAX];

    if (secdat_runtime_dir(runtime_dir, sizeof(runtime_dir)) != 0) {
        return 1;
    }

    return secdat_join_path(buffer, size, runtime_dir, "agent.sock");
}

static int secdat_session_agent_path_for_domain(const char *domain_id, char *buffer, size_t size)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    char runtime_dir[PATH_MAX];
    char socket_name[48];
    static const char hex_digits[] = "0123456789abcdef";
    size_t index;

    if (EVP_Digest(domain_id, strlen(domain_id), digest, &digest_length, EVP_sha256(), NULL) != 1 || digest_length != 32) {
        fprintf(stderr, _("failed to derive encryption key\n"));
        return 1;
    }
    if (secdat_runtime_dir(runtime_dir, sizeof(runtime_dir)) != 0) {
        return 1;
    }

    digest_length = 16;
    strcpy(socket_name, "agent-");
    for (index = 0; index < digest_length; index += 1) {
        socket_name[6 + index * 2] = hex_digits[digest[index] >> 4];
        socket_name[6 + index * 2 + 1] = hex_digits[digest[index] & 0x0f];
    }
    strcpy(socket_name + 6 + digest_length * 2, ".sock");
    secdat_secure_clear(digest, sizeof(digest));

    return secdat_join_path(buffer, size, runtime_dir, socket_name);
}

static int secdat_wrapped_master_key_path(char *buffer, size_t size)
{
    char state_dir[PATH_MAX];

    if (secdat_state_dir(state_dir, sizeof(state_dir)) != 0) {
        return 1;
    }

    return secdat_join_path(buffer, size, state_dir, "master-key.bin");
}

static int secdat_parse_i64(const char *value, time_t *result)
{
    char *end = NULL;
    long long parsed;

    errno = 0;
    parsed = strtoll(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return 1;
    }

    *result = (time_t)parsed;
    return 0;
}

static time_t secdat_session_idle_seconds(void)
{
    const char *value = getenv(SECDAT_SESSION_IDLE_ENV);
    time_t parsed = 0;

    if (value != NULL && value[0] != '\0' && secdat_parse_i64(value, &parsed) == 0 && parsed > 0) {
        return parsed;
    }

    return SECDAT_SESSION_IDLE_SECONDS;
}

static void secdat_trim_newline(char *buffer)
{
    size_t length = strlen(buffer);

    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r')) {
        buffer[length - 1] = '\0';
        length -= 1;
    }
}

static void secdat_session_record_reset(struct secdat_session_record *record)
{
    secdat_secure_clear(record->master_key, sizeof(record->master_key));
    record->master_key[0] = '\0';
    record->expires_at = 0;
}

static void secdat_session_record_expire_if_needed(struct secdat_session_record *record)
{
    time_t now = time(NULL);

    if (record->master_key[0] != '\0' && record->expires_at <= now) {
        secdat_session_record_reset(record);
    }
}

static int secdat_read_line(FILE *stream, char *buffer, size_t size)
{
    if (fgets(buffer, (int)size, stream) == NULL) {
        return 1;
    }

    secdat_trim_newline(buffer);
    return 0;
}

static int secdat_session_agent_handle_client(int client_fd, struct secdat_session_record *record, int *should_exit)
{
    FILE *stream;
    char command[64];
    char payload[sizeof(record->master_key)];

    *should_exit = 0;
    secdat_session_record_expire_if_needed(record);

    stream = fdopen(client_fd, "r+");
    if (stream == NULL) {
        fprintf(stderr, _("failed to open file descriptor\n"));
        return 1;
    }

    if (secdat_read_line(stream, command, sizeof(command)) != 0) {
        fclose(stream);
        return 1;
    }

    if (strcmp(command, "STATUS") == 0) {
        if (record->master_key[0] == '\0') {
            fprintf(stream, "ERR locked\n");
        } else {
            fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        }
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "GET") == 0) {
        if (record->master_key[0] == '\0') {
            fprintf(stream, "ERR locked\n");
        } else {
            record->expires_at = time(NULL) + secdat_session_idle_seconds();
            fprintf(stream, "OK %lld\n%s\n", (long long)record->expires_at, record->master_key);
        }
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "SET") == 0) {
        if (secdat_read_line(stream, payload, sizeof(payload)) != 0) {
            fclose(stream);
            return 1;
        }
        secdat_session_record_reset(record);
        if (secdat_copy_string(record->master_key, sizeof(record->master_key), payload) != 0) {
            fclose(stream);
            return 1;
        }
        record->expires_at = time(NULL) + secdat_session_idle_seconds();
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "CLEAR") == 0) {
        secdat_session_record_reset(record);
        fprintf(stream, "OK\n");
        fflush(stream);
        fclose(stream);
        *should_exit = 1;
        return 0;
    }

    fprintf(stream, "ERR invalid\n");
    fflush(stream);
    fclose(stream);
    return 0;
}

static int secdat_run_session_agent(const char *socket_path)
{
    int server_fd;
    int client_fd;
    int should_exit;
    struct sockaddr_un address;
    struct secdat_session_record record;

    memset(&record, 0, sizeof(record));
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(server_fd);
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(address.sun_path, socket_path);

    unlink(socket_path);
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(server_fd);
        fprintf(stderr, _("failed to bind session agent socket\n"));
        return 1;
    }
    if (listen(server_fd, 8) != 0) {
        unlink(socket_path);
        close(server_fd);
        fprintf(stderr, _("failed to listen on session agent socket\n"));
        return 1;
    }

    for (;;) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (secdat_session_agent_handle_client(client_fd, &record, &should_exit) != 0) {
            close(client_fd);
        }
        if (should_exit) {
            break;
        }
    }

    secdat_session_record_reset(&record);
    close(server_fd);
    unlink(socket_path);
    return 0;
}

static int secdat_spawn_session_agent(const char *domain_id)
{
    char runtime_dir[PATH_MAX];
    char socket_path[PATH_MAX];
    pid_t pid;
    int status;
    int retry;

    if (secdat_runtime_dir(runtime_dir, sizeof(runtime_dir)) != 0) {
        return 1;
    }
    if (secdat_ensure_directory(runtime_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_session_agent_path_for_domain(domain_id, socket_path, sizeof(socket_path)) != 0) {
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, _("failed to start session agent\n"));
        return 1;
    }
    if (pid == 0) {
        pid_t worker;
        int devnull;

        if (setsid() < 0) {
            _exit(1);
        }

        worker = fork();
        if (worker < 0) {
            _exit(1);
        }
        if (worker > 0) {
            _exit(0);
        }

        devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) {
                close(devnull);
            }
        }

        _exit(secdat_run_session_agent(socket_path) == 0 ? 0 : 1);
    }

    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, _("failed to start session agent\n"));
        return 1;
    }

    for (retry = 0; retry < SECDAT_AGENT_CONNECT_RETRIES; retry += 1) {
        int fd;
        struct sockaddr_un address;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            break;
        }
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strcpy(address.sun_path, socket_path);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            close(fd);
            return 0;
        }
        close(fd);
        usleep(10000);
    }

    fprintf(stderr, _("failed to connect to session agent\n"));
    return 1;
}

static int secdat_read_secret_from_tty(const char *prompt, char *buffer, size_t size)
{
    struct termios old_settings;
    struct termios new_settings;
    int restored = 0;
    size_t length;

    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, _("this command requires a terminal for passphrase input\n"));
        return 1;
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if (tcgetattr(STDIN_FILENO, &old_settings) != 0) {
        fprintf(stderr, _("failed to read terminal settings\n"));
        return 1;
    }

    new_settings = old_settings;
    new_settings.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_settings) != 0) {
        fprintf(stderr, _("failed to update terminal settings\n"));
        return 1;
    }

    if (fgets(buffer, (int)size, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings);
        fprintf(stderr, _("failed to read passphrase\n"));
        return 1;
    }

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings) == 0) {
        restored = 1;
    }
    fprintf(stderr, "\n");

    if (!restored) {
        fprintf(stderr, _("failed to update terminal settings\n"));
        return 1;
    }

    length = strlen(buffer);
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r')) {
        buffer[length - 1] = '\0';
        length -= 1;
    }

    if (buffer[0] == '\0') {
        fprintf(stderr, _("empty passphrase is not allowed\n"));
        return 1;
    }

    return 0;
}

static int secdat_read_secret_confirmation(char *buffer, size_t size)
{
    char confirmation[512];

    if (secdat_read_secret_from_tty(_("Create secdat passphrase: "), buffer, size) != 0) {
        return 1;
    }
    if (secdat_read_secret_from_tty(_("Confirm secdat passphrase: "), confirmation, sizeof(confirmation)) != 0) {
        secdat_secure_clear(buffer, strlen(buffer));
        return 1;
    }
    if (strcmp(buffer, confirmation) != 0) {
        secdat_secure_clear(confirmation, strlen(confirmation));
        secdat_secure_clear(buffer, strlen(buffer));
        fprintf(stderr, _("passphrase confirmation did not match\n"));
        return 1;
    }

    secdat_secure_clear(confirmation, strlen(confirmation));
    return 0;
}

static int secdat_read_secret_confirmation_prompts(
    const char *prompt,
    const char *confirm_prompt,
    char *buffer,
    size_t size
)
{
    char confirmation[512];

    if (secdat_read_secret_from_tty(prompt, buffer, size) != 0) {
        return 1;
    }
    if (secdat_read_secret_from_tty(confirm_prompt, confirmation, sizeof(confirmation)) != 0) {
        secdat_secure_clear(buffer, strlen(buffer));
        return 1;
    }
    if (strcmp(buffer, confirmation) != 0) {
        secdat_secure_clear(confirmation, strlen(confirmation));
        secdat_secure_clear(buffer, strlen(buffer));
        fprintf(stderr, _("passphrase confirmation did not match\n"));
        return 1;
    }

    secdat_secure_clear(confirmation, strlen(confirmation));
    return 0;
}

static const char *secdat_master_key_passphrase_env(void)
{
    const char *value = getenv("SECDAT_MASTER_KEY_PASSPHRASE");

    if (value == NULL || value[0] == '\0') {
        return NULL;
    }
    return value;
}

static int secdat_read_unlock_passphrase(char *buffer, size_t size)
{
    const char *env_passphrase = secdat_master_key_passphrase_env();

    if (env_passphrase != NULL) {
        if (secdat_copy_string(buffer, size, env_passphrase) != 0) {
            return 1;
        }
        return 0;
    }
    return secdat_read_secret_from_tty(_("Enter secdat passphrase: "), buffer, size);
}

static int secdat_read_new_master_key_passphrase(char *buffer, size_t size)
{
    const char *env_passphrase = secdat_master_key_passphrase_env();

    if (env_passphrase != NULL) {
        if (secdat_copy_string(buffer, size, env_passphrase) != 0) {
            return 1;
        }
        return 0;
    }
    return secdat_read_secret_confirmation(buffer, size);
}

static int secdat_session_agent_connect_domain(const char *domain_id, int start_if_missing)
{
    char socket_path[PATH_MAX];
    int fd;
    struct sockaddr_un address;

    if (secdat_session_agent_path_for_domain(domain_id, socket_path, sizeof(socket_path)) != 0) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, _("failed to create session agent socket\n"));
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        fprintf(stderr, _("path is too long\n"));
        return -1;
    }
    strcpy(address.sun_path, socket_path);

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
        return fd;
    }

    close(fd);
    if (errno == ECONNREFUSED || errno == ENOTSOCK) {
        unlink(socket_path);
    }
    if (!start_if_missing) {
        return -1;
    }
    if (secdat_spawn_session_agent(domain_id) != 0) {
        return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, _("failed to create session agent socket\n"));
        return -1;
    }
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        fprintf(stderr, _("path is too long\n"));
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        fprintf(stderr, _("failed to connect to session agent\n"));
        return -1;
    }

    return fd;
}

static int secdat_session_agent_connect_chain(const struct secdat_domain_chain *chain)
{
    size_t index;
    int fd;

    for (index = 0; index < chain->count; index += 1) {
        fd = secdat_session_agent_connect_domain(chain->ids[index], 0);
        if (fd >= 0) {
            return fd;
        }
    }

    return -1;
}

static int secdat_session_agent_status(const struct secdat_domain_chain *chain, struct secdat_session_record *record)
{
    FILE *stream;
    int fd;
    char response[64];

    memset(record, 0, sizeof(*record));
    fd = secdat_session_agent_connect_chain(chain);
    if (fd < 0) {
        return 1;
    }

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }

    fprintf(stream, "STATUS\n");
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);

    if (strncmp(response, "OK ", 3) != 0) {
        return 1;
    }
    if (secdat_parse_i64(response + 3, &record->expires_at) != 0) {
        return 1;
    }
    return 0;
}

static int secdat_session_agent_get(const struct secdat_domain_chain *chain, struct secdat_session_record *record)
{
    FILE *stream;
    int fd;
    char response[64];
    char secret[sizeof(record->master_key)];

    memset(record, 0, sizeof(*record));
    fd = secdat_session_agent_connect_chain(chain);
    if (fd < 0) {
        return 1;
    }

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }

    fprintf(stream, "GET\n");
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    if (strncmp(response, "OK ", 3) != 0) {
        fclose(stream);
        return 1;
    }
    if (secdat_parse_i64(response + 3, &record->expires_at) != 0 || secdat_read_line(stream, secret, sizeof(secret)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);

    return secdat_copy_string(record->master_key, sizeof(record->master_key), secret);
}

static int secdat_session_agent_set(const char *domain_id, const char *master_key)
{
    FILE *stream;
    int fd;
    char response[64];

    fd = secdat_session_agent_connect_domain(domain_id, 1);
    if (fd < 0) {
        return 1;
    }

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }

    fprintf(stream, "SET\n%s\n", master_key);
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    return strncmp(response, "OK ", 3) == 0 ? 0 : 1;
}

static int secdat_session_agent_clear(const char *domain_id)
{
    FILE *stream;
    int fd;
    char response[64];

    fd = secdat_session_agent_connect_domain(domain_id, 0);
    if (fd < 0) {
        return 0;
    }

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }

    fprintf(stream, "CLEAR\n");
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    return strcmp(response, "OK") == 0 ? 0 : 1;
}

static int secdat_wrapped_master_key_exists(void)
{
    char path[PATH_MAX];

    if (secdat_wrapped_master_key_path(path, sizeof(path)) != 0) {
        return 0;
    }

    return secdat_file_exists(path);
}

static int secdat_wrap_key_from_passphrase(
    const char *passphrase,
    const unsigned char salt[SECDAT_WRAP_SALT_LEN],
    uint32_t iterations,
    unsigned char key[32]
)
{
    if (PKCS5_PBKDF2_HMAC(passphrase, (int)strlen(passphrase), salt, SECDAT_WRAP_SALT_LEN, (int)iterations, EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, _("failed to derive wrap key\n"));
        return 1;
    }
    return 0;
}

static int secdat_generate_master_key(char *buffer, size_t size)
{
    static const char hex_digits[] = "0123456789abcdef";
    unsigned char random_bytes[SECDAT_MASTER_KEY_RANDOM_BYTES];
    size_t index;

    if (size < SECDAT_MASTER_KEY_RANDOM_BYTES * 2 + 1) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }

    for (index = 0; index < sizeof(random_bytes); index += 1) {
        buffer[index * 2] = hex_digits[random_bytes[index] >> 4];
        buffer[index * 2 + 1] = hex_digits[random_bytes[index] & 0x0f];
    }
    buffer[sizeof(random_bytes) * 2] = '\0';
    secdat_secure_clear(random_bytes, sizeof(random_bytes));
    return 0;
}

static int secdat_write_wrapped_master_key(const char *passphrase, const char *master_key)
{
    char state_dir[PATH_MAX];
    char path[PATH_MAX];
    unsigned char wrap_key[32];
    unsigned char salt[SECDAT_WRAP_SALT_LEN];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char tag[SECDAT_TAG_LEN];
    unsigned char *buffer = NULL;
    EVP_CIPHER_CTX *context = NULL;
    size_t plaintext_length = strlen(master_key) + 1;
    size_t total_length;
    int written_length;
    int final_length;
    int status = 1;

    if (secdat_state_dir(state_dir, sizeof(state_dir)) != 0) {
        return 1;
    }
    if (secdat_ensure_directory(state_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_wrapped_master_key_path(path, sizeof(path)) != 0) {
        return 1;
    }
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }
    if (secdat_wrap_key_from_passphrase(passphrase, salt, SECDAT_WRAP_PBKDF2_ITERATIONS, wrap_key) != 0) {
        return 1;
    }

    total_length = SECDAT_WRAP_HEADER_LEN + sizeof(salt) + sizeof(nonce) + plaintext_length + SECDAT_TAG_LEN;
    buffer = calloc(1, total_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    memcpy(buffer, secdat_wrapped_key_magic, sizeof(secdat_wrapped_key_magic));
    buffer[8] = 1;
    buffer[9] = SECDAT_WRAP_SALT_LEN;
    buffer[10] = SECDAT_NONCE_LEN;
    buffer[11] = 0;
    secdat_write_be32(buffer + 12, SECDAT_WRAP_PBKDF2_ITERATIONS);
    secdat_write_be32(buffer + 16, (uint32_t)(plaintext_length + SECDAT_TAG_LEN));
    memcpy(buffer + SECDAT_WRAP_HEADER_LEN, salt, sizeof(salt));
    memcpy(buffer + SECDAT_WRAP_HEADER_LEN + sizeof(salt), nonce, sizeof(nonce));

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create encryption context\n"));
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(context, NULL, NULL, wrap_key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize encryption\n"));
        goto cleanup;
    }
    if (EVP_EncryptUpdate(
            context,
            buffer + SECDAT_WRAP_HEADER_LEN + sizeof(salt) + sizeof(nonce),
            &written_length,
            (const unsigned char *)master_key,
            (int)plaintext_length
        ) != 1) {
        fprintf(stderr, _("failed to encrypt value\n"));
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(
            context,
            buffer + SECDAT_WRAP_HEADER_LEN + sizeof(salt) + sizeof(nonce) + written_length,
            &final_length
        ) != 1) {
        fprintf(stderr, _("failed to finalize encryption\n"));
        goto cleanup;
    }
    written_length += final_length;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, _("failed to obtain authentication tag\n"));
        goto cleanup;
    }
    memcpy(buffer + SECDAT_WRAP_HEADER_LEN + sizeof(salt) + sizeof(nonce) + written_length, tag, sizeof(tag));

    if (secdat_atomic_write_file(path, buffer, total_length) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(wrap_key, sizeof(wrap_key));
    secdat_secure_clear(tag, sizeof(tag));
    if (buffer != NULL) {
        secdat_secure_clear(buffer, total_length);
        free(buffer);
    }
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    return status;
}

static int secdat_read_wrapped_master_key(struct secdat_wrapped_master_key *wrapped)
{
    char path[PATH_MAX];
    unsigned char *data = NULL;
    size_t length = 0;

    memset(wrapped, 0, sizeof(*wrapped));
    if (secdat_wrapped_master_key_path(path, sizeof(path)) != 0) {
        return 1;
    }
    if (!secdat_file_exists(path) || secdat_read_file(path, &data, &length) != 0) {
        return 1;
    }
    if (length < SECDAT_WRAP_HEADER_LEN + SECDAT_WRAP_SALT_LEN + SECDAT_NONCE_LEN + SECDAT_TAG_LEN
        || memcmp(data, secdat_wrapped_key_magic, sizeof(secdat_wrapped_key_magic)) != 0
        || data[8] != 1
        || data[9] != SECDAT_WRAP_SALT_LEN
        || data[10] != SECDAT_NONCE_LEN) {
        free(data);
        fprintf(stderr, _("invalid wrapped master key\n"));
        return 1;
    }

    wrapped->iterations = secdat_read_be32(data + 12);
    wrapped->ciphertext_length = secdat_read_be32(data + 16);
    if (length != SECDAT_WRAP_HEADER_LEN + SECDAT_WRAP_SALT_LEN + SECDAT_NONCE_LEN + wrapped->ciphertext_length) {
        free(data);
        fprintf(stderr, _("invalid wrapped master key\n"));
        return 1;
    }

    memcpy(wrapped->salt, data + SECDAT_WRAP_HEADER_LEN, sizeof(wrapped->salt));
    memcpy(wrapped->nonce, data + SECDAT_WRAP_HEADER_LEN + sizeof(wrapped->salt), sizeof(wrapped->nonce));
    wrapped->ciphertext = malloc(wrapped->ciphertext_length);
    if (wrapped->ciphertext == NULL) {
        free(data);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(
        wrapped->ciphertext,
        data + SECDAT_WRAP_HEADER_LEN + sizeof(wrapped->salt) + sizeof(wrapped->nonce),
        wrapped->ciphertext_length
    );

    secdat_secure_clear(data, length);
    free(data);
    return 0;
}

static void secdat_wrapped_master_key_free(struct secdat_wrapped_master_key *wrapped)
{
    if (wrapped->ciphertext != NULL) {
        secdat_secure_clear(wrapped->ciphertext, wrapped->ciphertext_length);
        free(wrapped->ciphertext);
    }
    memset(wrapped, 0, sizeof(*wrapped));
}

static void secdat_secret_bundle_free(struct secdat_secret_bundle *bundle)
{
    if (bundle->ciphertext != NULL) {
        secdat_secure_clear(bundle->ciphertext, bundle->ciphertext_length);
        free(bundle->ciphertext);
    }
    memset(bundle, 0, sizeof(*bundle));
}

static int secdat_bundle_append(
    unsigned char **buffer,
    size_t *length,
    size_t *capacity,
    const void *data,
    size_t data_length
)
{
    unsigned char *new_buffer;
    size_t new_capacity;

    if (*length + data_length > *capacity) {
        new_capacity = *capacity == 0 ? 256 : *capacity;
        while (new_capacity < *length + data_length) {
            new_capacity *= 2;
        }
        new_buffer = realloc(*buffer, new_capacity);
        if (new_buffer == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        *buffer = new_buffer;
        *capacity = new_capacity;
    }

    if (data_length > 0) {
        memcpy(*buffer + *length, data, data_length);
    }
    *length += data_length;
    return 0;
}

static int secdat_bundle_append_u32(unsigned char **buffer, size_t *length, size_t *capacity, uint32_t value)
{
    unsigned char encoded[4];

    secdat_write_be32(encoded, value);
    return secdat_bundle_append(buffer, length, capacity, encoded, sizeof(encoded));
}

static int secdat_bundle_read_u32(const unsigned char *buffer, size_t length, size_t *offset, uint32_t *value)
{
    if (*offset + 4 > length) {
        fprintf(stderr, _("invalid secret bundle\n"));
        return 1;
    }

    *value = secdat_read_be32(buffer + *offset);
    *offset += 4;
    return 0;
}

static int secdat_collect_bundle_payload(const struct secdat_cli *cli, unsigned char **payload_out, size_t *payload_length_out)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list visible_keys = {0};
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    size_t capacity = 0;
    size_t index;
    int status = 1;

    if (secdat_domain_resolve_chain(cli->dir, &chain) != 0) {
        return 1;
    }
    if (secdat_collect_visible_keys(&chain, cli->store, NULL, NULL, &visible_keys) != 0) {
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }
    if (secdat_bundle_append_u32(&payload, &payload_length, &capacity, (uint32_t)visible_keys.count) != 0) {
        goto cleanup;
    }

    for (index = 0; index < visible_keys.count; index += 1) {
        unsigned char *plaintext = NULL;
        size_t plaintext_length = 0;
        uint32_t key_length = (uint32_t)strlen(visible_keys.items[index]);

        if (secdat_load_resolved_plaintext(&chain, cli->store, visible_keys.items[index], &plaintext, &plaintext_length, NULL, NULL) != 0) {
            goto cleanup;
        }
        if (plaintext_length > UINT32_MAX) {
            fprintf(stderr, _("secret bundle entry is too large\n"));
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            goto cleanup;
        }
        if (secdat_bundle_append_u32(&payload, &payload_length, &capacity, key_length) != 0
            || secdat_bundle_append_u32(&payload, &payload_length, &capacity, (uint32_t)plaintext_length) != 0
            || secdat_bundle_append(&payload, &payload_length, &capacity, visible_keys.items[index], key_length) != 0
            || secdat_bundle_append(&payload, &payload_length, &capacity, plaintext, plaintext_length) != 0) {
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            goto cleanup;
        }

        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
    }

    *payload_out = payload;
    *payload_length_out = payload_length;
    payload = NULL;
    payload_length = 0;
    status = 0;

cleanup:
    if (payload != NULL) {
        secdat_secure_clear(payload, payload_length);
        free(payload);
    }
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return status;
}

static int secdat_write_secret_bundle_file(
    const char *path,
    const char *passphrase,
    const unsigned char *payload,
    size_t payload_length
)
{
    unsigned char wrap_key[32];
    unsigned char salt[SECDAT_WRAP_SALT_LEN];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char tag[SECDAT_TAG_LEN];
    unsigned char *buffer = NULL;
    EVP_CIPHER_CTX *context = NULL;
    size_t total_length;
    int written_length;
    int final_length;
    int status = 1;

    if (secdat_file_exists(path)) {
        fprintf(stderr, _("bundle file already exists: %s\n"), path);
        return 1;
    }
    if (payload_length > UINT32_MAX - SECDAT_TAG_LEN) {
        fprintf(stderr, _("secret bundle is too large\n"));
        return 1;
    }
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }
    if (secdat_wrap_key_from_passphrase(passphrase, salt, SECDAT_WRAP_PBKDF2_ITERATIONS, wrap_key) != 0) {
        return 1;
    }

    total_length = SECDAT_BUNDLE_HEADER_LEN + sizeof(salt) + sizeof(nonce) + payload_length + SECDAT_TAG_LEN;
    buffer = calloc(1, total_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    memcpy(buffer, secdat_bundle_magic, sizeof(secdat_bundle_magic));
    buffer[8] = 1;
    buffer[9] = SECDAT_WRAP_SALT_LEN;
    buffer[10] = SECDAT_NONCE_LEN;
    buffer[11] = 0;
    secdat_write_be32(buffer + 12, SECDAT_WRAP_PBKDF2_ITERATIONS);
    secdat_write_be32(buffer + 16, (uint32_t)(payload_length + SECDAT_TAG_LEN));
    memcpy(buffer + SECDAT_BUNDLE_HEADER_LEN, salt, sizeof(salt));
    memcpy(buffer + SECDAT_BUNDLE_HEADER_LEN + sizeof(salt), nonce, sizeof(nonce));

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create encryption context\n"));
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(context, NULL, NULL, wrap_key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize encryption\n"));
        goto cleanup;
    }
    if (EVP_EncryptUpdate(
            context,
            buffer + SECDAT_BUNDLE_HEADER_LEN + sizeof(salt) + sizeof(nonce),
            &written_length,
            payload,
            (int)payload_length
        ) != 1) {
        fprintf(stderr, _("failed to encrypt value\n"));
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(
            context,
            buffer + SECDAT_BUNDLE_HEADER_LEN + sizeof(salt) + sizeof(nonce) + written_length,
            &final_length
        ) != 1) {
        fprintf(stderr, _("failed to finalize encryption\n"));
        goto cleanup;
    }
    written_length += final_length;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, _("failed to obtain authentication tag\n"));
        goto cleanup;
    }
    memcpy(buffer + SECDAT_BUNDLE_HEADER_LEN + sizeof(salt) + sizeof(nonce) + written_length, tag, sizeof(tag));

    if (secdat_atomic_write_file(path, buffer, total_length) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(wrap_key, sizeof(wrap_key));
    secdat_secure_clear(tag, sizeof(tag));
    if (buffer != NULL) {
        secdat_secure_clear(buffer, total_length);
        free(buffer);
    }
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    return status;
}

static int secdat_read_secret_bundle(struct secdat_secret_bundle *bundle, const char *path)
{
    unsigned char *data = NULL;
    size_t length = 0;

    memset(bundle, 0, sizeof(*bundle));
    if (secdat_read_file(path, &data, &length) != 0) {
        return 1;
    }
    if (length < SECDAT_BUNDLE_HEADER_LEN + SECDAT_WRAP_SALT_LEN + SECDAT_NONCE_LEN + SECDAT_TAG_LEN
        || memcmp(data, secdat_bundle_magic, sizeof(secdat_bundle_magic)) != 0
        || data[8] != 1
        || data[9] != SECDAT_WRAP_SALT_LEN
        || data[10] != SECDAT_NONCE_LEN) {
        secdat_secure_clear(data, length);
        free(data);
        fprintf(stderr, _("invalid secret bundle\n"));
        return 1;
    }

    bundle->iterations = secdat_read_be32(data + 12);
    bundle->ciphertext_length = secdat_read_be32(data + 16);
    if (length != SECDAT_BUNDLE_HEADER_LEN + SECDAT_WRAP_SALT_LEN + SECDAT_NONCE_LEN + bundle->ciphertext_length) {
        secdat_secure_clear(data, length);
        free(data);
        fprintf(stderr, _("invalid secret bundle\n"));
        return 1;
    }

    memcpy(bundle->salt, data + SECDAT_BUNDLE_HEADER_LEN, sizeof(bundle->salt));
    memcpy(bundle->nonce, data + SECDAT_BUNDLE_HEADER_LEN + sizeof(bundle->salt), sizeof(bundle->nonce));
    bundle->ciphertext = malloc(bundle->ciphertext_length);
    if (bundle->ciphertext == NULL) {
        secdat_secure_clear(data, length);
        free(data);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(
        bundle->ciphertext,
        data + SECDAT_BUNDLE_HEADER_LEN + sizeof(bundle->salt) + sizeof(bundle->nonce),
        bundle->ciphertext_length
    );

    secdat_secure_clear(data, length);
    free(data);
    return 0;
}

static int secdat_decrypt_secret_bundle(
    const char *path,
    const char *passphrase,
    unsigned char **payload,
    size_t *payload_length
)
{
    struct secdat_secret_bundle bundle;
    EVP_CIPHER_CTX *context = NULL;
    unsigned char wrap_key[32];
    unsigned char *plaintext = NULL;
    size_t plaintext_size;
    int written_length;
    int final_length;
    int status = 1;

    if (secdat_read_secret_bundle(&bundle, path) != 0) {
        return 1;
    }
    if (secdat_wrap_key_from_passphrase(passphrase, bundle.salt, bundle.iterations, wrap_key) != 0) {
        secdat_secret_bundle_free(&bundle);
        return 1;
    }

    plaintext_size = bundle.ciphertext_length - SECDAT_TAG_LEN;
    plaintext = malloc(plaintext_size == 0 ? 1 : plaintext_size);
    if (plaintext == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }
    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create decryption context\n"));
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(bundle.nonce), NULL) != 1
        || EVP_DecryptInit_ex(context, NULL, NULL, wrap_key, bundle.nonce) != 1) {
        fprintf(stderr, _("failed to initialize decryption\n"));
        goto cleanup;
    }
    if (EVP_DecryptUpdate(context, plaintext, &written_length, bundle.ciphertext, (int)plaintext_size) != 1) {
        fprintf(stderr, _("failed to decrypt value\n"));
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, SECDAT_TAG_LEN, bundle.ciphertext + plaintext_size) != 1) {
        fprintf(stderr, _("failed to set authentication tag\n"));
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(context, plaintext + written_length, &final_length) != 1) {
        fprintf(stderr, _("failed to unlock secret bundle\n"));
        goto cleanup;
    }
    written_length += final_length;
    *payload = plaintext;
    *payload_length = (size_t)written_length;
    plaintext = NULL;
    status = 0;

cleanup:
    secdat_secure_clear(wrap_key, sizeof(wrap_key));
    if (plaintext != NULL) {
        secdat_secure_clear(plaintext, plaintext_size);
        free(plaintext);
    }
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    secdat_secret_bundle_free(&bundle);
    return status;
}

static int secdat_unwrap_master_key(const char *passphrase, char *buffer, size_t size)
{
    struct secdat_wrapped_master_key wrapped;
    EVP_CIPHER_CTX *context = NULL;
    unsigned char wrap_key[32];
    unsigned char *plaintext = NULL;
    size_t plaintext_length;
    int written_length;
    int final_length;
    int status = 1;

    if (secdat_read_wrapped_master_key(&wrapped) != 0) {
        return 1;
    }
    if (secdat_wrap_key_from_passphrase(passphrase, wrapped.salt, wrapped.iterations, wrap_key) != 0) {
        secdat_wrapped_master_key_free(&wrapped);
        return 1;
    }

    plaintext_length = wrapped.ciphertext_length - SECDAT_TAG_LEN;
    plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (plaintext == NULL) {
        secdat_wrapped_master_key_free(&wrapped);
        secdat_secure_clear(wrap_key, sizeof(wrap_key));
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create decryption context\n"));
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(wrapped.nonce), NULL) != 1
        || EVP_DecryptInit_ex(context, NULL, NULL, wrap_key, wrapped.nonce) != 1) {
        fprintf(stderr, _("failed to initialize decryption\n"));
        goto cleanup;
    }
    if (EVP_DecryptUpdate(
            context,
            plaintext,
            &written_length,
            wrapped.ciphertext,
            (int)plaintext_length
        ) != 1) {
        fprintf(stderr, _("failed to decrypt value\n"));
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_GCM_SET_TAG,
            SECDAT_TAG_LEN,
            wrapped.ciphertext + plaintext_length
        ) != 1) {
        fprintf(stderr, _("failed to set authentication tag\n"));
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(context, plaintext + written_length, &final_length) != 1) {
        fprintf(stderr, _("failed to unlock persistent master key\n"));
        goto cleanup;
    }
    written_length += final_length;
    if (written_length <= 0 || (size_t)written_length > size || plaintext[written_length - 1] != '\0') {
        fprintf(stderr, _("invalid wrapped master key\n"));
        goto cleanup;
    }
    memcpy(buffer, plaintext, (size_t)written_length);
    status = 0;

cleanup:
    secdat_secure_clear(wrap_key, sizeof(wrap_key));
    if (plaintext != NULL) {
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
    }
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    secdat_wrapped_master_key_free(&wrapped);
    return status;
}

static void secdat_write_be32(unsigned char *buffer, uint32_t value)
{
    buffer[0] = (unsigned char)((value >> 24) & 0xff);
    buffer[1] = (unsigned char)((value >> 16) & 0xff);
    buffer[2] = (unsigned char)((value >> 8) & 0xff);
    buffer[3] = (unsigned char)(value & 0xff);
}

static uint32_t secdat_read_be32(const unsigned char *buffer)
{
    return ((uint32_t)buffer[0] << 24)
        | ((uint32_t)buffer[1] << 16)
        | ((uint32_t)buffer[2] << 8)
        | (uint32_t)buffer[3];
}

static int secdat_derive_key(const struct secdat_domain_chain *chain, unsigned char key[32])
{
    struct secdat_session_record record = {0};
    const char *master_key = getenv("SECDAT_MASTER_KEY");
    unsigned int key_length = 0;

    if (master_key == NULL || master_key[0] == '\0') {
        if (secdat_session_agent_get(chain, &record) == 0) {
            master_key = record.master_key;
        } else {
            fprintf(
                stderr,
                _("missing SECDAT_MASTER_KEY and no active secdat session; run secdat unlock or export SECDAT_MASTER_KEY\n")
            );
            return 1;
        }
    }

    if (EVP_Digest(master_key, strlen(master_key), key, &key_length, EVP_sha256(), NULL) != 1 || key_length != 32) {
        secdat_secure_clear(record.master_key, strlen(record.master_key));
        fprintf(stderr, _("failed to derive encryption key\n"));
        return 1;
    }

    secdat_secure_clear(record.master_key, strlen(record.master_key));

    return 0;
}

static int secdat_domain_chain_from_id(const char *domain_id, struct secdat_domain_chain *chain)
{
    char domain_root[PATH_MAX];

    if (secdat_domain_root_path(domain_id, domain_root, sizeof(domain_root)) != 0) {
        return 1;
    }

    return secdat_domain_resolve_chain(domain_root, chain);
}

static int secdat_command_status(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    int quiet = 0;
    int wrapped_present = secdat_wrapped_master_key_exists();

    if (cli->argc == 1 && (strcmp(cli->argv[0], "--quiet") == 0 || strcmp(cli->argv[0], "-q") == 0)) {
        quiet = 1;
    } else if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for status\n"));
        secdat_cli_print_try_help(cli, "status");
        return 2;
    }

    if (cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for status\n"));
        secdat_cli_print_try_help(cli, "status");
        return 2;
    }

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        if (!quiet) {
            puts(_("unlocked"));
            puts(_("source: environment"));
            puts(wrapped_present ? _("wrapped master key: present") : _("wrapped master key: absent"));
        }
        return 0;
    }

    if (secdat_domain_resolve_chain(cli->dir, &chain) == 0 && secdat_session_agent_status(&chain, &record) == 0) {
        if (!quiet) {
            puts(_("unlocked"));
            puts(_("source: session agent"));
            printf(_("expires in: %lld seconds\n"), (long long)(record.expires_at - time(NULL)));
            puts(wrapped_present ? _("wrapped master key: present") : _("wrapped master key: absent"));
        }
        secdat_secure_clear(record.master_key, strlen(record.master_key));
        secdat_domain_chain_free(&chain);
        return 0;
    }

    secdat_domain_chain_free(&chain);

    if (!quiet) {
        puts(_("locked"));
        puts(wrapped_present ? _("wrapped master key: present") : _("wrapped master key: absent"));
    }
    return 1;
}

static int secdat_command_unlock(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    const char *env_master_key = getenv("SECDAT_MASTER_KEY");
    int wrapped_present = secdat_wrapped_master_key_exists();
    int initialized = 0;
    char passphrase[512];
    const char *session_master_key = env_master_key;
    char secret[512];

    if (cli->argc != 0 || cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }
    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }

    if (!wrapped_present) {
        if (secdat_read_new_master_key_passphrase(passphrase, sizeof(passphrase)) != 0) {
            return 1;
        }
        if (session_master_key == NULL || session_master_key[0] == '\0') {
            if (secdat_generate_master_key(secret, sizeof(secret)) != 0) {
                secdat_secure_clear(passphrase, strlen(passphrase));
                return 1;
            }
            session_master_key = secret;
        }
        if (secdat_write_wrapped_master_key(passphrase, session_master_key) != 0) {
            secdat_secure_clear(passphrase, strlen(passphrase));
            if (session_master_key == secret) {
                secdat_secure_clear(secret, strlen(secret));
            }
            return 1;
        }
        initialized = 1;
        secdat_secure_clear(passphrase, strlen(passphrase));
    }

    if (session_master_key != NULL && session_master_key[0] != '\0') {
        if (secdat_session_agent_set(current_domain_id, session_master_key) != 0) {
            if (session_master_key == secret) {
                secdat_secure_clear(secret, strlen(secret));
            }
            return 1;
        }
        if (session_master_key == secret) {
            secdat_secure_clear(secret, strlen(secret));
        }
        if (initialized) {
            puts(env_master_key != NULL && env_master_key[0] != '\0'
                     ? _("persistent master key initialized; session unlocked from environment")
                     : _("persistent master key initialized; session unlocked"));
        } else {
            puts(_("session unlocked from environment"));
        }
        return 0;
    }

    if (!wrapped_present) {
        fprintf(stderr, _("no persistent master key is initialized; run secdat unlock once on a terminal to create one\n"));
        return 1;
    }

    if (secdat_read_unlock_passphrase(passphrase, sizeof(passphrase)) != 0) {
        return 1;
    }
    if (secdat_unwrap_master_key(passphrase, secret, sizeof(secret)) != 0) {
        secdat_secure_clear(passphrase, strlen(passphrase));
        return 1;
    }
    secdat_secure_clear(passphrase, strlen(passphrase));
    if (secdat_session_agent_set(current_domain_id, secret) != 0) {
        secdat_secure_clear(secret, strlen(secret));
        return 1;
    }

    secdat_secure_clear(secret, strlen(secret));
    puts(_("session unlocked"));
    return 0;
}

static int secdat_command_lock(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];

    if (cli->argc != 0 || cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for lock\n"));
        secdat_cli_print_try_help(cli, "lock");
        return 2;
    }
    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }

    if (secdat_session_agent_clear(current_domain_id) != 0) {
        return 1;
    }

    puts(_("session locked"));
    return 0;
}

static int secdat_command_passwd(const struct secdat_cli *cli)
{
    char current_passphrase[512];
    char new_passphrase[512];
    char master_key[512];

    if (cli->argc != 0 || cli->dir != NULL || cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for passwd\n"));
        secdat_cli_print_try_help(cli, "passwd");
        return 2;
    }
    if (!secdat_wrapped_master_key_exists()) {
        fprintf(stderr, _("no persistent master key is initialized; run secdat unlock once on a terminal to create one\n"));
        return 1;
    }
    if (secdat_read_unlock_passphrase(current_passphrase, sizeof(current_passphrase)) != 0) {
        return 1;
    }
    if (secdat_unwrap_master_key(current_passphrase, master_key, sizeof(master_key)) != 0) {
        secdat_secure_clear(current_passphrase, strlen(current_passphrase));
        return 1;
    }
    secdat_secure_clear(current_passphrase, strlen(current_passphrase));
    if (secdat_read_secret_confirmation_prompts(
            _("Create new secdat passphrase: "),
            _("Confirm new secdat passphrase: "),
            new_passphrase,
            sizeof(new_passphrase)
        ) != 0) {
        secdat_secure_clear(master_key, strlen(master_key));
        return 1;
    }
    if (secdat_write_wrapped_master_key(new_passphrase, master_key) != 0) {
        secdat_secure_clear(master_key, strlen(master_key));
        secdat_secure_clear(new_passphrase, strlen(new_passphrase));
        return 1;
    }

    secdat_secure_clear(master_key, strlen(master_key));
    secdat_secure_clear(new_passphrase, strlen(new_passphrase));
    puts(_("persistent master key passphrase updated"));
    return 0;
}

static int secdat_encrypt_value(
    const char *domain_id,
    const unsigned char *plaintext,
    size_t plaintext_length,
    unsigned char **encrypted,
    size_t *encrypted_length
)
{
    struct secdat_domain_chain chain = {0};
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[32];
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char tag[SECDAT_TAG_LEN];
    unsigned char *buffer = NULL;
    int ciphertext_length;
    int final_length;
    size_t total_ciphertext_length;
    size_t total_length;
    int status = 1;

    if (secdat_domain_chain_from_id(domain_id, &chain) != 0) {
        return 1;
    }
    if (secdat_derive_key(&chain, key) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    secdat_domain_chain_free(&chain);

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        goto cleanup;
    }

    total_ciphertext_length = plaintext_length + SECDAT_TAG_LEN;
    total_length = SECDAT_HEADER_LEN + sizeof(nonce) + total_ciphertext_length;
    buffer = calloc(1, total_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    memcpy(buffer, secdat_entry_magic, sizeof(secdat_entry_magic));
    buffer[8] = SECDAT_ENTRY_VERSION;
    buffer[9] = SECDAT_ENTRY_ALGORITHM_AES_256_GCM;
    buffer[10] = SECDAT_NONCE_LEN;
    buffer[11] = 0;
    secdat_write_be32(buffer + 12, (uint32_t)total_ciphertext_length);
    memcpy(buffer + SECDAT_HEADER_LEN, nonce, sizeof(nonce));

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create encryption context\n"));
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1
        || EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize encryption\n"));
        goto cleanup;
    }

    if (EVP_EncryptUpdate(
            context,
            buffer + SECDAT_HEADER_LEN + sizeof(nonce),
            &ciphertext_length,
            plaintext,
            (int)plaintext_length
        ) != 1) {
        fprintf(stderr, _("failed to encrypt value\n"));
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(context, buffer + SECDAT_HEADER_LEN + sizeof(nonce) + ciphertext_length, &final_length) != 1) {
        fprintf(stderr, _("failed to finalize encryption\n"));
        goto cleanup;
    }

    ciphertext_length += final_length;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, _("failed to obtain authentication tag\n"));
        goto cleanup;
    }

    memcpy(buffer + SECDAT_HEADER_LEN + sizeof(nonce) + ciphertext_length, tag, sizeof(tag));
    *encrypted = buffer;
    *encrypted_length = total_length;
    buffer = NULL;
    status = 0;

cleanup:
    secdat_secure_clear(key, sizeof(key));
    secdat_secure_clear(tag, sizeof(tag));
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    free(buffer);
    return status;
}

static int secdat_decrypt_value(
    const struct secdat_domain_chain *chain,
    const unsigned char *encrypted,
    size_t encrypted_length,
    unsigned char **plaintext,
    size_t *plaintext_length
)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char key[32];
    unsigned char *buffer = NULL;
    const unsigned char *nonce;
    const unsigned char *ciphertext;
    const unsigned char *tag;
    unsigned char algorithm;
    uint32_t ciphertext_length;
    size_t header_length;
    size_t payload_length;
    size_t decoded_length;
    int written_length;
    int final_length;
    int status = 1;

    if (encrypted_length < SECDAT_HEADER_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    if (memcmp(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || encrypted[8] != SECDAT_ENTRY_VERSION) {
        fprintf(stderr, _("unsupported encrypted entry format\n"));
        return 1;
    }

    algorithm = encrypted[9];
    if (algorithm != SECDAT_ENTRY_ALGORITHM_PLAINTEXT && algorithm != SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
        fprintf(stderr, _("unsupported encryption algorithm\n"));
        return 1;
    }

    ciphertext_length = secdat_read_be32(encrypted + 12);
    header_length = SECDAT_HEADER_LEN + encrypted[10];
    if (encrypted_length < header_length) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }
    payload_length = encrypted_length - header_length;
    if (payload_length != ciphertext_length) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    if (algorithm == SECDAT_ENTRY_ALGORITHM_PLAINTEXT) {
        if (encrypted[10] != 0) {
            fprintf(stderr, _("invalid encrypted entry\n"));
            return 1;
        }
        buffer = malloc(payload_length == 0 ? 1 : payload_length);
        if (buffer == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(buffer, encrypted + header_length, payload_length);
        *plaintext = buffer;
        *plaintext_length = payload_length;
        return 0;
    }

    if (encrypted[10] != SECDAT_NONCE_LEN || ciphertext_length < SECDAT_TAG_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    if (secdat_derive_key(chain, key) != 0) {
        return 1;
    }

    decoded_length = ciphertext_length - SECDAT_TAG_LEN;
    buffer = malloc(decoded_length == 0 ? 1 : decoded_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }

    nonce = encrypted + SECDAT_HEADER_LEN;
    ciphertext = encrypted + header_length;
    tag = ciphertext + decoded_length;

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        fprintf(stderr, _("failed to create decryption context\n"));
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, encrypted[10], NULL) != 1
        || EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize decryption\n"));
        goto cleanup;
    }

    if (EVP_DecryptUpdate(context, buffer, &written_length, ciphertext, (int)decoded_length) != 1) {
        fprintf(stderr, _("failed to decrypt value\n"));
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, SECDAT_TAG_LEN, (void *)tag) != 1) {
        fprintf(stderr, _("failed to set authentication tag\n"));
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(context, buffer + written_length, &final_length) != 1) {
        fprintf(stderr, _("failed to authenticate encrypted value\n"));
        goto cleanup;
    }

    *plaintext = buffer;
    *plaintext_length = (size_t)(written_length + final_length);
    buffer = NULL;
    status = 0;

cleanup:
    secdat_secure_clear(key, sizeof(key));
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (buffer != NULL) {
        secdat_secure_clear(buffer, decoded_length);
        free(buffer);
    }
    return status;
}

static int secdat_read_stdin(unsigned char **buffer, size_t *length)
{
    unsigned char chunk[4096];
    unsigned char *data = NULL;
    size_t used = 0;
    size_t capacity = 0;
    ssize_t read_length;
    unsigned char *new_data;

    while ((read_length = read(STDIN_FILENO, chunk, sizeof(chunk))) > 0) {
        if (used + (size_t)read_length > capacity) {
            capacity = capacity == 0 ? (size_t)read_length : capacity * 2;
            while (capacity < used + (size_t)read_length) {
                capacity *= 2;
            }
            new_data = realloc(data, capacity);
            if (new_data == NULL) {
                secdat_secure_clear(data, used);
                free(data);
                fprintf(stderr, _("out of memory\n"));
                return 1;
            }
            data = new_data;
        }

        memcpy(data + used, chunk, (size_t)read_length);
        used += (size_t)read_length;
    }

    if (read_length < 0) {
        secdat_secure_clear(data, used);
        free(data);
        fprintf(stderr, _("failed to read standard input\n"));
        return 1;
    }

    *buffer = data;
    *length = used;
    return 0;
}

static int secdat_collect_directory_keys(const char *directory_path, const char *suffix, struct secdat_key_list *keys)
{
    DIR *directory;
    struct dirent *entry;
    size_t suffix_length = strlen(suffix);
    size_t name_length;
    char encoded_name[NAME_MAX + 1];
    char *decoded_name = NULL;
    int status = 0;

    directory = opendir(directory_path);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), directory_path);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        name_length = strlen(entry->d_name);
        if (name_length <= suffix_length || strcmp(entry->d_name + name_length - suffix_length, suffix) != 0) {
            continue;
        }

        memcpy(encoded_name, entry->d_name, name_length - suffix_length);
        encoded_name[name_length - suffix_length] = '\0';
        if (secdat_unescape_component(encoded_name, &decoded_name) != 0) {
            status = 1;
            break;
        }

        if (secdat_key_list_append(keys, decoded_name) != 0) {
            free(decoded_name);
            status = 1;
            break;
        }

        free(decoded_name);
        decoded_name = NULL;
    }

    closedir(directory);
    return status;
}

static int secdat_pattern_list_matches(const struct secdat_key_list *patterns, const char *value)
{
    size_t index;

    if (patterns == NULL) {
        return 0;
    }

    for (index = 0; index < patterns->count; index += 1) {
        if (fnmatch(patterns->items[index], value, 0) == 0) {
            return 1;
        }
    }

    return 0;
}

static int secdat_collect_visible_keys(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_key_list *include_patterns,
    const struct secdat_key_list *exclude_patterns,
    struct secdat_key_list *visible_keys
)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct secdat_key_list hidden_keys = {0};
    struct secdat_key_list domain_keys = {0};
    size_t chain_index;
    size_t key_index;
    int status;

    for (chain_index = 0; chain_index < chain->count; chain_index += 1) {
        status = secdat_store_tombstones_dir(chain->ids[chain_index], store_name, tombstones_dir, sizeof(tombstones_dir));
        if (status != 0) {
            goto cleanup;
        }
        status = secdat_collect_directory_keys(tombstones_dir, ".tomb", &domain_keys);
        if (status != 0) {
            goto cleanup;
        }
        for (key_index = 0; key_index < domain_keys.count; key_index += 1) {
            if (secdat_key_list_append(&hidden_keys, domain_keys.items[key_index]) != 0) {
                status = 1;
                goto cleanup;
            }
        }
        secdat_key_list_free(&domain_keys);

        status = secdat_store_entries_dir(chain->ids[chain_index], store_name, entries_dir, sizeof(entries_dir));
        if (status != 0) {
            goto cleanup;
        }
        status = secdat_collect_directory_keys(entries_dir, ".sec", &domain_keys);
        if (status != 0) {
            goto cleanup;
        }

        for (key_index = 0; key_index < domain_keys.count; key_index += 1) {
            if (secdat_key_list_contains(&hidden_keys, domain_keys.items[key_index])) {
                continue;
            }
            if (secdat_key_list_contains(visible_keys, domain_keys.items[key_index])) {
                continue;
            }
            if (include_patterns != NULL && include_patterns->count > 0 && !secdat_pattern_list_matches(include_patterns, domain_keys.items[key_index])) {
                continue;
            }
            if (exclude_patterns != NULL && exclude_patterns->count > 0 && secdat_pattern_list_matches(exclude_patterns, domain_keys.items[key_index])) {
                continue;
            }
            if (secdat_key_list_append(visible_keys, domain_keys.items[key_index]) != 0) {
                status = 1;
                goto cleanup;
            }
        }
        secdat_key_list_free(&domain_keys);
    }

    qsort(visible_keys->items, visible_keys->count, sizeof(*visible_keys->items), secdat_compare_strings);
    status = 0;

cleanup:
    secdat_key_list_free(&domain_keys);
    secdat_key_list_free(&hidden_keys);
    return status;
}

static int secdat_find_effective_entry(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    char *buffer,
    size_t size,
    size_t *resolved_index
)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    size_t index;

    for (index = 0; index < chain->count; index += 1) {
        if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(entry_path)) {
            if (resolved_index != NULL) {
                *resolved_index = index;
            }
            if (strlen(entry_path) >= size) {
                fprintf(stderr, _("path is too long\n"));
                return 1;
            }
            strcpy(buffer, entry_path);
            return 0;
        }

        if (secdat_build_tombstone_path(chain->ids[index], store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(tombstone_path)) {
            break;
        }
    }

    return 1;
}

static int secdat_resolve_entry_path(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    char *buffer,
    size_t size
)
{
    return secdat_find_effective_entry(chain, store_name, key, buffer, size, NULL);
}

static int secdat_parent_has_visible_key(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    size_t index;

    for (index = 1; index < chain->count; index += 1) {
        if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
            return -1;
        }
        if (secdat_file_exists(entry_path)) {
            return 1;
        }

        if (secdat_build_tombstone_path(chain->ids[index], store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
            return -1;
        }
        if (secdat_file_exists(tombstone_path)) {
            return 0;
        }
    }

    return 0;
}

static int secdat_collect_list_keys(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_list_options *options,
    struct secdat_key_list *keys
)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct secdat_key_list local_entries = {0};
    struct secdat_key_list local_tombstones = {0};
    size_t index;
    int visible_in_parent;
    int status = 1;

    if (chain->count == 0) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    if (secdat_store_entries_dir(chain->ids[0], store_name, entries_dir, sizeof(entries_dir)) != 0) {
        return 1;
    }
    if (secdat_store_tombstones_dir(chain->ids[0], store_name, tombstones_dir, sizeof(tombstones_dir)) != 0) {
        return 1;
    }
    if (secdat_collect_directory_keys(entries_dir, ".sec", &local_entries) != 0) {
        goto cleanup;
    }
    if (secdat_collect_directory_keys(tombstones_dir, ".tomb", &local_tombstones) != 0) {
        goto cleanup;
    }

    for (index = 0; index < local_entries.count; index += 1) {
        visible_in_parent = secdat_parent_has_visible_key(chain, store_name, local_entries.items[index]);
        if (visible_in_parent < 0) {
            goto cleanup;
        }
        if (options->overridden && visible_in_parent) {
            if (secdat_key_list_append(keys, local_entries.items[index]) != 0) {
                goto cleanup;
            }
        }
    }

    for (index = 0; index < local_tombstones.count; index += 1) {
        visible_in_parent = secdat_parent_has_visible_key(chain, store_name, local_tombstones.items[index]);
        if (visible_in_parent < 0) {
            goto cleanup;
        }
        if (options->masked && visible_in_parent) {
            if (secdat_key_list_append(keys, local_tombstones.items[index]) != 0) {
                goto cleanup;
            }
            continue;
        }
        if (options->orphaned && !visible_in_parent) {
            if (secdat_key_list_append(keys, local_tombstones.items[index]) != 0) {
                goto cleanup;
            }
        }
    }

    status = 0;

cleanup:
    secdat_key_list_free(&local_entries);
    secdat_key_list_free(&local_tombstones);
    return status;
}

static int secdat_load_resolved_plaintext(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    unsigned char **plaintext,
    size_t *plaintext_length,
    size_t *resolved_index,
    int *unsafe_store
)
{
    char entry_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status;

    status = secdat_find_effective_entry(chain, store_name, key, entry_path, sizeof(entry_path), resolved_index);
    if (status != 0) {
        fprintf(stderr, _("key not found: %s\n"), key);
        fprintf(stderr, _("Hint: check secdat status, --dir, and --store to confirm the lookup context\n"));
        return 1;
    }

    if (secdat_read_file(entry_path, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    if (unsafe_store != NULL) {
        if (encrypted_length < SECDAT_HEADER_LEN) {
            fprintf(stderr, _("invalid encrypted entry\n"));
            free(encrypted);
            return 1;
        }
        if (memcmp(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || encrypted[8] != SECDAT_ENTRY_VERSION) {
            fprintf(stderr, _("unsupported encrypted entry format\n"));
            free(encrypted);
            return 1;
        }
        if (encrypted[9] != SECDAT_ENTRY_ALGORITHM_PLAINTEXT && encrypted[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
            fprintf(stderr, _("unsupported encryption algorithm\n"));
            free(encrypted);
            return 1;
        }
        *unsafe_store = encrypted[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
    }

    status = secdat_decrypt_value(chain, encrypted, encrypted_length, plaintext, plaintext_length);
    free(encrypted);
    return status;
}

static int secdat_command_ls(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list visible_keys = {0};
    struct secdat_ls_options options;
    char canonical_base_dir[PATH_MAX];
    size_t index;

    if (secdat_parse_ls_options(cli, &options) != 0) {
        return 2;
    }

    if (secdat_domain_resolve_chain(cli->dir, &chain) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        return 1;
    }

    if (secdat_canonicalize_directory_path(cli->dir, canonical_base_dir, sizeof(canonical_base_dir)) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (secdat_collect_visible_keys(&chain, cli->store, &options.include_patterns, &options.exclude_patterns, &visible_keys) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    for (index = 0; index < visible_keys.count; index += 1) {
        char output[PATH_MAX * 2];
        size_t resolved_index = 0;
        char domain_path[PATH_MAX];

        if (!options.canonical_domain && !options.canonical_store) {
            puts(visible_keys.items[index]);
            continue;
        }

        if (secdat_find_effective_entry(&chain, cli->store, visible_keys.items[index], output, sizeof(output), &resolved_index) != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (options.canonical_domain) {
            if (secdat_domain_root_path(chain.ids[resolved_index], domain_path, sizeof(domain_path)) != 0) {
                secdat_key_list_free(&options.include_patterns);
                secdat_key_list_free(&options.exclude_patterns);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
            if (domain_path[0] == '\0') {
                if (secdat_copy_string(domain_path, sizeof(domain_path), canonical_base_dir) != 0) {
                    secdat_key_list_free(&options.include_patterns);
                    secdat_key_list_free(&options.exclude_patterns);
                    secdat_domain_chain_free(&chain);
                    secdat_key_list_free(&visible_keys);
                    return 1;
                }
            }
        } else {
            domain_path[0] = '\0';
        }

        if (secdat_format_canonical_key(
                output,
                sizeof(output),
                visible_keys.items[index],
                domain_path,
                secdat_effective_store_name(cli->store),
                options.canonical_domain,
                options.canonical_store) != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        puts(output);
    }

    secdat_key_list_free(&options.include_patterns);
    secdat_key_list_free(&options.exclude_patterns);
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return 0;
}

static int secdat_command_list(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list keys = {0};
    struct secdat_list_options options;
    size_t index;
    int status;

    status = secdat_parse_list_options(cli, &options);
    if (status != 0) {
        return status;
    }
    if (secdat_domain_resolve_chain(cli->dir, &chain) != 0) {
        return 1;
    }
    if (secdat_collect_list_keys(&chain, cli->store, &options, &keys) != 0) {
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&keys);
        return 1;
    }

    for (index = 0; index < keys.count; index += 1) {
        puts(keys.items[index]);
    }

    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&keys);
    return 0;
}

static int secdat_command_exists(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char entry_path[PATH_MAX];
    int status;

    if (cli->argc == 0) {
        fprintf(stderr, _("missing key for exists\n"));
        secdat_cli_print_try_help(cli, "exists");
        return 2;
    }
    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for exists\n"));
        secdat_cli_print_try_help(cli, "exists");
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }

    status = secdat_resolve_entry_path(&chain, reference.store_value, reference.key, entry_path, sizeof(entry_path));
    secdat_domain_chain_free(&chain);
    if (status == 0) {
        return 0;
    }
    return 1;
}

static void secdat_write_shell_quoted(FILE *stream, const char *value);

static int secdat_write_shell_quoted_bytes(FILE *stream, const char *key, const unsigned char *value, size_t value_length)
{
    size_t index;

    if (memchr(value, '\0', value_length) != NULL) {
        fprintf(stderr, _("key value contains NUL byte and cannot be shell-escaped: %s\n"), key);
        return 1;
    }

    fputc('\'', stream);
    for (index = 0; index < value_length; index += 1) {
        if (value[index] == '\'') {
            fputs("'\\''", stream);
        } else {
            fputc((int)value[index], stream);
        }
    }
    fputc('\'', stream);
    if (fflush(stream) != 0 || ferror(stream)) {
        fprintf(stderr, _("failed to write standard output\n"));
        return 1;
    }
    return 0;
}

static int secdat_command_get(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int shellescaped = 0;
    ssize_t written;
    size_t offset;

    if (cli->argc == 0) {
        fprintf(stderr, _("missing key for get\n"));
        secdat_cli_print_try_help(cli, "get");
        return 2;
    }

    if (cli->argc == 2) {
        if (strcmp(cli->argv[1], "--stdout") == 0 || strcmp(cli->argv[1], "-o") == 0) {
            shellescaped = 0;
        } else if (strcmp(cli->argv[1], "--shellescaped") == 0) {
            shellescaped = 1;
        } else {
            fprintf(stderr, _("invalid arguments for get\n"));
            secdat_cli_print_try_help(cli, "get");
            return 2;
        }
    } else if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for get\n"));
        secdat_cli_print_try_help(cli, "get");
        return 2;
    }

    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, _("refusing to write secret to a terminal\n"));
        return 1;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }

    if (secdat_load_resolved_plaintext(&chain, reference.store_value, reference.key, &plaintext, &plaintext_length, NULL, NULL) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (shellescaped) {
        if (secdat_write_shell_quoted_bytes(stdout, reference.key, plaintext, plaintext_length) != 0) {
            secdat_domain_chain_free(&chain);
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            return 1;
        }
    } else {
        offset = 0;
        while (offset < plaintext_length) {
            written = write(STDOUT_FILENO, plaintext + offset, plaintext_length - offset);
            if (written <= 0) {
                fprintf(stderr, _("failed to write standard output\n"));
                secdat_domain_chain_free(&chain);
                secdat_secure_clear(plaintext, plaintext_length);
                free(plaintext);
                return 1;
            }
            offset += (size_t)written;
        }
    }

    secdat_domain_chain_free(&chain);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    return 0;
}

static int secdat_store_plaintext(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status;

    status = secdat_ensure_store_dirs(domain_id, store_name);
    if (status != 0) {
        return status;
    }

    status = secdat_build_entry_path(domain_id, store_name, key, entry_path, sizeof(entry_path));
    if (status != 0) {
        return status;
    }

    status = secdat_build_tombstone_path(domain_id, store_name, key, tombstone_path, sizeof(tombstone_path));
    if (status != 0) {
        return status;
    }

    if (unsafe_store) {
        encrypted_length = SECDAT_HEADER_LEN + plaintext_length;
        encrypted = calloc(1, encrypted_length == 0 ? 1 : encrypted_length);
        if (encrypted == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic));
        encrypted[8] = SECDAT_ENTRY_VERSION;
        encrypted[9] = SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
        encrypted[10] = 0;
        encrypted[11] = 0;
        secdat_write_be32(encrypted + 12, (uint32_t)plaintext_length);
        memcpy(encrypted + SECDAT_HEADER_LEN, plaintext, plaintext_length);
    } else if (secdat_encrypt_value(domain_id, plaintext, plaintext_length, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    status = secdat_remove_if_exists(tombstone_path);
    if (status == 0) {
        status = secdat_atomic_write_file(entry_path, encrypted, encrypted_length);
    }

    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_command_set(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    char current_domain_id[PATH_MAX];
    const char *key;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    const char *environment_name;
    const char *environment_value;
    const char *literal_value = NULL;
    int read_stdin = 1;
    int unsafe_store = 0;
    int index;
    int status;

    if (cli->argc < 1) {
        fprintf(stderr, _("missing key for set\n"));
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    key = reference.key;
    for (index = 1; index < cli->argc; index += 1) {
        if (strcmp(cli->argv[index], "--unsafe") == 0) {
            if (unsafe_store) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            unsafe_store = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--stdin") == 0 || strcmp(cli->argv[index], "-i") == 0) {
            if (!read_stdin || literal_value != NULL) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            read_stdin = 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--value") == 0 || strcmp(cli->argv[index], "-v") == 0) {
            if (!read_stdin || literal_value != NULL || index + 1 >= cli->argc) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            literal_value = cli->argv[index + 1];
            read_stdin = 0;
            index += 1;
            continue;
        }
        if (strcmp(cli->argv[index], "--env") == 0 || strcmp(cli->argv[index], "-e") == 0) {
            if (!read_stdin || literal_value != NULL || index + 1 >= cli->argc) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            environment_name = cli->argv[index + 1];
            environment_value = getenv(environment_name);
            if (environment_value == NULL) {
                fprintf(stderr, _("environment variable is not set: %s\n"), environment_name);
                return 1;
            }

            literal_value = environment_value;
            read_stdin = 0;
            index += 1;
            continue;
        }
        if (cli->argv[index][0] != '-') {
            if (!read_stdin || literal_value != NULL) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            literal_value = cli->argv[index];
            read_stdin = 0;
            continue;
        }

        fprintf(stderr, _("invalid arguments for set\n"));
        secdat_cli_print_try_help(cli, "set");
        return 2;
    }

    if (read_stdin) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, _("refusing to read secret from a terminal\n"));
            return 1;
        }

        if (secdat_read_stdin(&plaintext, &plaintext_length) != 0) {
            return 1;
        }
    } else {
        plaintext_length = strlen(literal_value);
        plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
        if (plaintext == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(plaintext, literal_value, plaintext_length);
    }

    if (secdat_domain_resolve_current(reference.domain_value, current_domain_id, sizeof(current_domain_id)) != 0) {
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return 1;
    }

    status = secdat_store_plaintext(current_domain_id, reference.store_value, key, plaintext, plaintext_length, unsafe_store);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    return status;
}

static int secdat_write_empty_file(const char *path)
{
    return secdat_atomic_write_file(path, (const unsigned char *)"", 0);
}

static int secdat_remove_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key, int ignore_missing)
{
    char current_domain_id[PATH_MAX];
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    size_t index;
    int found_inherited = 0;

    if (chain->count == 0 || strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(current_domain_id, chain->ids[0]);

    if (secdat_build_entry_path(current_domain_id, store_name, key, entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    if (secdat_file_exists(entry_path)) {
        if (unlink(entry_path) != 0) {
            fprintf(stderr, _("failed to remove key: %s\n"), key);
            return 1;
        }
        return secdat_remove_if_exists(tombstone_path);
    }

    for (index = 1; index < chain->count; index += 1) {
        if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(entry_path)) {
            found_inherited = 1;
            break;
        }

        if (secdat_build_tombstone_path(chain->ids[index], store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(tombstone_path)) {
            break;
        }
    }

    if (!found_inherited) {
        if (ignore_missing) {
            return 0;
        }
        fprintf(stderr, _("key not found: %s\n"), key);
        return 1;
    }

    if (secdat_ensure_store_dirs(current_domain_id, store_name) != 0) {
        return 1;
    }

    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    return secdat_write_empty_file(tombstone_path);
}

static int secdat_mask_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    char current_domain_id[PATH_MAX];
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    size_t index;
    int found_inherited = 0;

    if (chain->count == 0 || strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(current_domain_id, chain->ids[0]);

    if (secdat_build_entry_path(current_domain_id, store_name, key, entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    if (secdat_file_exists(tombstone_path)) {
        return 0;
    }
    if (secdat_file_exists(entry_path)) {
        fprintf(stderr, _("key exists locally and cannot be masked: %s\n"), key);
        return 1;
    }

    for (index = 1; index < chain->count; index += 1) {
        if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(entry_path)) {
            found_inherited = 1;
            break;
        }

        if (secdat_build_tombstone_path(chain->ids[index], store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(tombstone_path)) {
            break;
        }
    }

    if (!found_inherited) {
        fprintf(stderr, _("key not found: %s\n"), key);
        return 1;
    }

    if (secdat_ensure_store_dirs(current_domain_id, store_name) != 0) {
        return 1;
    }

    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    return secdat_write_empty_file(tombstone_path);
}

static int secdat_unmask_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    char current_domain_id[PATH_MAX];
    char tombstone_path[PATH_MAX];

    if (chain->count == 0 || strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(current_domain_id, chain->ids[0]);

    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }
    if (!secdat_file_exists(tombstone_path)) {
        fprintf(stderr, _("key is not masked in current domain: %s\n"), key);
        return 1;
    }

    return secdat_remove_if_exists(tombstone_path);
}

static int secdat_command_cp(const struct secdat_cli *cli)
{
    struct secdat_key_reference source_reference;
    struct secdat_key_reference destination_reference;
    struct secdat_domain_chain source_chain = {0};
    struct secdat_domain_chain destination_chain = {0};
    char destination_domain_id[PATH_MAX];
    char destination_path[PATH_MAX];
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int unsafe_store = 0;
    int status;

    if (cli->argc != 2) {
        fprintf(stderr, _("invalid arguments for cp\n"));
        secdat_cli_print_try_help(cli, "cp");
        return 2;
    }
    if (strcmp(cli->argv[0], cli->argv[1]) == 0) {
        fprintf(stderr, _("source and destination keys must differ\n"));
        return 1;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &source_reference) != 0) {
        return 1;
    }
    if (secdat_parse_key_reference(cli->argv[1], cli->dir, cli->store, &destination_reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(source_reference.domain_value, &source_chain) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(destination_reference.domain_value, &destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        return 1;
    }
    if (destination_chain.count == 0 || strlen(destination_chain.ids[0]) >= sizeof(destination_domain_id)) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(destination_domain_id, destination_chain.ids[0]);

    if (secdat_resolve_entry_path(&destination_chain, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("destination key already exists: %s\n"), destination_reference.key);
        return 1;
    }

    if (secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext(destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store);
    secdat_domain_chain_free(&source_chain);
    secdat_domain_chain_free(&destination_chain);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    return status;
}

static int secdat_command_mv(const struct secdat_cli *cli)
{
    struct secdat_key_reference source_reference;
    struct secdat_key_reference destination_reference;
    struct secdat_domain_chain source_chain = {0};
    struct secdat_domain_chain destination_chain = {0};
    char destination_domain_id[PATH_MAX];
    char destination_path[PATH_MAX];
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int unsafe_store = 0;
    int status;

    if (cli->argc != 2) {
        fprintf(stderr, _("invalid arguments for mv\n"));
        secdat_cli_print_try_help(cli, "mv");
        return 2;
    }
    if (strcmp(cli->argv[0], cli->argv[1]) == 0) {
        fprintf(stderr, _("source and destination keys must differ\n"));
        return 1;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &source_reference) != 0) {
        return 1;
    }
    if (secdat_parse_key_reference(cli->argv[1], cli->dir, cli->store, &destination_reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(source_reference.domain_value, &source_chain) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(destination_reference.domain_value, &destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        return 1;
    }
    if (destination_chain.count == 0 || strlen(destination_chain.ids[0]) >= sizeof(destination_domain_id)) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(destination_domain_id, destination_chain.ids[0]);

    if (secdat_resolve_entry_path(&destination_chain, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("destination key already exists: %s\n"), destination_reference.key);
        return 1;
    }

    if (secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext(destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    if (status != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return status;
    }

    status = secdat_remove_key_in_chain(&source_chain, source_reference.store_value, source_reference.key, 0);
    if (status != 0) {
        if (secdat_build_entry_path(destination_domain_id, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
            unlink(destination_path);
        }
    }

    secdat_domain_chain_free(&source_chain);
    secdat_domain_chain_free(&destination_chain);
    return status;
}

static int secdat_command_mask(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    int status;

    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for mask\n"));
        secdat_cli_print_try_help(cli, "mask");
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    status = secdat_mask_key_in_chain(&chain, reference.store_value, reference.key);
    secdat_domain_chain_free(&chain);
    return status;
}

static int secdat_command_unmask(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    int status;

    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for unmask\n"));
        secdat_cli_print_try_help(cli, "unmask");
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    status = secdat_unmask_key_in_chain(&chain, reference.store_value, reference.key);
    secdat_domain_chain_free(&chain);
    return status;
}

static int secdat_command_rm(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    int ignore_missing = 0;
    int status;

    if (cli->argc == 2 && strcmp(cli->argv[0], "--ignore-missing") == 0) {
        ignore_missing = 1;
    } else if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for rm\n"));
        secdat_cli_print_try_help(cli, "rm");
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[ignore_missing ? 1 : 0], cli->dir, cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    status = secdat_remove_key_in_chain(&chain, reference.store_value, reference.key, ignore_missing);
    secdat_domain_chain_free(&chain);
    return status;
}

static int secdat_collect_store_names(const char *domain_id, const char *pattern, struct secdat_key_list *stores)
{
    char domain_root[PATH_MAX];
    DIR *directory;
    struct dirent *entry;
    char *decoded_name = NULL;

    if (secdat_store_root(domain_id, NULL, domain_root, sizeof(domain_root)) != 0) {
        return 1;
    }
    secdat_parent_path(domain_root);

    directory = opendir(domain_root);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), domain_root);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (secdat_unescape_component(entry->d_name, &decoded_name) != 0) {
            closedir(directory);
            return 1;
        }
        if (pattern == NULL || fnmatch(pattern, decoded_name, 0) == 0) {
            if (secdat_key_list_append(stores, decoded_name) != 0) {
                free(decoded_name);
                closedir(directory);
                return 1;
            }
        }
        free(decoded_name);
        decoded_name = NULL;
    }

    closedir(directory);
    qsort(stores->items, stores->count, sizeof(*stores->items), secdat_compare_strings);
    return 0;
}

static int secdat_store_command_ls(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    struct secdat_key_list stores = {0};
    const char *pattern = NULL;
    size_t index;

    if (cli->store != NULL) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (secdat_parse_simple_ls_pattern(cli, "store ls", &pattern) != 0) {
        return 2;
    }

    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_collect_store_names(current_domain_id, pattern, &stores) != 0) {
        secdat_key_list_free(&stores);
        return 1;
    }

    for (index = 0; index < stores.count; index += 1) {
        puts(stores.items[index]);
    }

    secdat_key_list_free(&stores);
    return 0;
}

static int secdat_store_command_create(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct stat status;

    if (cli->store != NULL) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (cli->argc == 0) {
        fprintf(stderr, _("missing store name for store create\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for store create\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }

    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_store_root(current_domain_id, cli->argv[0], store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    if (stat(store_root, &status) == 0) {
        fprintf(stderr, _("store already exists: %s\n"), cli->argv[0]);
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

static int secdat_store_command_delete(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];

    if (cli->store != NULL) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (cli->argc == 0) {
        fprintf(stderr, _("missing store name for store delete\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for store delete\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }

    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_store_root(current_domain_id, cli->argv[0], store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    if (secdat_join_path(entries_dir, sizeof(entries_dir), store_root, "entries") != 0) {
        return 1;
    }
    if (secdat_join_path(tombstones_dir, sizeof(tombstones_dir), store_root, "tombstones") != 0) {
        return 1;
    }
    if (!secdat_directory_is_empty(entries_dir) || !secdat_directory_is_empty(tombstones_dir)) {
        fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
        return 1;
    }
    if (rmdir(entries_dir) != 0 || rmdir(tombstones_dir) != 0 || rmdir(store_root) != 0) {
        fprintf(stderr, _("failed to remove directory: %s\n"), store_root);
        return 1;
    }

    return 0;
}

static int secdat_plaintext_to_env_value(
    const char *key,
    const unsigned char *plaintext,
    size_t plaintext_length,
    char **value_out
)
{
    char *value;

    if (memchr(plaintext, '\0', plaintext_length) != NULL) {
        fprintf(stderr, _("key value contains NUL byte and cannot be exported: %s\n"), key);
        return 1;
    }

    value = malloc(plaintext_length + 1);
    if (value == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    if (plaintext_length > 0) {
        memcpy(value, plaintext, plaintext_length);
    }
    value[plaintext_length] = '\0';
    *value_out = value;
    return 0;
}

static int secdat_is_shell_identifier(const char *value)
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

static void secdat_write_shell_quoted(FILE *stream, const char *value)
{
    size_t index;

    fputc('\'', stream);
    for (index = 0; value[index] != '\0'; index += 1) {
        if (value[index] == '\'') {
            fputs("'\\''", stream);
        } else {
            fputc(value[index], stream);
        }
    }
    fputc('\'', stream);
}

static int secdat_command_export(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list visible_keys = {0};
    struct secdat_key_list include_patterns = {0};
    const char *pattern = NULL;
    char canonical_dir[PATH_MAX];
    size_t key_index;

    if (cli->argc == 2 && (strcmp(cli->argv[0], "--pattern") == 0 || strcmp(cli->argv[0], "-p") == 0)) {
        pattern = cli->argv[1];
    } else if (cli->argc != 0) {
        fprintf(stderr, _("invalid arguments for export\n"));
        secdat_cli_print_try_help(cli, "export");
        return 2;
    }

    if (secdat_canonicalize_directory_path(cli->dir, canonical_dir, sizeof(canonical_dir)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(cli->dir, &chain) != 0) {
        return 1;
    }
    if (pattern != NULL && secdat_key_list_append(&include_patterns, pattern) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_collect_visible_keys(&chain, cli->store, &include_patterns, NULL, &visible_keys) != 0) {
        secdat_key_list_free(&include_patterns);
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    for (key_index = 0; key_index < visible_keys.count; key_index += 1) {
        if (!secdat_is_shell_identifier(visible_keys.items[key_index])) {
            fprintf(stderr, _("key is not a valid shell identifier: %s\n"), visible_keys.items[key_index]);
            secdat_key_list_free(&include_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        fputs("eval \"export ", stdout);
        fputs(visible_keys.items[key_index], stdout);
        fputs("=$(", stdout);
        secdat_write_shell_quoted(stdout, cli->program_name == NULL ? "secdat" : cli->program_name);
        fputs(" --dir ", stdout);
        secdat_write_shell_quoted(stdout, canonical_dir);
        if (cli->store != NULL) {
            fputs(" --store ", stdout);
            secdat_write_shell_quoted(stdout, cli->store);
        }
        fputs(" get ", stdout);
        secdat_write_shell_quoted(stdout, visible_keys.items[key_index]);
        fputs(" --shellescaped)\"\n", stdout);
    }

    secdat_key_list_free(&include_patterns);
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return 0;
}

static int secdat_command_exec(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list visible_keys = {0};
    struct secdat_exec_options options;
    char **command_argv;
    size_t key_index;
    int status;

    status = secdat_parse_exec_options(cli, &options);
    if (status != 0) {
        secdat_cli_print_try_help(cli, "exec");
        return status;
    }

    if (secdat_domain_resolve_chain(cli->dir, &chain) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        return 1;
    }
    if (secdat_collect_visible_keys(&chain, cli->store, &options.include_patterns, &options.exclude_patterns, &visible_keys) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    for (key_index = 0; key_index < visible_keys.count; key_index += 1) {
        unsigned char *plaintext = NULL;
        size_t plaintext_length = 0;
        char *env_value = NULL;

        status = secdat_load_resolved_plaintext(
            &chain,
            cli->store,
            visible_keys.items[key_index],
            &plaintext,
            &plaintext_length,
            NULL,
            NULL
        );
        if (status != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        status = secdat_plaintext_to_env_value(
            visible_keys.items[key_index],
            plaintext,
            plaintext_length,
            &env_value
        );
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        if (status != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (setenv(visible_keys.items[key_index], env_value, 1) != 0) {
            fprintf(stderr, _("failed to export key to environment: %s\n"), visible_keys.items[key_index]);
            secdat_secure_clear(env_value, strlen(env_value));
            free(env_value);
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        secdat_secure_clear(env_value, strlen(env_value));
        free(env_value);
    }

    command_argv = &cli->argv[options.command_index];
    secdat_key_list_free(&options.include_patterns);
    secdat_key_list_free(&options.exclude_patterns);
    execvp(command_argv[0], command_argv);

    fprintf(stderr, _("failed to execute command: %s\n"), command_argv[0]);
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return 1;
}

static int secdat_command_save(const struct secdat_cli *cli)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    char passphrase[512];
    int status;

    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for save\n"));
        secdat_cli_print_try_help(cli, "save");
        return 2;
    }
    if (secdat_read_secret_confirmation_prompts(
            _("Create secdat bundle passphrase: "),
            _("Confirm secdat bundle passphrase: "),
            passphrase,
            sizeof(passphrase)
        ) != 0) {
        return 1;
    }
    if (secdat_collect_bundle_payload(cli, &payload, &payload_length) != 0) {
        secdat_secure_clear(passphrase, strlen(passphrase));
        return 1;
    }

    status = secdat_write_secret_bundle_file(cli->argv[0], passphrase, payload, payload_length);
    secdat_secure_clear(passphrase, strlen(passphrase));
    secdat_secure_clear(payload, payload_length);
    free(payload);
    return status;
}

static int secdat_command_load(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    size_t offset = 0;
    uint32_t entry_count;
    uint32_t index;
    char passphrase[512];
    int status = 1;

    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for load\n"));
        secdat_cli_print_try_help(cli, "load");
        return 2;
    }
    if (secdat_domain_resolve_current(cli->dir, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_read_secret_from_tty(_("Enter secdat bundle passphrase: "), passphrase, sizeof(passphrase)) != 0) {
        return 1;
    }
    if (secdat_decrypt_secret_bundle(cli->argv[0], passphrase, &payload, &payload_length) != 0) {
        secdat_secure_clear(passphrase, strlen(passphrase));
        return 1;
    }
    secdat_secure_clear(passphrase, strlen(passphrase));

    if (secdat_bundle_read_u32(payload, payload_length, &offset, &entry_count) != 0) {
        goto cleanup;
    }
    for (index = 0; index < entry_count; index += 1) {
        uint32_t key_length;
        uint32_t value_length;
        char *key = NULL;

        if (secdat_bundle_read_u32(payload, payload_length, &offset, &key_length) != 0
            || secdat_bundle_read_u32(payload, payload_length, &offset, &value_length) != 0) {
            goto cleanup;
        }
        if (key_length == 0 || offset + key_length + value_length > payload_length) {
            fprintf(stderr, _("invalid secret bundle\n"));
            goto cleanup;
        }
        if (memchr(payload + offset, '\0', key_length) != NULL) {
            fprintf(stderr, _("invalid secret bundle\n"));
            goto cleanup;
        }

        key = malloc((size_t)key_length + 1);
        if (key == NULL) {
            fprintf(stderr, _("out of memory\n"));
            goto cleanup;
        }
        memcpy(key, payload + offset, key_length);
        key[key_length] = '\0';
        offset += key_length;

        if (secdat_store_plaintext(current_domain_id, cli->store, key, payload + offset, value_length, 0) != 0) {
            secdat_secure_clear(key, (size_t)key_length + 1);
            free(key);
            goto cleanup;
        }
        secdat_secure_clear(key, (size_t)key_length + 1);
        free(key);
        offset += value_length;
    }
    if (offset != payload_length) {
        fprintf(stderr, _("invalid secret bundle\n"));
        goto cleanup;
    }
    status = 0;

cleanup:
    if (payload != NULL) {
        secdat_secure_clear(payload, payload_length);
        free(payload);
    }
    return status;
}

int secdat_run_command(const struct secdat_cli *cli)
{
    int status;

    switch (cli->command) {
    case SECDAT_COMMAND_LS:
        return secdat_command_ls(cli);
    case SECDAT_COMMAND_LIST:
        return secdat_command_list(cli);
    case SECDAT_COMMAND_MASK:
        return secdat_command_mask(cli);
    case SECDAT_COMMAND_UNMASK:
        return secdat_command_unmask(cli);
    case SECDAT_COMMAND_EXISTS:
        return secdat_command_exists(cli);
    case SECDAT_COMMAND_GET:
        return secdat_command_get(cli);
    case SECDAT_COMMAND_SET:
        return secdat_command_set(cli);
    case SECDAT_COMMAND_RM:
        return secdat_command_rm(cli);
    case SECDAT_COMMAND_MV:
        return secdat_command_mv(cli);
    case SECDAT_COMMAND_CP:
        return secdat_command_cp(cli);
    case SECDAT_COMMAND_EXEC:
        return secdat_command_exec(cli);
    case SECDAT_COMMAND_EXPORT:
        return secdat_command_export(cli);
    case SECDAT_COMMAND_SAVE:
        return secdat_command_save(cli);
    case SECDAT_COMMAND_LOAD:
        return secdat_command_load(cli);
    case SECDAT_COMMAND_UNLOCK:
        return secdat_command_unlock(cli);
    case SECDAT_COMMAND_PASSWD:
        return secdat_command_passwd(cli);
    case SECDAT_COMMAND_LOCK:
        return secdat_command_lock(cli);
    case SECDAT_COMMAND_STATUS:
        return secdat_command_status(cli);
    case SECDAT_COMMAND_STORE_CREATE:
        return secdat_store_command_create(cli);
    case SECDAT_COMMAND_STORE_DELETE:
        return secdat_store_command_delete(cli);
    case SECDAT_COMMAND_STORE_LS:
        return secdat_store_command_ls(cli);
    case SECDAT_COMMAND_DOMAIN_CREATE:
    case SECDAT_COMMAND_DOMAIN_DELETE:
    case SECDAT_COMMAND_DOMAIN_LS:
        return secdat_handle_domain_command(cli);
    default:
        fprintf(stderr, _("command not implemented yet: %s\n"), secdat_cli_command_name(cli->command));
        if (cli->dir != NULL) {
            fprintf(stderr, _("  dir=%s\n"), cli->dir);
        }
        if (cli->store != NULL) {
            fprintf(stderr, _("  store=%s\n"), cli->store);
        }
        status = 1;
        return status;
    }
}