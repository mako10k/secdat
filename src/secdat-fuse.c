#include "config.h"

#define FUSE_USE_VERSION 31

#include "domain.h"
#include "i18n.h"
#include "secdat-sdk.h"
#include "store.h"

#include <errno.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECDAT_BUILD_ID
#define SECDAT_BUILD_ID ""
#endif

struct secdat_fuse_string_list {
    const char **items;
    size_t count;
    size_t capacity;
};

struct secdat_fuse_state {
    struct secdat_sdk_options options;
    struct secdat_sdk_list_filters filters;
    struct secdat_fuse_string_list include_patterns;
    struct secdat_fuse_string_list exclude_patterns;
    struct secdat_fuse_string_list required_keys;
    char dir_buffer[PATH_MAX];
    char domain_buffer[PATH_MAX];
    const char *mountpoint;
    char **command_argv;
    int ready_fd;
    int foreground;
    int debug;
    int dry_run;
    int json;
    int size_metadata;
};

static int secdat_fuse_truncate(const char *path, off_t size, struct fuse_file_info *file_info);

static void secdat_fuse_i18n_init(void)
{
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);
}

static void secdat_fuse_secure_clear(void *buffer, size_t length)
{
    volatile unsigned char *cursor = buffer;

    while (length > 0) {
        *cursor = 0;
        cursor += 1;
        length -= 1;
    }
}

static void secdat_fuse_print_usage(const char *program_name, FILE *stream)
{
    fprintf(
        stream,
        _("Usage: %s [OPTIONS] MOUNTPOINT [-- CMD [ARGS...]]\n"
          "\n"
          "Mount selected secdat keys as files.\n"
          "With CMD, mount, run the command, then unmount automatically.\n"
          "\n"
          "Options:\n"
          "  -d, --dir DIR              set the base directory used for domain resolution\n"
          "      --domain DIR           require one exact registered domain root\n"
          "  -s, --store STORE          select the store namespace\n"
          "  -p, --pattern GLOB         include matching keys; may be repeated\n"
          "  -x, --pattern-exclude GLOB exclude matching keys; may be repeated\n"
          "      --sandbox-injectable   include only keys allowed for bulk sandbox injection\n"
          "      --require-key KEY      fail unless KEY remains selected; may be repeated\n"
          "      --dry-run              list files that would be mounted without mounting\n"
          "      --json                 write dry-run output as JSON\n"
          "      --size-metadata        report file sizes by reading secret values in getattr\n"
          "  -f, --foreground           keep the FUSE process in the foreground\n"
          "      --debug                enable FUSE debug output\n"
          "  -h, --help                 show this help\n"
          "  -V, --version              print the secdat-fuse version\n"),
        program_name
    );
}

static void secdat_fuse_print_version(void)
{
    printf("secdat-fuse %s", PACKAGE_VERSION);
    if (SECDAT_BUILD_ID[0] != '\0') {
        printf(" (%s)", SECDAT_BUILD_ID);
    }
    putchar('\n');
}

static void secdat_fuse_string_list_free(struct secdat_fuse_string_list *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int secdat_fuse_string_list_contains(const struct secdat_fuse_string_list *list, const char *value)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index], value) == 0) {
            return 1;
        }
    }
    return 0;
}

static int secdat_fuse_string_list_append(struct secdat_fuse_string_list *list, const char *value)
{
    const char **new_items;
    size_t new_capacity;

    if (secdat_fuse_string_list_contains(list, value)) {
        return 0;
    }
    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 4 : list->capacity * 2;
        new_items = realloc(list->items, sizeof(*new_items) * new_capacity);
        if (new_items == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }
    list->items[list->count] = value;
    list->count += 1;
    return 0;
}

static int secdat_fuse_path_to_key(const char *path, const char **key_out)
{
    const char *key;

    if (path == NULL || path[0] != '/') {
        return -ENOENT;
    }
    if (strcmp(path, "/") == 0) {
        *key_out = NULL;
        return 0;
    }

    key = path + 1;
    if (key[0] == '\0' || strchr(key, '/') != NULL) {
        return -ENOENT;
    }
    *key_out = key;
    return 0;
}

static int secdat_fuse_canonicalize_dir(const char *path, char *buffer, size_t size)
{
    const char *resolved_path = path != NULL ? path : ".";
    char resolved[PATH_MAX];

    if (realpath(resolved_path, resolved) == NULL) {
        fprintf(stderr, _("failed to resolve directory: %s\n"), resolved_path);
        return 1;
    }
    if (strlen(resolved) >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    strcpy(buffer, resolved);
    return 0;
}

static int secdat_fuse_pattern_list_matches(const struct secdat_fuse_string_list *patterns, const char *key)
{
    size_t index;

    for (index = 0; index < patterns->count; index += 1) {
        if (fnmatch(patterns->items[index], key, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

static int secdat_fuse_key_matches_selection(const struct secdat_fuse_state *state, const char *key)
{
    if (state->include_patterns.count > 0
        && !secdat_fuse_pattern_list_matches(&state->include_patterns, key)) {
        return 0;
    }
    if (state->exclude_patterns.count > 0
        && secdat_fuse_pattern_list_matches(&state->exclude_patterns, key)) {
        return 0;
    }
    return 1;
}

static int secdat_fuse_collect_selected_keys(
    const struct secdat_fuse_state *state,
    struct secdat_sdk_key_metadata_list *keys
)
{
    size_t read_index;
    size_t write_index = 0;

    memset(keys, 0, sizeof(*keys));
    if (secdat_sdk_list_keys_with_patterns(
            &state->options,
            &state->filters,
            state->include_patterns.items,
            state->include_patterns.count,
            state->exclude_patterns.items,
            state->exclude_patterns.count,
            keys) != 0) {
        return 1;
    }

    for (read_index = 0; read_index < keys->count; read_index += 1) {
        if (!secdat_fuse_key_matches_selection(state, keys->items[read_index].key)) {
            continue;
        }
        if (write_index != read_index) {
            keys->items[write_index] = keys->items[read_index];
        }
        write_index += 1;
    }
    keys->count = write_index;
    return 0;
}

static int secdat_fuse_selected_keys_contain(
    const struct secdat_sdk_key_metadata_list *keys,
    const char *required_key
)
{
    size_t index;

    for (index = 0; index < keys->count; index += 1) {
        if (strcmp(keys->items[index].key, required_key) == 0) {
            return 1;
        }
    }
    return 0;
}

static int secdat_fuse_missing_required_count(
    const struct secdat_fuse_state *state,
    const struct secdat_sdk_key_metadata_list *keys
)
{
    size_t index;
    int missing_count = 0;

    for (index = 0; index < state->required_keys.count; index += 1) {
        if (!secdat_fuse_selected_keys_contain(keys, state->required_keys.items[index])) {
            missing_count += 1;
        }
    }
    return missing_count;
}

static int secdat_fuse_key_is_selected(struct secdat_fuse_state *state, const char *key)
{
    struct secdat_sdk_key_metadata_list keys = {0};
    size_t index;
    int selected = 0;

    if (secdat_fuse_collect_selected_keys(state, &keys) != 0) {
        return -EACCES;
    }

    for (index = 0; index < keys.count; index += 1) {
        if (strcmp(keys.items[index].key, key) == 0) {
            selected = 1;
            break;
        }
    }
    secdat_sdk_free(keys.items);
    return selected ? 0 : -ENOENT;
}

static void *secdat_fuse_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char ready = '1';
    ssize_t written;

    (void)conn;

    cfg->kernel_cache = 0;
    cfg->auto_cache = 0;
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;
    cfg->direct_io = 1;
    if (state != NULL && state->ready_fd >= 0) {
        do {
            written = write(state->ready_fd, &ready, 1);
        } while (written < 0 && errno == EINTR);
        close(state->ready_fd);
        state->ready_fd = -1;
    }
    return state;
}

static int secdat_fuse_getattr(const char *path, struct stat *status, struct fuse_file_info *file_info)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    int result;

    (void)file_info;

    memset(status, 0, sizeof(*status));
    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }

    if (key == NULL) {
        status->st_mode = S_IFDIR | 0500;
        status->st_nlink = 2;
        status->st_uid = getuid();
        status->st_gid = getgid();
        return 0;
    }

    result = secdat_fuse_key_is_selected(state, key);
    if (result != 0) {
        return result;
    }

    status->st_mode = S_IFREG | 0600;
    status->st_nlink = 1;
    status->st_size = 0;
    if (state->size_metadata) {
        if (secdat_sdk_get(&state->options, key, &value, &value_length, &unsafe_store) != 0) {
            return -EACCES;
        }
        (void)unsafe_store;
        status->st_size = (off_t)value_length;
        secdat_fuse_secure_clear(value, value_length);
        secdat_sdk_free(value);
    }
    status->st_uid = getuid();
    status->st_gid = getgid();
    return 0;
}

static int secdat_fuse_readdir(
    const char *path,
    void *buffer,
    fuse_fill_dir_t filler,
    off_t offset,
    struct fuse_file_info *file_info,
    enum fuse_readdir_flags flags
)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    struct secdat_sdk_key_metadata_list keys = {0};
    size_t index;

    (void)offset;
    (void)file_info;
    (void)flags;

    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }

    if (secdat_fuse_collect_selected_keys(state, &keys) != 0) {
        return -EACCES;
    }

    if (filler(buffer, ".", NULL, 0, 0) != 0
        || filler(buffer, "..", NULL, 0, 0) != 0) {
        secdat_sdk_free(keys.items);
        return 0;
    }
    for (index = 0; index < keys.count; index += 1) {
        if (filler(buffer, keys.items[index].key, NULL, 0, 0) != 0) {
            break;
        }
    }
    secdat_sdk_free(keys.items);
    return 0;
}

static int secdat_fuse_open(const char *path, struct fuse_file_info *file_info)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
    int result;
    int access_mode;

    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }
    if (key == NULL) {
        return -EISDIR;
    }
    access_mode = file_info->flags & O_ACCMODE;
    if (access_mode != O_RDONLY && access_mode != O_WRONLY && access_mode != O_RDWR) {
        return -EINVAL;
    }
    result = secdat_fuse_key_is_selected(state, key);
    if (result != 0) {
        return result;
    }
    if (access_mode != O_RDONLY && (file_info->flags & O_TRUNC) != 0) {
        return secdat_fuse_truncate(path, 0, file_info);
    }
    return 0;
}

static int secdat_fuse_read(
    const char *path,
    char *buffer,
    size_t size,
    off_t offset,
    struct fuse_file_info *file_info
)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    int result;

    (void)file_info;

    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }
    if (key == NULL) {
        return -EISDIR;
    }

    result = secdat_fuse_key_is_selected(state, key);
    if (result != 0) {
        return result;
    }

    if (secdat_sdk_get(&state->options, key, &value, &value_length, &unsafe_store) != 0) {
        return -EACCES;
    }

    (void)unsafe_store;
    if (offset < 0 || (size_t)offset >= value_length) {
        result = 0;
    } else {
        size_t available = value_length - (size_t)offset;
        size_t copy_length = size < available ? size : available;

        memcpy(buffer, value + offset, copy_length);
        result = (int)copy_length;
    }

    secdat_fuse_secure_clear(value, value_length);
    secdat_sdk_free(value);
    return result;
}

static int secdat_fuse_readonly(void)
{
    return -EROFS;
}

static int secdat_fuse_mknod(const char *path, mode_t mode, dev_t device)
{
    (void)path;
    (void)mode;
    (void)device;
    return secdat_fuse_readonly();
}

static int secdat_fuse_mkdir(const char *path, mode_t mode)
{
    (void)path;
    (void)mode;
    return secdat_fuse_readonly();
}

static int secdat_fuse_unlink(const char *path)
{
    (void)path;
    return secdat_fuse_readonly();
}

static int secdat_fuse_rmdir(const char *path)
{
    (void)path;
    return secdat_fuse_readonly();
}

static int secdat_fuse_rename(const char *from, const char *to, unsigned int flags)
{
    (void)from;
    (void)to;
    (void)flags;
    return secdat_fuse_readonly();
}

static int secdat_fuse_chmod(const char *path, mode_t mode, struct fuse_file_info *file_info)
{
    (void)path;
    (void)mode;
    (void)file_info;
    return secdat_fuse_readonly();
}

static int secdat_fuse_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *file_info)
{
    (void)path;
    (void)uid;
    (void)gid;
    (void)file_info;
    return secdat_fuse_readonly();
}

static int secdat_fuse_resize_key(struct secdat_fuse_state *state, const char *key, size_t new_length)
{
    unsigned char *value = NULL;
    unsigned char *resized = NULL;
    size_t value_length = 0;
    size_t copy_length;
    int unsafe_store = 0;
    int result = 0;

    if (secdat_sdk_get(&state->options, key, &value, &value_length, &unsafe_store) != 0) {
        return -EACCES;
    }

    resized = malloc(new_length == 0 ? 1 : new_length);
    if (resized == NULL) {
        secdat_fuse_secure_clear(value, value_length);
        secdat_sdk_free(value);
        return -ENOMEM;
    }
    if (new_length > 0) {
        memset(resized, 0, new_length);
        copy_length = value_length < new_length ? value_length : new_length;
        if (copy_length > 0) {
            memcpy(resized, value, copy_length);
        }
    }

    (void)unsafe_store;
    if (secdat_sdk_set_preserve_attrs(&state->options, key, resized, new_length) != 0) {
        result = -EACCES;
    }
    secdat_fuse_secure_clear(resized, new_length);
    free(resized);
    secdat_fuse_secure_clear(value, value_length);
    secdat_sdk_free(value);
    return result;
}

static int secdat_fuse_truncate(const char *path, off_t size, struct fuse_file_info *file_info)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
    int result;

    (void)file_info;

    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }
    if (key == NULL) {
        return -EISDIR;
    }
    if (size < 0) {
        return -EINVAL;
    }
    result = secdat_fuse_key_is_selected(state, key);
    if (result != 0) {
        return result;
    }
    return secdat_fuse_resize_key(state, key, (size_t)size);
}

static int secdat_fuse_write(
    const char *path,
    const char *buffer,
    size_t size,
    off_t offset,
    struct fuse_file_info *file_info
)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
    unsigned char *value = NULL;
    unsigned char *updated = NULL;
    size_t value_length = 0;
    size_t write_offset;
    size_t end_offset;
    size_t updated_length;
    int unsafe_store = 0;
    int result;

    if (size > INT_MAX) {
        return -EFBIG;
    }
    if (offset < 0) {
        return -EINVAL;
    }

    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }
    if (key == NULL) {
        return -EISDIR;
    }
    result = secdat_fuse_key_is_selected(state, key);
    if (result != 0) {
        return result;
    }
    if (size == 0) {
        return 0;
    }

    if (secdat_sdk_get(&state->options, key, &value, &value_length, &unsafe_store) != 0) {
        return -EACCES;
    }
    (void)unsafe_store;

    if (file_info != NULL && (file_info->flags & O_APPEND) != 0) {
        write_offset = value_length;
    } else {
        write_offset = (size_t)offset;
    }
    if (write_offset > (size_t)-1 - size) {
        secdat_fuse_secure_clear(value, value_length);
        secdat_sdk_free(value);
        return -EFBIG;
    }
    end_offset = write_offset + size;

    updated_length = value_length > end_offset ? value_length : end_offset;
    updated = malloc(updated_length == 0 ? 1 : updated_length);
    if (updated == NULL) {
        secdat_fuse_secure_clear(value, value_length);
        secdat_sdk_free(value);
        return -ENOMEM;
    }
    memset(updated, 0, updated_length);
    if (value_length > 0) {
        memcpy(updated, value, value_length);
    }
    memcpy(updated + write_offset, buffer, size);

    if (secdat_sdk_set_preserve_attrs(&state->options, key, updated, updated_length) != 0) {
        result = -EACCES;
    } else {
        result = (int)size;
    }

    secdat_fuse_secure_clear(updated, updated_length);
    free(updated);
    secdat_fuse_secure_clear(value, value_length);
    secdat_sdk_free(value);
    return result;
}

static int secdat_fuse_create(const char *path, mode_t mode, struct fuse_file_info *file_info)
{
    (void)path;
    (void)mode;
    (void)file_info;
    return secdat_fuse_readonly();
}

static const struct fuse_operations secdat_fuse_operations = {
    .init = secdat_fuse_init,
    .getattr = secdat_fuse_getattr,
    .readdir = secdat_fuse_readdir,
    .open = secdat_fuse_open,
    .read = secdat_fuse_read,
    .mkdir = secdat_fuse_mkdir,
    .mknod = secdat_fuse_mknod,
    .unlink = secdat_fuse_unlink,
    .rmdir = secdat_fuse_rmdir,
    .rename = secdat_fuse_rename,
    .chmod = secdat_fuse_chmod,
    .chown = secdat_fuse_chown,
    .truncate = secdat_fuse_truncate,
    .write = secdat_fuse_write,
    .create = secdat_fuse_create,
};

static void secdat_write_json_string_list(FILE *stream, const struct secdat_fuse_string_list *list)
{
    size_t index;

    fputc('[', stream);
    for (index = 0; index < list->count; index += 1) {
        if (index > 0) {
            fputs(", ", stream);
        }
        secdat_write_json_string(stream, list->items[index]);
    }
    fputc(']', stream);
}

static void secdat_fuse_write_json_missing_required_keys(
    FILE *stream,
    const struct secdat_fuse_state *state,
    const struct secdat_sdk_key_metadata_list *keys
)
{
    size_t index;
    int emitted = 0;

    fputc('[', stream);
    for (index = 0; index < state->required_keys.count; index += 1) {
        if (secdat_fuse_selected_keys_contain(keys, state->required_keys.items[index])) {
            continue;
        }
        if (emitted) {
            fputs(", ", stream);
        }
        secdat_write_json_string(stream, state->required_keys.items[index]);
        emitted = 1;
    }
    fputc(']', stream);
}

static void secdat_fuse_write_json_files(
    FILE *stream,
    const struct secdat_sdk_key_metadata_list *keys,
    int include_files
)
{
    size_t index;
    size_t emitted = 0;

    fputc('[', stream);
    if (include_files) {
        for (index = 0; index < keys->count; index += 1) {
            if (emitted > 0) {
                fputs(", ", stream);
            }
            secdat_write_json_string(stream, keys->items[index].key);
            emitted += 1;
        }
    }
    fputc(']', stream);
}

static void secdat_fuse_write_json_dry_run(
    const struct secdat_fuse_state *state,
    const struct secdat_sdk_key_metadata_list *keys,
    int missing_required_count
)
{
    int include_files = missing_required_count == 0;

    fputs("{\n  \"ok\": ", stdout);
    fputs(missing_required_count == 0 ? "true" : "false", stdout);
    fputs(",\n  \"mountpoint\": ", stdout);
    secdat_write_json_string(stdout, state->mountpoint);
    fputs(",\n  \"file_count\": ", stdout);
    printf("%zu", include_files ? keys->count : 0);
    fputs(",\n  \"files\": ", stdout);
    secdat_fuse_write_json_files(stdout, keys, include_files);
    fputs(",\n  \"include_patterns\": ", stdout);
    secdat_write_json_string_list(stdout, &state->include_patterns);
    fputs(",\n  \"exclude_patterns\": ", stdout);
    secdat_write_json_string_list(stdout, &state->exclude_patterns);
    fputs(",\n  \"sandbox_injectable\": ", stdout);
    fputs(state->filters.sandbox_injectable ? "true" : "false", stdout);
    fputs(",\n  \"required_keys\": ", stdout);
    secdat_write_json_string_list(stdout, &state->required_keys);
    fputs(",\n  \"missing_required_keys\": ", stdout);
    secdat_fuse_write_json_missing_required_keys(stdout, state, keys);
    fputs("\n}\n", stdout);
}

static void secdat_fuse_print_missing_required_keys(
    const struct secdat_fuse_state *state,
    const struct secdat_sdk_key_metadata_list *keys
)
{
    size_t index;

    for (index = 0; index < state->required_keys.count; index += 1) {
        if (!secdat_fuse_selected_keys_contain(keys, state->required_keys.items[index])) {
            fprintf(stderr, _("required key is not selected for secdat-fuse mount: %s\n"), state->required_keys.items[index]);
        }
    }
}

static int secdat_fuse_validate_required_keys(const struct secdat_fuse_state *state)
{
    struct secdat_sdk_key_metadata_list keys = {0};
    int missing_required_count;

    if (state->required_keys.count == 0) {
        return 0;
    }
    if (secdat_fuse_collect_selected_keys(state, &keys) != 0) {
        return 1;
    }
    missing_required_count = secdat_fuse_missing_required_count(state, &keys);
    if (missing_required_count > 0) {
        secdat_fuse_print_missing_required_keys(state, &keys);
        secdat_sdk_free(keys.items);
        return 1;
    }
    secdat_sdk_free(keys.items);
    return 0;
}

static int secdat_fuse_print_dry_run(const struct secdat_fuse_state *state)
{
    struct secdat_sdk_key_metadata_list keys = {0};
    size_t index;
    int missing_required_count;

    if (secdat_fuse_collect_selected_keys(state, &keys) != 0) {
        return 1;
    }
    missing_required_count = secdat_fuse_missing_required_count(state, &keys);

    if (state->json) {
        secdat_fuse_write_json_dry_run(state, &keys, missing_required_count);
        secdat_sdk_free(keys.items);
        return missing_required_count == 0 ? 0 : 1;
    }

    if (missing_required_count > 0) {
        secdat_fuse_print_missing_required_keys(state, &keys);
        secdat_sdk_free(keys.items);
        return 1;
    }

    printf("mountpoint: %s\n", state->mountpoint);
    printf("file_count: %zu\n", keys.count);
    for (index = 0; index < keys.count; index += 1) {
        puts(keys.items[index].key);
    }
    secdat_sdk_free(keys.items);
    return 0;
}

static int secdat_fuse_parse_args(int argc, char **argv, struct secdat_fuse_state *state)
{
    static const struct option long_options[] = {
        {"dir", required_argument, NULL, 'd'},
        {"domain", required_argument, NULL, 1000},
        {"store", required_argument, NULL, 's'},
        {"pattern", required_argument, NULL, 'p'},
        {"pattern-exclude", required_argument, NULL, 'x'},
        {"sandbox-injectable", no_argument, NULL, 1001},
        {"dry-run", no_argument, NULL, 1002},
        {"require-key", required_argument, NULL, 1003},
        {"foreground", no_argument, NULL, 'f'},
        {"debug", no_argument, NULL, 1004},
        {"json", no_argument, NULL, 1005},
        {"size-metadata", no_argument, NULL, 1006},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    int option;

    memset(state, 0, sizeof(*state));
    state->ready_fd = -1;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "+:d:s:p:x:fhV", long_options, NULL)) != -1) {
        switch (option) {
        case 'd':
            state->options.dir = optarg;
            break;
        case 1000:
            state->options.domain = optarg;
            break;
        case 's':
            state->options.store = optarg;
            break;
        case 'p':
            if (secdat_fuse_string_list_append(&state->include_patterns, optarg) != 0) {
                return 1;
            }
            break;
        case 'x':
            if (secdat_fuse_string_list_append(&state->exclude_patterns, optarg) != 0) {
                return 1;
            }
            break;
        case 1001:
            state->filters.sandbox_injectable = 1;
            break;
        case 1002:
            state->dry_run = 1;
            break;
        case 1003:
            if (secdat_fuse_string_list_append(&state->required_keys, optarg) != 0) {
                return 1;
            }
            break;
        case 'f':
            state->foreground = 1;
            break;
        case 1004:
            state->debug = 1;
            break;
        case 1005:
            state->json = 1;
            break;
        case 1006:
            state->size_metadata = 1;
            break;
        case 'h':
            secdat_fuse_print_usage(argv[0], stdout);
            exit(0);
        case 'V':
            secdat_fuse_print_version();
            exit(0);
        case ':':
            fprintf(stderr, _("missing option value\n"));
            return 2;
        case '?':
        default:
            fprintf(stderr, _("unknown option: %s\n"), argv[optind - 1]);
            return 2;
        }
    }

    if (state->options.dir != NULL && state->options.domain != NULL) {
        fprintf(stderr, _("--dir and --domain cannot be combined\n"));
        return 2;
    }
    if (state->json && !state->dry_run) {
        fprintf(stderr, _("--json requires --dry-run\n"));
        return 2;
    }
    if (optind >= argc) {
        fprintf(stderr, _("missing mountpoint\n"));
        return 2;
    }
    state->mountpoint = argv[optind];
    optind += 1;

    if (optind < argc) {
        if (strcmp(argv[optind], "--") != 0 || optind + 1 >= argc) {
            fprintf(stderr, _("invalid arguments\n"));
            return 2;
        }
        state->command_argv = &argv[optind + 1];
    }
    if (state->dry_run && state->command_argv != NULL) {
        fprintf(stderr, _("invalid arguments\n"));
        return 2;
    }

    if (state->options.domain != NULL) {
        if (secdat_domain_validate_root(
                state->options.domain,
                state->domain_buffer,
                sizeof(state->domain_buffer)) != 0) {
            return 1;
        }
        state->options.domain = state->domain_buffer;
    } else {
        if (secdat_fuse_canonicalize_dir(state->options.dir, state->dir_buffer, sizeof(state->dir_buffer)) != 0) {
            return 1;
        }
        state->options.dir = state->dir_buffer;
    }
    return 0;
}

static void secdat_fuse_state_clear(struct secdat_fuse_state *state)
{
    secdat_fuse_string_list_free(&state->include_patterns);
    secdat_fuse_string_list_free(&state->exclude_patterns);
    secdat_fuse_string_list_free(&state->required_keys);
}

static int secdat_fuse_run_fuse_main(struct secdat_fuse_state *state, const char *program_name, int force_foreground)
{
    char *fuse_argv[8];
    char foreground_option[] = "-f";
    char debug_option[] = "-d";
    char option_flag[] = "-o";
    char mount_options[] = "default_permissions,fsname=secdat";
    int fuse_argc = 0;

    fuse_argv[fuse_argc++] = (char *)program_name;
    if (state->foreground || force_foreground) {
        fuse_argv[fuse_argc++] = foreground_option;
    }
    if (state->debug) {
        fuse_argv[fuse_argc++] = debug_option;
    }
    fuse_argv[fuse_argc++] = option_flag;
    fuse_argv[fuse_argc++] = mount_options;
    fuse_argv[fuse_argc++] = (char *)state->mountpoint;
    fuse_argv[fuse_argc] = NULL;

    return fuse_main(fuse_argc, fuse_argv, &secdat_fuse_operations, state);
}

static int secdat_fuse_wait_status_to_exit_code(int wait_status)
{
    if (WIFEXITED(wait_status)) {
        return WEXITSTATUS(wait_status);
    }
    if (WIFSIGNALED(wait_status)) {
        return 128 + WTERMSIG(wait_status);
    }
    return 1;
}

static int secdat_fuse_wait_for_mount_ready(pid_t mount_pid, int ready_fd)
{
    char ready;
    ssize_t read_count;
    int wait_status;
    pid_t waited;

    do {
        read_count = read(ready_fd, &ready, 1);
    } while (read_count < 0 && errno == EINTR);
    close(ready_fd);
    if (read_count == 1) {
        return 0;
    }

    do {
        waited = waitpid(mount_pid, &wait_status, WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0) {
        kill(mount_pid, SIGTERM);
        usleep(100000);
        kill(mount_pid, SIGKILL);
        do {
            waited = waitpid(mount_pid, &wait_status, 0);
        } while (waited < 0 && errno == EINTR);
    }
    if (waited < 0) {
        fprintf(stderr, _("failed to wait for secdat-fuse mount process\n"));
    }
    fprintf(stderr, _("failed to start secdat-fuse mount\n"));
    return 1;
}

static int secdat_fuse_wait_for_child(pid_t pid, const char *label)
{
    int wait_status;

    for (;;) {
        if (waitpid(pid, &wait_status, 0) >= 0) {
            return secdat_fuse_wait_status_to_exit_code(wait_status);
        }
        if (errno != EINTR) {
            fprintf(stderr, _("failed to wait for %s\n"), label);
            return 1;
        }
    }
}

static int secdat_fuse_run_command(char **command_argv)
{
    pid_t command_pid;

    command_pid = fork();
    if (command_pid < 0) {
        fprintf(stderr, _("failed to fork\n"));
        return 1;
    }
    if (command_pid == 0) {
        execvp(command_argv[0], command_argv);
        fprintf(stderr, _("failed to execute command: %s\n"), command_argv[0]);
        _exit(127);
    }
    return secdat_fuse_wait_for_child(command_pid, "command");
}

static int secdat_fuse_unmount(const char *mountpoint)
{
    pid_t unmount_pid;
    int status;

    unmount_pid = fork();
    if (unmount_pid < 0) {
        fprintf(stderr, _("failed to fork\n"));
        return 1;
    }
    if (unmount_pid == 0) {
        execlp("fusermount3", "fusermount3", "-u", mountpoint, (char *)NULL);
        fprintf(stderr, _("failed to execute command: %s\n"), "fusermount3");
        _exit(127);
    }

    status = secdat_fuse_wait_for_child(unmount_pid, "fusermount3");
    if (status != 0) {
        fprintf(stderr, _("failed to unmount secdat-fuse mountpoint: %s\n"), mountpoint);
    }
    return status;
}

static int secdat_fuse_run_command_mode(struct secdat_fuse_state *state, const char *program_name)
{
    int ready_pipe[2];
    pid_t mount_pid;
    int command_status;
    int unmount_status;
    int mount_status;

    if (pipe(ready_pipe) != 0) {
        fprintf(stderr, _("failed to create pipe\n"));
        return 1;
    }

    mount_pid = fork();
    if (mount_pid < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        fprintf(stderr, _("failed to fork\n"));
        return 1;
    }
    if (mount_pid == 0) {
        int status;

        close(ready_pipe[0]);
        state->ready_fd = ready_pipe[1];
        status = secdat_fuse_run_fuse_main(state, program_name, 1);
        if (state->ready_fd >= 0) {
            close(state->ready_fd);
            state->ready_fd = -1;
        }
        _exit(status == 0 ? 0 : 1);
    }

    close(ready_pipe[1]);
    if (secdat_fuse_wait_for_mount_ready(mount_pid, ready_pipe[0]) != 0) {
        return 1;
    }

    command_status = secdat_fuse_run_command(state->command_argv);
    unmount_status = secdat_fuse_unmount(state->mountpoint);
    if (unmount_status != 0) {
        kill(mount_pid, SIGTERM);
        usleep(100000);
        kill(mount_pid, SIGKILL);
    }
    mount_status = secdat_fuse_wait_for_child(mount_pid, "secdat-fuse mount process");

    if (command_status != 0) {
        return command_status;
    }
    if (unmount_status != 0) {
        return 1;
    }
    return mount_status == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    struct secdat_fuse_state state;
    int status;

    secdat_fuse_i18n_init();
    status = secdat_fuse_parse_args(argc, argv, &state);
    if (status != 0) {
        if (status == 2) {
            secdat_fuse_print_usage(argv[0], stderr);
        }
        return status;
    }

    if (state.dry_run) {
        status = secdat_fuse_print_dry_run(&state);
        secdat_fuse_state_clear(&state);
        return status;
    }

    if (secdat_fuse_validate_required_keys(&state) != 0) {
        secdat_fuse_state_clear(&state);
        return 1;
    }

    if (state.command_argv != NULL) {
        status = secdat_fuse_run_command_mode(&state, argv[0]);
        secdat_fuse_state_clear(&state);
        return status;
    }

    status = secdat_fuse_run_fuse_main(&state, argv[0], 0);
    secdat_fuse_state_clear(&state);
    return status;
}
