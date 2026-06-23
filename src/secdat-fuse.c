#include "config.h"

#define FUSE_USE_VERSION 31

#include "domain.h"
#include "i18n.h"
#include "secdat-sdk.h"

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <libintl.h>
#include <limits.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SECDAT_BUILD_ID
#define SECDAT_BUILD_ID ""
#endif

struct secdat_fuse_state {
    struct secdat_sdk_options options;
    struct secdat_sdk_list_filters filters;
    char dir_buffer[PATH_MAX];
    char domain_buffer[PATH_MAX];
    const char *mountpoint;
    int foreground;
    int debug;
    int dry_run;
};

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
        _("Usage: %s [OPTIONS] MOUNTPOINT\n"
          "\n"
          "Mount selected secdat keys as read-only files.\n"
          "\n"
          "Options:\n"
          "  -d, --dir DIR              set the base directory used for domain resolution\n"
          "      --domain DIR           require one exact registered domain root\n"
          "  -s, --store STORE          select the store namespace\n"
          "  -p, --pattern GLOB         include only matching keys\n"
          "  -x, --pattern-exclude GLOB exclude matching keys\n"
          "      --sandbox-injectable   include only keys allowed for bulk sandbox injection\n"
          "      --dry-run              list files that would be mounted without mounting\n"
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

static int secdat_fuse_key_is_selected(struct secdat_fuse_state *state, const char *key)
{
    struct secdat_sdk_key_metadata_list keys = {0};
    size_t index;
    int selected = 0;

    if (secdat_sdk_list_keys(&state->options, &state->filters, &keys) != 0) {
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
    (void)conn;

    cfg->kernel_cache = 0;
    cfg->auto_cache = 0;
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;
    cfg->direct_io = 1;
    return fuse_get_context()->private_data;
}

static int secdat_fuse_getattr(const char *path, struct stat *status, struct fuse_file_info *file_info)
{
    struct secdat_fuse_state *state = fuse_get_context()->private_data;
    const char *key = NULL;
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

    status->st_mode = S_IFREG | 0400;
    status->st_nlink = 1;
    status->st_size = 0;
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

    if (secdat_sdk_list_keys(&state->options, &state->filters, &keys) != 0) {
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

    result = secdat_fuse_path_to_key(path, &key);
    if (result != 0) {
        return result;
    }
    if (key == NULL) {
        return -EISDIR;
    }
    if ((file_info->flags & O_ACCMODE) != O_RDONLY) {
        return -EROFS;
    }
    return secdat_fuse_key_is_selected(state, key);
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

static int secdat_fuse_truncate(const char *path, off_t size, struct fuse_file_info *file_info)
{
    (void)path;
    (void)size;
    (void)file_info;
    return secdat_fuse_readonly();
}

static int secdat_fuse_write(
    const char *path,
    const char *buffer,
    size_t size,
    off_t offset,
    struct fuse_file_info *file_info
)
{
    (void)path;
    (void)buffer;
    (void)size;
    (void)offset;
    (void)file_info;
    return secdat_fuse_readonly();
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

static int secdat_fuse_print_dry_run(const struct secdat_fuse_state *state)
{
    struct secdat_sdk_key_metadata_list keys = {0};
    size_t index;

    if (secdat_sdk_list_keys(&state->options, &state->filters, &keys) != 0) {
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
        {"foreground", no_argument, NULL, 'f'},
        {"debug", no_argument, NULL, 1003},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    int option;

    memset(state, 0, sizeof(*state));
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
            state->filters.include_pattern = optarg;
            break;
        case 'x':
            state->filters.exclude_pattern = optarg;
            break;
        case 1001:
            state->filters.sandbox_injectable = 1;
            break;
        case 1002:
            state->dry_run = 1;
            break;
        case 'f':
            state->foreground = 1;
            break;
        case 1003:
            state->debug = 1;
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
    if (optind >= argc) {
        fprintf(stderr, _("missing mountpoint\n"));
        return 2;
    }
    if (optind + 1 < argc) {
        fprintf(stderr, _("invalid arguments\n"));
        return 2;
    }
    state->mountpoint = argv[optind];

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

int main(int argc, char **argv)
{
    struct secdat_fuse_state state;
    char *fuse_argv[8];
    char foreground_option[] = "-f";
    char debug_option[] = "-d";
    char option_flag[] = "-o";
    char mount_options[] = "ro,default_permissions,fsname=secdat";
    int fuse_argc = 0;
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
        return secdat_fuse_print_dry_run(&state);
    }

    fuse_argv[fuse_argc++] = argv[0];
    if (state.foreground) {
        fuse_argv[fuse_argc++] = foreground_option;
    }
    if (state.debug) {
        fuse_argv[fuse_argc++] = debug_option;
    }
    fuse_argv[fuse_argc++] = option_flag;
    fuse_argv[fuse_argc++] = mount_options;
    fuse_argv[fuse_argc++] = (char *)state.mountpoint;
    fuse_argv[fuse_argc] = NULL;

    return fuse_main(fuse_argc, fuse_argv, &secdat_fuse_operations, &state);
}
