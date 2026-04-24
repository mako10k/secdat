#include "store.h"

#include "domain.h"

#include "i18n.h"

#include <getopt.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SECDAT_USER_GLOBAL_SCOPE_ID "secdat:user-global-scope"

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
#define SECDAT_GET_ON_DEMAND_UNLOCK_ENV "SECDAT_GET_ON_DEMAND_UNLOCK"
#define SECDAT_GET_UNLOCK_TIMEOUT_ENV "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS"
#define SECDAT_ON_DEMAND_UNLOCK_WAIT_USEC 100000

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
    int safe;
    int unsafe_store;
};

struct secdat_exec_options {
    struct secdat_key_list include_patterns;
    struct secdat_key_list exclude_patterns;
    regex_t env_map_address_regex;
    regex_t env_map_regex;
    char *env_map_replacement;
    int env_map_configured;
    int env_map_has_address;
    size_t command_index;
};

struct secdat_list_options {
    int masked;
    int overridden;
    int orphaned;
    int safe;
    int unsafe_store;
};

struct secdat_key_access_options {
    int allow_on_demand_unlock;
    int timeout_configured;
    time_t timeout_seconds;
};

struct secdat_get_options {
    const char *keyref;
    int shellescaped;
    struct secdat_key_access_options access;
};

struct secdat_wait_unlock_options {
    int quiet;
    int timeout_configured;
    time_t timeout_seconds;
};

enum secdat_overlay_item_kind {
    SECDAT_OVERLAY_ITEM_ENTRY = 1,
    SECDAT_OVERLAY_ITEM_TOMBSTONE,
};

struct secdat_overlay_item {
    char *domain_id;
    char *store_name;
    char *key;
    unsigned char *plaintext;
    size_t plaintext_length;
    int unsafe_store;
    enum secdat_overlay_item_kind kind;
};

struct secdat_overlay_list {
    struct secdat_overlay_item *items;
    size_t count;
    size_t capacity;
};

struct secdat_effective_entry {
    int found;
    int tombstone;
    int from_overlay;
    int unsafe_store;
    size_t resolved_index;
    char path[PATH_MAX];
    unsigned char *plaintext;
    size_t plaintext_length;
};

static void secdat_prepare_option_argv(
    const struct secdat_cli *cli,
    const char *command_name,
    int *argc,
    char **argv
)
{
    int index;

    argv[0] = (char *)command_name;
    for (index = 0; index < cli->argc; index += 1) {
        argv[index + 1] = cli->argv[index];
    }
    argv[cli->argc + 1] = NULL;
    *argc = cli->argc + 1;
}

static void secdat_reset_getopt_state(void)
{
    opterr = 0;
    optind = 0;
}

static void secdat_key_list_free(struct secdat_key_list *list);

static void secdat_exec_options_reset(struct secdat_exec_options *options)
{
    secdat_key_list_free(&options->include_patterns);
    secdat_key_list_free(&options->exclude_patterns);
    if (options->env_map_has_address) {
        regfree(&options->env_map_address_regex);
    }
    if (options->env_map_configured) {
        regfree(&options->env_map_regex);
    }
    free(options->env_map_replacement);
    memset(options, 0, sizeof(*options));
}

enum secdat_session_access_mode {
    SECDAT_SESSION_ACCESS_PERSISTENT = 0,
    SECDAT_SESSION_ACCESS_VOLATILE,
    SECDAT_SESSION_ACCESS_READONLY,
};

struct secdat_session_record {
    char master_key[512];
    time_t expires_at;
    time_t duration_seconds;
    int volatile_mode;
    int readonly_mode;
    struct secdat_overlay_list overlay;
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
    int *unsafe_store,
    const struct secdat_key_access_options *access_options
);
static int secdat_store_plaintext(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
);
static int secdat_write_empty_file(const char *path);
static int secdat_entry_uses_plaintext_storage(const char *path, int *unsafe_store);
static int secdat_collect_store_names(const char *domain_id, const char *pattern, struct secdat_key_list *stores);
static int secdat_atomic_write_file(const char *path, const unsigned char *data, size_t length);
static int secdat_parse_i64(const char *value, time_t *result);
static int secdat_session_agent_connect_chain_details(const struct secdat_domain_chain *chain, size_t *matched_index, size_t *blocked_index);
static int secdat_session_agent_status(const struct secdat_domain_chain *chain, struct secdat_session_record *record);
static int secdat_session_agent_status_details(
    const struct secdat_domain_chain *chain,
    struct secdat_session_record *record,
    size_t *matched_index,
    size_t *blocked_index
);
static int secdat_session_agent_set(const char *domain_id, const char *master_key, enum secdat_session_access_mode access_mode, time_t duration_seconds);
static int secdat_session_agent_clear(const char *domain_id);
static time_t secdat_session_idle_seconds(void);
static time_t secdat_session_effective_duration(const struct secdat_session_record *record);
static void secdat_session_record_reset(struct secdat_session_record *record);
static void secdat_session_record_refresh(struct secdat_session_record *record);
static void secdat_print_unlock_guidance(const char *current_domain_root);
static void secdat_print_locked_read_guidance(const struct secdat_domain_chain *chain);
static int secdat_parse_get_options(const struct secdat_cli *cli, struct secdat_get_options *options);
static int secdat_parse_wait_unlock_options(const struct secdat_cli *cli, struct secdat_wait_unlock_options *options);
static int secdat_parse_session_duration_seconds(const char *value, time_t *duration_seconds);
static void secdat_format_remaining_duration(time_t expires_at, char *buffer, size_t size);
static int secdat_is_valid_env_name(const char *value);

struct secdat_unlock_options {
    time_t duration_seconds;
    char until_value[128];
    int include_descendants;
    int duration_configured;
    int until_configured;
    int inherit_mode;
    int assume_yes;
    int volatile_mode;
    int readonly_mode;
};

struct secdat_lock_options {
    int inherit_mode;
    int save_mode;
};

struct secdat_session_lookup_options {
    int ignore_current_explicit_lock;
};

struct secdat_overlay_lookup_result {
    int found;
    int tombstone;
    int unsafe_store;
    unsigned char *plaintext;
    size_t plaintext_length;
};

enum secdat_inherit_expectation {
    SECDAT_INHERIT_EXPECT_ANY = 0,
    SECDAT_INHERIT_EXPECT_UNLOCKED,
    SECDAT_INHERIT_EXPECT_LOCKED,
};

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

static int secdat_duplicate_bytes(const unsigned char *input, size_t length, unsigned char **output)
{
    unsigned char *copy;

    copy = malloc(length == 0 ? 1 : length);
    if (copy == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    if (length > 0) {
        memcpy(copy, input, length);
    }
    *output = copy;
    return 0;
}

static int secdat_overlay_store_name_copy(const char *store_name, char **buffer)
{
    const char *effective_store = store_name != NULL ? store_name : "";

    *buffer = strdup(effective_store);
    if (*buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    return 0;
}

static void secdat_overlay_item_free(struct secdat_overlay_item *item)
{
    if (item == NULL) {
        return;
    }

    free(item->domain_id);
    free(item->store_name);
    free(item->key);
    if (item->plaintext != NULL) {
        secdat_secure_clear(item->plaintext, item->plaintext_length);
        free(item->plaintext);
    }
    memset(item, 0, sizeof(*item));
}

static void secdat_overlay_list_clear(struct secdat_overlay_list *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->count; index += 1) {
        secdat_overlay_item_free(&list->items[index]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int secdat_overlay_list_find(
    const struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    const char *effective_store = store_name != NULL ? store_name : "";
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].domain_id, domain_id) == 0
            && strcmp(list->items[index].store_name, effective_store) == 0
            && strcmp(list->items[index].key, key) == 0) {
            return (int)index;
        }
    }

    return -1;
}

static int secdat_overlay_list_ensure_capacity(struct secdat_overlay_list *list)
{
    struct secdat_overlay_item *new_items;
    size_t new_capacity;

    if (list->count < list->capacity) {
        return 0;
    }

    new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
    new_items = realloc(list->items, sizeof(*new_items) * new_capacity);
    if (new_items == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    list->items = new_items;
    list->capacity = new_capacity;
    return 0;
}

static int secdat_overlay_list_set_entry(
    struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key,
    const unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
)
{
    struct secdat_overlay_item item;
    int existing_index;

    memset(&item, 0, sizeof(item));
    existing_index = secdat_overlay_list_find(list, domain_id, store_name, key);
    if (existing_index >= 0) {
        secdat_overlay_item_free(&list->items[existing_index]);
        memset(&list->items[existing_index], 0, sizeof(list->items[existing_index]));
    } else if (secdat_overlay_list_ensure_capacity(list) != 0) {
        return 1;
    }

    item.domain_id = strdup(domain_id);
    item.key = strdup(key);
    if (item.domain_id == NULL || item.key == NULL || secdat_overlay_store_name_copy(store_name, &item.store_name) != 0) {
        free(item.domain_id);
        free(item.key);
        free(item.store_name);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    if (secdat_duplicate_bytes(plaintext, plaintext_length, &item.plaintext) != 0) {
        secdat_overlay_item_free(&item);
        return 1;
    }
    item.plaintext_length = plaintext_length;
    item.unsafe_store = unsafe_store;
    item.kind = SECDAT_OVERLAY_ITEM_ENTRY;

    if (existing_index >= 0) {
        list->items[existing_index] = item;
    } else {
        list->items[list->count] = item;
        list->count += 1;
    }
    return 0;
}

static int secdat_overlay_list_set_tombstone(
    struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    struct secdat_overlay_item item;
    int existing_index;

    memset(&item, 0, sizeof(item));
    existing_index = secdat_overlay_list_find(list, domain_id, store_name, key);
    if (existing_index >= 0) {
        secdat_overlay_item_free(&list->items[existing_index]);
        memset(&list->items[existing_index], 0, sizeof(list->items[existing_index]));
    } else if (secdat_overlay_list_ensure_capacity(list) != 0) {
        return 1;
    }

    item.domain_id = strdup(domain_id);
    item.key = strdup(key);
    if (item.domain_id == NULL || item.key == NULL || secdat_overlay_store_name_copy(store_name, &item.store_name) != 0) {
        free(item.domain_id);
        free(item.key);
        free(item.store_name);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    item.kind = SECDAT_OVERLAY_ITEM_TOMBSTONE;

    if (existing_index >= 0) {
        list->items[existing_index] = item;
    } else {
        list->items[list->count] = item;
        list->count += 1;
    }
    return 0;
}

static void secdat_overlay_list_remove(
    struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    int index;

    index = secdat_overlay_list_find(list, domain_id, store_name, key);
    if (index < 0) {
        return;
    }

    secdat_overlay_item_free(&list->items[index]);
    if ((size_t)index + 1 < list->count) {
        memmove(&list->items[index], &list->items[index + 1], sizeof(*list->items) * (list->count - (size_t)index - 1));
    }
    list->count -= 1;
    memset(&list->items[list->count], 0, sizeof(list->items[list->count]));
}

static const struct secdat_overlay_item *secdat_overlay_list_lookup(
    const struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    int index;

    index = secdat_overlay_list_find(list, domain_id, store_name, key);
    if (index < 0) {
        return NULL;
    }
    return &list->items[index];
}

static void secdat_effective_entry_reset(struct secdat_effective_entry *entry)
{
    if (entry == NULL) {
        return;
    }
    if (entry->plaintext != NULL) {
        secdat_secure_clear(entry->plaintext, entry->plaintext_length);
        free(entry->plaintext);
    }
    memset(entry, 0, sizeof(*entry));
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

static int secdat_domain_root_list_append(struct secdat_domain_root_list *list, const char *value)
{
    char **new_roots;

    new_roots = realloc(list->roots, sizeof(*new_roots) * (list->count + 1));
    if (new_roots == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    list->roots = new_roots;
    list->roots[list->count] = strdup(value);
    if (list->roots[list->count] == NULL) {
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

static const char *secdat_cli_domain_base(const struct secdat_cli *cli)
{
    return cli->domain != NULL ? cli->domain : cli->dir;
}

static int secdat_default_domain_write_error(void)
{
    fprintf(stderr, _("writes to the default domain are not supported\n"));
    return 1;
}

static int secdat_require_writable_domain_id(const char *domain_id)
{
    if (domain_id != NULL && domain_id[0] != '\0') {
        return 0;
    }

    return secdat_default_domain_write_error();
}

static int secdat_require_writable_domain_chain(const struct secdat_domain_chain *chain)
{
    if (chain != NULL && chain->count > 0) {
        return 0;
    }

    return secdat_default_domain_write_error();
}

static int secdat_explicit_lock_marker_path(const char *domain_id, char *buffer, size_t size)
{
    char domain_root[PATH_MAX];

    if (strcmp(domain_id, "default") == 0) {
        return 1;
    }
    if (secdat_domain_data_root(domain_id, domain_root, sizeof(domain_root)) != 0) {
        return 1;
    }
    return snprintf(buffer, size, "%s/meta/explicit-lock", domain_root) >= (int)size ? 1 : 0;
}

static int secdat_domain_has_explicit_lock(const char *domain_id)
{
    char marker_path[PATH_MAX];
    struct stat status;

    if (secdat_explicit_lock_marker_path(domain_id, marker_path, sizeof(marker_path)) != 0) {
        return 0;
    }
    return stat(marker_path, &status) == 0 && S_ISREG(status.st_mode);
}

static int secdat_domain_set_explicit_lock(const char *domain_id)
{
    char marker_path[PATH_MAX];
    static const unsigned char marker_contents[] = "explicit-lock\n";

    if (secdat_explicit_lock_marker_path(domain_id, marker_path, sizeof(marker_path)) != 0) {
        return 0;
    }
    return secdat_atomic_write_file(marker_path, marker_contents, sizeof(marker_contents) - 1);
}

static int secdat_domain_clear_explicit_lock(const char *domain_id, int *removed)
{
    char marker_path[PATH_MAX];

    if (removed != NULL) {
        *removed = 0;
    }
    if (secdat_explicit_lock_marker_path(domain_id, marker_path, sizeof(marker_path)) != 0) {
        return 0;
    }
    if (unlink(marker_path) == 0) {
        if (removed != NULL) {
            *removed = 1;
        }
        return 0;
    }
    if (errno == ENOENT) {
        return 0;
    }

    fprintf(stderr, _("failed to remove file: %s\n"), marker_path);
    return 1;
}

static void secdat_print_unlock_guidance(const char *current_domain_root)
{
    struct secdat_domain_root_list descendants = {0};
    struct secdat_domain_status_summary summary;
    const size_t preview_limit = 3;
    const char *first_affected = NULL;
    size_t descendant_count = 0;
    size_t affected_count = 0;
    size_t preview_count = 0;
    size_t index;

    if (current_domain_root == NULL || current_domain_root[0] == '\0') {
        return;
    }

    if (secdat_collect_descendant_domain_roots(current_domain_root, &descendants) != 0) {
        return;
    }

    for (index = 0; index < descendants.count; index += 1) {
        if (strcmp(descendants.roots[index], current_domain_root) == 0) {
            continue;
        }
        descendant_count += 1;
        if (secdat_collect_domain_status_summary(descendants.roots[index], &summary) != 0) {
            continue;
        }
        if (summary.effective_source != SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK
            && summary.effective_source != SECDAT_EFFECTIVE_SOURCE_BLOCKED) {
            continue;
        }

        if (first_affected == NULL) {
            first_affected = descendants.roots[index];
        }
        affected_count += 1;
    }

    if (affected_count == 0) {
        if (descendant_count > 0) {
            printf(_("note: %zu descendant domains can now reuse this session\n"), descendant_count);
        }
        secdat_domain_root_list_free(&descendants);
        return;
    }

    printf(_("note: %zu descendant domains remain locked under this branch\n"), affected_count);
    puts(_("affected descendants:"));
    for (index = 0; index < descendants.count && preview_count < preview_limit; index += 1) {
        if (strcmp(descendants.roots[index], current_domain_root) == 0) {
            continue;
        }
        if (secdat_collect_domain_status_summary(descendants.roots[index], &summary) != 0) {
            continue;
        }
        if (summary.effective_source != SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK
            && summary.effective_source != SECDAT_EFFECTIVE_SOURCE_BLOCKED) {
            continue;
        }
        printf(_("  %s\n"), descendants.roots[index]);
        preview_count += 1;
    }
    if (affected_count > preview_limit) {
        printf(_("  ... and %zu more\n"), affected_count - preview_limit);
    }

    printf(_("inspect descendants: secdat --dir %s domain ls -l --descendants\n"), current_domain_root);
    if (first_affected != NULL) {
        printf(_("inspect one descendant: secdat --dir %s domain status\n"), first_affected);
        printf(_("unlock one descendant: secdat --dir %s unlock\n"), first_affected);
    }

    secdat_domain_root_list_free(&descendants);
}

static void secdat_print_locked_read_guidance(const struct secdat_domain_chain *chain)
{
    char current_domain_label[PATH_MAX];

    if (chain == NULL) {
        return;
    }
    if (secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        return;
    }

    if (chain->count == 0) {
        fprintf(stderr, _("resolved domain: %s\n"), current_domain_label);
        fprintf(stderr, _("inspect current domain: secdat domain status\n"));
        fprintf(stderr, _("unlock current domain: secdat unlock\n"));
        return;
    }

    fprintf(stderr, _("resolved domain: %s\n"), current_domain_label);
    fprintf(stderr, _("inspect current domain: secdat --dir %s domain status\n"), current_domain_label);
    fprintf(stderr, _("unlock current domain: secdat --dir %s unlock\n"), current_domain_label);
}

static int secdat_parse_boolean_text(const char *value, int *result)
{
    if (value == NULL || value[0] == '\0') {
        return 1;
    }
    if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
        *result = 1;
        return 0;
    }
    if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 || strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
        *result = 0;
        return 0;
    }
    return 1;
}

static int secdat_get_default_on_demand_unlock_enabled(void)
{
    const char *value = getenv(SECDAT_GET_ON_DEMAND_UNLOCK_ENV);
    int enabled = 0;

    if (value != NULL && secdat_parse_boolean_text(value, &enabled) == 0) {
        return enabled;
    }

    return 0;
}

static void secdat_get_default_unlock_timeout(struct secdat_key_access_options *options)
{
    const char *value = getenv(SECDAT_GET_UNLOCK_TIMEOUT_ENV);
    time_t parsed = 0;

    if (value != NULL && value[0] != '\0' && secdat_parse_i64(value, &parsed) == 0 && parsed >= 0) {
        options->timeout_configured = 1;
        options->timeout_seconds = parsed;
    }
}

static int secdat_parse_unlock_timeout_value(const char *value, struct secdat_key_access_options *options)
{
    time_t parsed = 0;

    if (value == NULL || value[0] == '\0' || secdat_parse_i64(value, &parsed) != 0 || parsed < 0) {
        fprintf(stderr, _("invalid value for --unlock-timeout: %s\n"), value != NULL ? value : "");
        return 2;
    }

    options->timeout_configured = 1;
    options->timeout_seconds = parsed;
    return 0;
}

static int secdat_parse_timeout_seconds(const char *value, time_t *timeout_seconds)
{
    time_t parsed = 0;

    if (value == NULL || value[0] == '\0' || secdat_parse_i64(value, &parsed) != 0 || parsed < 0) {
        return 1;
    }

    *timeout_seconds = parsed;
    return 0;
}

static int secdat_add_duration_component(long long *total_seconds, unsigned long long magnitude, long long unit_seconds)
{
    long long component_seconds;

    if (total_seconds == NULL || magnitude == 0 || unit_seconds <= 0) {
        return 1;
    }
    if (magnitude > (unsigned long long)(LLONG_MAX / unit_seconds)) {
        return 1;
    }

    component_seconds = (long long)magnitude * unit_seconds;
    if (*total_seconds > LLONG_MAX - component_seconds) {
        return 1;
    }

    *total_seconds += component_seconds;
    return 0;
}

static int secdat_duration_unit_seconds(const char *text, size_t length, long long *unit_seconds)
{
    if (text == NULL || unit_seconds == NULL || length == 0) {
        return 1;
    }

    if ((length == 1 && strncasecmp(text, "s", length) == 0)
        || (length == 3 && strncasecmp(text, "sec", length) == 0)
        || (length == 4 && strncasecmp(text, "secs", length) == 0)
        || (length == 6 && strncasecmp(text, "second", length) == 0)
        || (length == 7 && strncasecmp(text, "seconds", length) == 0)) {
        *unit_seconds = 1;
        return 0;
    }
    if ((length == 1 && strncasecmp(text, "m", length) == 0)
        || (length == 3 && strncasecmp(text, "min", length) == 0)
        || (length == 4 && strncasecmp(text, "mins", length) == 0)
        || (length == 6 && strncasecmp(text, "minute", length) == 0)
        || (length == 7 && strncasecmp(text, "minutes", length) == 0)) {
        *unit_seconds = 60;
        return 0;
    }
    if ((length == 1 && strncasecmp(text, "h", length) == 0)
        || (length == 2 && strncasecmp(text, "hr", length) == 0)
        || (length == 3 && strncasecmp(text, "hrs", length) == 0)
        || (length == 4 && strncasecmp(text, "hour", length) == 0)
        || (length == 5 && strncasecmp(text, "hours", length) == 0)) {
        *unit_seconds = 3600;
        return 0;
    }
    if ((length == 1 && strncasecmp(text, "d", length) == 0)
        || (length == 3 && strncasecmp(text, "day", length) == 0)
        || (length == 4 && strncasecmp(text, "days", length) == 0)) {
        *unit_seconds = 86400;
        return 0;
    }

    return 1;
}

static int secdat_parse_human_duration(const char *value, time_t *duration_seconds)
{
    const char *cursor = value;
    long long total_seconds = 0;
    int saw_unit = 0;

    if (cursor == NULL || *cursor == '\0') {
        return 1;
    }

    while (*cursor != '\0') {
        char *end = NULL;
        const char *unit_start;
        unsigned long long magnitude;
        long long unit_seconds;

        while (isspace((unsigned char)*cursor)) {
            cursor += 1;
        }
        if (*cursor == '\0') {
            break;
        }
        if (!isdigit((unsigned char)*cursor)) {
            return 1;
        }

        errno = 0;
        magnitude = strtoull(cursor, &end, 10);
        if (errno != 0 || end == cursor) {
            return 1;
        }
        cursor = end;
        while (isspace((unsigned char)*cursor)) {
            cursor += 1;
        }
        unit_start = cursor;
        while (isalpha((unsigned char)*cursor)) {
            cursor += 1;
        }
        if (unit_start == cursor) {
            while (isspace((unsigned char)*cursor)) {
                cursor += 1;
            }
            if (*cursor != '\0' || saw_unit || magnitude > (unsigned long long)(LLONG_MAX / 60)) {
                return 1;
            }
            *duration_seconds = (time_t)((long long)magnitude * 60);
            return *duration_seconds > 0 ? 0 : 1;
        }
        if (secdat_duration_unit_seconds(unit_start, (size_t)(cursor - unit_start), &unit_seconds) != 0
            || secdat_add_duration_component(&total_seconds, magnitude, unit_seconds) != 0) {
            return 1;
        }
        saw_unit = 1;
    }

    if (!saw_unit || total_seconds <= 0) {
        return 1;
    }

    *duration_seconds = (time_t)total_seconds;
    return 0;
}

static int secdat_parse_iso8601_duration(const char *value, time_t *duration_seconds)
{
    const char *cursor = value;
    long long total_seconds = 0;
    int in_time_section = 0;
    int saw_component = 0;

    if (cursor == NULL || *cursor == '\0') {
        return 1;
    }
    if (*cursor == '+') {
        cursor += 1;
    }
    if (*cursor != 'P' && *cursor != 'p') {
        return 1;
    }
    cursor += 1;

    while (*cursor != '\0') {
        char *end = NULL;
        unsigned long long magnitude;
        long long unit_seconds;
        char designator;

        if (*cursor == 'T' || *cursor == 't') {
            if (in_time_section) {
                return 1;
            }
            in_time_section = 1;
            cursor += 1;
            continue;
        }
        if (!isdigit((unsigned char)*cursor)) {
            return 1;
        }

        errno = 0;
        magnitude = strtoull(cursor, &end, 10);
        if (errno != 0 || end == cursor || *end == '\0') {
            return 1;
        }
        cursor = end;
        designator = (char)toupper((unsigned char)*cursor);
        cursor += 1;

        switch (designator) {
        case 'W':
            if (in_time_section) {
                return 1;
            }
            unit_seconds = 7 * 86400;
            break;
        case 'D':
            if (in_time_section) {
                return 1;
            }
            unit_seconds = 86400;
            break;
        case 'H':
            if (!in_time_section) {
                return 1;
            }
            unit_seconds = 3600;
            break;
        case 'M':
            if (!in_time_section) {
                return 1;
            }
            unit_seconds = 60;
            break;
        case 'S':
            if (!in_time_section) {
                return 1;
            }
            unit_seconds = 1;
            break;
        default:
            return 1;
        }

        if (secdat_add_duration_component(&total_seconds, magnitude, unit_seconds) != 0) {
            return 1;
        }
        saw_component = 1;
    }

    if (!saw_component || total_seconds <= 0) {
        return 1;
    }

    *duration_seconds = (time_t)total_seconds;
    return 0;
}

static int secdat_parse_fixed_digits(const char **cursor, size_t digits, int *value)
{
    size_t index;
    int parsed = 0;

    if (cursor == NULL || *cursor == NULL || value == NULL) {
        return 1;
    }
    for (index = 0; index < digits; index += 1) {
        if (!isdigit((unsigned char)(*cursor)[index])) {
            return 1;
        }
        parsed = parsed * 10 + ((*cursor)[index] - '0');
    }

    *cursor += digits;
    *value = parsed;
    return 0;
}

static int secdat_is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static int secdat_days_in_month(int year, int month)
{
    static const int days_per_month[] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    };

    if (month < 1 || month > 12) {
        return 0;
    }
    if (month == 2 && secdat_is_leap_year(year)) {
        return 29;
    }

    return days_per_month[month - 1];
}

static long long secdat_days_from_civil(int year, unsigned month, unsigned day)
{
    year -= month <= 2;
    {
        const int era = (year >= 0 ? year : year - 399) / 400;
        const unsigned year_of_era = (unsigned)(year - era * 400);
        const unsigned day_of_year = (153 * (month + (month > 2 ? (unsigned)-3 : 9)) + 2) / 5 + day - 1;
        const unsigned day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

        return era * 146097LL + (long long)day_of_era - 719468LL;
    }
}

static int secdat_parse_rfc3339_time_offset(const char **cursor, long long *offset_seconds)
{
    int sign;
    int hours;
    int minutes;

    if (cursor == NULL || *cursor == NULL || offset_seconds == NULL) {
        return 1;
    }
    if (**cursor == 'Z' || **cursor == 'z') {
        *offset_seconds = 0;
        *cursor += 1;
        return 0;
    }
    if (**cursor != '+' && **cursor != '-') {
        return 1;
    }

    sign = **cursor == '-' ? -1 : 1;
    *cursor += 1;
    if (secdat_parse_fixed_digits(cursor, 2, &hours) != 0) {
        return 1;
    }
    if (**cursor == ':') {
        *cursor += 1;
    }
    if (secdat_parse_fixed_digits(cursor, 2, &minutes) != 0 || hours > 23 || minutes > 59) {
        return 1;
    }

    *offset_seconds = sign * (hours * 3600LL + minutes * 60LL);
    return 0;
}

static int secdat_parse_absolute_duration(const char *value, time_t *duration_seconds)
{
    const char *cursor = value;
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second = 0;
    long long offset_seconds;
    long long epoch_seconds;
    long long remaining_seconds;
    time_t now;

    if (cursor == NULL || *cursor == '\0') {
        return 1;
    }
    if (secdat_parse_fixed_digits(&cursor, 4, &year) != 0 || *cursor != '-') {
        return 1;
    }
    cursor += 1;
    if (secdat_parse_fixed_digits(&cursor, 2, &month) != 0 || *cursor != '-') {
        return 1;
    }
    cursor += 1;
    if (secdat_parse_fixed_digits(&cursor, 2, &day) != 0 || (*cursor != 'T' && *cursor != 't')) {
        return 1;
    }
    cursor += 1;
    if (secdat_parse_fixed_digits(&cursor, 2, &hour) != 0 || *cursor != ':') {
        return 1;
    }
    cursor += 1;
    if (secdat_parse_fixed_digits(&cursor, 2, &minute) != 0) {
        return 1;
    }
    if (*cursor == ':') {
        cursor += 1;
        if (secdat_parse_fixed_digits(&cursor, 2, &second) != 0) {
            return 1;
        }
    }
    if (*cursor == '.') {
        cursor += 1;
        if (!isdigit((unsigned char)*cursor)) {
            return 1;
        }
        while (isdigit((unsigned char)*cursor)) {
            cursor += 1;
        }
    }
    if (secdat_parse_rfc3339_time_offset(&cursor, &offset_seconds) != 0 || *cursor != '\0') {
        return 1;
    }
    if (month < 1 || month > 12 || day < 1 || day > secdat_days_in_month(year, month)
        || hour > 23 || minute > 59 || second > 60) {
        return 1;
    }

    epoch_seconds = secdat_days_from_civil(year, (unsigned)month, (unsigned)day) * 86400LL
        + hour * 3600LL + minute * 60LL + (second == 60 ? 59 : second) - offset_seconds;
    now = time(NULL);
    remaining_seconds = epoch_seconds - (long long)now;
    if (remaining_seconds <= 0) {
        return 1;
    }

    *duration_seconds = (time_t)remaining_seconds;
    return 0;
}

static int secdat_parse_session_duration_seconds(const char *value, time_t *duration_seconds)
{
    if (value == NULL || value[0] == '\0') {
        return 1;
    }
    if (secdat_parse_iso8601_duration(value, duration_seconds) == 0) {
        return 0;
    }
    return secdat_parse_human_duration(value, duration_seconds);
}

static int secdat_parse_get_options(const struct secdat_cli *cli, struct secdat_get_options *options)
{
    static const struct option long_options[] = {
        {"stdout", no_argument, NULL, 'o'},
        {"shellescaped", no_argument, NULL, 'e'},
        {"on-demand-unlock", no_argument, NULL, 'w'},
        {"unlock-timeout", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;
    int parse_status;

    memset(options, 0, sizeof(*options));
    options->access.allow_on_demand_unlock = secdat_get_default_on_demand_unlock_enabled();
    secdat_get_default_unlock_timeout(&options->access);

    secdat_prepare_option_argv(cli, "get", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":oewt:", long_options, NULL)) != -1) {
        switch (option) {
        case 'o':
            options->shellescaped = 0;
            break;
        case 'e':
            options->shellescaped = 1;
            break;
        case 'w':
            options->access.allow_on_demand_unlock = 1;
            break;
        case 't':
            parse_status = secdat_parse_unlock_timeout_value(optarg, &options->access);
            if (parse_status != 0) {
                return parse_status;
            }
            break;
        case ':':
            if (optopt == 't') {
                fprintf(stderr, _("missing value for --unlock-timeout\n"));
            } else {
                fprintf(stderr, _("invalid arguments for get\n"));
                secdat_cli_print_try_help(cli, "get");
            }
            return 2;
        case '?':
        default:
            fprintf(stderr, _("invalid arguments for get\n"));
            secdat_cli_print_try_help(cli, "get");
            return 2;
        }
    }

    if (optind + 1 == argc) {
        options->keyref = argv[optind];
    } else if (optind < argc) {
        fprintf(stderr, _("invalid arguments for get\n"));
        secdat_cli_print_try_help(cli, "get");
        return 2;
    }

    if (options->keyref == NULL) {
        fprintf(stderr, _("missing key for get\n"));
        secdat_cli_print_try_help(cli, "get");
        return 2;
    }
    if (options->access.timeout_configured && !options->access.allow_on_demand_unlock) {
        fprintf(stderr, _("--unlock-timeout requires --on-demand-unlock or %s\n"), SECDAT_GET_ON_DEMAND_UNLOCK_ENV);
        return 2;
    }

    return 0;
}

static int secdat_parse_wait_unlock_options(const struct secdat_cli *cli, struct secdat_wait_unlock_options *options)
{
    static const struct option long_options[] = {
        {"quiet", no_argument, NULL, 'q'},
        {"timeout", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "wait-unlock", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":qt:", long_options, NULL)) != -1) {
        switch (option) {
        case 'q':
            options->quiet = 1;
            break;
        case 't':
            if (secdat_parse_timeout_seconds(optarg, &options->timeout_seconds) != 0) {
                fprintf(stderr, _("invalid value for --timeout: %s\n"), optarg);
                return 2;
            }
            options->timeout_configured = 1;
            break;
        case ':':
            if (optopt == 't') {
                fprintf(stderr, _("missing value for --timeout\n"));
                return 2;
            }
            break;
        case '?':
        default:
            break;
        }
        if (option == '?' || option == ':') {
            fprintf(stderr, _("invalid arguments for wait-unlock\n"));
            secdat_cli_print_try_help(cli, "wait-unlock");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for wait-unlock\n"));
        secdat_cli_print_try_help(cli, "wait-unlock");
        return 2;
    }

    return 0;
}

static void secdat_print_on_demand_unlock_guidance(
    const struct secdat_domain_chain *chain,
    const struct secdat_key_access_options *options
)
{
    char current_domain_label[PATH_MAX];

    if (chain == NULL) {
        return;
    }
    if (secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        return;
    }

    fprintf(stderr, _("waiting for another terminal to unlock secrets for resolved domain: %s\n"), current_domain_label);
    if (chain->count == 0) {
        fprintf(stderr, _("unlock from another terminal: secdat unlock\n"));
    } else {
        fprintf(stderr, _("unlock from another terminal: secdat --dir %s unlock\n"), current_domain_label);
    }
    if (options != NULL && options->timeout_configured) {
        fprintf(stderr, _("unlock wait timeout: %lld seconds\n"), (long long)options->timeout_seconds);
    }
}

static int secdat_wait_for_on_demand_unlock(
    const struct secdat_domain_chain *chain,
    const struct secdat_key_access_options *options
)
{
    time_t started_at;
    struct secdat_session_record record = {0};

    if (options == NULL || !options->allow_on_demand_unlock) {
        return 1;
    }

    secdat_print_on_demand_unlock_guidance(chain, options);
    started_at = time(NULL);

    for (;;) {
        if (secdat_session_agent_status(chain, &record) == 0) {
            secdat_session_record_reset(&record);
            return 0;
        }
        secdat_session_record_reset(&record);

        if (options->timeout_configured && time(NULL) - started_at >= options->timeout_seconds) {
            fprintf(stderr, _("timed out waiting for another terminal to unlock secrets after %lld seconds\n"), (long long)options->timeout_seconds);
            return 1;
        }

        usleep(SECDAT_ON_DEMAND_UNLOCK_WAIT_USEC);
    }
}

static void secdat_print_wait_unlock_guidance(
    const struct secdat_domain_chain *chain,
    const struct secdat_wait_unlock_options *options
)
{
    char current_domain_label[PATH_MAX];

    if (options != NULL && options->quiet) {
        return;
    }
    if (chain == NULL) {
        return;
    }
    if (secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        return;
    }

    fprintf(stderr, _("waiting for another terminal to unlock resolved domain: %s\n"), current_domain_label);
    if (chain->count == 0) {
        fprintf(stderr, _("unlock from another terminal: secdat unlock\n"));
    } else {
        fprintf(stderr, _("unlock from another terminal: secdat --dir %s unlock\n"), current_domain_label);
    }
    if (options != NULL && options->timeout_configured) {
        fprintf(stderr, _("wait-unlock timeout: %lld seconds\n"), (long long)options->timeout_seconds);
    }
}

static int secdat_wait_for_unlock(
    const struct secdat_domain_chain *chain,
    const struct secdat_wait_unlock_options *options
)
{
    time_t started_at;
    struct secdat_session_record record = {0};

    secdat_print_wait_unlock_guidance(chain, options);
    started_at = time(NULL);

    for (;;) {
        if (secdat_session_agent_status(chain, &record) == 0) {
            secdat_session_record_reset(&record);
            return 0;
        }
        secdat_session_record_reset(&record);

        if (options != NULL && options->timeout_configured && time(NULL) - started_at >= options->timeout_seconds) {
            if (!options->quiet) {
                fprintf(stderr, _("timed out waiting for another terminal to unlock resolved domain after %lld seconds\n"), (long long)options->timeout_seconds);
            }
            return 1;
        }

        usleep(SECDAT_ON_DEMAND_UNLOCK_WAIT_USEC);
    }
}

static const char *secdat_session_scope_id(const struct secdat_domain_chain *chain)
{
    if (chain != NULL && chain->count > 0) {
        return chain->ids[0];
    }

    return SECDAT_USER_GLOBAL_SCOPE_ID;
}

static int secdat_session_agent_set_current_scope(const struct secdat_domain_chain *chain, const char *master_key)
{
    return secdat_session_agent_set(secdat_session_scope_id(chain), master_key, SECDAT_SESSION_ACCESS_PERSISTENT, secdat_session_idle_seconds());
}

static int secdat_session_agent_clear_current_scope(const struct secdat_domain_chain *chain)
{
    return secdat_session_agent_clear(secdat_session_scope_id(chain));
}

static int secdat_parse_unlock_options(const struct secdat_cli *cli, struct secdat_unlock_options *options)
{
    static const struct option long_options[] = {
        {"duration", required_argument, NULL, 't'},
        {"until", required_argument, NULL, 'u'},
        {"inherit", no_argument, NULL, 'i'},
        {"volatile", no_argument, NULL, 'v'},
        {"readonly", no_argument, NULL, 'r'},
        {"descendants", no_argument, NULL, 'd'},
        {"yes", no_argument, NULL, 'y'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "unlock", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":t:u:ivrdy", long_options, NULL)) != -1) {
        switch (option) {
        case 't':
            if (secdat_parse_session_duration_seconds(optarg, &options->duration_seconds) != 0) {
                fprintf(stderr, _("invalid value for --duration: %s\n"), optarg != NULL ? optarg : "");
                return 2;
            }
            options->duration_configured = 1;
            break;
        case 'u':
            if (optarg == NULL || secdat_copy_string(options->until_value, sizeof(options->until_value), optarg) != 0) {
                fprintf(stderr, _("invalid value for --until: %s\n"), optarg != NULL ? optarg : "");
                return 2;
            }
            options->until_configured = 1;
            break;
        case 'i':
            options->inherit_mode = 1;
            break;
        case 'v':
            options->volatile_mode = 1;
            break;
        case 'r':
            options->readonly_mode = 1;
            break;
        case 'd':
            options->include_descendants = 1;
            break;
        case 'y':
            options->assume_yes = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for unlock\n"));
            secdat_cli_print_try_help(cli, "unlock");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }

    if (options->until_configured && options->duration_configured) {
        fprintf(stderr, _("--duration and --until cannot be combined\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }

    if (options->inherit_mode && (options->include_descendants || options->assume_yes || options->volatile_mode || options->readonly_mode)) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }
    if (options->volatile_mode && options->readonly_mode) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }
    if (options->volatile_mode && (options->include_descendants || options->assume_yes)) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }

    if (options->until_configured && secdat_parse_absolute_duration(options->until_value, &options->duration_seconds) != 0) {
        fprintf(stderr, _("invalid value for --until: %s\n"), options->until_value);
        return 2;
    }

    return 0;
}

static int secdat_parse_lock_options(const struct secdat_cli *cli, struct secdat_lock_options *options)
{
    static const struct option long_options[] = {
        {"inherit", no_argument, NULL, 'i'},
        {"save", no_argument, NULL, 's'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "lock", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":is", long_options, NULL)) != -1) {
        switch (option) {
        case 'i':
            options->inherit_mode = 1;
            break;
        case 's':
            options->save_mode = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for lock\n"));
            secdat_cli_print_try_help(cli, "lock");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for lock\n"));
        secdat_cli_print_try_help(cli, "lock");
        return 2;
    }

    if (options->inherit_mode && options->save_mode) {
        fprintf(stderr, _("invalid arguments for lock\n"));
        secdat_cli_print_try_help(cli, "lock");
        return 2;
    }

    return 0;
}

static int secdat_collect_locked_descendant_roots(
    const char *current_domain_root,
    struct secdat_domain_root_list *targets,
    size_t *affected_count
)
{
    struct secdat_domain_root_list descendants = {0};
    struct secdat_domain_status_summary summary;
    size_t index;

    targets->roots = NULL;
    targets->count = 0;
    *affected_count = 0;

    if (current_domain_root[0] == '\0') {
        return 0;
    }
    if (secdat_collect_descendant_domain_roots(current_domain_root, &descendants) != 0) {
        return 1;
    }

    for (index = 0; index < descendants.count; index += 1) {
        if (strcmp(descendants.roots[index], current_domain_root) == 0) {
            continue;
        }
        if (secdat_collect_domain_status_summary(descendants.roots[index], &summary) != 0) {
            secdat_domain_root_list_free(&descendants);
            secdat_domain_root_list_free(targets);
            return 1;
        }
        if (summary.effective_source != SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK
            && summary.effective_source != SECDAT_EFFECTIVE_SOURCE_BLOCKED) {
            continue;
        }
        if (secdat_domain_root_list_append(targets, descendants.roots[index]) != 0) {
            secdat_domain_root_list_free(&descendants);
            secdat_domain_root_list_free(targets);
            return 1;
        }
        *affected_count += 1;
    }

    secdat_domain_root_list_free(&descendants);
    return 0;
}

static int secdat_read_confirmation_from_tty(const char *prompt, char *buffer, size_t size)
{
    size_t length;

    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, _("unlock --descendants requires confirmation on a terminal or rerun with --yes\n"));
        return 1;
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (fgets(buffer, (int)size, stdin) == NULL) {
        fprintf(stderr, _("failed to read confirmation\n"));
        return 1;
    }

    length = strlen(buffer);
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r')) {
        buffer[length - 1] = '\0';
        length -= 1;
    }
    return 0;
}

static int secdat_confirm_descendant_unlock(size_t affected_count)
{
    char response[32];

    if (affected_count == 0) {
        return 0;
    }
    if (secdat_read_confirmation_from_tty(
            _("unlock descendant domains in this subtree? local locks will remain [y/N]: "),
            response,
            sizeof(response)
        ) != 0) {
        return 1;
    }
    if (strcmp(response, "y") == 0 || strcmp(response, "Y") == 0 || strcmp(response, "yes") == 0 || strcmp(response, "YES") == 0) {
        return 0;
    }

    fprintf(stderr, _("descendant unlock cancelled\n"));
    return 1;
}

static int secdat_unlock_descendant_sessions(
    const struct secdat_domain_root_list *targets,
    const char *master_key,
    enum secdat_session_access_mode access_mode,
    time_t duration_seconds
)
{
    char domain_id[PATH_MAX];
    size_t index;

    for (index = 0; index < targets->count; index += 1) {
        if (secdat_domain_resolve_current(targets->roots[index], domain_id, sizeof(domain_id)) != 0) {
            return 1;
        }
        if (secdat_session_agent_set(domain_id, master_key, access_mode, duration_seconds) != 0) {
            return 1;
        }
    }

    return 0;
}

static void secdat_print_descendant_unlock_summary(size_t affected_count)
{
    if (affected_count == 0) {
        return;
    }
    printf(_("note: unlocked %zu descendant domains in this subtree; local locks remain\n"), affected_count);
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
    if (!secdat_is_valid_env_name(reference->key)) {
        fprintf(stderr, _("key is not a valid environment variable name: %s\n"), reference->key);
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
    static const struct option long_options[] = {
        {"pattern", required_argument, NULL, 'p'},
        {"pattern-exclude", required_argument, NULL, 'x'},
        {"canonical", no_argument, NULL, 'c'},
        {"canonical-domain", no_argument, NULL, 'D'},
        {"canonical-store", no_argument, NULL, 'S'},
        {"safe", no_argument, NULL, 'e'},
        {"unsafe", no_argument, NULL, 'u'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "ls", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":p:x:cDSeu", long_options, NULL)) != -1) {
        switch (option) {
        case 'p':
            if (secdat_key_list_append(&options->include_patterns, optarg) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            break;
        case 'x':
            if (secdat_key_list_append(&options->exclude_patterns, optarg) != 0) {
                secdat_key_list_free(&options->include_patterns);
                secdat_key_list_free(&options->exclude_patterns);
                return 1;
            }
            break;
        case 'c':
            options->canonical_domain = 1;
            options->canonical_store = 1;
            break;
        case 'D':
            options->canonical_domain = 1;
            break;
        case 'S':
            options->canonical_store = 1;
            break;
        case 'e':
            options->safe = 1;
            break;
        case 'u':
            options->unsafe_store = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for ls\n"));
            secdat_key_list_free(&options->include_patterns);
            secdat_key_list_free(&options->exclude_patterns);
            return 2;
        }
    }

    while (optind < argc) {
        if (secdat_key_list_append(&options->include_patterns, argv[optind]) != 0) {
            secdat_key_list_free(&options->include_patterns);
            secdat_key_list_free(&options->exclude_patterns);
            return 1;
        }
        optind += 1;
    }

    return 0;
}

static int secdat_parse_exec_options(const struct secdat_cli *cli, struct secdat_exec_options *options)
{
    static const struct option long_options[] = {
        {"pattern", required_argument, NULL, 'p'},
        {"pattern-exclude", required_argument, NULL, 'x'},
        {"env-map-sed", required_argument, NULL, 1000},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "exec", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, "+:p:x:", long_options, NULL)) != -1) {
        switch (option) {
        case 'p':
            if (secdat_key_list_append(&options->include_patterns, optarg) != 0) {
                secdat_exec_options_reset(options);
                return 1;
            }
            break;
        case 'x':
            if (secdat_key_list_append(&options->exclude_patterns, optarg) != 0) {
                secdat_exec_options_reset(options);
                return 1;
            }
            break;
        case 1000:
            {
                const char *cursor = optarg;
                const char *segment_start;
                char *address_pattern = NULL;
                char *match_pattern = NULL;
                char *replacement = NULL;
                char regex_error[256];
                size_t length;
                char delimiter;
                int reg_status;

                if (options->env_map_configured) {
                    fprintf(stderr, _("--env-map-sed may be specified at most once\n"));
                    secdat_exec_options_reset(options);
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
                        fprintf(stderr, _("invalid --env-map-sed expression\n"));
                        secdat_exec_options_reset(options);
                        return 2;
                    }
                    length = (size_t)(address_end - (cursor + 1));
                    address_pattern = malloc(length + 1);
                    if (address_pattern == NULL) {
                        secdat_exec_options_reset(options);
                        return 1;
                    }
                    memcpy(address_pattern, cursor + 1, length);
                    address_pattern[length] = '\0';
                    reg_status = regcomp(&options->env_map_address_regex, address_pattern, 0);
                    if (reg_status != 0) {
                        regerror(reg_status, &options->env_map_address_regex, regex_error, sizeof(regex_error));
                        fprintf(stderr, _("invalid --env-map-sed regex: %s\n"), regex_error);
                        free(address_pattern);
                        secdat_exec_options_reset(options);
                        return 2;
                    }
                    options->env_map_has_address = 1;
                    free(address_pattern);
                    cursor = address_end + 1;
                }

                if (*cursor != 's') {
                    fprintf(stderr, _("invalid --env-map-sed expression\n"));
                    secdat_exec_options_reset(options);
                    return 2;
                }
                cursor += 1;
                delimiter = *cursor;
                if (delimiter == '\0' || delimiter == '\\' || isalnum((unsigned char)delimiter)) {
                    fprintf(stderr, _("invalid --env-map-sed expression\n"));
                    secdat_exec_options_reset(options);
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
                    fprintf(stderr, _("invalid --env-map-sed expression\n"));
                    secdat_exec_options_reset(options);
                    return 2;
                }
                length = (size_t)(cursor - segment_start);
                match_pattern = malloc(length + 1);
                if (match_pattern == NULL) {
                    secdat_exec_options_reset(options);
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
                    fprintf(stderr, _("invalid --env-map-sed expression\n"));
                    secdat_exec_options_reset(options);
                    return 2;
                }
                length = (size_t)(cursor - segment_start);
                replacement = malloc(length + 1);
                if (replacement == NULL) {
                    free(match_pattern);
                    secdat_exec_options_reset(options);
                    return 1;
                }
                memcpy(replacement, segment_start, length);
                replacement[length] = '\0';

                reg_status = regcomp(&options->env_map_regex, match_pattern, 0);
                if (reg_status != 0) {
                    regerror(reg_status, &options->env_map_regex, regex_error, sizeof(regex_error));
                    fprintf(stderr, _("invalid --env-map-sed regex: %s\n"), regex_error);
                    free(match_pattern);
                    free(replacement);
                    secdat_exec_options_reset(options);
                    return 2;
                }

                free(match_pattern);
                options->env_map_replacement = replacement;
                options->env_map_configured = 1;
            }
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for exec\n"));
            secdat_exec_options_reset(options);
            return 2;
        }
    }

    options->command_index = (size_t)(optind - 1);
    if (optind >= argc) {
        fprintf(stderr, _("invalid arguments for exec\n"));
        secdat_exec_options_reset(options);
        return 2;
    }

    return 0;
}

static int secdat_parse_list_options(const struct secdat_cli *cli, struct secdat_list_options *options)
{
    static const struct option long_options[] = {
        {"masked", no_argument, NULL, 'm'},
        {"overridden", no_argument, NULL, 'o'},
        {"orphaned", no_argument, NULL, 'O'},
        {"safe", no_argument, NULL, 'e'},
        {"unsafe", no_argument, NULL, 'u'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "list", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":moOeu", long_options, NULL)) != -1) {
        switch (option) {
        case 'm':
            options->masked = 1;
            break;
        case 'o':
            options->overridden = 1;
            break;
        case 'O':
            options->orphaned = 1;
            break;
        case 'e':
            options->safe = 1;
            break;
        case 'u':
            options->unsafe_store = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for list\n"));
            secdat_cli_print_try_help(cli, "list");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for list\n"));
        secdat_cli_print_try_help(cli, "list");
        return 2;
    }

    if (!options->masked && !options->overridden && !options->orphaned && !options->safe && !options->unsafe_store) {
        fprintf(stderr, _("missing state filter for list\n"));
        secdat_cli_print_try_help(cli, "list");
        return 2;
    }

    return 0;
}

static int secdat_parse_simple_ls_pattern(const struct secdat_cli *cli, const char *command_name, const char **pattern)
{
    static const struct option long_options[] = {
        {"pattern", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    *pattern = NULL;
    secdat_prepare_option_argv(cli, command_name, &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":p:", long_options, NULL)) != -1) {
        switch (option) {
        case 'p':
            if (*pattern != NULL) {
                fprintf(stderr, _("invalid arguments for %s\n"), command_name);
                return 2;
            }
            *pattern = optarg;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for %s\n"), command_name);
            return 2;
        }
    }

    if (optind + 1 == argc && *pattern == NULL) {
        *pattern = argv[optind];
        return 0;
    }
    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for %s\n"), command_name);
        return 2;
    }

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

static int secdat_hex_encode_bytes(const unsigned char *input, size_t length, char **output)
{
    static const char hex_digits[] = "0123456789abcdef";
    char *buffer;
    size_t index;

    buffer = malloc(length * 2 + 1);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    for (index = 0; index < length; index += 1) {
        buffer[index * 2] = hex_digits[input[index] >> 4];
        buffer[index * 2 + 1] = hex_digits[input[index] & 0x0f];
    }
    buffer[length * 2] = '\0';
    *output = buffer;
    return 0;
}

static int secdat_hex_decode_bytes(const char *input, unsigned char **output, size_t *length)
{
    unsigned char *buffer;
    size_t input_length;
    size_t index;
    int high;
    int low;

    input_length = strlen(input);
    if (input_length % 2 != 0) {
        fprintf(stderr, _("invalid overlay payload\n"));
        return 1;
    }
    buffer = malloc(input_length == 0 ? 1 : input_length / 2);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    for (index = 0; index < input_length; index += 2) {
        high = secdat_hex_value(input[index]);
        low = secdat_hex_value(input[index + 1]);
        if (high < 0 || low < 0) {
            free(buffer);
            fprintf(stderr, _("invalid overlay payload\n"));
            return 1;
        }
        buffer[index / 2] = (unsigned char)((high << 4) | low);
    }
    *output = buffer;
    *length = input_length / 2;
    return 0;
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

static const char *secdat_overlay_dump_encode_component(const char *input)
{
    return input != NULL && input[0] != '\0' ? input : "%";
}

static int secdat_overlay_dump_unescape_component(const char *input, char **output)
{
    if (strcmp(input, "%") == 0) {
        *output = strdup("");
        if (*output == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        return 0;
    }
    return secdat_unescape_component(input, output);
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

static time_t secdat_session_effective_duration(const struct secdat_session_record *record)
{
    if (record != NULL && record->duration_seconds > 0) {
        return record->duration_seconds;
    }

    return secdat_session_idle_seconds();
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
    record->duration_seconds = 0;
    record->volatile_mode = 0;
    record->readonly_mode = 0;
    secdat_overlay_list_clear(&record->overlay);
}

static void secdat_session_record_refresh(struct secdat_session_record *record)
{
    record->expires_at = time(NULL) + secdat_session_effective_duration(record);
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
    char duration_text[32];
    char line_domain[PATH_MAX * 3];
    char line_store[PATH_MAX * 3];
    char line_key[PATH_MAX * 3];
    char line_mode[32];
    char line_value[8192];
    char *domain_id = NULL;
    char *store_name = NULL;
    char *key = NULL;
    char *hex_value = NULL;
    unsigned char *decoded_value = NULL;
    size_t decoded_length = 0;
    const struct secdat_overlay_item *overlay_item;
    char *encoded_key = NULL;
    size_t index;

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
            fprintf(
                stream,
                "OK %lld %s %lld\n",
                (long long)record->expires_at,
                record->volatile_mode ? "volatile" : (record->readonly_mode ? "readonly" : "persistent"),
                (long long)secdat_session_effective_duration(record)
            );
        }
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "GET") == 0) {
        if (record->master_key[0] == '\0') {
            fprintf(stream, "ERR locked\n");
        } else {
            secdat_session_record_refresh(record);
            fprintf(stream, "OK %lld %lld\n%s\n", (long long)record->expires_at, (long long)secdat_session_effective_duration(record), record->master_key);
        }
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "SET") == 0) {
        if (secdat_read_line(stream, duration_text, sizeof(duration_text)) != 0
            || secdat_read_line(stream, payload, sizeof(payload)) != 0) {
            fclose(stream);
            return 1;
        }
        secdat_session_record_reset(record);
        if (secdat_parse_i64(duration_text, &record->duration_seconds) != 0 || record->duration_seconds <= 0) {
            fclose(stream);
            return 1;
        }
        if (secdat_copy_string(record->master_key, sizeof(record->master_key), payload) != 0) {
            fclose(stream);
            return 1;
        }
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "SETVOLATILE") == 0) {
        if (secdat_read_line(stream, duration_text, sizeof(duration_text)) != 0
            || secdat_read_line(stream, payload, sizeof(payload)) != 0) {
            fclose(stream);
            return 1;
        }
        secdat_session_record_reset(record);
        if (secdat_parse_i64(duration_text, &record->duration_seconds) != 0 || record->duration_seconds <= 0) {
            fclose(stream);
            return 1;
        }
        if (secdat_copy_string(record->master_key, sizeof(record->master_key), payload) != 0) {
            fclose(stream);
            return 1;
        }
        record->volatile_mode = 1;
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "SETREADONLY") == 0) {
        if (secdat_read_line(stream, duration_text, sizeof(duration_text)) != 0
            || secdat_read_line(stream, payload, sizeof(payload)) != 0) {
            fclose(stream);
            return 1;
        }
        secdat_session_record_reset(record);
        if (secdat_parse_i64(duration_text, &record->duration_seconds) != 0 || record->duration_seconds <= 0) {
            fclose(stream);
            return 1;
        }
        if (secdat_copy_string(record->master_key, sizeof(record->master_key), payload) != 0) {
            fclose(stream);
            return 1;
        }
        record->readonly_mode = 1;
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVLOOKUP") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "ERR missing\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        if (secdat_read_line(stream, line_domain, sizeof(line_domain)) != 0
            || secdat_read_line(stream, line_store, sizeof(line_store)) != 0
            || secdat_read_line(stream, line_key, sizeof(line_key)) != 0
            || secdat_unescape_component(line_domain, &domain_id) != 0
            || secdat_unescape_component(line_store, &store_name) != 0
            || secdat_unescape_component(line_key, &key) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            fclose(stream);
            return 1;
        }
        overlay_item = secdat_overlay_list_lookup(&record->overlay, domain_id, store_name, key);
        if (overlay_item == NULL) {
            fprintf(stream, "ERR missing\n");
        } else if (overlay_item->kind == SECDAT_OVERLAY_ITEM_TOMBSTONE) {
            fprintf(stream, "OK tomb\n");
        } else if (secdat_hex_encode_bytes(overlay_item->plaintext, overlay_item->plaintext_length, &hex_value) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            fclose(stream);
            return 1;
        } else {
            fprintf(stream, "OK entry %d\n%s\n", overlay_item->unsafe_store, hex_value);
        }
        free(hex_value);
        free(domain_id);
        free(store_name);
        free(key);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVPUT") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "ERR locked\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        if (secdat_read_line(stream, line_domain, sizeof(line_domain)) != 0
            || secdat_read_line(stream, line_store, sizeof(line_store)) != 0
            || secdat_read_line(stream, line_key, sizeof(line_key)) != 0
            || secdat_read_line(stream, line_mode, sizeof(line_mode)) != 0
            || secdat_read_line(stream, line_value, sizeof(line_value)) != 0
            || secdat_unescape_component(line_domain, &domain_id) != 0
            || secdat_unescape_component(line_store, &store_name) != 0
            || secdat_unescape_component(line_key, &key) != 0
            || secdat_hex_decode_bytes(line_value, &decoded_value, &decoded_length) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            if (decoded_value != NULL) {
                secdat_secure_clear(decoded_value, decoded_length);
                free(decoded_value);
            }
            fclose(stream);
            return 1;
        }
        if (secdat_overlay_list_set_entry(&record->overlay, domain_id, store_name, key, decoded_value, decoded_length, strcmp(line_mode, "1") == 0) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            secdat_secure_clear(decoded_value, decoded_length);
            free(decoded_value);
            fclose(stream);
            return 1;
        }
        secdat_secure_clear(decoded_value, decoded_length);
        free(decoded_value);
        free(domain_id);
        free(store_name);
        free(key);
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVTOMB") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "ERR locked\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        if (secdat_read_line(stream, line_domain, sizeof(line_domain)) != 0
            || secdat_read_line(stream, line_store, sizeof(line_store)) != 0
            || secdat_read_line(stream, line_key, sizeof(line_key)) != 0
            || secdat_unescape_component(line_domain, &domain_id) != 0
            || secdat_unescape_component(line_store, &store_name) != 0
            || secdat_unescape_component(line_key, &key) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            fclose(stream);
            return 1;
        }
        if (secdat_overlay_list_set_tombstone(&record->overlay, domain_id, store_name, key) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            fclose(stream);
            return 1;
        }
        free(domain_id);
        free(store_name);
        free(key);
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVDROP") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "ERR locked\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        if (secdat_read_line(stream, line_domain, sizeof(line_domain)) != 0
            || secdat_read_line(stream, line_store, sizeof(line_store)) != 0
            || secdat_read_line(stream, line_key, sizeof(line_key)) != 0
            || secdat_unescape_component(line_domain, &domain_id) != 0
            || secdat_unescape_component(line_store, &store_name) != 0
            || secdat_unescape_component(line_key, &key) != 0) {
            free(domain_id);
            free(store_name);
            free(key);
            fclose(stream);
            return 1;
        }
        secdat_overlay_list_remove(&record->overlay, domain_id, store_name, key);
        free(domain_id);
        free(store_name);
        free(key);
        secdat_session_record_refresh(record);
        fprintf(stream, "OK %lld\n", (long long)record->expires_at);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVLIST") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "OK 0\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        if (secdat_read_line(stream, line_domain, sizeof(line_domain)) != 0
            || secdat_read_line(stream, line_store, sizeof(line_store)) != 0
            || secdat_unescape_component(line_domain, &domain_id) != 0
            || secdat_unescape_component(line_store, &store_name) != 0) {
            free(domain_id);
            free(store_name);
            fclose(stream);
            return 1;
        }
        fprintf(stream, "OK ");
        for (index = 0; index < record->overlay.count; index += 1) {
            if (strcmp(record->overlay.items[index].domain_id, domain_id) == 0
                && strcmp(record->overlay.items[index].store_name, store_name) == 0) {
                fprintf(stream, "1");
                break;
            }
        }
        if (index == record->overlay.count) {
            fprintf(stream, "0\n");
            free(domain_id);
            free(store_name);
            fflush(stream);
            fclose(stream);
            return 0;
        }
        fprintf(stream, "\n");
        for (index = 0; index < record->overlay.count; index += 1) {
            if (strcmp(record->overlay.items[index].domain_id, domain_id) != 0
                || strcmp(record->overlay.items[index].store_name, store_name) != 0) {
                continue;
            }
            if (secdat_escape_component(record->overlay.items[index].key, &encoded_key) != 0) {
                free(domain_id);
                free(store_name);
                fclose(stream);
                return 1;
            }
            fprintf(
                stream,
                "%s %d %s\n",
                record->overlay.items[index].kind == SECDAT_OVERLAY_ITEM_TOMBSTONE ? "tomb" : "entry",
                record->overlay.items[index].unsafe_store,
                encoded_key
            );
            free(encoded_key);
            encoded_key = NULL;
        }
        free(domain_id);
        free(store_name);
        fflush(stream);
        fclose(stream);
        return 0;
    }

    if (strcmp(command, "OVDUMP") == 0) {
        if (record->master_key[0] == '\0' || !record->volatile_mode) {
            fprintf(stream, "ERR mode\n");
            fflush(stream);
            fclose(stream);
            return 0;
        }
        fprintf(stream, "OK %zu\n", record->overlay.count);
        for (index = 0; index < record->overlay.count; index += 1) {
            char *escaped_domain = NULL;
            char *escaped_store = NULL;
            char *escaped_key = NULL;

            if (secdat_escape_component(record->overlay.items[index].domain_id, &escaped_domain) != 0
                || secdat_escape_component(record->overlay.items[index].store_name, &escaped_store) != 0
                || secdat_escape_component(record->overlay.items[index].key, &escaped_key) != 0) {
                free(escaped_domain);
                free(escaped_store);
                free(escaped_key);
                fclose(stream);
                return 1;
            }
            if (record->overlay.items[index].kind == SECDAT_OVERLAY_ITEM_TOMBSTONE) {
                fprintf(
                    stream,
                    "tomb %d %s %s %s -\n",
                    record->overlay.items[index].unsafe_store,
                    escaped_domain,
                    secdat_overlay_dump_encode_component(escaped_store),
                    escaped_key
                );
            } else if (secdat_hex_encode_bytes(record->overlay.items[index].plaintext, record->overlay.items[index].plaintext_length, &hex_value) != 0) {
                free(escaped_domain);
                free(escaped_store);
                free(escaped_key);
                fclose(stream);
                return 1;
            } else {
                fprintf(
                    stream,
                    "entry %d %s %s %s %s\n",
                    record->overlay.items[index].unsafe_store,
                    escaped_domain,
                    secdat_overlay_dump_encode_component(escaped_store),
                    escaped_key,
                    hex_value
                );
            }
            free(hex_value);
            hex_value = NULL;
            free(escaped_domain);
            free(escaped_store);
            free(escaped_key);
        }
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
    return secdat_session_agent_connect_chain_details(chain, NULL, NULL);
}

static int secdat_session_agent_connect_chain_details_with_options(
    const struct secdat_domain_chain *chain,
    size_t *matched_index,
    size_t *blocked_index,
    const struct secdat_session_lookup_options *options
)
{
    size_t index;
    int fd;
    int ignore_current_explicit_lock = options != NULL && options->ignore_current_explicit_lock;

    if (matched_index != NULL) {
        *matched_index = SIZE_MAX;
    }
    if (blocked_index != NULL) {
        *blocked_index = SIZE_MAX;
    }

    for (index = 0; index < chain->count; index += 1) {
        fd = secdat_session_agent_connect_domain(chain->ids[index], 0);
        if (fd >= 0) {
            if (matched_index != NULL) {
                *matched_index = index;
            }
            return fd;
        }
        if (ignore_current_explicit_lock && index == 0) {
            continue;
        }
        if (secdat_domain_has_explicit_lock(chain->ids[index])) {
            if (blocked_index != NULL) {
                *blocked_index = index;
            }
            return -1;
        }
    }

    fd = secdat_session_agent_connect_domain(SECDAT_USER_GLOBAL_SCOPE_ID, 0);
    if (fd >= 0) {
        if (matched_index != NULL) {
            *matched_index = chain->count;
        }
        return fd;
    }

    return -1;
}

static int secdat_session_agent_connect_chain_details(const struct secdat_domain_chain *chain, size_t *matched_index, size_t *blocked_index)
{
    return secdat_session_agent_connect_chain_details_with_options(chain, matched_index, blocked_index, NULL);
}

static int secdat_session_agent_status(const struct secdat_domain_chain *chain, struct secdat_session_record *record)
{
    return secdat_session_agent_status_details(chain, record, NULL, NULL);
}

static int secdat_session_agent_status_details(
    const struct secdat_domain_chain *chain,
    struct secdat_session_record *record,
    size_t *matched_index,
    size_t *blocked_index
)
{
    FILE *stream;
    int fd;
    char duration_text[32];
    char response[64];
    char expires_text[32];
    char mode[16];

    memset(record, 0, sizeof(*record));
    fd = secdat_session_agent_connect_chain_details(chain, matched_index, blocked_index);
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
    mode[0] = '\0';
    duration_text[0] = '\0';
    if (sscanf(response, "OK %31s %15s %31s", expires_text, mode, duration_text) < 2) {
        return 1;
    }
    if (secdat_parse_i64(expires_text, &record->expires_at) != 0) {
        return 1;
    }
    record->duration_seconds = secdat_session_idle_seconds();
    if (strcmp(mode, "volatile") == 0) {
        record->volatile_mode = 1;
    } else if (strcmp(mode, "readonly") == 0) {
        record->readonly_mode = 1;
    }
    if (duration_text[0] != '\0' && secdat_parse_i64(duration_text, &record->duration_seconds) != 0) {
        return 1;
    }
    return 0;
}

static int secdat_session_agent_get(const struct secdat_domain_chain *chain, struct secdat_session_record *record)
{
    FILE *stream;
    int fd;
    char response[64];
    char duration_text[32];
    char expires_text[32];
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
    if (sscanf(response, "OK %31s %31s", expires_text, duration_text) != 2
        || secdat_parse_i64(expires_text, &record->expires_at) != 0
        || secdat_parse_i64(duration_text, &record->duration_seconds) != 0
        || secdat_read_line(stream, secret, sizeof(secret)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);

    return secdat_copy_string(record->master_key, sizeof(record->master_key), secret);
}

static int secdat_session_agent_set(const char *domain_id, const char *master_key, enum secdat_session_access_mode access_mode, time_t duration_seconds)
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

    fprintf(
        stream,
        "%s\n%lld\n%s\n",
        access_mode == SECDAT_SESSION_ACCESS_VOLATILE ? "SETVOLATILE"
            : (access_mode == SECDAT_SESSION_ACCESS_READONLY ? "SETREADONLY" : "SET"),
        (long long)duration_seconds,
        master_key
    );
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    return strncmp(response, "OK ", 3) == 0 ? 0 : 1;
}

static int secdat_session_agent_status_scope(const char *domain_id, struct secdat_session_record *record)
{
    FILE *stream;
    int fd;
    char response[64];
    char duration_text[32];
    char expires_text[32];
    char mode[16];

    memset(record, 0, sizeof(*record));
    fd = secdat_session_agent_connect_domain(domain_id, 0);
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
    mode[0] = '\0';
    duration_text[0] = '\0';
    if (sscanf(response, "OK %31s %15s %31s", expires_text, mode, duration_text) < 2 || secdat_parse_i64(expires_text, &record->expires_at) != 0) {
        return 1;
    }
    record->duration_seconds = secdat_session_idle_seconds();
    if (strcmp(mode, "volatile") == 0) {
        record->volatile_mode = 1;
    } else if (strcmp(mode, "readonly") == 0) {
        record->readonly_mode = 1;
    }
    if (duration_text[0] != '\0' && secdat_parse_i64(duration_text, &record->duration_seconds) != 0) {
        return 1;
    }
    return 0;
}

static int secdat_session_agent_effective_overlay_fd(
    const struct secdat_domain_chain *chain,
    struct secdat_session_record *record,
    size_t *matched_index
)
{
    int fd;

    memset(record, 0, sizeof(*record));
    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        return -1;
    }
    if (secdat_session_agent_status_details(chain, record, matched_index, NULL) != 0 || !record->volatile_mode) {
        secdat_secure_clear(record->master_key, strlen(record->master_key));
        return -1;
    }
    fd = secdat_session_agent_connect_chain_details(chain, matched_index, NULL);
    if (fd < 0) {
        secdat_secure_clear(record->master_key, strlen(record->master_key));
        return -1;
    }
    return fd;
}

static int secdat_overlay_write_triplet(FILE *stream, const char *domain_id, const char *store_name, const char *key)
{
    char *escaped_domain = NULL;
    char *escaped_store = NULL;
    char *escaped_key = NULL;
    int status = 1;

    if (secdat_escape_component(domain_id, &escaped_domain) != 0
        || secdat_escape_component(store_name != NULL ? store_name : "", &escaped_store) != 0
        || secdat_escape_component(key, &escaped_key) != 0) {
        goto cleanup;
    }
    fprintf(stream, "%s\n%s\n%s\n", escaped_domain, escaped_store, escaped_key);
    status = 0;

cleanup:
    free(escaped_domain);
    free(escaped_store);
    free(escaped_key);
    return status;
}

static int secdat_overlay_write_pair(FILE *stream, const char *domain_id, const char *store_name)
{
    char *escaped_domain = NULL;
    char *escaped_store = NULL;
    int status = 1;

    if (secdat_escape_component(domain_id, &escaped_domain) != 0
        || secdat_escape_component(store_name != NULL ? store_name : "", &escaped_store) != 0) {
        goto cleanup;
    }
    fprintf(stream, "%s\n%s\n", escaped_domain, escaped_store);
    status = 0;

cleanup:
    free(escaped_domain);
    free(escaped_store);
    return status;
}

static int secdat_session_agent_overlay_lookup(
    int fd,
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_overlay_lookup_result *result
)
{
    FILE *stream;
    char response[64];
    char payload[8192];

    memset(result, 0, sizeof(*result));
    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    fprintf(stream, "OVLOOKUP\n");
    if (secdat_overlay_write_triplet(stream, domain_id, store_name, key) != 0) {
        fclose(stream);
        return 1;
    }
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    if (strcmp(response, "ERR missing") == 0) {
        fclose(stream);
        return 0;
    }
    if (strcmp(response, "OK tomb") == 0) {
        result->found = 1;
        result->tombstone = 1;
        fclose(stream);
        return 0;
    }
    if (strncmp(response, "OK entry ", 9) != 0) {
        fclose(stream);
        return 1;
    }
    result->unsafe_store = strcmp(response + 9, "1") == 0;
    if (secdat_read_line(stream, payload, sizeof(payload)) != 0
        || secdat_hex_decode_bytes(payload, &result->plaintext, &result->plaintext_length) != 0) {
        fclose(stream);
        return 1;
    }
    result->found = 1;
    fclose(stream);
    return 0;
}

static int secdat_session_agent_overlay_store_plaintext(
    int fd,
    const char *domain_id,
    const char *store_name,
    const char *key,
    const unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
)
{
    FILE *stream;
    char response[64];
    char *encoded = NULL;
    int status = 1;

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    if (secdat_hex_encode_bytes(plaintext, plaintext_length, &encoded) != 0) {
        fclose(stream);
        return 1;
    }
    fprintf(stream, "OVPUT\n");
    if (secdat_overlay_write_triplet(stream, domain_id, store_name, key) != 0) {
        goto cleanup;
    }
    fprintf(stream, "%d\n%s\n", unsafe_store, encoded);
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        goto cleanup;
    }
    status = strncmp(response, "OK ", 3) == 0 ? 0 : 1;

cleanup:
    free(encoded);
    fclose(stream);
    return status;
}

static int secdat_session_agent_overlay_set_tombstone(
    int fd,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    FILE *stream;
    char response[64];

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    fprintf(stream, "OVTOMB\n");
    if (secdat_overlay_write_triplet(stream, domain_id, store_name, key) != 0) {
        fclose(stream);
        return 1;
    }
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    return strncmp(response, "OK ", 3) == 0 ? 0 : 1;
}

static int secdat_session_agent_overlay_drop(
    int fd,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    FILE *stream;
    char response[64];

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    fprintf(stream, "OVDROP\n");
    if (secdat_overlay_write_triplet(stream, domain_id, store_name, key) != 0) {
        fclose(stream);
        return 1;
    }
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    fclose(stream);
    return strncmp(response, "OK ", 3) == 0 ? 0 : 1;
}

static int secdat_session_agent_overlay_collect_keys(
    int fd,
    const char *domain_id,
    const char *store_name,
    struct secdat_key_list *entries,
    struct secdat_key_list *tombstones
)
{
    FILE *stream;
    char response[64];
    char row[PATH_MAX * 3];
    char kind[16];
    char escaped_key[PATH_MAX * 3];
    int unsafe_store;
    char *decoded_key = NULL;
    int status = 1;

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    fprintf(stream, "OVLIST\n");
    if (secdat_overlay_write_pair(stream, domain_id, store_name) != 0) {
        fclose(stream);
        return 1;
    }
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    if (strcmp(response, "OK 0") == 0) {
        fclose(stream);
        return 0;
    }
    if (strcmp(response, "OK 1") != 0) {
        fclose(stream);
        return 1;
    }
    while (secdat_read_line(stream, row, sizeof(row)) == 0) {
        if (sscanf(row, "%15s %d %4095s", kind, &unsafe_store, escaped_key) != 3) {
            break;
        }
        if (secdat_unescape_component(escaped_key, &decoded_key) != 0) {
            goto cleanup;
        }
        if (strcmp(kind, "tomb") == 0) {
            if (secdat_key_list_append(tombstones, decoded_key) != 0) {
                free(decoded_key);
                goto cleanup;
            }
        } else if (secdat_key_list_append(entries, decoded_key) != 0) {
            free(decoded_key);
            goto cleanup;
        }
        free(decoded_key);
        decoded_key = NULL;
    }
    status = 0;

cleanup:
    free(decoded_key);
    fclose(stream);
    return status;
}

static int secdat_overlay_list_append_dump_item(
    struct secdat_overlay_list *list,
    const char *domain_id,
    const char *store_name,
    const char *key,
    enum secdat_overlay_item_kind kind,
    int unsafe_store,
    const unsigned char *plaintext,
    size_t plaintext_length
)
{
    struct secdat_overlay_item item;

    memset(&item, 0, sizeof(item));
    if (secdat_overlay_list_ensure_capacity(list) != 0) {
        return 1;
    }
    item.domain_id = strdup(domain_id);
    item.key = strdup(key);
    if (item.domain_id == NULL || item.key == NULL || secdat_overlay_store_name_copy(store_name, &item.store_name) != 0) {
        free(item.domain_id);
        free(item.key);
        free(item.store_name);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    item.kind = kind;
    item.unsafe_store = unsafe_store;
    if (kind == SECDAT_OVERLAY_ITEM_ENTRY && secdat_duplicate_bytes(plaintext, plaintext_length, &item.plaintext) != 0) {
        secdat_overlay_item_free(&item);
        return 1;
    }
    item.plaintext_length = plaintext_length;
    list->items[list->count] = item;
    list->count += 1;
    return 0;
}

static int secdat_session_agent_overlay_dump(int fd, struct secdat_overlay_list *overlay)
{
    FILE *stream;
    char response[64];
    char row[16384];
    char kind[16];
    int unsafe_store;
    char escaped_domain[4096];
    char escaped_store[4096];
    char escaped_key[4096];
    char payload[8192];
    char *domain_id = NULL;
    char *store_name = NULL;
    char *key = NULL;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    size_t count;
    size_t index;
    int status = 1;

    stream = fdopen(fd, "r+");
    if (stream == NULL) {
        close(fd);
        return 1;
    }
    fprintf(stream, "OVDUMP\n");
    fflush(stream);
    if (secdat_read_line(stream, response, sizeof(response)) != 0) {
        fclose(stream);
        return 1;
    }
    if (sscanf(response, "OK %zu", &count) != 1) {
        fclose(stream);
        return 1;
    }
    for (index = 0; index < count; index += 1) {
        if (secdat_read_line(stream, row, sizeof(row)) != 0) {
            goto cleanup;
        }
        if (sscanf(row, "%15s %d %4095s %4095s %4095s %8191s", kind, &unsafe_store, escaped_domain, escaped_store, escaped_key, payload) != 6) {
            goto cleanup;
        }
        if (secdat_unescape_component(escaped_domain, &domain_id) != 0
            || secdat_overlay_dump_unescape_component(escaped_store, &store_name) != 0
            || secdat_unescape_component(escaped_key, &key) != 0) {
            goto cleanup;
        }
        if (strcmp(kind, "entry") == 0) {
            if (secdat_hex_decode_bytes(payload, &plaintext, &plaintext_length) != 0
                || secdat_overlay_list_append_dump_item(overlay, domain_id, store_name, key, SECDAT_OVERLAY_ITEM_ENTRY, unsafe_store, plaintext, plaintext_length) != 0) {
                goto cleanup;
            }
        } else if (strcmp(kind, "tomb") == 0) {
            if (secdat_overlay_list_append_dump_item(overlay, domain_id, store_name, key, SECDAT_OVERLAY_ITEM_TOMBSTONE, unsafe_store, NULL, 0) != 0) {
                goto cleanup;
            }
        } else {
            goto cleanup;
        }
        free(domain_id);
        free(store_name);
        free(key);
        domain_id = NULL;
        store_name = NULL;
        key = NULL;
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        plaintext = NULL;
        plaintext_length = 0;
    }
    status = 0;

cleanup:
    free(domain_id);
    free(store_name);
    free(key);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    fclose(stream);
    return status;
}

static int secdat_active_overlay_lookup(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_overlay_lookup_result *result
)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;
    int status;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        memset(result, 0, sizeof(*result));
        return 0;
    }
    status = secdat_session_agent_overlay_lookup(fd, domain_id, store_name, key, result);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return status;
}

static int secdat_active_overlay_collect_keys(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    struct secdat_key_list *entries,
    struct secdat_key_list *tombstones
)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;
    int status;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        return 0;
    }
    status = secdat_session_agent_overlay_collect_keys(fd, domain_id, store_name, entries, tombstones);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return status;
}

static int secdat_active_overlay_store_plaintext(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    const unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;
    int status;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        return 1;
    }
    status = secdat_session_agent_overlay_store_plaintext(fd, domain_id, store_name, key, plaintext, plaintext_length, unsafe_store);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return status;
}

static int secdat_active_overlay_set_tombstone(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;
    int status;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        return 1;
    }
    status = secdat_session_agent_overlay_set_tombstone(fd, domain_id, store_name, key);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return status;
}

static int secdat_active_overlay_drop(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key
)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;
    int status;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        return 1;
    }
    status = secdat_session_agent_overlay_drop(fd, domain_id, store_name, key);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return status;
}

static int secdat_active_overlay_enabled(const struct secdat_domain_chain *chain)
{
    struct secdat_session_record record = {0};
    size_t matched_index = SIZE_MAX;
    int fd;

    fd = secdat_session_agent_effective_overlay_fd(chain, &record, &matched_index);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return 1;
}

static int secdat_effective_session_is_readonly(const struct secdat_domain_chain *chain)
{
    struct secdat_session_record record = {0};

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        return 0;
    }
    if (secdat_session_agent_status_details(chain, &record, NULL, NULL) != 0) {
        return 0;
    }
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return record.readonly_mode;
}

static void secdat_print_readonly_write_guidance(const struct secdat_domain_chain *chain)
{
    char current_domain_label[PATH_MAX];

    if (chain == NULL || secdat_domain_display_label(chain->count == 0 ? "" : chain->ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        return;
    }
    fprintf(stderr, _("resolved domain: %s\n"), current_domain_label);
    if (chain->count == 0) {
        fprintf(stderr, _("unlock writable session: secdat unlock\n"));
    } else {
        fprintf(stderr, _("unlock writable session: secdat --dir %s unlock\n"), current_domain_label);
    }
}

static int secdat_require_mutable_session_chain(const struct secdat_domain_chain *chain, const char *command_name)
{
    if (!secdat_effective_session_is_readonly(chain)) {
        return 0;
    }
    fprintf(stderr, _("current session is readonly and cannot run %s\n"), command_name);
    secdat_print_readonly_write_guidance(chain);
    return 1;
}

int secdat_require_writable_session_access(const char *dir_override, const char *command_name)
{
    struct secdat_domain_chain chain = {0};
    int status;

    if (secdat_domain_resolve_chain(dir_override, &chain) != 0) {
        return 1;
    }
    status = secdat_require_mutable_session_chain(&chain, command_name);
    secdat_domain_chain_free(&chain);
    return status;
}

static const char *secdat_overlay_effective_store_name(const char *store_name)
{
    return store_name != NULL && store_name[0] != '\0' ? store_name : NULL;
}

static int secdat_persist_overlay_tombstone(const char *domain_id, const char *store_name, const char *key)
{
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstone_path[PATH_MAX];
    char entry_path[PATH_MAX];

    if (secdat_require_writable_domain_id(domain_id) != 0) {
        return 1;
    }
    if (secdat_domain_store_root(domain_id, secdat_overlay_effective_store_name(store_name), store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    if (secdat_join_path(entries_dir, sizeof(entries_dir), store_root, "entries") != 0) {
        return 1;
    }
    if (secdat_ensure_directory(entries_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_build_entry_path(domain_id, secdat_overlay_effective_store_name(store_name), key, entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    if (secdat_build_tombstone_path(domain_id, secdat_overlay_effective_store_name(store_name), key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }
    if (secdat_file_exists(entry_path) && unlink(entry_path) != 0) {
        fprintf(stderr, _("failed to remove key: %s\n"), key);
        return 1;
    }
    return secdat_write_empty_file(tombstone_path);
}

static int secdat_save_local_volatile_session_overlay(const struct secdat_domain_chain *chain)
{
    struct secdat_session_record record = {0};
    struct secdat_overlay_list overlay = {0};
    const char *scope_id = secdat_session_scope_id(chain);
    size_t index;
    int fd;
    int status = 1;

    if (secdat_session_agent_status_scope(scope_id, &record) != 0 || !record.volatile_mode) {
        fprintf(stderr, _("lock --save requires a local volatile session\n"));
        return 1;
    }
    fd = secdat_session_agent_connect_domain(scope_id, 0);
    if (fd < 0) {
        fprintf(stderr, _("lock --save requires a local volatile session\n"));
        return 1;
    }
    if (secdat_session_agent_overlay_dump(fd, &overlay) != 0) {
        goto cleanup;
    }
    for (index = 0; index < overlay.count; index += 1) {
        if (overlay.items[index].kind == SECDAT_OVERLAY_ITEM_ENTRY) {
            if (secdat_store_plaintext(
                    overlay.items[index].domain_id,
                    secdat_overlay_effective_store_name(overlay.items[index].store_name),
                    overlay.items[index].key,
                    overlay.items[index].plaintext,
                    overlay.items[index].plaintext_length,
                    overlay.items[index].unsafe_store
                ) != 0) {
                goto cleanup;
            }
        } else if (secdat_persist_overlay_tombstone(
                       overlay.items[index].domain_id,
                       secdat_overlay_effective_store_name(overlay.items[index].store_name),
                       overlay.items[index].key
                   ) != 0) {
            goto cleanup;
        }
    }
    status = 0;

cleanup:
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    secdat_overlay_list_clear(&overlay);
    return status;
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

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
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

        if (secdat_load_resolved_plaintext(&chain, cli->store, visible_keys.items[index], &plaintext, &plaintext_length, NULL, NULL, NULL) != 0) {
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

static int secdat_collect_domain_status_summary_for_chain(
    const struct secdat_domain_chain *chain,
    struct secdat_domain_status_summary *summary
)
{
    struct secdat_domain_chain empty_chain = {0};
    struct secdat_key_list visible_keys = {0};
    struct secdat_key_list stores = {0};
    struct secdat_session_record record = {0};
    const struct secdat_domain_chain *resolved_chain = chain != NULL ? chain : &empty_chain;
    size_t matched_index = SIZE_MAX;
    size_t blocked_index = SIZE_MAX;
    int status = 1;

    memset(summary, 0, sizeof(*summary));
    summary->wrapped_master_key_present = secdat_wrapped_master_key_exists();

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        summary->key_source = SECDAT_KEY_SOURCE_ENVIRONMENT;
        summary->effective_source = SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT;
    }

    if (resolved_chain->count > 0) {
        if (secdat_collect_store_names(resolved_chain->ids[0], NULL, &stores) != 0) {
            goto cleanup;
        }
        summary->store_count = stores.count;

        if (secdat_collect_visible_keys(resolved_chain, NULL, NULL, NULL, &visible_keys) != 0) {
            goto cleanup;
        }
        summary->visible_key_count = visible_keys.count;
    }

    if (summary->key_source != SECDAT_KEY_SOURCE_ENVIRONMENT
        && secdat_session_agent_status_details(resolved_chain, &record, &matched_index, &blocked_index) == 0) {
        summary->key_source = SECDAT_KEY_SOURCE_SESSION;
        summary->session_expires_at = record.expires_at;
        summary->effective_source = matched_index == 0
            ? SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION
            : SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION;
        if (matched_index != SIZE_MAX && matched_index > 0) {
            if (matched_index == resolved_chain->count) {
                if (secdat_domain_display_label("", summary->related_domain_root, sizeof(summary->related_domain_root)) != 0) {
                    goto cleanup;
                }
            } else if (secdat_domain_root_path(resolved_chain->ids[matched_index], summary->related_domain_root, sizeof(summary->related_domain_root)) != 0) {
                goto cleanup;
            }
        }
        secdat_secure_clear(record.master_key, strlen(record.master_key));
    } else if (summary->key_source != SECDAT_KEY_SOURCE_ENVIRONMENT) {
        if (blocked_index == 0) {
            summary->effective_source = SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK;
        } else if (blocked_index != SIZE_MAX && blocked_index < resolved_chain->count) {
            summary->effective_source = SECDAT_EFFECTIVE_SOURCE_BLOCKED;
            if (secdat_domain_root_path(resolved_chain->ids[blocked_index], summary->related_domain_root, sizeof(summary->related_domain_root)) != 0) {
                goto cleanup;
            }
        }
    }

    status = 0;

cleanup:
    if (status != 0) {
        secdat_secure_clear(record.master_key, strlen(record.master_key));
    }
    secdat_key_list_free(&visible_keys);
    secdat_key_list_free(&stores);
    return status;
}

int secdat_collect_domain_status_summary(const char *dir_override, struct secdat_domain_status_summary *summary)
{
    struct secdat_domain_chain chain = {0};
    int status;

    if (secdat_domain_resolve_chain(dir_override, &chain) != 0) {
        return 1;
    }

    status = secdat_collect_domain_status_summary_for_chain(&chain, summary);
    secdat_domain_chain_free(&chain);
    return status;
}

int secdat_collect_user_global_status_summary(struct secdat_domain_status_summary *summary)
{
    struct secdat_domain_chain chain = {0};

    return secdat_collect_domain_status_summary_for_chain(&chain, summary);
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

static int secdat_derive_key(
    const struct secdat_domain_chain *chain,
    unsigned char key[32],
    const struct secdat_key_access_options *access_options
)
{
    struct secdat_session_record record = {0};
    const char *master_key = getenv("SECDAT_MASTER_KEY");
    unsigned int key_length = 0;

    if (master_key == NULL || master_key[0] == '\0') {
        if (secdat_session_agent_get(chain, &record) == 0) {
            master_key = record.master_key;
        } else if (access_options != NULL && access_options->allow_on_demand_unlock) {
            if (secdat_wait_for_on_demand_unlock(chain, access_options) != 0 || secdat_session_agent_get(chain, &record) != 0) {
                return 1;
            }
            master_key = record.master_key;
        } else {
            fprintf(
                stderr,
                _("missing SECDAT_MASTER_KEY and no active secdat session; run secdat unlock or export SECDAT_MASTER_KEY\n")
            );
            secdat_print_locked_read_guidance(chain);
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

static int secdat_effective_unlock_state_without_current_explicit_lock(
    const struct secdat_domain_chain *chain,
    int *would_unlock,
    size_t *matched_index,
    size_t *blocked_index
)
{
    FILE *stream;
    struct secdat_session_record record = {0};
    struct secdat_session_lookup_options options = {0};
    char response[64];
    int fd;

    *would_unlock = 0;
    if (matched_index != NULL) {
        *matched_index = SIZE_MAX;
    }
    if (blocked_index != NULL) {
        *blocked_index = SIZE_MAX;
    }
    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        *would_unlock = 1;
        return 0;
    }

    options.ignore_current_explicit_lock = 1;
    fd = secdat_session_agent_connect_chain_details_with_options(chain, matched_index, blocked_index, &options);
    if (fd < 0) {
        return 0;
    }

    memset(&record, 0, sizeof(record));
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
    {
        char expires_text[32];

        if (sscanf(response, "OK %31s", expires_text) != 1 || secdat_parse_i64(expires_text, &record.expires_at) != 0) {
            return 1;
        }
    }

    *would_unlock = 1;
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return 0;
}

static int secdat_current_scope_has_local_session(const struct secdat_domain_chain *chain)
{
    struct secdat_session_record record = {0};

    return secdat_session_agent_status_scope(secdat_session_scope_id(chain), &record) == 0;
}

static int secdat_effective_unlock_state_without_current_local_session(
    const struct secdat_domain_chain *chain,
    int *would_unlock,
    size_t *matched_index,
    size_t *blocked_index
)
{
    struct secdat_domain_chain parent_chain = {0};
    FILE *stream;
    struct secdat_session_record record = {0};
    char response[64];
    int fd;

    *would_unlock = 0;
    if (matched_index != NULL) {
        *matched_index = SIZE_MAX;
    }
    if (blocked_index != NULL) {
        *blocked_index = SIZE_MAX;
    }
    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        *would_unlock = 1;
        return 0;
    }
    if (chain->count == 0) {
        return 0;
    }

    parent_chain.ids = chain->ids + 1;
    parent_chain.count = chain->count - 1;
    fd = secdat_session_agent_connect_chain_details(&parent_chain, matched_index, blocked_index);
    if (fd < 0) {
        return 0;
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
    {
        char expires_text[32];

        if (sscanf(response, "OK %31s", expires_text) != 1 || secdat_parse_i64(expires_text, &record.expires_at) != 0) {
            return 1;
        }
    }

    if (matched_index != NULL && *matched_index != SIZE_MAX) {
        *matched_index += 1;
    }
    if (blocked_index != NULL && *blocked_index != SIZE_MAX) {
        *blocked_index += 1;
    }

    *would_unlock = 1;
    secdat_secure_clear(record.master_key, strlen(record.master_key));
    return 0;
}

static int secdat_remove_local_explicit_lock(
    const struct secdat_domain_chain *chain,
    const char *current_domain_label,
    enum secdat_inherit_expectation expectation
)
{
    size_t blocked_index = SIZE_MAX;
    size_t matched_index = SIZE_MAX;
    int removed = 0;
    int would_unlock = 0;

    if (chain->count == 0) {
        fprintf(stderr, _("no local lock for: %s\n"), current_domain_label);
        return 1;
    }
    if (!secdat_domain_has_explicit_lock(chain->ids[0])) {
        fprintf(stderr, _("no local lock for: %s\n"), current_domain_label);
        return 1;
    }

    if (expectation != SECDAT_INHERIT_EXPECT_ANY) {
        if (secdat_effective_unlock_state_without_current_explicit_lock(chain, &would_unlock, &matched_index, &blocked_index) != 0) {
            return 1;
        }
        if ((expectation == SECDAT_INHERIT_EXPECT_UNLOCKED && !would_unlock)
            || (expectation == SECDAT_INHERIT_EXPECT_LOCKED && would_unlock)) {
            fprintf(stderr, _("refusing to remove local lock for: %s\n"), current_domain_label);
            fprintf(stderr, _("expected resulting state: %s\n"),
                expectation == SECDAT_INHERIT_EXPECT_UNLOCKED ? "unlocked" : "locked");
            fprintf(stderr, _("actual resulting state after removing local lock: %s\n"),
                would_unlock ? "unlocked" : "locked");
            return 1;
        }
    }

    if (secdat_domain_clear_explicit_lock(chain->ids[0], &removed) != 0) {
        return 1;
    }
    if (!removed) {
        fprintf(stderr, _("no local lock for: %s\n"), current_domain_label);
        return 1;
    }

    if (expectation == SECDAT_INHERIT_EXPECT_UNLOCKED) {
        puts(_("local lock removed; resulting state: unlocked"));
    } else if (expectation == SECDAT_INHERIT_EXPECT_LOCKED) {
        puts(_("local lock removed; resulting state: locked"));
    } else {
        puts(_("local lock removed"));
    }
    return 0;
}

static int secdat_clear_local_session(
    const struct secdat_domain_chain *chain,
    const char *current_domain_label,
    enum secdat_inherit_expectation expectation
)
{
    size_t blocked_index = SIZE_MAX;
    size_t matched_index = SIZE_MAX;
    int would_unlock = 0;

    if (!secdat_current_scope_has_local_session(chain)) {
        fprintf(stderr, _("no local lock or local unlock for: %s\n"), current_domain_label);
        return 1;
    }

    if (expectation != SECDAT_INHERIT_EXPECT_ANY) {
        if (secdat_effective_unlock_state_without_current_local_session(chain, &would_unlock, &matched_index, &blocked_index) != 0) {
            return 1;
        }
        if ((expectation == SECDAT_INHERIT_EXPECT_UNLOCKED && !would_unlock)
            || (expectation == SECDAT_INHERIT_EXPECT_LOCKED && would_unlock)) {
            fprintf(stderr, _("refusing to clear local unlock for: %s\n"), current_domain_label);
            fprintf(stderr, _("expected resulting state: %s\n"),
                expectation == SECDAT_INHERIT_EXPECT_UNLOCKED ? "unlocked" : "locked");
            fprintf(stderr, _("actual resulting state after clearing local unlock: %s\n"),
                would_unlock ? "unlocked" : "locked");
            return 1;
        }
    }

    if (secdat_session_agent_clear_current_scope(chain) != 0) {
        return 1;
    }

    if (expectation == SECDAT_INHERIT_EXPECT_UNLOCKED) {
        puts(_("local unlock cleared; resulting state: unlocked"));
    } else if (expectation == SECDAT_INHERIT_EXPECT_LOCKED) {
        puts(_("local unlock cleared; resulting state: locked"));
    } else {
        puts(_("local unlock cleared"));
    }
    return 0;
}

static int secdat_clear_local_inherit_override(
    const struct secdat_domain_chain *chain,
    const char *current_domain_label,
    enum secdat_inherit_expectation expectation
)
{
    if (chain->count > 0 && secdat_domain_has_explicit_lock(chain->ids[0])) {
        return secdat_remove_local_explicit_lock(chain, current_domain_label, expectation);
    }
    if (secdat_current_scope_has_local_session(chain)) {
        return secdat_clear_local_session(chain, current_domain_label, expectation);
    }

    fprintf(stderr, _("no local lock or local unlock for: %s\n"), current_domain_label);
    return 1;
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
    static const struct option long_options[] = {
        {"quiet", no_argument, NULL, 'q'},
        {NULL, 0, NULL, 0},
    };
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    char *argv[cli->argc + 2];
    int argc;
    int option;
    int quiet = 0;
    int wrapped_present = secdat_wrapped_master_key_exists();
    char remaining_text[32];

    secdat_prepare_option_argv(cli, "status", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":q", long_options, NULL)) != -1) {
        switch (option) {
        case 'q':
            quiet = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for status\n"));
            secdat_cli_print_try_help(cli, "status");
            return 2;
        }
    }

    if (optind != argc) {
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

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) == 0 && secdat_session_agent_status(&chain, &record) == 0) {
        if (!quiet) {
            puts(_("unlocked"));
            puts(_("source: session agent"));
            if (record.volatile_mode) {
                puts(_("overlay: volatile"));
            }
            if (record.readonly_mode) {
                puts(_("access: readonly"));
            }
            secdat_format_remaining_duration(record.expires_at, remaining_text, sizeof(remaining_text));
            printf(_("expires in: %s\n"), remaining_text);
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

static int secdat_command_wait_unlock(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    struct secdat_wait_unlock_options options;
    int parse_status;

    if (cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for wait-unlock\n"));
        secdat_cli_print_try_help(cli, "wait-unlock");
        return 2;
    }

    parse_status = secdat_parse_wait_unlock_options(cli, &options);
    if (parse_status != 0) {
        return parse_status;
    }

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        return 0;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }

    if (secdat_session_agent_status(&chain, &record) == 0) {
        secdat_session_record_reset(&record);
        secdat_domain_chain_free(&chain);
        return 0;
    }

    parse_status = secdat_wait_for_unlock(&chain, &options);
    secdat_domain_chain_free(&chain);
    return parse_status;
}

static int secdat_command_unlock(const struct secdat_cli *cli)
{
    struct secdat_domain_chain current_chain = {0};
    struct secdat_session_record active_record = {0};
    struct secdat_session_record secret_record = {0};
    char current_domain_label[PATH_MAX];
    char current_domain_root[PATH_MAX];
    struct secdat_unlock_options options;
    struct secdat_domain_root_list descendant_targets = {0};
    const char *env_master_key = getenv("SECDAT_MASTER_KEY");
    size_t descendant_unlock_count = 0;
    size_t matched_index = SIZE_MAX;
    int wrapped_present = secdat_wrapped_master_key_exists();
    int initialized = 0;
    int parse_status;
    enum secdat_session_access_mode access_mode;
    char passphrase[512];
    const char *session_master_key = env_master_key;
    time_t session_duration;
    char secret[512];

    if (cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for unlock\n"));
        secdat_cli_print_try_help(cli, "unlock");
        return 2;
    }
    parse_status = secdat_parse_unlock_options(cli, &options);
    if (parse_status != 0) {
        return parse_status;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &current_chain) != 0) {
        return 1;
    }
    if (secdat_domain_display_label(current_chain.count == 0 ? "" : current_chain.ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        secdat_domain_chain_free(&current_chain);
        return 1;
    }
    fprintf(stderr, _("resolved domain: %s\n"), current_domain_label);
    if (options.inherit_mode) {
        parse_status = secdat_clear_local_inherit_override(&current_chain, current_domain_label, SECDAT_INHERIT_EXPECT_UNLOCKED);
        secdat_domain_chain_free(&current_chain);
        return parse_status;
    }
    if (current_chain.count == 0) {
        current_domain_root[0] = '\0';
    } else if (secdat_domain_root_path(current_chain.ids[0], current_domain_root, sizeof(current_domain_root)) != 0) {
        secdat_domain_chain_free(&current_chain);
        return 1;
    }
    if (options.include_descendants) {
        if (secdat_collect_locked_descendant_roots(current_domain_root, &descendant_targets, &descendant_unlock_count) != 0) {
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        if (descendant_unlock_count > 0) {
            fprintf(stderr, _("this will unlock %zu descendant domains in the current subtree\n"), descendant_unlock_count);
            fprintf(stderr, _("local locks will remain after local unlock expiry or a later lock\n"));
            if (!options.assume_yes && secdat_confirm_descendant_unlock(descendant_unlock_count) != 0) {
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
        }
    }

    session_duration = (options.duration_configured || options.until_configured) ? options.duration_seconds : secdat_session_idle_seconds();
    access_mode = options.volatile_mode ? SECDAT_SESSION_ACCESS_VOLATILE : (options.readonly_mode ? SECDAT_SESSION_ACCESS_READONLY : SECDAT_SESSION_ACCESS_PERSISTENT);

    if (env_master_key == NULL || env_master_key[0] == '\0') {
        if (secdat_session_agent_status_details(&current_chain, &active_record, &matched_index, NULL) == 0
            && secdat_session_agent_get(&current_chain, &secret_record) == 0) {
            session_duration = (options.duration_configured || options.until_configured) ? options.duration_seconds : secdat_session_effective_duration(&active_record);
            if (!options.volatile_mode && !options.readonly_mode) {
                access_mode = active_record.volatile_mode ? SECDAT_SESSION_ACCESS_VOLATILE
                    : (active_record.readonly_mode ? SECDAT_SESSION_ACCESS_READONLY : SECDAT_SESSION_ACCESS_PERSISTENT);
            }
            if (secdat_session_agent_set(secdat_session_scope_id(&current_chain), secret_record.master_key, access_mode, session_duration) != 0) {
                secdat_session_record_reset(&secret_record);
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
            if (options.include_descendants && secdat_unlock_descendant_sessions(&descendant_targets, secret_record.master_key, access_mode, session_duration) != 0) {
                secdat_session_record_reset(&secret_record);
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
            secdat_session_record_reset(&secret_record);
            secdat_session_record_reset(&active_record);
            puts(access_mode == SECDAT_SESSION_ACCESS_VOLATILE ? _("volatile session refreshed") : (access_mode == SECDAT_SESSION_ACCESS_READONLY ? _("readonly session refreshed") : _("session refreshed")));
            if (options.include_descendants) {
                secdat_print_descendant_unlock_summary(descendant_unlock_count);
            } else {
                secdat_print_unlock_guidance(current_domain_root);
            }
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 0;
        }
        secdat_session_record_reset(&secret_record);
        secdat_session_record_reset(&active_record);
    }

    if (!wrapped_present && !options.volatile_mode && !options.readonly_mode) {
        if (secdat_read_new_master_key_passphrase(passphrase, sizeof(passphrase)) != 0) {
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        if (session_master_key == NULL || session_master_key[0] == '\0') {
            if (secdat_generate_master_key(secret, sizeof(secret)) != 0) {
                secdat_secure_clear(passphrase, strlen(passphrase));
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
            session_master_key = secret;
        }
        if (secdat_write_wrapped_master_key(passphrase, session_master_key) != 0) {
            secdat_secure_clear(passphrase, strlen(passphrase));
            if (session_master_key == secret) {
                secdat_secure_clear(secret, strlen(secret));
            }
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        initialized = 1;
        secdat_secure_clear(passphrase, strlen(passphrase));
    }

    if (session_master_key != NULL && session_master_key[0] != '\0') {
        if (secdat_session_agent_set(
                secdat_session_scope_id(&current_chain),
                session_master_key,
            access_mode,
            session_duration
            ) != 0) {
            if (session_master_key == secret) {
                secdat_secure_clear(secret, strlen(secret));
            }
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        if (options.include_descendants && secdat_unlock_descendant_sessions(
                &descendant_targets,
                session_master_key,
            access_mode,
            session_duration
            ) != 0) {
            if (session_master_key == secret) {
                secdat_secure_clear(secret, strlen(secret));
            }
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        if (session_master_key == secret) {
            secdat_secure_clear(secret, strlen(secret));
        }
        if (options.readonly_mode) {
            puts(env_master_key != NULL && env_master_key[0] != '\0'
                     ? _("readonly session unlocked from environment")
                     : _("readonly session unlocked"));
        } else if (options.volatile_mode && initialized) {
            puts(_("volatile session unlocked with an ephemeral master key"));
        } else if (options.volatile_mode) {
            puts(env_master_key != NULL && env_master_key[0] != '\0'
                     ? _("volatile session unlocked from environment")
                     : _("volatile session unlocked"));
        } else if (initialized) {
            puts(env_master_key != NULL && env_master_key[0] != '\0'
                     ? _("persistent master key initialized; session unlocked from environment")
                     : _("persistent master key initialized; session unlocked"));
        } else {
            puts(_("session unlocked from environment"));
        }
        if (options.include_descendants) {
            secdat_print_descendant_unlock_summary(descendant_unlock_count);
        } else {
            secdat_print_unlock_guidance(current_domain_root);
        }
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 0;
    }

    if (!wrapped_present) {
        if (options.volatile_mode) {
            if (secdat_generate_master_key(secret, sizeof(secret)) != 0) {
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
            if (secdat_session_agent_set(secdat_session_scope_id(&current_chain), secret, SECDAT_SESSION_ACCESS_VOLATILE, session_duration) != 0) {
                secdat_secure_clear(secret, strlen(secret));
                secdat_domain_root_list_free(&descendant_targets);
                secdat_domain_chain_free(&current_chain);
                return 1;
            }
            secdat_secure_clear(secret, strlen(secret));
            puts(_("volatile session unlocked with an ephemeral master key"));
            secdat_print_unlock_guidance(current_domain_root);
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 0;
        }
        if (options.readonly_mode) {
            fprintf(stderr, _("no persistent master key is initialized; readonly unlock requires an existing master key\n"));
            secdat_domain_root_list_free(&descendant_targets);
            secdat_domain_chain_free(&current_chain);
            return 1;
        }
        fprintf(stderr, _("no persistent master key is initialized; run secdat unlock once on a terminal to create one\n"));
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 1;
    }

    if (secdat_read_unlock_passphrase(passphrase, sizeof(passphrase)) != 0) {
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 1;
    }
    if (secdat_unwrap_master_key(passphrase, secret, sizeof(secret)) != 0) {
        secdat_secure_clear(passphrase, strlen(passphrase));
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 1;
    }
    secdat_secure_clear(passphrase, strlen(passphrase));
    if (secdat_session_agent_set(
            secdat_session_scope_id(&current_chain),
            secret,
            access_mode,
            session_duration
        ) != 0) {
        secdat_secure_clear(secret, strlen(secret));
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 1;
    }
    if (options.include_descendants && secdat_unlock_descendant_sessions(
            &descendant_targets,
            secret,
            access_mode,
            session_duration
        ) != 0) {
        secdat_secure_clear(secret, strlen(secret));
        secdat_domain_root_list_free(&descendant_targets);
        secdat_domain_chain_free(&current_chain);
        return 1;
    }

    secdat_secure_clear(secret, strlen(secret));
    puts(options.volatile_mode ? _("volatile session unlocked") : (options.readonly_mode ? _("readonly session unlocked") : _("session unlocked")));
    if (options.include_descendants) {
        secdat_print_descendant_unlock_summary(descendant_unlock_count);
    } else {
        secdat_print_unlock_guidance(current_domain_root);
    }
    secdat_domain_root_list_free(&descendant_targets);
    secdat_domain_chain_free(&current_chain);
    return 0;
}

static int secdat_command_lock(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    struct secdat_lock_options options;
    char current_domain_label[PATH_MAX];
    int parse_status;
    int should_persist_lock = 0;

    if (cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for lock\n"));
        secdat_cli_print_try_help(cli, "lock");
        return 2;
    }
    parse_status = secdat_parse_lock_options(cli, &options);
    if (parse_status != 0) {
        return parse_status;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (secdat_domain_display_label(chain.count == 0 ? "" : chain.ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (options.inherit_mode) {
        parse_status = secdat_remove_local_explicit_lock(&chain, current_domain_label, SECDAT_INHERIT_EXPECT_LOCKED);
        secdat_domain_chain_free(&chain);
        return parse_status;
    }
    if ((getenv("SECDAT_MASTER_KEY") == NULL || getenv("SECDAT_MASTER_KEY")[0] == '\0')
        && secdat_session_agent_status(&chain, &record) != 0) {
        secdat_domain_chain_free(&chain);
        puts(_("already locked"));
        return 0;
    }
    secdat_session_record_reset(&record);
    should_persist_lock = chain.count > 1;

    if (options.save_mode && secdat_save_local_volatile_session_overlay(&chain) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (secdat_session_agent_clear_current_scope(&chain) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (should_persist_lock && secdat_domain_set_explicit_lock(chain.ids[0]) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    secdat_domain_chain_free(&chain);

    puts(options.save_mode ? _("volatile session saved and locked") : _("session locked"));
    return 0;
}

static void secdat_format_remaining_duration(time_t expires_at, char *buffer, size_t size)
{
    time_t remaining = expires_at - time(NULL);
    long long hours;
    long long minutes;
    long long seconds;

    if (remaining < 0) {
        remaining = 0;
    }
    if (remaining >= 3600) {
        hours = (long long)(remaining / 3600);
        minutes = (long long)((remaining % 3600) / 60);
        snprintf(buffer, size, "%lldh%02lldm", hours, minutes);
        return;
    }

    minutes = (long long)(remaining / 60);
    seconds = (long long)(remaining % 60);
    snprintf(buffer, size, "%lldm%02llds", minutes, seconds);
}

static int secdat_command_inherit(const struct secdat_cli *cli)
{
    struct secdat_domain_chain chain = {0};
    char current_domain_label[PATH_MAX];
    int status;

    if (cli->argc != 0 || cli->store != NULL) {
        fprintf(stderr, _("invalid arguments for inherit\n"));
        secdat_cli_print_try_help(cli, "inherit");
        return 2;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (secdat_domain_display_label(chain.count == 0 ? "" : chain.ids[0], current_domain_label, sizeof(current_domain_label)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    status = secdat_clear_local_inherit_override(&chain, current_domain_label, SECDAT_INHERIT_EXPECT_ANY);
    secdat_domain_chain_free(&chain);
    return status;
}

static int secdat_command_passwd(const struct secdat_cli *cli)
{
    char current_passphrase[512];
    char new_passphrase[512];
    char master_key[512];

    if (cli->argc != 0 || cli->dir != NULL || cli->domain != NULL || cli->store != NULL) {
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
    if (secdat_derive_key(&chain, key, NULL) != 0) {
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
    size_t *plaintext_length,
    const struct secdat_key_access_options *access_options
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

    if (secdat_derive_key(chain, key, access_options) != 0) {
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
    struct secdat_key_list overlay_entries = {0};
    struct secdat_key_list overlay_tombstones = {0};
    size_t chain_index;
    size_t key_index;
    int status;

    for (chain_index = 0; chain_index < chain->count; chain_index += 1) {
        status = secdat_active_overlay_collect_keys(chain, chain->ids[chain_index], store_name, &overlay_entries, &overlay_tombstones);
        if (status != 0) {
            goto cleanup;
        }
        for (key_index = 0; key_index < overlay_tombstones.count; key_index += 1) {
            if (secdat_key_list_append(&hidden_keys, overlay_tombstones.items[key_index]) != 0) {
                status = 1;
                goto cleanup;
            }
        }
        secdat_key_list_free(&overlay_tombstones);

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

        for (key_index = 0; key_index < overlay_entries.count; key_index += 1) {
            if (secdat_key_list_contains(&hidden_keys, overlay_entries.items[key_index])) {
                continue;
            }
            if (secdat_key_list_contains(visible_keys, overlay_entries.items[key_index])) {
                continue;
            }
            if (include_patterns != NULL && include_patterns->count > 0 && !secdat_pattern_list_matches(include_patterns, overlay_entries.items[key_index])) {
                continue;
            }
            if (exclude_patterns != NULL && exclude_patterns->count > 0 && secdat_pattern_list_matches(exclude_patterns, overlay_entries.items[key_index])) {
                continue;
            }
            if (secdat_key_list_append(visible_keys, overlay_entries.items[key_index]) != 0) {
                status = 1;
                goto cleanup;
            }
        }
        secdat_key_list_free(&overlay_entries);

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
    secdat_key_list_free(&overlay_entries);
    secdat_key_list_free(&overlay_tombstones);
    return status;
}

static int secdat_resolve_effective_entry(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    int load_plaintext,
    struct secdat_effective_entry *entry
)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    struct secdat_overlay_lookup_result overlay = {0};
    size_t index;

    secdat_effective_entry_reset(entry);
    for (index = 0; index < chain->count; index += 1) {
        if (secdat_active_overlay_lookup(chain, chain->ids[index], store_name, key, &overlay) != 0) {
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            return 1;
        }
        if (overlay.found) {
            if (overlay.tombstone) {
                entry->tombstone = 1;
                return 1;
            }
            entry->found = 1;
            entry->from_overlay = 1;
            entry->unsafe_store = overlay.unsafe_store;
            entry->resolved_index = index;
            if (load_plaintext) {
                entry->plaintext = overlay.plaintext;
                entry->plaintext_length = overlay.plaintext_length;
                overlay.plaintext = NULL;
                overlay.plaintext_length = 0;
            } else {
                secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
                free(overlay.plaintext);
            }
            return 0;
        }

        if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(entry_path)) {
            entry->found = 1;
            entry->resolved_index = index;
            if (strlen(entry_path) >= sizeof(entry->path)) {
                fprintf(stderr, _("path is too long\n"));
                return 1;
            }
            strcpy(entry->path, entry_path);
            return 0;
        }

        if (secdat_build_tombstone_path(chain->ids[index], store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
            return 1;
        }
        if (secdat_file_exists(tombstone_path)) {
            entry->tombstone = 1;
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
    struct secdat_effective_entry entry = {0};
    int status;

    status = secdat_resolve_effective_entry(chain, store_name, key, 0, &entry);
    if (status == 0 && !entry.from_overlay) {
        if (strlen(entry.path) >= size) {
            secdat_effective_entry_reset(&entry);
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }
        strcpy(buffer, entry.path);
    } else if (status == 0 && size > 0) {
        buffer[0] = '\0';
    }
    secdat_effective_entry_reset(&entry);
    return status;
}

static int secdat_parent_has_visible_key(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    struct secdat_domain_chain parent_chain;
    struct secdat_effective_entry entry = {0};
    int status;

    if (chain->count <= 1) {
        return 0;
    }

    parent_chain.ids = chain->ids + 1;
    parent_chain.count = chain->count - 1;
    status = secdat_resolve_effective_entry(&parent_chain, store_name, key, 0, &entry);
    secdat_effective_entry_reset(&entry);
    return status == 0 ? 1 : 0;
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
    struct secdat_key_list overlay_entries = {0};
    struct secdat_key_list overlay_tombstones = {0};
    struct secdat_overlay_lookup_result overlay = {0};
    char entry_path[PATH_MAX];
    size_t index;
    int entry_is_unsafe;
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
    if (secdat_active_overlay_collect_keys(chain, chain->ids[0], store_name, &overlay_entries, &overlay_tombstones) != 0) {
        goto cleanup;
    }
    if (secdat_collect_directory_keys(entries_dir, ".sec", &local_entries) != 0) {
        goto cleanup;
    }
    if (secdat_collect_directory_keys(tombstones_dir, ".tomb", &local_tombstones) != 0) {
        goto cleanup;
    }

    for (index = 0; index < overlay_entries.count; index += 1) {
        if (secdat_key_list_append(&local_entries, overlay_entries.items[index]) != 0) {
            goto cleanup;
        }
    }
    for (index = 0; index < overlay_tombstones.count; index += 1) {
        if (secdat_key_list_append(&local_tombstones, overlay_tombstones.items[index]) != 0) {
            goto cleanup;
        }
    }

    for (index = 0; index < local_entries.count; index += 1) {
        if (options->safe || options->unsafe_store) {
            if (secdat_active_overlay_lookup(chain, chain->ids[0], store_name, local_entries.items[index], &overlay) != 0) {
                goto cleanup;
            }
            if (overlay.found && !overlay.tombstone) {
                entry_is_unsafe = overlay.unsafe_store;
                secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
                free(overlay.plaintext);
                overlay.plaintext = NULL;
                overlay.plaintext_length = 0;
            } else {
                if (secdat_build_entry_path(chain->ids[0], store_name, local_entries.items[index], entry_path, sizeof(entry_path)) != 0) {
                    goto cleanup;
                }
                if (secdat_entry_uses_plaintext_storage(entry_path, &entry_is_unsafe) != 0) {
                    goto cleanup;
                }
            }
            if (options->unsafe_store && entry_is_unsafe) {
                if (secdat_key_list_append(keys, local_entries.items[index]) != 0) {
                    goto cleanup;
                }
            }
            if (options->safe && !entry_is_unsafe) {
                if (secdat_key_list_append(keys, local_entries.items[index]) != 0) {
                    goto cleanup;
                }
            }
        }

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
    secdat_key_list_free(&overlay_entries);
    secdat_key_list_free(&overlay_tombstones);
    secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
    free(overlay.plaintext);
    return status;
}

static int secdat_load_resolved_plaintext(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    unsigned char **plaintext,
    size_t *plaintext_length,
    size_t *resolved_index,
    int *unsafe_store,
    const struct secdat_key_access_options *access_options
)
{
    struct secdat_effective_entry entry = {0};
    struct secdat_domain_chain resolved_chain = {0};
    const struct secdat_domain_chain *decrypt_chain = chain;
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    size_t chain_index;
    int status;

    status = secdat_resolve_effective_entry(chain, store_name, key, 1, &entry);
    if (status != 0) {
        fprintf(stderr, _("key not found: %s\n"), key);
        fprintf(stderr, _("Hint: check secdat status, --dir, and --store to confirm the lookup context\n"));
        return 1;
    }

    if (resolved_index != NULL) {
        *resolved_index = entry.resolved_index;
    }
    if (entry.from_overlay) {
        *plaintext = entry.plaintext;
        *plaintext_length = entry.plaintext_length;
        if (unsafe_store != NULL) {
            *unsafe_store = entry.unsafe_store;
        }
        entry.plaintext = NULL;
        entry.plaintext_length = 0;
        secdat_effective_entry_reset(&entry);
        return 0;
    }

    if (secdat_read_file(entry.path, &encrypted, &encrypted_length) != 0) {
        secdat_effective_entry_reset(&entry);
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

    if (entry.resolved_index > 0) {
        resolved_chain.ids = chain->ids + entry.resolved_index;
        resolved_chain.count = chain->count - entry.resolved_index;
        resolved_chain.current_path[0] = '\0';
        decrypt_chain = &resolved_chain;
        for (chain_index = 0; chain_index < entry.resolved_index; chain_index += 1) {
            if (secdat_domain_has_explicit_lock(chain->ids[chain_index])) {
                decrypt_chain = chain;
                break;
            }
        }
    }
    status = secdat_decrypt_value(decrypt_chain, encrypted, encrypted_length, plaintext, plaintext_length, access_options);
    free(encrypted);
    secdat_effective_entry_reset(&entry);
    return status;
}

static int secdat_entry_uses_plaintext_storage(const char *path, int *unsafe_store)
{
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status = 1;

    if (secdat_read_file(path, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    if (encrypted_length < SECDAT_HEADER_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        goto cleanup;
    }
    if (memcmp(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || encrypted[8] != SECDAT_ENTRY_VERSION) {
        fprintf(stderr, _("unsupported encrypted entry format\n"));
        goto cleanup;
    }
    if (encrypted[9] != SECDAT_ENTRY_ALGORITHM_PLAINTEXT && encrypted[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
        fprintf(stderr, _("unsupported encryption algorithm\n"));
        goto cleanup;
    }

    *unsafe_store = encrypted[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
    status = 0;

cleanup:
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
    int filter_by_storage;

    if (secdat_parse_ls_options(cli, &options) != 0) {
        return 2;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        secdat_key_list_free(&options.include_patterns);
        secdat_key_list_free(&options.exclude_patterns);
        return 1;
    }

    if (secdat_canonicalize_directory_path(secdat_cli_domain_base(cli), canonical_base_dir, sizeof(canonical_base_dir)) != 0) {
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

    filter_by_storage = options.safe || options.unsafe_store;

    for (index = 0; index < visible_keys.count; index += 1) {
        char output[PATH_MAX * 2];
        struct secdat_effective_entry entry = {0};
        char domain_path[PATH_MAX];
        int entry_is_unsafe;

        if (secdat_resolve_effective_entry(&chain, cli->store, visible_keys.items[index], 0, &entry) != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (filter_by_storage) {
            if (entry.from_overlay) {
                entry_is_unsafe = entry.unsafe_store;
            } else if (secdat_entry_uses_plaintext_storage(entry.path, &entry_is_unsafe) != 0) {
                secdat_effective_entry_reset(&entry);
                secdat_key_list_free(&options.include_patterns);
                secdat_key_list_free(&options.exclude_patterns);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
            if ((options.safe && entry_is_unsafe) || (options.unsafe_store && !entry_is_unsafe)) {
                secdat_effective_entry_reset(&entry);
                continue;
            }
        }

        if (!options.canonical_domain && !options.canonical_store) {
            puts(visible_keys.items[index]);
            secdat_effective_entry_reset(&entry);
            continue;
        }

        if (options.canonical_domain) {
            if (secdat_domain_root_path(chain.ids[entry.resolved_index], domain_path, sizeof(domain_path)) != 0) {
                secdat_effective_entry_reset(&entry);
                secdat_key_list_free(&options.include_patterns);
                secdat_key_list_free(&options.exclude_patterns);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
            if (domain_path[0] == '\0') {
                if (secdat_copy_string(domain_path, sizeof(domain_path), canonical_base_dir) != 0) {
                    secdat_effective_entry_reset(&entry);
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
            secdat_effective_entry_reset(&entry);
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        puts(output);
        secdat_effective_entry_reset(&entry);
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
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
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

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
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
    struct secdat_get_options options;
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int unsafe_store = 0;
    ssize_t written;
    size_t offset;
    int parse_status;

    parse_status = secdat_parse_get_options(cli, &options);
    if (parse_status != 0) {
        return parse_status;
    }

    if (secdat_parse_key_reference(options.keyref, secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }

    if (secdat_load_resolved_plaintext(
            &chain,
            reference.store_value,
            reference.key,
            &plaintext,
            &plaintext_length,
            NULL,
            &unsafe_store,
            &options.access
        ) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (isatty(STDOUT_FILENO) && !unsafe_store) {
        fprintf(stderr, _("refusing to write secret to a terminal\n"));
        secdat_domain_chain_free(&chain);
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return 1;
    }

    if (options.shellescaped) {
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

    if (secdat_require_writable_domain_id(domain_id) != 0) {
        return 1;
    }

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

static int secdat_store_plaintext_for_chain(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
)
{
    if (secdat_active_overlay_enabled(chain)) {
        return secdat_active_overlay_store_plaintext(chain, domain_id, store_name, key, plaintext, plaintext_length, unsafe_store);
    }
    return secdat_store_plaintext(domain_id, store_name, key, plaintext, plaintext_length, unsafe_store);
}

static int secdat_store_literal_keyref(
    const struct secdat_cli *cli,
    const char *keyref,
    const char *literal_value,
    int unsafe_store
)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char current_domain_id[PATH_MAX];
    const char *key;
    unsigned char *plaintext = NULL;
    size_t plaintext_length;
    int status;

    if (secdat_parse_key_reference(keyref, secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
        return 1;
    }

    plaintext_length = strlen(literal_value);
    plaintext = malloc(plaintext_length == 0 ? 1 : plaintext_length);
    if (plaintext == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    if (plaintext_length > 0) {
        memcpy(plaintext, literal_value, plaintext_length);
    }

    if (secdat_domain_resolve_current(reference.domain_value, current_domain_id, sizeof(current_domain_id)) != 0) {
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return 1;
    }

    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "set") != 0) {
        secdat_domain_chain_free(&chain);
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return 1;
    }

    key = reference.key;
    status = secdat_store_plaintext_for_chain(&chain, current_domain_id, reference.store_value, key, plaintext, plaintext_length, unsafe_store);
    secdat_domain_chain_free(&chain);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    return status;
}

static int secdat_is_assignment_operand(const char *value)
{
    return value != NULL && strchr(value, '=') != NULL;
}

static int secdat_store_assignment_operand(
    const struct secdat_cli *cli,
    const char *operand,
    int unsafe_store
)
{
    const char *separator = strchr(operand, '=');
    char *keyref;
    size_t keyref_length;
    int status;

    if (separator == NULL) {
        fprintf(stderr, _("invalid arguments for set\n"));
        secdat_cli_print_try_help(cli, "set");
        return 2;
    }

    keyref_length = (size_t)(separator - operand);
    keyref = malloc(keyref_length + 1);
    if (keyref == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(keyref, operand, keyref_length);
    keyref[keyref_length] = '\0';

    status = secdat_store_literal_keyref(cli, keyref, separator + 1, unsafe_store);
    free(keyref);
    return status;
}

static int secdat_command_set(const struct secdat_cli *cli)
{
    static const struct option long_options[] = {
        {"unsafe", no_argument, NULL, 'u'},
        {"stdin", no_argument, NULL, 'i'},
        {"value", required_argument, NULL, 'v'},
        {"env", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char current_domain_id[PATH_MAX];
    char *argv[cli->argc + 2];
    const char *key;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    const char *environment_name;
    const char *environment_value;
    const char *literal_value = NULL;
    const char *keyref = NULL;
    int read_stdin = 1;
    int unsafe_store = 0;
    int argc;
    int option;
    int status;

    secdat_prepare_option_argv(cli, "set", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":uiv:e:", long_options, NULL)) != -1) {
        switch (option) {
        case 'u':
            if (unsafe_store) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            unsafe_store = 1;
            break;
        case 'i':
            if (!read_stdin || literal_value != NULL) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            read_stdin = 1;
            break;
        case 'v':
            if (!read_stdin || literal_value != NULL) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            literal_value = optarg;
            read_stdin = 0;
            break;
        case 'e':
            if (!read_stdin || literal_value != NULL) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            environment_name = optarg;
            environment_value = getenv(environment_name);
            if (environment_value == NULL) {
                fprintf(stderr, _("environment variable is not set: %s\n"), environment_name);
                return 1;
            }
            literal_value = environment_value;
            read_stdin = 0;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for set\n"));
            secdat_cli_print_try_help(cli, "set");
            return 2;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, _("missing key for set\n"));
        return 2;
    }

    if (read_stdin && literal_value == NULL) {
        int saw_assignment = 0;
        int saw_non_assignment = 0;
        int assignment_index;

        for (assignment_index = optind; assignment_index < argc; assignment_index += 1) {
            if (secdat_is_assignment_operand(argv[assignment_index])) {
                saw_assignment = 1;
            } else {
                saw_non_assignment = 1;
            }
        }

        if (saw_assignment && saw_non_assignment) {
            fprintf(stderr, _("invalid arguments for set\n"));
            secdat_cli_print_try_help(cli, "set");
            return 2;
        }

        if (saw_assignment) {
            int assignment_index;

            for (assignment_index = optind; assignment_index < argc; assignment_index += 1) {
                status = secdat_store_assignment_operand(cli, argv[assignment_index], unsafe_store);
                if (status != 0) {
                    return status;
                }
            }
            return 0;
        }
    }

    keyref = argv[optind];
    optind += 1;
    if (optind < argc) {
        if (!read_stdin || literal_value != NULL || optind + 1 != argc) {
            fprintf(stderr, _("invalid arguments for set\n"));
            secdat_cli_print_try_help(cli, "set");
            return 2;
        }
        literal_value = argv[optind];
        read_stdin = 0;
        optind += 1;
    }
    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for set\n"));
        secdat_cli_print_try_help(cli, "set");
        return 2;
    }

    if (read_stdin) {
        if (secdat_parse_key_reference(keyref, secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
            return 1;
        }

        key = reference.key;

        if (isatty(STDIN_FILENO) && !unsafe_store) {
            fprintf(stderr, _("refusing to read secret from a terminal\n"));
            return 1;
        }

        if (secdat_read_stdin(&plaintext, &plaintext_length) != 0) {
            return 1;
        }
        if (secdat_domain_resolve_current(reference.domain_value, current_domain_id, sizeof(current_domain_id)) != 0) {
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            return 1;
        }

        if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            return 1;
        }
        if (secdat_require_mutable_session_chain(&chain, "set") != 0) {
            secdat_domain_chain_free(&chain);
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            return 1;
        }

        status = secdat_store_plaintext_for_chain(&chain, current_domain_id, reference.store_value, key, plaintext, plaintext_length, unsafe_store);
        secdat_domain_chain_free(&chain);
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return status;
    }

    return secdat_store_literal_keyref(cli, keyref, literal_value, unsafe_store);
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
    struct secdat_overlay_lookup_result overlay = {0};
    size_t index;
    int found_inherited = 0;
    int local_file_exists = 0;

    if (secdat_require_mutable_session_chain(chain, "rm") != 0) {
        return 1;
    }

    if (chain->count == 0) {
        current_domain_id[0] = '\0';
    } else if (strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    } else {
        strcpy(current_domain_id, chain->ids[0]);
    }

    if (secdat_active_overlay_enabled(chain)) {
        if (secdat_active_overlay_lookup(chain, current_domain_id, store_name, key, &overlay) != 0) {
            goto overlay_cleanup_error;
        }
        if (current_domain_id[0] != '\0' && secdat_build_entry_path(current_domain_id, store_name, key, entry_path, sizeof(entry_path)) == 0) {
            local_file_exists = secdat_file_exists(entry_path);
        }
        found_inherited = secdat_parent_has_visible_key(chain, store_name, key);
        if (found_inherited < 0) {
            goto overlay_cleanup_error;
        }
        if (overlay.found && overlay.tombstone) {
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            return (local_file_exists || found_inherited || ignore_missing) ? 0 : (fprintf(stderr, _("key not found: %s\n"), key), 1);
        }
        if (overlay.found && !overlay.tombstone) {
            if (secdat_active_overlay_drop(chain, current_domain_id, store_name, key) != 0) {
                goto overlay_cleanup_error;
            }
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            if (local_file_exists || found_inherited) {
                return secdat_active_overlay_set_tombstone(chain, current_domain_id, store_name, key);
            }
            return 0;
        }
        secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
        free(overlay.plaintext);
        if (local_file_exists || found_inherited) {
            return secdat_active_overlay_set_tombstone(chain, current_domain_id, store_name, key);
        }
        if (ignore_missing) {
            return 0;
        }
        fprintf(stderr, _("key not found: %s\n"), key);
        return 1;
    }

    if (secdat_require_writable_domain_chain(chain) != 0) {
        return 1;
    }

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

overlay_cleanup_error:
    secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
    free(overlay.plaintext);
    return 1;
}

static int secdat_mask_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    char current_domain_id[PATH_MAX];
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    struct secdat_overlay_lookup_result overlay = {0};
    size_t index;
    int found_inherited = 0;
    int local_file_exists = 0;

    if (secdat_require_mutable_session_chain(chain, "mask") != 0) {
        return 1;
    }

    if (chain->count == 0) {
        current_domain_id[0] = '\0';
    } else if (strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    } else {
        strcpy(current_domain_id, chain->ids[0]);
    }

    if (secdat_active_overlay_enabled(chain)) {
        if (secdat_active_overlay_lookup(chain, current_domain_id, store_name, key, &overlay) != 0) {
            goto overlay_cleanup_error;
        }
        if (overlay.found && overlay.tombstone) {
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            return 0;
        }
        if (current_domain_id[0] != '\0' && secdat_build_entry_path(current_domain_id, store_name, key, entry_path, sizeof(entry_path)) == 0) {
            local_file_exists = secdat_file_exists(entry_path);
        }
        if ((overlay.found && !overlay.tombstone) || local_file_exists) {
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            fprintf(stderr, _("key exists locally and cannot be masked: %s\n"), key);
            return 1;
        }
        found_inherited = secdat_parent_has_visible_key(chain, store_name, key);
        secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
        free(overlay.plaintext);
        if (found_inherited < 0) {
            return 1;
        }
        if (!found_inherited) {
            fprintf(stderr, _("key not found: %s\n"), key);
            return 1;
        }
        return secdat_active_overlay_set_tombstone(chain, current_domain_id, store_name, key);
    }

    if (secdat_require_writable_domain_chain(chain) != 0) {
        return 1;
    }

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

overlay_cleanup_error:
    secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
    free(overlay.plaintext);
    return 1;
}

static int secdat_unmask_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key)
{
    char current_domain_id[PATH_MAX];
    char tombstone_path[PATH_MAX];

    if (secdat_require_mutable_session_chain(chain, "unmask") != 0) {
        return 1;
    }

    if (chain->count == 0) {
        current_domain_id[0] = '\0';
    } else if (strlen(chain->ids[0]) >= sizeof(current_domain_id)) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    } else {
        strcpy(current_domain_id, chain->ids[0]);
    }

    if (secdat_active_overlay_enabled(chain)) {
        struct secdat_overlay_lookup_result overlay = {0};

        if (secdat_active_overlay_lookup(chain, current_domain_id, store_name, key, &overlay) != 0) {
            return 1;
        }
        if (overlay.found && overlay.tombstone) {
            secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
            free(overlay.plaintext);
            return secdat_active_overlay_drop(chain, current_domain_id, store_name, key);
        }
        secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
        free(overlay.plaintext);
        if (current_domain_id[0] != '\0' && secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) == 0 && secdat_file_exists(tombstone_path)) {
            fprintf(stderr, _("cannot unmask a persisted tombstone while volatile session overlay is active: %s\n"), key);
            return 1;
        }
        fprintf(stderr, _("key is not masked in current domain: %s\n"), key);
        return 1;
    }

    if (secdat_require_writable_domain_chain(chain) != 0) {
        return 1;
    }

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

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &source_reference) != 0) {
        return 1;
    }
    if (secdat_parse_key_reference(cli->argv[1], secdat_cli_domain_base(cli), cli->store, &destination_reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(source_reference.domain_value, &source_chain) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(destination_reference.domain_value, &destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        return 1;
    }
    if (secdat_require_mutable_session_chain(&destination_chain, "cp") != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }
    if (!secdat_active_overlay_enabled(&destination_chain) && secdat_require_writable_domain_chain(&destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }
    if (secdat_domain_resolve_current(destination_reference.domain_value, destination_domain_id, sizeof(destination_domain_id)) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    if (secdat_resolve_entry_path(&destination_chain, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("destination key already exists: %s\n"), destination_reference.key);
        return 1;
    }

    if (secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store, NULL) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext_for_chain(&destination_chain, destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store);
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

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &source_reference) != 0) {
        return 1;
    }
    if (secdat_parse_key_reference(cli->argv[1], secdat_cli_domain_base(cli), cli->store, &destination_reference) != 0) {
        return 1;
    }

    if (secdat_domain_resolve_chain(source_reference.domain_value, &source_chain) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(destination_reference.domain_value, &destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        return 1;
    }
    if (secdat_require_mutable_session_chain(&source_chain, "mv") != 0
        || secdat_require_mutable_session_chain(&destination_chain, "mv") != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }
    if (!secdat_active_overlay_enabled(&destination_chain) && secdat_require_writable_domain_chain(&destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }
    if (secdat_domain_resolve_current(destination_reference.domain_value, destination_domain_id, sizeof(destination_domain_id)) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    if (secdat_resolve_entry_path(&destination_chain, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        fprintf(stderr, _("destination key already exists: %s\n"), destination_reference.key);
        return 1;
    }

    if (secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store, NULL) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext_for_chain(&destination_chain, destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store);
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

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
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

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
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
    static const struct option long_options[] = {
        {"ignore-missing", no_argument, NULL, 'f'},
        {NULL, 0, NULL, 0},
    };
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char *argv[cli->argc + 2];
    int argc;
    int option;
    const char *keyref = NULL;
    int ignore_missing = 0;
    int status;

    secdat_prepare_option_argv(cli, "rm", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":f", long_options, NULL)) != -1) {
        switch (option) {
        case 'f':
            ignore_missing = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for rm\n"));
            secdat_cli_print_try_help(cli, "rm");
            return 2;
        }
    }

    if (optind + 1 != argc) {
        fprintf(stderr, _("invalid arguments for rm\n"));
        secdat_cli_print_try_help(cli, "rm");
        return 2;
    }

    keyref = argv[optind];

    if (secdat_parse_key_reference(keyref, secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
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

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (secdat_parse_simple_ls_pattern(cli, "store ls", &pattern) != 0) {
        return 2;
    }

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
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
    struct secdat_domain_chain chain = {0};
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct stat status;

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
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

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "store create") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_require_writable_domain_id(current_domain_id) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_store_root(current_domain_id, cli->argv[0], store_root, sizeof(store_root)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (stat(store_root, &status) == 0) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("store already exists: %s\n"), cli->argv[0]);
        return 1;
    }
    if (secdat_join_path(entries_dir, sizeof(entries_dir), store_root, "entries") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_join_path(tombstones_dir, sizeof(tombstones_dir), store_root, "tombstones") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_ensure_directory(entries_dir, 0700) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    secdat_domain_chain_free(&chain);
    return secdat_ensure_directory(tombstones_dir, 0700);
}

static int secdat_store_command_delete(const struct secdat_cli *cli)
{
    char current_domain_id[PATH_MAX];
    struct secdat_domain_chain chain = {0};
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
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

    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "store delete") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_require_writable_domain_id(current_domain_id) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_store_root(current_domain_id, cli->argv[0], store_root, sizeof(store_root)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_join_path(entries_dir, sizeof(entries_dir), store_root, "entries") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_join_path(tombstones_dir, sizeof(tombstones_dir), store_root, "tombstones") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (!secdat_directory_is_empty(entries_dir) || !secdat_directory_is_empty(tombstones_dir)) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
        return 1;
    }
    if (rmdir(entries_dir) != 0 || rmdir(tombstones_dir) != 0 || rmdir(store_root) != 0) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("failed to remove directory: %s\n"), store_root);
        return 1;
    }

    secdat_domain_chain_free(&chain);
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

static int secdat_is_valid_env_name(const char *value)
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

static int secdat_exec_env_name_from_key(
    const struct secdat_exec_options *options,
    const char *key,
    char **env_name_out,
    int *include_key
)
{
    regmatch_t matches[10];
    char *env_name;
    size_t total_length = 0;
    size_t replacement_index;
    int reg_status;

    *env_name_out = NULL;
    *include_key = 0;

    if (!options->env_map_configured) {
        env_name = strdup(key);
        if (env_name == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        *env_name_out = env_name;
        *include_key = 1;
        return 0;
    }

    if (options->env_map_has_address) {
        reg_status = regexec(&options->env_map_address_regex, key, 0, NULL, 0);
        if (reg_status == REG_NOMATCH) {
            return 0;
        }
        if (reg_status != 0) {
            fprintf(stderr, _("failed to match --env-map-sed against key: %s\n"), key);
            return 1;
        }
    }

    reg_status = regexec(&options->env_map_regex, key, (int)(sizeof(matches) / sizeof(matches[0])), matches, 0);
    if (reg_status == REG_NOMATCH) {
        return 0;
    }
    if (reg_status != 0) {
        fprintf(stderr, _("failed to match --env-map-sed against key: %s\n"), key);
        return 1;
    }

    for (replacement_index = 0; options->env_map_replacement[replacement_index] != '\0'; replacement_index += 1) {
        char current = options->env_map_replacement[replacement_index];

        if (current == '&') {
            total_length += (size_t)(matches[0].rm_eo - matches[0].rm_so);
            continue;
        }
        if (current == '\\' && isdigit((unsigned char)options->env_map_replacement[replacement_index + 1])) {
            int capture_index = options->env_map_replacement[replacement_index + 1] - '0';

            if (capture_index < (int)(sizeof(matches) / sizeof(matches[0])) && matches[capture_index].rm_so >= 0) {
                total_length += (size_t)(matches[capture_index].rm_eo - matches[capture_index].rm_so);
            }
            replacement_index += 1;
            continue;
        }
        if (current == '\\' && options->env_map_replacement[replacement_index + 1] != '\0') {
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
    for (replacement_index = 0; options->env_map_replacement[replacement_index] != '\0'; replacement_index += 1) {
        char current = options->env_map_replacement[replacement_index];

        if (current == '&') {
            size_t capture_length = (size_t)(matches[0].rm_eo - matches[0].rm_so);

            memcpy(env_name + total_length, key + matches[0].rm_so, capture_length);
            total_length += capture_length;
            continue;
        }
        if (current == '\\' && isdigit((unsigned char)options->env_map_replacement[replacement_index + 1])) {
            int capture_index = options->env_map_replacement[replacement_index + 1] - '0';

            if (capture_index < (int)(sizeof(matches) / sizeof(matches[0])) && matches[capture_index].rm_so >= 0) {
                size_t capture_length = (size_t)(matches[capture_index].rm_eo - matches[capture_index].rm_so);

                memcpy(env_name + total_length, key + matches[capture_index].rm_so, capture_length);
                total_length += capture_length;
            }
            replacement_index += 1;
            continue;
        }
        if (current == '\\' && options->env_map_replacement[replacement_index + 1] != '\0') {
            replacement_index += 1;
            current = options->env_map_replacement[replacement_index];
        }
        env_name[total_length] = current;
        total_length += 1;
    }
    env_name[total_length] = '\0';

    if (!secdat_is_valid_env_name(env_name)) {
        fprintf(stderr, _("invalid environment variable name from --env-map-sed: %s\n"), env_name);
        free(env_name);
        return 1;
    }

    *env_name_out = env_name;
    *include_key = 1;
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

    if (secdat_parse_simple_ls_pattern(cli, "export", &pattern) != 0) {
        secdat_cli_print_try_help(cli, "export");
        return 2;
    }

    if (secdat_canonicalize_directory_path(secdat_cli_domain_base(cli), canonical_dir, sizeof(canonical_dir)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
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
        if (!secdat_is_valid_env_name(visible_keys.items[key_index])) {
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
        fputs(cli->domain != NULL ? " --domain " : " --dir ", stdout);
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
    char **env_names = NULL;
    char **command_argv;
    size_t key_index;
    int status;

    status = secdat_parse_exec_options(cli, &options);
    if (status != 0) {
        secdat_cli_print_try_help(cli, "exec");
        return status;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        secdat_exec_options_reset(&options);
        return 1;
    }
    if (secdat_collect_visible_keys(&chain, cli->store, &options.include_patterns, &options.exclude_patterns, &visible_keys) != 0) {
        secdat_exec_options_reset(&options);
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    env_names = calloc(visible_keys.count, sizeof(*env_names));
    if (env_names == NULL && visible_keys.count > 0) {
        fprintf(stderr, _("out of memory\n"));
        secdat_exec_options_reset(&options);
        secdat_domain_chain_free(&chain);
        secdat_key_list_free(&visible_keys);
        return 1;
    }

    for (key_index = 0; key_index < visible_keys.count; key_index += 1) {
        int include_key = 0;
        size_t compare_index;

        status = secdat_exec_env_name_from_key(&options, visible_keys.items[key_index], &env_names[key_index], &include_key);
        if (status != 0) {
            size_t free_index;

            for (free_index = 0; free_index < visible_keys.count; free_index += 1) {
                free(env_names[free_index]);
            }
            free(env_names);
            secdat_exec_options_reset(&options);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }
        if (!include_key) {
            continue;
        }
        for (compare_index = 0; compare_index < key_index; compare_index += 1) {
            if (env_names[compare_index] != NULL && strcmp(env_names[compare_index], env_names[key_index]) == 0) {
                size_t free_index;

                fprintf(stderr, _("duplicate environment variable name from --env-map-sed: %s\n"), env_names[key_index]);
                for (free_index = 0; free_index < visible_keys.count; free_index += 1) {
                    free(env_names[free_index]);
                }
                free(env_names);
                secdat_exec_options_reset(&options);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
        }
    }

    for (key_index = 0; key_index < visible_keys.count; key_index += 1) {
        unsigned char *plaintext = NULL;
        size_t plaintext_length = 0;
        char *env_value = NULL;

        if (env_names[key_index] == NULL) {
            continue;
        }

        status = secdat_load_resolved_plaintext(
            &chain,
            cli->store,
            visible_keys.items[key_index],
            &plaintext,
            &plaintext_length,
            NULL,
            NULL,
            NULL
        );
        if (status != 0) {
            size_t free_index;

            for (free_index = 0; free_index < visible_keys.count; free_index += 1) {
                free(env_names[free_index]);
            }
            free(env_names);
            secdat_exec_options_reset(&options);
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
            size_t free_index;

            for (free_index = 0; free_index < visible_keys.count; free_index += 1) {
                free(env_names[free_index]);
            }
            free(env_names);
            secdat_exec_options_reset(&options);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (setenv(env_names[key_index], env_value, 1) != 0) {
            size_t free_index;

            fprintf(stderr, _("failed to export key to environment: %s\n"), env_names[key_index]);
            secdat_secure_clear(env_value, strlen(env_value));
            free(env_value);
            for (free_index = 0; free_index < visible_keys.count; free_index += 1) {
                free(env_names[free_index]);
            }
            free(env_names);
            secdat_exec_options_reset(&options);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        secdat_secure_clear(env_value, strlen(env_value));
        free(env_value);
    }

    command_argv = &cli->argv[options.command_index];
    for (key_index = 0; key_index < visible_keys.count; key_index += 1) {
        free(env_names[key_index]);
    }
    free(env_names);
    secdat_exec_options_reset(&options);
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
    struct secdat_domain_chain chain = {0};
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
    if (secdat_domain_resolve_current(secdat_cli_domain_base(cli), current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "load") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_read_secret_from_tty(_("Enter secdat bundle passphrase: "), passphrase, sizeof(passphrase)) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_decrypt_secret_bundle(cli->argv[0], passphrase, &payload, &payload_length) != 0) {
        secdat_secure_clear(passphrase, strlen(passphrase));
        secdat_domain_chain_free(&chain);
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

        if (secdat_store_plaintext_for_chain(&chain, current_domain_id, cli->store, key, payload + offset, value_length, 0) != 0) {
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
    secdat_domain_chain_free(&chain);
    if (payload != NULL) {
        secdat_secure_clear(payload, payload_length);
        free(payload);
    }
    return status;
}

int secdat_run_command(const struct secdat_cli *cli)
{
    char exact_domain_root[PATH_MAX];
    int status;

    if (cli->dir != NULL && cli->domain != NULL) {
        fprintf(stderr, _("cannot combine --dir and --domain\n"));
        return 2;
    }
    if (cli->domain != NULL && secdat_domain_validate_root(cli->domain, exact_domain_root, sizeof(exact_domain_root)) != 0) {
        return 1;
    }

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
    case SECDAT_COMMAND_INHERIT:
        return secdat_command_inherit(cli);
    case SECDAT_COMMAND_PASSWD:
        return secdat_command_passwd(cli);
    case SECDAT_COMMAND_LOCK:
        return secdat_command_lock(cli);
    case SECDAT_COMMAND_STATUS:
        return secdat_command_status(cli);
    case SECDAT_COMMAND_WAIT_UNLOCK:
        return secdat_command_wait_unlock(cli);
    case SECDAT_COMMAND_STORE_CREATE:
        return secdat_store_command_create(cli);
    case SECDAT_COMMAND_STORE_DELETE:
        return secdat_store_command_delete(cli);
    case SECDAT_COMMAND_STORE_LS:
        return secdat_store_command_ls(cli);
    case SECDAT_COMMAND_DOMAIN_CREATE:
    case SECDAT_COMMAND_DOMAIN_DELETE:
    case SECDAT_COMMAND_DOMAIN_LS:
    case SECDAT_COMMAND_DOMAIN_STATUS:
        return secdat_handle_domain_command(cli);
    default:
        fprintf(stderr, _("command not implemented yet: %s\n"), secdat_cli_command_name(cli->command));
        if (cli->dir != NULL) {
            fprintf(stderr, _("  dir=%s\n"), cli->dir);
        }
        if (cli->domain != NULL) {
            fprintf(stderr, _("  domain=%s\n"), cli->domain);
        }
        if (cli->store != NULL) {
            fprintf(stderr, _("  store=%s\n"), cli->store);
        }
        status = 1;
        return status;
    }
}