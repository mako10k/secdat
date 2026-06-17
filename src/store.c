#include "store.h"

#include "secdat-sdk.h"

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
#define SECDAT_V2_VALUE_VERSION 1
#define SECDAT_V2_OBJECT_PAYLOAD_VERSION 1
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
#define SECDAT_WRAP_PBKDF2_MIN_ITERATIONS SECDAT_WRAP_PBKDF2_ITERATIONS
#define SECDAT_WRAP_PBKDF2_MAX_ITERATIONS 10000000
#define SECDAT_AGENT_CONNECT_RETRIES 50
#define SECDAT_SESSION_IDLE_ENV "SECDAT_SESSION_IDLE_SECONDS"
#define SECDAT_WRAP_PBKDF2_ITERATIONS_ENV "SECDAT_MASTER_KEY_PBKDF2_ITERATIONS"
#define SECDAT_GET_ON_DEMAND_UNLOCK_ENV "SECDAT_GET_ON_DEMAND_UNLOCK"
#define SECDAT_GET_UNLOCK_TIMEOUT_ENV "SECDAT_GET_UNLOCK_TIMEOUT_SECONDS"
#define SECDAT_SUPPRESS_MIGRATION_HINTS_ENV "SECDAT_SUPPRESS_MIGRATION_HINTS"
#define SECDAT_ASKPASS_ENV "SECDAT_ASKPASS"
#define SECDAT_ON_DEMAND_UNLOCK_WAIT_USEC 100000
#define SECDAT_V2_TEXT_FILE_MAX 16384
#define SECDAT_V2_OBJECT_KEY_LEN 32

static const unsigned char secdat_entry_magic[8] = {'S', 'E', 'C', 'D', 'A', 'T', '1', '\0'};
static const unsigned char secdat_v2_value_magic[8] = {'S', 'E', 'C', 'D', 'V', 'A', 'L', '2'};
static const unsigned char secdat_v2_object_payload_magic[8] = {'S', 'E', 'C', 'D', 'O', 'B', 'J', '2'};
static const unsigned char secdat_wrapped_key_magic[8] = {'S', 'E', 'C', 'D', 'W', 'R', 'P', '\0'};
static const unsigned char secdat_bundle_magic[8] = {'S', 'E', 'C', 'D', 'B', 'N', 'D', 'L'};
static const char secdat_attrs_magic[] = "SECDATATTR1";
static const char secdat_store_format_magic[] = "SECDATSTORE1";
static const char secdat_v2_domain_entry_magic[] = "SECDATDENT1";
static const char secdat_v2_secret_object_magic[] = "SECDATSECOBJ1";

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
    int metadata;
    int sandbox_injectable;
};

struct secdat_exec_options {
    struct secdat_key_list include_patterns;
    struct secdat_key_list exclude_patterns;
    regex_t env_map_address_regex;
    regex_t env_map_regex;
    char *env_map_replacement;
    int env_map_configured;
    int env_map_has_address;
    int sandbox_injectable;
    size_t command_index;
};

struct secdat_export_options {
    const char *pattern;
    int sandbox_injectable;
};

struct secdat_list_options {
    int masked;
    int overridden;
    int orphaned;
    int safe;
    int unsafe_store;
    int sandbox_injectable;
};

enum secdat_key_visibility {
    SECDAT_KEY_VISIBILITY_ALWAYS = 0,
    SECDAT_KEY_VISIBILITY_UNLOCKED,
};

enum secdat_value_access {
    SECDAT_VALUE_ACCESS_UNLOCKED = 0,
    SECDAT_VALUE_ACCESS_ALWAYS,
};

enum secdat_sandbox_inject {
    SECDAT_SANDBOX_INJECT_NEVER = 0,
    SECDAT_SANDBOX_INJECT_EXPLICIT,
    SECDAT_SANDBOX_INJECT_BULK,
};

enum secdat_secret_inject {
    SECDAT_SECRET_INJECT_NEVER = 0,
    SECDAT_SECRET_INJECT_ALLOW,
};

struct secdat_secret_attrs {
    enum secdat_key_visibility key_visibility;
    enum secdat_value_access value_access;
    enum secdat_sandbox_inject sandbox_inject;
};

struct secdat_attr_options {
    const char *keyref;
    struct secdat_secret_attrs attrs;
    int set_key_visibility;
    int set_value_access;
    int set_sandbox_inject;
};

struct secdat_fsck_options {
    const char *format;
    int orphaned;
    int dangling;
    int refcount;
    int repair;
};

struct secdat_fsck_report {
    size_t entries;
    size_t metadata;
    size_t tombstones;
    size_t secret_objects;
    size_t issues;
    size_t repairs;
};

struct secdat_gc_options {
    const char *format;
    int orphaned;
    int dangling;
    int dry_run;
};

struct secdat_gc_report {
    size_t removals;
};

enum secdat_store_format {
    SECDAT_STORE_FORMAT_INVALID = 0,
    SECDAT_STORE_FORMAT_V1,
    SECDAT_STORE_FORMAT_V2,
};

enum secdat_v2_lookup_status {
    SECDAT_V2_LOOKUP_FOUND = 0,
    SECDAT_V2_LOOKUP_ABSENT = 1,
    SECDAT_V2_LOOKUP_ERROR = 2,
    SECDAT_V2_LOOKUP_INACCESSIBLE = 3,
};

struct secdat_store_migrate_options {
    const char *store_name;
    const char *to_format;
    int dry_run;
};

struct secdat_store_finalize_migration_options {
    const char *store_name;
    const char *from_format;
    int dry_run;
};

struct secdat_store_migrate_report {
    size_t domain_entries;
    size_t secret_objects;
    size_t metadata_sidecars;
    size_t tombstones;
    size_t public_values;
    size_t encrypted_values;
    size_t injectable_entries;
    size_t issues;
};

struct secdat_store_finalize_migration_report {
    size_t legacy_entries;
    size_t metadata_sidecars;
    size_t removable_legacy_entries;
    size_t removable_metadata_sidecars;
    size_t removed_legacy_entries;
    size_t removed_metadata_sidecars;
    size_t blocking_legacy_entries;
    size_t blocking_metadata_sidecars;
    size_t issues;
};

struct secdat_store_migrate_v1_plan {
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    struct secdat_key_list entries;
    struct secdat_key_list metadata;
    struct secdat_key_list tombstones;
};

struct secdat_v2_domain_entry_info {
    char entry_id[64];
    char secret_id[64];
    char object_domain[PATH_MAX];
    char object_store[PATH_MAX];
    char key[PATH_MAX];
    char encrypted_key[SECDAT_V2_TEXT_FILE_MAX];
    char wrapped_object_key[SECDAT_V2_TEXT_FILE_MAX];
    enum secdat_key_visibility key_visibility;
    enum secdat_sandbox_inject entry_inject;
    int has_key;
    int has_encrypted_key;
    int has_object_domain;
    int has_object_store;
    int has_wrapped_object_key;
};

struct secdat_v2_secret_object_info {
    char secret_id[64];
    enum secdat_value_access value_access;
    enum secdat_secret_inject secret_inject;
    int refcount_present;
    int has_value_payload;
    size_t refcount;
    size_t value_payload_length;
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
    int from_v2;
    int unsafe_store;
    size_t resolved_index;
    char path[PATH_MAX];
    char entry_id[64];
    char secret_id[64];
    char object_domain[PATH_MAX];
    char object_store[PATH_MAX];
    char wrapped_object_key[SECDAT_V2_TEXT_FILE_MAX];
    enum secdat_key_visibility key_visibility;
    enum secdat_sandbox_inject entry_inject;
    int has_wrapped_object_key;
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
static int secdat_resolve_entry_path(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    char *buffer,
    size_t size
);
static int secdat_store_plaintext(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
);
static int secdat_store_plaintext_with_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
);
static int secdat_store_plaintext_for_chain(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store
);
static int secdat_store_plaintext_attrs_for_chain(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
);
static int secdat_write_empty_file(const char *path);
static int secdat_entry_uses_plaintext_storage(const char *path, int *unsafe_store);
static int secdat_file_exists(const char *path);
static int secdat_read_store_format(const char *domain_id, const char *store_name, enum secdat_store_format *format);
static int secdat_collect_v2_visible_keys(const char *domain_id, const char *store_name, struct secdat_key_list *keys);
static int secdat_lookup_v2_domain_entry(
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_v2_domain_entry_info *info,
    char *entry_path,
    size_t entry_path_size
);
static int secdat_lookup_v2_domain_entry_authoritative(
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_v2_domain_entry_info *info,
    char *entry_path,
    size_t entry_path_size
);
static int secdat_build_v2_secret_value_path(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    char *buffer,
    size_t size
);
static int secdat_build_v2_secret_object_path(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    char *buffer,
    size_t size
);
static int secdat_read_v2_secret_object_payload(
    const char *path,
    const char *file_secret_id,
    unsigned char **payload,
    size_t *payload_length,
    int *has_payload
);
static const char *secdat_v2_entry_object_domain(
    const char *entry_domain_id,
    const struct secdat_v2_domain_entry_info *info
);
static const char *secdat_v2_entry_object_store(
    const char *entry_store_name,
    const struct secdat_v2_domain_entry_info *info
);
static const char *secdat_effective_entry_object_store(const struct secdat_effective_entry *entry);
static int secdat_load_v2_secret_attrs(
    const char *domain_id,
    const char *store_name,
    const struct secdat_effective_entry *entry,
    struct secdat_secret_attrs *attrs,
    int *unsafe_store
);
static int secdat_read_file(const char *path, unsigned char **data, size_t *length);
static void secdat_secret_attrs_default(int unsafe_store, struct secdat_secret_attrs *attrs);
static int secdat_secret_attrs_supported(const struct secdat_secret_attrs *attrs);
static int secdat_secret_attrs_are_default(const struct secdat_secret_attrs *attrs, int unsafe_store);
static const char *secdat_key_visibility_name(enum secdat_key_visibility value);
static const char *secdat_value_access_name(enum secdat_value_access value);
static const char *secdat_sandbox_inject_name(enum secdat_sandbox_inject value);
static int secdat_sandbox_inject_allows_bulk_selection(const struct secdat_secret_attrs *attrs);
static int secdat_parse_key_visibility(const char *value, enum secdat_key_visibility *parsed);
static int secdat_parse_value_access(const char *value, enum secdat_value_access *parsed);
static int secdat_parse_sandbox_inject_token(const char *value, enum secdat_sandbox_inject *parsed, int accept_allow_alias);
static int secdat_parse_sandbox_inject(const char *value, enum secdat_sandbox_inject *parsed);
static int secdat_parse_sandbox_inject_metadata(const char *value, enum secdat_sandbox_inject *parsed);
static int secdat_load_resolved_secret_attrs(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    struct secdat_secret_attrs *attrs,
    int *unsafe_store
);
static int secdat_collect_store_names(const char *domain_id, const char *pattern, struct secdat_key_list *stores);
static int secdat_count_v2_secret_references_to_object(
    const char *object_domain_id,
    const char *object_store_name,
    const char *secret_id,
    size_t *count
);
static int secdat_update_v2_secret_refcount(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    size_t refcount
);
static int secdat_atomic_write_file(const char *path, const unsigned char *data, size_t length);
static int secdat_remove_if_exists(const char *path);
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
static int secdat_command_unlock(const struct secdat_cli *cli);
static int secdat_command_lock(const struct secdat_cli *cli);
static int secdat_command_cp(const struct secdat_cli *cli);
static int secdat_command_mv(const struct secdat_cli *cli);
static int secdat_command_ln(const struct secdat_cli *cli);
static int secdat_command_mask(const struct secdat_cli *cli);
static int secdat_command_unmask(const struct secdat_cli *cli);
static int secdat_command_rm(const struct secdat_cli *cli);
static int secdat_command_secret_status(const struct secdat_cli *cli);

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

static int secdat_key_list_append_duplicate(struct secdat_key_list *list, const char *value)
{
    char **new_items;
    size_t new_capacity;

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

static const char *secdat_sdk_domain_base(const struct secdat_sdk_options *options)
{
    if (options == NULL) {
        return NULL;
    }
    return options->domain != NULL ? options->domain : options->dir;
}

static void secdat_sdk_init_cli(
    const struct secdat_sdk_options *options,
    struct secdat_cli *cli,
    enum secdat_command_type command,
    int argc,
    char **argv
)
{
    memset(cli, 0, sizeof(*cli));
    cli->program_name = "libsecdat";
    cli->dir = options != NULL ? options->dir : NULL;
    cli->domain = options != NULL ? options->domain : NULL;
    cli->store = options != NULL ? options->store : NULL;
    cli->command = command;
    cli->argc = argc;
    cli->argv = argv;
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

const char *secdat_key_source_json_name(enum secdat_key_source_type source)
{
    switch (source) {
    case SECDAT_KEY_SOURCE_ENVIRONMENT:
        return "environment";
    case SECDAT_KEY_SOURCE_SESSION:
        return "session";
    default:
        return "locked";
    }
}

const char *secdat_effective_source_json_name(enum secdat_effective_source_type source)
{
    switch (source) {
    case SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT:
        return "environment";
    case SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION:
        return "local_unlock";
    case SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION:
        return "inherited_unlock";
    case SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK:
        return "local_lock";
    case SECDAT_EFFECTIVE_SOURCE_BLOCKED:
        return "inherited_lock";
    default:
        return "locked";
    }
}

const char *secdat_effective_state_json_name(enum secdat_effective_source_type source)
{
    return source == SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT
            || source == SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION
            || source == SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION
        ? "unlocked"
        : "locked";
}

long long secdat_remaining_seconds(time_t expires_at)
{
    time_t now = time(NULL);

    if (expires_at <= now) {
        return 0;
    }
    return (long long)(expires_at - now);
}

static size_t secdat_valid_utf8_sequence_length(const unsigned char *cursor)
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

void secdat_write_json_string(FILE *stream, const char *value)
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
                size_t sequence_length = secdat_valid_utf8_sequence_length(cursor);
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

static int secdat_migration_hints_suppressed(void)
{
    const char *value = getenv(SECDAT_SUPPRESS_MIGRATION_HINTS_ENV);
    int suppressed = 0;

    return value != NULL && secdat_parse_boolean_text(value, &suppressed) == 0 && suppressed;
}

static void secdat_print_store_migration_hint(const char *program_name, const char *store_name)
{
    if (secdat_migration_hints_suppressed()) {
        return;
    }
    if (program_name == NULL || program_name[0] == '\0') {
        program_name = "secdat";
    }
    if (store_name == NULL || store_name[0] == '\0') {
        store_name = "default";
    }
    fprintf(stderr, _("Hint: inspect migration first with `%s store migrate %s --to-format v2 --dry-run`\n"), program_name, store_name);
    fprintf(stderr, _("Hint: suppress migration hints with %s=1\n"), SECDAT_SUPPRESS_MIGRATION_HINTS_ENV);
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
        {"secret-value", no_argument, NULL, 'e'},
        {"public-value", no_argument, NULL, 'u'},
        {"sandbox-injectable", no_argument, NULL, 1000},
        {"metadata", no_argument, NULL, 1001},
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
        case 1000:
            options->sandbox_injectable = 1;
            break;
        case 1001:
            options->metadata = 1;
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
        {"sandbox-injectable", no_argument, NULL, 1001},
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
        case 1001:
            options->sandbox_injectable = 1;
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

static int secdat_parse_export_options(const struct secdat_cli *cli, struct secdat_export_options *options)
{
    static const struct option long_options[] = {
        {"pattern", required_argument, NULL, 'p'},
        {"sandbox-injectable", no_argument, NULL, 1000},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));
    secdat_prepare_option_argv(cli, "export", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":p:", long_options, NULL)) != -1) {
        switch (option) {
        case 'p':
            if (options->pattern != NULL) {
                fprintf(stderr, _("invalid arguments for export\n"));
                return 2;
            }
            options->pattern = optarg;
            break;
        case 1000:
            options->sandbox_injectable = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for export\n"));
            return 2;
        }
    }

    if (optind + 1 == argc && options->pattern == NULL) {
        options->pattern = argv[optind];
        return 0;
    }
    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for export\n"));
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
        {"secret-value", no_argument, NULL, 'e'},
        {"public-value", no_argument, NULL, 'u'},
        {"sandbox-injectable", no_argument, NULL, 1000},
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
        case 1000:
            options->sandbox_injectable = 1;
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

    if (!options->masked && !options->overridden && !options->orphaned
        && !options->safe && !options->unsafe_store && !options->sandbox_injectable) {
        fprintf(stderr, _("missing state filter for list\n"));
        secdat_cli_print_try_help(cli, "list");
        return 2;
    }

    return 0;
}

static int secdat_parse_attr_options(const struct secdat_cli *cli, struct secdat_attr_options *options)
{
    static const struct option long_options[] = {
        {"key-visibility", required_argument, NULL, 1000},
        {"value-access", required_argument, NULL, 1001},
        {"sandbox-inject", required_argument, NULL, 1002},
        {"inject", required_argument, NULL, 1002},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));
    secdat_secret_attrs_default(0, &options->attrs);

    secdat_prepare_option_argv(cli, "attr", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            if (secdat_parse_key_visibility(optarg, &options->attrs.key_visibility) != 0) {
                return 2;
            }
            options->set_key_visibility = 1;
            break;
        case 1001:
            if (secdat_parse_value_access(optarg, &options->attrs.value_access) != 0) {
                return 2;
            }
            options->set_value_access = 1;
            break;
        case 1002:
            if (secdat_parse_sandbox_inject(optarg, &options->attrs.sandbox_inject) != 0) {
                return 2;
            }
            options->set_sandbox_inject = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for attr\n"));
            secdat_cli_print_try_help(cli, "attr");
            return 2;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, _("missing key for attr\n"));
        secdat_cli_print_try_help(cli, "attr");
        return 2;
    }
    options->keyref = argv[optind];
    optind += 1;
    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for attr\n"));
        secdat_cli_print_try_help(cli, "attr");
        return 2;
    }

    return 0;
}

static int secdat_parse_fsck_options(const struct secdat_cli *cli, struct secdat_fsck_options *options)
{
    static const struct option long_options[] = {
        {"orphaned", no_argument, NULL, 1000},
        {"dangling", no_argument, NULL, 1001},
        {"refcount", no_argument, NULL, 1002},
        {"format", required_argument, NULL, 1003},
        {"repair", no_argument, NULL, 1004},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));
    options->format = "v1";

    secdat_prepare_option_argv(cli, "fsck", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            options->orphaned = 1;
            break;
        case 1001:
            options->dangling = 1;
            break;
        case 1002:
            options->refcount = 1;
            break;
        case 1003:
            if (strcmp(optarg, "v1") != 0 && strcmp(optarg, "v2") != 0) {
                fprintf(stderr, _("invalid fsck format: %s\n"), optarg);
                return 2;
            }
            options->format = optarg;
            break;
        case 1004:
            options->repair = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for fsck\n"));
            secdat_cli_print_try_help(cli, "fsck");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for fsck\n"));
        secdat_cli_print_try_help(cli, "fsck");
        return 2;
    }
    if (!options->orphaned && !options->dangling && !options->refcount) {
        options->orphaned = 1;
        options->dangling = 1;
        options->refcount = 1;
    }
    if (options->repair) {
        if (strcmp(options->format, "v2") != 0) {
            fprintf(stderr, _("fsck --repair is only supported with --format v2\n"));
            return 2;
        }
        if (!options->refcount) {
            fprintf(stderr, _("fsck --repair currently requires --refcount\n"));
            return 2;
        }
    }

    return 0;
}

static int secdat_parse_gc_options(const struct secdat_cli *cli, struct secdat_gc_options *options)
{
    static const struct option long_options[] = {
        {"orphaned", no_argument, NULL, 1000},
        {"dangling", no_argument, NULL, 1001},
        {"dry-run", no_argument, NULL, 1002},
        {"format", required_argument, NULL, 1003},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));
    options->format = "v2";

    secdat_prepare_option_argv(cli, "gc", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            options->orphaned = 1;
            break;
        case 1001:
            options->dangling = 1;
            break;
        case 1002:
            options->dry_run = 1;
            break;
        case 1003:
            if (strcmp(optarg, "v2") != 0) {
                fprintf(stderr, _("invalid gc format: %s\n"), optarg);
                return 2;
            }
            options->format = optarg;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for gc\n"));
            secdat_cli_print_try_help(cli, "gc");
            return 2;
        }
    }

    if (optind != argc) {
        fprintf(stderr, _("invalid arguments for gc\n"));
        secdat_cli_print_try_help(cli, "gc");
        return 2;
    }
    if (!options->orphaned && !options->dangling) {
        options->orphaned = 1;
        options->dangling = 1;
    }

    return 0;
}

static int secdat_parse_store_migrate_options(const struct secdat_cli *cli, struct secdat_store_migrate_options *options)
{
    static const struct option long_options[] = {
        {"to-format", required_argument, NULL, 1000},
        {"dry-run", no_argument, NULL, 1001},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "store migrate", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            if (strcmp(optarg, "v2") != 0) {
                fprintf(stderr, _("invalid migration target format: %s\n"), optarg);
                return 2;
            }
            options->to_format = optarg;
            break;
        case 1001:
            options->dry_run = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for store migrate\n"));
            secdat_cli_print_try_help(cli, "store");
            return 2;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, _("missing store name for store migrate\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (optind + 1 != argc) {
        fprintf(stderr, _("invalid arguments for store migrate\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (options->to_format == NULL) {
        fprintf(stderr, _("store migrate requires --to-format v2\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    options->store_name = argv[optind];
    return 0;
}

static int secdat_parse_store_finalize_migration_options(
    const struct secdat_cli *cli,
    struct secdat_store_finalize_migration_options *options
)
{
    static const struct option long_options[] = {
        {"from-format", required_argument, NULL, 1000},
        {"dry-run", no_argument, NULL, 1001},
        {NULL, 0, NULL, 0},
    };
    char *argv[cli->argc + 2];
    int argc;
    int option;

    memset(options, 0, sizeof(*options));

    secdat_prepare_option_argv(cli, "store finalize-migration", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {
        switch (option) {
        case 1000:
            if (strcmp(optarg, "v1") != 0) {
                fprintf(stderr, _("invalid migration source format: %s\n"), optarg);
                return 2;
            }
            options->from_format = optarg;
            break;
        case 1001:
            options->dry_run = 1;
            break;
        case '?':
        case ':':
        default:
            fprintf(stderr, _("invalid arguments for store finalize-migration\n"));
            secdat_cli_print_try_help(cli, "store");
            return 2;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, _("missing store name for store finalize-migration\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (optind + 1 != argc) {
        fprintf(stderr, _("invalid arguments for store finalize-migration\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    if (options->from_format == NULL) {
        fprintf(stderr, _("store finalize-migration requires --from-format v1\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    options->store_name = argv[optind];
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

static int secdat_hex_string_is_valid(const char *input)
{
    size_t input_length;
    size_t index;

    input_length = strlen(input);
    if (input_length == 0 || input_length % 2 != 0) {
        return 0;
    }
    for (index = 0; index < input_length; index += 1) {
        if (secdat_hex_value(input[index]) < 0) {
            return 0;
        }
    }
    return 1;
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

static int secdat_directory_contains_only_names(
    const char *path,
    const char *const *allowed_names,
    size_t allowed_count,
    int *contains_only
)
{
    DIR *directory;
    struct dirent *entry;

    *contains_only = 1;
    directory = opendir(path);
    if (directory == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, _("failed to open directory: %s\n"), path);
        return 1;
    }

    while ((entry = readdir(directory)) != NULL) {
        size_t index;
        int allowed = 0;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        for (index = 0; index < allowed_count; index += 1) {
            if (strcmp(entry->d_name, allowed_names[index]) == 0) {
                allowed = 1;
                break;
            }
        }
        if (!allowed) {
            *contains_only = 0;
            closedir(directory);
            return 0;
        }
    }

    closedir(directory);
    return 0;
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

static int secdat_build_entry_metadata_path(const char *domain_id, const char *store_name, const char *key, char *buffer, size_t size)
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

    written = snprintf(buffer, size, "%s/%s.meta", entries_dir, escaped_key);
    free(escaped_key);
    if (written < 0 || (size_t)written >= size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }

    return 0;
}

static const char *secdat_key_visibility_name(enum secdat_key_visibility value)
{
    switch (value) {
    case SECDAT_KEY_VISIBILITY_ALWAYS:
        return "always";
    case SECDAT_KEY_VISIBILITY_UNLOCKED:
        return "unlocked";
    default:
        return "unknown";
    }
}

static const char *secdat_value_access_name(enum secdat_value_access value)
{
    switch (value) {
    case SECDAT_VALUE_ACCESS_UNLOCKED:
        return "unlocked";
    case SECDAT_VALUE_ACCESS_ALWAYS:
        return "always";
    default:
        return "unknown";
    }
}

static const char *secdat_sandbox_inject_name(enum secdat_sandbox_inject value)
{
    switch (value) {
    case SECDAT_SANDBOX_INJECT_NEVER:
        return "never";
    case SECDAT_SANDBOX_INJECT_EXPLICIT:
        return "explicit";
    case SECDAT_SANDBOX_INJECT_BULK:
        return "bulk";
    default:
        return "unknown";
    }
}

static int secdat_parse_key_visibility(const char *value, enum secdat_key_visibility *parsed)
{
    if (strcmp(value, "always") == 0) {
        *parsed = SECDAT_KEY_VISIBILITY_ALWAYS;
        return 0;
    }
    if (strcmp(value, "unlocked") == 0) {
        *parsed = SECDAT_KEY_VISIBILITY_UNLOCKED;
        return 0;
    }
    fprintf(stderr, _("invalid key visibility: %s\n"), value);
    return 1;
}

static int secdat_parse_value_access(const char *value, enum secdat_value_access *parsed)
{
    if (strcmp(value, "unlocked") == 0) {
        *parsed = SECDAT_VALUE_ACCESS_UNLOCKED;
        return 0;
    }
    if (strcmp(value, "always") == 0) {
        *parsed = SECDAT_VALUE_ACCESS_ALWAYS;
        return 0;
    }
    fprintf(stderr, _("invalid value access: %s\n"), value);
    return 1;
}

static int secdat_parse_sandbox_inject_token(const char *value, enum secdat_sandbox_inject *parsed, int accept_allow_alias)
{
    if (strcmp(value, "never") == 0) {
        *parsed = SECDAT_SANDBOX_INJECT_NEVER;
        return 0;
    }
    if (strcmp(value, "explicit") == 0) {
        *parsed = SECDAT_SANDBOX_INJECT_EXPLICIT;
        return 0;
    }
    if (strcmp(value, "bulk") == 0) {
        *parsed = SECDAT_SANDBOX_INJECT_BULK;
        return 0;
    }
    if (accept_allow_alias && strcmp(value, "allow") == 0) {
        *parsed = SECDAT_SANDBOX_INJECT_BULK;
        return 0;
    }
    return 1;
}

static int secdat_parse_sandbox_inject(const char *value, enum secdat_sandbox_inject *parsed)
{
    if (secdat_parse_sandbox_inject_token(value, parsed, 0) == 0) {
        return 0;
    }
    fprintf(stderr, _("invalid sandbox inject policy: %s\n"), value);
    return 1;
}

static int secdat_parse_sandbox_inject_metadata(const char *value, enum secdat_sandbox_inject *parsed)
{
    if (secdat_parse_sandbox_inject_token(value, parsed, 1) == 0) {
        return 0;
    }
    fprintf(stderr, _("invalid sandbox inject policy: %s\n"), value);
    return 1;
}

static void secdat_secret_attrs_default(int unsafe_store, struct secdat_secret_attrs *attrs)
{
    attrs->key_visibility = SECDAT_KEY_VISIBILITY_ALWAYS;
    attrs->value_access = unsafe_store ? SECDAT_VALUE_ACCESS_ALWAYS : SECDAT_VALUE_ACCESS_UNLOCKED;
    attrs->sandbox_inject = SECDAT_SANDBOX_INJECT_NEVER;
}

static int secdat_secret_attrs_supported(const struct secdat_secret_attrs *attrs)
{
    if (attrs->key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED) {
        fprintf(stderr, _("key_visibility=unlocked requires store format v2; run store migrate STORE --to-format v2 --dry-run first\n"));
        return 0;
    }
    return 1;
}

static int secdat_v2_secret_attrs_supported(const struct secdat_secret_attrs *attrs)
{
    (void)attrs;
    return 1;
}

static int secdat_secret_attrs_are_default(const struct secdat_secret_attrs *attrs, int unsafe_store)
{
    struct secdat_secret_attrs defaults;

    secdat_secret_attrs_default(unsafe_store, &defaults);
    return attrs->key_visibility == defaults.key_visibility
        && attrs->value_access == defaults.value_access
        && attrs->sandbox_inject == defaults.sandbox_inject;
}

static int secdat_parse_secret_attr_line(char *line, struct secdat_secret_attrs *attrs)
{
    char *separator;

    if (line[0] == '\0') {
        return 0;
    }
    separator = strchr(line, '=');
    if (separator == NULL) {
        fprintf(stderr, _("invalid secret metadata\n"));
        return 1;
    }
    *separator = '\0';
    separator += 1;

    if (strcmp(line, "key_visibility") == 0) {
        return secdat_parse_key_visibility(separator, &attrs->key_visibility);
    }
    if (strcmp(line, "value_access") == 0) {
        return secdat_parse_value_access(separator, &attrs->value_access);
    }
    if (strcmp(line, "sandbox_inject") == 0) {
        return secdat_parse_sandbox_inject_metadata(separator, &attrs->sandbox_inject);
    }

    fprintf(stderr, _("unsupported secret metadata field: %s\n"), line);
    return 1;
}

static int secdat_read_secret_attrs_path(const char *metadata_path, int unsafe_store, struct secdat_secret_attrs *attrs)
{
    unsigned char *data = NULL;
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    size_t length = 0;
    int status = 1;

    secdat_secret_attrs_default(unsafe_store, attrs);
    if (!secdat_file_exists(metadata_path)) {
        return 0;
    }

    if (secdat_read_file(metadata_path, &data, &length) != 0) {
        return 1;
    }
    if (length > 4096 || memchr(data, '\0', length) != NULL) {
        fprintf(stderr, _("invalid secret metadata\n"));
        goto cleanup;
    }

    text = malloc(length + 1);
    if (text == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }
    memcpy(text, data, length);
    text[length] = '\0';

    line = strtok_r(text, "\n", &saveptr);
    if (line == NULL || strcmp(line, secdat_attrs_magic) != 0) {
        fprintf(stderr, _("unsupported secret metadata format\n"));
        goto cleanup;
    }

    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        if (secdat_parse_secret_attr_line(line, attrs) != 0) {
            goto cleanup;
        }
    }

    attrs->value_access = unsafe_store ? SECDAT_VALUE_ACCESS_ALWAYS : SECDAT_VALUE_ACCESS_UNLOCKED;
    status = 0;

cleanup:
    free(text);
    free(data);
    return status;
}

static int secdat_read_secret_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    int unsafe_store,
    struct secdat_secret_attrs *attrs
)
{
    char metadata_path[PATH_MAX];

    if (secdat_build_entry_metadata_path(domain_id, store_name, key, metadata_path, sizeof(metadata_path)) != 0) {
        return 1;
    }
    return secdat_read_secret_attrs_path(metadata_path, unsafe_store, attrs);
}

static int secdat_remove_secret_attrs(const char *domain_id, const char *store_name, const char *key)
{
    char metadata_path[PATH_MAX];

    if (secdat_build_entry_metadata_path(domain_id, store_name, key, metadata_path, sizeof(metadata_path)) != 0) {
        return 1;
    }
    return secdat_remove_if_exists(metadata_path);
}

static int secdat_write_secret_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
)
{
    char metadata_path[PATH_MAX];
    char payload[512];
    int written;

    if (attrs == NULL || secdat_secret_attrs_are_default(attrs, unsafe_store)) {
        return secdat_remove_secret_attrs(domain_id, store_name, key);
    }
    if (!secdat_secret_attrs_supported(attrs)) {
        return 1;
    }
    if ((attrs->value_access == SECDAT_VALUE_ACCESS_ALWAYS) != (unsafe_store != 0)) {
        fprintf(stderr, _("secret value_access does not match storage mode\n"));
        return 1;
    }
    if (secdat_build_entry_metadata_path(domain_id, store_name, key, metadata_path, sizeof(metadata_path)) != 0) {
        return 1;
    }

    written = snprintf(
        payload,
        sizeof(payload),
        "%s\nkey_visibility=%s\nvalue_access=%s\nsandbox_inject=%s\n",
        secdat_attrs_magic,
        secdat_key_visibility_name(attrs->key_visibility),
        secdat_value_access_name(attrs->value_access),
        secdat_sandbox_inject_name(attrs->sandbox_inject)
    );
    if (written < 0 || (size_t)written >= sizeof(payload)) {
        fprintf(stderr, _("secret metadata is too large\n"));
        return 1;
    }

    return secdat_atomic_write_file(metadata_path, (const unsigned char *)payload, (size_t)written);
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

static int secdat_remove_directory_if_exists(const char *path)
{
    if (rmdir(path) == 0 || errno == ENOENT) {
        return 0;
    }

    fprintf(stderr, _("failed to remove directory: %s\n"), path);
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

static int secdat_wrapped_master_key_iterations(uint32_t *iterations)
{
    const char *value = getenv(SECDAT_WRAP_PBKDF2_ITERATIONS_ENV);
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || value[0] == '\0') {
        *iterations = SECDAT_WRAP_PBKDF2_ITERATIONS;
        return 0;
    }

    errno = 0;
    if (!isdigit((unsigned char)value[0])) {
        parsed = 0;
        end = (char *)value;
    } else {
        parsed = strtoul(value, &end, 10);
    }
    if (errno != 0
        || end == value
        || *end != '\0'
        || parsed < SECDAT_WRAP_PBKDF2_MIN_ITERATIONS
        || parsed > SECDAT_WRAP_PBKDF2_MAX_ITERATIONS
        || parsed > (unsigned long)INT_MAX) {
        fprintf(
            stderr,
            _("%s must be an integer between %u and %u\n"),
            SECDAT_WRAP_PBKDF2_ITERATIONS_ENV,
            (unsigned int)SECDAT_WRAP_PBKDF2_MIN_ITERATIONS,
            (unsigned int)SECDAT_WRAP_PBKDF2_MAX_ITERATIONS
        );
        return 1;
    }

    *iterations = (uint32_t)parsed;
    return 0;
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

static const char *secdat_askpass_command(void)
{
    const char *value = getenv(SECDAT_ASKPASS_ENV);

    if (value != NULL && value[0] != '\0') {
        return value;
    }

    value = getenv("SSH_ASKPASS");
    if (value != NULL && value[0] != '\0') {
        return value;
    }

    return NULL;
}

static int secdat_finalize_passphrase_buffer(char *buffer)
{
    size_t length = strlen(buffer);

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

static int secdat_read_secret_from_askpass(const char *askpass, const char *prompt, char *buffer, size_t size)
{
    int pipe_fds[2];
    pid_t pid;
    int status;
    size_t length = 0;
    int too_long = 0;
    ssize_t read_length;

    if (size == 0 || pipe(pipe_fds) != 0) {
        fprintf(stderr, _("failed to start askpass command\n"));
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        fprintf(stderr, _("failed to start askpass command\n"));
        return 1;
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);

        close(pipe_fds[0]);
        if (devnull < 0 || dup2(devnull, STDIN_FILENO) != STDIN_FILENO) {
            _exit(127);
        }
        if (devnull > STDERR_FILENO) {
            close(devnull);
        }
        if (dup2(pipe_fds[1], STDOUT_FILENO) != STDOUT_FILENO) {
            _exit(127);
        }
        if (pipe_fds[1] > STDERR_FILENO) {
            close(pipe_fds[1]);
        }
        execl(askpass, askpass, prompt, (char *)NULL);
        _exit(127);
    }

    close(pipe_fds[1]);
    while (1) {
        char chunk[128];

        read_length = read(pipe_fds[0], chunk, sizeof(chunk));
        if (read_length <= 0) {
            break;
        }
        if (length + (size_t)read_length < size) {
            memcpy(buffer + length, chunk, (size_t)read_length);
            length += (size_t)read_length;
        } else {
            size_t room = size > length + 1 ? size - length - 1 : 0;

            if (room > 0) {
                memcpy(buffer + length, chunk, room);
                length += room;
            }
            too_long = 1;
        }
        secdat_secure_clear(chunk, (size_t)read_length);
    }
    if (read_length < 0) {
        close(pipe_fds[0]);
        waitpid(pid, &status, 0);
        secdat_secure_clear(buffer, length);
        fprintf(stderr, _("failed to read askpass output\n"));
        return 1;
    }
    close(pipe_fds[0]);

    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        secdat_secure_clear(buffer, length);
        fprintf(stderr, _("askpass command failed\n"));
        return 1;
    }
    if (too_long) {
        secdat_secure_clear(buffer, length);
        fprintf(stderr, _("askpass output is too long\n"));
        return 1;
    }

    buffer[length] = '\0';
    return secdat_finalize_passphrase_buffer(buffer);
}

static int secdat_read_secret_from_tty(const char *prompt, char *buffer, size_t size)
{
    struct termios old_settings;
    struct termios new_settings;
    int restored = 0;
    const char *askpass;

    if (!isatty(STDIN_FILENO)) {
        askpass = secdat_askpass_command();
        if (askpass != NULL) {
            return secdat_read_secret_from_askpass(askpass, prompt, buffer, size);
        }
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
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_settings) != 0) {
        fprintf(stderr, _("failed to update terminal settings\n"));
        return 1;
    }

    if (fgets(buffer, (int)size, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
        fprintf(stderr, _("failed to read passphrase\n"));
        return 1;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_settings) == 0) {
        restored = 1;
    }
    fprintf(stderr, "\n");

    if (!restored) {
        fprintf(stderr, _("failed to update terminal settings\n"));
        return 1;
    }

    return secdat_finalize_passphrase_buffer(buffer);
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
    if (iterations == 0 || iterations > (uint32_t)INT_MAX) {
        fprintf(stderr, _("invalid wrap key iteration count\n"));
        return 1;
    }
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
    uint32_t iterations;

    if (secdat_state_dir(state_dir, sizeof(state_dir)) != 0) {
        return 1;
    }
    if (secdat_ensure_directory(state_dir, 0700) != 0) {
        return 1;
    }
    if (secdat_wrapped_master_key_path(path, sizeof(path)) != 0) {
        return 1;
    }
    if (secdat_wrapped_master_key_iterations(&iterations) != 0) {
        return 1;
    }
    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }
    if (secdat_wrap_key_from_passphrase(passphrase, salt, iterations, wrap_key) != 0) {
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
    secdat_write_be32(buffer + 12, iterations);
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

static int secdat_registered_root_is_directory(const char *registered_root)
{
    struct stat status;

    if (stat(registered_root, &status) == 0) {
        return S_ISDIR(status.st_mode) ? 1 : 0;
    }
    if (errno == ENOENT || errno == ENOTDIR) {
        return 0;
    }
    fprintf(stderr, _("failed to stat path: %s\n"), registered_root);
    return -1;
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

int secdat_collect_registered_domain_status_summary(const char *registered_root, struct secdat_domain_status_summary *summary)
{
    struct secdat_domain_chain chain = {0};
    int directory_status;
    int status;

    directory_status = secdat_registered_root_is_directory(registered_root);
    if (directory_status < 0) {
        return 1;
    }
    if (directory_status > 0) {
        return secdat_collect_domain_status_summary(registered_root, summary);
    }
    if (secdat_domain_resolve_registered_root_chain(registered_root, &chain) != 0) {
        return 1;
    }

    status = secdat_collect_domain_status_summary_for_chain(&chain, summary);
    if (status == 0) {
        summary->orphaned_domain = 1;
    }
    secdat_domain_chain_free(&chain);
    return status;
}

int secdat_collect_user_global_status_summary(struct secdat_domain_status_summary *summary)
{
    struct secdat_domain_chain chain = {0};

    return secdat_collect_domain_status_summary_for_chain(&chain, summary);
}

int secdat_sdk_collect_status(
    const struct secdat_sdk_options *options,
    struct secdat_sdk_status_summary *summary
)
{
    struct secdat_domain_status_summary internal_summary;
    struct secdat_domain_chain chain = {0};
    const char *domain_base;
    int status;

    if (summary == NULL) {
        return 1;
    }

    memset(summary, 0, sizeof(*summary));
    domain_base = secdat_sdk_domain_base(options);
    if (options != NULL && options->domain != NULL) {
        if (secdat_domain_resolve_chain(domain_base, &chain) != 0) {
            return 1;
        }
        status = secdat_collect_domain_status_summary_for_chain(&chain, &internal_summary);
        secdat_domain_chain_free(&chain);
    } else {
        status = secdat_collect_domain_status_summary(domain_base, &internal_summary);
    }
    if (status != 0) {
        return status;
    }

    summary->store_count = internal_summary.store_count;
    summary->visible_key_count = internal_summary.visible_key_count;
    summary->wrapped_master_key_present = internal_summary.wrapped_master_key_present;
    summary->key_source = (enum secdat_sdk_key_source_type)internal_summary.key_source;
    summary->effective_source = (enum secdat_sdk_effective_source_type)internal_summary.effective_source;
    summary->session_expires_at = internal_summary.session_expires_at;
    memcpy(summary->related_domain_root, internal_summary.related_domain_root, sizeof(summary->related_domain_root));
    return 0;
}

int secdat_sdk_exists(
    const struct secdat_sdk_options *options,
    const char *keyref,
    int *exists_out
)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char entry_path[PATH_MAX];
    int status;

    if (keyref == NULL || exists_out == NULL) {
        return 1;
    }

    *exists_out = 0;
    if (secdat_parse_key_reference(keyref, secdat_sdk_domain_base(options), options != NULL ? options->store : NULL, &reference) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }

    status = secdat_resolve_entry_path(&chain, reference.store_value, reference.key, entry_path, sizeof(entry_path));
    secdat_domain_chain_free(&chain);
    *exists_out = status == 0;
    return 0;
}

int secdat_sdk_get(
    const struct secdat_sdk_options *options,
    const char *keyref,
    unsigned char **value_out,
    size_t *value_length_out,
    int *unsafe_store_out
)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int unsafe_store = 0;

    if (keyref == NULL || value_out == NULL || value_length_out == NULL) {
        return 1;
    }

    *value_out = NULL;
    *value_length_out = 0;
    if (unsafe_store_out != NULL) {
        *unsafe_store_out = 0;
    }

    if (secdat_parse_key_reference(keyref, secdat_sdk_domain_base(options), options != NULL ? options->store : NULL, &reference) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    if (secdat_load_resolved_plaintext(&chain, reference.store_value, reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store, NULL) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    secdat_domain_chain_free(&chain);
    *value_out = plaintext;
    *value_length_out = plaintext_length;
    if (unsafe_store_out != NULL) {
        *unsafe_store_out = unsafe_store;
    }
    return 0;
}

int secdat_sdk_set(
    const struct secdat_sdk_options *options,
    const char *keyref,
    const unsigned char *value,
    size_t value_length,
    int unsafe_store
)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    char current_domain_id[PATH_MAX];
    unsigned char *plaintext = NULL;
    int status;

    if (keyref == NULL || (value == NULL && value_length != 0)) {
        return 1;
    }

    if (secdat_parse_key_reference(keyref, secdat_sdk_domain_base(options), options != NULL ? options->store : NULL, &reference) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_current(reference.domain_value, current_domain_id, sizeof(current_domain_id)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "set") != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    plaintext = malloc(value_length == 0 ? 1 : value_length);
    if (plaintext == NULL) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    if (value_length > 0) {
        memcpy(plaintext, value, value_length);
    }

    status = secdat_store_plaintext_for_chain(&chain, current_domain_id, reference.store_value, reference.key, plaintext, value_length, unsafe_store);
    secdat_domain_chain_free(&chain);
    secdat_secure_clear(plaintext, value_length);
    free(plaintext);
    return status;
}

int secdat_sdk_rm(
    const struct secdat_sdk_options *options,
    const char *keyref,
    int ignore_missing
)
{
    struct secdat_cli cli;
    char *argv[2];
    int argc = 0;

    if (keyref == NULL) {
        return 1;
    }

    if (ignore_missing) {
        argv[argc] = "-f";
        argc += 1;
    }
    argv[argc] = (char *)keyref;
    argc += 1;
    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_RM, argc, argv);
    return secdat_command_rm(&cli);
}

int secdat_sdk_mv(
    const struct secdat_sdk_options *options,
    const char *source_keyref,
    const char *destination_keyref
)
{
    struct secdat_cli cli;
    char *argv[2];

    if (source_keyref == NULL || destination_keyref == NULL) {
        return 1;
    }

    argv[0] = (char *)source_keyref;
    argv[1] = (char *)destination_keyref;
    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_MV, 2, argv);
    return secdat_command_mv(&cli);
}

int secdat_sdk_cp(
    const struct secdat_sdk_options *options,
    const char *source_keyref,
    const char *destination_keyref
)
{
    struct secdat_cli cli;
    char *argv[2];

    if (source_keyref == NULL || destination_keyref == NULL) {
        return 1;
    }

    argv[0] = (char *)source_keyref;
    argv[1] = (char *)destination_keyref;
    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_CP, 2, argv);
    return secdat_command_cp(&cli);
}

int secdat_sdk_mask(
    const struct secdat_sdk_options *options,
    const char *keyref
)
{
    struct secdat_cli cli;
    char *argv[1];

    if (keyref == NULL) {
        return 1;
    }

    argv[0] = (char *)keyref;
    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_MASK, 1, argv);
    return secdat_command_mask(&cli);
}

int secdat_sdk_unmask(
    const struct secdat_sdk_options *options,
    const char *keyref
)
{
    struct secdat_cli cli;
    char *argv[1];

    if (keyref == NULL) {
        return 1;
    }

    argv[0] = (char *)keyref;
    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_UNMASK, 1, argv);
    return secdat_command_unmask(&cli);
}

int secdat_sdk_unlock(const struct secdat_sdk_options *options)
{
    struct secdat_cli cli;

    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_UNLOCK, 0, NULL);
    cli.store = NULL;
    return secdat_command_unlock(&cli);
}

int secdat_sdk_lock(const struct secdat_sdk_options *options)
{
    struct secdat_cli cli;

    secdat_sdk_init_cli(options, &cli, SECDAT_COMMAND_LOCK, 0, NULL);
    cli.store = NULL;
    return secdat_command_lock(&cli);
}

void secdat_sdk_free(void *pointer)
{
    free(pointer);
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

static const char *secdat_session_mode_json_name(const struct secdat_session_record *record)
{
    if (record == NULL) {
        return NULL;
    }
    if (record->volatile_mode) {
        return "volatile";
    }
    if (record->readonly_mode) {
        return "readonly";
    }
    return "persistent";
}

static void secdat_print_json_nullable_string_field(const char *name, const char *value, int trailing_comma)
{
    printf("  \"%s\": ", name);
    if (value == NULL || value[0] == '\0') {
        fputs("null", stdout);
    } else {
        secdat_write_json_string(stdout, value);
    }
    fputs(trailing_comma ? ",\n" : "\n", stdout);
}

static void secdat_print_json_nullable_time_field(const char *name, time_t value, int trailing_comma)
{
    printf("  \"%s\": ", name);
    if (value <= 0) {
        fputs("null", stdout);
    } else {
        printf("%lld", (long long)value);
    }
    fputs(trailing_comma ? ",\n" : "\n", stdout);
}

static void secdat_print_json_nullable_remaining_field(const char *name, time_t expires_at, int trailing_comma)
{
    printf("  \"%s\": ", name);
    if (expires_at <= 0) {
        fputs("null", stdout);
    } else {
        printf("%lld", secdat_remaining_seconds(expires_at));
    }
    fputs(trailing_comma ? ",\n" : "\n", stdout);
}

static void secdat_print_status_json(
    enum secdat_key_source_type key_source,
    enum secdat_effective_source_type effective_source,
    time_t session_expires_at,
    const char *session_mode,
    const char *related_domain,
    int wrapped_present
)
{
    fputs("{\n", stdout);
    printf("  \"unlocked\": %s,\n", strcmp(secdat_effective_state_json_name(effective_source), "unlocked") == 0 ? "true" : "false");
    printf("  \"key_source\": ");
    secdat_write_json_string(stdout, secdat_key_source_json_name(key_source));
    fputs(",\n", stdout);
    printf("  \"effective_state\": ");
    secdat_write_json_string(stdout, secdat_effective_state_json_name(effective_source));
    fputs(",\n", stdout);
    printf("  \"effective_source\": ");
    secdat_write_json_string(stdout, secdat_effective_source_json_name(effective_source));
    fputs(",\n", stdout);
    secdat_print_json_nullable_time_field("session_expires_at", session_expires_at, 1);
    secdat_print_json_nullable_remaining_field("remaining_seconds", session_expires_at, 1);
    secdat_print_json_nullable_string_field("session_mode", session_mode, 1);
    secdat_print_json_nullable_string_field("related_domain", related_domain, 1);
    printf("  \"wrapped_master_key_present\": %s\n", wrapped_present ? "true" : "false");
    fputs("}\n", stdout);
}

static int secdat_command_status_json(const struct secdat_cli *cli, int wrapped_present)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    enum secdat_key_source_type key_source = SECDAT_KEY_SOURCE_LOCKED;
    enum secdat_effective_source_type effective_source = SECDAT_EFFECTIVE_SOURCE_LOCKED;
    size_t matched_index = SIZE_MAX;
    size_t blocked_index = SIZE_MAX;
    time_t session_expires_at = 0;
    const char *session_mode = NULL;
    char related_domain[PATH_MAX] = "";

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        key_source = SECDAT_KEY_SOURCE_ENVIRONMENT;
        effective_source = SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT;
        secdat_print_status_json(key_source, effective_source, 0, NULL, NULL, wrapped_present);
        return 0;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) == 0) {
        if (secdat_session_agent_status_details(&chain, &record, &matched_index, &blocked_index) == 0) {
            key_source = SECDAT_KEY_SOURCE_SESSION;
            effective_source = matched_index == 0
                ? SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION
                : SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION;
            session_expires_at = record.expires_at;
            session_mode = secdat_session_mode_json_name(&record);
            if (matched_index != SIZE_MAX && matched_index > 0) {
                if (matched_index == chain.count) {
                    if (secdat_domain_display_label("", related_domain, sizeof(related_domain)) != 0) {
                        related_domain[0] = '\0';
                    }
                } else if (secdat_domain_root_path(chain.ids[matched_index], related_domain, sizeof(related_domain)) != 0) {
                    related_domain[0] = '\0';
                }
            }
        } else if (blocked_index == 0) {
            effective_source = SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK;
        } else if (blocked_index != SIZE_MAX && blocked_index < chain.count) {
            effective_source = SECDAT_EFFECTIVE_SOURCE_BLOCKED;
            if (secdat_domain_root_path(chain.ids[blocked_index], related_domain, sizeof(related_domain)) != 0) {
                related_domain[0] = '\0';
            }
        }
        secdat_domain_chain_free(&chain);
    }

    secdat_print_status_json(
        key_source,
        effective_source,
        session_expires_at,
        session_mode,
        related_domain[0] != '\0' ? related_domain : NULL,
        wrapped_present
    );
    secdat_session_record_reset(&record);
    return strcmp(secdat_effective_state_json_name(effective_source), "unlocked") == 0 ? 0 : 1;
}

static int secdat_command_status(const struct secdat_cli *cli)
{
    static const struct option long_options[] = {
        {"quiet", no_argument, NULL, 'q'},
        {"json", no_argument, NULL, 1000},
        {NULL, 0, NULL, 0},
    };
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    char *argv[cli->argc + 2];
    int argc;
    int option;
    int quiet = 0;
    int json = 0;
    int wrapped_present = secdat_wrapped_master_key_exists();
    char remaining_text[32];

    secdat_prepare_option_argv(cli, "status", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":q", long_options, NULL)) != -1) {
        switch (option) {
        case 'q':
            quiet = 1;
            break;
        case 1000:
            json = 1;
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

    if (quiet && json) {
        fprintf(stderr, _("invalid arguments for status\n"));
        secdat_cli_print_try_help(cli, "status");
        return 2;
    }

    if (json) {
        return secdat_command_status_json(cli, wrapped_present);
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
        fprintf(stderr, _("no persistent master key is initialized; run secdat unlock once to create one\n"));
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
        fprintf(stderr, _("no persistent master key is initialized; run secdat unlock once to create one\n"));
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

static int secdat_encrypt_v2_object_value(
    const unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN],
    const unsigned char *plaintext,
    size_t plaintext_length,
    unsigned char **encrypted,
    size_t *encrypted_length
)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char nonce[SECDAT_NONCE_LEN];
    unsigned char tag[SECDAT_TAG_LEN];
    unsigned char *buffer = NULL;
    int ciphertext_length;
    int final_length;
    size_t total_ciphertext_length;
    size_t total_length;
    int status = 1;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }

    total_ciphertext_length = plaintext_length + SECDAT_TAG_LEN;
    total_length = SECDAT_HEADER_LEN + sizeof(nonce) + total_ciphertext_length;
    buffer = calloc(1, total_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }

    memcpy(buffer, secdat_v2_object_payload_magic, sizeof(secdat_v2_object_payload_magic));
    buffer[8] = SECDAT_V2_OBJECT_PAYLOAD_VERSION;
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
        || EVP_EncryptInit_ex(context, NULL, NULL, object_key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize encryption\n"));
        goto cleanup;
    }
    if (EVP_EncryptUpdate(context, NULL, &ciphertext_length, buffer, SECDAT_HEADER_LEN) != 1) {
        fprintf(stderr, _("failed to encrypt value\n"));
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
    secdat_secure_clear(tag, sizeof(tag));
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (buffer != NULL) {
        secdat_secure_clear(buffer, total_length);
        free(buffer);
    }
    return status;
}

static int secdat_decrypt_v2_object_value_with_key(
    const unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN],
    const unsigned char *encrypted,
    size_t encrypted_length,
    unsigned char **plaintext,
    size_t *plaintext_length
)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *buffer = NULL;
    const unsigned char *nonce;
    const unsigned char *ciphertext;
    const unsigned char *tag;
    uint32_t ciphertext_length;
    size_t header_length;
    size_t payload_length;
    size_t decoded_length;
    int written_length;
    int final_length;
    int status = 1;

    if (encrypted_length < SECDAT_HEADER_LEN
        || ((memcmp(encrypted, secdat_v2_value_magic, sizeof(secdat_v2_value_magic)) != 0
                || encrypted[8] != SECDAT_V2_VALUE_VERSION)
            && (memcmp(encrypted, secdat_v2_object_payload_magic, sizeof(secdat_v2_object_payload_magic)) != 0
                || encrypted[8] != SECDAT_V2_OBJECT_PAYLOAD_VERSION))
        || encrypted[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM
        || encrypted[10] != SECDAT_NONCE_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    ciphertext_length = secdat_read_be32(encrypted + 12);
    header_length = SECDAT_HEADER_LEN + encrypted[10];
    if (encrypted_length < header_length) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }
    payload_length = encrypted_length - header_length;
    if (payload_length != ciphertext_length || ciphertext_length < SECDAT_TAG_LEN) {
        fprintf(stderr, _("invalid encrypted entry\n"));
        return 1;
    }

    decoded_length = ciphertext_length - SECDAT_TAG_LEN;
    buffer = malloc(decoded_length == 0 ? 1 : decoded_length);
    if (buffer == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
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
        || EVP_DecryptInit_ex(context, NULL, NULL, object_key, nonce) != 1) {
        fprintf(stderr, _("failed to initialize decryption\n"));
        goto cleanup;
    }
    if (EVP_DecryptUpdate(context, NULL, &written_length, encrypted, SECDAT_HEADER_LEN) != 1) {
        fprintf(stderr, _("failed to decrypt value\n"));
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
    if (context != NULL) {
        EVP_CIPHER_CTX_free(context);
    }
    if (buffer != NULL) {
        secdat_secure_clear(buffer, decoded_length);
        free(buffer);
    }
    return status;
}

static int secdat_value_payload_is_v2_object_value(const unsigned char *data, size_t length)
{
    return length >= SECDAT_HEADER_LEN
        && ((memcmp(data, secdat_v2_value_magic, sizeof(secdat_v2_value_magic)) == 0
                && data[8] == SECDAT_V2_VALUE_VERSION)
            || (memcmp(data, secdat_v2_object_payload_magic, sizeof(secdat_v2_object_payload_magic)) == 0
                && data[8] == SECDAT_V2_OBJECT_PAYLOAD_VERSION));
}

static int secdat_value_payload_format_is_valid(const unsigned char *data, size_t length)
{
    uint32_t payload_length;
    size_t header_length;
    int v1_payload;
    int v2_payload;

    if (length < SECDAT_HEADER_LEN) {
        return 0;
    }

    v1_payload = memcmp(data, secdat_entry_magic, sizeof(secdat_entry_magic)) == 0
        && data[8] == SECDAT_ENTRY_VERSION;
    v2_payload = secdat_value_payload_is_v2_object_value(data, length);
    if (!v1_payload && !v2_payload) {
        return 0;
    }

    payload_length = secdat_read_be32(data + 12);
    header_length = SECDAT_HEADER_LEN + data[10];
    if (header_length < SECDAT_HEADER_LEN || length < header_length || length - header_length != payload_length) {
        return 0;
    }

    if (data[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT) {
        return v1_payload && data[10] == 0 && data[11] == 0;
    }
    if (data[9] == SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
        return data[10] == SECDAT_NONCE_LEN && data[11] == 0 && payload_length >= SECDAT_TAG_LEN;
    }
    return 0;
}

static const char *secdat_v2_effective_entry_unwrap_domain_id(
    const struct secdat_domain_chain *chain,
    const struct secdat_effective_entry *entry
)
{
    size_t chain_index;

    if (chain == NULL || entry == NULL || entry->resolved_index >= chain->count) {
        return NULL;
    }
    for (chain_index = 0; chain_index < entry->resolved_index; chain_index += 1) {
        if (secdat_domain_has_explicit_lock(chain->ids[chain_index])) {
            return chain->ids[0];
        }
    }
    return chain->ids[entry->resolved_index];
}

static int secdat_unwrap_object_key_hex(
    const char *domain_id,
    const char *wrapped_object_key,
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN]
)
{
    struct secdat_domain_chain chain = {0};
    unsigned char *encrypted = NULL;
    unsigned char *plaintext = NULL;
    size_t encrypted_length = 0;
    size_t plaintext_length = 0;
    int status = 1;

    if (wrapped_object_key == NULL || wrapped_object_key[0] == '\0') {
        return 1;
    }
    if (secdat_hex_decode_bytes(wrapped_object_key, &encrypted, &encrypted_length) != 0) {
        return 1;
    }
    if (secdat_domain_chain_from_id(domain_id, &chain) != 0) {
        goto cleanup;
    }
    if (secdat_decrypt_value(&chain, encrypted, encrypted_length, &plaintext, &plaintext_length, NULL) != 0) {
        goto cleanup;
    }
    if (plaintext_length != SECDAT_V2_OBJECT_KEY_LEN) {
        goto cleanup;
    }

    memcpy(object_key, plaintext, SECDAT_V2_OBJECT_KEY_LEN);
    status = 0;

cleanup:
    secdat_domain_chain_free(&chain);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_encode_value_for_storage(
    const char *domain_id,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    unsigned char **encrypted,
    size_t *encrypted_length
)
{
    unsigned char *buffer;

    if (unsafe_store) {
        *encrypted_length = SECDAT_HEADER_LEN + plaintext_length;
        buffer = calloc(1, *encrypted_length == 0 ? 1 : *encrypted_length);
        if (buffer == NULL) {
            fprintf(stderr, _("out of memory\n"));
            return 1;
        }
        memcpy(buffer, secdat_entry_magic, sizeof(secdat_entry_magic));
        buffer[8] = SECDAT_ENTRY_VERSION;
        buffer[9] = SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
        buffer[10] = 0;
        buffer[11] = 0;
        secdat_write_be32(buffer + 12, (uint32_t)plaintext_length);
        memcpy(buffer + SECDAT_HEADER_LEN, plaintext, plaintext_length);
        *encrypted = buffer;
        return 0;
    }

    return secdat_encrypt_value(domain_id, plaintext, plaintext_length, encrypted, encrypted_length);
}

static int secdat_encode_v2_value_for_storage(
    const unsigned char *object_key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    unsigned char **encrypted,
    size_t *encrypted_length
)
{
    if (unsafe_store) {
        return secdat_encode_value_for_storage("", plaintext, plaintext_length, 1, encrypted, encrypted_length);
    }
    if (object_key == NULL) {
        fprintf(stderr, _("invalid v2 domain entry: %s\n"), "missing-object-key");
        return 1;
    }
    return secdat_encrypt_v2_object_value(object_key, plaintext, plaintext_length, encrypted, encrypted_length);
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
    enum secdat_store_format format;

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

        if (secdat_read_store_format(chain->ids[chain_index], store_name, &format) != 0) {
            goto cleanup;
        }
        if (format == SECDAT_STORE_FORMAT_INVALID) {
            fprintf(stderr, _("invalid store format marker\n"));
            status = 1;
            goto cleanup;
        }
        if (format == SECDAT_STORE_FORMAT_V2) {
            status = secdat_collect_v2_visible_keys(chain->ids[chain_index], store_name, &domain_keys);
            if (status != 0) {
                goto cleanup;
            }
        } else {
            status = secdat_store_entries_dir(chain->ids[chain_index], store_name, entries_dir, sizeof(entries_dir));
            if (status != 0) {
                goto cleanup;
            }
            status = secdat_collect_directory_keys(entries_dir, ".sec", &domain_keys);
            if (status != 0) {
                goto cleanup;
            }
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
    char v2_entry_path[PATH_MAX];
    char v2_value_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    struct secdat_overlay_lookup_result overlay = {0};
    struct secdat_v2_domain_entry_info v2_info;
    size_t index;
    enum secdat_store_format format;

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

        if (secdat_read_store_format(chain->ids[index], store_name, &format) != 0) {
            return 1;
        }
        if (format == SECDAT_STORE_FORMAT_INVALID) {
            fprintf(stderr, _("invalid store format marker\n"));
            return 1;
        }
        if (format == SECDAT_STORE_FORMAT_V2) {
            const char *object_domain_id;
            const char *object_store_name;
            int v2_lookup_status;

            v2_lookup_status = secdat_lookup_v2_domain_entry(chain->ids[index], store_name, key, &v2_info, v2_entry_path, sizeof(v2_entry_path));
            if (v2_lookup_status > 1) {
                return 1;
            }
            if (v2_lookup_status == 0) {
                entry->found = 1;
                entry->from_v2 = 1;
                entry->resolved_index = index;
                entry->key_visibility = v2_info.key_visibility;
                entry->entry_inject = v2_info.entry_inject;
                object_domain_id = secdat_v2_entry_object_domain(chain->ids[index], &v2_info);
                object_store_name = secdat_v2_entry_object_store(store_name, &v2_info);
                if (secdat_copy_string(entry->entry_id, sizeof(entry->entry_id), v2_info.entry_id) != 0
                    || secdat_copy_string(entry->secret_id, sizeof(entry->secret_id), v2_info.secret_id) != 0
                    || secdat_copy_string(entry->object_domain, sizeof(entry->object_domain), object_domain_id) != 0
                    || secdat_copy_string(entry->object_store, sizeof(entry->object_store), object_store_name == NULL ? "" : object_store_name) != 0) {
                    return 1;
                }
                if (v2_info.has_wrapped_object_key) {
                    if (secdat_copy_string(entry->wrapped_object_key, sizeof(entry->wrapped_object_key), v2_info.wrapped_object_key) != 0) {
                        return 1;
                    }
                    entry->has_wrapped_object_key = 1;
                }
                if (secdat_build_v2_secret_value_path(entry->object_domain, secdat_effective_entry_object_store(entry), entry->secret_id, v2_value_path, sizeof(v2_value_path)) != 0) {
                    return 1;
                }
                if (secdat_file_exists(v2_value_path)) {
                    if (strlen(v2_value_path) >= sizeof(entry->path)) {
                        fprintf(stderr, _("path is too long\n"));
                        return 1;
                    }
                    strcpy(entry->path, v2_value_path);
                } else {
                    if (secdat_build_entry_path(chain->ids[index], store_name, key, entry_path, sizeof(entry_path)) != 0) {
                        return 1;
                    }
                    if (secdat_file_exists(entry_path)) {
                        if (strlen(entry_path) >= sizeof(entry->path)) {
                            fprintf(stderr, _("path is too long\n"));
                            return 1;
                        }
                        strcpy(entry->path, entry_path);
                    }
                }
                return 0;
            }
            goto check_tombstone;
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

check_tombstone:
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
    struct secdat_secret_attrs attrs;
    int visible_in_parent;
    enum secdat_store_format format;
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
    if (secdat_read_store_format(chain->ids[0], store_name, &format) != 0) {
        goto cleanup;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        goto cleanup;
    }
    if (format == SECDAT_STORE_FORMAT_V2) {
        if (secdat_collect_v2_visible_keys(chain->ids[0], store_name, &local_entries) != 0) {
            goto cleanup;
        }
    } else if (secdat_collect_directory_keys(entries_dir, ".sec", &local_entries) != 0) {
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
        if (options->safe || options->unsafe_store || options->sandbox_injectable) {
            if (secdat_active_overlay_lookup(chain, chain->ids[0], store_name, local_entries.items[index], &overlay) != 0) {
                goto cleanup;
            }
            if (overlay.found && !overlay.tombstone) {
                entry_is_unsafe = overlay.unsafe_store;
                secdat_secret_attrs_default(entry_is_unsafe, &attrs);
                secdat_secure_clear(overlay.plaintext, overlay.plaintext_length);
                free(overlay.plaintext);
                overlay.plaintext = NULL;
                overlay.plaintext_length = 0;
            } else if (format == SECDAT_STORE_FORMAT_V2) {
                if (secdat_load_resolved_secret_attrs(chain, store_name, local_entries.items[index], &attrs, &entry_is_unsafe) != 0) {
                    goto cleanup;
                }
            } else {
                if (secdat_build_entry_path(chain->ids[0], store_name, local_entries.items[index], entry_path, sizeof(entry_path)) != 0) {
                    goto cleanup;
                }
                if (secdat_entry_uses_plaintext_storage(entry_path, &entry_is_unsafe) != 0) {
                    goto cleanup;
                }
                if (secdat_read_secret_attrs(chain->ids[0], store_name, local_entries.items[index], entry_is_unsafe, &attrs) != 0) {
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
            if (options->sandbox_injectable && secdat_sandbox_inject_allows_bulk_selection(&attrs)) {
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
    struct secdat_domain_chain object_chain = {0};
    const struct secdat_domain_chain *decrypt_chain = chain;
    char object_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN];
    size_t encrypted_length = 0;
    size_t chain_index;
    int has_object_payload = 0;
    int v2_object_value = 0;
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

    if (entry.from_v2) {
        if (secdat_build_v2_secret_object_path(
                entry.object_domain,
                secdat_effective_entry_object_store(&entry),
                entry.secret_id,
                object_path,
                sizeof(object_path)
            ) != 0
            || secdat_read_v2_secret_object_payload(object_path, entry.secret_id, &encrypted, &encrypted_length, &has_object_payload) != 0) {
            fprintf(stderr, _("invalid v2 secret object: %s\n"), entry.secret_id);
            secdat_effective_entry_reset(&entry);
            return 1;
        }
    }

    if (!has_object_payload) {
        if (entry.from_v2 && entry.path[0] == '\0') {
            fprintf(stderr, _("v2 secret value storage is not implemented yet\n"));
            secdat_effective_entry_reset(&entry);
            return 1;
        }
        if (secdat_read_file(entry.path, &encrypted, &encrypted_length) != 0) {
            secdat_effective_entry_reset(&entry);
            return 1;
        }
    }

    if (unsafe_store != NULL) {
        if (encrypted_length < SECDAT_HEADER_LEN) {
            fprintf(stderr, _("invalid encrypted entry\n"));
            free(encrypted);
            return 1;
        }
        if (secdat_value_payload_is_v2_object_value(encrypted, encrypted_length)) {
            *unsafe_store = 0;
        } else if (memcmp(encrypted, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || encrypted[8] != SECDAT_ENTRY_VERSION) {
            fprintf(stderr, _("unsupported encrypted entry format\n"));
            free(encrypted);
            return 1;
        } else if (encrypted[9] != SECDAT_ENTRY_ALGORITHM_PLAINTEXT && encrypted[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
            fprintf(stderr, _("unsupported encryption algorithm\n"));
            free(encrypted);
            return 1;
        } else {
            *unsafe_store = encrypted[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
        }
    }

    v2_object_value = entry.from_v2 && secdat_value_payload_is_v2_object_value(encrypted, encrypted_length);
    if (v2_object_value) {
        const char *unwrap_domain_id;

        unwrap_domain_id = secdat_v2_effective_entry_unwrap_domain_id(chain, &entry);
        if (!entry.has_wrapped_object_key || unwrap_domain_id == NULL) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry.entry_id);
            free(encrypted);
            secdat_effective_entry_reset(&entry);
            return 1;
        }
        if (secdat_unwrap_object_key_hex(unwrap_domain_id, entry.wrapped_object_key, object_key) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry.entry_id);
            free(encrypted);
            secdat_effective_entry_reset(&entry);
            return 1;
        }
        status = secdat_decrypt_v2_object_value_with_key(object_key, encrypted, encrypted_length, plaintext, plaintext_length);
        secdat_secure_clear(object_key, sizeof(object_key));
        free(encrypted);
        secdat_effective_entry_reset(&entry);
        return status;
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
    if (entry.from_v2
        && entry.object_domain[0] != '\0'
        && (entry.resolved_index >= chain->count || strcmp(entry.object_domain, chain->ids[entry.resolved_index]) != 0)) {
        if (secdat_domain_chain_from_id(entry.object_domain, &object_chain) != 0) {
            free(encrypted);
            secdat_effective_entry_reset(&entry);
            return 1;
        }
        decrypt_chain = &object_chain;
    }
    status = secdat_decrypt_value(decrypt_chain, encrypted, encrypted_length, plaintext, plaintext_length, access_options);
    secdat_domain_chain_free(&object_chain);
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

static int secdat_load_resolved_secret_attrs(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    struct secdat_secret_attrs *attrs,
    int *unsafe_store
)
{
    struct secdat_effective_entry entry = {0};
    int entry_is_unsafe = 0;
    int status;

    status = secdat_resolve_effective_entry(chain, store_name, key, 0, &entry);
    if (status != 0) {
        fprintf(stderr, _("key not found: %s\n"), key);
        fprintf(stderr, _("Hint: check secdat status, --dir, and --store to confirm the lookup context\n"));
        return 1;
    }

    if (entry.from_overlay) {
        entry_is_unsafe = entry.unsafe_store;
        secdat_secret_attrs_default(entry_is_unsafe, attrs);
        if (unsafe_store != NULL) {
            *unsafe_store = entry_is_unsafe;
        }
        secdat_effective_entry_reset(&entry);
        return 0;
    }
    if (entry.from_v2) {
        if (secdat_load_v2_secret_attrs(chain->ids[entry.resolved_index], store_name, &entry, attrs, &entry_is_unsafe) != 0) {
            secdat_effective_entry_reset(&entry);
            return 1;
        }
        if (unsafe_store != NULL) {
            *unsafe_store = entry_is_unsafe;
        }
        secdat_effective_entry_reset(&entry);
        return 0;
    }

    if (secdat_entry_uses_plaintext_storage(entry.path, &entry_is_unsafe) != 0) {
        secdat_effective_entry_reset(&entry);
        return 1;
    }
    if (secdat_read_secret_attrs(chain->ids[entry.resolved_index], store_name, key, entry_is_unsafe, attrs) != 0) {
        secdat_effective_entry_reset(&entry);
        return 1;
    }
    if (unsafe_store != NULL) {
        *unsafe_store = entry_is_unsafe;
    }
    secdat_effective_entry_reset(&entry);
    return 0;
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
        struct secdat_secret_attrs attrs;
        char domain_path[PATH_MAX];
        int entry_is_unsafe;

        if (secdat_resolve_effective_entry(&chain, cli->store, visible_keys.items[index], 0, &entry) != 0) {
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (entry.from_overlay) {
            entry_is_unsafe = entry.unsafe_store;
            secdat_secret_attrs_default(entry_is_unsafe, &attrs);
        } else if (entry.from_v2) {
            if (secdat_load_v2_secret_attrs(chain.ids[entry.resolved_index], cli->store, &entry, &attrs, &entry_is_unsafe) != 0) {
                secdat_effective_entry_reset(&entry);
                secdat_key_list_free(&options.include_patterns);
                secdat_key_list_free(&options.exclude_patterns);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
        } else if (secdat_entry_uses_plaintext_storage(entry.path, &entry_is_unsafe) != 0
            || secdat_read_secret_attrs(chain.ids[entry.resolved_index], cli->store, visible_keys.items[index], entry_is_unsafe, &attrs) != 0) {
            secdat_effective_entry_reset(&entry);
            secdat_key_list_free(&options.include_patterns);
            secdat_key_list_free(&options.exclude_patterns);
            secdat_domain_chain_free(&chain);
            secdat_key_list_free(&visible_keys);
            return 1;
        }

        if (filter_by_storage) {
            if ((options.safe && entry_is_unsafe) || (options.unsafe_store && !entry_is_unsafe)) {
                secdat_effective_entry_reset(&entry);
                continue;
            }
        }
        if (options.sandbox_injectable && !secdat_sandbox_inject_allows_bulk_selection(&attrs)) {
            secdat_effective_entry_reset(&entry);
            continue;
        }

        if (!options.canonical_domain && !options.canonical_store) {
            fputs(visible_keys.items[index], stdout);
            if (options.metadata) {
                printf(
                    "\tkey_visibility=%s\tvalue_access=%s\tsandbox_inject=%s",
                    secdat_key_visibility_name(attrs.key_visibility),
                    secdat_value_access_name(attrs.value_access),
                    secdat_sandbox_inject_name(attrs.sandbox_inject)
                );
            }
            fputc('\n', stdout);
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

        fputs(output, stdout);
        if (options.metadata) {
            printf(
                "\tkey_visibility=%s\tvalue_access=%s\tsandbox_inject=%s",
                secdat_key_visibility_name(attrs.key_visibility),
                secdat_value_access_name(attrs.value_access),
                secdat_sandbox_inject_name(attrs.sandbox_inject)
            );
        }
        fputc('\n', stdout);
        secdat_effective_entry_reset(&entry);
    }

    secdat_key_list_free(&options.include_patterns);
    secdat_key_list_free(&options.exclude_patterns);
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return 0;
}

int secdat_print_completion_keys(
    const char *dir_override,
    const char *domain_override,
    const char *store_name,
    const char *current,
    int append_equals
)
{
    struct secdat_cli cli = {0};
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list visible_keys = {0};
    size_t index;
    int status = 1;

    cli.dir = dir_override;
    cli.domain = domain_override;
    cli.store = store_name;

    if (cli.dir != NULL && cli.domain != NULL) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(&cli), &chain) != 0) {
        goto cleanup;
    }
    if (secdat_collect_visible_keys(&chain, cli.store, NULL, NULL, &visible_keys) != 0) {
        goto cleanup;
    }

    for (index = 0; index < visible_keys.count; index += 1) {
        const char *key = visible_keys.items[index];
        size_t key_length = strlen(key);
        size_t current_length = current != NULL ? strlen(current) : 0;

        if (current_length > key_length || strncmp(key, current, current_length) != 0) {
            continue;
        }
        fputs(key, stdout);
        if (append_equals) {
            fputc('=', stdout);
        }
        fputc('\n', stdout);
    }

    status = 0;

cleanup:
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&visible_keys);
    return status;
}

static int secdat_fsck_validate_v1_entry_file(const char *entry_path, int *unsafe_store)
{
    unsigned char *data = NULL;
    size_t length = 0;
    uint32_t payload_length;
    size_t header_length;
    int valid = 0;

    if (secdat_read_file(entry_path, &data, &length) != 0) {
        return 1;
    }

    if (length < SECDAT_HEADER_LEN) {
        goto cleanup;
    }
    if (memcmp(data, secdat_entry_magic, sizeof(secdat_entry_magic)) != 0 || data[8] != SECDAT_ENTRY_VERSION) {
        goto cleanup;
    }
    if (data[9] != SECDAT_ENTRY_ALGORITHM_PLAINTEXT && data[9] != SECDAT_ENTRY_ALGORITHM_AES_256_GCM) {
        goto cleanup;
    }

    payload_length = secdat_read_be32(data + 12);
    header_length = SECDAT_HEADER_LEN + data[10];
    if (length < header_length || length - header_length != payload_length) {
        goto cleanup;
    }
    if (data[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT && data[10] != 0) {
        goto cleanup;
    }
    if (data[9] == SECDAT_ENTRY_ALGORITHM_AES_256_GCM
        && (data[10] != SECDAT_NONCE_LEN || payload_length < SECDAT_TAG_LEN)) {
        goto cleanup;
    }

    *unsafe_store = data[9] == SECDAT_ENTRY_ALGORITHM_PLAINTEXT;
    valid = 1;

cleanup:
    secdat_secure_clear(data, length);
    free(data);
    return valid ? 0 : 1;
}

static int secdat_fsck_metadata_value_access_matches(const char *line, int unsafe_store)
{
    if (strcmp(line, "unlocked") == 0) {
        return unsafe_store ? 0 : 1;
    }
    if (strcmp(line, "always") == 0) {
        return unsafe_store ? 1 : 0;
    }
    return 0;
}

static int secdat_fsck_validate_v1_metadata_file(const char *metadata_path, int unsafe_store)
{
    unsigned char *data = NULL;
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    size_t length = 0;
    int valid = 0;

    if (!secdat_file_exists(metadata_path)) {
        return 0;
    }
    if (secdat_read_file(metadata_path, &data, &length) != 0) {
        return 1;
    }
    if (length > 4096 || memchr(data, '\0', length) != NULL) {
        goto cleanup;
    }

    text = malloc(length + 1);
    if (text == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }
    memcpy(text, data, length);
    text[length] = '\0';

    line = strtok_r(text, "\n", &saveptr);
    if (line == NULL || strcmp(line, secdat_attrs_magic) != 0) {
        goto cleanup;
    }

    valid = 1;
    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        char *separator;

        if (line[0] == '\0') {
            continue;
        }
        separator = strchr(line, '=');
        if (separator == NULL) {
            valid = 0;
            break;
        }
        *separator = '\0';
        separator += 1;

        if (strcmp(line, "key_visibility") == 0) {
            if (strcmp(separator, "always") != 0) {
                valid = 0;
                break;
            }
            continue;
        }
        if (strcmp(line, "value_access") == 0) {
            if (!secdat_fsck_metadata_value_access_matches(separator, unsafe_store)) {
                valid = 0;
                break;
            }
            continue;
        }
        if (strcmp(line, "sandbox_inject") == 0) {
            if (strcmp(separator, "never") != 0
                && strcmp(separator, "explicit") != 0
                && strcmp(separator, "bulk") != 0
                && strcmp(separator, "allow") != 0) {
                valid = 0;
                break;
            }
            continue;
        }

        valid = 0;
        break;
    }

cleanup:
    if (text != NULL) {
        secdat_secure_clear((unsigned char *)text, length);
        free(text);
    }
    secdat_secure_clear(data, length);
    free(data);
    return valid ? 0 : 1;
}

static int secdat_store_format_path(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];

    if (secdat_store_root(domain_id, store_name, store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    return secdat_join_path(buffer, size, store_root, "format");
}

static int secdat_v2_domain_entries_dir(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];

    if (secdat_store_root(domain_id, store_name, store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    return secdat_join_path(buffer, size, store_root, "domain-ent");
}

static int secdat_v2_objects_dir(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char store_root[PATH_MAX];

    if (secdat_store_root(domain_id, store_name, store_root, sizeof(store_root)) != 0) {
        return 1;
    }
    return secdat_join_path(buffer, size, store_root, "objects");
}

static int secdat_v2_secret_objects_dir(const char *domain_id, const char *store_name, char *buffer, size_t size)
{
    char objects_dir[PATH_MAX];

    if (secdat_v2_objects_dir(domain_id, store_name, objects_dir, sizeof(objects_dir)) != 0) {
        return 1;
    }
    return secdat_join_path(buffer, size, objects_dir, "secret");
}

static int secdat_read_store_format(const char *domain_id, const char *store_name, enum secdat_store_format *format)
{
    char format_path[PATH_MAX];
    unsigned char *data = NULL;
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    size_t length = 0;
    int seen_format = 0;
    int status = 1;

    *format = SECDAT_STORE_FORMAT_V1;
    if (secdat_store_format_path(domain_id, store_name, format_path, sizeof(format_path)) != 0) {
        return 1;
    }
    if (!secdat_file_exists(format_path)) {
        return 0;
    }
    *format = SECDAT_STORE_FORMAT_INVALID;

    if (secdat_read_file(format_path, &data, &length) != 0) {
        return 1;
    }
    if (length > 4096 || memchr(data, '\0', length) != NULL) {
        goto invalid;
    }

    text = malloc(length + 1);
    if (text == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }
    memcpy(text, data, length);
    text[length] = '\0';

    line = strtok_r(text, "\n", &saveptr);
    if (line == NULL || strcmp(line, secdat_store_format_magic) != 0) {
        goto invalid;
    }
    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        char *separator;

        if (line[0] == '\0') {
            continue;
        }
        separator = strchr(line, '=');
        if (separator == NULL) {
            goto invalid;
        }
        *separator = '\0';
        separator += 1;
        if (strcmp(line, "format") == 0) {
            if (seen_format) {
                goto invalid;
            }
            seen_format = 1;
            if (strcmp(separator, "v1") == 0) {
                *format = SECDAT_STORE_FORMAT_V1;
            } else if (strcmp(separator, "v2") == 0) {
                *format = SECDAT_STORE_FORMAT_V2;
            } else {
                goto invalid;
            }
            continue;
        }
        if (strcmp(line, "state") == 0) {
            if (strcmp(separator, "ready") != 0 && strcmp(separator, "migrating-v2") != 0) {
                goto invalid;
            }
            continue;
        }
        goto invalid;
    }
    if (!seen_format) {
        goto invalid;
    }
    status = 0;
    goto cleanup;

invalid:
    status = 0;

cleanup:
    if (text != NULL) {
        secdat_secure_clear((unsigned char *)text, length);
        free(text);
    }
    secdat_secure_clear(data, length);
    free(data);
    return status;
}

static int secdat_uuid_is_valid(const char *value)
{
    size_t index;

    if (value == NULL || strlen(value) != 36) {
        return 0;
    }
    for (index = 0; index < 36; index += 1) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') {
                return 0;
            }
            continue;
        }
        if (!isxdigit((unsigned char)value[index])) {
            return 0;
        }
    }
    return 1;
}

static int secdat_generate_uuid_v4(char *buffer, size_t size)
{
    unsigned char raw[16];

    if (size < 37) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        fprintf(stderr, _("failed to generate random bytes\n"));
        return 1;
    }
    raw[6] = (unsigned char)((raw[6] & 0x0f) | 0x40);
    raw[8] = (unsigned char)((raw[8] & 0x3f) | 0x80);
    snprintf(
        buffer,
        size,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        raw[0],
        raw[1],
        raw[2],
        raw[3],
        raw[4],
        raw[5],
        raw[6],
        raw[7],
        raw[8],
        raw[9],
        raw[10],
        raw[11],
        raw[12],
        raw[13],
        raw[14],
        raw[15]
    );
    secdat_secure_clear(raw, sizeof(raw));
    return 0;
}

static int secdat_parse_size_value(const char *value, size_t *parsed)
{
    char *endptr = NULL;
    unsigned long long number;

    if (value == NULL || value[0] == '\0' || value[0] == '-') {
        return 1;
    }
    errno = 0;
    number = strtoull(value, &endptr, 10);
    if (errno != 0 || endptr == value || *endptr != '\0' || number > (unsigned long long)SIZE_MAX) {
        return 1;
    }
    *parsed = (size_t)number;
    return 0;
}

static int secdat_extract_v2_secret_object_header(
    const unsigned char *data,
    size_t length,
    char **text_out,
    size_t *text_length_out,
    size_t *payload_offset_out,
    int *has_payload_out
)
{
    char *text;
    size_t index;
    size_t text_length = length;
    size_t payload_offset = length;
    int has_payload = 0;

    for (index = 0; index + 1 < length; index += 1) {
        if (data[index] == '\n' && data[index + 1] == '\n') {
            text_length = index;
            payload_offset = index + 2;
            has_payload = 1;
            break;
        }
    }

    if (text_length > SECDAT_V2_TEXT_FILE_MAX || memchr(data, '\0', text_length) != NULL) {
        return 1;
    }
    text = malloc(text_length + 1);
    if (text == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(text, data, text_length);
    text[text_length] = '\0';
    if (strncmp(text, secdat_v2_secret_object_magic, strlen(secdat_v2_secret_object_magic)) != 0
        || (text[strlen(secdat_v2_secret_object_magic)] != '\n'
            && text[strlen(secdat_v2_secret_object_magic)] != '\0')) {
        secdat_secure_clear(text, text_length);
        free(text);
        return 1;
    }

    *text_out = text;
    *text_length_out = text_length;
    *payload_offset_out = payload_offset;
    *has_payload_out = has_payload;
    return 0;
}

static int secdat_read_v2_text_file(const char *path, const char *magic, char **text_out, size_t *length_out)
{
    unsigned char *data = NULL;
    char *text = NULL;
    size_t length = 0;

    if (secdat_read_file(path, &data, &length) != 0) {
        return 1;
    }
    if (length > SECDAT_V2_TEXT_FILE_MAX || memchr(data, '\0', length) != NULL) {
        secdat_secure_clear(data, length);
        free(data);
        return 1;
    }
    text = malloc(length + 1);
    if (text == NULL) {
        secdat_secure_clear(data, length);
        free(data);
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(text, data, length);
    text[length] = '\0';
    secdat_secure_clear(data, length);
    free(data);
    if (strncmp(text, magic, strlen(magic)) != 0 || (text[strlen(magic)] != '\n' && text[strlen(magic)] != '\0')) {
        secdat_secure_clear(text, length);
        free(text);
        return 1;
    }
    *text_out = text;
    *length_out = length;
    return 0;
}

static int secdat_read_v2_domain_entry_info(const char *path, const char *file_entry_id, struct secdat_v2_domain_entry_info *info)
{
    char *text = NULL;
    char *line;
    char *saveptr = NULL;
    char *decoded_key = NULL;
    char *decoded_object_domain = NULL;
    char *decoded_object_store = NULL;
    size_t length = 0;
    int seen_entry_id = 0;
    int seen_secret_id = 0;
    int seen_key_visibility = 0;
    int seen_entry_inject = 0;
    int valid = 0;

    memset(info, 0, sizeof(*info));
    if (!secdat_uuid_is_valid(file_entry_id)
        || secdat_read_v2_text_file(path, secdat_v2_domain_entry_magic, &text, &length) != 0) {
        return 1;
    }

    line = strtok_r(text, "\n", &saveptr);
    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        char *separator;

        if (line[0] == '\0') {
            continue;
        }
        separator = strchr(line, '=');
        if (separator == NULL) {
            goto cleanup;
        }
        *separator = '\0';
        separator += 1;
        if (strcmp(line, "entry_id") == 0) {
            if (seen_entry_id || !secdat_uuid_is_valid(separator) || strcmp(separator, file_entry_id) != 0
                || secdat_copy_string(info->entry_id, sizeof(info->entry_id), separator) != 0) {
                goto cleanup;
            }
            seen_entry_id = 1;
            continue;
        }
        if (strcmp(line, "secret_id") == 0) {
            if (seen_secret_id || !secdat_uuid_is_valid(separator)
                || secdat_copy_string(info->secret_id, sizeof(info->secret_id), separator) != 0) {
                goto cleanup;
            }
            seen_secret_id = 1;
            continue;
        }
        if (strcmp(line, "key_visibility") == 0) {
            if (seen_key_visibility) {
                goto cleanup;
            }
            seen_key_visibility = 1;
            if (strcmp(separator, "always") == 0) {
                info->key_visibility = SECDAT_KEY_VISIBILITY_ALWAYS;
            } else if (strcmp(separator, "unlocked") == 0) {
                info->key_visibility = SECDAT_KEY_VISIBILITY_UNLOCKED;
            } else {
                goto cleanup;
            }
            continue;
        }
        if (strcmp(line, "object_domain") == 0) {
            if (info->has_object_domain || separator[0] == '\0'
                || secdat_unescape_component(separator, &decoded_object_domain) != 0) {
                goto cleanup;
            }
            if (decoded_object_domain[0] == '\0'
                || secdat_copy_string(info->object_domain, sizeof(info->object_domain), decoded_object_domain) != 0) {
                goto cleanup;
            }
            free(decoded_object_domain);
            decoded_object_domain = NULL;
            info->has_object_domain = 1;
            continue;
        }
        if (strcmp(line, "object_store") == 0) {
            if (info->has_object_store || separator[0] == '\0'
                || secdat_unescape_component(separator, &decoded_object_store) != 0) {
                goto cleanup;
            }
            if (decoded_object_store[0] == '\0'
                || secdat_copy_string(info->object_store, sizeof(info->object_store), decoded_object_store) != 0) {
                goto cleanup;
            }
            free(decoded_object_store);
            decoded_object_store = NULL;
            info->has_object_store = 1;
            continue;
        }
        if (strcmp(line, "key") == 0) {
            if (info->has_key || separator[0] == '\0' || secdat_unescape_component(separator, &decoded_key) != 0) {
                goto cleanup;
            }
            if (decoded_key[0] == '\0' || secdat_copy_string(info->key, sizeof(info->key), decoded_key) != 0) {
                goto cleanup;
            }
            free(decoded_key);
            decoded_key = NULL;
            info->has_key = 1;
            continue;
        }
        if (strcmp(line, "encrypted_key") == 0) {
            if (info->has_encrypted_key || separator[0] == '\0'
                || !secdat_hex_string_is_valid(separator)
                || secdat_copy_string(info->encrypted_key, sizeof(info->encrypted_key), separator) != 0) {
                goto cleanup;
            }
            info->has_encrypted_key = 1;
            continue;
        }
        if (strcmp(line, "entry_inject") == 0) {
            if (seen_entry_inject) {
                goto cleanup;
            }
            if (strcmp(separator, "never") == 0) {
                info->entry_inject = SECDAT_SANDBOX_INJECT_NEVER;
            } else if (strcmp(separator, "explicit") == 0) {
                info->entry_inject = SECDAT_SANDBOX_INJECT_EXPLICIT;
            } else if (strcmp(separator, "bulk") == 0 || strcmp(separator, "allow") == 0) {
                info->entry_inject = SECDAT_SANDBOX_INJECT_BULK;
            } else {
                goto cleanup;
            }
            seen_entry_inject = 1;
            continue;
        }
        if (strcmp(line, "wrapped_object_key") == 0) {
            if (info->has_wrapped_object_key || separator[0] == '\0'
                || !secdat_hex_string_is_valid(separator)
                || secdat_copy_string(info->wrapped_object_key, sizeof(info->wrapped_object_key), separator) != 0) {
                goto cleanup;
            }
            info->has_wrapped_object_key = 1;
            continue;
        }
        goto cleanup;
    }

    valid = seen_entry_id && seen_secret_id && seen_key_visibility && seen_entry_inject
        && ((info->key_visibility == SECDAT_KEY_VISIBILITY_ALWAYS && info->has_key && !info->has_encrypted_key)
            || (info->key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED && !info->has_key && info->has_encrypted_key));

cleanup:
    free(decoded_key);
    free(decoded_object_domain);
    free(decoded_object_store);
    secdat_secure_clear(text, length);
    free(text);
    return valid ? 0 : 1;
}

static int secdat_parse_v2_secret_object_info_text(char *text, const char *file_secret_id, struct secdat_v2_secret_object_info *info)
{
    char *line;
    char *saveptr = NULL;
    int seen_secret_id = 0;
    int seen_value_access = 0;
    int seen_secret_inject = 0;
    int valid = 0;

    memset(info, 0, sizeof(*info));
    if (!secdat_uuid_is_valid(file_secret_id)) {
        return 1;
    }

    line = strtok_r(text, "\n", &saveptr);
    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
        char *separator;

        if (line[0] == '\0') {
            continue;
        }
        separator = strchr(line, '=');
        if (separator == NULL) {
            goto cleanup;
        }
        *separator = '\0';
        separator += 1;
        if (strcmp(line, "secret_id") == 0) {
            if (seen_secret_id || !secdat_uuid_is_valid(separator) || strcmp(separator, file_secret_id) != 0
                || secdat_copy_string(info->secret_id, sizeof(info->secret_id), separator) != 0) {
                goto cleanup;
            }
            seen_secret_id = 1;
            continue;
        }
        if (strcmp(line, "value_access") == 0) {
            if (seen_value_access) {
                goto cleanup;
            }
            if (strcmp(separator, "unlocked") == 0) {
                info->value_access = SECDAT_VALUE_ACCESS_UNLOCKED;
            } else if (strcmp(separator, "always") == 0) {
                info->value_access = SECDAT_VALUE_ACCESS_ALWAYS;
            } else {
                goto cleanup;
            }
            seen_value_access = 1;
            continue;
        }
        if (strcmp(line, "secret_inject") == 0) {
            if (seen_secret_inject) {
                goto cleanup;
            }
            if (strcmp(separator, "never") == 0) {
                info->secret_inject = SECDAT_SECRET_INJECT_NEVER;
            } else if (strcmp(separator, "allow") == 0) {
                info->secret_inject = SECDAT_SECRET_INJECT_ALLOW;
            } else {
                goto cleanup;
            }
            seen_secret_inject = 1;
            continue;
        }
        if (strcmp(line, "refcount") == 0) {
            if (info->refcount_present || secdat_parse_size_value(separator, &info->refcount) != 0) {
                goto cleanup;
            }
            info->refcount_present = 1;
            continue;
        }
        if (strcmp(line, "payload_length") == 0) {
            if (info->has_value_payload || secdat_parse_size_value(separator, &info->value_payload_length) != 0) {
                goto cleanup;
            }
            info->has_value_payload = 1;
            continue;
        }
        goto cleanup;
    }

    valid = seen_secret_id && seen_value_access && seen_secret_inject;

cleanup:
    return valid ? 0 : 1;
}

static int secdat_read_v2_secret_object_info(const char *path, const char *file_secret_id, struct secdat_v2_secret_object_info *info)
{
    unsigned char *data = NULL;
    char *text = NULL;
    size_t length = 0;
    size_t text_length = 0;
    size_t payload_offset = 0;
    int has_payload = 0;
    int status = 1;

    if (secdat_read_file(path, &data, &length) != 0
        || secdat_extract_v2_secret_object_header(data, length, &text, &text_length, &payload_offset, &has_payload) != 0
        || secdat_parse_v2_secret_object_info_text(text, file_secret_id, info) != 0) {
        goto cleanup;
    }
    if (has_payload) {
        if (!info->has_value_payload || info->value_payload_length != length - payload_offset) {
            goto cleanup;
        }
    } else if (info->has_value_payload) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(text, text_length);
    free(text);
    secdat_secure_clear(data, length);
    free(data);
    return status;
}

static int secdat_read_v2_secret_object_payload(
    const char *path,
    const char *file_secret_id,
    unsigned char **payload,
    size_t *payload_length,
    int *has_payload
)
{
    unsigned char *data = NULL;
    unsigned char *copy = NULL;
    char *text = NULL;
    struct secdat_v2_secret_object_info info;
    size_t length = 0;
    size_t text_length = 0;
    size_t copy_length = 0;
    size_t payload_offset = 0;
    int file_has_payload = 0;
    int status = 1;

    *payload = NULL;
    *payload_length = 0;
    *has_payload = 0;
    if (secdat_read_file(path, &data, &length) != 0
        || secdat_extract_v2_secret_object_header(data, length, &text, &text_length, &payload_offset, &file_has_payload) != 0
        || secdat_parse_v2_secret_object_info_text(text, file_secret_id, &info) != 0) {
        goto cleanup;
    }
    if (file_has_payload) {
        if (!info.has_value_payload || info.value_payload_length != length - payload_offset) {
            goto cleanup;
        }
        copy = malloc(info.value_payload_length == 0 ? 1 : info.value_payload_length);
        if (copy == NULL) {
            fprintf(stderr, _("out of memory\n"));
            goto cleanup;
        }
        copy_length = info.value_payload_length;
        if (info.value_payload_length > 0) {
            memcpy(copy, data + payload_offset, info.value_payload_length);
        }
        *payload = copy;
        *payload_length = info.value_payload_length;
        *has_payload = 1;
        copy = NULL;
    } else if (info.has_value_payload) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(copy, copy_length);
    free(copy);
    secdat_secure_clear(text, text_length);
    free(text);
    secdat_secure_clear(data, length);
    free(data);
    return status;
}

static int secdat_validate_v2_secret_object_payload_format(const char *path, const char *file_secret_id)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int has_payload = 0;
    int status = 1;

    if (secdat_read_v2_secret_object_payload(path, file_secret_id, &payload, &payload_length, &has_payload) != 0) {
        return 1;
    }
    if (!has_payload) {
        status = 0;
        goto cleanup;
    }
    status = secdat_value_payload_format_is_valid(payload, payload_length) ? 0 : 1;

cleanup:
    secdat_secure_clear(payload, payload_length);
    free(payload);
    return status;
}

static int secdat_validate_v2_secret_value_file(const char *path)
{
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int status;

    if (secdat_read_file(path, &payload, &payload_length) != 0) {
        return 1;
    }
    status = secdat_value_payload_format_is_valid(payload, payload_length) ? 0 : 1;
    secdat_secure_clear(payload, payload_length);
    free(payload);
    return status;
}

static int secdat_validate_v2_domain_entry_file(const char *path, const char *file_entry_id, char *secret_id, size_t secret_id_size)
{
    struct secdat_v2_domain_entry_info info;

    if (secdat_read_v2_domain_entry_info(path, file_entry_id, &info) != 0) {
        return 1;
    }
    return secdat_copy_string(secret_id, secret_id_size, info.secret_id);
}

static int secdat_validate_v2_secret_object_file(const char *path, const char *file_secret_id, int *refcount_present, size_t *refcount)
{
    struct secdat_v2_secret_object_info info;

    if (secdat_read_v2_secret_object_info(path, file_secret_id, &info) != 0) {
        return 1;
    }
    if (info.has_value_payload && secdat_validate_v2_secret_object_payload_format(path, file_secret_id) != 0) {
        return 1;
    }
    *refcount_present = info.refcount_present;
    *refcount = info.refcount;
    return 0;
}

static const char *secdat_v2_entry_object_domain(
    const char *entry_domain_id,
    const struct secdat_v2_domain_entry_info *info
)
{
    return info->has_object_domain ? info->object_domain : entry_domain_id;
}

static const char *secdat_v2_entry_object_store(
    const char *entry_store_name,
    const struct secdat_v2_domain_entry_info *info
)
{
    return info->has_object_store ? info->object_store : entry_store_name;
}

static const char *secdat_effective_entry_object_store(const struct secdat_effective_entry *entry)
{
    return entry->object_store[0] == '\0' ? NULL : entry->object_store;
}

static int secdat_build_v2_domain_entry_path(const char *domain_id, const char *store_name, const char *entry_id, char *buffer, size_t size)
{
    char domain_entries_dir[PATH_MAX];

    if (secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0) {
        return 1;
    }
    if (snprintf(buffer, size, "%s/%s.dent", domain_entries_dir, entry_id) >= (int)size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    return 0;
}

static int secdat_build_v2_secret_object_path(const char *domain_id, const char *store_name, const char *secret_id, char *buffer, size_t size)
{
    char secret_objects_dir[PATH_MAX];

    if (secdat_v2_secret_objects_dir(domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0) {
        return 1;
    }
    if (snprintf(buffer, size, "%s/%s.sec", secret_objects_dir, secret_id) >= (int)size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    return 0;
}

static int secdat_build_v2_secret_value_path(const char *domain_id, const char *store_name, const char *secret_id, char *buffer, size_t size)
{
    char secret_objects_dir[PATH_MAX];

    if (secdat_v2_secret_objects_dir(domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0) {
        return 1;
    }
    if (snprintf(buffer, size, "%s/%s.value", secret_objects_dir, secret_id) >= (int)size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    return 0;
}

static int secdat_v2_domain_entry_key_access_available(const char *domain_id)
{
    struct secdat_domain_chain chain = {0};
    struct secdat_session_record record = {0};
    int available = 0;

    if (getenv("SECDAT_MASTER_KEY") != NULL && getenv("SECDAT_MASTER_KEY")[0] != '\0') {
        return 1;
    }
    if (secdat_domain_chain_from_id(domain_id, &chain) != 0) {
        return 0;
    }
    available = secdat_session_agent_status(&chain, &record) == 0;
    secdat_domain_chain_free(&chain);
    return available;
}

static int secdat_v2_encrypt_domain_entry_key(const char *domain_id, const char *key, char **encrypted_key)
{
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status = 1;

    if (secdat_encrypt_value(domain_id, (const unsigned char *)key, strlen(key), &encrypted, &encrypted_length) != 0) {
        return 1;
    }
    if (secdat_hex_encode_bytes(encrypted, encrypted_length, encrypted_key) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_v2_decrypt_domain_entry_key(const char *domain_id, struct secdat_v2_domain_entry_info *info)
{
    struct secdat_domain_chain chain = {0};
    unsigned char *encrypted = NULL;
    unsigned char *plaintext = NULL;
    size_t encrypted_length = 0;
    size_t plaintext_length = 0;
    int status = 1;

    if (info->has_key) {
        return 0;
    }
    if (info->key_visibility != SECDAT_KEY_VISIBILITY_UNLOCKED || !info->has_encrypted_key) {
        return 1;
    }
    if (secdat_hex_decode_bytes(info->encrypted_key, &encrypted, &encrypted_length) != 0) {
        return 1;
    }
    if (secdat_domain_chain_from_id(domain_id, &chain) != 0) {
        goto cleanup;
    }
    if (secdat_decrypt_value(&chain, encrypted, encrypted_length, &plaintext, &plaintext_length, NULL) != 0) {
        goto cleanup;
    }
    if (plaintext_length == 0 || plaintext_length >= sizeof(info->key)
        || memchr(plaintext, '\0', plaintext_length) != NULL) {
        goto cleanup;
    }

    memcpy(info->key, plaintext, plaintext_length);
    info->key[plaintext_length] = '\0';
    if (!secdat_is_valid_env_name(info->key)) {
        info->key[0] = '\0';
        goto cleanup;
    }
    info->has_key = 1;
    status = 0;

cleanup:
    secdat_domain_chain_free(&chain);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_v2_domain_entry_key_matches(
    const char *domain_id,
    struct secdat_v2_domain_entry_info *info,
    const char *key,
    int require_key_access,
    int *matches
)
{
    *matches = 0;
    if (info->key_visibility == SECDAT_KEY_VISIBILITY_ALWAYS) {
        *matches = info->has_key && strcmp(info->key, key) == 0;
        return 0;
    }
    if (info->key_visibility != SECDAT_KEY_VISIBILITY_UNLOCKED) {
        return 1;
    }
    if (!secdat_v2_domain_entry_key_access_available(domain_id)) {
        if (require_key_access) {
            return secdat_v2_decrypt_domain_entry_key(domain_id, info);
        }
        return 0;
    }
    if (secdat_v2_decrypt_domain_entry_key(domain_id, info) != 0) {
        return 1;
    }
    *matches = strcmp(info->key, key) == 0;
    return 0;
}

static int secdat_collect_v2_visible_keys(const char *domain_id, const char *store_name, struct secdat_key_list *keys)
{
    char domain_entries_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    struct secdat_key_list entry_ids = {0};
    struct secdat_v2_domain_entry_info info;
    size_t index;
    int status = 1;

    if (secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_collect_directory_keys(domain_entries_dir, ".dent", &entry_ids) != 0) {
        goto cleanup;
    }
    if (entry_ids.count > 1) {
        qsort(entry_ids.items, entry_ids.count, sizeof(*entry_ids.items), secdat_compare_strings);
    }

    for (index = 0; index < entry_ids.count; index += 1) {
        if (secdat_build_v2_domain_entry_path(domain_id, store_name, entry_ids.items[index], entry_path, sizeof(entry_path)) != 0) {
            goto cleanup;
        }
        if (secdat_read_v2_domain_entry_info(entry_path, entry_ids.items[index], &info) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry_ids.items[index]);
            goto cleanup;
        }
        if (info.key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED) {
            if (!secdat_v2_domain_entry_key_access_available(domain_id)) {
                continue;
            }
            if (secdat_v2_decrypt_domain_entry_key(domain_id, &info) != 0) {
                fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry_ids.items[index]);
                goto cleanup;
            }
        }
        if (info.has_key) {
            if (secdat_key_list_append(keys, info.key) != 0) {
                goto cleanup;
            }
        }
    }

    status = 0;

cleanup:
    secdat_key_list_free(&entry_ids);
    return status;
}

static int secdat_lookup_v2_domain_entry_internal(
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_v2_domain_entry_info *info,
    char *entry_path,
    size_t entry_path_size,
    int require_authoritative_absence
)
{
    char domain_entries_dir[PATH_MAX];
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list entry_ids = {0};
    size_t index;
    int key_access_available;
    int hidden_entries_inaccessible = 0;
    int found = 0;
    int status = SECDAT_V2_LOOKUP_ERROR;

    if (secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_collect_directory_keys(domain_entries_dir, ".dent", &entry_ids) != 0) {
        goto cleanup;
    }
    if (entry_ids.count > 1) {
        qsort(entry_ids.items, entry_ids.count, sizeof(*entry_ids.items), secdat_compare_strings);
    }

    key_access_available = secdat_v2_domain_entry_key_access_available(domain_id);
    for (index = 0; index < entry_ids.count; index += 1) {
        int matches = 0;

        if (secdat_build_v2_domain_entry_path(domain_id, store_name, entry_ids.items[index], entry_path, entry_path_size) != 0) {
            goto cleanup;
        }
        if (secdat_read_v2_domain_entry_info(entry_path, entry_ids.items[index], info) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry_ids.items[index]);
            goto cleanup;
        }
        if (info->key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED && !key_access_available) {
            hidden_entries_inaccessible = 1;
            continue;
        }
        if (info->key_visibility == SECDAT_KEY_VISIBILITY_ALWAYS) {
            matches = info->has_key && strcmp(info->key, key) == 0;
        } else {
            if (secdat_v2_decrypt_domain_entry_key(domain_id, info) != 0) {
                fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry_ids.items[index]);
                goto cleanup;
            }
            matches = strcmp(info->key, key) == 0;
        }
        if (matches) {
            found = 1;
            break;
        }
    }

    if (found) {
        status = SECDAT_V2_LOOKUP_FOUND;
    } else if (require_authoritative_absence && hidden_entries_inaccessible) {
        fprintf(
            stderr,
            _("missing SECDAT_MASTER_KEY and no active secdat session; run secdat unlock or export SECDAT_MASTER_KEY\n")
        );
        if (secdat_domain_chain_from_id(domain_id, &chain) == 0) {
            secdat_print_locked_read_guidance(&chain);
        }
        status = SECDAT_V2_LOOKUP_INACCESSIBLE;
    } else {
        status = SECDAT_V2_LOOKUP_ABSENT;
    }

cleanup:
    secdat_domain_chain_free(&chain);
    secdat_key_list_free(&entry_ids);
    return status;
}

static int secdat_lookup_v2_domain_entry(
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_v2_domain_entry_info *info,
    char *entry_path,
    size_t entry_path_size
)
{
    return secdat_lookup_v2_domain_entry_internal(domain_id, store_name, key, info, entry_path, entry_path_size, 0);
}

static int secdat_lookup_v2_domain_entry_authoritative(
    const char *domain_id,
    const char *store_name,
    const char *key,
    struct secdat_v2_domain_entry_info *info,
    char *entry_path,
    size_t entry_path_size
)
{
    return secdat_lookup_v2_domain_entry_internal(domain_id, store_name, key, info, entry_path, entry_path_size, 1);
}

static int secdat_load_v2_secret_attrs(
    const char *domain_id,
    const char *store_name,
    const struct secdat_effective_entry *entry,
    struct secdat_secret_attrs *attrs,
    int *unsafe_store
)
{
    char object_path[PATH_MAX];
    struct secdat_v2_secret_object_info object;
    const char *object_domain_id = entry->object_domain[0] == '\0' ? domain_id : entry->object_domain;
    const char *object_store_name = entry->object_domain[0] == '\0' ? store_name : secdat_effective_entry_object_store(entry);

    if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry->secret_id, object_path, sizeof(object_path)) != 0) {
        return 1;
    }
    if (secdat_read_v2_secret_object_info(object_path, entry->secret_id, &object) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), entry->secret_id);
        return 1;
    }

    attrs->key_visibility = entry->key_visibility;
    attrs->value_access = object.value_access;
    attrs->sandbox_inject = object.secret_inject == SECDAT_SECRET_INJECT_NEVER
        ? SECDAT_SANDBOX_INJECT_NEVER
        : entry->entry_inject;
    if (unsafe_store != NULL) {
        *unsafe_store = object.value_access == SECDAT_VALUE_ACCESS_ALWAYS;
    }
    return 0;
}

static enum secdat_secret_inject secdat_secret_inject_from_attrs(const struct secdat_secret_attrs *attrs)
{
    return attrs->sandbox_inject == SECDAT_SANDBOX_INJECT_NEVER
        ? SECDAT_SECRET_INJECT_NEVER
        : SECDAT_SECRET_INJECT_ALLOW;
}

static const char *secdat_v2_secret_inject_name(enum secdat_secret_inject value)
{
    return value == SECDAT_SECRET_INJECT_NEVER ? "never" : "allow";
}

static int secdat_sandbox_inject_allows_bulk_selection(const struct secdat_secret_attrs *attrs)
{
    return attrs->sandbox_inject == SECDAT_SANDBOX_INJECT_BULK;
}

static int secdat_v2_generate_object_key(unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN])
{
    if (RAND_bytes(object_key, SECDAT_V2_OBJECT_KEY_LEN) != 1) {
        fprintf(stderr, _("failed to generate nonce\n"));
        return 1;
    }
    return 0;
}

static int secdat_v2_wrap_object_key(
    const char *domain_id,
    const unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN],
    char **wrapped_object_key
)
{
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    int status = 1;

    if (secdat_encrypt_value(domain_id, object_key, SECDAT_V2_OBJECT_KEY_LEN, &encrypted, &encrypted_length) != 0) {
        return 1;
    }
    if (secdat_hex_encode_bytes(encrypted, encrypted_length, wrapped_object_key) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_v2_unwrap_object_key(
    const char *domain_id,
    const struct secdat_v2_domain_entry_info *info,
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN]
)
{
    if (!info->has_wrapped_object_key) {
        return 1;
    }
    return secdat_unwrap_object_key_hex(domain_id, info->wrapped_object_key, object_key);
}

static int secdat_find_v2_object_key_in_store(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN],
    int *found
)
{
    char domain_entries_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    struct secdat_key_list entry_ids = {0};
    struct secdat_v2_domain_entry_info entry;
    size_t index;
    int status = 1;

    *found = 0;
    if (secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_collect_directory_keys(domain_entries_dir, ".dent", &entry_ids) != 0) {
        goto cleanup;
    }
    for (index = 0; index < entry_ids.count; index += 1) {
        if (secdat_build_v2_domain_entry_path(domain_id, store_name, entry_ids.items[index], entry_path, sizeof(entry_path)) != 0) {
            goto cleanup;
        }
        if (secdat_read_v2_domain_entry_info(entry_path, entry_ids.items[index], &entry) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry_ids.items[index]);
            goto cleanup;
        }
        if (strcmp(entry.secret_id, secret_id) != 0
            || strcmp(secdat_v2_entry_object_domain(domain_id, &entry), domain_id) != 0
            || strcmp(secdat_effective_store_name(secdat_v2_entry_object_store(store_name, &entry)), secdat_effective_store_name(store_name)) != 0
            || !entry.has_wrapped_object_key) {
            continue;
        }
        if (secdat_v2_unwrap_object_key(domain_id, &entry, object_key) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry.entry_id);
            goto cleanup;
        }
        *found = 1;
        break;
    }
    status = 0;

cleanup:
    secdat_key_list_free(&entry_ids);
    return status;
}

static int secdat_get_or_create_v2_object_key_in_store(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN]
)
{
    int found = 0;

    if (secdat_find_v2_object_key_in_store(domain_id, store_name, secret_id, object_key, &found) != 0) {
        return 1;
    }
    if (found) {
        return 0;
    }
    return secdat_v2_generate_object_key(object_key);
}

static int secdat_write_v2_domain_entry_file(
    const char *domain_id,
    const char *domain_entries_dir,
    const char *entry_id,
    const char *secret_id,
    const char *object_domain_id,
    const char *object_store_name,
    const char *key,
    const struct secdat_secret_attrs *attrs,
    const unsigned char *object_key,
    char *path_out,
    size_t path_out_size
)
{
    char *payload = NULL;
    char *encoded_key = NULL;
    char *encoded_object_domain = NULL;
    char *encoded_object_store = NULL;
    char *encrypted_key = NULL;
    char *wrapped_object_key = NULL;
    const char *effective_object_domain = object_domain_id != NULL ? object_domain_id : domain_id;
    const char *effective_object_store = secdat_effective_store_name(object_store_name);
    const char *key_field_name = NULL;
    const char *key_field_value = NULL;
    size_t payload_size;
    int written;
    int status = 1;

    if (snprintf(path_out, path_out_size, "%s/%s.dent", domain_entries_dir, entry_id) >= (int)path_out_size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    if (secdat_escape_component(effective_object_domain, &encoded_object_domain) != 0
        || secdat_escape_component(effective_object_store, &encoded_object_store) != 0) {
        goto cleanup;
    }
    if (attrs->key_visibility == SECDAT_KEY_VISIBILITY_ALWAYS) {
        if (secdat_escape_component(key, &encoded_key) != 0) {
            goto cleanup;
        }
        key_field_name = "key";
        key_field_value = encoded_key;
    } else if (attrs->key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED) {
        if (secdat_v2_encrypt_domain_entry_key(domain_id, key, &encrypted_key) != 0) {
            goto cleanup;
        }
        key_field_name = "encrypted_key";
        key_field_value = encrypted_key;
    } else {
        fprintf(stderr, _("invalid key visibility: %s\n"), secdat_key_visibility_name(attrs->key_visibility));
        goto cleanup;
    }
    if (object_key != NULL && secdat_v2_wrap_object_key(domain_id, object_key, &wrapped_object_key) != 0) {
        goto cleanup;
    }
    payload_size = strlen(secdat_v2_domain_entry_magic)
        + strlen(entry_id)
        + strlen(secret_id)
        + strlen(encoded_object_domain)
        + strlen(encoded_object_store)
        + strlen(secdat_key_visibility_name(attrs->key_visibility))
        + strlen(key_field_name)
        + strlen(key_field_value)
        + strlen(secdat_sandbox_inject_name(attrs->sandbox_inject))
        + strlen("object_domain") + strlen("object_store") + 4
        + (wrapped_object_key == NULL ? 0 : strlen(wrapped_object_key) + strlen("wrapped_object_key") + 2)
        + 128;
    payload = malloc(payload_size);
    if (payload == NULL) {
        fprintf(stderr, _("out of memory\n"));
        goto cleanup;
    }
    payload[0] = '\0';
    if (wrapped_object_key != NULL) {
        written = snprintf(
            payload,
            payload_size,
            "%s\nentry_id=%s\nsecret_id=%s\nobject_domain=%s\nobject_store=%s\nkey_visibility=%s\n%s=%s\nentry_inject=%s\nwrapped_object_key=%s\n",
            secdat_v2_domain_entry_magic,
            entry_id,
            secret_id,
            encoded_object_domain,
            encoded_object_store,
            secdat_key_visibility_name(attrs->key_visibility),
            key_field_name,
            key_field_value,
            secdat_sandbox_inject_name(attrs->sandbox_inject),
            wrapped_object_key
        );
    } else {
        written = snprintf(
            payload,
            payload_size,
            "%s\nentry_id=%s\nsecret_id=%s\nobject_domain=%s\nobject_store=%s\nkey_visibility=%s\n%s=%s\nentry_inject=%s\n",
            secdat_v2_domain_entry_magic,
            entry_id,
            secret_id,
            encoded_object_domain,
            encoded_object_store,
            secdat_key_visibility_name(attrs->key_visibility),
            key_field_name,
            key_field_value,
            secdat_sandbox_inject_name(attrs->sandbox_inject)
        );
    }
    if (written < 0 || (size_t)written >= payload_size) {
        fprintf(stderr, _("secret metadata is too large\n"));
        goto cleanup;
    }
    status = secdat_atomic_write_file(path_out, (const unsigned char *)payload, (size_t)written);

cleanup:
    if (payload != NULL) {
        secdat_secure_clear(payload, strlen(payload));
        free(payload);
    }
    free(encoded_key);
    free(encoded_object_domain);
    free(encoded_object_store);
    free(encrypted_key);
    if (wrapped_object_key != NULL) {
        secdat_secure_clear(wrapped_object_key, strlen(wrapped_object_key));
        free(wrapped_object_key);
    }
    return status;
}

static int secdat_write_v2_secret_object_file_with_inject(
    const char *secret_objects_dir,
    const char *secret_id,
    const struct secdat_secret_attrs *attrs,
    enum secdat_secret_inject secret_inject,
    int refcount_present,
    size_t refcount,
    const unsigned char *payload,
    size_t payload_length,
    char *path_out,
    size_t path_out_size
)
{
    char header[512];
    unsigned char *file_payload = NULL;
    size_t header_length;
    size_t file_payload_length;
    int written;

    if (snprintf(path_out, path_out_size, "%s/%s.sec", secret_objects_dir, secret_id) >= (int)path_out_size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    if (refcount_present) {
        written = snprintf(
            header,
            sizeof(header),
            payload != NULL
                ? "%s\nsecret_id=%s\nvalue_access=%s\nsecret_inject=%s\nrefcount=%zu\npayload_length=%zu\n\n"
                : "%s\nsecret_id=%s\nvalue_access=%s\nsecret_inject=%s\nrefcount=%zu\n",
            secdat_v2_secret_object_magic,
            secret_id,
            secdat_value_access_name(attrs->value_access),
            secdat_v2_secret_inject_name(secret_inject),
            refcount,
            payload_length
        );
    } else {
        written = snprintf(
            header,
            sizeof(header),
            payload != NULL
                ? "%s\nsecret_id=%s\nvalue_access=%s\nsecret_inject=%s\npayload_length=%zu\n\n"
                : "%s\nsecret_id=%s\nvalue_access=%s\nsecret_inject=%s\n",
            secdat_v2_secret_object_magic,
            secret_id,
            secdat_value_access_name(attrs->value_access),
            secdat_v2_secret_inject_name(secret_inject),
            payload_length
        );
    }
    if (written < 0 || (size_t)written >= sizeof(header)) {
        fprintf(stderr, _("secret metadata is too large\n"));
        return 1;
    }
    header_length = (size_t)written;
    if (payload == NULL) {
        return secdat_atomic_write_file(path_out, (const unsigned char *)header, header_length);
    }
    if (payload_length > SIZE_MAX - header_length) {
        fprintf(stderr, _("secret metadata is too large\n"));
        return 1;
    }
    file_payload_length = header_length + payload_length;
    file_payload = malloc(file_payload_length == 0 ? 1 : file_payload_length);
    if (file_payload == NULL) {
        fprintf(stderr, _("out of memory\n"));
        return 1;
    }
    memcpy(file_payload, header, header_length);
    if (payload_length > 0) {
        memcpy(file_payload + header_length, payload, payload_length);
    }
    written = secdat_atomic_write_file(path_out, file_payload, file_payload_length);
    secdat_secure_clear(file_payload, file_payload_length);
    free(file_payload);
    return written;
}

static int secdat_write_v2_secret_object_file(
    const char *secret_objects_dir,
    const char *secret_id,
    const struct secdat_secret_attrs *attrs,
    int refcount_present,
    size_t refcount,
    const unsigned char *payload,
    size_t payload_length,
    char *path_out,
    size_t path_out_size
)
{
    return secdat_write_v2_secret_object_file_with_inject(
        secret_objects_dir,
        secret_id,
        attrs,
        secdat_secret_inject_from_attrs(attrs),
        refcount_present,
        refcount,
        payload,
        payload_length,
        path_out,
        path_out_size
    );
}

static int secdat_update_v2_secret_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    const struct secdat_effective_entry *entry,
    const struct secdat_secret_attrs *attrs
)
{
    char domain_entries_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    struct secdat_v2_domain_entry_info domain_entry;
    struct secdat_v2_secret_object_info object;
    char *encrypted_key_probe = NULL;
    unsigned char *payload = NULL;
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN];
    const unsigned char *object_key_ptr = NULL;
    const char *object_domain_id = entry->object_domain[0] == '\0' ? domain_id : entry->object_domain;
    const char *object_store_name = entry->object_domain[0] == '\0' ? store_name : secdat_effective_entry_object_store(entry);
    size_t payload_length = 0;
    int has_payload = 0;
    int key_matches = 0;
    int status = 1;

    if (secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_v2_secret_objects_dir(object_domain_id, object_store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0
        || secdat_build_v2_domain_entry_path(domain_id, store_name, entry->entry_id, entry_path, sizeof(entry_path)) != 0
        || secdat_read_v2_domain_entry_info(entry_path, entry->entry_id, &domain_entry) != 0) {
        return 1;
    }
    if (strcmp(domain_entry.secret_id, entry->secret_id) != 0
        || domain_entry.key_visibility != entry->key_visibility
        || secdat_v2_domain_entry_key_matches(domain_id, &domain_entry, key, 1, &key_matches) != 0
        || !key_matches) {
        fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry->entry_id);
        return 1;
    }

    if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry->secret_id, object_path, sizeof(object_path)) != 0
        || secdat_read_v2_secret_object_info(object_path, entry->secret_id, &object) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), entry->secret_id);
        return 1;
    }
    if (secdat_read_v2_secret_object_payload(object_path, entry->secret_id, &payload, &payload_length, &has_payload) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), entry->secret_id);
        return 1;
    }
    if (object.secret_inject == SECDAT_SECRET_INJECT_NEVER && attrs->sandbox_inject != SECDAT_SANDBOX_INJECT_NEVER) {
        fprintf(stderr, _("secret object forbids sandbox injection: %s\n"), key);
        goto cleanup;
    }
    if (attrs->key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED) {
        if (secdat_v2_encrypt_domain_entry_key(domain_id, key, &encrypted_key_probe) != 0) {
            goto cleanup;
        }
        free(encrypted_key_probe);
        encrypted_key_probe = NULL;
    }
    if (attrs->value_access == SECDAT_VALUE_ACCESS_UNLOCKED) {
        if (domain_entry.has_wrapped_object_key) {
            if (secdat_v2_unwrap_object_key(domain_id, &domain_entry, object_key) != 0) {
                fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry->entry_id);
                goto cleanup;
            }
        } else if (secdat_get_or_create_v2_object_key_in_store(object_domain_id, object_store_name, entry->secret_id, object_key) != 0) {
            goto cleanup;
        }
        object_key_ptr = object_key;
    }

    if (secdat_write_v2_secret_object_file_with_inject(
            secret_objects_dir,
            entry->secret_id,
            attrs,
            object.secret_inject,
            object.refcount_present,
            object.refcount,
            has_payload ? payload : NULL,
            has_payload ? payload_length : 0,
            object_path,
            sizeof(object_path)
        ) != 0
        || secdat_write_v2_domain_entry_file(
            domain_id,
            domain_entries_dir,
            entry->entry_id,
            entry->secret_id,
            object_domain_id,
            object_store_name,
            key,
            attrs,
            object_key_ptr,
            entry_path,
            sizeof(entry_path)
        ) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    if (object_key_ptr != NULL) {
        secdat_secure_clear(object_key, sizeof(object_key));
    }
    secdat_secure_clear(payload, payload_length);
    free(payload);
    free(encrypted_key_probe);
    return status;
}

static int secdat_store_v2_plaintext_with_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
)
{
    char domain_entries_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    char value_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    char entry_id[37];
    char secret_id[37];
    struct secdat_secret_attrs write_attrs;
    struct secdat_v2_domain_entry_info entry;
    struct secdat_v2_secret_object_info object;
    unsigned char *encrypted = NULL;
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN];
    const unsigned char *object_key_ptr = NULL;
    char *encrypted_key_probe = NULL;
    size_t encrypted_length = 0;
    const char *object_domain_id = domain_id;
    const char *object_store_name = store_name;
    enum secdat_secret_inject target_secret_inject;
    int refcount_present = 1;
    size_t refcount = 1;
    int lookup_status;
    int status = 1;

    if (attrs != NULL) {
        write_attrs = *attrs;
    } else {
        secdat_secret_attrs_default(unsafe_store, &write_attrs);
    }
    if (!secdat_v2_secret_attrs_supported(&write_attrs)) {
        return 1;
    }
    target_secret_inject = secdat_secret_inject_from_attrs(&write_attrs);
    if ((write_attrs.value_access == SECDAT_VALUE_ACCESS_ALWAYS) != (unsafe_store != 0)) {
        fprintf(stderr, _("secret value_access does not match storage mode\n"));
        return 1;
    }
    if (secdat_ensure_store_dirs(domain_id, store_name) != 0
        || secdat_v2_domain_entries_dir(domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_v2_secret_objects_dir(domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0
        || secdat_ensure_directory(domain_entries_dir, 0700) != 0
        || secdat_ensure_directory(secret_objects_dir, 0700) != 0) {
        return 1;
    }

    lookup_status = secdat_lookup_v2_domain_entry_authoritative(domain_id, store_name, key, &entry, entry_path, sizeof(entry_path));
    if (lookup_status > 1) {
        return 1;
    }
    if (lookup_status == 0) {
        object_domain_id = secdat_v2_entry_object_domain(domain_id, &entry);
        object_store_name = secdat_v2_entry_object_store(store_name, &entry);
        if (secdat_copy_string(entry_id, sizeof(entry_id), entry.entry_id) != 0
            || secdat_copy_string(secret_id, sizeof(secret_id), entry.secret_id) != 0
            || secdat_build_v2_secret_object_path(object_domain_id, object_store_name, secret_id, object_path, sizeof(object_path)) != 0
            || secdat_read_v2_secret_object_info(object_path, secret_id, &object) != 0) {
            fprintf(stderr, _("invalid v2 secret object: %s\n"), entry.secret_id);
            return 1;
        }
        refcount_present = object.refcount_present;
        refcount = object.refcount;
        if (object.secret_inject == SECDAT_SECRET_INJECT_NEVER && target_secret_inject != SECDAT_SECRET_INJECT_NEVER) {
            fprintf(stderr, _("secret object forbids sandbox injection: %s\n"), key);
            return 1;
        }
        if (write_attrs.value_access == SECDAT_VALUE_ACCESS_UNLOCKED) {
            if (entry.has_wrapped_object_key) {
                if (secdat_v2_unwrap_object_key(domain_id, &entry, object_key) != 0) {
                    fprintf(stderr, _("invalid v2 domain entry: %s\n"), entry.entry_id);
                    return 1;
                }
            } else if (secdat_get_or_create_v2_object_key_in_store(object_domain_id, object_store_name, secret_id, object_key) != 0) {
                return 1;
            }
            object_key_ptr = object_key;
        }
    } else {
        if (secdat_generate_uuid_v4(entry_id, sizeof(entry_id)) != 0
            || secdat_generate_uuid_v4(secret_id, sizeof(secret_id)) != 0) {
            return 1;
        }
        if (snprintf(entry_path, sizeof(entry_path), "%s/%s.dent", domain_entries_dir, entry_id) >= (int)sizeof(entry_path)
            || snprintf(object_path, sizeof(object_path), "%s/%s.sec", secret_objects_dir, secret_id) >= (int)sizeof(object_path)) {
            fprintf(stderr, _("path is too long\n"));
            return 1;
        }
        if (write_attrs.value_access == SECDAT_VALUE_ACCESS_UNLOCKED) {
            if (secdat_v2_generate_object_key(object_key) != 0) {
                return 1;
            }
            object_key_ptr = object_key;
        }
    }

    if (secdat_v2_secret_objects_dir(object_domain_id, object_store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0
        || secdat_build_v2_secret_value_path(object_domain_id, object_store_name, secret_id, value_path, sizeof(value_path)) != 0
        || secdat_build_tombstone_path(domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0
        || secdat_encode_v2_value_for_storage(object_key_ptr, plaintext, plaintext_length, unsafe_store, &encrypted, &encrypted_length) != 0) {
        goto cleanup;
    }
    if (write_attrs.key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED
        && secdat_v2_encrypt_domain_entry_key(domain_id, key, &encrypted_key_probe) != 0) {
        goto cleanup;
    }
    free(encrypted_key_probe);
    encrypted_key_probe = NULL;

    if (secdat_remove_if_exists(tombstone_path) != 0
        || secdat_write_v2_secret_object_file_with_inject(
            secret_objects_dir,
            secret_id,
            &write_attrs,
            target_secret_inject,
            refcount_present,
            refcount,
            encrypted,
            encrypted_length,
            object_path,
            sizeof(object_path)
        ) != 0
        || secdat_write_v2_domain_entry_file(
            domain_id,
            domain_entries_dir,
            entry_id,
            secret_id,
            object_domain_id,
            object_store_name,
            key,
            &write_attrs,
            object_key_ptr,
            entry_path,
            sizeof(entry_path)
        ) != 0) {
        goto cleanup;
    }
    if (secdat_remove_if_exists(value_path) != 0) {
        goto cleanup;
    }
    status = 0;

cleanup:
    free(encrypted_key_probe);
    if (object_key_ptr != NULL) {
        secdat_secure_clear(object_key, sizeof(object_key));
    }
    secdat_secure_clear(encrypted, encrypted_length);
    free(encrypted);
    return status;
}

static int secdat_write_store_format_marker(const char *domain_id, const char *store_name, const char *format, const char *state)
{
    char format_path[PATH_MAX];
    char payload[128];
    int written;

    if (secdat_store_format_path(domain_id, store_name, format_path, sizeof(format_path)) != 0) {
        return 1;
    }
    written = snprintf(payload, sizeof(payload), "%s\nformat=%s\nstate=%s\n", secdat_store_format_magic, format, state);
    if (written < 0 || (size_t)written >= sizeof(payload)) {
        fprintf(stderr, _("secret metadata is too large\n"));
        return 1;
    }
    return secdat_atomic_write_file(format_path, (const unsigned char *)payload, (size_t)written);
}

static void secdat_fsck_report_issue(struct secdat_fsck_report *report, const char *kind, const char *key, const char *detail)
{
    printf("%s\t%s\t%s\n", kind, key, detail);
    report->issues += 1;
}

static void secdat_fsck_report_repair(struct secdat_fsck_report *report, const char *kind, const char *key, const char *detail)
{
    printf("%s\t%s\t%s\n", kind, key, detail);
    report->repairs += 1;
}

static void secdat_gc_report_removal(struct secdat_gc_report *report, int dry_run, const char *kind, const char *key, const char *detail)
{
    printf("%s-%s\t%s\t%s\n", dry_run ? "would-remove" : "removed", kind, key, detail);
    report->removals += 1;
}

static int secdat_gc_build_v2_artifact_path(const char *directory, const char *name, const char *suffix, char *buffer, size_t size)
{
    if (snprintf(buffer, size, "%s/%s%s", directory, name, suffix) >= (int)size) {
        fprintf(stderr, _("path is too long\n"));
        return 1;
    }
    return 0;
}

static int secdat_gc_remove_v2_domain_entry(const char *domain_entries_dir, const char *entry_id)
{
    char entry_path[PATH_MAX];

    if (secdat_gc_build_v2_artifact_path(domain_entries_dir, entry_id, ".dent", entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    return secdat_remove_if_exists(entry_path);
}

static int secdat_gc_remove_v2_secret_artifacts(const char *secret_objects_dir, const char *secret_id)
{
    char object_path[PATH_MAX];
    char value_path[PATH_MAX];

    if (secdat_gc_build_v2_artifact_path(secret_objects_dir, secret_id, ".sec", object_path, sizeof(object_path)) != 0
        || secdat_gc_build_v2_artifact_path(secret_objects_dir, secret_id, ".value", value_path, sizeof(value_path)) != 0) {
        return 1;
    }
    if (secdat_remove_if_exists(object_path) != 0
        || secdat_remove_if_exists(value_path) != 0) {
        return 1;
    }
    return 0;
}

static int secdat_fsck_v1_store(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_fsck_options *options,
    struct secdat_fsck_report *report
)
{
    char entries_dir[PATH_MAX];
    char tombstones_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char metadata_path[PATH_MAX];
    struct secdat_key_list entries = {0};
    struct secdat_key_list metadata = {0};
    struct secdat_key_list tombstones = {0};
    const char *current_domain_id;
    enum secdat_store_format format;
    size_t index;
    int unsafe_store = 0;
    int parent_visible;
    int status = 1;

    memset(report, 0, sizeof(*report));
    if (chain->count == 0) {
        fprintf(stderr, _("fsck requires a registered current domain\n"));
        return 1;
    }
    current_domain_id = chain->ids[0];
    if (secdat_read_store_format(current_domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("store format is v2; use --format v2\n"));
        return 2;
    }

    if (secdat_store_entries_dir(current_domain_id, store_name, entries_dir, sizeof(entries_dir)) != 0
        || secdat_store_tombstones_dir(current_domain_id, store_name, tombstones_dir, sizeof(tombstones_dir)) != 0) {
        return 1;
    }
    if (secdat_collect_directory_keys(entries_dir, ".sec", &entries) != 0
        || secdat_collect_directory_keys(entries_dir, ".meta", &metadata) != 0
        || secdat_collect_directory_keys(tombstones_dir, ".tomb", &tombstones) != 0) {
        goto cleanup;
    }

    report->entries = entries.count;
    report->metadata = metadata.count;
    report->tombstones = tombstones.count;

    if (options->dangling) {
        for (index = 0; index < entries.count; index += 1) {
            if (secdat_build_entry_path(current_domain_id, store_name, entries.items[index], entry_path, sizeof(entry_path)) != 0
                || secdat_build_entry_metadata_path(current_domain_id, store_name, entries.items[index], metadata_path, sizeof(metadata_path)) != 0) {
                goto cleanup;
            }
            if (secdat_fsck_validate_v1_entry_file(entry_path, &unsafe_store) != 0) {
                secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "invalid-entry");
                continue;
            }
            if (secdat_fsck_validate_v1_metadata_file(metadata_path, unsafe_store) != 0) {
                secdat_fsck_report_issue(report, "dangling-metadata", entries.items[index], "invalid-metadata");
            }
        }
    }

    if (options->orphaned) {
        for (index = 0; index < metadata.count; index += 1) {
            if (!secdat_key_list_contains(&entries, metadata.items[index])) {
                secdat_fsck_report_issue(report, "orphaned-metadata", metadata.items[index], "missing-entry");
            }
        }
        for (index = 0; index < tombstones.count; index += 1) {
            parent_visible = secdat_parent_has_visible_key(chain, store_name, tombstones.items[index]);
            if (!parent_visible) {
                secdat_fsck_report_issue(report, "orphaned-tombstone", tombstones.items[index], "missing-parent");
            }
        }
    }

    status = 0;

cleanup:
    secdat_key_list_free(&entries);
    secdat_key_list_free(&metadata);
    secdat_key_list_free(&tombstones);
    return status;
}

static int secdat_fsck_v2_store(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_fsck_options *options,
    struct secdat_fsck_report *report
)
{
    char domain_entries_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    char detail[128];
    struct secdat_key_list entries = {0};
    struct secdat_key_list objects = {0};
    struct secdat_key_list values = {0};
    struct secdat_key_list valid_objects = {0};
    struct secdat_key_list seen_entry_keys = {0};
    struct secdat_key_list duplicate_entry_keys = {0};
    struct secdat_v2_domain_entry_info entry_info;
    enum secdat_store_format format;
    const char *current_domain_id;
    size_t index;
    size_t actual_refcount;
    size_t cached_refcount;
    int refcount_present;
    int status = 1;

    memset(report, 0, sizeof(*report));
    if (chain->count == 0) {
        fprintf(stderr, _("fsck requires a registered current domain\n"));
        return 1;
    }
    current_domain_id = chain->ids[0];
    if (secdat_read_store_format(current_domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format != SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("store format is v1; use --format v1\n"));
        secdat_print_store_migration_hint("secdat", store_name);
        return 2;
    }

    if (secdat_v2_domain_entries_dir(current_domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_v2_secret_objects_dir(current_domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0) {
        return 1;
    }
    if (secdat_collect_directory_keys(domain_entries_dir, ".dent", &entries) != 0
        || secdat_collect_directory_keys(secret_objects_dir, ".sec", &objects) != 0
        || secdat_collect_directory_keys(secret_objects_dir, ".value", &values) != 0) {
        goto cleanup;
    }
    if (entries.count > 1) {
        qsort(entries.items, entries.count, sizeof(*entries.items), secdat_compare_strings);
    }
    if (objects.count > 1) {
        qsort(objects.items, objects.count, sizeof(*objects.items), secdat_compare_strings);
    }
    if (values.count > 1) {
        qsort(values.items, values.count, sizeof(*values.items), secdat_compare_strings);
    }

    report->entries = entries.count;
    report->secret_objects = objects.count;

    for (index = 0; index < objects.count; index += 1) {
        if (!secdat_uuid_is_valid(objects.items[index])) {
            if (options->dangling) {
                secdat_fsck_report_issue(report, "dangling-secret", objects.items[index], "invalid-secret");
            }
            continue;
        }
        if (snprintf(object_path, sizeof(object_path), "%s/%s.sec", secret_objects_dir, objects.items[index]) >= (int)sizeof(object_path)) {
            fprintf(stderr, _("path is too long\n"));
            goto cleanup;
        }
        if (secdat_validate_v2_secret_object_file(object_path, objects.items[index], &refcount_present, &cached_refcount) != 0) {
            if (options->dangling) {
                secdat_fsck_report_issue(report, "dangling-secret", objects.items[index], "invalid-secret");
            }
            continue;
        }
        if (secdat_key_list_append(&valid_objects, objects.items[index]) != 0) {
            goto cleanup;
        }
    }

    for (index = 0; index < values.count; index += 1) {
        if (secdat_key_list_contains(&objects, values.items[index])) {
            continue;
        }
        if (!secdat_uuid_is_valid(values.items[index])) {
            if (options->dangling) {
                secdat_fsck_report_issue(report, "dangling-value", values.items[index], "invalid-value");
            }
            continue;
        }
        if (options->dangling) {
            secdat_fsck_report_issue(report, "dangling-value", values.items[index], "missing-secret");
        } else if (options->orphaned) {
            secdat_fsck_report_issue(report, "orphaned-value", values.items[index], "missing-secret");
        }
    }

    for (index = 0; index < entries.count; index += 1) {
        if (!secdat_uuid_is_valid(entries.items[index])) {
            if (options->dangling) {
                secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "invalid-entry");
            }
            continue;
        }
        if (snprintf(entry_path, sizeof(entry_path), "%s/%s.dent", domain_entries_dir, entries.items[index]) >= (int)sizeof(entry_path)) {
            fprintf(stderr, _("path is too long\n"));
            goto cleanup;
        }
        if (secdat_read_v2_domain_entry_info(entry_path, entries.items[index], &entry_info) != 0) {
            if (options->dangling) {
                secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "invalid-entry");
            }
            continue;
        }
        if (options->dangling
            && entry_info.key_visibility == SECDAT_KEY_VISIBILITY_UNLOCKED
            && secdat_v2_domain_entry_key_access_available(current_domain_id)
            && secdat_v2_decrypt_domain_entry_key(current_domain_id, &entry_info) != 0) {
            secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "invalid-entry");
            continue;
        }
        if (options->dangling && entry_info.has_key) {
            if (secdat_key_list_contains(&seen_entry_keys, entry_info.key)) {
                if (!secdat_key_list_contains(&duplicate_entry_keys, entry_info.key)) {
                    secdat_fsck_report_issue(report, "duplicate-key", entry_info.key, "multiple-entries");
                    if (secdat_key_list_append(&duplicate_entry_keys, entry_info.key) != 0) {
                        goto cleanup;
                    }
                }
            } else if (secdat_key_list_append(&seen_entry_keys, entry_info.key) != 0) {
                goto cleanup;
            }
        }
        {
            const char *object_domain_id = secdat_v2_entry_object_domain(current_domain_id, &entry_info);
            const char *object_store_name = secdat_v2_entry_object_store(store_name, &entry_info);
            int object_is_local = strcmp(object_domain_id, current_domain_id) == 0
                && strcmp(secdat_effective_store_name(object_store_name), secdat_effective_store_name(store_name)) == 0;

            if (object_is_local) {
                if (options->dangling && !secdat_key_list_contains(&valid_objects, entry_info.secret_id)) {
                    secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "missing-secret");
                }
            } else if (options->dangling) {
                if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry_info.secret_id, object_path, sizeof(object_path)) != 0
                    || secdat_validate_v2_secret_object_file(object_path, entry_info.secret_id, &refcount_present, &cached_refcount) != 0) {
                    secdat_fsck_report_issue(report, "dangling-entry", entries.items[index], "missing-secret");
                }
            }
        }
    }

    if (options->orphaned) {
        for (index = 0; index < valid_objects.count; index += 1) {
            if (secdat_count_v2_secret_references_to_object(current_domain_id, store_name, valid_objects.items[index], &actual_refcount) != 0) {
                goto cleanup;
            }
            if (actual_refcount == 0) {
                secdat_fsck_report_issue(report, "orphaned-secret", valid_objects.items[index], "missing-entry");
            }
        }
    }

    if (options->refcount) {
        for (index = 0; index < valid_objects.count; index += 1) {
            if (snprintf(object_path, sizeof(object_path), "%s/%s.sec", secret_objects_dir, valid_objects.items[index]) >= (int)sizeof(object_path)) {
                fprintf(stderr, _("path is too long\n"));
                goto cleanup;
            }
            if (secdat_validate_v2_secret_object_file(object_path, valid_objects.items[index], &refcount_present, &cached_refcount) != 0) {
                goto cleanup;
            }
            if (!refcount_present) {
                continue;
            }
            if (secdat_count_v2_secret_references_to_object(current_domain_id, store_name, valid_objects.items[index], &actual_refcount) != 0) {
                goto cleanup;
            }
            if (cached_refcount != actual_refcount) {
                snprintf(detail, sizeof(detail), "expected=%zu actual=%zu", cached_refcount, actual_refcount);
                if (options->repair) {
                    if (secdat_update_v2_secret_refcount(current_domain_id, store_name, valid_objects.items[index], actual_refcount) != 0) {
                        goto cleanup;
                    }
                    secdat_fsck_report_repair(report, "repaired-refcount", valid_objects.items[index], detail);
                } else {
                    secdat_fsck_report_issue(report, "refcount-mismatch", valid_objects.items[index], detail);
                }
            }
        }
    }

    status = 0;

cleanup:
    secdat_key_list_free(&entries);
    secdat_key_list_free(&objects);
    secdat_key_list_free(&values);
    secdat_key_list_free(&valid_objects);
    secdat_key_list_free(&seen_entry_keys);
    secdat_key_list_free(&duplicate_entry_keys);
    return status;
}

static int secdat_command_fsck(const struct secdat_cli *cli)
{
    struct secdat_fsck_options options;
    struct secdat_fsck_report report;
    struct secdat_domain_chain chain = {0};
    int status;

    status = secdat_parse_fsck_options(cli, &options);
    if (status != 0) {
        return status;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (options.repair
        && (secdat_require_mutable_session_chain(&chain, "fsck --repair") != 0
            || secdat_require_writable_domain_chain(&chain) != 0)) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (strcmp(options.format, "v2") == 0) {
        status = secdat_fsck_v2_store(&chain, cli->store, &options, &report);
    } else {
        status = secdat_fsck_v1_store(&chain, cli->store, &options, &report);
    }
    secdat_domain_chain_free(&chain);
    if (status != 0) {
        return status;
    }
    if (report.issues == 0) {
        if (report.repairs != 0) {
            return 0;
        }
        puts("ok");
        return 0;
    }

    return 1;
}

static int secdat_gc_v2_store(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const struct secdat_gc_options *options,
    struct secdat_gc_report *report
)
{
    char domain_entries_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    struct secdat_key_list entries = {0};
    struct secdat_key_list objects = {0};
    struct secdat_key_list values = {0};
    struct secdat_key_list valid_objects = {0};
    struct secdat_v2_domain_entry_info entry_info;
    enum secdat_store_format format;
    const char *current_domain_id;
    size_t index;
    size_t actual_refcount;
    size_t cached_refcount;
    int refcount_present;
    int status = 1;

    memset(report, 0, sizeof(*report));
    if (chain->count == 0) {
        fprintf(stderr, _("gc requires a registered current domain\n"));
        return 1;
    }
    if (!options->dry_run && secdat_require_mutable_session_chain(chain, "gc") != 0) {
        return 1;
    }
    current_domain_id = chain->ids[0];
    if (secdat_read_store_format(current_domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format != SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("store format is v1; gc requires --format v2\n"));
        secdat_print_store_migration_hint("secdat", store_name);
        return 2;
    }

    if (secdat_v2_domain_entries_dir(current_domain_id, store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_v2_secret_objects_dir(current_domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0) {
        return 1;
    }
    if (secdat_collect_directory_keys(domain_entries_dir, ".dent", &entries) != 0
        || secdat_collect_directory_keys(secret_objects_dir, ".sec", &objects) != 0
        || secdat_collect_directory_keys(secret_objects_dir, ".value", &values) != 0) {
        goto cleanup;
    }
    if (entries.count > 1) {
        qsort(entries.items, entries.count, sizeof(*entries.items), secdat_compare_strings);
    }
    if (objects.count > 1) {
        qsort(objects.items, objects.count, sizeof(*objects.items), secdat_compare_strings);
    }
    if (values.count > 1) {
        qsort(values.items, values.count, sizeof(*values.items), secdat_compare_strings);
    }

    for (index = 0; index < objects.count; index += 1) {
        int invalid_object = 0;

        if (!secdat_uuid_is_valid(objects.items[index])) {
            invalid_object = 1;
        } else if (snprintf(object_path, sizeof(object_path), "%s/%s.sec", secret_objects_dir, objects.items[index]) >= (int)sizeof(object_path)) {
            fprintf(stderr, _("path is too long\n"));
            goto cleanup;
        } else if (secdat_validate_v2_secret_object_file(object_path, objects.items[index], &refcount_present, &cached_refcount) != 0) {
            invalid_object = 1;
        }

        if (invalid_object) {
            if (options->dangling) {
                secdat_gc_report_removal(report, options->dry_run, "dangling-secret", objects.items[index], "invalid-secret");
                if (!options->dry_run && secdat_gc_remove_v2_secret_artifacts(secret_objects_dir, objects.items[index]) != 0) {
                    goto cleanup;
                }
            }
            continue;
        }
        if (secdat_key_list_append(&valid_objects, objects.items[index]) != 0) {
            goto cleanup;
        }
    }

    for (index = 0; index < values.count; index += 1) {
        const char *kind = NULL;
        const char *detail = NULL;

        if (secdat_key_list_contains(&objects, values.items[index])) {
            continue;
        }
        if (!secdat_uuid_is_valid(values.items[index])) {
            if (!options->dangling) {
                continue;
            }
            kind = "dangling-value";
            detail = "invalid-value";
        } else if (options->dangling) {
            kind = "dangling-value";
            detail = "missing-secret";
        } else if (options->orphaned) {
            kind = "orphaned-value";
            detail = "missing-secret";
        } else {
            continue;
        }

        secdat_gc_report_removal(report, options->dry_run, kind, values.items[index], detail);
        if (!options->dry_run && secdat_gc_remove_v2_secret_artifacts(secret_objects_dir, values.items[index]) != 0) {
            goto cleanup;
        }
    }

    if (options->dangling) {
        for (index = 0; index < entries.count; index += 1) {
            int missing_secret = 0;

            if (!secdat_uuid_is_valid(entries.items[index])) {
                secdat_gc_report_removal(report, options->dry_run, "dangling-entry", entries.items[index], "invalid-entry");
                if (!options->dry_run && secdat_gc_remove_v2_domain_entry(domain_entries_dir, entries.items[index]) != 0) {
                    goto cleanup;
                }
                continue;
            }
            if (snprintf(entry_path, sizeof(entry_path), "%s/%s.dent", domain_entries_dir, entries.items[index]) >= (int)sizeof(entry_path)) {
                fprintf(stderr, _("path is too long\n"));
                goto cleanup;
            }
            if (secdat_read_v2_domain_entry_info(entry_path, entries.items[index], &entry_info) != 0) {
                secdat_gc_report_removal(report, options->dry_run, "dangling-entry", entries.items[index], "invalid-entry");
                if (!options->dry_run && secdat_gc_remove_v2_domain_entry(domain_entries_dir, entries.items[index]) != 0) {
                    goto cleanup;
                }
                continue;
            }
            {
                const char *object_domain_id = secdat_v2_entry_object_domain(current_domain_id, &entry_info);
                const char *object_store_name = secdat_v2_entry_object_store(store_name, &entry_info);
                int object_is_local = strcmp(object_domain_id, current_domain_id) == 0
                    && strcmp(secdat_effective_store_name(object_store_name), secdat_effective_store_name(store_name)) == 0;

                if (object_is_local) {
                    missing_secret = !secdat_key_list_contains(&valid_objects, entry_info.secret_id);
                } else if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry_info.secret_id, object_path, sizeof(object_path)) != 0
                    || secdat_validate_v2_secret_object_file(object_path, entry_info.secret_id, &refcount_present, &cached_refcount) != 0) {
                    missing_secret = 1;
                }
            }
            if (missing_secret) {
                secdat_gc_report_removal(report, options->dry_run, "dangling-entry", entries.items[index], "missing-secret");
                if (!options->dry_run && secdat_gc_remove_v2_domain_entry(domain_entries_dir, entries.items[index]) != 0) {
                    goto cleanup;
                }
            }
        }
    }

    if (options->orphaned) {
        for (index = 0; index < valid_objects.count; index += 1) {
            if (secdat_count_v2_secret_references_to_object(current_domain_id, store_name, valid_objects.items[index], &actual_refcount) != 0) {
                goto cleanup;
            }
            if (actual_refcount == 0) {
                secdat_gc_report_removal(report, options->dry_run, "orphaned-secret", valid_objects.items[index], "missing-entry");
                if (!options->dry_run && secdat_gc_remove_v2_secret_artifacts(secret_objects_dir, valid_objects.items[index]) != 0) {
                    goto cleanup;
                }
            }
        }
    }

    status = 0;

cleanup:
    secdat_key_list_free(&entries);
    secdat_key_list_free(&objects);
    secdat_key_list_free(&values);
    secdat_key_list_free(&valid_objects);
    return status;
}

static int secdat_command_gc(const struct secdat_cli *cli)
{
    struct secdat_gc_options options;
    struct secdat_gc_report report;
    struct secdat_domain_chain chain = {0};
    int status;

    status = secdat_parse_gc_options(cli, &options);
    if (status != 0) {
        return status;
    }

    if (strcmp(options.format, "v2") != 0) {
        fprintf(stderr, _("gc is only supported with --format v2\n"));
        return 2;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    status = secdat_gc_v2_store(&chain, cli->store, &options, &report);
    secdat_domain_chain_free(&chain);
    if (status != 0) {
        return status;
    }
    if (report.removals == 0) {
        puts("ok");
    }
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

static void secdat_print_secret_attrs(const struct secdat_secret_attrs *attrs)
{
    printf("key_visibility=%s\n", secdat_key_visibility_name(attrs->key_visibility));
    printf("value_access=%s\n", secdat_value_access_name(attrs->value_access));
    printf("sandbox_inject=%s\n", secdat_sandbox_inject_name(attrs->sandbox_inject));
}

static int secdat_command_attr(const struct secdat_cli *cli)
{
    struct secdat_attr_options options;
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    struct secdat_effective_entry entry = {0};
    struct secdat_secret_attrs attrs;
    struct secdat_secret_attrs original_attrs;
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;
    int unsafe_store = 0;
    int target_unsafe_store;
    int has_changes;
    int status;

    status = secdat_parse_attr_options(cli, &options);
    if (status != 0) {
        return status;
    }
    has_changes = options.set_key_visibility || options.set_value_access || options.set_sandbox_inject;

    if (secdat_parse_key_reference(options.keyref, secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }
    if (secdat_resolve_effective_entry(&chain, reference.store_value, reference.key, 0, &entry) != 0) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("key not found: %s\n"), reference.key);
        return 1;
    }

    if (secdat_load_resolved_secret_attrs(&chain, reference.store_value, reference.key, &attrs, &unsafe_store) != 0) {
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }
    original_attrs = attrs;
    if (!has_changes) {
        secdat_print_secret_attrs(&attrs);
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 0;
    }

    if (entry.from_v2) {
        if (entry.resolved_index != 0) {
            fprintf(stderr, _("cannot update inherited key attributes: %s\n"), reference.key);
            secdat_effective_entry_reset(&entry);
            secdat_domain_chain_free(&chain);
            return 1;
        }
        if (secdat_require_mutable_session_chain(&chain, "attr") != 0
            || secdat_require_writable_domain_chain(&chain) != 0) {
            secdat_effective_entry_reset(&entry);
            secdat_domain_chain_free(&chain);
            return 1;
        }
        if (options.set_key_visibility) {
            attrs.key_visibility = options.attrs.key_visibility;
        }
        if (options.set_sandbox_inject) {
            attrs.sandbox_inject = options.attrs.sandbox_inject;
        }
        if (options.set_value_access) {
            attrs.value_access = options.attrs.value_access;
        }
        if (!secdat_v2_secret_attrs_supported(&attrs)) {
            secdat_effective_entry_reset(&entry);
            secdat_domain_chain_free(&chain);
            return 1;
        }
        if (attrs.value_access != original_attrs.value_access) {
            target_unsafe_store = attrs.value_access == SECDAT_VALUE_ACCESS_ALWAYS;
            if (secdat_load_resolved_plaintext(&chain, reference.store_value, reference.key, &plaintext, &plaintext_length, NULL, NULL, NULL) != 0) {
                secdat_effective_entry_reset(&entry);
                secdat_domain_chain_free(&chain);
                return 1;
            }
            status = secdat_store_v2_plaintext_with_attrs(
                chain.count == 0 ? "" : chain.ids[0],
                reference.store_value,
                reference.key,
                plaintext,
                plaintext_length,
                target_unsafe_store,
                &attrs
            );
            secdat_secure_clear(plaintext, plaintext_length);
            free(plaintext);
            plaintext = NULL;
            plaintext_length = 0;
        } else {
            status = secdat_update_v2_secret_attrs(
                chain.count == 0 ? "" : chain.ids[0],
                reference.store_value,
                reference.key,
                &entry,
                &attrs
            );
        }
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return status;
    }
    if (entry.from_overlay) {
        fprintf(stderr, _("secret attributes cannot be changed for a volatile session overlay\n"));
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (entry.resolved_index != 0) {
        fprintf(stderr, _("cannot update inherited key attributes: %s\n"), reference.key);
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (secdat_require_mutable_session_chain(&chain, "attr") != 0
        || secdat_require_writable_domain_chain(&chain) != 0) {
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (options.set_key_visibility) {
        attrs.key_visibility = options.attrs.key_visibility;
    }
    if (options.set_sandbox_inject) {
        attrs.sandbox_inject = options.attrs.sandbox_inject;
    }
    if (options.set_value_access) {
        attrs.value_access = options.attrs.value_access;
    }
    if (!secdat_secret_attrs_supported(&attrs)) {
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    target_unsafe_store = attrs.value_access == SECDAT_VALUE_ACCESS_ALWAYS;
    if (target_unsafe_store != unsafe_store) {
        if (secdat_load_resolved_plaintext(&chain, reference.store_value, reference.key, &plaintext, &plaintext_length, NULL, NULL, NULL) != 0) {
            secdat_effective_entry_reset(&entry);
            secdat_domain_chain_free(&chain);
            return 1;
        }
        status = secdat_store_plaintext_attrs_for_chain(
            &chain,
            chain.count == 0 ? "" : chain.ids[0],
            reference.store_value,
            reference.key,
            plaintext,
            plaintext_length,
            target_unsafe_store,
            &attrs
        );
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
    } else {
        status = secdat_write_secret_attrs(chain.count == 0 ? "" : chain.ids[0], reference.store_value, reference.key, unsafe_store, &attrs);
    }

    secdat_effective_entry_reset(&entry);
    secdat_domain_chain_free(&chain);
    return status;
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

static int secdat_command_id(const struct secdat_cli *cli)
{
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    struct secdat_effective_entry entry = {0};
    int status;

    if (cli->argc == 0) {
        fprintf(stderr, _("missing key for id\n"));
        secdat_cli_print_try_help(cli, "id");
        return 2;
    }
    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for id\n"));
        secdat_cli_print_try_help(cli, "id");
        return 2;
    }

    if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &reference) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(reference.domain_value, &chain) != 0) {
        return 1;
    }

    status = secdat_resolve_effective_entry(&chain, reference.store_value, reference.key, 0, &entry);
    if (status != 0) {
        fprintf(stderr, _("key not found: %s\n"), reference.key);
        fprintf(stderr, _("Hint: check secdat status, --dir, and --store to confirm the lookup context\n"));
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (!entry.from_v2) {
        fprintf(stderr, _("secret id is available only for store format v2\n"));
        secdat_print_store_migration_hint(cli->program_name, reference.store_value);
        secdat_effective_entry_reset(&entry);
        secdat_domain_chain_free(&chain);
        return 1;
    }

    puts(entry.secret_id);
    secdat_effective_entry_reset(&entry);
    secdat_domain_chain_free(&chain);
    return 0;
}

static int secdat_command_secret_status(const struct secdat_cli *cli)
{
    const char *secret_id;
    const char *store_name = secdat_effective_store_name(cli->store);
    struct secdat_domain_chain chain = {0};
    enum secdat_store_format format;
    struct secdat_v2_secret_object_info object;
    char object_path[PATH_MAX];
    char value_path[PATH_MAX];
    size_t actual_refcount = 0;
    int legacy_value_sidecar;
    int status = 1;

    if (cli->argc == 0) {
        fprintf(stderr, _("missing UUID for secret status\n"));
        secdat_cli_print_try_help(cli, "secret");
        return 2;
    }
    if (cli->argc != 1) {
        fprintf(stderr, _("invalid arguments for secret status\n"));
        secdat_cli_print_try_help(cli, "secret");
        return 2;
    }

    secret_id = cli->argv[0];
    if (!secdat_uuid_is_valid(secret_id)) {
        fprintf(stderr, _("invalid UUID for secret status: %s\n"), secret_id);
        return 2;
    }

    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (chain.count == 0) {
        fprintf(stderr, _("secret status requires a registered current domain\n"));
        goto cleanup;
    }

    if (secdat_read_store_format(chain.ids[0], store_name, &format) != 0) {
        goto cleanup;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        goto cleanup;
    }
    if (format != SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("secret status is available only for store format v2\n"));
        secdat_print_store_migration_hint(cli->program_name, store_name);
        goto cleanup;
    }

    if (secdat_build_v2_secret_object_path(chain.ids[0], store_name, secret_id, object_path, sizeof(object_path)) != 0
        || secdat_build_v2_secret_value_path(chain.ids[0], store_name, secret_id, value_path, sizeof(value_path)) != 0) {
        goto cleanup;
    }
    if (!secdat_file_exists(object_path)) {
        fprintf(stderr, _("secret object not found: %s\n"), secret_id);
        goto cleanup;
    }
    if (secdat_read_v2_secret_object_info(object_path, secret_id, &object) != 0) {
        fprintf(stderr, _("invalid secret object: %s\n"), secret_id);
        goto cleanup;
    }
    if (secdat_count_v2_secret_references_to_object(chain.ids[0], store_name, secret_id, &actual_refcount) != 0) {
        goto cleanup;
    }

    legacy_value_sidecar = secdat_file_exists(value_path);

    printf("secret_id=%s\n", object.secret_id);
    printf("object_domain=%s\n", chain.ids[0]);
    printf("object_store=%s\n", store_name);
    printf("value_access=%s\n", secdat_value_access_name(object.value_access));
    printf("secret_inject=%s\n", secdat_v2_secret_inject_name(object.secret_inject));
    if (object.refcount_present) {
        printf("refcount_cached=%zu\n", object.refcount);
    } else {
        printf("refcount_cached=missing\n");
    }
    printf("refcount_actual=%zu\n", actual_refcount);
    printf("orphaned=%s\n", actual_refcount == 0 ? "yes" : "no");
    printf("object_payload=%s\n", object.has_value_payload ? "yes" : "no");
    printf("object_payload_length=%zu\n", object.has_value_payload ? object.value_payload_length : 0);
    printf("legacy_value_sidecar=%s\n", legacy_value_sidecar ? "yes" : "no");

    status = 0;

cleanup:
    secdat_domain_chain_free(&chain);
    return status;
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
    return secdat_store_plaintext_with_attrs(domain_id, store_name, key, plaintext, plaintext_length, unsafe_store, NULL);
}

static int secdat_store_plaintext_with_attrs(
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
)
{
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    enum secdat_store_format format;
    int status;

    if (secdat_require_writable_domain_id(domain_id) != 0) {
        return 1;
    }

    status = secdat_ensure_store_dirs(domain_id, store_name);
    if (status != 0) {
        return status;
    }

    if (secdat_read_store_format(domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_V2) {
        return secdat_store_v2_plaintext_with_attrs(domain_id, store_name, key, plaintext, plaintext_length, unsafe_store, attrs);
    }

    status = secdat_build_entry_path(domain_id, store_name, key, entry_path, sizeof(entry_path));
    if (status != 0) {
        return status;
    }

    status = secdat_build_tombstone_path(domain_id, store_name, key, tombstone_path, sizeof(tombstone_path));
    if (status != 0) {
        return status;
    }

    if (attrs != NULL && !secdat_secret_attrs_supported(attrs)) {
        return 1;
    }
    if (attrs != NULL && ((attrs->value_access == SECDAT_VALUE_ACCESS_ALWAYS) != (unsafe_store != 0))) {
        fprintf(stderr, _("secret value_access does not match storage mode\n"));
        return 1;
    }

    if (secdat_encode_value_for_storage(domain_id, plaintext, plaintext_length, unsafe_store, &encrypted, &encrypted_length) != 0) {
        return 1;
    }

    status = secdat_remove_if_exists(tombstone_path);
    if (status == 0) {
        status = secdat_atomic_write_file(entry_path, encrypted, encrypted_length);
    }
    if (status == 0) {
        status = secdat_write_secret_attrs(domain_id, store_name, key, unsafe_store, attrs);
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
    return secdat_store_plaintext_attrs_for_chain(chain, domain_id, store_name, key, plaintext, plaintext_length, unsafe_store, NULL);
}

static int secdat_store_plaintext_attrs_for_chain(
    const struct secdat_domain_chain *chain,
    const char *domain_id,
    const char *store_name,
    const char *key,
    unsigned char *plaintext,
    size_t plaintext_length,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
)
{
    if (secdat_active_overlay_enabled(chain)) {
        if (attrs != NULL && !secdat_secret_attrs_are_default(attrs, unsafe_store)) {
            fprintf(stderr, _("secret attributes are not supported in a volatile session overlay\n"));
            return 1;
        }
        return secdat_active_overlay_store_plaintext(chain, domain_id, store_name, key, plaintext, plaintext_length, unsafe_store);
    }
    return secdat_store_plaintext_with_attrs(domain_id, store_name, key, plaintext, plaintext_length, unsafe_store, attrs);
}

static int secdat_store_literal_keyref(
    const struct secdat_cli *cli,
    const char *keyref,
    const char *literal_value,
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
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
    status = secdat_store_plaintext_attrs_for_chain(&chain, current_domain_id, reference.store_value, key, plaintext, plaintext_length, unsafe_store, attrs);
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
    int unsafe_store,
    const struct secdat_secret_attrs *attrs
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

    status = secdat_store_literal_keyref(cli, keyref, separator + 1, unsafe_store, attrs);
    free(keyref);
    return status;
}

static int secdat_command_set(const struct secdat_cli *cli)
{
    static const struct option long_options[] = {
        {"unsafe", no_argument, NULL, 'u'},
        {"public-value", no_argument, NULL, 1000},
        {"secret-value", no_argument, NULL, 1001},
        {"key-visibility", required_argument, NULL, 1002},
        {"value-access", required_argument, NULL, 1003},
        {"sandbox-inject", required_argument, NULL, 1004},
        {"inject", required_argument, NULL, 1004},
        {"stdin", no_argument, NULL, 'i'},
        {"value", required_argument, NULL, 'v'},
        {"env", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    struct secdat_key_reference reference;
    struct secdat_domain_chain chain = {0};
    struct secdat_secret_attrs attrs;
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
    int value_mode_configured = 0;
    int argc;
    int option;
    int status;

    secdat_secret_attrs_default(0, &attrs);
    secdat_prepare_option_argv(cli, "set", &argc, argv);
    secdat_reset_getopt_state();
    while ((option = getopt_long(argc, argv, ":uiv:e:", long_options, NULL)) != -1) {
        switch (option) {
        case 'u':
        case 1000:
            if (value_mode_configured && attrs.value_access != SECDAT_VALUE_ACCESS_ALWAYS) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            unsafe_store = 1;
            attrs.value_access = SECDAT_VALUE_ACCESS_ALWAYS;
            value_mode_configured = 1;
            break;
        case 1001:
            if (value_mode_configured && attrs.value_access != SECDAT_VALUE_ACCESS_UNLOCKED) {
                fprintf(stderr, _("invalid arguments for set\n"));
                secdat_cli_print_try_help(cli, "set");
                return 2;
            }
            unsafe_store = 0;
            attrs.value_access = SECDAT_VALUE_ACCESS_UNLOCKED;
            value_mode_configured = 1;
            break;
        case 1002:
            if (secdat_parse_key_visibility(optarg, &attrs.key_visibility) != 0) {
                return 2;
            }
            break;
        case 1003:
            {
                enum secdat_value_access parsed;

                if (secdat_parse_value_access(optarg, &parsed) != 0) {
                    return 2;
                }
                if (value_mode_configured && attrs.value_access != parsed) {
                    fprintf(stderr, _("invalid arguments for set\n"));
                    secdat_cli_print_try_help(cli, "set");
                    return 2;
                }
                attrs.value_access = parsed;
                unsafe_store = parsed == SECDAT_VALUE_ACCESS_ALWAYS;
                value_mode_configured = 1;
            }
            break;
        case 1004:
            if (secdat_parse_sandbox_inject(optarg, &attrs.sandbox_inject) != 0) {
                return 2;
            }
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

    unsafe_store = attrs.value_access == SECDAT_VALUE_ACCESS_ALWAYS;

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
                status = secdat_store_assignment_operand(cli, argv[assignment_index], unsafe_store, &attrs);
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

        status = secdat_store_plaintext_attrs_for_chain(&chain, current_domain_id, reference.store_value, key, plaintext, plaintext_length, unsafe_store, &attrs);
        secdat_domain_chain_free(&chain);
        secdat_secure_clear(plaintext, plaintext_length);
        free(plaintext);
        return status;
    }

    return secdat_store_literal_keyref(cli, keyref, literal_value, unsafe_store, &attrs);
}

static int secdat_write_empty_file(const char *path)
{
    return secdat_atomic_write_file(path, (const unsigned char *)"", 0);
}

static int secdat_local_key_exists_in_store(const char *domain_id, const char *store_name, const char *key, int *exists)
{
    char entry_path[PATH_MAX];
    struct secdat_v2_domain_entry_info v2_entry;
    enum secdat_store_format format;
    int lookup_status;

    *exists = 0;
    if (secdat_read_store_format(domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_V2) {
        lookup_status = secdat_lookup_v2_domain_entry_authoritative(domain_id, store_name, key, &v2_entry, entry_path, sizeof(entry_path));
        if (lookup_status > 1) {
            return 1;
        }
        *exists = lookup_status == 0;
        return 0;
    }

    if (secdat_build_entry_path(domain_id, store_name, key, entry_path, sizeof(entry_path)) != 0) {
        return 1;
    }
    *exists = secdat_file_exists(entry_path);
    return 0;
}

static int secdat_count_v2_secret_references_to_object_in_store(
    const char *entry_domain_id,
    const char *entry_store_name,
    const char *object_domain_id,
    const char *object_store_name,
    const char *secret_id,
    size_t *count
)
{
    char domain_entries_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    struct secdat_key_list entry_ids = {0};
    struct secdat_v2_domain_entry_info entry;
    size_t index;
    int status = 1;

    if (secdat_v2_domain_entries_dir(entry_domain_id, entry_store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_collect_directory_keys(domain_entries_dir, ".dent", &entry_ids) != 0) {
        goto cleanup;
    }
    for (index = 0; index < entry_ids.count; index += 1) {
        const char *entry_object_domain_id;
        const char *entry_object_store_name;

        if (secdat_build_v2_domain_entry_path(entry_domain_id, entry_store_name, entry_ids.items[index], entry_path, sizeof(entry_path)) != 0) {
            goto cleanup;
        }
        if (secdat_read_v2_domain_entry_info(entry_path, entry_ids.items[index], &entry) != 0) {
            continue;
        }
        entry_object_domain_id = secdat_v2_entry_object_domain(entry_domain_id, &entry);
        entry_object_store_name = secdat_v2_entry_object_store(entry_store_name, &entry);
        if (strcmp(entry.secret_id, secret_id) == 0
            && strcmp(entry_object_domain_id, object_domain_id) == 0
            && strcmp(secdat_effective_store_name(entry_object_store_name), secdat_effective_store_name(object_store_name)) == 0) {
            *count += 1;
        }
    }
    status = 0;

cleanup:
    secdat_key_list_free(&entry_ids);
    return status;
}

static int secdat_count_v2_secret_references_to_object(
    const char *object_domain_id,
    const char *object_store_name,
    const char *secret_id,
    size_t *count
)
{
    struct secdat_domain_root_list roots = {0};
    struct secdat_domain_chain chain = {0};
    struct secdat_key_list stores = {0};
    enum secdat_store_format format;
    size_t root_index;
    size_t store_index;
    int status = 1;

    *count = 0;
    if (secdat_collect_registered_domain_roots(&roots) != 0) {
        return 1;
    }
    for (root_index = 0; root_index < roots.count; root_index += 1) {
        if (secdat_domain_resolve_registered_root_chain(roots.roots[root_index], &chain) != 0) {
            goto cleanup;
        }
        if (chain.count == 0) {
            secdat_domain_chain_free(&chain);
            continue;
        }
        if (secdat_collect_store_names(chain.ids[0], NULL, &stores) != 0) {
            goto cleanup;
        }
        for (store_index = 0; store_index < stores.count; store_index += 1) {
            if (secdat_read_store_format(chain.ids[0], stores.items[store_index], &format) != 0) {
                goto cleanup;
            }
            if (format == SECDAT_STORE_FORMAT_INVALID) {
                fprintf(stderr, _("invalid store format marker\n"));
                goto cleanup;
            }
            if (format != SECDAT_STORE_FORMAT_V2) {
                continue;
            }
            if (secdat_count_v2_secret_references_to_object_in_store(
                    chain.ids[0],
                    stores.items[store_index],
                    object_domain_id,
                    object_store_name,
                    secret_id,
                    count
                ) != 0) {
                goto cleanup;
            }
        }
        secdat_key_list_free(&stores);
        secdat_domain_chain_free(&chain);
    }
    status = 0;

cleanup:
    secdat_key_list_free(&stores);
    secdat_domain_chain_free(&chain);
    secdat_domain_root_list_free(&roots);
    return status;
}

static int secdat_update_v2_secret_refcount(
    const char *domain_id,
    const char *store_name,
    const char *secret_id,
    size_t refcount
)
{
    char secret_objects_dir[PATH_MAX];
    char object_path[PATH_MAX];
    struct secdat_v2_secret_object_info object;
    struct secdat_secret_attrs attrs;
    unsigned char *payload = NULL;
    size_t payload_length = 0;
    int has_payload = 0;
    int status;

    if (secdat_v2_secret_objects_dir(domain_id, store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0
        || secdat_build_v2_secret_object_path(domain_id, store_name, secret_id, object_path, sizeof(object_path)) != 0
        || secdat_read_v2_secret_object_info(object_path, secret_id, &object) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), secret_id);
        return 1;
    }
    if (!object.refcount_present) {
        return 0;
    }
    if (secdat_read_v2_secret_object_payload(object_path, secret_id, &payload, &payload_length, &has_payload) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), secret_id);
        return 1;
    }
    attrs.key_visibility = SECDAT_KEY_VISIBILITY_ALWAYS;
    attrs.value_access = object.value_access;
    attrs.sandbox_inject = object.secret_inject == SECDAT_SECRET_INJECT_NEVER
        ? SECDAT_SANDBOX_INJECT_NEVER
        : SECDAT_SANDBOX_INJECT_BULK;
    status = secdat_write_v2_secret_object_file_with_inject(
        secret_objects_dir,
        secret_id,
        &attrs,
        object.secret_inject,
        1,
        refcount,
        has_payload ? payload : NULL,
        has_payload ? payload_length : 0,
        object_path,
        sizeof(object_path)
    );
    secdat_secure_clear(payload, payload_length);
    free(payload);
    return status;
}

static int secdat_remove_v2_local_key(const char *domain_id, const char *store_name, const char *key, int *removed)
{
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    char value_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    char legacy_entry_path[PATH_MAX];
    struct secdat_v2_domain_entry_info entry;
    struct secdat_v2_secret_object_info object;
    const char *object_domain_id;
    const char *object_store_name;
    size_t references = 0;
    int lookup_status;
    int object_is_valid = 0;

    *removed = 0;
    lookup_status = secdat_lookup_v2_domain_entry_authoritative(domain_id, store_name, key, &entry, entry_path, sizeof(entry_path));
    if (lookup_status > 1) {
        return 1;
    }
    if (lookup_status != 0) {
        return 0;
    }
    object_domain_id = secdat_v2_entry_object_domain(domain_id, &entry);
    object_store_name = secdat_v2_entry_object_store(store_name, &entry);

    if (secdat_count_v2_secret_references_to_object(object_domain_id, object_store_name, entry.secret_id, &references) != 0) {
        return 1;
    }
    if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry.secret_id, object_path, sizeof(object_path)) != 0
        || secdat_build_v2_secret_value_path(object_domain_id, object_store_name, entry.secret_id, value_path, sizeof(value_path)) != 0) {
        return 1;
    }
    if (secdat_build_tombstone_path(domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0
        || secdat_build_entry_path(domain_id, store_name, key, legacy_entry_path, sizeof(legacy_entry_path)) != 0) {
        return 1;
    }
    if (secdat_read_v2_secret_object_info(object_path, entry.secret_id, &object) == 0) {
        object_is_valid = 1;
    }

    if (unlink(entry_path) != 0) {
        fprintf(stderr, _("failed to remove key: %s\n"), key);
        return 1;
    }
    if (secdat_remove_if_exists(legacy_entry_path) != 0
        || secdat_remove_secret_attrs(domain_id, store_name, key) != 0
        || secdat_remove_if_exists(tombstone_path) != 0) {
        return 1;
    }
    if (object_is_valid) {
        if (references <= 1) {
            if (secdat_remove_if_exists(value_path) != 0
                || secdat_remove_if_exists(object_path) != 0) {
                return 1;
            }
        } else if (secdat_update_v2_secret_refcount(object_domain_id, object_store_name, entry.secret_id, references - 1) != 0) {
            return 1;
        }
    }

    *removed = 1;
    return 0;
}

static int secdat_remove_key_in_chain(const struct secdat_domain_chain *chain, const char *store_name, const char *key, int ignore_missing)
{
    char current_domain_id[PATH_MAX];
    char entry_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    struct secdat_overlay_lookup_result overlay = {0};
    enum secdat_store_format format;
    int found_inherited = 0;
    int local_file_exists = 0;
    int removed_v2 = 0;

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
        if (current_domain_id[0] != '\0'
            && secdat_local_key_exists_in_store(current_domain_id, store_name, key, &local_file_exists) != 0) {
            goto overlay_cleanup_error;
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

    if (secdat_read_store_format(current_domain_id, store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_V2) {
        if (secdat_remove_v2_local_key(current_domain_id, store_name, key, &removed_v2) != 0) {
            return 1;
        }
        if (removed_v2) {
            return 0;
        }
    }

    if (secdat_file_exists(entry_path)) {
        if (unlink(entry_path) != 0) {
            fprintf(stderr, _("failed to remove key: %s\n"), key);
            return 1;
        }
        if (secdat_remove_secret_attrs(current_domain_id, store_name, key) != 0) {
            return 1;
        }
        return secdat_remove_if_exists(tombstone_path);
    }

    found_inherited = secdat_parent_has_visible_key(chain, store_name, key);
    if (found_inherited < 0) {
        return 1;
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
    char tombstone_path[PATH_MAX];
    struct secdat_overlay_lookup_result overlay = {0};
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
        if (current_domain_id[0] != '\0'
            && secdat_local_key_exists_in_store(current_domain_id, store_name, key, &local_file_exists) != 0) {
            goto overlay_cleanup_error;
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

    if (secdat_build_tombstone_path(current_domain_id, store_name, key, tombstone_path, sizeof(tombstone_path)) != 0) {
        return 1;
    }

    if (secdat_file_exists(tombstone_path)) {
        return 0;
    }
    if (secdat_local_key_exists_in_store(current_domain_id, store_name, key, &local_file_exists) != 0) {
        return 1;
    }
    if (local_file_exists) {
        fprintf(stderr, _("key exists locally and cannot be masked: %s\n"), key);
        return 1;
    }

    found_inherited = secdat_parent_has_visible_key(chain, store_name, key);
    if (found_inherited < 0) {
        return 1;
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

static int secdat_unwrap_v2_effective_object_key(
    const struct secdat_domain_chain *source_chain,
    const struct secdat_effective_entry *source_entry,
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN]
)
{
    const char *unwrap_domain_id;

    unwrap_domain_id = secdat_v2_effective_entry_unwrap_domain_id(source_chain, source_entry);
    if (!source_entry->has_wrapped_object_key || unwrap_domain_id == NULL) {
        return 1;
    }
    return secdat_unwrap_object_key_hex(unwrap_domain_id, source_entry->wrapped_object_key, object_key);
}

static int secdat_ln_arg_is_uuid_reference(const char *raw)
{
    return raw != NULL && raw[0] == '@';
}

static int secdat_parse_ln_uuid_source(const char *raw, const char **secret_id)
{
    *secret_id = NULL;
    if (!secdat_ln_arg_is_uuid_reference(raw)) {
        return 0;
    }
    if (!secdat_uuid_is_valid(raw + 1)) {
        fprintf(stderr, _("invalid UUID source for ln: %s\n"), raw);
        return -1;
    }
    *secret_id = raw + 1;
    return 1;
}

static int secdat_resolve_v2_effective_entry_by_secret_id(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *secret_id,
    struct secdat_effective_entry *entry
)
{
    struct secdat_key_list visible_keys = {0};
    size_t index;
    int status = 1;

    secdat_effective_entry_reset(entry);
    if (secdat_collect_visible_keys(chain, store_name, NULL, NULL, &visible_keys) != 0) {
        goto cleanup;
    }

    for (index = 0; index < visible_keys.count; index += 1) {
        if (secdat_resolve_effective_entry(chain, store_name, visible_keys.items[index], 0, entry) != 0) {
            goto cleanup;
        }
        if (entry->from_v2 && strcmp(entry->secret_id, secret_id) == 0) {
            status = 0;
            goto cleanup;
        }
        secdat_effective_entry_reset(entry);
    }

    fprintf(stderr, _("secret UUID is not authorized in current context: %s\n"), secret_id);

cleanup:
    if (status != 0) {
        secdat_effective_entry_reset(entry);
    }
    secdat_key_list_free(&visible_keys);
    return status;
}

static int secdat_link_v2_key(
    const struct secdat_domain_chain *source_chain,
    const char *destination_domain_id,
    const char *destination_store_name,
    const char *destination_key,
    const struct secdat_effective_entry *source_entry
)
{
    char domain_entries_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    char tombstone_path[PATH_MAX];
    char legacy_entry_path[PATH_MAX];
    char entry_id[37];
    struct secdat_secret_attrs attrs;
    struct secdat_v2_secret_object_info object;
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN];
    const unsigned char *object_key_ptr = NULL;
    const char *object_domain_id = source_entry->object_domain;
    const char *object_store_name = secdat_effective_entry_object_store(source_entry);
    size_t references = 0;
    int status = 1;
    int entry_written = 0;

    if (object_domain_id[0] == '\0') {
        fprintf(stderr, _("invalid v2 domain entry: %s\n"), source_entry->entry_id);
        return 1;
    }
    if (secdat_v2_domain_entries_dir(destination_domain_id, destination_store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_build_v2_secret_object_path(object_domain_id, object_store_name, source_entry->secret_id, object_path, sizeof(object_path)) != 0
        || secdat_read_v2_secret_object_info(object_path, source_entry->secret_id, &object) != 0) {
        fprintf(stderr, _("invalid v2 secret object: %s\n"), source_entry->secret_id);
        return 1;
    }
    if (secdat_count_v2_secret_references_to_object(object_domain_id, object_store_name, source_entry->secret_id, &references) != 0) {
        return 1;
    }
    if (references == 0) {
        fprintf(stderr, _("invalid v2 domain entry: %s\n"), source_entry->entry_id);
        return 1;
    }
    if (secdat_generate_uuid_v4(entry_id, sizeof(entry_id)) != 0
        || secdat_build_tombstone_path(destination_domain_id, destination_store_name, destination_key, tombstone_path, sizeof(tombstone_path)) != 0
        || secdat_build_entry_path(destination_domain_id, destination_store_name, destination_key, legacy_entry_path, sizeof(legacy_entry_path)) != 0) {
        return 1;
    }

    attrs.key_visibility = source_entry->key_visibility;
    attrs.value_access = object.value_access;
    attrs.sandbox_inject = source_entry->entry_inject;
    if (object.secret_inject == SECDAT_SECRET_INJECT_NEVER) {
        attrs.sandbox_inject = SECDAT_SANDBOX_INJECT_NEVER;
    }
    if (object.value_access == SECDAT_VALUE_ACCESS_UNLOCKED) {
        if (secdat_unwrap_v2_effective_object_key(source_chain, source_entry, object_key) != 0) {
            fprintf(stderr, _("invalid v2 domain entry: %s\n"), source_entry->entry_id);
            return 1;
        }
        object_key_ptr = object_key;
    }

    if (secdat_write_v2_domain_entry_file(
            destination_domain_id,
            domain_entries_dir,
            entry_id,
            source_entry->secret_id,
            object_domain_id,
            object_store_name,
            destination_key,
            &attrs,
            object_key_ptr,
            entry_path,
            sizeof(entry_path)
        ) != 0) {
        goto cleanup;
    }
    entry_written = 1;

    if (object.refcount_present
        && secdat_update_v2_secret_refcount(object_domain_id, object_store_name, source_entry->secret_id, references + 1) != 0) {
        goto cleanup;
    }
    if (secdat_remove_if_exists(tombstone_path) != 0
        || secdat_remove_if_exists(legacy_entry_path) != 0
        || secdat_remove_secret_attrs(destination_domain_id, destination_store_name, destination_key) != 0) {
        goto cleanup;
    }

    status = 0;

cleanup:
    if (status != 0 && entry_written) {
        (void)secdat_remove_if_exists(entry_path);
    }
    if (object_key_ptr != NULL) {
        secdat_secure_clear(object_key, sizeof(object_key));
    }
    return status;
}

static int secdat_command_ln(const struct secdat_cli *cli)
{
    struct secdat_key_reference source_reference;
    struct secdat_key_reference destination_reference;
    struct secdat_domain_chain source_chain = {0};
    struct secdat_domain_chain destination_chain = {0};
    struct secdat_effective_entry source_entry = {0};
    char destination_domain_id[PATH_MAX];
    char destination_path[PATH_MAX];
    const char *source_domain_value;
    const char *source_store_value;
    const char *source_secret_id = NULL;
    enum secdat_store_format format;
    int source_is_uuid;
    int status = 1;

    if (cli->argc != 2) {
        fprintf(stderr, _("invalid arguments for ln\n"));
        secdat_cli_print_try_help(cli, "ln");
        return 2;
    }

    source_is_uuid = secdat_parse_ln_uuid_source(cli->argv[0], &source_secret_id);
    if (source_is_uuid < 0) {
        secdat_cli_print_try_help(cli, "ln");
        return 2;
    }
    if (secdat_ln_arg_is_uuid_reference(cli->argv[1])) {
        fprintf(stderr, _("UUID references are only valid as ln source: %s\n"), cli->argv[1]);
        secdat_cli_print_try_help(cli, "ln");
        return 2;
    }
    if (!source_is_uuid && strcmp(cli->argv[0], cli->argv[1]) == 0) {
        fprintf(stderr, _("source and destination keys must differ\n"));
        return 1;
    }

    if (source_is_uuid) {
        source_domain_value = secdat_cli_domain_base(cli);
        source_store_value = cli->store;
        if (secdat_parse_key_reference(cli->argv[1], secdat_cli_domain_base(cli), cli->store, &destination_reference) != 0) {
            return 1;
        }
    } else {
        if (secdat_parse_key_reference(cli->argv[0], secdat_cli_domain_base(cli), cli->store, &source_reference) != 0
            || secdat_parse_key_reference(cli->argv[1], secdat_cli_domain_base(cli), cli->store, &destination_reference) != 0) {
            return 1;
        }
        source_domain_value = source_reference.domain_value;
        source_store_value = source_reference.store_value;
    }
    if (secdat_domain_resolve_current(destination_reference.domain_value, destination_domain_id, sizeof(destination_domain_id)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(source_domain_value, &source_chain) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(destination_reference.domain_value, &destination_chain) != 0) {
        secdat_domain_chain_free(&source_chain);
        return 1;
    }
    if (secdat_require_mutable_session_chain(&destination_chain, "ln") != 0
        || secdat_require_writable_domain_chain(&destination_chain) != 0) {
        goto cleanup;
    }
    if (secdat_active_overlay_enabled(&source_chain) || secdat_active_overlay_enabled(&destination_chain)) {
        fprintf(stderr, _("ln is not supported in a volatile session overlay\n"));
        goto cleanup;
    }
    if (secdat_read_store_format(destination_domain_id, destination_reference.store_value, &format) != 0) {
        goto cleanup;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        goto cleanup;
    }
    if (format != SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("ln requires source and destination in v2 stores\n"));
        secdat_print_store_migration_hint(cli->program_name, destination_reference.store_value);
        goto cleanup;
    }
    if (!secdat_v2_domain_entry_key_access_available(destination_domain_id)) {
        fprintf(stderr, _("missing SECDAT_MASTER_KEY and no active secdat session; run secdat unlock or export SECDAT_MASTER_KEY\n"));
        secdat_print_locked_read_guidance(&destination_chain);
        goto cleanup;
    }

    if (source_is_uuid) {
        if (secdat_resolve_v2_effective_entry_by_secret_id(&source_chain, source_store_value, source_secret_id, &source_entry) != 0) {
            goto cleanup;
        }
    } else {
        if (secdat_resolve_effective_entry(&source_chain, source_store_value, source_reference.key, 0, &source_entry) != 0) {
            fprintf(stderr, _("key not found: %s\n"), source_reference.key);
            goto cleanup;
        }
        if (!source_entry.from_v2) {
            fprintf(stderr, _("ln requires source and destination in v2 stores\n"));
            secdat_print_store_migration_hint(cli->program_name, source_store_value);
            goto cleanup;
        }
    }
    if (secdat_resolve_entry_path(&destination_chain, destination_reference.store_value, destination_reference.key, destination_path, sizeof(destination_path)) == 0) {
        fprintf(stderr, _("destination key already exists: %s\n"), destination_reference.key);
        goto cleanup;
    }

    status = secdat_link_v2_key(
        &source_chain,
        destination_domain_id,
        destination_reference.store_value,
        destination_reference.key,
        &source_entry
    );

cleanup:
    secdat_effective_entry_reset(&source_entry);
    secdat_domain_chain_free(&source_chain);
    secdat_domain_chain_free(&destination_chain);
    return status;
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
    struct secdat_secret_attrs attrs;
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

    if (secdat_load_resolved_secret_attrs(&source_chain, source_reference.store_value, source_reference.key, &attrs, &unsafe_store) != 0
        || secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store, NULL) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext_attrs_for_chain(&destination_chain, destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store, &attrs);
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
    struct secdat_secret_attrs attrs;
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

    if (secdat_load_resolved_secret_attrs(&source_chain, source_reference.store_value, source_reference.key, &attrs, &unsafe_store) != 0
        || secdat_load_resolved_plaintext(&source_chain, source_reference.store_value, source_reference.key, &plaintext, &plaintext_length, NULL, &unsafe_store, NULL) != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return 1;
    }

    status = secdat_store_plaintext_attrs_for_chain(&destination_chain, destination_domain_id, destination_reference.store_value, destination_reference.key, plaintext, plaintext_length, unsafe_store, &attrs);
    secdat_secure_clear(plaintext, plaintext_length);
    free(plaintext);
    if (status != 0) {
        secdat_domain_chain_free(&source_chain);
        secdat_domain_chain_free(&destination_chain);
        return status;
    }

    status = secdat_remove_key_in_chain(&source_chain, source_reference.store_value, source_reference.key, 0);
    if (status != 0) {
        (void)secdat_remove_key_in_chain(&destination_chain, destination_reference.store_value, destination_reference.key, 1);
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

static void secdat_store_migrate_report_issue(
    struct secdat_store_migrate_report *report,
    const char *kind,
    const char *key,
    const char *detail
)
{
    printf("cannot-migrate\t%s\t%s\t%s\n", kind, key, detail);
    report->issues += 1;
}

static void secdat_store_migrate_v1_plan_free(struct secdat_store_migrate_v1_plan *plan)
{
    secdat_key_list_free(&plan->entries);
    secdat_key_list_free(&plan->metadata);
    secdat_key_list_free(&plan->tombstones);
}

static int secdat_store_migrate_prepare_v2(
    const struct secdat_domain_chain *chain,
    const struct secdat_store_migrate_options *options,
    struct secdat_store_migrate_report *report,
    struct secdat_store_migrate_v1_plan *plan
)
{
    char entry_path[PATH_MAX];
    char metadata_path[PATH_MAX];
    struct stat store_status;
    struct secdat_secret_attrs attrs;
    const char *current_domain_id;
    enum secdat_store_format format;
    size_t index;
    int unsafe_store = 0;
    int status = 1;

    memset(report, 0, sizeof(*report));
    memset(plan, 0, sizeof(*plan));
    if (chain->count == 0) {
        fprintf(stderr, _("store migrate requires a registered current domain\n"));
        return 1;
    }
    current_domain_id = chain->ids[0];

    if (secdat_store_root(current_domain_id, options->store_name, plan->store_root, sizeof(plan->store_root)) != 0
        || secdat_store_entries_dir(current_domain_id, options->store_name, plan->entries_dir, sizeof(plan->entries_dir)) != 0
        || secdat_store_tombstones_dir(current_domain_id, options->store_name, plan->tombstones_dir, sizeof(plan->tombstones_dir)) != 0) {
        return 1;
    }
    if (stat(plan->store_root, &store_status) != 0 || !S_ISDIR(store_status.st_mode)) {
        fprintf(stderr, _("store not found: %s\n"), options->store_name);
        return 1;
    }
    if (secdat_read_store_format(current_domain_id, options->store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format != SECDAT_STORE_FORMAT_V1) {
        fprintf(stderr, _("store format is v2; migration is not needed\n"));
        return 2;
    }
    if (secdat_collect_directory_keys(plan->entries_dir, ".sec", &plan->entries) != 0
        || secdat_collect_directory_keys(plan->entries_dir, ".meta", &plan->metadata) != 0
        || secdat_collect_directory_keys(plan->tombstones_dir, ".tomb", &plan->tombstones) != 0) {
        return 1;
    }

    if (plan->entries.count > 1) {
        qsort(plan->entries.items, plan->entries.count, sizeof(*plan->entries.items), secdat_compare_strings);
    }
    if (plan->metadata.count > 1) {
        qsort(plan->metadata.items, plan->metadata.count, sizeof(*plan->metadata.items), secdat_compare_strings);
    }
    if (plan->tombstones.count > 1) {
        qsort(plan->tombstones.items, plan->tombstones.count, sizeof(*plan->tombstones.items), secdat_compare_strings);
    }

    report->domain_entries = plan->entries.count;
    report->secret_objects = plan->entries.count;
    report->metadata_sidecars = plan->metadata.count;
    report->tombstones = plan->tombstones.count;

    for (index = 0; index < plan->entries.count; index += 1) {
        if (secdat_build_entry_path(current_domain_id, options->store_name, plan->entries.items[index], entry_path, sizeof(entry_path)) != 0
            || secdat_build_entry_metadata_path(current_domain_id, options->store_name, plan->entries.items[index], metadata_path, sizeof(metadata_path)) != 0) {
            return 1;
        }
        if (secdat_fsck_validate_v1_entry_file(entry_path, &unsafe_store) != 0) {
            secdat_store_migrate_report_issue(report, "dangling-entry", plan->entries.items[index], "invalid-entry");
            continue;
        }
        if (secdat_fsck_validate_v1_metadata_file(metadata_path, unsafe_store) != 0) {
            secdat_store_migrate_report_issue(report, "dangling-metadata", plan->entries.items[index], "invalid-metadata");
            continue;
        }
        if (secdat_read_secret_attrs(current_domain_id, options->store_name, plan->entries.items[index], unsafe_store, &attrs) != 0) {
            return 1;
        }
        if (unsafe_store) {
            report->public_values += 1;
        } else {
            report->encrypted_values += 1;
        }
        if (secdat_sandbox_inject_allows_bulk_selection(&attrs)) {
            report->injectable_entries += 1;
        }
    }

    for (index = 0; index < plan->metadata.count; index += 1) {
        if (!secdat_key_list_contains(&plan->entries, plan->metadata.items[index])) {
            secdat_store_migrate_report_issue(report, "orphaned-metadata", plan->metadata.items[index], "missing-entry");
        }
    }
    for (index = 0; index < plan->tombstones.count; index += 1) {
        if (!secdat_parent_has_visible_key(chain, options->store_name, plan->tombstones.items[index])) {
            secdat_store_migrate_report_issue(report, "orphaned-tombstone", plan->tombstones.items[index], "missing-parent");
        }
    }

    if (report->issues > 0) {
        printf("issues=%zu\n", report->issues);
        return 1;
    }

    status = 0;
    return status;
}

static int secdat_store_migrate_dry_run_v2(
    const struct secdat_domain_chain *chain,
    const struct secdat_store_migrate_options *options,
    struct secdat_store_migrate_report *report
)
{
    struct secdat_store_migrate_v1_plan plan = {0};
    int status;

    status = secdat_store_migrate_prepare_v2(chain, options, report, &plan);
    if (status != 0) {
        goto cleanup;
    }

    puts("format=v1");
    printf("target_format=%s\n", options->to_format);
    puts("dry_run=yes");
    printf("store=%s\n", options->store_name);
    printf("domain_entries=%zu\n", report->domain_entries);
    printf("secret_objects=%zu\n", report->secret_objects);
    printf("metadata_sidecars=%zu\n", report->metadata_sidecars);
    printf("tombstones=%zu\n", report->tombstones);
    printf("public_values=%zu\n", report->public_values);
    printf("encrypted_values=%zu\n", report->encrypted_values);
    printf("injectable_entries=%zu\n", report->injectable_entries);
    puts("issues=0");
    status = 0;

cleanup:
    secdat_store_migrate_v1_plan_free(&plan);
    return status;
}

static void secdat_store_migrate_rollback_v2(
    const char *domain_id,
    const char *store_name,
    int had_format_marker,
    int marker_written,
    const struct secdat_key_list *written_paths
)
{
    char format_path[PATH_MAX];
    size_t index;

    for (index = written_paths->count; index > 0; index -= 1) {
        (void)secdat_remove_if_exists(written_paths->items[index - 1]);
    }
    if (!marker_written) {
        return;
    }
    if (had_format_marker) {
        (void)secdat_write_store_format_marker(domain_id, store_name, "v1", "ready");
        return;
    }
    if (secdat_store_format_path(domain_id, store_name, format_path, sizeof(format_path)) == 0) {
        (void)secdat_remove_if_exists(format_path);
    }
}

static int secdat_store_migrate_write_v2(
    const struct secdat_domain_chain *chain,
    const struct secdat_store_migrate_options *options,
    struct secdat_store_migrate_report *report
)
{
    struct secdat_store_migrate_v1_plan plan = {0};
    struct secdat_key_list written_paths = {0};
    struct secdat_fsck_options fsck_options = {"v2", 1, 1, 1, 0};
    struct secdat_fsck_report fsck_report;
    char domain_entries_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    char entry_path[PATH_MAX];
    char metadata_path[PATH_MAX];
    char object_path[PATH_MAX];
    char entry_id[37];
    char secret_id[37];
    struct secdat_secret_attrs attrs;
    unsigned char object_key[SECDAT_V2_OBJECT_KEY_LEN];
    const unsigned char *object_key_ptr = NULL;
    const char *current_domain_id;
    size_t index;
    int unsafe_store;
    int had_format_marker = 0;
    int marker_written = 0;
    int status = 1;

    status = secdat_store_migrate_prepare_v2(chain, options, report, &plan);
    if (status != 0) {
        goto cleanup;
    }
    status = 1;
    current_domain_id = chain->ids[0];

    if (secdat_v2_domain_entries_dir(current_domain_id, options->store_name, domain_entries_dir, sizeof(domain_entries_dir)) != 0
        || secdat_v2_secret_objects_dir(current_domain_id, options->store_name, secret_objects_dir, sizeof(secret_objects_dir)) != 0) {
        goto cleanup;
    }
    if (!secdat_directory_is_empty(domain_entries_dir) || !secdat_directory_is_empty(secret_objects_dir)) {
        fprintf(stderr, _("v2 migration artifacts already exist\n"));
        goto cleanup;
    }
    if (secdat_ensure_directory(domain_entries_dir, 0700) != 0
        || secdat_ensure_directory(secret_objects_dir, 0700) != 0) {
        goto cleanup;
    }

    for (index = 0; index < plan.entries.count; index += 1) {
        object_key_ptr = NULL;
        if (secdat_build_entry_path(current_domain_id, options->store_name, plan.entries.items[index], entry_path, sizeof(entry_path)) != 0
            || secdat_build_entry_metadata_path(current_domain_id, options->store_name, plan.entries.items[index], metadata_path, sizeof(metadata_path)) != 0) {
            goto rollback;
        }
        if (secdat_fsck_validate_v1_entry_file(entry_path, &unsafe_store) != 0
            || secdat_read_secret_attrs(current_domain_id, options->store_name, plan.entries.items[index], unsafe_store, &attrs) != 0) {
            goto rollback;
        }
        if (secdat_generate_uuid_v4(entry_id, sizeof(entry_id)) != 0
            || secdat_generate_uuid_v4(secret_id, sizeof(secret_id)) != 0) {
            goto rollback;
        }
        if (snprintf(object_path, sizeof(object_path), "%s/%s.sec", secret_objects_dir, secret_id) >= (int)sizeof(object_path)
            || secdat_key_list_append_duplicate(&written_paths, object_path) != 0
            || secdat_write_v2_secret_object_file(secret_objects_dir, secret_id, &attrs, 1, 1, NULL, 0, object_path, sizeof(object_path)) != 0) {
            goto rollback;
        }
        if (attrs.value_access == SECDAT_VALUE_ACCESS_UNLOCKED) {
            if (secdat_v2_generate_object_key(object_key) != 0) {
                goto rollback;
            }
            object_key_ptr = object_key;
        }
        if (snprintf(entry_path, sizeof(entry_path), "%s/%s.dent", domain_entries_dir, entry_id) >= (int)sizeof(entry_path)
            || secdat_key_list_append_duplicate(&written_paths, entry_path) != 0
            || secdat_write_v2_domain_entry_file(
                current_domain_id,
                domain_entries_dir,
                entry_id,
                secret_id,
                current_domain_id,
                options->store_name,
                plan.entries.items[index],
                &attrs,
                object_key_ptr,
                entry_path,
                sizeof(entry_path)
            ) != 0) {
            if (object_key_ptr != NULL) {
                secdat_secure_clear(object_key, sizeof(object_key));
            }
            goto rollback;
        }
        if (object_key_ptr != NULL) {
            secdat_secure_clear(object_key, sizeof(object_key));
        }
    }

    if (secdat_store_format_path(current_domain_id, options->store_name, entry_path, sizeof(entry_path)) != 0) {
        goto rollback;
    }
    had_format_marker = secdat_file_exists(entry_path);
    if (secdat_write_store_format_marker(current_domain_id, options->store_name, "v2", "ready") != 0) {
        goto rollback;
    }
    marker_written = 1;

    memset(&fsck_report, 0, sizeof(fsck_report));
    if (secdat_fsck_v2_store(chain, options->store_name, &fsck_options, &fsck_report) != 0 || fsck_report.issues != 0) {
        fprintf(stderr, _("v2 migration verification failed\n"));
        goto rollback;
    }

    puts("format=v1");
    printf("target_format=%s\n", options->to_format);
    puts("dry_run=no");
    printf("store=%s\n", options->store_name);
    printf("domain_entries=%zu\n", report->domain_entries);
    printf("secret_objects=%zu\n", report->secret_objects);
    printf("metadata_sidecars=%zu\n", report->metadata_sidecars);
    printf("tombstones=%zu\n", report->tombstones);
    printf("public_values=%zu\n", report->public_values);
    printf("encrypted_values=%zu\n", report->encrypted_values);
    printf("injectable_entries=%zu\n", report->injectable_entries);
    puts("issues=0");
    puts("verified=yes");
    status = 0;
    goto cleanup;

rollback:
    secdat_store_migrate_rollback_v2(current_domain_id, options->store_name, had_format_marker, marker_written, &written_paths);
    status = 1;

cleanup:
    secdat_key_list_free(&written_paths);
    secdat_store_migrate_v1_plan_free(&plan);
    return status;
}

static int secdat_store_command_migrate(const struct secdat_cli *cli)
{
    struct secdat_store_migrate_options options;
    struct secdat_store_migrate_report report;
    struct secdat_domain_chain chain = {0};
    int status;

    if (cli->store != NULL) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    status = secdat_parse_store_migrate_options(cli, &options);
    if (status != 0) {
        return status;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (!options.dry_run
        && (secdat_require_mutable_session_chain(&chain, "store migrate") != 0
            || secdat_require_writable_domain_chain(&chain) != 0)) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    if (options.dry_run) {
        status = secdat_store_migrate_dry_run_v2(&chain, &options, &report);
    } else {
        status = secdat_store_migrate_write_v2(&chain, &options, &report);
    }
    secdat_domain_chain_free(&chain);
    return status;
}

static void secdat_store_finalize_migration_report_issue(
    struct secdat_store_finalize_migration_report *report,
    const char *kind,
    const char *key,
    const char *detail
)
{
    printf("cannot-finalize\t%s\t%s\t%s\n", kind, key, detail);
    report->issues += 1;
}

static int secdat_store_finalize_migration_legacy_entry_status(
    const char *domain_id,
    const char *store_name,
    const char *key,
    const char **detail
)
{
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    char value_path[PATH_MAX];
    struct secdat_v2_domain_entry_info entry;
    struct secdat_v2_secret_object_info object;
    const char *object_domain_id;
    const char *object_store_name;
    int lookup_status;

    *detail = NULL;
    lookup_status = secdat_lookup_v2_domain_entry_authoritative(domain_id, store_name, key, &entry, entry_path, sizeof(entry_path));
    if (lookup_status > 1) {
        return 1;
    }
    if (lookup_status != 0) {
        *detail = "missing-v2-entry";
        return 0;
    }

    object_domain_id = secdat_v2_entry_object_domain(domain_id, &entry);
    object_store_name = secdat_v2_entry_object_store(store_name, &entry);
    if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry.secret_id, object_path, sizeof(object_path)) != 0
        || secdat_build_v2_secret_value_path(object_domain_id, object_store_name, entry.secret_id, value_path, sizeof(value_path)) != 0) {
        return 1;
    }
    if (secdat_read_v2_secret_object_info(object_path, entry.secret_id, &object) != 0) {
        *detail = "invalid-v2-secret";
        return 0;
    }
    if (object.has_value_payload) {
        if (secdat_validate_v2_secret_object_payload_format(object_path, entry.secret_id) != 0) {
            *detail = "invalid-object-payload";
            return 0;
        }
        *detail = "object-payload";
        return 0;
    }
    if (secdat_file_exists(value_path)) {
        if (secdat_validate_v2_secret_value_file(value_path) != 0) {
            *detail = "invalid-object-value-sidecar";
            return 0;
        }
        *detail = "object-value-sidecar";
        return 0;
    }

    *detail = "missing-object-payload";
    return 0;
}

static int secdat_store_finalize_migration_metadata_status(
    const char *domain_id,
    const char *store_name,
    const char *key,
    const char **detail
)
{
    char entry_path[PATH_MAX];
    char object_path[PATH_MAX];
    struct secdat_v2_domain_entry_info entry;
    struct secdat_v2_secret_object_info object;
    const char *object_domain_id;
    const char *object_store_name;
    int lookup_status;

    *detail = NULL;
    lookup_status = secdat_lookup_v2_domain_entry_authoritative(domain_id, store_name, key, &entry, entry_path, sizeof(entry_path));
    if (lookup_status > 1) {
        return 1;
    }
    if (lookup_status != 0) {
        *detail = "missing-v2-entry";
        return 0;
    }

    object_domain_id = secdat_v2_entry_object_domain(domain_id, &entry);
    object_store_name = secdat_v2_entry_object_store(store_name, &entry);
    if (secdat_build_v2_secret_object_path(object_domain_id, object_store_name, entry.secret_id, object_path, sizeof(object_path)) != 0) {
        return 1;
    }
    if (secdat_read_v2_secret_object_info(object_path, entry.secret_id, &object) != 0) {
        *detail = "invalid-v2-secret";
        return 0;
    }

    *detail = "v2-metadata";
    return 0;
}

static int secdat_store_finalize_migration_remove_legacy_entry(
    const char *domain_id,
    const char *store_name,
    const char *key,
    const char *detail,
    struct secdat_store_finalize_migration_report *report
)
{
    char entry_path[PATH_MAX];

    if (secdat_build_entry_path(domain_id, store_name, key, entry_path, sizeof(entry_path)) != 0
        || secdat_remove_if_exists(entry_path) != 0) {
        return 1;
    }
    printf("removed-legacy-entry\t%s\t%s\n", key, detail);
    report->removed_legacy_entries += 1;
    return 0;
}

static int secdat_store_finalize_migration_remove_metadata(
    const char *domain_id,
    const char *store_name,
    const char *key,
    const char *detail,
    struct secdat_store_finalize_migration_report *report
)
{
    char metadata_path[PATH_MAX];

    if (secdat_build_entry_metadata_path(domain_id, store_name, key, metadata_path, sizeof(metadata_path)) != 0
        || secdat_remove_if_exists(metadata_path) != 0) {
        return 1;
    }
    printf("removed-legacy-metadata\t%s\t%s\n", key, detail);
    report->removed_metadata_sidecars += 1;
    return 0;
}

static void secdat_store_finalize_migration_print_summary(
    const struct secdat_store_finalize_migration_options *options,
    const struct secdat_store_finalize_migration_report *report
)
{
    puts("format=v2");
    printf("from_format=%s\n", options->from_format);
    printf("dry_run=%s\n", options->dry_run ? "yes" : "no");
    printf("store=%s\n", options->store_name);
    printf("legacy_entries=%zu\n", report->legacy_entries);
    printf("metadata_sidecars=%zu\n", report->metadata_sidecars);
    printf("removable_legacy_entries=%zu\n", report->removable_legacy_entries);
    printf("removable_metadata_sidecars=%zu\n", report->removable_metadata_sidecars);
    printf("removed_legacy_entries=%zu\n", report->removed_legacy_entries);
    printf("removed_metadata_sidecars=%zu\n", report->removed_metadata_sidecars);
    printf("blocking_legacy_entries=%zu\n", report->blocking_legacy_entries);
    printf("blocking_metadata_sidecars=%zu\n", report->blocking_metadata_sidecars);
    printf("issues=%zu\n", report->issues);
}

static int secdat_store_finalize_migration_run_v1(
    const struct secdat_domain_chain *chain,
    const struct secdat_store_finalize_migration_options *options,
    struct secdat_store_finalize_migration_report *report
)
{
    char store_root[PATH_MAX];
    char entries_dir[PATH_MAX];
    struct stat store_status;
    struct secdat_key_list legacy_entries = {0};
    struct secdat_key_list metadata = {0};
    enum secdat_store_format format;
    const char *current_domain_id;
    size_t index;
    int status = 1;

    memset(report, 0, sizeof(*report));
    if (chain->count == 0) {
        fprintf(stderr, _("store finalize-migration requires a registered current domain\n"));
        return 1;
    }
    current_domain_id = chain->ids[0];

    if (secdat_store_root(current_domain_id, options->store_name, store_root, sizeof(store_root)) != 0
        || secdat_store_entries_dir(current_domain_id, options->store_name, entries_dir, sizeof(entries_dir)) != 0) {
        return 1;
    }
    if (stat(store_root, &store_status) != 0 || !S_ISDIR(store_status.st_mode)) {
        fprintf(stderr, _("store not found: %s\n"), options->store_name);
        return 1;
    }
    if (secdat_read_store_format(current_domain_id, options->store_name, &format) != 0) {
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }
    if (format != SECDAT_STORE_FORMAT_V2) {
        fprintf(stderr, _("store format is v1; finalize-migration requires a migrated v2 store\n"));
        return 2;
    }
    if (secdat_collect_directory_keys(entries_dir, ".sec", &legacy_entries) != 0
        || secdat_collect_directory_keys(entries_dir, ".meta", &metadata) != 0) {
        goto cleanup;
    }
    if (legacy_entries.count > 1) {
        qsort(legacy_entries.items, legacy_entries.count, sizeof(*legacy_entries.items), secdat_compare_strings);
    }
    if (metadata.count > 1) {
        qsort(metadata.items, metadata.count, sizeof(*metadata.items), secdat_compare_strings);
    }

    report->legacy_entries = legacy_entries.count;
    report->metadata_sidecars = metadata.count;

    for (index = 0; index < legacy_entries.count; index += 1) {
        const char *detail = NULL;

        if (secdat_store_finalize_migration_legacy_entry_status(
                current_domain_id,
                options->store_name,
                legacy_entries.items[index],
                &detail
            ) != 0) {
            goto cleanup;
        }
        if (strcmp(detail, "object-payload") == 0 || strcmp(detail, "object-value-sidecar") == 0) {
            if (options->dry_run) {
                printf("would-remove-legacy-entry\t%s\t%s\n", legacy_entries.items[index], detail);
            }
            report->removable_legacy_entries += 1;
        } else {
            secdat_store_finalize_migration_report_issue(report, "legacy-entry", legacy_entries.items[index], detail);
            report->blocking_legacy_entries += 1;
        }
    }

    for (index = 0; index < metadata.count; index += 1) {
        const char *detail = NULL;

        if (secdat_store_finalize_migration_metadata_status(
                current_domain_id,
                options->store_name,
                metadata.items[index],
                &detail
            ) != 0) {
            goto cleanup;
        }
        if (strcmp(detail, "v2-metadata") == 0) {
            if (options->dry_run) {
                printf("would-remove-legacy-metadata\t%s\t%s\n", metadata.items[index], detail);
            }
            report->removable_metadata_sidecars += 1;
        } else {
            secdat_store_finalize_migration_report_issue(report, "legacy-metadata", metadata.items[index], detail);
            report->blocking_metadata_sidecars += 1;
        }
    }

    if (!options->dry_run && report->issues == 0) {
        for (index = 0; index < legacy_entries.count; index += 1) {
            const char *detail = NULL;

            if (secdat_store_finalize_migration_legacy_entry_status(
                    current_domain_id,
                    options->store_name,
                    legacy_entries.items[index],
                    &detail
                ) != 0) {
                goto cleanup;
            }
            if (strcmp(detail, "object-payload") == 0 || strcmp(detail, "object-value-sidecar") == 0) {
                if (secdat_store_finalize_migration_remove_legacy_entry(
                        current_domain_id,
                        options->store_name,
                        legacy_entries.items[index],
                        detail,
                        report
                    ) != 0) {
                    goto cleanup;
                }
            }
        }
        for (index = 0; index < metadata.count; index += 1) {
            const char *detail = NULL;

            if (secdat_store_finalize_migration_metadata_status(
                    current_domain_id,
                    options->store_name,
                    metadata.items[index],
                    &detail
                ) != 0) {
                goto cleanup;
            }
            if (strcmp(detail, "v2-metadata") == 0) {
                if (secdat_store_finalize_migration_remove_metadata(
                        current_domain_id,
                        options->store_name,
                        metadata.items[index],
                        detail,
                        report
                    ) != 0) {
                    goto cleanup;
                }
            }
        }
    }

    secdat_store_finalize_migration_print_summary(options, report);
    status = report->issues == 0 ? 0 : 1;

cleanup:
    secdat_key_list_free(&legacy_entries);
    secdat_key_list_free(&metadata);
    return status;
}

static int secdat_store_command_finalize_migration(const struct secdat_cli *cli)
{
    struct secdat_store_finalize_migration_options options;
    struct secdat_store_finalize_migration_report report;
    struct secdat_domain_chain chain = {0};
    int status;

    if (cli->store != NULL) {
        fprintf(stderr, _("--store is not valid with store commands\n"));
        secdat_cli_print_try_help(cli, "store");
        return 2;
    }
    status = secdat_parse_store_finalize_migration_options(cli, &options);
    if (status != 0) {
        return status;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (!options.dry_run
        && (secdat_require_mutable_session_chain(&chain, "store finalize-migration") != 0
            || secdat_require_writable_domain_chain(&chain) != 0)) {
        secdat_domain_chain_free(&chain);
        return 1;
    }

    status = secdat_store_finalize_migration_run_v1(&chain, &options, &report);
    secdat_domain_chain_free(&chain);
    return status;
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
    char format_path[PATH_MAX];
    char domain_entries_dir[PATH_MAX];
    char objects_dir[PATH_MAX];
    char secret_objects_dir[PATH_MAX];
    struct stat store_status;
    enum secdat_store_format format;
    int contains_only;
    const char *v1_store_names[] = {"entries", "tombstones", "format"};
    const char *v2_store_names[] = {"entries", "tombstones", "domain-ent", "objects", "format"};
    const char *v2_objects_names[] = {"secret"};

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
    if (stat(store_root, &store_status) != 0 || !S_ISDIR(store_status.st_mode)) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("store not found: %s\n"), cli->argv[0]);
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
    if (secdat_read_store_format(current_domain_id, cli->argv[0], &format) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (format == SECDAT_STORE_FORMAT_INVALID) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("invalid store format marker\n"));
        return 1;
    }

    if (format == SECDAT_STORE_FORMAT_V2) {
        if (secdat_store_format_path(current_domain_id, cli->argv[0], format_path, sizeof(format_path)) != 0
            || secdat_v2_domain_entries_dir(current_domain_id, cli->argv[0], domain_entries_dir, sizeof(domain_entries_dir)) != 0
            || secdat_v2_objects_dir(current_domain_id, cli->argv[0], objects_dir, sizeof(objects_dir)) != 0
            || secdat_v2_secret_objects_dir(current_domain_id, cli->argv[0], secret_objects_dir, sizeof(secret_objects_dir)) != 0
            || secdat_directory_contains_only_names(objects_dir, v2_objects_names, sizeof(v2_objects_names) / sizeof(v2_objects_names[0]), &contains_only) != 0) {
            secdat_domain_chain_free(&chain);
            return 1;
        }
        if (!contains_only
            || !secdat_directory_is_empty(entries_dir)
            || !secdat_directory_is_empty(tombstones_dir)
            || !secdat_directory_is_empty(domain_entries_dir)
            || !secdat_directory_is_empty(secret_objects_dir)) {
            secdat_domain_chain_free(&chain);
            fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
            return 1;
        }
        if (secdat_directory_contains_only_names(store_root, v2_store_names, sizeof(v2_store_names) / sizeof(v2_store_names[0]), &contains_only) != 0) {
            secdat_domain_chain_free(&chain);
            return 1;
        }
        if (!contains_only) {
            secdat_domain_chain_free(&chain);
            fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
            return 1;
        }
        if (secdat_remove_directory_if_exists(entries_dir) != 0
            || secdat_remove_directory_if_exists(tombstones_dir) != 0
            || secdat_remove_directory_if_exists(domain_entries_dir) != 0
            || secdat_remove_directory_if_exists(secret_objects_dir) != 0
            || secdat_remove_directory_if_exists(objects_dir) != 0
            || secdat_remove_if_exists(format_path) != 0
            || secdat_remove_directory_if_exists(store_root) != 0) {
            secdat_domain_chain_free(&chain);
            return 1;
        }
        secdat_domain_chain_free(&chain);
        return 0;
    }

    if (!secdat_directory_is_empty(entries_dir) || !secdat_directory_is_empty(tombstones_dir)) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
        return 1;
    }
    if (secdat_directory_contains_only_names(store_root, v1_store_names, sizeof(v1_store_names) / sizeof(v1_store_names[0]), &contains_only) != 0) {
        secdat_domain_chain_free(&chain);
        return 1;
    }
    if (!contains_only) {
        secdat_domain_chain_free(&chain);
        fprintf(stderr, _("store is not empty: %s\n"), cli->argv[0]);
        return 1;
    }
    if (secdat_store_format_path(current_domain_id, cli->argv[0], format_path, sizeof(format_path)) != 0
        || secdat_remove_directory_if_exists(entries_dir) != 0
        || secdat_remove_directory_if_exists(tombstones_dir) != 0
        || secdat_remove_if_exists(format_path) != 0
        || secdat_remove_directory_if_exists(store_root) != 0) {
        secdat_domain_chain_free(&chain);
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

static int secdat_key_allows_bulk_sandbox_injection(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    int *allowed
)
{
    struct secdat_secret_attrs attrs;

    *allowed = 0;
    if (secdat_load_resolved_secret_attrs(chain, store_name, key, &attrs, NULL) != 0) {
        return 1;
    }
    *allowed = secdat_sandbox_inject_allows_bulk_selection(&attrs);
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
    struct secdat_export_options options;
    char canonical_dir[PATH_MAX];
    size_t key_index;

    if (secdat_parse_export_options(cli, &options) != 0) {
        secdat_cli_print_try_help(cli, "export");
        return 2;
    }

    if (secdat_canonicalize_directory_path(secdat_cli_domain_base(cli), canonical_dir, sizeof(canonical_dir)) != 0) {
        return 1;
    }
    if (secdat_domain_resolve_chain(secdat_cli_domain_base(cli), &chain) != 0) {
        return 1;
    }
    if (options.pattern != NULL && secdat_key_list_append(&include_patterns, options.pattern) != 0) {
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
        if (options.sandbox_injectable) {
            int allowed = 0;

            if (secdat_key_allows_bulk_sandbox_injection(&chain, cli->store, visible_keys.items[key_index], &allowed) != 0) {
                secdat_key_list_free(&include_patterns);
                secdat_domain_chain_free(&chain);
                secdat_key_list_free(&visible_keys);
                return 1;
            }
            if (!allowed) {
                continue;
            }
        }
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

        if (options.sandbox_injectable) {
            int allowed = 0;

            status = secdat_key_allows_bulk_sandbox_injection(&chain, cli->store, visible_keys.items[key_index], &allowed);
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
            if (!allowed) {
                continue;
            }
        }
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
    case SECDAT_COMMAND_ATTR:
        return secdat_command_attr(cli);
    case SECDAT_COMMAND_FSCK:
        return secdat_command_fsck(cli);
    case SECDAT_COMMAND_GC:
        return secdat_command_gc(cli);
    case SECDAT_COMMAND_MASK:
        return secdat_command_mask(cli);
    case SECDAT_COMMAND_UNMASK:
        return secdat_command_unmask(cli);
    case SECDAT_COMMAND_EXISTS:
        return secdat_command_exists(cli);
    case SECDAT_COMMAND_ID:
        return secdat_command_id(cli);
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
    case SECDAT_COMMAND_LN:
        return secdat_command_ln(cli);
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
    case SECDAT_COMMAND_STORE_MIGRATE:
        return secdat_store_command_migrate(cli);
    case SECDAT_COMMAND_STORE_FINALIZE_MIGRATION:
        return secdat_store_command_finalize_migration(cli);
    case SECDAT_COMMAND_SECRET_STATUS:
        return secdat_command_secret_status(cli);
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
