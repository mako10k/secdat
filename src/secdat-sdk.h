#ifndef SECDAT_SDK_H
#define SECDAT_SDK_H

#include <stddef.h>
#include <time.h>

#ifndef PATH_MAX
#include <limits.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum secdat_sdk_key_source_type {
    SECDAT_SDK_KEY_SOURCE_LOCKED = 0,
    SECDAT_SDK_KEY_SOURCE_ENVIRONMENT,
    SECDAT_SDK_KEY_SOURCE_SESSION,
    SECDAT_SDK_KEY_SOURCE_ORPHANED,
};

enum secdat_sdk_effective_source_type {
    SECDAT_SDK_EFFECTIVE_SOURCE_LOCKED = 0,
    SECDAT_SDK_EFFECTIVE_SOURCE_ENVIRONMENT,
    SECDAT_SDK_EFFECTIVE_SOURCE_LOCAL_SESSION,
    SECDAT_SDK_EFFECTIVE_SOURCE_INHERITED_SESSION,
    SECDAT_SDK_EFFECTIVE_SOURCE_EXPLICIT_LOCK,
    SECDAT_SDK_EFFECTIVE_SOURCE_BLOCKED,
    SECDAT_SDK_EFFECTIVE_SOURCE_ORPHANED,
};

struct secdat_sdk_options {
    const char *dir;
    const char *domain;
    const char *store;
};

struct secdat_sdk_list_filters {
    const char *include_pattern;
    const char *exclude_pattern;
    int safe;
    int unsafe_store;
    int bulk_gate;
};

struct secdat_sdk_domain_filters {
    const char *pattern;
    int include_ancestors;
    int include_descendants;
    int include_inherited;
};

struct secdat_sdk_status_summary {
    size_t store_count;
    size_t visible_key_count;
    int wrapped_master_key_present;
    enum secdat_sdk_key_source_type key_source;
    enum secdat_sdk_effective_source_type effective_source;
    time_t session_expires_at;
    char related_domain_root[PATH_MAX];
};

struct secdat_sdk_key_metadata {
    char key[PATH_MAX];
    char store[PATH_MAX];
    char canonical_keyref[PATH_MAX * 2];
    char source_domain[PATH_MAX];
    char source_type[16];
    int local;
    int inherited;
    int unsafe_store;
    char storage_mode[16];
    char key_visibility[16];
    char value_access[16];
    char bulk_select[16];
};

struct secdat_sdk_key_metadata_list {
    struct secdat_sdk_key_metadata *items;
    size_t count;
};

struct secdat_sdk_store_metadata {
    char name[PATH_MAX];
};

struct secdat_sdk_store_metadata_list {
    struct secdat_sdk_store_metadata *items;
    size_t count;
};

struct secdat_sdk_domain_metadata {
    char root[PATH_MAX];
    int unlocked;
    enum secdat_sdk_key_source_type key_source;
    enum secdat_sdk_effective_source_type effective_source;
    time_t session_expires_at;
    time_t remaining_seconds;
    char related_domain_root[PATH_MAX];
    size_t store_count;
    size_t visible_key_count;
    int orphaned_domain;
    int wrapped_master_key_present;
};

struct secdat_sdk_domain_metadata_list {
    struct secdat_sdk_domain_metadata *items;
    size_t count;
};

int secdat_sdk_get(
    const struct secdat_sdk_options *options,
    const char *keyref,
    unsigned char **value_out,
    size_t *value_length_out,
    int *unsafe_store_out
);
int secdat_sdk_set(
    const struct secdat_sdk_options *options,
    const char *keyref,
    const unsigned char *value,
    size_t value_length,
    int unsafe_store
);
int secdat_sdk_set_preserve_attrs(
    const struct secdat_sdk_options *options,
    const char *keyref,
    const unsigned char *value,
    size_t value_length
);
int secdat_sdk_rm(
    const struct secdat_sdk_options *options,
    const char *keyref,
    int ignore_missing
);
int secdat_sdk_mv(
    const struct secdat_sdk_options *options,
    const char *source_keyref,
    const char *destination_keyref
);
int secdat_sdk_cp(
    const struct secdat_sdk_options *options,
    const char *source_keyref,
    const char *destination_keyref
);
int secdat_sdk_mask(
    const struct secdat_sdk_options *options,
    const char *keyref
);
int secdat_sdk_unmask(
    const struct secdat_sdk_options *options,
    const char *keyref
);
int secdat_sdk_unlock(const struct secdat_sdk_options *options);
int secdat_sdk_lock(const struct secdat_sdk_options *options);
int secdat_sdk_exists(
    const struct secdat_sdk_options *options,
    const char *keyref,
    int *exists_out
);
int secdat_sdk_collect_status(
    const struct secdat_sdk_options *options,
    struct secdat_sdk_status_summary *summary
);

/* Metadata-only list APIs allocate result_out->items; release it with secdat_sdk_free(). */
int secdat_sdk_list_keys(
    const struct secdat_sdk_options *options,
    const struct secdat_sdk_list_filters *filters,
    struct secdat_sdk_key_metadata_list *result_out
);
int secdat_sdk_list_keys_with_patterns(
    const struct secdat_sdk_options *options,
    const struct secdat_sdk_list_filters *filters,
    const char *const *include_patterns,
    size_t include_pattern_count,
    const char *const *exclude_patterns,
    size_t exclude_pattern_count,
    struct secdat_sdk_key_metadata_list *result_out
);
int secdat_sdk_list_stores(
    const struct secdat_sdk_options *options,
    struct secdat_sdk_store_metadata_list *result_out
);
int secdat_sdk_list_domains(
    const struct secdat_sdk_options *options,
    const struct secdat_sdk_domain_filters *filters,
    struct secdat_sdk_domain_metadata_list *result_out
);

/* timeout_seconds <= 0 waits without a timeout, matching CLI wait-unlock without --timeout. */
int secdat_sdk_wait_unlock(
    const struct secdat_sdk_options *options,
    time_t timeout_seconds
);
void secdat_sdk_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif
