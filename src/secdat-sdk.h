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
};

enum secdat_sdk_effective_source_type {
    SECDAT_SDK_EFFECTIVE_SOURCE_LOCKED = 0,
    SECDAT_SDK_EFFECTIVE_SOURCE_ENVIRONMENT,
    SECDAT_SDK_EFFECTIVE_SOURCE_LOCAL_SESSION,
    SECDAT_SDK_EFFECTIVE_SOURCE_INHERITED_SESSION,
    SECDAT_SDK_EFFECTIVE_SOURCE_EXPLICIT_LOCK,
    SECDAT_SDK_EFFECTIVE_SOURCE_BLOCKED,
};

struct secdat_sdk_options {
    const char *dir;
    const char *domain;
    const char *store;
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
int secdat_sdk_exists(
    const struct secdat_sdk_options *options,
    const char *keyref,
    int *exists_out
);
int secdat_sdk_collect_status(
    const struct secdat_sdk_options *options,
    struct secdat_sdk_status_summary *summary
);
void secdat_sdk_free(void *pointer);

#ifdef __cplusplus
}
#endif

#endif