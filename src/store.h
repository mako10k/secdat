#ifndef SECDAT_STORE_H
#define SECDAT_STORE_H

#include "cli.h"

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

enum secdat_key_source_type {
	SECDAT_KEY_SOURCE_LOCKED = 0,
	SECDAT_KEY_SOURCE_ENVIRONMENT,
	SECDAT_KEY_SOURCE_SESSION,
	SECDAT_KEY_SOURCE_ORPHANED,
};

enum secdat_effective_source_type {
	SECDAT_EFFECTIVE_SOURCE_LOCKED = 0,
	SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT,
	SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION,
	SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION,
	SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK,
	SECDAT_EFFECTIVE_SOURCE_BLOCKED,
	SECDAT_EFFECTIVE_SOURCE_ORPHANED,
};

struct secdat_domain_status_summary {
	size_t store_count;
	size_t visible_key_count;
	int wrapped_master_key_present;
	int orphaned_domain;
	enum secdat_key_source_type key_source;
	enum secdat_effective_source_type effective_source;
	time_t session_expires_at;
	char related_domain_root[PATH_MAX];
};

int secdat_run_command(const struct secdat_cli *cli);
int secdat_print_completion_keys(
	const char *dir_override,
	const char *domain_override,
	const char *store_name,
	const char *current,
	int append_equals
);
int secdat_collect_domain_status_summary(const char *dir_override, struct secdat_domain_status_summary *summary);
int secdat_collect_registered_domain_status_summary(const char *registered_root, struct secdat_domain_status_summary *summary);
int secdat_collect_user_global_status_summary(struct secdat_domain_status_summary *summary);
int secdat_require_writable_session_access(const char *dir_override, const char *command_name);
int secdat_require_writable_registered_domain_access(const char *registered_root, const char *command_name);
const char *secdat_key_source_json_name(enum secdat_key_source_type source);
const char *secdat_effective_source_json_name(enum secdat_effective_source_type source);
const char *secdat_effective_state_json_name(enum secdat_effective_source_type source);
long long secdat_remaining_seconds(time_t expires_at);
void secdat_write_json_string(FILE *stream, const char *value);

#endif
