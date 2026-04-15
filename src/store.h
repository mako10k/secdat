#ifndef SECDAT_STORE_H
#define SECDAT_STORE_H

#include "cli.h"

#include <limits.h>
#include <stddef.h>
#include <time.h>

enum secdat_key_source_type {
	SECDAT_KEY_SOURCE_LOCKED = 0,
	SECDAT_KEY_SOURCE_ENVIRONMENT,
	SECDAT_KEY_SOURCE_SESSION,
};

enum secdat_effective_source_type {
	SECDAT_EFFECTIVE_SOURCE_LOCKED = 0,
	SECDAT_EFFECTIVE_SOURCE_ENVIRONMENT,
	SECDAT_EFFECTIVE_SOURCE_LOCAL_SESSION,
	SECDAT_EFFECTIVE_SOURCE_INHERITED_SESSION,
	SECDAT_EFFECTIVE_SOURCE_EXPLICIT_LOCK,
	SECDAT_EFFECTIVE_SOURCE_BLOCKED,
};

struct secdat_domain_status_summary {
	size_t store_count;
	size_t visible_key_count;
	int wrapped_master_key_present;
	enum secdat_key_source_type key_source;
	enum secdat_effective_source_type effective_source;
	time_t session_expires_at;
	char related_domain_root[PATH_MAX];
};

int secdat_run_command(const struct secdat_cli *cli);
int secdat_collect_domain_status_summary(const char *dir_override, struct secdat_domain_status_summary *summary);

#endif