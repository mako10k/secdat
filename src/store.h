#ifndef SECDAT_STORE_H
#define SECDAT_STORE_H

#include "cli.h"

#include <stddef.h>
#include <time.h>

enum secdat_key_source_type {
	SECDAT_KEY_SOURCE_LOCKED = 0,
	SECDAT_KEY_SOURCE_ENVIRONMENT,
	SECDAT_KEY_SOURCE_SESSION,
};

struct secdat_domain_status_summary {
	size_t store_count;
	size_t visible_key_count;
	int wrapped_master_key_present;
	enum secdat_key_source_type key_source;
	time_t session_expires_at;
};

int secdat_run_command(const struct secdat_cli *cli);
int secdat_collect_domain_status_summary(const char *dir_override, struct secdat_domain_status_summary *summary);

#endif