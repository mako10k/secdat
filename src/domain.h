#ifndef SECDAT_DOMAIN_H
#define SECDAT_DOMAIN_H

#include "cli.h"

#include <stddef.h>

struct secdat_domain_chain {
    char **ids;
    size_t count;
};

void secdat_domain_chain_free(struct secdat_domain_chain *chain);
int secdat_domain_resolve_current(const char *dir_override, char *buffer, size_t size);
int secdat_domain_resolve_chain(const char *dir_override, struct secdat_domain_chain *chain);
int secdat_domain_store_root(const char *domain_id, const char *store_name, char *buffer, size_t size);
int secdat_handle_domain_command(const struct secdat_cli *cli);

#endif