#ifndef SECDAT_STORE_EXEC_PORT_H
#define SECDAT_STORE_EXEC_PORT_H

#include "domain.h"

#include <stddef.h>

struct secdat_cli;

int secdat_exec_port_collect_visible_keys(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    char ***keys_out,
    size_t *count_out
);
void secdat_exec_port_free_keys(char **keys, size_t count);

int secdat_exec_port_key_allows_bulk_sandbox(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    int *allowed
);

int secdat_exec_port_load_plaintext(
    const struct secdat_domain_chain *chain,
    const char *store_name,
    const char *key,
    unsigned char **plaintext_out,
    size_t *plaintext_length_out
);

int secdat_exec_port_plaintext_to_env_value(
    const char *key,
    const unsigned char *plaintext,
    size_t plaintext_length,
    char **value_out
);

void secdat_exec_port_secure_clear(void *buffer, size_t length);

const char *secdat_exec_port_effective_store_name(const char *store_name);

#endif