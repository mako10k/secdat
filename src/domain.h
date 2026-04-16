#ifndef SECDAT_DOMAIN_H
#define SECDAT_DOMAIN_H

#include "cli.h"

#include <limits.h>
#include <stddef.h>

#ifndef PATH_MAX
#include <linux/limits.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct secdat_domain_chain {
    char **ids;
    size_t count;
    char current_path[PATH_MAX];
};

struct secdat_domain_root_list {
    char **roots;
    size_t count;
};

void secdat_domain_chain_free(struct secdat_domain_chain *chain);
void secdat_domain_root_list_free(struct secdat_domain_root_list *list);
int secdat_domain_validate_root(const char *domain_root, char *buffer, size_t size);
int secdat_domain_resolve_current(const char *dir_override, char *buffer, size_t size);
int secdat_domain_resolve_chain(const char *dir_override, struct secdat_domain_chain *chain);
int secdat_collect_descendant_domain_roots(const char *root_path, struct secdat_domain_root_list *list);
int secdat_domain_data_root(const char *domain_id, char *buffer, size_t size);
int secdat_domain_root_path(const char *domain_id, char *buffer, size_t size);
int secdat_domain_display_label(const char *domain_id, char *buffer, size_t size);
int secdat_domain_display_path(const char *dir_override, const char *domain_id, char *buffer, size_t size);
int secdat_domain_store_root(const char *domain_id, const char *store_name, char *buffer, size_t size);
int secdat_handle_domain_command(const struct secdat_cli *cli);

#endif