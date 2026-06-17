#ifndef SECDAT_CLI_H
#define SECDAT_CLI_H

#include <stddef.h>

enum secdat_command_type {
    SECDAT_COMMAND_HELP = 0,
    SECDAT_COMMAND_LS,
    SECDAT_COMMAND_LIST,
    SECDAT_COMMAND_ATTR,
    SECDAT_COMMAND_FSCK,
    SECDAT_COMMAND_GC,
    SECDAT_COMMAND_MASK,
    SECDAT_COMMAND_UNMASK,
    SECDAT_COMMAND_EXISTS,
    SECDAT_COMMAND_ID,
    SECDAT_COMMAND_GET,
    SECDAT_COMMAND_SET,
    SECDAT_COMMAND_RM,
    SECDAT_COMMAND_MV,
    SECDAT_COMMAND_CP,
    SECDAT_COMMAND_LN,
    SECDAT_COMMAND_EXEC,
    SECDAT_COMMAND_EXPORT,
    SECDAT_COMMAND_SAVE,
    SECDAT_COMMAND_LOAD,
    SECDAT_COMMAND_UNLOCK,
    SECDAT_COMMAND_INHERIT,
    SECDAT_COMMAND_PASSWD,
    SECDAT_COMMAND_LOCK,
    SECDAT_COMMAND_STATUS,
    SECDAT_COMMAND_WAIT_UNLOCK,
    SECDAT_COMMAND_STORE_CREATE,
    SECDAT_COMMAND_STORE_DELETE,
    SECDAT_COMMAND_STORE_LS,
    SECDAT_COMMAND_STORE_MIGRATE,
    SECDAT_COMMAND_STORE_FINALIZE_MIGRATION,
    SECDAT_COMMAND_SECRET_STATUS,
    SECDAT_COMMAND_DOMAIN_CREATE,
    SECDAT_COMMAND_DOMAIN_DELETE,
    SECDAT_COMMAND_DOMAIN_LS,
    SECDAT_COMMAND_DOMAIN_STATUS,
};

struct secdat_cli {
    const char *program_name;
    const char *dir;
    const char *domain;
    const char *store;
    const char *help_target;
    enum secdat_command_type command;
    int show_help;
    int show_version;
    int defaulted_to_get;
    int argc;
    char **argv;
};

int secdat_cli_parse(int argc, char **argv, struct secdat_cli *cli);
int secdat_cli_complete(int argc, char **argv);
void secdat_cli_print_usage(const char *program_name);
void secdat_cli_print_command_usage(const char *program_name, enum secdat_command_type command);
void secdat_cli_print_help_target(const char *program_name, const char *target);
void secdat_cli_print_try_help(const struct secdat_cli *cli, const char *target);
enum secdat_command_type secdat_cli_parse_command_name(const char *name);
const char *secdat_cli_command_name(enum secdat_command_type command);
int secdat_cli_is_command_group(const char *name);
int secdat_cli_suggestion_candidate(const char *input, const char *candidate, size_t *distance_out);
int secdat_cli_print_command_suggestions(const char *input, int fallback_get_context);
void secdat_cli_print_subcommand_suggestions(const char *group, const char *input);

#endif
