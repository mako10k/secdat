#ifndef SECDAT_CLI_H
#define SECDAT_CLI_H

#include <stddef.h>

enum secdat_command_type {
    SECDAT_COMMAND_HELP = 0,
    SECDAT_COMMAND_LS,
    SECDAT_COMMAND_GET,
    SECDAT_COMMAND_SET,
    SECDAT_COMMAND_RM,
    SECDAT_COMMAND_MV,
    SECDAT_COMMAND_CP,
    SECDAT_COMMAND_EXEC,
    SECDAT_COMMAND_DOMAIN_CREATE,
    SECDAT_COMMAND_DOMAIN_DELETE,
    SECDAT_COMMAND_DOMAIN_LS,
};

struct secdat_cli {
    const char *dir;
    const char *store;
    enum secdat_command_type command;
    int argc;
    char **argv;
};

int secdat_cli_parse(int argc, char **argv, struct secdat_cli *cli);
void secdat_cli_print_usage(const char *program_name);
const char *secdat_cli_command_name(enum secdat_command_type command);

#endif
