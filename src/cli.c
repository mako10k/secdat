#include "cli.h"

#include "i18n.h"

#include <stdio.h>
#include <string.h>

static int parse_global_options(int argc, char **argv, int *index, struct secdat_cli *cli)
{
    while (*index < argc) {
        if (strcmp(argv[*index], "--dir") == 0) {
            if (*index + 1 >= argc) {
                fprintf(stderr, _("missing value for --dir\n"));
                return 2;
            }
            cli->dir = argv[*index + 1];
            *index += 2;
            continue;
        }

        if (strcmp(argv[*index], "--store") == 0) {
            if (*index + 1 >= argc) {
                fprintf(stderr, _("missing value for --store\n"));
                return 2;
            }
            cli->store = argv[*index + 1];
            *index += 2;
            continue;
        }

        break;
    }

    return 0;
}

int secdat_cli_parse(int argc, char **argv, struct secdat_cli *cli)
{
    int index = 1;
    int result;

    cli->dir = NULL;
    cli->store = NULL;
    cli->command = SECDAT_COMMAND_HELP;
    cli->argc = 0;
    cli->argv = NULL;

    result = parse_global_options(argc, argv, &index, cli);
    if (result != 0) {
        return result;
    }

    if (index >= argc || strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
        return 0;
    }

    if (strcmp(argv[index], "ls") == 0) {
        cli->command = SECDAT_COMMAND_LS;
        index += 1;
    } else if (strcmp(argv[index], "get") == 0) {
        cli->command = SECDAT_COMMAND_GET;
        index += 1;
    } else if (strcmp(argv[index], "set") == 0) {
        cli->command = SECDAT_COMMAND_SET;
        index += 1;
    } else if (strcmp(argv[index], "rm") == 0) {
        cli->command = SECDAT_COMMAND_RM;
        index += 1;
    } else if (strcmp(argv[index], "mv") == 0) {
        cli->command = SECDAT_COMMAND_MV;
        index += 1;
    } else if (strcmp(argv[index], "cp") == 0) {
        cli->command = SECDAT_COMMAND_CP;
        index += 1;
    } else if (strcmp(argv[index], "exec") == 0) {
        cli->command = SECDAT_COMMAND_EXEC;
        index += 1;
    } else if (strcmp(argv[index], "store") == 0) {
        index += 1;
        if (index >= argc) {
            fprintf(stderr, _("missing store subcommand\n"));
            return 2;
        }

        if (strcmp(argv[index], "create") == 0) {
            cli->command = SECDAT_COMMAND_STORE_CREATE;
            index += 1;
        } else if (strcmp(argv[index], "delete") == 0) {
            cli->command = SECDAT_COMMAND_STORE_DELETE;
            index += 1;
        } else if (strcmp(argv[index], "ls") == 0) {
            cli->command = SECDAT_COMMAND_STORE_LS;
            index += 1;
        } else {
            fprintf(stderr, _("unknown store subcommand: %s\n"), argv[index]);
            return 2;
        }
    } else if (strcmp(argv[index], "domain") == 0) {
        index += 1;
        if (index >= argc) {
            fprintf(stderr, _("missing domain subcommand\n"));
            return 2;
        }

        if (strcmp(argv[index], "create") == 0) {
            cli->command = SECDAT_COMMAND_DOMAIN_CREATE;
            index += 1;
        } else if (strcmp(argv[index], "delete") == 0) {
            cli->command = SECDAT_COMMAND_DOMAIN_DELETE;
            index += 1;
        } else if (strcmp(argv[index], "ls") == 0) {
            cli->command = SECDAT_COMMAND_DOMAIN_LS;
            index += 1;
        } else {
            fprintf(stderr, _("unknown domain subcommand: %s\n"), argv[index]);
            return 2;
        }
    } else {
        fprintf(stderr, _("unknown command: %s\n"), argv[index]);
        return 2;
    }

    cli->argc = argc - index;
    cli->argv = &argv[index];
    return 0;
}

void secdat_cli_print_usage(const char *program_name)
{
    printf(_("Usage:\n"));
    printf(_("  %s [--dir DIR] [--store STORE] ls [--pattern GLOBPATTERN]\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] get KEY [--stdout]\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] set KEY [VALUE|--stdin|--env ENVNAME|--value VALUE]\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] rm KEY\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] mv SRC_KEY DST_KEY\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] cp SRC_KEY DST_KEY\n"), program_name);
    printf(_("  %s [--dir DIR] [--store STORE] exec [--pattern GLOBPATTERN] CMD [ARGS...]\n"), program_name);
    printf(_("  %s [--dir DIR] store create STORE\n"), program_name);
    printf(_("  %s [--dir DIR] store delete STORE\n"), program_name);
    printf(_("  %s [--dir DIR] store ls [--pattern GLOBPATTERN]\n"), program_name);
    printf(_("  %s [--dir DIR] domain create\n"), program_name);
    printf(_("  %s [--dir DIR] domain delete\n"), program_name);
    printf(_("  %s [--dir DIR] domain ls [--pattern GLOBPATTERN]\n"), program_name);
}

const char *secdat_cli_command_name(enum secdat_command_type command)
{
    switch (command) {
    case SECDAT_COMMAND_HELP:
        return "help";
    case SECDAT_COMMAND_LS:
        return "ls";
    case SECDAT_COMMAND_GET:
        return "get";
    case SECDAT_COMMAND_SET:
        return "set";
    case SECDAT_COMMAND_RM:
        return "rm";
    case SECDAT_COMMAND_MV:
        return "mv";
    case SECDAT_COMMAND_CP:
        return "cp";
    case SECDAT_COMMAND_EXEC:
        return "exec";
    case SECDAT_COMMAND_STORE_CREATE:
        return "store create";
    case SECDAT_COMMAND_STORE_DELETE:
        return "store delete";
    case SECDAT_COMMAND_STORE_LS:
        return "store ls";
    case SECDAT_COMMAND_DOMAIN_CREATE:
        return "domain create";
    case SECDAT_COMMAND_DOMAIN_DELETE:
        return "domain delete";
    case SECDAT_COMMAND_DOMAIN_LS:
        return "domain ls";
    default:
        return "unknown";
    }
}
