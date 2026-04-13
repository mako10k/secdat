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

enum secdat_command_type secdat_cli_parse_command_name(const char *name)
{
    if (strcmp(name, "ls") == 0) {
        return SECDAT_COMMAND_LS;
    }
    if (strcmp(name, "get") == 0) {
        return SECDAT_COMMAND_GET;
    }
    if (strcmp(name, "set") == 0) {
        return SECDAT_COMMAND_SET;
    }
    if (strcmp(name, "rm") == 0) {
        return SECDAT_COMMAND_RM;
    }
    if (strcmp(name, "mv") == 0) {
        return SECDAT_COMMAND_MV;
    }
    if (strcmp(name, "cp") == 0) {
        return SECDAT_COMMAND_CP;
    }
    if (strcmp(name, "exec") == 0) {
        return SECDAT_COMMAND_EXEC;
    }
    if (strcmp(name, "unlock") == 0) {
        return SECDAT_COMMAND_UNLOCK;
    }
    if (strcmp(name, "lock") == 0) {
        return SECDAT_COMMAND_LOCK;
    }
    if (strcmp(name, "status") == 0) {
        return SECDAT_COMMAND_STATUS;
    }
    if (strcmp(name, "store") == 0) {
        return SECDAT_COMMAND_STORE_LS;
    }
    if (strcmp(name, "domain") == 0) {
        return SECDAT_COMMAND_DOMAIN_LS;
    }
    return SECDAT_COMMAND_HELP;
}

static void secdat_cli_print_usage_line(const char *program_name, enum secdat_command_type command)
{
    switch (command) {
    case SECDAT_COMMAND_LS:
        printf(_("  %s [--dir DIR] [--store STORE] ls [GLOBPATTERN] [--canonical|--canonical-domain|--canonical-store]\n"), program_name);
        break;
    case SECDAT_COMMAND_GET:
        printf(_("  %s [--dir DIR] [--store STORE] get KEYREF [--stdout]\n"), program_name);
        break;
    case SECDAT_COMMAND_SET:
        printf(_("  %s [--dir DIR] [--store STORE] set KEYREF [VALUE|--stdin|--env ENVNAME|--value VALUE]\n"), program_name);
        break;
    case SECDAT_COMMAND_RM:
        printf(_("  %s [--dir DIR] [--store STORE] rm KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_MV:
        printf(_("  %s [--dir DIR] [--store STORE] mv SRC_KEYREF DST_KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_CP:
        printf(_("  %s [--dir DIR] [--store STORE] cp SRC_KEYREF DST_KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_EXEC:
        printf(_("  %s [--dir DIR] [--store STORE] exec [--pattern GLOBPATTERN] CMD [ARGS...]\n"), program_name);
        break;
    case SECDAT_COMMAND_UNLOCK:
        printf(_("  %s unlock\n"), program_name);
        break;
    case SECDAT_COMMAND_LOCK:
        printf(_("  %s lock\n"), program_name);
        break;
    case SECDAT_COMMAND_STATUS:
        printf(_("  %s status [--quiet]\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_CREATE:
        printf(_("  %s [--dir DIR] store create STORE\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_DELETE:
        printf(_("  %s [--dir DIR] store delete STORE\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_LS:
        printf(_("  %s [--dir DIR] store ls [GLOBPATTERN]\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_CREATE:
        printf(_("  %s [--dir DIR] domain create\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_DELETE:
        printf(_("  %s [--dir DIR] domain delete\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_LS:
        printf(_("  %s [--dir DIR] domain ls [GLOBPATTERN]\n"), program_name);
        break;
    default:
        break;
    }
}

int secdat_cli_parse(int argc, char **argv, struct secdat_cli *cli)
{
    int index = 1;
    int result;

    cli->dir = NULL;
    cli->store = NULL;
    cli->help_target = NULL;
    cli->command = SECDAT_COMMAND_HELP;
    cli->show_help = 0;
    cli->argc = 0;
    cli->argv = NULL;

    result = parse_global_options(argc, argv, &index, cli);
    if (result != 0) {
        return result;
    }

    if (index >= argc) {
        return 0;
    }

    if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
        cli->show_help = 1;
        if (index + 1 < argc) {
            cli->help_target = argv[index + 1];
        }
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
    } else if (strcmp(argv[index], "unlock") == 0) {
        cli->command = SECDAT_COMMAND_UNLOCK;
        index += 1;
    } else if (strcmp(argv[index], "lock") == 0) {
        cli->command = SECDAT_COMMAND_LOCK;
        index += 1;
    } else if (strcmp(argv[index], "status") == 0) {
        cli->command = SECDAT_COMMAND_STATUS;
        index += 1;
    } else if (strcmp(argv[index], "store") == 0) {
        index += 1;
        if (index >= argc) {
            cli->show_help = 1;
            cli->help_target = "store";
            return 0;
        }

        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            cli->show_help = 1;
            cli->help_target = "store";
            return 0;
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
            cli->show_help = 1;
            cli->help_target = "domain";
            return 0;
        }

        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            cli->show_help = 1;
            cli->help_target = "domain";
            return 0;
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
    if (cli->argc == 1 && (strcmp(cli->argv[0], "--help") == 0 || strcmp(cli->argv[0], "-h") == 0)) {
        cli->show_help = 1;
        cli->argc = 0;
    }
    return 0;
}

void secdat_cli_print_usage(const char *program_name)
{
    printf(_("Usage:\n"));
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_LS);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_GET);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_SET);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_RM);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_MV);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_CP);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_EXEC);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_UNLOCK);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_LOCK);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STATUS);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_CREATE);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_DELETE);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_LS);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_CREATE);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_DELETE);
    secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_LS);
    printf(_("\n"));
    printf(_("  KEYREF syntax: KEY[/ABSOLUTE/DOMAIN][:STORE]\n"));
}

void secdat_cli_print_command_usage(const char *program_name, enum secdat_command_type command)
{
    printf(_("Usage:\n"));
    secdat_cli_print_usage_line(program_name, command);
    if (command == SECDAT_COMMAND_LS || command == SECDAT_COMMAND_GET || command == SECDAT_COMMAND_SET
        || command == SECDAT_COMMAND_RM || command == SECDAT_COMMAND_MV || command == SECDAT_COMMAND_CP) {
        printf(_("\n"));
        printf(_("  KEYREF syntax: KEY[/ABSOLUTE/DOMAIN][:STORE]\n"));
    }
}

void secdat_cli_print_help_target(const char *program_name, const char *target)
{
    if (target != NULL && strcmp(target, "store") == 0) {
        printf(_("Usage:\n"));
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_CREATE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_DELETE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_LS);
        return;
    }

    if (target != NULL && strcmp(target, "domain") == 0) {
        printf(_("Usage:\n"));
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_CREATE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_DELETE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_LS);
        return;
    }

    secdat_cli_print_usage(program_name);
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
    case SECDAT_COMMAND_UNLOCK:
        return "unlock";
    case SECDAT_COMMAND_LOCK:
        return "lock";
    case SECDAT_COMMAND_STATUS:
        return "status";
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
