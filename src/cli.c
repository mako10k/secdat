#include "cli.h"

#include "i18n.h"

#include <getopt.h>
#include <stdio.h>
#include <string.h>

enum {
    SECDAT_OPTION_DOMAIN = 1000,
};

static int parse_global_options(int argc, char **argv, int *index, struct secdat_cli *cli)
{
    static const struct option long_options[] = {
        {"dir", required_argument, NULL, 'd'},
        {"domain", required_argument, NULL, SECDAT_OPTION_DOMAIN},
        {"store", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    int option;

    opterr = 0;
    optind = *index;
    while ((option = getopt_long(argc, argv, "+:d:s:hV", long_options, NULL)) != -1) {
        switch (option) {
        case 'd':
            cli->dir = optarg;
            break;
        case SECDAT_OPTION_DOMAIN:
            cli->domain = optarg;
            break;
        case 's':
            cli->store = optarg;
            break;
        case 'h':
            cli->show_help = 1;
            if (optind < argc && argv[optind][0] != '-') {
                cli->help_target = argv[optind];
            }
            *index = optind;
            return 0;
        case 'V':
            cli->show_version = 1;
            *index = optind;
            return 0;
        case ':':
            if (optind > 0 && strcmp(argv[optind - 1], "--dir") == 0) {
                fprintf(stderr, _("missing value for --dir\n"));
            } else if (optind > 0 && strcmp(argv[optind - 1], "--domain") == 0) {
                fprintf(stderr, _("missing value for --domain\n"));
            } else if (optind > 0 && strcmp(argv[optind - 1], "--store") == 0) {
                fprintf(stderr, _("missing value for --store\n"));
            } else if (optopt == 'd') {
                fprintf(stderr, _("missing value for --dir\n"));
            } else if (optopt == SECDAT_OPTION_DOMAIN) {
                fprintf(stderr, _("missing value for --domain\n"));
            } else if (optopt == 's') {
                fprintf(stderr, _("missing value for --store\n"));
            } else {
                fprintf(stderr, _("missing option value\n"));
            }
            return 2;
        case '?':
            fprintf(stderr, _("unknown option: %s\n"), argv[optind - 1]);
            return 2;
        default:
            break;
        }
    }

    *index = optind;
    return 0;
}

enum secdat_command_type secdat_cli_parse_command_name(const char *name)
{
    if (strcmp(name, "ls") == 0) {
        return SECDAT_COMMAND_LS;
    }
    if (strcmp(name, "list") == 0) {
        return SECDAT_COMMAND_LIST;
    }
    if (strcmp(name, "mask") == 0) {
        return SECDAT_COMMAND_MASK;
    }
    if (strcmp(name, "unmask") == 0) {
        return SECDAT_COMMAND_UNMASK;
    }
    if (strcmp(name, "exists") == 0) {
        return SECDAT_COMMAND_EXISTS;
    }
    if (strcmp(name, "help") == 0) {
        return SECDAT_COMMAND_HELP;
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
    if (strcmp(name, "export") == 0) {
        return SECDAT_COMMAND_EXPORT;
    }
    if (strcmp(name, "save") == 0) {
        return SECDAT_COMMAND_SAVE;
    }
    if (strcmp(name, "load") == 0) {
        return SECDAT_COMMAND_LOAD;
    }
    if (strcmp(name, "unlock") == 0) {
        return SECDAT_COMMAND_UNLOCK;
    }
    if (strcmp(name, "passwd") == 0) {
        return SECDAT_COMMAND_PASSWD;
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
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] ls [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN] [--pattern-exclude GLOBPATTERN] [--safe|--unsafe] [-c|--canonical] [-D|--canonical-domain] [-S|--canonical-store]\n"), program_name);
        break;
    case SECDAT_COMMAND_LIST:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] list [--masked] [--overridden] [--orphaned] [--safe] [--unsafe]\n"), program_name);
        break;
    case SECDAT_COMMAND_MASK:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] mask KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_UNMASK:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] unmask KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_EXISTS:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] exists KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_GET:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] get KEYREF [-o|--stdout|--shellescaped]\n"), program_name);
        break;
    case SECDAT_COMMAND_SET:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] set KEYREF [--unsafe] [VALUE|-i|--stdin|-e ENVNAME|--env ENVNAME|-v VALUE|--value VALUE]\n"), program_name);
        break;
    case SECDAT_COMMAND_RM:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] rm [--ignore-missing] KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_MV:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] mv SRC_KEYREF DST_KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_CP:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] cp SRC_KEYREF DST_KEYREF\n"), program_name);
        break;
    case SECDAT_COMMAND_EXEC:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] exec [-p GLOBPATTERN|--pattern GLOBPATTERN] [--pattern-exclude GLOBPATTERN] CMD [ARGS...]\n"), program_name);
        break;
    case SECDAT_COMMAND_EXPORT:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] export [-p GLOBPATTERN|--pattern GLOBPATTERN]\n"), program_name);
        break;
    case SECDAT_COMMAND_SAVE:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] save FILE\n"), program_name);
        break;
    case SECDAT_COMMAND_LOAD:
        printf(_("  %s [-d DIR|--dir DIR] [-s STORE|--store STORE] load FILE\n"), program_name);
        break;
    case SECDAT_COMMAND_UNLOCK:
        printf(_("  %s [-d DIR|--dir DIR] unlock\n"), program_name);
        break;
    case SECDAT_COMMAND_PASSWD:
        printf(_("  %s passwd\n"), program_name);
        break;
    case SECDAT_COMMAND_LOCK:
        printf(_("  %s [-d DIR|--dir DIR] lock\n"), program_name);
        break;
    case SECDAT_COMMAND_STATUS:
        printf(_("  %s [-d DIR|--dir DIR] status [-q|--quiet]\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_CREATE:
        printf(_("  %s [-d DIR|--dir DIR] store create STORE\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_DELETE:
        printf(_("  %s [-d DIR|--dir DIR] store delete STORE\n"), program_name);
        break;
    case SECDAT_COMMAND_STORE_LS:
        printf(_("  %s [-d DIR|--dir DIR] store ls [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_CREATE:
        printf(_("  %s [-d DIR|--dir DIR] domain create\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_DELETE:
        printf(_("  %s [-d DIR|--dir DIR] domain delete\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_LS:
        printf(_("  %s [-d DIR|--dir DIR] domain ls [-l|--long] [--ancestors] [--descendants] [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]\n"), program_name);
        break;
    case SECDAT_COMMAND_DOMAIN_STATUS:
        printf(_("  %s [-d DIR|--dir DIR] domain status [-q|--quiet]\n"), program_name);
        break;
    default:
        break;
    }
}

static void secdat_cli_print_common_usage(const char *program_name)
{
    printf(_("  %s [options] subcommand ...\n"), program_name);
}

static void secdat_cli_print_common_options(void)
{
    printf(_("\nOptions:\n"));
    printf(_("  -d, --dir DIR      set the base directory used for domain resolution\n"));
    printf(_("      --domain DIR   require one exact registered domain root instead of discovery\n"));
    printf(_("  -s, --store STORE  select the store namespace inside the resolved domain\n"));
    printf(_("  -h, --help         show global help, or combine with COMMAND for detailed help\n"));
    printf(_("  -V, --version      print the secdat version\n"));
}

static void secdat_cli_print_meta_usage_line(const char *program_name, const char *target)
{
    if (target != NULL && strcmp(target, "help") == 0) {
        printf(_("  %s help [COMMAND]\n"), program_name);
        return;
    }
    if (target != NULL && strcmp(target, "version") == 0) {
        printf(_("  %s version\n"), program_name);
    }
}

static void secdat_cli_print_help_routes(const char *program_name, const char *target)
{
    printf(_("\nHelp:\n"));
    printf(_("  %s --help\n"), program_name);
    printf(_("  %s help [COMMAND]\n"), program_name);
    if (target == NULL) {
        printf(_("  %s --help COMMAND\n"), program_name);
        printf(_("  %s COMMAND --help\n"), program_name);
    } else {
        printf(_("  %s --help %s\n"), program_name, target);
        printf(_("  %s %s --help\n"), program_name, target);
    }
    printf(_("  %s --version\n"), program_name);
    printf(_("  %s version\n"), program_name);
}

static void secdat_cli_print_shell_routes(const char *program_name)
{
    printf(_("\nShell:\n"));
    printf(_("  bash load current shell vars: source <(%s export)\n"), program_name);
    printf(_("  bash alternative: eval \"$(%s export)\"\n"), program_name);
    printf(_("  bash completion script: completions/secdat.bash\n"));
    printf(_("  man page source: docs/secdat.1\n"));
}

static void secdat_cli_print_support_routes(void)
{
    printf(_("\nSupport:\n"));
    printf(_("  issues: https://github.com/mako10k/secdat/issues\n"));
    printf(_("  repository: https://github.com/mako10k/secdat\n"));
    printf(_("  author: Makoto Katsumata <mako10k@mk10.org>\n"));
}

static void secdat_cli_print_group_meanings(void)
{
    printf(_("\nGroups:\n"));
    printf(_("  store: manage store namespaces inside the resolved current domain\n"));
    printf(_("  domain: manage domain roots and domain discovery scope\n"));
}

static void secdat_cli_print_command_meanings(void)
{
    printf(_("\nCommands:\n"));
    printf(_("  help: show global help or detailed help for one command\n"));
    printf(_("  ls: list effective keys visible from the current domain view, optionally filtered by safe or unsafe storage\n"));
    printf(_("  list: inspect current-domain masked, overridden, orphaned, safe, or unsafe local state\n"));
    printf(_("  mask: create a local tombstone to hide one inherited key\n"));
    printf(_("  unmask: remove one local tombstone from the current domain\n"));
    printf(_("  exists: check whether one resolved key is visible from the current domain view\n"));
    printf(_("  get: decrypt one resolved key and write it to standard output\n"));
    printf(_("  set: store or update one key in the resolved current domain; --unsafe stores plaintext visible while locked\n"));
    printf(_("  rm: remove one key locally or create a tombstone for an inherited key; --ignore-missing treats absent keys as success\n"));
    printf(_("  mv: rename or relocate one key between resolved locations\n"));
    printf(_("  cp: copy one key into another resolved location\n"));
    printf(_("  exec: inject resolved keys into a child process environment\n"));
    printf(_("  export: emit shell-ready export lines that defer secret reads to secdat get\n"));
    printf(_("  save: export the current visible secrets into a passphrase-protected bundle\n"));
    printf(_("  load: import a passphrase-protected bundle into the current domain view\n"));
    printf(_("  unlock: start or refresh an authenticated secret session for the current domain\n"));
    printf(_("  passwd: change the wrapped-master-key passphrase\n"));
    printf(_("  lock: clear the current domain's local secret session\n"));
    printf(_("  status: report whether secret material is available from the current domain scope\n"));
    printf(_("  version: print the secdat version\n"));
}

static void secdat_cli_print_target_meaning(const char *target)
{
    printf(_("\nMeaning:\n"));
    if (target != NULL && strcmp(target, "help") == 0) {
        printf(_("  show global help or detailed help for one command\n"));
        return;
    }
    if (target != NULL && strcmp(target, "ls") == 0) {
        printf(_("  list effective keys visible from the current domain view, optionally filtered by safe or unsafe storage\n"));
        return;
    }
    if (target != NULL && strcmp(target, "list") == 0) {
        printf(_("  inspect current-domain masked, overridden, orphaned, safe, or unsafe local state\n"));
        return;
    }
    if (target != NULL && strcmp(target, "mask") == 0) {
        printf(_("  create a local tombstone to hide one inherited key\n"));
        return;
    }
    if (target != NULL && strcmp(target, "unmask") == 0) {
        printf(_("  remove one local tombstone from the current domain\n"));
        return;
    }
    if (target != NULL && strcmp(target, "exists") == 0) {
        printf(_("  check whether one resolved key is visible from the current domain view\n"));
        return;
    }
    if (target != NULL && strcmp(target, "get") == 0) {
        printf(_("  decrypt one resolved key and write it to standard output\n"));
        return;
    }
    if (target != NULL && strcmp(target, "set") == 0) {
        printf(_("  store or update one key in the resolved current domain; --unsafe stores plaintext visible while locked\n"));
        return;
    }
    if (target != NULL && strcmp(target, "rm") == 0) {
        printf(_("  remove one key locally or create a tombstone for an inherited key; --ignore-missing treats absent keys as success\n"));
        return;
    }
    if (target != NULL && strcmp(target, "mv") == 0) {
        printf(_("  rename or relocate one key between resolved locations\n"));
        return;
    }
    if (target != NULL && strcmp(target, "cp") == 0) {
        printf(_("  copy one key into another resolved location\n"));
        return;
    }
    if (target != NULL && strcmp(target, "exec") == 0) {
        printf(_("  inject resolved keys into a child process environment\n"));
        return;
    }
    if (target != NULL && strcmp(target, "export") == 0) {
        printf(_("  emit shell-ready export lines that defer secret reads to secdat get\n"));
        return;
    }
    if (target != NULL && strcmp(target, "save") == 0) {
        printf(_("  export the current visible secrets into a passphrase-protected bundle\n"));
        return;
    }
    if (target != NULL && strcmp(target, "load") == 0) {
        printf(_("  import a passphrase-protected bundle into the current domain view\n"));
        return;
    }
    if (target != NULL && strcmp(target, "unlock") == 0) {
        printf(_("  start or refresh an authenticated secret session for the current domain\n"));
        return;
    }
    if (target != NULL && strcmp(target, "passwd") == 0) {
        printf(_("  change the wrapped-master-key passphrase\n"));
        return;
    }
    if (target != NULL && strcmp(target, "lock") == 0) {
        printf(_("  clear the current domain's local secret session\n"));
        return;
    }
    if (target != NULL && strcmp(target, "status") == 0) {
        printf(_("  report whether secret material is available from the current domain scope\n"));
        return;
    }
    if (target != NULL && strcmp(target, "version") == 0) {
        printf(_("  print the secdat version\n"));
        return;
    }
    if (target != NULL && strcmp(target, "store") == 0) {
        printf(_("  manage store namespaces inside the resolved current domain\n"));
        return;
    }
    if (target != NULL && strcmp(target, "domain") == 0) {
        printf(_("  manage domain roots and domain discovery scope\n"));
        return;
    }
}

static void secdat_cli_print_semantics(void)
{
    printf(_("\nSemantics:\n"));
    printf(_("  DIR: base directory used for domain resolution; defaults to the current working directory\n"));
    printf(_("  DOMAIN: directory-scoped configuration boundary used for inheritance and tombstones\n"));
    printf(_("  STORE: domain-local namespace selected by --store; defaults to the default store\n"));
    printf(_("  KEY / KEYREF: logical secret name, optionally qualified as [/ABSOLUTE/DOMAIN/]KEY[:STORE]\n"));
}

int secdat_cli_parse(int argc, char **argv, struct secdat_cli *cli)
{
    int index = 1;
    int result;

    cli->program_name = argc > 0 ? argv[0] : "secdat";
    cli->dir = NULL;
    cli->domain = NULL;
    cli->store = NULL;
    cli->help_target = NULL;
    cli->command = SECDAT_COMMAND_HELP;
    cli->show_help = 0;
    cli->show_version = 0;
    cli->argc = 0;
    cli->argv = NULL;

    result = parse_global_options(argc, argv, &index, cli);
    if (result != 0) {
        return result;
    }

    if (index >= argc) {
        return 0;
    }

    if (cli->show_help || cli->show_version) {
        return 0;
    }

    if (strcmp(argv[index], "help") == 0) {
        cli->show_help = 1;
        index += 1;
        if (index < argc) {
            cli->help_target = argv[index];
        }
        return 0;
    } else if (strcmp(argv[index], "version") == 0) {
        cli->show_version = 1;
        return 0;
    } else if (strcmp(argv[index], "ls") == 0) {
        cli->command = SECDAT_COMMAND_LS;
        index += 1;
    } else if (strcmp(argv[index], "list") == 0) {
        cli->command = SECDAT_COMMAND_LIST;
        index += 1;
    } else if (strcmp(argv[index], "mask") == 0) {
        cli->command = SECDAT_COMMAND_MASK;
        index += 1;
    } else if (strcmp(argv[index], "unmask") == 0) {
        cli->command = SECDAT_COMMAND_UNMASK;
        index += 1;
    } else if (strcmp(argv[index], "exists") == 0) {
        cli->command = SECDAT_COMMAND_EXISTS;
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
    } else if (strcmp(argv[index], "export") == 0) {
        cli->command = SECDAT_COMMAND_EXPORT;
        index += 1;
    } else if (strcmp(argv[index], "save") == 0) {
        cli->command = SECDAT_COMMAND_SAVE;
        index += 1;
    } else if (strcmp(argv[index], "load") == 0) {
        cli->command = SECDAT_COMMAND_LOAD;
        index += 1;
    } else if (strcmp(argv[index], "unlock") == 0) {
        cli->command = SECDAT_COMMAND_UNLOCK;
        index += 1;
    } else if (strcmp(argv[index], "passwd") == 0) {
        cli->command = SECDAT_COMMAND_PASSWD;
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
            secdat_cli_print_try_help(cli, "store");
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
        } else if (strcmp(argv[index], "status") == 0) {
            cli->command = SECDAT_COMMAND_DOMAIN_STATUS;
            index += 1;
        } else {
            fprintf(stderr, _("unknown domain subcommand: %s\n"), argv[index]);
            secdat_cli_print_try_help(cli, "domain");
            return 2;
        }
    } else {
        fprintf(stderr, _("unknown command: %s\n"), argv[index]);
        secdat_cli_print_try_help(cli, NULL);
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
    secdat_cli_print_common_usage(program_name);
    secdat_cli_print_common_options();
    secdat_cli_print_help_routes(program_name, NULL);
    secdat_cli_print_shell_routes(program_name);
    secdat_cli_print_support_routes();
    secdat_cli_print_group_meanings();
    secdat_cli_print_command_meanings();
    secdat_cli_print_semantics();
}

void secdat_cli_print_command_usage(const char *program_name, enum secdat_command_type command)
{
    const char *target = secdat_cli_command_name(command);

    printf(_("Usage:\n"));
    secdat_cli_print_usage_line(program_name, command);
    if (command == SECDAT_COMMAND_LS || command == SECDAT_COMMAND_MASK || command == SECDAT_COMMAND_UNMASK
        || command == SECDAT_COMMAND_EXISTS || command == SECDAT_COMMAND_GET || command == SECDAT_COMMAND_SET
        || command == SECDAT_COMMAND_RM || command == SECDAT_COMMAND_MV || command == SECDAT_COMMAND_CP) {
        printf(_("\n"));
        printf(_("  KEYREF syntax: [/ABSOLUTE/DOMAIN/]KEY[:STORE]\n"));
    }
    secdat_cli_print_help_routes(program_name, target);
    secdat_cli_print_target_meaning(target);
    if (command == SECDAT_COMMAND_EXPORT) {
        secdat_cli_print_shell_routes(program_name);
    }
    secdat_cli_print_support_routes();
    secdat_cli_print_semantics();
}

void secdat_cli_print_help_target(const char *program_name, const char *target)
{
    if (target != NULL && (strcmp(target, "help") == 0 || strcmp(target, "version") == 0)) {
        printf(_("Usage:\n"));
        secdat_cli_print_meta_usage_line(program_name, target);
        secdat_cli_print_help_routes(program_name, target);
        secdat_cli_print_target_meaning(target);
        secdat_cli_print_support_routes();
        return;
    }

    if (target != NULL && strcmp(target, "store") == 0) {
        printf(_("Usage:\n"));
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_CREATE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_DELETE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_LS);
        secdat_cli_print_help_routes(program_name, target);
        secdat_cli_print_target_meaning(target);
        secdat_cli_print_support_routes();
        secdat_cli_print_semantics();
        return;
    }

    if (target != NULL && strcmp(target, "domain") == 0) {
        printf(_("Usage:\n"));
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_CREATE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_DELETE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_LS);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_DOMAIN_STATUS);
        secdat_cli_print_help_routes(program_name, target);
        secdat_cli_print_target_meaning(target);
        secdat_cli_print_support_routes();
        secdat_cli_print_semantics();
        return;
    }

    secdat_cli_print_usage(program_name);
}

void secdat_cli_print_try_help(const struct secdat_cli *cli, const char *target)
{
    const char *program_name = "secdat";

    if (cli != NULL && cli->program_name != NULL && cli->program_name[0] != '\0') {
        program_name = cli->program_name;
    }

    if (target != NULL && target[0] != '\0') {
        fprintf(stderr, _("Try: %s help %s\n"), program_name, target);
        return;
    }

    fprintf(stderr, _("Try: %s help\n"), program_name);
}

const char *secdat_cli_command_name(enum secdat_command_type command)
{
    switch (command) {
    case SECDAT_COMMAND_HELP:
        return "help";
    case SECDAT_COMMAND_LS:
        return "ls";
    case SECDAT_COMMAND_LIST:
        return "list";
    case SECDAT_COMMAND_MASK:
        return "mask";
    case SECDAT_COMMAND_UNMASK:
        return "unmask";
    case SECDAT_COMMAND_EXISTS:
        return "exists";
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
    case SECDAT_COMMAND_EXPORT:
        return "export";
    case SECDAT_COMMAND_SAVE:
        return "save";
    case SECDAT_COMMAND_LOAD:
        return "load";
    case SECDAT_COMMAND_UNLOCK:
        return "unlock";
    case SECDAT_COMMAND_PASSWD:
        return "passwd";
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
    case SECDAT_COMMAND_DOMAIN_STATUS:
        return "domain status";
    default:
        return "unknown";
    }
}
