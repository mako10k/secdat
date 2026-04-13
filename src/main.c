#include "config.h"
#include "cli.h"

#include "i18n.h"
#include "store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <locale.h>

#include <string.h>

static void bind_domain_from_candidates(const char *argv0)
{
    const char *env_locale_dir = getenv("SECDAT_LOCALEDIR");
    char executable_locale_dir[PATH_MAX];
    const char *slash;

    if (env_locale_dir != NULL && env_locale_dir[0] != '\0') {
        bindtextdomain(PACKAGE_NAME, env_locale_dir);
        return;
    }

    bindtextdomain(PACKAGE_NAME, LOCALEDIR);

    if (argv0 == NULL) {
        bindtextdomain(PACKAGE_NAME, "./po/.locale");
        return;
    }

    slash = strrchr(argv0, '/');
    if (slash == NULL) {
        bindtextdomain(PACKAGE_NAME, "./po/.locale");
        return;
    }

    if ((size_t)(slash - argv0) >= sizeof(executable_locale_dir) - strlen("/../po/.locale") - 1) {
        bindtextdomain(PACKAGE_NAME, "./po/.locale");
        return;
    }

    memcpy(executable_locale_dir, argv0, (size_t)(slash - argv0));
    executable_locale_dir[slash - argv0] = '\0';
    strcat(executable_locale_dir, "/../po/.locale");
    bindtextdomain(PACKAGE_NAME, executable_locale_dir);
}

void secdat_i18n_init(const char *argv0)
{
    setlocale(LC_ALL, "");
    bind_domain_from_candidates(argv0);
    textdomain(PACKAGE_NAME);
}

int main(int argc, char **argv)
{
    struct secdat_cli cli;
    enum secdat_command_type help_command;
    int result;

    secdat_i18n_init(argv[0]);

    result = secdat_cli_parse(argc, argv, &cli);
    if (result != 0) {
        secdat_cli_print_usage(argv[0]);
        return result;
    }

    if (cli.show_version) {
        printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        return 0;
    }

    if (cli.show_help) {
        if (cli.command != SECDAT_COMMAND_HELP) {
            secdat_cli_print_command_usage(argv[0], cli.command);
            return 0;
        }
        if (cli.help_target != NULL) {
            help_command = secdat_cli_parse_command_name(cli.help_target);
            if (help_command != SECDAT_COMMAND_HELP) {
                if (strcmp(cli.help_target, "store") == 0 || strcmp(cli.help_target, "domain") == 0) {
                    secdat_cli_print_help_target(argv[0], cli.help_target);
                } else {
                    secdat_cli_print_command_usage(argv[0], help_command);
                }
                return 0;
            }
            if (strcmp(cli.help_target, "help") == 0 || strcmp(cli.help_target, "version") == 0) {
                secdat_cli_print_help_target(argv[0], cli.help_target);
                return 0;
            }
        }
    }

    if (cli.command == SECDAT_COMMAND_HELP) {
        secdat_cli_print_usage(argv[0]);
        return 0;
    }

    return secdat_run_command(&cli);
}