#include "cli.h"

#include "i18n.h"

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

static int run_placeholder(const struct secdat_cli *cli)
{
    fprintf(stderr, _("command not implemented yet: %s\n"), secdat_cli_command_name(cli->command));
    if (cli->dir != NULL) {
        fprintf(stderr, _("  dir=%s\n"), cli->dir);
    }
    if (cli->store != NULL) {
        fprintf(stderr, _("  store=%s\n"), cli->store);
    }
    return 1;
}

int main(int argc, char **argv)
{
    struct secdat_cli cli;
    int result;

    secdat_i18n_init(argv[0]);

    result = secdat_cli_parse(argc, argv, &cli);
    if (result != 0) {
        secdat_cli_print_usage(argv[0]);
        return result;
    }

    if (cli.command == SECDAT_COMMAND_HELP) {
        secdat_cli_print_usage(argv[0]);
        return 0;
    }

    return run_placeholder(&cli);
}