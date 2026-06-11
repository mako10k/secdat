#include "config.h"
#include "cli.h"

#include "i18n.h"
#include "store.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>

#include <locale.h>

#include <string.h>

#include <unistd.h>

#define SECDAT_REPOSITORY_URL "https://github.com/mako10k/secdat"
#define SECDAT_ISSUES_URL "https://github.com/mako10k/secdat/issues"
#define SECDAT_AUTHOR "Makoto Katsumata <mako10k@mk10.org>"

#ifndef SECDAT_BUILD_ID
#define SECDAT_BUILD_ID ""
#endif

static int bind_domain_from_executable_candidate(const char *argv0, const char *suffix)
{
    char locale_dir[PATH_MAX];
    const char *slash;
    struct stat status;
    size_t base_length;
    size_t suffix_length;

    if (argv0 == NULL) {
        return 0;
    }

    slash = strrchr(argv0, '/');
    if (slash == NULL) {
        return 0;
    }

    base_length = (size_t)(slash - argv0);
    suffix_length = strlen(suffix);
    if (base_length >= sizeof(locale_dir) || suffix_length >= sizeof(locale_dir) - base_length - 1) {
        return 0;
    }

    memcpy(locale_dir, argv0, base_length);
    locale_dir[base_length] = '\0';
    strcat(locale_dir, suffix);

    if (stat(locale_dir, &status) != 0 || !S_ISDIR(status.st_mode)) {
        return 0;
    }

    bindtextdomain(PACKAGE_NAME, locale_dir);
    return 1;
}

static const char *secdat_program_name_for_display(const char *argv0, char *buffer, size_t size)
{
    char path_buffer[PATH_MAX];
    char *base_name;
    char *directory_name;
    const char *normalized_base_name;

    if (argv0 == NULL || argv0[0] == '\0') {
        return PACKAGE_NAME;
    }

    if (strlen(argv0) >= sizeof(path_buffer)) {
        return argv0;
    }

    strcpy(path_buffer, argv0);
    base_name = strrchr(path_buffer, '/');
    base_name = base_name != NULL ? base_name + 1 : path_buffer;
    normalized_base_name = strncmp(base_name, "lt-", 3) == 0 ? base_name + 3 : base_name;

    if (base_name != path_buffer) {
        base_name[-1] = '\0';
        directory_name = strrchr(path_buffer, '/');
        directory_name = directory_name != NULL ? directory_name + 1 : path_buffer;

        if (strcmp(directory_name, ".libs") == 0) {
            if (directory_name == path_buffer) {
                return normalized_base_name;
            }
            directory_name[-1] = '\0';
            if (snprintf(buffer, size, "%s/%s", path_buffer, normalized_base_name) >= (int)size) {
                return argv0;
            }
            return buffer;
        }

        if (normalized_base_name != base_name) {
            if (snprintf(buffer, size, "%s/%s", path_buffer, normalized_base_name) >= (int)size) {
                return argv0;
            }
            return buffer;
        }
    }

    if (normalized_base_name != base_name) {
        return normalized_base_name;
    }

    return argv0;
}

static const char *secdat_relativize_program_name(const char *program_name, char *buffer, size_t size)
{
    char current_directory[PATH_MAX];
    size_t current_directory_length;

    if (program_name == NULL || program_name[0] != '/') {
        return program_name;
    }
    if (getcwd(current_directory, sizeof(current_directory)) == NULL) {
        return program_name;
    }

    current_directory_length = strlen(current_directory);
    if (strncmp(program_name, current_directory, current_directory_length) != 0 || program_name[current_directory_length] != '/') {
        return program_name;
    }
    if (snprintf(buffer, size, "./%s", program_name + current_directory_length + 1) >= (int)size) {
        return program_name;
    }
    return buffer;
}

static void bind_domain_from_candidates(const char *argv0)
{
    const char *env_locale_dir = getenv("SECDAT_LOCALEDIR");

    if (env_locale_dir != NULL && env_locale_dir[0] != '\0') {
        bindtextdomain(PACKAGE_NAME, env_locale_dir);
        return;
    }

    if (bind_domain_from_executable_candidate(argv0, "/../po/.locale")) {
        return;
    }

    if (bind_domain_from_executable_candidate(argv0, "/../../po/.locale")) {
        return;
    }

    bindtextdomain(PACKAGE_NAME, LOCALEDIR);

    if (argv0 == NULL) {
        bindtextdomain(PACKAGE_NAME, "./po/.locale");
        return;
    }

    bindtextdomain(PACKAGE_NAME, "./po/.locale");
}

void secdat_i18n_init(const char *argv0)
{
    setlocale(LC_ALL, "");
    bind_domain_from_candidates(argv0);
    textdomain(PACKAGE_NAME);
}

static void secdat_print_version(void)
{
    printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    if (SECDAT_BUILD_ID[0] != '\0') {
        printf(_("Build: %s\n"), SECDAT_BUILD_ID);
    }
    printf(_("Repository: %s\n"), SECDAT_REPOSITORY_URL);
    printf(_("Issues: %s\n"), SECDAT_ISSUES_URL);
    printf(_("Author: %s\n"), SECDAT_AUTHOR);
}

int main(int argc, char **argv)
{
    struct secdat_cli cli;
    enum secdat_command_type help_command;
    char program_name_buffer[PATH_MAX];
    char relative_program_name_buffer[PATH_MAX];
    const char *display_program_name;
    int result;

    secdat_i18n_init(argv[0]);
    display_program_name = secdat_program_name_for_display(argv[0], program_name_buffer, sizeof(program_name_buffer));
    display_program_name = secdat_relativize_program_name(display_program_name, relative_program_name_buffer, sizeof(relative_program_name_buffer));
    argv[0] = (char *)display_program_name;

    if (argc > 2 && strcmp(argv[1], "__completion") == 0 && strcmp(argv[2], "--bash") == 0) {
        return secdat_cli_complete(argc - 3, &argv[3]);
    }

    result = secdat_cli_parse(argc, argv, &cli);
    if (result != 0) {
        secdat_cli_print_usage(display_program_name);
        return result;
    }

    if (cli.show_version) {
        secdat_print_version();
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
            if (strcmp(cli.help_target, "help") == 0 || strcmp(cli.help_target, "version") == 0 || strcmp(cli.help_target, "usecases") == 0 || strcmp(cli.help_target, "concepts") == 0) {
                secdat_cli_print_help_target(argv[0], cli.help_target);
                return 0;
            }
        }
    }

    if (cli.command == SECDAT_COMMAND_HELP) {
        secdat_cli_print_usage(display_program_name);
        return 0;
    }

    return secdat_run_command(&cli);
}