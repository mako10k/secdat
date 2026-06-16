#include "cli.h"

#include "i18n.h"
#include "store.h"

#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

extern int wcwidth(wchar_t character);

enum {
    SECDAT_OPTION_DOMAIN = 1000,
};

#define SECDAT_CLI_USAGE_OPTIONS_WIDTH (sizeof("[-d DIR|--dir DIR] [-s STORE|--store STORE]") - 1)
#define SECDAT_CLI_USAGE_COMMAND_WIDTH (sizeof("domain status") - 1)
#define SECDAT_CLI_DETAIL_COLUMN 24
#define SECDAT_CLI_WRAP_WIDTH 96

static void secdat_cli_print_usage_columns(
    const char *program_name,
    const char *options,
    const char *command,
    const char *arguments
)
{
    size_t index;
    size_t options_width = options != NULL ? strlen(options) : 0;
    size_t command_width = strlen(command);

    printf("  %s ", program_name);
    if (options != NULL) {
        fputs(options, stdout);
    }
    for (index = options_width; index < SECDAT_CLI_USAGE_OPTIONS_WIDTH; index += 1) {
        fputc(' ', stdout);
    }

    fputc(' ', stdout);
    fputs(command, stdout);
    for (index = command_width; index < SECDAT_CLI_USAGE_COMMAND_WIDTH; index += 1) {
        fputc(' ', stdout);
    }

    if (arguments != NULL && arguments[0] != '\0') {
        fputc(' ', stdout);
        fputs(arguments, stdout);
    }
    fputc('\n', stdout);
}

static void secdat_cli_print_spaces(size_t count)
{
    while (count > 0) {
        fputc(' ', stdout);
        count -= 1;
    }
}

static size_t secdat_cli_decode_char(const char *text, size_t remaining, wchar_t *character, mbstate_t *state)
{
    size_t consumed;

    if (remaining == 0 || *text == '\0') {
        return 0;
    }

    consumed = mbrtowc(character, text, remaining, state);
    if (consumed == (size_t)-1 || consumed == (size_t)-2) {
        memset(state, 0, sizeof(*state));
        *character = (wchar_t)(unsigned char)*text;
        return 1;
    }
    if (consumed == 0) {
        *character = L'\0';
        return 0;
    }

    return consumed;
}

static size_t secdat_cli_display_width(const char *text, size_t length)
{
    mbstate_t state;
    size_t offset = 0;
    size_t width = 0;

    memset(&state, 0, sizeof(state));
    while (offset < length) {
        wchar_t character;
        size_t consumed = secdat_cli_decode_char(text + offset, length - offset, &character, &state);
        int character_width;

        if (consumed == 0) {
            break;
        }

        character_width = wcwidth(character);
        if (character_width < 0) {
            character_width = 1;
        }

        width += (size_t)character_width;
        offset += consumed;
    }

    return width;
}

static int secdat_cli_is_space_at(const char *text)
{
    mbstate_t state;
    wchar_t character;
    size_t consumed;

    memset(&state, 0, sizeof(state));
    consumed = secdat_cli_decode_char(text, strlen(text), &character, &state);
    if (consumed == 0) {
        return 0;
    }

    return iswspace(character) != 0;
}

static int secdat_cli_is_japanese_wrap_punctuation(wchar_t character)
{
    switch (character) {
    case L'、':
    case L'。':
    case L'，':
    case L'．':
        return 1;
    default:
        return 0;
    }
}

static void secdat_cli_print_wrapped_text(const char *text, size_t indent)
{
    const char *cursor = text;
    size_t available_width = SECDAT_CLI_WRAP_WIDTH > indent ? SECDAT_CLI_WRAP_WIDTH - indent : 1;

    while (*cursor != '\0') {
        const char *line_start;
        const char *line_end;
        const char *scan;
        const char *last_space = NULL;
        const char *last_punctuation_end = NULL;
        size_t width = 0;
        mbstate_t state;

        while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
            cursor += 1;
        }
        if (*cursor == '\0') {
            break;
        }

        line_start = cursor;
        line_end = cursor;
        scan = cursor;
        memset(&state, 0, sizeof(state));
        while (*scan != '\0') {
            wchar_t character;
            size_t consumed = secdat_cli_decode_char(scan, strlen(scan), &character, &state);
            int character_width;

            if (consumed == 0) {
                break;
            }

            character_width = wcwidth(character);
            if (character_width < 0) {
                character_width = 1;
            }

            if (width > 0 && width + (size_t)character_width > available_width) {
                break;
            }

            if (iswspace(character)) {
                last_space = scan;
            } else if (secdat_cli_is_japanese_wrap_punctuation(character)) {
                last_punctuation_end = scan + consumed;
            }
            line_end = scan + consumed;
            scan += consumed;
            width += (size_t)character_width;

            if (width >= available_width) {
                break;
            }
        }

        if (*scan != '\0' && !secdat_cli_is_space_at(scan)) {
            if (last_punctuation_end != NULL) {
                line_end = last_punctuation_end;
                scan = last_punctuation_end;
            } else if (last_space != NULL) {
                line_end = last_space;
                scan = last_space;
            }
        }

        fwrite(line_start, 1, (size_t)(line_end - line_start), stdout);
        while (*scan != '\0' && isspace((unsigned char)*scan)) {
            scan += 1;
        }
        if (*scan == '\0') {
            break;
        }

        fputc('\n', stdout);
        secdat_cli_print_spaces(indent);
        cursor = scan;
    }
    fputc('\n', stdout);
}

static void secdat_cli_print_detail_line(const char *line)
{
    const char *separator = NULL;
    size_t indent = 0;
    size_t line_length = strlen(line);
    size_t label_length;
    size_t label_width;
    const char *description;
    const char *cursor;

    while (indent < line_length && line[indent] == ' ') {
        indent += 1;
    }
    while (line_length > 0 && (line[line_length - 1] == '\n' || line[line_length - 1] == '\r')) {
        line_length -= 1;
    }
    if (indent >= line_length) {
        fputc('\n', stdout);
        return;
    }

    cursor = strstr(line + indent, ": ");
    if (cursor != NULL && (size_t)(cursor - line) < line_length) {
        separator = cursor;
        label_length = (size_t)(separator - (line + indent)) + 1;
        description = separator + 2;
    } else {
        size_t index = indent;
        while (index + 1 < line_length) {
            if (line[index] == ' ' && line[index + 1] == ' ') {
                size_t gap_start = index;
                size_t gap_end = index + 2;
                while (gap_end < line_length && line[gap_end] == ' ') {
                    gap_end += 1;
                }
                if (gap_end < line_length) {
                    separator = line + gap_start;
                    label_length = gap_start - indent;
                    description = line + gap_end;
                    break;
                }
            }
            index += 1;
        }
    }

    if (separator == NULL) {
        fwrite(line, 1, line_length, stdout);
        fputc('\n', stdout);
        return;
    }

    secdat_cli_print_spaces(indent);
    fwrite(line + indent, 1, label_length, stdout);
    label_width = secdat_cli_display_width(line + indent, label_length);
    if (indent + label_width + 1 >= SECDAT_CLI_DETAIL_COLUMN) {
        fputc('\n', stdout);
        secdat_cli_print_spaces(SECDAT_CLI_DETAIL_COLUMN);
    } else {
        secdat_cli_print_spaces(SECDAT_CLI_DETAIL_COLUMN - indent - label_width);
    }
    secdat_cli_print_wrapped_text(description, SECDAT_CLI_DETAIL_COLUMN);
}

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

static int secdat_cli_requests_explicit_help(enum secdat_command_type command, int argc, char **argv)
{
    int index;

    if (command == SECDAT_COMMAND_EXEC) {
        return 0;
    }

    for (index = 0; index < argc; index += 1) {
        if (strcmp(argv[index], "--") == 0) {
            break;
        }
        if (strcmp(argv[index], "--help") == 0 || strcmp(argv[index], "-h") == 0) {
            return 1;
        }
    }

    return 0;
}

static int secdat_cli_is_assignment_operand(const char *value)
{
    return value != NULL && strchr(value, '=') != NULL;
}

static int secdat_cli_completion_is_global_option_with_value(const char *value)
{
    return value != NULL
        && (strcmp(value, "--dir") == 0 || strcmp(value, "-d") == 0
            || strcmp(value, "--domain") == 0 || strcmp(value, "--store") == 0 || strcmp(value, "-s") == 0);
}

static int secdat_cli_completion_is_help_target(const char *value)
{
    return value != NULL && (strcmp(value, "help") == 0 || strcmp(value, "version") == 0
        || strcmp(value, "usecases") == 0 || strcmp(value, "concepts") == 0
        || strcmp(value, "store") == 0 || strcmp(value, "domain") == 0);
}

static int secdat_cli_completion_is_command_with_key_operand(const char *command)
{
    return command != NULL
        && (strcmp(command, "get") == 0 || strcmp(command, "exists") == 0 || strcmp(command, "id") == 0
            || strcmp(command, "attr") == 0
            || strcmp(command, "rm") == 0 || strcmp(command, "mask") == 0
            || strcmp(command, "unmask") == 0 || strcmp(command, "set") == 0
            || strcmp(command, "cp") == 0 || strcmp(command, "mv") == 0 || strcmp(command, "ln") == 0);
}

static int secdat_cli_completion_token_matches(const char *current, const char *candidate)
{
    if (candidate == NULL) {
        return 0;
    }
    if (current == NULL || current[0] == '\0') {
        return 1;
    }

    return strncmp(candidate, current, strlen(current)) == 0;
}

static void secdat_cli_completion_print_mode(const char *mode)
{
    printf("__secdat_completion_mode=%s\n", mode);
}

static void secdat_cli_completion_print_candidate(const char *current, const char *candidate)
{
    if (secdat_cli_completion_token_matches(current, candidate)) {
        puts(candidate);
    }
}

static void secdat_cli_completion_print_candidates(const char *current, const char *const *candidates)
{
    size_t index;

    for (index = 0; candidates[index] != NULL; index += 1) {
        secdat_cli_completion_print_candidate(current, candidates[index]);
    }
}

static void secdat_cli_completion_print_keys(
    int argc,
    char **argv,
    const char *current,
    int append_equals
)
{
    const char *dir = NULL;
    const char *domain = NULL;
    const char *store = NULL;
    int index;

    for (index = 0; index + 1 < argc; index += 1) {
        const char *token = argv[index];

        if (strcmp(token, "--dir") == 0 || strcmp(token, "-d") == 0) {
            if (index + 1 < argc - 1) {
                dir = argv[index + 1];
            }
            index += 1;
        } else if (strcmp(token, "--domain") == 0) {
            if (index + 1 < argc - 1) {
                domain = argv[index + 1];
            }
            index += 1;
        } else if (strcmp(token, "--store") == 0 || strcmp(token, "-s") == 0) {
            if (index + 1 < argc - 1) {
                store = argv[index + 1];
            }
            index += 1;
        }
    }

    (void)secdat_print_completion_keys(dir, domain, store, current, append_equals);
}

static void secdat_cli_completion_print_top_level_commands(const char *current)
{
    char previous[64] = "";
    enum secdat_command_type command;

    for (command = SECDAT_COMMAND_HELP; command <= SECDAT_COMMAND_DOMAIN_STATUS; command += 1) {
        const char *name = secdat_cli_command_name(command);
        size_t length = strcspn(name, " ");
        char token[64];

        if (length >= sizeof(token)) {
            length = sizeof(token) - 1;
        }
        memcpy(token, name, length);
        token[length] = '\0';

        if (strcmp(token, previous) == 0) {
            continue;
        }
        strcpy(previous, token);
        secdat_cli_completion_print_candidate(current, token);
    }

    secdat_cli_completion_print_candidate(current, "version");
}

static void secdat_cli_completion_print_group_subcommands(const char *group, const char *current)
{
    char prefix[32];
    char previous[64] = "";
    enum secdat_command_type command;
    size_t prefix_length;

    snprintf(prefix, sizeof(prefix), "%s ", group);
    prefix_length = strlen(prefix);

    for (command = SECDAT_COMMAND_HELP; command <= SECDAT_COMMAND_DOMAIN_STATUS; command += 1) {
        const char *name = secdat_cli_command_name(command);

        if (strncmp(name, prefix, prefix_length) != 0) {
            continue;
        }
        if (strcmp(name + prefix_length, previous) == 0) {
            continue;
        }
        strcpy(previous, name + prefix_length);
        secdat_cli_completion_print_candidate(current, name + prefix_length);
    }
}

static void secdat_cli_completion_print_help_targets(const char *current)
{
    secdat_cli_completion_print_top_level_commands(current);
    secdat_cli_completion_print_candidate(current, "usecases");
    secdat_cli_completion_print_candidate(current, "concepts");
}

static const char *secdat_cli_completion_command_prev_option_mode(const char *command, const char *subcommand, const char *previous)
{
    if (previous == NULL) {
        return "plain";
    }
    if (strcmp(previous, "save") == 0 || strcmp(previous, "load") == 0) {
        return "file";
    }
    if (strcmp(previous, "--dir") == 0 || strcmp(previous, "-d") == 0 || strcmp(previous, "--domain") == 0) {
        return "dir";
    }
    if (strcmp(previous, "--store") == 0 || strcmp(previous, "-s") == 0) {
        return "none";
    }
    if (strcmp(previous, "--help") == 0 || strcmp(previous, "-h") == 0) {
        return "help";
    }
    if (command == NULL) {
        return "plain";
    }
    if (strcmp(command, "ls") == 0) {
        if (strcmp(previous, "--pattern") == 0 || strcmp(previous, "-p") == 0
            || strcmp(previous, "--pattern-exclude") == 0 || strcmp(previous, "-x") == 0) {
            return "none";
        }
    } else if (strcmp(command, "get") == 0) {
        if (strcmp(previous, "--unlock-timeout") == 0 || strcmp(previous, "-t") == 0) {
            return "none";
        }
    } else if (strcmp(command, "set") == 0) {
        if (strcmp(previous, "--env") == 0 || strcmp(previous, "-e") == 0
            || strcmp(previous, "--value") == 0 || strcmp(previous, "-v") == 0
            || strcmp(previous, "--key-visibility") == 0
            || strcmp(previous, "--value-access") == 0
            || strcmp(previous, "--sandbox-inject") == 0
            || strcmp(previous, "--inject") == 0) {
            return "none";
        }
    } else if (strcmp(command, "attr") == 0) {
        if (strcmp(previous, "--key-visibility") == 0
            || strcmp(previous, "--value-access") == 0
            || strcmp(previous, "--sandbox-inject") == 0
            || strcmp(previous, "--inject") == 0) {
            return "none";
        }
    } else if (strcmp(command, "fsck") == 0) {
        if (strcmp(previous, "--format") == 0) {
            return "none";
        }
    } else if (strcmp(command, "exec") == 0) {
        if (strcmp(previous, "--pattern") == 0 || strcmp(previous, "-p") == 0
            || strcmp(previous, "--pattern-exclude") == 0 || strcmp(previous, "-x") == 0
            || strcmp(previous, "--env-map-sed") == 0) {
            return "none";
        }
    } else if (strcmp(command, "export") == 0) {
        if (strcmp(previous, "--pattern") == 0 || strcmp(previous, "-p") == 0) {
            return "none";
        }
    } else if (strcmp(command, "unlock") == 0) {
        if (strcmp(previous, "--duration") == 0 || strcmp(previous, "-t") == 0 || strcmp(previous, "--until") == 0) {
            return "none";
        }
    } else if (strcmp(command, "wait-unlock") == 0) {
        if (strcmp(previous, "--timeout") == 0 || strcmp(previous, "-t") == 0) {
            return "none";
        }
    } else if (strcmp(command, "store") == 0) {
        if (subcommand != NULL) {
            if (strcmp(subcommand, "ls") == 0
                && (strcmp(previous, "--pattern") == 0 || strcmp(previous, "-p") == 0)) {
                return "none";
            }
            if (strcmp(subcommand, "migrate") == 0 && strcmp(previous, "--to-format") == 0) {
                return "none";
            }
        }
    } else if (strcmp(command, "domain") == 0) {
        if (subcommand != NULL && strcmp(subcommand, "ls") == 0
            && (strcmp(previous, "--pattern") == 0 || strcmp(previous, "-p") == 0)) {
            return "none";
        }
    }

    return "plain";
}

static void secdat_cli_completion_parse_context(
    int argc,
    char **argv,
    const char **command,
    const char **subcommand,
    const char **current,
    const char **previous
)
{
    int index;

    *command = NULL;
    *subcommand = NULL;
    *current = argc > 0 ? argv[argc - 1] : "";
    *previous = argc > 1 ? argv[argc - 2] : NULL;

    for (index = 0; index + 1 < argc; ) {
        const char *token = argv[index];

        if (*command == NULL) {
            if (secdat_cli_completion_is_global_option_with_value(token)) {
                index += 2;
                continue;
            }
            if (strcmp(token, "--help") == 0 || strcmp(token, "-h") == 0 || strcmp(token, "--version") == 0 || strcmp(token, "-V") == 0) {
                index += 1;
                continue;
            }
            if (strcmp(token, "store") == 0 || strcmp(token, "domain") == 0) {
                *command = token;
                index += 1;
                continue;
            }
            if (strcmp(token, "help") == 0 || strcmp(token, "version") == 0 || secdat_cli_parse_command_name(token) != SECDAT_COMMAND_HELP) {
                *command = token;
                index += 1;
                continue;
            }
            if (secdat_cli_is_assignment_operand(token)) {
                *command = "set";
                break;
            }
            *command = "get";
            break;
        }

        if ((*subcommand) == NULL && (strcmp(*command, "store") == 0 || strcmp(*command, "domain") == 0)) {
            if (token[0] != '-') {
                *subcommand = token;
            }
            index += 1;
            continue;
        }

        index += 1;
    }
}

static int secdat_cli_completion_positional_count(int argc, char **argv, const char *command, const char *subcommand)
{
    int index;
    int count = 0;
    int skipped_command = 0;
    int skipped_subcommand = 0;

    for (index = 0; index + 1 < argc; index += 1) {
        const char *token = argv[index];

        if (secdat_cli_completion_is_global_option_with_value(token)) {
            index += 1;
            continue;
        }
        if (strcmp(token, "--help") == 0 || strcmp(token, "-h") == 0 || strcmp(token, "--version") == 0 || strcmp(token, "-V") == 0) {
            continue;
        }
        if (!skipped_command && command != NULL && strcmp(token, command) == 0) {
            skipped_command = 1;
            continue;
        }
        if (token[0] == '-') {
            const char *option_mode = secdat_cli_completion_command_prev_option_mode(command, subcommand, token);
            if ((strcmp(option_mode, "none") == 0 || strcmp(option_mode, "dir") == 0 || strcmp(option_mode, "file") == 0)
                && index + 1 < argc - 1) {
                index += 1;
            }
            continue;
        }
        if (command != NULL && (strcmp(command, "store") == 0 || strcmp(command, "domain") == 0)
            && !skipped_subcommand && subcommand != NULL && strcmp(token, subcommand) == 0) {
            skipped_subcommand = 1;
            continue;
        }
        count += 1;
    }

    return count;
}

int secdat_cli_complete(int argc, char **argv)
{
    static const char *const global_options[] = {
        "--dir", "-d", "--domain", "--store", "-s", "--help", "-h", "--version", "-V", NULL,
    };
    static const char *const ls_options[] = {
        "--pattern", "-p", "--pattern-exclude", "-x", "--safe", "-e", "--unsafe", "-u",
        "--public-value", "--secret-value", "--sandbox-injectable", "--metadata",
        "--canonical", "-c", "--canonical-domain", "-D", "--canonical-store", "-S", "--help", "-h", NULL,
    };
    static const char *const list_options[] = {
        "--masked", "-m", "--overridden", "-o", "--orphaned", "-O", "--safe", "-e", "--unsafe", "-u",
        "--public-value", "--secret-value", "--sandbox-injectable", "--help", "-h", NULL,
    };
    static const char *const attr_options[] = {
        "--key-visibility", "--value-access", "--sandbox-inject", "--inject", "--help", "-h", NULL,
    };
    static const char *const fsck_options[] = {
        "--orphaned", "--dangling", "--refcount", "--format", "--help", "-h", NULL,
    };
    static const char *const get_options[] = {
        "--on-demand-unlock", "-w", "--unlock-timeout", "-t", "--stdout", "-o", "--shellescaped", "-e", "--help", "-h", NULL,
    };
    static const char *const set_options[] = {
        "--unsafe", "-u", "--public-value", "--secret-value", "--stdin", "-i", "--env", "-e", "--value", "-v",
        "--key-visibility", "--value-access", "--sandbox-inject", "--inject", "--help", "-h", NULL,
    };
    static const char *const rm_options[] = {
        "--ignore-missing", "-f", "--help", "-h", NULL,
    };
    static const char *const exec_options[] = {
        "--pattern", "-p", "--pattern-exclude", "-x", "--env-map-sed", "--help", "-h", NULL,
    };
    static const char *const export_options[] = {
        "--pattern", "-p", "--help", "-h", NULL,
    };
    static const char *const unlock_options[] = {
        "--duration", "-t", "--until", "--inherit", "-i", "--volatile", "-v", "--readonly", "-r",
        "--descendants", "-d", "--yes", "-y", "--help", "-h", NULL,
    };
    static const char *const lock_options[] = {
        "--inherit", "-i", "--save", "-s", "--help", "-h", NULL,
    };
    static const char *const status_options[] = {
        "--quiet", "-q", "--help", "-h", NULL,
    };
    static const char *const wait_unlock_options[] = {
        "--timeout", "-t", "--quiet", "-q", "--help", "-h", NULL,
    };
    static const char *const store_ls_options[] = {
        "--pattern", "-p", "--help", "-h", NULL,
    };
    static const char *const store_migrate_options[] = {
        "--to-format", "--dry-run", "--help", "-h", NULL,
    };
    static const char *const domain_ls_options[] = {
        "--long", "-l", "--inherited", "-a", "--ancestors", "-A", "--descendants", "-R", "--pattern", "-p", "--help", "-h", NULL,
    };
    const char *command;
    const char *subcommand;
    const char *current;
    const char *previous;
    const char *mode;

    secdat_cli_completion_parse_context(argc, argv, &command, &subcommand, &current, &previous);
    mode = secdat_cli_completion_command_prev_option_mode(command, subcommand, previous);
    secdat_cli_completion_print_mode(mode);

    if (strcmp(mode, "dir") == 0 || strcmp(mode, "file") == 0 || strcmp(mode, "none") == 0) {
        return 0;
    }
    if (strcmp(mode, "help") == 0) {
        secdat_cli_completion_print_help_targets(current);
        return 0;
    }

    if (command == NULL) {
        secdat_cli_completion_print_top_level_commands(current);
        secdat_cli_completion_print_candidates(current, global_options);
        secdat_cli_completion_print_keys(argc, argv, current, 0);
        secdat_cli_completion_print_keys(argc, argv, current, 1);
        return 0;
    }

    if (strcmp(command, "help") == 0) {
        secdat_cli_completion_print_help_targets(current);
        return 0;
    }

    if (strcmp(command, "store") == 0 && subcommand == NULL) {
        secdat_cli_completion_print_group_subcommands("store", current);
        return 0;
    }
    if (strcmp(command, "domain") == 0 && subcommand == NULL) {
        secdat_cli_completion_print_group_subcommands("domain", current);
        return 0;
    }

    if (secdat_cli_completion_is_command_with_key_operand(command)
        && secdat_cli_completion_positional_count(argc, argv, command, subcommand) == 0) {
        secdat_cli_completion_print_keys(argc, argv, current, 0);
    }

    if (strcmp(command, "ls") == 0) {
        secdat_cli_completion_print_candidates(current, ls_options);
    } else if (strcmp(command, "list") == 0) {
        secdat_cli_completion_print_candidates(current, list_options);
    } else if (strcmp(command, "attr") == 0) {
        secdat_cli_completion_print_candidates(current, attr_options);
    } else if (strcmp(command, "fsck") == 0) {
        secdat_cli_completion_print_candidates(current, fsck_options);
    } else if (strcmp(command, "get") == 0) {
        secdat_cli_completion_print_candidates(current, get_options);
    } else if (strcmp(command, "set") == 0) {
        secdat_cli_completion_print_candidates(current, set_options);
    } else if (strcmp(command, "rm") == 0) {
        secdat_cli_completion_print_candidates(current, rm_options);
    } else if (strcmp(command, "exec") == 0) {
        secdat_cli_completion_print_candidates(current, exec_options);
    } else if (strcmp(command, "export") == 0) {
        secdat_cli_completion_print_candidates(current, export_options);
    } else if (strcmp(command, "unlock") == 0) {
        secdat_cli_completion_print_candidates(current, unlock_options);
    } else if (strcmp(command, "lock") == 0) {
        secdat_cli_completion_print_candidates(current, lock_options);
    } else if (strcmp(command, "status") == 0) {
        secdat_cli_completion_print_candidates(current, status_options);
    } else if (strcmp(command, "wait-unlock") == 0) {
        secdat_cli_completion_print_candidates(current, wait_unlock_options);
    } else if (strcmp(command, "store") == 0 && subcommand != NULL && strcmp(subcommand, "ls") == 0) {
        secdat_cli_completion_print_candidates(current, store_ls_options);
    } else if (strcmp(command, "store") == 0 && subcommand != NULL && strcmp(subcommand, "migrate") == 0) {
        secdat_cli_completion_print_candidates(current, store_migrate_options);
    } else if (strcmp(command, "domain") == 0 && subcommand != NULL && strcmp(subcommand, "ls") == 0) {
        secdat_cli_completion_print_candidates(current, domain_ls_options);
    }

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
    if (strcmp(name, "attr") == 0) {
        return SECDAT_COMMAND_ATTR;
    }
    if (strcmp(name, "fsck") == 0) {
        return SECDAT_COMMAND_FSCK;
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
    if (strcmp(name, "id") == 0) {
        return SECDAT_COMMAND_ID;
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
    if (strcmp(name, "ln") == 0) {
        return SECDAT_COMMAND_LN;
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
    if (strcmp(name, "inherit") == 0) {
        return SECDAT_COMMAND_INHERIT;
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
    if (strcmp(name, "wait-unlock") == 0) {
        return SECDAT_COMMAND_WAIT_UNLOCK;
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
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "ls", "[GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN] [-x GLOBPATTERN|--pattern-exclude GLOBPATTERN] [-e|--safe|--secret-value] [-u|--unsafe|--public-value] [--metadata] [--sandbox-injectable] [-c|--canonical] [-D|--canonical-domain] [-S|--canonical-store]");
        break;
    case SECDAT_COMMAND_LIST:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "list", "[-m|--masked] [-o|--overridden] [-O|--orphaned] [-e|--safe|--secret-value] [-u|--unsafe|--public-value] [--sandbox-injectable]");
        break;
    case SECDAT_COMMAND_ATTR:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "attr", "KEYREF [--key-visibility always|unlocked] [--value-access unlocked|always] [--sandbox-inject never|explicit|allow]");
        break;
    case SECDAT_COMMAND_FSCK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "fsck", "[--orphaned] [--dangling] [--refcount] [--format v1|v2]");
        break;
    case SECDAT_COMMAND_MASK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "mask", "KEYREF");
        break;
    case SECDAT_COMMAND_UNMASK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "unmask", "KEYREF");
        break;
    case SECDAT_COMMAND_EXISTS:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "exists", "KEYREF");
        break;
    case SECDAT_COMMAND_ID:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "id", "KEYREF");
        break;
    case SECDAT_COMMAND_GET:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "get", "[-w|--on-demand-unlock] [-t SECONDS|--unlock-timeout SECONDS] KEYREF [-o|--stdout|-e|--shellescaped]");
        break;
    case SECDAT_COMMAND_SET:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "set", "KEYREF [-u|--unsafe|--public-value|--secret-value] [--key-visibility always|unlocked] [--value-access unlocked|always] [--sandbox-inject never|explicit|allow] [VALUE|-i|--stdin|-e ENVNAME|--env ENVNAME|-v VALUE|--value VALUE]");
        break;
    case SECDAT_COMMAND_RM:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "rm", "[-f|--ignore-missing] KEYREF");
        break;
    case SECDAT_COMMAND_MV:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "mv", "SRC_KEYREF DST_KEYREF");
        break;
    case SECDAT_COMMAND_CP:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "cp", "SRC_KEYREF DST_KEYREF");
        break;
    case SECDAT_COMMAND_LN:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "ln", "SRC_KEYREF DST_KEYREF");
        break;
    case SECDAT_COMMAND_EXEC:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "exec", "[-p GLOBPATTERN|--pattern GLOBPATTERN] [-x GLOBPATTERN|--pattern-exclude GLOBPATTERN] [--env-map-sed EXPR] [--] CMD [ARGS...]");
        break;
    case SECDAT_COMMAND_EXPORT:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "export", "[-p GLOBPATTERN|--pattern GLOBPATTERN]");
        break;
    case SECDAT_COMMAND_SAVE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "save", "FILE");
        break;
    case SECDAT_COMMAND_LOAD:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR] [-s STORE|--store STORE]", "load", "FILE");
        break;
    case SECDAT_COMMAND_UNLOCK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "unlock", "[-t TTL|--duration TTL] [--until TIME] [-i|--inherit] [-v|--volatile|-r|--readonly] [-d|--descendants] [-y|--yes]");
        break;
    case SECDAT_COMMAND_INHERIT:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "inherit", "");
        break;
    case SECDAT_COMMAND_PASSWD:
        secdat_cli_print_usage_columns(program_name, "", "passwd", "");
        break;
    case SECDAT_COMMAND_LOCK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "lock", "[-i|--inherit] [-s|--save]");
        break;
    case SECDAT_COMMAND_STATUS:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "status", "[-q|--quiet]");
        break;
    case SECDAT_COMMAND_WAIT_UNLOCK:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "wait-unlock", "[-t SECONDS|--timeout SECONDS] [-q|--quiet]");
        break;
    case SECDAT_COMMAND_STORE_CREATE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "store create", "STORE");
        break;
    case SECDAT_COMMAND_STORE_DELETE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "store delete", "STORE");
        break;
    case SECDAT_COMMAND_STORE_LS:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "store ls", "[GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]");
        break;
    case SECDAT_COMMAND_STORE_MIGRATE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "store migrate", "STORE --to-format v2 [--dry-run]");
        break;
    case SECDAT_COMMAND_DOMAIN_CREATE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "domain create", "");
        break;
    case SECDAT_COMMAND_DOMAIN_DELETE:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "domain delete", "");
        break;
    case SECDAT_COMMAND_DOMAIN_LS:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "domain ls", "[-l|--long] [-a|--inherited] [-A|--ancestors] [-R|--descendants] [GLOBPATTERN] [-p GLOBPATTERN|--pattern GLOBPATTERN]");
        break;
    case SECDAT_COMMAND_DOMAIN_STATUS:
        secdat_cli_print_usage_columns(program_name, "[-d DIR|--dir DIR]", "domain status", "[-q|--quiet]");
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
    secdat_cli_print_detail_line(_("  -d, --dir DIR      set the base directory used for domain resolution\n"));
    secdat_cli_print_detail_line(_("      --domain DIR   require one exact registered domain root instead of discovery\n"));
    secdat_cli_print_detail_line(_("  -s, --store STORE  select the store namespace inside the resolved domain\n"));
    secdat_cli_print_detail_line(_("  -h, --help         show global help, or combine with COMMAND or TOPIC for detailed help\n"));
    secdat_cli_print_detail_line(_("  -V, --version      print the secdat version\n"));
}

static void secdat_cli_print_meta_usage_line(const char *program_name, const char *target)
{
    if (target != NULL && strcmp(target, "help") == 0) {
        secdat_cli_print_usage_columns(program_name, "", "help", "[COMMAND]");
        return;
    }
    if (target != NULL && strcmp(target, "version") == 0) {
        secdat_cli_print_usage_columns(program_name, "", "version", "");
        return;
    }
    if (target != NULL && strcmp(target, "usecases") == 0) {
        secdat_cli_print_usage_columns(program_name, "", "help", "usecases");
        return;
    }
    if (target != NULL && strcmp(target, "concepts") == 0) {
        secdat_cli_print_usage_columns(program_name, "", "help", "concepts");
    }
}

static void secdat_cli_print_help_routes(const char *program_name, const char *target)
{
    printf(_("\nHelp:\n"));
    printf(_("  %s --help\n"), program_name);
    printf(_("  %s help [COMMAND]\n"), program_name);
    printf(_("  %s help usecases\n"), program_name);
    printf(_("  %s help concepts\n"), program_name);
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
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  bash load current shell vars: source <(%s export)\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  bash alternative: eval \"$(%s export)\"\n"), program_name);
        secdat_cli_print_detail_line(buffer);
    }
    secdat_cli_print_detail_line(_("  bash completion script: completions/secdat.bash\n"));
    secdat_cli_print_detail_line(_("  man page source: docs/secdat.1\n"));
}

static void secdat_cli_print_support_routes(void)
{
    printf(_("\nSupport:\n"));
    secdat_cli_print_detail_line(_("  issues: https://github.com/mako10k/secdat/issues\n"));
    secdat_cli_print_detail_line(_("  repository: https://github.com/mako10k/secdat\n"));
    secdat_cli_print_detail_line(_("  author: Makoto Katsumata <mako10k@mk10.org>\n"));
}

static void secdat_cli_print_group_meanings(void)
{
    printf(_("\nGroups:\n"));
    secdat_cli_print_detail_line(_("  store: manage store namespaces and v1 to v2 migration inside the resolved current domain\n"));
    secdat_cli_print_detail_line(_("  domain: manage domain roots and domain discovery scope\n"));
}

static void secdat_cli_print_command_meanings(void)
{
    printf(_("\nCommands:\n"));
    secdat_cli_print_detail_line(_("  help: show global help or detailed help for one command\n"));
    secdat_cli_print_detail_line(_("  ls: list effective keys visible from the current domain view, optionally filtered by safe or unsafe storage\n"));
    secdat_cli_print_detail_line(_("  list: inspect current-domain masked, overridden, orphaned, safe, unsafe, or sandbox-injectable local state\n"));
    secdat_cli_print_detail_line(_("  attr: show or update one key's visibility, value-access, and sandbox injection attributes\n"));
    secdat_cli_print_detail_line(_("  fsck: check current-domain store metadata for migration and repair planning\n"));
    secdat_cli_print_detail_line(_("  mask: create a local tombstone to hide one inherited key\n"));
    secdat_cli_print_detail_line(_("  unmask: remove one local tombstone from the current domain\n"));
    secdat_cli_print_detail_line(_("  exists: check whether one resolved key is visible from the current domain view\n"));
    secdat_cli_print_detail_line(_("  id: print the v2 secret object UUID for one resolved key without reading its value\n"));
    secdat_cli_print_detail_line(_("  get: decrypt one resolved key and write it to standard output; --on-demand-unlock waits for another terminal to unlock\n"));
    secdat_cli_print_detail_line(_("  set: store or update one key in the resolved current domain; --unsafe stores plaintext visible while locked\n"));
    secdat_cli_print_detail_line(_("  rm: remove one key locally or create a tombstone for an inherited key; --ignore-missing treats absent keys as success\n"));
    secdat_cli_print_detail_line(_("  mv: rename or relocate one key between resolved locations\n"));
    secdat_cli_print_detail_line(_("  cp: copy one key into another resolved location\n"));
    secdat_cli_print_detail_line(_("  ln: link another key to the same v2 secret object, including cross-domain v2 links\n"));
    secdat_cli_print_detail_line(_("  exec: inject resolved keys into a child process environment\n"));
    secdat_cli_print_detail_line(_("  export: emit shell-ready export lines that defer secret reads to secdat get\n"));
    secdat_cli_print_detail_line(_("  save: export the current visible secrets into a passphrase-protected bundle\n"));
    secdat_cli_print_detail_line(_("  load: import a passphrase-protected bundle into the current domain view\n"));
    secdat_cli_print_detail_line(_("  unlock: start or refresh a local unlock for the current domain; --duration accepts plain minutes, suffix forms like 1h30m, or ISO 8601 durations such as PT1H30M, --until accepts an absolute RFC 3339 timestamp, and --inherit drops the current domain's local override to fall back to inherited state\n"));
    secdat_cli_print_detail_line(_("  inherit: force the current domain back to inherited state by removing a local lock or clearing a local unlock, without checking whether the result stays unlocked\n"));
    secdat_cli_print_detail_line(_("  passwd: change the wrapped-master-key passphrase\n"));
    secdat_cli_print_detail_line(_("  lock: return the current domain to a locked local state, or do nothing when it is already locked\n"));
    secdat_cli_print_detail_line(_("  status: report whether secret material is available from the current domain scope\n"));
    secdat_cli_print_detail_line(_("  wait-unlock: wait until the current domain scope becomes unlocked, or fail on timeout\n"));
    secdat_cli_print_detail_line(_("  version: print the secdat version\n"));
}

static void secdat_cli_print_topic_meanings(void)
{
    printf(_("\nTopics:\n"));
    secdat_cli_print_detail_line(_("  usecases: show example workflows and task-oriented command combinations\n"));
    secdat_cli_print_detail_line(_("  concepts: explain domains, stores, inheritance, local unlocks, local locks, and KEYREF resolution\n"));
}

static void secdat_cli_print_target_meaning(const char *target)
{
    printf(_("\nMeaning:\n"));
    if (target != NULL && strcmp(target, "help") == 0) {
        secdat_cli_print_detail_line(_("  help: show global help or detailed help for one command\n"));
        return;
    }
    if (target != NULL && strcmp(target, "ls") == 0) {
        secdat_cli_print_detail_line(_("  ls: list effective keys visible from the current domain view, optionally filtered by safe or unsafe storage\n"));
        return;
    }
    if (target != NULL && strcmp(target, "list") == 0) {
        secdat_cli_print_detail_line(_("  list: inspect current-domain masked, overridden, orphaned, safe, unsafe, or sandbox-injectable local state\n"));
        return;
    }
    if (target != NULL && strcmp(target, "attr") == 0) {
        secdat_cli_print_detail_line(_("  attr: show or update one key's visibility, value-access, and sandbox injection attributes\n"));
        return;
    }
    if (target != NULL && strcmp(target, "fsck") == 0) {
        secdat_cli_print_detail_line(_("  fsck: check current-domain store metadata for migration and repair planning\n"));
        return;
    }
    if (target != NULL && strcmp(target, "mask") == 0) {
        secdat_cli_print_detail_line(_("  mask: create a local tombstone to hide one inherited key\n"));
        return;
    }
    if (target != NULL && strcmp(target, "unmask") == 0) {
        secdat_cli_print_detail_line(_("  unmask: remove one local tombstone from the current domain\n"));
        return;
    }
    if (target != NULL && strcmp(target, "exists") == 0) {
        secdat_cli_print_detail_line(_("  exists: check whether one resolved key is visible from the current domain view\n"));
        return;
    }
    if (target != NULL && strcmp(target, "get") == 0) {
        secdat_cli_print_detail_line(_("  get: decrypt one resolved key and write it to standard output; --on-demand-unlock waits for another terminal to unlock\n"));
        return;
    }
    if (target != NULL && strcmp(target, "set") == 0) {
        secdat_cli_print_detail_line(_("  set: store or update one key in the resolved current domain; --unsafe stores plaintext visible while locked\n"));
        return;
    }
    if (target != NULL && strcmp(target, "rm") == 0) {
        secdat_cli_print_detail_line(_("  rm: remove one key locally or create a tombstone for an inherited key; --ignore-missing treats absent keys as success\n"));
        return;
    }
    if (target != NULL && strcmp(target, "mv") == 0) {
        secdat_cli_print_detail_line(_("  mv: rename or relocate one key between resolved locations\n"));
        return;
    }
    if (target != NULL && strcmp(target, "cp") == 0) {
        secdat_cli_print_detail_line(_("  cp: copy one key into another resolved location\n"));
        return;
    }
    if (target != NULL && strcmp(target, "ln") == 0) {
        secdat_cli_print_detail_line(_("  ln: link another key to the same v2 secret object, including cross-domain v2 links\n"));
        return;
    }
    if (target != NULL && strcmp(target, "exec") == 0) {
        secdat_cli_print_detail_line(_("  exec: inject resolved keys into a child process environment\n"));
        return;
    }
    if (target != NULL && strcmp(target, "export") == 0) {
        secdat_cli_print_detail_line(_("  export: emit shell-ready export lines that defer secret reads to secdat get\n"));
        return;
    }
    if (target != NULL && strcmp(target, "save") == 0) {
        secdat_cli_print_detail_line(_("  save: export the current visible secrets into a passphrase-protected bundle\n"));
        return;
    }
    if (target != NULL && strcmp(target, "load") == 0) {
        secdat_cli_print_detail_line(_("  load: import a passphrase-protected bundle into the current domain view\n"));
        return;
    }
    if (target != NULL && strcmp(target, "unlock") == 0) {
        secdat_cli_print_detail_line(_("  unlock: start or refresh a local unlock for the current domain; --duration accepts plain minutes, suffix forms like 1h30m, or ISO 8601 durations such as PT1H30M, --until accepts an absolute RFC 3339 timestamp, and --inherit drops the current domain's local override to fall back to inherited state\n"));
        return;
    }
    if (target != NULL && strcmp(target, "inherit") == 0) {
        secdat_cli_print_detail_line(_("  inherit: force the current domain back to inherited state by removing a local lock or clearing a local unlock, without checking whether the result stays unlocked\n"));
        return;
    }
    if (target != NULL && strcmp(target, "passwd") == 0) {
        secdat_cli_print_detail_line(_("  passwd: change the wrapped-master-key passphrase\n"));
        return;
    }
    if (target != NULL && strcmp(target, "lock") == 0) {
        secdat_cli_print_detail_line(_("  lock: return the current domain to a locked local state, or do nothing when it is already locked\n"));
        return;
    }
    if (target != NULL && strcmp(target, "status") == 0) {
        secdat_cli_print_detail_line(_("  status: report whether secret material is available from the current domain scope\n"));
        return;
    }
    if (target != NULL && strcmp(target, "wait-unlock") == 0) {
        secdat_cli_print_detail_line(_("  wait-unlock: wait until the current domain scope becomes unlocked, or fail on timeout\n"));
        return;
    }
    if (target != NULL && strcmp(target, "version") == 0) {
        secdat_cli_print_detail_line(_("  version: print the secdat version\n"));
        return;
    }
    if (target != NULL && strcmp(target, "usecases") == 0) {
        secdat_cli_print_detail_line(_("  usecases: show example workflows and task-oriented command combinations\n"));
        return;
    }
    if (target != NULL && strcmp(target, "concepts") == 0) {
        secdat_cli_print_detail_line(_("  concepts: explain domains, stores, inheritance, sessions, and KEYREF resolution\n"));
        return;
    }
    if (target != NULL && strcmp(target, "store") == 0) {
        secdat_cli_print_detail_line(_("  store: manage store namespaces and migrate v1 stores to the v2 domain-entry/object layout\n"));
        return;
    }
    if (target != NULL && strcmp(target, "domain") == 0) {
        secdat_cli_print_detail_line(_("  domain: manage domain roots and domain discovery scope\n"));
        return;
    }
}

static void secdat_cli_print_target_use_cases(const char *program_name, const char *target)
{
    if (target == NULL) {
        return;
    }

    printf(_("\nUse cases:\n"));
    if (strcmp(target, "get") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  read one value to stdout: %s get API_TOKEN --stdout\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  wait for another terminal to unlock before reading: %s get --on-demand-unlock --unlock-timeout 30 API_TOKEN --stdout\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "set") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  write one value from an argument: %s set API_TOKEN --value new-token\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  read a value from standard input without echoing it in shell history: printf 'token' | %s set API_TOKEN --stdin\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "export") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  load current shell variables without printing raw secrets: source <(%s export)\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  export one namespace before running another tool: eval \"$(%s --store app export --pattern 'APP_*')\"\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "exec") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  run one command with matching secrets injected: %s exec --pattern 'APP_*' env\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  exclude one inherited key while running a child process: %s exec --pattern 'APP_*' --pattern-exclude 'APP_DEBUG_*' CMD\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "ln") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  share one v2 secret object under another key: %s ln APP_TOKEN SERVICE_TOKEN\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  link across explicit domains/stores: %s ln /src/domain/APP_TOKEN:app /dst/domain/APP_TOKEN:ops\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "unlock") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  start a session for the current project directory: %s unlock\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  refresh an active session for 15 minutes without re-entering the passphrase: %s unlock --duration 15\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  unlock one specific domain from elsewhere: %s --dir ~/example/project unlock\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "wait-unlock") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  block a script until another terminal unlocks the same domain: %s --dir ~/example/project wait-unlock --timeout 900\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  poll quietly before a later secret read: %s wait-unlock --timeout 30 --quiet\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "status") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  check whether the current domain can read secrets now: %s status\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  use exit status only in scripts: %s status --quiet\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "list") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  inspect local tombstones and overrides before cleanup: %s list --masked\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inspect only plaintext-at-rest entries in the current domain: %s list --unsafe\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "store") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  create one namespace for app-specific keys: %s store create app\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inspect available namespaces before selecting one with --store: %s store ls\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inspect a v1 to v2 migration before writing: %s store migrate app --to-format v2 --dry-run\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  write the v2 domain-entry/object graph after review: %s store migrate app --to-format v2\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }
    if (strcmp(target, "domain") == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  register the current directory as a domain root: %s domain create\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inspect inherited and blocked descendants: %s domain ls -l --descendants\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        return;
    }

    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  see %s help usecases for workflow-oriented examples across multiple commands\n"), program_name);
        secdat_cli_print_detail_line(buffer);
    }
}

static void secdat_cli_print_use_cases_overview(const char *program_name)
{
    printf(_("\nUse cases:\n"));
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  bootstrap a new project domain: %s --dir ~/example/project unlock\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  read one secret directly: %s --dir ~/example/project get API_TOKEN --stdout\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  load shell variables without exposing raw values in exported text: source <(%s --dir ~/example/project export)\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inject secrets into one subprocess only: %s --dir ~/example/project exec --env-map-sed 's/^MY_APP_\\(.*\\)$/APP_\\1/' CMD\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  block automation until a human unlocks the domain elsewhere: %s --dir ~/example/project wait-unlock --timeout 900\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        snprintf(buffer, sizeof(buffer), _("  inspect inheritance and local locks under one branch: %s --dir ~/example/project domain ls -l --descendants\n"), program_name);
        secdat_cli_print_detail_line(buffer);
    }
}

static void secdat_cli_print_concepts_detail(const char *program_name)
{
    printf(_("\nConcepts:\n"));
    {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), _("  domain: a directory-scoped boundary for inheritance, sessions, and tombstones; resolve it with --dir or inspect it with %s domain status\n"), program_name);
        secdat_cli_print_detail_line(buffer);
        secdat_cli_print_detail_line(_("  store: a domain-local namespace selected by --store; use it to separate app, ops, or personal keys inside one domain\n"));
        secdat_cli_print_detail_line(_("  inheritance: reads fall back to parent domains until a local value, tombstone, or local lock changes the effective view\n"));
        secdat_cli_print_detail_line(_("  local lock: a local override that blocks reuse of an inherited unlock until the current domain unlocks or inherits again\n"));
        snprintf(buffer, sizeof(buffer), _("  local unlock: an authenticated master-key cache scoped to one domain branch; inspect availability with %s status and refresh it with %s unlock\n"), program_name, program_name);
        secdat_cli_print_detail_line(buffer);
        secdat_cli_print_detail_line(_("  KEYREF: the canonical lookup syntax KEY[/ABSOLUTE/DOMAIN][:STORE] expressed in help as [/ABSOLUTE/DOMAIN/]KEY[:STORE]\n"));
    }
}

static void secdat_cli_print_semantics(void)
{
    printf(_("\nSemantics:\n"));
    secdat_cli_print_detail_line(_("  DIR: base directory used for domain resolution; defaults to the current working directory\n"));
    secdat_cli_print_detail_line(_("  DOMAIN: directory-scoped configuration boundary used for inheritance and tombstones\n"));
    secdat_cli_print_detail_line(_("  STORE: domain-local namespace selected by --store; defaults to the default store\n"));
    secdat_cli_print_detail_line(_("  KEY / KEYREF: logical secret name, optionally qualified as [/ABSOLUTE/DOMAIN/]KEY[:STORE]\n"));
    secdat_cli_print_detail_line(_("  migration hints: v2-only errors suggest store migrate; set SECDAT_SUPPRESS_MIGRATION_HINTS=1 to hide those hints\n"));
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
    } else if (strcmp(argv[index], "attr") == 0) {
        cli->command = SECDAT_COMMAND_ATTR;
        index += 1;
    } else if (strcmp(argv[index], "fsck") == 0) {
        cli->command = SECDAT_COMMAND_FSCK;
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
    } else if (strcmp(argv[index], "id") == 0) {
        cli->command = SECDAT_COMMAND_ID;
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
    } else if (strcmp(argv[index], "ln") == 0) {
        cli->command = SECDAT_COMMAND_LN;
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
    } else if (strcmp(argv[index], "inherit") == 0) {
        cli->command = SECDAT_COMMAND_INHERIT;
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
    } else if (strcmp(argv[index], "wait-unlock") == 0) {
        cli->command = SECDAT_COMMAND_WAIT_UNLOCK;
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
        } else if (strcmp(argv[index], "migrate") == 0) {
            cli->command = SECDAT_COMMAND_STORE_MIGRATE;
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
    } else if (secdat_cli_is_assignment_operand(argv[index])) {
        cli->command = SECDAT_COMMAND_SET;
    } else {
        cli->command = SECDAT_COMMAND_GET;
    }

    cli->argc = argc - index;
    cli->argv = &argv[index];
    if (secdat_cli_requests_explicit_help(cli->command, cli->argc, cli->argv)) {
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
    secdat_cli_print_topic_meanings();
    secdat_cli_print_group_meanings();
    secdat_cli_print_command_meanings();
    secdat_cli_print_semantics();
}

void secdat_cli_print_command_usage(const char *program_name, enum secdat_command_type command)
{
    const char *target = secdat_cli_command_name(command);

    printf(_("Usage:\n"));
    secdat_cli_print_usage_line(program_name, command);
    if (command == SECDAT_COMMAND_LS || command == SECDAT_COMMAND_LIST || command == SECDAT_COMMAND_ATTR
        || command == SECDAT_COMMAND_MASK || command == SECDAT_COMMAND_UNMASK
        || command == SECDAT_COMMAND_EXISTS || command == SECDAT_COMMAND_ID || command == SECDAT_COMMAND_GET || command == SECDAT_COMMAND_SET
        || command == SECDAT_COMMAND_RM || command == SECDAT_COMMAND_MV || command == SECDAT_COMMAND_CP || command == SECDAT_COMMAND_LN) {
        printf(_("\n"));
        secdat_cli_print_detail_line(_("  KEYREF syntax: [/ABSOLUTE/DOMAIN/]KEY[:STORE]\n"));
    }
    secdat_cli_print_help_routes(program_name, target);
    secdat_cli_print_target_meaning(target);
    secdat_cli_print_target_use_cases(program_name, target);
    if (command == SECDAT_COMMAND_EXPORT) {
        secdat_cli_print_shell_routes(program_name);
    }
    secdat_cli_print_support_routes();
    secdat_cli_print_semantics();
}

void secdat_cli_print_help_target(const char *program_name, const char *target)
{
    if (target != NULL && (strcmp(target, "help") == 0 || strcmp(target, "version") == 0 || strcmp(target, "usecases") == 0 || strcmp(target, "concepts") == 0)) {
        printf(_("Usage:\n"));
        secdat_cli_print_meta_usage_line(program_name, target);
        secdat_cli_print_help_routes(program_name, target);
        secdat_cli_print_target_meaning(target);
        if (strcmp(target, "usecases") == 0) {
            secdat_cli_print_use_cases_overview(program_name);
        }
        if (strcmp(target, "concepts") == 0) {
            secdat_cli_print_concepts_detail(program_name);
        }
        secdat_cli_print_support_routes();
        return;
    }

    if (target != NULL && strcmp(target, "store") == 0) {
        printf(_("Usage:\n"));
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_CREATE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_DELETE);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_LS);
        secdat_cli_print_usage_line(program_name, SECDAT_COMMAND_STORE_MIGRATE);
        secdat_cli_print_help_routes(program_name, target);
        secdat_cli_print_target_meaning(target);
        secdat_cli_print_target_use_cases(program_name, target);
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
        secdat_cli_print_target_use_cases(program_name, target);
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
    case SECDAT_COMMAND_ATTR:
        return "attr";
    case SECDAT_COMMAND_FSCK:
        return "fsck";
    case SECDAT_COMMAND_MASK:
        return "mask";
    case SECDAT_COMMAND_UNMASK:
        return "unmask";
    case SECDAT_COMMAND_EXISTS:
        return "exists";
    case SECDAT_COMMAND_ID:
        return "id";
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
    case SECDAT_COMMAND_LN:
        return "ln";
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
    case SECDAT_COMMAND_INHERIT:
        return "inherit";
    case SECDAT_COMMAND_PASSWD:
        return "passwd";
    case SECDAT_COMMAND_LOCK:
        return "lock";
    case SECDAT_COMMAND_STATUS:
        return "status";
    case SECDAT_COMMAND_WAIT_UNLOCK:
        return "wait-unlock";
    case SECDAT_COMMAND_STORE_CREATE:
        return "store create";
    case SECDAT_COMMAND_STORE_DELETE:
        return "store delete";
    case SECDAT_COMMAND_STORE_LS:
        return "store ls";
    case SECDAT_COMMAND_STORE_MIGRATE:
        return "store migrate";
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
