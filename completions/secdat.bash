_secdat_complete()
{
    local cur prev cmd subcmd index
    local -a global_opts commands store_subcommands domain_subcommands

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    global_opts=(--dir -d --store -s --help -h --version -V)
    commands=(help version ls list mask unmask exists get set rm mv cp exec export save load unlock passwd lock status store domain)
    store_subcommands=(create delete ls)
    domain_subcommands=(create delete ls)

    if [[ "$prev" == "--dir" || "$prev" == "-d" ]]; then
        COMPREPLY=( $(compgen -d -- "$cur") )
        return 0
    fi

    if [[ "$prev" == "save" || "$prev" == "load" ]]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
        return 0
    fi

    cmd=""
    subcmd=""
    index=1
    while (( index < COMP_CWORD )); do
        case "${COMP_WORDS[index]}" in
            --dir|-d|--store|-s)
                ((index += 2))
                continue
                ;;
            help|version|ls|list|mask|unmask|exists|get|set|rm|mv|cp|exec|export|save|load|unlock|passwd|lock|status|store|domain)
                cmd="${COMP_WORDS[index]}"
                if [[ "$cmd" == "store" || "$cmd" == "domain" ]]; then
                    if (( index + 1 < COMP_CWORD )); then
                        subcmd="${COMP_WORDS[index+1]}"
                    fi
                fi
                break
                ;;
        esac
        ((index += 1))
    done

    if [[ -z "$cmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "${global_opts[*]}" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "${commands[*]}" -- "$cur") )
        fi
        return 0
    fi

    case "$cmd" in
        help)
            COMPREPLY=( $(compgen -W "${commands[*]}" -- "$cur") )
            return 0
            ;;
        store)
            if [[ -z "$subcmd" && $COMP_CWORD -le $((index + 1)) ]]; then
                COMPREPLY=( $(compgen -W "${store_subcommands[*]}" -- "$cur") )
                return 0
            fi
            case "$subcmd" in
                create|delete)
                    return 0
                    ;;
                ls)
                    COMPREPLY=( $(compgen -W "--pattern -p" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        domain)
            if [[ -z "$subcmd" && $COMP_CWORD -le $((index + 1)) ]]; then
                COMPREPLY=( $(compgen -W "${domain_subcommands[*]}" -- "$cur") )
                return 0
            fi
            case "$subcmd" in
                ls)
                    COMPREPLY=( $(compgen -W "--pattern -p" -- "$cur") )
                    return 0
                    ;;
            esac
            ;;
        ls)
            COMPREPLY=( $(compgen -W "--pattern -p --pattern-exclude --canonical -c --canonical-domain -D --canonical-store -S" -- "$cur") )
            return 0
            ;;
        list)
            COMPREPLY=( $(compgen -W "--masked --overridden --orphaned" -- "$cur") )
            return 0
            ;;
        get)
            COMPREPLY=( $(compgen -W "--stdout -o --shellescaped" -- "$cur") )
            return 0
            ;;
        rm)
            COMPREPLY=( $(compgen -W "--ignore-missing" -- "$cur") )
            return 0
            ;;
        set)
            COMPREPLY=( $(compgen -W "--stdin -i --env -e --value -v" -- "$cur") )
            return 0
            ;;
        exec)
            COMPREPLY=( $(compgen -W "--pattern -p --pattern-exclude" -- "$cur") )
            return 0
            ;;
        export)
            COMPREPLY=( $(compgen -W "--pattern -p" -- "$cur") )
            return 0
            ;;
        status)
            COMPREPLY=( $(compgen -W "--quiet -q" -- "$cur") )
            return 0
            ;;
        mask|unmask|exists|save|load|unlock|passwd|lock|mv|cp|version)
            return 0
            ;;
    esac

    return 0
}

complete -F _secdat_complete secdat