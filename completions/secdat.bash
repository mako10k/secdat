_secdat_complete()
{
    local cur bin output mode candidates offset

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    bin="${SECDAT_COMPLETION_BIN:-${COMP_WORDS[0]}}"

    if ! output="$(${bin} __completion --bash "${COMP_WORDS[@]:1}" 2>/dev/null)"; then
        return 0
    fi

    mode="${output%%$'\n'*}"
    mode="${mode#__secdat_completion_mode=}"
    output="${output#*$'\n'}"

    if [[ $output == __secdat_completion_offset=* ]]; then
        offset="${output%%$'\n'*}"
        offset="${offset#__secdat_completion_offset=}"
        output="${output#*$'\n'}"
    else
        offset=""
    fi

    candidates="$output"

    case "$mode" in
        dir)
            COMPREPLY=( $(compgen -d -- "$cur") )
            return 0
            ;;
        file)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        none)
            return 0
            ;;
        command)
            COMPREPLY=( $(compgen -c -- "$cur") )
            return 0
            ;;
        delegate)
            if [[ -n $offset ]] && declare -F _comp_command_offset &>/dev/null; then
                _comp_command_offset "$offset"
            elif [[ -n $offset && $COMP_CWORD -eq $offset ]]; then
                COMPREPLY=( $(compgen -c -- "$cur") )
            fi
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )

    return 0
}

complete -F _secdat_complete secdat