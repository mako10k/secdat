_secdat_complete()
{
    local cur bin output mode candidates

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    bin="${SECDAT_COMPLETION_BIN:-${COMP_WORDS[0]}}"

    if ! output="$(${bin} __completion --bash "${COMP_WORDS[@]:1}" 2>/dev/null)"; then
        return 0
    fi

    mode="${output%%$'\n'*}"
    mode="${mode#__secdat_completion_mode=}"
    candidates="${output#*$'\n'}"

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
    esac

    COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )

    return 0
}

complete -F _secdat_complete secdat