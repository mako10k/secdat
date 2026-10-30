# R: Adapt contextual CLI candidates to Bash completion without executing candidate text.
# Remove shell quoting literally, without expanding variables or commands.
# Output uses dynamically scoped variables owned by _secdat_complete.
_secdat_unquote_word()
{
    local input=$1 char next index state="" result="" escape digit limit code
    local quote_rules=${2-shell}
    for ((index=0; index<${#input}; index++)); do
        char=${input:index:1}
        next=${input:index+1:1}
        case $state in
            "'")
                if [[ $char == "'" ]]; then state=""; else result+=$char; fi ;;
            ansi)
                if [[ $char == "'" ]]; then
                    state=""
                elif [[ $char == '\' && $next ]]; then
                    escape="\\$next"
                    index=$((index+1))
                    limit=0
                    case $next in
                        [0-7]) limit=2 ;;
                        x) limit=2 ;;
                        u) limit=4 ;;
                        U) limit=8 ;;
                    esac
                    while (( limit > 0 && index+1 < ${#input} )); do
                        digit=${input:index+1:1}
                        if [[ $next == [0-7] ]]; then
                            [[ $digit == [0-7] ]] || break
                        else
                            [[ $digit == [0123456789abcdefABCDEF] ]] || break
                        fi
                        escape+=$digit
                        index=$((index+1))
                        limit=$((limit-1))
                    done
                    case $next in
                        "'"|'"'|'?') char=$next ;;
                        c)
                            if (( index+1 < ${#input} )) && [[ ${input:index+1:1} != "'" ]]; then
                                index=$((index+1))
                                char=${input:index:1}
                                printf -v code '%d' "'$char"
                                if [[ $char == '?' ]]; then code=127; else code=$((code & 31)); fi
                                printf -v escape '\\%03o' "$code"
                                printf -v char '%b' "$escape"
                            else
                                char='\c'
                            fi ;;
                        x|u|U)
                            if (( ${#escape} > 2 )); then
                                printf -v char '%b' "$escape"
                            else
                                char=$escape
                            fi ;;
                        *) printf -v char '%b' "$escape" ;;
                    esac
                    result+=$char
                else
                    result+=$char
                fi ;;
            '"')
                if [[ $char == '"' ]]; then
                    state=""
                elif [[ $char == '\' && ( $next == '$' || $next == '`' || $next == '"' || $next == '\' ) ]]; then
                    result+=$next
                    index=$((index+1))
                else
                    result+=$char
                fi ;;
            *)
                if [[ $quote_rules == shell && $char == '$' && $next == "'" ]]; then
                    state=ansi
                    index=$((index+1))
                elif [[ $char == "'" || $char == '"' ]]; then
                    state=$char
                elif [[ $char == '\' && $next ]]; then
                    result+=$next
                    index=$((index+1))
                else
                    result+=$char
                fi ;;
        esac
    done
    unquoted=$result
    quote_state=$state
}

_secdat_complete()
{
    local cur bin output mode candidates offset candidate existing duplicate
    local encoded escapes pair quoted replacement_prefix="" raw_cur
    local unquoted quote_state insertion_quote="" changed=0 raw_word closed_quote=0
    local i j line part cword=$COMP_CWORD
    local -a words=("${COMP_WORDS[@]:0:COMP_CWORD+1}")

    # Rejoin Readline's =/: breaks only where the original line has no space.
    # The normal bash-completion helper also trims a word at the cursor.
    if [[ -n ${COMP_LINE-} && -n ${COMP_POINT+x} ]] && declare -F _get_comp_words_by_ref &>/dev/null; then
        _get_comp_words_by_ref -n '=:' cur words cword
        words=("${words[@]:0:cword+1}")
        words[cword]=$cur
    elif [[ -n ${COMP_LINE-} ]]; then
        line=${COMP_LINE:0:${COMP_POINT:-${#COMP_LINE}}}
        words=()
        for ((i=0, j=0; i<=COMP_CWORD; i++, j++)); do
            part=${COMP_WORDS[i]}
            while [[ $i -gt 0 && $part && ! ${part//[=:]/} ]]; do
                if [[ $line != [[:blank:]]* && $j -gt 1 ]]; then
                    j=$((j-1))
                fi
                words[j]=${words[j]-}$part
                line=${line#*"$part"}
                if [[ $line == [[:blank:]]* ]]; then
                    j=$((j+1))
                fi
                if (( i < COMP_CWORD )); then
                    i=$((i+1))
                    part=${COMP_WORDS[i]}
                else
                    break 2
                fi
            done
            if (( i == COMP_CWORD )); then
                part=${line#"${line%%[![:blank:]]*}"}
            fi
            words[j]=${words[j]-}$part
            line=${line#*"$part"}
        done
        cword=$((${#words[@]}-1))
    fi

    COMPREPLY=()
    # Bash passes Readline's actual replacement span as the second argument.
    # It can be empty after a closed ANSI-C quote containing an escaped quote.
    raw_cur="${2-${COMP_WORDS[COMP_CWORD]}}"
    cur="${words[cword]}"
    if [[ $raw_cur && $cur == *"$raw_cur" ]]; then
        replacement_prefix=${cur:0:${#cur}-${#raw_cur}}
    elif [[ ! $raw_cur ]]; then
        replacement_prefix=$cur
    fi
    if [[ -n ${COMP_LINE-} ]]; then
        _secdat_unquote_word "$replacement_prefix"
        replacement_prefix=$unquoted
        raw_word=${words[cword]}
        for i in "${!words[@]}"; do
            _secdat_unquote_word "${words[i]}"
            words[i]=$unquoted
        done
        insertion_quote=$quote_state
        if [[ ! $insertion_quote ]]; then
            # Readline's quote scanner does not interpret ANSI-C escaped quotes.
            # It can still append a quote after the shell token is fully closed.
            _secdat_unquote_word "$raw_word" readline
            insertion_quote=$quote_state
            [[ ! $insertion_quote ]] || closed_quote=1
        fi
    fi
    cur=${words[cword]}
    if (( cword != COMP_CWORD )); then
        changed=1
    else
        for i in "${!words[@]}"; do
            [[ ${words[i]} == "${COMP_WORDS[i]}" ]] || changed=1
        done
    fi
    bin="${SECDAT_COMPLETION_BIN:-${COMP_WORDS[0]}}"

    if ! output="$(${bin} __completion --bash "${words[@]:1}" 2>/dev/null)"; then
        return 0
    fi

    # Reconstruction is for store operands. Keep the existing protocol and
    # original word indices for KEYREF, file and delegated command completion.
    if (( changed )) && [[ $output != __secdat_completion_mode=store$'\n'* && $output != __secdat_completion_mode=store ]]; then
        cur=$raw_cur
        cword=$COMP_CWORD
        if ! output="$("$bin" __completion --bash "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null)"; then
            return 0
        fi
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

    if [[ $mode == store ]]; then
        # Filename mode would stat candidates and append / for real directories.
        compopt -o noquote +o filenames 2>/dev/null || :
        while IFS= read -r encoded; do
            [[ $encoded && $encoded != *[!0123456789abcdefABCDEF]* && $((${#encoded}%2)) -eq 0 ]] || continue
            escapes=""
            for ((i=0; i<${#encoded}; i+=2)); do
                pair=${encoded:i:2}
                [[ $pair != 00 ]] || { escapes=""; break; }
                escapes+="\\x$pair"
            done
            [[ $escapes ]] || continue
            printf -v candidate '%b' "$escapes"
            [[ $candidate == "$cur"* ]] || continue
            candidate=${candidate:${#replacement_prefix}}
            # An already complete fixed prefix needs no insertion. In particular,
            # do not ask Readline to synthesize quotes for an empty suffix.
            [[ $candidate || ! $replacement_prefix ]] || continue
            case $insertion_quote in
                ansi)
                    quoted=${candidate//\\/\\\\}
                    quoted=${quoted//\'/\\\'}
                    quoted="'$quoted"
                    ;;
                "'")
                    quoted=${candidate//\'/\'\\\'\'}
                    quoted="'$quoted"
                    ;;
                '"')
                    quoted=${candidate//\\/\\\\}
                    quoted=${quoted//\$/\\\$}
                    quoted=${quoted//\`/\\\`}
                    quoted=${quoted//\"/\\\"}
                    quoted="\"$quoted"
                    ;;
                *) printf -v quoted '%q' "$candidate" ;;
            esac
            # Readline strips one matching opening quote from the reply. When
            # the shell token is already closed, retain another for the suffix.
            if (( closed_quote )); then
                quoted=$insertion_quote$quoted
            fi
            COMPREPLY+=("$quoted")
        done <<<"$output"
        return 0
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
            elif [[ -n $offset && $cword -eq $offset ]]; then
                COMPREPLY=( $(compgen -c -- "$cur") )
            fi
            return 0
            ;;
    esac

    while IFS= read -r candidate; do
        if [[ -n $candidate && $candidate == "$cur"* ]]; then
            COMPREPLY+=("$candidate")
        fi
    done <<<"$candidates"
    if [[ $cur == */* ]]; then
        while IFS= read -r candidate; do
            candidate="${candidate%/}/"
            duplicate=0
            for existing in "${COMPREPLY[@]}"; do
                if [[ $existing == "$candidate" ]]; then
                    duplicate=1
                    break
                fi
            done
            if (( ! duplicate )); then
                COMPREPLY+=("$candidate")
            fi
        done < <(compgen -d -- "$cur")
    fi

    return 0
}

complete -F _secdat_complete secdat
