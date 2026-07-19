_sippycup_campaign()
{
    local current previous command
    current="${COMP_WORDS[COMP_CWORD]}"
    previous="${COMP_WORDS[COMP_CWORD-1]}"
    command="${COMP_WORDS[1]:-}"

    case "${previous}" in
        plan|matrix|run|execute|--output|--events|--manifest|--manifest-output|--report-output|--markdown-output|--history)
            compopt -o filenames
            mapfile -t COMPREPLY < <(compgen -f -- "${current}")
            return
            ;;
        --runner|--secret-provider)
            mapfile -t COMPREPLY < <(compgen -c -- "${current}")
            return
            ;;
        --run-root)
            compopt -o dirnames
            mapfile -t COMPREPLY < <(compgen -d -- "${current}")
            return
            ;;
    esac

    if [[ "${COMP_CWORD}" -eq 1 ]]; then
        mapfile -t COMPREPLY < <(
            compgen -W "plan run execute matrix" -- "${current}"
        )
        return
    fi

    case "${command}" in
        plan)
            mapfile -t COMPREPLY < <(
                compgen -W "--resolve --max-calls --max-packets --max-bytes --max-duration-seconds --max-concurrent-calls --max-packets-per-second --max-calls-per-second --output --error-format" -- "${current}"
            )
            ;;
        matrix)
            mapfile -t COMPREPLY < <(
                compgen -W "--manifest-output --report-output --markdown-output --seed --max-cases --history --actions --max-actions --sequence-strength --error-format" -- "${current}"
            )
            ;;
        run)
            mapfile -t COMPREPLY < <(
                compgen -W "--manifest --run-root --interface --secret-env --secret-fd --secret-provider --error-format" -- "${current}"
            )
            ;;
        execute)
            mapfile -t COMPREPLY < <(
                compgen -W "--manifest --run-root --interface --secret-env --secret-fd --secret-provider --error-format" -- "${current}"
            )
            ;;
    esac
}

complete -F _sippycup_campaign campaign
