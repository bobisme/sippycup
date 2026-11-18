_sippycup_public_commands() {
    "${COMP_WORDS[0]}" commands --format json 2>/dev/null \
        | python3 -c '
import json
import sys
for item in json.load(sys.stdin)["commands"]:
    print(item["name"])
' 2>/dev/null
}

_sippycup() {
    local current="${COMP_WORDS[COMP_CWORD]}"
    local command_name=""
    local word
    local index

    for ((index = 1; index < COMP_CWORD; index++)); do
        word="${COMP_WORDS[index]}"
        case "${word}" in
            --admin|--isolated|--practice)
                ;;
            --)
                return 0
                ;;
            -*)
                ;;
            *)
                command_name="${word}"
                break
                ;;
        esac
    done

    if [[ -z "${command_name}" ]]; then
        COMPREPLY=(
            $(compgen -W \
                "--admin --isolated --practice --help --version $(_sippycup_public_commands)" \
                -- "${current}")
        )
        return 0
    fi

    case "${command_name}" in
        help)
            COMPREPLY=($(compgen -W "$(_sippycup_public_commands)" -- "${current}"))
            ;;
        commands)
            COMPREPLY=($(compgen -W "--format json" -- "${current}"))
            ;;
        doctor)
            COMPREPLY=($(compgen -W "--host --format json human" -- "${current}"))
            ;;
        capture)
            COMPREPLY=(
                $(compgen -W \
                    "--target --network --interface --output --dry-run --help" \
                    -- "${current}")
            )
            ;;
        preflight)
            COMPREPLY=($(compgen -W "--dry-run --help udp tcp tls" -- "${current}"))
            ;;
        call)
            COMPREPLY=(
                $(compgen -W \
                    "--dial --duration --answer-timeout --play --codec --username --realm --no-register --secret-env --secret-file --run-root --engagement --no-media-required --format --dry-run --help" \
                    -- "${current}")
            )
            ;;
        practice-target)
            COMPREPLY=(
                $(compgen -W \
                    "build up down status info help --address --format" \
                    -- "${current}")
            )
            ;;
        go)
            COMPREPLY=(
                $(compgen -d -W "--plain --line --format --no-runtime --image --help" -- "${current}")
            )
            ;;
        *)
            COMPREPLY=($(compgen -W "--help" -- "${current}"))
            ;;
    esac
}

complete -F _sippycup sippycup ./bin/sippycup
