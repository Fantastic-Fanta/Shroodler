# Bash completion for the `shroodler` CLI.
#
# Install (pick one):
#   source packages/cli/completions/shroodler.bash
#   cp packages/cli/completions/shroodler.bash /etc/bash_completion.d/shroodler
#   # or, with bash-completion's user dir:
#   cp packages/cli/completions/shroodler.bash ~/.local/share/bash-completion/completions/shroodler
#
# This is a static, hand-maintained script (no argcomplete/click dependency)
# -- if you add or rename a flag in shroodler/cli.py, update this file too.
# Only flag *names* are completed; most flags take a free-form value
# (URLs, file paths, etc.) which bash's default filename completion covers.

_shroodler_commands="crawl diff report baseline expected ingest-sessions payload authz-diff proxy history trend ask mcp-server audit-verify compare-engines sla suppress version"

_shroodler_flags_for() {
    case "$1" in
        crawl)
            echo "--profile --mode --depth --max-pages --max-time --output --format --ignore-robots --no-sitemap --allow-external --check-rate-limit --no-check-rate-limit --check-idor --header --user-agent --cookie --cookie-jar --storage-state --login-recipe --proxy --seed --seed-from --cookies-from"
            ;;
        diff)
            echo "--pages-only --gate --suppressions --format --output"
            ;;
        report)
            echo "--format --output --suppressions"
            ;;
        baseline|expected)
            echo "--output --name --suppressions"
            ;;
        ingest-sessions)
            echo "--target --output --allow-external"
            ;;
        payload)
            echo "--output --pack --allow-external --oob-host --require-policy --policy-file --audit-log"
            ;;
        authz-diff)
            echo "--output --cookie --header --no-anon-check --allow-external --require-policy --policy-file --audit-log"
            ;;
        history-record)
            echo "--label --history-dir"
            ;;
        history-list)
            echo "--target --format --history-dir"
            ;;
        trend)
            echo "--format --output --history-dir --gate-on-severity-increase"
            ;;
        ask)
            echo "--since"
            ;;
        mcp-server)
            echo ""
            ;;
        audit-verify)
            echo ""
            ;;
        compare-engines)
            echo "--output"
            ;;
        sla-apply)
            echo "--output --history-dir --owners --gate"
            ;;
        suppress-expiring)
            echo "--days --suppressions --format --output --gate"
            ;;
        *)
            echo ""
            ;;
    esac
}

_shroodler_complete() {
    local cur prev words cword
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Find the subcommand (first non-flag word after "shroodler"), if any.
    local subcmd=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            -*) ;;
            *) subcmd="${COMP_WORDS[i]}"; break ;;
        esac
    done

    if [[ -z "$subcmd" ]]; then
        COMPREPLY=($(compgen -W "$_shroodler_commands -V --version --debug" -- "$cur"))
        return
    fi

    # `history` has its own nested subcommand (record|list) before any flags.
    if [[ "$subcmd" == "history" ]]; then
        local hsub=""
        for ((i = 1; i < COMP_CWORD; i++)); do
            case "${COMP_WORDS[i]}" in
                record|list) hsub="${COMP_WORDS[i]}"; break ;;
            esac
        done
        if [[ -z "$hsub" ]]; then
            COMPREPLY=($(compgen -W "record list" -- "$cur"))
            return
        fi
        subcmd="history-$hsub"
    fi

    # `sla` has its own nested subcommand (apply) before any flags.
    if [[ "$subcmd" == "sla" ]]; then
        local ssub=""
        for ((i = 1; i < COMP_CWORD; i++)); do
            case "${COMP_WORDS[i]}" in
                apply) ssub="${COMP_WORDS[i]}"; break ;;
            esac
        done
        if [[ -z "$ssub" ]]; then
            COMPREPLY=($(compgen -W "apply" -- "$cur"))
            return
        fi
        subcmd="sla-$ssub"
    fi

    # `suppress` has its own nested subcommand (expiring) before any flags.
    if [[ "$subcmd" == "suppress" ]]; then
        local xsub=""
        for ((i = 1; i < COMP_CWORD; i++)); do
            case "${COMP_WORDS[i]}" in
                expiring) xsub="${COMP_WORDS[i]}"; break ;;
            esac
        done
        if [[ -z "$xsub" ]]; then
            COMPREPLY=($(compgen -W "expiring" -- "$cur"))
            return
        fi
        subcmd="suppress-$xsub"
    fi

    case "$prev" in
        --format)
            case "$subcmd" in
                crawl) COMPREPLY=($(compgen -W "json html csv sarif junit" -- "$cur")) ;;
                diff) COMPREPLY=($(compgen -W "text junit sarif" -- "$cur")) ;;
                report) COMPREPLY=($(compgen -W "html csv json sarif junit md markdown" -- "$cur")) ;;
                history-list|trend) COMPREPLY=($(compgen -W "text json" -- "$cur")) ;;
                suppress-expiring) COMPREPLY=($(compgen -W "text json github-pr-body" -- "$cur")) ;;
            esac
            return
            ;;
        --mode)
            COMPREPLY=($(compgen -W "static headless" -- "$cur"))
            return
            ;;
        --profile)
            COMPREPLY=($(compgen -W "safe balanced aggressive" -- "$cur"))
            return
            ;;
        --output|-o|--suppressions|--pack|--cookie-jar|--storage-state|--login-recipe|--seed-from|--cookies-from|--history-dir|--owners|--policy-file|--audit-log)
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$(_shroodler_flags_for "$subcmd")" -- "$cur"))
        return
    fi

    COMPREPLY=($(compgen -f -- "$cur"))
}

complete -F _shroodler_complete shroodler
