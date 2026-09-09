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

_shroodler_commands="crawl diff report baseline expected ingest-sessions ingest-har tokens cadence triage payload nuclei-ingest slither-ingest authz-diff peer-write session-export js-routes paced-fetch proxy history trend ask mcp-server audit-verify compare-engines ticket sla suppress reverify gen-regression-test attack-path self-scan program agent discover engagement-history engagement-diff version"

_shroodler_flags_for() {
    case "$1" in
        crawl)
            echo "--profile --mode --depth --max-pages --max-time --output --format --ignore-robots --no-sitemap --allow-external --check-rate-limit --no-check-rate-limit --check-idor --header --user-agent --cookie --cookie-jar --storage-state --login-recipe --reauth-max-retries --program --proxy --seed --spec --seed-from --from-capture --cookies-from --gql-schema --gql-wordlist --plugin --exclude-path"
            ;;
        diff)
            echo "--pages-only --gate --suppressions --format --output --source-root"
            ;;
        report)
            echo "--format --output --suppressions --merge-sarif"
            ;;
        baseline|expected)
            echo "--output --name --suppressions"
            ;;
        ingest-sessions)
            echo "--target --output --allow-external"
            ;;
        ingest-har)
            echo "--target --output --allow-external"
            ;;
        tokens)
            echo "--output"
            ;;
        cadence)
            echo "--tier --url --format --output"
            ;;
        triage)
            echo "--discover --no-active --allow-external --concurrency --rate --timeout --proxy --user-agent --header --output --format --hosts-out"
            ;;
        payload)
            echo "--output --pack --plugin --allow-external --oob-host --require-policy --policy-file --audit-log --adaptive --no-csrf"
            ;;
        nuclei-ingest)
            echo "--output"
            ;;
        slither-ingest)
            echo "--target --output"
            ;;
        authz-diff)
            echo "--output --cookie --header --no-anon-check --allow-external --require-policy --policy-file --audit-log --higher-priv-marker --lower-priv-marker --require-identity-confirmation --gql-schema --gql-wordlist --program"
            ;;
        peer-write)
            echo "--output --target --from-sessions --only-id --owner-cookie --peer-cookie --owner-cookies-from --peer-cookies-from --header --rate --nonsense-id --user-agent --user-agent-suffix --allow-external --require-policy --policy-file --audit-log --csrf-from --no-csrf --require-confirm --allow-unconfirmed --program --from-program"
            ;;
        session-export)
            echo "--from --cdp --origin --cookie --output --allow-external"
            ;;
        js-routes)
            echo "--output"
            ;;
        paced-fetch)
            echo "--url --urls-file --output --method --cookie --header --rate --user-agent --user-agent-suffix --allow-external --require-policy --policy-file --audit-log"
            ;;
        history-record)
            echo "--label --history-dir"
            ;;
        history-list)
            echo "--target --format --history-dir"
            ;;
        trend)
            echo "--format --output --history-dir --suppressions --gate-on-severity-increase --gate-on-waf-coverage-drop --waf-drop-threshold --gate-even-if-page-count-mismatch"
            ;;
        ask)
            echo "--since"
            ;;
        mcp-server)
            echo "--list-tools"
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
        ticket-file|ticket-sync)
            echo "--baseline --state --owners --suppressions --repo --apply --output"
            ;;
        suppress-expiring)
            echo "--days --suppressions --format --output --gate"
            ;;
        suppress)
            echo "--program --id --url --reason"
            ;;
        reverify)
            echo "--mode --allow-external --no-payloads --output --require-policy --policy-file --audit-log"
            ;;
        gen-regression-test)
            echo "--mode --allow-external --no-payloads --output --force"
            ;;
        attack-path)
            echo "--format --output"
            ;;
        self-scan)
            echo "--format --output"
            ;;
        program-init)
            echo "--scope-file"
            ;;
        program-status)
            echo ""
            ;;
        program-merge)
            echo ""
            ;;
        program-add-session)
            echo "--label --expires"
            ;;
        agent)
            echo "--program --target --max-iterations --max-pages-per-crawl --login-recipe --higher-priv-jar --lower-priv-jar --owner-cookie --peer-cookie --dry-run --llm-triage --run-discovery --write-authz-spec --ignore-robots --run-probes --no-openapi --reprobe --run-diff --llm-business-logic --chain-spec"
            ;;
        engagement-history)
            echo "--program"
            ;;
        engagement-diff)
            echo "--program"
            ;;
        discover)
            echo "--program --target --max-subdomains --probe-workers --skip-crtsh --skip-js-surface --dry-run"
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

    # `program` has nested subcommands (init|status|merge|add-session).
    if [[ "$subcmd" == "program" ]]; then
        local psub=""
        for ((i = 1; i < COMP_CWORD; i++)); do
            case "${COMP_WORDS[i]}" in
                init|status|merge|add-session) psub="${COMP_WORDS[i]}"; break ;;
            esac
        done
        if [[ -z "$psub" ]]; then
            COMPREPLY=($(compgen -W "init status merge add-session" -- "$cur"))
            return
        fi
        subcmd="program-$psub"
    fi
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

    # `ticket` has its own nested subcommand (file|sync) before any flags.
    if [[ "$subcmd" == "ticket" ]]; then
        local tsub=""
        for ((i = 1; i < COMP_CWORD; i++)); do
            case "${COMP_WORDS[i]}" in
                file|sync) tsub="${COMP_WORDS[i]}"; break ;;
            esac
        done
        if [[ -z "$tsub" ]]; then
            COMPREPLY=($(compgen -W "file sync" -- "$cur"))
            return
        fi
        subcmd="ticket-$tsub"
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
                diff) COMPREPLY=($(compgen -W "text junit sarif github-annotations" -- "$cur")) ;;
                report) COMPREPLY=($(compgen -W "html csv json sarif junit md markdown" -- "$cur")) ;;
                history-list) COMPREPLY=($(compgen -W "text json" -- "$cur")) ;;
                cadence) COMPREPLY=($(compgen -W "text json" -- "$cur")) ;;
                triage) COMPREPLY=($(compgen -W "text json hosts" -- "$cur")) ;;
                trend) COMPREPLY=($(compgen -W "text json" -- "$cur")) ;;
                suppress-expiring) COMPREPLY=($(compgen -W "text json github-pr-body" -- "$cur")) ;;
                attack-path) COMPREPLY=($(compgen -W "json markdown" -- "$cur")) ;;
                self-scan) COMPREPLY=($(compgen -W "html csv sarif junit markdown" -- "$cur")) ;;
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
        --output|-o|--suppressions|--pack|--cookie-jar|--storage-state|--login-recipe|--seed-from|--from-capture|--cookies-from|--history-dir|--owners|--policy-file|--audit-log|--source-root|--hosts-out|--baseline|--state|--spec|--gql-schema|--gql-wordlist|--merge-sarif|--scope-file)
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
