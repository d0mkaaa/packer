#!/bin/bash
# Packer bash completion script

_packer_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    local commands="install remove search info list update upgrade check clean repos transaction security fix doctor complete version versions benchmark"
    
    # Handle subcommands
    case "${COMP_WORDS[1]}" in
        install)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --no-deps --verify-signatures --skip-security-scan --interactive --preview" -- ${cur}) )
            else
                # Complete with available packages
                local packages=$(packer complete packages-available "${cur}" 2>/dev/null || echo "")
                COMPREPLY=( $(compgen -W "${packages}" -- ${cur}) )
            fi
            return 0
            ;;
        remove)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--force --cascade" -- ${cur}) )
            else
                # Complete with installed packages
                local packages=$(packer complete packages-installed "${cur}" 2>/dev/null || echo "")
                COMPREPLY=( $(compgen -W "${packages}" -- ${cur}) )
            fi
            return 0
            ;;
        info)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--files --deps --rdeps --security" -- ${cur}) )
            else
                # Complete with installed packages
                local packages=$(packer complete packages-installed "${cur}" 2>/dev/null || echo "")
                COMPREPLY=( $(compgen -W "${packages}" -- ${cur}) )
            fi
            return 0
            ;;
        upgrade)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--ignore --security-only" -- ${cur}) )
            else
                # Complete with upgradeable packages
                local packages=$(packer complete packages-upgradeable "${cur}" 2>/dev/null || echo "")
                COMPREPLY=( $(compgen -W "${packages}" -- ${cur}) )
            fi
            return 0
            ;;
        search)
            if [[ ${cur} == -* ]]; then
                COMPREPLY=( $(compgen -W "--exact --repo --version --sort --limit --installed --not-installed --detailed" -- ${cur}) )
            fi
            return 0
            ;;
        transaction)
            local transaction_commands="history rollback show"
            if [[ ${#COMP_WORDS[@]} -eq 3 ]]; then
                COMPREPLY=( $(compgen -W "${transaction_commands}" -- ${cur}) )
            elif [[ "${COMP_WORDS[2]}" == "rollback" || "${COMP_WORDS[2]}" == "show" ]]; then
                # Complete with transaction IDs
                local transactions=$(packer complete transaction-ids "${cur}" 2>/dev/null || echo "")
                COMPREPLY=( $(compgen -W "${transactions}" -- ${cur}) )
            fi
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _packer_completion packer

