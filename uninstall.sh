#!/bin/bash
#
# uninstall.sh - OpenEFA Uninstaller
# Part of the OpenEFA project (https://openefa.com)
#
# Completely removes OpenEFA from the system
#

set -e
set -u

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common and rollback functions
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/rollback.sh"
source "${SCRIPT_DIR}/lib/postfix.sh"

#
# Main uninstall flow
#
main() {
    show_banner

    cat << EOFWARNING

${COLOR_RED}╔════════════════════════════════════════════════════════════════╗
║                    UNINSTALL OpenEFA                           ║
╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}

${COLOR_YELLOW}WARNING: This will completely remove OpenEFA from your system!${COLOR_RESET}

The following will be removed:
  • All OpenEFA services
  • Database: spacy_email_db  
  • Database user: spacy_user
  • Installation directory: /opt/spacyserver
  • System user: spacy-filter
  • Postfix will be stopped (config backed up)

Postfix configuration will be backed up to /etc/postfix/backup_*

EOFWARNING

    echo ""
    
    if ! confirm "Are you ABSOLUTELY SURE you want to uninstall OpenEFA?"; then
        info "Uninstall cancelled"
        exit 0
    fi

    echo ""
    if ! confirm "This action cannot be undone. Continue?"; then
        info "Uninstall cancelled"
        exit 0
    fi

    # Check root
    require_root

    # Set default database variables
    DB_NAME="${DB_NAME:-spacy_email_db}"
    DB_USER="${DB_USER:-spacy_user}"

    # Initialize logging
    init_logging
    log_message "=== UNINSTALL STARTED ===" "INFO"

    section "Uninstalling OpenEFA"

    # Stop services
    info "Stopping OpenEFA services..."
    stop_all_services

    # Remove services
    info "Removing systemd services..."
    remove_services

    # Backup Postfix config before removal
    info "Backing up Postfix configuration..."
    backup_postfix_config

    # Stop Postfix
    info "Stopping Postfix..."
    systemctl stop postfix || true

    # Remove database
    if confirm "Remove database '${DB_NAME:-spacy_email_db}' and user '${DB_USER:-spacy_user}'?"; then
        remove_database
    else
        warn "Database preserved"
    fi

    # Remove files
    if confirm "Remove /opt/spacyserver directory?"; then
        info "Removing installation files..."
        rm -rf /opt/spacyserver
        success "Files removed"
    else
        warn "Files kept at /opt/spacyserver"
    fi

    # Remove spacy-filter user
    if confirm "Remove spacy-filter system user?"; then
        info "Removing spacy-filter user..."
        userdel -r spacy-filter 2>/dev/null || true
        success "User removed"
    fi

    # Remove logrotate config
    if [[ -f /etc/logrotate.d/openefa ]]; then
        rm -f /etc/logrotate.d/openefa
        debug "Removed logrotate config"
    fi

    # Cleanup
    cleanup_state

    cat << EOFSUCCESS

${COLOR_GREEN}╔════════════════════════════════════════════════════════════════╗
║                  UNINSTALL COMPLETE                            ║
╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}

OpenEFA has been removed from your system.

${COLOR_WHITE}What remains:${COLOR_RESET}
  • Postfix (stopped, config backed up to /etc/postfix/backup_*)
  • MariaDB server (can be removed with: apt remove mariadb-server)
  • Redis server (can be removed with: apt remove redis-server)
  • System packages (can be cleaned with: apt autoremove)

${COLOR_WHITE}Log file preserved:${COLOR_RESET} ${LOG_FILE}

${COLOR_CYAN}Thank you for trying OpenEFA!${COLOR_RESET}

EOFSUCCESS

    exit 0
}

# Run main
main "$@"
