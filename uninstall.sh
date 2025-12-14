#!/bin/bash
#
# uninstall.sh - OpenEFA Uninstaller
# Part of the OpenEFA project (https://openefa.com)
#
# Completely removes OpenEFA from the system
# This script is self-contained and can be run from /root/
#

set -e
set -u

# Logging
LOG_FILE="/var/log/openefa_uninstall.log"

#
# Helper functions
#
info() {
    echo "[INFO] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "${LOG_FILE}" 2>/dev/null || true
}

success() {
    echo "[✓] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "${LOG_FILE}" 2>/dev/null || true
}

warn() {
    echo "[WARN] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "${LOG_FILE}" 2>/dev/null || true
}

error() {
    echo "[ERROR] $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "${LOG_FILE}" 2>/dev/null || true
}

confirm() {
    read -p "$1 (yes/no): " -r
    [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Load existing configuration if available
load_config() {
    if [[ -f /etc/spacy-server/.env ]]; then
        source /etc/spacy-server/.env 2>/dev/null || true
    fi
    # Set defaults if not loaded
    DB_NAME="${DB_NAME:-spacy_email_db}"
    DB_USER="${DB_USER:-spacy_user}"
}

#
# Stop all services
#
stop_all_services() {
    local services=(
        "spacy-db-processor"
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "${service}" 2>/dev/null; then
            systemctl stop "${service}" 2>/dev/null || warn "Failed to stop ${service}"
        fi
    done
    success "Services stopped"
}

#
# Remove systemd service files
#
remove_services() {
    local services=(
        "spacy-db-processor"
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        if [[ -f "/etc/systemd/system/${service}.service" ]]; then
            systemctl disable "${service}" 2>/dev/null || true
            rm -f "/etc/systemd/system/${service}.service"
        fi
    done
    systemctl daemon-reload
    success "Services removed"
}

#
# Backup Postfix configuration
#
backup_postfix_config() {
    # Use /var/backups to avoid nested backups inside /etc/postfix
    local backup_dir="/var/backups/openefa/postfix_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${backup_dir}"

    if [[ -d /etc/postfix ]]; then
        # Copy config files, excluding any old backup directories
        find /etc/postfix -maxdepth 1 -type f -exec cp {} "${backup_dir}/" \; 2>/dev/null || true
        success "Postfix config backed up to ${backup_dir}"
    fi
}

#
# Remove database
#
remove_database() {
    local db_name="${DB_NAME:-spacy_email_db}"
    local db_user="${DB_USER:-spacy_user}"

    info "Removing database ${db_name}..."
    mysql -e "DROP DATABASE IF EXISTS ${db_name};" 2>/dev/null || warn "Failed to drop database"
    mysql -e "DROP USER IF EXISTS '${db_user}'@'localhost';" 2>/dev/null || warn "Failed to drop database user"
    success "Database removed"
}

#
# Main uninstall flow
#
main() {
    clear 2>/dev/null || true

    # Load configuration to get actual database name
    load_config

    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    UNINSTALL OpenEFA                           ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "WARNING: This will completely remove OpenEFA from your system!"
    echo ""
    echo "The following will be removed:"
    echo "  • All OpenEFA services"
    echo "  • Database: ${DB_NAME}"
    echo "  • Database user: ${DB_USER}"
    echo "  • Installation directory: /opt/spacyserver"
    echo "  • System user: spacy-filter"
    echo "  • Postfix will be stopped (config backed up)"
    echo ""
    echo "Postfix configuration will be backed up to /var/backups/openefa/"
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

    # Initialize logging
    echo "=== OpenEFA Uninstall Started: $(date) ===" > "${LOG_FILE}"

    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                  Uninstalling OpenEFA                          ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""

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
    systemctl stop postfix 2>/dev/null || true

    # Remove database
    if confirm "Remove database '${DB_NAME}' and user '${DB_USER}'?"; then
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
        info "Removed logrotate config"
    fi

    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                  UNINSTALL COMPLETE                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "OpenEFA has been removed from your system."
    echo ""
    echo "What remains:"
    echo "  • Postfix (stopped, config backed up to /var/backups/openefa/)"
    echo "  • MariaDB server (can be removed with: apt remove mariadb-server)"
    echo "  • Redis server (can be removed with: apt remove redis-server)"
    echo "  • System packages (can be cleaned with: apt autoremove)"
    echo ""
    echo "Log file preserved: ${LOG_FILE}"
    echo ""
    echo "Thank you for trying OpenEFA!"
    echo ""

    exit 0
}

# Run main
main "$@"
