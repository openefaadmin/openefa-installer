#!/bin/bash
#
# rollback.sh - Rollback functions for failed OpenEFA installation
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Stop all OpenEFA services
#
stop_all_services() {
    info "Stopping OpenEFA services..."

    local services=(
        "spacy-db-processor"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "${service}"; then
            systemctl stop "${service}" 2>/dev/null
            debug "Stopped: ${service}"
        fi
    done

    success "Services stopped"
}

#
# Remove OpenEFA services
#
remove_services() {
    info "Removing OpenEFA services..."

    local services=(
        "spacy-db-processor"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        if [[ -f "/etc/systemd/system/${service}.service" ]]; then
            systemctl disable "${service}" 2>/dev/null
            rm -f "/etc/systemd/system/${service}.service"
            debug "Removed: ${service}.service"
        fi
    done

    systemctl daemon-reload
    success "Services removed"
}

#
# Remove database and user
#
remove_database() {
    info "Removing database and user..."

    local db_name="${DB_NAME:-spacy_email_db}"
    local db_user="${DB_USER:-spacy_user}"

    mysql -u root << EOSQL 2>/dev/null
DROP DATABASE IF EXISTS ${db_name};
DROP USER IF EXISTS '${db_user}'@'localhost';
FLUSH PRIVILEGES;
EOSQL
    success "Database removed"
}

#
# Remove installed files
#
remove_files() {
    info "Removing installed files..."

    if confirm "Remove /opt/spacyserver directory?"; then
        rm -rf /opt/spacyserver
        success "Files removed"
    else
        warn "Files kept at /opt/spacyserver"
    fi
}

#
# Restore Postfix configuration
#
restore_postfix() {
    info "Restoring Postfix configuration..."

    # Find most recent backup
    local backup_dir=$(ls -dt /etc/postfix/backup_* 2>/dev/null | head -1)

    if [[ -d "${backup_dir}" ]]; then
        cp "${backup_dir}/main.cf" /etc/postfix/main.cf 2>/dev/null
        cp "${backup_dir}/master.cf" /etc/postfix/master.cf 2>/dev/null
        systemctl reload postfix
        success "Postfix configuration restored from: ${backup_dir}"
    else
        warn "No Postfix backup found"
    fi
}

#
# Remove installed packages (optional, careful!)
#
remove_packages() {
    warn "Package removal not recommended (may affect other services)"
    
    if ! confirm "Remove installed packages? (NOT RECOMMENDED)"; then
        info "Skipping package removal"
        return 0
    fi

    info "Removing packages..."

    local packages=(
        "python3-venv"
        "redis-server"
    )

    apt-get remove --purge -y "${packages[@]}" 2>/dev/null

    warn "MariaDB and Postfix left installed (manual removal required)"
}

#
# Full rollback
#
perform_full_rollback() {
    section "Rolling Back Installation"

    error "Installation failed. Initiating rollback..."

    stop_all_services
    remove_services
    remove_database
    restore_postfix
    remove_files
    remove_packages

    # Cleanup state file
    cleanup_state

    warn "Rollback complete. System restored to pre-installation state."
    warn "Log file preserved: ${LOG_FILE}"

    return 0
}

#
# Partial rollback based on installation state
#
perform_partial_rollback() {
    local failed_step="$1"

    warn "Installation failed at step: ${failed_step}"
    warn "Performing partial rollback..."

    # Check what was installed
    if is_step_completed "services_configured"; then
        stop_all_services
        remove_services
    fi

    if is_step_completed "postfix_configured"; then
        restore_postfix
    fi

    if is_step_completed "database_created"; then
        if confirm "Remove partially created database?"; then
            remove_database
        fi
    fi

    cleanup_state
    
    error "Partial rollback complete. Check logs: ${LOG_FILE}"
    return 0
}

# Export functions
export -f stop_all_services remove_services remove_database remove_files
export -f restore_postfix remove_packages perform_full_rollback
export -f perform_partial_rollback
