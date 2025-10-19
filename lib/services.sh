#!/bin/bash
#
# services.sh - Systemd service configuration for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Install systemd service file
# Args: $1=service_name
#
install_service_file() {
    local service_name="$1"
    local template="${SCRIPT_DIR}/templates/systemd/${service_name}.service"
    local service_file="/etc/systemd/system/${service_name}.service"

    if [[ ! -f "${template}" ]]; then
        error "Service template not found: ${template}"
        return 1
    fi

    info "Installing ${service_name}.service..."

    cp "${template}" "${service_file}"
    chmod 644 "${service_file}"

    success "${service_name}.service installed"
    return 0
}

#
# Enable and start a systemd service
# Args: $1=service_name
#
enable_and_start_service() {
    local service_name="$1"

    info "Enabling ${service_name}..."
    if run_cmd "systemctl enable ${service_name}" "Failed to enable ${service_name}"; then
        success "${service_name} enabled"
    else
        return 1
    fi

    info "Starting ${service_name}..."
    if run_cmd "systemctl start ${service_name}" "Failed to start ${service_name}"; then
        success "${service_name} started"
    else
        return 1
    fi

    # Verify service is running
    if systemctl is-active --quiet "${service_name}"; then
        success "${service_name} is active"
        return 0
    else
        error "${service_name} failed to start"
        systemctl status "${service_name}" --no-pager
        return 1
    fi
}

#
# Install and start database processor service
#
setup_db_processor_service() {
    section "Setting Up Database Processor Service"

    install_service_file "spacy-db-processor" || return 1
    systemctl daemon-reload

    # Give it a moment before starting
    sleep 2

    enable_and_start_service "spacy-db-processor" || return 1

    save_state "db_processor_service_configured"
    return 0
}

#
# Install and start SpacyWeb service
#
setup_spacyweb_service() {
    section "Setting Up SpacyWeb Service"

    install_service_file "spacyweb" || return 1
    systemctl daemon-reload

    sleep 2

    enable_and_start_service "spacyweb" || return 1

    save_state "spacyweb_service_configured"
    return 0
}

#
# Install and start API services
#
setup_api_services() {
    section "Setting Up API Services"

    local api_services=(
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
    )

    for service in "${api_services[@]}"; do
        install_service_file "${service}" || return 1
    done

    systemctl daemon-reload
    sleep 2

    for service in "${api_services[@]}"; do
        enable_and_start_service "${service}" || return 1
    done

    save_state "api_services_configured"
    return 0
}

#
# Configure logrotate for OpenEFA logs
#
setup_logrotate() {
    info "Configuring log rotation..."

    local logrotate_template="${SCRIPT_DIR}/templates/logrotate/openefa"
    local logrotate_file="/etc/logrotate.d/openefa"

    if [[ -f "${logrotate_template}" ]]; then
        cp "${logrotate_template}" "${logrotate_file}"
        chmod 644 "${logrotate_file}"
        success "Log rotation configured"
    else
        warn "Logrotate template not found (non-fatal)"
    fi

    return 0
}

#
# Configure cron job for email cleanup
#
setup_cleanup_cron() {
    info "Configuring email cleanup cron job..."

    # Check if cleanup script exists
    if [[ ! -f "/opt/spacyserver/cleanup_expired_emails.py" ]]; then
        warn "cleanup_expired_emails.py not found, skipping cron setup"
        return 0
    fi

    # Create cleanup log file
    touch /opt/spacyserver/logs/cleanup.log
    chown spacy-filter:spacy-filter /opt/spacyserver/logs/cleanup.log
    chmod 644 /opt/spacyserver/logs/cleanup.log

    # Add cron job for spacy-filter user (runs daily at 2 AM)
    local cron_entry="0 2 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py >> /opt/spacyserver/logs/cleanup.log 2>&1"

    # Get existing crontab, add new entry if not already present
    (crontab -u spacy-filter -l 2>/dev/null || true; echo "${cron_entry}") | \
        grep -v "cleanup_expired_emails.py" | \
        { cat; echo "${cron_entry}"; } | \
        crontab -u spacy-filter -

    success "Email cleanup cron job configured (daily at 2 AM)"
    return 0
}

#
# Fix notification file permissions (CRITICAL for v1.5.3+ SMS system)
#
fix_notification_permissions() {
    info "Setting notification file permissions..."

    local install_dir="/opt/spacyserver"

    # Create logs directory if it doesn't exist
    mkdir -p "${install_dir}/logs"

    # Create notifications.log with correct permissions
    touch "${install_dir}/logs/notifications.log"
    chown spacy-filter:spacy-filter "${install_dir}/logs/notifications.log"
    chmod 664 "${install_dir}/logs/notifications.log"
    debug "Set permissions: notifications.log (664, spacy-filter:spacy-filter)"

    # Fix notification_config.json permissions
    if [[ -f "${install_dir}/config/notification_config.json" ]]; then
        chown spacy-filter:spacy-filter "${install_dir}/config/notification_config.json"
        chmod 640 "${install_dir}/config/notification_config.json"
        debug "Set permissions: notification_config.json (640, spacy-filter:spacy-filter)"
    fi

    success "Notification permissions configured"
    return 0
}

#
# Run all service setup steps
#
setup_services() {
    if is_step_completed "services_configured"; then
        info "Services already configured, skipping..."
        return 0
    fi

    setup_db_processor_service || return 1
    setup_spacyweb_service || return 1
    setup_api_services || return 1
    setup_logrotate || return 1
    setup_cleanup_cron || return 1
    fix_notification_permissions || return 1

    save_state "services_configured"
    success "All services configured and running"
    return 0
}

# Export functions
export -f install_service_file enable_and_start_service
export -f setup_db_processor_service setup_spacyweb_service
export -f setup_api_services setup_logrotate setup_cleanup_cron fix_notification_permissions setup_services
