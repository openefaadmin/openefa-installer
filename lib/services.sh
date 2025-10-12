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

    save_state "services_configured"
    success "All services configured and running"
    return 0
}

# Export functions
export -f install_service_file enable_and_start_service
export -f setup_db_processor_service setup_spacyweb_service
export -f setup_api_services setup_logrotate setup_services
