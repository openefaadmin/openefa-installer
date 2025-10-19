#!/bin/bash
#
# modules.sh - OpenSpacy module installation
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Copy module files from installer to installation directory
#
copy_module_files() {
    info "Copying OpenSpacy module files..."

    local install_dir="/opt/spacyserver"
    local source_dir="${SCRIPT_DIR}/openefa-files"

    if [[ ! -d "${source_dir}" ]]; then
        error "Source files directory not found: ${source_dir}"
        return 1
    fi

    # Create directories
    create_directory "${install_dir}" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/modules" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/services" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/config" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/logs" "spacy-filter:spacy-filter" "755"
    create_directory "${install_dir}/web" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/api" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/scripts" "spacy-filter:spacy-filter" "750"
    create_directory "${install_dir}/tools" "spacy-filter:spacy-filter" "750"

    # Copy email_filter.py (main entry point)
    if [[ -f "${source_dir}/email_filter.py" ]]; then
        cp "${source_dir}/email_filter.py" "${install_dir}/"
        chown spacy-filter:spacy-filter "${install_dir}/email_filter.py"
        chmod 750 "${install_dir}/email_filter.py"
        debug "Copied: email_filter.py"
    fi

    # Copy VERSION file for system information display
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        cp "${SCRIPT_DIR}/VERSION" "${install_dir}/"
        chown spacy-filter:spacy-filter "${install_dir}/VERSION"
        chmod 644 "${install_dir}/VERSION"
        debug "Copied: VERSION"
    fi

    # Copy cleanup_expired_emails.py (email retention cleanup script)
    if [[ -f "${source_dir}/cleanup_expired_emails.py" ]]; then
        cp "${source_dir}/cleanup_expired_emails.py" "${install_dir}/"
        chown spacy-filter:spacy-filter "${install_dir}/cleanup_expired_emails.py"
        chmod 755 "${install_dir}/cleanup_expired_emails.py"
        debug "Copied: cleanup_expired_emails.py"
    fi

    # Copy modules directory
    if [[ -d "${source_dir}/modules" ]]; then
        cp -r "${source_dir}/modules/"* "${install_dir}/modules/"
        chown -R spacy-filter:spacy-filter "${install_dir}/modules"
        chmod -R 640 "${install_dir}/modules"/*.py
        debug "Copied: modules/*"
    fi

    # Copy services directory
    if [[ -d "${source_dir}/services" ]]; then
        cp -r "${source_dir}/services/"* "${install_dir}/services/"
        chown -R spacy-filter:spacy-filter "${install_dir}/services"
        chmod -R 640 "${install_dir}/services"/*.py
        debug "Copied: services/*"
    fi

    # Copy web directory
    if [[ -d "${source_dir}/web" ]]; then
        cp -r "${source_dir}/web/"* "${install_dir}/web/"
        chown -R spacy-filter:spacy-filter "${install_dir}/web"
        find "${install_dir}/web" -name "*.py" -exec chmod 640 {} \;
        debug "Copied: web/*"
    fi

    # Copy API directory
    if [[ -d "${source_dir}/api" ]]; then
        cp -r "${source_dir}/api/"* "${install_dir}/api/"
        chown -R spacy-filter:spacy-filter "${install_dir}/api"
        chmod -R 640 "${install_dir}/api"/*.py
        debug "Copied: api/*"
    fi

    # Copy scripts directory
    if [[ -d "${source_dir}/scripts" ]]; then
        cp -r "${source_dir}/scripts/"* "${install_dir}/scripts/"
        chown -R spacy-filter:spacy-filter "${install_dir}/scripts"
        chmod -R 750 "${install_dir}/scripts"/*.sh
        debug "Copied: scripts/*"
    fi

    # Copy tools directory
    if [[ -d "${source_dir}/tools" ]]; then
        cp -r "${source_dir}/tools/"* "${install_dir}/tools/"
        chown -R spacy-filter:spacy-filter "${install_dir}/tools"
        chmod -R 750 "${install_dir}/tools"/*.sh
        debug "Copied: tools/*"
    fi

    success "Module files copied"
    return 0
}

#
# Install module configuration files
#
install_module_configs() {
    info "Installing module configuration files..."

    local config_dir="/opt/spacyserver/config"
    local template_dir="${SCRIPT_DIR}/templates/config"

    # Copy JSON config templates
    for config_file in "${template_dir}"/*.json; do
        if [[ -f "${config_file}" ]]; then
            local filename=$(basename "${config_file}")
            cp "${config_file}" "${config_dir}/${filename}"
            chown spacy-filter:spacy-filter "${config_dir}/${filename}"
            chmod 640 "${config_dir}/${filename}"
            debug "Installed: ${filename}"
        fi
    done

    # Copy .app_config.ini (Flask secret key)
    if [[ -f "${template_dir}/.app_config.ini" ]]; then
        cp "${template_dir}/.app_config.ini" "${config_dir}/.app_config.ini"
        chown spacy-filter:spacy-filter "${config_dir}/.app_config.ini"
        chmod 640 "${config_dir}/.app_config.ini"
        debug "Installed: .app_config.ini"
    fi

    # Update quarantine_config.json with actual relay host
    if [[ -f "${config_dir}/quarantine_config.json" ]] && [[ -n "${RELAY_SERVER_IP:-}" ]]; then
        sed -i "s/YOUR_RELAY_HOST/${RELAY_SERVER_IP}/g" "${config_dir}/quarantine_config.json"
        debug "Updated quarantine_config.json with relay host: ${RELAY_SERVER_IP}"
    fi

    # Update authentication_config.json with actual values
    if [[ -f "${config_dir}/authentication_config.json" ]] && [[ -n "${RELAY_SERVER_IP:-}" ]]; then
        sed -i "s|YOUR_RELAY_SERVER|${RELAY_SERVER_IP}|g" "${config_dir}/authentication_config.json"
        # Calculate network from relay IP (e.g., 192.168.50.37 -> 192.168.50.0/24)
        local network_prefix=$(echo "${RELAY_SERVER_IP}" | cut -d. -f1-3)
        sed -i "s|YOUR_INTERNAL_NETWORK/24|${network_prefix}.0/24|g" "${config_dir}/authentication_config.json"
        debug "Updated authentication_config.json with relay: ${RELAY_SERVER_IP}, network: ${network_prefix}.0/24"
    fi

    success "Module configurations installed"
    return 0
}

#
# Update HOSTED_DOMAINS in SpacyWeb app.py
#
update_hosted_domains() {
    info "Configuring HOSTED_DOMAINS in SpacyWeb..."

    local app_file="/opt/spacyserver/web/app.py"

    if [[ ! -f "${app_file}" ]]; then
        warn "app.py not found, skipping HOSTED_DOMAINS update"
        return 0
    fi

    # Build Python list from domains array
    local domains_python="["
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        local first=true
        for domain in "${INSTALL_DOMAINS[@]}"; do
            if [[ "${first}" == "true" ]]; then
                domains_python+="'${domain}'"
                first=false
            else
                domains_python+=", '${domain}'"
            fi
        done
    else
        domains_python+="'${INSTALL_DOMAIN}'"
    fi
    domains_python+="]"

    # Update HOSTED_DOMAINS in app.py (handle multi-line format)
    if grep -q "^HOSTED_DOMAINS = \[" "${app_file}"; then
        # Find the line number of HOSTED_DOMAINS = [
        local start_line=$(grep -n "^HOSTED_DOMAINS = \[" "${app_file}" | cut -d: -f1)
        # Find the closing ] (next line that starts with ])
        local end_line=$(tail -n +${start_line} "${app_file}" | grep -n "^\]" | head -1 | cut -d: -f1)
        end_line=$((start_line + end_line - 1))

        # Delete the old HOSTED_DOMAINS block
        sed -i "${start_line},${end_line}d" "${app_file}"

        # Insert new HOSTED_DOMAINS on single line
        sed -i "${start_line}i\\HOSTED_DOMAINS = ${domains_python}" "${app_file}"

        local domain_count=1
        if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
            domain_count=${#INSTALL_DOMAINS[@]}
        fi
        success "HOSTED_DOMAINS updated with ${domain_count} domain(s)"
    else
        warn "HOSTED_DOMAINS not found in app.py, may need manual configuration"
    fi

    return 0
}

#
# Configure modules based on selected tier
#
configure_module_tier() {
    section "Configuring Module Tier ${MODULE_TIER}"

    local module_config="/opt/spacyserver/config/module_config.json"

    case "${MODULE_TIER}" in
        1)
            info "Tier 1: Core modules only"
            # Enable: auth, blocking, spam_scoring, rbl
            ;;
        2)
            info "Tier 2: Standard modules (Recommended)"
            # Enable: Tier 1 + BEC, typosquatting, DNS, obfuscation, marketing
            ;;
        3)
            info "Tier 3: Advanced modules (Full Stack)"
            # Enable: All modules including NER, thread awareness, learning
            ;;
    esac

    success "Module tier ${MODULE_TIER} configured"
    save_state "module_tier_configured"
    return 0
}

#
# Create email_filter_config.json with user's domains
#
create_email_filter_config() {
    info "Creating email_filter_config.json with configured domains..."

    local config_file="/opt/spacyserver/config/email_filter_config.json"
    local config_dir="/opt/spacyserver/config"

    # Build domain list for JSON
    local domains_json=""
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        domains_json=$(printf '"%s",' "${INSTALL_DOMAINS[@]}")
        domains_json=${domains_json%,}  # Remove trailing comma
    else
        domains_json="\"${INSTALL_DOMAIN}\""
    fi

    # Create config file
    cat > "${config_file}" <<EOF
{
    "processed_domains": [${domains_json}],
    "enable_debug_logging": ${ENABLE_DEBUG_LOGGING:-0},
    "servers": {
        "mailguard_host": "${RELAY_SERVER_IP}",
        "mailguard_port": ${RELAY_SERVER_PORT:-25}
    }
}
EOF

    chown spacy-filter:spacy-filter "${config_file}"
    chmod 640 "${config_file}"

    local domain_count=1
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        domain_count=${#INSTALL_DOMAINS[@]}
    fi

    success "Email filter config created with ${domain_count} domain(s)"
    return 0
}

#
# Set up module logging
#
configure_module_logging() {
    info "Configuring module logging..."

    local log_dir="/opt/spacyserver/logs"

    # Create log files
    touch "${log_dir}/email_filter_error.log"
    touch "${log_dir}/email_filter_debug.log"
    touch "${log_dir}/db_processor.log"

    chown -R spacy-filter:spacy-filter "${log_dir}"
    chmod 644 "${log_dir}"/*.log

    success "Module logging configured"
    return 0
}

#
# Install HTML Attachment Analyzer Module
#
install_html_attachment_analyzer() {
    info "Installing HTML Attachment Analyzer module..."

    local install_dir="/opt/spacyserver"
    local source_dir="${SCRIPT_DIR}/openefa-files"

    if [[ -f "${source_dir}/modules/html_attachment_analyzer.py" ]]; then
        cp "${source_dir}/modules/html_attachment_analyzer.py" \
           "${install_dir}/modules/"
        chown spacy-filter:spacy-filter "${install_dir}/modules/html_attachment_analyzer.py"
        chmod 644 "${install_dir}/modules/html_attachment_analyzer.py"
        success "HTML Attachment Analyzer module installed"
        debug "Module provides: credential theft detection, hidden iframe detection, brand impersonation"
    else
        warn "HTML Attachment Analyzer module not found in installer files"
    fi

    return 0
}

#
# Copy uninstall script to /root/ for future use
#
install_uninstall_script() {
    info "Installing uninstall script to /root/..."

    local uninstall_source="${SCRIPT_DIR}/uninstall.sh"
    local uninstall_dest="/root/openefa-uninstall.sh"

    if [[ -f "${uninstall_source}" ]]; then
        cp "${uninstall_source}" "${uninstall_dest}"
        chmod 700 "${uninstall_dest}"
        chown root:root "${uninstall_dest}"
        success "Uninstall script installed to ${uninstall_dest}"
        debug "To uninstall OpenEFA: sudo /root/openefa-uninstall.sh"
    else
        warn "Uninstall script not found in installer (non-fatal)"
    fi

    return 0
}

#
# Run all module installation steps
#
install_modules() {
    if is_step_completed "modules_installed"; then
        info "Modules already installed, skipping..."
        return 0
    fi

    section "Installing OpenSpacy Modules"

    copy_module_files || return 1
    install_module_configs || return 1
    create_email_filter_config || return 1
    update_hosted_domains || return 1
    configure_module_tier || return 1
    configure_module_logging || return 1
    install_html_attachment_analyzer || return 1
    install_uninstall_script || return 1

    save_state "modules_installed"
    success "Module installation complete"
    return 0
}

# Export functions
export -f copy_module_files install_module_configs create_email_filter_config update_hosted_domains
export -f configure_module_tier configure_module_logging install_html_attachment_analyzer
export -f install_uninstall_script install_modules
