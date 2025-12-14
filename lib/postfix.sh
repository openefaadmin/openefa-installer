#!/bin/bash
#
# postfix.sh - Postfix configuration for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Backup existing Postfix configuration
#
backup_postfix_config() {
    info "Backing up existing Postfix configuration..."

    local backup_dir="/etc/postfix/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${backup_dir}"

    cp -p /etc/postfix/main.cf "${backup_dir}/" 2>/dev/null
    cp -p /etc/postfix/master.cf "${backup_dir}/" 2>/dev/null
    cp -p /etc/postfix/transport "${backup_dir}/" 2>/dev/null || true
    cp -p /etc/postfix/virtual "${backup_dir}/" 2>/dev/null || true

    success "Postfix config backed up to: ${backup_dir}"
    save_state "postfix_backed_up"
    return 0
}

#
# Configure main.cf
#
configure_main_cf() {
    info "Configuring Postfix main.cf..."

    local main_cf="/etc/postfix/main.cf"
    backup_file "${main_cf}"

    # Use template
    local template="${SCRIPT_DIR}/templates/postfix/main.cf"
    if [[ ! -f "${template}" ]]; then
        error "Template not found: ${template}"
        return 1
    fi

    # Replace variables in template
    sed -e "s/{{INSTALL_DOMAIN}}/${INSTALL_DOMAIN}/g" \
        -e "s/{{HOSTNAME}}/$(hostname -f)/g" \
        "${template}" > "${main_cf}"

    success "main.cf configured"
    return 0
}

#
# Configure master.cf for email filtering
#
configure_master_cf() {
    info "Configuring Postfix master.cf..."

    local master_cf="/etc/postfix/master.cf"
    backup_file "${master_cf}"

    # Use template
    local template="${SCRIPT_DIR}/templates/postfix/master.cf"
    if [[ ! -f "${template}" ]]; then
        error "Template not found: ${template}"
        return 1
    fi

    cp "${template}" "${master_cf}"

    success "master.cf configured"
    return 0
}

#
# Configure transport maps for relay
#
configure_transport_maps() {
    info "Configuring transport maps..."

    local transport_file="/etc/postfix/transport"

    # Start transport file with header
    cat > "${transport_file}" << EOTRANSPORT
# OpenEFA Transport Map
# Routes configured domains to relay server

EOTRANSPORT

    # Add transport entry for each domain
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        for domain in "${INSTALL_DOMAINS[@]}"; do
            echo "${domain}    smtp:[${RELAY_SERVER_IP}]" >> "${transport_file}"
        done
    else
        # Fallback to single domain if array not set
        echo "${INSTALL_DOMAIN}    smtp:[${RELAY_SERVER_IP}]" >> "${transport_file}"
    fi

    # Hash the transport map
    if run_cmd "postmap ${transport_file}" "Failed to hash transport map"; then
        # Postfix requires root ownership for config files
        # spacy-filter uses sudo postmap to update transport when needed
        chown root:root "${transport_file}" "${transport_file}.db"
        chmod 644 "${transport_file}" "${transport_file}.db"

        local domain_count=1
        if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
            domain_count=${#INSTALL_DOMAINS[@]}
        fi
        success "Transport map configured for ${domain_count} domain(s)"
        return 0
    else
        return 1
    fi
}

#
# Configure virtual domains
#
configure_virtual_domains() {
    info "Configuring virtual domains..."

    local virtual_file="/etc/postfix/virtual"

    # Start virtual file with header
    cat > "${virtual_file}" << EOVIRTUAL
# OpenEFA Virtual Domains
# Domain aliases and catch-all configuration

EOVIRTUAL

    # Add virtual domain entry for each domain
    if [[ -n "${INSTALL_DOMAINS[@]}" ]] && [[ ${#INSTALL_DOMAINS[@]} -gt 0 ]]; then
        for domain in "${INSTALL_DOMAINS[@]}"; do
            echo "# Accept all mail for ${domain}" >> "${virtual_file}"
            echo "@${domain}  @${domain}" >> "${virtual_file}"
            echo "" >> "${virtual_file}"
        done
    else
        # Fallback to single domain if array not set
        echo "# Accept all mail for ${INSTALL_DOMAIN}" >> "${virtual_file}"
        echo "@${INSTALL_DOMAIN}  @${INSTALL_DOMAIN}" >> "${virtual_file}"
    fi

    # Hash the virtual map
    if run_cmd "postmap ${virtual_file}" "Failed to hash virtual map"; then
        success "Virtual domains configured"
        return 0
    else
        return 1
    fi
}

#
# Configure Postfix to use email filter
#
configure_email_filter() {
    info "Configuring email filter integration..."

    # Ensure email_filter.py has correct permissions (if it exists - may not be deployed yet)
    if [[ -f /opt/spacyserver/email_filter.py ]]; then
        chown spacy-filter:spacy-filter /opt/spacyserver/email_filter.py
        chmod 755 /opt/spacyserver/email_filter.py

        # Make sure Python shebang is correct
        if ! grep -q "^#!/opt/spacyserver/venv/bin/python3" /opt/spacyserver/email_filter.py; then
            warn "email_filter.py may need shebang update"
        fi
    fi

    success "Email filter integration configured"
    return 0
}

#
# Configure Postfix aliases
#
configure_aliases() {
    info "Configuring mail aliases..."

    # Add spacy-filter user to aliases if not present
    if ! grep -q "^spacy-filter:" /etc/aliases; then
        echo "spacy-filter: root" >> /etc/aliases
        run_cmd "newaliases" "Failed to update aliases"
    fi

    success "Aliases configured"
    return 0
}

#
# Set Postfix parameters via postconf
#
set_postfix_parameters() {
    info "Setting Postfix parameters..."

    # Key parameters
    postconf -e "myhostname=$(hostname -f)"
    postconf -e "mydestination=localhost, \$myhostname, localhost.\$mydomain"
    postconf -e "mynetworks=127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"

    # Set relay_domains (supports multiple domains)
    if [[ -n "${INSTALL_DOMAINS_LIST:-}" ]]; then
        postconf -e "relay_domains=${INSTALL_DOMAINS_LIST}"
    else
        postconf -e "relay_domains=${INSTALL_DOMAIN}"
    fi

    postconf -e "transport_maps=hash:/etc/postfix/transport"
    postconf -e "virtual_alias_maps=hash:/etc/postfix/virtual"
    postconf -e "smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination"
    postconf -e "smtpd_helo_required=yes"
    postconf -e "smtpd_delay_reject=yes"
    postconf -e "disable_vrfy_command=yes"
    postconf -e "smtpd_banner=\$myhostname ESMTP"
    postconf -e "message_size_limit=52428800"
    postconf -e "mailbox_size_limit=0"

    success "Postfix parameters set"
    return 0
}

#
# Reload Postfix configuration
#
reload_postfix() {
    info "Reloading Postfix configuration..."

    if systemctl is-active --quiet postfix; then
        if run_cmd "systemctl reload postfix" "Failed to reload Postfix"; then
            success "Postfix reloaded"
            return 0
        else
            return 1
        fi
    else
        info "Postfix not running, will start later"
        return 0
    fi
}

#
# Start and enable Postfix service
#
start_postfix() {
    info "Starting Postfix service..."

    if run_cmd "systemctl enable postfix" "Failed to enable Postfix"; then
        success "Postfix enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start postfix" "Failed to start Postfix"; then
        success "Postfix started"
        save_state "postfix_started"
        return 0
    else
        return 1
    fi
}

#
# Run all Postfix configuration steps
#
configure_postfix() {
    if is_step_completed "postfix_configured"; then
        info "Postfix already configured, skipping..."
        return 0
    fi

    section "Postfix Configuration"

    backup_postfix_config || return 1
    configure_main_cf || return 1
    configure_master_cf || return 1
    configure_transport_maps || return 1
    configure_virtual_domains || return 1
    set_postfix_parameters || return 1
    configure_email_filter || return 1
    configure_aliases || return 1
    start_postfix || return 1

    # Configure sudoers for Postfix management
    info "Configuring sudoers for Postfix management..."
    cat > /etc/sudoers.d/spacy-postfix << 'EOSUDO'
# Allow spacy-filter to manage Postfix configuration
# Required for domain management via web interface
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postconf -e *
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
EOSUDO
    chmod 440 /etc/sudoers.d/spacy-postfix
    if visudo -c -f /etc/sudoers.d/spacy-postfix >> "${LOG_FILE}" 2>&1; then
        success "Postfix sudoers configured"
    else
        error "Failed to configure sudoers"
        return 1
    fi

    save_state "postfix_configured"
    success "Postfix configuration complete"
    return 0
}

# Export functions
export -f backup_postfix_config configure_main_cf configure_master_cf
export -f configure_transport_maps configure_virtual_domains configure_email_filter
export -f configure_aliases set_postfix_parameters reload_postfix start_postfix
export -f configure_postfix
