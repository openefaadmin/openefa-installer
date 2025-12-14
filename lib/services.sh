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

    # Create log directory for SpacyWeb
    info "Creating SpacyWeb log directory..."
    mkdir -p /var/log/spacyweb
    chown spacy-filter:spacy-filter /var/log/spacyweb
    chmod 755 /var/log/spacyweb

    install_service_file "spacyweb" || return 1
    systemctl daemon-reload

    sleep 2

    enable_and_start_service "spacyweb" || return 1

    save_state "spacyweb_service_configured"
    return 0
}

#
# Install and start API services
# Legacy EFA v5 API services - no longer needed
#
setup_api_services() {
    info "API services setup skipped (legacy services removed)"
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

fix_config_permissions() {
    info "Fixing all config file permissions..."

    local install_dir="/opt/spacyserver"

    # Ensure config directory exists with correct permissions
    mkdir -p "${install_dir}/config"
    chown spacy-filter:spacy-filter "${install_dir}/config"
    chmod 750 "${install_dir}/config"

    # Fix all JSON config files in config directory
    find "${install_dir}/config" -maxdepth 1 -type f -name "*.json" -exec chown spacy-filter:spacy-filter {} \;
    find "${install_dir}/config" -maxdepth 1 -type f -name "*.json" -exec chmod 640 {} \;
    debug "Fixed permissions for all JSON config files"

    # Fix .my.cnf (database credentials) - actual file in /etc/spacy-server
    if [[ -f "/etc/spacy-server/.my.cnf" ]]; then
        chown spacy-filter:spacy-filter "/etc/spacy-server/.my.cnf"
        chmod 600 "/etc/spacy-server/.my.cnf"
        debug "Set permissions: /etc/spacy-server/.my.cnf (600, spacy-filter:spacy-filter)"
    fi

    # Fix .env (environment variables) - actual file in /etc/spacy-server
    if [[ -f "/etc/spacy-server/.env" ]]; then
        chown spacy-filter:spacy-filter "/etc/spacy-server/.env"
        chmod 600 "/etc/spacy-server/.env"
        debug "Set permissions: /etc/spacy-server/.env (600, spacy-filter:spacy-filter)"
    fi

    # Symlinks in /opt/spacyserver/config/ will follow to actual files
    # No need to set permissions on symlinks themselves

    # Fix modules.ini
    if [[ -f "${install_dir}/config/modules.ini" ]]; then
        chown spacy-filter:spacy-filter "${install_dir}/config/modules.ini"
        chmod 600 "${install_dir}/config/modules.ini"
        debug "Set permissions: modules.ini (600, spacy-filter:spacy-filter)"
    fi

    # Fix .app_config.ini
    if [[ -f "${install_dir}/config/.app_config.ini" ]]; then
        chown spacy-filter:spacy-filter "${install_dir}/config/.app_config.ini"
        chmod 640 "${install_dir}/config/.app_config.ini"
        debug "Set permissions: .app_config.ini (640, spacy-filter:spacy-filter)"
    fi

    success "Config file permissions fixed"
    return 0
}

#
# Setup Apache reverse proxy with SSL for SpacyWeb
#
setup_apache_ssl() {
    section "Setting Up Apache Reverse Proxy with SSL"

    local apache_template="${SCRIPT_DIR}/templates/apache/spacyweb.conf"
    local apache_site="/etc/apache2/sites-available/spacyweb.conf"
    local hostname="${INSTALL_HOSTNAME:-$(hostname -f)}"

    # Enable required Apache modules
    info "Enabling Apache modules..."
    a2enmod ssl proxy proxy_http headers rewrite >/dev/null 2>&1 || {
        warn "Some Apache modules may already be enabled"
    }

    echo ""
    info "SSL Certificate Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Choose how to configure SSL for the SpacyWeb dashboard:"
    echo ""
    echo "  1) Let's Encrypt (Recommended for public servers)"
    echo "     - Free, auto-renewing certificates"
    echo "     - Requires domain pointing to this server"
    echo ""
    echo "  2) Self-signed certificate"
    echo "     - Quick setup, works immediately"
    echo "     - Browser will show security warning"
    echo ""
    echo "  3) Custom certificate"
    echo "     - Use your own certificate files"
    echo "     - For purchased/enterprise certs"
    echo ""
    echo "  4) Skip SSL setup"
    echo "     - Configure manually later"
    echo ""

    local ssl_choice
    read -p "Select option [1-4]: " ssl_choice

    local ssl_cert_file=""
    local ssl_key_file=""

    case "${ssl_choice}" in
        1)
            # Let's Encrypt
            info "Setting up Let's Encrypt certificate..."

            local le_domain
            read -p "Enter domain name (e.g., mail.example.com): " le_domain

            if [[ -z "${le_domain}" ]]; then
                warn "No domain provided, skipping Let's Encrypt"
                return 0
            fi

            local le_email
            read -p "Enter email for renewal notices (recommended): " le_email

            # Ensure Apache is running for the challenge
            info "Starting Apache for Let's Encrypt challenge..."
            systemctl enable apache2 >/dev/null 2>&1
            systemctl start apache2 >/dev/null 2>&1

            # Build certbot command with or without email
            local certbot_cmd="certbot certonly --apache -d ${le_domain} --non-interactive --agree-tos"
            if [[ -n "${le_email}" ]]; then
                certbot_cmd="${certbot_cmd} --email ${le_email}"
            else
                certbot_cmd="${certbot_cmd} --register-unsafely-without-email"
                warn "No email provided - you won't receive renewal notices"
            fi

            # Run certbot
            info "Requesting certificate from Let's Encrypt..."
            if eval "${certbot_cmd}"; then
                ssl_cert_file="/etc/letsencrypt/live/${le_domain}/fullchain.pem"
                ssl_key_file="/etc/letsencrypt/live/${le_domain}/privkey.pem"
                hostname="${le_domain}"
                success "Let's Encrypt certificate obtained"
            else
                warn "Let's Encrypt failed - falling back to self-signed"
                # Generate self-signed as fallback
                mkdir -p /etc/ssl/spacyweb
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /etc/ssl/spacyweb/spacyweb.key \
                    -out /etc/ssl/spacyweb/spacyweb.crt \
                    -subj "/C=US/ST=State/L=City/O=OpenEFA/OU=SpacyWeb/CN=${le_domain}" \
                    >/dev/null 2>&1
                chmod 600 /etc/ssl/spacyweb/spacyweb.key
                chmod 644 /etc/ssl/spacyweb/spacyweb.crt
                ssl_cert_file="/etc/ssl/spacyweb/spacyweb.crt"
                ssl_key_file="/etc/ssl/spacyweb/spacyweb.key"
                hostname="${le_domain}"
                warn "Using self-signed certificate instead"
            fi
            ;;
        2)
            # Self-signed certificate
            info "Generating self-signed certificate..."

            mkdir -p /etc/ssl/spacyweb

            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/ssl/spacyweb/spacyweb.key \
                -out /etc/ssl/spacyweb/spacyweb.crt \
                -subj "/C=US/ST=State/L=City/O=OpenEFA/OU=SpacyWeb/CN=${hostname}" \
                >/dev/null 2>&1

            chmod 600 /etc/ssl/spacyweb/spacyweb.key
            chmod 644 /etc/ssl/spacyweb/spacyweb.crt

            ssl_cert_file="/etc/ssl/spacyweb/spacyweb.crt"
            ssl_key_file="/etc/ssl/spacyweb/spacyweb.key"
            success "Self-signed certificate generated"
            warn "Browsers will show a security warning with self-signed certs"
            ;;
        3)
            # Custom certificate
            echo ""
            read -p "Enter path to SSL certificate file: " ssl_cert_file
            read -p "Enter path to SSL private key file: " ssl_key_file

            if [[ ! -f "${ssl_cert_file}" ]] || [[ ! -f "${ssl_key_file}" ]]; then
                error "Certificate files not found"
                warn "Skipping SSL setup - configure manually"
                return 0
            fi
            success "Using custom certificate"
            ;;
        4|*)
            info "Setting up HTTP-only reverse proxy (no SSL)"

            # Create HTTP-only Apache config
            cat > "${apache_site}" << 'HTTPEOF'
<VirtualHost *:80>
    ServerName ${HOSTNAME}

    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Proxy to Gunicorn/SpacyWeb
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5500/
    ProxyPassReverse / http://127.0.0.1:5500/

    # Pass real client IP to backend
    RequestHeader set X-Forwarded-For "%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-Proto "http"
    RequestHeader set X-Forwarded-Host "%{HTTP_HOST}s"

    # Logging
    ErrorLog ${APACHE_LOG_DIR}/spacyweb-error.log
    CustomLog ${APACHE_LOG_DIR}/spacyweb-access.log combined
</VirtualHost>
HTTPEOF
            # Replace hostname placeholder
            sed -i "s/\${HOSTNAME}/${hostname}/g" "${apache_site}"

            # Enable modules and site
            a2enmod proxy proxy_http headers >/dev/null 2>&1
            a2dissite 000-default.conf >/dev/null 2>&1 || true
            a2ensite spacyweb.conf >/dev/null 2>&1

            # Restart Apache
            systemctl enable apache2 >/dev/null 2>&1
            systemctl restart apache2

            if systemctl is-active --quiet apache2; then
                success "Apache running with HTTP reverse proxy"
                warn "SSL not configured - access via http://${hostname}"
                info "To add SSL later, edit ${apache_site}"
            else
                error "Apache failed to start"
                systemctl status apache2 --no-pager
                return 1
            fi

            save_state "apache_ssl_configured"
            return 0
            ;;
    esac

    # Generate Apache config from template
    if [[ -f "${apache_template}" ]]; then
        sed -e "s|{{HOSTNAME}}|${hostname}|g" \
            -e "s|{{SSL_CERT_FILE}}|${ssl_cert_file}|g" \
            -e "s|{{SSL_KEY_FILE}}|${ssl_key_file}|g" \
            "${apache_template}" > "${apache_site}"

        success "Apache configuration created"
    else
        error "Apache template not found: ${apache_template}"
        return 1
    fi

    # Disable default site, enable spacyweb
    a2dissite 000-default.conf >/dev/null 2>&1 || true
    a2ensite spacyweb.conf >/dev/null 2>&1

    # Test Apache config
    if apache2ctl configtest >/dev/null 2>&1; then
        success "Apache configuration valid"
    else
        error "Apache configuration test failed"
        apache2ctl configtest
        return 1
    fi

    # Restart Apache
    systemctl enable apache2 >/dev/null 2>&1
    systemctl restart apache2

    if systemctl is-active --quiet apache2; then
        success "Apache running with SSL"
        echo ""
        info "SpacyWeb is now accessible at: https://${hostname}"
        echo ""
    else
        error "Apache failed to start"
        systemctl status apache2 --no-pager
        return 1
    fi

    save_state "apache_ssl_configured"
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
    setup_apache_ssl || warn "Apache SSL setup skipped or failed (non-fatal)"
    setup_api_services || return 1
    setup_logrotate || return 1
    setup_cleanup_cron || return 1
    fix_notification_permissions || return 1
    fix_config_permissions || return 1

    save_state "services_configured"
    success "All services configured and running"
    return 0
}

# Export functions
export -f install_service_file enable_and_start_service
export -f setup_db_processor_service setup_spacyweb_service setup_apache_ssl
export -f setup_api_services setup_logrotate setup_cleanup_cron fix_notification_permissions fix_config_permissions setup_services
