#!/bin/bash
# Security hardening functions for OpenEFA installer

# Install and configure fail2ban for brute force protection
install_fail2ban() {
    info "Installing fail2ban for brute force protection..."

    apt-get install -y fail2ban >/dev/null 2>&1 || {
        warn "Could not install fail2ban"
        return 1
    }

    # Create local jail configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban hosts for 1 hour
bantime = 3600
# Find failures within 10 minutes
findtime = 600
# Ban after 5 failures
maxretry = 5
# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[postfix]
enabled = true
port = smtp,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp,submission
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3
EOF

    # Create SpacyWeb filter for failed login attempts (matches Apache access log 401s)
    cat > /etc/fail2ban/filter.d/spacyweb.conf << 'EOF'
[Definition]
# Match 401 responses to /auth/login from Apache access log
failregex = ^<HOST> .* "POST /auth/login.*" 401 .*$
            ^<HOST> .* "POST /auth/login.*" 403 .*$
ignoreregex =
EOF

    # SpacyWeb jail - uses Apache access logs
    cat >> /etc/fail2ban/jail.local << 'EOF'

# SpacyWeb web interface protection via Apache logs
[spacyweb]
enabled = true
port = http,https
filter = spacyweb
logpath = /var/log/apache2/spacyweb-access.log
maxretry = 5
bantime = 3600
EOF

    # Enable and start fail2ban
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1

    if systemctl is-active --quiet fail2ban; then
        success "fail2ban installed and running"
        return 0
    else
        warn "fail2ban installed but not running"
        return 1
    fi
}

# Configure basic UFW firewall rules
configure_ufw() {
    info "Configuring UFW firewall..."

    # Check if ufw is installed
    if ! command -v ufw &>/dev/null; then
        apt-get install -y ufw >/dev/null 2>&1 || {
            warn "Could not install ufw"
            return 1
        }
    fi

    # Reset to defaults
    ufw --force reset >/dev/null 2>&1

    # Default policies
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1

    # Allow SSH
    ufw allow ssh >/dev/null 2>&1

    # Allow SMTP
    ufw allow 25/tcp >/dev/null 2>&1

    # Allow SpacyWeb (if user wants public access)
    # ufw allow 5500/tcp >/dev/null 2>&1

    # Allow from Tailscale network (100.64.0.0/10)
    ufw allow from 100.64.0.0/10 >/dev/null 2>&1

    # Enable UFW (non-interactive)
    echo "y" | ufw enable >/dev/null 2>&1

    if ufw status | grep -q "Status: active"; then
        success "UFW firewall configured and enabled"
        info "  - SSH (22): allowed"
        info "  - SMTP (25): allowed"
        info "  - Tailscale network: allowed"
        info "  - SpacyWeb (5500): Tailscale only (add 'ufw allow 5500/tcp' for public access)"
        return 0
    else
        warn "UFW configured but not enabled"
        return 1
    fi
}

# Set secure file permissions
secure_permissions() {
    info "Setting secure file permissions..."

    # Environment files - owner read only
    if [[ -f /etc/spacy-server/.env ]]; then
        chmod 600 /etc/spacy-server/.env
        chown spacy-filter:spacy-filter /etc/spacy-server/.env
    fi

    # SSL certificates if they exist
    if [[ -d /opt/spacyserver/web/certs ]]; then
        chmod 700 /opt/spacyserver/web/certs
        chmod 600 /opt/spacyserver/web/certs/*.pem 2>/dev/null
        chown -R spacy-filter:spacy-filter /opt/spacyserver/web/certs
    fi

    # Config directory
    if [[ -d /opt/spacyserver/config ]]; then
        chmod 750 /opt/spacyserver/config
        chmod 640 /opt/spacyserver/config/*.json 2>/dev/null
        chown -R spacy-filter:spacy-filter /opt/spacyserver/config
    fi

    success "File permissions secured"
}

# Main security hardening function
apply_security_hardening() {
    section "Security Hardening"

    # Always apply secure permissions
    secure_permissions

    # Install fail2ban (recommended)
    install_fail2ban

    # UFW is optional and may conflict with existing firewall rules
    # Only configure if explicitly requested or no firewall exists
    if [[ "${OPENEFA_CONFIGURE_UFW:-false}" == "true" ]]; then
        configure_ufw
    else
        info "Skipping UFW configuration (set OPENEFA_CONFIGURE_UFW=true to enable)"
        info "Note: UFW can conflict with Docker/Tailscale. Configure manually if needed."
    fi

    success "Security hardening complete"
}
