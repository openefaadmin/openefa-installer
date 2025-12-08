#!/bin/bash
#
# validation.sh - Post-installation validation for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Validate database connection
#
validate_database() {
    info "Validating database connection..."

    if mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" -e "SELECT 1;" &> /dev/null; then
        success "Database connection: OK"
        return 0
    else
        error "Database connection: FAILED"
        return 1
    fi
}

#
# Validate database tables
#
validate_database_tables() {
    info "Validating database schema..."

    local required_tables=(
        "users"
        "client_domains"
        "blocking_rules"
        "emails"
        "trusted_senders"
    )

    local missing_tables=()

    for table in "${required_tables[@]}"; do
        if ! mysql -u "${DB_USER}" -p"${DB_PASSWORD}" "${DB_NAME}" -e "DESCRIBE ${table};" &> /dev/null; then
            missing_tables+=("${table}")
        fi
    done

    if [[ ${#missing_tables[@]} -gt 0 ]]; then
        error "Missing tables: ${missing_tables[*]}"
        return 1
    fi

    success "Database schema: OK"
    return 0
}

#
# Validate Redis connection
#
validate_redis() {
    info "Validating Redis connection..."

    if redis-cli ping &> /dev/null; then
        success "Redis connection: OK"
        return 0
    else
        error "Redis connection: FAILED"
        return 1
    fi
}

#
# Validate Postfix is running
#
validate_postfix() {
    info "Validating Postfix service..."

    if systemctl is-active --quiet postfix; then
        success "Postfix: Running"
        return 0
    else
        error "Postfix: NOT RUNNING"
        return 1
    fi
}

#
# Validate OpenEFA services are running
#
validate_services() {
    info "Validating OpenEFA services..."

    local services=(
        "spacy-db-processor"
        "spacyweb"
    )

    local failed_services=()

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "${service}"; then
            success "${service}: Running"
        else
            error "${service}: NOT RUNNING"
            failed_services+=("${service}")
        fi
    done

    if [[ ${#failed_services[@]} -gt 0 ]]; then
        error "Failed services: ${failed_services[*]}"
        return 1
    fi

    return 0
}

#
# Validate Python environment
#
validate_python_env() {
    info "Validating Python environment..."

    if [[ -f "/opt/spacyserver/venv/bin/python3" ]]; then
        local python_version=$(/opt/spacyserver/venv/bin/python3 --version 2>&1)
        success "Python: ${python_version}"
        return 0
    else
        error "Python virtual environment not found"
        return 1
    fi
}

#
# Validate email filter script
#
validate_email_filter() {
    info "Validating email filter script..."

    if [[ -f "/opt/spacyserver/email_filter.py" ]]; then
        if [[ -x "/opt/spacyserver/email_filter.py" ]]; then
            success "Email filter: Installed and executable"
            return 0
        else
            error "Email filter: Not executable"
            return 1
        fi
    else
        error "Email filter: Not found"
        return 1
    fi
}

#
# Validate file permissions
#
validate_permissions() {
    info "Validating file permissions..."

    local paths=(
        "/opt/spacyserver"
        "/opt/spacyserver/config"
        "/opt/spacyserver/logs"
    )

    for path in "${paths[@]}"; do
        if [[ -d "${path}" ]]; then
            local owner=$(stat -c '%U:%G' "${path}")
            if [[ "${owner}" == "spacy-filter:spacy-filter" ]]; then
                debug "${path}: ${owner} (OK)"
            else
                warn "${path}: ${owner} (expected spacy-filter:spacy-filter)"
            fi
        fi
    done

    success "Permissions validated"
    return 0
}

#
# Validate SpacyWeb is accessible
#
validate_spacyweb() {
    info "Validating SpacyWeb accessibility..."

    sleep 3  # Give service time to fully start

    if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:5500 | grep -q "200\|302\|401"; then
        success "SpacyWeb: Accessible on port 5500"
        return 0
    else
        warn "SpacyWeb: May not be accessible yet (check firewall/SSL)"
        return 0  # Non-fatal
    fi
}

#
# Validate API endpoints
# Legacy EFA v5 API services removed - no longer needed
#
validate_apis() {
    info "API validation skipped (legacy services removed)"
    return 0
}

#
# Test email processing (optional)
#
test_email_processing() {
    if ! confirm "Send a test email through the system?"; then
        info "Skipping email test"
        return 0
    fi

    info "Sending test email..."

    # Use admin email from installation
    local test_recipient="${ADMIN_EMAIL}"
    local test_sender="openefa-test@${INSTALL_DOMAIN}"

    # Create a test email that will trigger spam detection for demo purposes
    local test_subject="OpenEFA Installation Test - System Operational"
    local test_body="Congratulations! Your OpenEFA installation is complete and operational.

This test email confirms that:
✓ Postfix is accepting and processing emails
✓ OpenEFA email filter is analyzing messages
✓ SpacyWeb dashboard is ready for use
✓ Database integration is functioning

You should see this email in your quarantine dashboard at:
https://$(hostname):5500

Installation completed at: $(date)
Installed domain: ${INSTALL_DOMAIN}
Admin email: ${ADMIN_EMAIL}

This is an automated test message from the OpenEFA installer.
For more information, visit: https://openefa.com"

    if command -v swaks &> /dev/null; then
        # Send test email using valid domain
        # Use --helo with FQDN to satisfy Postfix HELO requirements (reject_non_fqdn_helo_hostname)
        local helo_fqdn="$(hostname).${INSTALL_DOMAIN}"

        swaks --to "${test_recipient}" \
              --from "${test_sender}" \
              --server localhost \
              --helo "${helo_fqdn}" \
              --header "Subject: ${test_subject}" \
              --body "${test_body}" \
              2>&1 | tee /tmp/swaks_test.log

        if [[ $? -eq 0 ]]; then
            success "Test email sent successfully to ${test_recipient}"
            info "This email should appear in the SpacyWeb quarantine dashboard"
            info "Login at: https://$(hostname):5500"
            info "Check logs: /var/log/mail.log and /opt/spacyserver/logs/"
            return 0
        else
            warn "Test email failed - check /tmp/swaks_test.log for details"
            return 0  # Non-fatal
        fi
    else
        warn "swaks not available for email testing"
        info "Install swaks: apt-get install swaks"
        return 0
    fi
}

#
# Run all validation checks
#
run_all_validations() {
    section "Post-Installation Validation"

    local failed_validations=0

    # Critical validations (must pass)
    local critical_checks=(
        "validate_database"
        "validate_database_tables"
        "validate_redis"
        "validate_postfix"
        "validate_services"
        "validate_python_env"
        "validate_email_filter"
    )

    for check in "${critical_checks[@]}"; do
        if ! ${check}; then
            ((failed_validations++))
        fi
        echo ""
    done

    # Non-critical validations (warnings only)
    validate_permissions
    validate_spacyweb
    validate_apis
    test_email_processing

    echo ""

    if [[ ${failed_validations} -gt 0 ]]; then
        error "${failed_validations} critical validation(s) failed"
        return 1
    fi

    success "All validations passed!"
    return 0
}

# Export functions
export -f validate_database validate_database_tables validate_redis
export -f validate_postfix validate_services validate_python_env
export -f validate_email_filter validate_permissions validate_spacyweb
export -f validate_apis test_email_processing run_all_validations
