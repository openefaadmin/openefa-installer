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
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
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
#
validate_apis() {
    info "Validating API endpoints..."

    local api_ports=(5001 5002 5003)
    local failed_apis=()

    for port in "${api_ports[@]}"; do
        if ss -tuln | grep -q ":${port} "; then
            success "API port ${port}: Listening"
        else
            error "API port ${port}: NOT listening"
            failed_apis+=("${port}")
        fi
    done

    if [[ ${#failed_apis[@]} -gt 0 ]]; then
        error "Failed APIs on ports: ${failed_apis[*]}"
        return 1
    fi

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

    local test_email="postmaster@${INSTALL_DOMAIN}"

    if command -v swaks &> /dev/null; then
        swaks --to "${test_email}" \
              --from "test@example.com" \
              --server localhost \
              --header "Subject: OpenEFA Installation Test" \
              --body "This is a test email from OpenEFA installer." \
              &> /dev/null

        if [[ $? -eq 0 ]]; then
            success "Test email sent successfully"
            info "Check logs: /var/log/mail.log and /opt/spacyserver/logs/"
            return 0
        else
            warn "Test email failed (check logs)"
            return 0  # Non-fatal
        fi
    else
        warn "swaks not available for email testing"
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
