#!/bin/bash
#
# prompts.sh - User input prompts for OpenEFA installer
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Validate email address format
# Args: $1=email
# Returns: 0 if valid, 1 if invalid
#
validate_email() {
    local email="$1"
    local regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if [[ "${email}" =~ ${regex} ]]; then
        return 0
    else
        return 1
    fi
}

#
# Validate domain format
# Args: $1=domain
# Returns: 0 if valid, 1 if invalid
#
validate_domain() {
    local domain="$1"
    local regex="^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"

    if [[ "${domain}" =~ ${regex} ]]; then
        return 0
    else
        return 1
    fi
}

#
# Validate IP address format
# Args: $1=ip_address
# Returns: 0 if valid, 1 if invalid
#
validate_ip() {
    local ip="$1"
    local regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    if [[ ! "${ip}" =~ ${regex} ]]; then
        return 1
    fi

    # Check each octet is 0-255
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        if [[ ${octet} -lt 0 || ${octet} -gt 255 ]]; then
            return 1
        fi
    done

    return 0
}

#
# Validate password strength
# Args: $1=password
# Returns: 0 if valid, 1 if weak
#
validate_password() {
    local password="$1"

    # Minimum 8 characters
    if [[ ${#password} -lt 8 ]]; then
        error "Password must be at least 8 characters"
        return 1
    fi

    # Should contain mix of characters (basic check)
    if [[ ! "${password}" =~ [a-zA-Z] ]] || [[ ! "${password}" =~ [0-9] ]]; then
        warn "Password should contain both letters and numbers"
        # Warning only, not fatal
    fi

    return 0
}

#
# Prompt for primary domain to protect
#
prompt_domain() {
    section "Domain Configuration"

    while true; do
        read -p "Enter the primary domain to protect (e.g., example.com): " INSTALL_DOMAIN

        if [[ -z "${INSTALL_DOMAIN}" ]]; then
            error "Domain cannot be empty"
            continue
        fi

        if ! validate_domain "${INSTALL_DOMAIN}"; then
            error "Invalid domain format: ${INSTALL_DOMAIN}"
            continue
        fi

        info "Primary domain: ${INSTALL_DOMAIN}"
        if confirm "Is this correct?"; then
            export INSTALL_DOMAIN
            break
        fi
    done
}

#
# Prompt for database configuration
#
prompt_database() {
    section "Database Configuration"

    # Database name
    read -p "Database name [spacy_email_db]: " DB_NAME
    DB_NAME="${DB_NAME:-spacy_email_db}"
    export DB_NAME

    # Database user
    read -p "Database user [spacy_user]: " DB_USER
    DB_USER="${DB_USER:-spacy_user}"
    export DB_USER

    # Database password
    while true; do
        read -s -p "Database password: " DB_PASSWORD
        echo ""

        if [[ -z "${DB_PASSWORD}" ]]; then
            error "Password cannot be empty"
            continue
        fi

        if ! validate_password "${DB_PASSWORD}"; then
            continue
        fi

        read -s -p "Confirm password: " DB_PASSWORD_CONFIRM
        echo ""

        if [[ "${DB_PASSWORD}" != "${DB_PASSWORD_CONFIRM}" ]]; then
            error "Passwords do not match"
            continue
        fi

        export DB_PASSWORD
        break
    done

    success "Database configuration saved"
}

#
# Prompt for SpacyWeb admin account
#
prompt_admin_account() {
    section "SpacyWeb Admin Account"

    # Admin username
    while true; do
        read -p "Admin username [admin]: " ADMIN_USER
        ADMIN_USER="${ADMIN_USER:-admin}"

        if [[ -z "${ADMIN_USER}" ]]; then
            error "Username cannot be empty"
            continue
        fi

        export ADMIN_USER
        break
    done

    # Admin email
    while true; do
        read -p "Admin email: " ADMIN_EMAIL

        if [[ -z "${ADMIN_EMAIL}" ]]; then
            error "Email cannot be empty"
            continue
        fi

        if ! validate_email "${ADMIN_EMAIL}"; then
            error "Invalid email format: ${ADMIN_EMAIL}"
            continue
        fi

        export ADMIN_EMAIL
        break
    done

    # Admin password
    while true; do
        read -s -p "Admin password: " ADMIN_PASSWORD
        echo ""

        if [[ -z "${ADMIN_PASSWORD}" ]]; then
            error "Password cannot be empty"
            continue
        fi

        if ! validate_password "${ADMIN_PASSWORD}"; then
            continue
        fi

        read -s -p "Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo ""

        if [[ "${ADMIN_PASSWORD}" != "${ADMIN_PASSWORD_CONFIRM}" ]]; then
            error "Passwords do not match"
            continue
        fi

        export ADMIN_PASSWORD
        break
    done

    success "Admin account configuration saved"
}

#
# Prompt for relay/destination mail server
#
prompt_relay_server() {
    section "Mail Relay Configuration"

    info "Enter the IP address of your destination mail server"
    info "(This could be an existing EFA appliance, Zimbra, or Exchange server)"
    echo ""

    while true; do
        read -p "Relay server IP address: " RELAY_SERVER_IP

        if [[ -z "${RELAY_SERVER_IP}" ]]; then
            error "IP address cannot be empty"
            continue
        fi

        if ! validate_ip "${RELAY_SERVER_IP}"; then
            error "Invalid IP address format: ${RELAY_SERVER_IP}"
            continue
        fi

        info "Relay server: ${RELAY_SERVER_IP}"
        if confirm "Is this correct?"; then
            export RELAY_SERVER_IP
            break
        fi
    done

    # Optional relay port
    read -p "Relay server port [25]: " RELAY_SERVER_PORT
    RELAY_SERVER_PORT="${RELAY_SERVER_PORT:-25}"
    export RELAY_SERVER_PORT
}

#
# Prompt for internal DNS resolver
#
prompt_dns_resolver() {
    section "DNS Resolver Configuration"

    info "Enter your internal DNS resolver IP address"
    info "(Leave blank to use system default)"
    echo ""

    read -p "DNS resolver IP [system default]: " DNS_RESOLVER_IP

    if [[ -n "${DNS_RESOLVER_IP}" ]]; then
        if ! validate_ip "${DNS_RESOLVER_IP}"; then
            error "Invalid IP address format: ${DNS_RESOLVER_IP}"
            DNS_RESOLVER_IP=""
        fi
    fi

    export DNS_RESOLVER_IP
    
    if [[ -n "${DNS_RESOLVER_IP}" ]]; then
        success "DNS resolver: ${DNS_RESOLVER_IP}"
    else
        info "Using system default DNS resolver"
    fi
}

#
# Prompt for OpenSpacy module tier selection
#
prompt_module_tier() {
    section "OpenSpacy Module Selection"

    cat << EOF
Choose the module tier to install:

  1) Tier 1 - Core Only (Minimal)
     Authentication, blocking, basic spam scoring, RBL checker
     Recommended for: Low-resource systems, basic filtering needs

  2) Tier 2 - Standard (Recommended)
     Includes Tier 1 + BEC detection, typosquatting, DNS reputation,
     obfuscation detector, marketing filter, PDF analyzer, URL reputation
     Recommended for: Most installations, balanced performance

EOF

    while true; do
        read -p "Select tier [2]: " MODULE_TIER
        MODULE_TIER="${MODULE_TIER:-2}"

        case "${MODULE_TIER}" in
            1|2)
                export MODULE_TIER
                break
                ;;
            *)
                error "Invalid selection. Please choose 1 or 2"
                ;;
        esac
    done

    case "${MODULE_TIER}" in
        1) success "Selected: Tier 1 - Core Only" ;;
        2) success "Selected: Tier 2 - Standard (Recommended)" ;;
    esac
}

#
# Prompt for verbose/debug logging preference
#
prompt_logging() {
    section "Logging Configuration"

    info "Enable verbose/debug logging?"
    info "(Recommended for initial setup, can be disabled later)"
    echo ""

    if confirm "Enable debug logging?"; then
        export ENABLE_DEBUG_LOGGING=1
        success "Debug logging will be enabled"
    else
        export ENABLE_DEBUG_LOGGING=0
        info "Standard logging will be used"
    fi
}

#
# Display configuration summary and confirm
#
confirm_configuration() {
    section "Installation Summary"

    cat << EOF
The following configuration will be installed:

  Primary Domain:       ${INSTALL_DOMAIN}
  Database Name:        ${DB_NAME}
  Database User:        ${DB_USER}
  Admin Username:       ${ADMIN_USER}
  Admin Email:          ${ADMIN_EMAIL}
  Relay Server:         ${RELAY_SERVER_IP}:${RELAY_SERVER_PORT}
  DNS Resolver:         ${DNS_RESOLVER_IP:-System Default}
  Module Tier:          Tier ${MODULE_TIER}
  Debug Logging:        $([ "${ENABLE_DEBUG_LOGGING}" -eq 1 ] && echo "Enabled" || echo "Disabled")

Installation will proceed with these settings.

EOF

    if ! confirm "Continue with installation?"; then
        error "Installation cancelled by user"
        return 1
    fi

    return 0
}

#
# Check if running in non-interactive mode
#
is_non_interactive() {
    [[ -n "${OPENEFA_NONINTERACTIVE:-}" ]]
}

#
# Load configuration from environment variables (non-interactive mode)
#
load_config_from_env() {
    # Required variables
    if [[ -z "${OPENEFA_DOMAIN:-}" ]]; then
        error "OPENEFA_DOMAIN not set (required for non-interactive mode)"
        return 1
    fi

    if [[ -z "${OPENEFA_DB_PASSWORD:-}" ]]; then
        error "OPENEFA_DB_PASSWORD not set (required for non-interactive mode)"
        return 1
    fi

    if [[ -z "${OPENEFA_ADMIN_EMAIL:-}" ]]; then
        error "OPENEFA_ADMIN_EMAIL not set (required for non-interactive mode)"
        return 1
    fi

    if [[ -z "${OPENEFA_ADMIN_PASSWORD:-}" ]]; then
        error "OPENEFA_ADMIN_PASSWORD not set (required for non-interactive mode)"
        return 1
    fi

    if [[ -z "${OPENEFA_RELAY_IP:-}" ]]; then
        error "OPENEFA_RELAY_IP not set (required for non-interactive mode)"
        return 1
    fi

    # Assign required variables
    export INSTALL_DOMAIN="${OPENEFA_DOMAIN}"
    export DB_PASSWORD="${OPENEFA_DB_PASSWORD}"
    export ADMIN_EMAIL="${OPENEFA_ADMIN_EMAIL}"
    export ADMIN_PASSWORD="${OPENEFA_ADMIN_PASSWORD}"
    export RELAY_SERVER_IP="${OPENEFA_RELAY_IP}"

    # Optional variables with defaults
    export DB_NAME="${OPENEFA_DB_NAME:-spacy_email_db}"
    export DB_USER="${OPENEFA_DB_USER:-spacy_user}"
    export ADMIN_USER="${OPENEFA_ADMIN_USER:-admin}"
    export RELAY_SERVER_PORT="${OPENEFA_RELAY_PORT:-25}"
    export DNS_RESOLVER_IP="${OPENEFA_DNS_RESOLVER:-}"
    export MODULE_TIER="${OPENEFA_MODULE_TIER:-2}"
    export ENABLE_DEBUG_LOGGING="${OPENEFA_DEBUG_LOGGING:-1}"

    # Validate critical inputs
    if ! validate_domain "${INSTALL_DOMAIN}"; then
        error "Invalid domain format: ${INSTALL_DOMAIN}"
        return 1
    fi

    if ! validate_email "${ADMIN_EMAIL}"; then
        error "Invalid admin email format: ${ADMIN_EMAIL}"
        return 1
    fi

    if ! validate_ip "${RELAY_SERVER_IP}"; then
        error "Invalid relay server IP: ${RELAY_SERVER_IP}"
        return 1
    fi

    if ! validate_password "${DB_PASSWORD}"; then
        error "Database password does not meet requirements"
        return 1
    fi

    if ! validate_password "${ADMIN_PASSWORD}"; then
        error "Admin password does not meet requirements"
        return 1
    fi

    # Validate module tier
    if [[ ! "${MODULE_TIER}" =~ ^[123]$ ]]; then
        error "Invalid MODULE_TIER: ${MODULE_TIER} (must be 1, 2, or 3)"
        return 1
    fi

    info "Non-interactive mode: Configuration loaded from environment"
    return 0
}

#
# Run all prompts and gather configuration
#
gather_installation_config() {
    # Check if running in non-interactive mode
    if is_non_interactive; then
        if ! load_config_from_env; then
            return 1
        fi

        # Show configuration summary in non-interactive mode
        section "Installation Configuration (Non-Interactive Mode)"
        cat << EOF
  Primary Domain:       ${INSTALL_DOMAIN}
  Database Name:        ${DB_NAME}
  Database User:        ${DB_USER}
  Admin Username:       ${ADMIN_USER}
  Admin Email:          ${ADMIN_EMAIL}
  Relay Server:         ${RELAY_SERVER_IP}:${RELAY_SERVER_PORT}
  DNS Resolver:         ${DNS_RESOLVER_IP:-System Default}
  Module Tier:          Tier ${MODULE_TIER}
  Debug Logging:        $([ "${ENABLE_DEBUG_LOGGING}" -eq 1 ] && echo "Enabled" || echo "Disabled")

EOF
        info "Proceeding with non-interactive installation..."
    else
        # Interactive mode - prompt for everything
        prompt_domain
        prompt_database
        prompt_admin_account
        prompt_relay_server
        prompt_dns_resolver
        prompt_module_tier
        prompt_logging

        if ! confirm_configuration; then
            return 1
        fi
    fi

    # Save configuration to file for reference
    save_installation_config

    return 0
}

#
# Save configuration to file
#
save_installation_config() {
    local config_file="/tmp/openefa_install_config"

    cat > "${config_file}" << EOF
# OpenEFA Installation Configuration
# Generated: $(date)

INSTALL_DOMAIN="${INSTALL_DOMAIN}"
DB_NAME="${DB_NAME}"
DB_USER="${DB_USER}"
DB_PASSWORD="${DB_PASSWORD}"
ADMIN_USER="${ADMIN_USER}"
ADMIN_EMAIL="${ADMIN_EMAIL}"
ADMIN_PASSWORD="${ADMIN_PASSWORD}"
RELAY_SERVER_IP="${RELAY_SERVER_IP}"
RELAY_SERVER_PORT="${RELAY_SERVER_PORT}"
DNS_RESOLVER_IP="${DNS_RESOLVER_IP}"
MODULE_TIER="${MODULE_TIER}"
ENABLE_DEBUG_LOGGING="${ENABLE_DEBUG_LOGGING}"
EOF

    chmod 600 "${config_file}"
    log_message "Configuration saved to ${config_file}" "CONFIG"
}

# Export functions
export -f validate_email validate_domain validate_ip validate_password
export -f prompt_domain prompt_database prompt_admin_account
export -f prompt_relay_server prompt_dns_resolver prompt_module_tier
export -f prompt_logging confirm_configuration gather_installation_config
export -f save_installation_config is_non_interactive load_config_from_env
