#!/bin/bash
#
# install.sh - OpenEFA Email Security System Installer
# Part of the OpenEFA project (https://openefa.com)
#
# Licensed under GPL - Successor to the EFA Project
# Copyright (C) 2025 OpenEFA Community
#
# This script performs a complete installation of OpenEFA including:
# - System package installation
# - Database setup
# - Postfix configuration  
# - OpenSpacy modules
# - Web interface and APIs
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source all library functions
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/checks.sh"
source "${SCRIPT_DIR}/lib/prompts.sh"
source "${SCRIPT_DIR}/lib/packages.sh"
source "${SCRIPT_DIR}/lib/database.sh"
source "${SCRIPT_DIR}/lib/postfix.sh"
source "${SCRIPT_DIR}/lib/modules.sh"
source "${SCRIPT_DIR}/lib/services.sh"
source "${SCRIPT_DIR}/lib/rollback.sh"
source "${SCRIPT_DIR}/lib/validation.sh"

#
# Main installation flow
#
main() {
    local start_time=$(date +%s)

    # Show banner
    show_banner

    # Check root
    require_root

    # Initialize logging
    init_logging

    info "Starting OpenEFA installation..."
    info "Log file: ${LOG_FILE}"
    echo ""

    # Pre-flight checks
    if ! run_all_checks; then
        die "Pre-flight checks failed. Please resolve issues and try again." 1
    fi

    # Gather installation configuration from user
    if ! gather_installation_config; then
        die "Installation cancelled" 0
    fi

    # Create spacy-filter user if not exists
    if ! id -u spacy-filter &>/dev/null; then
        info "Creating spacy-filter user..."
        useradd -r -s /bin/bash -d /opt/spacyserver -m spacy-filter
        success "User spacy-filter created"
    fi

    # Installation steps
    local steps=(
        "install_all_packages:Installing system packages"
        "setup_database:Setting up database"
        "configure_postfix:Configuring Postfix"
        "install_modules:Installing OpenSpacy modules"
        "setup_services:Setting up services"
        "run_all_validations:Validating installation"
    )

    local step_num=1
    local total_steps=${#steps[@]}
    local failed=0

    for step_info in "${steps[@]}"; do
        local step_func="${step_info%%:*}"
        local step_desc="${step_info##*:}"

        echo ""
        section "Step ${step_num}/${total_steps}: ${step_desc}"

        # Execute step with error handling
        if ${step_func}; then
            success "Step ${step_num}/${total_steps} complete"
        else
            error "Step ${step_num}/${total_steps} failed: ${step_desc}"
            failed=1
            break
        fi

        ((step_num++))
    done

    # Calculate installation time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    echo ""

    if [[ ${failed} -eq 0 ]]; then
        # Success!
        cleanup_state
        show_summary "SUCCESS" "${duration}"
        
        cat << EOFSUCCESS

${COLOR_GREEN}╔════════════════════════════════════════════════════════════════╗
║                  INSTALLATION SUCCESSFUL!                      ║
╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}

${COLOR_CYAN}OpenEFA Email Security System is now running!${COLOR_RESET}

${COLOR_WHITE}Access Information:${COLOR_RESET}
  • SpacyWeb Dashboard: https://$(hostname -f):5500
  • Admin Username: ${ADMIN_USER}
  • Admin Email: ${ADMIN_EMAIL}

${COLOR_WHITE}Protected Domain:${COLOR_RESET}
  • ${INSTALL_DOMAIN}

${COLOR_WHITE}Services Running:${COLOR_RESET}
  • Postfix (Mail Server)
  • spacy-db-processor (Database Queue)
  • SpacyWeb (Dashboard - Port 5500)
  • Release API (Port 5001)
  • Whitelist API (Port 5002)
  • Block API (Port 5003)

${COLOR_RED}⚠️  CRITICAL - If using MailGuard/EFA downstream:${COLOR_RESET}
  ${COLOR_YELLOW}Deploy SpamAssassin rules to your MailGuard/EFA server:${COLOR_RESET}

  cd /opt/spacyserver/installer/templates/spamassassin
  scp *.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
  ssh root@YOUR_EFA_SERVER_IP "spamassassin --lint && systemctl restart mailscanner"

  ${COLOR_WHITE}Without this, MailGuard will IGNORE OpenEFA's analysis!${COLOR_RESET}
  See: /opt/spacyserver/docs/EFA_SPAMASSASSIN_INTEGRATION.md

${COLOR_WHITE}Next Steps:${COLOR_RESET}
  1. Update DNS MX records to point to this server
  2. Configure firewall to allow port 25 (SMTP) inbound
  3. Login to SpacyWeb to configure additional settings
  4. Add whitelists and blocking rules as needed
  5. Monitor logs: /opt/spacyserver/logs/
  6. Consider installing Let's Encrypt SSL certificate

${COLOR_WHITE}Useful Commands:${COLOR_RESET}
  • Check email logs: sudo tail -f /var/log/mail.log
  • Check SpaCy logs: sudo tail -f /opt/spacyserver/logs/email_filter_error.log
  • Service status: sudo systemctl status spacy-db-processor
  • OpenSpacyMenu: sudo /opt/spacyserver/tools/OpenSpacyMenu

${COLOR_YELLOW}Optional:${COLOR_RESET}
  • Run efa_integration.sh to configure APIs on existing EFA appliance
  • See README.md for detailed configuration guide

${COLOR_GREEN}Thank you for installing OpenEFA!${COLOR_RESET}
${COLOR_CYAN}Community: https://openefa.com | Forum: https://forum.openefa.com${COLOR_RESET}

EOFSUCCESS

        exit 0
    else
        # Failure - offer rollback
        show_summary "FAILED" "${duration}"
        
        error "Installation failed!"
        echo ""

        if confirm "Perform rollback and restore system to previous state?"; then
            perform_full_rollback
        else
            warn "System left in partially installed state"
            warn "Review log: ${LOG_FILE}"
            warn "You can manually run rollback with: ${SCRIPT_DIR}/lib/rollback.sh"
        fi

        exit 1
    fi
}

# Trap errors and perform rollback
trap 'if [[ $? -ne 0 ]]; then error "Installation interrupted"; fi' EXIT

# Run main installation
main "$@"
