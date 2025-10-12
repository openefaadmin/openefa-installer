#!/bin/bash
#
# efa_integration.sh - Configure OpenEFA APIs on existing EFA appliance
# Part of the OpenEFA project (https://openefa.com)
#
# This script configures an existing EFA (MailGuard) appliance to use
# OpenEFA's API endpoints for whitelisting, blocking, and release tracking.
#

set -e
set -u

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Main configuration
#
main() {
    show_banner

    cat << EOFINFO

${COLOR_CYAN}╔════════════════════════════════════════════════════════════════╗
║         OpenEFA + EFA Integration Configuration                ║
╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}

This script will help you configure an existing EFA (MailGuard) appliance
to integrate with OpenEFA's API endpoints.

${COLOR_WHITE}Integration provides:${COLOR_RESET}
  • Release Tracking - Learn from user releases (Port 5001)
  • Whitelist API - "Always Allow" button (Port 5002)
  • Block Sender API - "Always Block" button (Port 5003)

${COLOR_YELLOW}Requirements:${COLOR_RESET}
  • Existing EFA/MailGuard appliance
  • SSH access to EFA appliance (or manual configuration)
  • Network connectivity between EFA and OpenEFA server

EOFINFO

    echo ""

    if ! confirm "Continue with EFA integration?"; then
        info "Integration cancelled"
        exit 0
    fi

    # Get OpenEFA server IP
    echo ""
    read -p "Enter OpenEFA server IP address: " OPENEFA_IP

    if [[ -z "${OPENEFA_IP}" ]]; then
        die "IP address required" 1
    fi

    # Display configuration instructions
    section "EFA Configuration Instructions"

    cat << EOFCONFIG

${COLOR_WHITE}Manual Configuration Steps for EFA Appliance:${COLOR_RESET}

1. ${COLOR_CYAN}Configure Release Tracking API${COLOR_RESET}
   Edit your EFA MailWatch release button to call:
   
   curl -X POST http://${OPENEFA_IP}:5001/api/feedback/release \\
        -H "Content-Type: application/json" \\
        -d '{"sender":"SENDER_EMAIL","recipient":"RECIPIENT_EMAIL"}'

2. ${COLOR_CYAN}Configure Whitelist API${COLOR_RESET}
   Add "Always Allow" button that calls:
   
   curl -X POST http://${OPENEFA_IP}:5002/api/whitelist \\
        -H "Content-Type: application/json" \\
        -d '{"email":"SENDER_EMAIL","domain":"DOMAIN"}'

3. ${COLOR_CYAN}Configure Block Sender API${COLOR_RESET}
   Add "Always Block" button that calls:
   
   curl -X POST http://${OPENEFA_IP}:5003/api/block \\
        -H "Content-Type: application/json" \\
        -d '{"sender":"SENDER_EMAIL","domain":"DOMAIN","pattern_type":"exact"}'

4. ${COLOR_CYAN}Test API Connectivity${COLOR_RESET}
   From EFA appliance, test connection:
   
   curl -v http://${OPENEFA_IP}:5001/health
   curl -v http://${OPENEFA_IP}:5002/health  
   curl -v http://${OPENEFA_IP}:5003/health

${COLOR_WHITE}Firewall Configuration:${COLOR_RESET}
   Ensure EFA appliance can reach OpenEFA on ports 5001-5003:
   
   # On OpenEFA server:
   sudo ufw allow from EFA_IP to any port 5001:5003 proto tcp

${COLOR_WHITE}Verification:${COLOR_RESET}
   After configuration:
   1. Release an email from EFA quarantine
   2. Check OpenEFA logs: /opt/spacyserver/logs/
   3. Verify entry in trusted_senders table
   4. Test "Always Allow" and "Always Block" buttons

${COLOR_YELLOW}Note:${COLOR_RESET} Full EFA integration requires custom MailWatch modifications.
See /opt/spacyserver/docs/MAILGUARD_*_INTEGRATION.md for details.

EOFCONFIG

    echo ""

    if confirm "Save this configuration to file?"; then
        local config_file="/opt/spacyserver/efa_integration_config.txt"
        
        cat > "${config_file}" << EOFSAVE
OpenEFA + EFA Integration Configuration
========================================

OpenEFA Server IP: ${OPENEFA_IP}

API Endpoints:
  - Release Tracking: http://${OPENEFA_IP}:5001/api/feedback/release
  - Whitelist API:    http://${OPENEFA_IP}:5002/api/whitelist
  - Block Sender API: http://${OPENEFA_IP}:5003/api/block

Test Commands:
  curl -v http://${OPENEFA_IP}:5001/health
  curl -v http://${OPENEFA_IP}:5002/health
  curl -v http://${OPENEFA_IP}:5003/health

Configuration Date: $(date)
EOFSAVE

        success "Configuration saved to: ${config_file}"
    fi

    cat << EOFDONE

${COLOR_GREEN}EFA Integration Guide Complete!${COLOR_RESET}

${COLOR_CYAN}For detailed integration instructions, see:${COLOR_RESET}
  • /opt/spacyserver/docs/MAILGUARD_BLOCK_SENDER_INTEGRATION.md
  • https://forum.openefa.com

EOFDONE

    exit 0
}

# Run main
main "$@"
