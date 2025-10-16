#!/bin/bash
#
# Automated OpenEFA Installation Test Script
# Pre-configured for testing with hardcoded values using environment variables
#

echo "=========================================="
echo "OpenEFA Automated Installation Test"
echo "=========================================="
echo ""
echo "Test Configuration:"
echo "  Domain:        example.com"
echo "  Relay Server:  YOUR_RELAY_SERVER"
echo "  Module Tier:   2 (Standard)"
echo "  Debug Logging: Enabled"
echo ""

# Set non-interactive mode flag
export OPENEFA_NONINTERACTIVE=1

# Required configuration
export OPENEFA_DOMAIN="example.com"
export OPENEFA_DB_PASSWORD="OpenEFA_DB_Test_2025!"
export OPENEFA_ADMIN_EMAIL="admin@example.com"
export OPENEFA_ADMIN_PASSWORD="OpenEFA_Admin_2025!"
export OPENEFA_RELAY_IP="YOUR_RELAY_SERVER"

# Optional configuration (with defaults)
export OPENEFA_DB_NAME="spacy_email_db"
export OPENEFA_DB_USER="spacy_user"
export OPENEFA_ADMIN_USER="admin"
export OPENEFA_RELAY_PORT="25"
export OPENEFA_DNS_RESOLVER=""  # Empty = use system default
export OPENEFA_MODULE_TIER="2"  # 1=Core, 2=Standard, 3=Advanced
export OPENEFA_DEBUG_LOGGING="1"  # 1=enabled, 0=disabled

echo "Starting installation in non-interactive mode..."
echo ""

cd "$(dirname "$0")"
sudo -E bash ./install.sh

INSTALL_EXIT_CODE=$?

echo ""
echo "=========================================="
if [ ${INSTALL_EXIT_CODE} -eq 0 ]; then
    echo "Installation test COMPLETED successfully!"
else
    echo "Installation test FAILED (exit code: ${INSTALL_EXIT_CODE})"
fi
echo "=========================================="
echo ""

exit ${INSTALL_EXIT_CODE}
