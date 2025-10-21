#!/bin/bash
#
# OpenEFA CSRF Token Fix Script
# Version: 1.0
# Purpose: Fix CSRF token errors on existing installations
#
# This script regenerates the Flask secret key to fix "Bad Request - The CSRF session token is missing" errors
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log functions
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

info "OpenEFA CSRF Token Fix Script"
echo "================================"
echo ""

# Configuration
CONFIG_FILE="/opt/spacyserver/config/.app_config.ini"
BACKUP_FILE="${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    error "Configuration file not found: $CONFIG_FILE"
    exit 1
fi

info "Current configuration file: $CONFIG_FILE"

# Backup existing config
info "Creating backup: $BACKUP_FILE"
cp "$CONFIG_FILE" "$BACKUP_FILE"
success "Backup created"

# Generate new secret key
info "Generating new cryptographically secure secret key..."
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")

if [[ -z "$NEW_KEY" ]]; then
    error "Failed to generate secret key"
    exit 1
fi

success "Secret key generated (${#NEW_KEY} characters)"

# Create new config file
info "Writing new configuration..."
cat > "$CONFIG_FILE" << EOF
[flask]
secret_key = ${NEW_KEY}
EOF

# Set correct permissions
info "Setting file permissions..."
chown spacy-filter:spacy-filter "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"
success "Permissions set (640, spacy-filter:spacy-filter)"

# Verify the file
info "Verifying configuration file..."
if grep -q "^\[flask\]" "$CONFIG_FILE" && grep -q "^secret_key = " "$CONFIG_FILE"; then
    success "Configuration file is valid"
else
    error "Configuration file validation failed"
    warn "Restoring backup..."
    cp "$BACKUP_FILE" "$CONFIG_FILE"
    exit 1
fi

# Restart spacyweb service
info "Restarting spacyweb service..."
if systemctl restart spacyweb; then
    success "Service restarted"
else
    error "Failed to restart spacyweb service"
    warn "You may need to restart it manually: sudo systemctl restart spacyweb"
    exit 1
fi

# Check service status
sleep 2
info "Checking service status..."
if systemctl is-active --quiet spacyweb; then
    success "spacyweb service is running"
else
    error "spacyweb service is not running"
    warn "Check logs: sudo journalctl -u spacyweb -n 50"
    exit 1
fi

echo ""
success "CSRF token fix completed successfully!"
echo ""
info "Summary:"
echo "  - Backup saved to: $BACKUP_FILE"
echo "  - New secret key generated and installed"
echo "  - Service restarted and verified"
echo ""
info "Next steps:"
echo "  1. Clear your browser cache/cookies"
echo "  2. Try accessing the web interface again"
echo "  3. If issues persist, check logs: sudo journalctl -u spacyweb -f"
echo ""
