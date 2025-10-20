#!/bin/bash
#
# OpenEFA Release Package Creator
# Creates the final distribution package for public release
#

set -euo pipefail

VERSION="0.9.0"
INSTALLER_DIR="/opt/spacyserver/installer"
RELEASE_NAME="openefa-${VERSION}"
RELEASE_DIR="/tmp/${RELEASE_NAME}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

cat << "EOF"
═══════════════════════════════════════════════════════
  OpenEFA Release Package Creator
═══════════════════════════════════════════════════════

This creates the final distribution package:
  • Installer scripts
  • Library functions
  • Configuration templates
  • Application files (from openefa-files/)
  • Documentation
  • SQL schema

Ready for public release at: https://install.openefa.com

EOF

# Check if openefa-files exists
if [[ ! -d "$INSTALLER_DIR/openefa-files" ]]; then
    echo -e "${YELLOW}WARNING: openefa-files directory not found!${NC}"
    echo ""
    echo "Please run these steps first:"
    echo "  1. ./prepare_release.sh  (copy & sanitize production files)"
    echo "  2. Review SANITIZATION_CHECKLIST.md"
    echo "  3. Fix any issues found"
    echo "  4. Run ./scan_for_secrets.sh"
    echo "  5. Then run this script again"
    echo ""
    exit 1
fi

# Run secret scanner first
echo -e "${BLUE}Running security scan...${NC}"
if "$INSTALLER_DIR/scan_for_secrets.sh" "$INSTALLER_DIR/openefa-files"; then
    echo -e "${GREEN}✓ Security scan passed${NC}"
else
    echo -e "${YELLOW}Security scan found issues. Continue anyway? [y/N]${NC}"
    read -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""

#######################################
# Create release directory
#######################################
echo -e "${BLUE}Creating release directory...${NC}"

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

#######################################
# Copy installer framework
#######################################
echo -e "${BLUE}Copying installer framework...${NC}"

cp -r "$INSTALLER_DIR/lib" "$RELEASE_DIR/"
cp -r "$INSTALLER_DIR/templates" "$RELEASE_DIR/"
cp -r "$INSTALLER_DIR/sql" "$RELEASE_DIR/"
cp -r "$INSTALLER_DIR/docs" "$RELEASE_DIR/"

cp "$INSTALLER_DIR/install.sh" "$RELEASE_DIR/"
cp "$INSTALLER_DIR/uninstall.sh" "$RELEASE_DIR/"
cp "$INSTALLER_DIR/efa_integration.sh" "$RELEASE_DIR/"
cp "$INSTALLER_DIR/VERSION" "$RELEASE_DIR/"
cp "$INSTALLER_DIR/LICENSE" "$RELEASE_DIR/"

echo -e "${GREEN}✓ Installer framework copied${NC}"

#######################################
# Copy sanitized application files
#######################################
echo -e "${BLUE}Copying application files...${NC}"

# Create application directory structure in release
mkdir -p "$RELEASE_DIR/files"/{modules,services,web,api,tools,scripts}

# Copy from openefa-files (already sanitized)
cp "$INSTALLER_DIR/openefa-files/email_filter.py" "$RELEASE_DIR/files/" 2>/dev/null || echo "  Warning: email_filter.py not found"
cp -r "$INSTALLER_DIR/openefa-files/modules"/* "$RELEASE_DIR/files/modules/" 2>/dev/null || echo "  Warning: modules not found"
cp -r "$INSTALLER_DIR/openefa-files/services"/* "$RELEASE_DIR/files/services/" 2>/dev/null || echo "  Warning: services not found"
cp -r "$INSTALLER_DIR/openefa-files/web"/* "$RELEASE_DIR/files/web/" 2>/dev/null || echo "  Warning: web files not found"
cp -r "$INSTALLER_DIR/openefa-files/api"/* "$RELEASE_DIR/files/api/" 2>/dev/null || echo "  Warning: api files not found"
cp -r "$INSTALLER_DIR/openefa-files/tools"/* "$RELEASE_DIR/files/tools/" 2>/dev/null || echo "  Warning: tools not found"
cp -r "$INSTALLER_DIR/openefa-files/scripts"/* "$RELEASE_DIR/files/scripts/" 2>/dev/null || echo "  Warning: scripts not found"

echo -e "${GREEN}✓ Application files copied${NC}"

#######################################
# Modify install.sh to copy application files
#######################################
echo -e "${BLUE}Updating install.sh to deploy application files...${NC}"

# Add application file deployment to install.sh
cat >> "$RELEASE_DIR/install.sh" << 'INSTALL_ADDITION'

#######################################
# Deploy application files
#######################################
deploy_application_files() {
    log_info "Deploying application files..."

    local files_dir="$SCRIPT_DIR/files"

    if [[ ! -d "$files_dir" ]]; then
        log_error "Application files directory not found: $files_dir"
        return 1
    fi

    # Copy application files
    cp "$files_dir/email_filter.py" "$INSTALL_DIR/" || log_warning "email_filter.py not found"
    cp -r "$files_dir/modules"/* "$INSTALL_DIR/modules/" || log_warning "modules not found"
    cp -r "$files_dir/services"/* "$INSTALL_DIR/services/" || log_warning "services not found"
    cp -r "$files_dir/web"/* "$INSTALL_DIR/web/" || log_warning "web files not found"
    cp -r "$files_dir/api"/* "$INSTALL_DIR/api/" || log_warning "api files not found"
    cp -r "$files_dir/tools"/* "$INSTALL_DIR/tools/" || log_warning "tools not found"
    cp -r "$files_dir/scripts"/* "$INSTALL_DIR/scripts/" || log_warning "scripts not found"

    log_success "Application files deployed"
}

# Call this in main() after install_openspacy_modules
INSTALL_ADDITION

echo -e "${GREEN}✓ install.sh updated${NC}"

#######################################
# Create README in release root
#######################################
cat > "$RELEASE_DIR/README.txt" << 'README'
OpenEFA v0.9.0 - Installation Package
=====================================

QUICK START:

    sudo bash install.sh

REQUIREMENTS:

    • Ubuntu 24.04 LTS or 22.04 LTS
    • 2 GB RAM minimum
    • 10 GB free disk space
    • Root/sudo access

DOCUMENTATION:

    See docs/README.md for complete documentation
    See docs/INSTALLATION.md for step-by-step guide
    See docs/TROUBLESHOOTING.md for common issues

SUPPORT:

    Website: https://openefa.com
    Forum:   https://forum.openefa.com
    GitHub:  https://github.com/openefaadmin/openefa

LICENSE:

    GNU General Public License v3
    See LICENSE file for full text

ABOUT:

    OpenEFA is the successor to the EFA (Email Filter Appliance)
    project, providing advanced email security through AI-powered
    threat detection.

COPYRIGHT:

    Copyright (C) 2025 OpenEFA Project
README

#######################################
# Create installer manifest
#######################################
cat > "$RELEASE_DIR/MANIFEST.txt" << MANIFEST
OpenEFA v${VERSION} Release Manifest
Generated: $(date)

INSTALLER FILES:
  install.sh          - Main installation script
  uninstall.sh        - Complete removal script
  efa_integration.sh  - EFA API integration
  VERSION             - Version identifier
  LICENSE             - GPL v3 license

LIBRARIES:
$(find "$RELEASE_DIR/lib" -name "*.sh" -exec basename {} \; | sed 's/^/  /')

TEMPLATES:
  Config Templates: $(find "$RELEASE_DIR/templates/config" -name "*.template" | wc -l)
  Postfix Templates: $(find "$RELEASE_DIR/templates/postfix" -name "*.template" | wc -l)
  Systemd Services: $(find "$RELEASE_DIR/templates/systemd" -name "*.service" | wc -l)
  Logrotate: 1

DATABASE:
  schema_v1.sql       - Complete database schema (40+ tables)
  migrations/         - Database migration framework

APPLICATION FILES:
  email_filter.py     - Main email processing script
  modules/            - Security modules (Tier 1/2/3)
  services/           - Background services
  web/                - SpacyWeb dashboard
  api/                - API services (3 endpoints)
  tools/              - Management tools
  scripts/            - Utility scripts

DOCUMENTATION:
  docs/README.md              - Project overview
  docs/INSTALLATION.md        - Installation guide
  docs/TROUBLESHOOTING.md     - Common issues

TOTAL SIZE: $(du -sh "$RELEASE_DIR" | awk '{print $1}')
MANIFEST

#######################################
# Create checksums
#######################################
echo -e "${BLUE}Generating checksums...${NC}"

cd "$RELEASE_DIR"
find . -type f -exec sha256sum {} \; > SHA256SUMS
cd - > /dev/null

echo -e "${GREEN}✓ Checksums generated${NC}"

#######################################
# Create tarballs
#######################################
echo -e "${BLUE}Creating release packages...${NC}"

cd /tmp

# Full package
tar -czf "${RELEASE_NAME}.tar.gz" "$RELEASE_NAME"
echo -e "${GREEN}✓ Created: ${RELEASE_NAME}.tar.gz${NC}"

# Also create .zip for Windows users
zip -rq "${RELEASE_NAME}.zip" "$RELEASE_NAME"
echo -e "${GREEN}✓ Created: ${RELEASE_NAME}.zip${NC}"

cd - > /dev/null

#######################################
# Display summary
#######################################
cat << EOF

${GREEN}═══════════════════════════════════════════════════════
  Release Package Created Successfully!
═══════════════════════════════════════════════════════${NC}

${BLUE}Release Version:${NC} $VERSION

${BLUE}Package Files:${NC}
  /tmp/${RELEASE_NAME}.tar.gz
  /tmp/${RELEASE_NAME}.zip

${BLUE}Package Size:${NC}
  $(ls -lh /tmp/${RELEASE_NAME}.tar.gz | awk '{print $5}')

${BLUE}Contents:${NC}
  $(find "$RELEASE_DIR" -type f | wc -l) files
  $(du -sh "$RELEASE_DIR" | awk '{print $1}') total size

${BLUE}Checksums:${NC}
  SHA256SUMS file included in package

${BLUE}Next Steps:${NC}

  1. Test installation on fresh Ubuntu 24.04:
     cd /tmp
     tar -xzf ${RELEASE_NAME}.tar.gz
     cd ${RELEASE_NAME}
     sudo bash install.sh

  2. Verify all features work

  3. Upload to distribution server:
     scp /tmp/${RELEASE_NAME}.tar.gz server:/var/www/install.openefa.com/

  4. Update download links:
     https://install.openefa.com/${RELEASE_NAME}.tar.gz

  5. Announce release on forum

${BLUE}Distribution URLs:${NC}
  Direct download:
    https://install.openefa.com/${RELEASE_NAME}.tar.gz

  Quick install:
    curl -sSL https://install.openefa.com/install.sh | sudo bash

${GREEN}Release package ready for distribution!${NC}

═══════════════════════════════════════════════════════

EOF
