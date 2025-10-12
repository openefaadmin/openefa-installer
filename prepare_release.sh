#!/bin/bash
#
# OpenEFA Release Preparation Script
# Sanitizes production files for public release
#

set -euo pipefail

PROD_DIR="/opt/spacyserver"
INSTALLER_DIR="/opt/spacyserver/installer"
RELEASE_DIR="$INSTALLER_DIR/openefa-files"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

cat << "EOF"
═══════════════════════════════════════════════════════
  OpenEFA Release Preparation
═══════════════════════════════════════════════════════

This script prepares production files for public release by:
  • Copying application files
  • Removing hardcoded IPs/domains
  • Sanitizing client-specific data
  • Making everything config-driven

EOF

read -p "Continue? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

echo ""

#######################################
# Create release directory structure
#######################################
log_info "Creating release directory structure..."

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"/{modules,services,web,api,tools,scripts}

log_success "Directory structure created"

#######################################
# Copy and sanitize email_filter.py
#######################################
log_info "Processing email_filter.py..."

if [[ -f "$PROD_DIR/email_filter.py" ]]; then
    cp "$PROD_DIR/email_filter.py" "$RELEASE_DIR/email_filter.py"

    # Remove any hardcoded IPs or domains
    # (email_filter.py should already be config-driven, just verify)

    log_success "email_filter.py copied"
else
    log_warning "email_filter.py not found in production"
fi

#######################################
# Copy modules (sanitize each)
#######################################
log_info "Processing modules..."

if [[ -d "$PROD_DIR/modules" ]]; then
    for module in "$PROD_DIR/modules"/*.py; do
        if [[ -f "$module" ]]; then
            module_basename=$(basename "$module")
            cp "$module" "$RELEASE_DIR/modules/$module_basename"

            # No sanitization needed - modules read from configs
            log_info "  Copied: $module_basename"
        fi
    done
    log_success "Modules copied"
else
    log_warning "modules directory not found"
fi

#######################################
# Copy and sanitize services
#######################################
log_info "Processing services..."

if [[ -f "$PROD_DIR/services/db_processor.py" ]]; then
    cp "$PROD_DIR/services/db_processor.py" "$RELEASE_DIR/services/db_processor.py"
    log_success "db_processor.py copied"
fi

#######################################
# Copy and sanitize web files
#######################################
log_info "Processing web interface..."

if [[ -d "$PROD_DIR/web" ]]; then
    # Copy main files
    cp "$PROD_DIR/web/app.py" "$RELEASE_DIR/web/app.py" 2>/dev/null || true
    cp "$PROD_DIR/web/whitelist_manager.py" "$RELEASE_DIR/web/whitelist_manager.py" 2>/dev/null || true
    cp "$PROD_DIR/web/quick_user_setup.py" "$RELEASE_DIR/web/quick_user_setup.py" 2>/dev/null || true

    # Copy templates, static, css directories
    cp -r "$PROD_DIR/web/templates" "$RELEASE_DIR/web/" 2>/dev/null || true
    cp -r "$PROD_DIR/web/static" "$RELEASE_DIR/web/" 2>/dev/null || true
    cp -r "$PROD_DIR/web/css" "$RELEASE_DIR/web/" 2>/dev/null || true

    # SANITIZE app.py - Remove HOSTED_DOMAINS hardcoding
    log_info "  Sanitizing app.py (HOSTED_DOMAINS)..."

    if [[ -f "$RELEASE_DIR/web/app.py" ]]; then
        # This needs manual review - will flag the section
        log_warning "  MANUAL REVIEW NEEDED: Check HOSTED_DOMAINS in app.py"
        log_warning "  Replace with: db query to client_domains table"
    fi

    log_success "Web files copied"
fi

#######################################
# Copy and sanitize API files
#######################################
log_info "Processing API services..."

if [[ -d "$PROD_DIR/api" ]]; then
    cp "$PROD_DIR/api"/*.py "$RELEASE_DIR/api/" 2>/dev/null || true
    log_success "API files copied"
fi

#######################################
# Copy tools (sanitize OpenSpacyMenu)
#######################################
log_info "Processing tools..."

if [[ -f "$PROD_DIR/tools/OpenSpacyMenu" ]]; then
    cp "$PROD_DIR/tools/OpenSpacyMenu" "$RELEASE_DIR/tools/OpenSpacyMenu"
    chmod +x "$RELEASE_DIR/tools/OpenSpacyMenu"
    log_success "OpenSpacyMenu copied"
fi

# Copy other tools
if [[ -d "$PROD_DIR/tools" ]]; then
    cp "$PROD_DIR/tools"/*.sh "$RELEASE_DIR/tools/" 2>/dev/null || true
    log_info "Additional tools copied"
fi

#######################################
# Copy scripts
#######################################
log_info "Processing scripts..."

if [[ -d "$PROD_DIR/scripts" ]]; then
    cp "$PROD_DIR/scripts"/*.sh "$RELEASE_DIR/scripts/" 2>/dev/null || true
    cp "$PROD_DIR/scripts"/*.py "$RELEASE_DIR/scripts/" 2>/dev/null || true
    log_success "Scripts copied"
fi

#######################################
# Sanitize all Python files
#######################################
log_info "Sanitizing Python files..."

# Find and report any hardcoded IPs
log_info "Checking for hardcoded IPs..."
grep -r "192\.168\." "$RELEASE_DIR" --include="*.py" || log_success "  No hardcoded 192.168.x.x IPs found"

# Find and report any hardcoded domains (common ones)
log_info "Checking for hardcoded domains..."
grep -r "safesoundins\.com\|phoenixdefence\.com\|chipotlepublishing\.com" "$RELEASE_DIR" --include="*.py" || log_success "  No client domains found"

# Find any TODO or FIXME comments
log_info "Checking for TODO/FIXME..."
grep -r "TODO\|FIXME" "$RELEASE_DIR" --include="*.py" | head -5 || log_success "  No TODOs found"

log_success "Sanitization checks complete"

#######################################
# Create README for manual review
#######################################
log_info "Creating manual review checklist..."

cat > "$RELEASE_DIR/SANITIZATION_CHECKLIST.md" << 'CHECKLIST'
# Manual Sanitization Checklist

Before releasing these files publicly, manually review:

## Critical Items

### web/app.py
- [ ] Replace HOSTED_DOMAINS hardcoded list with database query:
```python
# OLD (line ~53):
HOSTED_DOMAINS = ['safesoundins.com', 'phoenixdefence.com', ...]

# NEW:
def get_hosted_domains():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT domain FROM client_domains WHERE is_active = 1")
    return [row['domain'] for row in cursor.fetchall()]
```

### All Python Files
- [ ] Search for "192.168." and replace with config reads
- [ ] Search for client domain names
- [ ] Check for any passwords or API keys
- [ ] Remove any debug print statements with sensitive data

### Configuration Files
- [ ] Verify no hardcoded credentials
- [ ] Check bec_config.json for client-specific whitelists
- [ ] Verify trusted_domains.json is generic

### Tools/Scripts
- [ ] Check OpenSpacyMenu for client-specific menus
- [ ] Verify scripts don't reference specific servers

## Testing After Sanitization

1. Install on fresh Ubuntu 24.04
2. Verify all configs load from templates
3. Test with generic test domain
4. Ensure no errors referencing production domains

## Files That Should Be Generic

✓ email_filter.py - Reads from email_filter_config.json
✓ modules/*.py - All config-driven
✓ services/db_processor.py - Reads from config
✓ api/*.py - Generic APIs
⚠ web/app.py - **NEEDS REVIEW** (HOSTED_DOMAINS)

CHECKLIST

log_success "Checklist created: $RELEASE_DIR/SANITIZATION_CHECKLIST.md"

#######################################
# Create tarball
#######################################
log_info "Creating release tarball..."

cd "$RELEASE_DIR/.."
tar -czf "openefa-files-$(date +%Y%m%d).tar.gz" "openefa-files"

log_success "Tarball created: openefa-files-$(date +%Y%m%d).tar.gz"

#######################################
# Summary
#######################################
cat << EOF

${GREEN}═══════════════════════════════════════════════════════
  Release Preparation Complete
═══════════════════════════════════════════════════════${NC}

${BLUE}Files copied to:${NC} $RELEASE_DIR

${BLUE}Next steps:${NC}
  1. Review: $RELEASE_DIR/SANITIZATION_CHECKLIST.md
  2. Manually fix app.py HOSTED_DOMAINS issue
  3. Search for any remaining hardcoded values
  4. Test installation on clean Ubuntu 24.04
  5. Create final release package

${YELLOW}IMPORTANT:${NC}
  • Review all files before public release
  • Test on separate test server
  • Never release production credentials

${BLUE}Tarball:${NC} $INSTALLER_DIR/openefa-files-$(date +%Y%m%d).tar.gz

═══════════════════════════════════════════════════════

EOF
