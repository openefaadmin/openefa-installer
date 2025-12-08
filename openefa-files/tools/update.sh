#!/bin/bash
#
# update.sh - OpenEFA Smart Update Script
# Part of the OpenEFA project (https://openefa.com)
#
# Updates an existing OpenEFA installation while preserving configuration
# and providing automatic backup/rollback capabilities.
#

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Version info
UPDATE_SCRIPT_VERSION="1.0.0"

# Colors
COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[0;34m'
COLOR_CYAN='\033[0;36m'
COLOR_RESET='\033[0m'

# Directories
INSTALL_DIR="/opt/spacyserver"
BACKUP_DIR=""
TEMP_DIR="/tmp/openefa-update-$$"
LOG_FILE="/tmp/openefa-update-$(date +%Y%m%d_%H%M%S).log"

# Load database configuration from environment
if [[ -f /etc/spacy-server/.env ]]; then
    source /etc/spacy-server/.env
fi
: "${DB_NAME:=spacy_email_db}"
: "${DB_USER:=spacy_user}"

# Flags
DRY_RUN=0
FORCE=0
BACKUP_ONLY=0
ROLLBACK=0
COMPONENT=""

#
# Logging functions
#
log() {
    echo -e "$1" | tee -a "${LOG_FILE}"
}

info() {
    log "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

success() {
    log "${COLOR_GREEN}[✓]${COLOR_RESET} $1"
}

warn() {
    log "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"
}

error() {
    log "${COLOR_RED}[ERROR]${COLOR_RESET} $1"
}

section() {
    log ""
    log "${COLOR_CYAN}╔════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
    log "${COLOR_CYAN}║ ${1}${COLOR_RESET}"
    log "${COLOR_CYAN}╚════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
    log ""
}

#
# Show banner
#
show_banner() {
    clear 2>/dev/null || true
    echo -e "${COLOR_CYAN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                    UPDATE OpenEFA                              ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_RESET}"
    echo ""
    info "OpenEFA Smart Update Script v${UPDATE_SCRIPT_VERSION}"
    echo ""
}

#
# Parse command line arguments
#
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=1
                info "Dry run mode enabled (no changes will be made)"
                shift
                ;;
            --force)
                FORCE=1
                warn "Force mode enabled (skipping safety checks)"
                shift
                ;;
            --backup-only)
                BACKUP_ONLY=1
                info "Backup-only mode (will not update)"
                shift
                ;;
            --rollback)
                ROLLBACK=1
                shift
                ;;
            --component)
                COMPONENT="$2"
                info "Component update mode: ${COMPONENT}"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

#
# Show help
#
show_help() {
    cat << EOF
OpenEFA Smart Update Script

Usage: sudo ./update.sh [OPTIONS]

Options:
  --dry-run         Show what would be updated without making changes
  --force           Skip safety checks and force update
  --backup-only     Create backup only, do not update
  --rollback        Restore from most recent backup
  --component NAME  Update specific component (email_filter, modules, web, etc.)
  --help, -h        Show this help message

Examples:
  sudo ./update.sh                        # Standard update
  sudo ./update.sh --dry-run              # Preview changes
  sudo ./update.sh --component modules    # Update only modules
  sudo ./update.sh --rollback             # Restore previous version

For more information: https://openefa.com/docs/updating
EOF
}

#
# Check if running as root
#
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        echo "Please run: sudo ./update.sh"
        exit 1
    fi
}

#
# Check existing installation
#
check_installation() {
    info "Checking for existing OpenEFA installation..."

    if [[ ! -d "${INSTALL_DIR}" ]]; then
        error "OpenEFA is not installed at ${INSTALL_DIR}"
        echo ""
        echo "To install OpenEFA, run:"
        echo "  curl -sSL http://install.openefa.com/install.sh | sudo bash"
        exit 1
    fi

    success "Found OpenEFA installation"
}

#
# Get current version
#
get_current_version() {
    if [[ -f "${INSTALL_DIR}/VERSION" ]]; then
        # Try new format (VERSION=x.x.x) first
        if grep -q "^VERSION=" "${INSTALL_DIR}/VERSION"; then
            source "${INSTALL_DIR}/VERSION"
            info "Current version: ${VERSION:-unknown}"
            info "Installed: ${INSTALLED:-unknown}"
            info "Last updated: ${UPDATED:-never}"
        else
            # Fall back to old format (plain version number)
            VERSION=$(cat "${INSTALL_DIR}/VERSION" | head -1 | tr -d '[:space:]')
            info "Current version: ${VERSION} (legacy format)"
        fi
    else
        warn "No VERSION file found (legacy installation)"
        VERSION="0.9.0"
    fi
}

#
# Check internet connectivity
#
check_internet() {
    info "Checking internet connectivity..."

    if ! curl -s --connect-timeout 5 https://github.com > /dev/null; then
        error "Cannot reach GitHub - check your internet connection"
        exit 1
    fi

    success "Internet connection OK"
}

#
# Check disk space
#
check_disk_space() {
    info "Checking disk space..."

    local available=$(df /opt | tail -1 | awk '{print $4}')
    local required=1048576  # 1GB in KB

    if [[ ${available} -lt ${required} ]]; then
        error "Insufficient disk space (need 1GB free in /opt)"
        exit 1
    fi

    success "Sufficient disk space available"
}

#
# Create backup
#
create_backup() {
    section "Creating Backup"

    BACKUP_DIR="/opt/spacyserver-backup-$(date +%Y%m%d_%H%M%S)"

    info "Backing up to: ${BACKUP_DIR}"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would create backup at ${BACKUP_DIR}"
        return 0
    fi

    # Create backup directory
    mkdir -p "${BACKUP_DIR}"

    # Copy files
    info "Copying files..."
    rsync -a --exclude='logs/*' --exclude='venv/*' "${INSTALL_DIR}/" "${BACKUP_DIR}/"

    # Backup database
    info "Backing up database..."
    mysqldump --defaults-file="${INSTALL_DIR}/config/.my.cnf" $DB_NAME > "${BACKUP_DIR}/database_backup.sql" 2>/dev/null || {
        warn "Database backup failed (non-fatal)"
    }

    # Save service status
    systemctl is-active spacy-db-processor > "${BACKUP_DIR}/service_status.txt" 2>&1 || true
    systemctl is-active spacyweb >> "${BACKUP_DIR}/service_status.txt" 2>&1 || true

    # Save version info
    if [[ -f "${INSTALL_DIR}/VERSION" ]]; then
        cp "${INSTALL_DIR}/VERSION" "${BACKUP_DIR}/"
    fi

    success "Backup created: ${BACKUP_DIR}"
    echo "${BACKUP_DIR}" > /tmp/openefa-last-backup
}

#
# Download latest version
#
download_latest() {
    section "Downloading Latest Version"

    info "Downloading from GitHub..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would download latest version from GitHub"
        return 0
    fi

    # Create temp directory
    mkdir -p "${TEMP_DIR}"
    cd "${TEMP_DIR}"

    # Clone installer repo
    if ! git clone --depth 1 https://github.com/openefaadmin/openefa-installer.git; then
        error "Failed to download from GitHub"
        exit 1
    fi

    success "Downloaded latest version"
}

#
# Compare versions and check if update is needed
#
compare_versions() {
    info "Comparing versions..."

    # Read latest version from downloaded repository
    local latest_version="Unknown"
    if [[ -f "${TEMP_DIR}/openefa-installer/VERSION" ]]; then
        # Parse VERSION=x.x.x format
        latest_version=$(grep "^VERSION=" "${TEMP_DIR}/openefa-installer/VERSION" 2>/dev/null | cut -d= -f2)
        if [[ -z "${latest_version}" ]]; then
            # Try plain text format
            latest_version=$(cat "${TEMP_DIR}/openefa-installer/VERSION" | head -1)
        fi
    fi

    info "Current version: ${VERSION:-Unknown}"
    info "Latest version: ${latest_version}"

    # Compare versions
    if [[ "${VERSION}" == "${latest_version}" ]] && [[ "${VERSION}" != "Unknown" ]]; then
        success "You are already on the latest version ${VERSION}"
        echo ""
        info "No update needed. Your OpenEFA installation is up to date!"
        cleanup
        exit 0
    elif [[ "${latest_version}" == "Unknown" ]]; then
        warn "Could not determine latest version from GitHub"
        if [[ ${FORCE} -eq 0 ]]; then
            error "Update aborted (use --force to override)"
            exit 1
        fi
    else
        success "Update available: ${VERSION} → ${latest_version}"
    fi
}

#
# Update email_filter.py
#
update_email_filter() {
    info "Updating email_filter.py..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update email_filter.py"
        return 0
    fi

    if [[ -f "${TEMP_DIR}/openefa-installer/openefa-files/email_filter.py" ]]; then
        cp "${TEMP_DIR}/openefa-installer/openefa-files/email_filter.py" "${INSTALL_DIR}/"
        chmod 755 "${INSTALL_DIR}/email_filter.py"
        chown spacy-filter:spacy-filter "${INSTALL_DIR}/email_filter.py"
        success "Updated email_filter.py"
    else
        warn "email_filter.py not found in update package"
    fi
}

#
# Update modules
#
update_modules() {
    info "Updating modules..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update modules"
        return 0
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/modules" ]]; then
        rsync -a "${TEMP_DIR}/openefa-installer/openefa-files/modules/" "${INSTALL_DIR}/modules/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/modules"
        chmod -R 640 "${INSTALL_DIR}/modules"/*.py
        success "Updated modules"
    else
        warn "Modules directory not found in update package"
    fi
}

#
# Update services
#
update_services() {
    info "Updating services..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update services"
        return 0
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/services" ]]; then
        rsync -a "${TEMP_DIR}/openefa-installer/openefa-files/services/" "${INSTALL_DIR}/services/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/services"
        chmod -R 640 "${INSTALL_DIR}/services"/*.py
        success "Updated services"
    else
        warn "Services directory not found in update package"
    fi
}

#
# Update web interface
#
update_web() {
    info "Updating web interface..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update web interface"
        return 0
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/web" ]]; then
        # Update Python files
        rsync -a --exclude='*.pyc' "${TEMP_DIR}/openefa-installer/openefa-files/web/" "${INSTALL_DIR}/web/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/web"
        success "Updated web interface"
    else
        warn "Web directory not found in update package"
    fi
}

#
# Update API endpoints
#
update_api() {
    info "Updating API endpoints..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update API endpoints"
        return 0
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/api" ]]; then
        rsync -a "${TEMP_DIR}/openefa-installer/openefa-files/api/" "${INSTALL_DIR}/api/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/api"
        chmod -R 640 "${INSTALL_DIR}/api"/*.py
        success "Updated API endpoints"
    else
        warn "API directory not found in update package"
    fi
}

#
# Update scripts and tools
#
update_scripts() {
    info "Updating scripts and tools..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update scripts and tools"
        return 0
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/scripts" ]]; then
        rsync -a "${TEMP_DIR}/openefa-installer/openefa-files/scripts/" "${INSTALL_DIR}/scripts/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/scripts"
        chmod -R 750 "${INSTALL_DIR}/scripts"/*.sh
        success "Updated scripts"
    fi

    if [[ -d "${TEMP_DIR}/openefa-installer/openefa-files/tools" ]]; then
        rsync -a "${TEMP_DIR}/openefa-installer/openefa-files/tools/" "${INSTALL_DIR}/tools/"
        chown -R spacy-filter:spacy-filter "${INSTALL_DIR}/tools"
        chmod -R 750 "${INSTALL_DIR}/tools"/*.sh
        success "Updated tools"
    fi
}

#
# Update VERSION file
#
update_version_file() {
    info "Updating version information..."

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would update VERSION file"
        return 0
    fi

    # Copy VERSION file from downloaded repository
    if [[ -f "${TEMP_DIR}/openefa-installer/VERSION" ]]; then
        cp "${TEMP_DIR}/openefa-installer/VERSION" "${INSTALL_DIR}/VERSION"
        chown spacy-filter:spacy-filter "${INSTALL_DIR}/VERSION"
        chmod 644 "${INSTALL_DIR}/VERSION"

        # Read the version to display
        local new_version=$(grep "^VERSION=" "${INSTALL_DIR}/VERSION" 2>/dev/null | cut -d= -f2)
        success "Updated VERSION file to ${new_version}"
    else
        warn "VERSION file not found in update package"
    fi
}

#
# Restart services
#
restart_services() {
    section "Restarting Services"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        info "[DRY RUN] Would restart services"
        return 0
    fi

    local services=(
        "spacy-db-processor"
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        info "Restarting ${service}..."
        if systemctl restart "${service}" 2>/dev/null; then
            success "${service} restarted"
        else
            warn "${service} failed to restart (may not be installed)"
        fi
    done
}

#
# Validate services
#
validate_services() {
    section "Validating Services"

    local failed=0
    local services=(
        "spacy-db-processor"
        "spacy-release-api"
        "spacy-whitelist-api"
        "spacy-block-api"
        "spacyweb"
    )

    for service in "${services[@]}"; do
        if systemctl is-active --quiet "${service}"; then
            success "${service} is running"
        else
            error "${service} is not running"
            ((failed++))
        fi
    done

    if [[ ${failed} -gt 0 ]]; then
        error "${failed} service(s) failed validation"
        warn "You may want to rollback: sudo ./update.sh --rollback"
        return 1
    fi

    success "All services validated successfully"
    return 0
}

#
# Perform rollback
#
perform_rollback() {
    section "Performing Rollback"

    if [[ ! -f /tmp/openefa-last-backup ]]; then
        error "No backup found to rollback to"
        exit 1
    fi

    local last_backup=$(cat /tmp/openefa-last-backup)

    if [[ ! -d "${last_backup}" ]]; then
        error "Backup directory not found: ${last_backup}"
        exit 1
    fi

    warn "This will restore OpenEFA from: ${last_backup}"
    read -p "Are you sure? (yes/no): " -r

    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        info "Rollback cancelled"
        exit 0
    fi

    # Stop services
    info "Stopping services..."
    systemctl stop spacy-db-processor spacy-release-api spacy-whitelist-api spacy-block-api spacyweb 2>/dev/null || true

    # Restore files
    info "Restoring files..."
    rsync -a --delete "${last_backup}/" "${INSTALL_DIR}/"

    # Restore database
    if [[ -f "${last_backup}/database_backup.sql" ]]; then
        info "Restoring database..."
        mysql --defaults-file="${INSTALL_DIR}/config/.my.cnf" $DB_NAME < "${last_backup}/database_backup.sql" 2>/dev/null || {
            warn "Database restore failed (you may need to restore manually)"
        }
    fi

    # Restart services
    restart_services

    success "Rollback complete"
}

#
# Cleanup
#
cleanup() {
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

#
# Main update process
#
main() {
    show_banner
    parse_args "$@"

    # Handle rollback
    if [[ ${ROLLBACK} -eq 1 ]]; then
        check_root
        perform_rollback
        exit 0
    fi

    # Pre-flight checks
    section "Pre-Flight Checks"
    check_root
    check_installation
    get_current_version
    check_internet
    check_disk_space

    # Create backup
    create_backup

    if [[ ${BACKUP_ONLY} -eq 1 ]]; then
        success "Backup complete (update skipped)"
        exit 0
    fi

    # Download latest version
    download_latest

    # Compare versions (exits if already up to date)
    compare_versions

    # Perform updates
    section "Updating Components"

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "email_filter" ]]; then
        update_email_filter
    fi

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "modules" ]]; then
        update_modules
    fi

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "services" ]]; then
        update_services
    fi

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "web" ]]; then
        update_web
    fi

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "api" ]]; then
        update_api
    fi

    if [[ -z "${COMPONENT}" ]] || [[ "${COMPONENT}" == "scripts" ]]; then
        update_scripts
    fi

    # Update version file
    update_version_file

    # Restart services
    restart_services

    # Validate
    if ! validate_services; then
        error "Update completed but some services failed validation"
        warn "Backup available at: ${BACKUP_DIR}"
        warn "To rollback: sudo ./update.sh --rollback"
        exit 1
    fi

    # Cleanup
    cleanup

    # Success
    section "Update Complete"
    success "OpenEFA has been updated successfully!"
    echo ""
    info "Backup saved to: ${BACKUP_DIR}"
    info "Log file: ${LOG_FILE}"
    echo ""

    if [[ ${DRY_RUN} -eq 1 ]]; then
        warn "This was a DRY RUN - no changes were actually made"
    fi
}

# Run main function
main "$@"
