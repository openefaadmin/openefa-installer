#!/bin/bash
#
# common.sh - Common utility functions for OpenEFA installer
# Part of the OpenEFA project (https://openefa.com)
#

# Prevent multiple sourcing
[[ -n "${OPENEFA_COMMON_LOADED:-}" ]] && return 0
readonly OPENEFA_COMMON_LOADED=1

# Color definitions
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_MAGENTA='\033[0;35m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_WHITE='\033[1;37m'
readonly COLOR_RESET='\033[0m'

# Log file location
readonly LOG_FILE="/var/log/openefa_install.log"
readonly LOG_DIR="/var/log"

# Installation state file for rollback
readonly STATE_FILE="/tmp/openefa_install_state"

#
# Initialize logging
#
init_logging() {
    # Ensure log directory exists
    mkdir -p "${LOG_DIR}"

    # Create/truncate log file
    : > "${LOG_FILE}"

    # Log installation start
    echo "=== OpenEFA Installation Started: $(date) ===" >> "${LOG_FILE}"
    echo "User: $(whoami)" >> "${LOG_FILE}"
    echo "Hostname: $(hostname)" >> "${LOG_FILE}"
    echo "OS: $(lsb_release -d 2>/dev/null | cut -f2)" >> "${LOG_FILE}"
    echo "" >> "${LOG_FILE}"
}

#
# Log message to file and optionally display
# Args: $1=message, $2=level (INFO|WARN|ERROR|DEBUG)
#
log_message() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Write to log file
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
}

#
# Display info message (green)
#
info() {
    local message="$1"
    echo -e "${COLOR_GREEN}[INFO]${COLOR_RESET} ${message}"
    log_message "${message}" "INFO"
}

#
# Display success message (bright green)
#
success() {
    local message="$1"
    echo -e "${COLOR_GREEN}✓ ${message}${COLOR_RESET}"
    log_message "${message}" "SUCCESS"
}

#
# Display warning message (yellow)
#
warn() {
    local message="$1"
    echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} ${message}"
    log_message "${message}" "WARN"
}

#
# Display error message (red)
#
error() {
    local message="$1"
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} ${message}"
    log_message "${message}" "ERROR"
}

#
# Display debug message (cyan) - only if DEBUG=1
#
debug() {
    local message="$1"
    log_message "${message}" "DEBUG"

    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${COLOR_CYAN}[DEBUG]${COLOR_RESET} ${message}"
    fi
}

#
# Display section header (magenta)
#
section() {
    local message="$1"
    echo ""
    echo -e "${COLOR_MAGENTA}▶ ${message}${COLOR_RESET}"
    echo ""
    log_message "=== ${message} ===" "SECTION"
}

#
# Display OpenEFA banner
#
show_banner() {
    clear 2>/dev/null || true  # Clear screen if terminal available
    echo -e "${COLOR_CYAN}"
    cat << 'EOF'
   ____                   _____ _____ _
  / __ \                 |  ___|  ___/ \
 | |  | |_ __   ___ _ __ | |__ | |_ / _ \
 | |  | | '_ \ / _ \ '_ \|  __||  _/ ___ \
 | |__| | |_) |  __/ | | | |___| |/ /   \ \
  \____/| .__/ \___|_| |_|_____|_/_/     \_\
        | |    Email Security System
        |_|    https://openefa.com
EOF
    echo -e "${COLOR_RESET}"
    echo "  Version 1.0.0 - GPL Licensed"
    echo "  Successor to the EFA Project"
    echo ""
}

#
# Display progress bar
# Args: $1=current, $2=total, $3=description
#
progress_bar() {
    local current=$1
    local total=$2
    local description="${3:-}"
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))

    # Build progress bar
    local bar="["
    for ((i=0; i<filled; i++)); do bar+="="; done
    for ((i=0; i<empty; i++)); do bar+=" "; done
    bar+="]"

    # Display with description
    echo -ne "\r${COLOR_BLUE}${bar} ${percent}%${COLOR_RESET} ${description}    "

    # Newline if complete
    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

#
# Save installation state (for rollback)
# Args: $1=step_name
#
save_state() {
    local step_name="$1"
    echo "${step_name}:$(date +%s)" >> "${STATE_FILE}"
    log_message "State saved: ${step_name}" "STATE"
}

#
# Check if step already completed (for resume)
# Args: $1=step_name
# Returns: 0 if completed, 1 if not
#
is_step_completed() {
    local step_name="$1"

    if [[ -f "${STATE_FILE}" ]]; then
        grep -q "^${step_name}:" "${STATE_FILE}"
        return $?
    fi

    return 1
}

#
# Cleanup state file
#
cleanup_state() {
    rm -f "${STATE_FILE}"
    log_message "State file cleaned up" "STATE"
}

#
# Exit with error message and code
# Args: $1=message, $2=exit_code (default 1)
#
die() {
    local message="$1"
    local exit_code="${2:-1}"

    error "${message}"
    error "Installation failed. Check log: ${LOG_FILE}"

    exit "${exit_code}"
}

#
# Check if script is run as root
#
require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)" 1
    fi
}

#
# Run command and check for errors
# Args: $1=command, $2=error_message
#
run_cmd() {
    local cmd="$1"
    local error_msg="${2:-Command failed}"

    debug "Running: ${cmd}"

    if eval "${cmd}" >> "${LOG_FILE}" 2>&1; then
        return 0
    else
        local exit_code=$?
        error "${error_msg}"
        debug "Exit code: ${exit_code}"
        return ${exit_code}
    fi
}

#
# Confirm action with user
# Args: $1=prompt
# Returns: 0 if yes, 1 if no
#
confirm() {
    local prompt="$1"
    local response

    while true; do
        read -p "${prompt} [y/N]: " response
        case "${response}" in
            [Yy]|[Yy][Ee][Ss])
                return 0
                ;;
            [Nn]|[Nn][Oo]|"")
                return 1
                ;;
            *)
                echo "Please answer yes or no."
                ;;
        esac
    done
}

#
# Display installation summary
# Args: $1=status (SUCCESS|FAILED), $2=duration_seconds
#
show_summary() {
    local status="$1"
    local duration="$2"
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    echo ""
    echo "========================================"

    if [[ "${status}" == "SUCCESS" ]]; then
        echo -e "${COLOR_GREEN}Installation Status: SUCCESS${COLOR_RESET}"
    else
        echo -e "${COLOR_RED}Installation Status: FAILED${COLOR_RESET}"
    fi

    echo "Duration: ${minutes}m ${seconds}s"
    echo "Log file: ${LOG_FILE}"
    echo "========================================"
    echo ""
}

#
# Backup file with timestamp
# Args: $1=file_path
#
backup_file() {
    local file_path="$1"

    if [[ -f "${file_path}" ]]; then
        local backup_path="${file_path}.backup.$(date +%Y%m%d_%H%M%S)"
        cp -p "${file_path}" "${backup_path}"
        info "Backed up: ${file_path} -> ${backup_path}"
        log_message "File backed up: ${file_path}" "BACKUP"
    fi
}

#
# Create directory with proper permissions
# Args: $1=dir_path, $2=owner, $3=permissions
#
create_directory() {
    local dir_path="$1"
    local owner="${2:-root:root}"
    local perms="${3:-755}"

    if [[ ! -d "${dir_path}" ]]; then
        mkdir -p "${dir_path}"
        chown "${owner}" "${dir_path}"
        chmod "${perms}" "${dir_path}"
        debug "Created directory: ${dir_path} (${owner}:${perms})"
    fi
}

#
# Download file with retry
# Args: $1=url, $2=destination, $3=max_retries (default 3)
#
download_file() {
    local url="$1"
    local dest="$2"
    local max_retries="${3:-3}"
    local retry=0

    while [[ $retry -lt $max_retries ]]; do
        if curl -fsSL "${url}" -o "${dest}"; then
            success "Downloaded: ${url}"
            return 0
        else
            retry=$((retry + 1))
            warn "Download failed (attempt ${retry}/${max_retries})"
            sleep 2
        fi
    done

    error "Failed to download: ${url}"
    return 1
}

# Export functions for use in other scripts
export -f init_logging log_message info success warn error debug section
export -f show_banner progress_bar save_state is_step_completed cleanup_state
export -f die require_root run_cmd confirm show_summary backup_file
export -f create_directory download_file
