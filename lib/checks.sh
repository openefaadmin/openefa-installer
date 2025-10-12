#!/bin/bash
#
# checks.sh - Pre-flight system checks for OpenEFA installer
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

# Minimum system requirements
readonly MIN_RAM_MB=2048
readonly MIN_DISK_GB=20
readonly MIN_CORES=2

#
# Check if OS is supported (Ubuntu 24.04 or 22.04)
#
check_os() {
    info "Checking operating system..."

    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect operating system"
        return 1
    fi

    source /etc/os-release

    # Check if Ubuntu
    if [[ "${ID}" != "ubuntu" ]]; then
        error "Unsupported OS: ${ID}"
        error "OpenEFA requires Ubuntu 24.04 LTS or 22.04 LTS"
        return 1
    fi

    # Check version
    case "${VERSION_ID}" in
        24.04)
            success "OS: Ubuntu 24.04 LTS (Supported)"
            return 0
            ;;
        22.04)
            success "OS: Ubuntu 22.04 LTS (Supported)"
            return 0
            ;;
        *)
            error "Unsupported Ubuntu version: ${VERSION_ID}"
            error "OpenEFA requires Ubuntu 24.04 LTS or 22.04 LTS"
            return 1
            ;;
    esac
}

#
# Check if system has sufficient RAM
#
check_ram() {
    info "Checking system memory..."

    local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local total_ram_mb=$((total_ram_kb / 1024))

    if [[ ${total_ram_mb} -lt ${MIN_RAM_MB} ]]; then
        error "Insufficient RAM: ${total_ram_mb} MB (minimum: ${MIN_RAM_MB} MB)"
        return 1
    fi

    success "RAM: ${total_ram_mb} MB (OK)"
    return 0
}

#
# Check if system has sufficient disk space
#
check_disk() {
    info "Checking disk space..."

    local available_gb=$(df -BG /opt | tail -1 | awk '{print $4}' | sed 's/G//')

    if [[ ${available_gb} -lt ${MIN_DISK_GB} ]]; then
        error "Insufficient disk space: ${available_gb} GB available (minimum: ${MIN_DISK_GB} GB)"
        return 1
    fi

    success "Disk space: ${available_gb} GB available (OK)"
    return 0
}

#
# Check if system has sufficient CPU cores
#
check_cpu() {
    info "Checking CPU cores..."

    local cpu_cores=$(nproc)

    if [[ ${cpu_cores} -lt ${MIN_CORES} ]]; then
        warn "Low CPU cores: ${cpu_cores} (recommended: ${MIN_CORES}+)"
        return 0  # Warning only, not fatal
    fi

    success "CPU cores: ${cpu_cores} (OK)"
    return 0
}

#
# Check if required commands are available
#
check_commands() {
    info "Checking required system commands..."

    local required_commands=("curl" "systemctl" "awk" "grep" "sed")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "${cmd}" &> /dev/null; then
            missing_commands+=("${cmd}")
        fi
    done

    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        error "Missing required commands: ${missing_commands[*]}"
        return 1
    fi

    success "Required commands: All present"
    return 0
}

#
# Check if Postfix is already installed (conflict detection)
#
check_existing_postfix() {
    info "Checking for existing Postfix installation..."

    if systemctl is-active --quiet postfix; then
        warn "Postfix is already running"
        warn "OpenEFA will reconfigure Postfix for email filtering"

        if ! confirm "Continue and reconfigure Postfix?"; then
            error "Installation cancelled by user"
            return 1
        fi
    else
        success "No conflicting Postfix installation"
    fi

    return 0
}

#
# Check if MariaDB/MySQL is already installed
#
check_existing_database() {
    info "Checking for existing database server..."

    if systemctl is-active --quiet mariadb || systemctl is-active --quiet mysql; then
        warn "Database server is already running (will be configured for OpenEFA)"
        success "Will use existing MariaDB/MySQL installation"
    else
        success "No existing database server detected (will install MariaDB)"
    fi

    return 0
}

#
# Check if port 25 (SMTP) is available
#
check_port_25() {
    info "Checking if port 25 (SMTP) is available..."

    if ss -tuln | grep -q ":25 "; then
        warn "Port 25 is already in use"
        ss -tulnp | grep ":25 "
        
        if ! confirm "Continue anyway?"; then
            error "Installation cancelled by user"
            return 1
        fi
    else
        success "Port 25 is available"
    fi

    return 0
}

#
# Check if ports 5001-5003 (APIs) are available
#
check_api_ports() {
    info "Checking API ports (5001-5003, 5500)..."

    local ports=(5001 5002 5003 5500)
    local in_use=()

    for port in "${ports[@]}"; do
        if ss -tuln | grep -q ":${port} "; then
            in_use+=("${port}")
        fi
    done

    if [[ ${#in_use[@]} -gt 0 ]]; then
        warn "Ports already in use: ${in_use[*]}"
        
        if ! confirm "Continue anyway?"; then
            error "Installation cancelled by user"
            return 1
        fi
    else
        success "API ports are available"
    fi

    return 0
}

#
# Check network connectivity
#
check_network() {
    info "Checking network connectivity..."

    # Try to reach common DNS servers
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null || ping -c 1 -W 2 1.1.1.1 &> /dev/null; then
        success "Network connectivity: OK"
        return 0
    else
        error "No network connectivity detected"
        error "Internet access is required for installation"
        return 1
    fi
}

#
# Check DNS resolution
#
check_dns() {
    info "Checking DNS resolution..."

    if host google.com &> /dev/null || host cloudflare.com &> /dev/null; then
        success "DNS resolution: OK"
        return 0
    else
        warn "DNS resolution issues detected"
        return 0  # Warning only
    fi
}

#
# Check if installation is already present
#
check_existing_installation() {
    info "Checking for existing OpenEFA installation..."

    if [[ -d "/opt/spacyserver" ]]; then
        warn "Found existing OpenEFA installation at /opt/spacyserver"
        export UPGRADE_MODE=1
        info "Running in UPGRADE mode (will preserve existing data)"
    else
        success "No existing installation detected"
        export UPGRADE_MODE=0
    fi

    return 0
}

#
# Check system timezone
#
check_timezone() {
    info "Checking system timezone..."

    local timezone=$(timedatectl show -p Timezone --value 2>/dev/null)

    if [[ -z "${timezone}" ]]; then
        warn "Cannot detect system timezone"
    else
        info "System timezone: ${timezone}"
    fi

    return 0
}

#
# Run all pre-flight checks
#
run_all_checks() {
    section "Pre-Flight System Checks"

    local checks=(
        "check_os"
        "check_ram"
        "check_disk"
        "check_cpu"
        "check_commands"
        "check_network"
        "check_dns"
        "check_existing_installation"
        "check_existing_postfix"
        "check_existing_database"
        "check_port_25"
        "check_api_ports"
        "check_timezone"
    )

    local failed_checks=0

    for check in "${checks[@]}"; do
        if ! ${check}; then
            ((failed_checks++))
        fi
        echo ""
    done

    if [[ ${failed_checks} -gt 0 ]]; then
        error "${failed_checks} pre-flight check(s) failed"
        return 1
    fi

    success "All pre-flight checks passed"
    return 0
}

# Export functions
export -f check_os check_ram check_disk check_cpu check_commands
export -f check_existing_postfix check_existing_database check_port_25
export -f check_api_ports check_network check_dns check_existing_installation
export -f check_timezone run_all_checks
