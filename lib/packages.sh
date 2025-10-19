#!/bin/bash
#
# packages.sh - System package installation for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Update package lists
#
update_package_lists() {
    info "Updating package lists..."

    if run_cmd "apt-get update" "Failed to update package lists"; then
        success "Package lists updated"
        save_state "package_lists_updated"
        return 0
    else
        return 1
    fi
}

#
# Install core system packages
#
install_core_packages() {
    section "Installing Core System Packages"

    local packages=(
        "postfix"
        "postfix-pcre"
        "mariadb-server"
        "mariadb-client"
        "redis-server"
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "libmariadb-dev"
        "pkg-config"
        "clamav"
        "clamav-daemon"
        "clamav-freshclam"
        "cron"
    )

    info "Installing: ${packages[*]}"

    # Set postfix to no-configuration during install
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections

    if run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${packages[*]}" "Failed to install core packages"; then
        success "Core packages installed"
        save_state "core_packages_installed"
        return 0
    else
        return 1
    fi
}

#
# Install additional utility packages
#
install_utility_packages() {
    info "Installing utility packages..."

    local packages=(
        "curl"
        "wget"
        "git"
        "vim"
        "nano"
        "htop"
        "net-tools"
        "dnsutils"
        "telnet"
        "mailutils"
        "swaks"
        "logrotate"
        "certbot"
        "ssl-cert"
        "iputils-ping"
    )

    if run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${packages[*]}" "Failed to install utility packages"; then
        success "Utility packages installed"
        save_state "utility_packages_installed"
        return 0
    else
        warn "Some utility packages failed to install (non-fatal)"
        return 0  # Non-fatal
    fi
}

#
# Install Python packages in virtual environment
#
install_python_packages() {
    section "Setting Up Python Environment"

    local venv_path="/opt/spacyserver/venv"

    # Create virtual environment
    info "Creating Python virtual environment..."
    if run_cmd "python3 -m venv ${venv_path}" "Failed to create virtual environment"; then
        success "Virtual environment created"
    else
        return 1
    fi

    # Activate and install packages
    info "Installing Python packages..."
    
    local pip_packages=(
        "numpy>=2.3.0"
        "Flask==3.0.0"
        "Flask-CORS==4.0.0"
        "Flask-Login==0.6.3"
        "redis==5.0.1"
        "mysql-connector-python==8.2.0"
        "pymysql==1.1.0"
        "python-dotenv==1.0.0"
        "SQLAlchemy==2.0.23"
        "dnspython==2.4.2"
        "requests==2.31.0"
        "cryptography==41.0.7"
        "Pillow==10.1.0"
        "PyPDF2==3.0.1"
        "pyzbar==0.1.9"
        "qrcode==7.4.2"
        "python-Levenshtein==0.23.0"
        "bcrypt==4.1.2"
        "pandas==2.1.4"
        "matplotlib==3.8.2"
        "seaborn==0.13.0"
        "reportlab==4.0.7"
        "psutil==5.9.6"
        "pyspf==2.0.14"
        "py3dns==4.0.2"
        "dkimpy==1.1.8"
        "email-validator==2.3.0"
        "pyclamd==0.4.0"
    )

    # Install base packages
    if run_cmd "${venv_path}/bin/pip install --upgrade pip setuptools wheel" "Failed to upgrade pip"; then
        success "Pip upgraded"
    else
        return 1
    fi

    # Install packages
    for package in "${pip_packages[@]}"; do
        info "Installing ${package}..."
        if ! ${venv_path}/bin/pip install "${package}" >> "${LOG_FILE}" 2>&1; then
            warn "Failed to install ${package} (will retry)"
        fi
    done

    # Install SpaCy packages based on module tier
    if [[ "${MODULE_TIER:-2}" == "3" ]]; then
        info "Installing SpaCy AI models (Tier 3 - this may take a few minutes)..."

        if run_cmd "${venv_path}/bin/pip install spacy==3.7.2" "Failed to install spacy"; then
            success "SpaCy installed"
        else
            return 1
        fi

        # Download English language model (large for better accuracy)
        if run_cmd "${venv_path}/bin/python -m spacy download en_core_web_lg" "Failed to download SpaCy model"; then
            success "SpaCy language model downloaded"
        else
            warn "SpaCy model download failed (can be installed later)"
        fi
    fi

    # Rebuild pandas, matplotlib, and seaborn against NumPy 2.x
    # This ensures binary compatibility with the installed numpy version
    info "Rebuilding data science packages for NumPy 2.x compatibility..."
    if ${venv_path}/bin/pip uninstall -y pandas matplotlib seaborn >> "${LOG_FILE}" 2>&1; then
        if ${venv_path}/bin/pip install --no-cache-dir pandas matplotlib seaborn >> "${LOG_FILE}" 2>&1; then
            success "Data science packages rebuilt successfully"
        else
            warn "Package rebuild had issues (may affect SpacyWeb)"
        fi
    else
        warn "Could not rebuild packages (continuing anyway)"
    fi

    success "Python environment configured"
    save_state "python_packages_installed"
    return 0
}

#
# Configure MariaDB service
#
configure_mariadb() {
    info "Configuring MariaDB service..."

    # Verify MariaDB package is actually installed
    if ! dpkg -l | grep -q "^ii.*mariadb-server"; then
        error "MariaDB server package not installed"
        info "Attempting to install MariaDB..."
        if ! apt-get install -y mariadb-server mariadb-client; then
            error "Failed to install MariaDB"
            return 1
        fi
    fi

    # Verify MariaDB data directory was created by package installation
    if [[ ! -d /var/lib/mysql ]]; then
        error "MariaDB data directory not created at /var/lib/mysql"
        error "Package installation may have failed"
        return 1
    fi

    # Enable and start MariaDB
    if run_cmd "systemctl enable mariadb" "Failed to enable MariaDB"; then
        success "MariaDB enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start mariadb" "Failed to start MariaDB"; then
        success "MariaDB started"
    else
        error "MariaDB failed to start - checking logs..."
        journalctl -xeu mariadb.service -n 20 --no-pager >> "${LOG_FILE}" 2>&1
        return 1
    fi

    # Wait for MariaDB to be ready
    info "Waiting for MariaDB to be ready..."
    local retries=0
    while [[ $retries -lt 30 ]]; do
        if mysqladmin ping &> /dev/null; then
            success "MariaDB is ready"
            save_state "mariadb_configured"
            return 0
        fi
        sleep 1
        ((retries++))
    done

    error "MariaDB failed to start properly"
    return 1
}

#
# Configure Redis service
#
configure_redis() {
    info "Configuring Redis service..."

    # Enable and start Redis
    if run_cmd "systemctl enable redis-server" "Failed to enable Redis"; then
        success "Redis enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start redis-server" "Failed to start Redis"; then
        success "Redis started"
    else
        return 1
    fi

    # Test Redis connectivity
    if redis-cli ping &> /dev/null; then
        success "Redis is ready"
        save_state "redis_configured"
        return 0
    else
        error "Redis failed to start properly"
        return 1
    fi
}

#
# Configure ClamAV service
#
configure_clamav() {
    info "Configuring ClamAV antivirus service..."

    # Stop freshclam if running (it conflicts during initial setup)
    systemctl stop clamav-freshclam 2>/dev/null || true

    # Update virus definitions
    info "Downloading virus definitions (this may take a few minutes)..."
    if run_cmd "freshclam" "Failed to download virus definitions"; then
        success "Virus definitions downloaded"
    else
        warn "Failed to download definitions, will try via service"
    fi

    # Enable and start freshclam service
    if run_cmd "systemctl enable clamav-freshclam" "Failed to enable freshclam"; then
        success "Freshclam enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start clamav-freshclam" "Failed to start freshclam"; then
        success "Freshclam started"
    else
        warn "Freshclam service issue (non-fatal)"
    fi

    # Wait for virus definitions
    info "Waiting for virus definitions to be available..."
    local retries=0
    while [[ $retries -lt 60 ]]; do
        if [[ -f /var/lib/clamav/daily.cvd ]] || [[ -f /var/lib/clamav/daily.cld ]]; then
            success "Virus definitions available"
            break
        fi
        sleep 2
        ((retries++))
    done

    # Enable and start ClamAV daemon
    if run_cmd "systemctl enable clamav-daemon" "Failed to enable ClamAV daemon"; then
        success "ClamAV daemon enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start clamav-daemon" "Failed to start ClamAV daemon"; then
        success "ClamAV daemon started"
    else
        warn "ClamAV daemon will start automatically"
    fi

    # Add spacy-filter user to clamav group
    if run_cmd "usermod -a -G clamav spacy-filter" "Failed to add user to clamav group"; then
        success "Permissions configured"
    else
        warn "Permission configuration failed (non-fatal)"
    fi

    # Verify ClamAV is working
    info "Verifying ClamAV installation..."
    sleep 5  # Give daemon time to start

    if systemctl is-active --quiet clamav-daemon; then
        success "ClamAV daemon is running"
    else
        warn "ClamAV daemon not yet started (will start automatically)"
    fi

    save_state "clamav_configured"
    success "ClamAV antivirus configured"
    return 0
}

#
# Install all packages
#
install_all_packages() {
    if is_step_completed "all_packages_installed"; then
        info "Packages already installed, skipping..."
        return 0
    fi

    update_package_lists || return 1
    install_core_packages || return 1
    install_utility_packages || return 1
    configure_mariadb || return 1
    configure_redis || return 1
    configure_clamav || return 1
    install_python_packages || return 1
    install_enhanced_dependencies || warn "Some enhanced dependencies failed (continuing)"

    save_state "all_packages_installed"
    success "All packages installed successfully"
    return 0
}

# Export functions
export -f update_package_lists install_core_packages install_utility_packages
export -f install_python_packages configure_mariadb configure_redis configure_clamav
export -f install_all_packages
