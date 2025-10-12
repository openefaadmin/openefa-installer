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

        # Download English language model
        if run_cmd "${venv_path}/bin/python -m spacy download en_core_web_sm" "Failed to download SpaCy model"; then
            success "SpaCy language model downloaded"
        else
            warn "SpaCy model download failed (can be installed later)"
        fi
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

    # Enable and start MariaDB
    if run_cmd "systemctl enable mariadb" "Failed to enable MariaDB"; then
        success "MariaDB enabled"
    else
        return 1
    fi

    if run_cmd "systemctl start mariadb" "Failed to start MariaDB"; then
        success "MariaDB started"
    else
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
    install_python_packages || return 1

    save_state "all_packages_installed"
    success "All packages installed successfully"
    return 0
}

# Export functions
export -f update_package_lists install_core_packages install_utility_packages
export -f install_python_packages configure_mariadb configure_redis
export -f install_all_packages
