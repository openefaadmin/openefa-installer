#!/bin/bash
#
# dependencies.sh - Enhanced dependency installation for OpenEFA
# Part of the OpenEFA project (https://openefa.com)
#
# This module handles:
# - Minimal Ubuntu compatibility (diagnostic tools first)
# - Additional Python packages (spacy, textblob, etc.)
# - Utils module creation (fixes "No module named 'utils'" bug)
#

# Source common functions
source "${SCRIPT_DIR}/lib/common.sh"

#
# Install diagnostic tools FIRST (minimal Ubuntu compatibility)
# This fixes installations on minimal Ubuntu that lack basic networking tools
#
install_diagnostic_tools() {
    section "Installing Diagnostic Tools (Minimal Ubuntu Compatibility)"

    local diagnostic_packages=(
        "iputils-ping"
        "dnsutils"
        "net-tools"
        "lsb-release"
        "wget"
        "curl"
    )

    info "These tools are required for pre-flight checks and may be missing on minimal Ubuntu..."

    # Update package lists quietly
    apt-get update -qq >/dev/null 2>&1

    local installed_count=0
    local already_installed_count=0

    for pkg in "${diagnostic_packages[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            success "$pkg (already installed)"
            ((already_installed_count++))
        else
            info "Installing $pkg..."
            if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" 2>&1 | grep -v "^debconf:" >/dev/null; then
                success "$pkg installed"
                ((installed_count++))
            else
                warn "Could not install $pkg (non-critical, continuing)"
            fi
        fi
    done

    if [ $installed_count -gt 0 ]; then
        success "Installed $installed_count diagnostic tools"
    fi
    if [ $already_installed_count -gt 0 ]; then
        info "$already_installed_count tools already present"
    fi

    save_state "diagnostic_tools_installed"
    return 0
}

#
# Install additional Python packages required for OpenEFA
# These are critical packages not in the base list
#
install_additional_python_packages() {
    section "Installing Additional Python Packages"

    local venv_path="/opt/spacyserver/venv"

    if [ ! -d "$venv_path" ]; then
        error "Virtual environment not found at $venv_path"
        return 1
    fi

    info "Installing spaCy, textblob, and other analysis packages..."

    local additional_packages=(
        "spacy==3.8.7"
        "textblob"
        "geoip2"
        "PyMuPDF"
    )

    for pkg in "${additional_packages[@]}"; do
        info "Installing $pkg..."
        if run_cmd "${venv_path}/bin/pip install -q '$pkg'" "Failed to install $pkg"; then
            success "$pkg installed"
        else
            warn "$pkg installation failed (may affect some features)"
        fi
    done

    save_state "additional_python_packages_installed"
    return 0
}

#
# Download spaCy language models
#
install_spacy_models() {
    section "Downloading spaCy Language Models"

    local venv_path="/opt/spacyserver/venv"

    if [ ! -d "$venv_path" ]; then
        error "Virtual environment not found"
        return 1
    fi

    # Check if spacy is installed
    if ! ${venv_path}/bin/python3 -c "import spacy" 2>/dev/null; then
        warn "spaCy not installed, skipping model download"
        return 0
    fi

    # Check if model is already downloaded
    if ${venv_path}/bin/python3 -c "import spacy; spacy.load('en_core_web_lg')" 2>/dev/null; then
        success "spaCy model 'en_core_web_lg' already installed"
        return 0
    fi

    info "Downloading en_core_web_lg model (this may take a few minutes, ~800MB)..."

    if run_cmd "${venv_path}/bin/python3 -m spacy download en_core_web_lg" "Failed to download spaCy model"; then
        success "spaCy model downloaded successfully"
        save_state "spacy_model_installed"
        return 0
    else
        warn "spaCy model download failed (AI features will be limited)"
        return 0  # Non-fatal
    fi
}

#
# Create utils module (fixes "No module named 'utils'" bug)
# This is a critical fix for modules that import from utils.logging
#
create_utils_module() {
    section "Creating Utils Module"

    local utils_dir="/opt/spacyserver/utils"

    info "Creating utils module directory..."
    mkdir -p "$utils_dir"

    # Create __init__.py
    info "Creating utils/__init__.py..."
    cat > "${utils_dir}/__init__.py" << 'EOF'
"""
OpenSpacy Utils Module
Provides shared utilities for email analysis modules
"""

__version__ = "1.0.0"
EOF

    # Create logging.py
    info "Creating utils/logging.py..."
    cat > "${utils_dir}/logging.py" << 'EOF'
"""
Logging utilities for OpenSpacy email analysis modules
Provides safe logging functions that prevent output buffer overflows
"""

import sys
import datetime


def safe_log(message: str, level: str = "INFO", max_length: int = 500):
    """
    Safe logging to stderr with length limit

    Args:
        message: Log message to output
        level: Log level (INFO, WARNING, ERROR, DEBUG)
        max_length: Maximum message length before truncation
    """
    try:
        if isinstance(message, str) and len(message) > max_length:
            message = message[:max_length-3] + "..."

        # Write to debug file for persistence
        try:
            with open('/tmp/email_filter_debug.log', 'a') as f:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{timestamp}] [{level}] {message}\n")
        except:
            pass

        # Only critical messages to stderr for postfix
        if level in ["ERROR", "CRITICAL"] or any(x in message for x in ["ERROR", "CRITICAL", "❌", "TIMEOUT"]):
            print(f"[{level}] {message}", file=sys.stderr)
    except Exception as e:
        # Failsafe - if logging itself fails, try basic output
        try:
            print(f"[LOGGING ERROR] {str(e)}", file=sys.stderr)
        except:
            pass


def log_sentiment_debug(message: str):
    """Debug logging for sentiment analysis"""
    safe_log(message, level="DEBUG")


def log_debug(message: str):
    """General debug logging"""
    safe_log(message, level="DEBUG")


def log_warning(message: str):
    """Warning level logging"""
    safe_log(message, level="WARNING")


def log_error(message: str):
    """Error level logging"""
    safe_log(message, level="ERROR")


def log_info(message: str):
    """Info level logging"""
    safe_log(message, level="INFO")
EOF

    # Set ownership
    if id "spacy-filter" &>/dev/null 2>&1; then
        chown -R spacy-filter:spacy-filter "$utils_dir"
        success "Utils module created and ownership set"
    else
        success "Utils module created (ownership will be set later)"
    fi

    # Test the module
    if python3 -c "import sys; sys.path.insert(0, '/opt/spacyserver'); from utils.logging import safe_log" 2>/dev/null; then
        success "Utils module verified working"
    else
        warn "Utils module created but import test failed"
    fi

    save_state "utils_module_created"
    return 0
}

#
# Install all enhanced dependencies
# This is the main function to call from the installer
#
install_enhanced_dependencies() {
    section "Enhanced Dependency Installation"

    # Step 1: Install diagnostic tools FIRST (minimal Ubuntu fix)
    install_diagnostic_tools || return 1

    # Step 2: Install additional Python packages
    install_additional_python_packages || warn "Some Python packages failed (continuing)"

    # Step 3: Download spaCy models
    install_spacy_models || warn "spaCy model download failed (continuing)"

    # Step 4: Create utils module (critical fix)
    create_utils_module || return 1

    success "Enhanced dependencies installed successfully"
    return 0
}
