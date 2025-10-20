#!/bin/bash
#
# bootstrap.sh - OpenEFA Installer Bootstrap Script
# Downloads and runs the OpenEFA installer from GitHub
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/bootstrap.sh | sudo bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# GitHub repository details
GITHUB_USER="openefaadmin"
GITHUB_REPO="openefa-installer"
GITHUB_BRANCH="main"
INSTALL_DIR="/tmp/openefa-installer-$(date +%s)"

echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║              OpenEFA Installer Bootstrap                       ║"
echo "║           AI-Powered Email Security System                     ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check for required commands
for cmd in git tar; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${YELLOW}Installing required package: $cmd${NC}"
        if command -v apt-get &> /dev/null; then
            apt-get update -qq
            apt-get install -y -qq $cmd
        else
            echo -e "${RED}Error: apt-get not found. Please install $cmd manually.${NC}"
            exit 1
        fi
    fi
done

echo -e "${GREEN}→${NC} Downloading OpenEFA installer from GitHub..."
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# Clone the repository
if git clone -q --depth 1 --branch "${GITHUB_BRANCH}" \
    "https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git" installer 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Installer downloaded successfully"
else
    echo -e "${RED}✗ Failed to download installer from GitHub${NC}"
    echo -e "${YELLOW}Please check your internet connection and try again${NC}"
    exit 1
fi

cd installer

# Verify install.sh exists
if [[ ! -f "install.sh" ]]; then
    echo -e "${RED}✗ Error: install.sh not found in repository${NC}"
    exit 1
fi

# Make install.sh executable
chmod +x install.sh

echo ""
echo ""

# Check if OpenEFA is already installed
if [[ -d "/opt/spacyserver" ]] && [[ -f "/opt/spacyserver/VERSION" ]]; then
    source /opt/spacyserver/VERSION
    echo -e "${YELLOW}⚠  OpenEFA is already installed (Version: ${VERSION})${NC}"
    echo ""
    echo "What would you like to do?"
    echo "  1) Update to latest version (recommended)"
    echo "  2) Reinstall (will backup and overwrite)"
    echo "  3) Cancel"
    echo ""
    read -p "Enter choice [1-3]: " choice

    case $choice in
        1)
            echo ""
            echo -e "${CYAN}Starting OpenEFA update...${NC}"
            echo ""
            if [ -t 0 ]; then
                exec ./update.sh
            else
                exec ./update.sh < /dev/tty
            fi
            ;;
        2)
            echo ""
            echo -e "${YELLOW}⚠  Warning: Reinstalling will backup current installation${NC}"
            read -p "Are you sure? (yes/no): " confirm
            if [[ "$confirm" == "yes" ]]; then
                echo -e "${CYAN}Starting OpenEFA reinstallation...${NC}"
                echo ""
                if [ -t 0 ]; then
                    exec ./install.sh "$@"
                else
                    exec ./install.sh "$@" < /dev/tty
                fi
            else
                echo "Cancelled."
                exit 0
            fi
            ;;
        3|*)
            echo "Cancelled."
            exit 0
            ;;
    esac
else
    # Fresh installation
    echo -e "${CYAN}Starting OpenEFA installation...${NC}"
    echo ""
    if [ -t 0 ]; then
        exec ./install.sh "$@"
    else
        exec ./install.sh "$@" < /dev/tty
    fi
fi
