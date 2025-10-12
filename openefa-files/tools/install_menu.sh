#!/bin/bash
# Installation script for OpenSpaCy Admin Menu System
# Save this as: install_menu.sh

set -e

echo "Installing OpenSpaCy Admin Menu System..."

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Create necessary directories
echo -e "${BLUE}Creating SpaCy directory structure...${NC}"
sudo mkdir -p /opt/spacyserver/{tools,backups,scripts,config,modules,logs}

# Install jq if not present (required for JSON manipulation)
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Installing jq (required for JSON processing)...${NC}"
    sudo apt-get update
    sudo apt-get install -y jq
else
    echo -e "${GREEN}✓${NC} jq is already installed"
fi

# Copy the menu script to tools directory
echo -e "${BLUE}Installing OpenSpaCy menu and tools...${NC}"
sudo cp OpenSpacyMenu /opt/spacyserver/tools/OpenSpacyMenu
sudo chmod +x /opt/spacyserver/tools/OpenSpacyMenu

# Install the info tool if it exists
if [[ -f "spacy-info" ]]; then
    sudo cp spacy-info /opt/spacyserver/tools/spacy-info
    sudo chmod +x /opt/spacyserver/tools/spacy-info
    sudo ln -sf /opt/spacyserver/tools/spacy-info /usr/local/bin/spacy-info
fi

# Create symlink in /usr/local/bin for global access
sudo ln -sf /opt/spacyserver/tools/OpenSpacyMenu /usr/local/bin/OpenSpacyMenu

# Set proper ownership for the entire SpaCy directory structure
sudo chown -R $(whoami):$(whoami) /opt/spacyserver/{tools,backups,scripts,logs}
sudo chown -R $(whoami):$(whoami) /opt/spacyserver/config 2>/dev/null || echo "Note: Config directory ownership unchanged"

# Create version file
echo "1.0.0" | sudo tee /opt/spacyserver/VERSION > /dev/null

# Test the installation
echo -e "${BLUE}Testing installation...${NC}"
if command -v OpenSpacyMenu &> /dev/null; then
    echo -e "${GREEN}✓${NC} OpenSpacyMenu installed successfully"
else
    echo -e "${RED}✗${NC} Installation failed"
    exit 1
fi

if command -v spacy-info &> /dev/null; then
    echo -e "${GREEN}✓${NC} spacy-info installed successfully"
else
    echo -e "${YELLOW}⚠${NC} spacy-info not installed (optional)"
fi

echo ""
echo -e "${GREEN}Installation completed!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  Type 'OpenSpacyMenu' from anywhere to launch the admin interface"
echo "  Type 'spacy-info' to see system status and information"
echo ""
echo -e "${YELLOW}Tools installed in:${NC}"
echo "  /opt/spacyserver/tools/"
echo ""
echo -e "${YELLOW}Features installed:${NC}"
echo "  • BEC Configuration Management (fully functional)"
echo "  • Service Management"
echo "  • System Information"
echo "  • Automatic backups with timestamps"
echo "  • Interactive whitelist management"
echo "  • SpaCy system overview tool"
echo ""
echo -e "${BLUE}Try it now: OpenSpacyMenu${NC}"
