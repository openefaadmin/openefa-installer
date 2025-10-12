#!/bin/bash

# MaxMind GeoLite2 Database Setup Script
# Downloads and installs the GeoLite2-Country database for email blocking

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SPACY_ROOT="/opt/spacyserver"
DATA_DIR="${SPACY_ROOT}/data"
DB_FILE="${DATA_DIR}/GeoLite2-Country.mmdb"
TEMP_DIR="/tmp/geolite2_setup_$$"

# Ensure data directory exists
mkdir -p "${DATA_DIR}"

echo -e "${GREEN}MaxMind GeoLite2 Database Setup${NC}"
echo "================================="
echo

# Check if license key is provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage: $0 <LICENSE_KEY>${NC}"
    echo
    echo "You need a MaxMind license key to download GeoLite2 databases."
    echo "Sign up for free at: https://www.maxmind.com/en/geolite2/signup"
    echo
    echo "Once you have your license key, run:"
    echo "  $0 YOUR_LICENSE_KEY"
    exit 1
fi

LICENSE_KEY="$1"

# Create temp directory
mkdir -p "${TEMP_DIR}"
cd "${TEMP_DIR}"

echo -e "${GREEN}Downloading GeoLite2-Country database...${NC}"

# Download the database using the license key
DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${LICENSE_KEY}&suffix=tar.gz"

if ! wget -q -O GeoLite2-Country.tar.gz "${DOWNLOAD_URL}"; then
    echo -e "${RED}Failed to download database. Please check your license key.${NC}"
    rm -rf "${TEMP_DIR}"
    exit 1
fi

echo -e "${GREEN}Extracting database...${NC}"

# Extract the tar.gz file
tar -xzf GeoLite2-Country.tar.gz

# Find the .mmdb file (it's in a dated subdirectory)
MMDB_FILE=$(find . -name "*.mmdb" -type f | head -1)

if [ -z "${MMDB_FILE}" ]; then
    echo -e "${RED}Could not find .mmdb file in archive${NC}"
    rm -rf "${TEMP_DIR}"
    exit 1
fi

# Backup existing database if it exists
if [ -f "${DB_FILE}" ]; then
    BACKUP_FILE="${DB_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${YELLOW}Backing up existing database to ${BACKUP_FILE}${NC}"
    cp "${DB_FILE}" "${BACKUP_FILE}"
fi

# Move the database to the correct location
echo -e "${GREEN}Installing database to ${DB_FILE}...${NC}"
mv "${MMDB_FILE}" "${DB_FILE}"

# Set proper permissions
chmod 644 "${DB_FILE}"
chown root:root "${DB_FILE}"

# Clean up
cd /
rm -rf "${TEMP_DIR}"

echo
echo -e "${GREEN}✅ GeoLite2-Country database installed successfully!${NC}"
echo

# Test the installation
echo -e "${GREEN}Testing GeoIP functionality...${NC}"
python3 -c "
import geoip2.database
import sys

try:
    reader = geoip2.database.Reader('${DB_FILE}')
    # Test with Google's DNS server
    response = reader.country('8.8.8.8')
    print(f'✅ GeoIP working! Test IP 8.8.8.8 is in {response.country.name} ({response.country.iso_code})')
    reader.close()
except Exception as e:
    print(f'❌ GeoIP test failed: {e}')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo
    echo -e "${GREEN}Installation complete! The email blocking module can now use country-based blocking.${NC}"
    echo
    echo "To test country blocking, run:"
    echo "  python3 ${SPACY_ROOT}/modules/email_blocking.py test recipient@yourdomain.com sender@foreign.com --ip <IP_ADDRESS>"
    echo
    echo "To add country blocking rules, use:"
    echo "  python3 ${SPACY_ROOT}/modules/email_blocking.py add-rule yourdomain.com country CN"
else
    echo -e "${RED}Installation completed but test failed. Please check the database file.${NC}"
    exit 1
fi

# Optional: Set up automatic updates via cron
echo
echo -e "${YELLOW}To keep the database updated, consider adding this to crontab:${NC}"
echo "  # Update GeoLite2 database weekly (Wednesdays at 3 AM)"
echo "  0 3 * * 3 ${SPACY_ROOT}/scripts/setup_maxmind_geoip.sh ${LICENSE_KEY} > /dev/null 2>&1"
echo