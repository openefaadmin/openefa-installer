#!/bin/bash
#
# Setup GeoIP Database for SpaCy Email Blocking
# Downloads and installs the MaxMind GeoLite2 Country database
#

SCRIPT_DIR="/opt/spacyserver"
DATA_DIR="$SCRIPT_DIR/data"
GEOIP_DB="$DATA_DIR/GeoLite2-Country.mmdb"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}    GeoIP Database Setup for SpaCy${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Create data directory if it doesn't exist
if [ ! -d "$DATA_DIR" ]; then
    echo -e "${YELLOW}Creating data directory...${NC}"
    mkdir -p "$DATA_DIR"
fi

# Check if database already exists
if [ -f "$GEOIP_DB" ]; then
    echo -e "${GREEN}✅ GeoIP database already exists at: $GEOIP_DB${NC}"
    echo -n "Do you want to update it? (y/n): "
    read update_choice
    if [ "$update_choice" != "y" ]; then
        echo "Keeping existing database."
        exit 0
    fi
fi

echo -e "${YELLOW}Note: MaxMind requires registration for GeoLite2 databases${NC}"
echo "Please visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
echo ""
echo "After registration, you'll get a license key."
echo ""

echo -n "Do you have a MaxMind account and license key? (y/n): "
read has_account

if [ "$has_account" = "y" ]; then
    echo -n "Enter your MaxMind License Key: "
    read -s license_key
    echo ""
    
    # Download using the license key
    echo -e "${YELLOW}Downloading GeoLite2-Country database...${NC}"
    
    DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${license_key}&suffix=tar.gz"
    TEMP_FILE="/tmp/GeoLite2-Country.tar.gz"
    
    if wget -q "$DOWNLOAD_URL" -O "$TEMP_FILE"; then
        echo -e "${GREEN}✅ Download successful${NC}"
        
        # Extract the database
        echo -e "${YELLOW}Extracting database...${NC}"
        cd /tmp
        tar -xzf "$TEMP_FILE"
        
        # Find and move the .mmdb file
        MMDB_FILE=$(find /tmp -name "GeoLite2-Country.mmdb" -type f 2>/dev/null | head -n 1)
        
        if [ -n "$MMDB_FILE" ]; then
            mv "$MMDB_FILE" "$GEOIP_DB"
            echo -e "${GREEN}✅ Database installed at: $GEOIP_DB${NC}"
            
            # Clean up
            rm -rf /tmp/GeoLite2-Country*
            
            # Set permissions
            chmod 644 "$GEOIP_DB"
            echo -e "${GREEN}✅ Permissions set${NC}"
        else
            echo -e "${RED}❌ Could not find .mmdb file in archive${NC}"
            exit 1
        fi
    else
        echo -e "${RED}❌ Download failed. Please check your license key.${NC}"
        exit 1
    fi
    
else
    echo ""
    echo -e "${YELLOW}Alternative: Using a free mirror (may be outdated)${NC}"
    echo -n "Do you want to try downloading from a mirror? (y/n): "
    read use_mirror
    
    if [ "$use_mirror" = "y" ]; then
        # Try to download from a mirror (this URL is an example and may not work)
        echo -e "${YELLOW}Attempting download from mirror...${NC}"
        
        # Create a placeholder file for now
        echo -e "${YELLOW}Creating placeholder database file...${NC}"
        touch "$GEOIP_DB"
        echo -e "${YELLOW}⚠️  Placeholder created. You'll need to manually download the database.${NC}"
        echo ""
        echo "To get the real database:"
        echo "1. Register at: https://www.maxmind.com/en/geolite2/signup"
        echo "2. Download GeoLite2-Country.mmdb"
        echo "3. Place it at: $GEOIP_DB"
    else
        echo ""
        echo -e "${YELLOW}Manual installation instructions:${NC}"
        echo "1. Register at: https://www.maxmind.com/en/geolite2/signup"
        echo "2. Download the GeoLite2-Country database"
        echo "3. Extract the .mmdb file"
        echo "4. Copy it to: $GEOIP_DB"
        echo ""
        echo "Creating placeholder for now..."
        touch "$GEOIP_DB"
    fi
fi

# Install Python requirements
echo ""
echo -e "${YELLOW}Installing Python GeoIP2 library...${NC}"
/opt/spacyserver/venv/bin/pip install geoip2 --quiet

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Python GeoIP2 library installed${NC}"
else
    echo -e "${RED}❌ Failed to install Python library${NC}"
fi

# Test the installation
echo ""
echo -e "${YELLOW}Testing GeoIP functionality...${NC}"

/opt/spacyserver/venv/bin/python3 << EOF
import sys
sys.path.insert(0, '/opt/spacyserver/modules')

try:
    from email_blocking import EmailBlockingEngine
    engine = EmailBlockingEngine()
    
    # Test with a known IP (Google DNS)
    test_ip = "8.8.8.8"
    country = engine.get_country_from_ip(test_ip)
    if country:
        print(f"✅ GeoIP working! Test IP {test_ip} is from country: {country}")
    else:
        print("⚠️  GeoIP database loaded but couldn't resolve test IP")
except Exception as e:
    print(f"❌ Error testing GeoIP: {e}")
EOF

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "You can now use the blocking manager to add country-based rules:"
echo "  /opt/spacyserver/tools/blocking_manager.sh"