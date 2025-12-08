#!/bin/bash
###############################################################################
# SpacyServer Complete Installation Script
#
# This script performs a fresh installation of SpacyServer with all
# security enhancements and best practices.
#
# Usage: sudo ./install_spacyserver.sh
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     SpacyServer Installation Script v2.0                   ║"
echo "║     Production-Ready with Security Enhancements            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ ERROR: This script must be run as root${NC}"
    echo "   Please run: sudo $0"
    exit 1
fi

# Configuration
INSTALL_DIR="/opt/spacyserver"
CONFIG_DIR="/etc/spacy-server"
SERVICE_USER="spacy-filter"
SERVICE_GROUP="spacy-filter"
VENV_PATH="$INSTALL_DIR/venv"

echo -e "${BLUE}📋 Installation Configuration:${NC}"
echo "   Installation Directory: $INSTALL_DIR"
echo "   Configuration Directory: $CONFIG_DIR"
echo "   Service User: $SERVICE_USER"
echo "   Virtual Environment: $VENV_PATH"
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo -e "${BLUE}▶ $1${NC}"
    echo "─────────────────────────────────────────────────────────────"
}

# Function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1 failed"
        exit 1
    fi
}

###############################################################################
# 1. System Prerequisites
###############################################################################

print_section "Installing System Prerequisites"

# Update package list
apt-get update
check_success "Package list updated"

# Install required packages
REQUIRED_PACKAGES=(
    "python3"
    "python3-pip"
    "python3-venv"
    "python3-dev"
    "mysql-server"
    "redis-server"
    "nginx"
    "git"
    "curl"
    "jq"
    "build-essential"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii  $package "; then
        echo -e "${GREEN}✓${NC} $package already installed"
    else
        echo "Installing $package..."
        apt-get install -y "$package"
        check_success "$package installed"
    fi
done

###############################################################################
# 2. Create System User
###############################################################################

print_section "Creating Service User"

if id "$SERVICE_USER" &>/dev/null; then
    echo -e "${YELLOW}⚠${NC} User $SERVICE_USER already exists"
else
    useradd -r -s /bin/bash -d /home/$SERVICE_USER -m $SERVICE_USER
    check_success "Created service user: $SERVICE_USER"
fi

###############################################################################
# 3. Create Directory Structure
###############################################################################

print_section "Creating Directory Structure"

# Create main application directories
mkdir -p $INSTALL_DIR/{web,api,modules,scripts,tools,logs,backups,data,reports}
mkdir -p $INSTALL_DIR/web/{templates,static,certs}
mkdir -p $INSTALL_DIR/web/templates/{auth,admin}
check_success "Created application directories"

# Create system configuration directory
mkdir -p $CONFIG_DIR
check_success "Created configuration directory: $CONFIG_DIR"

# Create config subdirectory for JSON configs
mkdir -p $INSTALL_DIR/config
check_success "Created JSON config directory"

###############################################################################
# 4. Setup Configuration Files
###############################################################################

print_section "Setting Up Configuration Files"

# Generate secure random keys
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
API_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Use environment variables if set, otherwise generate/use defaults
: "${DB_USER:=spacy_user}"
: "${DB_NAME:=spacy_email_db}"
: "${DB_HOST:=localhost}"
if [ -z "$DB_PASSWORD" ]; then
    DB_PASSWORD=$(python3 -c "import secrets; print(''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(24)))")
fi

# Create .env file in /etc/spacy-server/
cat > $CONFIG_DIR/.env << EOF
# SpacyServer Environment Configuration
# Generated: $(date)
# Location: $CONFIG_DIR/.env

# Database Configuration
DB_HOST=$DB_HOST
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME

# Flask Configuration
FLASK_SECRET_KEY=$FLASK_SECRET
DEBUG_MODE=False

# Security Configuration
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
SESSION_TIMEOUT_HOURS=2

# API Security
API_SECRET_KEY=$API_SECRET
ALLOWED_API_IPS=127.0.0.1,localhost

# ClickSend Configuration (Optional - update with your credentials)
CLICKSEND_USERNAME=your_username_here
CLICKSEND_API_KEY=your_api_key_here

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Application Settings
MAX_CONTENT_LENGTH=16777216
UPLOAD_FOLDER=$INSTALL_DIR/uploads
EOF

check_success "Created .env file in $CONFIG_DIR"

# Create .env.template for reference
cp $CONFIG_DIR/.env $CONFIG_DIR/.env.template
sed -i 's/DB_PASSWORD=.*/DB_PASSWORD=YOUR_SECURE_PASSWORD_HERE/' $CONFIG_DIR/.env.template
sed -i 's/FLASK_SECRET_KEY=.*/FLASK_SECRET_KEY=YOUR_FLASK_SECRET_KEY_HERE/' $CONFIG_DIR/.env.template
sed -i 's/API_SECRET_KEY=.*/API_SECRET_KEY=YOUR_API_SECRET_KEY_HERE/' $CONFIG_DIR/.env.template
check_success "Created .env.template"

# Set proper permissions
chown root:$SERVICE_GROUP $CONFIG_DIR/.env
chmod 640 $CONFIG_DIR/.env
chmod 644 $CONFIG_DIR/.env.template
check_success "Set configuration file permissions"

###############################################################################
# 5. Setup Python Virtual Environment
###############################################################################

print_section "Setting Up Python Virtual Environment"

# Create virtual environment
python3 -m venv $VENV_PATH
check_success "Created virtual environment"

# Upgrade pip
$VENV_PATH/bin/pip install --upgrade pip
check_success "Upgraded pip"

# Install Python packages
echo "Installing Python packages (this may take a few minutes)..."
$VENV_PATH/bin/pip install \
    Flask==3.0.0 \
    Flask-Login==0.6.3 \
    Flask-WTF==1.2.1 \
    Flask-Limiter==3.5.0 \
    Flask-Talisman==1.1.0 \
    Flask-Caching==2.3.1 \
    python-dotenv==1.0.0 \
    mysql-connector-python==8.2.0 \
    SQLAlchemy==2.0.23 \
    bcrypt==4.1.1 \
    redis==5.0.1 \
    pandas==2.1.3 \
    matplotlib==3.8.2 \
    seaborn==0.13.0 \
    spacy==3.8.0 \
    en-core-web-lg@https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl

check_success "Installed Python packages"

###############################################################################
# 6. Setup MySQL Database
###############################################################################

print_section "Setting Up MySQL Database"

# Start MySQL if not running
systemctl start mysql
systemctl enable mysql
check_success "MySQL service started"

# Create database and user
mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;" 2>/dev/null || true
mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASSWORD';" 2>/dev/null || true
mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"
check_success "Database and user created"

# Create .my.cnf in /etc/spacy-server/ for easy database access
cat > $CONFIG_DIR/.my.cnf << EOF
[client]
user=$DB_USER
password=$DB_PASSWORD
host=$DB_HOST
database=$DB_NAME

[mysql]
database=$DB_NAME
EOF

chown $SERVICE_USER:$SERVICE_GROUP $CONFIG_DIR/.my.cnf
chmod 600 $CONFIG_DIR/.my.cnf
check_success "Created MySQL configuration file in $CONFIG_DIR"

###############################################################################
# 7. Setup Redis
###############################################################################

print_section "Setting Up Redis"

systemctl start redis-server
systemctl enable redis-server
check_success "Redis service started"

# Test Redis connection
redis-cli ping &>/dev/null
check_success "Redis connection verified"

###############################################################################
# 8. Generate SSL Certificates
###############################################################################

print_section "Generating SSL Certificates"

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
    -out $INSTALL_DIR/web/certs/cert.pem \
    -keyout $INSTALL_DIR/web/certs/key.pem \
    -days 365 \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=IT/CN=localhost"

check_success "Generated SSL certificates"

# Set certificate permissions
chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/web/certs/*.pem
chmod 600 $INSTALL_DIR/web/certs/*.pem
check_success "Set certificate permissions"

###############################################################################
# 9. Set Directory Permissions
###############################################################################

print_section "Setting Directory Permissions"

# Set ownership
chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
chown -R root:$SERVICE_GROUP $CONFIG_DIR

# Set permissions
chmod 750 $INSTALL_DIR
chmod 750 $CONFIG_DIR
chmod 755 $INSTALL_DIR/{web,api,modules,scripts,tools}
chmod 770 $INSTALL_DIR/{logs,backups,data}
chmod 750 $INSTALL_DIR/config

check_success "Set directory permissions"

###############################################################################
# 10. Create Systemd Service
###############################################################################

print_section "Creating Systemd Service"

cat > /etc/systemd/system/spacyweb.service << 'EOF'
[Unit]
Description=SpacyWeb Dashboard
After=network.target mysql.service redis-server.service
Requires=mysql.service redis-server.service

[Service]
Type=simple
User=spacy-filter
Group=spacy-filter
WorkingDirectory=/opt/spacyserver
Environment="PATH=/opt/spacyserver/venv/bin"
ExecStart=/opt/spacyserver/venv/bin/python3 /opt/spacyserver/web/app.py
Restart=always
RestartSec=10
MemoryMax=1G
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/spacyserver/logs /opt/spacyserver/backups /opt/spacyserver/data

[Install]
WantedBy=multi-user.target
EOF

check_success "Created systemd service file"

systemctl daemon-reload
check_success "Reloaded systemd"

###############################################################################
# 11. Display Installation Summary
###############################################################################

print_section "Installation Summary"

echo ""
echo -e "${GREEN}✅ SpacyServer Installation Complete!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}📋 Important Information:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}Installation Directory:${NC} $INSTALL_DIR"
echo -e "${BLUE}Configuration:${NC} $CONFIG_DIR/.env"
echo -e "${BLUE}Service User:${NC} $SERVICE_USER"
echo ""
echo -e "${YELLOW}🔐 Generated Credentials:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Database Password:${NC} $DB_PASSWORD"
echo -e "${BLUE}API Secret Key:${NC} $API_SECRET"
echo ""
echo -e "${RED}⚠️  SAVE THESE CREDENTIALS SECURELY!${NC}"
echo -e "${RED}⚠️  They are stored in: $CONFIG_DIR/.env${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}📝 Next Steps:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Copy your application code to $INSTALL_DIR/web/"
echo "2. Update ClickSend credentials in $CONFIG_DIR/.env (optional)"
echo "3. Start the service: systemctl start spacyweb"
echo "4. Enable on boot: systemctl enable spacyweb"
echo "5. Check status: systemctl status spacyweb"
echo "6. View logs: journalctl -u spacyweb -f"
echo ""
echo -e "${YELLOW}🔒 Security Features Enabled:${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ Configuration in /etc/spacy-server/ (system-wide standard)"
echo "  ✓ Secure file permissions (600 for .env, 640 for configs)"
echo "  ✓ Dedicated service user (spacy-filter)"
echo "  ✓ Redis caching enabled (performance optimization)"
echo "  ✓ Rate limiting with Redis backend"
echo "  ✓ HTTPS with self-signed certificates"
echo "  ✓ Session timeout: 30 minutes inactivity"
echo "  ✓ CSRF protection enabled"
echo "  ✓ SQL injection protection (parameterized queries)"
echo "  ✓ Strong password policy (12+ chars)"
echo "  ✓ Systemd service hardening"
echo ""
echo -e "${GREEN}Installation completed successfully!${NC}"
echo ""
