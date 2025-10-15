# OpenEFA Installer

**AI-Powered Email Security and Filtering System**

OpenEFA is a modern, open-source email security appliance that combines advanced AI/ML spam detection with traditional email filtering techniques. Built as the successor to the discontinued EFA Project, OpenEFA provides enterprise-grade email protection with cutting-edge features like Business Email Compromise (BEC) detection, typosquatting analysis, and conversation learning.

## Quick Installation

**One-Line Install** (Recommended):
```bash
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/bootstrap.sh | sudo bash
```

**Or download and review first**:
```bash
# Download the installer
git clone https://github.com/openefaadmin/openefa-installer.git
cd openefa-installer

# Review the code
cat install.sh

# Run the installer
sudo ./install.sh
```

## Features

### Core Security Features
- **ClamAV Antivirus**: Real-time virus scanning of all email attachments (2M+ signatures)
- **AI-Powered Spam Detection**: Advanced machine learning models for superior spam identification
- **SPF/DKIM/DMARC Authentication**: Complete email authentication as the sole provider
- **BEC Detection**: Business Email Compromise detection with trust scoring (0-5 scale)
- **Typosquatting Detection**: Brand impersonation via domain similarity analysis
- **Real-time Blackhole Lists (RBL)**: Integration with Spamhaus, SORBS, SpamCop
- **PDF Analysis**: TOAD (Telephone-Oriented Attack Document) detection
- **URL Reputation**: Homograph attack detection and suspicious URL patterns
- **Behavioral Baselines**: Account compromise detection via anomaly analysis

### Intelligent Learning
- **Conversation Learning**: MySQL-based pattern recognition to reduce false positives
- **Thread Awareness**: Legitimate reply detection with spam score adjustment
- **Adaptive Scoring**: Dynamic spam scoring based on sender history

### Multi-Tenancy & Self-Service
- **SpacyWeb Dashboard**: Web interface on port 5500 (HTTPS)
- **Domain-Scoped Access**: Users manage only their authorized domains
- **Whitelist/Blacklist Management**: Self-service sender management
- **Real-time Statistics**: Blocking rules effectiveness and email metrics
- **Audit Logging**: Complete change tracking for compliance

### APIs for Integration
- **Release Tracking API** (Port 5001): Track quarantine releases
- **Whitelist API** (Port 5002): "Always Allow" button integration
- **Block Sender API** (Port 5003): "Always Block" button integration

## System Requirements

### Minimum Requirements
- **OS**: Ubuntu 24.04 LTS (primary) or Ubuntu 22.04 LTS
- **RAM**: 2 GB (4 GB recommended)
- **Disk**: 20 GB free space
- **CPU**: 2 cores minimum
- **Network**: Static IP address, open ports 25, 443, 5500

### Supported Configurations
- **Standalone**: Complete email security appliance
- **Relay Mode**: Front-end to existing email infrastructure (MailGuard/EFA)
- **Multi-Domain**: Single installation protecting multiple domains

## Installation Options

### Interactive Installation (Default)
The installer will prompt for:
1. **Primary Domain**: Initial domain to protect (e.g., `example.com`)
2. **Admin Account**: Email and password for SpacyWeb dashboard
3. **Relay Server**: Destination mail server IP and port (e.g., `192.168.1.100:25`)
4. **DNS Server**: Internal DNS resolver IP (e.g., `192.168.1.1`)
5. **Module Tier**: Security feature level (1=Core, 2=Standard, 3=Advanced+AI)
6. **Debug Mode**: Enable verbose logging (recommended during setup)

### Non-Interactive Installation
Set environment variables before running:
```bash
export OPENEFA_DOMAIN="example.com"
export OPENEFA_ADMIN_EMAIL="admin@example.com"
export OPENEFA_ADMIN_PASSWORD="SecurePassword123"
export OPENEFA_RELAY_HOST="192.168.1.100"
export OPENEFA_RELAY_PORT="25"
export OPENEFA_DNS_SERVER="192.168.1.1"
export OPENEFA_MODULE_TIER="2"
export OPENEFA_DEBUG_MODE="yes"

curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/install.sh | sudo -E bash
```

## Module Tiers Explained

### Tier 1 - Core (Minimal Resource Usage)
Essential email security features:
- SPF/DKIM/DMARC authentication
- Email blocking (sender/domain/country)
- Basic spam scoring
- RBL checker

**Resource Impact**: ~50 MB RAM per process

### Tier 2 - Standard (Recommended)
Core features plus advanced detection:
- BEC detector + Typosquatting
- DNS reputation analysis
- Obfuscation detector
- Marketing filter
- Funding spam detector

**Resource Impact**: ~100 MB RAM per process

### Tier 3 - Advanced + AI (High Performance Required)
All features including AI/NLP models:
- Named Entity Recognition (SpaCy NLP models ~500MB download)
- Thread awareness enhanced
- Conversation learning system
- Behavioral baseline analysis
- PDF analyzer
- URL reputation
- Compliance module

**Resource Impact**: ~300-500 MB RAM per process

## Post-Installation

### ⚠️ CRITICAL: Configure Your MailGuard/EFA Server

**If you have an existing MailGuard or EFA server downstream**, you **MUST** deploy SpamAssassin rules to make it trust OpenEFA's scoring.

**Why this is critical**:
- Without these rules, MailGuard will ignore OpenEFA's analysis
- Authentication checks will run twice and fail (due to relay hop)
- Legitimate emails will be incorrectly blocked

**Quick Setup** (3 minutes):
```bash
# On your OpenEFA server
cd /opt/spacyserver/installer/templates/spamassassin

# Copy to MailGuard/EFA server
scp spacy_rules.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp local.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp zzz_spacy_trust.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/

# On MailGuard server, verify and restart
ssh root@YOUR_EFA_SERVER_IP "spamassassin --lint && systemctl restart mailscanner"
```

**Full Documentation**: See `/opt/spacyserver/docs/EFA_SPAMASSASSIN_INTEGRATION.md` or `docs/EFA_SPAMASSASSIN_INTEGRATION.md` in this repository.

**Step-by-step checklist**: See `docs/MAILGUARD_INTEGRATION_CHECKLIST.md`

---

### Services Installed
```bash
# Check all services
systemctl status spacy-db-processor
systemctl status spacyweb
systemctl status spacy-release-api
systemctl status spacy-whitelist-api
systemctl status spacy-block-api
systemctl status postfix
```

### Access SpacyWeb Dashboard
```
https://YOUR_SERVER_IP:5500
```
Login with admin credentials configured during installation.

### Configuration Files
- **Main Config**: `/opt/spacyserver/config/email_filter_config.json`
- **BEC Settings**: `/opt/spacyserver/config/bec_config.json`
- **Module Control**: `/opt/spacyserver/config/module_config.json`
- **Authentication**: `/opt/spacyserver/config/authentication_config.json`

### Log Locations
- **Email Processing**: `/opt/spacyserver/logs/email_filter_error.log`
- **Database Queue**: `/opt/spacyserver/logs/db_processor.log`
- **SpacyWeb**: `/opt/spacyserver/logs/spacyweb.log`
- **Mail Flow**: `/var/log/mail.log`

## Management Tools

### OpenSpacyMenu
Comprehensive management interface:
```bash
sudo /opt/spacyserver/tools/OpenSpacyMenu
```

Features:
- Domain management
- Whitelist/blocklist administration
- System status and diagnostics
- Log viewing and analysis
- Backup and restore
- RBL configuration (Option 23)

### Command-Line Tools
```bash
# Domain management
/opt/spacyserver/tools/domain_manager.sh

# Blocking rules
/opt/spacyserver/tools/blocking_manager.sh

# Unblock sender
/opt/spacyserver/tools/unblock_sender.sh

# Test email processing
/opt/spacyserver/scripts/test_spacy_server.sh

# Live email monitoring
/opt/spacyserver/scripts/live_email_monitor.sh
```

## DNS Configuration

### MX Records
Point your domain's MX record to the OpenEFA server:
```
example.com.    IN  MX  10  mail.example.com.
mail.example.com. IN  A   YOUR_OPENEFA_IP
```

### SPF Record
Update SPF to include OpenEFA:
```
example.com.    IN  TXT  "v=spf1 mx ip4:YOUR_OPENEFA_IP -all"
```

### DMARC Record
```
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
```

## Updating OpenEFA

### Smart Update Script

OpenEFA includes an intelligent update mechanism that preserves your configuration while updating code components.

**One-Line Update** (Recommended):
```bash
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/update.sh | sudo bash
```

**Or download and review first**:
```bash
wget https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/update.sh
chmod +x update.sh
sudo ./update.sh
```

### Update Features

✅ **Automatic Backup**: Creates timestamped backup before updating
✅ **Config Preservation**: Never overwrites your configuration files
✅ **Service Validation**: Verifies all services after update
✅ **Rollback Capability**: One-command restore if update fails
✅ **Selective Updates**: Update specific components only

### What Gets Updated

- `email_filter.py` - Main email processing engine
- `modules/*` - All security modules
- `services/*` - Background services (db_processor, APIs)
- `web/*` - SpacyWeb dashboard
- `scripts/*` and `tools/*` - Utility scripts

### What Gets Preserved

- `config/*.json` - All user configurations
- `config/.my.cnf` - Database credentials
- `config/.app_config.ini` - Flask secret key
- `logs/*` - Log files
- Database content

### Update Options

```bash
# Standard update (with prompts)
sudo ./update.sh

# Dry run (preview changes without applying)
sudo ./update.sh --dry-run

# Update specific component only
sudo ./update.sh --component email_filter
sudo ./update.sh --component modules
sudo ./update.sh --component web

# Backup only (no update)
sudo ./update.sh --backup-only

# Rollback to previous version
sudo ./update.sh --rollback
```

### Version Tracking

After first update, OpenEFA creates `/opt/spacyserver/VERSION`:
```
VERSION=1.0.0
INSTALLED=2025-10-13
UPDATED=2025-10-13
COMMIT=872b1b0
```

### Update Safety

The update script includes multiple safety features:

1. **Pre-flight Checks**: Verifies root access, disk space, internet connectivity
2. **Automatic Backup**: Creates `/opt/spacyserver-backup-YYYYMMDD_HHMMSS/`
3. **Database Backup**: Exports database with mysqldump
4. **Service Validation**: Tests all services after update
5. **Auto-Rollback**: Offers rollback if validation fails
6. **Detailed Logging**: Saves log to `/tmp/openefa-update-*.log`

### Manual Component Update

If you only need to update a single file (e.g., after a bugfix):

```bash
# Update email_filter.py only
sudo curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/openefa-files/email_filter.py \
  -o /opt/spacyserver/email_filter.py
sudo chmod 755 /opt/spacyserver/email_filter.py
sudo chown spacy-filter:spacy-filter /opt/spacyserver/email_filter.py

# Update a specific module
sudo curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/openefa-files/modules/bec_detector.py \
  -o /opt/spacyserver/modules/bec_detector.py
sudo chown spacy-filter:spacy-filter /opt/spacyserver/modules/bec_detector.py

# Restart services after manual update
sudo systemctl restart spacy-db-processor spacyweb
```

---

## Uninstallation

```bash
cd /opt/spacyserver/installer
sudo ./uninstall.sh
```

This will:
- Stop and remove all services
- Remove installed packages (optional)
- Drop database (optional)
- Restore Postfix configuration
- Remove OpenEFA files

## Architecture

### Email Flow
```
Internet → OpenEFA (Authentication + AI Analysis) → Relay Server → Final Delivery
```

### Processing Pipeline
```
email_filter.py → Security Modules → Redis Queue → db_processor.py → MariaDB
                ↓
         SpamAssassin Headers
```

### Key Components
- **email_filter.py**: Main Postfix integration point (90s timeout)
- **db_processor.py**: Asynchronous database writer service
- **Security Modules**: Modular detection engines (BEC, typosquatting, etc.)
- **SpacyWeb**: Flask-based web interface
- **APIs**: RESTful integration endpoints

## Troubleshooting

### Email Not Processing
```bash
# Check email filter logs
tail -f /opt/spacyserver/logs/email_filter_error.log

# Check Postfix logs
tail -f /var/log/mail.log

# Test email processing manually
echo "Test" | mail -s "Test" user@example.com
```

### Service Issues
```bash
# Restart services
systemctl restart spacy-db-processor
systemctl restart postfix

# Check service status
journalctl -u spacy-db-processor -n 50
```

### Database Connection Issues
```bash
# Test database connection
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db

# Check Redis
redis-cli ping
```

### Common Issues
- **Status 120**: Email processing timeout - check `/opt/spacyserver/logs/`
- **Status 1**: Module crash - check for import errors in logs
- **Mail Loop**: Check `mydestination` only includes `localhost`
- **DNS Issues**: Verify DNS server is accessible from OpenEFA

## Support & Documentation

### Community
- **Website**: https://openefa.com
- **Forum**: https://forum.openefa.com
- **Issue Tracker**: https://github.com/openefaadmin/openefa-installer/issues

### Documentation
- **Full Documentation**: Coming soon at docs.openefa.com
- **EFA Replacement Roadmap**: See `/opt/spacyserver/docs/EFA_REPLACEMENT_ROADMAP.md` after install
- **Design Documents**: See `/opt/spacyserver/docs/` directory

## Development

### Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Testing
Test environment requirements:
- Fresh Ubuntu 24.04 LTS installation
- Snapshot capability for rollback testing
- Test domain with real email flow

## License

OpenEFA is released under the GNU General Public License v3.0 (GPL-3.0).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation.

## Credits

OpenEFA is developed as the modern successor to the EFA Project (efa-project.org), honoring its legacy while bringing cutting-edge AI and security features to open-source email protection.

**Project Lead**: Scott Barbour
**Organization**: Segue Logic LLC
**Contact**: scott@seguelogic.com

---

**Built with ❤️ for the email security community**

*Last Updated: October 2025 - v1.0.0 Beta*
