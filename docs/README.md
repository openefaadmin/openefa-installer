# OpenEFA Email Security System

**Open-source Email Filtering Appliance - Successor to the EFA Project**

OpenEFA is a complete email security system featuring AI-powered spam detection, phishing protection, BEC (Business Email Compromise) detection, and comprehensive email filtering capabilities.

## Features

- **AI-Powered Detection**: SpaCy NLP for advanced threat detection
- **BEC & Typosquatting**: Brand impersonation and domain spoofing detection
- **Authentication**: Full SPF/DKIM/DMARC validation
- **PDF Analysis**: TOAD (Telephone-Oriented Attack Delivery) detection
- **Thread Awareness**: Conversation learning system
- **Multi-Tenancy**: Web-based dashboard with domain-scoped administration
- **API Integration**: REST APIs for whitelist, blocking, and release tracking
- **Comprehensive Logging**: Debug and verbose logging with log rotation

## Quick Install

```bash
# Download installer
curl -sSL https://install.openefa.com/install.sh -o openefa-install.sh

# Run installation
sudo bash openefa-install.sh
```

## System Requirements

- **OS**: Ubuntu 24.04 LTS or 22.04 LTS
- **RAM**: 2 GB minimum (4 GB recommended)
- **Disk**: 20 GB minimum (30 GB recommended)
- **CPU**: 2 cores minimum (4+ recommended)
- **Network**: Internet access during installation

## Architecture

```
Internet → OpenEFA (Authentication + Filtering) → Relay Server → Mailboxes
```

OpenEFA acts as an inbound mail gateway, performing:
1. SPF/DKIM/DMARC authentication
2. AI-powered spam/phishing detection
3. BEC and typosquatting analysis
4. Content filtering and scoring
5. Relay to destination mail server

## Module Tiers

### Tier 1 - Core (Minimal)
- Authentication (SPF/DKIM/DMARC)
- Email blocking (sender/domain/country)
- Basic spam scoring
- RBL checker

### Tier 2 - Standard (Recommended)
- All Tier 1 modules
- BEC detector + Typosquatting
- DNS reputation
- Obfuscation detector
- Marketing filter

### Tier 3 - Advanced (Full Stack)
- All Tier 2 modules
- NER (Named Entity Recognition - AI)
- Thread awareness enhanced
- Conversation learning system
- Behavioral baseline
- PDF analyzer

## Post-Installation

After installation completes:

1. **Update DNS**: Point MX records to OpenEFA server
2. **Firewall**: Allow port 25 (SMTP) inbound
3. **Web Access**: https://your-server:5500 (SpacyWeb Dashboard)
4. **SSL Certificate**: Install Let's Encrypt for production use
5. **Configuration**: Add whitelists, blocking rules, additional domains

## Management

### Command-Line Tools
```bash
# OpenSpacyMenu - Main management interface
sudo /opt/spacyserver/tools/OpenSpacyMenu

# Service management
sudo systemctl status spacy-db-processor
sudo systemctl restart spacyweb

# Log monitoring
sudo tail -f /var/log/mail.log
sudo tail -f /opt/spacyserver/logs/email_filter_error.log
```

### Web Interface
- Access: https://your-server:5500
- Admin login with credentials from installation
- Manage whitelists, blocking rules, domains
- View statistics and reports

## Documentation

- [Installation Guide](INSTALLATION.md) - Detailed installation steps
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions
- [EFA Replacement Roadmap](/opt/spacyserver/docs/EFA_REPLACEMENT_ROADMAP.md)
- [Installer Design](/opt/spacyserver/docs/INSTALLER_DESIGN.md)

## Community & Support

- **Website**: https://openefa.com
- **Forum**: https://forum.openefa.com
- **GitHub**: https://github.com/openefaadmin/openefa
- **Documentation**: https://docs.openefa.com

## System Management

### Updating OpenEFA

To update to the latest version:

```bash
sudo /opt/spacyserver/tools/update.sh
```

The update script will:
- Check your current version
- Download the latest release from GitHub
- Create a backup before updating
- Deploy new features and fixes
- Restart services
- Provide rollback option if needed

### Uninstallation

To completely remove OpenEFA from your system:

```bash
sudo /root/openefa-uninstall.sh
```

This script is installed during initial setup and removes all OpenEFA components while preserving system configurations.

## License

OpenEFA is licensed under the GNU General Public License v3.0 (GPL-3.0).

This project is the successor to the EFA Project (Email Filter Appliance) and maintains the GPL licensing tradition.

## Credits

OpenEFA is built on the foundation of the EFA Project and incorporates modern AI/ML capabilities through the OpenSpacy filtering engine.

**Third-Party Data:**
- This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com

**Contributing**: We welcome contributions! See our forum for development guidelines.

---

**OpenEFA** - Modern Email Security for the Open Source Community
