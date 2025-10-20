# OpenEFA Installation Guide

Detailed installation instructions for the OpenEFA Email Security System.

## Pre-Installation Checklist

### System Requirements

- [ ] Ubuntu 24.04 LTS or 22.04 LTS (fresh installation recommended)
- [ ] Minimum 2 GB RAM (4 GB recommended)
- [ ] Minimum 20 GB disk space (30 GB recommended)
- [ ] 2+ CPU cores
- [ ] Root/sudo access
- [ ] Internet connectivity
- [ ] Static IP address
- [ ] Fully Qualified Domain Name (FQDN)

### Network Requirements

- [ ] Port 25 (SMTP) inbound - for receiving email
- [ ] Port 5500 (HTTPS) - for SpacyWeb dashboard (optional external access)
- [ ] Network route to destination mail server (for relay)

### Information to Gather

Before starting installation, have ready:

1. **Primary domain to protect** (e.g., example.com)
2. **Destination mail server IP** (EFA, Zimbra, Exchange, etc.)
3. **DNS resolver IP** (if using internal DNS)
4. **Admin email address** (for SpacyWeb access)
5. **Strong passwords** (database + admin account)

## Installation Steps

### Step 1: Download Installer

```bash
# Option 1: Direct download from OpenEFA
curl -sSL https://install.openefa.com/install.sh -o openefa-install.sh

# Option 2: Clone from GitHub
git clone https://github.com/openefaadmin/openefa.git
cd openefa/installer
```

### Step 2: Run Installer

```bash
sudo bash install.sh
```

### Step 3: Answer Prompts

The installer will ask for:

1. **Primary Domain**: Domain you want to protect
2. **Database Configuration**:
   - Database name (default: spacy_email_db)
   - Database user (default: spacy_user)
   - Database password (strong password required)
3. **Admin Account**:
   - Username (default: admin)
   - Email address
   - Password (strong password required)
4. **Mail Relay**:
   - Destination server IP address
   - Port (default: 25)
5. **DNS Resolver**:
   - Internal DNS IP (or use system default)
6. **Module Tier**: Choose 1, 2, or 3 (Tier 2 recommended)
7. **Debug Logging**: Enable or disable (recommended for initial setup)

### Step 4: Monitor Installation

The installer will:

1. Run pre-flight system checks
2. Install system packages (Postfix, MariaDB, Redis, Python)
3. Set up database and create schema
4. Configure Postfix for email filtering
5. Install OpenSpacy modules
6. Create and start systemd services
7. Run post-installation validation

Installation typically takes 10-15 minutes depending on internet speed.

### Step 5: Post-Installation Configuration

After successful installation:

#### Update DNS Records

Update your domain's MX records to point to the OpenEFA server:

```
example.com.  IN MX 10 openefa.example.com.
```

#### Configure Firewall

```bash
# Allow SMTP inbound
sudo ufw allow 25/tcp

# Allow SpacyWeb (if needed externally)
sudo ufw allow 5500/tcp

# Enable firewall
sudo ufw enable
```

#### SSL Certificate (Recommended)

Replace self-signed certificate with Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d openefa.example.com

# Update Postfix main.cf
sudo postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/openefa.example.com/fullchain.pem"
sudo postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/openefa.example.com/privkey.pem"
sudo systemctl reload postfix
```

#### Test Email Flow

```bash
# Send test email
swaks --to user@example.com \
      --from test@external.com \
      --server localhost \
      --header "Subject: OpenEFA Test"

# Monitor logs
sudo tail -f /var/log/mail.log
sudo tail -f /opt/spacyserver/logs/email_filter_error.log
```

## Configuration

### Adding Additional Domains

Via SpacyWeb (Admin only):
1. Login to https://your-server:5500
2. Navigate to Config → Domains
3. Click "Add Domain"
4. Enter domain name and client name
5. Update Postfix transport maps:

```bash
echo "newdomain.com    smtp:[destination-ip]" | sudo tee -a /etc/postfix/transport
sudo postmap /etc/postfix/transport
sudo systemctl reload postfix
```

### Whitelist Management

**Via SpacyWeb**:
- Login → Whitelist Management
- Add senders/domains with trust score bonus
- Set bypass flags for specific checks

**Via Command Line**:
```bash
# Edit BEC config
sudo nano /opt/spacyserver/config/bec_config.json

# Restart db-processor to reload
sudo systemctl restart spacy-db-processor
```

### Blocking Rules

**Via SpacyWeb**:
- Login → Blocking Rules
- Add sender, domain, or country blocks
- Set priorities and enable/disable rules

**Via Command Line**:
```bash
# Database access
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db

# Add blocking rule
INSERT INTO blocking_rules (domain, pattern_type, pattern, action, priority, is_active)
VALUES ('example.com', 'sender', 'spam@badguy.com', 'reject', 100, 1);
```

## Upgrade Mode

If installer detects existing OpenEFA installation:

1. Choose "Upgrade" when prompted
2. Existing configs are preserved
3. Database schema is migrated
4. Services are restarted with new code

## EFA Integration

To integrate with existing EFA/MailGuard appliance:

```bash
sudo /opt/spacyserver/installer/efa_integration.sh
```

This configures APIs for:
- Release tracking (Port 5001)
- Whitelist API (Port 5002)
- Block sender API (Port 5003)

## Verification

### Check Services

```bash
# All services should be active
sudo systemctl status postfix
sudo systemctl status spacy-db-processor
sudo systemctl status spacyweb
sudo systemctl status spacy-release-api
sudo systemctl status spacy-whitelist-api
sudo systemctl status spacy-block-api
```

### Check Logs

```bash
# Mail flow
sudo tail -100 /var/log/mail.log

# Email filter
sudo tail -100 /opt/spacyserver/logs/email_filter_error.log

# Database processor
sudo journalctl -u spacy-db-processor -n 50

# SpacyWeb
sudo journalctl -u spacyweb -n 50
```

### Check Database

```bash
# Connect to database
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db

# Verify tables
SHOW TABLES;

# Check domains
SELECT * FROM client_domains;

# Check users
SELECT username, email, role FROM users;
```

## Next Steps

1. **Monitor email flow** for first 24-48 hours
2. **Adjust whitelists** as needed for false positives
3. **Configure additional domains** via SpacyWeb
4. **Set up backups** (database + configs)
5. **Review effectiveness dashboard** in SpacyWeb
6. **Join community forum** for support

## Backup and Restore

### Backup

```bash
# Database backup
sudo -u spacy-filter mysqldump --defaults-file=/opt/spacyserver/config/.my.cnf \
  spacy_email_db > openefa_backup_$(date +%Y%m%d).sql

# Config backup
sudo tar -czf openefa_config_$(date +%Y%m%d).tar.gz /opt/spacyserver/config

# Full system backup via SpacyWeb
# Login → Config → Backup & Restore
```

### Restore

```bash
# Restore database
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf \
  spacy_email_db < openefa_backup_20250101.sql

# Restore configs
sudo tar -xzf openefa_config_20250101.tar.gz -C /

# Restart services
sudo systemctl restart spacy-db-processor spacyweb
```

## Support

- Documentation: https://docs.openefa.com
- Community Forum: https://forum.openefa.com
- GitHub Issues: https://github.com/openefaadmin/openefa/issues
