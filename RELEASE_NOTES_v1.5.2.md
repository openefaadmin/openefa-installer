# OpenEFA Installer v1.5.2 Release Notes

**Release Date:** October 18, 2025
**Release Type:** Bug Fix & Enhancement
**Priority:** Recommended Update

---

## 🎯 Overview

Version 1.5.2 completes the email retention system implementation and fixes critical security gaps discovered during production deployment. This release includes three major updates (v1.5.0, v1.5.1, v1.5.2) that improve spam analysis, add antivirus protection, and ensure complete installation.

---

## 🆕 What's New in v1.5.2

### Installation Completeness Fix

**Problem Solved**: Email cleanup script and cron job were not being deployed during installation, despite database configuration being present.

**What's Fixed**:
- ✅ Cleanup script now automatically deployed to `/opt/spacyserver/cleanup_expired_emails.py`
- ✅ Cron job automatically configured (daily at 2:00 AM)
- ✅ `cron` package added to core dependencies (fixes minimal Ubuntu installations)
- ✅ No manual intervention required

---

## 🛡️ What's New in v1.5.1

### ClamAV Antivirus Integration (CRITICAL SECURITY FIX)

**Problem Solved**: Emails were being processed WITHOUT virus scanning, despite ClamAV daemon running.

**What's Fixed**:
- ✅ Antivirus scanner now integrated into email processing pipeline
- ✅ All email attachments scanned before delivery
- ✅ Virus detection adds +20 spam points and quarantines infected emails
- ✅ New headers: `X-Virus-Detected`, `X-Virus-Names`
- ✅ Scans against 27,796+ virus signatures

**Impact**: Critical security gap closed - all incoming emails now protected against viruses.

---

## 📊 What's New in v1.5.0

### Spam Score Headers Enhancement

**Problem Solved**: Comprehensive spam headers were being added to emails but NOT stored in database.

**What's Fixed**:
- ✅ Spam headers now properly stored in database
- ✅ Removed duplicate `X-SpaCy-Spam-Score` header
- ✅ `X-Spam-Score-Total` is now single source of truth
- ✅ Fixed thread analysis misleading "disabled" header
- ✅ Enhanced admin UI with spam score breakdown

### Email Retention System UI

- ✅ New cleanup configuration card in System Administration dashboard
- ✅ Detailed spam breakdown in email detail view
- ✅ Better visibility into spam scoring decisions

---

## 🔧 Technical Changes

### Package Dependencies
- **Added**: `cron` to core system packages (prevents cron missing on minimal installations)

### Installation Scripts
- **lib/packages.sh**: Added cron dependency
- **lib/modules.sh**: Cleanup script deployment logic
- **lib/services.sh**: Cron job setup function (`setup_cleanup_cron()`)

### Email Processing
- **email_filter.py**:
  - Integrated antivirus scanning (lines 1673-1710)
  - Fixed database storage timing for headers
  - Removed duplicate spam score headers
  - Cleaned up thread analysis headers

### Email Retention
- **cleanup_expired_emails.py**: NEW - Automated email deletion script
  - Configurable retention period (default: 30 days)
  - Separate handling for quarantine vs. analyzed emails
  - Logging to `/opt/spacyserver/logs/cleanup.log`

### Database Schema
- **Added column**: `client_domains.relay_port` (default: 25)
- **Added table**: `system_settings` (cleanup configuration)

### Web Interface
- **app.py**: Cleanup configuration routes
- **config_dashboard.html**: Email Cleanup configuration card
- **email_detail.html**: Spam score breakdown UI

---

## 📦 Installation

### Fresh Installation

```bash
git clone https://github.com/openefaadmin/openefa-installer.git
cd openefa-installer
sudo ./install.sh
```

The installer will now automatically:
- Install all required packages (including cron)
- Deploy email cleanup script
- Configure cron job for daily cleanup
- Enable ClamAV antivirus scanning
- Set up comprehensive spam headers

### Upgrading from v1.4.x or earlier

```bash
cd /opt/openefa-installer
git pull origin main

# Update email filter with antivirus integration
sudo cp openefa-files/email_filter.py /opt/spacyserver/
sudo chown spacy-filter:spacy-filter /opt/spacyserver/email_filter.py
sudo chmod 755 /opt/spacyserver/email_filter.py

# Deploy cleanup script
sudo cp openefa-files/cleanup_expired_emails.py /opt/spacyserver/
sudo chown spacy-filter:spacy-filter /opt/spacyserver/cleanup_expired_emails.py
sudo chmod 755 /opt/spacyserver/cleanup_expired_emails.py

# Update web interface
sudo cp -r openefa-files/web/* /opt/spacyserver/web/
sudo chown -R spacy-filter:spacy-filter /opt/spacyserver/web

# Set up cron job
(sudo crontab -u spacy-filter -l 2>/dev/null || true; echo "0 2 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py >> /opt/spacyserver/logs/cleanup.log 2>&1") | sudo crontab -u spacy-filter -

# Apply database changes
sudo mysql -u root -p spacy_email_db < sql/schema_v1.sql

# Restart services
sudo systemctl restart spacy-db-processor
sudo systemctl restart spacyweb
```

---

## ✅ Verification

After installation or upgrade, verify all features are working:

### 1. Check Cleanup Script
```bash
# Verify script exists
ls -lh /opt/spacyserver/cleanup_expired_emails.py

# Check cron job
sudo crontab -u spacy-filter -l | grep cleanup

# Test manual execution
sudo -u spacy-filter /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py

# View cleanup log
tail -20 /opt/spacyserver/logs/cleanup.log
```

### 2. Check Antivirus Integration
```bash
# Verify ClamAV is running
systemctl status clamav-daemon

# Send test email with attachment and check logs
sudo tail -f /opt/spacyserver/logs/email_filter_debug.log | grep -i virus
```

### 3. Check Spam Headers
```bash
# Send test email and verify headers in database
sudo mysql -u root -p -e "SELECT subject, spam_score FROM spacy_email_db.email_analysis ORDER BY id DESC LIMIT 5;"
```

### 4. Check Web Interface
- Navigate to: `https://your-server:5500/config`
- Verify "Email Cleanup" card appears in System Administration section
- Click on any email in quarantine
- Verify "Spam Score Breakdown" section appears

---

## 🔍 Known Issues

None at this time. All issues discovered during v1.5.0-v1.5.1 testing have been resolved.

---

## 📊 Testing

This release has been thoroughly tested on:
- **Production Server**: Ubuntu 22.04 LTS (full installation)
- **Dev Server**: Ubuntu 24.04 LTS (minimal installation)

All features verified working:
- ✅ Email filtering with antivirus scanning
- ✅ Spam header storage in database
- ✅ Cleanup script execution
- ✅ Cron job configuration
- ✅ Web interface enhancements
- ✅ All services running correctly

---

## 🐛 Bug Fixes

### v1.5.2
- Fixed cleanup script not being deployed during installation
- Fixed cron job not being configured automatically
- Added cron to package dependencies for minimal Ubuntu installations

### v1.5.1
- **CRITICAL**: Fixed emails not being scanned for viruses
- Fixed antivirus module not being called in email processing pipeline

### v1.5.0
- **CRITICAL**: Fixed spam headers not being stored in database
- Fixed duplicate spam score headers (removed X-SpaCy-Spam-Score)
- Fixed misleading thread analysis "disabled" header

---

## 🔐 Security Enhancements

- **Antivirus Protection**: All emails now scanned for viruses before delivery
- **Automated Cleanup**: Old emails automatically deleted based on retention policy
- **Enhanced Headers**: Better spam score tracking for security analysis

---

## 📝 Documentation

- **CHANGES_v1.5.0.md**: Detailed v1.5.0 changes
- **CHANGES_v1.5.1.md**: Detailed v1.5.1 changes (antivirus integration)
- **CHANGES_v1.5.2.md**: Detailed v1.5.2 changes (cleanup deployment)
- **PROJECT_MEMORY.md**: Updated with all v1.5.x session notes

---

## 🙏 Credits

Development and testing by the OpenEFA team with assistance from Claude Code.

---

## 📞 Support

- **Issues**: https://github.com/openefaadmin/openefa-installer/issues
- **Forum**: https://forum.openefa.com
- **Website**: https://openefa.com

---

## 📅 Changelog Summary

| Version | Date | Type | Description |
|---------|------|------|-------------|
| v1.5.2 | 2025-10-18 | Bug Fix | Cleanup script deployment fix, cron dependency added |
| v1.5.1 | 2025-10-18 | Security | ClamAV antivirus integration (CRITICAL) |
| v1.5.0 | 2025-10-18 | Bug Fix | Spam headers storage fix, UI enhancements |
| v1.4.0 | 2025-10-17 | Feature | Email retention system, relay port configuration |

---

**Full Changelog**: https://github.com/openefaadmin/openefa-installer/compare/v1.4.0...v1.5.2

**Download**: https://github.com/openefaadmin/openefa-installer/archive/refs/tags/v1.5.2.tar.gz
