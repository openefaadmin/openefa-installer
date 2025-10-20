# OpenEFA v1.5.5 Release Notes

**Release Date:** October 20, 2025
**Version:** 1.5.5
**Type:** Critical Bug Fix Release

## Overview

Version 1.5.5 fixes critical template regressions introduced in v1.5.4 that broke backup management and other UI functionality.

---

## Critical Fixes

### 1. Fixed Template Regressions from v1.5.4

**Problem:**
- Backup management page lost download functionality
- Older versions of templates accidentally included in v1.5.4 installer
- Updates overwrote working templates with broken versions

**Fixed Templates:**
- `backup_management.html` - Restored auto-download functionality and backup options (14,507 → 19,580 bytes)
  - Re-added "Download Database Backup" and "Download Full System Backup" button labels
  - Restored backup option checkboxes (email attachments, config files, web application)
  - Re-implemented auto-download after backup creation (downloads to desktop immediately)
  - JavaScript now triggers download using `window.location.href = /api/backup/download/${filename}`
- `base.html` - Updated to latest version (13,325 → 13,510 bytes)
- `email_detail.html` - Updated to latest version (40,716 → 37,877 bytes)
- `emails.html` - Updated to latest version (34,478 → 32,605 bytes)
- `quarantine_detail.html` - Updated to latest version (16,036 → 13,461 bytes)

### 2. Fixed Config File Permission Errors

**Problem:**
- Full system backup failed with "Permission denied: /opt/spacyserver/config/module_config.json"
- Some config files owned by root:root instead of spacy-filter:spacy-filter
- Web application runs as spacy-filter user but couldn't read root-owned files

**Fix:**
- Created `fix_config_permissions()` function in lib/services.sh
- Automatically fixes ownership and permissions for all config files:
  - JSON config files: spacy-filter:spacy-filter with 640 permissions
  - .my.cnf (database credentials): spacy-filter:spacy-filter with 600 permissions
  - modules.ini: spacy-filter:spacy-filter with 600 permissions
  - .app_config.ini: spacy-filter:spacy-filter with 640 permissions
- Function runs automatically during installation
- Prevents backup failures and config access issues

### 3. System Settings Table Documentation

**Note:** The `system_settings` table IS included in the SQL schema and works correctly on fresh installs.

**Workaround for v1.5.4 Upgrades:**
If you see "Table 'spacy_email_db.system_settings' doesn't exist":

```sql
mysql -u root -p spacy_email_db <<'EOF'
CREATE TABLE IF NOT EXISTS `system_settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `setting_key` varchar(100) NOT NULL UNIQUE,
  `setting_value` text NOT NULL,
  `description` text DEFAULT NULL,
  `updated_by` varchar(100) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO system_settings (setting_key, setting_value, description, updated_by) VALUES
('cleanup_expired_emails_enabled', 'true', 'Enable automatic cleanup of expired quarantine emails', 'system'),
('cleanup_retention_days', '30', 'Number of days to retain emails before cleanup', 'system'),
('prevent_spam_release', 'false', 'Prevent releasing emails marked as spam (spam_score >= 5.0)', 'system')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);
EOF
```

---

## Upgrade Instructions

### Automatic Update (Recommended):
```bash
curl -sSL http://install.openefa.com/update.sh | sudo bash
# Select option "1" to update
```

### Post-Update:
1. If you have the system_settings error, run the SQL above
2. Restart SpacyWeb: `sudo systemctl restart spacyweb`
3. Test: Configuration → Backup & Restore → Download backup

---

## File Manifest

### Modified Files
- `VERSION` (1.5.4 → 1.5.5)
- `openefa-files/web/templates/backup_management.html` (restored auto-download functionality)
- `openefa-files/web/templates/base.html`
- `openefa-files/web/templates/email_detail.html`
- `openefa-files/web/templates/emails.html`
- `openefa-files/web/templates/quarantine_detail.html`
- `lib/services.sh` (added fix_config_permissions function)

### New Files
- `CHANGES_v1.5.5.md`

---

## Changelog Summary

**Fixed:**
- Template regressions from v1.5.4 (5 templates restored)
- Backup auto-download functionality restored (downloads to desktop immediately)
- Backup option checkboxes restored (attachments, config files, web application)
- Config file permission errors preventing full system backups
- All web templates synced to latest working versions
- All config files now have correct spacy-filter ownership and permissions

**Priority:** HIGH - All v1.5.4 users should upgrade immediately
