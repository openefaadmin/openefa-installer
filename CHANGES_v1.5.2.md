# OpenEFA Installer v1.5.2 - Installation Fix for Email Cleanup

**Release Date:** 2025-10-18
**Priority:** Medium - Installation Completeness
**Type:** Bug Fix

---

## Overview

Version 1.5.2 fixes an installation issue where the email cleanup script and its cron job were not being deployed during installation, despite the cleanup system being configured in the database.

---

## Issue Fixed

### Problem
During installation verification on the dev server (192.168.50.66), the following issue was discovered:

- **Missing File**: `/opt/spacyserver/cleanup_expired_emails.py` was not deployed
- **Missing Cron Job**: No cron job was configured to run the cleanup script
- **Inconsistency**: Database had cleanup enabled (`cleanup_expired_emails_enabled: true`) but the script wasn't available

### Root Cause
The installer was not configured to:
1. Copy `cleanup_expired_emails.py` from the installer files to the installation directory
2. Set up the cron job to run the cleanup script daily

---

## Changes Made

### 1. Package Dependencies (`lib/packages.sh`)

Added `cron` to core system packages to ensure cron is installed on minimal Ubuntu installations:

```bash
local packages=(
    # ... existing packages ...
    "cron"  # ← NEW - Required for cleanup cron jobs
)
```

**Location**: `/opt/openefa-installer/lib/packages.sh` line 47

**Reason**: Dev server testing revealed that minimal Ubuntu installations may not have cron pre-installed, which prevented the cleanup cron job from being configured.

### 2. File Deployment (`lib/modules.sh`)

Added cleanup script deployment to the `copy_module_files()` function:

```bash
# Copy cleanup_expired_emails.py (email retention cleanup script)
if [[ -f "${source_dir}/cleanup_expired_emails.py" ]]; then
    cp "${source_dir}/cleanup_expired_emails.py" "${install_dir}/"
    chown spacy-filter:spacy-filter "${install_dir}/cleanup_expired_emails.py"
    chmod 755 "${install_dir}/cleanup_expired_emails.py"
    debug "Copied: cleanup_expired_emails.py"
fi
```

**Location**: `/opt/openefa-installer/lib/modules.sh` lines 43-49

### 3. Cron Job Setup (`lib/services.sh`)

Added new function `setup_cleanup_cron()` to configure the daily cleanup job:

```bash
setup_cleanup_cron() {
    info "Configuring email cleanup cron job..."

    # Check if cleanup script exists
    if [[ ! -f "/opt/spacyserver/cleanup_expired_emails.py" ]]; then
        warn "cleanup_expired_emails.py not found, skipping cron setup"
        return 0
    fi

    # Create cleanup log file
    touch /opt/spacyserver/logs/cleanup.log
    chown spacy-filter:spacy-filter /opt/spacyserver/logs/cleanup.log
    chmod 644 /opt/spacyserver/logs/cleanup.log

    # Add cron job for spacy-filter user (runs daily at 2 AM)
    local cron_entry="0 2 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py >> /opt/spacyserver/logs/cleanup.log 2>&1"

    # Get existing crontab, add new entry if not already present
    (crontab -u spacy-filter -l 2>/dev/null || true; echo "${cron_entry}") | \
        grep -v "cleanup_expired_emails.py" | \
        { cat; echo "${cron_entry}"; } | \
        crontab -u spacy-filter -

    success "Email cleanup cron job configured (daily at 2 AM)"
    return 0
}
```

**Location**: `/opt/openefa-installer/lib/services.sh` lines 147-175

### 4. Integration into Installation Flow

Modified `setup_services()` to call `setup_cleanup_cron()`:

```bash
setup_services() {
    # ... existing code ...
    setup_db_processor_service || return 1
    setup_spacyweb_service || return 1
    setup_api_services || return 1
    setup_logrotate || return 1
    setup_cleanup_cron || return 1  # ← NEW
    # ... existing code ...
}
```

**Location**: `/opt/openefa-installer/lib/services.sh` line 190

---

## What Gets Installed

### File Deployed
- **Path**: `/opt/spacyserver/cleanup_expired_emails.py`
- **Owner**: `spacy-filter:spacy-filter`
- **Permissions**: `755` (executable)
- **Purpose**: Deletes emails older than retention period based on system settings

### Cron Job Created
- **User**: `spacy-filter`
- **Schedule**: `0 2 * * *` (daily at 2:00 AM)
- **Command**: `/opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py`
- **Logging**: Output redirected to `/opt/spacyserver/logs/cleanup.log`

### Log File Created
- **Path**: `/opt/spacyserver/logs/cleanup.log`
- **Owner**: `spacy-filter:spacy-filter`
- **Permissions**: `644`

---

## Verification After Installation

After running the installer, verify the cleanup system is properly configured:

```bash
# 1. Verify script exists
ls -lh /opt/spacyserver/cleanup_expired_emails.py

# 2. Verify cron job is configured
sudo crontab -u spacy-filter -l | grep cleanup

# 3. Verify cleanup settings in database
mysql -u root -p -e "SELECT setting_key, setting_value FROM spacy_email_db.system_settings WHERE setting_key LIKE 'cleanup%';"

# 4. Check cleanup log file exists
ls -lh /opt/spacyserver/logs/cleanup.log
```

**Expected Results**:
- Script exists: `-rwxr-xr-x spacy-filter spacy-filter 6.5K cleanup_expired_emails.py`
- Cron entry: `0 2 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py >> /opt/spacyserver/logs/cleanup.log 2>&1`
- Database settings: `cleanup_expired_emails_enabled: true`, `cleanup_retention_days: 30`
- Log file exists: `-rw-r--r-- spacy-filter spacy-filter cleanup.log`

---

## Testing

### Manual Test of Cleanup Script
```bash
# Run cleanup script manually to test
sudo -u spacy-filter /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py

# Check the log for results
tail -20 /opt/spacyserver/logs/cleanup.log
```

---

## Files Modified

1. **`/opt/openefa-installer/lib/packages.sh`**
   - Added `cron` to core packages array (line 47)

2. **`/opt/openefa-installer/lib/modules.sh`**
   - Added cleanup script deployment (lines 43-49)

3. **`/opt/openefa-installer/lib/services.sh`**
   - Added `setup_cleanup_cron()` function (lines 147-175)
   - Modified `setup_services()` to call new function (line 190)
   - Updated function exports (line 200)

4. **`/opt/openefa-installer/VERSION`**
   - Bumped to 1.5.2

5. **`/opt/openefa-installer/CHANGES_v1.5.2.md`** (NEW)
   - This document

---

## Impact

- **Existing Installations**: No impact - this only affects fresh installations
- **New Installations**: Cleanup system will be fully configured and operational
- **Upgrade Path**: If you installed v1.5.0 or v1.5.1, you can manually:
  1. Copy the cleanup script: `sudo cp /opt/openefa-installer/openefa-files/cleanup_expired_emails.py /opt/spacyserver/`
  2. Set permissions: `sudo chown spacy-filter:spacy-filter /opt/spacyserver/cleanup_expired_emails.py && sudo chmod 755 /opt/spacyserver/cleanup_expired_emails.py`
  3. Add cron job: `(sudo crontab -u spacy-filter -l 2>/dev/null; echo "0 2 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/cleanup_expired_emails.py >> /opt/spacyserver/logs/cleanup.log 2>&1") | sudo crontab -u spacy-filter -`

---

## Related Features

This fix ensures the **Email Retention System** (v1.4.0) works as designed:

- **Automatic Cleanup**: Emails older than retention period are deleted daily
- **Configurable Retention**: Default 30 days, configurable via SpacyWeb
- **Prevent Spam Release**: Optional setting to prevent release of quarantined emails after retention period
- **Admin Control**: Enable/disable cleanup via `/config/cleanup` in SpacyWeb

---

## Developer Notes

The cleanup system requires three components to work together:

1. **Database Configuration** (`system_settings` table) - Already working ✅
2. **Python Script** (`cleanup_expired_emails.py`) - Fixed in this release ✅
3. **Cron Scheduler** (crontab for spacy-filter user) - Fixed in this release ✅
4. **Web Interface** (`/config/cleanup` route in app.py) - Already working ✅

All four components are now properly installed and configured by the installer.

---

**Next Version**: TBD
**Previous Version**: [v1.5.1](CHANGES_v1.5.1.md) - ClamAV Antivirus Integration
