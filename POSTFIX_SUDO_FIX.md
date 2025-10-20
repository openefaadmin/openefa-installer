# Postfix Sudo Permissions Fix

**Date:** October 20, 2025
**Issue:** Domain addition failing due to insufficient sudo permissions
**Priority:** HIGH

## Problem

When adding domains via the web interface, the operation was failing because the `spacy-filter` user lacked sudo permissions to run `postmap` command.

### Error Symptoms:
- Domain addition would fail with permission errors
- `postmap` command unable to compile transport database
- Transport file updates not being applied

---

## Root Cause

The original sudoers configuration only included:
```bash
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
```

But the domain management functions in `app.py` require **three** Postfix commands:
1. `postfix reload` - Reload Postfix configuration
2. `postconf -e *` - Update relay_domains parameter
3. `postmap /etc/postfix/transport` - Compile transport map

---

## Solution

### 1. Updated Sudoers Configuration

**File:** `/etc/sudoers.d/spacy-postfix`

**NEW Configuration:**
```bash
# Allow spacy-filter to manage Postfix configuration
# Required for domain management via web interface
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postconf -e *
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
```

### 2. Updated app.py to Use Sudo for postmap

**File:** `/opt/spacyserver/web/app.py` (line 154)

**BEFORE:**
```python
result = subprocess.run(['postmap', transport_file],
                      capture_output=True, text=True, timeout=10)
```

**AFTER:**
```python
result = subprocess.run(['sudo', '/usr/sbin/postmap', transport_file],
                      capture_output=True, text=True, timeout=10)
```

---

## Files Modified

### Live System:
1. `/etc/sudoers.d/spacy-postfix` - Updated sudo permissions
2. `/opt/spacyserver/web/app.py` - Added sudo to postmap command

### Installer:
1. `/opt/openefa-installer/lib/postfix.sh` - Updated sudoers generation (lines 285-300)
2. `/opt/openefa-installer/openefa-files/web/app.py` - Added sudo to postmap command

---

## Testing

### Verify Sudo Permissions:
```bash
sudo -l -U spacy-filter | grep -E "postfix|postmap|postconf"
```

**Expected Output:**
```
(ALL) NOPASSWD: /usr/sbin/postfix reload
(ALL) NOPASSWD: /usr/sbin/postconf -e *
(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
```

### Test Domain Addition:
1. Log into web interface: `https://server-ip:5500`
2. Navigate to: Configuration → Domain Management
3. Click "Add Domain"
4. Enter test domain and relay host
5. Verify domain is added successfully

### Check Logs:
```bash
journalctl -u spacyweb -f --no-pager
tail -f /opt/spacyserver/logs/spacyweb.log
tail -f /var/log/mail.log
```

**Expected Log Entries:**
```
INFO - Reloaded X hosted domains from database
INFO - Updated Postfix transport file with X domains and reloaded Postfix
INFO - Updated Postfix relay_domains with X domains
```

---

## Why These Permissions Are Needed

### 1. `postfix reload`
- **When:** After updating transport map or relay_domains
- **Purpose:** Apply configuration changes without stopping mail service
- **Security:** Read-only operation, safe to allow

### 2. `postconf -e *`
- **When:** Adding/removing domains to update relay_domains parameter
- **Purpose:** Modify `/etc/postfix/main.cf` relay_domains setting
- **Security:** Limited to configuration updates, parameters validated in app.py

### 3. `postmap /etc/postfix/transport`
- **When:** After updating transport file with new domain routing
- **Purpose:** Compile text file into Berkeley DB format for Postfix
- **Security:** Limited to specific file, validated path in app.py

---

## Security Considerations

### ✅ Safe Practices Implemented:
1. **Specific Paths:** Sudo permissions limited to exact commands and paths
2. **NOPASSWD:** No password prompt needed (service runs as daemon)
3. **File Validation:** `visudo -c` validates syntax before applying
4. **Permissions:** 440 permissions on sudoers file (read-only)
5. **Audit:** All operations logged to syslog

### ⚠️ Security Notes:
- `postconf -e *` allows any parameter modification
  - Mitigated by: app.py only uses it for relay_domains
  - Alternative: Could restrict to `postconf -e relay_domains=*`
- All commands run with full root privileges
  - Necessary for Postfix configuration
  - Limited to specific Postfix management tasks

---

## Integration with v1.5.7 Security Update

This fix is part of the comprehensive security improvements in v1.5.7:

**Related Security Enhancements:**
- ✅ Credentials moved to `/etc/spacy-server/`
- ✅ CSRF protection on all forms
- ✅ SQL injection prevention
- ✅ Auto-generated secrets
- ✅ Proper sudo permissions (this fix)

**Documentation:**
- See: `INSTALLER_SECURITY_UPDATE_v1.5.7.md` for complete security changes
- See: `.gitignore` for credential protection

---

## Deployment Instructions

### For New Installations:
The installer now includes correct sudo permissions automatically.
No manual configuration needed.

### For Existing Installations:

1. **Update sudoers file:**
   ```bash
   sudo bash -c 'cat > /etc/sudoers.d/spacy-postfix << "EOSUDO"
   # Allow spacy-filter to manage Postfix configuration
   # Required for domain management via web interface
   spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
   spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postconf -e *
   spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
   EOSUDO
   '
   ```

2. **Set permissions and validate:**
   ```bash
   sudo chmod 440 /etc/sudoers.d/spacy-postfix
   sudo visudo -c -f /etc/sudoers.d/spacy-postfix
   ```

3. **Update app.py** (if using old version):
   Edit `/opt/spacyserver/web/app.py`, find line with:
   ```python
   result = subprocess.run(['postmap', transport_file],
   ```

   Change to:
   ```python
   result = subprocess.run(['sudo', '/usr/sbin/postmap', transport_file],
   ```

4. **Restart service:**
   ```bash
   sudo systemctl restart spacyweb
   ```

5. **Verify:**
   ```bash
   sudo systemctl status spacyweb --no-pager
   sudo -l -U spacy-filter | grep postfix
   ```

---

## Changelog

### Fixed in v1.5.7 (October 20, 2025)

**Installer Changes:**
- Added `postconf` sudo permission to `lib/postfix.sh`
- Added `postmap` sudo permission to `lib/postfix.sh`
- Updated `openefa-files/web/app.py` to use sudo for postmap
- Enhanced comments in sudoers configuration

**Live System Changes:**
- Updated `/etc/sudoers.d/spacy-postfix` with complete permissions
- Updated `/opt/spacyserver/web/app.py` to use sudo for postmap
- Restarted spacyweb service

**Result:**
- ✅ Domain addition now works correctly
- ✅ Transport map updates apply successfully
- ✅ Relay domains update without errors
- ✅ All Postfix operations function as expected

---

**Generated with Claude Code**
**Co-Authored-By:** Claude <noreply@anthropic.com>
