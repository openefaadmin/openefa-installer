# Known Issues and Workarounds

This document tracks known issues in the OpenEFA installer and deployed systems along with their workarounds and resolution status.

---

## 🔴 CRITICAL: Installer Skip-Detection Causing Incomplete Updates

**Issue ID**: INST-001
**Severity**: High
**Affects**: All versions
**Status**: Known, workaround available
**Reported**: v1.5.7.6 (2025-10-20)

### Description

When running the installer on a system with existing OpenEFA components (partial installs, reinstalls, or updates), the installer's state detection mechanism may detect that certain components are "already configured" and skip their setup, even when critical configuration updates are needed.

This is particularly problematic for:
- Postfix configuration updates (sudoers file permissions)
- System service configurations
- Security-related configuration changes
- New dependency installations

### Symptoms

1. **Domain Addition Failures**: Domains added via SpacyWeb GUI are saved to database but not added to Postfix `relay_domains` in `/etc/postfix/main.cf`

2. **Missing Sudo Permissions**: `/etc/sudoers.d/spacy-postfix` contains only partial permissions:
   ```bash
   # Incomplete (old version):
   spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload

   # Missing permissions:
   # spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postconf -e *
   # spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
   ```

3. **Installer Output Shows Skips**:
   ```
   ✅ Postfix already configured, skipping...
   ✅ Dependencies already installed, skipping...
   ```

4. **Services May Be Outdated**: Even though installer completes successfully, services may be running old versions of code or missing new dependencies.

### Root Cause

The installer uses state files and detection logic to avoid re-running expensive operations. However, this logic:
1. Doesn't distinguish between "component exists" and "component is up-to-date"
2. Doesn't force-update critical security configurations
3. Doesn't handle partial or failed previous installations correctly

### Impact

**User Report**: "that is and has been a problem on a lot of our installs"

Systems affected by this issue may:
- Fail to relay email for domains added via GUI
- Lack critical sudo permissions for domain management
- Miss security updates in configuration files
- Run outdated service configurations

### Workaround (Manual Fix)

If you encounter domain management issues after installation:

#### 1. Fix Sudoers File

Edit `/etc/sudoers.d/spacy-postfix` and ensure it contains ALL permissions:

```bash
sudo visudo -f /etc/sudoers.d/spacy-postfix
```

Add these lines:
```bash
# Allow spacy-filter to manage Postfix configuration
# Required for domain management via web interface
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postconf -e *
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postmap /etc/postfix/transport
```

#### 2. Verify Domain Management Works

Test with this debug script:
```bash
#!/bin/bash
# Test domain addition to Postfix

DOMAIN="test-example.com"

echo "Current relay_domains:"
sudo postconf relay_domains

echo ""
echo "Adding $DOMAIN to relay_domains..."

# Get current value
CURRENT=$(sudo postconf -h relay_domains)

# Add new domain
if [[ -z "$CURRENT" ]]; then
    NEW="$DOMAIN"
else
    NEW="$CURRENT, $DOMAIN"
fi

# Update configuration
echo "sudo postconf -e \"relay_domains=$NEW\""
sudo -u spacy-filter sudo postconf -e "relay_domains=$NEW"

echo ""
echo "New relay_domains:"
sudo postconf relay_domains

echo ""
echo "Reloading Postfix..."
sudo -u spacy-filter sudo postfix reload

echo "✅ Test complete"
```

Run as root:
```bash
chmod +x test_domain_add.sh
sudo ./test_domain_add.sh
```

If you see `relay_domains` updated successfully, the fix worked.

#### 3. Force Reinstall If Needed

For severely incomplete installations:

```bash
# Full uninstall
cd /opt/spacyserver/installer  # or /opt/openefa-installer
sudo ./uninstall.sh

# Clean state files
sudo rm -rf /var/lib/openefa-state

# Fresh install
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/install.sh | sudo bash
```

### Permanent Fix (In Development)

The installer needs architectural changes:

1. **Version-Aware Updates**: Track component versions and force updates when versions change
2. **Configuration Drift Detection**: Hash configuration files and re-apply if they differ from expected state
3. **Mandatory Security Updates**: Never skip security-critical configuration updates
4. **State Validation**: Verify actual system state matches expected state after "skip" decisions

### Related Issues

- SQL injection protection added in v1.5.7.2 requires `security_validators.py` - may be missing on upgraded systems
- Flask security packages (flask-wtf, flask-limiter, flask-talisman, flask-caching) added in v1.5.7.4-1.5.7.6 - may be missing on earlier installs
- Database credentials moved from `/opt/spacyserver/config/.my.cnf` to `/etc/spacy-server/.my.cnf` in v1.5.7.1 - old code may still reference old path

### Testing Checklist After Fresh Install

After any fresh install or reinstall, verify:

```bash
# 1. Check sudoers has all permissions
sudo cat /etc/sudoers.d/spacy-postfix
# Should contain: postfix reload, postconf -e *, postmap commands

# 2. Verify Flask security packages
source /opt/spacyserver/venv/bin/activate
pip list | grep -i flask
# Should show: flask-wtf, flask-limiter, flask-talisman, flask-caching
deactivate

# 3. Check database credentials path
grep "read_default_file" /opt/spacyserver/services/db_processor.py
# Should show: /etc/spacy-server/.my.cnf (NOT /opt/spacyserver/config/.my.cnf)

# 4. Test domain addition via GUI
# Add a test domain via https://server-ip:5500
# Then verify:
sudo postconf relay_domains
# Should show the newly added domain

# 5. Verify security validators
ls -la /opt/spacyserver/web/security_validators.py
# Should exist for SQL injection protection
```

---

## Version History

- **v1.5.7.6** (2025-10-20): Issue documented, manual workaround provided
- **v1.5.7.3** (2025-10-20): Fixed db_processor.py path bug
- **v1.5.7.2** (2025-10-20): Added SQL injection protection

---

## Reporting New Issues

If you encounter a bug not listed here:

1. Check `/opt/spacyserver/VERSION` or `/opt/openefa-installer/VERSION` for your version
2. Collect logs from `/opt/spacyserver/logs/` and `/var/log/mail.log`
3. Report at: https://github.com/openefaadmin/openefa-installer/issues

Include:
- Version number
- Full error messages
- Steps to reproduce
- Output of `systemctl status spacyweb spacy-db-processor --no-pager`
