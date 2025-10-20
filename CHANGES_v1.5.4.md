# OpenEFA v1.5.4 Release Notes

**Release Date:** October 19, 2025
**Version:** 1.5.4
**Type:** Feature Release + Bug Fixes

## Overview

Version 1.5.4 introduces advanced phishing detection capabilities, enhanced security controls, dashboard improvements, and critical bug fixes to improve system reliability and user experience.

---

## New Features

### 1. HTML Attachment Analyzer Module

**Description:** Advanced detection system for analyzing HTML file attachments to identify sophisticated phishing attempts.

**Capabilities:**
- **Credential Theft Detection:** Identifies HTML forms requesting sensitive information (passwords, SSNs, credit cards, security questions)
- **Hidden Iframe Detection:** Detects concealed iframes used for drive-by downloads or malicious content loading
- **Tracking Pixel Detection:** Identifies surveillance and tracking mechanisms (1x1 images, web beacons)
- **Brand Impersonation:** Recognizes fake login pages mimicking major brands (Microsoft, PayPal, Chase, Amazon, Apple, Google)
- **Urgency Tactics Detection:** Flags psychological manipulation techniques ("urgent action required", "expires in 24 hours")
- **High-Risk URI Analysis:** Identifies suspicious domains (.tk, .ml, .ga, .cf), URL shorteners, IP-based URLs

**Impact:** Adds 10-40 points to spam score based on threat severity

**Files Added:**
- `openefa-files/modules/html_attachment_analyzer.py` (696 lines, 27KB)

**Integration:**
- Automatically invoked during email processing for HTML attachments
- Fully integrated into email_filter.py module system
- Installer automatically deploys and configures the module

**Technical Details:**
- Uses BeautifulSoup for safe HTML parsing (no JavaScript execution)
- Regex-based pattern matching for sensitive form fields
- Brand detection via keyword and domain analysis
- Comprehensive logging for security auditing

---

### 2. Release Restrictions for Critical Threats

**Description:** Role-based access control preventing standard users from releasing very high-risk emails.

**Security Policy:**
- Emails with spam score ≥ 90.0 can only be released by:
  - Superadmin users
  - Admin users
  - Domain admin users
- Client-level users receive 403 Forbidden with clear error message
- All unauthorized release attempts are logged for security auditing

**User Experience:**
- Clear error message explains restriction and directs user to contact administrator
- JSON response includes `requires_admin: true` flag for frontend handling
- Maintains audit trail of all release attempts

**Files Modified:**
- `openefa-files/web/app.py` (lines 5246-5256)

**Implementation:**
```python
if spam_score >= 90.0:
    if not (current_user.is_superadmin() or current_user.is_admin() or current_user.role == 'domain_admin'):
        logger.warning(f"Client user {current_user.email} attempted to release critical threat")
        return jsonify({'success': False, 'error': 'Critical security threat...', 'requires_admin': True}), 403
```

---

### 3. Dashboard Card Improvements

**A. Security Threats Card (formerly "Virus Detected")**

**Changes:**
- Renamed from "Virus Detected" to "Security Threats"
- Updated description: "Viruses, URIs, BEC, etc."
- Enhanced query to include multiple threat types:
  ```sql
  SUM(CASE WHEN spam_score >= 50 OR email_category IN ('spam', 'phishing', 'virus') THEN 1 END)
  ```
- Now counts: viruses, high-spam emails, phishing, malicious URIs, BEC attempts

**B. Expiring Soon Card**

**Bug Fix:**
- **Problem:** Showed incorrect count (6 emails expiring on fresh install)
- **Cause:** Query was `spam_score >= 5.0` instead of time-based calculation
- **Fix:** Changed to proper timestamp-based query:
  ```sql
  COUNT(CASE WHEN timestamp < DATE_SUB(NOW(), INTERVAL 23 DAY) THEN 1 END)
  ```
- **Calculation:** 30-day retention - 7-day warning = 23 days threshold

**Files Modified:**
- `openefa-files/web/app.py` (lines 4960-4969)
- `openefa-files/web/templates/quarantine.html` (lines 188-194)

---

### 4. System Information Page

**Description:** Superadmin-only page displaying system version and component details.

**Features:**
- Displays OpenEFA version from VERSION file
- Shows system details (hostname, OS, Python version)
- Lists component versions with status indicators
- Support information and documentation links
- Auto-refresh every 30 seconds

**Access Control:**
- Protected by `@superadmin_required` decorator
- Only visible to users with superadmin role
- Configuration dashboard card shows "Superadmin" badge

**Files Added:**
- `openefa-files/web/templates/system_info.html` (223 lines, 7.1KB)

**Files Modified:**
- `openefa-files/web/templates/config_dashboard.html` (added System Information card)
- `openefa-files/web/app.py` (updated to read VERSION from /opt/spacyserver/)

**VERSION File Deployment:**
- Installer now copies VERSION file to /opt/spacyserver/
- Ensures version information persists after installation
- Proper permissions: spacy-filter:spacy-filter 644

---

## Bug Fixes

### 5. SMS Notification Permission Fix

**Problem:**
- Notification service failed to initialize due to permission denied errors
- Files owned by root:root, but email_filter runs as spacy-filter user

**Affected Files:**
- `/opt/spacyserver/logs/notifications.log` (root:root 644)
- `/opt/spacyserver/config/notification_config.json` (root:root 600)

**Fix:**
- Created `fix_notification_permissions()` function in lib/services.sh
- Sets proper ownership: spacy-filter:spacy-filter
- Sets correct permissions: 664 for log, 640 for config
- Automatically called during installation

**Files Modified:**
- `lib/services.sh` (lines 180-203, 219)

**Impact:** SMS notifications now work reliably for high-risk email alerts

---

### 6. Test Email Delivery Fix

**Problem:**
- Installation test email never arrived
- Using test@example.com (rejected by Postfix)
- Missing FQDN in HELO (violates reject_non_fqdn_helo_hostname)
- Silent output prevented debugging

**Fix:**
- Changed sender to: `openefa-test@${INSTALL_DOMAIN}`
- Added FQDN HELO: `$(hostname).${INSTALL_DOMAIN}`
- Changed recipient to: `${ADMIN_EMAIL}`
- Made output visible: `2>&1 | tee /tmp/swaks_test.log`
- Improved email body with helpful information

**Files Modified:**
- `lib/validation.sh` (lines 228-284)

**Impact:** Test email now reliably arrives in quarantine dashboard after installation

---

### 7. Config Dashboard Cleanup

**Changes:**
- **Removed:** Advanced Settings card (linked to non-existent /config/advanced route)
- **Added:** System Information card with superadmin gate
- **Result:** Cleaner configuration dashboard without broken links

**Files Modified:**
- `openefa-files/web/templates/config_dashboard.html`

---

### 8. User Edit Form Submission Fix

**Problem:**
- User update form button would not activate/submit
- Error: "An invalid form control with name='' is not focusable"
- Caused by hidden "Add New Alias" email field having `required` attribute
- HTML5 validation cannot focus hidden required fields, blocking form submission

**Affected Functionality:**
- Could not update user first name, last name, company name
- Could not change user roles or domain assignments
- Affected all users (superadmin, admin, domain_admin)

**Fix:**
- Removed `required` attribute from hidden alias email field (`#new-alias-email`)
- Validation still works when actually adding aliases (handled by JavaScript)
- Main user update form now submits properly

**Files Modified:**
- `openefa-files/web/templates/admin/edit_user.html` (line 169)

**Impact:** User management now works correctly for updating user information

---

## Installation Impact

### New Installations
All v1.5.4 features are automatically deployed:
- HTML attachment analyzer module installed and configured
- Release restrictions active (spam ≥ 90 requires admin)
- Dashboard improvements applied
- Notification permissions properly set
- Test email uses correct configuration
- VERSION file deployed to /opt/spacyserver/
- System information page available to superadmins

### Upgrades from v1.5.3
When upgrading from v1.5.3 → v1.5.4:
- HTML attachment analyzer will be added to modules directory
- Database schema: No changes required
- Configuration files: No migration needed
- Existing emails: Will be re-scored if re-analyzed
- User permissions: No changes required
- Service restarts: SpacyWeb, Postfix recommended

### Installer Modifications

**New Functions:**
- `install_html_attachment_analyzer()` in lib/modules.sh
- `fix_notification_permissions()` in lib/services.sh

**Updated Functions:**
- `copy_module_files()` - Now deploys VERSION file
- `test_email_processing()` - Improved test email configuration
- `install_modules()` - Calls HTML analyzer installation

---

## Security Considerations

### HTML Attachment Analyzer
- **Safe parsing:** Uses BeautifulSoup (no JavaScript execution)
- **No external requests:** All analysis is local
- **Privacy:** No data sent to third parties
- **Performance:** Minimal impact (~100ms per HTML attachment)

### Release Restrictions
- **Defense in depth:** Prevents accidental release of critical threats
- **Audit trail:** All attempts logged for security review
- **User experience:** Clear messaging guides users to proper escalation
- **Bypass:** Admins retain full control for legitimate releases

### Notification Permissions
- **Least privilege:** spacy-filter user has minimal required access
- **Secure storage:** notification_config.json protected at 640
- **API security:** ClickSend credentials properly isolated

---

## Testing Performed

### HTML Attachment Analyzer
- ✅ PayPal phishing test (score: 85.5, spam detected)
- ✅ Chase Bank phishing test (score: 100.5, critical threat)
- ✅ Microsoft login phishing (score: 105.5, critical threat)
- ✅ SMS notifications sent for high-risk emails
- ✅ Dashboard Security Threats card updated correctly

### Release Restrictions
- ✅ Client user blocked from releasing spam ≥ 90 (403 error)
- ✅ Admin user can release critical threats
- ✅ Unauthorized attempts logged correctly

### Dashboard Improvements
- ✅ Security Threats card counts viruses, URIs, high spam
- ✅ Expiring Soon shows 0 on fresh install
- ✅ Cards update in real-time

### Test Email
- ✅ Arrives in quarantine after installation
- ✅ Proper spam score (0.5 for legitimate test)
- ✅ Visible output for debugging

### System Information
- ✅ Page loads correctly for superadmins
- ✅ VERSION displayed accurately
- ✅ Component status shown properly
- ✅ Auto-refresh works

---

## Upgrade Instructions

### From v1.5.3 to v1.5.4

**Option 1: Using update.sh (Recommended)**
```bash
cd /opt/openefa-installer
sudo ./update.sh
```

**Option 2: Manual Upgrade**
```bash
# Backup current system
cd /opt/openefa-installer
sudo ./backup.sh

# Download latest version
cd /tmp
wget https://github.com/openefaadmin/openefa/archive/refs/tags/v1.5.4.tar.gz
tar -xzf v1.5.4.tar.gz
cd openefa-1.5.4

# Run installer (will detect existing installation)
sudo ./install.sh
```

**Post-Upgrade Steps:**
```bash
# Restart services
sudo systemctl restart spacyweb
sudo systemctl restart postfix
sudo systemctl restart spacy-db-processor

# Verify services
sudo systemctl status spacyweb
sudo systemctl status postfix

# Check logs
sudo tail -f /opt/spacyserver/logs/email_filter_debug.log
sudo tail -f /var/log/mail.log
```

---

## Known Issues

None at this time.

---

## File Manifest

### New Files
- `openefa-files/modules/html_attachment_analyzer.py`
- `openefa-files/web/templates/system_info.html`
- `openefa-files/web/templates/admin/edit_user.html`
- `CHANGES_v1.5.4.md`
- `RELEASE_PREP_v1.5.4.md`

### Modified Files
- `VERSION` (1.5.3 → 1.5.4)
- `openefa-files/web/app.py`
- `openefa-files/web/templates/quarantine.html`
- `openefa-files/web/templates/config_dashboard.html`
- `openefa-files/web/templates/admin/edit_user.html`
- `openefa-files/email_filter.py`
- `lib/modules.sh`
- `lib/services.sh`
- `lib/validation.sh`
- `PENDING_CHANGES.md`

---

## Contributors

- Development: Claude Code with Scott Barbour
- Testing: Scott Barbour
- Documentation: Claude Code

---

## Support

- **Website:** https://openefa.com
- **Documentation:** https://docs.openefa.com
- **GitHub:** https://github.com/openefaadmin/openefa
- **Issues:** https://github.com/openefaadmin/openefa/issues

---

## Changelog Summary

**Added:**
- HTML Attachment Analyzer module for advanced phishing detection
- Release restrictions for critical threats (spam ≥ 90)
- System Information page for superadmins
- VERSION file deployment to /opt/spacyserver/

**Changed:**
- Dashboard "Virus Detected" renamed to "Security Threats" with enhanced query
- Dashboard "Expiring Soon" fixed to use timestamp-based calculation
- Test email improved with proper domain and FQDN HELO
- Config dashboard cleaned up (removed broken Advanced Settings)

**Fixed:**
- SMS notification permission issues (notifications.log, notification_config.json)
- Test email delivery (domain, HELO, visibility)
- Dashboard card accuracy (Expiring Soon calculation)
- User edit form submission blocked by hidden required field

**Security:**
- Role-based access control for high-risk email release
- Enhanced phishing detection for HTML attachments
- Audit logging for unauthorized release attempts
