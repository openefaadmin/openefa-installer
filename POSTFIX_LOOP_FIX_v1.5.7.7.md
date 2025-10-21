# Postfix Mail Loop Fix - v1.5.7.7

**Date:** October 20, 2025
**Priority:** HIGH - Bug Fix
**Issue:** Mail relay loop errors for system emails

---

## Problem

Postfix was generating "mail for [hostname] loops back to myself" errors when trying to deliver system emails (postmaster notifications, double-bounce messages, etc.).

### Symptoms

```
postfix/smtp[xxxxx]: to=<postmaster@hostname>, relay=hostname[127.0.1.1]:25,
delay=0, dsn=5.4.6, status=bounced (mail for hostname loops back to myself)
```

### Root Cause

The installer was configuring Postfix with:
```bash
mydestination = localhost
```

This meant Postfix would ONLY accept local delivery for `localhost`. When system processes sent emails to `postmaster@hostname` or `root@hostname`, Postfix didn't recognize the hostname as a local destination and tried to relay the message, which caused a mail loop.

---

## Solution

Updated the installer to dynamically configure `mydestination` to include the system hostname:

```bash
mydestination = localhost, $myhostname, localhost.$mydomain
```

This uses Postfix variables that are automatically expanded:
- `$myhostname` - The system's hostname (dynamically determined)
- `$mydomain` - The system's domain (dynamically determined)

### Why This Works

Now Postfix will accept local delivery for:
1. `localhost` - Standard local delivery
2. `$myhostname` - The actual hostname (e.g., `openspacy`, `mailserver`, etc.)
3. `localhost.$mydomain` - Domain-qualified localhost

This ensures system emails to `postmaster@hostname`, `root@hostname`, etc. are delivered locally instead of attempting to relay.

---

## Files Modified

### 1. `/opt/openefa-installer/lib/postfix.sh`

**Line 200 - BEFORE:**
```bash
postconf -e "mydestination=localhost"
```

**Line 200 - AFTER:**
```bash
postconf -e "mydestination=localhost, \$myhostname, localhost.\$mydomain"
```

**Note:** The `\$` escapes prevent bash variable expansion, allowing Postfix to expand these variables at runtime.

---

### 2. `/opt/openefa-installer/templates/postfix/main.cf`

**Line 25 - BEFORE:**
```
mydestination = $myhostname, {{HOSTNAME}}, localhost
```

**Line 25 - AFTER:**
```
mydestination = localhost, $myhostname, localhost.$mydomain
```

**Note:** Simplified to match the standard Postfix pattern and added `localhost.$mydomain` for consistency.

---

### 3. `/opt/openefa-installer/templates/postfix/main.cf.template`

**Line 9 - BEFORE:**
```
mydestination = localhost
```

**Line 9 - AFTER:**
```
mydestination = localhost, $myhostname, localhost.$mydomain
```

**Note:** This template file is not currently used by the installer but updated for consistency.

---

## Testing

### On Production Server (openspacy)

Applied fix manually to verify:
```bash
sudo postconf -e "mydestination = localhost, \$myhostname, localhost.\$mydomain"
sudo postfix reload
```

**Test Command:**
```bash
echo "Test message" | mail -s "Test postmaster fix" postmaster
```

**Result:** ✅ Email delivered successfully via spacyfilter, no loop errors

**Before Fix:**
```
status=bounced (mail for openspacy loops back to myself)
```

**After Fix:**
```
status=sent (delivered via spacyfilter service)
```

---

## Impact

### For New Installations
- ✅ System emails will be handled correctly out-of-the-box
- ✅ No more mail loop errors for hostname-based delivery
- ✅ Postmaster notifications work properly
- ✅ Double-bounce messages are handled correctly

### For Existing Installations
Existing installations can be fixed with:
```bash
sudo postconf -e "mydestination = localhost, \$myhostname, localhost.\$mydomain"
sudo postfix reload
```

Or by running the installer update script (will be included in v1.5.7.7 update).

---

## Why This Is Important

1. **System Stability:** Prevents mail queue buildup from bouncing system messages
2. **Monitoring:** Ensures system notifications reach administrators
3. **Compliance:** Proper handling of RFC-required postmaster address
4. **User Experience:** Works correctly on ANY hostname (not hardcoded to "openspacy")

---

## Postfix Variables Explained

These are **Postfix configuration variables**, not bash variables:

- `$myhostname` - Automatically set to the system's fully-qualified hostname
  - Example: `openspacy.localdomain`, `mail.example.com`, etc.
- `$mydomain` - Derived from `$myhostname` by removing the first component
  - Example: If `$myhostname = mail.example.com`, then `$mydomain = example.com`

By using these variables, the configuration works on **any** system without hardcoding specific hostnames.

---

## Documentation Updates

Added to:
- ✅ `/opt/openefa-installer/POSTFIX_LOOP_FIX_v1.5.7.7.md` (this document)
- ⏳ Update KNOWN_ISSUES.md (if this was a reported issue)
- ⏳ Update TROUBLESHOOTING.md with this fix

---

## Related Issues

This fix resolves:
- Double-bounce message loops
- Postmaster delivery failures
- System notification delivery issues
- Generic hostname compatibility (not hardcoded to specific server names)

---

## Version Information

- **Fixed in Version:** 1.5.7.7
- **Previous Version:** 1.5.7.6
- **Date:** October 20, 2025
- **Type:** Bug Fix

---

## Validation Checklist

For installations after this fix:

```bash
# 1. Check mydestination is set correctly
sudo postconf mydestination
# Should show: mydestination = localhost, $myhostname, localhost.$mydomain

# 2. Test postmaster delivery
echo "test" | mail -s "Test" postmaster

# 3. Check logs for successful delivery (no loop errors)
tail -20 /var/log/mail.log | grep postmaster
# Should show: status=sent (not status=bounced)

# 4. Verify mail queue is empty
mailq
# Should show: Mail queue is empty
```

---

**Generated with Claude Code**
**Co-Authored-By:** Claude <noreply@anthropic.com>
