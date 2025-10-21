# Fix CSRF Token Error on Clean Installations

## Problem
After a fresh OpenEFA installation, you may encounter this error when accessing the web interface:

```
Bad Request
The CSRF session token is missing.
```

This error occurs across all browsers and is caused by a missing or invalid Flask secret key.

## Solution

Run this single command to fix the issue:

```bash
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/fix_csrf_token.sh | sudo bash
```

### What This Does

The fix script will:
1. ✅ Backup your current configuration file
2. ✅ Generate a new unique cryptographically secure secret key
3. ✅ Update the Flask configuration with the new key
4. ✅ Set proper file permissions
5. ✅ Restart the spacyweb service
6. ✅ Verify the service is running

### After Running the Fix

1. **Clear your browser cache and cookies** for the OpenEFA site
2. **Access the web interface again** - it should now work

### If You Prefer Manual Fix

If you don't want to use the curl command, you can manually fix it:

```bash
# Download the fix script
wget https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/fix_csrf_token.sh

# Make it executable
chmod +x fix_csrf_token.sh

# Run it
sudo ./fix_csrf_token.sh
```

## Future Installations

This issue has been fixed in version **1.5.7.8** and later. All new installations will automatically generate unique secret keys and will not experience this problem.

## Technical Details

**Root Cause:** Versions prior to 1.5.7.8 used a static, hardcoded Flask secret key from a template file instead of generating a unique one during installation.

**Fix Applied:** The installer now generates a unique 64-byte cryptographically secure secret key using Python's `secrets.token_urlsafe(64)` during installation.

**Files Modified:** `/opt/spacyserver/config/.app_config.ini`

## Still Having Issues?

If the fix doesn't work:

1. Check the service logs:
   ```bash
   sudo journalctl -u spacyweb -n 50
   ```

2. Verify the config file exists:
   ```bash
   sudo cat /opt/spacyserver/config/.app_config.ini
   ```

3. Check file permissions:
   ```bash
   sudo ls -la /opt/spacyserver/config/.app_config.ini
   ```
   Should show: `-rw-r----- 1 spacy-filter spacy-filter`

4. Report the issue at: https://github.com/openefaadmin/openefa-installer/issues
