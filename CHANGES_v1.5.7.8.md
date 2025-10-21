# OpenEFA v1.5.7.8 - Critical Security Fix

**Release Date:** 2025-10-21
**Release Type:** Hotfix
**Priority:** CRITICAL - All new installations affected

## Critical Fixes

### CSRF Token Generation Issue - Clean Installs
**Issue:** New installations were failing with "Bad Request - The CSRF session token is missing" error across all browsers.

**Root Cause:** The Flask secret key used for CSRF token generation was using a static, hardcoded value from the template file `/templates/config/.app_config.ini` instead of generating a unique cryptographically secure key during installation.

**Impact:**
- All clean installations failed to load the web interface
- Static secret key across installations created a security vulnerability
- CSRF protection was not functioning correctly

**Fix:**
- Modified `lib/modules.sh::install_module_configs()` to generate a unique Flask secret key using Python's `secrets.token_urlsafe(64)` during installation
- Each installation now receives a cryptographically secure, unique secret key
- Aligns with the same secure key generation method used for FLASK_SECRET_KEY in the .env file

**Files Modified:**
- `lib/modules.sh` (lines 131-145)
- `VERSION` (bumped to 1.5.7.8)

## Security Improvements

### Unique Secret Key Generation
- Each installation now generates a unique 64-byte URL-safe secret key
- Eliminates the security risk of shared secret keys across installations
- Ensures proper CSRF token generation and validation

## Testing Notes

For users experiencing the CSRF error on existing installations, you can regenerate the secret key by running:

```bash
# Generate new secret key
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")

# Update config file
sudo tee /opt/spacyserver/config/.app_config.ini > /dev/null << EOF
[flask]
secret_key = ${NEW_KEY}
EOF

# Fix permissions
sudo chown spacy-filter:spacy-filter /opt/spacyserver/config/.app_config.ini
sudo chmod 640 /opt/spacyserver/config/.app_config.ini

# Restart service
sudo systemctl restart spacyweb
```

## Upgrade Path

- **New Installations:** Will automatically receive unique secret keys
- **Existing Installations:** Working installations do not need to update unless experiencing CSRF issues
- **Failed Installations:** Follow the testing notes above to regenerate the secret key

## Related Issues

This fix addresses the installer bug reported where clean installations fail with CSRF token errors regardless of browser used.
