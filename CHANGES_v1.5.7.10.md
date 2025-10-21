# OpenEFA v1.5.7.10 - Final CSRF Fix (Flask-Talisman Configuration)

**Release Date:** 2025-10-21
**Release Type:** Hotfix
**Priority:** CRITICAL - All HTTP installations affected

## Critical Fixes

### CSRF Token Error - Flask-Talisman Override Issue
**Issue:** Even with `SESSION_COOKIE_SECURE=False` in .env, users still get "Bad Request - The CSRF session token is missing" error when trying to login over HTTP.

**Root Cause:** Flask-Talisman was overriding the Flask `SESSION_COOKIE_SECURE` configuration and forcing the Secure flag on session cookies, regardless of the .env setting. This meant cookies were still being rejected by browsers on HTTP connections.

**Complete CSRF Fix Timeline:**
- **v1.5.7.8:** Fixed Flask secret key generation (was using static template)
- **v1.5.7.9:** Set `SESSION_COOKIE_SECURE=False` in .env (but Talisman still overrode it)
- **v1.5.7.10:** Added `session_cookie_secure=False` to Talisman configuration ✅ **FINAL FIX**

**Why This Happened:**
Flask-Talisman is a security library that enforces HTTPS and security headers. By default, Talisman forces secure cookies even when Flask's `SESSION_COOKIE_SECURE` is set to False. The Talisman configuration needs an explicit `session_cookie_secure=False` parameter to allow HTTP cookies.

**Impact:**
- All clean installations accessing over HTTP cannot login
- Setting .env `SESSION_COOKIE_SECURE=False` alone was insufficient
- Session cookies still had the "Secure" flag, causing browser rejection
- No session = No CSRF token = Login fails with 400 Bad Request

**Fix:**
- Added `session_cookie_secure=False` parameter to Talisman configuration in `app.py`
- Updated `fix_csrf_token.sh` to patch both .env AND app.py Talisman settings
- Now session cookies work correctly over HTTP

**Files Modified:**
- `openefa-files/web/app.py` (line 327: added Talisman session_cookie_secure parameter)
- `fix_csrf_token.sh` (added Talisman configuration patching)
- `VERSION` (bumped to 1.5.7.10)

## Technical Details

### Flask-Talisman Cookie Behavior

**Before Fix:**
```python
Talisman(app,
    force_https=False,
    strict_transport_security=True,
    ...
)
# Result: Cookies still had "Secure" flag even with SESSION_COOKIE_SECURE=False in .env
```

**After Fix:**
```python
Talisman(app,
    session_cookie_secure=False,  # Allow session cookies over HTTP
    force_https=False,
    strict_transport_security=True,
    ...
)
# Result: Cookies work correctly over HTTP (no Secure flag)
```

### Cookie Header Comparison

**Before Fix (v1.5.7.9):**
```
Set-Cookie: guardianmail_session=...; Secure; HttpOnly; Path=/; SameSite=Lax
```
↑ The "Secure" flag prevents cookies from being sent over HTTP

**After Fix (v1.5.7.10):**
```
Set-Cookie: guardianmail_session=...; HttpOnly; Path=/; SameSite=Lax
```
↑ No "Secure" flag - cookies work over HTTP

### Configuration Hierarchy

1. **Talisman `session_cookie_secure` parameter** (HIGHEST PRIORITY)
   - Overrides Flask's SESSION_COOKIE_SECURE setting
   - Defaults to True if not specified

2. **Flask `app.config['SESSION_COOKIE_SECURE']`**
   - Set from .env `SESSION_COOKIE_SECURE`
   - Overridden by Talisman if Talisman doesn't specify session_cookie_secure

3. **.env `SESSION_COOKIE_SECURE`**
   - Loaded by Flask via `os.getenv()`
   - Cannot override Talisman settings

## Upgrade Path

### For New Installations
- Will automatically have both fixes applied
- Login will work immediately over HTTP
- No manual intervention needed

### For Existing Failed Installations (v1.5.7.8 or v1.5.7.9)

**Run the updated fix script:**
```bash
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/fix_csrf_token.sh | sudo bash
```

The script now fixes **THREE** things:
1. ✅ Generates unique Flask secret key (.app_config.ini)
2. ✅ Sets SESSION_COOKIE_SECURE=False (.env file)
3. ✅ Adds session_cookie_secure=False to Talisman (app.py) **NEW!**

### Manual Fix (Alternative)

If you prefer manual fixing:

```bash
# 1. Edit app.py
sudo nano /opt/spacyserver/web/app.py

# 2. Find the Talisman(app, line (around line 326)
# 3. Add this line RIGHT AFTER Talisman(app,:
    session_cookie_secure=False,  # Allow HTTP for local deployments

# 4. The result should look like:
Talisman(app,
    session_cookie_secure=False,  # Allow HTTP for local deployments
    force_https=False,
    ...
)

# 5. Restart service
sudo systemctl restart spacyweb

# 6. Clear browser cache/cookies and try logging in
```

## Security Considerations

### For HTTP Deployments (Default)
Current configuration is appropriate for:
- Internal/private networks (192.168.x.x, 10.x.x.x)
- Development/testing environments
- Deployments behind a reverse proxy handling HTTPS

Active protections still include:
- ✅ HttpOnly flag (prevents JavaScript access to cookies)
- ✅ SameSite=Lax (prevents CSRF attacks via cross-site requests)
- ✅ Flask-WTF CSRF protection
- ✅ Rate limiting
- ✅ SQL injection protection
- ✅ Content Security Policy

### For HTTPS Deployments

When you configure HTTPS, update **BOTH** settings:

```bash
# 1. Update .env
sudo nano /etc/spacy-server/.env
# Change: SESSION_COOKIE_SECURE=False
# To:     SESSION_COOKIE_SECURE=True

# 2. Update app.py
sudo nano /opt/spacyserver/web/app.py
# Change: session_cookie_secure=False
# To:     session_cookie_secure=True

# 3. Restart
sudo systemctl restart spacyweb
```

## Testing Notes

**Verified on:**
- Clean installation on Ubuntu
- Access via HTTP on port 5500
- Tested login with CSRF token submission
- Confirmed session cookie does NOT have Secure flag
- Login successful after fix

**Test Commands:**
```bash
# Check cookie headers
curl -v http://localhost:5500/auth/login 2>&1 | grep Set-Cookie

# Should show (without "Secure" flag):
# Set-Cookie: guardianmail_session=...; HttpOnly; Path=/; SameSite=Lax
```

## Lessons Learned

1. **Security libraries can override application settings**
   - Flask-Talisman takes precedence over Flask config
   - Must configure Talisman directly, not just Flask

2. **Test with actual HTTP requests, not just code review**
   - Cookie headers reveal actual behavior
   - `curl -v` is essential for debugging cookie issues

3. **Document configuration hierarchy**
   - Multiple layers of security configuration can conflict
   - Need clear documentation of what overrides what

## Related Issues

This fix completes the CSRF token issue resolution:
- **v1.5.7.8:** Fixed Flask secret key generation
- **v1.5.7.9:** Fixed .env SESSION_COOKIE_SECURE setting
- **v1.5.7.10:** Fixed Flask-Talisman session_cookie_secure parameter ✅

All three issues combined prevented CSRF tokens from working on fresh HTTP installations.

## Future Enhancements

Consider:
1. Adding installation prompt for HTTP vs HTTPS deployment
2. Automatically configuring both Talisman and Flask based on choice
3. Adding a web UI setting to switch between HTTP/HTTPS mode
4. Creating a diagnostic script that checks all CSRF-related settings
