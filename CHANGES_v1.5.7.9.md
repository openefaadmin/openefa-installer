# OpenEFA v1.5.7.9 - Critical CSRF Fix (Session Cookie Issue)

**Release Date:** 2025-10-21
**Release Type:** Hotfix
**Priority:** CRITICAL - All HTTP installations affected

## Critical Fixes

### CSRF Token Error - SESSION_COOKIE_SECURE Issue
**Issue:** Users accessing OpenEFA over HTTP get "Bad Request - The CSRF session token is missing" error when trying to login.

**Root Cause:** The `.env` file was setting `SESSION_COOKIE_SECURE=True`, which requires HTTPS. When users access the web interface over HTTP (the default installation uses HTTP on port 5500), browsers reject the session cookie because the "Secure" flag requires HTTPS. Without a session cookie, CSRF tokens cannot be generated or validated.

**Why This Happened:**
- v1.5.7.8 fixed the Flask secret key generation but missed the SESSION_COOKIE_SECURE setting
- The session cookie security flag was set to True for all installations
- HTTP-only deployments (most local/internal installations) cannot use Secure cookies
- This prevented session creation, which broke CSRF protection

**Impact:**
- All clean installations accessing over HTTP cannot login
- Login form appears but submitting credentials fails with 400 Bad Request
- CSRF token is missing because no session can be established
- Affects all browsers identically (not browser-specific)

**Fix:**
- Changed default `SESSION_COOKIE_SECURE` from `True` to `False` in `/etc/spacy-server/.env`
- Updated `lib/database.sh` to create .env with `SESSION_COOKIE_SECURE=False`
- Updated `fix_csrf_token.sh` to also check and fix SESSION_COOKIE_SECURE setting
- Added documentation explaining when to use True (HTTPS) vs False (HTTP)

**Files Modified:**
- `lib/database.sh` (lines 135-140)
- `fix_csrf_token.sh` (added SESSION_COOKIE_SECURE check and fix)
- `VERSION` (bumped to 1.5.7.9)

## Technical Details

### SESSION_COOKIE_SECURE Behavior
When `SESSION_COOKIE_SECURE=True`:
- Browser will ONLY send the cookie over HTTPS connections
- HTTP connections will not receive or send the cookie
- No cookie = No session = No CSRF token = Login fails

When `SESSION_COOKIE_SECURE=False`:
- Browser sends the cookie over both HTTP and HTTPS
- Works for local/internal HTTP deployments
- Should be set to True when HTTPS is configured

### Security Considerations

**For HTTP deployments (default):**
- `SESSION_COOKIE_SECURE=False` is required for the system to work
- Still secure on private/internal networks (192.168.x.x, 10.x.x.x)
- Other protections remain active: HTTPONLY, SameSite=Lax, CSRF protection

**For HTTPS deployments:**
- Set `SESSION_COOKIE_SECURE=True` in `/etc/spacy-server/.env`
- Restart spacyweb: `sudo systemctl restart spacyweb`
- Provides additional protection against man-in-the-middle attacks

## Upgrade Path

### For New Installations
- Will automatically use `SESSION_COOKIE_SECURE=False`
- Login will work immediately over HTTP

### For Existing Failed Installations
Run the fix script:
```bash
curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/fix_csrf_token.sh | sudo bash
```

The script now:
1. Generates a new Flask secret key (from v1.5.7.8)
2. Fixes SESSION_COOKIE_SECURE setting (NEW in v1.5.7.9)
3. Restarts the service
4. Verifies everything is working

### Manual Fix (Alternative)
```bash
# Edit .env file
sudo nano /etc/spacy-server/.env

# Change this line:
SESSION_COOKIE_SECURE=True

# To this:
SESSION_COOKIE_SECURE=False

# Restart service
sudo systemctl restart spacyweb

# Clear browser cache/cookies and try again
```

## Testing Notes

**Test Environment:**
- Clean installation on Ubuntu
- Accessed via HTTP on port 5500
- Confirmed login now works after fix

**Verification:**
1. Check .env setting: `grep SESSION_COOKIE_SECURE /etc/spacy-server/.env`
2. Should show: `SESSION_COOKIE_SECURE=False`
3. Access web interface over HTTP
4. Login should work without CSRF errors

## Related Issues

This fix completes the CSRF token issue resolution started in v1.5.7.8:
- v1.5.7.8: Fixed Flask secret key generation
- v1.5.7.9: Fixed SESSION_COOKIE_SECURE for HTTP deployments

Both issues combined prevented CSRF tokens from working on fresh installations.

## Future Enhancements

Consider adding installation prompts to ask:
- Will you be using HTTPS? (Yes/No)
- If Yes: Set SESSION_COOKIE_SECURE=True
- If No: Set SESSION_COOKIE_SECURE=False (current default)

This would allow automatic configuration based on deployment type.
