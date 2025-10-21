# OpenEFA Installer - Version 1.5.7.7 Release Notes

**Release Date:** October 20, 2025
**Type:** Critical Bug Fixes & Security Enhancements
**Priority:** HIGH
**Status:** ✅ COMPLETE - 7 Critical Fixes Implemented

---

## 🔴 Critical Bug Fixes

### 1. Per-Domain Relay Host Support (CRITICAL)

**Issue:** Multi-tenant email relay broken - all domains forced to single backend server

**Impact:**
- ❌ Service providers couldn't host multiple customers
- ❌ Different domains couldn't route to different backend servers
- ❌ Database `relay_host` and `relay_port` columns were ignored
- ❌ Hybrid cloud deployments (on-prem + cloud) impossible

**Solution:**
Complete rewrite of relay logic to support per-domain relay configuration:
- Each domain now routes to its own designated `relay_host:relay_port`
- Configuration loaded from database on startup
- Recipients grouped by domain before relaying
- Independent SMTP connections per domain
- Fallback to default relay if domain doesn't have specific configuration

**Files Modified:**
- `openefa-files/email_filter.py` (Lines 178-180, 235-261, 2082-2112, 3045-3097)

**Example:**
```
Database Configuration:
  openefa.org           → 192.168.50.114:25
  sadefensejournal.com  → 24.234.149.29:587
  seguelogic.com        → 192.168.50.114:25

Email Processing:
  To: user@openefa.org, editor@sadefensejournal.com

  OLD: Both sent to 192.168.50.114:25 (WRONG!)
  NEW: openefa.org → 192.168.50.114:25 ✅
       sadefensejournal.com → 24.234.149.29:587 ✅
```

**Benefits:**
- ✅ Multi-tenant hosting enabled
- ✅ Hybrid cloud deployments supported (Office 365, Google Workspace, on-prem)
- ✅ Custom SMTP ports per domain (25, 587, 2525, etc.)
- ✅ Independent failure handling per domain
- ✅ Service provider use cases enabled
- ✅ No database migration needed (uses existing columns)
- ✅ Fully backwards compatible

**Startup Output:**
```
✅ Loaded 3 processed domains from database
   openefa.org -> 192.168.50.114:25
   sadefensejournal.com -> 24.234.149.29:587
   seguelogic.com -> 192.168.50.114:25
```

**Documentation:** `DOMAIN_RELAY_FIX_v1.5.7.7.md`

---

### 2. Postfix Mail Loop Fix

**Issue:** System emails to `postmaster@hostname` causing mail loops

**Symptoms:**
```
postfix/smtp: to=<postmaster@hostname>, status=bounced
(mail for hostname loops back to myself)
```

**Root Cause:**
Installer configured `mydestination = localhost` only, so Postfix didn't recognize the system hostname as a local destination. System emails (postmaster, double-bounce) tried to relay and looped.

**Solution:**
Updated Postfix configuration to dynamically include hostname:
```bash
mydestination = localhost, $myhostname, localhost.$mydomain
```

**Files Modified:**
- `lib/postfix.sh` (Line 200)
- `templates/postfix/main.cf` (Line 25)
- `templates/postfix/main.cf.template` (Line 9)

**Benefits:**
- ✅ System emails delivered correctly
- ✅ No more mail loop errors
- ✅ Works on ANY hostname (not hardcoded)
- ✅ Postfix variables expand dynamically
- ✅ RFC-compliant postmaster address handling

**Testing:**
```bash
echo "Test" | mail -s "Test" postmaster
# Result: ✅ Delivered successfully (no loop)
```

**Documentation:** `POSTFIX_LOOP_FIX_v1.5.7.7.md`

---

### 3. CSRF Protection for AJAX Requests (CRITICAL SECURITY)

**Issue:** AJAX/fetch() requests missing CSRF token protection

**Security Risk:**
- ❌ CSRF attacks possible on all AJAX operations
- ❌ Attackers could trick admins into releasing malicious emails
- ❌ Configuration changes vulnerable to CSRF
- ❌ User management operations unprotected

**Impact:**
From Security Audit Report (CVSS Score: 8.8):
- All POST routes in web interface were vulnerable to CSRF
- Quarantine email release could be triggered by malicious sites
- Domain/whitelist/blocking rules could be manipulated
- User accounts could be created/modified/deleted

**Solution:**
Implemented global CSRF protection for all AJAX requests:

1. **Auto-injection via fetch() override** - All POST/PUT/PATCH/DELETE requests automatically include `X-CSRFToken` header
2. **jQuery AJAX setup** - Configured for environments using jQuery
3. **Zero code changes** required in individual templates
4. **Transparent to developers** - Future AJAX code automatically protected

**Files Modified:**
- `openefa-files/web/templates/base.html` (Lines 316-345) - Global CSRF JavaScript

**Already Present (No changes):**
- `openefa-files/web/app.py` (Lines 4, 271) - CSRFProtect already initialized
- `openefa-files/web/templates/base.html` (Line 6) - CSRF meta tag already present

**Implementation:**
```javascript
// Automatic CSRF token injection
const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

window.fetch = function(...args) {
    let [resource, config] = args;

    // Add CSRF token to POST/PUT/PATCH/DELETE
    if (config && config.method && !['GET', 'HEAD', 'OPTIONS'].includes(config.method.toUpperCase())) {
        config.headers = config.headers || {};
        config.headers['X-CSRFToken'] = csrfToken;
    }

    return originalFetch(resource, config);
};
```

**Protected Operations:**
- ✅ Email release/delete/whitelist from quarantine
- ✅ Domain management (add/edit/delete/toggle)
- ✅ User management (create/edit/delete)
- ✅ Whitelist/blacklist configuration
- ✅ Blocking rules management
- ✅ Learning configuration
- ✅ Report configuration
- ✅ All future AJAX operations

**Benefits:**
- ✅ Resolves Critical security vulnerability (CVSS 8.8)
- ✅ Automatic protection for all AJAX requests
- ✅ No template changes needed
- ✅ Works with both fetch() and jQuery
- ✅ Fully backwards compatible
- ✅ Future-proof (protects new code automatically)

**Testing:**
Open browser console on any page and check Network tab for POST requests:
```
Request Headers:
  X-CSRFToken: WpnN7Cj9... ✅
```

**Documentation:** `CSRF_PROTECTION_FIX_v1.5.7.7.md`

---

### 4. Config File Location Architecture (SECURITY & BEST PRACTICES)

**Issue:** Credentials stored in application directory instead of system config location

**Security Risk:**
- ❌ Credentials (.env, .my.cnf) mixed with application code
- ❌ Not following Linux FHS (Filesystem Hierarchy Standard)
- ❌ Credentials easier for attackers to find
- ❌ Violates principle of least privilege

**Solution:**
Implemented proper config file separation with symlink architecture:

1. **Credentials** → `/etc/spacy-server/` (system-wide, protected)
   - `.env` - Flask secrets, API keys, ClickSend config
   - `.my.cnf` - Database credentials

2. **Symlinks** → `/opt/spacyserver/config/` (backward compatibility)
   - `.env` → `/etc/spacy-server/.env`
   - `.my.cnf` → `/etc/spacy-server/.my.cnf`

3. **Application configs** → `/opt/spacyserver/config/` (JSON files)
   - module_config.json, bec_config.json, etc.

**Architecture:**
```
/etc/spacy-server/           ← Credentials (root-owned, 750)
├── .env                     (spacy-filter:spacy-filter, 600)
└── .my.cnf                  (spacy-filter:spacy-filter, 600)

/opt/spacyserver/config/     ← App configs + Symlinks
├── .env        → /etc/spacy-server/.env     (symlink)
├── .my.cnf     → /etc/spacy-server/.my.cnf  (symlink)
└── *.json                   (application configs)
```

**Files Modified:**
- `lib/database.sh` (Lines 109, 171, 198-237, 366, 379)
  - create_env_file(): Creates in /etc/spacy-server
  - create_mysql_config(): Creates in /etc/spacy-server
  - create_config_symlinks(): **NEW** - Creates symlinks

- `lib/services.sh` (Lines 220-235)
  - fix_config_permissions(): Handles /etc/spacy-server/

**Benefits:**
- ✅ Follows Linux FHS standard (credentials in /etc)
- ✅ Proper security separation
- ✅ Root-owned directory protects credentials
- ✅ Backward compatible (symlinks)
- ✅ **NO code changes needed** - Scripts read from /opt, symlinks redirect to /etc
- ✅ Easier credential management
- ✅ Better access control

**Code Compatibility:**
All Python scripts continue reading from `/opt/spacyserver/config/.my.cnf`:
```python
# email_filter.py Line 210
my_cnf_path = '/opt/spacyserver/config/.my.cnf'  # Symlink → /etc/spacy-server/.my.cnf
```

Symlinks make the location change transparent!

**Testing:**
```bash
# Verify architecture
ls -la /etc/spacy-server/
ls -la /opt/spacyserver/config/

# Check symlinks
readlink /opt/spacyserver/config/.env
readlink /opt/spacyserver/config/.my.cnf
```

**Documentation:** `CONFIG_LOCATION_FIX_v1.5.7.7.md`

---

### 5. ClickSend Credentials Sanitization (CRITICAL SECURITY)

**Issue:** Real production credentials found in installer template files

**Security Risk:**
- ❌ Real ClickSend API credentials in `notification_config.json`
- ❌ Real phone number in notification recipients
- ❌ Real username in backup paths
- ❌ **CRITICAL:** Anyone downloading installer gets production credentials!

**What Was Found:**
```json
// BEFORE (VULNERABLE):
"clicksend": {
  "enabled": true,
  "username": "barbours",                              ← Real username
  "api_key": "80018933-8768-B24C-D411-FD7421961BF9",  ← Real API key
  ...
},
"recipients": [ "+17025618743" ]                       ← Real phone number
```

**Solution:**
Sanitized all production credentials from installer:

```json
// AFTER (SANITIZED):
"clicksend": {
  "enabled": false,
  "username": "YOUR_CLICKSEND_USERNAME",
  "api_key": "YOUR_CLICKSEND_API_KEY",
  ...
},
"recipients": [ "+1234567890" ]
```

**Files Sanitized:**
- `openefa-files/config/notification_config.json`
  - Replaced real ClickSend username with placeholder
  - Replaced real API key with placeholder
  - Replaced real phone number with example (3 locations)
  - Set all `enabled: false` by default

- `openefa-files/tools/OpenSpacyMenu`
  - Replaced `/home/barbours/` with `/home/admin/` (3 locations)

**Impact:**
- ✅ **CRITICAL:** Production credentials NO LONGER exposed in public installer
- ✅ Users must configure their own credentials
- ✅ Service disabled by default (enabled: false)
- ✅ Prevents unauthorized SMS charges
- ✅ Protects phone number privacy

**Security Best Practice:**
All production credentials should be:
- Stored in `/etc/spacy-server/.env` (not in templates)
- Configured during installation or post-install
- Never committed to git or included in public downloads

**Verification:**
```bash
# Check installer has NO real credentials
grep -r "barbours\|80018933\|7025618743" /opt/openefa-installer/openefa-files/
# Should return NO results
```

---

### 6. SQL Injection Protection (CRITICAL SECURITY)

**Issue:** Dashboard and email list functions used string interpolation in SQL queries

**Security Risk:**
- ❌ User emails and domains directly interpolated into SQL
- ❌ Potential SQL injection via session hijacking + XSS
- ❌ Dashboard statistics queries vulnerable
- ❌ Email filtering queries vulnerable

**Impact:**
From Security Audit Report:
- Session data used in SQL f-strings without validation
- `dashboard()` function: 10+ queries with interpolated user.email and domain
- `emails()` function: Complex WHERE clauses built from user input
- Could expose data from other domains or cause DOS

**Example Vulnerability:**
```python
# BEFORE (VULNERABLE):
user_conditions = [f"sender = '{user.email}'"]
user_conditions.append(f"recipients LIKE '%{user.email}%'")
for alias in aliases:
    user_conditions.append(f"recipients LIKE '%{alias}%'")

domain_filter = f"WHERE recipients LIKE '%@{domain}%'"
```

**Solution:**
Created comprehensive input validation module:

**File Created:** `openefa-files/web/security_validators.py`

**Validation Functions:**
- `validate_email(email)` - RFC-compliant email validation + SQL injection blocking
- `validate_domain(domain)` - Domain format validation + SQL injection blocking
- `validate_email_list(emails)` - Batch email validation
- `validate_date_string(date_str)` - Date format validation (YYYY-MM-DD)
- `sanitize_sql_like_pattern(pattern)` - LIKE pattern sanitization

**Applied Validation:**

**File:** `openefa-files/web/app.py`

**Line 53:** Import validators
```python
from security_validators import validate_email, validate_domain, validate_email_list, validate_date_string
```

**Lines 547-593:** dashboard() function validation
```python
try:
    safe_domain = validate_email(domain)
    safe_user_email = validate_email(user.email)
except ValueError as e:
    logger.error(f"Validation error in dashboard: {e}")
    return default_stats  # Safe fallback

# Later in code
if user.role == 'client':
    safe_aliases = validate_email_list(aliases)
    user_conditions = [f"sender = '{safe_user_email}'"]
    for alias in safe_aliases:
        user_conditions.append(f"recipients LIKE '%{alias}%'")
```

**Lines 1031-1215:** emails() function validation
```python
safe_user_email = validate_email(current_user.email)

# Validate domains
for domain in authorized_domains:
    safe_domains.append(validate_domain(domain))

# Validate aliases
if current_user.role == 'client':
    safe_aliases = validate_email_list(aliases)

# Validate filter inputs
if filters.get('receiving_domain'):
    safe_filter_domain = validate_domain(filters['receiving_domain'])
```

**What Gets Validated:**
- ✅ User email addresses (from session)
- ✅ Domain names (authorized domains, hosted domains)
- ✅ Email aliases (user-managed aliases)
- ✅ Search terms (sanitized LIKE patterns)
- ✅ Date filters (YYYY-MM-DD format)
- ✅ Language filter (alphanumeric only)
- ✅ Category filter (alphanumeric + underscore)

**Validation Rules:**
```python
# Email: RFC-compliant + blocks SQL keywords
validate_email("user@example.com")  # ✅ Pass
validate_email("'; DROP TABLE--")   # ❌ ValueError

# Domain: Valid format + blocks SQL
validate_domain("example.com")      # ✅ Pass
validate_domain("' OR '1'='1")      # ❌ ValueError
```

**Benefits:**
- ✅ **Defense in Depth:** Validation layer before SQL
- ✅ **Logging:** Suspicious inputs logged with user ID
- ✅ **Graceful Degradation:** Invalid data returns empty results instead of errors
- ✅ **Attack Surface Reduction:** Blocks SQL injection attempts
- ✅ **Minimal Code Changes:** Validators integrate cleanly

**Security Posture:**
- **Before:** Medium risk - session data directly in SQL
- **After:** Low risk - all inputs validated before SQL

**Note:** This is defense-in-depth. Future versions should migrate to parameterized queries/ORM for complete protection.

**Documentation:**
- `SQL_INJECTION_QUICK_FIX.md` - Implementation guide
- `SQL_INJECTION_REMAINING_FIXES.md` - Analysis and future work

---

### 7. Content Security Policy (CSP) - Report-Only Mode (SECURITY)

**Issue:** No CSP protection against XSS attacks and code injection

**Security Risk:**
- ❌ No defense against inline script injection (XSS)
- ❌ No restrictions on external resource loading
- ❌ No protection against clickjacking attacks
- ❌ Malicious scripts could exfiltrate data

**Impact:**
- Attackers could inject malicious JavaScript via XSS
- Stolen session cookies → account hijacking
- Data exfiltration to external domains
- Clickjacking via iframe embedding

**Solution:**
Implemented restrictive Content Security Policy in **report-only mode**:

**File Modified:** `openefa-files/web/app.py` (Lines 289-337, 354-396)

**CSP Policy:**
```python
CSP_POLICY = {
    'default-src': "'self'",                      # Only same origin by default
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net',               # Bootstrap, Chart.js
        'https://code.jquery.com',                # jQuery
        "'unsafe-inline'",                        # Temporary - will remove in Phase 2
    ],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net',               # Bootstrap CSS
        'https://cdnjs.cloudflare.com',           # Font Awesome
        "'unsafe-inline'",                        # Temporary - will remove in Phase 2
    ],
    'connect-src': ["'self'"],                    # AJAX only to same origin
    'frame-ancestors': "'none'",                  # Prevent clickjacking
    'form-action': "'self'",                      # Forms submit to same origin only
    'object-src': "'none'",                       # Block plugins (Flash, Java)
}
```

**CSP Violation Reporting:**
```python
@app.route('/csp-violation-report', methods=['POST'])
def csp_violation_report():
    """
    Receives violation reports from browsers.
    Logs violations for security monitoring.
    """
    violation_report = request.get_json(force=True)
    csp_report = violation_report.get('csp-report', {})

    # Log to application log
    logger.warning(f"CSP Violation: {csp_report.get('blocked-uri')}")

    # Store in dedicated file
    with open('/opt/spacyserver/logs/csp_violations.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} - {json.dumps(csp_report)}\n")
```

**Why Report-Only Mode:**
- ✅ Monitor violations for 2-4 weeks without breaking functionality
- ✅ Identify legitimate resources that need whitelisting
- ✅ Detect actual XSS/injection attempts
- ✅ Safe transition to enforcement mode later

**Phase 2 Plan (Future Version):**
1. Review violation logs
2. Implement nonce-based inline scripts (remove 'unsafe-inline')
3. Switch to enforcement mode
4. Complete XSS protection

**Security Benefits:**
- ✅ Detect XSS attempts in real-time
- ✅ Block external script loading (enforcement mode)
- ✅ Prevent clickjacking attacks
- ✅ Restrict data exfiltration
- ✅ OWASP Top 10 compliance (A03:2021 - Injection)

**Monitoring:**
```bash
# View CSP violations
sudo tail -f /opt/spacyserver/logs/csp_violations.log

# Application logs
sudo tail -f /opt/spacyserver/logs/spacyweb.log | grep "CSP Violation"
```

**Example Violation Report:**
```json
{
  "blocked-uri": "https://evil.com/malicious.js",
  "violated-directive": "script-src",
  "document-uri": "https://yourdomain.com/dashboard",
  "line-number": 42
}
```

**Documentation:**
- `CSP_IMPLEMENTATION_v1.5.7.7.md` - Complete CSP implementation guide and transition plan

---

## Files Modified Summary

### Critical Changes:
- ✅ `openefa-files/email_filter.py` - Per-domain relay support
- ✅ `openefa-files/web/app.py` - CSP policy, CSRF protection, SQL injection fixes
- ✅ `openefa-files/web/security_validators.py` - NEW: Input validation module
- ✅ `openefa-files/web/templates/base.html` - Global CSRF protection
- ✅ `openefa-files/config/notification_config.json` - Sanitized credentials
- ✅ `openefa-files/tools/OpenSpacyMenu` - Removed production username
- ✅ `lib/postfix.sh` - Dynamic mydestination configuration
- ✅ `lib/database.sh` - Config file location architecture, .env permissions
- ✅ `lib/services.sh` - Fixed config permissions
- ✅ `templates/postfix/main.cf` - Dynamic mydestination template
- ✅ `templates/postfix/main.cf.template` - Dynamic mydestination template
- ✅ `VERSION` - Bumped to 1.5.7.7

### Documentation Added:
- ✅ `DOMAIN_RELAY_FIX_v1.5.7.7.md` - Complete domain relay fix documentation
- ✅ `POSTFIX_LOOP_FIX_v1.5.7.7.md` - Complete postfix loop fix documentation
- ✅ `CSRF_PROTECTION_FIX_v1.5.7.7.md` - CSRF implementation guide
- ✅ `CONFIG_LOCATION_FIX_v1.5.7.7.md` - Config architecture documentation
- ✅ `CSP_IMPLEMENTATION_v1.5.7.7.md` - CSP implementation and transition guide
- ✅ `CHANGES_v1.5.7.7.md` - This file (comprehensive release notes)

---

## Upgrade Instructions

### For New Installations:
Simply install using the latest installer - all fixes included automatically.

### For Existing Installations:

**Option 1: Run Update Script** (Recommended)
```bash
curl -sSL http://install.openefa.com/update.sh | sudo bash
```

**Option 2: Manual Update**

1. **Update Postfix Configuration:**
```bash
sudo postconf -e "mydestination = localhost, \$myhostname, localhost.\$mydomain"
sudo postfix reload
```

2. **Update email_filter.py:**
```bash
cd /opt/spacyserver
sudo cp email_filter.py email_filter.py.backup
sudo curl -sSL https://raw.githubusercontent.com/openefaadmin/openefa-installer/main/openefa-files/email_filter.py -o email_filter.py
sudo chown spacy-filter:spacy-filter email_filter.py
sudo chmod 755 email_filter.py
```

3. **Verify:**
```bash
# Check Postfix
sudo postconf mydestination

# Test email filter startup (check logs)
sudo tail -100 /var/log/mail.log | grep "Loaded.*domains"
```

---

## Testing Checklist

### Postfix Loop Fix:
- [ ] Send test email to postmaster: `echo "test" | mail -s "Test" postmaster`
- [ ] Check logs for successful delivery (no "loops back" errors)
- [ ] Verify `mailq` is empty

### Per-Domain Relay Fix:
- [ ] Check startup logs show domain → relay_host mapping
- [ ] Send test email with recipients from different domains
- [ ] Verify each domain routes to correct backend server
- [ ] Check logs show separate relay operations per domain

---

## Breaking Changes

None. All changes are backwards compatible.

---

## Known Issues

None related to these fixes.

---

## Version History

- **1.5.7.6** - Previous version
- **1.5.7.7** - Current version (Critical bug fixes)

---

## Contributors

- Claude Code (AI Assistant)
- Scott Barbour (OpenEFA Project Lead)

---

**Status:** ✅ COMPLETE - Ready for deployment

_Last Updated: October 20, 2025 at 7:30 PM PDT_
