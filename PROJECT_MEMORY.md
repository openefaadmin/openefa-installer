# OpenEFA Project Memory
**Last Updated:** October 18, 2025

## Recent Session Summary (October 18, 2025)

### Domain Management Enhancement

#### relay_port Column Addition
**Status:** ✅ Complete

**Enhancement:** Added configurable relay port support to domain management
- Added `relay_port` column to `client_domains` table schema with default value of 25
- Updated installer database functions to include relay_port in domain insertion
- Allows per-domain relay port configuration via GUI (Domain Management page)
- Files modified:
  - `sql/schema_v1.sql` - Added relay_port column
  - `lib/database.sh` - Updated insert_initial_domain() function
- Version bumped to 1.1.0

**Benefits:**
- Supports relay servers using non-standard SMTP ports (e.g., 587, 2525)
- Enables flexible multi-tenant configurations with different relay requirements
- Fully integrated with existing domain management UI

---

## Previous Session Summary (October 16-17, 2025)

### Major Installer Fixes and Integration

#### Customer Issue Resolution
**Status:** ✅ Complete and tested on minimal Ubuntu 24.04

**Problem:** Customer experiencing "Command died with status 1" error on minimal Ubuntu installation
- Email filter crashing when processing emails
- Error: "No module named 'utils'"
- Missing Python packages: spacy, textblob, geoip2, PyMuPDF
- Pre-flight checks failing on minimal Ubuntu (missing iputils-ping, dnsutils)

**Root Causes:**
1. Minimal Ubuntu lacks diagnostic tools (iputils-ping, dnsutils, net-tools) causing pre-flight checks to fail
2. Utils module not created during installation (marketing_spam_filter.py and analysis.py import from utils.logging)
3. NumPy/Pandas/Matplotlib binary incompatibility (pandas compiled against NumPy 1.x, installer uses NumPy 2.x)
4. MariaDB data directory not initialized on some minimal installations
5. openefa-files directory excluded from installer package
6. behavioral_baseline.py config parser not stripping whitespace from keys

**Solutions Implemented:**

1. **Diagnostic Tools Installation** ✅
   - Install iputils-ping, dnsutils, net-tools BEFORE pre-flight checks
   - New function: `install_diagnostic_tools()` in lib/dependencies.sh
   - Called in install.sh lines 55-59

2. **Utils Module Creation** ✅
   - Automatically create /opt/spacyserver/utils/ directory
   - Create utils/__init__.py and utils/logging.py with safe_log(), log_sentiment_debug()
   - Function: `create_utils_module()` in lib/dependencies.sh

3. **NumPy/Pandas Compatibility Fix** ✅
   - Install numpy>=2.3.0 FIRST in pip packages list (lib/packages.sh line 117)
   - Automatically rebuild pandas, matplotlib, seaborn after initial install
   - Rebuild code in lib/packages.sh lines 180-191
   - Ensures binary compatibility with NumPy 2.x

4. **MariaDB Package Verification** ✅
   - Verify MariaDB package installed before attempting to start
   - Check data directory exists after package installation
   - Improved error logging with journalctl output
   - Code in lib/packages.sh lines 187-220

5. **Complete Application Files** ✅
   - Include openefa-files/ directory in installer package (was excluded)
   - Contains all 36 Python modules, web templates, scripts
   - Package size: 836KB (was 109KB without openefa-files)

6. **Multi-Tenant Role System** ✅
   - Updated web templates with correct role names
   - Roles: User (client), Domain Admin (domain_admin), SuperAdmin (admin)
   - Files updated:
     - openefa-files/web/templates/admin/edit_user.html
     - openefa-files/web/templates/admin/create_user.html
     - openefa-files/web/templates/admin/users.html
     - openefa-files/web/templates/auth/profile.html

7. **Behavioral Baseline Config Parser Fix** ✅
   - Fixed .my.cnf parsing to strip whitespace from keys
   - Changed: `config[key.strip()] = value.strip().strip('"')`
   - File: openefa-files/modules/behavioral_baseline.py line 57-58
   - Resolves database authentication errors

**Files Modified:**
- `/opt/openefa-installer/install.sh` - Added diagnostic tools installation call
- `/opt/openefa-installer/lib/packages.sh` - numpy first, pandas rebuild, MariaDB verification
- `/opt/openefa-installer/lib/dependencies.sh` - Diagnostic tools, utils module, enhanced dependencies
- `/opt/openefa-installer/openefa-files/modules/behavioral_baseline.py` - Config parser fix
- `/opt/openefa-installer/openefa-files/web/templates/admin/*.html` - Role name updates

**Testing Results:**
- ✅ Fresh install on Ubuntu 24.04 Minimal Server
- ✅ All pre-flight checks pass
- ✅ MariaDB installs and starts successfully
- ✅ All Python packages install without errors
- ✅ Utils module created automatically
- ✅ All 18 modules load successfully
- ✅ SpacyWeb starts and accessible on port 5500
- ✅ Correct role names displayed: User, Domain Admin, SuperAdmin
- ✅ Email filter processes test emails without "Command died with status 1" error
- ✅ Behavioral baseline connects to database successfully
- ✅ Exit code 0 (success)

**Installation Duration:** ~4-5 minutes on minimal Ubuntu

**Final Package:** openefa-installer-v2.7-final.tar.gz (836KB)

---

### Database Schema Updates (Multi-Tenant)

**New Table: `user_domain_assignments`**
```sql
CREATE TABLE user_domain_assignments (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  domain VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by INT DEFAULT NULL,
  is_active TINYINT(1) DEFAULT 1,
  UNIQUE KEY (user_id, domain),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

**New Stored Procedures:**
- `sp_assign_domain_to_user` - Assign domain to domain_admin user
- `sp_remove_domain_from_user` - Remove domain assignment
- `sp_get_user_domains` - Get all domains for a user

**New View:**
- `v_user_domains` - Join users with their assigned domains

**Migration Files:**
- `/opt/openefa-installer/sql/migrations/000_create_migrations_table.sql`
- `/opt/openefa-installer/sql/migrations/001_add_domain_admin_role.sql`

**Updated Schema:**
- `/opt/openefa-installer/sql/schema_v1.sql` - Added user_domain_assignments table (lines 820-833)

---

### Role System Implementation

**Three Roles:**
1. **admin** (SuperAdmin) - Full system access, all domains
2. **domain_admin** (Domain Admin) - Assigned domains only, manage domain users
3. **client** (User) - Own email address only, view own emails

**Access Control Matrix:**

| Feature | SuperAdmin | Domain Admin | User |
|---------|------------|--------------|------|
| View Emails | All domains | Assigned domains | Own emails |
| Manage Quarantine | All | Assigned domains | Own emails |
| User Management | All users | Domain users | None |
| Domain Config | All | Assigned domains | None |
| System Settings | Full access | None | None |

**Web Templates Updated:**
- Dropdown options show: User, Domain Admin, SuperAdmin
- Badge colors:
  - SuperAdmin: Red badge (bg-danger)
  - Domain Admin: Yellow badge (bg-warning text-dark)
  - User: Blue badge (bg-primary)

---

### Installer Architecture

**Installation Order:**
1. Initialize logging
2. **Install diagnostic tools** (iputils-ping, dnsutils, net-tools, lsb-release) ← NEW
3. Run pre-flight checks
4. Gather installation config
5. Create spacy-filter user
6. Install system packages
7. Install Python packages
   - **numpy>=2.3.0 installed FIRST** ← NEW
   - All other packages
   - **Rebuild pandas/matplotlib/seaborn** ← NEW
8. Install enhanced dependencies
   - spacy, textblob, geoip2, PyMuPDF
   - Download spaCy language models
   - **Create utils module** ← NEW
9. Setup database
   - Create tables
   - **Apply migrations** ← NEW
10. Configure Postfix
11. Install OpenSpacy modules
12. Setup services
13. Validate installation

**Key Installer Functions:**

`install_diagnostic_tools()` - lib/dependencies.sh
```bash
# Installs ping, nslookup, netstat, lsb_release before pre-flight checks
# Ensures minimal Ubuntu compatibility
```

`create_utils_module()` - lib/dependencies.sh
```bash
# Creates /opt/spacyserver/utils/ directory
# Generates __init__.py and logging.py with safe_log() function
# Fixes "No module named 'utils'" import errors
```

`install_python_packages()` - lib/packages.sh
```bash
# numpy>=2.3.0 installed FIRST (line 117)
# Then all other packages
# Rebuild pandas, matplotlib, seaborn for NumPy 2.x compatibility (lines 180-191)
```

---

### Documentation Created

**INTEGRATION_SUMMARY.md** - Comprehensive technical documentation
- Overview of all changes
- Database schema updates
- Installation flow diagram
- Testing results
- Rollout instructions

**TESTING_GUIDE.md** - Detailed testing procedures
- 7 test scenarios for minimal Ubuntu
- Pre-installation checklist
- Test results template
- Common issues and fixes
- Cleanup commands for re-testing

**GIT_COMMIT_CHECKLIST.md** - Ready-to-use git workflow
- Pre-commit checklist
- Ready-to-use git commands (single or multiple commits)
- Rollback plan
- Post-commit tasks

**TRANSFER_TO_TEST_SERVER.txt** - Step-by-step transfer guide
- Package creation commands
- SCP transfer instructions
- Extraction and testing commands
- Expected results checklist

---

### Known Issues and Resolutions

**Issue 1: "Command died with status 1"**
**Status:** ✅ Resolved
- Missing utils module and Python packages
- Fixed by automatic utils module creation and enhanced dependencies

**Issue 2: Pre-flight checks fail on minimal Ubuntu**
**Status:** ✅ Resolved
- Missing diagnostic tools (iputils-ping, dnsutils)
- Fixed by installing diagnostic tools before pre-flight checks run

**Issue 3: NumPy/Pandas binary incompatibility**
**Status:** ✅ Resolved
- Pandas wheels compiled against NumPy 1.x, installer uses NumPy 2.x
- Fixed by installing numpy first, then rebuilding pandas/matplotlib/seaborn

**Issue 4: MariaDB fails to start**
**Status:** ✅ Resolved
- Data directory not initialized on some installations
- Fixed by verifying package installation and improving error logging

**Issue 5: openefa-files missing**
**Status:** ✅ Resolved
- Directory excluded from installer package
- Fixed by removing exclusion (was --exclude='openefa-files')

**Issue 6: Behavioral baseline database authentication fails**
**Status:** ✅ Resolved
- Config parser not stripping whitespace from keys in .my.cnf
- Fixed by adding .strip() to key parsing

---

### Testing Environment

**Test Server:** 192.168.50.66 (ubtemplate)
**OS:** Ubuntu 24.04 LTS Minimal Server
**RAM:** 4GB
**Disk:** 40GB
**Network:** Internet connected

**Test Iterations:** 6 clean installations from snapshot
- v2.0 - Initial integration attempt (failed: MariaDB)
- v2.1 - Added MariaDB initialization (failed: still MariaDB issues)
- v2.2 - MariaDB verification only (failed: missing openefa-files)
- v2.3 - Added openefa-files (failed: numpy/pandas compatibility)
- v2.4 - numpy first (failed: still compatibility issues)
- v2.5 - Added pandas rebuild (failed: role names wrong)
- v2.6 - Corrected role names (success: spacyweb warning only)
- v2.7 - Fixed behavioral_baseline parser ✅ **COMPLETE SUCCESS**

---

## Previous Session Summary (October 15, 2025)

### Major Features Implemented

#### 1. Domain Relay Host Management
**Status:** ✅ Complete and tested

**Description:** Full relay host configuration system for routing emails after processing.

**Components:**
- **Database:** Added `relay_host` column to `client_domains` table
- **Web UI:** Added relay host field to domain add/edit forms in `domain_management.html`
- **Backend:** `update_postfix_transport()` function in `app.py` automatically generates `/etc/postfix/transport`
- **Automation:** Automatic Postfix transport file updates and reload on domain add/edit/delete/toggle operations

**File Locations:**
- `/opt/openefa-installer/sql/schema_v1.sql` - Schema with relay_host column
- `/opt/openefa-installer/openefa-files/web/app.py` - update_postfix_transport() function (lines 99-153)
- `/opt/openefa-installer/openefa-files/web/templates/domain_management.html` - UI for relay host management
- `/opt/openefa-installer/lib/database.sh` - Insert relay_host when creating initial domains (lines 143-161)
- `/opt/openefa-installer/lib/postfix.sh` - Transport file permissions and sudoers setup (lines 103-105, 285-297)

**How it Works:**
1. User adds/edits domain with relay host IP or hostname in web interface
2. Domain saved to database with relay_host value
3. `update_postfix_transport()` function automatically called
4. Function queries database for all active domains with relay_host
5. Generates `/etc/postfix/transport` file with format: `domain    smtp:[relay_host]`
6. Runs `postmap /etc/postfix/transport` to compile hash database
7. Runs `sudo /usr/sbin/postfix reload` to apply changes (passwordless via sudoers)

**Permissions:**
- Transport file: `spacy-filter:postfix` with mode 660
- Sudoers rule: `/etc/sudoers.d/spacy-postfix` allows `spacy-filter` to run `postfix reload` without password

**Testing:** ✅ Verified working with curl install on October 15, 2025

---

#### 2. Enhanced Email Viewing (All Emails)
**Status:** ✅ Complete and tested

**Description:** Complete rewrite of email detail view with headers, authentication data, and management actions.

**Components:**
- **Database Columns Added:**
  - `raw_email` (LONGTEXT) - Complete raw MIME email
  - `original_spf` (VARCHAR 50) - SPF authentication result
  - `original_dkim` (VARCHAR 50) - DKIM authentication result
  - `original_dmarc` (VARCHAR 50) - DMARC authentication result

- **Backend Processing:**
  - `db_processor.py` extracts authentication headers from raw emails using regex
  - Checks both custom `X-SpaCy-Auth-Results` header and standard `Authentication-Results` header
  - Stores in database for display

- **Web Interface:**
  - Collapsible email body section (Bootstrap 5 collapse component)
  - Headers display with "Show Headers" button
  - SPF/DKIM/DMARC authentication results in Metadata section
  - Action buttons: Release, Whitelist, Mark as Spam, Delete

**File Locations:**
- `/opt/openefa-installer/openefa-files/services/db_processor.py` - Authentication extraction (lines 291-352)
- `/opt/openefa-installer/openefa-files/modules/email_database.py` - SQLAlchemy model with new columns
- `/opt/openefa-installer/openefa-files/web/app.py` - Headers API endpoint (lines 4237-4312)
- `/opt/openefa-installer/openefa-files/web/templates/email_detail.html` - Complete UI rewrite

**API Endpoints:**
- `GET /api/quarantine/<email_id>/headers` - Returns email headers (checks both email_quarantine and email_analysis tables)
- `POST /api/emails/<email_id>/release` - Release email to recipient
- `POST /api/emails/<email_id>/whitelist` - Add sender to whitelist
- `POST /api/emails/<email_id>/spam` - Mark as spam
- `POST /api/emails/<email_id>/delete` - Delete email

**Testing:** ✅ Verified working with curl install on October 15, 2025

---

#### 3. Quarantine Brief Content Preview
**Status:** ✅ Complete and tested

**Description:** Shows 3-5 line preview of email content in User Messages view instead of full content.

**Implementation:**
- Backend parsing in `quarantine_view()` function extracts first 3-5 lines or 250 characters
- Template displays `content_preview` field instead of `text_content`
- Improves page load performance and reduces clutter

**File Locations:**
- `/opt/openefa-installer/openefa-files/web/app.py` - quarantine_view() function creates content_preview field
- `/opt/openefa-installer/openefa-files/web/templates/quarantine.html` - Line 374 displays preview

**Testing:** ✅ Verified working with curl install on October 15, 2025

---

#### 4. User Creation Form Improvements
**Status:** ✅ Complete and tested

**Description:** Prevents accidental wrong domain assignment during user creation.

**Changes:**
- Domain dropdown defaults to "Select Domain" (empty value)
- Required field validation prevents submission without domain selection
- Auto-populate feature disabled (commented out in JavaScript)
- Warning text: "⚠️ Please verify the domain is correct before creating the user"

**File Locations:**
- `/opt/openefa-installer/openefa-files/web/templates/admin/create_user.html` - Lines 43-49 (dropdown), 113-114 (disabled auto-populate)

**Testing:** ✅ Verified working with curl install on October 15, 2025

---

#### 5. Whitelist Management Domain Indicator
**Status:** ✅ Complete and tested

**Description:** Clear visual indication of which domain is currently being managed.

**Changes:**
- Header shows current domain in large badge: "Current Domain: [openefa.org]"
- Domain switcher dropdown highlights current domain with checkmark and "Current" badge
- Shows all available domains for multi-domain users

**File Locations:**
- `/opt/openefa-installer/openefa-files/web/templates/whitelist_management.html` - Domain indicator in header and switcher

**Testing:** ✅ Verified working with curl install on October 15, 2025

---

### Database Schema Updates

**Table: `client_domains`**
```sql
ALTER TABLE client_domains ADD COLUMN relay_host VARCHAR(255) DEFAULT NULL AFTER client_name;
```

**Table: `email_analysis`**
```sql
ALTER TABLE email_analysis ADD COLUMN raw_email LONGTEXT NULL AFTER pii_types;
ALTER TABLE email_analysis ADD COLUMN original_spf VARCHAR(50) NULL AFTER raw_email;
ALTER TABLE email_analysis ADD COLUMN original_dkim VARCHAR(50) NULL AFTER original_spf;
ALTER TABLE email_analysis ADD COLUMN original_dmarc VARCHAR(50) NULL AFTER original_dkim;
```

**Database Privileges:**
```sql
GRANT SELECT ON mysql.proc TO 'spacy_user'@'localhost';
```
- Required for database backup functionality (SHOW CREATE PROCEDURE)

---

### Installer Updates

**Files Modified:**
1. `/opt/openefa-installer/sql/schema_v1.sql` - Added all new columns
2. `/opt/openefa-installer/lib/database.sh` - Insert relay_host with initial domains, grant mysql.proc privilege
3. `/opt/openefa-installer/lib/postfix.sh` - Set transport file permissions and sudoers configuration

**Key Installer Changes:**

**database.sh (lines 143-161):**
```bash
# Now includes relay_host in INSERT
INSERT INTO client_domains (domain, client_name, relay_host, active, created_at)
VALUES ('${domain}', '${domain}', '${RELAY_SERVER_IP}', 1, NOW())
```

**postfix.sh (lines 103-105):**
```bash
# Set permissions so spacy-filter can update the transport file
chown spacy-filter:postfix "${transport_file}" "${transport_file}.db"
chmod 660 "${transport_file}" "${transport_file}.db"
```

**postfix.sh (lines 285-297):**
```bash
# Configure sudoers for Postfix reload
cat > /etc/sudoers.d/spacy-postfix << 'EOSUDO'
# Allow spacy-filter to reload Postfix for transport map updates
spacy-filter ALL=(ALL) NOPASSWD: /usr/sbin/postfix reload
EOSUDO
chmod 440 /etc/sudoers.d/spacy-postfix
visudo -c -f /etc/sudoers.d/spacy-postfix
```

---

### Git Repository

**Repository:** https://github.com/openefaadmin/openefa-installer
**Branch:** main
**Last Commit:** 98cd35c (October 15, 2025)
**Commit Message:** "Add relay host management and email viewing enhancements"

**Installation URL:** http://install.openefa.com/install.sh

**Install Command:**
```bash
curl -sSL http://install.openefa.com/install.sh | sudo bash
```

---

### Testing Results

**Date:** October 15, 2025

**Test 1: Local Install**
- ✅ Fresh install successful
- ✅ Email flowing and being processed
- ✅ User Messages view displaying emails
- ✅ All Emails view with headers, SPF/DKIM/DMARC, action buttons
- ✅ Domain added with relay host
- ✅ Transport file automatically updated
- ✅ Postfix reloaded automatically
- ✅ Email forwarded to relay host

**Test 2: Curl Install (from GitHub)**
- ✅ Uninstall completed
- ✅ Fresh install via curl successful
- ✅ All features working as expected
- ✅ Domain management functional
- ✅ Transport file updates working
- ✅ Email processing and forwarding working

---

### Known Issues and Resolutions

**Issue 1: Transport file ownership**
**Problem:** When manually writing transport file as root, ownership changes to root:root, preventing web app from updating it
**Resolution:** Installer sets correct ownership (spacy-filter:postfix 660) and Python preserves it during writes
**Status:** ✅ Resolved

**Issue 2: Postfix reload permission denied**
**Problem:** Web app (running as spacy-filter) couldn't reload Postfix
**Resolution:** Added sudoers rule for passwordless `postfix reload` command
**Status:** ✅ Resolved

**Issue 3: Database backup privilege error**
**Problem:** SHOW CREATE PROCEDURE failed with insufficient privileges
**Resolution:** Added `GRANT SELECT ON mysql.proc` to installer
**Status:** ✅ Resolved

---

### File Permissions Reference

**Critical Files:**
```
/etc/postfix/transport        spacy-filter:postfix  660
/etc/postfix/transport.db      spacy-filter:postfix  660
/etc/sudoers.d/spacy-postfix   root:root             440
/opt/spacyserver/web/app.py    spacy-filter:spacy-filter  640
```

---

### Architecture Notes

**Email Flow:**
1. Email arrives at Postfix SMTP server
2. Postfix pipes to SpaCy filter (`email_filter.py`)
3. SpaCy filter processes email through modules
4. `db_processor.py` stores in database with headers and authentication data
5. If safe, email queued for delivery
6. Postfix checks transport map for relay host
7. Email delivered to configured relay host

**Transport Map Update Flow:**
1. User modifies domain via web interface (add/edit/delete/toggle)
2. `update_postfix_transport()` function called automatically
3. Function queries database for active domains with relay_host
4. Generates `/etc/postfix/transport` file
5. Runs `postmap` to compile hash database
6. Runs `sudo postfix reload` to apply changes
7. New routing immediately active

---

### Development Environment

**Server:** openspacy (192.168.50.58)
**OS:** Ubuntu 24.04 LTS
**Python:** 3.x
**Database:** MariaDB
**Web Framework:** Flask
**MTA:** Postfix 3.8.6
**Service User:** spacy-filter (UID 999)

---

### Backup Locations

**System Backups:** `/home/sgadmin/backups/`
**Application Backups:** `/opt/spacyserver/backups/`

**Latest Backups (October 15, 2025):**
- `full_backup_20251015_222816.tar.gz` (394K)
- `spacy_db_backup_20251015_222813.sql.gz` (19K)

---

### Next Steps / Future Enhancements

**Suggested Future Work:**
1. Entities tab improvements (mentioned by user as "can come later")
2. AI summary enhancements (mentioned by user as "can come later")
3. Enhanced reporting dashboard
4. Multi-relay support per domain (primary/backup)
5. Transport map testing tool in web UI

---

### Session Summary

**Duration:** October 15, 2025 (full day session)
**Primary Goal:** Restore features after fresh install and integrate into installer
**Outcome:** ✅ Complete success

**Features Delivered:**
- ✅ Domain relay host management with automatic Postfix integration
- ✅ Enhanced email viewing with full header access and authentication data
- ✅ Email management actions (release, whitelist, mark spam, delete)
- ✅ Quarantine brief content preview
- ✅ User creation form improvements
- ✅ Whitelist management domain indicators
- ✅ Automatic transport map updates
- ✅ Proper permissions and sudoers configuration
- ✅ All features integrated into installer
- ✅ Successfully tested with curl install from GitHub

**Code Quality:**
- Clean separation of concerns
- Automatic cleanup and error handling
- Comprehensive logging
- Security best practices (file permissions, sudoers)
- Database integrity (foreign keys, cascades)

**Documentation:**
- Detailed commit message
- Inline code comments
- This project memory document

---

### Important Code References

**update_postfix_transport() function** (`app.py` lines 99-153):
```python
def update_postfix_transport():
    """
    Update Postfix transport file from database.
    Reads all active domains with relay_hosts and writes to /etc/postfix/transport
    """
    import subprocess
    transport_file = '/etc/postfix/transport'

    try:
        # Get all active domains with relay hosts from database
        cursor.execute("""
            SELECT domain, relay_host
            FROM client_domains
            WHERE active = 1 AND relay_host IS NOT NULL AND relay_host != ''
            ORDER BY domain
        """)

        # Build transport file content
        # Write to file
        # Run postmap
        # Reload Postfix with sudo

        logger.info(f"Updated Postfix transport file with {len(domains)} domains and reloaded Postfix")
        return True
    except Exception as e:
        logger.error(f"Failed to update Postfix transport: {e}")
        return False
```

**Authentication Header Extraction** (`db_processor.py` lines 291-352):
- Parses raw email using `email.message_from_string()`
- Checks custom `X-SpaCy-Auth-Results` header first
- Falls back to standard `Authentication-Results` header
- Uses regex to extract SPF, DKIM, DMARC results
- Handles multiple formats and edge cases

---

### Contact and Support

**Project:** OpenEFA Email Security System
**License:** GPL
**Website:** https://openefa.com
**Successor to:** EFA Project

**Installation Support:**
- Documentation: README.md in repository
- Install script: http://install.openefa.com/install.sh
- Issues: GitHub repository issues page

---

*This project memory document is maintained to track development progress, decisions, and implementation details for the OpenEFA project.*
