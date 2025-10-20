# OpenEFA Installer Testing Guide - Minimal Ubuntu

**Purpose**: Test integrated installer on fresh minimal Ubuntu before pushing to GitHub
**Date**: 2025-10-16

---

## Test Environment Setup

### Server Requirements:
- **OS**: Ubuntu 24.04 LTS Minimal Server (or 22.04)
- **RAM**: 2GB minimum (4GB recommended)
- **Disk**: 20GB minimum
- **Network**: Internet connection required
- **Access**: SSH with sudo/root access

---

## Pre-Test Preparation

### 1. Package the Installer

On your working server:
```bash
cd /opt/openefa-installer

# Create a tarball of the updated installer
tar -czf /tmp/openefa-installer-v2.tar.gz \
  --exclude='.git' \
  --exclude='*.backup' \
  --exclude='*.log' \
  .

ls -lh /tmp/openefa-installer-v2.tar.gz
```

### 2. Transfer to Test Server

```bash
# Transfer the package
scp /tmp/openefa-installer-v2.tar.gz user@test-server:/tmp/

# Or if you want to test the bootstrap method:
# Host the installer on a web server and curl it
```

---

## Test Scenarios

### TEST 1: Fresh Minimal Ubuntu Install
**Purpose**: Verify diagnostic tools install before pre-flight checks

**Steps:**
```bash
# On test server (fresh minimal Ubuntu):
cd /tmp
tar -xzf openefa-installer-v2.tar.gz
cd openefa-installer-v2  # Or whatever it extracts to

# Run installer
sudo ./install.sh
```

**What to Watch For:**
- [ ] Diagnostic tools install BEFORE pre-flight checks
- [ ] No "command not found" errors for ping, nslookup, etc.
- [ ] Pre-flight checks all pass
- [ ] Installation completes without errors
- [ ] Utils module created at /opt/spacyserver/utils/
- [ ] spaCy model downloads successfully

**Expected Output:**
```
╔══════════════════════════════════════════════════════════════╗
║  OpenSpacy Email Security - Dependency Installer v2         ║
╚══════════════════════════════════════════════════════════════╝

[1/9] Installing Diagnostic Tools (Minimal Ubuntu Compatibility)
  → Installing iputils-ping...
  ✓ iputils-ping installed
  → Installing dnsutils...
  ✓ dnsutils installed
  ...

[Pre-flight checks]
  ✓ DNS resolution: OK
  ...
```

**Verification After Install:**
```bash
# Check files exist
ls -la /opt/spacyserver/utils/
ls -la /opt/spacyserver/venv/bin/spacy

# Run verification
cd /opt/spacyserver
sudo ./verify_installation.sh

# Expected: 45-48 passed, 0-5 warnings, 0 failed
```

**Test Email Filter:**
```bash
cat > /tmp/test.eml << 'EOF'
From: test@example.com
To: admin@yourdomain.com
Subject: Test Email

This is a test.
EOF

/opt/spacyserver/email_filter.py test@test.com < /tmp/test.eml

# Expected: Should process without "Command died with status 1"
```

---

### TEST 2: Re-run Installer (Idempotency Check)
**Purpose**: Verify installer handles existing installation gracefully

**Steps:**
```bash
# Without uninstalling, run installer again
cd /opt/openefa-installer
sudo ./install.sh
```

**What to Watch For:**
- [ ] Detects existing installation
- [ ] Skips already completed steps
- [ ] Doesn't break existing config
- [ ] Completes successfully or offers to upgrade

---

### TEST 3: Database Migration Test
**Purpose**: Verify SQL migrations work correctly

**Steps:**
```bash
# Check if migrations table exists
mysql -e "SHOW TABLES FROM spacy_email_db LIKE 'schema_migrations';"

# Check if user_domain_assignments exists
mysql -e "SHOW TABLES FROM spacy_email_db LIKE 'user_domain_assignments';"

# Verify table structure
mysql spacy_email_db -e "DESCRIBE user_domain_assignments;"

# Test stored procedures
mysql spacy_email_db -e "SHOW PROCEDURE STATUS WHERE Db = 'spacy_email_db';"
```

**Expected Tables:**
- schema_migrations
- user_domain_assignments

**Expected Procedures:**
- sp_assign_domain_to_user
- sp_remove_domain_from_user
- sp_get_user_domains

---

### TEST 4: Utils Module Test
**Purpose**: Verify utils module fixes import errors

**Steps:**
```bash
cd /opt/spacyserver
source venv/bin/activate

# Test imports
python3 << 'PYEOF'
import sys
sys.path.insert(0, '/opt/spacyserver')

# Test utils.logging import (was failing before)
from utils.logging import safe_log, log_sentiment_debug
print("✅ utils.logging imports successfully")

# Test modules that depend on utils
sys.path.insert(0, '/opt/spacyserver/modules')
import marketing_spam_filter
print("✅ marketing_spam_filter imports successfully")

import analysis
print("✅ analysis imports successfully")
PYEOF
```

**Expected Output:**
```
✅ utils.logging imports successfully
✅ marketing_spam_filter imports successfully
✅ analysis imports successfully
```

---

### TEST 5: Module Loading Test
**Purpose**: Verify all modules load in email_filter.py

**Steps:**
```bash
# Create test email
cat > /tmp/minimal_test.eml << 'EOF'
From: sender@example.com
To: recipient@testdomain.com
Subject: Module Load Test

Testing module loading.
EOF

# Run filter and capture module loading messages
/opt/spacyserver/email_filter.py test@test.com < /tmp/minimal_test.eml 2>&1 | grep "Module.*loaded"
```

**Expected Output (should include):**
```
✅ Module otp_detector loaded
✅ Module entity_extraction loaded
✅ Module email_dns loaded
✅ Module email_phishing loaded
✅ Module email_sentiment loaded
✅ Module email_language loaded
✅ Module email_obfuscation loaded
✅ Module marketing_spam_filter loaded with 2 functions
✅ Module bec_detector loaded
✅ Module enhanced_analysis loaded with 3 functions
✅ Module toad_detector loaded
✅ Module pdf_analyzer loaded
✅ Module fraud_funding_detector loaded
✅ Module url_reputation loaded
✅ Module behavioral_baseline loaded
✅ Module rbl_checker loaded
✅ Module antivirus_scanner loaded
```

**Critical Check:**
- ✅ marketing_spam_filter (was failing before - "No module named 'utils'")
- ✅ enhanced_analysis (was failing before - "No module named 'utils'")

---

### TEST 6: User Role System Test
**Purpose**: Verify domain_admin role system works

**Steps:**
```bash
mysql spacy_email_db << 'SQLEOF'
-- Test user creation with domain_admin role
INSERT INTO users (email, password_hash, domain, role, first_name, last_name, is_active)
VALUES (
  'admin@testcustomer.com',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5ztW0VyJ4Xy4.',
  'testcustomer.com',
  'domain_admin',
  'Test',
  'Admin',
  1
);

-- Get the user ID (should be last inserted)
SELECT @user_id := LAST_INSERT_ID();

-- Assign domains to this user
CALL sp_assign_domain_to_user(@user_id, 'testcustomer.com', 1);
CALL sp_assign_domain_to_user(@user_id, 'testcustomer.net', 1);

-- Verify assignments
SELECT * FROM user_domain_assignments WHERE user_id = @user_id;

-- Test the view
SELECT * FROM v_user_domains WHERE user_id = @user_id;

-- Get domains for user
CALL sp_get_user_domains(@user_id);

-- Cleanup (optional)
-- DELETE FROM users WHERE email = 'admin@testcustomer.com';
SQLEOF
```

**Expected Output:**
- User created with role 'domain_admin'
- Two domain assignments created
- View returns correct data
- Stored procedure returns assigned domains

---

## Testing Checklist

### Pre-Installation:
- [ ] Fresh minimal Ubuntu server ready
- [ ] Installer package transferred
- [ ] Network connectivity verified
- [ ] Sudo/root access confirmed

### During Installation:
- [ ] Diagnostic tools install first
- [ ] Pre-flight checks pass (no errors)
- [ ] Package installation completes
- [ ] Python packages install successfully
- [ ] spaCy model downloads (12.8 MB)
- [ ] Utils module created
- [ ] Database setup completes
- [ ] Migrations applied
- [ ] Services start successfully

### Post-Installation:
- [ ] verify_installation.sh shows 45+ passed
- [ ] Email filter processes test email
- [ ] No "Command died with status 1" error
- [ ] All modules load successfully
- [ ] marketing_spam_filter loads (was failing)
- [ ] enhanced_analysis loads (was failing)
- [ ] user_domain_assignments table exists
- [ ] Stored procedures exist
- [ ] Web dashboard accessible (port 5500)

### Database Verification:
- [ ] schema_migrations table exists
- [ ] user_domain_assignments table exists
- [ ] Stored procedures created
- [ ] Can create domain_admin users
- [ ] Can assign domains to users

---

## Common Issues & Fixes

### Issue 1: "command not found: ping"
**Status**: Should NOT occur with new installer
**Cause**: Diagnostic tools not installed before checks
**Fix**: Verify install_diagnostic_tools() runs first

### Issue 2: "No module named 'utils'"
**Status**: Should NOT occur with new installer
**Cause**: Utils module not created
**Fix**: Verify create_utils_module() completed

### Issue 3: spaCy model download fails
**Cause**: Network issue or pip problem
**Fix**: Manual download
```bash
cd /opt/spacyserver
source venv/bin/activate
python -m spacy download en_core_web_sm
```

### Issue 4: Database migration fails
**Cause**: MySQL permissions or syntax error
**Fix**: Check logs, verify MySQL running
```bash
systemctl status mysql
mysql -e "SELECT 1"
```

---

## Test Results Template

Use this to document your test results:

```
═══════════════════════════════════════════════════════════════
OPENEFA INSTALLER TEST RESULTS
═══════════════════════════════════════════════════════════════

Test Server Info:
  OS: Ubuntu 24.04 LTS Minimal Server
  RAM: 4GB
  Disk: 40GB
  Date: 2025-10-16

TEST 1: Fresh Install
  Status: PASS / FAIL
  Duration: ___ minutes
  Issues: [list any]

  Diagnostic Tools: PASS / FAIL
  Pre-flight Checks: PASS / FAIL
  Package Installation: PASS / FAIL
  Utils Module: PASS / FAIL
  spaCy Model: PASS / FAIL
  Database Migration: PASS / FAIL
  Verification: __/49 passed

TEST 2: Idempotency
  Status: PASS / FAIL
  Notes: [behavior on re-run]

TEST 3: Database Migration
  schema_migrations: EXISTS / MISSING
  user_domain_assignments: EXISTS / MISSING
  Stored Procedures: PASS / FAIL

TEST 4: Utils Module
  Import utils.logging: PASS / FAIL
  Import marketing_spam_filter: PASS / FAIL
  Import analysis: PASS / FAIL

TEST 5: Module Loading
  All modules loaded: YES / NO
  Failed modules: [list]

TEST 6: Email Filter
  Test email processed: YES / NO
  Exit code: [0 = success, 1 = fail]
  Errors: [list any]

TEST 7: User Roles
  Create domain_admin: PASS / FAIL
  Assign domains: PASS / FAIL
  Stored procedures: PASS / FAIL

OVERALL RESULT: PASS / FAIL

Issues Found: [list]
Changes Needed: [list]

Ready for GitHub: YES / NO

═══════════════════════════════════════════════════════════════
```

---

## Cleanup Between Tests

To test multiple times on the same server:

```bash
# Run uninstaller (if it exists)
cd /opt/openefa-installer
sudo ./uninstall.sh

# OR manual cleanup:
sudo systemctl stop spacy-db-processor spacyweb
sudo systemctl disable spacy-db-processor spacyweb
mysql -e "DROP DATABASE IF EXISTS spacy_email_db;"
sudo rm -rf /opt/spacyserver
sudo userdel -r spacy-filter 2>/dev/null || true
sudo apt-get purge -y postfix mariadb-server redis-server
sudo apt-get autoremove -y
```

---

## When Tests Pass - Push to GitHub

When all tests pass, follow: `GIT_COMMIT_CHECKLIST.md`

---

## Support

**Issues**: Note them in this document
**Questions**: Document for team review
**Blockers**: Stop testing, fix issues first

---

**Test it thoroughly - production deployments depend on it!** 🚀
