# OpenEFA Installer Security Update v1.5.7

**Date:** October 20, 2025
**Type:** Security Enhancement
**Priority:** HIGH

## Summary

This update implements critical security improvements to prevent credential exposure and follows Linux Filesystem Hierarchy Standard (FHS) best practices for configuration management.

---

## Key Changes

### 1. Secure Credentials Storage

**BEFORE (Insecure):**
- Database credentials hardcoded in scripts
- `.my.cnf` in application directory: `/opt/spacyserver/config/.my.cnf`
- No `.env` file for Flask secrets
- Credentials could be committed to git

**AFTER (Secure):**
- All credentials in `/etc/spacy-server/` (system configuration directory)
- `.env` file created with auto-generated secrets
- `.my.cnf` moved to `/etc/spacy-server/`
- Strict file permissions (640/600)
- Protected by `.gitignore`

---

## Directory Structure

### `/etc/spacy-server/` - Secure Credentials (NEW)

```
/etc/spacy-server/
├── .env              (640, root:spacy-filter)
├── .my.cnf           (600, spacy-filter:spacy-filter)
└── README            (644, documentation)
```

**Contents:**
- **`.env`** - Flask secrets, database credentials, API keys, ClickSend config
- **`.my.cnf`** - MySQL client configuration with credentials

### `/opt/spacyserver/config/` - Application Configuration (Existing)

```
/opt/spacyserver/config/
├── bec_config.json
├── module_config.json
├── email_filter_config.json
├── trusted_domains.json
└── ... (other JSON configs)
```

**Contents:**
- JSON configuration files (NO CREDENTIALS)
- Application settings and thresholds
- Module configuration
- Safe to commit to version control

---

## Files Modified

### 1. `/opt/openefa-installer/lib/database.sh`

**Added:**
- `create_env_file()` - Generates `/etc/spacy-server/.env` with secure random keys
- Auto-generates `FLASK_SECRET_KEY` (64-byte URL-safe token)
- Auto-generates `API_SECRET_KEY` (32-byte hex token)
- Auto-generates `DB_PASSWORD` (24-character alphanumeric)

**Modified:**
- `create_mysql_config()` - Now creates `.my.cnf` in `/etc/spacy-server/`
- `setup_database()` - Calls `create_env_file()` before other setup steps

**Security Features:**
```bash
# Generates cryptographically secure random keys
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
API_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
DB_PASSWORD=$(python3 -c "import secrets; print(''.join(secrets.choice('abc...') for _ in range(24)))")
```

### 2. `/opt/openefa-installer/openefa-files/web/app.py`

**Changed:**
```python
# OLD
MY_CNF_PATH = "/opt/spacyserver/config/.my.cnf"

# NEW
MY_CNF_PATH = "/etc/spacy-server/.my.cnf"
```

**Added:**
```python
from dotenv import load_dotenv
load_dotenv('/etc/spacy-server/.env')
```

### 3. `/opt/openefa-installer/openefa-files/scripts/send_daily_notification_summary.py`

**BEFORE (Hardcoded Password):**
```python
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='spacy_user',
        password='AdrastosIhadn63r',  # ← EXPOSED!
        database='spacy_email_db'
    )
```

**AFTER (Secure from .env):**
```python
from dotenv import load_dotenv
load_dotenv('/etc/spacy-server/.env')

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'spacy_user'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME', 'spacy_email_db')
    )
```

### 4. `/opt/openefa-installer/.gitignore`

**Added Patterns:**
```gitignore
# Credentials
*.my.cnf
.my.cnf
*secret*

# Reports that may contain sensitive info
reports/
SECURITY_*.md
*_SECURITY_*.md
*CREDENTIAL*.md

# Backups
backups/
*.backup
*.bak
```

---

## Security Improvements

### 1. No Hardcoded Credentials
✅ All credentials generated at installation time
✅ No default passwords in code
✅ Secure random generation using Python `secrets` module

### 2. Proper File Permissions
```
/etc/spacy-server/               750  root:spacy-filter
/etc/spacy-server/.env           640  root:spacy-filter
/etc/spacy-server/.my.cnf        600  spacy-filter:spacy-filter
```

### 3. Git Protection
✅ `.gitignore` patterns prevent credential files from being committed
✅ Report files with sensitive data excluded
✅ Backup files excluded

### 4. Separation of Concerns
✅ **System credentials** → `/etc/spacy-server/` (FHS standard)
✅ **Application config** → `/opt/spacyserver/config/` (safe to version control)
✅ Clear distinction between sensitive and non-sensitive data

---

## Installation Behavior

When running `install.sh`, the installer will:

1. Create `/etc/spacy-server/` directory with proper ownership
2. Generate secure random passwords and secrets
3. Create `.env` file with all credentials
4. Create `.my.cnf` with database credentials
5. Set strict file permissions (640/600)
6. Display generated credentials to admin (SAVE THESE!)

**Example Output:**
```
✓ .env file created: /etc/spacy-server/.env
✓ MySQL config created: /etc/spacy-server/.my.cnf

🔐 Generated Credentials:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Database Password: kF9xL2mN4pQ7rS8t
API Secret Key: a7b3c9d1e5f2g8h4...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  SAVE THESE CREDENTIALS SECURELY!
⚠️  They are stored in: /etc/spacy-server/.env
```

---

## Migration Guide (Existing Installations)

If you have an existing installation, follow these steps:

### Step 1: Create new directory
```bash
sudo mkdir -p /etc/spacy-server
sudo chown root:spacy-filter /etc/spacy-server
sudo chmod 750 /etc/spacy-server
```

### Step 2: Move .my.cnf
```bash
sudo mv /opt/spacyserver/config/.my.cnf /etc/spacy-server/.my.cnf
sudo chown spacy-filter:spacy-filter /etc/spacy-server/.my.cnf
sudo chmod 600 /etc/spacy-server/.my.cnf
```

### Step 3: Create .env file
```bash
sudo nano /etc/spacy-server/.env
```

Add the following (replace with your actual values):
```bash
# Database Configuration
DB_HOST=localhost
DB_USER=spacy_user
DB_PASSWORD=your_db_password_here
DB_NAME=spacy_email_db

# Flask Configuration
FLASK_SECRET_KEY=your_generated_secret_key_here
DEBUG_MODE=False

# Security Configuration
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
SESSION_TIMEOUT_HOURS=2

# API Security
API_SECRET_KEY=your_generated_api_key_here
ALLOWED_API_IPS=127.0.0.1,localhost

# ClickSend Configuration (Optional)
CLICKSEND_USERNAME=your_username_here
CLICKSEND_API_KEY=your_api_key_here
CLICKSEND_ENABLED=false

# Redis Configuration
REDIS_URL=redis://localhost:6379

# Application Settings
MAX_CONTENT_LENGTH=16777216
UPLOAD_FOLDER=/opt/spacyserver/uploads
```

### Step 4: Set permissions
```bash
sudo chown spacy-filter:spacy-filter /etc/spacy-server/.env
sudo chmod 600 /etc/spacy-server/.env
```

### Step 5: Update app.py (if using old version)
```bash
# Edit /opt/spacyserver/web/app.py
# Change:
MY_CNF_PATH = "/opt/spacyserver/config/.my.cnf"
# To:
MY_CNF_PATH = "/etc/spacy-server/.my.cnf"

# Add at top:
from dotenv import load_dotenv
load_dotenv('/etc/spacy-server/.env')
```

### Step 6: Restart services
```bash
sudo systemctl restart spacyweb
```

---

## Verification

### Check file permissions:
```bash
ls -la /etc/spacy-server/
```

Expected output:
```
drwxr-x--- 2 root         spacy-filter  4096 Oct 20 09:00 .
-rw------- 1 spacy-filter spacy-filter   600 Oct 20 09:00 .env
-rw------- 1 spacy-filter spacy-filter   142 Oct 20 09:00 .my.cnf
```

### Test database connection:
```bash
sudo -u spacy-filter mysql --defaults-file=/etc/spacy-server/.my.cnf -e "SELECT 1;"
```

### Test web application:
```bash
sudo systemctl status spacyweb
curl -k https://localhost:5500/auth/login
```

---

## ClickSend Configuration

ClickSend credentials are now stored in `/etc/spacy-server/.env`:

```bash
CLICKSEND_USERNAME=your_username_here
CLICKSEND_API_KEY=your_api_key_here
CLICKSEND_ENABLED=true
```

**To update:**
```bash
sudo nano /etc/spacy-server/.env
# Edit CLICKSEND_* values
# Save and exit

sudo systemctl restart spacyweb
```

**No need to edit JSON files!** All credentials are in `.env`.

---

## Security Best Practices

### ✅ DO:
- Store all credentials in `/etc/spacy-server/.env`
- Use generated passwords (not defaults)
- Regularly rotate credentials
- Keep file permissions strict (640/600)
- Backup `/etc/spacy-server/` securely

### ❌ DON'T:
- Commit `.env` or `.my.cnf` to git
- Put credentials in JSON config files
- Share credentials in documentation
- Use default/example passwords in production
- Make config files world-readable

---

## Files That Should NEVER Be Committed

```
/etc/spacy-server/.env
/etc/spacy-server/.my.cnf
*.backup
reports/
SECURITY_*.md (if they contain real credentials)
```

These are protected by `.gitignore` in the installer repository.

---

## Additional Security Enhancements

### CSRF Protection
- All POST requests require CSRF tokens
- Flask-WTF enabled with automatic token generation
- Token validation on all forms

### SQL Injection Prevention
- Parameterized queries throughout codebase
- No string concatenation in SQL
- SQLAlchemy ORM where appropriate

### Session Security
- Secure cookies (HTTPS only)
- HttpOnly flag (prevent XSS cookie theft)
- SameSite=Lax (CSRF protection)
- 2-hour timeout

---

## Support

If you encounter issues:

1. Check file permissions: `ls -la /etc/spacy-server/`
2. Verify credentials: `cat /etc/spacy-server/.env` (as root)
3. Check logs: `journalctl -u spacyweb -f`
4. Test database: `sudo -u spacy-filter mysql --defaults-file=/etc/spacy-server/.my.cnf`

For help, visit: https://github.com/openefa/openefa-installer/issues

---

## Changelog

### v1.5.7 - October 20, 2025

**Security Enhancements:**
- Created `/etc/spacy-server/` for secure credential storage
- Auto-generate Flask secrets and database passwords
- Moved `.my.cnf` to system config directory
- Created `.env` file for all credentials
- Removed hardcoded passwords from scripts
- Enhanced `.gitignore` to prevent credential exposure

**Files Modified:**
- `lib/database.sh` - Added `create_env_file()`, updated paths
- `openefa-files/web/app.py` - Updated paths to `/etc/spacy-server/`
- `openefa-files/scripts/send_daily_notification_summary.py` - Load from `.env`
- `.gitignore` - Added patterns for reports/ and credentials

**Migration Required:** Yes (for existing installations)

---

**Generated with Claude Code**
**Co-Authored-By:** Claude <noreply@anthropic.com>
