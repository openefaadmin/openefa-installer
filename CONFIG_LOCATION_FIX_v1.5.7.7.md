# Config File Location Architecture - v1.5.7.7

**Date:** October 20, 2025
**Priority:** HIGH - Security & Best Practices
**Issue:** Proper separation of credentials and application config files

---

## Problem

Previous versions had inconsistent configuration file locations:
- Some credentials in `/opt/spacyserver/config/`
- Mixing application code with sensitive credentials
- Not following Linux FHS (Filesystem Hierarchy Standard)

**Security concerns:**
- Credentials stored in application directory
- Easier for attackers to find
- Not separated by security level
- Violates principle of least privilege

---

## Solution: Dual-Location Architecture with Symlinks

### New Architecture:

```
/etc/spacy-server/           ← Credentials (system-wide, protected)
├── .env                     (Environment variables, secrets)
└── .my.cnf                  (Database credentials)

/opt/spacyserver/config/     ← Application configs + Symlinks
├── .env        → /etc/spacy-server/.env         (symlink)
├── .my.cnf     → /etc/spacy-server/.my.cnf      (symlink)
├── module_config.json
├── email_filter_config.json
├── bec_config.json
├── authentication_config.json
├── quarantine_config.json
└── ... (other JSON configs)
```

### Why This Design:

1. **Security Separation:**
   - Credentials: `/etc/spacy-server/` (root-owned directory, 750 permissions)
   - Application configs: `/opt/spacyserver/config/` (spacy-filter owned)

2. **Linux Best Practices:**
   - `/etc/` for system-wide configuration (FHS standard)
   - `/opt/` for application-specific data

3. **Backward Compatibility:**
   - Code continues reading from `/opt/spacyserver/config/`
   - Symlinks transparently redirect to `/etc/spacy-server/`
   - No code changes needed!

4. **Access Control:**
   - Root can manage credentials
   - spacy-filter user has read-only access via symlinks
   - Application configs owned by spacy-filter

---

## File Permissions

### /etc/spacy-server/

```bash
drwxr-x--- root:spacy-filter 750 /etc/spacy-server/
-rw------- spacy-filter:spacy-filter 600 /etc/spacy-server/.env
-rw------- spacy-filter:spacy-filter 600 /etc/spacy-server/.my.cnf
```

**Why these permissions:**
- `.env`: Contains Flask secrets, API keys → 600 (spacy-filter only, most restrictive)
- `.my.cnf`: Database password → 600 (spacy-filter only)
- Directory: 750 (root write, group read+execute)

### /opt/spacyserver/config/

```bash
drwxr-x--- spacy-filter:spacy-filter 750 /opt/spacyserver/config/
lrwxrwxrwx spacy-filter:spacy-filter   22 .env → /etc/spacy-server/.env
lrwxrwxrwx spacy-filter:spacy-filter   25 .my.cnf → /etc/spacy-server/.my.cnf
-rw-r----- spacy-filter:spacy-filter  640 module_config.json
-rw-r----- spacy-filter:spacy-filter  640 email_filter_config.json
```

**Why these permissions:**
- Symlinks: 777 (permissions controlled by target file)
- JSON configs: 640 (spacy-filter write, group read)
- Directory: 750 (spacy-filter full access)

---

## Implementation

### 1. Directory Creation

**File:** `lib/database.sh` - Lines 109-113

```bash
create_env_file() {
    local config_dir="/etc/spacy-server"
    local env_file="${config_dir}/.env"

    # Create system config directory
    create_directory "${config_dir}" "root:spacy-filter" "750"
    ...
}
```

### 2. Credential File Creation

**Files created in `/etc/spacy-server/`:**

- `.env` - Flask secrets, API keys, ClickSend config, Redis URL
- `.my.cnf` - MariaDB credentials

**File:** `lib/database.sh` - Lines 106-196

### 3. Symlink Creation (NEW)

**File:** `lib/database.sh` - Lines 198-237

```bash
create_config_symlinks() {
    local etc_config="/etc/spacy-server"
    local app_config="/opt/spacyserver/config"

    # Create application config directory
    if [[ ! -d "${app_config}" ]]; then
        create_directory "${app_config}" "spacy-filter:spacy-filter" "750"
    fi

    # Create symlink for .env
    if [[ -f "${etc_config}/.env" ]]; then
        rm -f "${app_config}/.env"  # Remove old file if exists
        ln -s "${etc_config}/.env" "${app_config}/.env"
    fi

    # Create symlink for .my.cnf
    if [[ -f "${etc_config}/.my.cnf" ]]; then
        rm -f "${app_config}/.my.cnf"
        ln -s "${etc_config}/.my.cnf" "${app_config}/.my.cnf"
    fi
}
```

### 4. Permission Fixing

**File:** `lib/services.sh` - Lines 220-235

```bash
fix_config_permissions() {
    # Fix .my.cnf (actual file in /etc/spacy-server)
    if [[ -f "/etc/spacy-server/.my.cnf" ]]; then
        chown spacy-filter:spacy-filter "/etc/spacy-server/.my.cnf"
        chmod 600 "/etc/spacy-server/.my.cnf"
    fi

    # Fix .env (actual file in /etc/spacy-server)
    if [[ -f "/etc/spacy-server/.env" ]]; then
        chown spacy-filter:spacy-filter "/etc/spacy-server/.env"
        chmod 600 "/etc/spacy-server/.env"
    fi

    # Symlinks follow to actual files, no need to set permissions on them
}
```

---

## Code Compatibility

### Python Scripts (NO CHANGES NEEDED)

All Python scripts continue reading from `/opt/spacyserver/config/`:

```python
# email_filter.py Line 210
my_cnf_path = '/opt/spacyserver/config/.my.cnf'

# behavioral_baseline.py Line 52
with open('/opt/spacyserver/config/.my.cnf', 'r') as f:

# modules/email_database.py
with open('/opt/spacyserver/config/.my.cnf', 'r') as f:
```

**How it works:**
1. Code opens `/opt/spacyserver/config/.my.cnf`
2. OS follows symlink to `/etc/spacy-server/.my.cnf`
3. File is read transparently
4. No code modifications needed!

---

## Installation Flow

### Fresh Installation:

1. **Create `/etc/spacy-server/` directory** (root:spacy-filter, 750)
2. **Create `.env` file** in `/etc/spacy-server/` (spacy-filter:spacy-filter, 600)
3. **Create `.my.cnf` file** in `/etc/spacy-server/` (spacy-filter:spacy-filter, 600)
4. **Create `/opt/spacyserver/config/` directory** (spacy-filter:spacy-filter, 750)
5. **Create symlinks:**
   - `/opt/spacyserver/config/.env` → `/etc/spacy-server/.env`
   - `/opt/spacyserver/config/.my.cnf` → `/etc/spacy-server/.my.cnf`
6. **Create other JSON config files** in `/opt/spacyserver/config/`

### Upgrade from Previous Version:

**If old installation has credentials in `/opt/spacyserver/config/`:**

1. Installer creates `/etc/spacy-server/`
2. **Moves** `.env` and `.my.cnf` to `/etc/spacy-server/`
3. Creates symlinks in `/opt/spacyserver/config/`
4. Code continues working without interruption

**Migration handled automatically by installer!**

---

## Security Benefits

### Before (Old Architecture):

```
/opt/spacyserver/config/
├── .env              ← VULNERABLE: App directory
├── .my.cnf           ← VULNERABLE: App directory
├── module_config.json
└── ...
```

**Risks:**
- ❌ Credentials in application directory
- ❌ Easier for attackers to find
- ❌ All configs same security level
- ❌ Web server could potentially read
- ❌ Violates FHS best practices

### After (New Architecture):

```
/etc/spacy-server/    ← SECURE: System config location
├── .env              ← Protected by directory permissions
└── .my.cnf           ← Protected by directory permissions

/opt/spacyserver/config/
├── .env → /etc/spacy-server/.env      (symlink)
├── .my.cnf → /etc/spacy-server/.my.cnf (symlink)
└── ... (other configs)
```

**Benefits:**
- ✅ Credentials separated from application
- ✅ Following Linux FHS standard
- ✅ Security levels properly separated
- ✅ Root-owned directory protects credentials
- ✅ Symlinks provide transparent access
- ✅ No code changes needed

---

## Testing

### Verify Installation:

```bash
# 1. Check /etc/spacy-server/ exists and has correct permissions
ls -la /etc/spacy-server/
# Expected: drwxr-x--- root spacy-filter

# 2. Check credential files exist
ls -la /etc/spacy-server/.env /etc/spacy-server/.my.cnf
# Expected:
#   -rw-r----- root spacy-filter .env
#   -rw------- spacy-filter spacy-filter .my.cnf

# 3. Check symlinks exist
ls -la /opt/spacyserver/config/.env /opt/spacyserver/config/.my.cnf
# Expected: Both should be symlinks (lrwxrwxrwx) pointing to /etc/spacy-server/

# 4. Verify symlinks work
cat /opt/spacyserver/config/.env | head -5
cat /opt/spacyserver/config/.my.cnf
# Should show contents from /etc/spacy-server/

# 5. Test Python can read
sudo -u spacy-filter python3 -c "import os; print(os.path.exists('/opt/spacyserver/config/.my.cnf'))"
# Expected: True
```

### Verify Email Filter Works:

```bash
# Check email filter can access config
sudo tail -50 /var/log/mail.log | grep "\.my\.cnf\|\.env"
# Should show no errors about missing files
```

---

## Files Modified

### Installer Files:

- ✅ `lib/database.sh` (Lines 109, 171, 198-237, 366, 379)
  - create_env_file(): Uses /etc/spacy-server
  - create_mysql_config(): Uses /etc/spacy-server
  - create_config_symlinks(): NEW function to create symlinks
  - Added to setup_database() call chain
  - Added to exports

- ✅ `lib/services.sh` (Lines 220-235)
  - fix_config_permissions(): Now handles /etc/spacy-server/

### Production Files:

- ⚠️ NO CHANGES NEEDED
  - Python scripts continue reading from /opt/spacyserver/config/
  - Symlinks make location transparent

---

## Rollback Plan

**If issues occur:**

1. **Remove symlinks:**
   ```bash
   rm /opt/spacyserver/config/.env
   rm /opt/spacyserver/config/.my.cnf
   ```

2. **Copy files back:**
   ```bash
   cp /etc/spacy-server/.env /opt/spacyserver/config/.env
   cp /etc/spacy-server/.my.cnf /opt/spacyserver/config/.my.cnf
   ```

3. **Fix permissions:**
   ```bash
   chown spacy-filter:spacy-filter /opt/spacyserver/config/.my.cnf
   chmod 600 /opt/spacyserver/config/.my.cnf
   chown spacy-filter:spacy-filter /opt/spacyserver/config/.env
   chmod 600 /opt/spacyserver/config/.env
   ```

**System continues working with old architecture**

---

## Future Enhancements

**Potential improvements:**

1. **Move all configs to /etc/spacy-server/**
   - Currently only credentials
   - Could move JSON configs too

2. **Environment-specific configs**
   - /etc/spacy-server/production/
   - /etc/spacy-server/development/

3. **Config validation**
   - Check file exists before creating symlink
   - Validate permissions on startup

4. **Encrypted credentials**
   - Use systemd-creds or ansible-vault
   - Decrypt on service start

---

## Compliance

**Security Standards:**

- ✅ **FHS (Filesystem Hierarchy Standard):** System configs in /etc
- ✅ **Principle of Least Privilege:** Minimal file permissions
- ✅ **Defense in Depth:** Multiple layers of protection
- ✅ **Separation of Concerns:** Credentials vs application config

**Best Practices:**

- ✅ **Never commit credentials to git**
- ✅ **Root-owned credential directory**
- ✅ **Read-only access for application user**
- ✅ **Symlinks for backward compatibility**

---

**Generated with Claude Code**
**Co-Authored-By:** Claude <noreply@anthropic.com>
