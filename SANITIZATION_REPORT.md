# OpenEFA Installer - Production Data Sanitization Report

**Generated**: 2025-10-15
**Server**: 192.168.50.58 (openspacy - Test/Development)
**Repository**: /opt/openefa-installer/

## Executive Summary

The installer contains **extensive production data** that must be sanitized before public release. Found **15+ production client domains**, **5 VIP/executive profiles**, **800+ whitelist entries**, and **hardcoded internal IP addresses** throughout the codebase.

---

## 🚨 Critical Issues Found

### 1. Hardcoded IP Addresses (10+ occurrences)

**Production IP: 192.168.50.37 (MailGuard server)**

| File | Line(s) | Issue |
|------|---------|-------|
| `openefa-files/email_filter.py` | 171, 174, 2253, 2267 | Hardcoded MailGuard IP |
| `openefa-files/web/app.py` | 3806 | Hardcoded relay host |
| `openefa-files/modules/quarantine_manager.py` | 277 | Hardcoded destination host |
| `openefa-files/tools/auto_update_spamassassin.sh` | 52 | Hardcoded SSH target |
| `openefa-files/automated_test_install.sh` | 9, 35 | Test relay server |
| `templates/config/authentication_config.json` | 4, 6 | Default sender IP, trusted network |
| `templates/config/email_filter_config.json` | 58, 61-62 | MailGuard host, trusted servers |
| `automated_test_install.sh` | 13, 26 | Test configuration |

**Additional IPs:**
- **192.168.50.114** - Found in email_filter.py (line 174) and email_filter_config.json (line 61)
- **192.168.50.0/24** - Network range in authentication_config.json (line 6)

**Impact**: Exposes internal network topology and relay infrastructure.

---

### 2. Production Client Domains (15+ domains)

**File: `openefa-files/email_filter.py` (Lines 121-131)**

#### Internal Domains (Line 121-124):
```python
'covereddata.com', 'seguelogic.com', 'safesoundins.com', 'offgriddynamics.com',
'rdjohnsonlaw.com', 'escudolaw.com', 'barbour.tech', 'securedata247.com',
'chrystinakatz.com', 'epolaw.ai', 'epobot.ai', 'sd247.guardiannet.world',
'openefa.com', 'openefa.org', 'guardiannet.world', 'statvu.com'
```

#### Processed Domains (Line 127-131):
```python
'seguelogic.com', 'offgriddynamics.com', 'covereddata.com', 'securedata247.com',
'rdjohnsonlaw.com', 'safesoundins.com', 'openefa.com', 'openefa.org',
'barbour.tech', 'escudolaw.com', 'chrystinakatz.com', 'epolaw.ai',
'epobot.ai', 'sd247.guardiannet.world', 'guardiannet.world',
'phoenixdefence.com', 'chipotlepublishing.com', 'statvu.com'
```

#### System Bypass Domains (Line 143):
```python
'spacy.covereddata.com'
```

#### Journal Addresses (Line 134-135):
```python
'journal@spacy.covereddata.com',
'journal@covereddata.com'
```

#### Trusted Infrastructure (Line 175):
```python
'zimbra.apollomx.com', 'mailguard.covereddata.com'
```

**Additional References:**
- Line 742: Authentication bypass logic for `mailguard.covereddata.com`, `spacy.covereddata.com`
- Line 2350-2351: Mail loop prevention for `spacy.covereddata.com`
- Line 2461-2463: Journal address detection
- Line 2602: Authentication header with `spacy.covereddata.com`

**Other Files:**
- `openefa-files/services/db_processor.py` (Line 202): `covereddata.com` in Message-ID generation
- `openefa-files/tools/domain_manager.sh` (Line 91): `journal@spacy.covereddata.com`
- `openefa-files/scripts/test_spacy_server.sh` (Lines 15, 99): `spacy.covereddata.com`

**Impact**: Exposes client list and internal infrastructure hostnames.

---

### 3. VIP/Executive Profiles (3,265 lines!)

**File: `templates/config/bec_config.json`**

#### Production Executive Data (Lines 2-85):

**5 VIP Profiles with Full Details:**

1. **scott@seguelogic.com** (Lines 3-24)
   - Name: Scott Barbour
   - Title: Chief Executive Officer
   - Full schedule, timezone, communication style, common topics
   - Aliases: CEO, Chief Executive, President, Owner

2. **sierra@seguelogic.com** (Lines 25-47)
   - Name: Sierra Izumi
   - Title: Operations Director
   - Alternate email: sierraizumi08152@gmail.com
   - Full profile data

3. **rob@rdjohnsonlaw.com** (Lines 48-59)
   - Name: Rob Johnson
   - Title: Esq

4. **dan@chipotlepublishing.com** (Lines 60-71)
   - Name: Dan Shea
   - Title: General Director

5. **debbie@chipotlepublishing.com** (Lines 72-85)
   - Name: Debbie Shea
   - Title: General Manager

#### Authentication-Aware Whitelist (Lines 86+):

**800+ whitelist entries** including legitimate services (good) mixed with production client senders (bad):

**Examples of entries that SHOULD stay** (legitimate services):
- `noreply@dattobackup.com`
- `calendar-notification@google.com`
- `alerts@bankofamerica.com`
- `noreply@stripe.com`

**Examples of entries that NEED REVIEW** (might be client-specific)

**Impact**: Exposes client VIP names, roles, schedules, and personal information. GDPR/privacy concern!

---

## 📊 Sanitization Priority Matrix

| Priority | Category | Files Affected | Effort | Risk |
|----------|----------|----------------|--------|------|
| 🔴 **P0** | VIP/Executive Data | 1 | High | Legal |
| 🔴 **P0** | Production Domains | 8 | High | Medium |
| 🟡 **P1** | Internal IPs | 10 | Medium | Low |
| 🟢 **P2** | Test Scripts | 3 | Low | None |

---

## 🛠️ Recommended Sanitization Strategy

### Phase 1: Remove VIP Data (P0 - Immediate)

**File**: `templates/config/bec_config.json`

**Actions**:
1. **Remove all executive entries** (Lines 2-85)
2. **Review authentication_aware whitelist** (Lines 86+)
   - Keep: Generic service providers (Google, Microsoft, banks, etc.)
   - Remove: Client-specific email addresses
   - Remove: Any entries that reference production domains
3. **Create minimal template** with example structure only

**Example sanitized structure**:
```json
{
  "executives": {
    "ceo@example.com": {
      "name": "Example CEO",
      "title": "Chief Executive Officer",
      "aliases": ["CEO", "Chief Executive"],
      "typical_hours": {"start": 8, "end": 18},
      "timezone": "America/New_York",
      "common_topics": ["strategy", "board"],
      "communication_style": "formal"
    }
  },
  "authentication_aware": {
    "senders": {
      "noreply@service.com": {
        "trust_score_bonus": 5,
        "description": "Example trusted service"
      }
    }
  }
}
```

---

### Phase 2: Sanitize Production Domains (P0 - Immediate)

**File**: `openefa-files/email_filter.py`

**Current hardcoded lists (Lines 121-144):**
- internal_domains: 16 production domains
- processed_domains: 17 production domains
- journal_addresses: 2 production addresses
- bypass_domains: 1 production domain

**Replacement Strategy:**

#### Option A: Empty Sets (Recommended)
```python
"domains": {
    "internal_domains": set(),  # Load from client_domains table
    "processed_domains": set(),  # Load from client_domains table
    "journal_addresses": set(),  # Configurable per installation
    "trusted_domains": set()
},
"system_bypass": {
    "bypass_domains": [],  # Load from config
    "bypass_addresses": []
}
```

#### Option B: Generic Examples
```python
"domains": {
    "internal_domains": {
        'example.com', 'client1.com', 'client2.com'
    },
    "processed_domains": {
        'example.com', 'client1.com', 'client2.com'
    },
    "journal_addresses": {
        'journal@mailserver.local'
    }
}
```

**Additional Changes Needed**:
- Line 175: Remove `'zimbra.apollomx.com', 'mailguard.covereddata.com'`
- Line 742: Change domain check to be configurable
- Line 2350: Make bypass domain configurable
- Line 2602: Use configurable hostname instead of `spacy.covereddata.com`

**Other Files:**
- `openefa-files/services/db_processor.py` (Line 202): Use configured hostname
- `openefa-files/tools/domain_manager.sh` (Line 91): Use variable for journal address

---

### Phase 3: Replace Hardcoded IPs (P1 - High Priority)

**Strategy**: Replace all hardcoded IPs with configuration variables or environment variables.

#### File-by-File Changes:

**1. openefa-files/email_filter.py**
```python
# Line 171 - BEFORE:
"mailguard_host": os.getenv('SPACY_MAILGUARD_HOST', '192.168.50.37'),

# AFTER:
"mailguard_host": os.getenv('SPACY_MAILGUARD_HOST', 'mailguard.local'),

# Line 174 - BEFORE:
'192.168.50.114', '192.168.50.37',

# AFTER:
# Load from config file instead

# Lines 2253, 2267 - BEFORE:
with smtplib.SMTP('192.168.50.37', 25, timeout=30) as smtp:

# AFTER:
relay_host = config.get('mailguard_host', 'localhost')
with smtplib.SMTP(relay_host, 25, timeout=30) as smtp:
```

**2. templates/config/authentication_config.json**
```json
{
  "spf": {
    "default_sender_ip": "YOUR_MAILGUARD_IP",
    "trusted_networks": [
      "YOUR_INTERNAL_NETWORK/24"
    ]
  }
}
```

**3. templates/config/email_filter_config.json**
```json
{
  "relay": {
    "mailguard_host": "YOUR_MAILGUARD_IP",
    "mailguard_port": 25,
    "trusted_servers": [
      "YOUR_TRUSTED_SERVER_IP"
    ]
  }
}
```

**4. openefa-files/modules/quarantine_manager.py**
```python
# Line 277 - Use config variable instead
'host': dest.get('host', config.get('relay_host', 'localhost'))
```

**5. automated_test_install.sh & openefa-files/automated_test_install.sh**
```bash
# Use environment variable or prompt
export OPENEFA_RELAY_IP="${OPENEFA_RELAY_IP:-YOUR_RELAY_SERVER_IP}"
```

---

### Phase 4: Clean Test Scripts (P2 - Low Priority)

**Files:**
- `automated_test_install.sh`
- `openefa-files/automated_test_install.sh`
- `openefa-files/tools/auto_update_spamassassin.sh`

**Actions:**
- Replace hardcoded IPs with environment variables
- Add comments explaining configuration needed
- Update documentation

---

## ✅ Sanitization Checklist

### Immediate Actions (Before Public Release):

- [ ] **Remove all VIP/executive profiles** from bec_config.json
- [ ] **Review and sanitize whitelist** in bec_config.json (keep generic services only)
- [ ] **Replace production domain lists** in email_filter.py with empty sets or examples
- [ ] **Remove internal infrastructure hostnames** (zimbra.apollomx.com, mailguard.covereddata.com)
- [ ] **Replace all 192.168.50.x IP addresses** with placeholders or config variables
- [ ] **Update all configuration templates** to use YOUR_* placeholders
- [ ] **Search for @covereddata.com, @seguelogic.com, etc.** in all files
- [ ] **Review automated_test_install.sh** for any remaining production data
- [ ] **Update documentation** to explain configuration requirements
- [ ] **Test clean install** to ensure placeholders work correctly

### Verification Steps:

```bash
# Run from /opt/openefa-installer/

# Check for remaining production IPs
grep -r "192\.168\.50\." --include="*.py" --include="*.sh" --include="*.json" . | grep -v ".git" | grep -v "scan_for_secrets"

# Check for production domains
grep -r "covereddata\|seguelogic\|safesoundins\|phoenixdefence\|chipotlepublishing" --include="*.py" --include="*.sh" --include="*.json" . | grep -v ".git"

# Check for production emails
grep -r "@seguelogic\|@rdjohnsonlaw\|@chipotlepublishing\|@covereddata" --include="*.json" . | grep -v ".git"

# Check for internal hostnames
grep -r "zimbra\.apollomx\|mailguard\.covereddata\|spacy\.covereddata" --include="*.py" --include="*.sh" . | grep -v ".git"
```

---

## 📝 Notes

1. **Keep Generic Service Whitelists**: Entries like `noreply@stripe.com`, `calendar-notification@google.com` are fine - these are public services, not client data.

2. **Configuration Over Hardcoding**: After sanitization, installer should prompt for or read from config:
   - Relay/MailGuard IP address
   - Internal network range
   - Journal address pattern
   - System hostname

3. **Database-Driven Approach**: The `client_domains` table should be the source of truth for domain lists, not hardcoded arrays.

4. **Privacy Compliance**: VIP data removal is critical for GDPR/privacy compliance. Names, roles, schedules, and personal emails must not be in public code.

5. **Documentation**: Update README and installation docs to clearly explain what configuration is needed during setup.

---

## 🎯 Success Criteria

**Ready for Public Release When**:
- ✅ Zero production client domain names in code
- ✅ Zero production email addresses in code
- ✅ Zero internal IP addresses hardcoded
- ✅ Zero VIP/personal information in templates
- ✅ All config uses generic examples or prompts for user input
- ✅ Clean install works with placeholder configuration
- ✅ Documentation explains all required configuration steps

---

**Generated by**: Claude Code
**Review Status**: 🔴 **REQUIRES IMMEDIATE SANITIZATION**
**Next Step**: Review this report with team and prioritize sanitization tasks
