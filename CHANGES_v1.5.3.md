# OpenEFA Installer v1.5.3 - SMS Notification System & Documentation

**Release Date:** 2025-10-19
**Priority:** High - Enhanced Monitoring & Documentation
**Type:** Feature Addition + Documentation

---

## Overview

Version 1.5.3 introduces a comprehensive SMS notification system for real-time security alerts and system health monitoring, plus complete structured documentation for the OpenEFA project.

---

## Major Features Added

### 1. SMS Notification System (ClickSend Integration)

Real-time SMS alerts for critical email threats and system health issues.

#### Components Added

**Core Notification Service:**
- **`notification_service.py`** - Main notification service with ClickSend API integration
- **`config/notification_config.json`** - Configuration for SMS alerts, rate limiting, and recipients
- **Database tables** - `notification_log`, `notification_rate_limit`, `notification_settings`

**Monitoring Scripts:**
- **`scripts/send_daily_notification_summary.py`** - Daily email statistics summary (runs 8:00 AM)
- **`scripts/system_health_monitor.py`** - System health checks every 10 minutes

**Email Filter Integration:**
- Phishing detection → SMS alert
- Business Email Compromise (BEC) → SMS alert
- Virus/malware detection → SMS alert
- High spam scores (≥80) → SMS alert

#### Features

**Real-Time Threat Alerts:**
```
SECURITY ALERT: Phishing attempt blocked from scammer@evil.com
SECURITY ALERT: Business Email Compromise attempt from ceo@fake-domain.com
SECURITY ALERT: Virus detected in email from infected@badsite.com
ALERT: High-risk email detected. Score: 95, Reason: high_spam_score
```

**System Health Monitoring:**
```
CRITICAL: Postfix mail server is DOWN
WARNING: 15 emails stuck in mail queue
CRITICAL: Database connection failed
CRITICAL: Disk space at 92%
```

**Daily Summaries:**
```
OpenEFA Daily Report: Processed 107, Blocked 5, Threats 2, Quarantined 50
```

**Rate Limiting:**
- Max 10 SMS per hour per recipient
- 5-minute cooldown between notifications
- 30-minute duplicate suppression
- System alert cooldown per alert type

#### Database Schema

**notification_log table:**
```sql
CREATE TABLE notification_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    notification_type ENUM('high_risk_alert', 'system_alert', 'daily_summary'),
    recipient VARCHAR(20),
    message TEXT,
    email_id INT,
    trigger_reason VARCHAR(100),
    status ENUM('pending', 'sent', 'failed', 'rate_limited'),
    response_code VARCHAR(50),
    response_message TEXT,
    sent_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**notification_rate_limit table:**
```sql
CREATE TABLE notification_rate_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recipient VARCHAR(20),
    notification_type VARCHAR(50),
    last_sent DATETIME,
    hourly_count INT DEFAULT 0,
    hour_window DATETIME
);
```

#### Cron Jobs Added

```cron
# Send daily notification summary at 8:00 AM
0 8 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/send_daily_notification_summary.py >> /opt/spacyserver/logs/daily_summary.log 2>&1

# Monitor system health every 10 minutes
*/10 * * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/system_health_monitor.py >> /opt/spacyserver/logs/health_monitor.log 2>&1
```

---

### 2. Comprehensive Documentation System

Professional, structured documentation covering all aspects of OpenEFA.

#### Documentation Structure

```
/opt/spacyserver/docs/
├── README.md                           # Main index and navigation
├── 01-overview/
│   ├── introduction.md                 # What is OpenEFA?
│   └── features.md                     # Complete feature list
├── 02-installation/                    # Installation guides (planned)
├── 03-core-concepts/
│   └── learning-philosophy.md          # ⭐ System-wide vs per-domain learning
├── 04-modules/                         # Module documentation (planned)
├── 05-scoring-breakdown/               # Scoring system (planned)
├── 06-web-interface/                   # Web UI guides (planned)
├── 07-administration/                  # Admin guides (planned)
├── 08-configuration/                   # Config reference (planned)
├── 09-api/                             # API documentation (planned)
├── 10-database/                        # Database schema (planned)
├── 11-troubleshooting/                 # Troubleshooting (planned)
├── 12-development/                     # Developer guides (planned)
└── 13-appendix/                        # Glossary, commands (planned)
```

#### Featured Documentation

**learning-philosophy.md (741 lines)**
Comprehensive explanation of OpenEFA's two-tier learning architecture:

- **System-Wide Vocabulary** - Shared language intelligence across all domains
- **Per-Domain Relationships** - Isolated sender-recipient trust tracking
- **Why This Design is Superior** - Machine learning theory and practical benefits
- **Multi-Tenant Considerations** - How different companies coexist
- **Real-World Examples** - Medical vs Construction company scenarios
- **Scoring Weights** - Domain relationships carry highest weight (35%)
- **Privacy & Security** - Hashed vocabulary, isolated relationships
- **FAQ Section** - Common questions answered

**Key Topics Covered:**
- The 80/20 rule in business communication
- Why spam detection doesn't need industry-specific models
- Machine learning benefits from larger datasets
- New domains get immediate intelligence
- Database schema and scoring methodology

**introduction.md (295 lines)**
- What is OpenEFA?
- Key features overview
- Architecture highlights
- Technology stack
- Use cases and deployment models

**features.md (394 lines)**
- Comprehensive feature catalog
- Component descriptions
- Integration points
- Feature comparison tables

#### Documentation Principles

- **Progressive Disclosure:** Simple → Complex
- **Task-Oriented:** Organized by user goals
- **Role-Based Navigation:** Admin, DomainAdmin, User, Developer
- **Practical Examples:** Real-world scenarios
- **Searchable:** Clear naming and indexing

---

## Files Added/Modified

### New Files Added

#### Notification System (7 files)
1. **`/opt/spacyserver/notification_service.py`** (478 lines)
   - ClickSend SMS integration
   - Rate limiting and cooldown logic
   - Database logging
   - Test mode support

2. **`/opt/spacyserver/config/notification_config.json`**
   - ClickSend API credentials
   - Notification recipients
   - Alert enable/disable toggles
   - Rate limiting configuration

3. **`/opt/spacyserver/scripts/send_daily_notification_summary.py`** (187 lines)
   - Daily email statistics calculation
   - SMS summary generation
   - Configurable timezone support

4. **`/opt/spacyserver/scripts/system_health_monitor.py`** (268 lines)
   - Postfix service monitoring
   - Mail queue size checking
   - Database connectivity testing
   - Disk space monitoring
   - Alert cooldown management

5. **`/opt/spacyserver/sql/create_notification_tables.sql`**
   - Database schema for notification system
   - notification_log table
   - notification_rate_limit table
   - notification_settings table

6. **`/opt/spacyserver/CLICKSEND_SETUP.txt`**
   - User setup guide
   - Configuration instructions
   - Testing procedures

7. **`/opt/spacyserver/FORUM_POST_CLICKSEND_NOTIFICATIONS.md`**
   - Forum announcement post
   - Feature description
   - Community documentation

#### Documentation (4 files + 13 directories)
8. **`/opt/spacyserver/docs/README.md`** (282 lines)
   - Main documentation index
   - Navigation by role
   - Quick reference links
   - Document status tracker

9. **`/opt/spacyserver/docs/03-core-concepts/learning-philosophy.md`** (741 lines)
   - Learning architecture explanation
   - Multi-tenant design philosophy
   - Real-world examples and FAQ

10. **`/opt/spacyserver/docs/01-overview/introduction.md`** (295 lines)
    - OpenEFA overview
    - Key features
    - Quick start guide

11. **`/opt/spacyserver/docs/01-overview/features.md`** (394 lines)
    - Complete feature catalog
    - Component descriptions
    - Integration details

12. **13 Documentation Directories** created for organized structure

### Modified Files

#### Email Filter Integration
1. **`/opt/spacyserver/email_filter.py`** (lines 58-71, 1297-1310, 1504-1516, 1733-1745, 2921-2934)

   **Added notification service import:**
   ```python
   # Import notification service for SMS alerts
   NOTIFICATION_SERVICE = None
   try:
       from notification_service import NotificationService
       NOTIFICATION_SERVICE = NotificationService()
       print("✅ Notification service initialized", file=sys.stderr)
   except Exception as e:
       print("⚠️  Notification service not available: {e}", file=sys.stderr)
   ```

   **Integration points:**
   - **Line ~1299:** Phishing detection → `send_high_risk_alert()`
   - **Line ~1504:** BEC detection (confidence ≥0.8) → `send_high_risk_alert()`
   - **Line ~1734:** Virus detection → `send_high_risk_alert()`
   - **Line ~2923:** High spam score (≥80) quarantine → `send_high_risk_alert()`

   **Changes:** +58 lines, graceful degradation if notification service unavailable

---

## Installation Impact

### New Installations (v1.5.3)

Will automatically include:
- ✅ SMS notification system fully configured
- ✅ System health monitoring enabled
- ✅ Daily summary reports scheduled
- ✅ Complete documentation available
- ✅ Email filter integrated with notifications

### Existing Installations

**Manual Upgrade Steps:**

1. **Copy notification files:**
```bash
sudo cp /opt/openefa-installer/openefa-files/notification_service.py /opt/spacyserver/
sudo cp /opt/openefa-installer/openefa-files/config/notification_config.json /opt/spacyserver/config/
sudo cp /opt/openefa-installer/openefa-files/scripts/send_daily_notification_summary.py /opt/spacyserver/scripts/
sudo cp /opt/openefa-installer/openefa-files/scripts/system_health_monitor.py /opt/spacyserver/scripts/
```

2. **Set permissions:**
```bash
sudo chown spacy-filter:spacy-filter /opt/spacyserver/notification_service.py
sudo chmod 755 /opt/spacyserver/notification_service.py
sudo chown spacy-filter:spacy-filter /opt/spacyserver/scripts/*.py
sudo chmod 755 /opt/spacyserver/scripts/*.py
sudo chown spacy-filter:spacy-filter /opt/spacyserver/config/notification_config.json
sudo chmod 600 /opt/spacyserver/config/notification_config.json
```

3. **Create database tables:**
```bash
mysql -u root -p spacy_email_db < /opt/openefa-installer/openefa-files/sql/create_notification_tables.sql
```

4. **Install Python dependency:**
```bash
sudo /opt/spacyserver/venv/bin/pip install clicksend-client==5.0.78
```

5. **Configure ClickSend API:**
Edit `/opt/spacyserver/config/notification_config.json` with your ClickSend credentials

6. **Add cron jobs:**
```bash
(sudo crontab -u spacy-filter -l 2>/dev/null; cat <<EOF
0 8 * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/send_daily_notification_summary.py >> /opt/spacyserver/logs/daily_summary.log 2>&1
*/10 * * * * /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/system_health_monitor.py >> /opt/spacyserver/logs/health_monitor.log 2>&1
EOF
) | sudo crontab -u spacy-filter -
```

7. **Update email_filter.py:**
```bash
sudo cp /opt/openefa-installer/openefa-files/email_filter.py /opt/spacyserver/
sudo chown spacy-filter:spacy-filter /opt/spacyserver/email_filter.py
sudo chmod 755 /opt/spacyserver/email_filter.py
sudo systemctl restart postfix
```

8. **Copy documentation:**
```bash
sudo cp -r /opt/openefa-installer/openefa-files/docs /opt/spacyserver/
sudo chown -R spacy-filter:spacy-filter /opt/spacyserver/docs
```

---

## Configuration

### Notification Configuration

Edit `/opt/spacyserver/config/notification_config.json`:

```json
{
  "clicksend": {
    "username": "your_clicksend_username",
    "api_key": "your_clicksend_api_key"
  },
  "recipients": {
    "default": "+1234567890"
  },
  "alerts": {
    "phishing_detected": true,
    "bec_detected": true,
    "virus_detected": true,
    "high_spam_score": true,
    "system_health": true,
    "daily_summary": true
  },
  "rate_limits": {
    "max_per_hour": 10,
    "cooldown_minutes": 5,
    "duplicate_suppression_minutes": 30
  },
  "thresholds": {
    "high_spam_score": 80,
    "mail_queue_warning": 10,
    "disk_space_warning": 90
  },
  "timezone": "America/Los_Angeles"
}
```

### Testing

**Test ClickSend connection:**
```bash
sudo -u spacy-filter /opt/spacyserver/venv/bin/python3 /opt/spacyserver/notification_service.py test
```

**Test daily summary:**
```bash
sudo -u spacy-filter /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/send_daily_notification_summary.py
```

**Test system health monitor:**
```bash
sudo -u spacy-filter /opt/spacyserver/venv/bin/python3 /opt/spacyserver/scripts/system_health_monitor.py
```

---

## Verification

### Check Notification System

```bash
# 1. Verify notification service exists
ls -lh /opt/spacyserver/notification_service.py

# 2. Verify configuration file
ls -lh /opt/spacyserver/config/notification_config.json

# 3. Verify database tables
mysql -u root -p -e "SHOW TABLES FROM spacy_email_db LIKE 'notification%';"

# 4. Verify cron jobs
sudo crontab -u spacy-filter -l | grep -E "daily_summary|health_monitor"

# 5. Check logs
ls -lh /opt/spacyserver/logs/{notifications,daily_summary,health_monitor}.log

# 6. Verify Python dependency
/opt/spacyserver/venv/bin/pip list | grep clicksend
```

### Check Documentation

```bash
# Verify documentation structure
ls -la /opt/spacyserver/docs/

# Count documentation files
find /opt/spacyserver/docs -name "*.md" | wc -l

# View main index
cat /opt/spacyserver/docs/README.md
```

---

## Dependencies

### New Python Packages
- **clicksend-client** (5.0.78) - ClickSend SMS API integration

### Existing Dependencies (no changes)
- All dependencies from v1.5.2 and earlier

---

## Security Considerations

### Notification System

**Credentials Protection:**
- ClickSend API key stored in `notification_config.json`
- File permissions: `600` (owner read/write only)
- Credentials never logged to files
- Database password in scripts (consider using .my.cnf)

**Rate Limiting:**
- Prevents SMS spam/abuse
- Cooldown periods between alerts
- Hourly limits per recipient
- Cost control for ClickSend usage

**Database Access:**
- Notification tables use existing spacy_user credentials
- Audit trail in notification_log table
- No sensitive email content in notifications

### Documentation

**Public Documentation:**
- Safe to include in public repositories
- No credentials or sensitive data
- Generic examples only
- Security best practices documented

---

## Cost Management

### ClickSend SMS Costs

- **Rate:** ~1 credit per 160 characters (~$0.08 USD per SMS)
- **Estimated daily usage:** 5-15 SMS
- **Monthly estimate:** 150-450 SMS (~$12-36 USD/month)
- **Rate limiting prevents:** Runaway costs from alert storms

**Monitor usage:**
- ClickSend dashboard: https://dashboard.clicksend.com
- Database query: `SELECT COUNT(*) FROM notification_log WHERE status='sent' AND sent_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);`

---

## Documentation Roadmap

### Phase 1: Essential Documentation (Complete ✅)
- ✅ Main README.md index
- ✅ Introduction and features overview
- ✅ Learning philosophy (system-wide vs per-domain)
- ✅ Documentation structure (13 sections)

### Phase 2: Administrator Documentation (Planned)
- 📝 Installation guides
- 📝 Configuration reference
- 📝 User management
- 📝 Domain configuration
- 📝 Troubleshooting guides

### Phase 3: Advanced Topics (Planned)
- 📝 Module documentation
- 📝 API reference
- 📝 Database schema details
- 📝 Development guide

---

## Troubleshooting

### Notification Issues

**SMS not received:**
- Check ClickSend credits balance
- Verify phone number format (+1 country code)
- Check `notification_log` table for status
- Verify rate limits not exceeded
- Test with: `/opt/spacyserver/notification_service.py test`

**No alerts for email threats:**
- Check `email_filter.py` has notification integration
- Verify `NOTIFICATION_SERVICE` initialized (check mail.log)
- Check notification_config.json enabled settings
- Verify ClickSend API credentials

**Cron jobs not running:**
- Check crontab: `sudo crontab -u spacy-filter -l`
- Check log files for errors
- Verify file permissions (executable)
- Ensure spacy-filter user has access

---

## Backwards Compatibility

- ✅ **Email filter:** Graceful degradation if notification service unavailable
- ✅ **Database:** New tables don't affect existing functionality
- ✅ **Cron jobs:** Independent of existing jobs
- ✅ **Configuration:** New config file, doesn't modify existing configs
- ✅ **Documentation:** Addition only, no changes to existing files

---

## Testing Performed

### Production Testing (192.168.50.58)
- ✅ ClickSend SMS delivery verified
- ✅ Phishing detection → SMS alert received
- ✅ BEC detection → SMS alert received
- ✅ Virus detection → SMS alert received
- ✅ System health monitoring → Postfix down alert received
- ✅ Daily summary → SMS received at scheduled time
- ✅ Rate limiting → Verified cooldown working
- ✅ Database logging → All notifications logged
- ✅ Cron jobs → Running on schedule

### Documentation Testing
- ✅ All Markdown files validated
- ✅ Links verified
- ✅ Code examples tested
- ✅ Structure navigation tested

---

## Related Features

This release builds upon:
- **v1.5.2** - Email cleanup system
- **v1.5.1** - ClamAV antivirus integration
- **v1.5.0** - Spam score breakdown and detailed email analysis
- **v1.4.x** - Multi-tenant architecture and user management

---

## Known Issues / Limitations

1. **Notification Configuration:**
   - Database password hard-coded in scripts (should use .my.cnf)
   - Single recipient per alert type (multi-recipient planned)

2. **Documentation:**
   - Only 4 of 13 planned sections have content
   - Additional modules need documentation
   - API reference not yet written

3. **System Health Monitoring:**
   - Basic checks only (CPU, memory monitoring planned)
   - No predictive alerting yet

---

## Future Enhancements (Not in v1.5.3)

- [ ] Multi-recipient notification support
- [ ] Voice call escalation for critical alerts
- [ ] Email notifications (in addition to SMS)
- [ ] Web dashboard for notification management
- [ ] Slack/Discord integration
- [ ] Alert acknowledgment system
- [ ] Quiet hours scheduling
- [ ] Complete documentation for all 13 sections
- [ ] Interactive documentation examples
- [ ] Video tutorials

---

## File Manifest

### Files Added to Installer
```
openefa-files/
├── notification_service.py                     (NEW)
├── config/notification_config.json             (NEW)
├── scripts/send_daily_notification_summary.py  (NEW)
├── scripts/system_health_monitor.py            (NEW)
├── sql/create_notification_tables.sql          (NEW)
├── CLICKSEND_SETUP.txt                         (NEW)
├── FORUM_POST_CLICKSEND_NOTIFICATIONS.md       (NEW)
└── docs/                                       (NEW)
    ├── README.md
    ├── 01-overview/
    │   ├── introduction.md
    │   └── features.md
    ├── 02-installation/
    ├── 03-core-concepts/
    │   └── learning-philosophy.md
    ├── 04-modules/ through 13-appendix/
```

### Files Modified in Installer
```
openefa-files/
├── email_filter.py                             (UPDATED)
    └── Added notification service integration
        ├── Import NotificationService
        ├── Phishing alert integration
        ├── BEC alert integration
        ├── Virus alert integration
        └── High spam score alert integration
```

### Installer Metadata
```
/opt/openefa-installer/
├── VERSION                                     (UPDATED: 1.5.2 → 1.5.3)
└── CHANGES_v1.5.3.md                          (NEW: This document)
```

---

## Git Commit Summary

**Commit Message:**
```
OpenEFA Installer v1.5.3 - SMS Notifications & Documentation

- Add ClickSend SMS notification system for real-time threat alerts
- Add system health monitoring (Postfix, database, disk, queue)
- Add daily email summary reports via SMS
- Integrate notifications into email_filter.py (phishing, BEC, virus, high spam)
- Add comprehensive documentation structure (13 sections)
- Add learning philosophy documentation (system-wide vs per-domain)
- Add introduction and features documentation
- Update email_filter.py with notification integration (+58 lines)
- Add rate limiting and cooldown for cost control
- Add notification database tables and audit logging
- Include cron jobs for daily summaries and health monitoring

New files: 12 (notification system + documentation)
Modified files: 1 (email_filter.py)
Version: 1.5.2 → 1.5.3
```

---

## Developer Notes

### Notification Service Architecture

The notification system uses a modular design:

1. **Core Service** (`notification_service.py`)
   - ClickSend API integration
   - Rate limiting logic
   - Database logging
   - Graceful error handling

2. **Integration Layer** (`email_filter.py`)
   - Lazy import (doesn't break if service unavailable)
   - Context-aware alerts (includes email metadata)
   - Non-blocking (exceptions caught)

3. **Monitoring Scripts**
   - Independent cron-scheduled checks
   - Stateful cooldown tracking
   - Configurable thresholds

4. **Database Layer**
   - Audit trail for all notifications
   - Rate limiting state management
   - Historical reporting data

### Documentation Philosophy

Progressive disclosure approach:
- **Level 1:** Quick overviews (introduction.md)
- **Level 2:** Getting started guides
- **Level 3:** Deep understanding (learning-philosophy.md)
- **Level 4:** Technical reference

Task-oriented organization:
- Organized by user goals (not system components)
- Role-based navigation (Admin, DomainAdmin, User, Developer)
- Cross-referenced related topics

---

**Next Version:** TBD
**Previous Version:** [v1.5.2](CHANGES_v1.5.2.md) - Email Cleanup System Fix

---

**Document Version:** 1.0
**Last Updated:** 2025-10-19
**Author:** OpenEFA Development Team
