# EFA/MailGuard SpamAssassin Integration

**Purpose**: Configure your downstream EFA/MailGuard server to read and respond to OpenEFA (SpaCy) scoring headers.

**Critical**: Without this integration, MailGuard will re-run its own authentication checks (SPF/DKIM/DMARC) and ignore OpenEFA's analysis, defeating the purpose of having OpenEFA in your mail flow.

---

## Overview

OpenEFA performs comprehensive email analysis and adds headers to each message:

- `X-SpaCy-Spam-Score` - Overall spam probability (0-100+)
- `X-SpaCy-Auth-Score` - Authentication quality (-10 to +10)
- `X-SpaCy-Auth-SPF` - SPF result (pass/fail/softfail/neutral)
- `X-SpaCy-Auth-DKIM` - DKIM result (pass/fail)
- `X-SpaCy-Auth-DMARC` - DMARC result (pass/fail)
- `X-BEC-Detected` - Business Email Compromise detection
- `X-Known-Scammer` - Known scammer identification
- Plus 20+ other analysis headers

Your MailGuard/EFA server needs SpamAssassin rules to:
1. **Trust OpenEFA's authentication** instead of re-checking
2. **Apply OpenEFA's spam scoring** to final delivery decisions
3. **Neutralize duplicate authentication checks** to prevent double-scoring

---

## Required Files

OpenEFA provides 4 SpamAssassin configuration files that must be deployed to your MailGuard/EFA server:

### 1. `spacy_rules.cf` (15KB, ~305 lines)
**Purpose**: Core SpaCy integration - authentication handling and scoring

**Key Features**:
- Detects emails processed by OpenEFA (`X-SpaCy-Processed` header)
- **Neutralizes MailGuard's own authentication checks** (sets SPF/DKIM/DMARC scores to 0)
- Applies OpenEFA's authentication scoring based on `X-SpaCy-Auth-*` headers
- Defines authentication quality tiers:
  - Perfect Auth (SPF+DKIM+DMARC pass): -6.0 points
  - Excellent Auth (SPF+DKIM pass): -5.0 points
  - DMARC validated: -3.0 points
  - Good Auth (DKIM only): -2.0 points
  - Auth failures from trusted domains: +3.0 to +8.0 points
- Known scammer overrides (blocks specific bad actors regardless of auth)
- Financial scam pattern detection
- Vendor whitelist handling

**Deploy to**: `/etc/mail/spamassassin/spacy_rules.cf`

### 2. `local.cf` (7KB, ~194 lines)
**Purpose**: Standard SpamAssassin configuration and general spam rules

**Key Features**:
- Spam threshold: `required_score 5.4`
- Bayes learning configuration
- Marketing/sales spam detection
- Unicode obfuscation detection
- Cryptocurrency scam patterns
- Phishing and lookalike domain detection
- URL shortener penalties
- Time-based anomaly detection

**Deploy to**: `/etc/mail/spamassassin/local.cf`

### 3. `zzz_spacy_trust.cf` (2.5KB, ~123 lines)
**Purpose**: Complete trust configuration - makes MailGuard defer to OpenEFA

**Key Features**:
- **Disables ALL local authentication checks** (SPF/DKIM/DMARC scores set to 0)
- Trusts OpenEFA's authentication scoring:
  - High Pass (10+): -5.0 points
  - Pass (5-9): -3.0 points
  - Neutral (0-4): 0 points
  - Fail (-1 to -4): +2.0 points
  - High Fail (-5 or worse): +5.0 points
- Trusts OpenEFA's spam scoring:
  - High spam (5+): +3.0 points
  - Low spam (1-4): +1.0 points
- Special detection handling:
  - BEC detected: +10.0 points
  - Known scammer: +20.0 points
  - Auth abuse: +5.0 points
- Network trust: Marks OpenEFA server (192.168.50.89) as trusted

**Deploy to**: `/etc/mail/spamassassin/zzz_spacy_trust.cf`

**Why "zzz_" prefix?**: SpamAssassin processes files alphabetically. The `zzz_` prefix ensures this file loads LAST, so it can override any conflicting rules from earlier files.

### 4. `spacy_whitelist_integration.cf` (Optional)
**Purpose**: Dynamic whitelist integration via OpenEFA APIs

**Note**: This file is for advanced integration where MailGuard calls OpenEFA APIs. Not required for basic operation.

---

## Installation Methods

### Method 1: Manual Deployment (One-Time Setup)

If your MailGuard/EFA server is accessible and you have SSH access:

```bash
# On OpenEFA server (where installer ran)
cd /opt/spacyserver/config/spamassassin_cf

# Copy files to MailGuard/EFA server
scp spacy_rules.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp local.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp zzz_spacy_trust.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/

# SSH into MailGuard and restart SpamAssassin
ssh root@YOUR_EFA_SERVER_IP
spamassassin --lint    # Test configuration for syntax errors
systemctl restart mailscanner  # Or: service mailscanner restart
```

### Method 2: Using OpenEFA Deployment Tool

OpenEFA includes an automated deployment tool (requires SSH key setup):

```bash
sudo /opt/spacyserver/tools/deploy_spamassassin_rules.sh YOUR_EFA_SERVER_IP
```

This script will:
- Copy all 3 required files to `/etc/mail/spamassassin/`
- Run `spamassassin --lint` to validate syntax
- Restart MailScanner service
- Verify deployment

### Method 3: Non-Interactive (For Automated Deployments)

If you're using configuration management (Ansible, Salt, etc.):

```bash
# Source files location after OpenEFA install
/opt/spacyserver/config/spamassassin_cf/

# Destination on MailGuard/EFA
/etc/mail/spamassassin/

# Required files
spacy_rules.cf
local.cf
zzz_spacy_trust.cf

# After copying, run
spamassassin --lint
systemctl restart mailscanner
```

---

## Verification

### 1. Check File Deployment

```bash
# On MailGuard/EFA server
ls -l /etc/mail/spamassassin/spacy_*.cf /etc/mail/spamassassin/local.cf /etc/mail/spamassassin/zzz_spacy_trust.cf

# Should show all 3 files with proper permissions (644)
```

### 2. Test SpamAssassin Configuration

```bash
# On MailGuard/EFA server
spamassassin --lint

# Should return no errors
# If errors appear, check syntax in the .cf files
```

### 3. Verify Rule Loading

```bash
# On MailGuard/EFA server
spamassassin -D --lint 2>&1 | grep -i spacy

# Should show SpaCy rules being loaded
```

### 4. Test Email Flow

Send a test email through OpenEFA → MailGuard:

```bash
# On OpenEFA server
echo "Test email body" | mail -s "SpaCy Integration Test" your-email@yourdomain.com

# Check headers in received email for:
# - X-SpaCy-Processed: yes
# - X-SpaCy-Spam-Score: X.X
# - X-SpaCy-Auth-Score: X.X
# - X-Spam-Status should reflect SpaCy's scoring
```

### 5. Monitor Mail Logs

```bash
# On MailGuard/EFA server
tail -f /var/log/maillog | grep -i spam

# Look for SpamAssassin scores that reflect OpenEFA's analysis
```

---

## How It Works

### Email Flow

```
Internet → OpenEFA → MailGuard/EFA → Mailbox Server
            (AI)      (Trusts AI)     (Final Delivery)
```

### Scoring Example

**Scenario**: Gmail user sends legitimate email

1. **OpenEFA Analysis**:
   - SPF: pass ✓
   - DKIM: pass ✓
   - DMARC: pass ✓
   - Spam modules: clean (score 0.5)
   - Auth score: +10 (perfect)
   - Adds headers: `X-SpaCy-Auth-Score: 10`, `X-SpaCy-Spam-Score: 0.5`

2. **MailGuard Processing** (with SpaCy rules):
   - Detects `X-SpaCy-Processed` header
   - **Neutralizes** its own SPF_PASS (-0.3), DKIM_VALID (-0.5), DMARC_PASS (-0.5)
   - Applies `SPACY_AUTH_PERFECT` rule: **-6.0 points**
   - Final score: -6.0 + normal spam rules
   - Result: **Delivers cleanly**

3. **MailGuard Processing** (WITHOUT SpaCy rules - BAD!):
   - Runs own SPF check: -0.3 (pass)
   - Runs own DKIM check: -0.5 (pass)
   - Runs own DMARC check: -0.5 (pass)
   - **Ignores OpenEFA's analysis completely**
   - Final score: -1.3 + normal spam rules
   - Result: Less accurate filtering, duplicate work

### Authentication Neutralization

This is the **most critical feature**:

```spamassassin
# When OpenEFA processed the email, zero out MailGuard's own auth checks
meta SPACY_ZERO_SPF_FAIL (SPF_FAIL && __SPACY_CHECKED_AUTH)
score SPACY_ZERO_SPF_FAIL -7.0

meta SPACY_ZERO_DMARC_FAIL (DMARC_FAIL && __SPACY_CHECKED_AUTH)
score SPACY_ZERO_DMARC_FAIL -3.0
```

**Why?**: By the time email reaches MailGuard, it's been relayed through OpenEFA, so MailGuard's authentication checks will see:
- **SPF**: Fails (sender is now OpenEFA, not original sender)
- **DKIM**: May fail (signatures can break during relay)
- **DMARC**: Fails (SPF/DKIM failures)

Without neutralization, legitimate emails get penalized for authentication failures caused by the relay itself!

---

## Troubleshooting

### Issue: Legitimate emails still being scored as spam

**Symptom**: Emails processed by OpenEFA still getting high spam scores on MailGuard

**Diagnosis**:
```bash
# Check if SpaCy rules are loaded
spamassassin -D --lint 2>&1 | grep -i "spacy_rules"

# Check email headers
# Look for both X-SpaCy-* AND X-Spam-Status
```

**Solution**:
1. Verify all 3 .cf files deployed
2. Ensure `zzz_spacy_trust.cf` is present (needed for neutralization)
3. Restart MailScanner: `systemctl restart mailscanner`

### Issue: SpamAssassin lint errors

**Symptom**: `spamassassin --lint` shows syntax errors

**Common causes**:
- File encoding (must be UTF-8)
- Line endings (use Unix LF, not Windows CRLF)
- Regex syntax errors
- Score values (must be numeric)

**Fix**:
```bash
# Convert line endings if needed
dos2unix /etc/mail/spamassassin/spacy_rules.cf

# Check specific file
spamassassin --lint -D -p /etc/mail/spamassassin/spacy_rules.cf 2>&1 | grep -i error
```

### Issue: Rules not applying

**Symptom**: SpaCy headers present but scores not changing

**Check**:
```bash
# Verify rule matching
echo "X-SpaCy-Processed: yes" | spamassassin -D 2>&1 | grep -i spacy

# Check if trusted_networks set correctly
grep "trusted_networks" /etc/mail/spamassassin/*.cf
```

**Solution**: Ensure `trusted_networks 192.168.50.89` (or your OpenEFA IP) is set in `zzz_spacy_trust.cf`

### Issue: MailScanner not restarting

**Symptom**: `systemctl restart mailscanner` fails

**Check logs**:
```bash
journalctl -u mailscanner -n 50
tail -f /var/log/maillog
```

**Common causes**:
- SpamAssassin configuration errors (run `spamassassin --lint`)
- File permissions (should be 644, owned by root)
- Conflicting rules from other .cf files

---

## Customization

### Adjusting Spam Threshold

Default threshold: 5.4

To make filtering more aggressive (catch more spam, more false positives):
```bash
# In /etc/mail/spamassassin/local.cf
required_score 4.5
```

To make filtering more lenient (fewer false positives, miss some spam):
```bash
required_score 6.5
```

### Domain-Specific Rules

Add custom rules for your organization:

```bash
# In /etc/mail/spamassassin/local.cf or custom file

# Trust internal corporate domains
header __CORPORATE_DOMAIN From =~ /\@(?:yourcompany\.com|subsidiary\.com)$/i
meta CORPORATE_EMAIL (__CORPORATE_DOMAIN && __SPACY_PROCESSED)
score CORPORATE_EMAIL -1.0
describe CORPORATE_EMAIL Trusted corporate domain processed by OpenEFA
```

### Whitelisting Specific Senders

**Option 1**: Use OpenEFA's whitelist (recommended)
- Login to SpacyWeb: https://your-openefa-server:5500
- Go to Whitelist management
- Add sender with trust score bonus

**Option 2**: Add SpamAssassin rule
```bash
# In /etc/mail/spamassassin/local.cf

header TRUSTED_VENDOR From =~ /\@trusted-vendor\.com$/i
score TRUSTED_VENDOR -3.0
describe TRUSTED_VENDOR Whitelisted vendor domain
```

---

## File Locations Reference

### OpenEFA Server (Source)
```
/opt/spacyserver/config/spamassassin_cf/spacy_rules.cf
/opt/spacyserver/config/spamassassin_cf/local.cf
/opt/spacyserver/config/spamassassin_cf/zzz_spacy_trust.cf
```

### MailGuard/EFA Server (Destination)
```
/etc/mail/spamassassin/spacy_rules.cf
/etc/mail/spamassassin/local.cf
/etc/mail/spamassassin/zzz_spacy_trust.cf
```

### Backup Copies (Generated)
```
/opt/spacyserver/mailguard_configs/generated/quarantine_feedback_*.cf
```

---

## Advanced: Dynamic Rules from Quarantine Feedback

OpenEFA can automatically generate SpamAssassin rules based on emails your users release from quarantine:

### How It Works
1. User releases email from MailGuard quarantine
2. MailGuard calls OpenEFA release tracking API (port 5001)
3. OpenEFA tracks sender in `trusted_senders` table
4. After 3 releases, sender auto-whitelisted
5. Daily cron job generates SpamAssassin rules from patterns
6. Rules deployed to MailGuard automatically

### Setup (Optional)

```bash
# On OpenEFA server
# Add to spacy-filter user's crontab
sudo -u spacy-filter crontab -e

# Add daily rule generation (3 AM)
0 3 * * * /opt/spacyserver/tools/auto_update_spamassassin.sh daily

# Add weekly comprehensive analysis (Sunday 2 AM)
0 2 * * 0 /opt/spacyserver/tools/auto_update_spamassassin.sh weekly
```

This creates rules like:
```spamassassin
# Auto-generated from 7-day quarantine feedback
header QUARANTINE_TRUSTED_SENDER_01 From =~ /trusted-user@example\.com/i
score QUARANTINE_TRUSTED_SENDER_01 -3.5
describe QUARANTINE_TRUSTED_SENDER_01 Quarantine-trusted sender (releases: 5, trust: 8)
```

---

## Integration with MailGuard APIs (Optional)

If you want MailGuard to communicate back to OpenEFA:

### 1. Release Tracking API (Port 5001)
**Purpose**: Track when users release emails from quarantine

**Setup on MailGuard**:
```bash
# Add to MailScanner release script
curl -X POST http://YOUR_OPENEFA_IP:5001/api/feedback/release \
  -H "Content-Type: application/json" \
  -d '{"sender": "user@example.com", "recipient": "you@yourdomain.com", "message_id": "..."}'
```

### 2. Whitelist API (Port 5002)
**Purpose**: "Always Allow" button integration

**Setup on MailGuard**:
```bash
# Add to MailGuard web interface
curl -X POST http://YOUR_OPENEFA_IP:5002/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{"sender": "user@example.com", "domain": "yourdomain.com"}'
```

### 3. Block Sender API (Port 5003)
**Purpose**: "Always Block" button integration

**Setup on MailGuard**:
```bash
# Add to MailGuard web interface
curl -X POST http://YOUR_OPENEFA_IP:5003/api/block \
  -H "Content-Type: application/json" \
  -d '{"sender": "spammer@bad.com", "domain": "yourdomain.com", "reason": "User reported spam"}'
```

**Note**: These API integrations are optional. OpenEFA works fine without them using just the SpamAssassin rules.

---

## Maintenance

### Regular Tasks

**Weekly**: Check rule deployment status
```bash
ssh root@YOUR_EFA_SERVER_IP "ls -l /etc/mail/spamassassin/spacy*.cf"
```

**Monthly**: Review scoring effectiveness
```bash
# On MailGuard
grep "X-Spam-Status" /var/log/maillog | awk '{print $NF}' | sort | uniq -c
```

**After OpenEFA Updates**: Redeploy rules if updated
```bash
sudo /opt/spacyserver/tools/deploy_spamassassin_rules.sh YOUR_EFA_SERVER_IP
```

### Log Monitoring

```bash
# On MailGuard - monitor spam scoring
tail -f /var/log/maillog | grep -E "SpaCy|X-Spam-Status"

# On OpenEFA - monitor email processing
tail -f /var/log/mail.log | grep -i spacy
tail -f /opt/spacyserver/logs/email_filter_debug.log
```

---

## Getting Help

**Documentation**: Full docs available at `/opt/spacyserver/docs/`

**Forum**: https://forum.openefa.com - Post questions and integration issues

**GitHub Issues**: https://github.com/openefaadmin/openefa-installer/issues

**Logs to Include When Asking for Help**:
1. MailGuard: `/var/log/maillog` (sanitized)
2. OpenEFA: `/var/log/mail.log` and `/opt/spacyserver/logs/email_filter_debug.log`
3. Full email headers showing both X-SpaCy-* and X-Spam-Status
4. Output of `spamassassin --lint` on MailGuard

---

## Summary

**Required**: Deploy 3 SpamAssassin configuration files to your MailGuard/EFA server:
1. `spacy_rules.cf` - Core integration and scoring
2. `local.cf` - General spam detection rules
3. `zzz_spacy_trust.cf` - Trust configuration (disables duplicate auth checks)

**Critical**: Without these files, your MailGuard will ignore OpenEFA's analysis and re-run authentication checks that will fail due to the relay hop.

**Verification**: After deployment, test emails should show X-SpaCy-* headers AND appropriate spam scores based on OpenEFA's analysis.

**Support**: These configurations are battle-tested on production systems processing thousands of emails daily. If you encounter issues, reach out on the forum with specific error messages and log excerpts.
