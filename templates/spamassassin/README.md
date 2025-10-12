# SpamAssassin Configuration Files for MailGuard/EFA Integration

## Overview

These SpamAssassin configuration files enable your downstream MailGuard or EFA server to read and trust OpenEFA's email analysis.

**⚠️ CRITICAL**: Without deploying these files to your MailGuard/EFA server, it will **ignore** OpenEFA's authentication and spam scoring, defeating the purpose of having OpenEFA in your mail flow.

## Files in This Directory

### 1. `spacy_rules.cf` (~16KB)
**Core OpenEFA integration rules**

- Detects emails processed by OpenEFA
- Neutralizes duplicate authentication checks (SPF/DKIM/DMARC)
- Applies OpenEFA's authentication scoring
- Handles known scammers and financial fraud patterns
- Vendor whitelisting

**Deploy to**: `/etc/mail/spamassassin/spacy_rules.cf`

### 2. `local.cf` (~7KB)
**General SpamAssassin configuration**

- Sets spam threshold (5.4)
- Bayes learning configuration
- Marketing/phishing detection
- Unicode obfuscation patterns
- Cryptocurrency scams

**Deploy to**: `/etc/mail/spamassassin/local.cf`

### 3. `zzz_spacy_trust.cf` (~4KB)
**Complete trust configuration**

- Disables ALL local authentication checks
- Trusts OpenEFA's scoring completely
- Marks OpenEFA server as trusted network
- Overrides conflicting rules from other files

**Deploy to**: `/etc/mail/spamassassin/zzz_spacy_trust.cf`

**Note**: The `zzz_` prefix ensures this file loads last (alphabetically) so it can override earlier rules.

## Quick Deployment

### Method 1: Manual SCP

```bash
# From your OpenEFA server
cd /opt/spacyserver/installer/templates/spamassassin

scp spacy_rules.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp local.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/
scp zzz_spacy_trust.cf root@YOUR_EFA_SERVER_IP:/etc/mail/spamassassin/

# SSH into MailGuard and restart
ssh root@YOUR_EFA_SERVER_IP
spamassassin --lint
systemctl restart mailscanner
```

### Method 2: Automated Tool

```bash
sudo /opt/spacyserver/tools/deploy_spamassassin_rules.sh YOUR_EFA_SERVER_IP
```

## Verification

```bash
# On MailGuard/EFA server
spamassassin --lint                    # Should return no errors
spamassassin -D --lint 2>&1 | grep -i spacy   # Should show rules loading

# Check files deployed
ls -l /etc/mail/spamassassin/spacy*.cf
```

## Full Documentation

For complete integration guide, troubleshooting, and customization:

**See**: `/opt/spacyserver/docs/EFA_SPAMASSASSIN_INTEGRATION.md`

Or after installation: `cat /opt/spacyserver/docs/EFA_SPAMASSASSIN_INTEGRATION.md`

## Why This Is Necessary

**Email Flow**: Internet → OpenEFA → MailGuard → Mailbox

When email reaches MailGuard after being relayed through OpenEFA:
- **SPF will fail** (sender IP is now OpenEFA, not original sender)
- **DKIM may fail** (signatures can break during relay)
- **DMARC will fail** (depends on SPF/DKIM)

Without these rules, MailGuard will **penalize legitimate emails** for authentication failures caused by the relay itself!

These SpamAssassin rules:
1. **Neutralize MailGuard's authentication checks** (set scores to 0)
2. **Apply OpenEFA's authentication analysis** (from X-SpaCy-Auth-* headers)
3. **Trust OpenEFA's spam scoring** (from X-SpaCy-Spam-Score header)

Result: **Accurate filtering** based on OpenEFA's AI analysis instead of broken relay-induced auth failures.

## Support

- **Forum**: https://forum.openefa.com
- **GitHub**: https://github.com/openefaadmin/openefa-installer/issues
- **Docs**: https://openefa.com

---

**TL;DR**: Copy these 3 files to `/etc/mail/spamassassin/` on your MailGuard/EFA server and restart MailScanner. See full docs for detailed explanation.
