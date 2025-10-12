#!/bin/bash
# Setup script for mail log integration with SpaCy

echo "Setting up mail log integration..."

# 1. Create symbolic link for easy access
ln -sf /var/log/mail.log /opt/spacyserver/logs/system_mail.log 2>/dev/null

# 2. Create rsyslog configuration to duplicate mail logs to SpaCy
cat > /tmp/30-spacy-mail.conf << 'EOF'
# SpaCy Mail Log Integration
# Duplicate mail facility logs to SpaCy directory

# Create a new ruleset for SpaCy
$RuleSet spacy_mail

# Log mail facility to SpaCy log file
mail.*  /opt/spacyserver/logs/spacymail_rsyslog.log

# Also log SpaCy filter messages specifically
:msg, contains, "spacyfilter" /opt/spacyserver/logs/spacyfilter_activity.log

# Switch back to default ruleset
$RuleSet RSYSLOG_DefaultRuleset

# Apply SpaCy ruleset to mail facility
mail.* :omruleset:spacy_mail
EOF

# 3. Create logrotate configuration
cat > /tmp/spacy-logs << 'EOF'
/opt/spacyserver/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    sharedscripts
    postrotate
        # Reload rsyslog after rotation
        systemctl reload rsyslog 2>/dev/null || true
    endscript
}
EOF

echo "Configuration files created."
echo ""
echo "To complete setup, run these commands as root:"
echo "  sudo cp /tmp/30-spacy-mail.conf /etc/rsyslog.d/"
echo "  sudo cp /tmp/spacy-logs /etc/logrotate.d/"
echo "  sudo systemctl restart rsyslog"
echo ""
echo "Then you can:"
echo "  - View combined logs at: /opt/spacyserver/logs/spacymail_rsyslog.log"
echo "  - Analyze logs with: /opt/spacyserver/scripts/analyze_mail_logs.py"
echo "  - View SpaCy filter activity: /opt/spacyserver/logs/spacyfilter_activity.log"