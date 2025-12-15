#!/bin/bash
# Fix file permissions after root edits (e.g., Claude Code sessions)
# Usage: sudo /opt/spacyserver/scripts/fix_permissions.sh
# Safe to run via cron - idempotent and doesn't restart services

set -e

echo "Fixing OpenEFA file permissions..."

# /etc/spacy-server - env files readable by spacy-filter
chown root:spacy-filter /etc/spacy-server/.env 2>/dev/null || true
chmod 640 /etc/spacy-server/.env 2>/dev/null || true
chown root:spacy-filter /etc/spacy-server/.my.cnf 2>/dev/null || true
chmod 640 /etc/spacy-server/.my.cnf 2>/dev/null || true

# Config files - readable by spacy-filter
chown -R spacy-filter:spacy-filter /opt/spacyserver/config/
chmod 640 /opt/spacyserver/config/*.json 2>/dev/null || true
chmod 640 /opt/spacyserver/config/*.ini 2>/dev/null || true
chmod 640 /opt/spacyserver/config/.env 2>/dev/null || true

# Main application directories
chown -R spacy-filter:spacy-filter /opt/spacyserver/modules/
chown -R spacy-filter:spacy-filter /opt/spacyserver/web/
chown -R spacy-filter:spacy-filter /opt/spacyserver/services/
chown -R spacy-filter:spacy-filter /opt/spacyserver/scripts/

# Email filter (needs to be executable by postfix)
chown spacy-filter:spacy-filter /opt/spacyserver/email_filter.py
chmod 755 /opt/spacyserver/email_filter.py

# Postfix config files must be root owned
chown root:root /etc/postfix/transport /etc/postfix/transport.db 2>/dev/null || true
chmod 644 /etc/postfix/transport /etc/postfix/transport.db 2>/dev/null || true
chown root:root /etc/postfix/main.cf /etc/postfix/master.cf 2>/dev/null || true

# Log files
chown spacy-filter:spacy-filter /var/log/spacy_filter.log 2>/dev/null || true
chown spacy-filter:spacy-filter /var/log/spacyweb.log 2>/dev/null || true

# Virtual environment
chown -R spacy-filter:spacy-filter /opt/spacyserver/venv/

# Data directories
chown -R spacy-filter:spacy-filter /opt/spacyserver/data/ 2>/dev/null || true
chown -R spacy-filter:spacy-filter /opt/spacyserver/templates/ 2>/dev/null || true

echo "✅ Permissions fixed"
