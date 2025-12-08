#!/bin/bash
#
# Send Daily Security Report
# Automatically sends email security report to specified address
#
# Usage:
#   ./send_daily_security_report.sh [email@example.com]
#
# If no email specified, uses default from config

# Default email address (change this to your admin email)
DEFAULT_EMAIL="admin@example.com"

# Get email from argument or use default
EMAIL_TO="${1:-$DEFAULT_EMAIL}"

# Set PATH to ensure python3 is found
export PATH=/usr/local/bin:/usr/bin:/bin:$PATH

# Change to script directory
cd /opt/spacyserver/scripts

# Activate virtual environment if it exists
if [ -f /opt/spacyserver/venv/bin/activate ]; then
    source /opt/spacyserver/venv/bin/activate
fi

# Run the report generator
/usr/bin/python3 /opt/spacyserver/scripts/security_daily_report.py --email "$EMAIL_TO"

# Log execution
echo "$(date '+%Y-%m-%d %H:%M:%S') - Daily security report sent to $EMAIL_TO" >> /var/log/spacyserver_reports.log
