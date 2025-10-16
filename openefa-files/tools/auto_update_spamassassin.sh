#!/bin/bash
#
# Automatic SpamAssassin Rule Updater
# Updates MailGuard SpamAssassin rules based on quarantine feedback
# Run daily via cron
#

SCRIPT_DIR="/opt/spacyserver/tools"
LOG_FILE="/opt/spacyserver/logs/spamassassin_rule_updates.log"
PYTHON="/opt/spacyserver/venv/bin/python3"
RULE_GENERATOR="$SCRIPT_DIR/spamassassin_rule_generator.py"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to send notification (could integrate with monitoring system)
notify() {
    local status="$1"
    local message="$2"
    log "$status: $message"
    
    # Could add email notification, Slack webhook, etc.
    # echo "$message" | mail -s "SpamAssassin Rule Update $status" admin@domain.com
}

main() {
    log "Starting SpamAssassin rule update from quarantine feedback..."
    
    # Check if rule generator exists
    if [[ ! -f "$RULE_GENERATOR" ]]; then
        notify "ERROR" "Rule generator script not found: $RULE_GENERATOR"
        exit 1
    fi
    
    # Check if Python virtual environment exists
    if [[ ! -f "$PYTHON" ]]; then
        notify "ERROR" "Python virtual environment not found: $PYTHON"
        exit 1
    fi
    
    # Run rule generation and deployment
    if $PYTHON "$RULE_GENERATOR" --days 7 2>&1 | tee -a "$LOG_FILE"; then
        notify "SUCCESS" "SpamAssassin rules updated successfully from quarantine feedback"
        
        # Log statistics to show impact
        log "Checking MailGuard SpamAssassin configuration..."
        if ssh -o ConnectTimeout=10 spacy@YOUR_MAILGUARD_SERVER "sudo spamassassin --lint" >/dev/null 2>&1; then
            log "MailGuard SpamAssassin configuration verified successfully"
        else
            notify "WARNING" "MailGuard SpamAssassin configuration check failed"
        fi
        
    else
        notify "ERROR" "Failed to update SpamAssassin rules"
        exit 1
    fi
    
    # Clean up old rule backups (keep last 30 days)
    log "Cleaning up old rule backups..."
    find /opt/spacyserver/mailguard_configs/generated -name "quarantine_feedback_rules_*.cf" -type f -mtime +30 -delete 2>/dev/null
    
    log "SpamAssassin rule update completed"
}

# Weekly full analysis (more comprehensive)
weekly_analysis() {
    log "Starting weekly comprehensive rule analysis..."
    
    if $PYTHON "$RULE_GENERATOR" --days 30 2>&1 | tee -a "$LOG_FILE"; then
        notify "SUCCESS" "Weekly comprehensive SpamAssassin rules updated"
    else
        notify "ERROR" "Weekly comprehensive rule update failed"
    fi
}

# Handle script arguments
case "${1:-daily}" in
    daily)
        main
        ;;
    weekly)
        weekly_analysis
        ;;
    test)
        log "Running test analysis (no deployment)..."
        $PYTHON "$RULE_GENERATOR" --test --days 7 2>&1 | tee -a "$LOG_FILE"
        ;;
    *)
        echo "Usage: $0 {daily|weekly|test}"
        echo "  daily  - Update rules based on last 7 days (default)"
        echo "  weekly - Update rules based on last 30 days" 
        echo "  test   - Analyze patterns without deploying"
        exit 1
        ;;
esac