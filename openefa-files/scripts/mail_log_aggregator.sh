#!/bin/bash
# Mail Log Aggregator for SpaCy Server
# Combines system mail logs with SpaCy processing logs

LOG_DIR="/opt/spacyserver/logs"
SPACY_MAIL_LOG="$LOG_DIR/spacymail.log"
COMBINED_LOG="$LOG_DIR/combined_mail.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to format and append logs
aggregate_logs() {
    # Follow mail.log and format for SpaCy
    tail -F /var/log/mail.log 2>/dev/null | while read line; do
        # Extract relevant SpaCy filter messages
        if echo "$line" | grep -q "spacyfilter"; then
            echo "[POSTFIX] $line" >> "$SPACY_MAIL_LOG"
        fi
        
        # Log all mail activity to combined log
        echo "[SYSTEM] $line" >> "$COMBINED_LOG"
    done &
    
    # Also monitor SpaCy's own logs
    tail -F "$LOG_DIR/email_filter_log.txt" 2>/dev/null | while read line; do
        echo "[SPACY] $line" >> "$SPACY_MAIL_LOG"
        echo "[SPACY] $line" >> "$COMBINED_LOG"
    done &
}

# Start aggregation
echo "Starting mail log aggregation at $(date)" >> "$SPACY_MAIL_LOG"
aggregate_logs

# Keep script running
wait