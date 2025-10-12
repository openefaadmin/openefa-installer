#!/bin/bash
echo "🔍 Live Email Monitoring for SpaCy Fix Verification (FIXED)"
echo "Monitoring for: Liberty Mutual, Pure Insurance, Salesforce, Gmail emails"
echo "Started: $(date)"
echo ""

MONITOR_LOG="/var/log/spacyserver/live_email_monitor.log"
mkdir -p /var/log/spacyserver

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

log_event "🚀 Live email monitoring started (FIXED VERSION)"

journalctl -f -n 0 | while read line; do
    if echo "$line" | grep -E "(libertymutual\.com|pureinsurance\.com|salesforce\.com|gmail\.com)" > /dev/null; then
        if echo "$line" | grep "from=" > /dev/null; then
            SENDER=$(echo "$line" | grep -o 'from=<[^>]*>' | sed 's/from=<//;s/>//')
            # FIXED: Better Queue ID extraction
            QUEUE_ID=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://')
            
            if [[ "$SENDER" =~ (libertymutual\.com|pureinsurance\.com|salesforce\.com|gmail\.com) ]]; then
                echo ""
                log_event "📧 TARGET EMAIL DETECTED!"
                log_event "   Queue ID: $QUEUE_ID"
                log_event "   Sender: $SENDER"
                echo "   ✅ Tracking queue $QUEUE_ID for processing..."
            fi
        fi
        
        if echo "$line" | grep "spacyfilter" > /dev/null; then
            QUEUE_ID=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://')
            STATUS=$(echo "$line" | grep -o 'status=[A-Z]*' | sed 's/status=//')
            
            if [[ "$STATUS" == "SOFTBOUNCE" ]]; then
                log_event "❌ PROCESSING ERROR for $QUEUE_ID"
            else
                log_event "✅ PROCESSING SUCCESS for $QUEUE_ID"
            fi
        fi
    fi
    
    if echo "$line" | grep "non-production format message" > /dev/null; then
        log_event "🚨 REDIS ERROR DETECTED!"
    fi
    
    if echo "$line" | grep "EMERGENCY.*Redis disabled" > /dev/null; then
        log_event "🔧 Emergency fix active - Redis queue disabled"
    fi
done
