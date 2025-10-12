#!/bin/bash
##############################################################################
# Live Email Monitoring Script for SpaCy Fix Verification
# Purpose: Monitor for Liberty Mutual, Pure Insurance, and Salesforce emails
##############################################################################

echo "🔍 Live Email Monitoring for SpaCy Fix Verification"
echo "Monitoring for: Liberty Mutual, Pure Insurance, Salesforce emails"
echo "Started: $(date)"
echo "Press Ctrl+C to stop"
echo ""

# Create log file for monitoring results
MONITOR_LOG="/var/log/spacyserver/live_email_monitor.log"
mkdir -p /var/log/spacyserver

# Function to log with timestamp
log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$MONITOR_LOG"
}

log_event "🚀 Live email monitoring started"

# Monitor in real-time with multiple patterns
journalctl -f -n 0 | while read line; do
    
    # Check for emails from our target domains
    if echo "$line" | grep -E "(gmail\.com|libertymutual\.com|pureinsurance\.com|salesforce\.com)" > /dev/null; then
        
        # Extract relevant info
        if echo "$line" | grep "from=" > /dev/null; then
            SENDER=$(echo "$line" | grep -o 'from=<[^>]*>' | sed 's/from=<//;s/>//')
            QUEUE_ID=$(echo "$line" | grep -o '^[A-Z0-9]*:' | sed 's/://')
            
            if [[ "$SENDER" =~ (gmail\.com|libertymutual\.com|pureinsurance\.com|salesforce\.com) ]]; then
                echo ""
                log_event "📧 TARGET EMAIL DETECTED!"
                log_event "   Queue ID: $QUEUE_ID"
                log_event "   Sender: $SENDER"
                
                # Start tracking this specific email
                echo "   Tracking queue $QUEUE_ID for processing..."
            fi
        fi
        
        # Check for spacyfilter processing
        if echo "$line" | grep "spacyfilter" > /dev/null; then
            QUEUE_ID=$(echo "$line" | grep -o '^[A-Z0-9]*:' | sed 's/://')
            STATUS=$(echo "$line" | grep -o 'status=[A-Z]*' | sed 's/status=//')
            
            if [[ "$STATUS" == "SOFTBOUNCE" ]]; then
                log_event "❌ PROCESSING ERROR for $QUEUE_ID"
                log_event "   Status: $STATUS"
                log_event "   Line: $line"
            else
                log_event "✅ PROCESSING SUCCESS for $QUEUE_ID"
                log_event "   Status: $STATUS"
            fi
        fi
    fi
    
    # Check for Redis errors (should be ZERO now)
    if echo "$line" | grep "non-production format message" > /dev/null; then
        echo ""
        log_event "🚨 REDIS ERROR DETECTED (This should not happen after fix!)"
        log_event "   Error: $line"
        echo ""
    fi
    
    # Check for successful relays to mailguard
    if echo "$line" | grep -E "(relay=.*192\.168\.50\.37|relayed.*mailguard)" > /dev/null; then
        QUEUE_ID=$(echo "$line" | grep -o '^[A-Z0-9]*:' | sed 's/://')
        log_event "🎯 SUCCESSFUL RELAY to mailguard for $QUEUE_ID"
    fi
    
    # Check for emergency Redis disabled messages
    if echo "$line" | grep "EMERGENCY.*Redis disabled" > /dev/null; then
        log_event "🔧 Emergency fix active - Redis queue disabled"
    fi

done &

# Also run a summary check every 5 minutes
while true; do
    sleep 300  # 5 minutes
    
    echo ""
    log_event "📊 5-MINUTE SUMMARY:"
    
    # Count Redis errors in last 5 minutes (should be 0)
    REDIS_ERRORS=$(journalctl --since "5 minutes ago" | grep "non-production format message" | wc -l)
    log_event "   Redis errors in last 5 minutes: $REDIS_ERRORS"
    
    # Count emails from target domains
    TARGET_EMAILS=$(journalctl --since "5 minutes ago" | grep -E "(gmail\.com|libertymutual\.com|pureinsurance\.com|salesforce\.com)" | wc -l)
    log_event "   Target domain emails in last 5 minutes: $TARGET_EMAILS"
    
    # Count successful relays
    SUCCESSFUL_RELAYS=$(journalctl --since "5 minutes ago" | grep -E "relay=.*192\.168\.50\.37" | wc -l)
    log_event "   Successful relays in last 5 minutes: $SUCCESSFUL_RELAYS"
    
    if [ "$REDIS_ERRORS" -eq 0 ]; then
        log_event "   ✅ No Redis errors - fix is working!"
    else
        log_event "   ❌ Redis errors detected - investigation needed"
    fi
    
    echo ""
done &

# Trap Ctrl+C to clean up
trap 'echo ""; log_event "🛑 Monitoring stopped by user"; kill $(jobs -p); exit 0' INT

# Keep script running
wait

##############################################################################
# Usage Examples and What to Look For
##############################################################################

cat << 'EOF'

=== WHAT TO LOOK FOR TOMORROW ===

✅ GOOD SIGNS (Fix is working):
   📧 TARGET EMAIL DETECTED! (from Liberty Mutual, Pure Insurance, etc.)
   ✅ PROCESSING SUCCESS for [QUEUE_ID]
   🎯 SUCCESSFUL RELAY to mailguard for [QUEUE_ID]
   🔧 Emergency fix active - Redis queue disabled
   📊 Redis errors in last 5 minutes: 0

❌ BAD SIGNS (Would need investigation):
   🚨 REDIS ERROR DETECTED (should not happen)
   ❌ PROCESSING ERROR for [QUEUE_ID]
   📊 Redis errors in last 5 minutes: >0

=== MANUAL CHECKS ===

# Check specific queue ID processing:
journalctl | grep "QUEUE_ID" | tail -10

# Check overall email flow:
tail -f /var/log/mail.log | grep -E "(gmail|libertymutual|pureinsurance|salesforce)"

# Verify Redis error count:
journalctl --since "1 hour ago" | grep "non-production format message" | wc -l

=== LOG LOCATIONS ===

Live monitoring log: /var/log/spacyserver/live_email_monitor.log
Postfix logs: /var/log/mail.log
SpaCy logs: /var/log/spacyserver/

EOF
