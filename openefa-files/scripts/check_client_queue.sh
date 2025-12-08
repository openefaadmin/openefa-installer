#!/bin/bash
# Check mail queue for legitimate client emails only
# Filters out spam backscatter

echo "=============================================="
echo "Client Email Queue Check"
echo "=============================================="
echo ""

# Get client domains
CLIENT_DOMAINS=$(mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -N -e "SELECT domain FROM client_domains WHERE active = 1;")

# Get full queue
QUEUE_OUTPUT=$(mailq 2>&1)

# Check if empty
if echo "$QUEUE_OUTPUT" | grep -q "queue is empty"; then
    echo "✅ Mail queue is empty"
    exit 0
fi

# Parse queue for client emails
echo "Checking for emails to/from client domains..."
echo ""

LEGITIMATE_FOUND=0
BACKSCATTER_COUNT=0
TOTAL_COUNT=$(echo "$QUEUE_OUTPUT" | grep -oP '^\d+(?= Request)' | tail -1)

while IFS= read -r line; do
    # Look for lines with email addresses
    if [[ "$line" =~ @ ]] && [[ ! "$line" =~ ^- ]]; then
        IS_CLIENT_MAIL=false
        
        # Check if it's for any client domain
        for domain in $CLIENT_DOMAINS; do
            if echo "$line" | grep -qi "@$domain"; then
                IS_CLIENT_MAIL=true
                break
            fi
        done
        
        if [[ "$IS_CLIENT_MAIL" == "true" ]]; then
            # This is a client email - print previous line (queue ID) and this line
            if [[ ! "$line" =~ MAILER-DAEMON ]]; then
                echo "📧 CLIENT EMAIL FOUND:"
                echo "$PREV_LINE"
                echo "$line"
                echo ""
                ((LEGITIMATE_FOUND++))
            else
                # Bounce to client domain - still important
                echo "🔄 BOUNCE TO CLIENT:"
                echo "$PREV_LINE"
                echo "$line"
                echo ""
                ((LEGITIMATE_FOUND++))
            fi
        elif echo "$line" | grep -q "MAILER-DAEMON"; then
            ((BACKSCATTER_COUNT++))
        fi
    fi
    PREV_LINE="$line"
done <<< "$QUEUE_OUTPUT"

echo "=============================================="
echo "📊 Summary:"
echo "   Total messages in queue: ${TOTAL_COUNT:-0}"
echo "   Client-related emails: $LEGITIMATE_FOUND"
echo "   Spam backscatter: $BACKSCATTER_COUNT"
echo "=============================================="

if [ "$LEGITIMATE_FOUND" -gt 0 ]; then
    echo ""
    echo "⚠️  WARNING: $LEGITIMATE_FOUND client email(s) stuck in queue!"
    exit 1
else
    echo ""
    echo "✅ No client emails stuck in queue"
    exit 0
fi
