#!/bin/bash
#
# MailGuard Integration Script
# Called by MailGuard when emails are released from quarantine
# Notifies SpaCy to learn from user feedback
#

# SpaCy API endpoint - replace YOUR_OPENEFA_IP with your OpenEFA server IP
SPACY_API="${SPACY_API_URL:-http://YOUR_OPENEFA_IP:5001/api/feedback/release}"

# Function to notify SpaCy of release
notify_spacy_release() {
    local message_id="$1"
    local sender="$2"
    local recipient="$3"
    local subject="$4"
    local spam_score="$5"
    local release_user="$6"
    
    # Create JSON payload
    json_data=$(cat <<EOF
{
    "message_id": "$message_id",
    "sender": "$sender",
    "recipient": "$recipient",
    "subject": "$subject",
    "spam_score": $spam_score,
    "release_time": "$(date '+%Y-%m-%d %H:%M:%S')",
    "release_user": "$release_user"
}
EOF
)
    
    # Send to SpaCy API
    response=$(curl -s -X POST "$SPACY_API" \
        -H "Content-Type: application/json" \
        -d "$json_data" 2>/dev/null)
    
    # Log the result
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Released: $sender -> $recipient (ID: $message_id)" >> /var/log/spacy_integration.log
    echo "Response: $response" >> /var/log/spacy_integration.log
}

# Export function for use in PHP
export -f notify_spacy_release

# If called with arguments, process them
if [ $# -ge 3 ]; then
    notify_spacy_release "$@"
fi