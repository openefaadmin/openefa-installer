#!/bin/bash
#
# Unblock Sender Tool
# Usage: ./unblock_sender.sh <email_or_domain> [--hard]
#

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

SEARCH_TERM="$1"
HARD_DELETE="$2"

if [ -z "$SEARCH_TERM" ]; then
    echo "Usage: $0 <email_or_domain> [--hard]"
    echo ""
    echo "Examples:"
    echo "  $0 spammer@evil.com          # Soft delete (disable)"
    echo "  $0 '*@evil.com'               # Unblock entire domain"
    echo "  $0 spammer@evil.com --hard   # Permanently delete"
    echo ""
    echo "Search for existing blocks:"
    sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -e "
        SELECT br.id, cd.domain AS for_domain, br.rule_value, br.rule_pattern, br.active, br.created_at, br.created_by
        FROM blocking_rules br
        JOIN client_domains cd ON br.client_domain_id = cd.id
        WHERE br.active = 1
        ORDER BY br.created_at DESC
        LIMIT 20;
    "
    exit 0
fi

# Search for matching rules
echo "Searching for blocking rules matching: $SEARCH_TERM"
echo ""

MATCHING_RULES=$(sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -N -e "
    SELECT br.id, cd.domain, br.rule_value, br.rule_pattern
    FROM blocking_rules br
    JOIN client_domains cd ON br.client_domain_id = cd.id
    WHERE br.rule_value LIKE '%${SEARCH_TERM}%' AND br.active = 1;
")

if [ -z "$MATCHING_RULES" ]; then
    echo "No active blocking rules found for: $SEARCH_TERM"
    exit 0
fi

echo "Found matching rules:"
echo "$MATCHING_RULES" | while IFS=$'\t' read -r id domain rule_value rule_pattern; do
    echo "  [ID: $id] $rule_value ($rule_pattern) for $domain"
done
echo ""

# Confirm
read -p "Unblock these rules? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Get rule IDs
RULE_IDS=$(echo "$MATCHING_RULES" | cut -f1)

if [ "$HARD_DELETE" == "--hard" ]; then
    # Hard delete
    echo "Permanently deleting rules..."
    for id in $RULE_IDS; do
        sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -e "
            DELETE FROM blocking_rules WHERE id = $id;
        "
        echo "  ✓ Deleted rule ID: $id"
    done
else
    # Soft delete (set active=0)
    echo "Disabling rules (soft delete)..."
    for id in $RULE_IDS; do
        sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -e "
            UPDATE blocking_rules SET active = 0 WHERE id = $id;
        "
        echo "  ✓ Disabled rule ID: $id"
    done
fi

echo ""
echo "✅ Unblock complete!"
echo ""
echo "Note: Cache is automatically refreshed within 5 minutes, or restart email_filter to clear immediately."