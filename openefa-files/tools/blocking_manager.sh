#!/bin/bash
#
# Email Blocking Manager for SpaCy
# Provides easy management of domain and country blocking rules
#

SCRIPT_DIR="/opt/spacyserver"
PYTHON="/opt/spacyserver/venv/bin/python3"
BLOCKING_MODULE="$SCRIPT_DIR/modules/email_blocking.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display the menu
show_menu() {
    clear
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}    SpaCy Email Blocking Manager${NC}"
    echo -e "${BLUE}======================================${NC}"
    echo ""
    echo "1. Add Client Domain"
    echo "2. Add Blocking Rule"
    echo "3. Add Whitelist Exception"
    echo "4. Test Email Blocking"
    echo "5. View Blocking Statistics"
    echo "6. Block Entire Country"
    echo "7. Block Domain Pattern"
    echo "8. List Client Domains"
    echo "9. List Rules for Domain"
    echo "10. Remove Blocking Rule"
    echo "0. Exit"
    echo ""
    echo -n "Select option: "
}

# Function to add a client domain
add_client_domain() {
    echo -e "\n${YELLOW}Add Client Domain${NC}"
    echo -n "Enter domain (e.g., example.com): "
    read domain
    echo -n "Enter client name (optional): "
    read client_name
    
    if [ -z "$client_name" ]; then
        $PYTHON $BLOCKING_MODULE add-client "$domain"
    else
        $PYTHON $BLOCKING_MODULE add-client "$domain" --name "$client_name"
    fi
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to add a blocking rule
add_blocking_rule() {
    echo -e "\n${YELLOW}Add Blocking Rule${NC}"
    echo -n "Enter client domain: "
    read domain
    
    echo "Rule types:"
    echo "  1. Domain (e.g., .cn, *.cn, example.com)"
    echo "  2. Country (e.g., CN for China, RU for Russia)"
    echo "  3. IP Address (e.g., 192.168.1.1)"
    echo "  4. CIDR Range (e.g., 192.168.0.0/16)"
    echo -n "Select rule type (1-4): "
    read rule_type_num
    
    case $rule_type_num in
        1) rule_type="domain" ;;
        2) rule_type="country" ;;
        3) rule_type="ip" ;;
        4) rule_type="cidr" ;;
        *) echo "Invalid selection"; return ;;
    esac
    
    echo -n "Enter value to block: "
    read value
    
    pattern="exact"
    if [ "$rule_type" = "domain" ]; then
        echo "Pattern types:"
        echo "  1. Exact match"
        echo "  2. Wildcard (e.g., *.cn)"
        echo "  3. Regular expression"
        echo -n "Select pattern type (1-3): "
        read pattern_num
        
        case $pattern_num in
            1) pattern="exact" ;;
            2) pattern="wildcard" ;;
            3) pattern="regex" ;;
        esac
    fi
    
    echo -n "Enter description (optional): "
    read description

    echo -n "Specific recipient (optional, e.g., user@yourdomain.com): "
    read recipient_pattern

    echo -n "Priority (1-1000, lower = higher priority, default 100): "
    read priority
    [ -z "$priority" ] && priority=100

    cmd="$PYTHON $BLOCKING_MODULE add-rule \"$domain\" \"$rule_type\" \"$value\" --pattern \"$pattern\" --priority $priority"
    [ -n "$description" ] && cmd="$cmd --description \"$description\""
    [ -n "$recipient_pattern" ] && cmd="$cmd --recipient \"$recipient_pattern\""
    
    eval $cmd
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to add a whitelist exception
add_whitelist() {
    echo -e "\n${YELLOW}Add Whitelist Exception${NC}"
    echo -n "Enter client domain: "
    read domain
    
    echo "What to whitelist:"
    echo "  1. Domain"
    echo "  2. Country"
    echo "  3. IP Address"
    echo "  4. CIDR Range"
    echo -n "Select type (1-4): "
    read rule_type_num
    
    case $rule_type_num in
        1) rule_type="domain" ;;
        2) rule_type="country" ;;
        3) rule_type="ip" ;;
        4) rule_type="cidr" ;;
        *) echo "Invalid selection"; return ;;
    esac
    
    echo -n "Enter value to whitelist: "
    read value
    
    echo -n "Enter description (optional): "
    read description
    
    cmd="$PYTHON $BLOCKING_MODULE add-rule \"$domain\" \"$rule_type\" \"$value\" --whitelist --priority 1"
    [ -n "$description" ] && cmd="$cmd --description \"$description\""
    
    eval $cmd
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to test email blocking
test_blocking() {
    echo -e "\n${YELLOW}Test Email Blocking${NC}"
    echo -n "Enter recipient email: "
    read recipient
    echo -n "Enter sender email: "
    read sender
    echo -n "Enter sender IP (optional): "
    read ip
    
    if [ -z "$ip" ]; then
        $PYTHON $BLOCKING_MODULE test "$recipient" "$sender"
    else
        $PYTHON $BLOCKING_MODULE test "$recipient" "$sender" --ip "$ip"
    fi
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to view statistics
view_stats() {
    echo -e "\n${YELLOW}View Blocking Statistics${NC}"
    echo -n "Enter client domain: "
    read domain
    echo -n "Number of days to look back (default 7): "
    read days
    [ -z "$days" ] && days=7
    
    $PYTHON $BLOCKING_MODULE stats "$domain" --days $days
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to block entire country
block_country() {
    echo -e "\n${YELLOW}Block Entire Country${NC}"
    echo -n "Enter client domain: "
    read domain
    
    echo "Common country codes:"
    echo "  CN - China"
    echo "  RU - Russia"
    echo "  KP - North Korea"
    echo "  IR - Iran"
    echo "  NG - Nigeria"
    echo "  VN - Vietnam"
    echo "  IN - India"
    echo "  BR - Brazil"
    echo ""
    echo -n "Enter country code (2 letters): "
    read country
    
    country=$(echo "$country" | tr '[:lower:]' '[:upper:]')
    
    $PYTHON $BLOCKING_MODULE add-rule "$domain" "country" "$country" \
        --description "Block all emails from $country"
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to block domain pattern
block_domain_pattern() {
    echo -e "\n${YELLOW}Block Domain Pattern${NC}"
    echo -n "Enter client domain: "
    read domain
    
    echo "Examples:"
    echo "  *.cn     - Block all .cn domains"
    echo "  *.ru     - Block all .ru domains"
    echo "  *spam*   - Block domains containing 'spam'"
    echo ""
    echo -n "Enter pattern to block: "
    read pattern
    
    $PYTHON $BLOCKING_MODULE add-rule "$domain" "domain" "$pattern" \
        --pattern "wildcard" --description "Block domain pattern: $pattern"
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to list client domains
list_clients() {
    echo -e "\n${YELLOW}Client Domains${NC}"
    echo "Querying database..."
    
    mysql -e "
        SELECT domain, client_name, created_at, active 
        FROM spacy_email_db.client_domains 
        ORDER BY domain;
    " 2>/dev/null | column -t
    
    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to list rules for a domain
list_rules() {
    echo -e "\n${YELLOW}List Rules for Domain${NC}"
    echo -n "Enter client domain: "
    read domain

    echo -e "\n📋 Rules for $domain:"
    $PYTHON $BLOCKING_MODULE list-rules "$domain"

    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Function to remove a blocking rule
remove_rule() {
    echo -e "\n${YELLOW}Remove Blocking Rule${NC}"
    echo -n "Enter client domain to see rules: "
    read domain

    echo -e "\n📋 Current rules for $domain:"
    $PYTHON $BLOCKING_MODULE list-rules "$domain"

    echo ""
    echo -n "Enter Rule ID to remove (or 0 to cancel): "
    read rule_id

    if [ "$rule_id" = "0" ] || [ -z "$rule_id" ]; then
        echo "Cancelled"
    else
        echo -n "Are you sure you want to remove rule ID $rule_id? (y/N): "
        read confirm

        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            $PYTHON $BLOCKING_MODULE remove-rule "$rule_id"
        else
            echo "Cancelled"
        fi
    fi

    echo -e "\n${GREEN}Press Enter to continue...${NC}"
    read
}

# Quick setup for common scenarios
quick_setup_china_block() {
    echo -e "\n${YELLOW}Quick Setup: Block China (.cn domains and CN country)${NC}"
    echo -n "Enter client domain: "
    read domain
    
    echo "Adding rules to block China..."
    
    # Add client domain if not exists
    $PYTHON $BLOCKING_MODULE add-client "$domain"
    
    # Block .cn domains
    $PYTHON $BLOCKING_MODULE add-rule "$domain" "domain" "*.cn" \
        --pattern "wildcard" --description "Block all .cn domains"
    
    # Block China country
    $PYTHON $BLOCKING_MODULE add-rule "$domain" "country" "CN" \
        --description "Block all emails from China"
    
    echo -e "\n${GREEN}China blocking rules added successfully!${NC}"
    echo -e "${GREEN}Press Enter to continue...${NC}"
    read
}

# Main loop
while true; do
    show_menu
    read -r choice
    
    case $choice in
        1) add_client_domain ;;
        2) add_blocking_rule ;;
        3) add_whitelist ;;
        4) test_blocking ;;
        5) view_stats ;;
        6) block_country ;;
        7) block_domain_pattern ;;
        8) list_clients ;;
        9) list_rules ;;
        10) remove_rule ;;
        0) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done