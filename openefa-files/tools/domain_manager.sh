#!/bin/bash
# Domain Management Script for SpaCy Server
# Manages domains in Postfix virtual and DNS whitelist

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Config paths
POSTFIX_VIRTUAL="/etc/postfix/virtual"
POSTFIX_TRANSPORT="/etc/postfix/transport"
DNS_WHITELIST="/opt/spacyserver/config/dns_whitelist.json"
EMAIL_FILTER="/opt/spacyserver/email_filter.py"
BACKUP_DIR="/opt/spacyserver/backups"
CONFIG_FILE="/opt/spacyserver/config/email_filter_config.json"

# Get relay host from config or use default
MAILGUARD_IP=$(jq -r '.relay_host // "localhost"' "$CONFIG_FILE" 2>/dev/null || echo "localhost")

# Create backup
backup_configs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    cp "$POSTFIX_VIRTUAL" "$BACKUP_DIR/postfix_virtual_$timestamp.backup"
    cp "$POSTFIX_TRANSPORT" "$BACKUP_DIR/postfix_transport_$timestamp.backup"
    cp "$DNS_WHITELIST" "$BACKUP_DIR/dns_whitelist_$timestamp.backup"
    cp "$EMAIL_FILTER" "$BACKUP_DIR/email_filter_$timestamp.backup"
    echo -e "${GREEN}✓ Configs backed up to $BACKUP_DIR${NC}"
}

# List current domains
list_domains() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    Current Managed Domains                    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}Postfix Relay Domains:${NC}"
    postconf -h relay_domains | tr ' ' '\n' | sort | while read domain; do
        if [[ -n "$domain" ]]; then
            echo -e "  ${GREEN}✓${NC} $domain"
        fi
    done
    echo ""
    echo -e "${WHITE}Postfix Transport Map:${NC}"
    grep -v "^#" "$POSTFIX_TRANSPORT" | grep -v "^journal@" | grep -v '^\*' | grep "smtp:" | awk '{print $1}' | sort | while read domain; do
        if [[ -n "$domain" ]]; then
            echo -e "  ${GREEN}✓${NC} $domain → mailguard"
        fi
    done
    echo ""
    echo -e "${WHITE}Postfix Virtual Domains:${NC}"
    grep "^@" "$POSTFIX_VIRTUAL" | grep -v "journal@" | awk '{print $1}' | sed 's/@//' | sort | while read domain; do
        echo -e "  ${GREEN}✓${NC} $domain"
    done
    echo ""
    echo -e "${WHITE}DNS Whitelist Domains:${NC}"
    python3 -c "
import json
with open('$DNS_WHITELIST', 'r') as f:
    config = json.load(f)
    domains = sorted(config.get('dns_whitelist', []))
    for domain in domains:
        print(f'  ✓ {domain}')
" 2>/dev/null || echo "Error reading DNS whitelist"
}

# Add a new domain
add_domain() {
    local domain="$1"
    
    # Validate domain format (allow multi-level domains like subdomain.domain.tld)
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}✗ Invalid domain format: $domain${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Adding domain: $domain${NC}"
    
    # Backup first
    backup_configs
    
    # Check if domain already exists in Postfix virtual
    if grep -q "^@$domain" "$POSTFIX_VIRTUAL"; then
        echo -e "${YELLOW}⚠ Domain $domain already exists in Postfix virtual${NC}"
    else
        # Add to Postfix virtual (before the journal line)
        sed -i "/^journal@spacy.covereddata.com/i @$domain @$domain" "$POSTFIX_VIRTUAL"
        echo -e "${GREEN}✓ Added $domain to Postfix virtual${NC}"
    fi
    
    # Add to DNS whitelist
    python3 << EOF
import json
try:
    with open('$DNS_WHITELIST', 'r') as f:
        config = json.load(f)
    
    domains = config.get('dns_whitelist', [])
    if '$domain' not in domains:
        domains.append('$domain')
        domains.sort()
        config['dns_whitelist'] = domains
        
        with open('$DNS_WHITELIST', 'w') as f:
            json.dump(config, f, indent=2)
        print("✓ Added $domain to DNS whitelist")
    else:
        print("⚠ Domain $domain already in DNS whitelist")
except Exception as e:
    print(f"✗ Error updating DNS whitelist: {e}")
    exit(1)
EOF
    
    # Note: email_filter.py no longer needs manual domain updates
    # Domains are auto-discovered by the conversation learning system
    echo -e "${GREEN}✓ Domain will be auto-discovered by SpaCy when emails arrive${NC}"
    
    # Add to Postfix relay_domains
    echo -e "${YELLOW}Updating Postfix relay_domains...${NC}"
    current_relay=$(postconf -h relay_domains)
    if [[ ! "$current_relay" =~ "$domain" ]]; then
        new_relay="$current_relay $domain"
        sudo postconf -e "relay_domains = $new_relay"
        echo -e "${GREEN}✓ Added $domain to relay_domains${NC}"
    else
        echo -e "${YELLOW}⚠ Domain $domain already in relay_domains${NC}"
    fi
    
    # Add to Postfix transport map
    echo -e "${YELLOW}Updating Postfix transport map...${NC}"
    if ! grep -q "^$domain " "$POSTFIX_TRANSPORT"; then
        # Add before the journal line or at the end if no journal line
        if grep -q "^journal@" "$POSTFIX_TRANSPORT"; then
            sudo sed -i "/^journal@/i $domain smtp:[$MAILGUARD_IP]" "$POSTFIX_TRANSPORT"
        else
            # Add before the catch-all discard line if it exists
            if grep -q '^\*' "$POSTFIX_TRANSPORT"; then
                sudo sed -i "/^\*/i $domain smtp:[$MAILGUARD_IP]" "$POSTFIX_TRANSPORT"
            else
                echo "$domain smtp:[$MAILGUARD_IP]" | sudo tee -a "$POSTFIX_TRANSPORT" > /dev/null
            fi
        fi
        echo -e "${GREEN}✓ Added $domain to transport map${NC}"
    else
        echo -e "${YELLOW}⚠ Domain $domain already in transport map${NC}"
    fi
    
    # Rebuild Postfix maps
    echo -e "${YELLOW}Rebuilding Postfix configuration...${NC}"
    sudo postmap "$POSTFIX_VIRTUAL"
    sudo postmap "$POSTFIX_TRANSPORT"
    sudo postfix reload
    
    echo -e "${GREEN}✓ Domain $domain successfully added and configured${NC}"
}

# Remove a domain
remove_domain() {
    local domain="$1"
    
    echo -e "${YELLOW}Removing domain: $domain${NC}"
    
    # Backup first
    backup_configs
    
    # Remove from Postfix virtual
    if grep -q "^@$domain" "$POSTFIX_VIRTUAL"; then
        sed -i "/^@$domain @$domain/d" "$POSTFIX_VIRTUAL"
        echo -e "${GREEN}✓ Removed $domain from Postfix virtual${NC}"
    else
        echo -e "${YELLOW}⚠ Domain $domain not found in Postfix virtual${NC}"
    fi
    
    # Remove from DNS whitelist
    python3 << EOF
import json
try:
    with open('$DNS_WHITELIST', 'r') as f:
        config = json.load(f)
    
    domains = config.get('dns_whitelist', [])
    if '$domain' in domains:
        domains.remove('$domain')
        config['dns_whitelist'] = domains
        
        with open('$DNS_WHITELIST', 'w') as f:
            json.dump(config, f, indent=2)
        print("✓ Removed $domain from DNS whitelist")
    else:
        print("⚠ Domain $domain not in DNS whitelist")
except Exception as e:
    print(f"✗ Error updating DNS whitelist: {e}")
    exit(1)
EOF
    
    # Note: email_filter.py no longer needs manual domain updates
    # Domains are auto-discovered by the conversation learning system
    echo -e "${GREEN}✓ Domain will be auto-removed from SpaCy learning system${NC}"
    
    # Skip the old email_filter.py update code
    if false; then
    python3 << EOF
import re

try:
    # Read the email_filter.py file
    with open('$EMAIL_FILTER', 'r') as f:
        content = f.read()
    
    # Function to remove domain from a set
    def remove_domain_from_set(set_block, domain):
        # Extract all domains from the set
        domains = re.findall(r"'([^']+)'", set_block)
        # Remove the target domain
        if domain in domains:
            domains.remove(domain)
        
        # Reconstruct the set block
        if domains:
            # Format domains nicely
            domain_lines = []
            for i in range(0, len(domains), 4):  # 4 domains per line
                line_domains = domains[i:i+4]
                line = "                    " + ", ".join(f"'{d}'" for d in line_domains)
                domain_lines.append(line)
            
            # Join with commas and proper indentation
            domains_str = ",\\n".join(domain_lines)
            return f'{{\\n{domains_str}\\n                }}'
        else:
            return '{\\n                }'
    
    # Remove from internal_domains
    internal_pattern = r'("internal_domains":\s*\{[^}]+\}),?'
    internal_match = re.search(internal_pattern, content, re.DOTALL)
    
    if internal_match:
        full_match = internal_match.group(0)
        internal_block = internal_match.group(1)
        if "'$domain'" in internal_block:
            # Extract just the set content
            set_content = re.search(r'\{([^}]+)\}', internal_block).group(0)
            new_set = remove_domain_from_set(set_content, '$domain')
            # Preserve the comma if it was there
            trailing_comma = ',' if full_match.endswith(',') else ''
            new_internal = f'"internal_domains": {new_set}{trailing_comma}'
            content = content.replace(full_match, new_internal)
            print("✓ Removed $domain from internal_domains in email_filter.py")
        else:
            print("⚠ Domain $domain not in internal_domains")
    
    # Remove from processed_domains
    processed_pattern = r'("processed_domains":\s*\{[^}]+\}),?'
    processed_match = re.search(processed_pattern, content, re.DOTALL)
    
    if processed_match:
        full_match = processed_match.group(0)
        processed_block = processed_match.group(1)
        if "'$domain'" in processed_block:
            # Extract just the set content
            set_content = re.search(r'\{([^}]+)\}', processed_block).group(0)
            new_set = remove_domain_from_set(set_content, '$domain')
            # Preserve the comma if it was there
            trailing_comma = ',' if full_match.endswith(',') else ''
            new_processed = f'"processed_domains": {new_set}{trailing_comma}'
            content = content.replace(full_match, new_processed)
            print("✓ Removed $domain from processed_domains in email_filter.py")
        else:
            print("⚠ Domain $domain not in processed_domains")
    
    # Write back the modified content
    with open('$EMAIL_FILTER', 'w') as f:
        f.write(content)
        
except Exception as e:
    print(f"✗ Error updating email_filter.py: {e}")
    exit(1)
EOF
    fi  # End of skipped email_filter.py update
    
    # Remove from Postfix relay_domains
    echo -e "${YELLOW}Updating Postfix relay_domains...${NC}"
    current_relay=$(postconf -h relay_domains)
    if [[ "$current_relay" =~ "$domain" ]]; then
        # Remove the domain from the list
        new_relay=$(echo "$current_relay" | sed "s/\b$domain\b//g" | sed 's/  */ /g' | sed 's/^ *//;s/ *$//')
        sudo postconf -e "relay_domains = $new_relay"
        echo -e "${GREEN}✓ Removed $domain from relay_domains${NC}"
    else
        echo -e "${YELLOW}⚠ Domain $domain not in relay_domains${NC}"
    fi
    
    # Remove from Postfix transport map
    echo -e "${YELLOW}Updating Postfix transport map...${NC}"
    if grep -q "^$domain " "$POSTFIX_TRANSPORT"; then
        sudo sed -i "/^$domain /d" "$POSTFIX_TRANSPORT"
        echo -e "${GREEN}✓ Removed $domain from transport map${NC}"
    else
        echo -e "${YELLOW}⚠ Domain $domain not in transport map${NC}"
    fi
    
    # Rebuild Postfix maps
    echo -e "${YELLOW}Rebuilding Postfix configuration...${NC}"
    sudo postmap "$POSTFIX_VIRTUAL"
    sudo postmap "$POSTFIX_TRANSPORT"
    sudo postfix reload
    
    echo -e "${GREEN}✓ Domain $domain successfully removed${NC}"
}

# Interactive menu
show_menu() {
    while true; do
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                   Domain Management Menu                      ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${WHITE}Options:${NC}"
        echo -e "${GREEN}1.${NC} List all managed domains"
        echo -e "${GREEN}2.${NC} Add a new domain"
        echo -e "${GREEN}3.${NC} Remove a domain"
        echo -e "${GREEN}4.${NC} Add multiple domains (batch)"
        echo -e "${GREEN}9.${NC} Return to main menu"
        echo ""
        read -p "Enter your choice: " choice
        
        case $choice in
            1)
                list_domains
                echo ""
                read -p "Press Enter to continue..."
                ;;
            2)
                read -p "Enter domain to add (e.g., example.com): " domain
                if [[ -n "$domain" ]]; then
                    add_domain "$domain"
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
            3)
                list_domains
                echo ""
                read -p "Enter domain to remove: " domain
                if [[ -n "$domain" ]]; then
                    read -p "Are you sure you want to remove $domain? (y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        remove_domain "$domain"
                    fi
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
            4)
                echo "Enter domains to add (one per line, empty line to finish):"
                while true; do
                    read domain
                    if [[ -z "$domain" ]]; then
                        break
                    fi
                    add_domain "$domain"
                done
                echo ""
                read -p "Press Enter to continue..."
                ;;
            9)
                return
                ;;
            *)
                echo -e "${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
        clear
    done
}

# Main execution
if [[ "$1" == "add" ]] && [[ -n "$2" ]]; then
    add_domain "$2"
elif [[ "$1" == "remove" ]] && [[ -n "$2" ]]; then
    remove_domain "$2"
elif [[ "$1" == "list" ]]; then
    list_domains
else
    show_menu
fi