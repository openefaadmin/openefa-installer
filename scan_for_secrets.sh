#!/bin/bash
#
# OpenEFA Secret Scanner
# Scans files for potentially sensitive data before release
#

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

SCAN_DIR="${1:-/opt/spacyserver/installer/openefa-files}"

if [[ ! -d "$SCAN_DIR" ]]; then
    echo "Usage: $0 [directory-to-scan]"
    echo "Default: /opt/spacyserver/installer/openefa-files"
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  OpenEFA Secret Scanner"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Scanning: $SCAN_DIR"
echo ""

ISSUES_FOUND=0

#######################################
# Check for IP addresses
#######################################
echo -e "${YELLOW}[1] Checking for hardcoded IP addresses...${NC}"

# Private IPs
if grep -rn "192\.168\.[0-9]\+\.[0-9]\+" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null; then
    echo -e "${RED}  ✗ Found 192.168.x.x IP addresses${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No 192.168.x.x IPs found${NC}"
fi

if grep -rn "10\.[0-9]\+\.[0-9]\+\.[0-9]\+" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null; then
    echo -e "${RED}  ✗ Found 10.x.x.x IP addresses${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No 10.x.x.x IPs found${NC}"
fi

echo ""

#######################################
# Check for client domains
#######################################
echo -e "${YELLOW}[2] Checking for client domain names...${NC}"

CLIENT_DOMAINS=(
    "safesoundins\.com"
    "phoenixdefence\.com"
    "chipotlepublishing\.com"
    "americankx\.com"
)

for domain in "${CLIENT_DOMAINS[@]}"; do
    if grep -rn "$domain" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null; then
        echo -e "${RED}  ✗ Found client domain: $domain${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

if [[ $ISSUES_FOUND -eq 0 ]]; then
    echo -e "${GREEN}  ✓ No client domains found${NC}"
fi

echo ""

#######################################
# Check for passwords
#######################################
echo -e "${YELLOW}[3] Checking for passwords...${NC}"

PASSWORD_PATTERNS=(
    "password\s*=\s*['\"][^'\"]{8,}"
    "PASSWORD\s*=\s*['\"][^'\"]{8,}"
    "passwd\s*=\s*['\"][^'\"]{8,}"
    "DB_PASS\s*=\s*['\"][^'\"]{8,}"
)

for pattern in "${PASSWORD_PATTERNS[@]}"; do
    if grep -rn -E "$pattern" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null; then
        echo -e "${RED}  ✗ Possible hardcoded password found${NC}"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
done

if [[ $ISSUES_FOUND -eq 0 ]]; then
    echo -e "${GREEN}  ✓ No obvious passwords found${NC}"
fi

echo ""

#######################################
# Check for API keys
#######################################
echo -e "${YELLOW}[4] Checking for API keys...${NC}"

if grep -rn -E "api_key|API_KEY|api-key" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null | grep -v "^#" | grep "=" ; then
    echo -e "${RED}  ✗ Possible API keys found${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No API keys found${NC}"
fi

echo ""

#######################################
# Check for email addresses
#######################################
echo -e "${YELLOW}[5] Checking for specific email addresses...${NC}"

if grep -rn -E "[a-zA-Z0-9._%+-]+@(safesoundins|phoenixdefence|chipotlepublishing)\.com" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null; then
    echo -e "${RED}  ✗ Found client email addresses${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No client emails found${NC}"
fi

echo ""

#######################################
# Check for HOSTED_DOMAINS
#######################################
echo -e "${YELLOW}[6] Checking for HOSTED_DOMAINS hardcoding...${NC}"

if grep -rn "HOSTED_DOMAINS\s*=\s*\[" "$SCAN_DIR" --include="*.py" 2>/dev/null; then
    echo -e "${RED}  ✗ Found hardcoded HOSTED_DOMAINS${NC}"
    echo -e "${RED}    Fix: Use get_hosted_domains() function${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No HOSTED_DOMAINS hardcoding${NC}"
fi

echo ""

#######################################
# Check for TODO/FIXME with sensitive info
#######################################
echo -e "${YELLOW}[7] Checking for TODOs/FIXMEs...${NC}"

TODO_COUNT=$(grep -rn "TODO\|FIXME" "$SCAN_DIR" --include="*.py" --include="*.sh" 2>/dev/null | wc -l)

if [[ $TODO_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}  ⚠ Found $TODO_COUNT TODO/FIXME comments${NC}"
    echo -e "${YELLOW}    Review these before release${NC}"
else
    echo -e "${GREEN}  ✓ No TODOs/FIXMEs${NC}"
fi

echo ""

#######################################
# Check for debug code
#######################################
echo -e "${YELLOW}[8] Checking for debug code...${NC}"

if grep -rn "print.*password\|print.*secret\|print.*key" "$SCAN_DIR" --include="*.py" 2>/dev/null; then
    echo -e "${RED}  ✗ Found debug prints with sensitive data${NC}"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No sensitive debug code${NC}"
fi

echo ""

#######################################
# Check file permissions
#######################################
echo -e "${YELLOW}[9] Checking for sensitive file permissions...${NC}"

SENSITIVE_FILES=$(find "$SCAN_DIR" -type f \( -name "*.key" -o -name "*.pem" -o -name "*secret*" \) 2>/dev/null)

if [[ -n "$SENSITIVE_FILES" ]]; then
    echo -e "${RED}  ✗ Found sensitive files:${NC}"
    echo "$SENSITIVE_FILES"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo -e "${GREEN}  ✓ No sensitive files found${NC}"
fi

echo ""

#######################################
# Summary
#######################################
echo "═══════════════════════════════════════════════════════"

if [[ $ISSUES_FOUND -eq 0 ]]; then
    echo -e "${GREEN}✓ PASSED: No critical issues found${NC}"
    echo ""
    echo "Files appear safe for public release."
    exit 0
else
    echo -e "${RED}✗ FAILED: Found $ISSUES_FOUND issue(s)${NC}"
    echo ""
    echo "Please review and fix issues before release."
    echo ""
    echo "Common fixes:"
    echo "  • Remove hardcoded IPs → Read from config"
    echo "  • Remove client domains → Read from database"
    echo "  • Remove HOSTED_DOMAINS → Use get_hosted_domains()"
    echo "  • Remove debug prints with sensitive data"
    exit 1
fi
