#!/bin/bash
#
# Fix admin user domain access
# This script updates the admin user's authorized_domains to match their primary domain
#

echo "OpenEFA - Fix Admin Domain Access"
echo "=================================="
echo ""

# Get the admin user's email
read -p "Enter admin email address: " ADMIN_EMAIL

# Get the primary domain
read -p "Enter primary domain configured during install: " PRIMARY_DOMAIN

echo ""
echo "This will update the admin user '$ADMIN_EMAIL' to have access to domain '$PRIMARY_DOMAIN'"
read -p "Continue? (y/n): " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Update the database
echo ""
echo "Updating database..."

mysql spacy_email_db << EOSQL
UPDATE users 
SET authorized_domains = '${PRIMARY_DOMAIN}',
    domain = '${PRIMARY_DOMAIN}'
WHERE email = '${ADMIN_EMAIL}';
EOSQL

if [[ $? -eq 0 ]]; then
    echo "✓ Admin user updated successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Log out of SpacyWeb (port 5500)"
    echo "2. Log back in with your admin credentials"
    echo "3. You should now have access to ${PRIMARY_DOMAIN}"
else
    echo "✗ Failed to update database"
    exit 1
fi
