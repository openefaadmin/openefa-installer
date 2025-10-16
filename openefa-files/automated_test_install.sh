#!/bin/bash
#
# Automated OpenEFA Installation Test Script
# Pre-configured for testing with hardcoded values
#

echo "Starting automated OpenEFA installation test..."
echo "Test domain: example.com"
echo "Relay server: YOUR_RELAY_SERVER"
echo ""

# Provide all answers to the installer prompts
# Order of prompts:
# 1. Domain
# 2. Database password
# 3. Confirm database password
# 4. Admin username (press enter for default "admin")
# 5. Admin email
# 6. Admin password
# 7. Confirm admin password
# 8. Relay host IP
# 9. DNS resolver (press enter for default "8.8.8.8")
# 10. Install Tier 2 modules? (y/n)
# 11. Install Tier 3 modules? (y/n)
# 12. Proceed with installation? (y/n)

cat << EOF | sudo bash install.sh
example.com
OpenEFA_DB_Test_2025!
OpenEFA_DB_Test_2025!

admin@example.com
OpenEFA_Admin_2025!
OpenEFA_Admin_2025!
YOUR_RELAY_SERVER

y
y
y
EOF

echo ""
echo "Installation test completed!"
