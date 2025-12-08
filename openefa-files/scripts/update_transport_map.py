#!/opt/spacyserver/venv/bin/python3
"""
Postfix Transport Map Updater
Regenerates /etc/postfix/transport and relay_domains from database
"""
import mysql.connector
import subprocess
import shutil
import os
from datetime import datetime

# Database connection from environment
db = mysql.connector.connect(
    host=os.getenv('DB_HOST', 'localhost'),
    user=os.getenv('DB_USER', 'spacy_user'),
    password=os.getenv('DB_PASSWORD', ''),
    database=os.getenv('DB_NAME', 'spacy_email_db')
)

cursor = db.cursor(dictionary=True)

print("=" * 80)
print("POSTFIX TRANSPORT MAP UPDATER")
print("=" * 80)
print()

# Backup existing transport map
transport_file = '/etc/postfix/transport'
backup_file = f'{transport_file}.backup-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
try:
    shutil.copy2(transport_file, backup_file)
    print(f"✓ Backed up existing transport map to: {backup_file}")
except Exception as e:
    print(f"⚠️  Warning: Could not backup transport map: {e}")

print()

# Get all active domains from database
print("Fetching active domains from client_domains...")
cursor.execute("""
    SELECT domain, relay_host, relay_port, client_name
    FROM client_domains
    WHERE active = 1
    ORDER BY domain
""")
domains = cursor.fetchall()
print(f"Found {len(domains)} active domains")
print()

# Generate transport map file
print("Generating /etc/postfix/transport...")
transport_content = """# OpenEFA Transport Map
# Routes configured domains to relay server
# Auto-generated from database - do not edit manually

"""

relay_domain_list = []

for domain_info in domains:
    domain = domain_info['domain']
    relay_host = domain_info['relay_host']
    relay_port = domain_info['relay_port'] or 25

    # Add to transport map
    if relay_port == 25:
        transport_content += f"{domain}    smtp:[{relay_host}]\n"
    else:
        transport_content += f"{domain}    smtp:[{relay_host}]:{relay_port}\n"

    # Add to relay_domains list
    relay_domain_list.append(domain)

    print(f"  {domain} -> {relay_host}:{relay_port}")

# Write transport map
try:
    with open(transport_file, 'w') as f:
        f.write(transport_content)
    print(f"\n✓ Updated {transport_file}")
except Exception as e:
    print(f"\n✗ Error writing transport map: {e}")
    cursor.close()
    db.close()
    exit(1)

# Compile transport map
print("\nCompiling transport map...")
try:
    result = subprocess.run(['postmap', transport_file], capture_output=True, text=True, check=True)
    print("✓ Transport map compiled successfully")
except subprocess.CalledProcessError as e:
    print(f"✗ Error compiling transport map: {e}")
    cursor.close()
    db.close()
    exit(1)

# Update relay_domains in main.cf
relay_domains_str = ', '.join(sorted(relay_domain_list))
print(f"\nUpdating relay_domains parameter...")
print(f"  Adding {len(relay_domain_list)} domains to relay_domains")

try:
    result = subprocess.run(
        ['postconf', '-e', f'relay_domains = {relay_domains_str}'],
        capture_output=True,
        text=True,
        check=True
    )
    print("✓ Updated relay_domains in main.cf")
except subprocess.CalledProcessError as e:
    print(f"✗ Error updating relay_domains: {e}")
    cursor.close()
    db.close()
    exit(1)

# Reload Postfix
print("\nReloading Postfix...")
try:
    result = subprocess.run(['systemctl', 'reload', 'postfix'], capture_output=True, text=True, check=True)
    print("✓ Postfix reloaded successfully")
except subprocess.CalledProcessError as e:
    print(f"✗ Error reloading Postfix: {e}")
    cursor.close()
    db.close()
    exit(1)

print()
print("=" * 80)
print("✅ POSTFIX CONFIGURATION UPDATED SUCCESSFULLY")
print("=" * 80)
print()
print("Summary:")
print(f"  - {len(domains)} domains configured in transport map")
print(f"  - {len(relay_domain_list)} domains in relay_domains")
print(f"  - Backup saved: {backup_file}")
print()
print("Next steps:")
print("  1. Verify configuration: postconf relay_domains")
print("  2. Test mail delivery: echo 'test' | mail -s 'Test' test@yourdomain.com")
print("  3. Monitor logs: tail -f /var/log/mail.log")
print()

cursor.close()
db.close()
