#!/opt/spacyserver/venv/bin/python3
"""
Domain Configuration Synchronization Script
Ensures domains are configured in all necessary tables for complete functionality
"""
import mysql.connector
import sys
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
print("DOMAIN CONFIGURATION SYNCHRONIZATION")
print("=" * 80)
print()

# Step 1: Get all active domains from client_domains (source of truth)
print("Step 1: Fetching active domains from client_domains...")
cursor.execute("""
    SELECT domain, client_name, active
    FROM client_domains
    WHERE active = 1
    ORDER BY domain
""")
active_domains = cursor.fetchall()
print(f"Found {len(active_domains)} active domains in client_domains")
print()

# Step 2: Check hosted_domains table
print("Step 2: Checking hosted_domains table...")
cursor.execute("SELECT domain FROM hosted_domains")
hosted_domains = {row['domain'] for row in cursor.fetchall()}
print(f"Currently {len(hosted_domains)} domains in hosted_domains")
print()

# Step 3: Identify missing domains
missing_from_hosted = []
for domain_info in active_domains:
    domain = domain_info['domain']
    if domain not in hosted_domains:
        missing_from_hosted.append(domain_info)

if missing_from_hosted:
    print(f"⚠️  Found {len(missing_from_hosted)} domains missing from hosted_domains:")
    for domain_info in missing_from_hosted:
        print(f"   - {domain_info['domain']} ({domain_info['client_name']})")
    print()

    # Add missing domains
    print("Adding missing domains to hosted_domains...")
    for domain_info in missing_from_hosted:
        domain = domain_info['domain']
        company_name = domain_info['client_name'] or domain

        cursor.execute("""
            INSERT INTO hosted_domains (domain, company_name, is_active, created_at)
            VALUES (%s, %s, 1, NOW())
            ON DUPLICATE KEY UPDATE
                company_name = VALUES(company_name),
                is_active = 1
        """, (domain, company_name))
        print(f"   ✓ Added {domain}")

    db.commit()
    print(f"\n✅ Successfully added {len(missing_from_hosted)} domains to hosted_domains")
else:
    print("✅ All active domains are already in hosted_domains")

print()

# Step 4: Summary Report
print("=" * 80)
print("DOMAIN CONFIGURATION SUMMARY")
print("=" * 80)

# Get final counts
cursor.execute("SELECT COUNT(*) as count FROM client_domains WHERE active = 1")
client_count = cursor.fetchone()['count']

cursor.execute("SELECT COUNT(*) as count FROM hosted_domains WHERE is_active = 1")
hosted_count = cursor.fetchone()['count']

print(f"Active domains in client_domains:  {client_count}")
print(f"Active domains in hosted_domains:  {hosted_count}")

if client_count == hosted_count:
    print("\n✅ SYNCHRONIZED: All domains are properly configured")
else:
    print(f"\n⚠️  WARNING: Mismatch detected ({client_count} vs {hosted_count})")

print()
print("=" * 80)
print("CONFIGURATION CHECKLIST FOR NEW DOMAINS")
print("=" * 80)
print("""
When adding a new domain, ensure it is configured in:

1. ✓ client_domains table (active=1, relay_host, relay_port)
2. ✓ hosted_domains table (is_active=1, company_name)
3. ✓ /etc/postfix/transport map (domain -> relay host)
4. ✓ /etc/postfix/main.cf relay_domains parameter
5. ✓ Run: postmap /etc/postfix/transport
6. ✓ Run: systemctl reload postfix
7. ✓ Verify domain appears in web GUI dropdowns
8. ✓ Test inbound mail delivery
9. ✓ Test outbound mail relay

This script automatically syncs #1 and #2.
For Postfix configuration (#3-6), use the update_transport_map.py script.
""")

cursor.close()
db.close()
