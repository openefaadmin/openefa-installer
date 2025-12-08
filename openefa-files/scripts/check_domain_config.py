#!/opt/spacyserver/venv/bin/python3
"""
Domain Configuration Audit Tool
Checks that domains are properly configured across all systems
"""
import mysql.connector
import subprocess
import re
import os

# Database connection from environment
db = mysql.connector.connect(
    host=os.getenv('DB_HOST', 'localhost'),
    user=os.getenv('DB_USER', 'spacy_user'),
    password=os.getenv('DB_PASSWORD', ''),
    database=os.getenv('DB_NAME', 'spacy_email_db')
)

cursor = db.cursor(dictionary=True)

print("=" * 80)
print("DOMAIN CONFIGURATION AUDIT")
print("=" * 80)
print()

# Get active domains from database
cursor.execute("SELECT domain, client_name FROM client_domains WHERE active = 1 ORDER BY domain")
client_domains = {row['domain']: row['client_name'] for row in cursor.fetchall()}

cursor.execute("SELECT domain, company_name FROM hosted_domains WHERE is_active = 1 ORDER BY domain")
hosted_domains = {row['domain']: row['company_name'] for row in cursor.fetchall()}

# Read postfix transport map
try:
    with open('/etc/postfix/transport', 'r') as f:
        transport_lines = f.readlines()
    transport_domains = set()
    for line in transport_lines:
        line = line.strip()
        if line and not line.startswith('#'):
            parts = line.split()
            if parts:
                transport_domains.add(parts[0])
except Exception as e:
    print(f"⚠️  Error reading /etc/postfix/transport: {e}")
    transport_domains = set()

# Get relay_domains from postfix
try:
    result = subprocess.run(['postconf', 'relay_domains'], capture_output=True, text=True)
    relay_domains_line = result.stdout.strip()
    # Extract domain list from "relay_domains = domain1, domain2, ..."
    if '=' in relay_domains_line:
        relay_domains_str = relay_domains_line.split('=', 1)[1].strip()
        relay_domains = {d.strip() for d in relay_domains_str.split(',') if d.strip()}
    else:
        relay_domains = set()
except Exception as e:
    print(f"⚠️  Error reading postconf relay_domains: {e}")
    relay_domains = set()

# Analysis
all_domains = client_domains.keys()
issues = []

print("📊 CONFIGURATION STATUS BY DOMAIN")
print("-" * 80)
print(f"{'Domain':<30} {'Client DB':<12} {'Hosted DB':<12} {'Transport':<12} {'Relay':<12}")
print("-" * 80)

for domain in sorted(all_domains):
    in_client = '✓' if domain in client_domains else '✗'
    in_hosted = '✓' if domain in hosted_domains else '✗ MISSING'
    in_transport = '✓' if domain in transport_domains else '✗ MISSING'
    in_relay = '✓' if domain in relay_domains else '✗ MISSING'

    status_line = f"{domain:<30} {in_client:<12} {in_hosted:<12} {in_transport:<12} {in_relay:<12}"
    print(status_line)

    # Track issues
    if domain not in hosted_domains:
        issues.append(f"Domain {domain} missing from hosted_domains table")
    if domain not in transport_domains:
        issues.append(f"Domain {domain} missing from /etc/postfix/transport")
    if domain not in relay_domains:
        issues.append(f"Domain {domain} missing from relay_domains")

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Active domains in client_domains:  {len(client_domains)}")
print(f"Active domains in hosted_domains:  {len(hosted_domains)}")
print(f"Domains in transport map:          {len(transport_domains)}")
print(f"Domains in relay_domains:          {len(relay_domains)}")
print()

if issues:
    print("⚠️  ISSUES FOUND:")
    for issue in issues:
        print(f"   - {issue}")
    print()
    print("Run /opt/spacyserver/scripts/sync_domains.py to fix database issues")
    print("Run /opt/spacyserver/scripts/update_transport_map.py to fix Postfix config")
else:
    print("✅ ALL DOMAINS PROPERLY CONFIGURED")

print()
cursor.close()
db.close()
