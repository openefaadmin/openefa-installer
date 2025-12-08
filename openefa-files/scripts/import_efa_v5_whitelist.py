#!/usr/bin/env python3
"""
OpenEFA Whitelist Import Tool
Imports whitelists from EFA v5 JSON export or CSV files into OpenEFA
"""

import sys
import os
import json
import csv
import argparse
import logging
from datetime import datetime
import pymysql
from pymysql.cursors import DictCursor
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EFAv5Importer:
    def __init__(self, json_file):
        self.json_file = json_file
        self.bec_config_path = '/opt/spacyserver/config/bec_config.json'
        self.trusted_domains_path = '/opt/spacyserver/config/trusted_domains.json'
        self.db_config = self._load_db_config()
        self.stats = {
            'whitelisted_senders': 0,
            'whitelisted_domains': 0,
            'users_created': 0,
            'domain_assignments': 0,
            'skipped': 0
        }
        self.domain = None

    def _load_db_config(self):
        """Load database configuration from .env file"""
        env_path = '/opt/spacyserver/config/.env'
        config = {
            'host': 'localhost',
            'user': 'spacy_user',
            'password': '',
            'database': 'spacy_email_db'
        }

        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('DB_HOST='):
                        config['host'] = line.split('=', 1)[1].strip()
                    elif line.startswith('DB_USER='):
                        config['user'] = line.split('=', 1)[1].strip()
                    elif line.startswith('DB_PASSWORD='):
                        config['password'] = line.split('=', 1)[1].strip()
                    elif line.startswith('DB_NAME='):
                        config['database'] = line.split('=', 1)[1].strip()

        return config

    def load_export(self):
        """Load the EFA v5 JSON export"""
        logger.info(f"Loading export from {self.json_file}")

        with open(self.json_file, 'r') as f:
            data = json.load(f)

        self.domain = data.get('domain')
        logger.info(f"Domain: {self.domain}")

        return data

    def import_whitelists(self, export_data):
        """Import whitelist entries from EFA v5 export"""
        logger.info("Importing whitelist entries...")

        # Load existing BEC config
        with open(self.bec_config_path, 'r') as f:
            bec_config = json.load(f)

        # Ensure structure exists
        if 'whitelist' not in bec_config:
            bec_config['whitelist'] = {}
        if 'authentication_aware' not in bec_config['whitelist']:
            bec_config['whitelist']['authentication_aware'] = {'senders': {}}
        if 'senders' not in bec_config['whitelist']['authentication_aware']:
            bec_config['whitelist']['authentication_aware']['senders'] = {}
        if 'domains' not in bec_config['whitelist']:
            bec_config['whitelist']['domains'] = {}

        # Load trusted domains
        if os.path.exists(self.trusted_domains_path):
            with open(self.trusted_domains_path, 'r') as f:
                trusted_domains = json.load(f)
        else:
            trusted_domains = {'trusted_domains': []}

        # Process database whitelists
        db_whitelists = export_data.get('whitelist_infrastructure', {}).get('database_whitelists', [])

        for entry in db_whitelists:
            from_address = entry.get('from_address', '')
            to_address = entry.get('to_address', '')
            description = entry.get('description', 'Imported from EFA v5')

            if not from_address:
                continue

            # Determine if it's a domain or sender
            # If no @ sign, it's a domain
            # If @ but looks like a full email, it's a sender

            if '@' not in from_address:
                # Domain whitelist
                logger.info(f"  Adding domain whitelist: {from_address}")

                bec_config['whitelist']['domains'][from_address] = {
                    'trust_level': 5,
                    'require_auth': ['spf'],
                    'bypass_bec_checks': False,
                    'bypass_typosquatting': False,
                    'added_date': datetime.now().isoformat(),
                    'added_by': 'EFA_v5_Import',
                    'for_domain': self.domain,
                    'import_note': description
                }
                self.stats['whitelisted_domains'] += 1

                # Also add to trusted domains for fast-track
                if from_address not in trusted_domains.get('trusted_domains', []):
                    if 'trusted_domains' not in trusted_domains:
                        trusted_domains['trusted_domains'] = []
                    trusted_domains['trusted_domains'].append(from_address)

            else:
                # Individual sender whitelist
                logger.info(f"  Adding sender whitelist: {from_address}")

                bec_config['whitelist']['authentication_aware']['senders'][from_address] = {
                    'trust_score_bonus': 5,
                    'require_auth': ['spf'],
                    'for_domain': self.domain,
                    'imported_from': 'efa_v5',
                    'import_date': datetime.now().isoformat(),
                    'import_note': description,
                    'original_recipient': to_address
                }
                self.stats['whitelisted_senders'] += 1

        # Save updated configurations
        logger.info("Saving BEC configuration...")
        with open(self.bec_config_path, 'w') as f:
            json.dump(bec_config, f, indent=2)

        logger.info("Saving trusted domains...")
        with open(self.trusted_domains_path, 'w') as f:
            json.dump(trusted_domains, f, indent=2)

        logger.info(f"Whitelist import complete:")
        logger.info(f"  - Senders: {self.stats['whitelisted_senders']}")
        logger.info(f"  - Domains: {self.stats['whitelisted_domains']}")

    def create_domain_admin(self, export_data, username, fullname, password=None):
        """Create a domain admin user for the imported domain"""
        logger.info(f"Creating domain admin user: {username}")

        conn = pymysql.connect(**self.db_config, cursorclass=DictCursor)

        try:
            with conn.cursor() as cursor:
                # Check if user already exists
                cursor.execute(
                    "SELECT * FROM users WHERE email = %s",
                    (username,)
                )

                existing_user = cursor.fetchone()

                if existing_user:
                    logger.info(f"User {username} already exists (ID: {existing_user['id']})")
                    user_id = existing_user['id']

                    # Update authorized_domains if needed
                    authorized = existing_user.get('authorized_domains', '')
                    if authorized:
                        domains = [d.strip() for d in authorized.split(',')]
                    else:
                        domains = []

                    if self.domain not in domains:
                        domains.append(self.domain)
                        cursor.execute(
                            "UPDATE users SET authorized_domains = %s WHERE id = %s",
                            (','.join(domains), user_id)
                        )
                        conn.commit()
                        logger.info(f"Added {self.domain} to authorized domains for {username}")
                else:
                    # Split fullname into first and last
                    name_parts = fullname.split(' ', 1)
                    first_name = name_parts[0] if name_parts else ''
                    last_name = name_parts[1] if len(name_parts) > 1 else ''

                    # Set default password hash (user will need password reset)
                    import bcrypt
                    if password:
                        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    else:
                        # Create unusable password hash - forces password reset
                        password_hash = bcrypt.hashpw('TEMP_UNUSED'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

                    # Create new user
                    cursor.execute("""
                        INSERT INTO users
                        (email, password_hash, domain, authorized_domains, role,
                         first_name, last_name, is_active, email_verified, created_at)
                        VALUES (%s, %s, %s, %s, 'domain_admin', %s, %s, 1, 1, NOW())
                    """, (username, password_hash, self.domain, self.domain, first_name, last_name))

                    conn.commit()
                    user_id = cursor.lastrowid
                    logger.info(f"Created user {username} (ID: {user_id})")
                    self.stats['users_created'] += 1

                    if not password:
                        logger.warning(f"No password provided - {username} will need to use password reset")
                    else:
                        logger.info("Password set for user")

        finally:
            conn.close()

    def import_csv(self, csv_file):
        """Import whitelist entries from CSV file"""
        logger.info(f"Importing from CSV: {csv_file}")

        # Load existing BEC config
        with open(self.bec_config_path, 'r') as f:
            bec_config = json.load(f)

        # Ensure structure exists
        if 'whitelist' not in bec_config:
            bec_config['whitelist'] = {}
        if 'authentication_aware' not in bec_config['whitelist']:
            bec_config['whitelist']['authentication_aware'] = {'senders': {}}
        if 'senders' not in bec_config['whitelist']['authentication_aware']:
            bec_config['whitelist']['authentication_aware']['senders'] = {}
        if 'domains' not in bec_config['whitelist']:
            bec_config['whitelist']['domains'] = {}

        # Load trusted domains
        if os.path.exists(self.trusted_domains_path):
            with open(self.trusted_domains_path, 'r') as f:
                trusted_domains = json.load(f)
        else:
            trusted_domains = {'trusted_domains': []}

        # Read CSV file
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, start=2):  # Start at 2 to account for header
                try:
                    entry_type = row.get('entry_type', '').strip().lower()
                    value = row.get('value', '').strip().lower()
                    for_domain = row.get('for_domain', '').strip().lower()
                    description = row.get('description', '').strip()
                    trust_level = int(row.get('trust_level', 3))  # Default to 3 (least privilege)
                    require_auth_str = row.get('require_auth', 'spf').strip()

                    # Parse require_auth (handle comma-separated values)
                    if ',' in require_auth_str:
                        require_auth = [a.strip().lower() for a in require_auth_str.split(',')]
                    else:
                        require_auth = [require_auth_str.lower()] if require_auth_str else ['spf']

                    # Validate required fields
                    if not entry_type or not value or not for_domain:
                        logger.warning(f"Row {row_num}: Missing required fields (entry_type, value, or for_domain)")
                        self.stats['skipped'] += 1
                        continue

                    # Set domain for this batch
                    if not self.domain:
                        self.domain = for_domain

                    # Process based on entry type
                    if entry_type == 'sender':
                        # Validate email format
                        if '@' not in value:
                            logger.warning(f"Row {row_num}: Invalid email format: {value}")
                            self.stats['skipped'] += 1
                            continue

                        logger.info(f"  Row {row_num}: Adding sender whitelist: {value} for {for_domain}")

                        bec_config['whitelist']['authentication_aware']['senders'][value] = {
                            'trust_score_bonus': trust_level,
                            'require_auth': require_auth,
                            'for_domain': for_domain,
                            'imported_from': 'csv',
                            'import_date': datetime.now().isoformat(),
                            'import_note': description or 'Imported from CSV'
                        }
                        self.stats['whitelisted_senders'] += 1

                    elif entry_type == 'domain':
                        logger.info(f"  Row {row_num}: Adding domain whitelist: {value} for {for_domain}")

                        bec_config['whitelist']['domains'][value] = {
                            'trust_level': trust_level,
                            'require_auth': require_auth,
                            'bypass_bec_checks': False,
                            'bypass_typosquatting': False,
                            'added_date': datetime.now().isoformat(),
                            'added_by': 'CSV_Import',
                            'for_domain': for_domain,
                            'import_note': description or 'Imported from CSV'
                        }
                        self.stats['whitelisted_domains'] += 1

                        # Also add to trusted domains for fast-track
                        if value not in trusted_domains.get('trusted_domains', []):
                            if 'trusted_domains' not in trusted_domains:
                                trusted_domains['trusted_domains'] = []
                            trusted_domains['trusted_domains'].append(value)

                    else:
                        logger.warning(f"Row {row_num}: Invalid entry_type '{entry_type}' (must be 'sender' or 'domain')")
                        self.stats['skipped'] += 1

                except Exception as e:
                    logger.error(f"Row {row_num}: Error processing row: {e}")
                    self.stats['skipped'] += 1

        # Save updated configurations
        logger.info("Saving BEC configuration...")
        with open(self.bec_config_path, 'w') as f:
            json.dump(bec_config, f, indent=2)

        logger.info("Saving trusted domains...")
        with open(self.trusted_domains_path, 'w') as f:
            json.dump(trusted_domains, f, indent=2)

        logger.info(f"CSV import complete:")
        logger.info(f"  - Senders: {self.stats['whitelisted_senders']}")
        logger.info(f"  - Domains: {self.stats['whitelisted_domains']}")
        logger.info(f"  - Skipped: {self.stats['skipped']}")

    def print_summary(self):
        """Print import summary"""
        print("\n" + "="*60)
        print(f"Whitelist Import Summary")
        if self.domain:
            print(f"Primary Domain: {self.domain}")
        print("="*60)
        print(f"Whitelisted Senders: {self.stats['whitelisted_senders']}")
        print(f"Whitelisted Domains: {self.stats['whitelisted_domains']}")
        print(f"Users Created: {self.stats['users_created']}")
        print(f"Domain Assignments: {self.stats['domain_assignments']}")
        print(f"Skipped Entries: {self.stats['skipped']}")
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Import whitelist into OpenEFA from JSON or CSV')
    parser.add_argument('import_file', help='Path to import file (JSON or CSV)', nargs='?')
    parser.add_argument('--csv', help='Path to CSV file for import')
    parser.add_argument('--admin-user', help='Username for domain admin (e.g., dustin@barbour.tech)')
    parser.add_argument('--admin-name', help='Full name for domain admin (e.g., "Dustin Barbour")')
    parser.add_argument('--admin-password', help='Password for domain admin (optional - can use password reset)')
    parser.add_argument('--dry-run', action='store_true', help='Preview what would be imported without making changes')

    args = parser.parse_args()

    # Determine import file and type
    import_file = args.csv if args.csv else args.import_file

    if not import_file:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(import_file):
        logger.error(f"Import file not found: {import_file}")
        sys.exit(1)

    # Determine file type
    is_csv = import_file.lower().endswith('.csv') or args.csv
    is_json = import_file.lower().endswith('.json')

    if not is_csv and not is_json:
        logger.error("Import file must be .csv or .json")
        sys.exit(1)

    importer = EFAv5Importer(import_file)

    if is_csv:
        # CSV Import
        if args.dry_run:
            print("\n=== DRY RUN MODE (CSV) ===")
            # Count rows in CSV
            with open(import_file, 'r') as f:
                row_count = sum(1 for row in csv.DictReader(f))
            print(f"Would import {row_count} whitelist entries from CSV")
            return

        importer.import_csv(import_file)

    else:
        # JSON Import (EFA v5)
        export_data = importer.load_export()

        if args.dry_run:
            print("\n=== DRY RUN MODE (JSON) ===")
            print(f"Would import {len(export_data.get('whitelist_infrastructure', {}).get('database_whitelists', []))} whitelist entries")
            if args.admin_user:
                print(f"Would create domain admin: {args.admin_user}")
            return

        # Import whitelists
        importer.import_whitelists(export_data)

        # Create domain admin if specified
        if args.admin_user and args.admin_name:
            importer.create_domain_admin(
                export_data,
                args.admin_user,
                args.admin_name,
                args.admin_password
            )
        elif args.admin_user or args.admin_name:
            logger.warning("Both --admin-user and --admin-name are required to create admin account")

    # Print summary
    importer.print_summary()

    print("\nNext steps:")
    print(f"1. Verify whitelists in web UI: https://YOUR_SERVER_IP:5500")
    if importer.domain:
        print(f"2. Check BEC config: cat /opt/spacyserver/config/bec_config.json | grep -A5 '{importer.domain}'")
    if args.admin_user and not args.admin_password:
        print(f"3. Set password for {args.admin_user} via web interface password reset")
    print(f"4. Test email flow: Send test emails from whitelisted senders")

if __name__ == '__main__':
    main()
