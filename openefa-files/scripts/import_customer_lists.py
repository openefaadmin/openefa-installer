#!/usr/bin/env python3
"""
Customer Whitelist/Blocklist Import Tool
Imports SilverSky/cloud.postoffice.net lists into SpaCy
"""

import sys
import os
import json
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

class CustomerListImporter:
    def __init__(self, customer_domain):
        self.customer_domain = customer_domain.lower()
        self.db_config = self._load_db_config()
        self.stats = {
            'whitelisted_senders': 0,
            'whitelisted_domains': 0,
            'blocked_senders': 0,
            'blocked_domains': 0,
            'blocked_ips': 0,
            'skipped': 0
        }
    
    def _load_db_config(self):
        """Load database configuration"""
        config_path = '/opt/spacyserver/config/.my.cnf'
        config = {}
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('['):
                        key, value = line.strip().split('=', 1)
                        config[key.strip()] = value.strip().strip('"')
        
        return {
            'host': config.get('host', 'localhost'),
            'user': config.get('user', 'spacy_user'),
            'password': config.get('password', ''),
            'database': config.get('database', 'spacy_email_db')
        }
    
    def setup_customer_domain(self):
        """Ensure customer domain exists in database"""
        conn = pymysql.connect(**self.db_config, cursorclass=DictCursor)
        try:
            with conn.cursor() as cursor:
                # Check if domain exists
                cursor.execute(
                    "SELECT * FROM client_domains WHERE domain = %s",
                    (self.customer_domain,)
                )
                
                if not cursor.fetchone():
                    # Add domain
                    cursor.execute(
                        """INSERT INTO client_domains 
                           (domain, client_name, created_at, active) 
                           VALUES (%s, %s, NOW(), 1)""",
                        (self.customer_domain, self.customer_domain.split('.')[0].title())
                    )
                    conn.commit()
                    logger.info(f"Added customer domain: {self.customer_domain}")
                else:
                    logger.info(f"Customer domain already exists: {self.customer_domain}")
        finally:
            conn.close()
    
    def import_whitelist(self, whitelist_file):
        """Import whitelist from SilverSky/cloud.postoffice.net format"""
        logger.info(f"Importing whitelist from {whitelist_file}")
        
        # Load existing BEC config
        bec_config_path = '/opt/spacyserver/config/bec_config.json'
        with open(bec_config_path, 'r') as f:
            bec_config = json.load(f)
        
        # Ensure structure exists
        if 'whitelist' not in bec_config:
            bec_config['whitelist'] = {}
        if 'authentication_aware' not in bec_config['whitelist']:
            bec_config['whitelist']['authentication_aware'] = {'senders': {}}
        if 'senders' not in bec_config['whitelist']['authentication_aware']:
            bec_config['whitelist']['authentication_aware']['senders'] = {}
        
        # Also handle trusted domains
        trusted_domains_path = '/opt/spacyserver/config/trusted_domains.json'
        if os.path.exists(trusted_domains_path):
            with open(trusted_domains_path, 'r') as f:
                trusted_domains = json.load(f)
        else:
            trusted_domains = {'trusted_domains': []}
        
        with open(whitelist_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Parse different formats
                    # Format 1: email@domain.com
                    # Format 2: @domain.com or domain.com (whole domain)
                    # Format 3: IP address
                    
                    if '@' in line and not line.startswith('@'):
                        # Individual sender
                        email = line
                        logger.info(f"  Adding sender: {email}")
                        
                        # Add to BEC config with SPF-only requirement (common for imports)
                        bec_config['whitelist']['authentication_aware']['senders'][email] = {
                            'trust_score_bonus': 5,
                            'require_auth': ['spf'],
                            'for_domain': self.customer_domain,
                            'imported_from': 'silversky',
                            'import_date': datetime.now().isoformat()
                        }
                        self.stats['whitelisted_senders'] += 1
                        
                    elif line.startswith('@') or '.' in line:
                        # Domain whitelist
                        domain = line.lstrip('@')
                        logger.info(f"  Adding domain: {domain}")
                        
                        # Add to trusted domains for fast-track
                        if domain not in trusted_domains['trusted_domains']:
                            trusted_domains['trusted_domains'].append(domain)
                            self.stats['whitelisted_domains'] += 1
                        
                    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                        # IP address - add to whitelist
                        logger.info(f"  Adding IP to whitelist: {line}")
                        # Note: Would need to add IP whitelist support
                        self.stats['skipped'] += 1
                        
                    else:
                        logger.warning(f"  Skipping unrecognized format at line {line_num}: {line}")
                        self.stats['skipped'] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing line {line_num}: {e}")
                    self.stats['skipped'] += 1
        
        # Save updated configurations
        with open(bec_config_path, 'w') as f:
            json.dump(bec_config, f, indent=2)
        
        with open(trusted_domains_path, 'w') as f:
            json.dump(trusted_domains, f, indent=2)
        
        logger.info(f"Whitelist import complete:")
        logger.info(f"  - Senders: {self.stats['whitelisted_senders']}")
        logger.info(f"  - Domains: {self.stats['whitelisted_domains']}")
        logger.info(f"  - Skipped: {self.stats['skipped']}")
    
    def import_blocklist(self, blocklist_file):
        """Import blocklist from SilverSky format"""
        logger.info(f"Importing blocklist from {blocklist_file}")
        
        conn = pymysql.connect(**self.db_config, cursorclass=DictCursor)
        
        try:
            with conn.cursor() as cursor:
                with open(blocklist_file, 'r') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip().lower()
                        if not line or line.startswith('#'):
                            continue
                        
                        try:
                            # Determine type of block
                            if '@' in line and not line.startswith('@'):
                                # Individual sender block
                                email = line
                                logger.info(f"  Blocking sender: {email}")
                                
                                cursor.execute("""
                                    INSERT INTO blocking_rules 
                                    (domain, rule_type, value, pattern, description, priority, is_whitelist)
                                    VALUES (%s, 'sender', %s, 'exact', %s, 100, 0)
                                    ON DUPLICATE KEY UPDATE value=VALUES(value)
                                """, (
                                    self.customer_domain,
                                    email,
                                    f'Imported from SilverSky blocklist'
                                ))
                                self.stats['blocked_senders'] += 1
                                
                            elif line.startswith('@') or ('.' in line and not re.match(r'^\d', line)):
                                # Domain block
                                domain = line.lstrip('@')
                                
                                # Check if it's a wildcard pattern
                                if '*' in domain:
                                    pattern_type = 'wildcard'
                                else:
                                    pattern_type = 'exact'
                                
                                logger.info(f"  Blocking domain: {domain}")
                                
                                cursor.execute("""
                                    INSERT INTO blocking_rules 
                                    (domain, rule_type, value, pattern, description, priority, is_whitelist)
                                    VALUES (%s, 'domain', %s, %s, %s, 100, 0)
                                    ON DUPLICATE KEY UPDATE value=VALUES(value)
                                """, (
                                    self.customer_domain,
                                    domain,
                                    pattern_type,
                                    f'Imported from SilverSky blocklist'
                                ))
                                self.stats['blocked_domains'] += 1
                                
                            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                                # IP address block
                                logger.info(f"  Blocking IP: {line}")
                                
                                cursor.execute("""
                                    INSERT INTO blocking_rules 
                                    (domain, rule_type, value, pattern, description, priority, is_whitelist)
                                    VALUES (%s, 'ip', %s, 'exact', %s, 100, 0)
                                    ON DUPLICATE KEY UPDATE value=VALUES(value)
                                """, (
                                    self.customer_domain,
                                    line,
                                    f'Imported from SilverSky blocklist'
                                ))
                                self.stats['blocked_ips'] += 1
                                
                            else:
                                logger.warning(f"  Skipping unrecognized format at line {line_num}: {line}")
                                self.stats['skipped'] += 1
                                
                        except Exception as e:
                            logger.error(f"Error processing line {line_num}: {e}")
                            self.stats['skipped'] += 1
                
                conn.commit()
                
        finally:
            conn.close()
        
        logger.info(f"Blocklist import complete:")
        logger.info(f"  - Blocked senders: {self.stats['blocked_senders']}")
        logger.info(f"  - Blocked domains: {self.stats['blocked_domains']}")
        logger.info(f"  - Blocked IPs: {self.stats['blocked_ips']}")
        logger.info(f"  - Skipped: {self.stats['skipped']}")
    
    def configure_postfix_routing(self, exchange_server):
        """Configure Postfix to route customer domain to Exchange"""
        logger.info(f"Configuring Postfix routing for {self.customer_domain} -> {exchange_server}")
        
        # Update transport map
        transport_file = '/etc/postfix/transport'
        transport_entry = f"{self.customer_domain}\tsmtp:[{exchange_server}]:25\n"
        
        # Check if entry already exists
        existing = False
        if os.path.exists(transport_file):
            with open(transport_file, 'r') as f:
                if self.customer_domain in f.read():
                    existing = True
        
        if not existing:
            with open(transport_file, 'a') as f:
                f.write(transport_entry)
            
            # Rebuild transport database
            os.system('postmap /etc/postfix/transport')
            logger.info("Added transport entry")
        else:
            logger.info("Transport entry already exists")
        
        # Add to relay_domains
        os.system(f'postconf -e "relay_domains = \$relay_domains, {self.customer_domain}"')
        
        # Reload Postfix
        os.system('postfix reload')
        logger.info("Postfix configuration updated")
    
    def print_summary(self):
        """Print import summary"""
        print("\n" + "="*60)
        print(f"Import Summary for {self.customer_domain}")
        print("="*60)
        print(f"Whitelisted Senders: {self.stats['whitelisted_senders']}")
        print(f"Whitelisted Domains: {self.stats['whitelisted_domains']}")
        print(f"Blocked Senders: {self.stats['blocked_senders']}")
        print(f"Blocked Domains: {self.stats['blocked_domains']}")
        print(f"Blocked IPs: {self.stats['blocked_ips']}")
        print(f"Skipped Entries: {self.stats['skipped']}")
        print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Import customer whitelist/blocklist from SilverSky')
    parser.add_argument('customer_domain', help='Customer domain (e.g., example.com)')
    parser.add_argument('--whitelist', help='Path to whitelist file')
    parser.add_argument('--blocklist', help='Path to blocklist file')
    parser.add_argument('--exchange-server', help='Exchange server hostname/IP for routing')
    parser.add_argument('--setup-only', action='store_true', help='Only setup domain, do not import')
    
    args = parser.parse_args()
    
    importer = CustomerListImporter(args.customer_domain)
    
    # Setup customer domain
    importer.setup_customer_domain()
    
    if args.setup_only:
        print(f"Customer domain {args.customer_domain} is configured.")
        return
    
    # Import lists
    if args.whitelist:
        if os.path.exists(args.whitelist):
            importer.import_whitelist(args.whitelist)
        else:
            logger.error(f"Whitelist file not found: {args.whitelist}")
    
    if args.blocklist:
        if os.path.exists(args.blocklist):
            importer.import_blocklist(args.blocklist)
        else:
            logger.error(f"Blocklist file not found: {args.blocklist}")
    
    # Configure routing if Exchange server provided
    if args.exchange_server:
        importer.configure_postfix_routing(args.exchange_server)
    
    # Print summary
    importer.print_summary()
    
    print("\nNext steps:")
    print("1. Test email flow with: echo 'Test' | mail -s 'Test' user@" + args.customer_domain)
    print("2. Monitor logs: tail -f /var/log/mail.log")
    print("3. Check effectiveness: /opt/spacyserver/tools/OpenSpacyMenu option 22")
    print("4. View in web UI: https://100.83.45.26:5500")

if __name__ == '__main__':
    main()