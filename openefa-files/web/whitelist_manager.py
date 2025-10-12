#!/usr/bin/env python3
"""
Whitelist Management Functions for SpacyWeb
Provides domain-scoped whitelist operations with audit logging
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import shutil
import mysql.connector
from mysql.connector import pooling

class WhitelistManager:
    """Manages whitelist operations for SpaCy Email System"""

    def __init__(self):
        self.bec_config_path = "/opt/spacyserver/config/bec_config.json"
        self.trusted_domains_path = "/opt/spacyserver/config/trusted_domains.json"
        self.audit_log_path = "/opt/spacyserver/logs/whitelist_audit.log"
        self.backup_dir = "/opt/spacyserver/backups"

        # Database configuration
        self.db_config = {
            'user': 'spacy_user',
            'password': 'Correct-Horse-Battery-Staple-2024',
            'host': 'localhost',
            'database': 'spacy_email_db',
            'pool_name': 'whitelist_pool',
            'pool_size': 5
        }

        try:
            self.db_pool = mysql.connector.pooling.MySQLConnectionPool(**self.db_config)
        except Exception as e:
            print(f"Warning: Could not create database pool: {e}")
            self.db_pool = None

    def get_multi_domain_whitelist(self, domains: List[str]) -> Dict:
        """Get whitelist entries for multiple domains"""
        result = {
            'senders': [],
            'domains': [],
            'trusted_domains': []
        }

        # Read BEC config for sender whitelist
        try:
            with open(self.bec_config_path, 'r') as f:
                bec_config = json.load(f)

            # Get authentication-aware senders
            if 'whitelist' in bec_config and 'authentication_aware' in bec_config['whitelist']:
                if 'senders' in bec_config['whitelist']['authentication_aware']:
                    for sender, config in bec_config['whitelist']['authentication_aware']['senders'].items():
                        # Check if this sender is for any of the requested domains
                        # First check if it has a for_domain field
                        if 'for_domain' in config:
                            if config['for_domain'] in domains:
                                result['senders'].append({
                                    'email': sender,
                                    'trust_bonus': config.get('trust_score_bonus', 0),
                                    'require_auth': config.get('require_auth', []),
                                    'added_date': config.get('added_date', 'Unknown'),
                                    'added_by': config.get('added_by', 'System'),
                                    'for_domain': config['for_domain']
                                })
                        else:
                            # Fall back to checking if sender domain matches any of the requested domains
                            sender_domain = sender.split('@')[1] if '@' in sender else ''
                            if sender_domain in domains:
                                result['senders'].append({
                                    'email': sender,
                                    'trust_bonus': config.get('trust_score_bonus', 0),
                                    'require_auth': config.get('require_auth', []),
                                    'added_date': config.get('added_date', 'Unknown'),
                                    'added_by': config.get('added_by', 'System'),
                                    'for_domain': sender_domain  # Use sender domain as implied for_domain
                                })

            # Get legacy format senders
            if 'whitelist' in bec_config and 'senders' in bec_config['whitelist']:
                for sender, trust_level in bec_config['whitelist']['senders'].items():
                    sender_domain = sender.split('@')[1] if '@' in sender else ''
                    # For legacy entries, only show if sender domain matches
                    if sender_domain in domains:
                        # Check if not already in result
                        if not any(s['email'] == sender for s in result['senders']):
                            result['senders'].append({
                                'email': sender,
                                'trust_bonus': trust_level,
                                'require_auth': ['spf'],  # Default
                                'added_date': 'Legacy',
                                'added_by': 'System',
                                'for_domain': sender_domain
                            })

            # Get whitelisted domains
            if 'whitelist' in bec_config and 'domains' in bec_config['whitelist']:
                for wl_domain, config in bec_config['whitelist']['domains'].items():
                    # Check if this domain whitelist is for any of the requested domains
                    if 'for_domain' in config:
                        if config['for_domain'] in domains:
                            result['domains'].append({
                                'domain': wl_domain,
                                'trust_level': config.get('trust_level', 5),
                                'require_auth': config.get('require_auth', ['spf']),
                                'bypass_bec': config.get('bypass_bec_checks', False),
                                'bypass_typo': config.get('bypass_typosquatting', False),
                                'for_domain': config['for_domain']
                            })
                    # Also show common email providers that apply globally
                    elif wl_domain in ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']:
                        # Add once for all domains (don't duplicate)
                        if not any(d['domain'] == wl_domain for d in result['domains']):
                            result['domains'].append({
                                'domain': wl_domain,
                                'trust_level': config.get('trust_level', 5),
                                'require_auth': config.get('require_auth', ['spf']),
                                'bypass_bec': config.get('bypass_bec_checks', False),
                                'bypass_typo': config.get('bypass_typosquatting', False),
                                'for_domain': 'global'
                            })
        except Exception as e:
            print(f"Error reading BEC config: {e}")

        # Read trusted domains (system-wide fast-track)
        try:
            with open(self.trusted_domains_path, 'r') as f:
                trusted_domains = json.load(f)
                for domain in domains:
                    if domain in trusted_domains:
                        result['trusted_domains'].append({
                            'domain': domain,
                            'note': trusted_domains[domain]
                        })
        except Exception as e:
            print(f"Error reading trusted domains: {e}")

        return result

    def get_domain_whitelist(self, domain: str) -> Dict:
        """Get all whitelist entries for a specific domain"""
        result = {
            'senders': [],
            'domains': [],
            'trusted_domains': []
        }

        # Read BEC config for sender whitelist
        try:
            with open(self.bec_config_path, 'r') as f:
                bec_config = json.load(f)

            # Get authentication-aware senders
            if 'whitelist' in bec_config and 'authentication_aware' in bec_config['whitelist']:
                if 'senders' in bec_config['whitelist']['authentication_aware']:
                    for sender, config in bec_config['whitelist']['authentication_aware']['senders'].items():
                        # Check if this sender is for the requested domain
                        # First check if it has a for_domain field
                        if 'for_domain' in config:
                            if config['for_domain'] != domain:
                                continue  # Skip if not for this domain
                        else:
                            # Fall back to checking if sender domain matches
                            if not self._is_sender_for_domain(sender, domain):
                                continue  # Skip if sender domain doesn't match

                        result['senders'].append({
                            'email': sender,
                            'trust_bonus': config.get('trust_score_bonus', 0),
                            'require_auth': config.get('require_auth', []),
                            'added_date': config.get('added_date', 'Unknown'),
                            'added_by': config.get('added_by', 'System')
                        })

            # Get legacy format senders
            if 'whitelist' in bec_config and 'senders' in bec_config['whitelist']:
                for sender, trust_level in bec_config['whitelist']['senders'].items():
                    # For legacy entries, only show if sender domain matches
                    if self._is_sender_for_domain(sender, domain):
                        # Check if not already in result
                        if not any(s['email'] == sender for s in result['senders']):
                            result['senders'].append({
                                'email': sender,
                                'trust_bonus': trust_level,
                                'require_auth': ['spf'],  # Default
                                'added_date': 'Legacy',
                                'added_by': 'System'
                            })

            # Get whitelisted domains
            if 'whitelist' in bec_config and 'domains' in bec_config['whitelist']:
                for wl_domain, config in bec_config['whitelist']['domains'].items():
                    # Check if this domain whitelist is for the requested domain
                    if 'for_domain' in config:
                        if config['for_domain'] != domain:
                            continue  # Skip if not for this domain
                    # Also show common email providers that apply globally
                    elif wl_domain not in ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com']:
                        continue  # Skip domains without for_domain that aren't common providers

                    result['domains'].append({
                        'domain': wl_domain,
                        'trust_level': config.get('trust_level', 5),
                        'require_auth': config.get('require_auth', ['spf']),
                        'bypass_bec': config.get('bypass_bec_checks', False),
                        'bypass_typo': config.get('bypass_typosquatting', False)
                    })
        except Exception as e:
            print(f"Error reading BEC config: {e}")

        # Read trusted domains (system-wide fast-track)
        try:
            with open(self.trusted_domains_path, 'r') as f:
                trusted_domains = json.load(f)
                if domain in trusted_domains:
                    result['trusted_domains'].append({
                        'domain': domain,
                        'note': trusted_domains[domain]
                    })
        except Exception as e:
            print(f"Error reading trusted domains: {e}")

        return result

    def add_sender_whitelist(self, domain: str, sender_email: str, trust_bonus: int = 3,
                            require_auth: List[str] = None, added_by: str = "Web Admin") -> Tuple[bool, str]:
        """Add a sender to the whitelist for a domain"""

        # Validate email format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sender_email):
            return False, "Invalid email format"

        # Check if sender domain matches or is external
        sender_domain = sender_email.split('@')[1]
        if sender_domain != domain:
            # Log that this is an external sender being whitelisted for this domain
            self._audit_log(f"External sender {sender_email} whitelisted for domain {domain} by {added_by}")

        if require_auth is None:
            require_auth = ['spf']

        # Backup before modifying
        self._backup_config()

        try:
            with open(self.bec_config_path, 'r') as f:
                bec_config = json.load(f)

            # Initialize structure if needed
            if 'whitelist' not in bec_config:
                bec_config['whitelist'] = {}
            if 'authentication_aware' not in bec_config['whitelist']:
                bec_config['whitelist']['authentication_aware'] = {}
            if 'senders' not in bec_config['whitelist']['authentication_aware']:
                bec_config['whitelist']['authentication_aware']['senders'] = {}

            # Add the sender
            bec_config['whitelist']['authentication_aware']['senders'][sender_email] = {
                'trust_score_bonus': trust_bonus,
                'require_auth': require_auth,
                'added_date': datetime.now().isoformat(),
                'added_by': added_by,
                'for_domain': domain  # Track which domain this whitelist is for
            }

            # Write back
            with open(self.bec_config_path, 'w') as f:
                json.dump(bec_config, f, indent=2)

            # Ensure proper ownership
            try:
                os.chmod(self.bec_config_path, 0o664)
            except Exception as e:
                pass  # Log but don't fail

            self._audit_log(f"Added sender {sender_email} to whitelist for {domain} (trust: {trust_bonus}, auth: {require_auth}) by {added_by}")
            return True, f"Successfully added {sender_email} to whitelist"

        except Exception as e:
            return False, f"Error adding to whitelist: {str(e)}"

    def remove_sender_whitelist(self, domain: str, sender_email: str, removed_by: str = "Web Admin") -> Tuple[bool, str]:
        """Remove a sender from the whitelist"""

        # Backup before modifying
        self._backup_config()

        try:
            with open(self.bec_config_path, 'r') as f:
                bec_config = json.load(f)

            removed = False

            # Check authentication-aware senders
            if ('whitelist' in bec_config and
                'authentication_aware' in bec_config['whitelist'] and
                'senders' in bec_config['whitelist']['authentication_aware']):

                if sender_email in bec_config['whitelist']['authentication_aware']['senders']:
                    # Verify this sender was whitelisted for this domain
                    sender_config = bec_config['whitelist']['authentication_aware']['senders'][sender_email]
                    # Only allow removal if it was added for this domain
                    # or if it's from the same domain (no for_domain field but domain matches)
                    if sender_config.get('for_domain') == domain:
                        del bec_config['whitelist']['authentication_aware']['senders'][sender_email]
                        removed = True
                    elif not sender_config.get('for_domain'):
                        # Legacy entry - check if sender domain matches
                        sender_domain = sender_email.split('@')[1] if '@' in sender_email else ''
                        if sender_domain == domain:
                            del bec_config['whitelist']['authentication_aware']['senders'][sender_email]
                            removed = True

            # Check legacy format
            if not removed and 'whitelist' in bec_config and 'senders' in bec_config['whitelist']:
                if sender_email in bec_config['whitelist']['senders']:
                    del bec_config['whitelist']['senders'][sender_email]
                    removed = True

            if removed:
                with open(self.bec_config_path, 'w') as f:
                    json.dump(bec_config, f, indent=2)

                # Ensure proper ownership
                try:
                    os.chmod(self.bec_config_path, 0o664)
                except Exception as e:
                    pass  # Log but don't fail

                self._audit_log(f"Removed sender {sender_email} from whitelist for {domain} by {removed_by}")
                return True, f"Successfully removed {sender_email} from whitelist"
            else:
                return False, f"Sender {sender_email} not found in whitelist"

        except Exception as e:
            return False, f"Error removing from whitelist: {str(e)}"

    def add_domain_whitelist(self, domain: str, target_domain: str, trust_level: int = 5,
                            require_auth: List[str] = None, bypass_checks: bool = False,
                            added_by: str = "Web Admin") -> Tuple[bool, str]:
        """Add a domain to the whitelist"""

        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target_domain):
            return False, "Invalid domain format"

        if require_auth is None:
            require_auth = ['spf']

        # Backup before modifying
        self._backup_config()

        try:
            with open(self.bec_config_path, 'r') as f:
                bec_config = json.load(f)

            # Initialize structure if needed
            if 'whitelist' not in bec_config:
                bec_config['whitelist'] = {}
            if 'domains' not in bec_config['whitelist']:
                bec_config['whitelist']['domains'] = {}

            # Add the domain
            bec_config['whitelist']['domains'][target_domain] = {
                'trust_level': trust_level,
                'require_auth': require_auth,
                'bypass_bec_checks': bypass_checks,
                'bypass_typosquatting': bypass_checks,
                'added_date': datetime.now().isoformat(),
                'added_by': added_by,
                'for_domain': domain  # Track which domain this whitelist is for
            }

            # Write back
            with open(self.bec_config_path, 'w') as f:
                json.dump(bec_config, f, indent=2)

            # Ensure proper ownership
            try:
                os.chmod(self.bec_config_path, 0o664)
            except Exception as e:
                pass  # Log but don't fail

            self._audit_log(f"Added domain {target_domain} to whitelist for {domain} (trust: {trust_level}) by {added_by}")
            return True, f"Successfully added {target_domain} to domain whitelist"

        except Exception as e:
            return False, f"Error adding domain to whitelist: {str(e)}"

    def search_sender_in_emails(self, domain: str, sender_email: str, days: int = 30) -> List[Dict]:
        """Search for emails from a specific sender in the database"""

        if not self.db_pool:
            return []

        results = []

        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor(dictionary=True)

            # First get exact matches
            exact_query = """
                SELECT
                    message_id,
                    sender,
                    recipient,
                    subject,
                    spam_score,
                    final_verdict,
                    timestamp,
                    1 as is_exact_match
                FROM email_analysis
                WHERE LOWER(sender) = LOWER(%s)
                    AND recipient LIKE %s
                    AND timestamp > DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY timestamp DESC
                LIMIT 50
            """

            cursor.execute(exact_query, (sender_email, f"%@{domain}", days))
            exact_results = cursor.fetchall()

            # Then get partial matches (but exclude exact matches)
            partial_query = """
                SELECT
                    message_id,
                    sender,
                    recipient,
                    subject,
                    spam_score,
                    final_verdict,
                    timestamp,
                    0 as is_exact_match
                FROM email_analysis
                WHERE sender LIKE %s
                    AND LOWER(sender) != LOWER(%s)
                    AND recipient LIKE %s
                    AND timestamp > DATE_SUB(NOW(), INTERVAL %s DAY)
                ORDER BY timestamp DESC
                LIMIT 50
            """

            cursor.execute(partial_query, (f"%{sender_email}%", sender_email, f"%@{domain}", days))
            partial_results = cursor.fetchall()

            # Combine results with exact matches first
            results = exact_results + partial_results

            # Convert datetime objects to strings
            for row in results:
                if row['timestamp']:
                    row['timestamp'] = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"Database error searching for sender: {e}")

        return results

    def get_whitelist_stats(self, domain: str) -> Dict:
        """Get statistics about whitelist usage for a domain"""

        stats = {
            'total_senders': 0,
            'total_domains': 0,
            'recent_additions': [],
            'most_active': []
        }

        whitelist = self.get_domain_whitelist(domain)
        stats['total_senders'] = len(whitelist['senders'])
        stats['total_domains'] = len(whitelist['domains'])

        # Get recent additions (last 7)
        sorted_senders = sorted(whitelist['senders'],
                               key=lambda x: x.get('added_date', ''),
                               reverse=True)
        stats['recent_additions'] = sorted_senders[:7]

        # Get most active whitelisted senders from database
        if self.db_pool:
            try:
                conn = self.db_pool.get_connection()
                cursor = conn.cursor(dictionary=True)

                # Get email addresses from whitelist
                whitelisted_emails = [s['email'] for s in whitelist['senders']]

                if whitelisted_emails:
                    placeholders = ','.join(['%s'] * len(whitelisted_emails))
                    query = f"""
                        SELECT
                            sender,
                            COUNT(*) as email_count,
                            AVG(spam_score) as avg_score
                        FROM email_analysis
                        WHERE sender IN ({placeholders})
                            AND recipient LIKE %s
                            AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
                        GROUP BY sender
                        ORDER BY email_count DESC
                        LIMIT 10
                    """

                    params = whitelisted_emails + [f"%@{domain}"]
                    cursor.execute(query, params)
                    stats['most_active'] = cursor.fetchall()

                cursor.close()
                conn.close()

            except Exception as e:
                print(f"Database error getting stats: {e}")

        return stats

    def _is_sender_for_domain(self, sender_email: str, domain: str) -> bool:
        """Check if a sender is relevant for a domain"""
        # Check if sender email domain matches the requested domain
        sender_domain = sender_email.split('@')[1] if '@' in sender_email else ''

        # The sender is relevant if:
        # 1. The sender's domain matches the requested domain (internal emails)
        # 2. OR we need to check the 'for_domain' field in the config

        # For now, we'll check both the sender's domain and look for the for_domain field
        # when we read the config
        if sender_domain == domain:
            return True

        # We'll need to check the for_domain field when reading the config
        # This is handled in get_domain_whitelist method
        return False

    def _backup_config(self):
        """Backup configuration before modifications"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{self.backup_dir}/bec_config_backup_{timestamp}.json"

        try:
            shutil.copy2(self.bec_config_path, backup_path)
        except Exception as e:
            print(f"Warning: Could not create backup: {e}")

    def _audit_log(self, message: str):
        """Log whitelist changes for audit trail"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"

        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Warning: Could not write to audit log: {e}")