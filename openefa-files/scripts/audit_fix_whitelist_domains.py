#!/usr/bin/env python3
"""
Audit and fix whitelist entries to add missing for_domain associations
"""

import json
import sys
import os
from datetime import datetime
import mysql.connector
from collections import defaultdict

def get_db_connection():
    """Get database connection"""
    return mysql.connector.connect(
        option_files='/opt/spacyserver/config/.my.cnf'
    )

def get_client_domains():
    """Get list of client domains from database"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get domains that have received emails
    cursor.execute("""
        SELECT DISTINCT SUBSTRING_INDEX(recipients, '@', -1) as domain
        FROM email_analysis
        WHERE recipients LIKE '%@%'
        ORDER BY domain
    """)

    domains = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    return domains

def analyze_sender_domain_associations(sender_email, client_domains):
    """Analyze which client domain a sender should be associated with"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Find which domains this sender has sent emails to
    cursor.execute("""
        SELECT
            SUBSTRING_INDEX(recipients, '@', -1) as recipient_domain,
            COUNT(*) as email_count
        FROM email_analysis
        WHERE LOWER(sender) = LOWER(%s)
            AND recipients LIKE '%@%'
        GROUP BY recipient_domain
        ORDER BY email_count DESC
    """, (sender_email,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()

    # Return the domain with most emails, or None if no matches
    if results and results[0]['recipient_domain'] in client_domains:
        return results[0]['recipient_domain']

    return None

def audit_whitelist():
    """Audit current whitelist entries"""
    config_path = "/opt/spacyserver/config/bec_config.json"

    with open(config_path, 'r') as f:
        bec_config = json.load(f)

    client_domains = get_client_domains()
    print(f"\n=== CLIENT DOMAINS FOUND ===")
    for domain in client_domains:
        print(f"  - {domain}")

    audit_results = {
        'needs_assignment': [],
        'has_assignment': [],
        'internal_senders': [],
        'suggested_assignments': {}
    }

    print(f"\n=== ANALYZING WHITELIST ENTRIES ===\n")

    # Check authentication-aware senders
    if 'whitelist' in bec_config and 'authentication_aware' in bec_config['whitelist']:
        if 'senders' in bec_config['whitelist']['authentication_aware']:
            for sender, config in bec_config['whitelist']['authentication_aware']['senders'].items():
                sender_domain = sender.split('@')[1] if '@' in sender else 'unknown'

                if 'for_domain' in config:
                    audit_results['has_assignment'].append({
                        'sender': sender,
                        'for_domain': config['for_domain'],
                        'trust_bonus': config.get('trust_score_bonus', 0)
                    })
                    print(f"✓ {sender} -> assigned to {config['for_domain']}")
                elif sender_domain in client_domains:
                    audit_results['internal_senders'].append({
                        'sender': sender,
                        'domain': sender_domain,
                        'trust_bonus': config.get('trust_score_bonus', 0)
                    })
                    print(f"◆ {sender} -> internal sender for {sender_domain}")
                else:
                    # Try to find association from email history
                    suggested_domain = analyze_sender_domain_associations(sender, client_domains)
                    audit_results['needs_assignment'].append({
                        'sender': sender,
                        'trust_bonus': config.get('trust_score_bonus', 0),
                        'suggested_domain': suggested_domain
                    })
                    if suggested_domain:
                        audit_results['suggested_assignments'][sender] = suggested_domain
                        print(f"✗ {sender} -> NEEDS ASSIGNMENT (suggest: {suggested_domain})")
                    else:
                        print(f"✗ {sender} -> NEEDS ASSIGNMENT (no suggestion)")

    # Check legacy senders
    if 'whitelist' in bec_config and 'senders' in bec_config['whitelist']:
        for sender, trust_level in bec_config['whitelist']['senders'].items():
            sender_domain = sender.split('@')[1] if '@' in sender else 'unknown'

            if sender_domain in client_domains:
                audit_results['internal_senders'].append({
                    'sender': sender,
                    'domain': sender_domain,
                    'trust_bonus': trust_level,
                    'legacy': True
                })
                print(f"◆ {sender} -> internal sender for {sender_domain} (LEGACY)")
            else:
                suggested_domain = analyze_sender_domain_associations(sender, client_domains)
                audit_results['needs_assignment'].append({
                    'sender': sender,
                    'trust_bonus': trust_level,
                    'suggested_domain': suggested_domain,
                    'legacy': True
                })
                if suggested_domain:
                    audit_results['suggested_assignments'][sender] = suggested_domain
                    print(f"✗ {sender} -> NEEDS ASSIGNMENT (suggest: {suggested_domain}) (LEGACY)")
                else:
                    print(f"✗ {sender} -> NEEDS ASSIGNMENT (no suggestion) (LEGACY)")

    # Check domain whitelists
    print(f"\n=== DOMAIN WHITELIST ENTRIES ===\n")
    if 'whitelist' in bec_config and 'domains' in bec_config['whitelist']:
        for domain, config in bec_config['whitelist']['domains'].items():
            if 'for_domain' in config:
                print(f"✓ {domain} -> assigned to {config['for_domain']}")
            else:
                print(f"✗ {domain} -> NO ASSIGNMENT (global whitelist)")

    return audit_results, bec_config, client_domains

def apply_fixes(audit_results, bec_config, client_domains, auto_fix=False):
    """Apply fixes to whitelist entries"""

    if not audit_results['needs_assignment'] and not audit_results['internal_senders']:
        print("\n✓ All whitelist entries have proper domain associations!")
        return False

    print(f"\n=== PROPOSED FIXES ===\n")

    fixes_to_apply = {}

    # Handle entries needing assignment
    if audit_results['needs_assignment']:
        print("External senders needing domain assignment:")
        for item in audit_results['needs_assignment']:
            sender = item['sender']
            suggested = item.get('suggested_domain')

            if suggested and auto_fix:
                fixes_to_apply[sender] = suggested
                print(f"  AUTO-FIX: {sender} -> {suggested}")
            elif suggested:
                print(f"  {sender}")
                print(f"    Suggested: {suggested}")
                response = input(f"    Assign to domain (or press Enter for {suggested}): ").strip()
                if response:
                    if response in client_domains:
                        fixes_to_apply[sender] = response
                    else:
                        print(f"    ✗ Invalid domain: {response}")
                else:
                    fixes_to_apply[sender] = suggested
            else:
                print(f"  {sender}")
                print(f"    Available domains: {', '.join(client_domains)}")
                response = input("    Assign to domain (or 'skip'): ").strip()
                if response and response != 'skip' and response in client_domains:
                    fixes_to_apply[sender] = response

    # Handle internal senders (automatic assignment)
    if audit_results['internal_senders']:
        print("\nInternal senders (will auto-assign to their domain):")
        for item in audit_results['internal_senders']:
            sender = item['sender']
            domain = item['domain']
            fixes_to_apply[sender] = domain
            print(f"  {sender} -> {domain}")

    if not fixes_to_apply:
        print("\nNo fixes to apply.")
        return False

    # Apply the fixes
    response = input(f"\nApply {len(fixes_to_apply)} fixes? (y/n): ").strip().lower()
    if response != 'y':
        print("Aborted.")
        return False

    # Backup config first
    backup_path = f"/opt/spacyserver/config/bec_config.json.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    with open(backup_path, 'w') as f:
        json.dump(bec_config, f, indent=2)
    print(f"\nBackup saved to: {backup_path}")

    # Apply fixes
    applied_count = 0

    for sender, domain in fixes_to_apply.items():
        # Check authentication-aware senders
        if ('whitelist' in bec_config and
            'authentication_aware' in bec_config['whitelist'] and
            'senders' in bec_config['whitelist']['authentication_aware'] and
            sender in bec_config['whitelist']['authentication_aware']['senders']):

            bec_config['whitelist']['authentication_aware']['senders'][sender]['for_domain'] = domain
            applied_count += 1

        # Check legacy senders - migrate them to authentication-aware format
        elif ('whitelist' in bec_config and
              'senders' in bec_config['whitelist'] and
              sender in bec_config['whitelist']['senders']):

            trust_level = bec_config['whitelist']['senders'][sender]

            # Ensure authentication_aware structure exists
            if 'authentication_aware' not in bec_config['whitelist']:
                bec_config['whitelist']['authentication_aware'] = {}
            if 'senders' not in bec_config['whitelist']['authentication_aware']:
                bec_config['whitelist']['authentication_aware']['senders'] = {}

            # Migrate to new format
            bec_config['whitelist']['authentication_aware']['senders'][sender] = {
                'trust_score_bonus': trust_level,
                'require_auth': ['spf'],
                'for_domain': domain,
                'migrated_from_legacy': datetime.now().isoformat()
            }

            # Remove from legacy
            del bec_config['whitelist']['senders'][sender]
            applied_count += 1
            print(f"  Migrated {sender} from legacy format")

    # Save updated config
    config_path = "/opt/spacyserver/config/bec_config.json"
    with open(config_path, 'w') as f:
        json.dump(bec_config, f, indent=2)

    print(f"\n✓ Applied {applied_count} fixes to {config_path}")
    return True

def main():
    print("=== SpaCy Whitelist Domain Association Audit ===\n")

    # Check for auto-fix flag
    auto_fix = '--auto-fix' in sys.argv
    if auto_fix:
        print("AUTO-FIX MODE: Will use suggested domains automatically\n")

    # Run audit
    audit_results, bec_config, client_domains = audit_whitelist()

    # Print summary
    print(f"\n=== SUMMARY ===")
    print(f"Total client domains: {len(client_domains)}")
    print(f"Entries with assignment: {len(audit_results['has_assignment'])}")
    print(f"Internal senders (auto-assignable): {len(audit_results['internal_senders'])}")
    print(f"Entries needing assignment: {len(audit_results['needs_assignment'])}")
    print(f"Suggested assignments available: {len(audit_results['suggested_assignments'])}")

    # Apply fixes
    if audit_results['needs_assignment'] or audit_results['internal_senders']:
        apply_fixes(audit_results, bec_config, client_domains, auto_fix)

    print("\n=== COMPLETE ===")

if __name__ == "__main__":
    main()