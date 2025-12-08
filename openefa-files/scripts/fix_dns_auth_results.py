#!/usr/bin/env python3
"""
Fix DNS authentication results for existing emails in the database.

This script extracts SPF, DKIM, and DMARC results from the X-SpaCy-Auth-Results
header in stored emails and updates the database columns.
"""

import sys
import os
import re
import mysql.connector
from email import message_from_string
from email.parser import Parser
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/opt/spacyserver/config/.env')

# Add parent directory to path for imports
sys.path.insert(0, '/opt/spacyserver')

def get_db_connection():
    """Get MySQL database connection"""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'spacy_user'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME', 'spacy_email_db'),
            port=int(os.getenv('DB_PORT', 3306)),
            autocommit=False,
            connection_timeout=10
        )
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)

def extract_auth_results(raw_email_text):
    """
    Extract SPF, DKIM, DMARC from X-SpaCy-Auth-Results or X-SpaCy-Trusted-Auth header

    Returns: dict with 'spf', 'dkim', 'dmarc' keys or None if header not found
    """
    if not raw_email_text:
        return None

    try:
        # Parse email to get headers
        msg = message_from_string(raw_email_text)

        # Look for X-SpaCy-Auth-Results header (normal emails)
        auth_header = msg.get('X-SpaCy-Auth-Results', '')

        # If not found, check X-SpaCy-Trusted-Auth header (trusted domain emails)
        if not auth_header:
            auth_header = msg.get('X-SpaCy-Trusted-Auth', '')

        if not auth_header:
            return None

        # Example headers:
        # "openspacy; spf=pass; dkim=fail; dmarc=pass (p=reject)"
        # "spf=pass dkim=pass dmarc=none"
        results = {
            'spf': 'none',
            'dkim': 'none',
            'dmarc': 'none'
        }

        # Extract SPF
        spf_match = re.search(r'spf=([a-z]+)', auth_header, re.IGNORECASE)
        if spf_match:
            results['spf'] = spf_match.group(1).lower()

        # Extract DKIM
        dkim_match = re.search(r'dkim=([a-z]+)', auth_header, re.IGNORECASE)
        if dkim_match:
            results['dkim'] = dkim_match.group(1).lower()

        # Extract DMARC (may not be present in X-SpaCy-Trusted-Auth)
        dmarc_match = re.search(r'dmarc=([a-z]+)', auth_header, re.IGNORECASE)
        if dmarc_match:
            results['dmarc'] = dmarc_match.group(1).lower()

        return results

    except Exception as e:
        print(f"⚠️  Error parsing email: {e}")
        return None

def main():
    """Main function to fix DNS auth results"""
    print("=" * 80)
    print("DNS Authentication Results Fix Script")
    print("=" * 80)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Find all emails where DNS results are 'none' or NULL
    print("\n🔍 Finding emails with missing DNS authentication results...")

    query = """
        SELECT id, message_id, sender, subject, raw_email, raw_email_path,
               original_spf, original_dkim, original_dmarc
        FROM email_analysis
        WHERE (original_spf = 'none' OR original_spf IS NULL)
           OR (original_dkim = 'none' OR original_dkim IS NULL)
           OR (original_dmarc = 'none' OR original_dmarc IS NULL)
        ORDER BY id ASC
    """

    cursor.execute(query)
    emails = cursor.fetchall()

    print(f"📊 Found {len(emails)} emails to process")

    if len(emails) == 0:
        print("✅ No emails need fixing!")
        cursor.close()
        conn.close()
        return

    # Process each email
    fixed_count = 0
    skipped_count = 0
    error_count = 0

    for idx, email in enumerate(emails, 1):
        email_id = email['id']
        message_id = email['message_id']

        if idx % 100 == 0:
            print(f"📧 Processing email {idx}/{len(emails)}...")

        # Get raw email text
        raw_email_text = None

        if email['raw_email']:
            # Email stored in database
            raw_email_text = email['raw_email']
        elif email['raw_email_path']:
            # Email stored on disk
            try:
                with open(email['raw_email_path'], 'r', encoding='utf-8') as f:
                    raw_email_text = f.read()
            except Exception as e:
                print(f"⚠️  Email {email_id}: Could not read file {email['raw_email_path']}: {e}")
                error_count += 1
                continue
        else:
            # No raw email available
            skipped_count += 1
            continue

        # Extract auth results from header
        auth_results = extract_auth_results(raw_email_text)

        if not auth_results:
            # No X-SpaCy-Auth-Results header found
            skipped_count += 1
            continue

        # Check if we actually have new data (not all 'none')
        if (auth_results['spf'] == 'none' and
            auth_results['dkim'] == 'none' and
            auth_results['dmarc'] == 'none'):
            skipped_count += 1
            continue

        # Update database
        try:
            update_query = """
                UPDATE email_analysis
                SET original_spf = %s,
                    original_dkim = %s,
                    original_dmarc = %s
                WHERE id = %s
            """

            update_cursor = conn.cursor()
            update_cursor.execute(update_query, (
                auth_results['spf'],
                auth_results['dkim'],
                auth_results['dmarc'],
                email_id
            ))
            update_cursor.close()

            fixed_count += 1

            if idx % 100 == 0 or fixed_count <= 10:
                print(f"✅ Email {email_id} ({message_id[:50]}): "
                      f"SPF={auth_results['spf']}, "
                      f"DKIM={auth_results['dkim']}, "
                      f"DMARC={auth_results['dmarc']}")

        except Exception as e:
            print(f"❌ Email {email_id}: Database update failed: {e}")
            error_count += 1
            continue

    # Commit all changes
    conn.commit()
    cursor.close()
    conn.close()

    # Print summary
    print("\n" + "=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"✅ Fixed: {fixed_count} emails")
    print(f"⏭️  Skipped: {skipped_count} emails (no header or already 'none')")
    print(f"❌ Errors: {error_count} emails")
    print(f"📊 Total processed: {len(emails)} emails")
    print("=" * 80)

if __name__ == "__main__":
    main()
