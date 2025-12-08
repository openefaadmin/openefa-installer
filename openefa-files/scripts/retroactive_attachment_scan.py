#!/usr/bin/env python3
"""
Retroactive Attachment Scanner

Scans emails from the past 15 days using the new Attachment Inspector
to identify threats that may have been missed.

Usage:
    python3 retroactive_attachment_scan.py [--days N] [--limit N]
"""

import sys
import os
sys.path.insert(0, '/opt/spacyserver')

import mysql.connector
from datetime import datetime, timedelta
from email import message_from_string
import logging
import argparse
from dotenv import load_dotenv

# Load environment
load_dotenv('/etc/spacy-server/.env')

# Import the new inspector
from modules.attachment_inspector import analyze_attachments

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_db_connection():
    """Get database connection"""
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'spacy_user'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME', 'spacy_email_db'),
        port=int(os.getenv('DB_PORT', 3306))
    )


def get_emails_with_attachments(days=15, limit=None):
    """
    Query emails from the past N days that have attachments

    Args:
        days: Number of days to look back
        limit: Optional limit on number of emails to scan

    Returns:
        List of email records
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Calculate date threshold
    date_threshold = datetime.now() - timedelta(days=days)

    query = """
        SELECT
            id,
            message_id,
            sender,
            recipients,
            subject,
            timestamp as received_at,
            spam_score,
            email_category,
            has_attachments,
            raw_email
        FROM email_analysis
        WHERE has_attachments = 1
          AND timestamp >= %s
        ORDER BY timestamp DESC
    """

    params = [date_threshold]

    if limit:
        query += " LIMIT %s"
        params.append(limit)

    cursor.execute(query, params)
    results = cursor.fetchall()

    cursor.close()
    conn.close()

    return results


def scan_email(email_record):
    """
    Scan a single email with the attachment inspector

    Args:
        email_record: Database record dict

    Returns:
        Dict with scan results
    """
    result = {
        'email_id': email_record['id'],
        'message_id': email_record['message_id'],
        'sender': email_record['sender'],
        'subject': email_record['subject'],
        'received_at': email_record['received_at'],
        'original_spam_score': email_record['spam_score'],
        'original_category': email_record['email_category'],
        'inspector_results': None,
        'threats_found': [],
        'error': None
    }

    try:
        # Parse raw email
        raw_email = email_record.get('raw_email')
        if not raw_email:
            result['error'] = 'No raw email content'
            return result

        # Handle compressed data if needed
        if isinstance(raw_email, bytes):
            try:
                import zlib
                raw_email = zlib.decompress(raw_email).decode('utf-8', errors='ignore')
            except:
                raw_email = raw_email.decode('utf-8', errors='ignore')

        msg = message_from_string(raw_email)

        # Run attachment inspector
        inspector_results = analyze_attachments(msg)
        result['inspector_results'] = inspector_results

        # Collect threats
        if inspector_results.get('dangerous_files'):
            result['threats_found'].append({
                'type': 'dangerous_files',
                'count': len(inspector_results['dangerous_files']),
                'details': inspector_results['dangerous_files']
            })

        if inspector_results.get('mismatches'):
            result['threats_found'].append({
                'type': 'type_mismatches',
                'count': len(inspector_results['mismatches']),
                'details': inspector_results['mismatches']
            })

        if inspector_results.get('archive_bombs'):
            result['threats_found'].append({
                'type': 'archive_bombs',
                'count': len(inspector_results['archive_bombs']),
                'details': inspector_results['archive_bombs']
            })

        if inspector_results.get('html_forms'):
            result['threats_found'].append({
                'type': 'html_phishing_forms',
                'count': len(inspector_results['html_forms']),
                'details': inspector_results['html_forms']
            })

        if inspector_results.get('macro_documents'):
            result['threats_found'].append({
                'type': 'macro_documents',
                'count': len(inspector_results['macro_documents']),
                'details': inspector_results['macro_documents']
            })

    except Exception as e:
        logger.error(f"Error scanning email {email_record['id']}: {e}")
        result['error'] = str(e)

    return result


def generate_report(scan_results, days):
    """Generate comprehensive report"""

    total_scanned = len(scan_results)
    total_with_threats = sum(1 for r in scan_results if r['threats_found'])
    total_errors = sum(1 for r in scan_results if r['error'])

    # Categorize by original classification
    threats_in_spam = []
    threats_in_clean = []
    threats_in_quarantine = []

    for result in scan_results:
        if result['threats_found']:
            category = result['original_category']
            if category == 'spam':
                threats_in_spam.append(result)
            elif category == 'clean':
                threats_in_clean.append(result)
            else:
                threats_in_quarantine.append(result)

    # Count threat types
    threat_type_counts = {
        'dangerous_files': 0,
        'type_mismatches': 0,
        'archive_bombs': 0,
        'html_phishing_forms': 0,
        'macro_documents': 0
    }

    for result in scan_results:
        for threat in result['threats_found']:
            threat_type = threat['type']
            if threat_type in threat_type_counts:
                threat_type_counts[threat_type] += threat['count']

    # Generate report
    print("\n" + "=" * 80)
    print("RETROACTIVE ATTACHMENT SCAN REPORT")
    print("=" * 80)
    print(f"Scan Period: Past {days} days")
    print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    print(f"\n📊 SUMMARY:")
    print(f"  Total emails scanned: {total_scanned}")
    print(f"  Emails with threats found: {total_with_threats} ({100*total_with_threats/total_scanned if total_scanned > 0 else 0:.1f}%)")
    print(f"  Scan errors: {total_errors}")

    print(f"\n🎯 THREAT DETECTION BY CATEGORY:")
    print(f"  Threats in CLEAN emails: {len(threats_in_clean)} ⚠️ MISSED THREATS!")
    print(f"  Threats in SPAM emails: {len(threats_in_spam)} (already caught)")
    print(f"  Threats in QUARANTINE: {len(threats_in_quarantine)}")

    print(f"\n🔍 THREAT TYPES DETECTED:")
    for threat_type, count in threat_type_counts.items():
        if count > 0:
            icon = {
                'dangerous_files': '🔴',
                'type_mismatches': '⚠️',
                'archive_bombs': '💣',
                'html_phishing_forms': '📝',
                'macro_documents': '📄'
            }.get(threat_type, '•')
            print(f"  {icon} {threat_type.replace('_', ' ').title()}: {count}")

    # Detailed findings for missed threats (clean emails)
    if threats_in_clean:
        print(f"\n" + "=" * 80)
        print(f"🚨 MISSED THREATS - Previously Classified as CLEAN")
        print("=" * 80)

        for i, result in enumerate(threats_in_clean, 1):
            print(f"\n[{i}] Email ID: {result['email_id']}")
            print(f"    Date: {result['received_at']}")
            print(f"    From: {result['sender']}")
            print(f"    Subject: {result['subject'][:60]}...")
            print(f"    Original Spam Score: {result['original_spam_score']}")

            inspector = result['inspector_results']
            if inspector:
                new_score = result['original_spam_score'] + inspector.get('spam_score', 0)
                print(f"    Inspector Score: +{inspector.get('spam_score', 0)} → NEW TOTAL: {new_score}")

            print(f"    Threats:")
            for threat in result['threats_found']:
                print(f"      • {threat['type']}: {threat['count']} found")
                for detail in threat['details'][:3]:  # Show first 3
                    if isinstance(detail, dict):
                        if 'filename' in detail:
                            print(f"        - {detail.get('filename')}: {detail.get('reason', detail.get('declared', 'N/A'))}")
                    else:
                        print(f"        - {detail}")

    # Summary of potentially dangerous emails in clean category
    if threats_in_clean:
        high_risk_missed = [r for r in threats_in_clean
                           if r['inspector_results']
                           and r['inspector_results'].get('spam_score', 0) >= 8.0]

        print(f"\n" + "=" * 80)
        print(f"⚠️ HIGH PRIORITY: {len(high_risk_missed)} high-risk emails marked as CLEAN")
        print("=" * 80)
        print("These emails should be reviewed and potentially quarantined.")

        for result in high_risk_missed:
            print(f"\n  Email ID {result['email_id']}: {result['subject'][:50]}...")
            print(f"    Inspector added +{result['inspector_results']['spam_score']} spam score")

            # Show what was found
            if result['inspector_results'].get('dangerous_files'):
                for danger in result['inspector_results']['dangerous_files']:
                    print(f"    🔴 {danger['filename']}: {danger['reason']}")

    print("\n" + "=" * 80)
    print(f"✅ Scan complete - {total_scanned} emails analyzed")
    print("=" * 80)

    return {
        'total_scanned': total_scanned,
        'total_with_threats': total_with_threats,
        'threats_in_clean': len(threats_in_clean),
        'threats_in_spam': len(threats_in_spam),
        'high_risk_missed': len(high_risk_missed) if threats_in_clean else 0,
        'threat_counts': threat_type_counts
    }


def main():
    parser = argparse.ArgumentParser(description='Retroactive attachment scan')
    parser.add_argument('--days', type=int, default=15, help='Days to look back (default: 15)')
    parser.add_argument('--limit', type=int, help='Limit number of emails to scan')
    parser.add_argument('--category', choices=['clean', 'spam', 'quarantine', 'all'],
                       default='all', help='Only scan specific category')

    args = parser.parse_args()

    print(f"\n🔍 Starting retroactive attachment scan...")
    print(f"   Looking back: {args.days} days")
    if args.limit:
        print(f"   Limit: {args.limit} emails")

    # Get emails
    logger.info(f"Querying emails from past {args.days} days with attachments...")
    emails = get_emails_with_attachments(days=args.days, limit=args.limit)

    if not emails:
        print("\n❌ No emails with attachments found in the specified period.")
        return

    logger.info(f"Found {len(emails)} emails with attachments")

    # Scan each email
    print(f"\n📧 Scanning {len(emails)} emails...")
    scan_results = []

    for i, email in enumerate(emails, 1):
        if i % 10 == 0:
            print(f"   Progress: {i}/{len(emails)} ({100*i/len(emails):.1f}%)")

        result = scan_email(email)
        scan_results.append(result)

    # Generate report
    report_stats = generate_report(scan_results, args.days)

    # Save detailed results to file
    output_file = f"/tmp/attachment_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(output_file, 'w') as f:
        f.write(f"Retroactive Attachment Scan\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Period: {args.days} days\n\n")

        for result in scan_results:
            if result['threats_found']:
                f.write(f"\nEmail ID: {result['email_id']}\n")
                f.write(f"Subject: {result['subject']}\n")
                f.write(f"From: {result['sender']}\n")
                f.write(f"Category: {result['original_category']}\n")
                f.write(f"Threats:\n")
                for threat in result['threats_found']:
                    f.write(f"  - {threat['type']}: {threat['count']}\n")
                    for detail in threat['details']:
                        f.write(f"    {detail}\n")
                f.write("\n" + "-" * 60 + "\n")

    print(f"\n💾 Detailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
