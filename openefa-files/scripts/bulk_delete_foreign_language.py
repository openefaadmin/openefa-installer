#!/opt/spacyserver/venv/bin/python3
"""
Bulk Delete Foreign Language Emails Script
Identifies and marks foreign language emails (non-English/Spanish) as deleted
in both email_quarantine and email_analysis tables

Usage:
    python3 bulk_delete_foreign_language.py          # Interactive mode
    python3 bulk_delete_foreign_language.py --yes    # Auto-confirm
"""

import mysql.connector
import os
import sys
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'spacy_user'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'spacy_email_db'),
    'port': int(os.getenv('DB_PORT', 3306))
}

# Foreign languages to detect (non-English/Spanish)
FOREIGN_LANGUAGES = ['ja', 'zh', 'ko', 'ru', 'vi', 'ar', 'th', 'hi', 'pt', 'fr', 'de', 'it']

def contains_foreign_characters(text):
    """
    Check if text contains non-English/Spanish characters (CJK, Cyrillic, Arabic, etc.)
    Returns True if foreign characters are detected
    """
    if not text:
        return False

    # Unicode ranges for common foreign scripts
    foreign_patterns = [
        r'[\u3040-\u309F]',  # Hiragana (Japanese)
        r'[\u30A0-\u30FF]',  # Katakana (Japanese)
        r'[\u4E00-\u9FFF]',  # CJK Unified Ideographs (Chinese/Japanese/Korean)
        r'[\uAC00-\uD7AF]',  # Hangul (Korean)
        r'[\u0400-\u04FF]',  # Cyrillic (Russian)
        r'[\u0600-\u06FF]',  # Arabic
        r'[\u0E00-\u0E7F]',  # Thai
        r'[\u0900-\u097F]',  # Devanagari (Hindi)
    ]

    for pattern in foreign_patterns:
        if re.search(pattern, text):
            return True

    return False

def main():
    """Main function to bulk delete foreign language emails"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        print("🔍 Searching for foreign language emails...")

        # Find emails in email_analysis with foreign languages
        query_analysis = """
            SELECT id, message_id, sender, subject, detected_language, spam_score
            FROM email_analysis
            WHERE detected_language IN (%s)
            AND is_deleted = 0
            ORDER BY timestamp DESC
        """ % ','.join(['%s'] * len(FOREIGN_LANGUAGES))

        cursor.execute(query_analysis, FOREIGN_LANGUAGES)
        foreign_emails_analysis = cursor.fetchall()

        print(f"📊 Found {len(foreign_emails_analysis)} foreign language emails in email_analysis")

        if foreign_emails_analysis:
            print("\n📝 Sample of emails to be marked as deleted:")
            for i, email in enumerate(foreign_emails_analysis[:10]):
                print(f"  {i+1}. ID: {email['id']} | Lang: {email['detected_language']} | "
                      f"From: {email['sender'][:50]} | Subject: {email['subject'][:50]}")

            if len(foreign_emails_analysis) > 10:
                print(f"  ... and {len(foreign_emails_analysis) - 10} more")

        # Find emails in email_quarantine with foreign languages
        # Join with email_analysis to get detected_language
        query_quarantine = """
            SELECT eq.id, eq.message_id, eq.sender, eq.subject, ea.detected_language, eq.quarantine_status
            FROM email_quarantine eq
            JOIN email_analysis ea ON eq.message_id = ea.message_id
            WHERE ea.detected_language IN (%s)
            AND eq.quarantine_status != 'deleted'
            ORDER BY eq.timestamp DESC
        """ % ','.join(['%s'] * len(FOREIGN_LANGUAGES))

        cursor.execute(query_quarantine, FOREIGN_LANGUAGES)
        foreign_emails_quarantine = cursor.fetchall()

        print(f"📊 Found {len(foreign_emails_quarantine)} foreign language emails in email_quarantine (with analysis)")

        # Find emails in email_quarantine WITHOUT analysis records but with foreign characters
        query_quarantine_no_analysis = """
            SELECT eq.id, eq.message_id, eq.sender, eq.subject, eq.quarantine_status
            FROM email_quarantine eq
            LEFT JOIN email_analysis ea ON eq.message_id = ea.message_id
            WHERE ea.id IS NULL
            AND eq.quarantine_status != 'deleted'
            ORDER BY eq.timestamp DESC
        """

        cursor.execute(query_quarantine_no_analysis)
        quarantine_no_analysis = cursor.fetchall()

        # Filter for foreign characters in subject/sender
        foreign_emails_no_analysis = []
        for email in quarantine_no_analysis:
            if contains_foreign_characters(email['subject']) or contains_foreign_characters(email['sender']):
                foreign_emails_no_analysis.append(email)

        print(f"📊 Found {len(foreign_emails_no_analysis)} foreign language emails in email_quarantine (without analysis)")

        if foreign_emails_no_analysis:
            print("\n📝 Sample of emails without analysis records:")
            for i, email in enumerate(foreign_emails_no_analysis[:5]):
                print(f"  {i+1}. ID: {email['id']} | "
                      f"From: {email['sender'][:50]} | Subject: {email['subject'][:50]}")

            if len(foreign_emails_no_analysis) > 5:
                print(f"  ... and {len(foreign_emails_no_analysis) - 5} more")

        # Ask for confirmation
        total_count = len(foreign_emails_analysis) + len(foreign_emails_quarantine) + len(foreign_emails_no_analysis)
        if total_count == 0:
            print("✅ No foreign language emails found to delete")
            return

        print(f"\n⚠️  Total emails to be marked as deleted: {total_count}")
        print("   - These will only be visible when clicking 'Show Deleted'")
        print("   - The email content will be preserved in the database")

        # Check for --yes flag
        auto_confirm = '--yes' in sys.argv or '-y' in sys.argv

        if not auto_confirm:
            response = input("\n❓ Do you want to proceed? (yes/no): ").strip().lower()
            if response != 'yes':
                print("❌ Operation cancelled")
                return
        else:
            print("\n✓ Auto-confirming (--yes flag provided)")

        # Update email_analysis table
        deleted_analysis = 0
        if foreign_emails_analysis:
            analysis_ids = [email['id'] for email in foreign_emails_analysis]
            placeholders = ','.join(['%s'] * len(analysis_ids))

            update_analysis = f"""
                UPDATE email_analysis
                SET is_deleted = 1
                WHERE id IN ({placeholders})
            """

            cursor.execute(update_analysis, analysis_ids)
            deleted_analysis = cursor.rowcount
            print(f"✅ Marked {deleted_analysis} emails as deleted in email_analysis")

        # Update email_quarantine table (with analysis records)
        deleted_quarantine = 0
        if foreign_emails_quarantine:
            quarantine_ids = [email['id'] for email in foreign_emails_quarantine]
            placeholders = ','.join(['%s'] * len(quarantine_ids))

            update_quarantine = f"""
                UPDATE email_quarantine
                SET quarantine_status = 'deleted'
                WHERE id IN ({placeholders})
            """

            cursor.execute(update_quarantine, quarantine_ids)
            deleted_quarantine = cursor.rowcount
            print(f"✅ Marked {deleted_quarantine} emails as deleted in email_quarantine (with analysis)")

        # Update email_quarantine table (without analysis records)
        deleted_no_analysis = 0
        if foreign_emails_no_analysis:
            no_analysis_ids = [email['id'] for email in foreign_emails_no_analysis]
            placeholders = ','.join(['%s'] * len(no_analysis_ids))

            update_no_analysis = f"""
                UPDATE email_quarantine
                SET quarantine_status = 'deleted'
                WHERE id IN ({placeholders})
            """

            cursor.execute(update_no_analysis, no_analysis_ids)
            deleted_no_analysis = cursor.rowcount
            print(f"✅ Marked {deleted_no_analysis} emails as deleted in email_quarantine (without analysis)")

        conn.commit()

        print(f"\n🎉 Successfully processed {deleted_analysis + deleted_quarantine + deleted_no_analysis} emails")
        print("   These emails are now hidden and will only show when 'Show Deleted' is clicked")

        cursor.close()
        conn.close()

    except mysql.connector.Error as e:
        print(f"❌ Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
