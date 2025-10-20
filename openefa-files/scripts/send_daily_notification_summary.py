#!/opt/spacyserver/venv/bin/python3
"""
Daily Notification Summary Script
Sends SMS notification with daily email filtering statistics
Run via cron (e.g., daily at 8 AM)
"""

import sys
import os
import mysql.connector
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from /etc/spacy-server/.env
load_dotenv('/etc/spacy-server/.env')

# Add parent directory to path for imports
sys.path.insert(0, '/opt/spacyserver')

from notification_service import NotificationService


def get_db_connection():
    """Get database connection using credentials from environment"""
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'spacy_user'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME', 'spacy_email_db')
    )


def get_daily_stats(hours=24):
    """
    Get email filtering statistics for the last N hours
    Returns dict with total_processed, spam_blocked, threats_detected, quarantined
    """
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Calculate time window
        time_threshold = datetime.now() - timedelta(hours=hours)

        # Total emails processed
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM email_analysis
            WHERE timestamp >= %s
        """, (time_threshold,))
        result = cursor.fetchone()
        total_processed = result['total'] if result else 0

        # Spam blocked (high spam scores)
        cursor.execute("""
            SELECT COUNT(*) as spam_count
            FROM email_analysis
            WHERE timestamp >= %s
            AND spam_score >= 50
        """, (time_threshold,))
        result = cursor.fetchone()
        spam_blocked = result['spam_count'] if result else 0

        # Threats detected (high spam scores as proxy for threats)
        cursor.execute("""
            SELECT COUNT(*) as threat_count
            FROM email_analysis
            WHERE timestamp >= %s
            AND spam_score >= 80
        """, (time_threshold,))
        result = cursor.fetchone()
        threats_detected = result['threat_count'] if result else 0

        # Quarantined emails
        cursor.execute("""
            SELECT COUNT(*) as quarantine_count
            FROM email_quarantine
            WHERE timestamp >= %s
        """, (time_threshold,))
        result = cursor.fetchone()
        quarantined = result['quarantine_count'] if result else 0

        return {
            'total_processed': total_processed,
            'spam_blocked': spam_blocked,
            'threats_detected': threats_detected,
            'quarantined': quarantined
        }

    finally:
        cursor.close()
        conn.close()


def main():
    """Send daily summary notification"""
    print("=" * 60)
    print("Daily Notification Summary")
    print("=" * 60)

    # Get statistics
    print("Gathering statistics...")
    stats = get_daily_stats(hours=24)

    print(f"Total processed: {stats['total_processed']}")
    print(f"Spam blocked: {stats['spam_blocked']}")
    print(f"Threats detected: {stats['threats_detected']}")
    print(f"Quarantined: {stats['quarantined']}")

    # Send notification
    print("\nSending notification...")
    service = NotificationService()
    result = service.send_daily_summary(stats)

    print(f"Result: {result}")

    if result.get('status') == 'disabled':
        print("⚠️  Daily summary notifications are disabled in config")
        return 0

    # Check if any notifications were sent successfully
    success_count = 0
    for recipient, recipient_result in result.items():
        if isinstance(recipient_result, dict):
            if recipient_result.get('status') == 'sent':
                success_count += 1
                print(f"✅ Sent to {recipient}")
            else:
                print(f"❌ Failed to send to {recipient}: {recipient_result}")

    print(f"\nSummary: {success_count} notification(s) sent successfully")
    return 0 if success_count > 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
