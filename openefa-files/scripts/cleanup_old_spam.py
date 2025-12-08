#!/usr/bin/env python3
"""
Auto Soft-Delete Old Spam Emails
Marks high-scoring spam emails as deleted based on age and spam score.
This is a SOFT delete - emails remain in database and viewable via "Show Deleted".
Hard deletion happens after 30 days via separate cleanup process.

Tiered Policy:
- Score >= 15.0: Soft delete after 7 days
- Score 10.0-14.9: Soft delete after 30 days
- Score 6.0-9.9: Soft delete after 90 days
- Score < 6.0: Never auto-deleted
"""

import sys
import os
import logging
from datetime import datetime, timedelta
import mysql.connector
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
env_path = '/etc/spacy-server/.env'
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    logger.error(f"Environment file not found: {env_path}")
    sys.exit(1)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306))
}

def get_spam_threshold():
    """Get spam threshold from environment or default to 10.0"""
    try:
        return float(os.getenv('SPACY_SPAM_THRESHOLD', '10.0'))
    except ValueError:
        logger.warning("Invalid SPACY_SPAM_THRESHOLD in environment, using default 10.0")
        return 10.0

def soft_delete_old_spam(dry_run=False):
    """
    Soft delete old spam emails based on score and age.

    Args:
        dry_run: If True, only count emails that would be deleted without actually deleting

    Returns:
        dict: Statistics of emails processed
    """
    spam_threshold = get_spam_threshold()

    # Calculate date thresholds
    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)
    ninety_days_ago = now - timedelta(days=90)

    stats = {
        'very_high_spam': 0,  # >= 15.0, > 7 days old
        'high_spam': 0,       # 10.0-14.9, > 30 days old
        'suspicious': 0,      # 6.0-9.9, > 90 days old
        'total': 0,
        'errors': 0
    }

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Query to find emails to soft delete
        # Only soft delete if not already deleted and not quarantined
        query = """
            SELECT id, spam_score, timestamp, subject, sender
            FROM email_analysis
            WHERE is_deleted = 0
                AND (disposition IS NULL OR disposition != 'deleted')
                AND disposition != 'quarantined'
                AND (
                    (spam_score >= 15.0 AND timestamp < %s)
                    OR (spam_score >= 10.0 AND spam_score < 15.0 AND timestamp < %s)
                    OR (spam_score >= 6.0 AND spam_score < 10.0 AND timestamp < %s)
                )
            ORDER BY spam_score DESC, timestamp ASC
        """

        cursor.execute(query, (seven_days_ago, thirty_days_ago, ninety_days_ago))
        emails_to_delete = cursor.fetchall()

        logger.info(f"Found {len(emails_to_delete)} emails to soft delete")

        if dry_run:
            # Just count and categorize
            for email in emails_to_delete:
                score = email['spam_score']
                if score >= 15.0:
                    stats['very_high_spam'] += 1
                elif score >= 10.0:
                    stats['high_spam'] += 1
                elif score >= 6.0:
                    stats['suspicious'] += 1
                stats['total'] += 1

            logger.info(f"DRY RUN - Would soft delete:")
            logger.info(f"  Very High Spam (>=15.0, >7 days): {stats['very_high_spam']}")
            logger.info(f"  High Spam (10.0-14.9, >30 days): {stats['high_spam']}")
            logger.info(f"  Suspicious (6.0-9.9, >90 days): {stats['suspicious']}")
            logger.info(f"  Total: {stats['total']}")
        else:
            # Actually perform soft delete
            update_query = """
                UPDATE email_analysis
                SET disposition = 'deleted',
                    is_deleted = 1
                WHERE id = %s
            """

            for email in emails_to_delete:
                try:
                    cursor.execute(update_query, (email['id'],))
                    score = email['spam_score']

                    if score >= 15.0:
                        stats['very_high_spam'] += 1
                    elif score >= 10.0:
                        stats['high_spam'] += 1
                    elif score >= 6.0:
                        stats['suspicious'] += 1
                    stats['total'] += 1

                    logger.debug(f"Soft deleted: ID={email['id']}, Score={score:.1f}, Subject={email['subject'][:50]}")

                except Exception as e:
                    logger.error(f"Error soft deleting email ID {email['id']}: {e}")
                    stats['errors'] += 1

            conn.commit()
            logger.info(f"Successfully soft deleted {stats['total']} emails")
            logger.info(f"  Very High Spam (>=15.0, >7 days): {stats['very_high_spam']}")
            logger.info(f"  High Spam (10.0-14.9, >30 days): {stats['high_spam']}")
            logger.info(f"  Suspicious (6.0-9.9, >90 days): {stats['suspicious']}")
            if stats['errors'] > 0:
                logger.warning(f"  Errors: {stats['errors']}")

        cursor.close()
        conn.close()

    except mysql.connector.Error as e:
        logger.error(f"Database error: {e}")
        stats['errors'] += 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        stats['errors'] += 1

    return stats

if __name__ == '__main__':
    # Check for dry-run flag
    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv

    if dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
    else:
        logger.info("Running spam cleanup - emails will be soft deleted")

    stats = soft_delete_old_spam(dry_run=dry_run)

    if stats['errors'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)
