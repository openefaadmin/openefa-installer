#!/opt/spacyserver/venv/bin/python3
"""
Reprocess Sentiment Analysis for Existing Emails
Analyzes all emails with sentiment_polarity = 0 and updates the database
"""

import sys
import os
sys.path.insert(0, '/opt/spacyserver')

import pymysql
import logging
from datetime import datetime

# Import the sentiment analyzer
from modules.email_sentiment import sentiment_analyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Connect to MySQL database"""
    return pymysql.connect(
        read_default_file='/etc/spacy-server/.my.cnf',
        database=os.getenv('DB_NAME', 'spacy_email_db'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

def reprocess_sentiment_analysis(limit=None, dry_run=False):
    """
    Reprocess sentiment analysis for emails with sentiment_polarity = 0

    Args:
        limit: Maximum number of emails to process (None = all)
        dry_run: If True, don't actually update the database
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Count emails needing sentiment analysis
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM email_analysis
            WHERE sentiment_polarity = 0 OR sentiment_polarity IS NULL
        """)
        total_count = cursor.fetchone()['total']

        logger.info(f"Found {total_count} emails needing sentiment analysis")

        if total_count == 0:
            logger.info("No emails need processing!")
            return

        # Get emails that need sentiment analysis
        query = """
            SELECT id, subject, content_summary
            FROM email_analysis
            WHERE sentiment_polarity = 0 OR sentiment_polarity IS NULL
            ORDER BY id ASC
        """

        if limit:
            query += f" LIMIT {int(limit)}"

        cursor.execute(query)
        emails = cursor.fetchall()

        logger.info(f"Processing {len(emails)} emails...")

        processed = 0
        updated = 0
        errors = 0

        for email in emails:
            try:
                # Prepare email data for sentiment analysis
                email_data = {
                    'subject': email.get('subject', ''),
                    'body': email.get('content_summary', '')
                }

                # Run sentiment analysis
                sentiment_results = sentiment_analyzer.analyze_email_sentiment(email_data)

                if sentiment_results:
                    # Calculate values to store
                    polarity = sentiment_results.get('polarity', 0.0)
                    subjectivity = sentiment_results.get('subjectivity', 0.0)
                    extremity = abs(polarity)  # Use absolute value of polarity as extremity

                    # Determine manipulation score based on manipulation_risk
                    manipulation_risk = sentiment_results.get('manipulation_risk', 'low')
                    if manipulation_risk == 'high':
                        manipulation_score = 0.8
                    elif manipulation_risk == 'medium':
                        manipulation_score = 0.5
                    else:
                        manipulation_score = 0.2

                    if not dry_run:
                        # Update the database
                        update_query = """
                            UPDATE email_analysis
                            SET sentiment_polarity = %s,
                                sentiment_subjectivity = %s,
                                sentiment_extremity = %s,
                                sentiment_manipulation = %s
                            WHERE id = %s
                        """
                        cursor.execute(update_query, (
                            polarity,
                            subjectivity,
                            extremity,
                            manipulation_score,
                            email['id']
                        ))
                        updated += 1
                    else:
                        logger.info(f"[DRY RUN] Email {email['id']}: polarity={polarity:.3f}, subjectivity={subjectivity:.3f}")
                        updated += 1

                    processed += 1

                    # Commit every 50 emails
                    if processed % 50 == 0:
                        if not dry_run:
                            conn.commit()
                        logger.info(f"Progress: {processed}/{len(emails)} emails processed, {updated} updated")

                else:
                    logger.warning(f"No sentiment results for email {email['id']}")
                    errors += 1

            except Exception as e:
                logger.error(f"Error processing email {email['id']}: {e}")
                errors += 1

        # Final commit
        if not dry_run:
            conn.commit()

        logger.info("=" * 60)
        logger.info(f"SUMMARY:")
        logger.info(f"  Total emails processed: {processed}")
        logger.info(f"  Successfully updated: {updated}")
        logger.info(f"  Errors: {errors}")
        if dry_run:
            logger.info(f"  MODE: DRY RUN (no database changes made)")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Reprocess sentiment analysis for existing emails')
    parser.add_argument('--limit', type=int, help='Limit number of emails to process')
    parser.add_argument('--dry-run', action='store_true', help='Test run without updating database')
    parser.add_argument('--all', action='store_true', help='Process all emails (confirms you want to process all)')

    args = parser.parse_args()

    # Safety check
    if not args.limit and not args.all and not args.dry_run:
        print("ERROR: Please specify either --limit N, --all, or --dry-run")
        print("\nExamples:")
        print("  Test with 10 emails: python3 reprocess_sentiment.py --limit 10 --dry-run")
        print("  Process 100 emails:  python3 reprocess_sentiment.py --limit 100")
        print("  Process all emails:  python3 reprocess_sentiment.py --all")
        sys.exit(1)

    logger.info("Starting sentiment analysis reprocessing...")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info(f"Limit: {args.limit or 'None (all emails)'}")

    reprocess_sentiment_analysis(limit=args.limit, dry_run=args.dry_run)
    logger.info("Done!")
