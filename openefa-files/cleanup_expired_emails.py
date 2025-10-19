#!/usr/bin/env python3
"""
Email Quarantine Cleanup Script
Automatically deletes expired emails from email_quarantine and email_analysis tables
Runs daily via cron: 0 2 * * *
"""

import mysql.connector
import sys
import logging
from datetime import datetime, timedelta
import os

# Set up logging
log_file = '/opt/spacyserver/logs/cleanup.log'
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Get database connection using .my.cnf config"""
    try:
        conn = mysql.connector.connect(
            option_files='/opt/spacyserver/config/.my.cnf',
            option_groups=['client'],
            user='spacy_user',
            database='spacy_email_db'
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_setting(cursor, setting_key, default_value):
    """Get a setting from system_settings table"""
    try:
        cursor.execute("""
            SELECT setting_value
            FROM system_settings
            WHERE setting_key = %s
        """, (setting_key,))
        result = cursor.fetchone()
        if result:
            return result[0]
        return default_value
    except Exception as e:
        logger.warning(f"Error getting setting {setting_key}: {e}. Using default: {default_value}")
        return default_value

def cleanup_quarantine_table(conn, cursor, retention_days):
    """Clean up expired emails from email_quarantine table"""
    try:
        # Count emails to be deleted
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM email_quarantine
            WHERE quarantine_expires_at < NOW()
        """)
        result = cursor.fetchone()
        count_to_delete = result[0] if result else 0

        if count_to_delete == 0:
            logger.info("No expired emails in email_quarantine to delete")
            return 0

        # Delete expired emails
        cursor.execute("""
            DELETE FROM email_quarantine
            WHERE quarantine_expires_at < NOW()
        """)

        deleted_count = cursor.rowcount
        conn.commit()

        logger.info(f"Deleted {deleted_count} expired emails from email_quarantine")
        return deleted_count

    except Exception as e:
        logger.error(f"Error cleaning up email_quarantine: {e}")
        conn.rollback()
        return 0

def cleanup_analysis_table(conn, cursor, retention_days):
    """Clean up old emails from email_analysis table"""
    try:
        # Calculate cutoff date
        cutoff_date = datetime.now() - timedelta(days=retention_days)

        # Count emails to be deleted
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM email_analysis
            WHERE timestamp < %s
        """, (cutoff_date,))
        result = cursor.fetchone()
        count_to_delete = result[0] if result else 0

        if count_to_delete == 0:
            logger.info(f"No emails older than {retention_days} days in email_analysis to delete")
            return 0

        # Delete old emails
        cursor.execute("""
            DELETE FROM email_analysis
            WHERE timestamp < %s
        """, (cutoff_date,))

        deleted_count = cursor.rowcount
        conn.commit()

        logger.info(f"Deleted {deleted_count} emails older than {retention_days} days from email_analysis")
        return deleted_count

    except Exception as e:
        logger.error(f"Error cleaning up email_analysis: {e}")
        conn.rollback()
        return 0

def main():
    """Main cleanup routine"""
    logger.info("=" * 80)
    logger.info("Starting email cleanup process")

    try:
        # Get database connection
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to connect to database. Exiting.")
            sys.exit(1)

        cursor = conn.cursor()

        # Check if cleanup is enabled
        cleanup_enabled = get_setting(cursor, 'cleanup_expired_emails_enabled', 'true')
        if cleanup_enabled.lower() not in ('true', '1', 'yes', 'enabled'):
            logger.info("Cleanup is disabled in system settings. Exiting.")
            cursor.close()
            conn.close()
            sys.exit(0)

        # Get retention days setting
        retention_days_str = get_setting(cursor, 'cleanup_retention_days', '30')
        try:
            retention_days = int(retention_days_str)
        except ValueError:
            logger.warning(f"Invalid retention_days value: {retention_days_str}. Using default: 30")
            retention_days = 30

        logger.info(f"Cleanup enabled: {cleanup_enabled}")
        logger.info(f"Retention days: {retention_days}")

        # Clean up email_quarantine table (uses quarantine_expires_at)
        quarantine_deleted = cleanup_quarantine_table(conn, cursor, retention_days)

        # Clean up email_analysis table (uses timestamp + retention_days)
        analysis_deleted = cleanup_analysis_table(conn, cursor, retention_days)

        total_deleted = quarantine_deleted + analysis_deleted

        # Log cleanup summary
        logger.info(f"Cleanup complete. Total deleted: {total_deleted} emails")
        logger.info(f"  - email_quarantine: {quarantine_deleted} emails")
        logger.info(f"  - email_analysis: {analysis_deleted} emails")

        # Insert cleanup log entry
        try:
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address)
                VALUES (NULL, 'CLEANUP_AUTO_RUN', %s, 'localhost')
            """, (f'Deleted {total_deleted} emails (quarantine: {quarantine_deleted}, analysis: {analysis_deleted})',))
            conn.commit()
        except Exception as e:
            logger.warning(f"Failed to log cleanup to audit_log: {e}")

        cursor.close()
        conn.close()

        logger.info("Email cleanup process completed successfully")
        logger.info("=" * 80)

        # Print summary for cron output
        print(f"Cleanup Summary: Deleted: {total_deleted} emails (quarantine: {quarantine_deleted}, analysis: {analysis_deleted})")

        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error in cleanup process: {e}")
        logger.error("=" * 80)
        sys.exit(1)

if __name__ == "__main__":
    main()
