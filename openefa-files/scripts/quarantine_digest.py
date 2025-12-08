#!/usr/bin/env python3
"""
Quarantine Digest Generator
Sends periodic email digests to users listing their quarantined emails
"""

import sys
import os
import json
import logging
import argparse
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, '/opt/spacyserver')

import mysql.connector
from mysql.connector import Error
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template, Environment, FileSystemLoader
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Configuration paths
CONFIG_PATH = '/opt/spacyserver/config/digest_config.json'
TEMPLATE_PATH = '/opt/spacyserver/web/templates'
MY_CNF_PATH = '/etc/spacy-server/.my.cnf'

class QuarantineDigestGenerator:
    """Generate and send quarantine digest emails to users"""

    def __init__(self, config_path=CONFIG_PATH, dry_run=False):
        """Initialize the digest generator"""
        self.config = self._load_config(config_path)
        self.dry_run = dry_run
        self._setup_logging()
        self.db_conn = None
        self.jinja_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH))

    def _load_config(self, config_path):
        """Load configuration from JSON file"""
        with open(config_path, 'r') as f:
            return json.load(f)

    def _setup_logging(self):
        """Set up logging to file and console"""
        log_file = self.config['logging']['log_file']
        log_level = getattr(logging, self.config['logging']['log_level'])

        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def _get_db_connection(self):
        """Get database connection using .my.cnf credentials"""
        if self.db_conn and self.db_conn.is_connected():
            return self.db_conn

        try:
            self.db_conn = mysql.connector.connect(
                option_files=MY_CNF_PATH,
                option_groups='client',
                database=os.getenv('DB_NAME', 'spacy_email_db')
            )
            return self.db_conn
        except Error as e:
            self.logger.error(f"Database connection error: {e}")
            raise

    def get_users_for_digest(self, frequency='daily', current_time=None):
        """
        Get list of users who should receive digest at this time

        Args:
            frequency: 'daily', 'weekly', or 'realtime'
            current_time: datetime object (defaults to now)

        Returns:
            List of user dictionaries with preferences
        """
        if current_time is None:
            current_time = datetime.now()

        conn = self._get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Base query for enabled users with specified frequency
        query = """
            SELECT
                uqn.*,
                u.first_name,
                u.last_name,
                u.company_name,
                u.authorized_domains,
                u.role
            FROM user_quarantine_notifications uqn
            JOIN users u ON uqn.user_id = u.id
            WHERE uqn.enabled = 1
              AND uqn.frequency = %s
              AND u.is_active = 1
        """

        # For daily digests, check delivery time
        if frequency == 'daily':
            # Allow 15-minute window around scheduled time
            current_time_str = current_time.strftime('%H:%M:%S')
            query += """
                AND TIME(uqn.delivery_time) BETWEEN
                    SUBTIME(%s, '00:15:00') AND ADDTIME(%s, '00:15:00')
            """
            cursor.execute(query, (frequency, current_time_str, current_time_str))

        # For weekly digests, check both day and time
        elif frequency == 'weekly':
            current_day = current_time.isoweekday()  # 1=Monday, 7=Sunday
            current_time_str = current_time.strftime('%H:%M:%S')
            query += """
                AND uqn.delivery_day = %s
                AND TIME(uqn.delivery_time) BETWEEN
                    SUBTIME(%s, '00:15:00') AND ADDTIME(%s, '00:15:00')
            """
            cursor.execute(query, (frequency, current_day, current_time_str, current_time_str))

        # For realtime, just get enabled users
        else:
            cursor.execute(query, (frequency,))

        users = cursor.fetchall()
        cursor.close()

        self.logger.info(f"Found {len(users)} users for {frequency} digest at {current_time}")
        return users

    def get_quarantine_emails_for_user(self, user_preferences):
        """
        Get quarantined emails for a specific user based on their permissions

        Args:
            user_preferences: Dictionary with user_id, domain, authorized_domains, preferences

        Returns:
            List of email dictionaries
        """
        conn = self._get_db_connection()
        cursor = conn.cursor(dictionary=True)

        user_id = user_preferences['user_id']
        domain = user_preferences['domain']
        user_email = user_preferences['email']
        user_role = user_preferences.get('role', 'client')
        min_spam_score = float(user_preferences['min_spam_score'])
        max_emails = int(user_preferences['max_emails'])
        include_released = bool(user_preferences.get('include_released', False))

        # Get authorized domains for multi-domain support (domain_admin/admin)
        authorized_domains = []
        if user_preferences.get('authorized_domains'):
            authorized_domains = [d.strip() for d in user_preferences['authorized_domains'].split(',') if d.strip()]

        # Ensure primary domain is included
        if domain and domain not in authorized_domains:
            authorized_domains.append(domain)

        # Get managed aliases for client role users
        managed_aliases = []
        if user_role == 'client':
            cursor_temp = self._get_db_connection().cursor(dictionary=True)
            cursor_temp.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (user_id,))
            managed_aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
            cursor_temp.close()

        # Determine time window based on frequency
        frequency = user_preferences.get('frequency', 'daily')
        if frequency == 'daily':
            time_window_hours = 24
        elif frequency == 'weekly':
            time_window_hours = 168  # 7 days
        else:
            time_window_hours = 1  # realtime = last hour

        # Build query based on user permissions
        # Disposition filter: quarantined (with time window), or quarantined + released (last 7 days) if include_released is enabled
        # Note: Released emails don't need spam score filter (they were already approved)
        if include_released:
            disposition_clause = "((e.disposition = 'quarantined' AND e.spam_score >= %s AND e.timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)) OR (e.disposition = 'released' AND e.timestamp >= DATE_SUB(NOW(), INTERVAL 168 HOUR)))"
            params = [min_spam_score, time_window_hours]
        else:
            disposition_clause = "(e.disposition = 'quarantined' AND e.spam_score >= %s AND e.timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR))"
            params = [min_spam_score, time_window_hours]

        query = f"""
            SELECT
                e.id,
                e.sender,
                e.subject,
                e.recipients,
                e.timestamp,
                e.spam_score,
                e.disposition,
                e.message_id
            FROM email_analysis e
            WHERE {disposition_clause}
        """

        # Add filtering based on user role
        if user_role == 'client':
            # CLIENT ROLE: Only show emails sent by OR received by this specific user or their aliases
            email_conditions = []

            # Check sender = user
            email_conditions.append("e.sender = %s")
            params.append(user_email)

            # Check recipients contains user email
            email_conditions.append("e.recipients LIKE %s")
            params.append(f'%{user_email}%')

            # Check recipients contains any managed alias
            for alias in managed_aliases:
                email_conditions.append("e.recipients LIKE %s")
                params.append(f'%{alias}%')

            query += " AND (" + " OR ".join(email_conditions) + ")"
        else:
            # DOMAIN_ADMIN/ADMIN ROLE: Show emails for ALL authorized domains
            if authorized_domains:
                domain_conditions = []
                for auth_domain in authorized_domains:
                    domain_conditions.append("e.recipients LIKE %s")
                    params.append(f'%@{auth_domain}%')

                query += " AND (" + " OR ".join(domain_conditions) + ")"
            else:
                # Fallback to primary domain only
                query += " AND e.recipients LIKE %s"
                params.append(f'%@{domain}%')

        # Order by most recent first
        query += " ORDER BY e.timestamp DESC LIMIT %s"
        params.append(max_emails)

        cursor.execute(query, params)
        emails = cursor.fetchall()
        cursor.close()

        if user_role == 'client':
            alias_info = f" + {len(managed_aliases)} aliases" if managed_aliases else ""
            self.logger.info(f"Found {len(emails)} quarantined emails for client user {user_id} ({user_email}{alias_info}) in last {time_window_hours} hours")
        else:
            self.logger.info(f"Found {len(emails)} quarantined emails for {user_role} user {user_id} in last {time_window_hours} hours (domains: {', '.join(authorized_domains)})")
        return emails

    def generate_secure_token(self, user_id, email_id, action, expires_hours=72):
        """
        Generate secure token for action link

        Args:
            user_id: User ID
            email_id: Email ID
            action: 'release', 'whitelist', 'delete', 'view'
            expires_hours: Token expiration in hours

        Returns:
            Token string
        """
        # Generate cryptographically secure random token
        token = secrets.token_urlsafe(32)  # 256 bits

        # Calculate expiration
        expires_at = datetime.now() + timedelta(hours=expires_hours)

        # Store token in database
        conn = self._get_db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO quarantine_digest_tokens
            (token, user_id, email_id, action, expires_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (token, user_id, email_id, action, expires_at))
        conn.commit()
        cursor.close()

        self.logger.debug(f"Generated token for user {user_id}, email {email_id}, action {action}")
        return token

    def generate_digest_html(self, user, emails, preferences):
        """
        Generate HTML email digest

        Args:
            user: User dictionary with name, email, domain
            emails: List of quarantined emails
            preferences: User preferences dictionary

        Returns:
            HTML string
        """
        # Load template
        template = self.jinja_env.get_template('quarantine_digest_email.html')

        # Prepare email data with tokens and extract recipient domain
        email_data = []
        for email in emails:
            # Generate tokens for this email
            release_token = self.generate_secure_token(
                user['user_id'],
                email['id'],
                'release',
                self.config['token_settings']['expiration_hours']
            ) if self.config['features']['click_to_release'] else None

            whitelist_token = self.generate_secure_token(
                user['user_id'],
                email['id'],
                'whitelist',
                self.config['token_settings']['expiration_hours']
            ) if self.config['features']['click_to_whitelist'] else None

            # Format timestamp
            timestamp = email['timestamp']
            if isinstance(timestamp, datetime):
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M')
            else:
                timestamp_str = str(timestamp)

            # Extract recipient domain for grouping
            recipient_domain = 'unknown'
            recipients_str = email.get('recipients', '')
            if recipients_str:
                # Parse recipients (could be JSON array or CSV string)
                import json
                try:
                    recipients = json.loads(recipients_str)
                except:
                    recipients = [r.strip() for r in recipients_str.split(',') if r.strip()]

                # Get domain from first recipient
                if recipients and '@' in str(recipients[0]):
                    recipient_domain = str(recipients[0]).split('@')[1].lower()

            email_data.append({
                'id': email['id'],
                'sender': email['sender'] or 'Unknown',
                'subject': email['subject'] or '(No Subject)',
                'timestamp': timestamp_str,
                'spam_score': float(email['spam_score']),
                'release_token': release_token,
                'whitelist_token': whitelist_token,
                'recipient_domain': recipient_domain,
                'disposition': email['disposition']
            })

        # Calculate date range
        frequency = preferences['frequency']
        if frequency == 'daily':
            start_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')
        elif frequency == 'weekly':
            start_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')
        else:
            start_date = datetime.now().strftime('%Y-%m-%d')
            end_date = datetime.now().strftime('%Y-%m-%d')

        # Calculate average spam score
        avg_spam_score = None
        if emails:
            total_score = sum(float(e['spam_score']) for e in emails)
            avg_spam_score = total_score / len(emails)

        # Group emails by recipient domain
        from collections import defaultdict
        emails_by_domain = defaultdict(list)
        for email in email_data:
            emails_by_domain[email['recipient_domain']].append(email)

        # Sort domains alphabetically
        sorted_domains = sorted(emails_by_domain.keys())

        # Render template
        html = template.render(
            user=user,
            domain=user['domain'],
            frequency=frequency,
            email_count=len(emails),
            emails=email_data,
            emails_by_domain=emails_by_domain,
            sorted_domains=sorted_domains,
            start_date=start_date,
            end_date=end_date,
            avg_spam_score=avg_spam_score,
            base_url=self.config['urls']['base_url'],
            action_path=self.config['urls']['action_path'],
            settings_path=self.config['urls']['settings_path'],
            quarantine_path=self.config['urls']['quarantine_path'],
            release_enabled=self.config['features']['click_to_release'],
            whitelist_enabled=self.config['features']['click_to_whitelist'],
            token_expiration_hours=self.config['token_settings']['expiration_hours']
        )

        return html

    def send_digest_email(self, user, html_content):
        """
        Send digest email via SMTP

        Args:
            user: User dictionary with email address
            html_content: HTML email body

        Returns:
            (success: bool, error_message: str or None)
        """
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would send digest to {user['email']}")
            return True, None

        try:
            smtp_config = self.config['smtp']

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"OpenEFA Quarantine Digest - {user['domain']}"
            msg['From'] = f"{smtp_config['from_name']} <{smtp_config['from_address']}>"
            msg['To'] = user['email']

            # Attach HTML
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)

            # Send via SMTP
            with smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=smtp_config['timeout']) as server:
                if smtp_config.get('use_tls'):
                    server.starttls()

                server.send_message(msg)

            self.logger.info(f"✅ Sent digest to {user['email']}")
            return True, None

        except Exception as e:
            self.logger.error(f"❌ Failed to send digest to {user['email']}: {e}")
            return False, str(e)

    def log_digest_sent(self, user, email_count, status='sent', error_message=None):
        """
        Log digest delivery to database

        Args:
            user: User dictionary
            email_count: Number of emails in digest
            status: 'sent', 'failed', or 'bounced'
            error_message: Error details if failed
        """
        conn = self._get_db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO quarantine_digest_log
            (user_id, email, domain, frequency, email_count, status, error_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            user['user_id'],
            user['email'],
            user['domain'],
            user['frequency'],
            email_count,
            status,
            error_message
        ))
        conn.commit()
        cursor.close()

        # Update last_sent_at in user preferences
        cursor = conn.cursor()
        query = """
            UPDATE user_quarantine_notifications
            SET last_sent_at = NOW(), last_email_count = %s
            WHERE user_id = %s
        """
        cursor.execute(query, (email_count, user['user_id']))
        conn.commit()
        cursor.close()

    def process_user_digest(self, user):
        """
        Process digest for a single user

        Args:
            user: User dictionary with preferences

        Returns:
            (success: bool, email_count: int)
        """
        try:
            # Get quarantined emails for this user
            emails = self.get_quarantine_emails_for_user(user)

            # Skip if no emails and min_emails_for_digest is set
            min_emails = self.config['digest_limits'].get('min_emails_for_digest', 1)
            if len(emails) < min_emails:
                self.logger.info(f"Skipping digest for {user['email']} - only {len(emails)} emails (min: {min_emails})")
                return True, 0

            # Generate HTML digest
            html_content = self.generate_digest_html(user, emails, user)

            # Send email
            success, error_msg = self.send_digest_email(user, html_content)

            # Log to database
            status = 'sent' if success else 'failed'
            self.log_digest_sent(user, len(emails), status, error_msg)

            return success, len(emails)

        except Exception as e:
            self.logger.error(f"Error processing digest for user {user['user_id']}: {e}")
            self.log_digest_sent(user, 0, 'failed', str(e))
            return False, 0

    def run(self, frequency='daily'):
        """
        Main entry point - run digest generation for specified frequency

        Args:
            frequency: 'daily', 'weekly', or 'realtime'
        """
        self.logger.info(f"Starting {frequency} digest generation")

        if not self.config['enabled']:
            self.logger.warning("Digest system is disabled in configuration")
            return

        # Get users who should receive digest
        users = self.get_users_for_digest(frequency)

        if not users:
            self.logger.info(f"No users scheduled for {frequency} digest at this time")
            return

        # Process each user
        success_count = 0
        failure_count = 0
        total_emails = 0

        for user in users:
            success, email_count = self.process_user_digest(user)
            if success:
                success_count += 1
                total_emails += email_count
            else:
                failure_count += 1

        # Summary
        self.logger.info(f"Digest generation complete:")
        self.logger.info(f"  - Total users: {len(users)}")
        self.logger.info(f"  - Successful: {success_count}")
        self.logger.info(f"  - Failed: {failure_count}")
        self.logger.info(f"  - Total emails in digests: {total_emails}")

    def cleanup_expired_tokens(self):
        """Remove expired tokens from database"""
        conn = self._get_db_connection()
        cursor = conn.cursor()

        query = "DELETE FROM quarantine_digest_tokens WHERE expires_at < NOW()"
        cursor.execute(query)
        deleted_count = cursor.rowcount
        conn.commit()
        cursor.close()

        self.logger.info(f"Cleaned up {deleted_count} expired tokens")

    def close(self):
        """Close database connection"""
        if self.db_conn and self.db_conn.is_connected():
            self.db_conn.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Generate and send quarantine digest emails')
    parser.add_argument('--frequency', choices=['daily', 'weekly', 'realtime'], default='daily',
                        help='Digest frequency to process')
    parser.add_argument('--dry-run', action='store_true',
                        help='Dry run mode - do not send emails')
    parser.add_argument('--cleanup-tokens', action='store_true',
                        help='Clean up expired tokens and exit')
    parser.add_argument('--config', default=CONFIG_PATH,
                        help='Path to configuration file')

    args = parser.parse_args()

    try:
        generator = QuarantineDigestGenerator(config_path=args.config, dry_run=args.dry_run)

        if args.cleanup_tokens:
            generator.cleanup_expired_tokens()
        else:
            generator.run(frequency=args.frequency)

        generator.close()

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
