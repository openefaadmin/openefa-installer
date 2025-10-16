#!/opt/spacyserver/venv/bin/python3
"""
Quarantine Manager Module
Handles email quarantine storage, retrieval, and management
"""

import mysql.connector
import json
import datetime
from typing import Dict, Optional, List
from email.message import EmailMessage
import configparser
import os

class QuarantineManager:
    """Manage email quarantine operations"""

    def __init__(self):
        self.db_config = self._load_db_config()
        self.quarantine_config = self._load_quarantine_config()

    def _load_db_config(self) -> Dict:
        """Load database configuration"""
        try:
            config = configparser.ConfigParser()
            config.read('/opt/spacyserver/config/.my.cnf')
            return {
                'user': config.get('client', 'user', fallback='root'),
                'password': config.get('client', 'password', fallback=''),
                'host': config.get('client', 'host', fallback='localhost'),
                'database': config.get('client', 'database', fallback='spacy_email_db')
            }
        except Exception as e:
            print(f"Error loading database config: {e}")
            return {}

    def _load_quarantine_config(self) -> Dict:
        """Load quarantine configuration"""
        try:
            config_path = '/opt/spacyserver/config/quarantine_config.json'
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                # Default config if file doesn't exist
                return {
                    'retention': {'default_days': 30},
                    'quarantine_triggers': {'spam_score_threshold': 5.0}
                }
        except Exception as e:
            print(f"Error loading quarantine config: {e}")
            return {'retention': {'default_days': 30}}

    def should_quarantine(self, spam_score: float, virus_detected: bool = False,
                         policy_violation: bool = False) -> bool:
        """Determine if email should be quarantined"""
        threshold = self.quarantine_config.get('quarantine_triggers', {}).get('spam_score_threshold', 5.0)

        # Quarantine if:
        # 1. Spam score exceeds threshold
        # 2. Virus detected
        # 3. Policy violation
        if spam_score >= threshold:
            return True
        if virus_detected:
            return True
        if policy_violation:
            return True

        return False

    def store_email(self, msg: EmailMessage, email_data: Dict, analysis_results: Dict) -> Optional[int]:
        """
        Store email in quarantine

        Args:
            msg: EmailMessage object
            email_data: Dict with sender, recipients, subject, etc.
            analysis_results: Dict with spam_score, module results, auth results

        Returns:
            Quarantine ID if successful, None if failed
        """
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            # Extract data
            message_id = email_data.get('message_id', '')
            sender = email_data.get('sender', '')
            sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
            recipients = email_data.get('recipients', [])
            subject = email_data.get('subject', '')
            text_content = email_data.get('text_content', '')

            # Get recipient domains
            recipient_domains = list(set([r.split('@')[-1].lower() for r in recipients if '@' in r]))

            # Spam analysis
            spam_score = analysis_results.get('spam_score', 0.0)
            spam_modules = analysis_results.get('spam_modules', {})
            virus_detected = analysis_results.get('virus_detected', False)
            virus_names = analysis_results.get('virus_names', [])
            phishing_detected = analysis_results.get('phishing_detected', False)

            # Authentication results
            auth_results = analysis_results.get('auth_results', {})
            spf_result = auth_results.get('spf', 'none')
            dkim_result = auth_results.get('dkim', 'none')
            dmarc_result = auth_results.get('dmarc', 'none')
            auth_score = auth_results.get('auth_score', 0.0)

            # Extract attachments info
            has_attachments = False
            attachment_count = 0
            attachment_names = []

            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    has_attachments = True
                    attachment_count += 1
                    filename = part.get_filename()
                    if filename:
                        attachment_names.append(filename)

            # Determine quarantine reason
            if virus_detected:
                reason = 'virus'
            elif spam_score >= 8.0:
                reason = 'spam_high'
            elif spam_score >= 5.0:
                reason = 'spam'
            else:
                reason = 'policy'

            # Calculate expiration (30 days default)
            retention_days = self.quarantine_config.get('retention', {}).get('default_days', 30)
            expires_at = datetime.datetime.now() + datetime.timedelta(days=retention_days)

            # Get email size
            email_size = len(msg.as_string())

            # Get HTML content if exists
            html_content = None
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    try:
                        html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        pass
                    break

            # Insert into quarantine table
            query = """
                INSERT INTO email_quarantine (
                    message_id, timestamp, quarantine_status, quarantine_reason,
                    quarantine_expires_at, sender, sender_domain, recipients,
                    recipient_domains, subject, raw_email, email_size, text_content,
                    html_content, has_attachments, attachment_count, attachment_names,
                    spam_score, spam_modules_detail, virus_detected, virus_names,
                    phishing_detected, spf_result, dkim_result, dmarc_result, auth_score
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """

            values = (
                message_id,
                datetime.datetime.now(),
                'held',
                reason,
                expires_at,
                sender,
                sender_domain,
                json.dumps(recipients),
                json.dumps(recipient_domains),
                subject[:500],  # Truncate subject to 500 chars
                msg.as_string(),
                email_size,
                text_content[:65535] if text_content else None,  # MEDIUMTEXT limit
                html_content[:65535] if html_content else None,
                has_attachments,
                attachment_count,
                json.dumps(attachment_names) if attachment_names else None,
                spam_score,
                json.dumps(spam_modules),
                virus_detected,
                json.dumps(virus_names) if virus_names else None,
                phishing_detected,
                spf_result,
                dkim_result,
                dmarc_result,
                auth_score
            )

            cursor.execute(query, values)
            quarantine_id = cursor.lastrowid

            # Log the action
            log_query = """
                INSERT INTO quarantine_actions_log
                (quarantine_id, action_type, performed_by, user_role, action_details)
                VALUES (%s, %s, %s, %s, %s)
            """

            log_values = (
                quarantine_id,
                'quarantined',
                'system',
                'system',
                json.dumps({
                    'spam_score': float(spam_score),
                    'reason': reason,
                    'timestamp': datetime.datetime.now().isoformat()
                })
            )

            cursor.execute(log_query, log_values)
            conn.commit()

            print(f"✅ Email quarantined: {message_id} (ID: {quarantine_id}, Score: {spam_score})")
            return quarantine_id

        except mysql.connector.Error as e:
            print(f"❌ Database error storing quarantine: {e}")
            if conn:
                conn.rollback()
            return None
        except Exception as e:
            print(f"❌ Error storing quarantine: {e}")
            if conn:
                conn.rollback()
            return None
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def get_quarantine_count(self, status: str = 'held') -> int:
        """Get count of quarantined emails"""
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            query = """
                SELECT COUNT(*) FROM email_quarantine
                WHERE quarantine_status = %s
                AND quarantine_expires_at > NOW()
            """

            cursor.execute(query, (status,))
            count = cursor.fetchone()[0]
            return count

        except Exception as e:
            print(f"Error getting quarantine count: {e}")
            return 0
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def get_release_destination(self) -> Dict:
        """Get configured release destination"""
        mode = self.quarantine_config.get('release_destination', {}).get('mode', 'mailguard')

        if mode == 'mailguard':
            dest = self.quarantine_config.get('release_destination', {}).get('mailguard', {})
        else:
            dest = self.quarantine_config.get('release_destination', {}).get('zimbra', {})

        return {
            'mode': mode,
            'host': dest.get('host', 'YOUR_RELAY_SERVER'),
            'port': dest.get('port', 25),
            'timeout': dest.get('timeout', 30),
            'use_tls': dest.get('use_tls', False)
        }


# Singleton instance
_quarantine_manager = None

def get_quarantine_manager() -> QuarantineManager:
    """Get singleton quarantine manager instance"""
    global _quarantine_manager
    if _quarantine_manager is None:
        _quarantine_manager = QuarantineManager()
    return _quarantine_manager
