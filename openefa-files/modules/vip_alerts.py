#!/usr/bin/env python3
"""
VIP Email Alert System - SMS Notification Module
Integrates with email_filter.py to send SMS alerts for VIP senders
"""

import os
import sys
import json
import logging
from datetime import datetime, time
from typing import Optional, Dict, Tuple
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor
import requests

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Setup logging
logger = logging.getLogger(__name__)

class VIPAlertSystem:
    """Handles VIP sender detection and SMS alert delivery"""

    def __init__(self, db_config: Optional[Dict] = None, clicksend_config: Optional[Dict] = None):
        """
        Initialize VIP alert system

        Args:
            db_config: Database connection config (optional, loads from .my.cnf if not provided)
            clicksend_config: ClickSend API credentials (optional, loads from env if not provided)
        """
        # Load DB config
        if db_config:
            self.db_config = db_config
        else:
            self.db_config = self._load_db_config()

        # Load ClickSend config
        if clicksend_config:
            self.clicksend_username = clicksend_config.get('username')
            self.clicksend_api_key = clicksend_config.get('api_key')
        else:
            self.clicksend_username = os.getenv('CLICKSEND_USERNAME')
            self.clicksend_api_key = os.getenv('CLICKSEND_API_KEY')

        self.clicksend_enabled = os.getenv('CLICKSEND_ENABLED', 'true').lower() == 'true'
        self.clicksend_base_url = 'https://rest.clicksend.com/v3'
        self.per_alert_price = 0.20  # $0.20 per alert

    def _load_db_config(self) -> Dict:
        """Load database config from .my.cnf"""
        config_path = '/opt/spacyserver/config/.my.cnf'
        if os.path.exists(config_path):
            config = {}
            with open(config_path, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('['):
                        key, value = line.strip().split('=', 1)
                        config[key.strip()] = value.strip().strip('"')

            return {
                'host': config.get('host', os.getenv('DB_HOST', 'localhost')),
                'user': config.get('user', os.getenv('DB_USER', 'spacy_user')),
                'password': config.get('password', ''),
                'database': config.get('database', os.getenv('DB_NAME', 'spacy_email_db'))
            }
        else:
            return {
                'host': os.getenv('DB_HOST', 'localhost'),
                'user': os.getenv('DB_USER', 'spacy_user'),
                'password': os.getenv('DB_PASSWORD', ''),
                'database': os.getenv('DB_NAME', 'spacy_email_db')
            }

    def get_db_connection(self):
        """Get database connection"""
        return pymysql.connect(
            **self.db_config,
            cursorclass=DictCursor,
            charset='utf8mb4'
        )

    def check_vip_sender(self, recipient_email: str, sender_email: str,
                        message_id: str, subject: str, spam_score: float,
                        client_domain_id: int) -> bool:
        """
        Check if sender is VIP and send alert if configured

        Args:
            recipient_email: Email address receiving the message
            sender_email: Email address that sent the message
            message_id: Unique message ID
            subject: Email subject line
            spam_score: Calculated spam score
            client_domain_id: Client domain ID

        Returns:
            True if alert was sent, False otherwise
        """
        conn = None
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Find matching VIP sender configuration
            cursor.execute("""
                SELECT
                    id, vip_sender_name, mobile_number, alert_enabled,
                    alert_hours_start, alert_hours_end,
                    max_alerts_per_hour, min_spam_score_threshold
                FROM vip_senders
                WHERE user_email = %s
                AND vip_sender_email = %s
                AND client_domain_id = %s
                AND alert_enabled = TRUE
            """, (recipient_email, sender_email, client_domain_id))

            vip_config = cursor.fetchone()
            if not vip_config:
                return False

            vip_sender_id = vip_config['id']

            # Check spam score threshold
            if spam_score >= vip_config['min_spam_score_threshold']:
                self._log_alert(
                    cursor, vip_sender_id, message_id, sender_email,
                    recipient_email, subject, spam_score,
                    vip_config['mobile_number'], client_domain_id,
                    status='spam_filtered',
                    error_msg=f"Spam score {spam_score} >= threshold {vip_config['min_spam_score_threshold']}"
                )
                conn.commit()
                logger.info(f"VIP alert skipped for {message_id} - spam score too high ({spam_score})")
                return False

            # Check rate limits and quiet hours using stored procedure
            cursor.callproc('check_vip_alert_allowed',
                          (vip_sender_id, datetime.now(), 0, ''))

            # Get procedure output
            cursor.execute("SELECT @_check_vip_alert_allowed_2 as allowed, @_check_vip_alert_allowed_3 as reason")
            result = cursor.fetchone()

            allowed = result['allowed']
            reason = result['reason']

            if not allowed:
                # Log why alert was blocked
                status_map = {
                    'Outside quiet hours': 'quiet_hours',
                    'Rate limit exceeded': 'rate_limited',
                    'Alerts disabled': 'spam_filtered'
                }
                self._log_alert(
                    cursor, vip_sender_id, message_id, sender_email,
                    recipient_email, subject, spam_score,
                    vip_config['mobile_number'], client_domain_id,
                    status=status_map.get(reason, 'spam_filtered'),
                    error_msg=reason
                )
                conn.commit()
                logger.info(f"VIP alert blocked for {message_id}: {reason}")
                return False

            # All checks passed - send SMS
            success = self._send_sms_alert(
                cursor, vip_sender_id, message_id, sender_email,
                recipient_email, subject, spam_score,
                vip_config['mobile_number'],
                vip_config['vip_sender_name'],
                client_domain_id
            )

            if success:
                # Update rate limit counter
                cursor.callproc('record_alert_rate_limit',
                              (vip_sender_id, datetime.now()))
                conn.commit()
                logger.info(f"VIP alert sent successfully for {message_id}")

            return success

        except Exception as e:
            logger.error(f"Error checking VIP sender: {e}", exc_info=True)
            return False
        finally:
            if conn:
                conn.close()

    def check_vip_recipient(self, recipient_email: str, sender_email: str,
                           message_id: str, subject: str, spam_score: float,
                           client_domain_id: int, quarantine_reason: str = None) -> bool:
        """
        Check if recipient is monitored (VIP) and send alert when email is quarantined

        Args:
            recipient_email: Email address receiving the message (MONITORED ADDRESS)
            sender_email: Email address that sent the message
            message_id: Unique message ID
            subject: Email subject line
            spam_score: Calculated spam score
            client_domain_id: Client domain ID
            quarantine_reason: Why email was quarantined

        Returns:
            True if alert was sent, False otherwise
        """
        conn = None
        try:
            import syslog
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Checking {recipient_email} for domain_id={client_domain_id}, score={spam_score}")
            conn = self.get_db_connection()
            cursor = conn.cursor()

            # Find matching VIP recipient configuration
            cursor.execute("""
                SELECT
                    id, user_email, monitored_recipient_name, mobile_number, alert_enabled,
                    alert_hours_start, alert_hours_end,
                    max_alerts_per_hour, min_spam_score_threshold, alert_on_quarantine
                FROM vip_recipients
                WHERE monitored_recipient_email = %s
                AND client_domain_id = %s
                AND alert_enabled = TRUE
                AND alert_on_quarantine = TRUE
            """, (recipient_email, client_domain_id))

            vip_config = cursor.fetchone()
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Config found: {vip_config is not None}")
            if not vip_config:
                syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: No config found for {recipient_email}")
                return False

            vip_recipient_id = vip_config['id']
            alert_user_email = vip_config['user_email']
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: vip_recipient_id={vip_recipient_id}, alert_user_email={alert_user_email}")

            # Check spam score threshold
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Checking spam score: {spam_score} >= {vip_config['min_spam_score_threshold']}")
            if spam_score < vip_config['min_spam_score_threshold']:
                syslog.syslog(syslog.LOG_INFO, f"VIP recipient alert skipped for {message_id} - spam score too low ({spam_score} < {vip_config['min_spam_score_threshold']})")
                return False
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Spam score check PASSED")

            # Check rate limits and quiet hours
            # Note: We'll use a simplified rate limit check since this is for recipients, not senders
            # Check how many alerts sent in the last hour
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Checking rate limits...")
            cursor.execute("""
                SELECT COUNT(*) as recent_alerts
                FROM sms_alert_log
                WHERE client_domain_id = %s
                AND recipient_email = %s
                AND delivery_status = 'sent'
                AND sent_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (client_domain_id, alert_user_email))

            result = cursor.fetchone()
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Recent alerts: {result['recent_alerts']}/{vip_config['max_alerts_per_hour']}")
            if result['recent_alerts'] >= vip_config['max_alerts_per_hour']:
                syslog.syslog(syslog.LOG_INFO, f"VIP recipient alert rate limited for {message_id}")
                return False
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Rate limit check PASSED")

            # Check quiet hours
            now = datetime.now()
            current_time = now.time()

            # Convert timedelta to time if needed (MySQL TIME type returns timedelta)
            from datetime import timedelta
            alert_start = vip_config['alert_hours_start']
            if isinstance(alert_start, timedelta):
                alert_start = (datetime.min + alert_start).time()

            alert_end = vip_config['alert_hours_end']
            if isinstance(alert_end, timedelta):
                alert_end = (datetime.min + alert_end).time()

            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Checking quiet hours: {current_time} between {alert_start} and {alert_end}")
            if not (alert_start <= current_time <= alert_end):
                syslog.syslog(syslog.LOG_INFO, f"VIP recipient alert outside quiet hours for {message_id}")
                return False
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: Quiet hours check PASSED")

            # All checks passed - send SMS
            syslog.syslog(syslog.LOG_INFO, f"VIP RECIPIENT: All checks passed, sending SMS alert to {vip_config['mobile_number']}")
            success = self._send_recipient_sms_alert(
                cursor, vip_recipient_id, message_id, sender_email,
                recipient_email, subject, spam_score,
                vip_config['mobile_number'],
                vip_config['monitored_recipient_name'],
                client_domain_id,
                quarantine_reason
            )

            if success:
                conn.commit()
                logger.info(f"VIP recipient alert sent successfully for {message_id}")

            return success

        except Exception as e:
            logger.error(f"Error checking VIP recipient: {e}", exc_info=True)
            return False
        finally:
            if conn:
                conn.close()

    def _send_recipient_sms_alert(self, cursor, vip_recipient_id: int, message_id: str,
                                  sender_email: str, recipient_email: str, subject: str,
                                  spam_score: float, mobile_number: str,
                                  recipient_name: Optional[str], client_domain_id: int,
                                  quarantine_reason: Optional[str] = None) -> bool:
        """
        Send SMS alert for monitored recipient quarantine

        Returns:
            True if SMS sent successfully, False otherwise
        """
        try:
            # Format SMS message
            recipient_display = recipient_name or recipient_email
            subject_truncated = subject[:40] + '...' if len(subject) > 40 else subject
            reason_text = f" ({quarantine_reason})" if quarantine_reason else ""

            # Get dashboard URL from environment or use placeholder
            dashboard_url = os.getenv('DASHBOARD_URL', 'https://your-server:5500')
            sms_body = (
                f"⚠️ Quarantine Alert\n\n"
                f"To: {recipient_display}\n"
                f"From: {sender_email}\n"
                f"Subject: {subject_truncated}\n"
                f"Score: {spam_score:.1f}{reason_text}\n\n"
                f"View: {dashboard_url}/emails?search={message_id}\n\n"
                f"OpenEFA"
            )

            # ClickSend API request
            payload = {
                "messages": [{
                    "source": "openefa",
                    "to": mobile_number,
                    "body": sms_body,
                    "custom_string": message_id
                }]
            }

            response = requests.post(
                f"{self.clicksend_base_url}/sms/send",
                auth=(self.clicksend_username, self.clicksend_api_key),
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10
            )

            response_data = response.json()

            if response.status_code == 200 and response_data.get('http_code') == 200:
                # Success
                message_data = response_data['data']['messages'][0]
                clicksend_msg_id = message_data.get('message_id')
                cost = float(message_data.get('cost', 0.08))

                self._log_recipient_alert(
                    cursor, vip_recipient_id, message_id, sender_email,
                    recipient_email, subject, spam_score, mobile_number,
                    client_domain_id, status='sent',
                    clicksend_msg_id=clicksend_msg_id,
                    clicksend_response=json.dumps(response_data),
                    cost_usd=cost,
                    sms_body=sms_body
                )

                return True
            else:
                # Failed
                error_msg = response_data.get('response_msg', 'Unknown error')
                self._log_recipient_alert(
                    cursor, vip_recipient_id, message_id, sender_email,
                    recipient_email, subject, spam_score, mobile_number,
                    client_domain_id, status='failed',
                    error_msg=error_msg,
                    clicksend_response=json.dumps(response_data),
                    sms_body=sms_body
                )
                logger.error(f"ClickSend API error for recipient alert: {error_msg}")
                return False

        except Exception as e:
            logger.error(f"Error sending recipient SMS: {e}", exc_info=True)
            self._log_recipient_alert(
                cursor, vip_recipient_id, message_id, sender_email,
                recipient_email, subject, spam_score, mobile_number,
                client_domain_id, status='failed',
                error_msg=str(e)
            )
            return False

    def _log_recipient_alert(self, cursor, vip_recipient_id: int, message_id: str,
                            sender_email: str, recipient_email: str, subject: str,
                            spam_score: float, mobile_number: str, client_domain_id: int,
                            status: str = 'pending', clicksend_msg_id: Optional[str] = None,
                            clicksend_response: Optional[str] = None,
                            cost_usd: float = 0.08, error_msg: Optional[str] = None,
                            sms_body: Optional[str] = None):
        """Log recipient SMS alert to database for billing and tracking"""

        # Determine billing cycle (YYYY-MM)
        billing_cycle = datetime.now().strftime('%Y-%m')

        # Only billable if actually sent/delivered
        billable_amount = self.per_alert_price if status in ('sent', 'delivered') else 0.00
        billing_status = 'unbilled' if status in ('sent', 'delivered') else 'unbilled'

        cursor.execute("""
            INSERT INTO sms_alert_log (
                message_id, email_subject, sender_email, recipient_email,
                spam_score, vip_sender_id, client_domain_id, mobile_number,
                sms_message, delivery_status, clicksend_message_id,
                clicksend_response, cost_usd, billable_amount_usd,
                billing_status, billing_cycle, error_message
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            message_id, subject, sender_email, recipient_email,
            spam_score, vip_recipient_id, client_domain_id, mobile_number,
            sms_body, status, clicksend_msg_id, clicksend_response,
            cost_usd, billable_amount, billing_status, billing_cycle, error_msg
        ))

    def _send_sms_alert(self, cursor, vip_sender_id: int, message_id: str,
                       sender_email: str, recipient_email: str, subject: str,
                       spam_score: float, mobile_number: str,
                       vip_sender_name: Optional[str], client_domain_id: int) -> bool:
        """
        Send SMS alert via ClickSend API

        Returns:
            True if SMS sent successfully, False otherwise
        """
        try:
            # Format SMS message
            sender_display = vip_sender_name or sender_email
            subject_truncated = subject[:50] + '...' if len(subject) > 50 else subject

            # Get dashboard URL from environment or use placeholder
            dashboard_url = os.getenv('DASHBOARD_URL', 'https://your-server:5500')
            sms_body = (
                f"📧 VIP Email Alert\n\n"
                f"From: {sender_display}\n"
                f"Subject: {subject_truncated}\n\n"
                f"View: {dashboard_url}/emails?search={message_id}\n\n"
                f"OpenEFA"
            )

            # ClickSend API request
            payload = {
                "messages": [{
                    "source": "openefa",
                    "to": mobile_number,
                    "body": sms_body,
                    "custom_string": message_id
                }]
            }

            response = requests.post(
                f"{self.clicksend_base_url}/sms/send",
                auth=(self.clicksend_username, self.clicksend_api_key),
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10
            )

            response_data = response.json()

            if response.status_code == 200 and response_data.get('http_code') == 200:
                # Success
                message_data = response_data['data']['messages'][0]
                clicksend_msg_id = message_data.get('message_id')
                cost = float(message_data.get('cost', 0.08))  # Default to $0.08 if not provided

                self._log_alert(
                    cursor, vip_sender_id, message_id, sender_email,
                    recipient_email, subject, spam_score, mobile_number,
                    client_domain_id, status='sent',
                    clicksend_msg_id=clicksend_msg_id,
                    clicksend_response=json.dumps(response_data),
                    cost_usd=cost,
                    sms_body=sms_body
                )

                return True
            else:
                # Failed
                error_msg = response_data.get('response_msg', 'Unknown error')
                self._log_alert(
                    cursor, vip_sender_id, message_id, sender_email,
                    recipient_email, subject, spam_score, mobile_number,
                    client_domain_id, status='failed',
                    error_msg=error_msg,
                    clicksend_response=json.dumps(response_data),
                    sms_body=sms_body
                )
                logger.error(f"ClickSend API error: {error_msg}")
                return False

        except Exception as e:
            logger.error(f"Error sending SMS: {e}", exc_info=True)
            self._log_alert(
                cursor, vip_sender_id, message_id, sender_email,
                recipient_email, subject, spam_score, mobile_number,
                client_domain_id, status='failed',
                error_msg=str(e)
            )
            return False

    def _log_alert(self, cursor, vip_sender_id: int, message_id: str,
                   sender_email: str, recipient_email: str, subject: str,
                   spam_score: float, mobile_number: str, client_domain_id: int,
                   status: str = 'pending', clicksend_msg_id: Optional[str] = None,
                   clicksend_response: Optional[str] = None,
                   cost_usd: float = 0.08, error_msg: Optional[str] = None,
                   sms_body: Optional[str] = None):
        """Log SMS alert to database for billing and tracking"""

        # Determine billing cycle (YYYY-MM)
        billing_cycle = datetime.now().strftime('%Y-%m')

        # Only billable if actually sent/delivered
        billable_amount = self.per_alert_price if status in ('sent', 'delivered') else 0.00
        billing_status = 'unbilled' if status in ('sent', 'delivered') else 'unbilled'

        cursor.execute("""
            INSERT INTO sms_alert_log (
                message_id, email_subject, sender_email, recipient_email,
                spam_score, vip_sender_id, client_domain_id, mobile_number,
                sms_message, delivery_status, clicksend_message_id,
                clicksend_response, cost_usd, billable_amount_usd,
                billing_status, billing_cycle, error_message
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            message_id, subject, sender_email, recipient_email,
            spam_score, vip_sender_id, client_domain_id, mobile_number,
            sms_body, status, clicksend_msg_id, clicksend_response,
            cost_usd, billable_amount, billing_status, billing_cycle, error_msg
        ))

    def get_monthly_billing(self, client_domain_id: int, user_email: str,
                          billing_cycle: Optional[str] = None) -> Dict:
        """
        Get billing summary for a user/domain for a specific month

        Args:
            client_domain_id: Client domain ID
            user_email: User email address
            billing_cycle: YYYY-MM format, defaults to current month

        Returns:
            Dict with billing summary
        """
        if not billing_cycle:
            billing_cycle = datetime.now().strftime('%Y-%m')

        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    COUNT(*) as total_alerts,
                    SUM(CASE WHEN delivery_status IN ('sent', 'delivered') THEN 1 ELSE 0 END) as billable_alerts,
                    SUM(CASE WHEN delivery_status = 'delivered' THEN 1 ELSE 0 END) as delivered_alerts,
                    SUM(CASE WHEN delivery_status = 'failed' THEN 1 ELSE 0 END) as failed_alerts,
                    SUM(CASE WHEN delivery_status = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited_alerts,
                    SUM(cost_usd) as total_cost,
                    SUM(billable_amount_usd) as total_billable,
                    AVG(billable_amount_usd) as avg_per_alert
                FROM sms_alert_log
                WHERE client_domain_id = %s
                AND recipient_email = %s
                AND billing_cycle = %s
            """, (client_domain_id, user_email, billing_cycle))

            result = cursor.fetchone()

            return {
                'billing_cycle': billing_cycle,
                'client_domain_id': client_domain_id,
                'user_email': user_email,
                'total_alerts': result['total_alerts'] or 0,
                'billable_alerts': result['billable_alerts'] or 0,
                'delivered_alerts': result['delivered_alerts'] or 0,
                'failed_alerts': result['failed_alerts'] or 0,
                'rate_limited_alerts': result['rate_limited_alerts'] or 0,
                'total_cost_usd': float(result['total_cost'] or 0),
                'total_billable_usd': float(result['total_billable'] or 0),
                'avg_per_alert_usd': float(result['avg_per_alert'] or 0),
                'profit_margin_pct': (
                    ((float(result['total_billable'] or 0) - float(result['total_cost'] or 0)) /
                     float(result['total_billable'] or 1)) * 100
                ) if result['total_billable'] else 0
            }
        finally:
            conn.close()

    def generate_invoice_line_items(self, client_domain_id: int,
                                    billing_cycle: Optional[str] = None) -> list:
        """
        Generate invoice line items for all users in a domain

        Args:
            client_domain_id: Client domain ID
            billing_cycle: YYYY-MM format, defaults to current month

        Returns:
            List of line items for invoice
        """
        if not billing_cycle:
            billing_cycle = datetime.now().strftime('%Y-%m')

        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    recipient_email,
                    COUNT(*) as alert_count,
                    SUM(billable_amount_usd) as total_amount,
                    GROUP_CONCAT(DISTINCT vip_sender_email SEPARATOR ', ') as vip_senders
                FROM sms_alert_log sal
                JOIN vip_senders vs ON sal.vip_sender_id = vs.id
                WHERE sal.client_domain_id = %s
                AND sal.billing_cycle = %s
                AND sal.billing_status = 'unbilled'
                AND sal.delivery_status IN ('sent', 'delivered')
                GROUP BY recipient_email
                HAVING total_amount > 0
            """, (client_domain_id, billing_cycle))

            line_items = []
            for row in cursor.fetchall():
                line_items.append({
                    'user_email': row['recipient_email'],
                    'description': f"VIP Email Alerts - {row['alert_count']} alerts",
                    'quantity': row['alert_count'],
                    'unit_price': self.per_alert_price,
                    'total': float(row['total_amount']),
                    'details': f"Alerts from: {row['vip_senders']}"
                })

            return line_items
        finally:
            conn.close()


def test_vip_alert():
    """Test function for VIP alert system"""

    # Load config from environment or use placeholders
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'spacy_user'),
        'password': os.getenv('DB_PASSWORD', 'your_password'),
        'database': os.getenv('DB_NAME', 'spacy_email_db')
    }

    clicksend_config = {
        'username': os.getenv('CLICKSEND_USERNAME', 'your_clicksend_username'),
        'api_key': os.getenv('CLICKSEND_API_KEY', 'your_clicksend_api_key')
    }

    vip_system = VIPAlertSystem(db_config, clicksend_config)

    # Test check
    result = vip_system.check_vip_sender(
        recipient_email='admin@example.com',
        sender_email='vip@example.gov',
        message_id='test-msg-12345',
        subject='Test VIP Alert',
        spam_score=2.5,
        client_domain_id=1
    )

    print(f"Alert sent: {result}")

    # Get billing summary
    billing = vip_system.get_monthly_billing(1, 'admin@example.com')
    print(f"Billing summary: {json.dumps(billing, indent=2)}")


if __name__ == '__main__':
    test_vip_alert()
