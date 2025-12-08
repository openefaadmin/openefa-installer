#!/usr/bin/env python3
"""
OpenEFA SMS Notification Service
Backend service for sending SMS notifications via ClickSend API
Supports high-risk email alerts, system alerts, and daily summaries
"""

import json
import os
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# ClickSend imports
try:
    import clicksend_client
    from clicksend_client.rest import ApiException
    CLICKSEND_AVAILABLE = True
except ImportError:
    CLICKSEND_AVAILABLE = False

# Configuration paths
CONFIG_PATH = '/opt/spacyserver/config/notification_config.json'
LOG_PATH = '/opt/spacyserver/logs/notifications.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NotificationService')


class NotificationService:
    """Backend SMS notification service using ClickSend API"""

    def __init__(self, config_path: str = CONFIG_PATH):
        """Initialize notification service with configuration"""
        self.config_path = config_path
        self.config = self._load_config()
        self.db_config = self._get_db_config()
        self.clicksend_client = None

        if not CLICKSEND_AVAILABLE:
            logger.warning("ClickSend client library not installed. Run: pip install clicksend-client")
            return

        if self.config['clicksend']['enabled']:
            self._initialize_clicksend()

    def _load_config(self) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {self.config_path} - SMS notifications disabled")
            # Return minimal default config with notifications disabled
            return {
                'clicksend': {'enabled': False},
                'rate_limiting': {'max_notifications_per_hour': 5, 'cooldown_minutes': 60},
                'notification_types': {'high_risk': False, 'system_alert': False, 'daily_summary': False}
            }
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            raise

    def _get_db_config(self) -> Dict:
        """Get database configuration from environment variables"""
        return {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'spacy_user'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME', 'spacy_email_db')
        }

    def _initialize_clicksend(self):
        """Initialize ClickSend API client using environment variables"""
        try:
            # Read ClickSend credentials from environment variables
            username = os.getenv('CLICKSEND_USERNAME')
            api_key = os.getenv('CLICKSEND_API_KEY')
            enabled = os.getenv('CLICKSEND_ENABLED', 'false').lower() == 'true'

            # Check if ClickSend is enabled
            if not enabled:
                logger.info("ClickSend notifications disabled in configuration")
                return

            # Validate credentials are configured
            if not username or username == 'YOUR_CLICKSEND_USERNAME':
                logger.warning("ClickSend username not configured. Please update .env file")
                return

            if not api_key or api_key == 'YOUR_CLICKSEND_API_KEY':
                logger.warning("ClickSend API key not configured. Please update .env file")
                return

            # Configure ClickSend
            configuration = clicksend_client.Configuration()
            configuration.username = username
            configuration.password = api_key

            self.clicksend_client = clicksend_client.SMSApi(
                clicksend_client.ApiClient(configuration)
            )
            logger.info("ClickSend API client initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize ClickSend client: {e}")
            self.clicksend_client = None

    def _get_db_connection(self):
        """Create database connection"""
        try:
            return mysql.connector.connect(**self.db_config)
        except Error as e:
            logger.error(f"Database connection error: {e}")
            return None

    def _check_rate_limit(self, recipient: str, notification_type: str) -> Tuple[bool, str]:
        """
        Check if notification is within rate limits
        Returns: (allowed, reason)
        """
        conn = self._get_db_connection()
        if not conn:
            return False, "Database connection failed"

        try:
            cursor = conn.cursor(dictionary=True)
            rate_config = self.config['rate_limiting']
            max_per_hour = rate_config['max_notifications_per_hour']
            cooldown_minutes = rate_config['cooldown_minutes']

            # Check hourly rate limit
            cursor.execute("""
                SELECT hourly_count, hour_window, last_sent
                FROM notification_rate_limit
                WHERE recipient = %s AND notification_type = %s
            """, (recipient, notification_type))

            result = cursor.fetchone()

            if result:
                hour_window = result['hour_window']
                hourly_count = result['hourly_count']
                last_sent = result['last_sent']

                # Reset hourly counter if window has passed
                if datetime.now() - hour_window > timedelta(hours=1):
                    cursor.execute("""
                        UPDATE notification_rate_limit
                        SET hourly_count = 0, hour_window = NOW()
                        WHERE recipient = %s AND notification_type = %s
                    """, (recipient, notification_type))
                    conn.commit()
                    return True, "Rate limit reset"

                # Check if within hourly limit
                if hourly_count >= max_per_hour:
                    return False, f"Hourly limit exceeded ({max_per_hour}/hour)"

                # Check cooldown period
                if datetime.now() - last_sent < timedelta(minutes=cooldown_minutes):
                    return False, f"Cooldown period active ({cooldown_minutes} min)"

            return True, "Within rate limits"

        except Error as e:
            logger.error(f"Rate limit check error: {e}")
            return False, f"Database error: {e}"
        finally:
            cursor.close()
            conn.close()

    def _update_rate_limit(self, recipient: str, notification_type: str):
        """Update rate limiting counters"""
        conn = self._get_db_connection()
        if not conn:
            return

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notification_rate_limit
                (recipient, notification_type, last_sent, hourly_count, hour_window)
                VALUES (%s, %s, NOW(), 1, NOW())
                ON DUPLICATE KEY UPDATE
                    last_sent = NOW(),
                    hourly_count = hourly_count + 1
            """, (recipient, notification_type))
            conn.commit()
        except Error as e:
            logger.error(f"Rate limit update error: {e}")
        finally:
            cursor.close()
            conn.close()

    def _log_notification(self, notification_type: str, recipient: str,
                         message: str, email_id: Optional[str] = None,
                         trigger_reason: Optional[str] = None,
                         status: str = 'pending',
                         response_code: Optional[str] = None,
                         response_message: Optional[str] = None) -> int:
        """Log notification to database"""
        conn = self._get_db_connection()
        if not conn:
            return 0

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO notification_log
                (notification_type, recipient, message, email_id, trigger_reason,
                 status, response_code, response_message, sent_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (notification_type, recipient, message, email_id, trigger_reason,
                  status, response_code, response_message,
                  datetime.now() if status == 'sent' else None))
            conn.commit()
            return cursor.lastrowid
        except Error as e:
            logger.error(f"Notification logging error: {e}")
            return 0
        finally:
            cursor.close()
            conn.close()

    def _send_sms(self, recipient: str, message: str) -> Tuple[bool, str, str]:
        """
        Send SMS via ClickSend
        Returns: (success, response_code, response_message)
        """
        if not self.clicksend_client:
            return False, "CLIENT_NOT_INITIALIZED", "ClickSend client not initialized"

        try:
            # Get sender name from config (fallback to "OpenSpacy" if not configured)
            sender_name = self.config.get('clicksend', {}).get('sender_name', 'OpenSpacy')

            # Create SMS message
            sms_message = clicksend_client.SmsMessage(
                source=sender_name,
                body=message,
                to=recipient
            )

            sms_messages = clicksend_client.SmsMessageCollection(
                messages=[sms_message]
            )

            # Send SMS
            api_response = self.clicksend_client.sms_send_post(sms_messages)

            # Parse response
            if hasattr(api_response, 'response_code'):
                response_code = api_response.response_code
                response_msg = api_response.response_msg if hasattr(api_response, 'response_msg') else "Success"

                if response_code == 'SUCCESS':
                    logger.info(f"SMS sent successfully to {recipient}")
                    return True, response_code, response_msg
                else:
                    logger.warning(f"SMS send failed: {response_code} - {response_msg}")
                    return False, response_code, response_msg
            else:
                return True, "SENT", "Message queued"

        except ApiException as e:
            logger.error(f"ClickSend API error: {e}")
            return False, "API_ERROR", str(e)
        except Exception as e:
            logger.error(f"Unexpected error sending SMS: {e}")
            return False, "EXCEPTION", str(e)

    def send_notification(self, notification_type: str, recipients: List[str],
                         message: str, email_id: Optional[str] = None,
                         trigger_reason: Optional[str] = None) -> Dict:
        """
        Send notification to recipients with rate limiting
        Returns dictionary with results for each recipient
        """
        if not self.config['clicksend']['enabled']:
            logger.warning("ClickSend notifications are disabled in configuration")
            return {'status': 'disabled', 'message': 'Notifications disabled in config'}

        results = {}

        for recipient in recipients:
            # Check rate limits
            allowed, reason = self._check_rate_limit(recipient, notification_type)

            if not allowed:
                logger.warning(f"Rate limit exceeded for {recipient}: {reason}")
                self._log_notification(notification_type, recipient, message,
                                      email_id, trigger_reason,
                                      status='rate_limited', response_message=reason)
                results[recipient] = {'status': 'rate_limited', 'reason': reason}
                continue

            # Send SMS
            success, response_code, response_msg = self._send_sms(recipient, message)

            # Log notification
            status = 'sent' if success else 'failed'
            self._log_notification(notification_type, recipient, message,
                                  email_id, trigger_reason, status,
                                  response_code, response_msg)

            # Update rate limits if sent successfully
            if success:
                self._update_rate_limit(recipient, notification_type)

            results[recipient] = {
                'status': status,
                'response_code': response_code,
                'response_message': response_msg
            }

        return results

    def send_high_risk_alert(self, email_data: Dict) -> Dict:
        """Send high-risk email alert"""
        settings = self.config['notification_settings']['high_risk_alerts']

        if not settings['enabled']:
            return {'status': 'disabled'}

        # Check if specific trigger is enabled
        trigger_reason = email_data.get('trigger_reason', 'high_spam_score')
        triggers = settings.get('triggers', {})

        # If trigger exists in config and is disabled, skip notification
        if trigger_reason in triggers and not triggers[trigger_reason]:
            logger.info(f"Skipping notification for disabled trigger: {trigger_reason}")
            return {'status': 'disabled', 'reason': f'trigger_{trigger_reason}_disabled'}

        # Determine which template to use
        templates = self.config['message_templates']

        if trigger_reason == 'phishing_detected':
            message = templates['phishing_detected'].format(sender=email_data.get('sender', 'Unknown'))
        elif trigger_reason == 'bec_detected':
            message = templates['bec_detected'].format(sender=email_data.get('sender', 'Unknown'))
        elif trigger_reason == 'virus_detected':
            message = templates['virus_detected'].format(sender=email_data.get('sender', 'Unknown'))
        else:
            message = templates['high_risk_email'].format(
                sender=email_data.get('sender', 'Unknown'),
                score=email_data.get('spam_score', 0),
                reason=trigger_reason
            )

        return self.send_notification(
            'high_risk_alert',
            settings['recipients'],
            message,
            email_id=email_data.get('message_id'),
            trigger_reason=trigger_reason
        )

    def send_system_alert(self, error_type: str, message_details: str) -> Dict:
        """Send system alert notification"""
        settings = self.config['notification_settings']['system_alerts']

        if not settings['enabled']:
            return {'status': 'disabled'}

        template = self.config['message_templates']['system_error']
        message = template.format(error_type=error_type, message=message_details)

        return self.send_notification(
            'system_alert',
            settings['recipients'],
            message,
            trigger_reason=error_type
        )

    def send_daily_summary(self, stats: Dict) -> Dict:
        """Send daily summary report"""
        settings = self.config['notification_settings']['daily_summary']

        if not settings['enabled']:
            return {'status': 'disabled'}

        template = self.config['message_templates']['daily_summary']
        message = template.format(
            total=stats.get('total_processed', 0),
            spam=stats.get('spam_blocked', 0),
            threats=stats.get('threats_detected', 0),
            quarantined=stats.get('quarantined', 0)
        )

        return self.send_notification(
            'daily_summary',
            settings['recipients'],
            message,
            trigger_reason='daily_report'
        )

    def test_connection(self) -> Tuple[bool, str]:
        """Test ClickSend API connection and credentials"""
        if not CLICKSEND_AVAILABLE:
            return False, "ClickSend library not installed"

        if not self.clicksend_client:
            return False, "ClickSend client not initialized - check credentials in config"

        try:
            # Try to get account info
            account_api = clicksend_client.AccountApi(self.clicksend_client.api_client)
            response = account_api.account_get()
            return True, "Connection successful"
        except ApiException as e:
            return False, f"API Error: {e}"
        except Exception as e:
            return False, f"Error: {e}"


def main():
    """CLI interface for notification service"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  notification_service.py test              - Test ClickSend connection")
        print("  notification_service.py alert <message>   - Send test system alert")
        print("  notification_service.py summary           - Send test daily summary")
        sys.exit(1)

    service = NotificationService()
    command = sys.argv[1]

    if command == 'test':
        success, message = service.test_connection()
        print(f"Connection test: {'SUCCESS' if success else 'FAILED'}")
        print(f"Message: {message}")

    elif command == 'alert' and len(sys.argv) > 2:
        message = ' '.join(sys.argv[2:])
        result = service.send_system_alert('TEST', message)
        print(f"Alert sent: {result}")

    elif command == 'summary':
        test_stats = {
            'total_processed': 1234,
            'spam_blocked': 567,
            'threats_detected': 12,
            'quarantined': 45
        }
        result = service.send_daily_summary(test_stats)
        print(f"Summary sent: {result}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == '__main__':
    main()
