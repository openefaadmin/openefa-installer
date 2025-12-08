#!/usr/bin/env python3
"""
Recipient Verification Module for OpenEFA
Handles SMTP recipient callout verification and domain testing
"""

import smtplib
import socket
import logging
from typing import Dict, Tuple, Optional
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RecipientVerificationTester:
    """Test and verify recipient verification capabilities of relay hosts"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def test_relay_host(self, relay_host: str, relay_port: int, test_domain: str) -> Dict:
        """
        Test if a relay host supports recipient verification

        Args:
            relay_host: IP or hostname of relay server
            relay_port: SMTP port (typically 25)
            test_domain: Domain to test with

        Returns:
            Dict with keys: supported (bool), smtp_code (int), message (str), error (str)
        """
        result = {
            'supported': False,
            'smtp_code': None,
            'message': '',
            'error': None,
            'server_name': None,
            'test_timestamp': datetime.now().isoformat()
        }

        # Generate a test recipient that definitely shouldn't exist
        test_recipient = f"openefa-test-invalid-user-{datetime.now().strftime('%Y%m%d%H%M%S')}@{test_domain}"

        try:
            logger.info(f"Testing recipient verification for {relay_host}:{relay_port}")
            logger.info(f"Test recipient: {test_recipient}")

            # Connect to relay host
            smtp = smtplib.SMTP(relay_host, relay_port, timeout=self.timeout)

            # Get server identification
            code, msg = smtp.ehlo()
            result['server_name'] = msg.decode().split('\n')[0].strip()
            logger.info(f"Connected to: {result['server_name']}")

            # Start mail transaction with empty sender (bounce address)
            # Some servers reject specific sender domains, so use empty sender
            smtp.mail("")

            # Test recipient verification
            try:
                code, msg = smtp.rcpt(test_recipient)
                result['smtp_code'] = code
                result['message'] = msg.decode() if isinstance(msg, bytes) else str(msg)

                if code == 250:
                    # Server accepted - no verification enabled
                    result['supported'] = False
                    logger.info(f"✗ Server accepts all recipients (code {code})")
                elif code in [450, 451, 452, 550, 551, 553]:
                    # Server rejected - verification is working!
                    # 450-452: Temporary failures (Zimbra often returns these)
                    # 550-553: Permanent failures
                    result['supported'] = True
                    logger.info(f"✓ Server rejects invalid recipients (code {code})")
                else:
                    # Unexpected code
                    result['supported'] = False
                    result['error'] = f"Unexpected SMTP code: {code}"
                    logger.warning(f"⚠ Unexpected response code: {code}")

            except smtplib.SMTPRecipientsRefused as e:
                # Server rejected - this is what we want!
                result['supported'] = True
                result['smtp_code'] = 550
                result['message'] = str(e)
                logger.info(f"✓ Server rejects invalid recipients (exception)")

            # Clean up
            try:
                smtp.quit()
            except:
                pass

        except socket.timeout:
            result['error'] = f"Connection timeout to {relay_host}:{relay_port}"
            logger.error(result['error'])
        except ConnectionRefusedError:
            result['error'] = f"Connection refused by {relay_host}:{relay_port}"
            logger.error(result['error'])
        except Exception as e:
            result['error'] = f"{type(e).__name__}: {str(e)}"
            logger.error(f"Error testing relay host: {result['error']}")

        return result

    def verify_recipient(self, relay_host: str, relay_port: int, recipient: str) -> Tuple[bool, int, str]:
        """
        Verify a specific recipient with the upstream relay host

        Args:
            relay_host: IP or hostname of relay server
            relay_port: SMTP port
            recipient: Full email address to verify

        Returns:
            Tuple of (is_valid, smtp_code, message)
        """
        try:
            smtp = smtplib.SMTP(relay_host, relay_port, timeout=self.timeout)
            smtp.ehlo()
            # Use empty sender to avoid sender verification issues
            smtp.mail("")

            try:
                code, msg = smtp.rcpt(recipient)
                message = msg.decode() if isinstance(msg, bytes) else str(msg)

                # Close connection
                try:
                    smtp.quit()
                except:
                    pass

                if code == 250:
                    return (True, code, message)
                elif code in [450, 451, 452, 550, 551, 553]:
                    # Treat 4xx and 5xx rejections as invalid recipient
                    # 450-452: Temporary failure (mailbox unavailable, full, etc.)
                    # 550-553: Permanent failure (user unknown, etc.)
                    return (False, code, message)
                else:
                    # Uncertain - treat as valid to avoid false positives
                    return (True, code, f"Uncertain (code {code}): {message}")

            except smtplib.SMTPRecipientsRefused as e:
                # Recipient refused - invalid
                try:
                    smtp.quit()
                except:
                    pass
                return (False, 550, str(e))

        except Exception as e:
            logger.error(f"Error verifying recipient {recipient}: {e}")
            # On error, fail open (accept) to avoid blocking legitimate mail
            return (True, 0, f"Verification error: {str(e)}")


class RecipientVerificationManager:
    """Manages recipient verification for domains using database configuration"""

    def __init__(self, db_connection):
        """
        Args:
            db_connection: MySQL database connection
        """
        self.db = db_connection
        self.tester = RecipientVerificationTester()
        self.cache = {}  # Cache domain verification settings

    def get_domain_verification_config(self, domain: str) -> Dict:
        """
        Get recipient verification configuration for a domain

        Returns:
            Dict with keys: mode, status, relay_host, relay_port, should_verify
        """
        # Check cache first
        if domain in self.cache:
            return self.cache[domain]

        try:
            # Check if connection is alive before attempting query
            if not self.db.is_connected():
                logger.warning("Database connection lost, attempting to reconnect...")
                self.db.ping(reconnect=True, attempts=3, delay=1)

            # Query database
            cursor = self.db.cursor(dictionary=True)
            cursor.execute("""
                SELECT
                    recipient_verification_mode,
                    recipient_verification_status,
                    relay_host,
                    relay_port
                FROM client_domains
                WHERE domain = %s AND active = 1
            """, (domain,))

            result = cursor.fetchone()
            cursor.close()
        except Exception as e:
            logger.error(f"Failed to query domain verification config: {e}")
            result = None

        if not result:
            return {
                'mode': 'disabled',
                'status': 'unknown',
                'relay_host': None,
                'relay_port': 25,
                'should_verify': False
            }

        # Determine if we should verify based on mode and status
        mode = result['recipient_verification_mode'] or 'auto'
        status = result['recipient_verification_status'] or 'unknown'

        should_verify = False
        if mode == 'enabled':
            should_verify = True
        elif mode == 'auto' and status == 'supported':
            should_verify = True
        elif mode == 'disabled':
            should_verify = False

        config = {
            'mode': mode,
            'status': status,
            'relay_host': result['relay_host'],
            'relay_port': result['relay_port'] or 25,
            'should_verify': should_verify
        }

        # Cache result
        self.cache[domain] = config

        return config

    def verify_recipient(self, recipient: str) -> Tuple[bool, int, str]:
        """
        Verify if a recipient is valid using upstream relay host

        Args:
            recipient: Email address to verify (e.g., user@example.com)

        Returns:
            Tuple of (is_valid, smtp_code, message)
        """
        # Extract domain
        if '@' not in recipient:
            return (False, 550, "Invalid email format")

        domain = recipient.split('@')[1].lower()

        # Get verification config for domain
        config = self.get_domain_verification_config(domain)

        if not config['should_verify']:
            # Verification not enabled for this domain - accept
            return (True, 250, "Verification disabled for domain")

        if not config['relay_host']:
            # No relay host configured - accept
            return (True, 250, "No relay host configured")

        # Perform actual verification
        is_valid, code, message = self.tester.verify_recipient(
            config['relay_host'],
            config['relay_port'],
            recipient
        )

        # Log the verification attempt
        self._log_verification(domain, recipient, is_valid, code, message)

        return (is_valid, code, message)

    def _log_verification(self, domain: str, recipient: str, is_valid: bool, code: int, message: str):
        """Log verification attempt to database"""
        try:
            # Check if connection is alive before attempting query
            if not self.db.is_connected():
                logger.warning("Database connection lost during verification logging, attempting to reconnect...")
                self.db.ping(reconnect=True, attempts=3, delay=1)

            cursor = self.db.cursor()

            result_type = 'accepted' if is_valid else 'rejected'
            if code == 0:
                result_type = 'error'

            cursor.execute("""
                INSERT INTO recipient_verification_stats
                (domain, recipient_email, verification_result, smtp_code, smtp_message)
                VALUES (%s, %s, %s, %s, %s)
            """, (domain, recipient, result_type, code, message[:500]))

            self.db.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"Failed to log verification: {e}")

    def test_and_update_domain(self, domain: str) -> Dict:
        """
        Test recipient verification for a domain and update database

        Args:
            domain: Domain to test

        Returns:
            Test results dict
        """
        # Get domain config
        cursor = self.db.cursor(dictionary=True)
        cursor.execute("""
            SELECT relay_host, relay_port
            FROM client_domains
            WHERE domain = %s
        """, (domain,))

        result = cursor.fetchone()
        cursor.close()

        if not result or not result['relay_host']:
            return {
                'success': False,
                'error': 'Domain not found or no relay host configured'
            }

        # Test the relay host
        test_result = self.tester.test_relay_host(
            result['relay_host'],
            result['relay_port'] or 25,
            domain
        )

        # Update database with results
        status = 'supported' if test_result['supported'] else 'not_supported'

        cursor = self.db.cursor()
        cursor.execute("""
            UPDATE client_domains
            SET recipient_verification_status = %s,
                recipient_verification_last_tested = NOW()
            WHERE domain = %s
        """, (status, domain))

        self.db.commit()
        cursor.close()

        # Clear cache for this domain
        if domain in self.cache:
            del self.cache[domain]

        return {
            'success': True,
            'supported': test_result['supported'],
            'status': status,
            'smtp_code': test_result['smtp_code'],
            'message': test_result['message'],
            'error': test_result['error'],
            'server_name': test_result['server_name']
        }

    def clear_cache(self):
        """Clear the configuration cache"""
        self.cache = {}


# Standalone testing functions for CLI usage

def test_domain_verification(domain: str, relay_host: str, relay_port: int = 25) -> Dict:
    """
    Standalone function to test domain verification
    Usage: python3 recipient_verification.py test example.com mail.example.com
    """
    tester = RecipientVerificationTester()
    return tester.test_relay_host(relay_host, relay_port, domain)


def verify_single_recipient(recipient: str, relay_host: str, relay_port: int = 25) -> Tuple[bool, int, str]:
    """
    Standalone function to verify a single recipient
    Usage: python3 recipient_verification.py verify user@example.com mail.example.com
    """
    tester = RecipientVerificationTester()
    return tester.verify_recipient(relay_host, relay_port, recipient)


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Test domain:     python3 recipient_verification.py test <domain> <relay_host> [port]")
        print("  Verify recipient: python3 recipient_verification.py verify <email> <relay_host> [port]")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'test' and len(sys.argv) >= 4:
        domain = sys.argv[2]
        relay_host = sys.argv[3]
        relay_port = int(sys.argv[4]) if len(sys.argv) > 4 else 25

        print(f"\nTesting recipient verification for {domain} via {relay_host}:{relay_port}\n")
        result = test_domain_verification(domain, relay_host, relay_port)

        print("Results:")
        print(f"  Supported: {result['supported']}")
        print(f"  SMTP Code: {result['smtp_code']}")
        print(f"  Message: {result['message']}")
        print(f"  Server: {result['server_name']}")
        if result['error']:
            print(f"  Error: {result['error']}")

    elif command == 'verify' and len(sys.argv) >= 4:
        recipient = sys.argv[2]
        relay_host = sys.argv[3]
        relay_port = int(sys.argv[4]) if len(sys.argv) > 4 else 25

        print(f"\nVerifying recipient: {recipient} via {relay_host}:{relay_port}\n")
        is_valid, code, message = verify_single_recipient(recipient, relay_host, relay_port)

        print("Results:")
        print(f"  Valid: {is_valid}")
        print(f"  SMTP Code: {code}")
        print(f"  Message: {message}")

    else:
        print("Invalid command or arguments")
        sys.exit(1)
