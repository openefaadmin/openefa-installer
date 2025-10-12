#!/usr/bin/env python3
"""
API endpoint to receive whitelist notifications from MailGuard
When users click "Always Allow Sender" in MailWatch interface,
it notifies SpaCy to add the sender to the whitelist
"""

import json
import logging
import os
import sys
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/opt/spacyserver/config/.env')

# Add parent directory to path for imports
sys.path.insert(0, '/opt/spacyserver')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/spacyserver/logs/whitelist_notification.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def add_to_whitelist(sender_email, recipient_email, reason="MailWatch user whitelist request"):
    """Add sender to SpaCy whitelist configuration"""
    try:
        # Load BEC config
        config_path = '/opt/spacyserver/config/bec_config.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Initialize whitelist structure if needed
        if 'whitelist' not in config:
            config['whitelist'] = {}
        if 'authentication_aware' not in config['whitelist']:
            config['whitelist']['authentication_aware'] = {'senders': {}}

        # Check if already whitelisted
        if sender_email in config['whitelist']['authentication_aware']['senders']:
            logger.info(f"Sender {sender_email} already whitelisted")
            return {'status': 'already_whitelisted', 'message': f'{sender_email} is already whitelisted'}

        # Extract recipient domain
        recipient_domain = recipient_email.split('@')[1] if '@' in recipient_email else None

        # Add to whitelist with maximum trust
        config['whitelist']['authentication_aware']['senders'][sender_email] = {
            'trust_score_bonus': 10,  # Maximum trust
            'require_auth': ['spf'],  # SPF minimum
            'bypass_bec_checks': True,
            'bypass_financial_checks': True,
            'bypass_typosquatting': True,
            'bypass_url_checks': True,
            'for_domain': recipient_domain,
            'description': f"User-requested whitelist via MailWatch for {recipient_domain}",
            'reason': reason,
            'whitelist_date': datetime.now().isoformat(),
            'whitelist_source': 'mailwatch_always_allow'
        }

        # Save config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        # Ensure proper ownership and permissions
        try:
            import pwd
            import grp
            # Get spacy-filter user/group IDs
            spacy_uid = pwd.getpwnam('spacy-filter').pw_uid
            spacy_gid = grp.getgrnam('spacy-filter').gr_gid
            # Set ownership
            os.chown(config_path, spacy_uid, spacy_gid)
            # Set permissions
            os.chmod(config_path, 0o664)
        except Exception as perm_error:
            logger.warning(f"Could not set permissions on {config_path}: {perm_error}")

        logger.info(f"Successfully whitelisted {sender_email} for {recipient_domain}")

        # Also update trusted_senders database
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'spacy_user'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME', 'spacy_email_db')
            )
            cursor = conn.cursor()

            # Check if exists
            cursor.execute("SELECT sender_email FROM trusted_senders WHERE sender_email = %s", (sender_email,))
            if cursor.fetchone():
                # Update existing
                cursor.execute("""
                    UPDATE trusted_senders
                    SET trust_score = 10,
                        last_released = NOW(),
                        last_subject = %s
                    WHERE sender_email = %s
                """, (f"Always Allow via MailWatch for {recipient_domain}", sender_email))
            else:
                # Insert new
                cursor.execute("""
                    INSERT INTO trusted_senders
                    (sender_email, trust_score, release_count, first_seen, last_released, last_subject)
                    VALUES (%s, 10, 0, NOW(), NOW(), %s)
                """, (sender_email, f"Always Allow via MailWatch for {recipient_domain}"))

            conn.commit()
            cursor.close()
            conn.close()
        except Exception as db_error:
            logger.warning(f"Could not update database: {db_error}")

        return {'status': 'success', 'message': f'Successfully whitelisted {sender_email} for {recipient_domain}'}

    except Exception as e:
        logger.error(f"Error whitelisting {sender_email}: {e}")
        return {'status': 'error', 'message': str(e)}

@app.route('/api/whitelist', methods=['POST'])
def whitelist_notification():
    """
    Receive whitelist notification from MailGuard

    Expected JSON payload:
    {
        "sender": "user@example.com",
        "recipient": "user@clientdomain.com",
        "subject": "Email subject (optional)",
        "message_id": "4cXXXXXXXX (optional)",
        "user": "admin@clientdomain.com (who clicked whitelist)",
        "reason": "User requested whitelist"
    }
    """
    try:
        # Log raw request
        logger.info(f"Received whitelist request from {request.remote_addr}")
        logger.info(f"Raw data: {request.data}")

        # Parse JSON
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400

        # Extract required fields
        sender = data.get('sender')
        recipient = data.get('recipient')
        user = data.get('user', 'unknown')
        reason = data.get('reason', 'User clicked Always Allow in MailWatch')
        subject = data.get('subject', '')
        message_id = data.get('message_id', '')

        if not sender:
            return jsonify({'error': 'Missing sender email'}), 400

        if not recipient:
            return jsonify({'error': 'Missing recipient email'}), 400

        logger.info(f"Whitelist request: {sender} -> {recipient} (requested by {user})")

        # Add to whitelist
        result = add_to_whitelist(sender, recipient, reason)

        # Log the whitelist action
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'spacy_user'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME', 'spacy_email_db')
            )
            cursor = conn.cursor()

            # Create whitelist_requests table if not exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    sender_email VARCHAR(255),
                    recipient_email VARCHAR(255),
                    requested_by VARCHAR(255),
                    message_id VARCHAR(100),
                    subject VARCHAR(500),
                    reason VARCHAR(500),
                    request_time DATETIME,
                    status VARCHAR(50),
                    INDEX idx_sender (sender_email),
                    INDEX idx_recipient (recipient_email),
                    INDEX idx_time (request_time)
                )
            """)

            # Log the request
            cursor.execute("""
                INSERT INTO whitelist_requests
                (sender_email, recipient_email, requested_by, message_id, subject, reason, request_time, status)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (sender, recipient, user, message_id, subject, reason, result['status']))

            conn.commit()
            cursor.close()
            conn.close()
        except Exception as db_error:
            logger.warning(f"Could not log whitelist request: {db_error}")

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error processing whitelist request: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'SpaCy Whitelist API'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)