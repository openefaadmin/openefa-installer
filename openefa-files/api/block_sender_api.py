#!/opt/spacyserver/venv/bin/python3
"""
Block Sender API for SpaCy Email Security System

Receives block requests from MailGuard and adds blocking rules to the database.

API Endpoint: http://<openefa-server-ip>:5003/api/block
Method: POST
Payload: {
    "message_id": "ABC123",
    "sender": "spammer@example.com",
    "recipient": "user@domain.com",
    "block_type": "domain",  # Options: "email", "domain", "pattern"
    "block_user": "admin",
    "reason": "User blocked via MailWatch"
}

Author: OpenEFA Team
Date: 2025-09-29
"""

import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/spacyserver/logs/block_sender_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Database connection
DB_CONFIG_FILE = '/opt/spacyserver/config/.my.cnf'
DATABASE_NAME = 'spacy_email_db'

def get_db_connection():
    """Create database connection from .my.cnf"""
    try:
        # Read MySQL config
        config = {}
        with open(DB_CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('user='):
                    config['user'] = line.split('=', 1)[1]
                elif line.startswith('password='):
                    config['password'] = line.split('=', 1)[1]
                elif line.startswith('host='):
                    config['host'] = line.split('=', 1)[1]

        # Create engine
        connection_string = f"mysql+pymysql://{config['user']}:{config['password']}@{config.get('host', 'localhost')}/{DATABASE_NAME}?charset=utf8mb4"
        engine = create_engine(connection_string, pool_pre_ping=True, pool_recycle=3600)
        Session = sessionmaker(bind=engine)
        return Session()
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

def get_client_domain_id(session, domain):
    """Get or create client_domain_id for a domain"""
    try:
        # Check if domain exists
        result = session.execute(
            text("SELECT id FROM client_domains WHERE domain = :domain"),
            {"domain": domain}
        )
        row = result.fetchone()

        if row:
            return row[0]

        # Create new client domain
        result = session.execute(
            text("""
                INSERT INTO client_domains (domain, client_name, created_at, active)
                VALUES (:domain, :client_name, NOW(), 1)
            """),
            {"domain": domain, "client_name": f"Auto-created for {domain}"}
        )
        session.commit()
        return result.lastrowid
    except Exception as e:
        logger.error(f"Failed to get/create client_domain_id for {domain}: {e}")
        session.rollback()
        raise

def add_blocking_rule(session, client_domain_id, rule_type, rule_value, rule_pattern, description, created_by):
    """Add a blocking rule to the database"""
    try:
        # Check if rule already exists
        result = session.execute(
            text("""
                SELECT id FROM blocking_rules
                WHERE client_domain_id = :client_id
                AND rule_type = :rule_type
                AND rule_value = :rule_value
                AND active = 1
            """),
            {
                "client_id": client_domain_id,
                "rule_type": rule_type,
                "rule_value": rule_value
            }
        )

        if result.fetchone():
            logger.info(f"Blocking rule already exists: {rule_value} for client {client_domain_id}")
            return {"status": "exists", "message": "Rule already exists"}

        # Insert new rule
        session.execute(
            text("""
                INSERT INTO blocking_rules
                (client_domain_id, rule_type, rule_value, rule_pattern, description, created_at, created_by, active, priority)
                VALUES (:client_id, :rule_type, :rule_value, :rule_pattern, :description, NOW(), :created_by, 1, 100)
            """),
            {
                "client_id": client_domain_id,
                "rule_type": rule_type,
                "rule_value": rule_value,
                "rule_pattern": rule_pattern,
                "description": description,
                "created_by": created_by
            }
        )
        session.commit()

        logger.info(f"✅ Added blocking rule: {rule_value} ({rule_pattern}) for client {client_domain_id}")
        return {"status": "success", "message": "Blocking rule added"}

    except Exception as e:
        logger.error(f"Failed to add blocking rule: {e}")
        session.rollback()
        raise

def clear_blocking_cache(domain):
    """Clear Redis cache for blocking rules"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)
        cache_key = f"rules:{domain}"
        r.delete(cache_key)
        logger.info(f"Cleared cache for {domain}")
    except Exception as e:
        logger.warning(f"Failed to clear cache (non-critical): {e}")

@app.route('/api/block', methods=['POST'])
def block_sender():
    """
    Block a sender based on email or domain
    """
    try:
        # Log request
        logger.info(f"Request from {request.remote_addr}")
        logger.info(f"Content-Type: {request.content_type}")

        # Parse JSON
        data = request.get_json()
        logger.info(f"Raw data: {data}")

        # Validate required fields
        required_fields = ['sender', 'recipient', 'block_type']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        sender = data['sender']
        recipient = data['recipient']
        block_type = data['block_type']  # 'email', 'domain', 'pattern', 'sender_recipient'
        block_user = data.get('block_user', 'unknown')
        reason = data.get('reason', 'User blocked via MailWatch')
        message_id = data.get('message_id', 'N/A')

        # Handle multiple recipients (comma-separated)
        if ',' in recipient:
            recipient = recipient.split(',')[0].strip()
            logger.info(f"Multiple recipients detected, using first: {recipient}")

        # Extract recipient domain
        recipient_domain = recipient.split('@')[-1] if '@' in recipient else recipient

        # Extract sender domain
        sender_domain = sender.split('@')[-1] if '@' in sender else sender

        # Normalize block_type (MailGuard may send 'sender_recipient')
        if block_type == 'sender_recipient':
            block_type = 'email'
            logger.info(f"Normalized block_type 'sender_recipient' to 'email'")

        # Determine rule type and value based on block_type
        if block_type == 'email':
            rule_type = 'domain'  # We store email blocks as domain rules
            rule_value = sender  # Exact email
            rule_pattern = 'exact'
            description = f"{reason} - Exact email: {sender}"
        elif block_type == 'domain':
            rule_type = 'domain'
            rule_value = f"*@{sender_domain}"  # Wildcard domain
            rule_pattern = 'wildcard'
            description = f"{reason} - Entire domain: {sender_domain}"
        elif block_type == 'pattern':
            rule_type = 'domain'
            sender_user = sender.split('@')[0] if '@' in sender else sender
            rule_value = f"{sender_user}*@{sender_domain}"
            rule_pattern = 'wildcard'
            description = f"{reason} - Pattern: {sender_user}*@{sender_domain}"
        else:
            return jsonify({"error": f"Invalid block_type: {block_type}"}), 400

        logger.info(f"Block request: {sender} → {recipient} (Type: {block_type}, User: {block_user})")

        # Get database session
        session = get_db_connection()

        try:
            # Get or create client_domain_id
            client_domain_id = get_client_domain_id(session, recipient_domain)

            # Add blocking rule
            result = add_blocking_rule(
                session,
                client_domain_id,
                rule_type,
                rule_value,
                rule_pattern,
                description,
                block_user
            )

            # Clear cache
            clear_blocking_cache(recipient_domain)

            # Return success
            return jsonify({
                "success": True,
                "message": result['message'],
                "rule": {
                    "type": rule_type,
                    "value": rule_value,
                    "pattern": rule_pattern,
                    "for_domain": recipient_domain
                }
            }), 200

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error processing block request: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "block-sender-api"}), 200

if __name__ == '__main__':
    logger.info("Starting Block Sender API on port 5003...")
    app.run(host='0.0.0.0', port=5003, debug=False)