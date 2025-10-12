#!/usr/bin/env python3
"""
Quarantine Release Feedback API
Receives notifications from MailGuard when users release emails from quarantine
Uses this feedback to improve SpaCy's spam detection accuracy
"""

from flask import Flask, request, jsonify
import logging
import json
import mysql.connector
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, '/opt/spacyserver')
from modules.conversation_learner_mysql import ConversationLearner

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/spacyserver/logs/quarantine_feedback.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'spacy_user',
    'database': 'spacy_email_db'
}

# Load MySQL password from config
try:
    with open('/opt/spacyserver/config/.my.cnf', 'r') as f:
        for line in f:
            if line.startswith('password='):
                DB_CONFIG['password'] = line.split('=')[1].strip()
                break
except Exception as e:
    logger.error(f"Failed to load database password: {e}")

def update_sender_trust(sender_email, subject, recipient):
    """
    Update trust scores for senders when emails are released from quarantine
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Check if sender is already in trusted_senders
        cursor.execute("""
            SELECT trust_score, release_count 
            FROM trusted_senders 
            WHERE sender_email = %s
        """, (sender_email,))
        
        result = cursor.fetchone()
        
        if result:
            # Update existing sender
            trust_score, release_count = result
            new_trust_score = min(10, trust_score + 1)  # Increase trust, max 10
            new_release_count = release_count + 1
            
            cursor.execute("""
                UPDATE trusted_senders 
                SET trust_score = %s, 
                    release_count = %s,
                    last_released = NOW(),
                    last_subject = %s
                WHERE sender_email = %s
            """, (new_trust_score, new_release_count, subject, sender_email))
            
            logger.info(f"Updated trust for {sender_email}: score={new_trust_score}, releases={new_release_count}")
            
            # Auto-whitelist after 3 releases
            if new_release_count >= 3:
                add_to_whitelist(sender_email, recipient)
        else:
            # Add new sender
            cursor.execute("""
                INSERT INTO trusted_senders 
                (sender_email, trust_score, release_count, first_seen, last_released, last_subject)
                VALUES (%s, 5, 1, NOW(), NOW(), %s)
            """, (sender_email, subject))
            
            logger.info(f"Added new trusted sender: {sender_email}")
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"Failed to update sender trust: {e}")
        return False

def add_to_whitelist(sender_email, recipient_domain):
    """
    Add sender to BEC config whitelist after multiple releases
    """
    try:
        import json
        
        # Load BEC config
        with open('/opt/spacyserver/config/bec_config.json', 'r') as f:
            config = json.load(f)
        
        # Check if already whitelisted
        senders = config.get('whitelist', {}).get('authentication_aware', {}).get('senders', {})
        
        if sender_email.lower() not in [s.lower() for s in senders.keys()]:
            # Add to whitelist
            senders[sender_email] = {
                "require_auth": ["spf"],
                "description": f"Auto-whitelisted after 3+ quarantine releases for {recipient_domain}",
                "bypass_financial_checks": True,
                "trust_score_bonus": 3,
                "trust_level": 4,
                "auto_whitelisted": True,
                "whitelist_date": datetime.now().isoformat()
            }
            
            # Save config
            with open('/opt/spacyserver/config/bec_config.json', 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Auto-whitelisted {sender_email} after multiple releases")
            
    except Exception as e:
        logger.error(f"Failed to add to whitelist: {e}")

def train_on_released_email(sender_email, subject, recipient):
    """
    Use released emails to train the conversation learning system
    """
    try:
        learner = ConversationLearner()
        
        # Create a synthetic email data structure for learning
        email_data = {
            'from': sender_email,
            'to': recipient,
            'subject': subject,
            'spam_score': 0.0,  # Treat as definitely not spam
            'is_legitimate': True,
            'user_released': True
        }
        
        # Create minimal text content from subject for learning
        text_content = subject if subject else f"Released email from {sender_email}"
        
        # Force learning from this email with required parameters
        learner.learn_from_email(email_data, text_content, 0.0)
        
        logger.info(f"Trained conversation learner on released email from {sender_email}")
        
    except Exception as e:
        logger.error(f"Failed to train on released email: {e}")

@app.route('/api/feedback/release', methods=['POST'])
def handle_release():
    """
    Handle quarantine release notifications from MailGuard
    Expected JSON payload:
    {
        "message_id": "4cLmcF5Ww9zYmV6b",
        "sender": "user@example.com",
        "recipient": "user@yourdomain.com",
        "subject": "Email subject",
        "spam_score": 8.5,
        "release_time": "2025-09-09 10:00:00",
        "release_user": "admin"
    }
    """
    try:
        # Log raw request data for debugging
        logger.info(f"Request from {request.remote_addr}")
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"Raw data: {request.data[:500]}")  # First 500 chars
        
        data = request.json
        
        if not data:
            logger.error(f"No JSON data in request from {request.remote_addr}")
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract fields
        message_id = data.get('message_id')
        sender = data.get('sender')
        recipient = data.get('recipient')
        subject = data.get('subject', '')
        spam_score = data.get('spam_score', 0)
        release_user = data.get('release_user', 'unknown')
        
        # If sender is null, try to extract from recipient domain for now
        if not sender:
            sender = f"unknown@{message_id[:8]}"  # Use partial message ID as placeholder
            logger.warning(f"No sender info for {message_id}, using placeholder: {sender}")
        
        if not recipient:
            return jsonify({'error': 'Missing recipient'}), 400
        
        logger.info(f"Release notification: {sender} -> {recipient} (ID: {message_id}, Score: {spam_score})")
        
        # Update sender trust
        update_sender_trust(sender, subject, recipient)
        
        # Train conversation learner
        train_on_released_email(sender, subject, recipient)
        
        # Log the release event
        try:
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine_releases 
                (message_id, sender, recipient, subject, original_spam_score, release_time, release_user)
                VALUES (%s, %s, %s, %s, %s, NOW(), %s)
            """, (message_id, sender, recipient, subject, spam_score, release_user))
            conn.commit()
            cursor.close()
            conn.close()
        except:
            pass  # Table might not exist yet
        
        return jsonify({
            'status': 'success',
            'message': f'Processed release feedback for {sender}'
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing release feedback: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/feedback/stats', methods=['GET'])
def get_stats():
    """
    Get statistics about quarantine releases and learning
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)
        
        # Get release statistics
        cursor.execute("""
            SELECT 
                COUNT(*) as total_releases,
                COUNT(DISTINCT sender_email) as unique_senders,
                COUNT(CASE WHEN release_count >= 3 THEN 1 END) as auto_whitelisted
            FROM trusted_senders
        """)
        
        stats = cursor.fetchone()
        
        # Get recent releases
        cursor.execute("""
            SELECT sender_email, trust_score, release_count, last_released
            FROM trusted_senders
            ORDER BY last_released DESC
            LIMIT 10
        """)
        
        recent = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'statistics': stats,
            'recent_releases': recent
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

if __name__ == '__main__':
    # Create tables if they don't exist
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Create trusted_senders table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trusted_senders (
                sender_email VARCHAR(255) PRIMARY KEY,
                trust_score INT DEFAULT 5,
                release_count INT DEFAULT 1,
                first_seen DATETIME,
                last_released DATETIME,
                last_subject VARCHAR(500),
                INDEX idx_trust (trust_score),
                INDEX idx_releases (release_count)
            )
        """)
        
        # Create quarantine_releases log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_releases (
                id INT AUTO_INCREMENT PRIMARY KEY,
                message_id VARCHAR(100),
                sender VARCHAR(255),
                recipient VARCHAR(255),
                subject VARCHAR(500),
                original_spam_score FLOAT,
                release_time DATETIME,
                release_user VARCHAR(100),
                INDEX idx_sender (sender),
                INDEX idx_time (release_time)
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("Database tables initialized")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    # Run the API
    app.run(host='0.0.0.0', port=5001, debug=False)