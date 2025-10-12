#!/usr/bin/env python3
"""
Feed a specific email into the conversation learning system by Message-ID
Retrieves email details from the database and feeds it as a good example
"""

import sys
import mysql.connector
from datetime import datetime
import hashlib
import json

def get_db_connection():
    """Connect to the database using the same credentials as the system"""
    return mysql.connector.connect(
        option_files='/opt/spacyserver/config/.my.cnf'
    )

def hash_text(text):
    """Create privacy-preserving hash of text"""
    return hashlib.sha256(text.encode()).hexdigest()[:16]

def get_email_by_message_id(message_id):
    """Retrieve email details from database by Message-ID"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Support partial matching - if no @ sign, search as prefix
        if '@' not in message_id:
            # Partial match - add wildcard for domain part
            search_pattern = f"{message_id}%"
            
            # Try email_analysis table first with LIKE pattern
            cursor.execute("""
                SELECT message_id, sender, recipients, subject, 
                       subject as body_preview, spam_score, timestamp
                FROM email_analysis 
                WHERE message_id LIKE %s OR message_id LIKE %s
                ORDER BY timestamp DESC
                LIMIT 1
            """, (search_pattern, f"<{search_pattern}"))
            
            result = cursor.fetchone()
            
            if not result:
                # Try spacy_analysis table as fallback
                cursor.execute("""
                    SELECT message_id, sender, recipients, subject,
                           subject as body_preview, spam_score, timestamp
                    FROM spacy_analysis
                    WHERE message_id LIKE %s OR message_id LIKE %s
                    ORDER BY timestamp DESC
                    LIMIT 1
                """, (search_pattern, f"<{search_pattern}"))
                result = cursor.fetchone()
        else:
            # Full message ID provided - exact match
            cursor.execute("""
                SELECT message_id, sender, recipients, subject, 
                       subject as body_preview, spam_score, timestamp
                FROM email_analysis 
                WHERE message_id = %s OR message_id = %s
                LIMIT 1
            """, (message_id, f"<{message_id}>"))
            
            result = cursor.fetchone()
            
            if not result:
                # Try spacy_analysis table as fallback
                cursor.execute("""
                    SELECT message_id, sender, recipients, subject,
                           subject as body_preview, spam_score, timestamp
                    FROM spacy_analysis
                    WHERE message_id = %s OR message_id = %s
                    LIMIT 1
                """, (message_id, f"<{message_id}>"))
                result = cursor.fetchone()
        
        return result
        
    finally:
        cursor.close()
        conn.close()

def feed_email_to_learning(email_data, override_spam_score=None):
    """Feed email data into the conversation learning system"""
    
    if not email_data:
        return False, "Email not found in database"
    
    sender = email_data['sender']
    recipients = email_data['recipients'].split(',') if email_data['recipients'] else []
    subject = email_data['subject'] or ""
    body = email_data.get('body_preview', '') or subject  # Use subject as body if no body available
    spam_score = override_spam_score if override_spam_score is not None else (email_data['spam_score'] or 0.0)
    
    # Extract domains
    sender_domain = sender.split('@')[-1].lower() if '@' in sender else 'unknown'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Add to conversation_relationships
        for recipient in recipients:
            recipient = recipient.strip()
            if '@' in recipient:
                recipient_domain = recipient.split('@')[-1].lower()
                
                cursor.execute("""
                    INSERT INTO conversation_relationships 
                    (sender_domain, recipient_domain, message_count, avg_spam_score, last_communication)
                    VALUES (%s, %s, 1, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                    message_count = message_count + 1,
                    avg_spam_score = (avg_spam_score * message_count + VALUES(avg_spam_score)) / (message_count + 1),
                    last_communication = NOW()
                """, (sender_domain, recipient_domain, spam_score))
        
        # Add vocabulary patterns
        words = (subject + " " + body).lower().split()
        unique_words = list(set(w for w in words if len(w) > 3 and w.isalnum()))
        
        for word in unique_words[:30]:  # Increased limit for better learning
            word_hash = hash_text(word)
            cursor.execute("""
                INSERT INTO conversation_vocabulary
                (word_hash, frequency, last_seen)
                VALUES (%s, 1, NOW())
                ON DUPLICATE KEY UPDATE
                frequency = frequency + 1,
                last_seen = NOW()
            """, (word_hash,))
        
        # Add common professional phrases if found
        professional_phrases = [
            "best regards", "thank you", "please find attached", "looking forward",
            "schedule a meeting", "follow up", "pursuant to", "in accordance",
            "policy", "invoice", "contract", "agreement", "proposal"
        ]
        
        body_lower = body.lower()
        for phrase in professional_phrases:
            if phrase in body_lower or phrase in subject.lower():
                cursor.execute("""
                    INSERT INTO conversation_phrases
                    (phrase, frequency, avg_spam_score)
                    VALUES (%s, 1, %s)
                    ON DUPLICATE KEY UPDATE
                    frequency = frequency + 1,
                    avg_spam_score = (avg_spam_score * frequency + VALUES(avg_spam_score)) / (frequency + 1)
                """, (phrase, spam_score))
        
        # Update domain stats
        cursor.execute("""
            INSERT INTO conversation_domain_stats
            (domain, total_messages, avg_spam_score, last_updated)
            VALUES (%s, 1, %s, NOW())
            ON DUPLICATE KEY UPDATE
            total_messages = total_messages + 1,
            avg_spam_score = (avg_spam_score * total_messages + VALUES(avg_spam_score)) / (total_messages + 1),
            last_updated = NOW()
        """, (sender_domain, spam_score))
        
        conn.commit()
        
        return True, {
            'sender': sender,
            'recipients': recipients,
            'subject': subject[:50] + '...' if len(subject) > 50 else subject,
            'spam_score': spam_score,
            'vocabulary_count': len(unique_words[:30]),
            'sender_domain': sender_domain
        }
        
    except Exception as e:
        conn.rollback()
        return False, f"Error feeding email: {str(e)}"
    finally:
        cursor.close()
        conn.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: feed_email_by_id.py <message_id> [override_spam_score]")
        sys.exit(1)
    
    message_id = sys.argv[1]
    override_score = float(sys.argv[2]) if len(sys.argv) > 2 else None
    
    # Get email from database
    email_data = get_email_by_message_id(message_id)
    
    if not email_data:
        print(f"❌ Email with Message-ID '{message_id}' not found in database")
        sys.exit(1)
    
    # Feed to learning system
    success, result = feed_email_to_learning(email_data, override_score)
    
    if success:
        print(f"✅ Successfully fed email to learning system:")
        print(f"   From: {result['sender']}")
        print(f"   To: {', '.join(result['recipients'][:2])}{'...' if len(result['recipients']) > 2 else ''}")
        print(f"   Subject: {result['subject']}")
        print(f"   Spam Score: {result['spam_score']:.2f}")
        print(f"   Added {result['vocabulary_count']} vocabulary patterns")
        print(f"   Updated domain stats for: {result['sender_domain']}")
    else:
        print(f"❌ Failed: {result}")
        sys.exit(1)

if __name__ == "__main__":
    main()