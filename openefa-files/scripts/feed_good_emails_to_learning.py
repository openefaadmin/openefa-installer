#!/usr/bin/env python3
"""
Feed historical good emails into the conversation learning system
This helps train the system on legitimate communication patterns
"""

import sys
import json
import mysql.connector
from datetime import datetime
import hashlib
import argparse

def get_db_connection():
    """Connect to the database using the same credentials as the system"""
    return mysql.connector.connect(
        option_files='/opt/spacyserver/config/.my.cnf'
    )

def hash_text(text):
    """Create privacy-preserving hash of text"""
    return hashlib.sha256(text.encode()).hexdigest()[:16]

def feed_email_to_learning(sender_email, recipient_emails, subject, body_sample, spam_score=0.0):
    """
    Feed a known good email into the learning system
    
    Args:
        sender_email: Sender's email address
        recipient_emails: List of recipient email addresses
        subject: Email subject line
        body_sample: Sample of email body text
        spam_score: Original spam score (lower is better)
    """
    
    # Extract domains
    sender_domain = sender_email.split('@')[-1].lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Add to conversation_relationships
        for recipient in recipient_emails:
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
        
        # Add vocabulary patterns from subject and body
        words = (subject + " " + body_sample).lower().split()
        unique_words = list(set(w for w in words if len(w) > 3 and w.isalnum()))
        
        for word in unique_words[:20]:  # Limit to 20 most relevant words
            word_hash = hash_text(word)
            cursor.execute("""
                INSERT INTO conversation_vocabulary
                (word_hash, frequency, last_seen)
                VALUES (%s, 1, NOW())
                ON DUPLICATE KEY UPDATE
                frequency = frequency + 1,
                last_seen = NOW()
            """, (word_hash,))
        
        # Add professional phrases
        if "policy" in body_sample.lower() or "insurance" in body_sample.lower():
            phrases = [
                "insurance policy", "deductible", "premium", 
                "coverage", "business insurance"
            ]
            for phrase in phrases:
                if phrase in body_sample.lower():
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
        print(f"✓ Successfully fed email from {sender_email} into learning system")
        print(f"  - Added/updated relationship: {sender_domain} → {recipient_domain}")
        print(f"  - Added {len(unique_words[:20])} vocabulary patterns")
        print(f"  - Trust score: {1.0 - (spam_score / 10.0):.2f}")
        
    except Exception as e:
        print(f"✗ Error feeding email: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Feed good emails into conversation learning system")
    parser.add_argument("--sender", required=True, help="Sender email address")
    parser.add_argument("--recipients", required=True, help="Comma-separated recipient emails")
    parser.add_argument("--subject", default="", help="Email subject")
    parser.add_argument("--body", default="", help="Sample of email body")
    parser.add_argument("--score", type=float, default=0.0, help="Spam score (lower is better)")

    args = parser.parse_args()

    recipients = [r.strip() for r in args.recipients.split(',')]
    feed_email_to_learning(
        args.sender,
        recipients,
        args.subject,
        args.body,
        args.score
    )

    print("\n✓ Email successfully added to learning system")