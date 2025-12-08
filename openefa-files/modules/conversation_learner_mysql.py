#!/usr/bin/env python3
"""
Conversation Pattern Learning Module (MySQL Version)
Learns from legitimate client conversations to improve spam/ham classification
"""

import json
import re
import mysql.connector
from mysql.connector import pooling
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import hashlib
import os
import configparser

# Read database configuration from .my.cnf
def get_db_config():
    """Load database configuration from .my.cnf file"""
    config = configparser.ConfigParser()
    config.read('/opt/spacyserver/config/.my.cnf')
    return {
        'host': config.get('client', 'host', fallback='localhost'),
        'user': config.get('client', 'user'),
        'password': config.get('client', 'password'),
        'database': config.get('client', 'database'),
        'pool_name': 'conversation_learner_pool',
        'pool_size': 5
    }

# MySQL connection pool for better performance
try:
    db_config = get_db_config()
    connection_pool = pooling.MySQLConnectionPool(**db_config)
except Exception as e:
    print(f"Failed to create connection pool: {e}")
    connection_pool = None
    db_config = None

class ConversationLearner:
    """
    Learns patterns from legitimate client conversations using MySQL.
    Uses privacy-preserving techniques to avoid storing sensitive data.
    """
    
    def __init__(self):
        self.connection_pool = connection_pool
        
    def get_connection(self):
        """Get a connection from the pool"""
        if self.connection_pool:
            return self.connection_pool.get_connection()
        else:
            # Fallback to direct connection using .my.cnf
            return mysql.connector.connect(
                option_files='/opt/spacyserver/config/.my.cnf'
            )
    
    def hash_word(self, word: str) -> str:
        """Hash a word for privacy-preserving storage"""
        salt = "spacy_conv_2025"
        return hashlib.sha256(f"{salt}{word.lower()}".encode()).hexdigest()[:16]
    
    def extract_professional_phrases(self, text: str) -> List[str]:
        """Extract professional/business phrases from text"""
        professional_phrases = [
            'per our discussion', 'as discussed', 'following up',
            'please find attached', 'thank you for', 'looking forward',
            'best regards', 'sincerely', 'please let me know',
            'at your earliest convenience', 'for your review',
            'please advise', 'kindly', 'regarding', 'concerning',
            'as per', 'with reference to', 'further to',
            'please confirm', 'appreciated', 'thanks for',
            'meeting', 'schedule', 'appointment', 'deadline',
            'invoice', 'payment', 'contract', 'agreement',
            'proposal', 'quotation', 'estimate'
        ]
        
        found_phrases = []
        text_lower = text.lower()
        for phrase in professional_phrases:
            if phrase in text_lower:
                found_phrases.append(phrase)
        
        return found_phrases
    
    def extract_conversation_features(self, text: str, sender: str, 
                                     recipients: List[str]) -> Dict:
        """Extract privacy-preserving features from conversation"""
        # Get domains
        sender_domain = sender.split('@')[1].lower() if '@' in sender else ''
        recipient_domains = [r.split('@')[1].lower() for r in recipients if '@' in r]
        
        # Clean text for analysis
        text_clean = re.sub(r'[^\w\s]', ' ', text.lower())
        words = text_clean.split()
        
        # Extract features
        features = {
            'word_hashes': [],
            'professional_phrases': self.extract_professional_phrases(text),
            'text_length': len(text),
            'word_count': len(words),
            'sentence_count': len(re.findall(r'[.!?]+', text)),
            'question_count': text.count('?'),
            'sender_domain': sender_domain,
            'recipient_domains': recipient_domains,
            'has_greeting': any(g in text.lower()[:100] for g in ['dear', 'hi', 'hello', 'good morning', 'good afternoon']),
            'has_signature': any(s in text.lower()[-200:] for s in ['regards', 'sincerely', 'best', 'thanks', 'thank you']),
        }
        
        # Hash non-sensitive words (skip emails, numbers, short words)
        for word in words:
            if (len(word) > 3 and 
                not any(c.isdigit() for c in word) and
                '@' not in word and
                '.' not in word):
                features['word_hashes'].append(self.hash_word(word))
        
        # Remove duplicates
        features['word_hashes'] = list(set(features['word_hashes']))[:100]  # Limit to 100 unique hashes
        
        return features
    
    def learn_from_email(self, msg, text_content: str, spam_score: float) -> bool:
        """
        Learn from an email if it appears legitimate.

        Returns True if learning occurred, False otherwise.
        """
        # Only learn from very low spam score emails initially
        if spam_score > 2.5:
            return False

        # Also update behavioral baseline if available
        try:
            from behavioral_baseline import BehavioralBaseline
            behavior = BehavioralBaseline()

            # Extract recipients for behavioral tracking
            recipients_list = []
            for field in ['To', 'Cc']:
                if msg.get(field):
                    recipients_list.extend([r.strip() for r in msg.get(field).split(',')])

            email_data = {
                'from': msg.get('From', ''),
                'recipients': recipients_list,
                'subject': msg.get('Subject', ''),
                'body': text_content,
                'message_id': msg.get('Message-ID', '')
            }
            behavior.update_baseline(email_data)
        except Exception as e:
            # Don't fail if behavioral module not available
            pass

        # Extract sender and recipients
        sender = msg.get('From', '')
        recipients = []
        for field in ['To', 'Cc']:
            if msg.get(field):
                recipients.extend([r.strip() for r in msg.get(field).split(',')])
        
        if not sender or not recipients:
            return False
        
        # Extract features
        features = self.extract_conversation_features(text_content, sender, recipients)
        
        if not features['sender_domain'] or not features['recipient_domains']:
            return False
        
        # Store patterns in MySQL
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Update vocabulary patterns
            for word_hash in features['word_hashes'][:50]:  # Limit per email
                cursor.execute("""
                    INSERT INTO conversation_vocabulary (word_hash, frequency)
                    VALUES (%s, 1)
                    ON DUPLICATE KEY UPDATE 
                        frequency = frequency + 1,
                        last_seen = CURRENT_TIMESTAMP
                """, (word_hash,))
            
            # Update domain relationships
            for recipient_domain in features['recipient_domains']:
                cursor.execute("""
                    INSERT INTO conversation_relationships 
                    (sender_domain, recipient_domain, message_count, avg_spam_score)
                    VALUES (%s, %s, 1, %s)
                    ON DUPLICATE KEY UPDATE 
                        message_count = message_count + 1,
                        avg_spam_score = (avg_spam_score * message_count + %s) / (message_count + 1),
                        last_communication = CURRENT_TIMESTAMP
                """, (features['sender_domain'], recipient_domain, spam_score, spam_score))
            
            # Update phrase patterns
            for phrase in features['professional_phrases']:
                cursor.execute("""
                    INSERT INTO conversation_phrases (phrase, frequency, avg_spam_score)
                    VALUES (%s, 1, %s)
                    ON DUPLICATE KEY UPDATE 
                        frequency = frequency + 1,
                        avg_spam_score = (avg_spam_score * frequency + %s) / (frequency + 1),
                        last_seen = CURRENT_TIMESTAMP
                """, (phrase, spam_score, spam_score))
            
            # Update conversation statistics for the domain
            cursor.execute("""
                INSERT INTO conversation_domain_stats 
                (domain, total_messages, avg_message_length, avg_spam_score)
                VALUES (%s, 1, %s, %s)
                ON DUPLICATE KEY UPDATE
                    total_messages = total_messages + 1,
                    avg_message_length = (avg_message_length * total_messages + %s) / (total_messages + 1),
                    avg_spam_score = (avg_spam_score * total_messages + %s) / (total_messages + 1),
                    last_updated = CURRENT_TIMESTAMP
            """, (features['sender_domain'], features['text_length'], spam_score, 
                  features['text_length'], spam_score))
            
            # Update daily progress
            today = datetime.now().strftime('%Y-%m-%d')
            cursor.execute("""
                INSERT INTO conversation_learning_progress 
                (date, patterns_learned, emails_processed)
                VALUES (%s, 1, 1)
                ON DUPLICATE KEY UPDATE
                    patterns_learned = patterns_learned + 1,
                    emails_processed = emails_processed + 1
            """, (today,))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error learning from email: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()
    
    def calculate_legitimacy_score(self, msg, text_content: str) -> Dict:
        """
        Calculate how legitimate this email appears based on learned patterns.
        
        Returns dict with scores and confidence levels.
        """
        # Extract sender and recipients
        sender = msg.get('From', '')
        recipients = []
        for field in ['To', 'Cc']:
            if msg.get(field):
                recipients.extend([r.strip() for r in msg.get(field).split(',')])
        
        if not sender:
            return {'overall_score': 0, 'confidence': 0, 'adjustment': 0}
        
        # Extract features
        features = self.extract_conversation_features(text_content, sender, recipients)
        
        scores = {
            'vocabulary_match': 0.0,
            'domain_relationship': 0.0,
            'phrase_match': 0.0,
            'conversation_style': 0.0,
            'overall_score': 0.0,
            'confidence': 0.0,
            'adjustment': 0.0
        }
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Check vocabulary overlap
            if features['word_hashes']:
                # Security: Validate all hashes are integers to prevent injection
                word_hashes = [int(h) for h in features['word_hashes']]
                format_strings = ','.join(['%s'] * len(word_hashes))
                query = """
                    SELECT COUNT(*) FROM conversation_vocabulary
                    WHERE word_hash IN ({})
                    AND frequency > 2
                """.format(format_strings)
                cursor.execute(query, word_hashes)
                matches = cursor.fetchone()[0]
                scores['vocabulary_match'] = min(matches / 10, 1.0)  # Scale to 0-1
            
            # Check domain relationships
            if features['sender_domain'] and features['recipient_domains']:
                for recipient_domain in features['recipient_domains']:
                    cursor.execute("""
                        SELECT message_count, avg_spam_score 
                        FROM conversation_relationships
                        WHERE sender_domain = %s AND recipient_domain = %s
                        AND message_count > 2
                    """, (features['sender_domain'], recipient_domain))
                    result = cursor.fetchone()
                    if result:
                        count, avg_spam = result
                        # Strong relationship with low spam history
                        if count > 5 and avg_spam < 3:
                            scores['domain_relationship'] = 1.0
                        elif count > 2:
                            scores['domain_relationship'] = 0.5
                        break
            
            # Check professional phrases
            if features['professional_phrases']:
                # Security: Sanitize phrases (truncate to max 100 chars each to prevent injection)
                safe_phrases = [str(p)[:100] for p in features['professional_phrases']]
                format_strings = ','.join(['%s'] * len(safe_phrases))
                query = """
                    SELECT COUNT(*) FROM conversation_phrases
                    WHERE phrase IN ({})
                    AND frequency > 3
                """.format(format_strings)
                cursor.execute(query, safe_phrases)
                matches = cursor.fetchone()[0]
                scores['phrase_match'] = min(matches / 3, 1.0)
            
            # Check conversation style (greeting + signature + normal length)
            style_score = 0
            if features['has_greeting']:
                style_score += 0.3
            if features['has_signature']:
                style_score += 0.3
            if 100 < features['text_length'] < 10000:
                style_score += 0.4
            scores['conversation_style'] = style_score
            
            # Get domain statistics for confidence
            cursor.execute("""
                SELECT total_messages FROM conversation_domain_stats
                WHERE domain = %s
            """, (features['sender_domain'],))
            result = cursor.fetchone()
            domain_history = result[0] if result else 0
            
            # Calculate overall score with weights
            weights = {
                'vocabulary_match': 0.25,
                'domain_relationship': 0.35,
                'phrase_match': 0.25,
                'conversation_style': 0.15
            }
            
            scores['overall_score'] = sum(
                scores[key] * weight for key, weight in weights.items()
            )
            
            # Calculate confidence based on how much we've learned
            cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 5')
            vocab_size = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM conversation_relationships WHERE message_count > 5')
            relationship_count = cursor.fetchone()[0]
            
            # Confidence increases with more data
            scores['confidence'] = min(
                (vocab_size / 500) * 0.3 +  # Vocabulary knowledge
                (relationship_count / 50) * 0.4 +  # Relationship knowledge
                (min(domain_history, 100) / 100) * 0.3,  # Domain history
                1.0
            )
            
            # Get max adjustment from config
            cursor.execute("""
                SELECT config_value FROM conversation_learning_config
                WHERE config_key = 'max_adjustment'
            """)
            max_adjustment = float(cursor.fetchone()[0] or 2.0)
            
            # Calculate spam score adjustment
            if scores['overall_score'] > 0.7 and scores['confidence'] > 0.4:
                # Strong legitimate pattern match
                scores['adjustment'] = -max_adjustment * scores['overall_score'] * scores['confidence']
            elif scores['overall_score'] > 0.5 and scores['confidence'] > 0.3:
                # Moderate legitimate pattern match
                scores['adjustment'] = -(max_adjustment/2) * scores['overall_score'] * scores['confidence']
            elif scores['overall_score'] < 0.2 and scores['confidence'] > 0.5:
                # Doesn't match known patterns (suspicious)
                scores['adjustment'] = 0.5 * (1 - scores['overall_score']) * scores['confidence']
            else:
                scores['adjustment'] = 0
            
            return scores
            
        except Exception as e:
            print(f"Error calculating legitimacy: {e}")
            return scores
        finally:
            cursor.close()
            conn.close()
    
    def get_statistics(self) -> Dict:
        """Get learning statistics for monitoring"""
        conn = self.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        stats = {}
        try:
            # Get stats from view
            cursor.execute('SELECT * FROM conversation_learning_stats')
            result = cursor.fetchone()
            if result:
                stats.update(result)
            
            # Get top relationships
            cursor.execute("""
                SELECT sender_domain, recipient_domain, message_count 
                FROM conversation_relationships 
                ORDER BY message_count DESC 
                LIMIT 5
            """)
            stats['top_relationships'] = cursor.fetchall()
            
        except Exception as e:
            print(f"Error getting statistics: {e}")
        finally:
            cursor.close()
            conn.close()
        
        return stats


def analyze_with_learning(msg, text_content: str, spam_score: float) -> Dict:
    """
    Main entry point for conversation learning and analysis.
    
    Returns:
        Dict with legitimacy scores and spam adjustment
    """
    try:
        learner = ConversationLearner()
        
        # Calculate legitimacy based on learned patterns
        legitimacy = learner.calculate_legitimacy_score(msg, text_content)
        
        # Learn from this email if it's legitimate
        learned = False
        if spam_score < 2.5:  # Conservative learning threshold
            learned = learner.learn_from_email(msg, text_content, spam_score)
        
        return {
            'legitimacy_scores': legitimacy,
            'spam_adjustment': legitimacy['adjustment'],
            'learned_from_email': learned,
            'confidence': legitimacy['confidence']
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'legitimacy_scores': {'overall_score': 0, 'confidence': 0},
            'spam_adjustment': 0.0,
            'learned_from_email': False
        }