#!/usr/bin/env python3
"""
Conversation Pattern Learning Module
Learns from legitimate client conversations to improve spam/ham classification
"""

import json
import re
import numpy as np
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set, Optional
import hashlib
from pathlib import Path
import sqlite3
import os

class ConversationLearner:
    """
    Learns patterns from legitimate client conversations to improve classification.
    Uses privacy-preserving techniques to avoid storing sensitive data.
    """
    
    def __init__(self, db_path: str = "/opt/spacyserver/data/conversation_patterns.db"):
        self.db_path = db_path
        self.ensure_database()
        
    def ensure_database(self):
        """Create database and tables if they don't exist"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables for pattern storage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vocabulary_patterns (
                word_hash TEXT PRIMARY KEY,
                frequency INTEGER DEFAULT 1,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_relationships (
                sender_domain TEXT,
                recipient_domain TEXT,
                message_count INTEGER DEFAULT 1,
                last_communication TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                avg_spam_score REAL DEFAULT 0,
                PRIMARY KEY (sender_domain, recipient_domain)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phrase_patterns (
                phrase TEXT PRIMARY KEY,
                frequency INTEGER DEFAULT 1,
                avg_spam_score REAL DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversation_stats (
                domain TEXT PRIMARY KEY,
                total_messages INTEGER DEFAULT 0,
                avg_length INTEGER DEFAULT 0,
                avg_spam_score REAL DEFAULT 0,
                common_topics TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
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
        
        # Store patterns in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Update vocabulary patterns
            for word_hash in features['word_hashes'][:50]:  # Limit per email
                cursor.execute('''
                    INSERT INTO vocabulary_patterns (word_hash, frequency, last_seen)
                    VALUES (?, 1, CURRENT_TIMESTAMP)
                    ON CONFLICT(word_hash) 
                    DO UPDATE SET frequency = frequency + 1, last_seen = CURRENT_TIMESTAMP
                ''', (word_hash,))
            
            # Update domain relationships
            for recipient_domain in features['recipient_domains']:
                cursor.execute('''
                    INSERT INTO domain_relationships 
                    (sender_domain, recipient_domain, message_count, avg_spam_score, last_communication)
                    VALUES (?, ?, 1, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(sender_domain, recipient_domain)
                    DO UPDATE SET 
                        message_count = message_count + 1,
                        avg_spam_score = (avg_spam_score * message_count + ?) / (message_count + 1),
                        last_communication = CURRENT_TIMESTAMP
                ''', (features['sender_domain'], recipient_domain, spam_score, spam_score))
            
            # Update phrase patterns
            for phrase in features['professional_phrases']:
                cursor.execute('''
                    INSERT INTO phrase_patterns (phrase, frequency, avg_spam_score, last_seen)
                    VALUES (?, 1, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(phrase)
                    DO UPDATE SET 
                        frequency = frequency + 1,
                        avg_spam_score = (avg_spam_score * frequency + ?) / (frequency + 1),
                        last_seen = CURRENT_TIMESTAMP
                ''', (phrase, spam_score, spam_score))
            
            # Update conversation statistics for the domain
            cursor.execute('''
                INSERT INTO conversation_stats 
                (domain, total_messages, avg_length, avg_spam_score, last_updated)
                VALUES (?, 1, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(domain)
                DO UPDATE SET
                    total_messages = total_messages + 1,
                    avg_length = (avg_length * total_messages + ?) / (total_messages + 1),
                    avg_spam_score = (avg_spam_score * total_messages + ?) / (total_messages + 1),
                    last_updated = CURRENT_TIMESTAMP
            ''', (features['sender_domain'], features['text_length'], spam_score, 
                  features['text_length'], spam_score))
            
            conn.commit()
            return True
            
        except Exception as e:
            print(f"Error learning from email: {e}")
            conn.rollback()
            return False
        finally:
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
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check vocabulary overlap
            if features['word_hashes']:
                placeholders = ','.join(['?' for _ in features['word_hashes']])
                cursor.execute(f'''
                    SELECT COUNT(*) FROM vocabulary_patterns 
                    WHERE word_hash IN ({placeholders})
                    AND frequency > 2
                ''', features['word_hashes'])
                matches = cursor.fetchone()[0]
                scores['vocabulary_match'] = min(matches / 10, 1.0)  # Scale to 0-1
            
            # Check domain relationships
            if features['sender_domain'] and features['recipient_domains']:
                for recipient_domain in features['recipient_domains']:
                    cursor.execute('''
                        SELECT message_count, avg_spam_score 
                        FROM domain_relationships
                        WHERE sender_domain = ? AND recipient_domain = ?
                        AND message_count > 2
                    ''', (features['sender_domain'], recipient_domain))
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
                placeholders = ','.join(['?' for _ in features['professional_phrases']])
                cursor.execute(f'''
                    SELECT COUNT(*) FROM phrase_patterns 
                    WHERE phrase IN ({placeholders})
                    AND frequency > 3
                ''', features['professional_phrases'])
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
            cursor.execute('''
                SELECT total_messages FROM conversation_stats
                WHERE domain = ?
            ''', (features['sender_domain'],))
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
            cursor.execute('SELECT COUNT(*) FROM vocabulary_patterns WHERE frequency > 5')
            vocab_size = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM domain_relationships WHERE message_count > 5')
            relationship_count = cursor.fetchone()[0]
            
            # Confidence increases with more data
            scores['confidence'] = min(
                (vocab_size / 500) * 0.3 +  # Vocabulary knowledge
                (relationship_count / 50) * 0.4 +  # Relationship knowledge
                (min(domain_history, 100) / 100) * 0.3,  # Domain history
                1.0
            )
            
            # Calculate spam score adjustment
            if scores['overall_score'] > 0.7 and scores['confidence'] > 0.4:
                # Strong legitimate pattern match
                scores['adjustment'] = -2.0 * scores['overall_score'] * scores['confidence']
            elif scores['overall_score'] > 0.5 and scores['confidence'] > 0.3:
                # Moderate legitimate pattern match
                scores['adjustment'] = -1.0 * scores['overall_score'] * scores['confidence']
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
            conn.close()
    
    def get_statistics(self) -> Dict:
        """Get learning statistics for monitoring"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        try:
            cursor.execute('SELECT COUNT(*) FROM vocabulary_patterns')
            stats['vocabulary_size'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM domain_relationships')
            stats['relationships'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM phrase_patterns')
            stats['phrases'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*), AVG(total_messages) FROM conversation_stats')
            result = cursor.fetchone()
            stats['domains_tracked'] = result[0]
            stats['avg_messages_per_domain'] = result[1] or 0
            
            cursor.execute('''
                SELECT sender_domain, recipient_domain, message_count 
                FROM domain_relationships 
                ORDER BY message_count DESC 
                LIMIT 5
            ''')
            stats['top_relationships'] = cursor.fetchall()
            
        except Exception as e:
            print(f"Error getting statistics: {e}")
        finally:
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