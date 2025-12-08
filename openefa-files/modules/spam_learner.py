"""
Spam Pattern Learning Module
Learns from user feedback (mark as spam / mark as not spam) and adjusts pattern weights.
Uses simple pattern-based weight adjustment instead of Bayesian filtering.
"""

import mysql.connector
import re
import logging
import os
from typing import List, Dict, Set
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

logger = logging.getLogger(__name__)


class SpamLearner:
    """
    Learns spam patterns from user feedback and adjusts detection weights.
    """

    def __init__(self, db_config=None):
        """Initialize the spam learner with database connection"""
        self.db_config = db_config or {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'spacy_user'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME', 'spacy_email_db'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'autocommit': False
        }

        # Learning rate - how much to adjust weights per feedback
        self.spam_weight_increase = 1.0  # Add 1.0 points when pattern seen in spam
        self.ham_weight_decrease = -0.5  # Subtract 0.5 points when pattern seen in ham

        # Confidence threshold - only apply learned weights when confidence > this
        self.min_confidence_threshold = 0.6  # 60% confidence required
        self.min_observations = 3  # Need at least 3 observations before applying

    def learn_from_spam(self, email_data: Dict, client_domain_id: int, user_email: str) -> Dict:
        """
        Learn patterns from an email marked as spam.

        Args:
            email_data: Dict with 'subject', 'body', 'sender', 'headers', etc.
            client_domain_id: Domain ID where this spam was reported
            user_email: User who marked it as spam

        Returns:
            Dict with learning results
        """
        try:
            patterns = self._extract_patterns(email_data)

            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor(dictionary=True)

            patterns_learned = 0
            for pattern_type, pattern_values in patterns.items():
                for pattern_value in pattern_values:
                    # Update or insert pattern weight
                    self._update_pattern_weight(
                        cursor,
                        client_domain_id,
                        pattern_type,
                        pattern_value,
                        is_spam=True,
                        user_email=user_email
                    )
                    patterns_learned += 1

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"Learned {patterns_learned} spam patterns from email for domain {client_domain_id}")

            return {
                'success': True,
                'patterns_learned': patterns_learned,
                'pattern_types': list(patterns.keys())
            }

        except Exception as e:
            logger.error(f"Error learning from spam: {e}")
            return {'success': False, 'error': str(e)}

    def learn_from_ham(self, email_data: Dict, client_domain_id: int, user_email: str) -> Dict:
        """
        Learn patterns from an email marked as NOT spam (ham/safe).
        Reduces weights for patterns that incorrectly flagged it.

        Args:
            email_data: Dict with 'subject', 'body', 'sender', 'headers', etc.
            client_domain_id: Domain ID where this was marked safe
            user_email: User who marked it as safe

        Returns:
            Dict with learning results
        """
        try:
            patterns = self._extract_patterns(email_data)

            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor(dictionary=True)

            patterns_learned = 0
            for pattern_type, pattern_values in patterns.items():
                for pattern_value in pattern_values:
                    # Update pattern weight (decrease for false positive)
                    self._update_pattern_weight(
                        cursor,
                        client_domain_id,
                        pattern_type,
                        pattern_value,
                        is_spam=False,
                        user_email=user_email
                    )
                    patterns_learned += 1

            conn.commit()
            cursor.close()
            conn.close()

            logger.info(f"Learned {patterns_learned} ham patterns from email for domain {client_domain_id}")

            return {
                'success': True,
                'patterns_learned': patterns_learned,
                'pattern_types': list(patterns.keys())
            }

        except Exception as e:
            logger.error(f"Error learning from ham: {e}")
            return {'success': False, 'error': str(e)}

    def _extract_patterns(self, email_data: Dict) -> Dict[str, Set[str]]:
        """
        Extract learnable patterns from an email.

        Returns:
            Dict of pattern_type -> set of pattern values
        """
        patterns = {
            'phishing_phrase': set(),
            'url_pattern': set(),
            'sender_domain': set(),
            'subject_keyword': set()
        }

        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        sender = email_data.get('sender', '').lower()

        # Extract sender domain
        if '@' in sender:
            if '<' in sender and '>' in sender:
                sender = sender.split('<')[1].split('>')[0]
            sender_domain = sender.split('@')[1] if '@' in sender else sender
            patterns['sender_domain'].add(sender_domain)

        # Extract significant phrases from subject (2-4 word phrases)
        subject_words = re.findall(r'\b\w+\b', subject)
        for i in range(len(subject_words) - 1):
            # 2-word phrases
            phrase = f"{subject_words[i]} {subject_words[i+1]}"
            if len(phrase) > 5:  # Skip very short phrases
                patterns['subject_keyword'].add(phrase)

            # 3-word phrases
            if i < len(subject_words) - 2:
                phrase = f"{subject_words[i]} {subject_words[i+1]} {subject_words[i+2]}"
                if len(phrase) > 10:
                    patterns['phishing_phrase'].add(phrase)

        # Extract significant phrases from body
        body_text = subject + " " + body

        # Common phishing phrases (extract if present)
        phishing_keywords = [
            'verify your account', 'verify this', 'confirm your', 'urgent action',
            'suspended', 'unusual activity', 'click here', 'act now',
            'verify immediately', 'account locked', 'security alert',
            'update payment', 'confirm identity', 'will be', 'has been'
        ]

        for keyword in phishing_keywords:
            if keyword in body_text:
                patterns['phishing_phrase'].add(keyword)

        # Extract URL patterns
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body)

        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                # Store full domain
                patterns['url_pattern'].add(domain)

                # Also store TLD pattern for random subdomains
                if '.' in domain:
                    parts = domain.split('.')
                    # Check for random subdomain patterns (long alphanumeric)
                    if len(parts) >= 3 and len(parts[0]) > 10 and parts[0].isalnum():
                        tld_pattern = f"*.{'.'.join(parts[-2:])}"
                        patterns['url_pattern'].add(tld_pattern)
            except:
                pass

        # Remove empty patterns
        patterns = {k: v for k, v in patterns.items() if v}

        return patterns

    def _update_pattern_weight(self, cursor, client_domain_id: int, pattern_type: str,
                               pattern_value: str, is_spam: bool, user_email: str):
        """
        Update or insert a pattern weight in the database.
        """
        # Truncate pattern_value to fit in database
        pattern_value = pattern_value[:500]

        # Check if pattern exists
        cursor.execute("""
            SELECT id, spam_count, ham_count, weight_adjustment
            FROM spam_pattern_weights
            WHERE client_domain_id = %s AND pattern_type = %s AND pattern_value = %s
        """, (client_domain_id, pattern_type, pattern_value))

        existing = cursor.fetchone()

        if existing:
            # Update existing pattern
            new_spam_count = existing['spam_count'] + (1 if is_spam else 0)
            new_ham_count = existing['ham_count'] + (0 if is_spam else 1)
            total_count = new_spam_count + new_ham_count
            new_confidence = new_spam_count / total_count if total_count > 0 else 0

            # Adjust weight
            weight_change = self.spam_weight_increase if is_spam else self.ham_weight_decrease
            new_weight = existing['weight_adjustment'] + weight_change

            cursor.execute("""
                UPDATE spam_pattern_weights
                SET spam_count = %s,
                    ham_count = %s,
                    confidence = %s,
                    weight_adjustment = %s,
                    last_updated = NOW()
                WHERE id = %s
            """, (new_spam_count, new_ham_count, new_confidence, new_weight, existing['id']))
        else:
            # Insert new pattern
            spam_count = 1 if is_spam else 0
            ham_count = 0 if is_spam else 1
            confidence = 1.0 if is_spam else 0.0
            weight = self.spam_weight_increase if is_spam else self.ham_weight_decrease

            cursor.execute("""
                INSERT INTO spam_pattern_weights
                (client_domain_id, pattern_type, pattern_value, weight_adjustment,
                 spam_count, ham_count, confidence, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (client_domain_id, pattern_type, pattern_value, weight,
                  spam_count, ham_count, confidence, user_email))

    def get_learned_weights(self, client_domain_id: int, patterns: Dict[str, Set[str]]) -> float:
        """
        Get the total learned weight adjustment for given patterns.
        Only applies weights that meet confidence threshold.

        Args:
            client_domain_id: Domain to get weights for
            patterns: Dict of pattern_type -> set of pattern values

        Returns:
            Total weight adjustment (can be positive or negative)
        """
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor(dictionary=True)

            total_adjustment = 0.0
            patterns_applied = 0

            for pattern_type, pattern_values in patterns.items():
                for pattern_value in pattern_values:
                    pattern_value = pattern_value[:500]

                    cursor.execute("""
                        SELECT weight_adjustment, confidence, spam_count, ham_count
                        FROM spam_pattern_weights
                        WHERE client_domain_id = %s
                          AND pattern_type = %s
                          AND pattern_value = %s
                          AND confidence >= %s
                          AND (spam_count + ham_count) >= %s
                    """, (client_domain_id, pattern_type, pattern_value,
                          self.min_confidence_threshold, self.min_observations))

                    result = cursor.fetchone()
                    if result:
                        total_adjustment += result['weight_adjustment']
                        patterns_applied += 1

            cursor.close()
            conn.close()

            if patterns_applied > 0:
                logger.info(f"Applied {patterns_applied} learned pattern weights for domain {client_domain_id}, total adjustment: {total_adjustment:.2f}")

            return total_adjustment

        except Exception as e:
            logger.error(f"Error getting learned weights: {e}")
            return 0.0


# Global instance
spam_learner = SpamLearner()
