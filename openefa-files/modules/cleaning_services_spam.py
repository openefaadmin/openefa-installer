#!/usr/bin/env python3
"""
Cleaning Services Spam Detector Module
Detects unsolicited cleaning, janitorial, and facility maintenance spam
"""

import re
from typing import Dict, Any, List, Tuple
import logging

logger = logging.getLogger(__name__)

class CleaningServicesSpamDetector:
    """Detects cleaning and janitorial service spam patterns"""

    def __init__(self):
        # Common cleaning service keywords and phrases
        self.cleaning_keywords = [
            'cleaning service', 'janitorial', 'custodial', 'facility maintenance',
            'commercial cleaning', 'office cleaning', 'deep clean', 'sanitization',
            'disinfection service', 'carpet cleaning', 'floor care', 'window washing',
            'pressure washing', 'housekeeping service', 'maid service',
            'dust-free', 'spotless environment', 'cleaning standards',
            'cleaners', 'cleaning issue', 'standards slipping', 'things being missed'
        ]

        # Phrases that indicate unsolicited cleaning pitches
        self.spam_phrases = [
            'already have cleaners', 'noticed.*runs 24/7', 'keeping.*dust.free',
            'small lapse in cleaning', 'overheating.*static risks',
            'operational headache off your plate', 'quick.*no.pressure chat',
            'no.strings quote', 'spotless environment.*right impression',
            'cleaning.*compliant with', 'specialized.*cleaning',
            'handle it differently', 'standards slipping', 'step in'
        ]

        # Known cleaning spam domains (will grow over time)
        self.known_spam_domains = [
            'vegasprimeshineofficial.com', 'primeshine', 'citywide',
            'janitorial', 'cleaningservice', 'facilitymaintenance',
            'commercialcleaning', 'officecleaners'
        ]

        # Legitimate cleaning contexts (to avoid false positives)
        self.legitimate_contexts = [
            'data cleaning', 'clean code', 'clean install', 'clean build',
            'disk cleanup', 'cache cleaning', 'memory cleanup', 'clean slate',
            'clean energy', 'clean technology', 'cleanup branch', 'git clean'
        ]

        # Industry-specific targeting patterns
        self.targeted_patterns = [
            r'server rooms?\s+dust.free',
            r'data.center\s+cleaning',
            r'chain.of.custody\s+standards',
            r'compliance.*cleaning',
            r'24/7.*dust.*traffic',
            r'hvac.*cleaning',
            r'first day of (fall|spring|summer|winter)'  # Seasonal pitch pattern
        ]

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze email for cleaning service spam patterns"""
        try:
            subject = email_data.get('subject', '').lower()
            body = email_data.get('body', '').lower()
            sender = email_data.get('sender', '').lower()
            sender_domain = sender.split('@')[1] if '@' in sender else ''

            # Combine subject and body for analysis
            content = f"{subject} {body}"

            # Skip if it's a legitimate technical context
            for legit in self.legitimate_contexts:
                if legit in content:
                    return {
                        'detected': False,
                        'confidence': 0,
                        'reason': 'Legitimate technical context'
                    }

            indicators = []
            score = 0

            # Check for cleaning keywords
            keyword_count = sum(1 for keyword in self.cleaning_keywords
                              if keyword in content)
            if keyword_count > 0:
                score += min(keyword_count * 2, 8)
                indicators.append(f'cleaning_keywords:{keyword_count}')

            # Check for spam phrases
            spam_phrase_matches = 0
            for phrase in self.spam_phrases:
                if re.search(phrase, content, re.IGNORECASE):
                    spam_phrase_matches += 1
            if spam_phrase_matches > 0:
                score += min(spam_phrase_matches * 3, 12)
                indicators.append(f'spam_phrases:{spam_phrase_matches}')

            # Check sender domain
            for spam_domain in self.known_spam_domains:
                if spam_domain in sender_domain:
                    score += 8
                    indicators.append(f'known_spam_domain:{spam_domain}')
                    break

            # Check for targeted industry patterns
            for pattern in self.targeted_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    score += 5
                    indicators.append('targeted_industry_pitch')
                    break

            # Check for typical spam patterns
            if 'unsubscribe' in content and keyword_count > 2:
                score += 3
                indicators.append('mass_mail_cleaning')

            # Check for fake personalization
            if re.search(r'noticed (your company|you)', content) and keyword_count > 0:
                score += 4
                indicators.append('fake_personalization')

            # Seasonal pitch detection
            if re.search(r'(spring|fall|summer|winter).*(cleaning|maintenance)', content):
                score += 3
                indicators.append('seasonal_pitch')

            # Determine if it's spam
            detected = score >= 8
            confidence = min(score / 20, 1.0)  # Normalize confidence

            result = {
                'detected': detected,
                'confidence': confidence,
                'score': score,
                'indicators': indicators,
                'category': 'cleaning_services_spam'
            }

            # Add headers if detected
            if detected:
                result['headers_to_add'] = {
                    'X-Cleaning-Spam-Detected': 'true',
                    'X-Cleaning-Spam-Score': str(score),
                    'X-Cleaning-Spam-Confidence': f'{confidence:.3f}',
                    'X-Cleaning-Spam-Indicators': ','.join(indicators)
                }

                logger.info(f"Cleaning services spam detected: {sender} -> Score: {score}")

            return result

        except Exception as e:
            logger.error(f"Error in cleaning services spam detection: {e}")
            return {
                'detected': False,
                'confidence': 0,
                'error': str(e)
            }

def process_email(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for email processing"""
    detector = CleaningServicesSpamDetector()
    return detector.analyze(email_data)

if __name__ == "__main__":
    # Test with sample data
    test_email = {
        'subject': 'Re: Cleaning issue',
        'body': '''A lot of businesses we talk to already have cleaners… but still notice
        things being missed or standards slipping. That's usually where we step in.
        Would it make sense to have a quick chat about how we handle it differently?
        Best, Vegas Prime Shine''',
        'sender': 'sue@vegasprimeshineofficial.com'
    }

    result = process_email(test_email)
    print(f"Detection result: {result}")