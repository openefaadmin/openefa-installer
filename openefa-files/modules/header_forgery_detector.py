#!/usr/bin/env python3
"""
Header Forgery Detection Module
Detects suspicious header patterns that indicate email forgery or manipulation
"""

import re
import logging
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('header_forgery_detector')


class HeaderForgeryDetector:
    """Analyzes email headers for signs of forgery or manipulation"""

    def __init__(self):
        # Configurable thresholds
        self.max_future_hours = 2  # Allow 2 hours in future (timezone issues)
        self.max_past_days = 60     # Flag emails older than 60 days
        self.very_old_days = 365    # Flag emails older than 1 year as highly suspicious

        # Known legitimate newsletter/mailing list patterns
        # These commonly have different Reply-To addresses
        self.newsletter_indicators = [
            'unsubscribe', 'newsletter', 'mailing list', 'bulk',
            'no-reply', 'noreply', 'donotreply', 'mailer-daemon',
            'mailchimp', 'sendgrid', 'mailgun', 'postmark'
        ]

        # Spam score weights
        self.scores = {
            'reply_to_mismatch': 2.0,           # Different Reply-To domain (common in scams)
            'reply_to_mismatch_suspicious': 4.0, # Reply-To mismatch + no newsletter indicators
            'return_path_mismatch': 1.5,        # Different Return-Path (less suspicious)
            'return_path_suspicious': 3.0,      # Return-Path from free email provider
            'date_in_future': 2.5,              # Email claims to be from the future
            'date_very_old': 2.0,               # Email older than 1 year
            'date_moderately_old': 0.5,         # Email older than 60 days
            'missing_date': 1.0,                # No Date header at all
            'missing_message_id': 1.0,          # No Message-ID (suspicious)
            'malformed_from': 3.0,              # From header is malformed
        }

    def extract_domain(self, email_address: str) -> Optional[str]:
        """Extract domain from email address, handling various formats"""
        if not email_address:
            return None

        # Handle formats like: "Name <email@domain.com>" or just "email@domain.com"
        email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_address)
        if email_match:
            domain = email_match.group(1).lower()
            return domain
        return None

    def is_newsletter_email(self, msg: EmailMessage, from_header: str, reply_to: str) -> bool:
        """Check if email appears to be a legitimate newsletter/mailing list"""
        # Check various headers and content for newsletter indicators
        headers_to_check = [
            from_header.lower(),
            reply_to.lower(),
            str(msg.get('List-Unsubscribe', '')).lower(),
            str(msg.get('List-Id', '')).lower(),
            str(msg.get('X-Mailer', '')).lower(),
            str(msg.get('X-Campaign', '')).lower(),
            str(msg.get('Precedence', '')).lower(),
        ]

        combined = ' '.join(headers_to_check)
        return any(indicator in combined for indicator in self.newsletter_indicators)

    def is_free_email_provider(self, domain: str) -> bool:
        """Check if domain is a free email provider"""
        if not domain:
            return False

        free_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'yandex.com', 'gmx.com', 'mail.ru', 'qq.com', '163.com'
        ]
        return domain.lower() in free_providers

    def check_reply_to_forgery(self, msg: EmailMessage, from_header: str) -> Tuple[List[str], float]:
        """Check for Reply-To header mismatches"""
        issues = []
        score = 0.0

        reply_to = msg.get('Reply-To', '').strip()
        if not reply_to:
            return issues, score

        from_domain = self.extract_domain(from_header)
        reply_to_domain = self.extract_domain(reply_to)

        if not from_domain or not reply_to_domain:
            return issues, score

        # Check if domains match
        if from_domain != reply_to_domain:
            # Check if this is a legitimate newsletter/mailing list
            if self.is_newsletter_email(msg, from_header, reply_to):
                issues.append(f'reply_to_mismatch_newsletter: From={from_domain}, Reply-To={reply_to_domain} (likely legitimate)')
                score += 0.0  # No penalty for newsletters
                logger.info(f"Reply-To mismatch but appears to be newsletter: {from_domain} → {reply_to_domain}")
            else:
                issues.append(f'reply_to_mismatch: From={from_domain}, Reply-To={reply_to_domain}')
                score += self.scores['reply_to_mismatch_suspicious']
                logger.warning(f"Suspicious Reply-To mismatch: {from_domain} → {reply_to_domain}")

        return issues, score

    def check_return_path_forgery(self, msg: EmailMessage, from_header: str) -> Tuple[List[str], float]:
        """Check for Return-Path header mismatches"""
        issues = []
        score = 0.0

        return_path = msg.get('Return-Path', '').strip()
        if not return_path:
            return issues, score

        # Clean up Return-Path (often has <brackets>)
        return_path = re.sub(r'[<>]', '', return_path)

        from_domain = self.extract_domain(from_header)
        return_path_domain = self.extract_domain(return_path)

        if not from_domain or not return_path_domain:
            return issues, score

        # Check if domains match
        if from_domain != return_path_domain:
            # Less suspicious than Reply-To mismatch (often legitimate)
            issues.append(f'return_path_mismatch: From={from_domain}, Return-Path={return_path_domain}')

            # Higher score if Return-Path is from free email provider (more suspicious)
            if self.is_free_email_provider(return_path_domain):
                score += self.scores['return_path_suspicious']
                logger.warning(f"Return-Path from free provider: {return_path_domain}")
            else:
                score += self.scores['return_path_mismatch']
                logger.info(f"Return-Path mismatch: {from_domain} → {return_path_domain}")

        return issues, score

    def check_date_forgery(self, msg: EmailMessage) -> Tuple[List[str], float]:
        """Check for Date header anomalies"""
        issues = []
        score = 0.0

        date_header = msg.get('Date', '').strip()
        if not date_header:
            issues.append('missing_date: No Date header')
            score += self.scores['missing_date']
            logger.warning("Email missing Date header")
            return issues, score

        try:
            email_date = parsedate_to_datetime(date_header)
            now = datetime.now(timezone.utc)

            # Make both timezone-aware for comparison
            if email_date.tzinfo is None:
                email_date = email_date.replace(tzinfo=timezone.utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)

            # Check for future dates
            future_threshold = now + timedelta(hours=self.max_future_hours)
            if email_date > future_threshold:
                hours_future = (email_date - now).total_seconds() / 3600
                issues.append(f'date_in_future: Email dated {hours_future:.1f} hours in future')
                score += self.scores['date_in_future']
                logger.warning(f"Email dated in future: {date_header} ({hours_future:.1f}h)")

            # Check for very old dates
            very_old_threshold = now - timedelta(days=self.very_old_days)
            if email_date < very_old_threshold:
                days_old = (now - email_date).days
                issues.append(f'date_very_old: Email is {days_old} days old')
                score += self.scores['date_very_old']
                logger.warning(f"Email very old: {date_header} ({days_old} days)")

            # Check for moderately old dates
            elif email_date < now - timedelta(days=self.max_past_days):
                days_old = (now - email_date).days
                issues.append(f'date_moderately_old: Email is {days_old} days old')
                score += self.scores['date_moderately_old']
                logger.info(f"Email moderately old: {date_header} ({days_old} days)")

        except Exception as e:
            issues.append(f'date_parse_error: Could not parse date: {date_header}')
            score += self.scores['missing_date']
            logger.error(f"Error parsing Date header '{date_header}': {e}")

        return issues, score

    def check_message_id(self, msg: EmailMessage) -> Tuple[List[str], float]:
        """Check for missing or malformed Message-ID"""
        issues = []
        score = 0.0

        message_id = msg.get('Message-ID', '').strip()
        if not message_id:
            issues.append('missing_message_id: No Message-ID header')
            score += self.scores['missing_message_id']
            logger.warning("Email missing Message-ID header")

        return issues, score

    def check_from_header(self, from_header: str) -> Tuple[List[str], float]:
        """Check for malformed From header"""
        issues = []
        score = 0.0

        if not from_header or from_header.strip() == '':
            issues.append('malformed_from: Empty From header')
            score += self.scores['malformed_from']
            logger.warning("Email has empty From header")
            return issues, score

        # Check for valid email format
        if '@' not in from_header:
            issues.append('malformed_from: From header missing @ symbol')
            score += self.scores['malformed_from']
            logger.warning(f"Malformed From header: {from_header}")

        return issues, score

    def analyze(self, msg: EmailMessage, from_header: str) -> Dict:
        """
        Analyze email headers for forgery indicators

        Args:
            msg: EmailMessage object
            from_header: From header value

        Returns:
            Dict with analysis results including spam_score and detected issues
        """
        logger.info("Starting header forgery analysis")

        all_issues = []
        total_score = 0.0

        # Check From header
        issues, score = self.check_from_header(from_header)
        all_issues.extend(issues)
        total_score += score

        # Check Reply-To
        issues, score = self.check_reply_to_forgery(msg, from_header)
        all_issues.extend(issues)
        total_score += score

        # Check Return-Path
        issues, score = self.check_return_path_forgery(msg, from_header)
        all_issues.extend(issues)
        total_score += score

        # Check Date header
        issues, score = self.check_date_forgery(msg)
        all_issues.extend(issues)
        total_score += score

        # Check Message-ID
        issues, score = self.check_message_id(msg)
        all_issues.extend(issues)
        total_score += score

        result = {
            'spam_score': round(total_score, 2),
            'forgery_detected': total_score > 0,
            'issues': all_issues,
            'issue_count': len(all_issues),
            'checks_performed': [
                'from_header',
                'reply_to_mismatch',
                'return_path_mismatch',
                'date_anomalies',
                'message_id'
            ]
        }

        if total_score > 0:
            logger.warning(f"Header forgery detected! Score: {total_score}, Issues: {len(all_issues)}")
        else:
            logger.info("No header forgery detected")

        return result


# Module entry point for email_filter.py
def detect_header_forgery(msg: EmailMessage, from_header: str = None, auth_results: Dict = None) -> Dict:
    """
    Entry point for header forgery detection module

    Args:
        msg: EmailMessage object
        from_header: Optional From header (will extract if not provided)

    Returns:
        Dict with spam_score and analysis details
    """
    if from_header is None:
        from_header = msg.get('From', '')

    detector = HeaderForgeryDetector()
    return detector.analyze(msg, from_header)
