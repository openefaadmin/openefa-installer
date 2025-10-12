#!/usr/bin/env python3
"""
Refund/Payment Scam Detection Module
Detects fake refund, payment, and subscription renewal scams
"""

import re
from typing import Dict, List, Optional, Tuple

class RefundScamDetector:
    """Detects refund, payment, and subscription scams"""
    
    def __init__(self):
        # Brand names commonly impersonated
        self.impersonated_brands = [
            'paypal', 'mcafee', 'norton', 'microsoft', 'apple', 'amazon',
            'netflix', 'spotify', 'adobe', 'quickbooks', 'geek squad',
            'best buy', 'walmart', 'costco', 'sam\'s club', 'ebay'
        ]
        
        # High-risk patterns for refund scams
        self.refund_patterns = [
            r'refund.*(?:will be|has been|is).*processed',
            r'(?:payment|transaction|charge).*(?:completed|processed|withdrawn)',
            r'amount.*(?:withdrawn|debited|charged).*(?:from your|your).*account',
            r'(?:auto|automatic).*(?:renewal|subscription|payment)',
            r'(?:cancel|stop).*(?:within|in).*(?:\d+\s*hours?|today)',
            r'(?:dispute|cancel).*(?:transaction|payment|charge)',
            r'reference.*(?:number|id|code).*[A-Z0-9]{10,}',
            r'(?:invoice|receipt).*(?:no|number|id).*[:]\s*[A-Z0-9]+',
            r'(?:subscription|membership).*(?:renewed|charged|activated)',
            r'if you did not.*(?:approve|authorize|make)',
            r'(?:call|contact).*(?:immediately|urgent|now).*cancel',
            r'toll[\s-]*free.*(?:number|phone|contact)',
            r'\$\d{2,4}\.\d{2}.*(?:charged|withdrawn|debited)',
            r'(?:24|48|72).*hours?.*(?:cancel|refund|dispute)'
        ]
        
        # Phone number patterns (especially toll-free)
        self.phone_patterns = [
            r'(?:1[\s.-]?)?(?:800|888|877|866|855|844|833)[\s.-]?\d{3}[\s.-]?\d{4}',
            r'\+1\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
            r'(?:call|contact|phone|tel).*[:]\s*[\d\s\(\)\+\-\.]+',
            r'(?:support|help).*(?:line|number).*[:]\s*[\d\s\(\)\+\-\.]+'
        ]
        
        # Suspicious sender patterns
        self.suspicious_sender_patterns = [
            r'^[a-z]{8,20}@gmail\.com$',  # Random letters @gmail
            r'^[a-z]+[0-9]{4,}@gmail\.com$',  # Letters + numbers @gmail
            r'^no[\-_]?reply@',  # No-reply addresses claiming refunds
            r'@[a-z]{10,}\.com$',  # Random domain names
        ]

    def detect(self, sender: str, subject: str, body: str, headers: Dict) -> Dict:
        """
        Analyze email for refund/payment scams
        
        Args:
            sender: Email sender address
            subject: Email subject
            body: Email body text
            headers: Email headers dictionary
            
        Returns:
            Detection results with confidence score and headers to add
        """
        try:
            confidence = 0.0
            detected_patterns = []
            risk_level = 'low'
            
            # Normalize text for analysis
            text_lower = (subject + ' ' + body).lower()
            sender_lower = sender.lower()
            
            # Check for brand impersonation
            brand_mentioned = None
            for brand in self.impersonated_brands:
                if brand in text_lower:
                    brand_mentioned = brand
                    # Check if sender domain matches brand
                    if brand not in sender_lower and f'@{brand}.' not in sender_lower:
                        confidence += 0.3
                        detected_patterns.append(f'Brand impersonation: {brand}')
                    break
            
            # Check refund scam patterns
            refund_matches = 0
            for pattern in self.refund_patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    refund_matches += 1
                    confidence += 0.15
            
            if refund_matches > 0:
                detected_patterns.append(f'Refund scam patterns: {refund_matches}')
            
            # Check for phone numbers (major red flag in refund scams)
            phone_found = False
            for pattern in self.phone_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    phone_found = True
                    confidence += 0.25
                    detected_patterns.append('Phone number in body')
                    break
            
            # Check suspicious sender patterns
            for pattern in self.suspicious_sender_patterns:
                if re.match(pattern, sender_lower):
                    confidence += 0.2
                    detected_patterns.append('Suspicious sender pattern')
                    break
            
            # Check for undisclosed recipients
            to_header = headers.get('to', '').lower()
            if 'undisclosed' in to_header or not '@' in to_header:
                confidence += 0.15
                detected_patterns.append('Undisclosed recipients')
            
            # High-risk combinations
            if brand_mentioned and phone_found and refund_matches >= 2:
                confidence += 0.3
                risk_level = 'critical'
                detected_patterns.append('High-risk pattern combination')
            elif refund_matches >= 3:
                confidence += 0.2
                risk_level = 'high'
            elif confidence >= 0.5:
                risk_level = 'high'
            elif confidence >= 0.3:
                risk_level = 'medium'
            
            # Cap confidence at 1.0
            confidence = min(confidence, 1.0)
            
            # Calculate spam score addition
            if confidence >= 0.7:
                spam_score_add = 8.0  # Major penalty for high confidence
            elif confidence >= 0.5:
                spam_score_add = 5.0
            elif confidence >= 0.3:
                spam_score_add = 3.0
            else:
                spam_score_add = 0.0
            
            return {
                'detected': confidence >= 0.3,
                'confidence': round(confidence, 3),
                'risk_level': risk_level,
                'patterns': detected_patterns,
                'brand_impersonation': brand_mentioned,
                'headers_to_add': {
                    'X-Refund-Scam-Detected': 'true' if confidence >= 0.3 else 'false',
                    'X-Refund-Scam-Confidence': str(round(confidence, 3)),
                    'X-Refund-Scam-Risk': risk_level,
                    'X-Refund-Scam-Score': str(spam_score_add)
                },
                'spam_score_adjustment': spam_score_add
            }
            
        except Exception as e:
            return {
                'detected': False,
                'confidence': 0.0,
                'error': str(e),
                'headers_to_add': {},
                'spam_score_adjustment': 0.0
            }

def analyze_email(sender: str, subject: str, body: str, headers: Dict) -> Dict:
    """
    Main entry point for the module
    """
    detector = RefundScamDetector()
    return detector.detect(sender, subject, body, headers)