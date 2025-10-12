#!/usr/bin/env python3
"""
Enhanced Funding/Financing Spam Detection Module for SpaCy
Comprehensive detection of business funding, loan, and grant scams
"""

import re
import json
import datetime
from typing import Dict, List, Set, Optional, Tuple, Any

class FundingSpamDetector:
    """Advanced funding/financing spam detection with multiple pattern matching"""
    
    def __init__(self):
        # High-confidence funding spam patterns
        self.high_confidence_patterns = {
            'fake_approval': [
                r'(?:loan|funding|grant).*(?:pre-?approved|approved|qualified)',
                r'congratulations.*(?:approved|qualified).*(?:loan|funding)',
                r'your.*(?:loan|funding|credit).*(?:approved|ready)',
                r'(?:business|sba|government).*(?:loan|grant).*approved',
                r'funding.*(?:pre-?approved|guaranteed|confirmed)',
                r'final.*approval.*pending.*(?:loan|funding|grant)'
            ],
            
            'urgency_tactics': [
                r'(?:expires?|deadline).*(?:today|tomorrow|24.*hours?|48.*hours?)',
                r'limited.*time.*(?:offer|approval|funding)',
                r'act.*(?:now|fast|quickly|immediately).*(?:funding|loan)',
                r'urgent.*(?:funding|loan|capital|financing).*(?:needed|required)',
                r'time.*sensitive.*(?:funding|loan|grant|financing)',
                r'(?:hurry|rush|quick|fast).*(?:approval|funding|loan)'
            ],
            
            'suspicious_amounts': [
                r'\$(?:10,000|50,000|100,000|250,000|500,000|1,000,000)',
                r'up.*to.*\$[0-9,]+.*(?:funding|loan|grant)',
                r'(?:million|thousand).*dollar.*(?:funding|loan|grant)',
                r'\$[0-9,]+.*(?:guaranteed|approved|available).*(?:funding|loan)',
                r'(?:5|10|25|50|100|250|500)k.*(?:funding|loan|available)'
            ],
            
            'predatory_language': [
                r'no.*(?:credit.*check|collateral|paperwork|documentation)',
                r'bad.*credit.*(?:ok|okay|welcome|approved)',
                r'guaranteed.*(?:approval|funding|loan)',
                r'same.*day.*(?:funding|approval|cash|money)',
                r'instant.*(?:approval|funding|cash|money)',
                r'easy.*(?:approval|qualification|money|funding)'
            ],
            
            'impersonation_indicators': [
                r'(?:sba|small.*business.*administration).*(?:loan|grant|funding)',
                r'government.*(?:grant|funding|stimulus|relief)',
                r'(?:federal|state).*(?:grant|funding|loan|program)',
                r'(?:covid|ppp|eidl).*(?:relief|funding|loan|grant)',
                r'(?:disaster|emergency).*(?:funding|loan|grant|relief)',
                r'(?:minority|women|veteran).*(?:grant|funding|program)'
            ]
        }
        
        # Medium-confidence patterns
        self.medium_confidence_patterns = {
            'business_targeting': [
                r'business.*(?:owner|entrepreneur|founder)',
                r'growing.*(?:business|company|startup)',
                r'expand.*(?:business|operations|company)',
                r'(?:startup|small.*business).*(?:funding|capital|loan)',
                r'business.*(?:cash.*flow|working.*capital|expansion)',
                r'merchant.*(?:cash.*advance|funding|loan)'
            ],
            
            'financial_jargon': [
                r'working.*capital.*(?:loan|funding|advance)',
                r'merchant.*cash.*advance',
                r'invoice.*(?:factoring|financing|funding)',
                r'asset.*based.*(?:lending|financing|loan)',
                r'revenue.*based.*(?:financing|funding|loan)',
                r'equipment.*(?:financing|loan|funding)'
            ],
            
            'contact_pressure': [
                r'call.*(?:now|today|immediately).*(?:for|about).*(?:funding|loan)',
                r'speak.*(?:specialist|advisor|consultant).*(?:funding|loan)',
                r'free.*consultation.*(?:funding|loan|financing)',
                r'schedule.*(?:call|meeting).*(?:funding|loan|capital)',
                r'discuss.*(?:funding|loan|financing).*(?:options|needs)'
            ]
        }
        
        # Low-confidence but indicative patterns
        self.low_confidence_patterns = {
            'generic_business': [
                r'business.*(?:growth|success|opportunity)',
                r'financial.*(?:solution|service|option)',
                r'capital.*(?:solution|source|provider)',
                r'funding.*(?:solution|option|source|partner)',
                r'alternative.*(?:lending|financing|funding)'
            ],
            
            'vague_offers': [
                r'exclusive.*(?:offer|opportunity|access)',
                r'special.*(?:program|offer|rate|terms)',
                r'limited.*(?:offer|opportunity|program)',
                r'confidential.*(?:funding|loan|program)',
                r'private.*(?:lender|funding|investor)'
            ]
        }
        
        # Sender reputation patterns
        self.suspicious_senders = {
            'generic_domains': [
                r'.*funding.*@(?:gmail|yahoo|hotmail|outlook)\.com$',
                r'.*loan.*@(?:gmail|yahoo|hotmail|outlook)\.com$',
                r'.*capital.*@(?:gmail|yahoo|hotmail|outlook)\.com$',
                r'.*finance.*@(?:gmail|yahoo|hotmail|outlook)\.com$'
            ],
            
            'suspicious_names': [
                r'funding.*(?:specialist|advisor|consultant|expert)',
                r'loan.*(?:specialist|advisor|consultant|officer)',
                r'business.*(?:funding|loan|capital).*(?:specialist|advisor)',
                r'financial.*(?:advisor|consultant|specialist)'
            ],
            
            'fake_company_patterns': [
                r'(?:national|american|united|federal).*(?:funding|loan|capital)',
                r'(?:business|small.*business|sba).*(?:funding|loan|capital).*(?:corp|inc|llc)',
                r'(?:merchant|invoice|asset).*(?:funding|capital|finance).*(?:corp|inc|llc)'
            ]
        }
        
        # Whitelist patterns (legitimate funding sources)
        self.legitimate_patterns = [
            r'@(?:sba\.gov|treasury\.gov|federalreserve\.gov)',
            r'@(?:chase\.com|bankofamerica\.com|wellsfargo\.com|citibank\.com)',
            r'@(?:amex\.com|americanexpress\.com|discover\.com)',
            r'quickbooks.*@intuit\.com',
            r'@(?:lendingclub\.com|prosper\.com|sofi\.com)',
            r'noreply@(?:paypal\.com|stripe\.com|square\.com)'
        ]
    
    def analyze_funding_spam(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive analysis of funding/financing spam patterns
        
        Args:
            email_data: Dictionary containing email content and metadata
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'is_funding_spam': False,
            'confidence_score': 0.0,
            'spam_type': 'none',
            'risk_factors': [],
            'detected_patterns': [],
            'sender_reputation': 'unknown',
            'recommended_action': 'allow'
        }
        
        try:
            # Extract email content
            sender = email_data.get('from', '').lower()
            subject = email_data.get('subject', '').lower()
            body = email_data.get('body', '').lower()
            display_name = email_data.get('display_name', '').lower()
            
            # Combine text for analysis
            full_text = f"{subject} {body} {display_name}"
            
            # Check for legitimate senders first
            if self._is_legitimate_sender(sender):
                results['sender_reputation'] = 'legitimate'
                results['recommended_action'] = 'allow'
                return results
            
            # Analyze patterns
            confidence_score = 0.0
            detected_patterns = []
            risk_factors = []
            
            # High-confidence pattern analysis
            high_score, high_patterns, high_risks = self._analyze_pattern_group(
                full_text, self.high_confidence_patterns, weight=3.0
            )
            confidence_score += high_score
            detected_patterns.extend(high_patterns)
            risk_factors.extend(high_risks)
            
            # Medium-confidence pattern analysis
            medium_score, medium_patterns, medium_risks = self._analyze_pattern_group(
                full_text, self.medium_confidence_patterns, weight=2.0
            )
            confidence_score += medium_score
            detected_patterns.extend(medium_patterns)
            risk_factors.extend(medium_risks)
            
            # Low-confidence pattern analysis
            low_score, low_patterns, low_risks = self._analyze_pattern_group(
                full_text, self.low_confidence_patterns, weight=1.0
            )
            confidence_score += low_score
            detected_patterns.extend(low_patterns)
            risk_factors.extend(low_risks)
            
            # Sender reputation analysis
            sender_score, sender_risks = self._analyze_sender_reputation(sender, display_name)
            confidence_score += sender_score
            risk_factors.extend(sender_risks)
            
            # Determine spam type and action
            spam_type, action = self._determine_spam_type(confidence_score, detected_patterns)
            
            # Cap confidence score
            confidence_score = min(confidence_score, 10.0)
            
            # Final determination
            is_spam = confidence_score >= 4.0  # Threshold for spam detection
            
            results.update({
                'is_funding_spam': is_spam,
                'confidence_score': confidence_score,
                'spam_type': spam_type,
                'risk_factors': risk_factors,
                'detected_patterns': detected_patterns,
                'recommended_action': action
            })
            
        except Exception as e:
            results['error'] = str(e)
            results['risk_factors'] = [f'Analysis error: {str(e)[:100]}']
        
        return results
    
    def _analyze_pattern_group(self, text: str, pattern_group: Dict[str, List[str]], 
                              weight: float) -> Tuple[float, List[str], List[str]]:
        """Analyze a group of patterns"""
        score = 0.0
        patterns = []
        risks = []
        
        for category, pattern_list in pattern_group.items():
            for pattern in pattern_list:
                if re.search(pattern, text, re.IGNORECASE):
                    score += weight
                    patterns.append(f"{category}: {pattern}")
                    risks.append(f"Detected {category} pattern")
                    break  # Only count one pattern per category
        
        return score, patterns, risks
    
    def _analyze_sender_reputation(self, sender: str, display_name: str) -> Tuple[float, List[str]]:
        """Analyze sender reputation indicators"""
        score = 0.0
        risks = []
        
        # Check suspicious sender patterns
        for category, pattern_list in self.suspicious_senders.items():
            for pattern in pattern_list:
                if re.search(pattern, sender, re.IGNORECASE) or re.search(pattern, display_name, re.IGNORECASE):
                    score += 2.0
                    risks.append(f"Suspicious sender: {category}")
                    break
        
        return score, risks
    
    def _is_legitimate_sender(self, sender: str) -> bool:
        """Check if sender is from legitimate financial institution"""
        for pattern in self.legitimate_patterns:
            if re.search(pattern, sender, re.IGNORECASE):
                return True
        return False
    
    def _determine_spam_type(self, confidence_score: float, patterns: List[str]) -> Tuple[str, str]:
        """Determine spam type and recommended action"""
        if confidence_score >= 8.0:
            return 'high_confidence_funding_scam', 'block'
        elif confidence_score >= 6.0:
            return 'probable_funding_spam', 'quarantine'
        elif confidence_score >= 4.0:
            return 'suspicious_funding_offer', 'flag'
        elif confidence_score >= 2.0:
            return 'potential_funding_marketing', 'allow_with_warning'
        else:
            return 'none', 'allow'
    
    def get_spamassassin_score_adjustment(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate SpamAssassin score adjustment based on analysis"""
        if not analysis_results.get('is_funding_spam', False):
            return 0.0
        
        confidence = analysis_results.get('confidence_score', 0.0)
        spam_type = analysis_results.get('spam_type', 'none')
        
        # Base score adjustment
        if spam_type == 'high_confidence_funding_scam':
            return 8.0
        elif spam_type == 'probable_funding_spam':
            return 6.0
        elif spam_type == 'suspicious_funding_offer':
            return 4.0
        elif spam_type == 'potential_funding_marketing':
            return 2.0
        
        # Fallback to confidence-based scoring
        return min(confidence * 1.5, 8.0)


# Integration function for SpaCy email filter
def analyze_funding_spam(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main function for integration with SpaCy email filter
    
    Args:
        email_data: Dictionary containing email content and metadata
        
    Returns:
        Dictionary with funding spam analysis results
    """
    detector = FundingSpamDetector()
    return detector.analyze_funding_spam(email_data)


# Testing function
if __name__ == "__main__":
    # Test cases
    test_emails = [
        {
            'from': 'funding-specialist@gmail.com',
            'subject': 'Congratulations! Your business loan is pre-approved for $250,000',
            'body': 'Your SBA loan application has been approved. No credit check required. Call now before this limited time offer expires!',
            'display_name': 'Business Funding Specialist'
        },
        {
            'from': 'notifications@chase.com',
            'subject': 'Your business credit line application status',
            'body': 'Thank you for your application. We will review and contact you within 5 business days.',
            'display_name': 'Chase Business Banking'
        }
    ]
    
    detector = FundingSpamDetector()
    
    for i, email in enumerate(test_emails):
        print(f"\n=== Test Email {i+1} ===")
        result = detector.analyze_funding_spam(email)
        print(f"Is Spam: {result['is_funding_spam']}")
        print(f"Confidence: {result['confidence_score']:.2f}")
        print(f"Type: {result['spam_type']}")
        print(f"Action: {result['recommended_action']}")
        print(f"Risk Factors: {result['risk_factors'][:3]}")  # Show first 3
