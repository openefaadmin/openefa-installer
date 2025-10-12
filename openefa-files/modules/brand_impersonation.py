#!/usr/bin/env python3
"""
Enhanced Brand Impersonation Detection Module for SpaCy
Specifically designed to catch financial institution phishing
"""

import re
import sys
from typing import Dict, List, Any

def detect_brand_impersonation(from_header: str, subject: str, content: str = "") -> Dict[str, Any]:
    """
    Detect brand impersonation in emails
    Returns scoring adjustments and risk analysis
    """
    # Major brands and their legitimate domains
    financial_brands = {
        'american express': ['americanexpress.com', 'aexp.com'],
        'amex': ['americanexpress.com', 'aexp.com'],
        'chase': ['chase.com', 'jpmchase.com'],
        'bank of america': ['bankofamerica.com', 'bofa.com'],
        'wells fargo': ['wellsfargo.com', 'wf.com'],
        'citibank': ['citibank.com', 'citi.com'],
        'capital one': ['capitalone.com'],
        'discover': ['discover.com'],
        'paypal': ['paypal.com'],
        'visa': ['visa.com'],
        'mastercard': ['mastercard.com']
    }
    
    result = {
        'is_impersonation': False,
        'confidence': 0.0,
        'brand': None,
        'spam_score_increase': 0.0,
        'phishing_score_increase': 0.0,
        'risk_factors': []
    }
    
    try:
        # Extract display name and domain
        display_name = extract_display_name(from_header)
        sender_email = extract_email_from_header(from_header)
        actual_domain = extract_domain(sender_email) if sender_email else ""
        
        if not display_name or not actual_domain:
            return result
        
        display_lower = display_name.lower()
        
        # Check for brand impersonation
        for brand, legitimate_domains in financial_brands.items():
            if brand in display_lower:
                # Found brand in display name
                if actual_domain.lower() not in [d.lower() for d in legitimate_domains]:
                    # Domain doesn't match - IMPERSONATION!
                    result['is_impersonation'] = True
                    result['brand'] = brand
                    result['confidence'] = 0.9
                    result['spam_score_increase'] = 5.0  # High penalty
                    result['phishing_score_increase'] = 0.7  # High phishing risk
                    result['risk_factors'].append(f"Brand '{brand}' impersonated")
                    result['risk_factors'].append(f"Fake domain: {actual_domain}")
                    
                    # Check for phishing subject patterns
                    phishing_subjects = [
                        r'dispute\s+status', r'account\s+suspended', r'verify\s+account',
                        r'security\s+alert', r'payment\s+failed', r'fraud\s+alert'
                    ]
                    
                    for pattern in phishing_subjects:
                        if re.search(pattern, subject.lower()):
                            result['spam_score_increase'] += 2.0
                            result['phishing_score_increase'] += 0.2
                            result['risk_factors'].append(f"Phishing subject: {pattern}")
                            break
                    
                    break
    
    except Exception as e:
        print(f"Brand impersonation detection error: {e}", file=sys.stderr)
    
    return result

def extract_display_name(from_header: str) -> str:
    """Extract display name from From header"""
    try:
        if '<' in from_header and '>' in from_header:
            display_part = from_header.split('<')[0].strip()
            return display_part.strip('"').strip("'").strip()
        return ""
    except:
        return ""

def extract_email_from_header(from_header: str) -> str:
    """Extract email address from From header"""
    try:
        if '<' in from_header and '>' in from_header:
            match = re.search(r'<([^>]+)>', from_header)
            if match:
                return match.group(1).strip()
        
        match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_header)
        if match:
            return match.group(0).strip()
        
        return from_header.strip()
    except:
        return ""

def extract_domain(email: str) -> str:
    """Extract domain from email address"""
    try:
        if '@' in email:
            return email.split('@')[-1].lower().strip()
        return ""
    except:
        return ""

# Test with the spam example
if __name__ == "__main__":
    test_result = detect_brand_impersonation(
        "American Express <amx@secure.net>",
        "Completed: View Dispute Status"
    )
    print(f"Test Result: {test_result}")
