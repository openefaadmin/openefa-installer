#!/usr/bin/env python3
"""
Comprehensive Brand Impersonation Detection Module
Detects impersonation of major brands across multiple categories
"""

import re
import sys
from typing import Dict, List, Any, Tuple

def safe_log(message: str):
    """Safe logging to stderr"""
    try:
        print(f"DEBUG: {message}", file=sys.stderr)
    except:
        pass

# Comprehensive brand database with legitimate domains
BRAND_DOMAINS = {
    # Financial Institutions
    'financial': {
        'capital one': ['capitalone.com', 'capitalonebank.com'],
        'capitalone': ['capitalone.com', 'capitalonebank.com'],
        'chase': ['chase.com', 'jpmchase.com', 'jpmorgan.com'],
        'bank of america': ['bankofamerica.com', 'bofa.com'],
        'wells fargo': ['wellsfargo.com', 'wf.com'],
        'citibank': ['citi.com', 'citibank.com', 'citigroup.com'],
        'us bank': ['usbank.com'],
        'american express': ['americanexpress.com', 'aexp.com'],
        'amex': ['americanexpress.com', 'aexp.com'],
        'discover': ['discover.com', 'discovercard.com'],
        'paypal': ['paypal.com'],
        'venmo': ['venmo.com'],
        'zelle': ['zellepay.com'],
        'cash app': ['cash.app', 'square.com'],
        'stripe': ['stripe.com'],
        'square': ['squareup.com', 'square.com'],
    },
    
    # Tech Companies
    'tech': {
        'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com', 'microsoftonline.com'],
        'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
        'google': ['google.com', 'gmail.com', 'youtube.com'],
        'amazon': ['amazon.com', 'amazonaws.com'],
        'meta': ['meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com'],
        'facebook': ['facebook.com', 'fb.com', 'meta.com'],
        'instagram': ['instagram.com', 'meta.com'],
        'whatsapp': ['whatsapp.com', 'meta.com'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com'],
        'netflix': ['netflix.com'],
        'spotify': ['spotify.com'],
        'adobe': ['adobe.com'],
        'dropbox': ['dropbox.com'],
        'zoom': ['zoom.us', 'zoom.com'],
        'mcafee': ['mcafee.com'],
        'norton': ['norton.com', 'nortonlifelock.com'],
        'kaspersky': ['kaspersky.com'],
        'avast': ['avast.com'],
        't-mobile': ['t-mobile.com', 'notifications.t-mobile.com'],
        'verizon': ['verizon.com', 'vzw.com'],
        'at&t': ['att.com'],
    },
    
    # Shipping & Logistics
    'shipping': {
        'fedex': ['fedex.com'],
        'ups': ['ups.com'],
        'usps': ['usps.com', 'usps.gov'],
        'dhl': ['dhl.com'],
        'postal service': ['usps.com', 'usps.gov'],
        'united states postal': ['usps.com', 'usps.gov'],
    },
    
    # Government Agencies
    'government': {
        'irs': ['irs.gov'],
        'internal revenue': ['irs.gov'],
        'social security': ['ssa.gov'],
        'medicare': ['medicare.gov'],
        'medicaid': ['medicaid.gov'],
        'department of': ['.gov'],  # Any department should be .gov
        'federal': ['.gov'],
        'united states': ['.gov'],
    },
    
    # E-commerce & Retail
    'retail': {
        'walmart': ['walmart.com'],
        'target': ['target.com'],
        'best buy': ['bestbuy.com'],
        'home depot': ['homedepot.com'],
        'costco': ['costco.com'],
        'ebay': ['ebay.com'],
        'etsy': ['etsy.com'],
        'alibaba': ['alibaba.com', 'aliexpress.com'],
    },
    
    # Cryptocurrency
    'crypto': {
        'coinbase': ['coinbase.com'],
        'binance': ['binance.com', 'binance.us'],
        'kraken': ['kraken.com'],
        'crypto.com': ['crypto.com'],
        'blockchain': ['blockchain.com'],
    }
}

def extract_domain_from_email(email: str) -> str:
    """Extract domain from email address"""
    try:
        if '@' not in email:
            return ''
        email = email.strip().lower()
        email = re.sub(r'[<>]', '', email)
        domain = email.split('@')[-1]
        domain = re.sub(r'[<>\[\]()]', '', domain)
        return domain
    except:
        return ''

def check_brand_impersonation(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive brand impersonation detection
    Returns detailed risk assessment
    """
    result = {
        'is_impersonation': False,
        'confidence': 0.0,
        'brand_detected': None,
        'brand_category': None,
        'spam_score_increase': 0.0,
        'risk_factors': [],
        'headers_to_add': {}
    }

    try:
        # Extract email components
        sender_email = email_data.get('from', '').lower()
        display_name = email_data.get('display_name', '').lower()
        subject = email_data.get('subject', '').lower()
        # Fix: email_filter.py passes 'body', not 'content'
        content = (email_data.get('body', '') or email_data.get('content', '')).lower()[:2000]  # First 2000 chars

        sender_domain = extract_domain_from_email(sender_email)

        if not sender_domain:
            return result

        # First, check if sender domain matches any legitimate brand
        sender_is_legitimate_brand = None
        for category, brands in BRAND_DOMAINS.items():
            for brand_name, legitimate_domains in brands.items():
                for legit_domain in legitimate_domains:
                    if legit_domain == '.gov':
                        if sender_domain.endswith('.gov'):
                            sender_is_legitimate_brand = brand_name
                            break
                    elif (sender_domain == legit_domain or
                          sender_domain.endswith('.' + legit_domain)):
                        sender_is_legitimate_brand = brand_name
                        safe_log(f"Sender {sender_domain} is legitimate {brand_name}")
                        break
                if sender_is_legitimate_brand:
                    break
            if sender_is_legitimate_brand:
                break

        # Check each brand category
        for category, brands in BRAND_DOMAINS.items():
            for brand_name, legitimate_domains in brands.items():
                # Special handling for names that might be surnames
                # Skip "zelle" if "zeller" appears (likely a surname like Teresa Zeller)
                if brand_name == 'zelle' and 'zeller' in display_name:
                    continue
                
                # Use word boundaries for short brand names to avoid false positives
                if len(brand_name) <= 5:
                    # For short brands, require word boundaries
                    brand_pattern = r'\b' + re.escape(brand_name) + r'\b'
                    brand_in_display = bool(re.search(brand_pattern, display_name))
                    brand_in_subject = bool(re.search(brand_pattern, subject))
                    brand_in_content = bool(re.search(brand_pattern, content[:500]))
                else:
                    # For longer brands, substring match is OK
                    brand_in_display = brand_name in display_name
                    brand_in_subject = brand_name in subject
                    brand_in_content = brand_name in content[:500]
                
                # Check if brand name appears in display name or subject
                if (brand_in_display or brand_in_subject or brand_in_content):

                    # CRITICAL: If sender is already identified as a legitimate brand,
                    # skip impersonation check for other brands (e.g., Zoom emails may mention "Login with Facebook")
                    if sender_is_legitimate_brand and brand_name != sender_is_legitimate_brand:
                        # Only flag if it's in the display name or subject (not just content)
                        if not (brand_in_display or brand_in_subject):
                            continue  # Skip - likely just a mention in content (e.g., social login buttons)

                    # Skip if brand mention is ONLY in content (not display/subject)
                    # This avoids false positives from HTML/CSS/templates mentioning brands
                    if brand_in_content and not (brand_in_display or brand_in_subject):
                        continue  # Content-only mentions are too weak

                    # Debug logging for Zoom case
                    if brand_name == 'zoom':
                        safe_log(f"Zoom brand check: sender_domain={sender_domain}, legitimate_domains={legitimate_domains}")

                    # Check if sender domain is legitimate
                    is_legitimate = False
                    for legit_domain in legitimate_domains:
                        if legit_domain == '.gov':
                            # Special case for government domains
                            if sender_domain.endswith('.gov'):
                                is_legitimate = True
                                break
                        elif (sender_domain == legit_domain or
                              sender_domain.endswith('.' + legit_domain)):
                            is_legitimate = True
                            if brand_name == 'zoom':
                                safe_log(f"Zoom identified as legitimate: {sender_domain} matches {legit_domain}")
                            break

                    if not is_legitimate:
                        # This is impersonation!
                        result['is_impersonation'] = True
                        result['brand_detected'] = brand_name
                        result['brand_category'] = category
                        
                        # Set confidence based on category
                        confidence_scores = {
                            'financial': 0.95,
                            'government': 1.0,  # Government impersonation is always high confidence
                            'tech': 0.9,
                            'shipping': 0.9,
                            'retail': 0.85,
                            'crypto': 0.95
                        }
                        result['confidence'] = confidence_scores.get(category, 0.85)
                        
                        # Add risk factors
                        result['risk_factors'].append(f"Claims to be '{brand_name}' but sending from '{sender_domain}'")
                        result['risk_factors'].append(f"Brand category: {category}")
                        
                        # Check for phishing indicators
                        phishing_keywords = {
                            'financial': ['verify', 'suspended', 'locked', 'secure', 'update payment'],
                            'government': ['refund', 'owe', 'audit', 'penalty', 'legal action'],
                            'tech': ['verify', 'suspended', 'security', 'unusual activity', 'reset'],
                            'shipping': ['delivery', 'package', 'customs', 'fee', 'tracking'],
                            'retail': ['order', 'refund', 'cancel', 'confirm', 'receipt'],
                            'crypto': ['wallet', 'transfer', 'verification', 'withdrawal', 'deposit']
                        }
                        
                        category_keywords = phishing_keywords.get(category, [])
                        for keyword in category_keywords:
                            if keyword in subject or keyword in content:
                                result['confidence'] = min(1.0, result['confidence'] + 0.05)
                                result['risk_factors'].append(f"Contains suspicious keyword: '{keyword}'")
                                break
                        
                        # Calculate spam score increase
                        # REDUCED: Brand mentions alone are weak indicators (too many false positives)
                        # Only add significant points if combined with phishing keywords
                        base_scores = {
                            'financial': 2.0,  # Reduced from 8.0
                            'government': 3.0,  # Reduced from 10.0
                            'tech': 1.5,  # Reduced from 7.0
                            'shipping': 2.0,  # Reduced from 6.0
                            'retail': 1.0,  # Reduced from 5.0
                            'crypto': 2.5  # Reduced from 8.0
                        }
                        result['spam_score_increase'] = base_scores.get(category, 1.0)
                        
                        # Add headers
                        result['headers_to_add']['X-Brand-Impersonation'] = 'true'
                        result['headers_to_add']['X-Brand-Name'] = brand_name
                        result['headers_to_add']['X-Brand-Category'] = category
                        result['headers_to_add']['X-Brand-Confidence'] = str(result['confidence'])
                        
                        safe_log(f"BRAND IMPERSONATION: {brand_name} ({category}) from {sender_domain}")
                        return result  # Return immediately on first match
        
    except Exception as e:
        safe_log(f"Error in brand impersonation detection: {e}")
        result['risk_factors'].append(f"Detection error: {str(e)[:50]}")
    
    return result

def detect_brand_impersonation(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """Wrapper function for compatibility"""
    return check_brand_impersonation(email_data)

# For testing
if __name__ == "__main__":
    test_cases = [
        {
            'from': 'security@scammer.com',
            'display_name': 'Apple Security',
            'subject': 'Your Apple ID has been locked',
            'content': 'Please verify your account'
        },
        {
            'from': 'noreply@phishing.net',
            'display_name': 'IRS',
            'subject': 'Tax Refund Available',
            'content': 'You have a refund waiting'
        },
        {
            'from': 'updates@fake-site.com',
            'display_name': 'FedEx',
            'subject': 'Package Delivery Failed',
            'content': 'Your package requires additional fees'
        }
    ]
    
    for test in test_cases:
        result = check_brand_impersonation(test)
        if result['is_impersonation']:
            print(f"✓ Detected: {result['brand_detected']} ({result['brand_category']}) - {result['confidence']:.0%} confidence")
        else:
            print(f"✗ Not detected: {test['display_name']}")