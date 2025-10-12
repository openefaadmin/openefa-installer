#!/usr/bin/env python3
"""
Sender Reputation Module
Adjusts authentication penalties for known legitimate but misconfigured senders
"""

import re
from typing import Dict, Any
import dns.resolver

def check_sender_reputation(sender_email: str, sender_ip: str, auth_results: Dict) -> Dict[str, Any]:
    """
    Check sender reputation and adjust auth scoring for known good but misconfigured senders
    """
    result = {
        'reputation_score': 0,
        'reputation_adjustment': 0,
        'reputation_notes': [],
        'is_trusted_provider': False
    }
    
    try:
        # Extract domain from sender
        sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ''
        
        # Check if sent via known good ESPs (Email Service Providers)
        trusted_esp_ranges = {
            'Amazon SES': [
                '54.240.0.0/18',    # us-east-1
                '54.240.64.0/18',   # us-west-2  
                '69.169.224.0/20',  # eu-west-1
                '23.249.208.0/20',  # ap-southeast-1
                '23.251.224.0/19',  # ap-northeast-1
                '76.223.128.0/19',  # us-east-1
                '76.223.176.0/20',  # us-west-2
            ],
            'SendGrid': [
                '167.89.0.0/16',
                '168.245.0.0/16',
                '208.117.48.0/20',
            ],
            'Google/Gmail': [
                '209.85.128.0/17',
                '209.85.0.0/17',
                '172.217.0.0/16',
                '142.250.0.0/15',
                '108.177.0.0/17',
            ],
            'Microsoft/Outlook': [
                '52.100.0.0/14',
                '40.92.0.0/15',
                '40.107.0.0/16',
                '52.102.0.0/16',
                '52.103.0.0/16',
            ]
        }
        
        # Check if IP is from trusted ESP
        esp_detected = None
        for esp_name, ip_ranges in trusted_esp_ranges.items():
            if is_ip_in_ranges(sender_ip, ip_ranges):
                esp_detected = esp_name
                result['is_trusted_provider'] = True
                result['reputation_notes'].append(f"Sent via {esp_name}")
                break
        
        # Known legitimate but misconfigured senders
        known_good_misconfigured = {
            'qnap.com': {
                'provider': 'Amazon SES',
                'issue': 'Missing amazonses.com in SPF',
                'adjustment': 8  # Reduce penalty significantly
            },
            'adobe.com': {
                'provider': 'Various',
                'issue': 'Complex SPF chain',
                'adjustment': 5
            },
            'oracle.com': {
                'provider': 'OracleCloud',
                'issue': 'Complex SPF setup',
                'adjustment': 5
            },
            'apple.com': {
                'provider': 'Apple',
                'issue': 'Strict SPF policy',
                'adjustment': 6
            },
            'dropbox.com': {
                'provider': 'Multiple',
                'issue': 'Multiple sending services',
                'adjustment': 5
            },
            'salesforce.com': {
                'provider': 'Salesforce',
                'issue': 'Complex deployment',
                'adjustment': 5
            },
            'constantcontact.com': {
                'provider': 'Constant Contact',
                'issue': 'Marketing platform',
                'adjustment': 4
            },
            'mailchimp.com': {
                'provider': 'Mailchimp',
                'issue': 'Marketing platform',
                'adjustment': 4
            },
            'sendgrid.com': {
                'provider': 'SendGrid',
                'issue': 'Email service provider',
                'adjustment': 5
            },
            'amazonses.com': {
                'provider': 'Amazon SES',
                'issue': 'Transactional email service',
                'adjustment': 6
            },
            'mandrillapp.com': {
                'provider': 'Mandrill/Mailchimp',
                'issue': 'Transactional email service',
                'adjustment': 5
            }
        }
        
        # Check for known misconfigured sender
        if sender_domain in known_good_misconfigured:
            config = known_good_misconfigured[sender_domain]
            result['reputation_adjustment'] = config['adjustment']
            result['reputation_notes'].append(
                f"Known legitimate sender with {config['issue']}"
            )
            result['reputation_score'] = 5  # Good reputation
        
        # Additional checks for Amazon SES authenticated emails
        if esp_detected == 'Amazon SES':
            # Check if DKIM passed for Amazon SES
            if 'amazonses.com' in str(auth_results.get('dkim_domains', [])):
                result['reputation_adjustment'] += 3
                result['reputation_notes'].append("Valid Amazon SES DKIM signature")
            
            # Common legitimate senders via Amazon SES
            ses_legitimate_patterns = [
                r'no-?reply@',
                r'noreply@',
                r'notifications?@',
                r'alerts?@',
                r'support@',
                r'info@',
                r'news@',
                r'updates?@'
            ]
            
            for pattern in ses_legitimate_patterns:
                if re.match(pattern, sender_email.lower()):
                    result['reputation_adjustment'] += 2
                    result['reputation_notes'].append("Common automated sender pattern")
                    break
        
        # Check for specific sender reputation from headers
        # Password reset emails are typically legitimate
        if esp_detected and any(keyword in str(auth_results.get('subject', '')).lower() 
                                for keyword in ['password', 'reset', 'verify', 'confirm', 'account']):
            result['reputation_adjustment'] += 3
            result['reputation_notes'].append("Account-related transactional email")
            
        # Cap the adjustment to prevent over-correction
        if result['reputation_adjustment'] > 10:
            result['reputation_adjustment'] = 10
            
    except Exception as e:
        result['error'] = str(e)
    
    return result

def is_ip_in_ranges(ip: str, ranges: list) -> bool:
    """Check if IP is in any of the given CIDR ranges"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        for cidr in ranges:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except:
        pass
    
    return False

def apply_reputation_adjustment(auth_score: float, sender_email: str, sender_ip: str, 
                               auth_results: Dict, subject: str = '') -> tuple:
    """
    Apply reputation-based adjustments to authentication score
    Returns: (adjusted_score, reputation_info)
    """
    # Add subject to auth_results for analysis
    auth_results['subject'] = subject
    
    # Get reputation assessment
    reputation = check_sender_reputation(sender_email, sender_ip, auth_results)
    
    # Calculate adjusted score
    adjusted_score = auth_score
    
    if reputation['reputation_adjustment'] > 0:
        # Apply adjustment to reduce penalty
        adjusted_score = auth_score + reputation['reputation_adjustment']
        
        # Don't let it go too positive if original was very negative
        if auth_score < -5 and adjusted_score > 0:
            adjusted_score = 0  # Neutral at best for severely failed auth
    
    reputation_info = {
        'original_score': auth_score,
        'adjusted_score': adjusted_score,
        'adjustment': reputation['reputation_adjustment'],
        'notes': reputation['reputation_notes'],
        'is_trusted_provider': reputation['is_trusted_provider']
    }
    
    return adjusted_score, reputation_info

if __name__ == "__main__":
    # Test the module
    test_cases = [
        {
            'sender': 'no-reply@qnap.com',
            'ip': '54.240.11.21',
            'auth_results': {'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail'},
            'subject': 'Password Reset Request'
        },
        {
            'sender': 'support@example.com',
            'ip': '1.2.3.4',
            'auth_results': {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'},
            'subject': 'Your order confirmation'
        }
    ]
    
    for test in test_cases:
        print(f"\nTesting: {test['sender']} from {test['ip']}")
        print("-" * 50)
        
        # Calculate original auth score (simplified)
        original_score = 0
        if test['auth_results']['spf'] == 'fail':
            original_score -= 5
        if test['auth_results']['dkim'] == 'fail':
            original_score -= 4
        if test['auth_results']['dmarc'] == 'fail':
            original_score -= 5
            
        adjusted_score, info = apply_reputation_adjustment(
            original_score, 
            test['sender'], 
            test['ip'],
            test['auth_results'],
            test['subject']
        )
        
        print(f"Original auth score: {original_score}")
        print(f"Adjusted auth score: {adjusted_score}")
        print(f"Adjustment: {info['adjustment']}")
        print(f"Notes: {', '.join(info['notes'])}")
        print(f"Trusted provider: {info['is_trusted_provider']}")