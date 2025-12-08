#!/usr/bin/env python3
"""
Domain Age Detection Module
Checks domain creation date and expiration to detect disposable spam domains

Created: 2025-12-03
Purpose: Penalize newly created domains and domains about to expire (disposable spam domains)
"""

import subprocess
import re
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import sys

# Cache for whois results to avoid repeated lookups
# Format: {domain: {'created': datetime, 'expires': datetime, 'cached_at': datetime}}
_domain_cache = {}
CACHE_TTL_HOURS = 24  # Cache results for 24 hours

def parse_whois_date(date_str: str) -> Optional[datetime]:
    """
    Parse various whois date formats into datetime
    """
    if not date_str:
        return None

    # Clean up the date string first
    date_str = date_str.strip()

    # Remove trailing timezone info like +0000 for some formats
    date_str = re.sub(r'\+\d{2}:?\d{2}$', '', date_str).strip()

    # Normalize .0Z or .123Z to just remove it (handle various decimal places)
    date_str = re.sub(r'\.\d*Z?$', '', date_str).strip()

    # Remove trailing Z
    date_str = date_str.rstrip('Z').strip()

    # Common date formats in whois responses
    date_formats = [
        '%Y-%m-%dT%H:%M:%S',           # ISO format (after cleanup)
        '%Y-%m-%d %H:%M:%S',           # Standard datetime
        '%Y-%m-%d',                     # Simple date
        '%d-%b-%Y',                     # 01-Jan-2024
        '%d %b %Y',                     # 01 Jan 2024
        '%Y/%m/%d',                     # 2024/01/01
        '%Y.%m.%d',                     # 2024.01.01
        '%d.%m.%Y',                     # 01.01.2024
        '%B %d, %Y',                    # January 01, 2024
        '%b %d, %Y',                    # Jan 01, 2024
    ]

    for fmt in date_formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def get_domain_whois(domain: str) -> Dict:
    """
    Get whois information for a domain
    Returns dict with 'created', 'expires', 'registrar', 'country'
    """
    result = {
        'domain': domain,
        'created': None,
        'expires': None,
        'registrar': None,
        'country': None,
        'error': None
    }

    try:
        # Run whois command with timeout
        proc = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=10
        )

        whois_output = proc.stdout

        if not whois_output or 'No match' in whois_output or 'NOT FOUND' in whois_output.upper():
            result['error'] = 'Domain not found'
            return result

        # Parse creation date - try various field names
        creation_patterns = [
            r'Creation Date:\s*(.+)',
            r'Created:\s*(.+)',
            r'Created On:\s*(.+)',
            r'Registration Date:\s*(.+)',
            r'Domain Registration Date:\s*(.+)',
            r'created:\s*(.+)',
        ]

        for pattern in creation_patterns:
            match = re.search(pattern, whois_output, re.IGNORECASE)
            if match:
                result['created'] = parse_whois_date(match.group(1))
                if result['created']:
                    break

        # Parse expiration date
        expiry_patterns = [
            r'Registry Expiry Date:\s*(.+)',
            r'Expir(?:y|ation) Date:\s*(.+)',
            r'Expires:\s*(.+)',
            r'Expires On:\s*(.+)',
            r'Expiration Date:\s*(.+)',
            r'paid-till:\s*(.+)',
        ]

        for pattern in expiry_patterns:
            match = re.search(pattern, whois_output, re.IGNORECASE)
            if match:
                result['expires'] = parse_whois_date(match.group(1))
                if result['expires']:
                    break

        # Parse registrar
        registrar_match = re.search(r'Registrar:\s*(.+)', whois_output, re.IGNORECASE)
        if registrar_match:
            result['registrar'] = registrar_match.group(1).strip()

        # Parse country
        country_patterns = [
            r'Registrant Country:\s*(.+)',
            r'country:\s*(.+)',
        ]
        for pattern in country_patterns:
            match = re.search(pattern, whois_output, re.IGNORECASE)
            if match:
                result['country'] = match.group(1).strip()[:2].upper()  # Take first 2 chars
                break

    except subprocess.TimeoutExpired:
        result['error'] = 'Whois timeout'
    except Exception as e:
        result['error'] = str(e)

    return result


def check_domain_age(domain: str, use_cache: bool = True) -> Dict:
    """
    Check domain age and return analysis with spam penalty

    Returns:
        {
            'domain': str,
            'age_days': int or None,
            'days_until_expiry': int or None,
            'is_new_domain': bool,
            'is_expiring_soon': bool,
            'spam_penalty': float,
            'risk_indicators': list,
            'whois_data': dict
        }
    """
    global _domain_cache

    result = {
        'domain': domain,
        'age_days': None,
        'days_until_expiry': None,
        'is_new_domain': False,
        'is_expiring_soon': False,
        'spam_penalty': 0.0,
        'risk_indicators': [],
        'whois_data': None,
        'cached': False
    }

    # Check cache
    if use_cache and domain in _domain_cache:
        cached = _domain_cache[domain]
        cache_age = datetime.now() - cached['cached_at']
        if cache_age.total_seconds() < CACHE_TTL_HOURS * 3600:
            result['cached'] = True
            result['whois_data'] = cached
        else:
            # Cache expired
            del _domain_cache[domain]

    # Fetch whois if not cached
    if not result['whois_data']:
        whois_data = get_domain_whois(domain)
        result['whois_data'] = whois_data

        # Cache successful lookups
        if not whois_data.get('error'):
            _domain_cache[domain] = {
                **whois_data,
                'cached_at': datetime.now()
            }

    whois_data = result['whois_data']
    now = datetime.now()

    # Calculate domain age
    if whois_data.get('created'):
        age = now - whois_data['created']
        result['age_days'] = age.days

        # Check for new domains
        if age.days <= 7:
            result['is_new_domain'] = True
            result['spam_penalty'] += 8.0  # Very new domain - high risk
            result['risk_indicators'].append(f'very_new_domain:{age.days}d')
        elif age.days <= 30:
            result['is_new_domain'] = True
            result['spam_penalty'] += 5.0  # New domain - moderate risk
            result['risk_indicators'].append(f'new_domain:{age.days}d')
        elif age.days <= 90:
            result['spam_penalty'] += 2.0  # Recently created - slight risk
            result['risk_indicators'].append(f'recent_domain:{age.days}d')

    # Calculate days until expiry
    if whois_data.get('expires'):
        until_expiry = whois_data['expires'] - now
        result['days_until_expiry'] = until_expiry.days

        # Check for expiring soon
        if until_expiry.days <= 14:
            result['is_expiring_soon'] = True
            result['spam_penalty'] += 5.0  # About to expire - likely disposable
            result['risk_indicators'].append(f'expiring_very_soon:{until_expiry.days}d')
        elif until_expiry.days <= 30:
            result['is_expiring_soon'] = True
            result['spam_penalty'] += 3.0  # Expiring soon
            result['risk_indicators'].append(f'expiring_soon:{until_expiry.days}d')
        elif until_expiry.days <= 60:
            result['spam_penalty'] += 1.0  # Might be disposable
            result['risk_indicators'].append(f'short_registration:{until_expiry.days}d')

    # Cap penalty at 15.0
    result['spam_penalty'] = min(result['spam_penalty'], 15.0)

    return result


def analyze_sender_domain_age(sender_email: str, only_if_suspicious: bool = True,
                               domain_entropy_penalty: float = 0.0) -> Dict:
    """
    Analyze sender domain age - optionally only for suspicious domains

    Args:
        sender_email: The sender's email address
        only_if_suspicious: If True, only check domains that have other suspicious indicators
        domain_entropy_penalty: Penalty from domain entropy module (if > 0, domain is suspicious)

    Returns:
        Domain age analysis dict or empty dict if skipped
    """
    if '@' not in sender_email:
        return {'skipped': True, 'reason': 'invalid_email'}

    domain = sender_email.split('@')[1].lower()

    # Skip well-known legitimate domains to save whois lookups
    trusted_domains = {
        'gmail.com', 'googlemail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
        'aol.com', 'icloud.com', 'me.com', 'live.com', 'msn.com', 'protonmail.com',
        'proton.me', 'fastmail.com', 'zoho.com', 'yandex.com', 'mail.ru'
    }

    # Extract base domain (handle subdomains)
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
    else:
        base_domain = domain

    if base_domain in trusted_domains:
        return {'skipped': True, 'reason': 'trusted_domain'}

    # Skip trusted TLDs
    trusted_tlds = {'.gov', '.mil', '.edu', '.gov.uk', '.gov.au'}
    for tld in trusted_tlds:
        if domain.endswith(tld):
            return {'skipped': True, 'reason': 'trusted_tld'}

    # If only_if_suspicious, check if we should proceed
    if only_if_suspicious and domain_entropy_penalty < 3.0:
        return {'skipped': True, 'reason': 'not_suspicious'}

    # Perform the domain age check
    return check_domain_age(base_domain)


# Test function
if __name__ == '__main__':
    test_domains = [
        'tvizxjmlt.shop',   # Suspicious spam domain
        'google.com',        # Established domain
        'example.com',       # Test domain
    ]

    print("Domain Age Analysis Test")
    print("=" * 70)

    for domain in test_domains:
        print(f"\nAnalyzing: {domain}")
        result = check_domain_age(domain, use_cache=False)
        print(f"  Age: {result['age_days']} days" if result['age_days'] else "  Age: Unknown")
        print(f"  Expires in: {result['days_until_expiry']} days" if result['days_until_expiry'] else "  Expires: Unknown")
        print(f"  Spam Penalty: {result['spam_penalty']}")
        print(f"  Risk Indicators: {result['risk_indicators']}")
        if result['whois_data'].get('error'):
            print(f"  Error: {result['whois_data']['error']}")
