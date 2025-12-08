#!/usr/bin/env python3
"""
Domain Entropy and Randomness Detection Module
Detects randomly-generated domain names commonly used in phishing attacks
"""
import re
import math
from collections import Counter
from typing import Dict, Tuple, List

# Common legitimate words that appear in domains
COMMON_WORDS = {
    'mail', 'email', 'service', 'support', 'info', 'contact', 'admin', 'help',
    'web', 'site', 'net', 'online', 'secure', 'account', 'login', 'portal',
    'cloud', 'server', 'host', 'data', 'tech', 'digital', 'system', 'api',
    'app', 'mobile', 'desk', 'box', 'link', 'connect', 'pro', 'plus', 'max'
}

# High-risk TLDs frequently abused for phishing
# NOTE: Nuclear TLDs (.tk, .ml, .ga, .cf, .gq, .cfd) are hard-blocked in blocking_rules table
# with 50.0 spam penalty, so they're excluded here to avoid double-penalization
HIGH_RISK_TLDS = {
    '.xyz', '.top', '.pw', '.cc', '.ws', '.buzz', '.loan',
    '.work', '.click', '.link', '.trade', '.date', '.racing', '.review',
    '.stream', '.download', '.bid', '.win', '.party', '.science',
    '.accountant', '.faith', '.cricket', '.space', '.id', '.rest',
    '.icu', '.monster', '.online', '.site', '.ru'
}

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string
    Higher entropy = more random
    """
    if not text:
        return 0.0

    # Count character frequencies
    counter = Counter(text)
    length = len(text)

    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def calculate_consonant_vowel_ratio(text: str) -> float:
    """
    Calculate ratio of consonants to vowels
    Random strings tend to have unusual ratios
    """
    vowels = set('aeiou')
    consonants = set('bcdfghjklmnpqrstvwxyz')

    text_lower = text.lower()
    vowel_count = sum(1 for c in text_lower if c in vowels)
    consonant_count = sum(1 for c in text_lower if c in consonants)

    if vowel_count == 0:
        return 100.0  # All consonants = very suspicious

    return consonant_count / vowel_count

def has_repeated_patterns(text: str) -> bool:
    """
    Check for repeated character patterns (e.g., 'abab', 'xyzxyz')
    """
    # Check for 2-char patterns
    for i in range(len(text) - 3):
        pattern = text[i:i+2]
        if text[i+2:i+4] == pattern:
            return True

    # Check for 3-char patterns
    for i in range(len(text) - 5):
        pattern = text[i:i+3]
        if text[i+3:i+6] == pattern:
            return True

    return False

def is_keyboard_pattern(text: str) -> bool:
    """
    Detect keyboard walk patterns commonly used in phishing domains
    Examples: qwerty, asdfgh, zxcvbn, qazwsx, mnbvcd
    """
    text_lower = text.lower()

    # Common keyboard rows (QWERTY layout)
    keyboard_rows = [
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm',
        # Reverse patterns
        'poiuytrewq',
        'lkjhgfdsa',
        'mnbvcxz'
    ]

    # Diagonal/column patterns
    keyboard_diagonals = [
        'qazwsx',  # Left column down
        'wsxedc',  # Left-center column
        'edcrfv',  # Center column
        'rfvtgb',  # Center-right column
        'tgbyhn',  # Right-center column
        'yhnujm',  # Right column
        'ujmik',   # Far right column
        # Reverse patterns
        'wsxqaz',
        'cdexsw',
        'vfrced',
        'bgtfvr',
        'nhytgb',
        'mjuyhn',
        'kiujm'
    ]

    all_patterns = keyboard_rows + keyboard_diagonals

    # Check for sequences of 4+ characters from keyboard patterns
    for pattern in all_patterns:
        for i in range(len(pattern) - 3):
            sequence = pattern[i:i+4]
            if sequence in text_lower:
                return True
            # Also check 5 and 6 character sequences for stronger detection
            if i <= len(pattern) - 5:
                sequence5 = pattern[i:i+5]
                if sequence5 in text_lower:
                    return True
            if i <= len(pattern) - 6:
                sequence6 = pattern[i:i+6]
                if sequence6 in text_lower:
                    return True

    return False

def contains_common_words(domain: str) -> bool:
    """
    Check if domain contains recognizable words
    """
    domain_lower = domain.lower()

    # Check for any common words
    for word in COMMON_WORDS:
        if word in domain_lower:
            return True

    return False

def analyze_domain_randomness(domain: str) -> Tuple[float, Dict[str, any]]:
    """
    Analyze a domain for randomness indicators
    Returns: (risk_score, details_dict)

    Risk score: 0-10 (higher = more suspicious)
    """
    if not domain:
        return 0.0, {}

    # Extract just the domain name (remove TLD)
    domain_parts = domain.lower().split('.')
    if len(domain_parts) < 2:
        return 0.0, {}

    # Get domain name without TLD
    domain_name = domain_parts[-2]
    tld = '.' + domain_parts[-1]

    # Skip if domain is too short (< 4 chars often legitimate like fb.com, go.com)
    if len(domain_name) < 4:
        return 0.0, {'domain_name': domain_name, 'tld': tld, 'risk_score': 0.0}

    # Calculate various indicators
    entropy = calculate_entropy(domain_name)
    cv_ratio = calculate_consonant_vowel_ratio(domain_name)
    has_patterns = has_repeated_patterns(domain_name)
    has_words = contains_common_words(domain_name)
    is_high_risk_tld = tld in HIGH_RISK_TLDS
    is_keyboard = is_keyboard_pattern(domain_name)

    # Start scoring
    risk_score = 0.0
    indicators = []

    # HIGH ENTROPY (random-looking characters)
    # Typical entropy: legitimate words ~2.5-3.5, random strings ~4.0+
    if entropy > 4.0:
        risk_score += 4.0
        indicators.append(f"very_high_entropy:{entropy:.2f}")
    elif entropy > 3.5:
        risk_score += 2.0
        indicators.append(f"high_entropy:{entropy:.2f}")

    # CONSONANT-VOWEL RATIO
    # Normal ratio: 1.5-2.5, suspicious: >4.0 or <0.8
    if cv_ratio > 4.0:
        risk_score += 2.0
        indicators.append(f"consonant_heavy:{cv_ratio:.1f}")
    elif cv_ratio < 0.8:
        risk_score += 1.5
        indicators.append(f"vowel_heavy:{cv_ratio:.1f}")

    # NO RECOGNIZABLE WORDS
    if not has_words and len(domain_name) >= 6:
        risk_score += 1.5
        indicators.append("no_common_words")

    # REPEATED PATTERNS (often random generators create these)
    if has_patterns:
        risk_score += 1.0
        indicators.append("repeated_patterns")

    # KEYBOARD PATTERN (phishers use keyboard walks like qazwsx, mnbvcd)
    if is_keyboard:
        risk_score += 3.0
        indicators.append("keyboard_pattern")

    # HIGH-RISK TLD
    if is_high_risk_tld:
        risk_score += 2.5
        indicators.append(f"high_risk_tld:{tld}")

    # CONSECUTIVE CONSONANTS (e.g., 'mjuynb', 'zysnor')
    consecutive_consonants = 0
    max_consecutive = 0
    for char in domain_name.lower():
        if char in 'bcdfghjklmnpqrstvwxyz':
            consecutive_consonants += 1
            max_consecutive = max(max_consecutive, consecutive_consonants)
        else:
            consecutive_consonants = 0

    if max_consecutive >= 4:
        risk_score += 1.5
        indicators.append(f"consonant_cluster:{max_consecutive}")

    # Cap risk score at 10
    risk_score = min(risk_score, 10.0)

    details = {
        'domain_name': domain_name,
        'tld': tld,
        'entropy': round(entropy, 2),
        'cv_ratio': round(cv_ratio, 2),
        'has_patterns': has_patterns,
        'has_common_words': has_words,
        'is_high_risk_tld': is_high_risk_tld,
        'is_keyboard_pattern': is_keyboard,
        'max_consecutive_consonants': max_consecutive,
        'indicators': indicators,
        'risk_score': round(risk_score, 1)
    }

    return risk_score, details

def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from email text/HTML
    Returns both full domains and subdomains for analysis
    """
    domains = set()

    # Pattern for domains in URLs
    url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    matches = re.findall(url_pattern, text)
    domains.update(matches)

    # Pattern for email addresses
    email_pattern = r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    matches = re.findall(email_pattern, text)
    domains.update(matches)

    return list(domains)

def extract_all_domain_parts(domain: str) -> List[str]:
    """
    Extract all analyzable parts of a domain including subdomains
    Example: qazwsx.mifon.cfd -> ['qazwsx.mifon.cfd', 'qazwsx', 'mifon.cfd', 'mifon']
    """
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return [domain]

    variations = []

    # Full domain
    variations.append(domain)

    # Subdomain parts (all non-TLD parts)
    for i in range(len(parts) - 1):  # Exclude TLD
        part = parts[i]
        if len(part) >= 4:  # Only analyze parts with 4+ characters
            variations.append(part)

    return variations

def analyze_email_domains(sender_email: str, email_body: str, links: List[str] = None) -> Dict:
    """
    Main function to analyze all domains in an email
    Returns analysis with spam score penalty
    """
    all_domains = set()

    # Extract sender domain (keep full domain with subdomains)
    if '@' in sender_email:
        sender_domain = sender_email.split('@')[1].lower()
        all_domains.add(sender_domain)

        # Also analyze subdomain parts separately
        parts = sender_domain.split('.')
        # If there are subdomains (more than 2 parts), analyze them individually
        if len(parts) > 2:
            for i, part in enumerate(parts[:-1]):  # All parts except TLD
                if len(part) >= 4:
                    # Create synthetic domain for subdomain analysis (part + tld)
                    synthetic = f"{part}.{parts[-1]}"
                    all_domains.add(synthetic)

    # Extract domains from email body
    body_domains = extract_domains_from_text(email_body)
    all_domains.update(body_domains)

    # Add explicit links if provided
    if links:
        for link in links:
            link_domains = extract_domains_from_text(link)
            all_domains.update(link_domains)

    # Analyze each domain
    results = {
        'domains_analyzed': [],
        'total_risk_score': 0.0,
        'max_risk_score': 0.0,
        'high_risk_domains': [],
        'spam_penalty': 0.0
    }

    for domain in all_domains:
        # Extract and analyze all parts of the domain (including subdomains)
        domain_parts = extract_all_domain_parts(domain)

        for part in domain_parts:
            risk_score, details = analyze_domain_randomness(part)

            if risk_score > 0:
                results['domains_analyzed'].append(details)
                results['total_risk_score'] += risk_score
                results['max_risk_score'] = max(results['max_risk_score'], risk_score)

                # Flag high-risk domains (score >= 5.0)
                if risk_score >= 5.0:
                    results['high_risk_domains'].append({
                        'domain': part,
                        'risk_score': risk_score,
                        'indicators': details['indicators']
                    })

    # Calculate spam penalty
    # High-risk domains get significant penalties
    if results['max_risk_score'] >= 7.0:
        results['spam_penalty'] = 8.0  # Very suspicious random domain
    elif results['max_risk_score'] >= 5.0:
        results['spam_penalty'] = 5.0  # Suspicious random domain
    elif results['max_risk_score'] >= 3.0:
        results['spam_penalty'] = 2.0  # Moderately suspicious

    return results

# Test function
if __name__ == '__main__':
    # Test with the phishing domains from email 150828
    test_domains = [
        'mjuynb.paxor.cfd',  # Sender domain
        'zysnor.cfd',        # Phishing link domain
        'google.com',        # Legitimate comparison
        'sbisec.co.jp'       # Legitimate Japanese bank
    ]

    print("Domain Randomness Analysis Test")
    print("=" * 70)

    for domain in test_domains:
        risk_score, details = analyze_domain_randomness(domain)
        print(f"\nDomain: {domain}")
        print(f"Risk Score: {risk_score}/10")
        if 'entropy' in details:
            print(f"Entropy: {details['entropy']}")
            print(f"C/V Ratio: {details['cv_ratio']}")
            print(f"High-Risk TLD: {details['is_high_risk_tld']}")
            print(f"Indicators: {', '.join(details['indicators'])}")
        else:
            print("(Skipped - domain too short or invalid)")
