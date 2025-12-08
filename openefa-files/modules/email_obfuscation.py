# email_obfuscation.py

import re

ZERO_WIDTH_RE = re.compile(r'[\u200B\u200C\u200D\uFEFF]')
BASE64_RE = re.compile(r'([A-Za-z0-9+/]{40,}={0,2})')
PUNCTUATION_RE = re.compile(r'[!?.]{5,}|([^\w\s])\1{4,}')
UNICODE_RE = re.compile(r'[^\x00-\x7F]')

# Detect random character strings in From display names (like "731848onlineUtWDvnSVvKJZzzg")
# Pattern: Mix of upper/lowercase with no spaces and >20 chars of seemingly random text
RANDOM_STRING_RE = re.compile(r'[A-Za-z]{20,}')

def _check_randomness(text):
    """Check if text appears to be random characters (high entropy)"""
    if len(text) < 20:
        return False

    # Check for lack of common patterns (vowels, common word patterns, etc.)
    vowels = sum(1 for c in text.lower() if c in 'aeiou')
    vowel_ratio = vowels / len(text) if len(text) > 0 else 0

    # Natural text has ~40% vowels, random strings have ~20%
    # Also check for long runs of consonants
    consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', text.lower())

    # Random if low vowel ratio OR multiple long consonant runs
    return vowel_ratio < 0.25 or len(consonant_runs) >= 2

def analyze_obfuscation(email_data):
    text = email_data.get('body', '')
    subject = email_data.get('subject', '')
    from_header = email_data.get('from_header', '')

    obfuscation_flags = {
        'zero_width': bool(ZERO_WIDTH_RE.search(text)),
        'base64_blob': bool(BASE64_RE.search(text)),
        'punctuation_spam': bool(PUNCTUATION_RE.search(text)),
        'unicode_spoof': bool(UNICODE_RE.search(text)),
        'garbled_from_name': False,
        'suspicious_subject': False
    }

    # Extract display name from From header
    display_name = ''
    if '<' in from_header and '>' in from_header:
        display_name = from_header.split('<')[0].strip().strip('"')

    # Check for garbled/random display names
    if display_name:
        # Look for long random strings in display name
        matches = RANDOM_STRING_RE.findall(display_name)
        for match in matches:
            if _check_randomness(match):
                obfuscation_flags['garbled_from_name'] = True
                break

        # Check for patterns like "Support 731848online..."
        # Generic names followed by numbers and random text
        generic_patterns = r'(support|helpdesk|admin|service|team|account)\s*\d{5,}'
        if re.search(generic_patterns, display_name, re.IGNORECASE):
            obfuscation_flags['garbled_from_name'] = True

    # Check subject for suspicious patterns
    if subject:
        # ALL CAPS subjects (>80% capitals)
        if len(subject) > 10:
            caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
            if caps_ratio > 0.8:
                obfuscation_flags['suspicious_subject'] = True

    # Weight the scores
    weights = {
        'zero_width': 3.0,         # Hidden chars are very suspicious
        'base64_blob': 2.0,         # Large base64 blobs are suspicious
        'punctuation_spam': 2.0,    # Excessive punctuation
        'unicode_spoof': 1.5,       # Unicode spoofing
        'garbled_from_name': 8.0,   # HIGH: Random From names are very suspicious
        'suspicious_subject': 2.0   # ALL CAPS subjects
    }

    score = sum(weights[k] for k, v in obfuscation_flags.items() if v)

    result = {
        'obfuscation_score': score,
        'headers_to_add': {
            'X-Obfuscation-Score': f"{score:.1f}",
            'X-Obfuscation-Flags': ','.join(k for k, v in obfuscation_flags.items() if v) or 'None'
        }
    }
    return result

