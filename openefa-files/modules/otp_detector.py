import re

# Supported OTP sender domains for Microsoft and others
OTP_SENDER_DOMAINS = {
    'microsoft': [
        'microsoft.com',
        'accountprotection.microsoft.com',
        'login.microsoftonline.com',
        'email.microsoft.com',
        'microsoftonline.com',
        'outlook.com'  # Added common Outlook domain
    ],
    # You can add more providers below, e.g.:
    # 'google': ['google.com', 'accounts.google.com'],
}

# OTP-related subject keywords for Microsoft (add more as needed)
OTP_KEYWORDS = {
    'microsoft': [
        'verification code',
        'security code',
        'one-time code',
        'sign in code',
        'account security code',
        'access code',
        'authentication code',
        'code'
    ],
    # Add more keywords for other providers if needed
}

def extract_otp(subject, body, from_header):
    """
    Scans the subject, body, and from_header for known OTP patterns.
    Returns (provider, code) if found, otherwise (None, None).
    """
    from_header = from_header.lower()
    subject = subject.lower()
    body_lower = body.lower()
    
    for provider, domains in OTP_SENDER_DOMAINS.items():
        if any(domain in from_header for domain in domains):
            keywords = OTP_KEYWORDS.get(provider, [])
            
            # Check if subject OR body contains OTP keywords
            has_otp_keywords = (
                any(kw in subject for kw in keywords) or
                any(kw in body_lower for kw in keywords)
            )
            
            if has_otp_keywords:
                # Try multiple OTP patterns, prioritizing longer codes
                otp_patterns = [
                    r'\b(\d{8})\b',      # 8-digit codes (priority)
                    r'\b(\d{7})\b',      # 7-digit codes
                    r'\b(\d{6})\b',      # 6-digit codes (most common)
                    r'\b(\d{4})\b'       # 4-digit codes (backup)
                ]
                
                for pattern in otp_patterns:
                    # Search in body first (more reliable), then subject
                    match = re.search(pattern, body)
                    if not match:
                        match = re.search(pattern, subject)
                    
                    if match:
                        code = match.group(1)
                        # Basic validation: avoid obvious non-OTP numbers
                        if not _is_likely_non_otp(code):
                            return provider.title(), code
    
    return None, None

def _is_likely_non_otp(code):
    """
    Basic filter to avoid obvious non-OTP numbers like years, common sequences
    """
    # Avoid years (1900-2099)
    if len(code) == 4 and 1900 <= int(code) <= 2099:
        return True
    
    # Avoid simple sequences (111111, 123456, etc.)
    if len(set(code)) <= 2:  # Too few unique digits
        return True
    
    # Avoid sequential patterns
    if code in ['123456', '654321', '111111', '000000']:
        return True
    
    return False

# Example: add other providers in the future
# OTP_SENDER_DOMAINS['google'] = ['google.com', 'accounts.google.com']
# OTP_KEYWORDS['google'] = ['Google verification code', 'Google security code']
