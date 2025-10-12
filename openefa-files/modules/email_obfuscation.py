# email_obfuscation.py

import re

ZERO_WIDTH_RE = re.compile(r'[\u200B\u200C\u200D\uFEFF]')
BASE64_RE = re.compile(r'([A-Za-z0-9+/]{40,}={0,2})')
PUNCTUATION_RE = re.compile(r'[!?.]{5,}|([^\w\s])\1{4,}')
UNICODE_RE = re.compile(r'[^\x00-\x7F]')

def analyze_obfuscation(email_data):
    text = email_data.get('body', '')
    obfuscation_flags = {
        'zero_width': bool(ZERO_WIDTH_RE.search(text)),
        'base64_blob': bool(BASE64_RE.search(text)),
        'punctuation_spam': bool(PUNCTUATION_RE.search(text)),
        'unicode_spoof': bool(UNICODE_RE.search(text))
    }

    score = sum(obfuscation_flags.values()) * 1.5  # 1.5 pts per flag
    result = {
        'obfuscation_score': score,
        'headers_to_add': {
            'X-Obfuscation-Score': f"{score:.1f}",
            'X-Obfuscation-Flags': ','.join(k for k, v in obfuscation_flags.items() if v) or 'None'
        }
    }
    return result

