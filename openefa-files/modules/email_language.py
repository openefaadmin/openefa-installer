#!/usr/bin/env python3
"""
Improved Language Detection Module for SpaCy Email System
Reduces false positives while maintaining security effectiveness
"""

import re
import logging
import sys
from collections import Counter

try:
    from langdetect import detect, detect_langs
    from langdetect.lang_detect_exception import LangDetectException
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False

def safe_log(message):
    """Safe logging to stderr"""
    try:
        print(f"DEBUG: {message}", file=sys.stderr)
    except:
        pass

def clean_text_for_language_detection(text):
    """
    Clean text to remove content that can cause false language detection
    """
    # Remove base64-like content (long strings of alphanumeric + =/)
    text = re.sub(r'[A-Za-z0-9+/]{50,}={0,2}', ' ', text)
    
    # Remove HTML tags and entities
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&[a-zA-Z]+;', ' ', text)
    text = re.sub(r'&#\d+;', ' ', text)
    
    # Remove email addresses and URLs
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' ', text)
    text = re.sub(r'https?://[^\s]+', ' ', text)
    
    # Remove tracking codes and IDs (common in marketing emails)
    text = re.sub(r'\b[A-Za-z0-9]{20,}\b', ' ', text)
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def detect_cjk_language(text):
    """
    Improved CJK detection with higher thresholds and better character filtering
    """
    # Clean the text first
    clean_text = clean_text_for_language_detection(text)
    
    char_counts = {
        'chinese': 0,
        'japanese_hiragana': 0,
        'japanese_katakana': 0,
        'japanese_kanji': 0,
        'korean': 0,
        'latin': 0,
        'total_meaningful': 0  # Only count letters, not all characters
    }

    for char in clean_text:
        # Only count meaningful characters (letters, not punctuation/numbers)
        if char.isalpha():
            char_counts['total_meaningful'] += 1

            # More precise Unicode ranges
            if '一' <= char <= '龯':  # More restricted CJK range
                char_counts['chinese'] += 1
                char_counts['japanese_kanji'] += 1
            elif 'ひ' <= char <= 'ゖ':  # Hiragana range
                char_counts['japanese_hiragana'] += 1
            elif 'ア' <= char <= 'ヺ':  # Katakana range  
                char_counts['japanese_katakana'] += 1
            elif '가' <= char <= '힣':  # Korean Hangul
                char_counts['korean'] += 1
            elif ('A' <= char <= 'Z') or ('a' <= char <= 'z'):
                char_counts['latin'] += 1

    # Require minimum meaningful characters
    if char_counts['total_meaningful'] < 20:
        return 'en', 0.0, char_counts

    cjk_total = (char_counts['chinese'] + char_counts['japanese_hiragana'] + 
                 char_counts['japanese_katakana'] + char_counts['korean'])
    cjk_ratio = cjk_total / char_counts['total_meaningful']

    # INCREASED threshold from 0.05 to 0.3 (30% CJK characters required)
    if cjk_ratio < 0.3:
        return 'en', 0.0, char_counts

    # Require significant presence for each language
    if char_counts['japanese_hiragana'] > 5 or char_counts['japanese_katakana'] > 5:
        confidence = min((char_counts['japanese_hiragana'] + char_counts['japanese_katakana'] + 
                         char_counts['japanese_kanji']) / char_counts['total_meaningful'], 1.0)
        return 'ja', confidence, char_counts

    if char_counts['korean'] > 10 and char_counts['korean'] > char_counts['chinese']:
        confidence = min(char_counts['korean'] / char_counts['total_meaningful'], 1.0)
        return 'ko', confidence, char_counts

    if char_counts['chinese'] > 10:
        confidence = min(char_counts['chinese'] / char_counts['total_meaningful'], 1.0)
        return 'zh', confidence, char_counts

    return 'en', 0.0, char_counts

def is_known_legitimate_sender(sender_domain, sender_address):
    """
    Check if sender is from known legitimate domains that should be exempt from language blocking
    """
    LEGITIMATE_DOMAINS = {
        'datto.com', 'kaseya.com', 'microsoft.com', 'google.com', 'amazon.com',
        'apple.com', 'adobe.com', 'salesforce.com', 'marketo.com', 'mailchimp.com',
        'constantcontact.com', 'sendgrid.net', 'amazonses.com'
    }
    
    LEGITIMATE_PATTERNS = [
        r'.*\.amazonaws\.com$',
        r'.*\.sendgrid\.net$',
        r'.*\.mailgun\.org$',
        r'.*\.sparkpost\.com$'
    ]
    
    if sender_domain.lower() in LEGITIMATE_DOMAINS:
        return True
        
    for pattern in LEGITIMATE_PATTERNS:
        if re.match(pattern, sender_domain.lower()):
            return True
            
    return False

def detect_language_comprehensive(text, sender_domain='', sender_address=''):
    """
    Improved language detection with better false positive handling
    """
    result = {
        'language': 'unknown',
        'confidence': 0.0,
        'method': 'none',
        'cjk_detected': False,
        'char_stats': {},
        'langdetect_results': None,
        'is_legitimate_sender': False
    }

    # Check if this is a legitimate sender
    result['is_legitimate_sender'] = is_known_legitimate_sender(sender_domain, sender_address)

    # Clean text for analysis
    clean_text = clean_text_for_language_detection(text)
    
    if not clean_text or len(clean_text.strip()) < 30:  # Increased minimum
        result['language'] = 'en'  # Default to English for short/empty content
        result['confidence'] = 0.5
        result['method'] = 'default'
        return result

    # Try CJK detection with improved thresholds
    cjk_lang, cjk_confidence, char_counts = detect_cjk_language(clean_text)
    result['char_stats'] = char_counts

    # INCREASED confidence threshold from 0.1 to 0.5
    if cjk_lang in ['ja', 'ko', 'zh'] and cjk_confidence > 0.5:
        result['language'] = cjk_lang
        result['confidence'] = cjk_confidence
        result['method'] = 'cjk_detection'
        result['cjk_detected'] = True
        safe_log(f"CJK detection: {cjk_lang} with confidence {cjk_confidence:.2f}")
        return result

    # Cyrillic detection with higher threshold
    cyrillic_count = len(re.findall(r'[а-яА-ЯёЁ]', clean_text))
    total_chars = len(re.sub(r'\s', '', clean_text))

    if total_chars > 0 and cyrillic_count / total_chars > 0.5:  # Increased from 0.3
        result['language'] = 'ru'
        result['confidence'] = min(cyrillic_count / total_chars, 1.0)
        result['method'] = 'cyrillic_detection'
        return result

    # Use langdetect as fallback with higher confidence requirements
    if LANGDETECT_AVAILABLE:
        try:
            detected_lang = detect(clean_text)
            all_langs = detect_langs(clean_text)
            lang_confidence = 0.0
            for lang_prob in all_langs:
                if lang_prob.lang == detected_lang:
                    lang_confidence = lang_prob.prob
                    break

            result['langdetect_results'] = [(l.lang, l.prob) for l in all_langs[:3]]

            # INCREASED confidence threshold from 0.8 to 0.9
            if lang_confidence > 0.9:
                result['language'] = detected_lang
                result['confidence'] = lang_confidence
                result['method'] = 'langdetect'
                return result

        except LangDetectException as e:
            safe_log(f"Langdetect error: {e}")

    # Default to English if no clear language detected
    result['language'] = 'en'
    result['confidence'] = 0.5
    result['method'] = 'default'
    return result

def analyze_email_language(msg, text_content, from_header):
    """
    Improved email language analysis with reduced false positives
    """
    analysis = {
        'language': 'unknown',
        'confidence': 0.0,
        'method': 'none',
        'risk_indicators': [],
        'headers_to_add': {}
    }

    # REMOVED blanket language blocking - now use context-based approach
    HIGH_RISK_COMBINATIONS = [
        ('ja', ['.cn']),  # Japanese content from Chinese domains
        ('zh', ['.jp']),  # Chinese content from Japanese domains
    ]

    try:
        subject = msg.get('Subject', '')
        full_text = f"{subject}\n{text_content}"

        # Extract sender domain
        sender_domain = ''
        sender_address = from_header
        if '@' in from_header:
            match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
            if match:
                sender_domain = match.group(1)

        # Perform language detection
        lang_result = detect_language_comprehensive(full_text, sender_domain, sender_address)
        analysis['language'] = lang_result['language']
        analysis['confidence'] = lang_result['confidence']
        analysis['method'] = lang_result['method']

        # Add basic headers
        analysis['headers_to_add']['X-Detected-Language'] = lang_result['language']
        analysis['headers_to_add']['X-Language-Confidence'] = f"{lang_result['confidence']:.2f}"
        analysis['headers_to_add']['X-Language-Method'] = lang_result['method']

        # Only flag high-risk combinations, not individual languages
        for risky_lang, risky_domains in HIGH_RISK_COMBINATIONS:
            if (lang_result['language'] == risky_lang and 
                any(sender_domain.endswith(domain) for domain in risky_domains) and
                not lang_result['is_legitimate_sender']):
                
                risk_msg = f"High-risk: {risky_lang} content from {sender_domain}"
                analysis['risk_indicators'].append(risk_msg)
                analysis['headers_to_add']['X-Language-Phishing-Risk'] = 'high'
                safe_log(f"High-risk language/domain combo: {risk_msg}")

        # Only apply penalties for confirmed high-risk scenarios
        if analysis['risk_indicators'] and not lang_result['is_legitimate_sender']:
            # Much lower penalty than before
            analysis['headers_to_add']['X-Language-Spam-Penalty'] = '2.0'  # Reduced from 7.0
        elif lang_result['is_legitimate_sender']:
            analysis['headers_to_add']['X-Language-Sender-Trusted'] = 'true'

        safe_log(f"Language detection: {analysis['language']} ({analysis['confidence']:.2f}) via {analysis['method']}")
        if lang_result['is_legitimate_sender']:
            safe_log(f"Sender {sender_domain} is in legitimate sender list")
        if analysis['risk_indicators']:
            safe_log(f"Language risk indicators: {', '.join(analysis['risk_indicators'])}")

    except Exception as e:
        safe_log(f"Language analysis error: {e}")
        # Default to English on error
        analysis['language'] = 'en'
        analysis['confidence'] = 0.5
        analysis['method'] = 'error_default'

    return analysis
