#!/usr/bin/env python3
"""
Email Analysis Module

Contains all email content analysis functions including:
- Sentiment analysis
- Email classification
- Topic extraction
- Content summarization
- Urgency scoring
- Entity analysis
- Domain spoofing detection
- Link analysis
- Government communication detection
"""

import re
import json
import difflib
import requests
from urllib.parse import urlparse
from utils.logging import safe_log, log_sentiment_debug

# Import analysis libraries with fallbacks
try:
    from textblob import TextBlob
except ImportError:
    TextBlob = None
    safe_log("WARNING: TextBlob not available - sentiment analysis will use fallback")

try:
    from langdetect import detect, DetectorFactory
    DetectorFactory.seed = 0
except ImportError:
    detect = None
    safe_log("WARNING: langdetect not available - language detection will use fallback")


def is_government_communication(sender, subject, text_content):
    """
    Enhanced detection for government communications
    Returns: (is_gov_comm, confidence_score, detection_method)
    """
    if not sender:
        return False, 0.0, "no_sender"
    
    sender_lower = sender.lower()
    subject_lower = subject.lower() if subject else ""
    content_lower = text_content.lower() if text_content else ""
    
    # Government domain patterns
    gov_domains = [
        '.gov', '.mil', 
        'messages.cisa.gov', 'alerts.cisa.gov',
        'noreply.dhs.gov', 'notifications.treasury.gov',
        'alerts.fbi.gov', 'notifications.nsa.gov'
    ]
    
    confidence = 0.0
    detection_methods = []
    
    # Check sender domain
    for domain in gov_domains:
        if domain in sender_lower:
            confidence += 8.0
            detection_methods.append(f"gov_domain:{domain}")
            break
    
    # Government communication indicators
    gov_indicators = {
        'advisory_keywords': [
            'cybersecurity advisory', 'security advisory', 'threat advisory',
            'vulnerability notification', 'security alert', 'threat intelligence',
            'binding operational directive', 'federal civilian executive branch',
            'known exploited vulnerabilities', 'kev catalog'
        ],
        'agency_references': [
            'cisa', 'cybersecurity and infrastructure security agency',
            'department of homeland security', 'dhs', 'nsa', 'fbi',
            'national security agency', 'federal bureau of investigation'
        ],
        'official_patterns': [
            'official website of the united states government',
            'govdelivery', 'manage subscriptions', 'privacy policy',
            'this email was sent', 'using govdelivery communications cloud'
        ]
    }
    
    combined_text = f"{subject_lower} {content_lower}"
    
    for category, keywords in gov_indicators.items():
        matches = sum(1 for keyword in keywords if keyword in combined_text)
        if matches > 0:
            confidence += min(matches * 1.5, 4.0)  # Cap per category
            detection_methods.append(f"{category}:{matches}")
    
    # CVE pattern detection (strong government indicator)
    cve_pattern = r'cve-\d{4}-\d+'
    cve_matches = len(re.findall(cve_pattern, combined_text))
    if cve_matches > 0:
        confidence += min(cve_matches * 2.0, 6.0)
        detection_methods.append(f"cve_references:{cve_matches}")
    
    # Technical security terms
    security_terms = [
        'vulnerabilities', 'exploits', 'malware', 'threat actors',
        'indicators of compromise', 'tactics techniques procedures',
        'mitigations', 'remediation', 'security controls'
    ]
    
    security_matches = sum(1 for term in security_terms if term in combined_text)
    if security_matches >= 3:
        confidence += min(security_matches * 0.5, 3.0)
        detection_methods.append(f"security_terms:{security_matches}")
    
    is_gov_comm = confidence >= 8.0
    return is_gov_comm, min(confidence, 10.0), "; ".join(detection_methods)


def adjust_scores_for_government_communication(spam_score, urgency_score, manipulation_score, 
                                             extremity_score, is_gov_comm, confidence):
    """
    Adjust NLP scores for government communications
    """
    if not is_gov_comm or confidence < 8.0:
        return spam_score, urgency_score, manipulation_score, extremity_score
    
    # Calculate reduction factor based on confidence
    reduction_factor = min(confidence / 10.0, 0.8)  # Max 80% reduction
    
    # Adjust scores with government context
    adjusted_spam = max(0.0, spam_score - (spam_score * reduction_factor))
    
    # Government communications often have legitimate urgency
    adjusted_urgency = max(0.0, urgency_score * 0.3) if urgency_score > 6.0 else urgency_score
    
    # Reduce manipulation score for technical/official content
    adjusted_manipulation = max(0.0, manipulation_score - (manipulation_score * 0.7))
    
    # Reduce extremity for official communications
    adjusted_extremity = max(0.0, extremity_score - (extremity_score * 0.6))
    
    return adjusted_spam, adjusted_urgency, adjusted_manipulation, adjusted_extremity


def filter_government_entities(entities, is_gov_comm):
    """
    Filter out false positive entities for government communications
    """
    if not is_gov_comm:
        return entities
    
    filtered_entities = []
    
    for entity in entities:
        entity_text = entity.get('text', '').lower()
        entity_label = entity.get('label', '')
        
        # Skip CVE references marked as money
        if entity_label == 'MONEY' and ('cve-' in entity_text or 'cvss' in entity_text):
            continue
            
        # Skip technical IDs marked as money
        if entity_label == 'MONEY' and any(pattern in entity_text for pattern in [
            '#', 'id:', 'ref:', 'cve', 'version', 'build'
        ]):
            continue
            
        # Skip government agency names marked as persons when in org context
        if entity_label == 'PERSON' and any(agency in entity_text for agency in [
            'cisa', 'dhs', 'nsa', 'fbi', 'cybersecurity'
        ]):
            # Reclassify as ORG
            entity['label'] = 'ORG'
            
        filtered_entities.append(entity)
    
    return filtered_entities


def enhanced_government_analysis(sender, subject, text_content, entities, 
                                spam_score, urgency_score, sentiment_analysis):
    """
    Complete government communication analysis and score adjustment
    """
    # Detect government communication
    is_gov_comm, confidence, detection_method = is_government_communication(
        sender, subject, text_content
    )
    
    if is_gov_comm:
        # Log government communication detection
        safe_log(f"Government communication detected: confidence={confidence:.1f}, "
                f"method={detection_method}")
        
        # Filter entities
        filtered_entities = filter_government_entities(entities, is_gov_comm)
        
        # Adjust scores
        adjusted_spam, adjusted_urgency, adjusted_manipulation, adjusted_extremity = \
            adjust_scores_for_government_communication(
                spam_score, urgency_score, 
                sentiment_analysis.get('manipulation_score', 0),
                sentiment_analysis.get('extremity_score', 0),
                is_gov_comm, confidence
            )
        
        # Update sentiment analysis
        sentiment_analysis['manipulation_score'] = adjusted_manipulation
        sentiment_analysis['extremity_score'] = adjusted_extremity
        
        # Add government communication indicators
        if 'manipulation_indicators' not in sentiment_analysis:
            sentiment_analysis['manipulation_indicators'] = []
        sentiment_analysis['manipulation_indicators'].append('government_communication')
        
        return {
            'is_government': True,
            'confidence': confidence,
            'detection_method': detection_method,
            'adjusted_spam_score': adjusted_spam,
            'adjusted_urgency_score': adjusted_urgency,
            'filtered_entities': filtered_entities,
            'sentiment_analysis': sentiment_analysis
        }
    
    return {
        'is_government': False,
        'confidence': 0.0,
        'detection_method': 'none',
        'adjusted_spam_score': spam_score,
        'adjusted_urgency_score': urgency_score,
        'filtered_entities': entities,
        'sentiment_analysis': sentiment_analysis
    }


def detect_business_context(text, subject, sender=None):
    """
    Detect if this is a legitimate business communication context
    
    Returns:
        dict: {
            'is_business_context': bool,
            'business_terms_found': list,
            'context_confidence': float,
            'sender_reputation': str
        }
    """
    try:
        # Business software and service terms
        business_terms = [
            'workflow', 'integration', 'solution', 'platform', 'tool', 'software',
            'system', 'service', 'automation', 'productivity', 'efficiency',
            'accounting', 'quickbooks', 'autotask', 'crm', 'erp', 'dashboard',
            'api', 'sync', 'synchronization', 'backup', 'cloud', 'saas',
            'implementation', 'deployment', 'configuration', 'optimization',
            'analytics', 'reporting', 'metrics', 'kpi', 'roi'
        ]
        
        # Legitimate business marketing terms
        business_marketing_terms = [
            'webinar', 'demo', 'training', 'certification', 'workshop', 'seminar',
            'best practices', 'use case', 'case study', 'whitepaper', 'ebook',
            'resource', 'guide', 'tutorial', 'documentation', 'support',
            'partnership', 'collaboration', 'integration', 'upgrade', 'migration'
        ]
        
        # Known legitimate business domains
        business_domains = [
            'microsoft.com', 'google.com', 'salesforce.com', 'oracle.com', 'sap.com',
            'adobe.com', 'intuit.com', 'quickbooks.com', 'datto.com', 'kaseya.com',
            'pax8.com', 'unitrends.com', 'connectwise.com', 'autotask.com',
            'hubspot.com', 'mailchimp.com', 'constant-contact.com', 'zoom.us'
        ]
        
        combined_text = (subject + ' ' + text).lower()
        
        # Check for business terms
        business_terms_found = [term for term in business_terms if term in combined_text]
        marketing_terms_found = [term for term in business_marketing_terms if term in combined_text]
        
        # Check sender domain reputation
        sender_reputation = 'unknown'
        if sender:
            sender_domain = sender.lower().split('@')[-1]
            if sender_domain in business_domains:
                sender_reputation = 'trusted_business'
            elif sender_domain.endswith('.gov') or sender_domain.endswith('.edu'):
                sender_reputation = 'institutional'
            elif any(domain in sender_domain for domain in ['gmail.com', 'yahoo.com', 'hotmail.com']):
                sender_reputation = 'consumer'
        
        # Calculate confidence
        total_terms_found = len(business_terms_found) + len(marketing_terms_found)
        context_confidence = min(1.0, total_terms_found / 3.0)  # Scale 0-1
        
        # Boost confidence for trusted senders
        if sender_reputation == 'trusted_business':
            context_confidence = min(1.0, context_confidence + 0.3)
        elif sender_reputation == 'institutional':
            context_confidence = min(1.0, context_confidence + 0.2)
        
        is_business_context = (
            total_terms_found >= 2 or 
            sender_reputation in ['trusted_business', 'institutional'] or
            context_confidence >= 0.5
        )
        
        return {
            'is_business_context': is_business_context,
            'business_terms_found': business_terms_found + marketing_terms_found,
            'context_confidence': context_confidence,
            'sender_reputation': sender_reputation
        }
        
    except Exception as e:
        safe_log(f"Business context detection error: {e}", "ERROR")
        return {
            'is_business_context': False,
            'business_terms_found': [],
            'context_confidence': 0.0,
            'sender_reputation': 'unknown'
        }


def detect_domain_spoofing(sender_email, email_text, subject, legitimate_domains, spoofing_patterns):
    """
    Detect potential domain spoofing in sender address and email content
    
    Args:
        sender_email: Sender's email address
        email_text: Email body text
        subject: Email subject
        legitimate_domains: Dictionary of legitimate domains and their spoofed variants
        spoofing_patterns: List of character substitution patterns
    
    Returns:
        dict: {
            'spoofing_score': float,
            'spoofed_domains': list,
            'suspicious_patterns': list,
            'risk_level': str
        }
    """
    spoofing_score = 0.0
    spoofed_domains = []
    suspicious_patterns = []
    
    try:
        # Extract domain from sender email
        if sender_email and '@' in sender_email:
            sender_domain = sender_email.lower().split('@')[-1]
            
            # Check against known spoofed domains
            for legit_domain, spoofed_variants in legitimate_domains.items():
                if sender_domain in spoofed_variants:
                    spoofing_score += 5.0  # High penalty for known spoofed domains
                    spoofed_domains.append({
                        'domain': sender_domain,
                        'spoofs': legit_domain,
                        'confidence': 'high',
                        'method': 'known_variant'
                    })
                    suspicious_patterns.append(f"known_spoofed_domain:{sender_domain}")
                elif sender_domain != legit_domain:
                    # Check similarity using difflib
                    similarity = difflib.SequenceMatcher(None, sender_domain, legit_domain).ratio()
                    if similarity > 0.8:  # Very similar domains
                        spoofing_score += 3.0 * similarity
                        spoofed_domains.append({
                            'domain': sender_domain,
                            'spoofs': legit_domain,
                            'confidence': 'medium',
                            'similarity': similarity,
                            'method': 'similarity_match'
                        })
                        suspicious_patterns.append(f"similar_domain:{sender_domain}->{legit_domain}")
            
            # Check for suspicious character patterns in sender domain
            for pattern, description in spoofing_patterns:
                if re.search(pattern, sender_domain):
                    suspicious_patterns.append(f"suspicious_chars:{description}")
                    spoofing_score += 1.0
            
            # Check for unusual TLDs in business/financial contexts
            business_keywords = ['payment', 'invoice', 'account', 'security', 'verify', 'update', 
                                'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google']
            combined_text = (subject + ' ' + email_text).lower()
            if any(keyword in combined_text for keyword in business_keywords):
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.buzz', '.click']
                for tld in suspicious_tlds:
                    if sender_domain.endswith(tld):
                        spoofing_score += 2.0
                        suspicious_patterns.append(f"suspicious_tld:{tld}")
                        break
        
        # Extract and check URLs in email content for spoofing
        email_domains = extract_domains_from_text(email_text + ' ' + subject)
        for domain in email_domains:
            for legit_domain, spoofed_variants in legitimate_domains.items():
                if domain in spoofed_variants:
                    spoofing_score += 3.0  # Penalty for spoofed domains in content
                    spoofed_domains.append({
                        'domain': domain,
                        'spoofs': legit_domain,
                        'confidence': 'high',
                        'method': 'content_spoofed_link'
                    })
                    suspicious_patterns.append(f"spoofed_link:{domain}")
        
        # Determine risk level
        if spoofing_score >= 5.0:
            risk_level = 'high'
        elif spoofing_score >= 2.0:
            risk_level = 'medium'
        elif spoofing_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'none'
        
        return {
            'spoofing_score': spoofing_score,
            'spoofed_domains': spoofed_domains,
            'suspicious_patterns': suspicious_patterns,
            'risk_level': risk_level
        }
        
    except Exception as e:
        safe_log(f"Domain spoofing detection error: {e}", "ERROR")
        return {
            'spoofing_score': 0.0,
            'spoofed_domains': [],
            'suspicious_patterns': [],
            'risk_level': 'none'
        }


def extract_domains_from_text(text):
    """Extract domains from URLs and email addresses in text"""
    domains = set()
    
    try:
        # Extract from URLs
        url_pattern = r'https?://([^\s/]+)'
        url_matches = re.findall(url_pattern, text)
        for match in url_matches:
            domains.add(match.lower())
        
        # Extract from email addresses
        email_pattern = r'[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})'
        email_matches = re.findall(email_pattern, text)
        for match in email_matches:
            domains.add(match.lower())
            
    except Exception as e:
        safe_log(f"Domain extraction error: {e}", "ERROR")
    
    return list(domains)


def analyze_entity_combinations(entities):
    """Identify suspicious combinations of entities"""
    entity_types = [ent.get("label") for ent in entities]
    combos = []
    
    # Check for specific combinations
    if "MONEY" in entity_types and "URL" in entity_types:
        combos.append("MONEY+URL")
    
    if "MONEY" in entity_types and "PERSON" in entity_types:
        combos.append("MONEY+PERSON")
        
    if "ORG" in entity_types and "MONEY" in entity_types:
        combos.append("ORG+MONEY")
        
    if "EMAIL" in entity_types and "CARDINAL" in entity_types:
        combos.append("EMAIL+CARDINAL")
        
    if entity_types.count("MONEY") >= 3:
        combos.append("MULTIPLE_MONEY")
        
    if entity_types.count("URL") >= 3:
        combos.append("MULTIPLE_URL")
        
    if "WORK_OF_ART" in entity_types and "PERSON" in entity_types:
        combos.append("CREATIVE_CONTENT")
        
    return combos


def calculate_urgency_score(text, sender=None, is_system_notification=False):
    """
    Calculate how urgent the email appears based on language patterns
    
    Args:
        text: The email text
        sender: The sender email address
        is_system_notification: Whether this is a known system notification
    """
    try:
        urgent_words = ['immediately', 'urgent', 'now', 'asap', 'critical', 'important', 
                       'deadline', 'limited time', 'expires', 'act now', 'hurry',
                       'action required', 'limited offer', 'don\'t wait', 'before it\'s too late']
        
        # For system notifications, some urgency is expected
        if is_system_notification:
            # Remove words that are normal for system alerts
            urgent_words = [w for w in urgent_words if w not in ['critical', 'important', 'urgent']]
        
        # Count occurrences of urgent words
        text_lower = text.lower()
        urgent_count = sum(1 for word in urgent_words if word in text_lower)
        
        # Check for time pressure phrases
        time_phrases = ['within 24 hours', 'within 48 hours', 'today only', 'expires today',
                       'by tomorrow', 'last chance', 'final notice', 'closing soon']
        time_pressure_count = sum(1 for phrase in time_phrases if phrase in text_lower)
        
        # Check for exclamation marks (excessive usage often indicates urgency)
        exclamation_count = min(5, text.count('!'))
        
        # Count ALL CAPS words (indicates shouting/urgency)
        words = text.split()
        all_caps_count = sum(1 for word in words if word.isupper() and len(word) > 2)
        
        # Calculate final score (capped at 10)
        urgency_score = min(10.0, urgent_count + (time_pressure_count * 2.0) + 
                           exclamation_count * 0.5 + all_caps_count * 0.3)
        
        # Reduce urgency score for known system notifications
        if is_system_notification:
            urgency_score = urgency_score * 0.5  # Cut in half for system notifications
            
        return urgency_score
    except Exception as e:
        safe_log(f"Error calculating urgency score: {e}", "ERROR")
        return 0.0


def calculate_sentiment(text, subject=None, sender=None, recipients=None, 
                       known_senders=None, system_notification_senders=None, 
                       system_notification_recipients=None, system_notification_patterns=None):
    """
    Calculate comprehensive sentiment metrics including:
    - Overall polarity (-1 to 1)
    - Intensity/strength
    - Emotional manipulation indicators
    - Extremity score
    
    Args:
        text: Email body text
        subject: Email subject
        sender: Sender email address
        recipients: List of recipient addresses
        known_senders: Dict of known legitimate senders
        system_notification_senders: Set of system notification sender addresses
        system_notification_recipients: Set of system notification recipient addresses
        system_notification_patterns: List of (keyword, secondary_keywords) tuples
    
    Returns a dictionary with sentiment metrics
    """
    # Check if this is from a known sender or system notification
    is_known_sender = check_known_sender(sender, known_senders) if sender else False
    is_system_notification = is_system_notification_content(
        text, subject or '', recipients, sender,
        system_notification_senders, system_notification_recipients, system_notification_patterns
    )
    
    # Check if this is a government communication
    is_gov_comm, gov_confidence, _ = is_government_communication(sender, subject, text)
    
    # NEW: Check business context
    business_context = detect_business_context(text, subject or '', sender)
    
    # Log to sentiment debug
    log_sentiment_debug("calculate_sentiment called", {
        "subject": subject,
        "text_length": len(text) if text else 0,
        "is_system_notification": is_system_notification,
        "is_known_sender": is_known_sender,
        "is_government": is_gov_comm,
        "is_business_context": business_context['is_business_context'],
        "business_confidence": business_context['context_confidence'],
        "sender_reputation": business_context['sender_reputation']
    })
    
    try:
        # Safety check for input
        if not text or not isinstance(text, str):
            safe_log(f"Invalid text input for sentiment analysis: {type(text)}", "ERROR")
            text = "" if not text else str(text)
            
        if subject and not isinstance(subject, str):
            safe_log(f"Invalid subject input for sentiment analysis: {type(subject)}", "ERROR")
            subject = str(subject) if subject else ""
        
        # Combine subject and text with subject given more weight
        combined_text = (subject + " " + subject + " " + text) if subject else text
        
        # Basic sentiment analysis with TextBlob - wrapped in try/except
        polarity = 0
        subjectivity = 0
        if TextBlob:
            try:
                blob = TextBlob(combined_text)
                polarity = blob.sentiment.polarity
                subjectivity = blob.sentiment.subjectivity
                safe_log(f"TextBlob sentiment: polarity={polarity}, subjectivity={subjectivity}")
                
                log_sentiment_debug("TextBlob analysis complete", {
                    "polarity": polarity,
                    "subjectivity": subjectivity
                })
            except Exception as blob_err:
                safe_log(f"TextBlob analysis failed: {blob_err}", "ERROR")
                log_sentiment_debug(f"TextBlob error: {blob_err}")
        
        # Manual detection of intensity factors
        all_caps_count = len([word for word in combined_text.split() if word.isupper() and len(word) > 2])
        exclamation_count = combined_text.count('!')
        
        # Direct detection of urgency words
        urgent_words = ['urgent', 'immediately', 'hurry', 'expire', 'act now', "don't wait", 'limited']
        
        # For system notifications and government communications, filter out technical urgency words
        if is_system_notification or is_gov_comm:
            # These are normal in system notifications and government advisories
            technical_urgent_words = ['critical', 'error', 'failed', 'warning', 'alert']
            urgent_words = [w for w in urgent_words if w not in technical_urgent_words]
            
        urgent_count = sum(1 for word in urgent_words if word in combined_text.lower())
        
        # Direct detection of threatening words
        threatening_words = ['warning', 'terminate', 'suspended', 'penalties', 'security', 'suspicious']
        
        # For system notifications and government communications, these words are normal
        if is_system_notification or is_gov_comm:
            system_normal_words = ['warning', 'suspended', 'security', 'error', 'failed']
            threatening_words = [w for w in threatening_words if w not in system_normal_words]
            
        threatening_count = sum(1 for word in threatening_words if word in combined_text.lower())
        
        # Direct detection of flattery
        flattery_words = ['valued', 'special', 'exclusive', 'selected', 'exceptional']
        flattery_count = sum(1 for word in flattery_words if word in combined_text.lower())
        
        # Calculate manipulation score manually
        base_manipulation = ((urgent_count * 1.5) + (threatening_count * 2.0) + 
                           (flattery_count * 1.0) + (all_caps_count * 0.5) + 
                           (exclamation_count * 0.8) + (abs(polarity) * 2))
        
        # Apply context-based reductions
        if is_system_notification:
            manipulation_score = min(10, base_manipulation * 0.2)  # 80% reduction
        elif business_context['is_business_context']:
            # Scale reduction based on business confidence
            reduction_factor = 1.0 - (business_context['context_confidence'] * 0.6)  # Up to 60% reduction
            manipulation_score = min(10, base_manipulation * reduction_factor)
            
            # Additional reduction for trusted business senders
            if business_context['sender_reputation'] == 'trusted_business':
                manipulation_score = min(6.0, manipulation_score)  # Cap at 6.0 for trusted business
        elif is_gov_comm and gov_confidence >= 8.0:
            manipulation_score = min(10, base_manipulation * 0.2)  # 80% reduction for government
        elif is_known_sender:
            manipulation_score = min(10, base_manipulation * 0.7)  # 30% reduction for known senders
        else:
            manipulation_score = min(10, base_manipulation)
        
        # Calculate extremity score manually
        base_extremity = (abs(polarity) * 5 + subjectivity * 3 + 
                         (all_caps_count * 0.3) + (exclamation_count * 0.2))
        
        # Apply similar context reductions for extremity
        if is_system_notification:
            extremity_score = min(10, base_extremity * 0.3)  # 70% reduction
        elif business_context['is_business_context']:
            reduction_factor = 1.0 - (business_context['context_confidence'] * 0.5)  # Up to 50% reduction
            extremity_score = min(10, base_extremity * reduction_factor)
        elif is_gov_comm and gov_confidence >= 8.0:
            extremity_score = min(10, base_extremity * 0.3)  # 70% reduction for government
        else:
            extremity_score = min(10, base_extremity)
        
        # Determine manipulation indicators
        manipulation_indicators = []
        if urgent_count >= 2 and not (is_system_notification or is_gov_comm):
            manipulation_indicators.append("urgent_positive" if polarity > 0 else "urgent_negative")
        if threatening_count >= 2 and not (is_system_notification or is_gov_comm):
            manipulation_indicators.append("threatening_negative")
        if flattery_count >= 2:
            manipulation_indicators.append("flattery")
        if polarity > 0.6 and subjectivity > 0.6 and not (is_system_notification or is_gov_comm or business_context['is_business_context']):
            manipulation_indicators.append("excessive_positivity")
        if (all_caps_count > 5 or exclamation_count > 3) and not (is_system_notification or is_gov_comm):
            manipulation_indicators.append("excessive_emphasis")
        
        # Add context indicators
        if business_context['is_business_context']:
            manipulation_indicators.append("business_context")
        if is_gov_comm and gov_confidence >= 8.0:
            manipulation_indicators.append("government_communication")
        
        # Log feature counts for debugging
        log_sentiment_debug("Enhanced sentiment features calculated", {
            "all_caps_words": all_caps_count,
            "exclamation_marks": exclamation_count,
            "urgent_words": urgent_count,
            "threatening_words": threatening_count,
            "flattery_words": flattery_count,
            "extremity_score": extremity_score,
            "manipulation_score": manipulation_score,
            "indicators": ', '.join(manipulation_indicators) if manipulation_indicators else "none",
            "business_terms": ', '.join(business_context['business_terms_found'][:3]) if business_context['business_terms_found'] else "none",
            "adjustments_applied": (
                "system_notification" if is_system_notification 
                else "government" if is_gov_comm
                else f"business_context_{business_context['context_confidence']:.2f}" if business_context['is_business_context']
                else "known_sender" if is_known_sender
                else "none"
            )
        })
        
        result = {
            "polarity": polarity,
            "subjectivity": subjectivity,
            "polarity_variance": 0,  # Simplified for now
            "extremity_score": extremity_score,
            "manipulation_score": manipulation_score,
            "manipulation_indicators": manipulation_indicators,
            "business_context": business_context  # NEW: Include business context in results
        }
        
        return result
        
    except Exception as e:
        safe_log(f"Enhanced sentiment analysis error: {e}", "ERROR")
        log_sentiment_debug(f"ERROR in sentiment analysis: {e}")
            
        # Return default values with basic calculation attempt
        return {
            "polarity": 0,
            "subjectivity": 0,
            "polarity_variance": 0,
            "extremity_score": min(5, text.count('!') + text.count('?') + sum(1 for w in text.split() if w.isupper())),
            "manipulation_score": min(5, text.count('urgent') + text.count('URGENT') + text.count('!')),
            "manipulation_indicators": ["error_fallback"],
            "business_context": {"is_business_context": False, "context_confidence": 0.0}
        }


def detect_language(text):
    """Detect the language of the text content"""
    try:
        if not text or len(text.strip()) < 20:
            return ('en', 1.0)  # Default to English for very short texts
        
        if detect:
            try:
                language = detect(text)
                
                # Estimate confidence (langdetect doesn't provide this directly)
                # We use a simplified approach based on text length
                confidence = min(1.0, len(text) / 500.0)
                
                return (language, confidence)
            except:
                return ('en', 0.5)  # Default to English if detection fails
        else:
            return ('en', 0.5)  # No detection library available
            
    except Exception as e:
        safe_log(f"Language detection error: {e}", "ERROR")
        return ('en', 0.0)  # Default to English


def classify_email(text, subject, sender=None, recipients=None, has_attachments=False, has_links=False,
                  known_senders=None, system_notification_senders=None, 
                  system_notification_recipients=None, system_notification_patterns=None):
    """
    Advanced email classification using multiple signals:
    - Content analysis
    - Structure analysis
    - Sender patterns
    - Recipient patterns
    - Metadata (attachments, links)
    - Government communication detection
    
    Returns primary category and confidence score
    """
    try:
        # Check if this is from a known sender
        is_known_sender = check_known_sender(sender, known_senders)
        
        # Check if content matches system notification patterns OR sent to notification recipients
        is_system_notification = is_system_notification_content(
            text, subject, recipients, sender,
            system_notification_senders, system_notification_recipients, system_notification_patterns
        )
        
        # Check if this is a government communication
        is_gov_comm, gov_confidence, gov_method = is_government_communication(sender, subject, text)
        
        # NEW: Check business context
        business_context = detect_business_context(text, subject, sender)
        
        # Log if classified by recipient or sender
        if recipients and system_notification_recipients and any(r.lower() in system_notification_recipients for r in recipients):
            safe_log(f"Email classified as system_notification due to recipient")
        elif sender and system_notification_senders and sender.lower() in system_notification_senders:
            safe_log(f"Email classified as system_notification due to sender: {sender}")
        elif is_gov_comm:
            safe_log(f"Email classified as government communication: confidence={gov_confidence:.1f}")
        
        # Combine subject and text with subject given more weight
        combined_text = subject + " " + subject + " " + text
        combined_text = combined_text.lower()
        
        # Define categories and their associated keywords/patterns
        categories = {
            'government_advisory': {
                'keywords': ['cybersecurity advisory', 'security advisory', 'vulnerability notification',
                           'threat advisory', 'security alert', 'cve-', 'exploited vulnerabilities',
                           'binding operational directive', 'federal civilian executive branch',
                           'indicators of compromise', 'threat actors', 'mitigations'],
                'subject_patterns': ['advisory', 'alert', 'vulnerability', 'cve', 'exploited', 'security'],
                'metadata_signals': {'gov_domain': 10, 'cve_references': 8, 'official_content': 6}
            },
            'marketing': {
                'keywords': ['offer', 'discount', 'sale', 'promotion', 'subscribe', 'newsletter', 'limited time', 
                          'exclusive', 'deal', 'coupon', 'campaign', 'marketing', 'advertise', 'buy now',
                          'special offer', 'just for you', 'new product', 'introducing', 'announcement'],
                'subject_patterns': ['off', '%', 'sale', 'deal', 'new', 'promo', 'exclusive'],
                'metadata_signals': {'has_unsubscribe': 3, 'many_links': 2, 'image_heavy': 2}
            },
            'transactional': {
                'keywords': ['receipt', 'invoice', 'statement', 'account', 'transaction', 'purchase', 'order', 
                           'payment', 'paid', 'confirmation', 'shipped', 'tracking', 'delivered', 
                           'subscription', 'your account', 'password', 'login'],
                'subject_patterns': ['receipt', 'invoice', 'order', 'confirm', 'payment', 'shipped'],
                'metadata_signals': {'has_pdf': 3, 'sender_official': 4, 'few_links': 1}
            },
            'system_notification': {
                'keywords': ['backup', 'error', 'failed', 'success', 'completed', 'alert', 'warning', 
                           'critical', 'monitor', 'server', 'service', 'task', 'job', 'process',
                           'disk', 'cpu', 'memory', 'usage', 'threshold', 'status', 'report'],
                'subject_patterns': ['alert', 'error', 'warning', 'backup', 'monitor', 'report', 'status'],
                'metadata_signals': {'known_sender': 5, 'automated': 3, 'consistent_format': 2}
            },
            'phishing': {
                'keywords': ['verify', 'confirm', 'update', 'security', 'suspicious', 'unusual', 'login', 'account',
                          'password', 'expired', 'blocked', 'unauthorized', 'validate', 'click here', 'click link',
                          'banking', 'paypal', 'apple id', 'microsoft', 'google', 'amazon', 'ebay'],
                'subject_patterns': ['urgent', 'alert', 'warning', 'security', 'verify', 'account'],
                'metadata_signals': {'suspicious_links': 5, 'masked_links': 4, 'domain_mismatch': 5}
            },
            'notification': {
                'keywords': ['notification', 'alert', 'reminder', 'notice', 'update', 'status', 
                            'completed', 'processed', 'confirmed', 'verification', 'activity', 'changed',
                            'scheduled', 'upcoming', 'calendar', 'event', 'meeting'],
                'subject_patterns': ['notify', 'alert', 'remind', 'update'],
                'metadata_signals': {'automated_sender': 3, 'consistent_format': 2}
            },
            'personal': {
                'keywords': ['hello', 'hi', 'hey', 'thanks', 'thank you', 'appreciate', 'best regards', 
                           'sincerely', 'cheers', 'regards', 'best wishes', 'hope you', 'how are you',
                           'personal', 'private', 'confidential'],
                'subject_patterns': ['re:', 'fwd:', 'hello', 'hi', 'fyi', 'personal'],
                'metadata_signals': {'few_links': 2, 'conversational': 3, 'no_marketing': 2}
            },
            'business': {
                'keywords': ['meeting', 'agenda', 'project', 'client', 'proposal', 'contract', 'business', 
                         'report', 'quarterly', 'fiscal', 'budget', 'conference', 'deadline', 'goals',
                         'objectives', 'strategy', 'team', 'department', 'company'],
                'subject_patterns': ['meeting', 'report', 'update', 'project', 'proposal'],
                'metadata_signals': {'has_attachment': 2, 'business_sender': 3, 'formal_tone': 2}
            },
            'spam': {
                'keywords': ['viagra', 'pills', 'winner', 'lottery', 'prize', 'claim', 'millions', 'billionaire',
                          'rich', 'money', 'cash', 'investment', 'bank transfer', 'inheritance', 'prince',
                          'overseas', 'foreign', 'fund', 'confidential', 'opportunity'],
                'subject_patterns': ['congrat', 'winner', 'prize', 'urgent', 'million', 'dollar', 'free'],
                'metadata_signals': {'suspicious_origin': 4, 'poor_grammar': 3, 'excessive_punctuation': 2}
            }
        }
        
        # If government communication detected, boost government_advisory category
        if is_gov_comm and gov_confidence >= 8.0:
            categories['government_advisory']['metadata_signals']['gov_domain'] = 15
            categories['government_advisory']['metadata_signals']['cve_references'] = 10
        
        # Add bonus score for system notifications if from known sender or to known recipient
        if 'system_notification' in categories:
            if is_known_sender:
                categories['system_notification']['metadata_signals']['known_sender'] = 8
            if is_system_notification:
                categories['system_notification']['metadata_signals']['automated'] = 5
                # Add extra bonus if both sender and recipient indicate system notification
                if sender and system_notification_senders and sender.lower() in system_notification_senders:
                    categories['system_notification']['metadata_signals']['known_sender'] = 10
                if recipients and system_notification_recipients and any(r.lower() in system_notification_recipients for r in recipients):
                    categories['system_notification']['metadata_signals']['automated'] = 7
        
        # NEW: Boost business category for business context
        if business_context['is_business_context']:
            if 'business' in categories:
                categories['business']['metadata_signals']['business_context'] = int(business_context['context_confidence'] * 5)
            # Also boost marketing for business senders (legitimate business marketing)
            if 'marketing' in categories and business_context['sender_reputation'] == 'trusted_business':
                categories['marketing']['metadata_signals']['legitimate_business_marketing'] = 4
        
        # Start scoring each category
        category_scores = {}
        for category, signals in categories.items():
            # Initialize score
            score = 0
            
            # Score based on keywords
            keyword_matches = sum(1 for keyword in signals['keywords'] if keyword in combined_text)
            keyword_score = keyword_matches / len(signals['keywords']) * 10 if keyword_matches > 0 else 0
            score += keyword_score
            
            # Score based on subject patterns
            subject_lower = subject.lower()
            subject_matches = sum(1 for pattern in signals['subject_patterns'] if pattern in subject_lower)
            subject_score = subject_matches / len(signals['subject_patterns']) * 15 if subject_matches > 0 else 0
            score += subject_score
            
            # Add metadata signal scores if available
            if 'has_attachment' in signals['metadata_signals'] and has_attachments:
                score += signals['metadata_signals']['has_attachment']
                
            if 'many_links' in signals['metadata_signals'] and has_links and has_links > 3:
                score += signals['metadata_signals']['many_links']
                
            if 'few_links' in signals['metadata_signals'] and (not has_links or has_links <= 1):
                score += signals['metadata_signals']['few_links']
            
            if 'suspicious_links' in signals['metadata_signals'] and 'suspicious' in str(text).lower():
                score += signals['metadata_signals']['suspicious_links']
                
            # Additional signal: check for unsubscribe text (strong indicator of marketing)
            if 'has_unsubscribe' in signals['metadata_signals'] and 'unsubscribe' in combined_text:
                score += signals['metadata_signals']['has_unsubscribe']
                
            # Special case: if sender contains a commercial domain and category is transactional
            if sender and 'sender_official' in signals['metadata_signals']:
                commercial_domains = ['.com', '.org', '.net', '.co', '.io']
                if any(domain in sender.lower() for domain in commercial_domains):
                    score += signals['metadata_signals']['sender_official']
                    
            # Apply metadata signals for system notifications
            if category == 'system_notification':
                if 'known_sender' in signals['metadata_signals'] and is_known_sender:
                    score += signals['metadata_signals']['known_sender']
                if 'automated' in signals['metadata_signals'] and is_system_notification:
                    score += signals['metadata_signals']['automated']
                    
            # Apply metadata signals for government advisory
            if category == 'government_advisory':
                if 'gov_domain' in signals['metadata_signals'] and is_gov_comm:
                    score += signals['metadata_signals']['gov_domain']
                if 'cve_references' in signals['metadata_signals'] and 'cve-' in combined_text:
                    score += signals['metadata_signals']['cve_references']
                if 'official_content' in signals['metadata_signals'] and ('govdelivery' in combined_text or 'official website' in combined_text):
                    score += signals['metadata_signals']['official_content']
                    
            # NEW: Apply business context signals
            if 'business_context' in signals['metadata_signals'] and business_context['is_business_context']:
                score += signals['metadata_signals']['business_context']
            if 'legitimate_business_marketing' in signals['metadata_signals']:
                score += signals['metadata_signals']['legitimate_business_marketing']
                    
            # Penalize score for obvious category mismatches
            # Example: if looks like marketing but claims to be personal
            if category == 'personal' and 'unsubscribe' in combined_text:
                score -= 5
                
            if category == 'transactional' and 'discount' in combined_text and 'coupon' in combined_text:
                score -= 3
                
            category_scores[category] = max(0, score)  # Ensure no negative scores
            
        # Get the top categories based on score
        sorted_categories = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        
        # If no significant scores, mark as 'general'
        if not sorted_categories or sorted_categories[0][1] < 3:
            primary_category = 'general'
            confidence = 1.0
        else:
            primary_category = sorted_categories[0][0]
            
            # Calculate confidence (0-10 scale)
            top_score = sorted_categories[0][1]
            
            # If we have a second place category, use the gap to determine confidence
            if len(sorted_categories) > 1 and sorted_categories[1][1] > 0:
                second_score = sorted_categories[1][1]
                score_gap = top_score - second_score
                
                # Higher gap = higher confidence
                confidence = min(10, (score_gap / second_score * 7) + 3) if second_score > 0 else 10
            else:
                confidence = min(10, top_score)
                
        # Get top 3 categories with scores
        top_three = sorted_categories[:3] if len(sorted_categories) >= 3 else sorted_categories
        
        safe_log(f"Classification: {primary_category} (confidence: {confidence:.1f})")
        if is_gov_comm:
            safe_log(f"Government communication context applied")
        if business_context['is_business_context']:
            safe_log(f"Business context detected (confidence: {business_context['context_confidence']:.2f})")
        
        return {
            "primary_category": primary_category,
            "confidence": confidence,
            "top_categories": top_three,
            "all_scores": category_scores
        }
    except Exception as e:
        safe_log(f"Enhanced email classification error: {e}", "ERROR")
        return {
            "primary_category": 'general',
            "confidence": 1.0,
            "top_categories": [('general', 1.0)],
            "all_scores": {}
        }


def extract_topics(text, subject, num_topics=5):
    """Extract key topics from the email content"""
    try:
        # Early return for very short texts
        if len(text.split()) < 10:
            return []
        
        # Combine subject and text with subject given more weight
        combined_text = subject + " " + subject + " " + text
        
        try:
            # Tokenize and clean
            words = combined_text.lower().split()
            
            # Fallback stopword list (since we can't import NLTK in this module)
            stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'if', 'because', 'as', 'what', 
                         'while', 'of', 'to', 'in', 'for', 'with', 'about', 'against', 'between',
                         'into', 'through', 'during', 'before', 'after', 'above', 'below', 'from',
                         'up', 'down', 'on', 'off', 'over', 'under', 'again', 'further', 'then',
                         'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any',
                         'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no',
                         'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'can',
                         'will', 'just', 'should', 'now'}
            
            # Manual filtering of words
            filtered_words = [word for word in words if word.isalnum() and word not in stop_words and len(word) > 2]
            
            # Count word frequencies
            word_counts = {}
            for word in filtered_words:
                word_counts[word] = word_counts.get(word, 0) + 1
            
            # Sort by frequency
            sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
            
            # Get top N topics
            topics = [word for word, count in sorted_words[:num_topics]]
            
            return topics
        except Exception as e:
            safe_log(f"Topic extraction text processing error: {e}", "ERROR")
            return []
    except Exception as e:
        safe_log(f"Topic extraction error: {e}", "ERROR")
        return []


def summarize_content(text, max_sentences=3):
    """Create an extractive summary of the email content"""
    try:
        # For very short texts, just return the full text
        if len(text) < 200:
            return text
        
        try:
            # Split into sentences - simple approach
            sentences = re.split(r'(?<=[.!?])\s+', text)
        except:
            # Even simpler fallback
            sentences = text.split('. ')
        
        # If we only have a few sentences, return them all
        if len(sentences) <= max_sentences:
            return text
        
        # Simple approach - take first sentence, last sentence, and one from the middle
        summary_sentences = [sentences[0]]
        
        if len(sentences) > 2:
            middle_idx = len(sentences) // 2
            summary_sentences.append(sentences[middle_idx])
            
        if len(sentences) > 1:
            summary_sentences.append(sentences[-1])
            
        # If we still need more sentences, add from the beginning
        while len(summary_sentences) < max_sentences and len(summary_sentences) < len(sentences):
            idx = len(summary_sentences)
            if idx < len(sentences):
                summary_sentences.append(sentences[idx])
        
        # Create summary
        summary = ' '.join(summary_sentences)
        
        return summary
    except Exception as e:
        safe_log(f"Summarization error: {e}", "ERROR")
        return text[:200] + "..." if len(text) > 200 else text


def extract_and_analyze_links(text):
    """Extract and analyze URLs in the email content"""
    try:
        url_regex = r'https?://[^\s\)"]+'
        urls = re.findall(url_regex, text)
        suspicious_links = []
        bad_tlds = {'.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.icu', '.loan', '.buzz'}
        tracking_keywords = {'utm_', 'trackid', 'ref=', 'redirect', 'click', 'track=', 'tracking='}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                tld = '.' + parsed.netloc.split('.')[-1].lower() if parsed.netloc and '.' in parsed.netloc else ''
                
                # Check for suspicious TLDs
                if tld in bad_tlds:
                    suspicious_links.append(f"{url} (suspicious TLD)")
                    
                # Check for tracking parameters
                elif parsed.query and any(k in parsed.query.lower() for k in tracking_keywords):
                    suspicious_links.append(f"{url} (tracking params)")
                    
                # Check for excessively long domains
                elif len(parsed.netloc) > 40:
                    suspicious_links.append(f"{url} (long domain)")
                    
                # Check for numeric-heavy domains
                elif sum(c.isdigit() for c in parsed.netloc) > len(parsed.netloc) * 0.3:
                    suspicious_links.append(f"{url} (numeric domain)")
            except:
                # If URL parsing fails, consider it suspicious
                suspicious_links.append(f"{url} (malformed URL)")
                
        return urls, suspicious_links
    except Exception as e:
        safe_log(f"Link analysis error: {e}", "ERROR")
        return [], []


def call_spacy_api(text_content):
    """Call the spaCy API for entity recognition"""
    try:
        response = requests.post("http://127.0.0.1:5000/analyze", json={"text": text_content})
        entities = response.json().get("entities", [])
        return entities
    except Exception as e:
        safe_log(f"SpaCy API error: {e}", "ERROR")
        return []


def check_known_sender(sender_address, known_senders=None):
    """
    Check if the sender is from a known legitimate source
    
    Returns:
        bool: True if sender is known and legitimate
    """
    if not sender_address or not known_senders:
        return False
    
    sender_lower = sender_address.lower()
    sender_domain = sender_lower.split('@')[-1]
    
    # Check exact domain match
    if sender_domain in known_senders:
        return True
    
    # Check subdomain matches (e.g., alerts.datto.com matches datto.com)
    for known_domain in known_senders.keys():
        if sender_domain.endswith('.' + known_domain) or sender_domain == known_domain:
            return True
            
    return False


def is_system_notification_content(text, subject, recipients=None, sender=None,
                                 system_notification_senders=None, 
                                 system_notification_recipients=None,
                                 system_notification_patterns=None):
    """
    Check if the content matches system notification patterns
    OR if it's sent to a system notification recipient
    OR if it's from a system notification sender
    """
    # Check if from a system notification sender
    if sender and system_notification_senders and sender.lower() in system_notification_senders:
        return True
        
    # Check if sent to a system notification recipient
    if recipients and system_notification_recipients:
        for recipient in recipients:
            if recipient.lower() in system_notification_recipients:
                return True
    
    # Then check content patterns
    if system_notification_patterns:
        combined_text = (subject + ' ' + text).lower()
        
        for primary_keyword, secondary_keywords in system_notification_patterns:
            if primary_keyword in combined_text:
                for secondary in secondary_keywords:
                    if secondary in combined_text:
                        return True
    return False


def extract_text_from_html(html_content):
    """Extract plain text from HTML content"""
    try:
        # Simple HTML tag removal - could be improved with a proper HTML parser
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    except Exception as e:
        safe_log(f"HTML extraction error: {e}", "ERROR")
        return ""
