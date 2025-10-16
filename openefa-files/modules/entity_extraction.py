#!/usr/bin/env python3
"""
Entity Extraction Module for Email Analysis
Extracts named entities and content summaries from email text
"""

import spacy
import json
import re
from pathlib import Path

# Global spaCy model
nlp = None

def load_spacy_model():
    """Load spaCy LARGE model with error handling"""
    global nlp
    if nlp is not None:
        return nlp
    
    try:
        nlp = spacy.load('en_core_web_lg')
        return nlp
    except OSError as e:
        print(f"Error loading spaCy LARGE model, trying small model: {e}")
        try:
            nlp = spacy.load('en_core_web_sm')
            return nlp
        except OSError as e2:
            print(f"Error loading any spaCy model: {e2}")
            return None

def extract_phone_numbers(text):
    """Extract phone numbers using regex patterns"""
    phone_patterns = [
        # US phone formats
        r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',  # (123) 456-7890, 123-456-7890, etc.
        r'\b\d{3}\.\d{3}\.\d{4}\b',  # 123.456.7890
        r'\b\d{3}\s\d{3}\s\d{4}\b',  # 123 456 7890
        r'\b\+1\s?\d{10}\b',  # +1 1234567890
        r'\b\d{10}\b',  # 1234567890
        # International formats
        r'\b\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b',
    ]
    
    phone_numbers = []
    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Clean up the match
            clean_match = match.strip()
            # Avoid duplicates and very short numbers
            if len(clean_match) >= 10 and clean_match not in [p.split(' (')[0] for p in phone_numbers]:
                phone_numbers.append(f"{clean_match} (PHONE)")
    
    return phone_numbers

def extract_email_addresses(text):
    """Extract email addresses using regex"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    
    email_entities = []
    for email in emails:
        # Filter out common non-email patterns
        if email and not email.startswith('@') and not email.endswith('@'):
            email_entities.append(f"{email} (EMAIL)")
    
    return email_entities

def extract_entities(text):
    """Extract named entities from text using spaCy LARGE model plus custom extractors"""
    try:
        model = load_spacy_model()
        if not model or not text:
            return []
        
        # With the large model, we can process more text efficiently
        text_limited = text[:10000] if len(text) > 10000 else text
        
        # Process with spaCy
        doc = model(text_limited)
        
        entities = []
        for ent in doc.ents:
            # The large model is better at entity recognition, so we can be more selective
            entity_text = ent.text.strip()
            entity_label = ent.label_
            
            # Filter out very short entities, common words, and low-confidence entities
            skip_words = ['re', 'fwd', 'the', 'and', 'or', 'but', 'so']
            if (len(entity_text) > 1 and 
                entity_text.lower() not in skip_words and
                not entity_text.isdigit() and
                len(entity_text) < 100):  # Avoid very long entities
                
                entities.append(f"{entity_text} ({entity_label})")
        
        # Add phone numbers
        phone_numbers = extract_phone_numbers(text_limited)
        entities.extend(phone_numbers)
        
        # Add email addresses
        email_addresses = extract_email_addresses(text_limited)
        entities.extend(email_addresses)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_entities = []
        for entity in entities:
            if entity not in seen:
                seen.add(entity)
                unique_entities.append(entity)
        
        return unique_entities[:40]  # Increased limit to accommodate phone/email entities
        
    except Exception as e:
        print(f"Entity extraction error: {e}")
        return []

def extract_topics(text, subject=""):
    """Extract topics/themes from email content"""
    try:
        if not text:
            return []
        
        text_lower = text.lower()
        subject_lower = subject.lower()
        combined_text = f"{subject_lower} {text_lower}"
        
        # Define topic keywords
        topic_keywords = {
            'payment': ['payment', 'invoice', 'bill', 'charge', 'fee', 'cost', 'price', 'amount'],
            'meeting': ['meeting', 'conference', 'call', 'appointment', 'schedule', 'agenda'],
            'project': ['project', 'task', 'deadline', 'milestone', 'deliverable', 'progress'],
            'legal': ['contract', 'agreement', 'legal', 'law', 'court', 'attorney', 'lawyer'],
            'support': ['help', 'support', 'assistance', 'question', 'issue', 'problem'],
            'marketing': ['promotion', 'offer', 'sale', 'discount', 'deal', 'campaign'],
            'technical': ['server', 'system', 'error', 'backup', 'update', 'maintenance'],
            'security': ['security', 'password', 'login', 'verify', 'confirm', 'access'],
            'notification': ['notification', 'alert', 'reminder', 'notice', 'update'],
            'business': ['business', 'company', 'client', 'customer', 'service', 'proposal']
        }
        
        detected_topics = []
        for topic, keywords in topic_keywords.items():
            matches = sum(1 for keyword in keywords if keyword in combined_text)
            if matches >= 1:  # At least one keyword match
                detected_topics.append(topic)
        
        return detected_topics[:10]  # Limit to 10 topics
        
    except Exception as e:
        print(f"Topic extraction error: {e}")
        return []

def generate_content_summary(text, subject=""):
    """Generate a content summary from email text using spaCy LARGE model"""
    try:
        if not text or len(text.strip()) < 20:
            return ""
        
        # If subject is meaningful, use it
        if subject and len(subject.strip()) > 5:
            # Clean up subject (remove Re:, Fwd:, etc.)
            clean_subject = re.sub(r'^(re:|fwd:|fw:)\s*', '', subject.strip(), flags=re.IGNORECASE)
            if len(clean_subject) > 5:
                return clean_subject[:200]
        
        # Use spaCy for better sentence segmentation with large model
        model = load_spacy_model()
        if model:
            doc = model(text[:2000])  # Limit for summary generation
            sentences = [sent.text.strip() for sent in doc.sents]
        else:
            # Fallback to regex
            sentences = re.split(r'[.!?]+', text)
        
        # Find the most meaningful sentence
        for sentence in sentences:
            sentence = sentence.strip()
            # Skip very short sentences, greetings, and signatures
            skip_starts = ['dear', 'hi', 'hello', 'thanks', 'thank you', 'best regards', 'sincerely']
            skip_ends = ['regards', 'thanks', 'thank you']
            
            if (len(sentence) > 30 and 
                not any(sentence.lower().startswith(start) for start in skip_starts) and
                not re.match(r'^[a-zA-Z\s]{1,15}$', sentence) and
                not any(sentence.lower().endswith(end) for end in skip_ends)):
                return sentence[:250]  # Longer summaries with large model
        
        # Fallback: use first 200 characters of text
        return text.strip()[:200]
        
    except Exception as e:
        print(f"Content summary error: {e}")
        return ""

def analyze_email_content(text, subject="", sender=""):
    """Complete content analysis combining entities, topics, and summary"""
    try:
        return {
            'entities': extract_entities(text),
            'topics': extract_topics(text, subject),
            'content_summary': generate_content_summary(text, subject),
            'word_count': len(text.split()) if text else 0,
            'char_count': len(text) if text else 0
        }
    except Exception as e:
        print(f"Email content analysis error: {e}")
        return {
            'entities': [],
            'topics': [],
            'content_summary': "",
            'word_count': 0,
            'char_count': 0
        }

# Test function
if __name__ == "__main__":
    test_text = """
    RE: Invoice for Legal Services
    
    Dear Client,
    
    Thank you for your payment of $500.00 for legal services provided by R.D. Johnson Law Offices.
    Please contact us at lawyer@example.com or call (555) 123-4567 if you have any questions.
    
    This invoice covers services provided on June 15, 2025 for contract review.
    
    Best regards,
    Robert D. Johnson
    R.D. Johnson Law Offices, LLC
    """
    
    print("Testing entity extraction...")
    entities = extract_entities(test_text)
    print(f"Entities: {entities}")
    
    print("\nTesting topic extraction...")
    topics = extract_topics(test_text, "RE: Invoice for Legal Services")
    print(f"Topics: {topics}")
    
    print("\nTesting content summary...")
    summary = generate_content_summary(test_text, "RE: Invoice for Legal Services")
    print(f"Summary: {summary}")
    
    print("\nTesting full analysis...")
    full_analysis = analyze_email_content(test_text, "RE: Invoice for Legal Services", "lawyer@example.com")
    print(f"Full analysis: {json.dumps(full_analysis, indent=2)}")
