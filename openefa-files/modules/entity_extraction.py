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
    """Generate an intelligent multi-sentence summary from email text using spaCy LARGE model"""
    try:
        if not text or len(text.strip()) < 20:
            return ""

        # Calculate word count to determine summary strategy
        word_count = len(text.split())

        # Use spaCy for better sentence segmentation with large model
        model = load_spacy_model()
        if not model:
            # Fallback: use first 200 characters of text
            return text.strip()[:200]

        # Process more text for longer emails (up to 50,000 chars for 4000+ word emails)
        text_limit = min(len(text), 50000)
        doc = model(text[:text_limit])
        sentences = [sent.text.strip() for sent in doc.sents]

        # Filter out greetings, signatures, and low-value sentences
        skip_starts = ['dear', 'hi', 'hello', 'thanks', 'thank you', 'best regards',
                       'sincerely', 'regards', 'cheers', 'yours', 'kind regards',
                       'from:', 'to:', 'sent:', 'subject:', 'date:']
        skip_ends = ['regards', 'thanks', 'thank you', 'sincerely', 'cheers']
        skip_contains = ['unsubscribe', 'click here', 'view in browser', 'privacy policy']

        meaningful_sentences = []
        for sent in sentences:
            sent_lower = sent.lower()
            # Skip short, greeting, signature, and boilerplate sentences
            if (len(sent) > 30 and
                not any(sent_lower.startswith(start) for start in skip_starts) and
                not any(sent_lower.endswith(end) for end in skip_ends) and
                not any(skip in sent_lower for skip in skip_contains) and
                not re.match(r'^[a-zA-Z\s]{1,15}$', sent)):
                meaningful_sentences.append(sent)

        # If no meaningful sentences found, fallback to first 200 chars
        if not meaningful_sentences:
            return text.strip()[:200]

        # Determine number of sentences to include based on email length
        if word_count < 100:
            # Short emails (< 100 words): 1 sentence
            num_sentences = 1
        elif word_count < 400:
            # Medium emails (100-400 words): 2 sentences
            num_sentences = 2
        elif word_count < 1000:
            # Long emails (400-1000 words): 3 sentences
            num_sentences = 3
        else:
            # Very long emails (1000+ words): 4-5 sentences
            num_sentences = min(5, max(4, word_count // 800))

        # Score sentences based on importance indicators
        scored_sentences = []
        for sent in meaningful_sentences[:50]:  # Limit to first 50 meaningful sentences
            score = 0
            sent_doc = model(sent)

            # Higher score for sentences with more named entities
            entities = [ent for ent in sent_doc.ents]
            score += len(entities) * 2

            # Higher score for sentences with key nouns and verbs
            nouns = [token for token in sent_doc if token.pos_ in ['NOUN', 'PROPN']]
            verbs = [token for token in sent_doc if token.pos_ == 'VERB']
            score += len(nouns) + len(verbs)

            # Higher score for sentences with numbers/dates/money (often important facts)
            if any(ent.label_ in ['MONEY', 'DATE', 'TIME', 'CARDINAL', 'PERCENT'] for ent in entities):
                score += 5

            # Bonus for first few sentences (often most important)
            position = meaningful_sentences.index(sent)
            if position < 3:
                score += (3 - position) * 3

            # Penalize very long sentences (harder to read in summary)
            if len(sent) > 200:
                score -= 2

            scored_sentences.append((sent, score))

        # Sort by score and take top N sentences
        scored_sentences.sort(key=lambda x: x[1], reverse=True)
        top_sentences = scored_sentences[:num_sentences]

        # Re-order selected sentences by their original appearance order for coherence
        top_sentences.sort(key=lambda x: meaningful_sentences.index(x[0]))

        # Build summary
        summary_parts = []

        # Optionally include cleaned subject as context for very long emails
        if subject and len(subject.strip()) > 5 and word_count >= 400:
            clean_subject = re.sub(r'^(re:|fwd:|fw:)\s*', '', subject.strip(), flags=re.IGNORECASE)
            if len(clean_subject) > 5:
                summary_parts.append(f"Subject: {clean_subject}")

        # Add selected sentences
        for sent, score in top_sentences:
            summary_parts.append(sent)

        # Join and limit total length
        summary = ' '.join(summary_parts)

        # Limit summary length based on email size
        if word_count < 400:
            max_summary_len = 300
        elif word_count < 1000:
            max_summary_len = 500
        else:
            max_summary_len = 750

        if len(summary) > max_summary_len:
            # Try to cut at sentence boundary
            summary = summary[:max_summary_len]
            last_period = summary.rfind('.')
            if last_period > max_summary_len * 0.8:  # If we can find period in last 20%
                summary = summary[:last_period + 1]
            else:
                summary = summary + '...'

        return summary

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
