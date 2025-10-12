#!/usr/bin/env python3
"""
Compliance and Legal Entity Extraction Module
Extracts specialized entities for compliance tracking and debt monitoring
"""

import re
import json
from typing import List, Dict, Any

def extract_legal_entities(text: str) -> Dict[str, List[str]]:
    """Extract legal and compliance-specific entities"""
    entities = {
        'case_numbers': [],
        'court_dates': [],
        'legal_deadlines': [],
        'law_firms': [],
        'attorneys': [],
        'legal_documents': [],
        'court_names': []
    }
    
    # Case number patterns - balanced between avoiding false positives and catching real cases
    case_patterns = [
        r'\b(?:Case|Docket|Matter|File)\s*(?:#|No\.?|number)?\s*[:.]?\s*([A-Z0-9]{2,}[\-][A-Z0-9]{2,}[\-]?[A-Z0-9]*)',  # Hyphenated format
        r'\b(?:Case|Docket|Matter)\s*(?:#|No\.?|number)?\s*[:.]?\s*([0-9]{4,})',  # Simple number format
        r'\b([0-9]{4}[-\s]?[A-Z]{2,3}[-\s]?[0-9]{4,6})\b',  # 2024-CV-12345 format
    ]
    
    for pattern in case_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        # Filter to ensure it has numbers
        for m in matches:
            if any(c.isdigit() for c in m) and len(str(m)) >= 4:
                entities['case_numbers'].append(m)
    
    # Legal document types
    doc_types = [
        'summons', 'complaint', 'motion', 'brief', 'order', 
        'judgment', 'subpoena', 'notice', 'petition', 'warrant',
        'affidavit', 'deposition', 'discovery', 'interrogatories'
    ]
    for doc in doc_types:
        if doc.lower() in text.lower():
            entities['legal_documents'].append(doc.capitalize())
    
    # Court names
    court_patterns = [
        r'((?:Supreme|Superior|District|Circuit|Municipal|Federal|State)\s+Court)',
        r'(Court\s+of\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
        r'([\w\s]+\s+County\s+Court)'
    ]
    
    for pattern in court_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities['court_names'].extend(matches)
    
    # Attorney patterns (Esq., Attorney at Law, etc.)
    attorney_patterns = [
        r'([A-Z][a-z]+(?:\s+[A-Z]\.?\s*)?[A-Z][a-z]+),?\s+Esq\.?',
        r'Attorney\s+([A-Z][a-z]+\s+[A-Z][a-z]+)',
        r'([A-Z][a-z]+\s+[A-Z][a-z]+),?\s+Attorney\s+at\s+Law'
    ]
    
    for pattern in attorney_patterns:
        matches = re.findall(pattern, text)
        entities['attorneys'].extend(matches)
    
    # Legal deadline indicators
    deadline_patterns = [
        r'(?:due|deadline|must\s+(?:be\s+)?(?:filed|submitted|responded?)|response\s+required)\s+(?:by\s+|on\s+|before\s+)?([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
        r'(?:within|in)\s+(\d+)\s+(?:days?|weeks?|months?)',
        r'(?:no\s+later\s+than|NLT)\s+([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})'
    ]
    
    for pattern in deadline_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities['legal_deadlines'].extend(matches)
    
    # Remove duplicates
    for key in entities:
        entities[key] = list(set(entities[key]))
    
    return entities

def extract_financial_entities(text: str) -> Dict[str, List[Any]]:
    """Extract financial and debt-related entities"""
    entities = {
        'amounts': [],
        'invoice_numbers': [],
        'account_numbers': [],
        'payment_terms': [],
        'payment_status': [],
        'interest_rates': []
    }
    
    # Money amounts (more comprehensive)
    money_patterns = [
        r'\$[\d,]+\.?\d*(?:\s*(?:million|billion|thousand|k|m|b))?',
        r'USD\s*[\d,]+\.?\d*',
        r'[\d,]+\.?\d*\s*(?:dollars?|cents?)',
        r'(?:amount|balance|payment|total)(?:\s*:?\s*of?)?\s*\$?[\d,]+\.?\d*'
    ]
    
    for pattern in money_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities['amounts'].extend(matches)
    
    # Invoice/Account numbers - balanced patterns
    invoice_patterns = [
        r'(?:Invoice|Inv\.?|Bill)\s*(?:#|No\.?|number)?\s*[:.]?\s*([A-Z0-9\-]+)',
        r'(?:Account|Acct\.?)\s*(?:#|No\.?|number)?\s*[:.]?\s*([A-Z0-9\-]+)',
        r'(?:Reference|Ref\.?)\s*(?:#|No\.?|number)?\s*[:.]?\s*([A-Z0-9\-]+)',
        r'(?:PO|Purchase\s*Order)\s*(?:#|No\.?|number)?\s*[:.]?\s*([A-Z0-9\-]+)'
    ]
    
    for pattern in invoice_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        # Filter to ensure it has numbers and isn't just a word
        for m in matches:
            # Must have at least one digit and be at least 3 chars
            if any(c.isdigit() for c in m) and len(m) >= 3 and not m.isalpha():
                entities['invoice_numbers'].append(m)
    
    # Payment terms
    terms_patterns = [
        r'(?:Net|NET)\s*(\d+)',
        r'(?:Due\s+(?:on|upon)\s+receipt)',
        r'(\d+)\s*(?:days?|months?)\s*(?:payment\s*)?terms?',
        r'(?:COD|C\.O\.D\.)',
        r'(?:payment\s+due|due\s+date)(?:\s*:?\s*)([A-Za-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4})'
    ]
    
    for pattern in terms_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            entities['payment_terms'].extend(matches if isinstance(matches[0], str) else [m[0] if isinstance(m, tuple) else m for m in matches])
    
    # Payment status keywords
    status_keywords = ['paid', 'unpaid', 'overdue', 'past due', 'delinquent', 'outstanding', 'settled', 'pending']
    for keyword in status_keywords:
        if keyword in text.lower():
            entities['payment_status'].append(keyword)
    
    # Interest rates
    interest_patterns = [
        r'(\d+\.?\d*)\s*%\s*(?:interest|APR|rate)',
        r'(?:interest|rate)\s*(?:of\s+)?(\d+\.?\d*)\s*%'
    ]
    
    for pattern in interest_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        entities['interest_rates'].extend(matches)
    
    # Remove duplicates
    for key in entities:
        entities[key] = list(set(entities[key]))
    
    return entities

def extract_compliance_keywords(text: str) -> Dict[str, List[str]]:
    """Extract compliance-related keywords and phrases"""
    
    compliance_terms = {
        'regulatory': ['compliance', 'regulation', 'regulatory', 'audit', 'inspection', 'violation', 'penalty', 'fine'],
        'risk': ['risk', 'liability', 'exposure', 'breach', 'incident', 'non-compliance'],
        'action_required': ['must', 'shall', 'required', 'mandatory', 'obligation', 'immediately', 'urgent'],
        'legal_process': ['litigation', 'lawsuit', 'claim', 'dispute', 'arbitration', 'mediation', 'settlement'],
        'deadlines': ['deadline', 'due date', 'expiry', 'expiration', 'time limit', 'statute of limitations']
    }
    
    found_keywords = {}
    text_lower = text.lower()
    
    for category, keywords in compliance_terms.items():
        found = [kw for kw in keywords if kw in text_lower]
        if found:
            found_keywords[category] = found
    
    return found_keywords

def analyze_compliance_content(text: str, subject: str = "") -> Dict[str, Any]:
    """Complete compliance analysis combining all extraction methods"""
    try:
        legal_entities = extract_legal_entities(text)
        financial_entities = extract_financial_entities(text)
        compliance_keywords = extract_compliance_keywords(text)
        
        # Determine compliance risk level based on findings
        risk_score = 0
        if legal_entities.get('legal_deadlines'):
            risk_score += 30
        if legal_entities.get('court_dates'):
            risk_score += 25
        if financial_entities.get('payment_status') and 'overdue' in financial_entities['payment_status']:
            risk_score += 20
        if compliance_keywords.get('action_required'):
            risk_score += 15
        if compliance_keywords.get('regulatory'):
            risk_score += 10
        
        risk_level = 'low'
        if risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 25:
            risk_level = 'medium'
        
        return {
            'legal_entities': legal_entities,
            'financial_entities': financial_entities,
            'compliance_keywords': compliance_keywords,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'requires_attention': risk_score >= 25
        }
    except Exception as e:
        print(f"Compliance analysis error: {e}")
        return {
            'legal_entities': {},
            'financial_entities': {},
            'compliance_keywords': {},
            'risk_score': 0,
            'risk_level': 'unknown',
            'requires_attention': False
        }

# Module registration function for dynamic loading
def get_module_functions():
    """Return available functions for module loader"""
    return {
        'analyze_compliance_content': analyze_compliance_content,
        'extract_legal_entities': extract_legal_entities,
        'extract_financial_entities': extract_financial_entities
    }

# Test function
if __name__ == "__main__":
    test_text = """
    RE: Case #2024-CV-12345 - Smith vs. Johnson
    
    Dear Mr. Johnson,
    
    This is to notify you that the motion hearing is scheduled for September 15, 2024 at 2:00 PM 
    in Superior Court of California. Attorney Robert Smith, Esq. will be representing the plaintiff.
    
    Please note the following deadlines:
    - Discovery responses due by August 30, 2024
    - Reply brief must be filed within 10 days
    
    The outstanding balance of $45,000 on Invoice #INV-2024-789 remains unpaid and is now 
    60 days past due. Interest accrues at 1.5% per month.
    
    Payment terms: Net 30
    Account #: ACC-456789
    
    Failure to comply may result in litigation.
    
    Sincerely,
    Law Offices of Smith & Associates
    """
    
    print("Testing compliance extraction...")
    results = analyze_compliance_content(test_text)
    print(json.dumps(results, indent=2))