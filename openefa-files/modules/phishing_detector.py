#!/usr/bin/env python3
"""
Phishing Detection Module for SpaCy Email Filter
Detects common phishing patterns including document sharing scams,
fake invoices, and credential harvesting attempts.
"""

import re
from typing import Dict, List, Optional
from email.message import EmailMessage
import logging

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        # Document sharing phishing patterns
        self.doc_share_patterns = [
            r"document.{0,20}shared.{0,20}with.{0,20}you",
            r"shared.{0,20}document.{0,20}with.{0,20}you",
            r"document.{0,20}ready.{0,20}for.{0,20}review",
            r"review.{0,20}document",
            r"agreement.{0,20}ready.{0,20}for.{0,20}review",
            r"contract.{0,20}ready.{0,20}for.{0,20}signature",
            r"invoice.{0,20}ready.{0,20}for.{0,20}review",
            r"file.{0,20}shared.{0,20}via",
            r"shared.{0,20}folder",
            r"click.{0,20}to.{0,20}view.{0,20}document",
            r"view.{0,20}shared.{0,20}file",
            r"download.{0,20}your.{0,20}document",
            r"access.{0,20}your.{0,20}file",
            r"secure.{0,20}document.{0,20}transfer"
        ]
        
        # Vague business proposal patterns
        self.vague_proposal_patterns = [
            r"business.{0,20}proposal",
            r"proposal.{0,20}for.{0,20}you",
            r"have.{0,20}proposal",
            r"regarding.{0,20}(?:the.{0,20})?proposal",
            r"investment.{0,20}opportunity",
            r"profitable.{0,20}venture",
            r"mutual.{0,20}benefit",
            r"partnership.{0,20}opportunity",
            r"previous.{0,20}email",
            r"(?:this.{0,20}is.{0,20})?(?:my.{0,20})?second.{0,20}email",
            r"reply.{0,20}to.{0,20}this.{0,20}email.{0,20}only",
            r"for.{0,20}more.{0,20}information"
        ]
        
        # Urgency patterns often combined with phishing
        self.urgency_patterns = [
            r"sign.{0,20}as.{0,20}soon.{0,20}as.{0,20}possible",
            r"immediate.{0,20}action.{0,20}required",
            r"urgent.{0,20}response.{0,20}needed",
            r"expires.{0,20}in.{0,20}\d+.{0,20}(hours?|days?)",
            r"action.{0,20}required.{0,20}within",
            r"deadline.{0,20}approaching"
        ]
        
        # Credential harvesting indicators
        self.credential_patterns = [
            r"verify.{0,20}your.{0,20}(account|identity|credentials)",
            r"confirm.{0,20}your.{0,20}(password|identity|account)",
            r"update.{0,20}your.{0,20}(password|security|account)",
            r"suspended.{0,20}account",
            r"locked.{0,20}account",
            r"click.{0,20}here.{0,20}to.{0,20}(verify|confirm|update)",
            r"validate.{0,20}your.{0,20}credentials"
        ]
        
        # Suspicious link text patterns
        self.link_text_patterns = [
            r"review document",
            r"view document",
            r"download file",
            r"access file",
            r"click here",
            r"verify now",
            r"confirm identity",
            r"secure link"
        ]
        
        # Known phishing service domains (often compromised or abused)
        self.suspicious_service_domains = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
            "rebrand.ly", "branch.io", "app.link", "smart.link"
        ]
        
        # Casino/gambling domains sending "business" emails
        self.inappropriate_sender_domains = [
            "fallsview.com", "casino", "gaming", "lottery", "betting",
            "gambling", "poker", "slots", "jackpot", "vegas"
        ]

    def analyze(self, msg: EmailMessage, text_content: str, from_header: str) -> Dict:
        """Analyze email for phishing indicators"""
        results = {
            'detected': False,
            'confidence': 0.0,
            'phishing_type': 'none',
            'indicators': [],
            'risk_score': 0.0,
            'headers_to_add': {}
        }
        
        try:
            # Convert text to lowercase for pattern matching
            text_lower = text_content.lower() if text_content else ""
            subject = self._get_header(msg, 'Subject', '').lower()
            from_lower = from_header.lower() if from_header else ""
            
            # Check for document sharing phishing
            doc_share_score = self._check_document_sharing(text_lower, subject)
            if doc_share_score > 0:
                results['indicators'].append(f"document_sharing_scam:{doc_share_score:.1f}")
                results['risk_score'] += doc_share_score
            
            # Check for vague business proposals
            vague_score = self._check_vague_proposals(text_lower, subject)
            if vague_score > 0:
                results['indicators'].append(f"vague_proposal:{vague_score:.1f}")
                results['risk_score'] += vague_score
            
            # Check for urgency combined with requests
            urgency_score = self._check_urgency_patterns(text_lower)
            if urgency_score > 0:
                results['indicators'].append(f"urgency_pressure:{urgency_score:.1f}")
                results['risk_score'] += urgency_score
            
            # Check for credential harvesting
            cred_score = self._check_credential_harvesting(text_lower, subject)
            if cred_score > 0:
                results['indicators'].append(f"credential_harvesting:{cred_score:.1f}")
                results['risk_score'] += cred_score
            
            # Check sender domain appropriateness
            domain_score = self._check_sender_domain(from_lower, subject, text_lower)
            if domain_score > 0:
                results['indicators'].append(f"inappropriate_sender:{domain_score:.1f}")
                results['risk_score'] += domain_score
            
            # Check for sender/content mismatch
            mismatch_score = self._check_sender_content_mismatch(msg, from_header, subject, text_lower)
            if mismatch_score > 0:
                results['indicators'].append(f"sender_content_mismatch:{mismatch_score:.1f}")
                results['risk_score'] += mismatch_score
            
            # Determine phishing type and confidence
            if results['risk_score'] >= 8.0:
                results['detected'] = True
                results['confidence'] = min(0.95, results['risk_score'] / 10)
                results['phishing_type'] = self._determine_phishing_type(results['indicators'])
            elif results['risk_score'] >= 5.0:
                results['detected'] = True
                results['confidence'] = min(0.75, results['risk_score'] / 10)
                results['phishing_type'] = self._determine_phishing_type(results['indicators'])
            elif results['risk_score'] >= 3.0:
                results['detected'] = True
                results['confidence'] = min(0.50, results['risk_score'] / 10)
                results['phishing_type'] = 'suspicious'
            
            # Add headers for SpamAssassin
            if results['detected']:
                results['headers_to_add']['X-Phishing-Detected'] = 'true'
                results['headers_to_add']['X-Phishing-Type'] = results['phishing_type']
                results['headers_to_add']['X-Phishing-Score'] = str(results['risk_score'])
                results['headers_to_add']['X-Phishing-Confidence'] = f"{results['confidence']:.3f}"
                if results['indicators']:
                    results['headers_to_add']['X-Phishing-Indicators'] = ','.join(results['indicators'][:3])
            
        except Exception as e:
            logger.error(f"Phishing detection error: {e}")
        
        return results
    
    def _check_document_sharing(self, text_lower: str, subject: str) -> float:
        """Check for document sharing phishing patterns"""
        score = 0.0
        matches = 0
        
        combined_text = f"{subject} {text_lower[:2000]}"
        
        for pattern in self.doc_share_patterns:
            if re.search(pattern, combined_text):
                matches += 1
                score += 2.5
        
        # High confidence if multiple patterns match
        if matches >= 3:
            score += 3.0
        
        # Check for suspicious button/link text
        for link_pattern in self.link_text_patterns:
            if re.search(link_pattern, text_lower):
                score += 1.5
        
        return min(score, 8.0)
    
    def _check_vague_proposals(self, text_lower: str, subject: str) -> float:
        """Check for vague business proposal patterns"""
        score = 0.0
        matches = 0
        
        combined_text = f"{subject} {text_lower[:2000]}"
        
        for pattern in self.vague_proposal_patterns:
            if re.search(pattern, combined_text):
                matches += 1
                score += 2.0
        
        # High confidence if multiple patterns match
        if matches >= 3:
            score += 3.0
        elif matches >= 2:
            score += 1.5
        
        return min(score, 8.0)
    
    def _check_urgency_patterns(self, text_lower: str) -> float:
        """Check for urgency pressure tactics"""
        score = 0.0
        
        for pattern in self.urgency_patterns:
            if re.search(pattern, text_lower):
                score += 2.0
        
        return min(score, 4.0)
    
    def _check_credential_harvesting(self, text_lower: str, subject: str) -> float:
        """Check for credential harvesting attempts"""
        score = 0.0
        
        combined_text = f"{subject} {text_lower[:1000]}"
        
        for pattern in self.credential_patterns:
            if re.search(pattern, combined_text):
                score += 3.0
        
        return min(score, 6.0)
    
    def _check_sender_domain(self, from_lower: str, subject: str, text_lower: str) -> float:
        """Check if sender domain is inappropriate for content"""
        score = 0.0
        
        # Check for inappropriate sender domains
        for domain_keyword in self.inappropriate_sender_domains:
            if domain_keyword in from_lower:
                # Casino domain sending business documents = highly suspicious
                if any(word in subject + " " + text_lower[:500] for word in 
                       ["document", "agreement", "contract", "invoice", "legal", "business"]):
                    score += 5.0
                    break
        
        # Check for URL shorteners in a "business" context
        for shortener in self.suspicious_service_domains:
            if shortener in text_lower:
                if any(word in text_lower[:500] for word in 
                       ["document", "agreement", "review", "sign"]):
                    score += 3.0
        
        return min(score, 7.0)
    
    def _check_sender_content_mismatch(self, msg: EmailMessage, from_header: str, 
                                       subject: str, text_lower: str) -> float:
        """Check for mismatches between sender and content claims"""
        score = 0.0
        
        # Extract domain from From header
        from_domain = ""
        if '@' in from_header:
            from_domain = from_header.split('@')[-1].lower().strip('>')
        
        # Check if content claims to be from a different organization
        # Example: From casino.com but claims "Rdjohnsonlaw shared folder"
        if from_domain:
            # Look for organization names in content that don't match sender
            org_pattern = r"(?:from|via|by|on behalf of)\s+([a-z0-9\-]+(?:\.[a-z]+)?)"
            org_matches = re.findall(org_pattern, text_lower[:1000])
            
            for org in org_matches:
                if org and from_domain not in org and org not in from_domain:
                    # Significant mismatch
                    if any(word in org for word in ["law", "bank", "financial", "secure"]):
                        score += 4.0
                    else:
                        score += 2.0
        
        # Check for generic/service account claiming personal communication
        if from_header:
            generic_accounts = ["noreply", "no-reply", "donotreply", "service", "system", 
                              "notification", "alert", "automated"]
            if any(generic in from_header.lower() for generic in generic_accounts):
                if any(personal in text_lower[:200] for personal in 
                       ["dear", "hi ", "hello", "personal", "your account"]):
                    score += 2.0
        
        return min(score, 5.0)
    
    def _determine_phishing_type(self, indicators: List[str]) -> str:
        """Determine the primary type of phishing based on indicators"""
        if any("document_sharing" in ind for ind in indicators):
            return "document_sharing_scam"
        elif any("credential_harvesting" in ind for ind in indicators):
            return "credential_harvesting"
        elif any("inappropriate_sender" in ind for ind in indicators):
            return "sender_impersonation"
        elif any("mismatch" in ind for ind in indicators):
            return "identity_spoofing"
        else:
            return "general_phishing"
    
    def _get_header(self, msg: EmailMessage, header_name: str, default: str = '') -> str:
        """Safely get email header"""
        try:
            value = msg.get(header_name, default)
            return str(value) if value else default
        except:
            return default

def check_phishing(msg: EmailMessage, text_content: str, from_header: str) -> Dict:
    """Main entry point for phishing detection"""
    detector = PhishingDetector()
    return detector.analyze(msg, text_content, from_header)