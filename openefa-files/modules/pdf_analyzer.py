#!/usr/bin/env python3
"""
PDF Attachment Analysis Module for SpaCy Email Security
Addresses gaps identified in PDF-based phishing attacks from THN article

NEW CAPABILITIES:
- QR code extraction and analysis
- PDF annotation inspection (sticky notes, comments, form fields)
- Phone number extraction for TOAD detection
- PDF-specific threat patterns
"""

import re
import hashlib
import logging
from typing import Dict, List, Tuple, Optional, Any
from email.message import EmailMessage
import json

# PDF analysis imports
try:
    import PyPDF2
    import fitz  # PyMuPDF for better PDF parsing
    from PIL import Image
    import cv2
    import numpy as np
    PDF_ANALYSIS_AVAILABLE = True
except ImportError as e:
    PDF_ANALYSIS_AVAILABLE = False
    print(f"PDF analysis libraries not available: {e}")

class PDFAttachmentAnalyzer:
    """
    Analyzes PDF attachments for threats identified in THN article:
    - QR codes pointing to phishing sites
    - PDF annotations with malicious URLs
    - TOAD phone numbers
    - Brand impersonation in PDF content
    """
    
    def __init__(self):
        self.logger = logging.getLogger('pdf_analyzer')
        
        # TOAD phone number patterns
        self.phone_patterns = [
            r'\+?1[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})',  # US
            r'\+?44[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}',      # UK
            r'\+?[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}' # International
        ]
        
        # Brand impersonation keywords from article
        self.impersonated_brands = {
            'microsoft': ['microsoft', 'office', 'o365', 'outlook', 'teams', 'onedrive', 'sharepoint'],
            'docusign': ['docusign', 'document sign', 'e-signature', 'digital signature'],
            'norton': ['norton', 'nortonlifelock', 'symantec'],
            'paypal': ['paypal', 'pay pal'],
            'geek_squad': ['geek squad', 'geeksquad', 'best buy support']
        }
        
        # TOAD trigger phrases
        self.toad_indicators = [
            r'call\s+(?:us\s+)?(?:immediately|urgent|asap)',
            r'contact\s+(?:our\s+)?(?:support|customer\s+service)',
            r'verify\s+(?:your\s+)?(?:account|identity|payment)',
            r'suspicious\s+(?:activity|transaction)',
            r'account\s+(?:suspended|locked|compromised)',
            r'unauthorized\s+(?:access|charge|transaction)',
            r'click\s+here\s+to\s+verify',
            r'call\s+toll[- ]?free',
            r'customer\s+support\s+line'
        ]
        
        # QR code phishing indicators
        self.qr_phishing_domains = [
            'bit.ly', 'tinyurl.com', 'short.link', 't.co',
            'login-microsoft', 'secure-office', 'verify-account'
        ]

    def analyze_pdf_attachment(self, attachment_data: bytes, filename: str = '') -> Dict[str, Any]:
        """
        Main analysis function for PDF attachments
        Returns comprehensive threat assessment
        """
        if not PDF_ANALYSIS_AVAILABLE:
            return {
                'analysis_available': False,
                'error': 'PDF analysis libraries not installed'
            }
        
        results = {
            'filename': filename,
            'analysis_available': True,
            'file_size': len(attachment_data),
            'threats_detected': [],
            'risk_score': 0.0,
            'phone_numbers': [],
            'qr_codes': [],
            'annotations': [],
            'brand_impersonation': [],
            'toad_indicators': [],
            'suspicious_urls': []
        }
        
        try:
            # Parse PDF content
            pdf_text = self._extract_pdf_text(attachment_data)
            annotations = self._extract_pdf_annotations(attachment_data)
            qr_codes = self._extract_qr_codes(attachment_data)
            
            # Analyze for threats
            phone_analysis = self._analyze_phone_numbers(pdf_text)
            brand_analysis = self._analyze_brand_impersonation(pdf_text)
            toad_analysis = self._analyze_toad_indicators(pdf_text)
            url_analysis = self._analyze_suspicious_urls(pdf_text, annotations)
            qr_analysis = self._analyze_qr_codes(qr_codes)
            
            # Compile results
            results.update({
                'phone_numbers': phone_analysis['phone_numbers'],
                'qr_codes': qr_analysis['qr_codes'],
                'annotations': annotations,
                'brand_impersonation': brand_analysis['brands_detected'],
                'toad_indicators': toad_analysis['indicators'],
                'suspicious_urls': url_analysis['suspicious_urls']
            })
            
            # Calculate risk score
            risk_score = self._calculate_pdf_risk_score(results)
            results['risk_score'] = risk_score
            
            # Generate threat summary
            threats = self._generate_threat_summary(results)
            results['threats_detected'] = threats
            
            self.logger.info(f"PDF analysis complete: {filename}, risk_score={risk_score}")
            
        except Exception as e:
            self.logger.error(f"PDF analysis failed: {e}")
            results['error'] = str(e)
            results['analysis_available'] = False
        
        return results

    def _extract_pdf_text(self, pdf_data: bytes) -> str:
        """Extract all text content from PDF"""
        try:
            # Try PyMuPDF first (better for complex PDFs)
            doc = fitz.open(stream=pdf_data, filetype="pdf")
            text = ""
            for page in doc:
                text += page.get_text()
            doc.close()
            return text
        except:
            # Fallback to PyPDF2
            try:
                from io import BytesIO
                reader = PyPDF2.PdfReader(BytesIO(pdf_data))
                text = ""
                for page in reader.pages:
                    text += page.extract_text()
                return text
            except:
                return ""

    def _extract_pdf_annotations(self, pdf_data: bytes) -> List[Dict[str, Any]]:
        """Extract PDF annotations (sticky notes, comments, form fields)"""
        annotations = []
        try:
            doc = fitz.open(stream=pdf_data, filetype="pdf")
            for page_num, page in enumerate(doc):
                for annot in page.annots():
                    annotation_data = {
                        'page': page_num + 1,
                        'type': annot.type[1],  # Annotation type name
                        'content': annot.content,
                        'rect': list(annot.rect),
                    }
                    
                    # Check for URLs in annotation
                    if annot.uri:
                        annotation_data['url'] = annot.uri
                    
                    annotations.append(annotation_data)
            doc.close()
        except Exception as e:
            self.logger.error(f"Annotation extraction failed: {e}")
        
        return annotations

    def _extract_qr_codes(self, pdf_data: bytes) -> List[Dict[str, Any]]:
        """Extract and decode QR codes from PDF pages"""
        qr_codes = []
        try:
            doc = fitz.open(stream=pdf_data, filetype="pdf")
            for page_num, page in enumerate(doc):
                # Render page as image
                pix = page.get_pixmap()
                img_data = pix.tobytes("png")
                
                # Convert to OpenCV format for QR detection
                nparr = np.frombuffer(img_data, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                
                # Detect QR codes
                detector = cv2.QRCodeDetector()
                data, bbox, _ = detector.detectAndDecode(img)
                
                if data:
                    qr_codes.append({
                        'page': page_num + 1,
                        'data': data,
                        'bbox': bbox.tolist() if bbox is not None else None
                    })
            
            doc.close()
        except Exception as e:
            self.logger.error(f"QR code extraction failed: {e}")
        
        return qr_codes

    def _analyze_phone_numbers(self, text: str) -> Dict[str, Any]:
        """Extract and analyze phone numbers for TOAD detection"""
        phone_numbers = []
        
        for pattern in self.phone_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                phone_data = {
                    'number': match.group(0).strip(),
                    'context': text[max(0, match.start()-50):match.end()+50],
                    'normalized': re.sub(r'[^\d]', '', match.group(0))
                }
                
                # Check if phone number appears in suspicious context
                context_lower = phone_data['context'].lower()
                is_suspicious = any(
                    re.search(indicator, context_lower) 
                    for indicator in self.toad_indicators
                )
                phone_data['suspicious_context'] = is_suspicious
                
                phone_numbers.append(phone_data)
        
        return {'phone_numbers': phone_numbers}

    def _analyze_brand_impersonation(self, text: str) -> Dict[str, Any]:
        """Detect brand impersonation attempts"""
        brands_detected = []
        text_lower = text.lower()
        
        for brand, keywords in self.impersonated_brands.items():
            brand_mentions = 0
            found_keywords = []
            
            for keyword in keywords:
                if keyword in text_lower:
                    brand_mentions += text_lower.count(keyword)
                    found_keywords.append(keyword)
            
            if brand_mentions > 0:
                brands_detected.append({
                    'brand': brand,
                    'mention_count': brand_mentions,
                    'keywords_found': found_keywords,
                    'confidence': min(brand_mentions * 0.2, 1.0)
                })
        
        return {'brands_detected': brands_detected}

    def _analyze_toad_indicators(self, text: str) -> Dict[str, Any]:
        """Detect TOAD (callback phishing) indicators"""
        indicators = []
        text_lower = text.lower()
        
        for pattern in self.toad_indicators:
            matches = re.finditer(pattern, text_lower)
            for match in matches:
                indicators.append({
                    'pattern': pattern,
                    'match': match.group(0),
                    'context': text[max(0, match.start()-30):match.end()+30]
                })
        
        return {'indicators': indicators}

    def _analyze_suspicious_urls(self, text: str, annotations: List[Dict]) -> Dict[str, Any]:
        """Analyze URLs in text and annotations"""
        suspicious_urls = []
        
        # Extract URLs from text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        # Add URLs from annotations
        for annot in annotations:
            if 'url' in annot:
                urls.append(annot['url'])
        
        # Analyze each URL
        for url in urls:
            url_lower = url.lower()
            is_suspicious = False
            reasons = []
            
            # Check against known phishing domains
            for domain in self.qr_phishing_domains:
                if domain in url_lower:
                    is_suspicious = True
                    reasons.append(f"Uses suspicious domain: {domain}")
            
            # Check for Microsoft impersonation
            if any(term in url_lower for term in ['microsoft', 'office', 'login']):
                if 'microsoft.com' not in url_lower:
                    is_suspicious = True
                    reasons.append("Microsoft impersonation detected")
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'short.link']
            if any(shortener in url_lower for shortener in shorteners):
                is_suspicious = True
                reasons.append("URL shortener detected")
            
            if is_suspicious:
                suspicious_urls.append({
                    'url': url,
                    'reasons': reasons,
                    'risk_level': 'high' if len(reasons) > 1 else 'medium'
                })
        
        return {'suspicious_urls': suspicious_urls}

    def _analyze_qr_codes(self, qr_codes: List[Dict]) -> Dict[str, Any]:
        """Analyze QR code content for threats"""
        analyzed_qr = []
        
        for qr in qr_codes:
            qr_data = qr['data']
            analysis = {
                'page': qr['page'],
                'content': qr_data,
                'type': 'unknown',
                'risk_level': 'low',
                'threats': []
            }
            
            # Determine QR code type
            if qr_data.startswith('http'):
                analysis['type'] = 'url'
                
                # Analyze URL for threats
                url_analysis = self._analyze_suspicious_urls(qr_data, [])
                if url_analysis['suspicious_urls']:
                    analysis['risk_level'] = 'high'
                    analysis['threats'].extend(['phishing_url', 'brand_impersonation'])
            
            elif qr_data.startswith('tel:'):
                analysis['type'] = 'phone'
                analysis['threats'].append('potential_toad')
                analysis['risk_level'] = 'medium'
            
            analyzed_qr.append(analysis)
        
        return {'qr_codes': analyzed_qr}

    def _calculate_pdf_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score for PDF attachment"""
        risk_score = 0.0
        
        # Phone numbers in suspicious context
        suspicious_phones = [p for p in results['phone_numbers'] if p.get('suspicious_context')]
        risk_score += len(suspicious_phones) * 2.0
        
        # Brand impersonation
        for brand in results['brand_impersonation']:
            risk_score += brand['confidence'] * 1.5
        
        # TOAD indicators
        risk_score += len(results['toad_indicators']) * 1.0
        
        # Suspicious URLs
        high_risk_urls = [u for u in results['suspicious_urls'] if u['risk_level'] == 'high']
        risk_score += len(high_risk_urls) * 2.5
        
        # QR codes with threats
        risky_qr = [q for q in results['qr_codes'] if q['risk_level'] in ['high', 'medium']]
        risk_score += len(risky_qr) * 2.0
        
        # PDF annotations (inherently suspicious)
        risk_score += len(results['annotations']) * 0.5
        
        return min(risk_score, 10.0)  # Cap at 10

    def _generate_threat_summary(self, results: Dict[str, Any]) -> List[str]:
        """Generate list of detected threats"""
        threats = []
        
        if results['phone_numbers']:
            threats.append("TOAD_PHONE_NUMBERS")
        
        if results['brand_impersonation']:
            threats.append("BRAND_IMPERSONATION")
        
        if results['toad_indicators']:
            threats.append("CALLBACK_PHISHING_INDICATORS")
        
        if results['suspicious_urls']:
            threats.append("SUSPICIOUS_URLS")
        
        if any(q['risk_level'] == 'high' for q in results['qr_codes']):
            threats.append("MALICIOUS_QR_CODES")
        
        if results['annotations']:
            threats.append("PDF_ANNOTATIONS")
        
        if results['risk_score'] >= 7.0:
            threats.append("HIGH_RISK_PDF")
        
        return threats

# Integration function for email_filter.py
def analyze_pdf_attachments(msg: EmailMessage) -> Dict[str, Any]:
    """
    Analyze all PDF attachments in email message
    Returns comprehensive threat assessment
    """
    analyzer = PDFAttachmentAnalyzer()
    attachment_results = []
    overall_risk = 0.0
    all_threats = set()
    
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'application/pdf':
                    filename = part.get_filename() or 'unknown.pdf'
                    attachment_data = part.get_payload(decode=True)
                    
                    if attachment_data:
                        result = analyzer.analyze_pdf_attachment(attachment_data, filename)
                        attachment_results.append(result)
                        
                        if result.get('analysis_available'):
                            overall_risk = max(overall_risk, result['risk_score'])
                            all_threats.update(result['threats_detected'])
    
    except Exception as e:
        return {
            'analysis_available': False,
            'error': str(e)
        }
    
    return {
        'analysis_available': True,
        'attachment_count': len(attachment_results),
        'attachments': attachment_results,
        'overall_risk_score': overall_risk,
        'all_threats': list(all_threats),
        'requires_blocking': overall_risk >= 7.0
    }

if __name__ == "__main__":
    # Test the PDF analyzer
    analyzer = PDFAttachmentAnalyzer()
    print("PDF Attachment Analyzer initialized")
    print(f"PDF analysis available: {PDF_ANALYSIS_AVAILABLE}")
