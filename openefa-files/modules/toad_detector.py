#!/usr/bin/env python3
"""
TOAD (Telephone-Oriented Attack Delivery) Detection Module
Specifically addresses callback phishing threats identified in THN article

DETECTS:
- Phone numbers in suspicious contexts
- VoIP provider analysis
- TOAD campaign patterns
- Urgency + callback combinations
- Known TOAD indicator phrases
"""

import re
import logging
import json
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timedelta

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

class TOADDetector:
    """
    Telephone-Oriented Attack Delivery (Callback Phishing) Detection
    Based on patterns identified in THN article
    """
    
    def __init__(self):
        self.logger = logging.getLogger('toad_detector')
        
        # TOAD trigger phrases from article analysis
        self.toad_triggers = {
            'urgency_phrases': [
                r'call\s+(?:us\s+)?(?:immediately|urgent|asap|now)',
                r'contact\s+(?:us\s+)?(?:immediately|urgent|asap)',
                r'time[- ]?sensitive',
                r'expires?\s+(?:today|tomorrow|soon)',
                r'limited\s+time',
                r'urgent\s+(?:action|response)\s+required',
                r'immediate\s+(?:action|attention|response)',
                r'within\s+\d+\s+hours?'
            ],
            
            'verification_phrases': [
                r'verify\s+(?:your\s+)?(?:account|identity|payment|transaction)',
                r'confirm\s+(?:your\s+)?(?:account|identity|payment|transaction)',
                r'validate\s+(?:your\s+)?(?:account|identity|payment)',
                r'authenticate\s+(?:your\s+)?(?:account|identity)',
                r'security\s+verification',
                r'account\s+verification'
            ],
            
            'threat_phrases': [
                r'(?:account|payment|service)\s+(?:suspended|locked|disabled|blocked)',
                r'suspicious\s+(?:activity|transaction|login|access)',
                r'unauthorized\s+(?:access|charge|transaction|login)',
                r'security\s+(?:breach|alert|warning)',
                r'fraudulent\s+(?:activity|transaction|charge)',
                r'compromise[d]?\s+account'
            ],
            
            'support_phrases': [
                r'call\s+(?:our\s+)?(?:support|customer\s+service|help\s+desk)',
                r'contact\s+(?:our\s+)?(?:support|customer\s+service|help\s+desk)',
                r'(?:customer|technical)\s+support\s+(?:line|number|team)',
                r'help\s+desk\s+(?:number|line)',
                r'toll[- ]?free\s+(?:number|line)',
                r'support\s+hotline'
            ]
        }
        
        # Known VoIP providers often used in TOAD attacks
        self.suspicious_voip_providers = [
            'bandwidth.com', 'twilio.com', 'nexmo.com', 'plivo.com',
            'vonage.com', 'grasshopper.com', 'ringcentral.com',
            'google voice', 'skype number', 'dialpad.com'
        ]
        
        # TOAD-specific phone number patterns
        self.toad_phone_patterns = [
            r'\+?1[- ]?800[- ]?\d{3}[- ]?\d{4}',  # US toll-free
            r'\+?1[- ]?888[- ]?\d{3}[- ]?\d{4}',  # US toll-free
            r'\+?1[- ]?877[- ]?\d{3}[- ]?\d{4}',  # US toll-free
            r'\+?1[- ]?866[- ]?\d{3}[- ]?\d{4}',  # US toll-free
            r'\+?1[- ]?855[- ]?\d{3}[- ]?\d{4}',  # US toll-free
            r'call\s+\+?\d{1,3}[- ]?\d{3,4}[- ]?\d{3,4}[- ]?\d{3,4}',  # Generic with "call"
            r'dial\s+\+?\d{1,3}[- ]?\d{3,4}[- ]?\d{3,4}[- ]?\d{3,4}'   # Generic with "dial"
        ]
        
        # Known TOAD campaign indicators
        self.campaign_indicators = {
            'microsoft_impersonation': [
                r'microsoft\s+(?:support|security|account)\s+team',
                r'office\s+365\s+(?:support|security)',
                r'windows\s+(?:support|security|defender)',
                r'microsoft\s+security\s+alert'
            ],
            
            'financial_impersonation': [
                r'(?:bank|banking)\s+(?:support|security|fraud)\s+team',
                r'credit\s+card\s+(?:support|security|fraud)',
                r'payment\s+(?:support|security|verification)',
                r'fraud\s+(?:prevention|detection)\s+team'
            ],
            
            'tech_support_scams': [
                r'(?:computer|pc|device)\s+(?:support|repair|security)',
                r'technical\s+support\s+(?:team|department)',
                r'virus\s+(?:removal|protection)\s+(?:team|support)',
                r'malware\s+(?:removal|protection)\s+(?:team|support)'
            ]
        }
        
        # Brands mentioned in the article
        self.impersonated_brands = [
            'microsoft', 'docusign', 'nortonlifelock', 'norton',
            'paypal', 'geek squad', 'best buy', 'amazon'
        ]

    def analyze_email_for_toad(self, subject: str, body: str, sender: str) -> Dict[str, Any]:
        """
        Main TOAD analysis function
        Returns comprehensive TOAD threat assessment
        """
        results = {
            'toad_detected': False,
            'confidence': 0.0,
            'risk_score': 0.0,
            'phone_numbers': [],
            'toad_indicators': [],
            'brand_impersonation': None,
            'campaign_type': None,
            'urgency_level': 'none',
            'recommended_action': 'allow'
        }
        
        try:
            # Combine all text for analysis
            full_text = f"{subject} {body}".lower()
            
            # Extract and analyze phone numbers
            phone_analysis = self._extract_phone_numbers(full_text)
            results['phone_numbers'] = phone_analysis['numbers']
            
            # Detect TOAD trigger phrases
            trigger_analysis = self._detect_toad_triggers(full_text)
            results['toad_indicators'] = trigger_analysis['triggers']
            
            # Analyze brand impersonation
            brand_analysis = self._analyze_brand_impersonation(full_text, sender)
            results['brand_impersonation'] = brand_analysis
            
            # Determine campaign type
            campaign_analysis = self._identify_campaign_type(full_text)
            results['campaign_type'] = campaign_analysis['type']
            
            # Calculate urgency level
            urgency_analysis = self._calculate_urgency_level(trigger_analysis)
            results['urgency_level'] = urgency_analysis['level']
            
            # Calculate overall TOAD risk score
            risk_score = self._calculate_toad_risk_score(
                phone_analysis, trigger_analysis, brand_analysis, 
                campaign_analysis, urgency_analysis
            )
            results['risk_score'] = risk_score
            
            # Determine if TOAD is detected
            results['toad_detected'] = risk_score >= 6.0
            results['confidence'] = min(risk_score / 10.0, 1.0)
            
            # Recommend action
            if risk_score >= 8.0:
                results['recommended_action'] = 'block'
            elif risk_score >= 6.0:
                results['recommended_action'] = 'quarantine'
            elif risk_score >= 4.0:
                results['recommended_action'] = 'flag'
            else:
                results['recommended_action'] = 'allow'
            
            self.logger.info(f"TOAD analysis complete: risk_score={risk_score}, detected={results['toad_detected']}")
            
        except Exception as e:
            self.logger.error(f"TOAD analysis failed: {e}")
            results['error'] = str(e)
        
        return results

    def _extract_phone_numbers(self, text: str) -> Dict[str, Any]:
        """Extract and analyze phone numbers for TOAD characteristics"""
        numbers = []
        
        # Extract phone numbers using multiple patterns
        for pattern in self.toad_phone_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                phone_data = {
                    'number': match.group(0).strip(),
                    'context': text[max(0, match.start()-50):match.end()+50],
                    'normalized': re.sub(r'[^\d+]', '', match.group(0)),
                    'is_toll_free': False,
                    'is_suspicious': False,
                    'provider_info': None
                }
                
                # Check if toll-free (common in TOAD)
                if re.search(r'[18](?:00|77|88|66|55)', phone_data['normalized']):
                    phone_data['is_toll_free'] = True
                
                # Analyze context for suspicious indicators
                context_lower = phone_data['context'].lower()
                suspicious_indicators = 0
                
                # Check for urgency in context
                for trigger_list in self.toad_triggers.values():
                    for trigger in trigger_list:
                        if re.search(trigger, context_lower):
                            suspicious_indicators += 1
                
                phone_data['is_suspicious'] = suspicious_indicators > 0
                phone_data['suspicious_indicator_count'] = suspicious_indicators
                
                # Try to get carrier information (if phonenumbers library available)
                if PHONENUMBERS_AVAILABLE:
                    try:
                        parsed_number = phonenumbers.parse(phone_data['normalized'], 'US')
                        if phonenumbers.is_valid_number(parsed_number):
                            carrier_name = carrier.name_for_number(parsed_number, 'en')
                            location = geocoder.description_for_number(parsed_number, 'en')
                            
                            phone_data['provider_info'] = {
                                'carrier': carrier_name,
                                'location': location,
                                'is_voip': carrier_name.lower() in [p.lower() for p in self.suspicious_voip_providers]
                            }
                    except:
                        pass
                
                numbers.append(phone_data)
        
        return {
            'numbers': numbers,
            'total_count': len(numbers),
            'suspicious_count': len([n for n in numbers if n['is_suspicious']]),
            'toll_free_count': len([n for n in numbers if n['is_toll_free']])
        }

    def _detect_toad_triggers(self, text: str) -> Dict[str, Any]:
        """Detect TOAD-specific trigger phrases"""
        triggers = []
        
        for category, phrase_list in self.toad_triggers.items():
            for phrase_pattern in phrase_list:
                matches = re.finditer(phrase_pattern, text, re.IGNORECASE)
                for match in matches:
                    triggers.append({
                        'category': category,
                        'phrase': match.group(0),
                        'pattern': phrase_pattern,
                        'context': text[max(0, match.start()-30):match.end()+30]
                    })
        
        # Count by category
        category_counts = {}
        for trigger in triggers:
            category = trigger['category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'triggers': triggers,
            'total_count': len(triggers),
            'category_counts': category_counts,
            'has_urgency': category_counts.get('urgency_phrases', 0) > 0,
            'has_verification': category_counts.get('verification_phrases', 0) > 0,
            'has_threats': category_counts.get('threat_phrases', 0) > 0,
            'has_support': category_counts.get('support_phrases', 0) > 0
        }

    def _analyze_brand_impersonation(self, text: str, sender: str) -> Optional[Dict[str, Any]]:
        """Analyze for brand impersonation in TOAD context"""
        for brand in self.impersonated_brands:
            if brand in text or brand in sender.lower():
                # Check if sender domain matches brand
                sender_domain = sender.split('@')[-1].lower() if '@' in sender else ''
                is_legitimate = brand in sender_domain
                
                return {
                    'brand': brand,
                    'mentioned_in_content': brand in text,
                    'mentioned_in_sender': brand in sender.lower(),
                    'sender_domain': sender_domain,
                    'is_legitimate_domain': is_legitimate,
                    'impersonation_detected': not is_legitimate and brand in text
                }
        
        return None

    def _identify_campaign_type(self, text: str) -> Dict[str, Any]:
        """Identify the type of TOAD campaign"""
        campaign_scores = {}
        
        for campaign_type, indicators in self.campaign_indicators.items():
            score = 0
            matched_indicators = []
            
            for indicator in indicators:
                matches = re.findall(indicator, text, re.IGNORECASE)
                if matches:
                    score += len(matches)
                    matched_indicators.extend(matches)
            
            if score > 0:
                campaign_scores[campaign_type] = {
                    'score': score,
                    'indicators': matched_indicators
                }
        
        if campaign_scores:
            # Return the campaign type with highest score
            top_campaign = max(campaign_scores.items(), key=lambda x: x[1]['score'])
            return {
                'type': top_campaign[0],
                'confidence': min(top_campaign[1]['score'] * 0.3, 1.0),
                'indicators': top_campaign[1]['indicators']
            }
        
        return {'type': None, 'confidence': 0.0, 'indicators': []}

    def _calculate_urgency_level(self, trigger_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate urgency level based on triggers"""
        urgency_count = trigger_analysis['category_counts'].get('urgency_phrases', 0)
        threat_count = trigger_analysis['category_counts'].get('threat_phrases', 0)
        
        total_urgency = urgency_count + threat_count
        
        if total_urgency >= 3:
            level = 'critical'
        elif total_urgency >= 2:
            level = 'high'
        elif total_urgency >= 1:
            level = 'medium'
        else:
            level = 'none'
        
        return {
            'level': level,
            'urgency_indicator_count': urgency_count,
            'threat_indicator_count': threat_count,
            'total_urgency_score': total_urgency
        }

    def _calculate_toad_risk_score(self, phone_analysis: Dict, trigger_analysis: Dict, 
                                   brand_analysis: Optional[Dict], campaign_analysis: Dict,
                                   urgency_analysis: Dict) -> float:
        """Calculate overall TOAD risk score"""
        risk_score = 0.0
        
        # Phone number factors
        if phone_analysis['total_count'] > 0:
            risk_score += phone_analysis['total_count'] * 1.5  # Base score for having phone numbers
            risk_score += phone_analysis['suspicious_count'] * 2.0  # Extra for suspicious context
            risk_score += phone_analysis['toll_free_count'] * 1.0  # Toll-free numbers are common in TOAD
        
        # TOAD trigger factors
        trigger_counts = trigger_analysis['category_counts']
        risk_score += trigger_counts.get('urgency_phrases', 0) * 1.5
        risk_score += trigger_counts.get('verification_phrases', 0) * 1.0
        risk_score += trigger_counts.get('threat_phrases', 0) * 2.0
        risk_score += trigger_counts.get('support_phrases', 0) * 1.0
        
        # Brand impersonation factor
        if brand_analysis and brand_analysis.get('impersonation_detected'):
            risk_score += 3.0
        
        # Campaign type factor
        if campaign_analysis['type']:
            risk_score += campaign_analysis['confidence'] * 2.0
        
        # Urgency level factor
        urgency_multipliers = {
            'critical': 2.0,
            'high': 1.5,
            'medium': 1.2,
            'none': 1.0
        }
        urgency_multiplier = urgency_multipliers.get(urgency_analysis['level'], 1.0)
        risk_score *= urgency_multiplier
        
        # Combination bonuses (multiple factors present)
        combination_bonus = 0.0
        factors_present = 0
        
        if phone_analysis['total_count'] > 0:
            factors_present += 1
        if trigger_analysis['total_count'] > 2:
            factors_present += 1
        if brand_analysis:
            factors_present += 1
        if urgency_analysis['level'] in ['high', 'critical']:
            factors_present += 1
        
        if factors_present >= 3:
            combination_bonus = 2.0
        elif factors_present >= 2:
            combination_bonus = 1.0
        
        risk_score += combination_bonus
        
        return min(risk_score, 10.0)  # Cap at 10

# Integration function for email_filter.py
def analyze_toad_threats(subject: str, body: str, sender: str) -> Dict[str, Any]:
    """
    Analyze email for TOAD (callback phishing) threats
    Returns threat assessment and recommended actions
    """
    detector = TOADDetector()
    return detector.analyze_email_for_toad(subject, body, sender)

if __name__ == "__main__":
    # Test the TOAD detector
    detector = TOADDetector()
    
    # Test with sample TOAD email
    test_subject = "URGENT: Microsoft Account Suspended - Call Immediately"
    test_body = """
    Your Microsoft account has been suspended due to suspicious activity.
    
    To verify your identity and restore access, please call our support team
    immediately at 1-800-555-0123.
    
    This is time-sensitive and must be resolved within 24 hours.
    
    Microsoft Security Team
    """
    test_sender = "security-alert@microsoft-support.info"
    
    result = detector.analyze_email_for_toad(test_subject, test_body, test_sender)
    print("TOAD Analysis Result:")
    print(json.dumps(result, indent=2))
