#!/usr/bin/env python3
"""
OnMicrosoft.com Brand Impersonation Detection Module

Detects abuse of Microsoft 365 tenant domains (*.onmicrosoft.com) to impersonate
well-known brands. These are particularly dangerous because:
1. They pass SPF/DKIM (legitimate Microsoft infrastructure)
2. Anyone can create a Microsoft 365 tenant
3. Attackers use them to impersonate trusted brands
4. Many spam filters trust Microsoft domains

Scoring:
- Brand name + onmicrosoft.com domain: +15 points (VERY HIGH RISK)
- Company/organization name + onmicrosoft.com: +10 points (HIGH RISK)
"""

import re
import logging
from email.utils import parseaddr
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class OnMicrosoftImpersonationDetector:
    """Detect brand impersonation via Microsoft 365 tenant domains"""

    # Major brands often impersonated via onmicrosoft.com
    # These should NEVER legitimately email from *.onmicrosoft.com
    HIGH_VALUE_BRANDS = [
        # Tech companies
        'linkedin', 'google', 'apple', 'amazon', 'facebook', 'meta',
        'twitter', 'x corp', 'salesforce', 'oracle', 'adobe', 'zoom',
        'slack', 'dropbox', 'box', 'atlassian', 'spotify', 'netflix',
        'uber', 'lyft', 'airbnb', 'ebay', 'paypal', 'venmo',

        # Financial institutions
        'chase', 'bank of america', 'wells fargo', 'citibank', 'citi',
        'capital one', 'discover', 'american express', 'amex', 'usaa',
        'schwab', 'fidelity', 'vanguard', 'td bank', 'pnc bank',
        'us bank', 'truist', 'regions bank', 'fifth third',

        # Payment processors
        'stripe', 'square', 'coinbase', 'robinhood', 'cashapp',

        # Shipping/logistics
        'fedex', 'ups', 'dhl', 'usps', 'postal service',

        # Government/official
        'irs', 'social security', 'ssa', 'federal', 'treasury',
        'department of', 'gov.', 'state of', 'county of',

        # Other high-value targets
        'docusign', 'intuit', 'turbotax', 'quickbooks', 'costco',
        'walmart', 'target', 'home depot', 'lowes', 'best buy'
    ]

    # Suspicious keywords that amplify the threat
    URGENCY_KEYWORDS = [
        'urgent', 'action required', 'verify', 'suspended', 'locked',
        'security alert', 'fraud alert', 'overdue', 'payment',
        'invoice', 'refund', 'confirm', 'update required', 'expires',
        'account', 'billing', 'subscription', 'receivable', 'collections'
    ]

    # Legitimate Microsoft services that may use onmicrosoft.com
    # These are whitelisted to prevent false positives
    LEGITIMATE_MICROSOFT_SENDERS = [
        'microsoft', 'office 365', 'office365', 'azure', 'dynamics',
        'teams', 'sharepoint', 'onedrive', 'outlook', 'exchange',
        'power bi', 'powerbi', 'intune', 'security center'
    ]

    def __init__(self):
        """Initialize the detector"""
        pass

    def extract_domain(self, email_address: str) -> Optional[str]:
        """Extract domain from email address"""
        try:
            if '@' in email_address:
                return email_address.split('@')[1].lower().strip()
            return None
        except Exception as e:
            logger.error(f"Error extracting domain from {email_address}: {e}")
            return None

    def is_onmicrosoft_domain(self, domain: str) -> bool:
        """Check if domain is a Microsoft 365 tenant domain"""
        if not domain:
            return False
        return domain.endswith('.onmicrosoft.com') or domain == 'onmicrosoft.com'

    def contains_brand(self, text: str) -> tuple[bool, List[str]]:
        """
        Check if text contains any high-value brand names
        Returns (found, list_of_brands_found)
        """
        if not text:
            return False, []

        text_lower = text.lower()
        brands_found = []

        for brand in self.HIGH_VALUE_BRANDS:
            if brand in text_lower:
                brands_found.append(brand)

        return len(brands_found) > 0, brands_found

    def is_legitimate_microsoft(self, display_name: str) -> bool:
        """Check if this is a legitimate Microsoft service"""
        if not display_name:
            return False

        display_lower = display_name.lower()
        return any(legit in display_lower for legit in self.LEGITIMATE_MICROSOFT_SENDERS)

    def contains_urgency(self, text: str) -> tuple[bool, List[str]]:
        """
        Check if text contains urgency/phishing keywords
        Returns (found, list_of_keywords_found)
        """
        if not text:
            return False, []

        text_lower = text.lower()
        keywords_found = []

        for keyword in self.URGENCY_KEYWORDS:
            if keyword in text_lower:
                keywords_found.append(keyword)

        return len(keywords_found) > 0, keywords_found

    def analyze(self, msg, recipients: List[str] = None) -> Dict[str, Any]:
        """
        Analyze email for onmicrosoft.com brand impersonation

        Args:
            msg: Email message object
            recipients: List of recipient email addresses (optional)

        Returns:
            Dict with analysis results including spam_score_increase
        """
        results = {
            'impersonation_detected': False,
            'spam_score_increase': 0.0,
            'threat_level': 'none',  # none, medium, high, critical
            'indicators': [],
            'brands_found': [],
            'display_name': '',
            'sender_email': '',
            'sender_domain': ''
        }

        try:
            # Parse From header
            from_header = msg.get('From', '')
            display_name, sender_email = parseaddr(from_header)

            if not sender_email:
                return results

            # Clean up
            display_name = display_name.strip().strip('"').strip("'")
            sender_email = sender_email.lower().strip()
            sender_domain = self.extract_domain(sender_email)

            results['display_name'] = display_name
            results['sender_email'] = sender_email
            results['sender_domain'] = sender_domain or ''

            # Check if sender is from onmicrosoft.com
            if not self.is_onmicrosoft_domain(sender_domain):
                return results

            # Check if this is legitimate Microsoft communication
            if self.is_legitimate_microsoft(display_name):
                logger.info(f"✅ Legitimate Microsoft service: '{display_name}' from {sender_domain}")
                return results

            # Check for brand impersonation in display name
            has_brand, brands_found = self.contains_brand(display_name)

            if has_brand:
                results['impersonation_detected'] = True
                results['brands_found'] = brands_found
                results['threat_level'] = 'critical'
                results['spam_score_increase'] = 15.0

                results['indicators'].append(f"OnMicrosoft.com domain impersonating: {', '.join(brands_found)}")
                results['indicators'].append(f"Display name: '{display_name}'")
                results['indicators'].append(f"Actual domain: {sender_domain}")

                logger.warning(f"🚨 ONMICROSOFT BRAND IMPERSONATION DETECTED!")
                logger.warning(f"   Display: '{display_name}'")
                logger.warning(f"   Brands: {', '.join(brands_found)}")
                logger.warning(f"   Domain: {sender_domain}")
                logger.warning(f"   Score: +{results['spam_score_increase']}")

                # Check subject line for additional threat indicators
                subject = msg.get('Subject', '')
                has_urgency, urgency_keywords = self.contains_urgency(subject)

                if has_urgency:
                    # Amplify score for urgent/phishing subjects
                    results['spam_score_increase'] += 5.0
                    results['indicators'].append(f"Urgent subject keywords: {', '.join(urgency_keywords)}")
                    logger.warning(f"   ⚠️  Urgent subject: {subject}")

                # Check display name for urgency too
                display_urgency, display_urgent_keywords = self.contains_urgency(display_name)
                if display_urgency:
                    results['spam_score_increase'] += 3.0
                    results['indicators'].append(f"Urgent display name keywords: {', '.join(display_urgent_keywords)}")

            else:
                # No specific brand, but still onmicrosoft.com with non-Microsoft display
                # This is suspicious but lower priority
                if display_name and not self.is_legitimate_microsoft(display_name):
                    # Check if display name looks like a company/organization
                    if any(word in display_name.lower() for word in ['team', 'support', 'service', 'department', 'corp', 'inc', 'llc', 'ltd']):
                        results['impersonation_detected'] = True
                        results['threat_level'] = 'high'
                        results['spam_score_increase'] = 10.0
                        results['indicators'].append(f"OnMicrosoft.com used by non-Microsoft organization: '{display_name}'")
                        logger.warning(f"⚠️  OnMicrosoft non-Microsoft org: '{display_name}' from {sender_domain}")

            return results

        except Exception as e:
            logger.error(f"Error in OnMicrosoft impersonation detection: {e}", exc_info=True)
            return results


def analyze_onmicrosoft_impersonation(msg, recipients: List[str] = None) -> Dict[str, Any]:
    """
    Main entry point for onmicrosoft.com impersonation detection

    Args:
        msg: Email message object
        recipients: List of recipient email addresses (optional)

    Returns:
        Dict with analysis results including spam_score_increase
    """
    detector = OnMicrosoftImpersonationDetector()
    return detector.analyze(msg, recipients)


if __name__ == '__main__':
    # Test with the LinkedIn phishing example
    from email.message import EmailMessage

    print("OnMicrosoft.com Brand Impersonation Detector - Test Cases")
    print("=" * 70)

    # Test 1: LinkedIn phishing (should detect)
    msg1 = EmailMessage()
    msg1['From'] = 'Receivable Team | Linkedin Corporation <tranhoaison@truongchinhtribinhdinh.onmicrosoft.com>'
    msg1['Subject'] = 'Re: Overdue Notice'

    result1 = analyze_onmicrosoft_impersonation(msg1)
    print("\nTest 1: LinkedIn Phishing")
    print(f"  Detected: {result1['impersonation_detected']}")
    print(f"  Score: +{result1['spam_score_increase']}")
    print(f"  Threat: {result1['threat_level']}")
    print(f"  Brands: {result1['brands_found']}")
    print(f"  Indicators: {result1['indicators']}")

    # Test 2: Legitimate Microsoft (should NOT detect)
    msg2 = EmailMessage()
    msg2['From'] = 'Microsoft Teams <noreply@contoso.onmicrosoft.com>'
    msg2['Subject'] = 'You have been added to a team'

    result2 = analyze_onmicrosoft_impersonation(msg2)
    print("\nTest 2: Legitimate Microsoft Teams")
    print(f"  Detected: {result2['impersonation_detected']}")
    print(f"  Score: +{result2['spam_score_increase']}")

    # Test 3: Bank impersonation (should detect)
    msg3 = EmailMessage()
    msg3['From'] = 'Chase Bank Alerts <alerts@chase-security.onmicrosoft.com>'
    msg3['Subject'] = 'Security Alert: Verify Your Account'

    result3 = analyze_onmicrosoft_impersonation(msg3)
    print("\nTest 3: Chase Bank Phishing")
    print(f"  Detected: {result3['impersonation_detected']}")
    print(f"  Score: +{result3['spam_score_increase']}")
    print(f"  Threat: {result3['threat_level']}")
    print(f"  Brands: {result3['brands_found']}")
