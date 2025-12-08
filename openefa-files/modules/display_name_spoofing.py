#!/usr/bin/env python3
"""
Display Name Spoofing Detection Module

Detects various forms of sender identity spoofing including:
1. Display name domain mismatch from actual sender domain
2. Display name impersonating recipient's domain
3. Internal spoofing with random/fake sender addresses
4. Display name containing executive/authority titles
5. Display name containing brand names with mismatched domains
6. Unicode/homograph attacks in display names

Scoring:
- Recipient domain impersonation (full domain): +8 points (HIGH RISK)
- Internal spoofing with random sender: +7 points (HIGH RISK)
- Brand impersonation: +7 points (PHISHING)
- Executive title + domain mismatch: +6 points (BEC INDICATOR)
- Display name domain mismatch: +5 points (MEDIUM RISK)
- Unicode tricks: +4 points (OBFUSCATION)
- Urgent keywords (amplifier): +2 points (when combined with other indicators)
"""

import re
import logging
from email.utils import parseaddr
from typing import Dict, Any, List, Optional
import unicodedata

logger = logging.getLogger(__name__)


class DisplayNameSpoofingDetector:
    """Detect display name spoofing and sender identity fraud"""

    # Executive/authority titles that suggest BEC attempts
    EXECUTIVE_TITLES = [
        'ceo', 'cfo', 'cto', 'coo', 'president', 'director', 'executive',
        'manager', 'chairman', 'owner', 'founder', 'vice president', 'vp',
        'chief', 'admin', 'administrator', 'accounting', 'finance', 'hr',
        'human resources', 'payroll', 'boss', 'supervisor'
    ]

    # Common brand names often impersonated
    BRAND_NAMES = [
        'microsoft', 'apple', 'google', 'amazon', 'facebook', 'meta',
        'paypal', 'bank', 'chase', 'wells fargo', 'citibank', 'usaa',
        'american express', 'visa', 'mastercard', 'fedex', 'ups', 'dhl',
        'usps', 'irs', 'social security', 'linkedin', 'twitter', 'netflix',
        'adobe', 'docusign', 'dropbox', 'salesforce', 'ebay', 'walmart'
    ]

    # Security/urgent keywords often used in spoofing
    URGENT_KEYWORDS = [
        'security', 'alert', 'urgent', 'action required', 'verify',
        'suspended', 'locked', 'expires', 'expiring', 'confirm',
        'update required', 'immediate', 'attention', 'warning'
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

    def extract_display_name_domain(self, display_name: str) -> Optional[str]:
        """
        Extract domain-like strings from display name
        Looks for patterns like: "user@domain.com" or "domain.com"
        """
        try:
            # Check for email address pattern in display name
            email_pattern = r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
            matches = re.findall(email_pattern, display_name)
            if matches:
                return matches[0].lower()

            # Check for domain.com pattern (without @)
            domain_pattern = r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
            matches = re.findall(domain_pattern, display_name)
            if matches:
                # Filter out obvious non-domains
                for match in matches:
                    if len(match) > 4 and '.' in match:
                        return match.lower()

            return None
        except Exception as e:
            logger.error(f"Error extracting domain from display name: {e}")
            return None

    def contains_unicode_tricks(self, text: str) -> bool:
        """
        Detect Unicode homograph attacks or suspicious characters
        """
        try:
            # Check for mixed scripts (Latin + Cyrillic, etc.)
            scripts = set()
            for char in text:
                if char.isalpha():
                    try:
                        script = unicodedata.name(char).split()[0]
                        scripts.add(script)
                    except:
                        pass

            # Multiple scripts is suspicious
            if len(scripts) > 1:
                return True

            # Check for confusable characters (Cyrillic that look like Latin)
            confusables = {
                'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
                'х': 'x', 'у': 'y', 'В': 'B', 'Н': 'H', 'К': 'K',
                'М': 'M', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X'
            }

            for char in text:
                if char in confusables:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking Unicode tricks: {e}")
            return False

    def check_executive_title(self, display_name: str) -> bool:
        """Check if display name contains executive/authority titles"""
        display_lower = display_name.lower()
        return any(title in display_lower for title in self.EXECUTIVE_TITLES)

    def check_brand_impersonation(self, display_name: str) -> bool:
        """Check if display name contains brand names"""
        display_lower = display_name.lower()
        return any(brand in display_lower for brand in self.BRAND_NAMES)

    def check_urgent_keywords(self, display_name: str) -> bool:
        """Check if display name contains urgent/security keywords"""
        display_lower = display_name.lower()
        return any(keyword in display_lower for keyword in self.URGENT_KEYWORDS)

    def analyze(self, msg, recipients: List[str]) -> Dict[str, Any]:
        """
        Analyze email for display name spoofing

        Args:
            msg: Email message object
            recipients: List of recipient email addresses

        Returns:
            Dict with spoofing analysis results
        """
        results = {
            'spoofing_detected': False,
            'spoofing_score': 0.0,
            'spoofing_type': [],
            'indicators': [],
            'display_name': '',
            'sender_email': '',
            'sender_domain': '',
            'display_domain': None,
            'recipient_domains': []
        }

        try:
            # Parse From header
            from_header = msg.get('From', '')
            display_name, sender_email = parseaddr(from_header)

            if not sender_email:
                return results

            # Clean up display name and email
            display_name = display_name.strip().strip('"').strip("'")
            sender_email = sender_email.lower().strip()
            sender_domain = self.extract_domain(sender_email)

            results['display_name'] = display_name
            results['sender_email'] = sender_email
            results['sender_domain'] = sender_domain or ''

            # Extract recipient domains
            recipient_domains = []
            for recipient in recipients:
                domain = self.extract_domain(recipient)
                if domain:
                    recipient_domains.append(domain)
            results['recipient_domains'] = recipient_domains

            score = 0.0
            spoofing_types = []
            indicators = []

            # ============================================================
            # CHECK 0: Local Part Domain Impersonation (NO DISPLAY NAME NEEDED)
            # ============================================================
            # Check if sender email local part contains recipient domain
            # This catches attacks like: storage.sadefensejournal.com@sendgrid.net
            # This check runs EVEN IF there's no display name
            if recipient_domains:
                for recipient_domain in recipient_domains:
                    sender_local_part = sender_email.split('@')[0] if '@' in sender_email else ''
                    if sender_local_part and recipient_domain in sender_local_part.lower():
                        score += 8.0
                        spoofing_types.append('local_part_domain_impersonation')
                        indicators.append(f"Sender local part contains recipient domain: {sender_local_part} (domain: {recipient_domain})")
                        logger.warning(f"🚨 LOCAL PART IMPERSONATION: Sender '{sender_email}' has recipient domain '{recipient_domain}' in local part")
                        break

            # Skip remaining display name checks if no display name or display name is just the email
            if not display_name or display_name == sender_email:
                # If we detected local part impersonation, return that result
                if score > 0:
                    results['spoofing_detected'] = True
                    results['spoofing_score'] = score
                    results['spoofing_type'] = spoofing_types
                    results['indicators'] = indicators
                return results

            # Extract domain from display name (if any)
            display_domain = self.extract_display_name_domain(display_name)
            results['display_domain'] = display_domain

            # ============================================================
            # CHECK 1: Recipient Domain Impersonation (HIGHEST PRIORITY)
            # ============================================================
            # Display name contains recipient's domain - major red flag
            if recipient_domains:
                for recipient_domain in recipient_domains:
                    # Check if display name contains recipient domain (full domain)
                    if recipient_domain in display_name.lower():
                        score += 8.0
                        spoofing_types.append('recipient_domain_impersonation')
                        indicators.append(f"Display name contains recipient domain: {recipient_domain}")
                        logger.warning(f"🚨 RECIPIENT DOMAIN IMPERSONATION: Display name '{display_name}' contains recipient domain {recipient_domain}")
                        break

                    # Also check if display name contains the base domain name (without TLD)
                    # This catches "Smallarmsreview" matching "smallarmsreview.com"
                    domain_base = recipient_domain.split('.')[0]  # Extract "smallarmsreview" from "smallarmsreview.com"
                    if len(domain_base) > 3 and domain_base in display_name.lower():
                        # Additional check: Is sender domain same as recipient but with random email address?
                        if sender_domain == recipient_domain:
                            # Check if sender email local part looks random/suspicious
                            sender_local = sender_email.split('@')[0] if '@' in sender_email else ''
                            if sender_local and self.looks_like_random_address(sender_local):
                                score += 7.0
                                spoofing_types.append('internal_spoofing_random_sender')
                                indicators.append(f"Display name '{display_name}' impersonates domain with random sender: {sender_local}@{sender_domain}")
                                logger.warning(f"🚨 INTERNAL SPOOFING: Display name '{display_name}' + random sender '{sender_local}' on domain {sender_domain}")
                                break

            # ============================================================
            # CHECK 2: Display Name Domain Mismatch
            # ============================================================
            # Display name contains a domain that doesn't match sender domain
            if display_domain and sender_domain:
                if display_domain != sender_domain:
                    score += 5.0
                    spoofing_types.append('domain_mismatch')
                    indicators.append(f"Display domain '{display_domain}' != sender domain '{sender_domain}'")
                    logger.warning(f"⚠️  DOMAIN MISMATCH: Display shows '{display_domain}' but sender is '{sender_domain}'")

            # ============================================================
            # CHECK 3: Executive Title + Domain Mismatch (BEC Indicator)
            # ============================================================
            has_exec_title = self.check_executive_title(display_name)
            if has_exec_title and display_domain and display_domain != sender_domain:
                score += 6.0
                spoofing_types.append('executive_impersonation')
                indicators.append(f"Executive title in display name with domain mismatch")
                logger.warning(f"🎯 BEC INDICATOR: Executive title with domain mismatch: '{display_name}'")
            elif has_exec_title:
                # Just having exec title adds small penalty
                score += 1.0
                indicators.append("Display name contains executive title")

            # ============================================================
            # CHECK 4: Brand Impersonation
            # ============================================================
            has_brand = self.check_brand_impersonation(display_name)
            if has_brand and sender_domain:
                # Check if sender domain is likely legitimate for that brand
                # (This is basic - could be enhanced with known domain list)
                score += 7.0
                spoofing_types.append('brand_impersonation')
                indicators.append(f"Brand name in display but sender domain is '{sender_domain}'")
                logger.warning(f"🏢 BRAND IMPERSONATION: Brand in display name: '{display_name}'")

            # ============================================================
            # CHECK 5: Unicode/Homograph Attacks
            # ============================================================
            if self.contains_unicode_tricks(display_name):
                score += 4.0
                spoofing_types.append('unicode_tricks')
                indicators.append("Unicode homograph characters detected")
                logger.warning(f"🔤 UNICODE TRICKS: Suspicious characters in '{display_name}'")

            # ============================================================
            # CHECK 6: Urgent Keywords (Amplifier)
            # ============================================================
            if self.check_urgent_keywords(display_name):
                # This alone isn't spoofing, but amplifies other issues
                if score > 0:
                    score += 2.0
                    indicators.append("Urgent/security keywords in display name")

            # ============================================================
            # CHECK 7: Empty Display Name with High-Risk Content
            # ============================================================
            # Sometimes spammers use empty display names
            if not display_name and sender_domain:
                # Check if sender domain is suspicious (very short, random-looking)
                if len(sender_domain) < 8 or self.looks_random(sender_domain):
                    score += 1.0
                    indicators.append("Empty display name with suspicious domain")

            # Set results
            if score > 0:
                results['spoofing_detected'] = True
                results['spoofing_score'] = round(score, 2)
                results['spoofing_type'] = spoofing_types
                results['indicators'] = indicators

            return results

        except Exception as e:
            logger.error(f"Error in display name spoofing detection: {e}", exc_info=True)
            return results

    def looks_random(self, domain: str) -> bool:
        """
        Check if domain looks randomly generated
        (High consonant/vowel ratio, repeated patterns, etc.)
        """
        try:
            # Remove TLD
            domain_name = domain.split('.')[0]

            # Check for very short domains
            if len(domain_name) < 4:
                return False  # Too short to judge

            # Count vowels and consonants
            vowels = 'aeiou'
            vowel_count = sum(1 for c in domain_name.lower() if c in vowels)
            consonant_count = sum(1 for c in domain_name.lower() if c.isalpha() and c not in vowels)

            # Random domains often have very few vowels
            if consonant_count > 0:
                vowel_ratio = vowel_count / consonant_count
                if vowel_ratio < 0.2:  # Less than 1 vowel per 5 consonants
                    return True

            # Check for repeated character patterns (like "revteh")
            for i in range(len(domain_name) - 2):
                pattern = domain_name[i:i+2]
                if domain_name.count(pattern) > 2:
                    return True

            return False

        except Exception:
            return False

    def looks_like_random_address(self, local_part: str) -> bool:
        """
        Check if email local part (before @) looks randomly generated
        Detects patterns like: MDlKH2zNEZWHWMf, xJ4k9pL2mN, etc.

        Indicators of random addresses:
        - Mix of upper/lower case in random pattern
        - High ratio of consonants to vowels
        - Contains numbers mixed with letters
        - No recognizable words or patterns
        - Length > 10 characters but looks random
        """
        try:
            if not local_part or len(local_part) < 6:
                return False

            # Normalize for analysis
            local_lower = local_part.lower()

            # Check 1: Mixed case randomness (alternating or random caps)
            # Random generators often produce strings like "MdLkH2zN"
            has_upper = any(c.isupper() for c in local_part)
            has_lower = any(c.islower() for c in local_part)
            has_digit = any(c.isdigit() for c in local_part)

            # If it has mixed case and is long, it's suspicious
            if has_upper and has_lower and len(local_part) > 10:
                # Count case transitions (like MdLkH has many transitions)
                transitions = 0
                for i in range(len(local_part) - 1):
                    if local_part[i].isalpha() and local_part[i+1].isalpha():
                        if local_part[i].isupper() != local_part[i+1].isupper():
                            transitions += 1
                # More than 3 case transitions in a short string is very suspicious
                if transitions > 3:
                    return True

            # Check 2: Very low vowel ratio (random strings have few vowels)
            vowels = 'aeiou'
            vowel_count = sum(1 for c in local_lower if c in vowels)
            consonant_count = sum(1 for c in local_lower if c.isalpha() and c not in vowels)

            if consonant_count > 4:
                vowel_ratio = vowel_count / consonant_count if consonant_count > 0 else 1
                # Less than 1 vowel per 4 consonants is suspicious
                if vowel_ratio < 0.25:
                    return True

            # Check 3: Numbers mixed with letters (like "2zN3W" pattern)
            if has_digit and len(local_part) > 8:
                # Count transitions between letters and numbers
                letter_number_transitions = 0
                for i in range(len(local_part) - 1):
                    if (local_part[i].isalpha() and local_part[i+1].isdigit()) or \
                       (local_part[i].isdigit() and local_part[i+1].isalpha()):
                        letter_number_transitions += 1
                # More than 2 letter-number transitions suggests random generation
                if letter_number_transitions > 2:
                    return True

            # Check 4: Very long with no recognizable patterns
            if len(local_part) > 15:
                # Long addresses are often random unless they contain dots or underscores
                if '.' not in local_part and '_' not in local_part and '-' not in local_part:
                    return True

            # Check 5: Contains common random string patterns
            # Base64-like patterns, hex-like patterns
            if len(local_part) > 12:
                # Check if it looks like base64 (lots of mixed case + numbers)
                alpha_numeric = sum(1 for c in local_part if c.isalnum())
                if alpha_numeric == len(local_part) and has_upper and has_lower and has_digit:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking random address: {e}")
            return False


def analyze_display_name_spoofing(msg, recipients: List[str] = None) -> Dict[str, Any]:
    """
    Main entry point for display name spoofing detection

    Args:
        msg: Email message object
        recipients: List of recipient email addresses (optional)

    Returns:
        Dict with analysis results including spoofing_score
    """
    if recipients is None:
        # Try to extract from message
        recipients = []
        for to_field in ['To', 'Cc']:
            to_header = msg.get(to_field, '')
            if to_header:
                # Simple extraction - just get email addresses
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', to_header)
                recipients.extend(emails)

    detector = DisplayNameSpoofingDetector()
    return detector.analyze(msg, recipients)


if __name__ == '__main__':
    # Test cases
    print("Display Name Spoofing Detector - Test Cases")
    print("=" * 60)

    # Would need actual email message objects to test
    # This is just a placeholder for manual testing
    pass
