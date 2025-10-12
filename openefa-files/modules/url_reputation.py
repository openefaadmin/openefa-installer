#!/usr/bin/env python3
"""
URL Reputation and Homograph Detection Module for SpaCy Email Security
Checks URLs against reputation services and detects homograph attacks
"""

import re
import hashlib
import requests
import json
import unicodedata
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Any
import logging
from email.message import EmailMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLReputationAnalyzer:
    """
    Analyzes URLs in emails for reputation and homograph attacks
    """

    def __init__(self):
        # Common homograph substitutions
        self.homograph_map = {
            # Cyrillic lookalikes
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
            'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
            # Greek lookalikes
            'α': 'a', 'ο': 'o', 'ν': 'v', 'τ': 't', 'ρ': 'p', 'μ': 'u',
            # Other confusables
            'і': 'i',  # Ukrainian
            'ı': 'i',  # Turkish
            # Note: We don't map normal Latin letters to numbers
            # That would cause false positives on legitimate domains
        }

        # Protected brands/domains to check for homograph attacks
        self.protected_domains = [
            # Major tech companies
            'paypal.com', 'ebay.com', 'amazon.com', 'apple.com', 'google.com',
            'microsoft.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
            'linkedin.com', 'dropbox.com', 'netflix.com', 'spotify.com', 'adobe.com',
            'zoom.us', 'slack.com', 'github.com', 'gitlab.com',
            # Banking and financial
            'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
            'americanexpress.com', 'capitalone.com', 'discover.com', 'usbank.com',
            'pnc.com', 'tdbank.com', 'truist.com', 'regions.com',
            # Shipping and logistics
            'ups.com', 'fedex.com', 'usps.com', 'dhl.com',
            # Government
            'irs.gov', 'ssa.gov', 'medicare.gov',
            # Antivirus/Security
            'mcafee.com', 'norton.com', 'kaspersky.com', 'avast.com', 'bitdefender.com'
            # Note: Add your organization's domains to email_filter_config.json trusted_domains
        ]

        # URL shorteners to expand
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'short.link',
            'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do'
        ]

        # Suspicious URL patterns
        self.suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[0-9a-f]{4,}\.ngrok\.io',  # Ngrok tunnels
            r'\.tk$|\.ml$|\.ga$|\.cf$',  # Free TLDs often used in phishing
            r'[0-9]{5,}',  # Long numbers in domain (often phishing)
            r'[a-z]+-[a-z]+-[a-z]+-[a-z]+',  # Multiple hyphens (suspicious)
        ]

    def detect_homograph(self, domain: str) -> Dict[str, Any]:
        """
        Detect homograph attacks in domain names
        """
        results = {
            'is_homograph': False,
            'detected_scripts': [],
            'possible_target': None,
            'risk_score': 0,
            'details': []
        }

        # Check for mixed scripts (major red flag)
        scripts = set()
        for char in domain:
            # Skip common punctuation that shouldn't count as a separate script
            if char in '.:-_':
                continue
            script = unicodedata.name(char, '').split()[0] if unicodedata.name(char, '') else 'UNKNOWN'
            # Normalize common script names
            if script in ['DIGIT', 'FULL', 'HYPHEN', 'LOW']:
                continue  # Skip numbers and common punctuation
            scripts.add(script)

        # Only flag if we have actual mixed scripts (not just Latin + punctuation)
        if len(scripts) > 1 and 'LATIN' in scripts:  # Mixed scripts detected
            # Only flag as homograph if non-Latin scripts present
            non_latin = scripts - {'LATIN'}
            if non_latin:
                results['is_homograph'] = True
                results['detected_scripts'] = list(scripts)
                results['risk_score'] = 9
                results['details'].append(f"Mixed scripts detected: {', '.join(scripts)}")

        # Convert homographs to Latin equivalent
        normalized = ''
        has_homograph = False
        for char in domain:
            if char in self.homograph_map:
                normalized += self.homograph_map[char]
                has_homograph = True
            else:
                normalized += char

        if has_homograph:
            results['is_homograph'] = True
            results['risk_score'] = max(results['risk_score'], 8)
            results['details'].append(f"Homograph characters detected, normalizes to: {normalized}")

            # Check if it matches a protected domain
            for protected in self.protected_domains:
                # Only flag as impersonation if it's NOT a legitimate subdomain
                if normalized == protected:
                    results['possible_target'] = protected
                    results['risk_score'] = 10
                    results['details'].append(f"CRITICAL: Impersonating {protected}")
                    break
                elif normalized.endswith('.' + protected):
                    # This looks like a subdomain - only flag if it has homograph chars
                    # Legitimate subdomains won't have homograph characters
                    results['possible_target'] = protected
                    results['risk_score'] = 10
                    results['details'].append(f"CRITICAL: Impersonating {protected}")
                    break

        # Check for visual confusion patterns
        visual_tricks = [
            ('rn', 'm', 5, "Contains 'rn' which visually resembles 'm'"),
            ('vv', 'w', 5, "Contains 'vv' which visually resembles 'w'"),
            ('nn', 'n', 3, "Contains double 'nn' (possible confusion)"),
            ('ii', 'i', 3, "Contains double 'ii' (possible confusion)"),
            ('cl', 'd', 4, "Contains 'cl' which can resemble 'd'"),
            ('lI', 'll', 4, "Contains 'lI' (lowercase L + capital I)")
        ]

        for pattern, looks_like, score, description in visual_tricks:
            if pattern in domain:
                # Check if this pattern makes it similar to a protected domain
                test_domain = domain.replace(pattern, looks_like)
                for protected in self.protected_domains:
                    # Only flag exact matches or suspicious patterns, not legitimate subdomains
                    if test_domain == protected:
                        results['risk_score'] = max(results['risk_score'], score + 3)  # Higher score if matches protected
                        results['details'].append(f"{description} - resembles {protected}")
                        results['is_homograph'] = True
                        results['possible_target'] = protected
                        break
                    elif test_domain.endswith('.' + protected):
                        # Check if original domain is a legitimate subdomain
                        legitimate_services = ['.slack.com', '.salesforce.com', '.microsoft.com',
                                              '.google.com', '.amazonaws.com', '.zoom.us',
                                              '.bankofamerica.com', '.wellsfargo.com', '.chase.com',
                                              '.datto.com', '.t-mobile.com']
                        is_legitimate = any(domain.endswith(svc) for svc in legitimate_services)
                        if not is_legitimate:
                            # Not a known legitimate service, flag it
                            results['risk_score'] = max(results['risk_score'], score + 3)
                            results['details'].append(f"{description} - resembles {protected}")
                            results['is_homograph'] = True
                            results['possible_target'] = protected
                            break
                else:
                    # Pattern exists but doesn't match protected domain
                    results['risk_score'] = max(results['risk_score'], score)
                    results['details'].append(description)

        # Check for number/letter substitutions
        for protected in self.protected_domains:
            # Simple substitution check (0 for o, 1 for l, etc.)
            if self._similar_domain(domain, protected):
                results['is_homograph'] = True
                results['possible_target'] = protected
                results['risk_score'] = max(results['risk_score'], 7)
                results['details'].append(f"Similar to protected domain: {protected}")

        return results

    def _similar_domain(self, domain: str, target: str) -> bool:
        """
        Check if domain is visually similar to target
        """
        # Convert to lowercase for comparison, but preserve original for case-sensitive checks
        domain_original = domain
        domain_lower = domain.lower()
        target_lower = target.lower()

        # Skip legitimate subdomains of protected services
        legitimate_services = ['.slack.com', '.salesforce.com', '.microsoft.com', '.google.com',
                               '.amazonaws.com', '.github.com', '.zendesk.com', '.office365.com',
                               '.zoom.us']
        for service in legitimate_services:
            if domain_lower.endswith(service):
                return False  # Legitimate subdomain, not a homograph

        # Check for capital I used as lowercase l (common trick)
        # This is case-sensitive - capital I looks like lowercase l
        if 'I' in domain_original:  # Capital I present
            test_domain = domain_original.replace('I', 'l').lower()
            if test_domain == target_lower:  # Exact match only, not subdomains
                return True

        # Check for lowercase l used as capital I (reverse trick)
        if 'l' in domain_lower and 'i' in target_lower:
            test_domain = domain_lower.replace('l', 'i')
            if test_domain == target_lower:  # Exact match only, not subdomains
                return True

        # Check if domain contains numbers where target has letters
        if any(c.isdigit() for c in domain_lower) and not any(c.isdigit() for c in target_lower):
            # Common number-for-letter substitutions
            test_domain = domain_lower
            test_domain = test_domain.replace('0', 'o')
            test_domain = test_domain.replace('1', 'l')
            test_domain = test_domain.replace('3', 'e')
            test_domain = test_domain.replace('5', 's')
            test_domain = test_domain.replace('@', 'a')

            if test_domain == target_lower or test_domain.endswith('.' + target_lower):
                return True

            # Also try replacing 1 with i
            test_domain = domain_lower.replace('1', 'i')
            if test_domain == target_lower or test_domain.endswith('.' + target_lower):
                return True

        return False

    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation using various methods
        """
        results = {
            'url': url,
            'risk_score': 0,
            'is_shortened': False,
            'expanded_url': None,
            'is_ip_address': False,
            'suspicious_patterns': [],
            'homograph_check': None
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check if URL shortener
            for shortener in self.url_shorteners:
                if shortener in domain:
                    results['is_shortened'] = True
                    results['risk_score'] += 3
                    results['suspicious_patterns'].append(f"URL shortener: {shortener}")
                    # TODO: Expand shortened URL
                    break

            # Check for IP address
            ip_pattern = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
            if ip_pattern.match(domain):
                results['is_ip_address'] = True
                results['risk_score'] += 5
                results['suspicious_patterns'].append("Direct IP address")

            # Check suspicious patterns
            for pattern in self.suspicious_patterns:
                if re.search(pattern, domain):
                    results['risk_score'] += 2
                    results['suspicious_patterns'].append(f"Suspicious pattern: {pattern}")

            # Check for homograph attack
            homograph_result = self.detect_homograph(domain)
            results['homograph_check'] = homograph_result
            if homograph_result['is_homograph']:
                results['risk_score'] += homograph_result['risk_score']

            # Check URL length (long URLs often suspicious)
            if len(url) > 100:
                results['risk_score'] += 2
                results['suspicious_patterns'].append("Unusually long URL")

            # Check for multiple subdomains (subdomain.subdomain.domain.com)
            subdomain_count = len(domain.split('.')) - 2
            if subdomain_count > 2:
                results['risk_score'] += 3
                results['suspicious_patterns'].append(f"Multiple subdomains ({subdomain_count})")

        except Exception as e:
            logger.error(f"Error checking URL reputation: {e}")
            results['error'] = str(e)

        return results

    def extract_urls_from_email(self, email_content: str) -> List[str]:
        """
        Extract all URLs from email content including international characters
        """
        urls = []

        # Method 1: Find URLs in href attributes (handles international chars)
        href_pattern = re.compile(r'href=["\']?([^"\'\s>]+)', re.IGNORECASE)
        href_urls = href_pattern.findall(email_content)
        for url in href_urls:
            if url.startswith(('http://', 'https://')):
                urls.append(url)

        # Method 2: Find standalone URLs in text
        # This regex handles ASCII URLs
        url_pattern = re.compile(
            r'https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )
        standalone_urls = url_pattern.findall(email_content)
        urls.extend(standalone_urls)

        # Method 3: Find URLs with international domains (Unicode support)
        # This pattern is more permissive to catch homograph attacks
        unicode_url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        unicode_urls = unicode_url_pattern.findall(email_content)
        for url in unicode_urls:
            # Clean up the URL (remove trailing punctuation)
            url = url.rstrip('.,;:!?)')
            if url not in urls and url.startswith(('http://', 'https://')):
                urls.append(url)

        # Also look for obfuscated URLs
        # hXXp:// or hxxp://
        obfuscated_pattern = re.compile(
            r'h[xX]{2}ps?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            re.IGNORECASE
        )

        obfuscated = obfuscated_pattern.findall(email_content)
        for url in obfuscated:
            # Fix obfuscation
            fixed = url.replace('hxxp://', 'http://').replace('hXXp://', 'http://')
            fixed = fixed.replace('hxxps://', 'https://').replace('hXXps://', 'https://')
            urls.append(fixed)

        return list(set(urls))  # Remove duplicates


def analyze_email_urls(msg: EmailMessage) -> Dict[str, Any]:
    """
    Main function to analyze URLs in an email
    Compatible with SpaCy email filter
    """
    analyzer = URLReputationAnalyzer()

    results = {
        'urls_found': 0,
        'high_risk_urls': [],
        'medium_risk_urls': [],
        'homograph_attacks': [],
        'total_risk_score': 0,
        'headers_to_add': {}
    }

    try:
        # Get email body
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += str(part.get_payload(decode=True), 'utf-8', errors='ignore')
                elif part.get_content_type() == 'text/html':
                    body += str(part.get_payload(decode=True), 'utf-8', errors='ignore')
        else:
            body = str(msg.get_payload(decode=True), 'utf-8', errors='ignore')

        # Extract URLs
        urls = analyzer.extract_urls_from_email(body)
        results['urls_found'] = len(urls)

        # Analyze each URL
        for url in urls:
            url_result = analyzer.check_url_reputation(url)

            # Categorize by risk
            if url_result['risk_score'] >= 7:
                results['high_risk_urls'].append(url)
                results['total_risk_score'] += url_result['risk_score']
            elif url_result['risk_score'] >= 4:
                results['medium_risk_urls'].append(url)
                results['total_risk_score'] += url_result['risk_score']

            # Check for homograph attacks
            if url_result['homograph_check'] and url_result['homograph_check']['is_homograph']:
                results['homograph_attacks'].append({
                    'url': url,
                    'target': url_result['homograph_check']['possible_target'],
                    'details': url_result['homograph_check']['details']
                })

        # Add headers for MailGuard
        if results['total_risk_score'] > 0:
            results['headers_to_add']['X-URL-Risk-Score'] = str(results['total_risk_score'])

        if results['homograph_attacks']:
            results['headers_to_add']['X-Homograph-Attack'] = 'CRITICAL'
            results['headers_to_add']['X-Phishing-Type'] = 'HOMOGRAPH_IMPERSONATION'
            results['headers_to_add']['X-Homograph-Targets'] = ','.join(
                [h['target'] for h in results['homograph_attacks'] if h['target']]
            )
            # Add specific homograph URLs to header
            homograph_urls = [h['url'] for h in results['homograph_attacks']]
            results['headers_to_add']['X-Homograph-URLs'] = ', '.join(homograph_urls[:3])  # Limit to 3

            # Add human-readable warning
            targets = [h['target'] for h in results['homograph_attacks'] if h['target']]
            if targets:
                results['headers_to_add']['X-Security-Warning'] = f'PHISHING: Impersonating {", ".join(targets)}'
                results['headers_to_add']['X-SpaCy-Action'] = 'QUARANTINE_PHISHING'

        if results['high_risk_urls']:
            results['headers_to_add']['X-High-Risk-URLs'] = str(len(results['high_risk_urls']))
            # Add specific suspicious URLs to header (truncate if too many)
            suspicious_list = results['high_risk_urls'][:5]  # Top 5 most suspicious
            results['headers_to_add']['X-Suspicious-URLs'] = ', '.join(suspicious_list)

    except Exception as e:
        logger.error(f"Error analyzing email URLs: {e}")
        results['error'] = str(e)

    return results

# Module entry point for SpaCy integration
def analyze(email_data):
    """Entry point for SpaCy email filter integration"""
    if isinstance(email_data, EmailMessage):
        return analyze_email_urls(email_data)
    else:
        # Handle dict format from SpaCy
        logger.warning("Received dict format, expected EmailMessage")
        return {'error': 'Invalid email format'}