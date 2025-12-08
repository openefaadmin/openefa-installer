#!/usr/bin/env python3
"""
HTML Email Body Analysis Module for OpenEFA Email Security
Detects phishing, credential theft, and manipulation in HTML email bodies

CAPABILITIES:
- Credential theft form detection in email body
- CSS-based hiding/obfuscation detection
- Brand impersonation detection
- Hidden text (zero-font, white-on-white)
- Suspicious JavaScript in email body
- Invisible iframes and tracking
- Unicode homograph attacks
- Link manipulation detection
- Off-screen positioning tricks

IMPORTANT: This analyzes the HTML EMAIL BODY, not attachments
NOTE: Complements html_attachment_analyzer.py

Author: OpenEFA Team
Created: 2025-11-14
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from email.message import EmailMessage
from urllib.parse import urlparse
import unicodedata

# HTML parsing imports
try:
    from bs4 import BeautifulSoup, NavigableString
    import lxml
    HTML_ANALYSIS_AVAILABLE = True
except ImportError as e:
    HTML_ANALYSIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class HTMLBodyAnalyzer:
    """
    Analyzes HTML email body for phishing and manipulation:
    - Credential theft forms (fake login pages)
    - CSS-based hiding and obfuscation
    - Brand impersonation
    - Hidden/invisible content
    - Link manipulation
    - Unicode homograph attacks
    """

    def __init__(self):
        # Brand names commonly impersonated
        self.impersonated_brands = {
            'microsoft': [
                'microsoft', 'office', 'o365', 'office365', 'outlook',
                'onedrive', 'sharepoint', 'teams', 'azure', 'live.com'
            ],
            'google': [
                'google', 'gmail', 'drive', 'docs', 'workspace', 'chrome'
            ],
            'apple': [
                'apple', 'icloud', 'itunes', 'app store', 'apple id'
            ],
            'paypal': [
                'paypal', 'pay pal'
            ],
            'banking': [
                'chase', 'bank of america', 'wells fargo', 'citibank',
                'us bank', 'capital one', 'discover', 'american express'
            ],
            'docusign': [
                'docusign', 'document sign', 'e-signature', 'digital signature'
            ],
            'amazon': [
                'amazon', 'aws', 'prime'
            ],
            'shipping': [
                'fedex', 'ups', 'usps', 'dhl', 'shipping'
            ]
        }

        # Legitimate domains for each brand (including subdomains and tracking services)
        # Used to verify sender authenticity and link destinations
        self.brand_legitimate_domains = {
            'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com',
                         'azure.com', 'microsoftonline.com', 'sharepoint.com', 'onedrive.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com',
                      'gstatic.com', 'googleusercontent.com'],
            'apple': ['apple.com', 'icloud.com', 'itunes.com', 'me.com'],
            'paypal': ['paypal.com', 'paypalobjects.com'],
            'amazon': ['amazon.com', 'amazonses.com', 'awstrack.me', 'amazonaws.com',
                      'aws.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca'],
            'docusign': ['docusign.com', 'docusign.net'],
            'shipping': ['fedex.com', 'ups.com', 'usps.com', 'dhl.com'],
            'banking': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
                       'capitalone.com', 'discover.com', 'americanexpress.com']
        }

        # Known legitimate email tracking/marketing service domains
        # These are used by legitimate senders for click tracking
        self.legitimate_tracking_domains = [
            # Major email service providers
            'sendgrid.net', 'sendgrid.com',
            'mailchimp.com', 'list-manage.com', 'mcusercontent.com',
            'constantcontact.com', 'ctctcdn.com',
            'hubspot.com', 'hubspotlinks.com', 'hs-analytics.net',
            'mailgun.com', 'mailgun.org',
            'postmarkapp.com',
            'sparkpost.com', 'sparkpostmail.com',
            'sendinblue.com', 'sibautomation.com',
            'klaviyo.com',
            'activecampaign.com',
            'aweber.com',
            'getresponse.com',
            'convertkit.com',
            'drip.com',
            'campaignmonitor.com', 'cmail19.com', 'cmail20.com',
            'emma.com', 'e2ma.net',
            'salesforce.com', 'exacttarget.com',
            'marketo.com', 'mktoweb.com',
            'eloqua.com',
            # Amazon specific
            'awstrack.me', 'amazonses.com', 'amazonaws.com',
            # Google specific
            'google.com', 'goog', 'googlemail.com',
            # Microsoft specific
            'protection.outlook.com', 'microsoftonline.com',
            # Generic tracking subdomains (partial matches)
            'click.', 'track.', 'link.', 'go.', 'email.', 'e.', 'links.',
            'trk.', 'r.', 'ct.', 'url.', 'emltrk.',
        ]

        # Credential theft indicators
        self.credential_keywords = [
            'password', 'passwd', 'pwd', 'pass',
            'username', 'user', 'email', 'login',
            'signin', 'sign-in', 'account',
            'verify', 'confirm', 'authenticate',
            'security code', '2fa', 'otp'
        ]

        # Score weights
        self.scores = {
            'credential_form': 8.0,          # Login form in email body
            'hidden_content': 5.0,           # CSS-based hiding
            'brand_impersonation': 6.0,      # Fake brand with external link
            'invisible_iframe': 7.0,         # Hidden iframe
            'suspicious_javascript': 4.0,    # Obfuscated JS
            'link_manipulation': 5.0,        # Display text != actual link
            'unicode_homograph': 6.0,        # Lookalike domains
            'unicode_homograph_body': 10.0,  # Lookalike chars in body text (phishing obfuscation)
            'tracking_pixel': 1.0,           # 1x1 image
            'form_external_action': 5.0,     # Form posts to external site
            'css_obfuscation': 4.0,          # Advanced CSS hiding tricks
        }

    def analyze(self, msg: EmailMessage) -> Dict[str, Any]:
        """
        Analyze HTML email body for phishing and manipulation

        Returns:
            {
                'spam_score': float,
                'issues': List[str],
                'forms_detected': int,
                'hidden_elements': List[str],
                'brand_impersonation': List[str],
                'link_manipulation': List[str],
                'unicode_attacks': List[str]
            }
        """

        # OPTION 3: Respect trusted internal senders
        # Add your internal notification addresses here
        from_header = msg.get('From', '').lower()
        trusted_senders = [
            # 'noreply@yourdomain.com',  # Example: Internal digest emails
        ]

        for trusted_sender in trusted_senders:
            if trusted_sender in from_header:
                logger.info(f"Skipping HTML body analysis for trusted sender: {from_header}")
                return {
                    'spam_score': 0.0,
                    'analysis_available': True,
                    'issues': [],
                    'trusted_sender': True
                }

        # Extract sender domain for brand verification
        sender_domain = self._extract_sender_domain(from_header)

        if not HTML_ANALYSIS_AVAILABLE:
            logger.warning("HTML analysis libraries not available (beautifulsoup4, lxml)")
            return {
                'spam_score': 0.0,
                'analysis_available': False,
                'error': 'HTML libraries not installed'
            }

        # Extract HTML body
        html_body = self._extract_html_body(msg)
        if not html_body:
            return {
                'spam_score': 0.0,
                'analysis_available': True,
                'issues': [],
                'no_html_body': True
            }

        try:
            soup = BeautifulSoup(html_body, 'lxml')

            spam_score = 0.0
            issues = []

            # 1. Detect credential theft forms
            form_results = self._analyze_forms(soup)
            if form_results['credential_forms']:
                spam_score += self.scores['credential_form']
                issues.append(f"credential_form_detected: {form_results['credential_forms']} form(s)")
            if form_results['external_forms']:
                spam_score += self.scores['form_external_action']
                issues.append(f"external_form_action: {form_results['external_forms']} form(s)")

            # 2. Detect CSS-based hiding
            hidden_results = self._detect_css_hiding(soup, html_body)
            if hidden_results['hidden_count'] > 0:
                spam_score += self.scores['hidden_content']
                issues.extend(hidden_results['techniques'])

            # 3. Detect brand impersonation with external links
            brand_results = self._detect_brand_impersonation(soup, html_body, sender_domain)
            if brand_results['impersonations']:
                spam_score += self.scores['brand_impersonation']
                for brand in brand_results['impersonations']:
                    issues.append(f"brand_impersonation: {brand}")

            # 4. Detect invisible iframes
            iframe_results = self._detect_hidden_iframes(soup)
            if iframe_results['hidden_iframes']:
                spam_score += self.scores['invisible_iframe']
                issues.append(f"hidden_iframes: {iframe_results['hidden_iframes']} found")

            # 5. Analyze JavaScript
            js_results = self._analyze_javascript(soup, html_body)
            if js_results['suspicious_js']:
                spam_score += self.scores['suspicious_javascript']
                issues.append(f"suspicious_javascript: {js_results['suspicious_js']} patterns")

            # 6. Detect link manipulation
            link_results = self._detect_link_manipulation(soup)
            if link_results['manipulated_links']:
                spam_score += self.scores['link_manipulation']
                for link_issue in link_results['manipulated_links'][:3]:  # Limit to 3
                    issues.append(f"link_manipulation: {link_issue}")

            # 7. Detect Unicode homograph attacks (links and body text)
            unicode_results = self._detect_unicode_homographs(soup)
            if unicode_results['homographs']:
                spam_score += self.scores['unicode_homograph']
                for homograph in unicode_results['homographs'][:2]:  # Limit to 2
                    issues.append(f"unicode_homograph: {homograph}")

            # 7b. Detect homograph obfuscation in body text (phishing technique)
            if unicode_results.get('has_body_homoglyphs', False):
                spam_score += self.scores['unicode_homograph_body']
                for body_issue in unicode_results.get('body_homographs', [])[:2]:
                    issues.append(f"unicode_homograph_body: {body_issue}")

            # 8. Detect tracking pixels
            tracking_results = self._detect_tracking_pixels(soup)
            if tracking_results['tracking_pixels'] > 2:  # Allow 1-2 for legitimate emails
                spam_score += self.scores['tracking_pixel']
                issues.append(f"tracking_pixels: {tracking_results['tracking_pixels']} found")

            return {
                'spam_score': round(spam_score, 2),
                'analysis_available': True,
                'issues': issues,
                'forms_detected': form_results['total_forms'],
                'credential_forms': form_results['credential_forms'],
                'hidden_elements': hidden_results['techniques'],
                'brand_impersonation': brand_results['impersonations'],
                'link_manipulation': link_results['manipulated_links'],
                'unicode_attacks': unicode_results['homographs'],
                'body_homographs': unicode_results.get('body_homographs', []),
                'tracking_pixels': tracking_results['tracking_pixels']
            }

        except Exception as e:
            logger.error(f"HTML body analysis error: {e}")
            return {
                'spam_score': 0.0,
                'analysis_available': False,
                'error': str(e)
            }

    def _extract_html_body(self, msg: EmailMessage) -> Optional[str]:
        """Extract HTML body from email message"""
        html_body = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/html':
                    try:
                        html_body = part.get_content()
                        break
                    except Exception as e:
                        logger.debug(f"Could not extract HTML body: {e}")
        else:
            # Single part message
            if msg.get_content_type() == 'text/html':
                try:
                    html_body = msg.get_content()
                except Exception as e:
                    logger.debug(f"Could not extract HTML body: {e}")

        return html_body

    def _extract_sender_domain(self, from_header: str) -> Optional[str]:
        """Extract the domain from From header for brand verification"""
        try:
            # Handle formats like "Name <email@domain.com>" or "email@domain.com"
            if '<' in from_header and '>' in from_header:
                email = from_header.split('<')[1].split('>')[0]
            else:
                email = from_header.strip()

            if '@' in email:
                return email.split('@')[1].lower()
        except Exception as e:
            logger.debug(f"Could not extract sender domain: {e}")
        return None

    def _is_legitimate_tracking_domain(self, domain: str) -> bool:
        """Check if a domain is a known legitimate email tracking service"""
        domain_lower = domain.lower()
        for tracking_domain in self.legitimate_tracking_domains:
            # Exact match or subdomain match
            if domain_lower == tracking_domain or domain_lower.endswith('.' + tracking_domain):
                return True
            # Partial match for subdomain patterns (e.g., 'click.', 'track.')
            if tracking_domain.endswith('.') and tracking_domain in domain_lower:
                return True
        return False

    def _is_brand_legitimate_domain(self, domain: str, brand_category: str) -> bool:
        """Check if a domain is a legitimate domain for the given brand"""
        if brand_category not in self.brand_legitimate_domains:
            return False

        domain_lower = domain.lower()
        for legit_domain in self.brand_legitimate_domains[brand_category]:
            # Exact match or subdomain match (e.g., sellercentral.amazon.com matches amazon.com)
            if domain_lower == legit_domain or domain_lower.endswith('.' + legit_domain):
                return True
        return False

    def _sender_matches_brand(self, sender_domain: Optional[str], brand_category: str) -> bool:
        """Check if the sender domain matches the brand being mentioned"""
        if not sender_domain:
            return False

        # Check if sender domain is a legitimate domain for this brand
        return self._is_brand_legitimate_domain(sender_domain, brand_category)

    def _analyze_forms(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect credential theft forms in email body"""
        forms = soup.find_all('form')
        credential_forms = 0
        external_forms = 0

        for form in forms:
            # Check for password fields
            password_fields = form.find_all('input', {'type': 'password'})

            # Check for credential-related input fields by name/id
            credential_inputs = form.find_all('input', {'name': re.compile(
                r'password|passwd|pwd|email|username|user|login|signin', re.IGNORECASE
            )})

            # Also check by id attribute
            credential_inputs_by_id = form.find_all('input', {'id': re.compile(
                r'password|passwd|pwd|email|username|user|login|signin', re.IGNORECASE
            )})

            total_credential_inputs = len(set(credential_inputs) | set(credential_inputs_by_id))

            # Credential form if it has password field OR multiple credential-related fields
            # This avoids flagging simple newsletter signup forms (just email + submit)
            if len(password_fields) > 0 or total_credential_inputs >= 2:
                credential_forms += 1

            # Check if form posts to external domain
            action = form.get('action', '')
            if action and (action.startswith('http://') or action.startswith('https://')):
                external_forms += 1

        return {
            'total_forms': len(forms),
            'credential_forms': credential_forms,
            'external_forms': external_forms
        }

    def _detect_css_hiding(self, soup: BeautifulSoup, html_text: str) -> Dict[str, Any]:
        """
        Detect CSS-based hiding techniques.

        Improvements (2025-12-01):
        - Exempt standard email preview text patterns (display:none + small font + max-height:0)
        - Exempt common responsive email design patterns
        - Focus on truly suspicious hiding (content meant to deceive)
        """
        hidden_count = 0
        techniques = []

        # Check if this looks like standard email preview text pattern
        # Preview text is a legitimate technique: hidden div at top with small/zero font
        # Pattern: display:none + (opacity:0 OR max-height:0 OR font-size:1px)
        preview_text_pattern = r'(?:display\s*:\s*none|mso-hide\s*:\s*all)[^}]*(?:opacity\s*:\s*0|max-height\s*:\s*0|font-size\s*:\s*1px|overflow\s*:\s*hidden)'
        has_preview_text = bool(re.search(preview_text_pattern, html_text, re.IGNORECASE | re.DOTALL))

        # Also check for common preview-text class names
        preview_classes = ['preview-text', 'preheader', 'preview', 'hidden-preheader']
        has_preview_class = any(
            soup.find(class_=re.compile(cls, re.IGNORECASE)) for cls in preview_classes
        )

        is_likely_preview_text = has_preview_text or has_preview_class

        # 1. Zero or near-zero font size
        # EXEMPT: If it's part of preview text pattern, skip this check
        if not is_likely_preview_text:
            zero_font_pattern = r'font-size\s*:\s*0(?:px|pt|em)?(?!\d)'  # Avoid matching font-size: 0.9em etc.
            # Check if zero font is used in a suspicious context (not in a preview div)
            zero_font_elements = soup.find_all(style=re.compile(r'font-size\s*:\s*0(?:px|pt|em)?(?!\d)', re.IGNORECASE))
            # Filter out elements that look like preview text
            suspicious_zero_font = [
                el for el in zero_font_elements
                if not any(cls in str(el.get('class', [])).lower() for cls in ['preview', 'preheader', 'hidden'])
                and len(el.get_text(strip=True)) > 50  # Only flag if there's substantial hidden text
            ]
            if suspicious_zero_font:
                hidden_count += 1
                techniques.append('css_hiding: zero_font_size (suspicious context)')

        # 2. White text on white background
        # This is less common in legitimate emails - keep detection but check context
        white_on_white_patterns = [
            r'color\s*:\s*(?:#fff|#ffffff|white)[^}]*background(?:-color)?\s*:\s*(?:#fff|#ffffff|white)',
            r'background(?:-color)?\s*:\s*(?:#fff|#ffffff|white)[^}]*color\s*:\s*(?:#fff|#ffffff|white)'
        ]
        for pattern in white_on_white_patterns:
            matches = re.findall(pattern, html_text, re.IGNORECASE | re.DOTALL)
            # Only flag if there's substantial content with white-on-white (not just styling)
            if matches and len(matches) > 2:  # More than 2 occurrences is suspicious
                hidden_count += 1
                techniques.append('css_hiding: white_on_white (multiple occurrences)')
                break

        # 3. Off-screen positioning - only flag if significant content is hidden
        # Skip this check for now as it has high false positive rate in legitimate emails
        # offscreen_patterns = [...]

        # 4. Display none or visibility hidden
        # INCREASED threshold and added context checks
        hidden_style_pattern = r'(?:display\s*:\s*none|visibility\s*:\s*hidden)'
        hidden_elements = soup.find_all(style=re.compile(hidden_style_pattern, re.IGNORECASE))

        # Filter out common legitimate hidden elements
        suspicious_hidden = []
        for el in hidden_elements:
            # Skip if it's likely preview text or responsive design
            el_class = str(el.get('class', [])).lower()
            el_id = str(el.get('id', '')).lower()

            if any(pattern in el_class or pattern in el_id for pattern in
                   ['preview', 'preheader', 'mobile', 'desktop', 'responsive', 'hidden-', 'mso-', 'outlook']):
                continue

            # Skip if element has minimal content
            content = el.get_text(strip=True)
            if len(content) < 20:
                continue

            suspicious_hidden.append(el)

        # Only flag if there are many suspicious hidden elements
        if len(suspicious_hidden) > 10:
            hidden_count += 1
            techniques.append(f'css_hiding: {len(suspicious_hidden)} suspicious hidden elements')

        # 5. Opacity zero - EXEMPT preview text patterns
        if not is_likely_preview_text:
            # Check for opacity:0 with substantial hidden content
            opacity_elements = soup.find_all(style=re.compile(r'opacity\s*:\s*0(?:\.0+)?(?![1-9])', re.IGNORECASE))
            suspicious_opacity = [
                el for el in opacity_elements
                if len(el.get_text(strip=True)) > 50
                and not any(cls in str(el.get('class', [])).lower() for cls in ['preview', 'preheader'])
            ]
            if suspicious_opacity:
                hidden_count += 1
                techniques.append('css_hiding: opacity_zero (suspicious context)')

        return {
            'hidden_count': hidden_count,
            'techniques': techniques
        }

    def _detect_brand_impersonation(self, soup: BeautifulSoup, html_text: str, sender_domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect brand impersonation with external links.

        Improvements (2025-12-01):
        1. Check if sender domain matches the brand (skip if legitimate sender)
        2. Whitelist known tracking/marketing service domains
        3. Recognize legitimate subdomains of brands (e.g., sellercentral.amazon.com)
        4. Require stronger credential context for flagging
        """
        impersonations = []

        # Get all text content
        body_text = soup.get_text().lower()

        # Check if email has STRONG credential-related context (indicates potential phishing)
        # Made more restrictive to reduce false positives on transactional emails
        strong_credential_keywords = [
            'password', 'login', 'signin', 'sign-in',
            'suspended', 'locked', 'security alert',
            'unusual activity', 'verify identity', 'unauthorized',
            'expire', 'deactivate', 'reactivate'
        ]

        # Weaker context words that are common in legitimate transactional emails
        # These alone should NOT trigger brand impersonation checks
        weak_context_keywords = ['account', 'verify', 'confirm', 'click here']

        has_strong_credential_context = any(kw in body_text for kw in strong_credential_keywords)

        # Only flag brand impersonation if there's STRONG credential/urgency context
        # This avoids false positives on legitimate order notifications, shipping updates, etc.
        if not has_strong_credential_context:
            return {'impersonations': []}

        # Check for brand mentions with credential context
        for brand_category, keywords in self.impersonated_brands.items():
            # IMPROVEMENT #4: Skip if sender domain matches this brand
            if self._sender_matches_brand(sender_domain, brand_category):
                logger.debug(f"Skipping brand impersonation check for {brand_category} - sender {sender_domain} is legitimate")
                continue

            for keyword in keywords:
                if keyword in body_text:
                    # Check if there are links to domains NOT matching the brand
                    links = soup.find_all('a', href=True)
                    suspicious_link_found = False

                    for link in links:
                        href = link['href'].lower()

                        # Skip non-http links
                        if not (href.startswith('http://') or href.startswith('https://')):
                            continue

                        link_domain = urlparse(href).netloc

                        # Skip empty domains
                        if not link_domain:
                            continue

                        # IMPROVEMENT #2: Check if link is to a legitimate domain for this brand
                        if self._is_brand_legitimate_domain(link_domain, brand_category):
                            continue

                        # IMPROVEMENT #1: Skip if link is to a known tracking service
                        if self._is_legitimate_tracking_domain(link_domain):
                            continue

                        # Simple keyword check in domain (original logic, as fallback)
                        if keyword in link_domain:
                            continue

                        # If we get here, this is a suspicious link
                        impersonations.append(f"{brand_category} mentioned but link to {link_domain}")
                        suspicious_link_found = True
                        break

                    if suspicious_link_found:
                        break  # Found suspicious link for this brand, move to next brand

        return {
            'impersonations': list(set(impersonations))[:3]  # Limit to 3 unique
        }

    def _detect_hidden_iframes(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect invisible iframes"""
        iframes = soup.find_all('iframe')
        hidden_iframes = 0

        for iframe in iframes:
            # Check for hidden attributes
            width = iframe.get('width', '100')
            height = iframe.get('height', '100')
            style = iframe.get('style', '')

            # Hidden if width/height is 0 or very small
            try:
                if (str(width).rstrip('px') == '0' or
                    str(height).rstrip('px') == '0' or
                    int(str(width).rstrip('px%')) < 5 or
                    int(str(height).rstrip('px%')) < 5):
                    hidden_iframes += 1
                    continue
            except (ValueError, AttributeError):
                pass

            # Hidden via CSS
            if 'display:none' in style or 'visibility:hidden' in style:
                hidden_iframes += 1

        return {
            'hidden_iframes': hidden_iframes
        }

    def _analyze_javascript(self, soup: BeautifulSoup, html_text: str) -> Dict[str, Any]:
        """Analyze JavaScript for suspicious patterns"""
        suspicious_js = 0

        # Patterns indicating obfuscation or malicious behavior
        suspicious_patterns = [
            r'eval\s*\(',                    # eval() often used for obfuscation
            r'unescape\s*\(',                # unescape() for obfuscation
            r'fromCharCode\s*\(',            # Character code obfuscation
            r'document\.write\s*\(',         # Dynamic content injection
            r'window\.location\s*=',         # Redirection
            r'atob\s*\(',                    # Base64 decode (obfuscation)
            r'exec\s*\(',                    # Code execution
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, html_text, re.IGNORECASE):
                suspicious_js += 1

        return {
            'suspicious_js': suspicious_js
        }

    def _detect_link_manipulation(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect links where display text doesn't match actual URL"""
        manipulated_links = []

        # Known legitimate tracking/redirect domains (newsletters, marketing)
        legitimate_tracking_domains = [
            'convertkit', 'mailchimp', 'sendgrid', 'constantcontact',
            'hubspot', 'activecampaign', 'aweber', 'getresponse',
            'mailerlite', 'campaignmonitor', 'sendinblue', 'drip',
            'klaviyo', 'omnisend', 'moosend', 'emailoctopus',
            'click.', 'link.', 'go.', 'track.', 'email.',  # Common tracking subdomains
        ]

        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            display_text = link.get_text(strip=True)

            # Skip empty links or anchor links
            if not display_text or href.startswith('#') or href.startswith('mailto:'):
                continue

            # Check if display text looks like a URL but doesn't match href
            if re.match(r'https?://', display_text, re.IGNORECASE):
                display_domain = urlparse(display_text).netloc
                href_domain = urlparse(href).netloc

                if display_domain and href_domain and display_domain != href_domain:
                    # Skip if href domain is a known tracking service
                    is_legitimate_tracking = any(
                        tracker in href_domain.lower()
                        for tracker in legitimate_tracking_domains
                    )

                    if not is_legitimate_tracking:
                        manipulated_links.append(f"shows '{display_domain}' but links to '{href_domain}'")

        return {
            'manipulated_links': manipulated_links[:5]  # Limit to 5
        }

    def _detect_unicode_homographs(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect Unicode homograph attacks (lookalike characters) in links AND body text"""
        homographs = []
        body_homographs = []

        # Known homograph pairs (Cyrillic, Greek, etc. that look like Latin)
        # These are characters that look identical/similar to Latin letters but are from other scripts
        suspicious_chars = {
            'а': 'a',  # Cyrillic 'a' (U+0430)
            'А': 'A',  # Cyrillic 'A' (U+0410)
            'е': 'e',  # Cyrillic 'e' (U+0435)
            'Е': 'E',  # Cyrillic 'E' (U+0415)
            'о': 'o',  # Cyrillic 'o' (U+043E)
            'О': 'O',  # Cyrillic 'O' (U+041E)
            'р': 'p',  # Cyrillic 'p' (U+0440)
            'Р': 'P',  # Cyrillic 'P' (U+0420)
            'с': 'c',  # Cyrillic 'c' (U+0441)
            'С': 'C',  # Cyrillic 'C' (U+0421)
            'у': 'y',  # Cyrillic 'y' (U+0443)
            'х': 'x',  # Cyrillic 'x' (U+0445)
            'Х': 'X',  # Cyrillic 'X' (U+0425)
            'і': 'i',  # Cyrillic 'i' (U+0456)
            'І': 'I',  # Cyrillic 'I' (U+0406)
            'ї': 'i',  # Cyrillic 'yi' (U+0457)
            'ј': 'j',  # Cyrillic 'je' (U+0458)
            'ѕ': 's',  # Cyrillic 'dze' (U+0455)
            'ԁ': 'd',  # Cyrillic 'komi de' (U+0501)
            'ɑ': 'a',  # Latin small alpha (U+0251)
            'ο': 'o',  # Greek omicron (U+03BF)
            'Ο': 'O',  # Greek Omicron (U+039F)
            'ν': 'v',  # Greek nu (U+03BD)
            'Ν': 'N',  # Greek Nu (U+039D)
            'Α': 'A',  # Greek Alpha (U+0391)
            'α': 'a',  # Greek alpha (U+03B1) - not exactly same but close
            'Β': 'B',  # Greek Beta (U+0392)
            'Ε': 'E',  # Greek Epsilon (U+0395)
            'Ζ': 'Z',  # Greek Zeta (U+0396)
            'Η': 'H',  # Greek Eta (U+0397)
            'Ι': 'I',  # Greek Iota (U+0399)
            'Κ': 'K',  # Greek Kappa (U+039A)
            'Μ': 'M',  # Greek Mu (U+039C)
            'Ρ': 'P',  # Greek Rho (U+03A1)
            'Τ': 'T',  # Greek Tau (U+03A4)
            'Υ': 'Y',  # Greek Upsilon (U+03A5)
            'Χ': 'X',  # Greek Chi (U+03A7)
        }

        # Check links for homograph domains
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            domain = urlparse(href).netloc

            for char in domain:
                if char in suspicious_chars:
                    try:
                        char_name = unicodedata.name(char)
                        if 'CYRILLIC' in char_name or 'GREEK' in char_name:
                            homographs.append(f"domain '{domain}' contains {char_name}")
                            break
                    except ValueError:
                        pass

        # NEW: Check body text for homograph obfuscation
        # This catches phishing that uses Cyrillic lookalikes like "Асtіоn" instead of "Action"
        body_text = soup.get_text()
        if body_text:
            # Count homoglyph characters in body
            homoglyph_count = 0
            latin_count = 0
            sample_homoglyphs = []

            for char in body_text[:5000]:  # Check first 5000 chars
                if char in suspicious_chars:
                    homoglyph_count += 1
                    if len(sample_homoglyphs) < 5:
                        try:
                            char_name = unicodedata.name(char)
                            sample_homoglyphs.append(f"{char}→{suspicious_chars[char]} ({char_name})")
                        except ValueError:
                            sample_homoglyphs.append(f"{char}→{suspicious_chars[char]}")
                elif char.isalpha() and ord(char) < 128:
                    latin_count += 1

            # Detect mixed script attack: Cyrillic/Greek chars mixed with Latin
            # This is a strong phishing indicator - legitimate emails don't mix scripts this way
            total_alpha = homoglyph_count + latin_count
            if total_alpha > 20 and homoglyph_count >= 3:
                # Calculate ratio - mixed scripts are suspicious
                homoglyph_ratio = homoglyph_count / total_alpha
                # Suspicious if we have homoglyphs mixed with Latin (not pure Cyrillic text)
                if 0.01 < homoglyph_ratio < 0.5:  # Mixed script pattern
                    body_homographs.append(f"body contains {homoglyph_count} lookalike chars mixed with Latin")
                    if sample_homoglyphs:
                        body_homographs.append(f"samples: {', '.join(sample_homoglyphs[:3])}")

        return {
            'homographs': list(set(homographs))[:3],  # Limit to 3 unique domain issues
            'body_homographs': body_homographs[:3],   # Body text homoglyph issues
            'has_body_homoglyphs': len(body_homographs) > 0
        }

    def _detect_tracking_pixels(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect tracking pixels (1x1 images)"""
        images = soup.find_all('img')
        tracking_pixels = 0

        for img in images:
            width = img.get('width', '')
            height = img.get('height', '')
            style = img.get('style', '')

            # Check for 1x1 dimensions
            try:
                if ((str(width).rstrip('px') == '1' and str(height).rstrip('px') == '1') or
                    ('width:1px' in style and 'height:1px' in style)):
                    tracking_pixels += 1
            except (ValueError, AttributeError):
                pass

        return {
            'tracking_pixels': tracking_pixels
        }


# Module entry point
def analyze_html_body(msg: EmailMessage) -> Dict[str, Any]:
    """Module entry point for HTML body analysis"""
    analyzer = HTMLBodyAnalyzer()
    return analyzer.analyze(msg)


if __name__ == '__main__':
    # Test mode
    print("HTML Body Analyzer - Test Mode")
    print(f"HTML Analysis Available: {HTML_ANALYSIS_AVAILABLE}")
