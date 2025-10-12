# /opt/spacyserver/modules/email_phishing.py
"""
Email Phishing Detection Module
Compatible with existing SpaCy email processing system
UPDATED: Enhanced comprehensive 419/advance fee fraud detection with adaptive weighting and pattern matching
SAFE VERSION: Maintains backward compatibility while adding 419 detection
"""
import re
import logging
import configparser
import urllib.parse
from pathlib import Path

class EmailPhishingDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config()
        self.enabled = self._is_enabled()
        self._load_detection_patterns()

    def _load_config(self):
        """Load configuration from modules.ini"""
        config = configparser.RawConfigParser()
        config_file = Path("/opt/spacyserver/config/modules.ini")

        if config_file.exists():
            config.read(config_file)
        return config

    def _is_enabled(self):
        """Check if phishing detection is enabled"""
        try:
            return self.config.getboolean('module_phishing', 'enabled', fallback=True)
        except:
            return True

    def _load_detection_patterns(self):
        """Load phishing detection patterns and rules"""
        # Suspicious phrases commonly used in phishing emails
        self.suspicious_phrases = [
            # Urgency-based
            "urgent action required", "immediate action", "act now", "expires today",
            "limited time", "deadline approaching", "time sensitive",

            # Account-related
            "account suspended", "account locked", "verify your account",
            "confirm your identity", "update your information", "unusual activity",
            "security alert", "unauthorized access", "login attempt",

            # Financial
            "update payment", "payment failed", "billing problem", "refund pending",
            "wire transfer", "claim your money", "prize winner", "lottery winner",
            "inheritance", "tax refund",

            # Social engineering
            "click here", "download now", "open attachment", "follow this link",
            "congratulations", "you have won", "special offer", "free gift",

            # 419/Advance fee fraud patterns
            "dear friend", "dear sir", "dear madam", "greetings in the name",
            "help me", "help me invest", "assist me", "need your help", "need your assistance",
            "late father", "late husband", "late mother", "deceased father", "deceased husband",
            "biological daughter", "only daughter", "only son", "only child", "widow",
            "former president", "former minister", "government official", "military officer",
            "war victim", "refugee", "political asylum", "persecution",
            "confidential business", "strictly confidential", "top secret", "private proposal",
            "god fearing", "trust worthy", "honest person", "reliable person",
            "transfer funds", "invest in your country", "business partnership", "joint venture",
            "bank account", "next of kin", "beneficiary", "inherit",
            "million dollars", "million euros", "million pounds", "million usd",
            "consignment", "security company", "diplomatic immunity", "diplomatic bag",
            "contact me immediately", "reply urgently", "time is running out", "respond quickly",

            # Geographic/political red flags for 419 scams
            "nigeria", "lagos", "abuja", "benin city", "port harcourt",
            "libya", "gaddafi", "muammar", "tripoli",
            "iraq", "saddam", "hussein", "baghdad",
            "syria", "assad", "damascus", "aleppo",
            "afghanistan", "kabul", "taliban",
            "sudan", "darfur", "khartoum",
            "zimbabwe", "mugabe", "harare",
            "ivory coast", "cote d'ivoire", "abidjan",
            "burkina faso", "sierra leone", "liberia",
            "democratic republic", "congo", "kinshasa",

            # Financial institution spoofing for 419
            "central bank", "reserve bank", "world bank", "imf",
            "security finance", "global finance", "international bank",
            "foreign exchange", "forex investment", "offshore bank",

            # Common 419 story elements
            "oil deal", "gold transaction", "diamond business", "crude oil",
            "contract payment", "over invoice", "inflated contract", "excess funds",
            "compensation fund", "inheritance fund", "trust fund", "estate",
            "unclaimed funds", "dormant account", "abandoned account", "sleeping account",

            # Insurance / business marketing spam phrases
            'insurance offer', 'home insurance', 'quick quote',
            'coverage starts today', 'no medical exam', 'instant approval',
            'low monthly payment', 'best insurance rates', 'limited time quote',
        ]

        # Enhanced 419 fraud patterns with higher weights
        self.fraud_419_high_risk = [
            # Death + inheritance combinations
            'late father', 'late husband', 'late mother', 'deceased father', 
            'deceased husband', 'inheritance', 'estate', 'next of kin',
            'beneficiary', 'heir', 'will', 'testament',
            
            # African countries/institutions 
            'nigeria', 'ecowas', 'african development bank', 'central bank',
            'petroleum corporation', 'mining company', 'oil revenue',
            
            # Partnership language
            '50/50', 'fifty fifty', 'business partner', 'equal sharing',
            'cooperation', 'collaboration', 'mutual benefit',
            
            # Large money amounts
            'million dollars', 'million euros', 'million pounds', 'million usd',
            
            # Emotional manipulation
            'god fearing', 'trust worthy', 'widow', 'orphan', 'refugee'
            
            # Modern generic 419 variants
            'am expecting your response', 'expecting your reply',
            'business proposal', 'confidential matter',
            'undisclosed recipients', 'urgent response needed'
        ]

        # Money amount patterns for 419 detection
        self.money_patterns = [
            r'\$[\d,]+\.?\d*\s*million',           # $10.5 million
            r'\$[\d,]+\.?\d*\s*billion',          # $1.2 billion  
            r'USD[\s\$]*[\d,]+',                  # USD 10,500,000
            r'\([A-Z]{3}\$[\d,\.]+\)',            # (US$10,500,000.00)
            r'[\d,]+\s*million\s*dollars?',       # 10 million dollars
            r'[\d,]+\s*billion\s*dollars?',       # 2 billion dollars
            r'US\$[\d,\.]+',                      # US$10,500,000
        ]

        # Suspicious URL patterns
        self.suspicious_url_patterns = [
            r'bit\.ly', r'tinyurl\.com', r'goo\.gl', r'ow\.ly',  # URL shorteners
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.(tk|ml|ga|cf|pw)',  # Suspicious TLDs
            r'secure-[a-z]+\.(com|net|org)',  # Fake security domains
            r'[a-z]+-update\.(com|net|org)',  # Update-themed domains
        ]

        # Legitimate domains that are often spoofed
        self.legitimate_domains = [
            'paypal.com', 'amazon.com', 'microsoft.com', 'google.com',
            'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'ebay.com', 'netflix.com', 'spotify.com', 'dropbox.com',
            'wells-fargo.com', 'chase.com', 'bankofamerica.com'
        ]

        # Characters often used for spoofing
        self.spoofing_chars = {
            'a': ['@', 'à', 'á', 'â', 'ã', 'ä', 'å'],
            'e': ['3', 'è', 'é', 'ê', 'ë'],
            'i': ['1', '!', 'ì', 'í', 'î', 'ï'],
            'o': ['0', 'ò', 'ó', 'ô', 'õ', 'ö'],
            'u': ['ù', 'ú', 'û', 'ü'],
            'l': ['1', 'I', '|'],
            'n': ['ñ']
        }

    def detect_phishing(self, email_data):
        """
        Main phishing detection function with enhanced 419 detection

        Args:
            email_data (dict): Email data with sender, subject, body, etc.

        Returns:
            dict: Phishing detection results or None if disabled
        """
        if not self.enabled:
            return None

        try:
            sender = email_data.get('sender', '')
            subject = email_data.get('subject', '')
            body = email_data.get('body', '')

            # Calculate individual risk scores
            content_risk = self._analyze_content(subject, body)
            url_risk = self._analyze_urls(body)
            sender_risk = self._analyze_sender(sender)
            urgency_risk = self._analyze_urgency(subject, body)
            
            # NEW: Enhanced 419 fraud detection
            fraud_419_risk = self._analyze_419_patterns(subject, body, sender)

            # Enhanced weighting based on 419 score
            if fraud_419_risk >= 0.7:  # High 419 risk - boost its importance
                total_risk = (
                    content_risk * 0.20 +
                    url_risk * 0.20 +
                    sender_risk * 0.10 +
                    urgency_risk * 0.10 +
                    fraud_419_risk * 0.40  # 40% weight for high 419 scores
                )
                weighting_used = "high_419"
            elif fraud_419_risk >= 0.4:  # Medium 419 risk
                total_risk = (
                    content_risk * 0.22 +
                    url_risk * 0.22 +
                    sender_risk * 0.13 +
                    urgency_risk * 0.13 +
                    fraud_419_risk * 0.30  # 30% weight for medium 419 scores
                )
                weighting_used = "medium_419"
            else:  # Low/no 419 risk - use balanced weights
                total_risk = (
                    content_risk * 0.30 +
                    url_risk * 0.30 +
                    sender_risk * 0.20 +
                    urgency_risk * 0.20 +
                    fraud_419_risk * 0.00  # No weight if not 419-related
                )
                weighting_used = "standard"

            # Get risk threshold from config
            risk_threshold = self.config.getfloat('module_phishing', 'risk_threshold', fallback=0.6)

            # Determine risk level
            risk_level = self._get_risk_level(total_risk)
            is_phishing = total_risk >= risk_threshold

            # Get specific indicators found
            indicators = self._get_specific_indicators(email_data, fraud_419_risk)

            result = {
                "risk_score": round(total_risk, 3),
                "risk_level": risk_level,
                "is_phishing": is_phishing,
                "component_scores": {
                    "content": round(content_risk, 3),
                    "urls": round(url_risk, 3),
                    "sender": round(sender_risk, 3),
                    "urgency": round(urgency_risk, 3),
                    "fraud_419": round(fraud_419_risk, 3)
                },
                "indicators": indicators,
                "recommendation": self._get_recommendation(risk_level, is_phishing, fraud_419_risk),
                "weighting_used": weighting_used
            }

            # Log suspicious emails if configured
            if is_phishing and self.config.getboolean('module_phishing', 'log_suspicious', fallback=True):
                if fraud_419_risk >= 0.6:
                    self.logger.warning(f"419 FRAUD DETECTED: {subject[:50]}... (risk: {total_risk:.3f}, 419: {fraud_419_risk:.3f})")
                else:
                    self.logger.warning(f"Phishing detected: {subject[:50]}... (risk: {total_risk:.3f})")

            return result

        except Exception as e:
            self.logger.error(f"Phishing detection failed: {e}")
            return None

    def _analyze_419_patterns(self, subject, body, sender):
        """Enhanced 419/advance fee fraud detection"""
        combined_text = f"{subject} {body} {sender}".lower()
        risk_score = 0.0
        fraud_indicators = []

        # Check for high-risk 419 patterns
        high_risk_matches = 0
        for pattern in self.fraud_419_high_risk:
            if pattern in combined_text:
                high_risk_matches += 1
                fraud_indicators.append(pattern)
        
        # Scoring based on high-risk matches
        if high_risk_matches >= 4:
            risk_score += 0.8  # Very high risk for multiple 419 indicators
        elif high_risk_matches >= 3:
            risk_score += 0.6  # High risk for three 419 indicators
        elif high_risk_matches >= 2:
            risk_score += 0.4  # Medium risk for two 419 indicators
        elif high_risk_matches >= 1:
            risk_score += 0.2  # Low risk for one 419 indicator

        # Check for money amount patterns (common in 419)
        money_found = False
        for pattern in self.money_patterns:
            if re.search(pattern, combined_text, re.IGNORECASE):
                risk_score += 0.3
                fraud_indicators.append("large_money_amount")
                money_found = True
                break

        # Check for dangerous combinations
        has_death = any(word in combined_text for word in ['deceased', 'late', 'died', 'death'])
        has_inheritance = any(word in combined_text for word in ['inheritance', 'estate', 'will', 'beneficiary'])
        has_african = any(word in combined_text for word in ['nigeria', 'african', 'ecowas'])
        
        if has_death and has_inheritance:
            risk_score += 0.4  # Major red flag for death + inheritance
            fraud_indicators.append("death_inheritance_combo")
            
        if has_african and has_inheritance:
            risk_score += 0.3  # Red flag for African + inheritance
            fraud_indicators.append("african_inheritance_combo")

        # Emotional manipulation indicators
        emotional_words = ['god fearing', 'trust worthy', 'widow', 'orphan', 'refugee', 'persecution']
        emotional_matches = sum(1 for word in emotional_words if word in combined_text)
        if emotional_matches >= 2:
            risk_score += 0.2
            fraud_indicators.append("emotional_manipulation")

        # Store indicators for reporting
        self._fraud_indicators = fraud_indicators[:5]  # Limit to 5 most important
        
        return min(risk_score, 1.0)

    def _analyze_content(self, subject, body):
        """Analyze email content for phishing indicators"""
        combined_text = f"{subject} {body}".lower()
        risk_score = 0.0

        # Check for suspicious phrases
        phrase_matches = 0
        for phrase in self.suspicious_phrases:
            if phrase in combined_text:
                phrase_matches += 1

        # Scale phrase matches to risk score
        risk_score += min(phrase_matches * 0.15, 0.8)

        # Check for excessive punctuation (!!!, ???)
        punct_pattern = r'[!?]{2,}'
        punct_matches = len(re.findall(punct_pattern, subject + body))
        risk_score += min(punct_matches * 0.1, 0.2)

        # Check for ALL CAPS (excluding short words)
        caps_words = re.findall(r'\b[A-Z]{4,}\b', subject + body)
        if len(caps_words) > 2:
            risk_score += 0.2

        return min(risk_score, 1.0)

    def _analyze_urls(self, content):
        """Analyze URLs in email content for suspicious patterns"""
        # Find all URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)

        if not urls:
            return 0.0

        risk_score = 0.0

        for url in urls:
            # Check against suspicious URL patterns
            for pattern in self.suspicious_url_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    risk_score += 0.4

            # Check for domain spoofing
            try:
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc.lower()

                # Check for lookalike domains
                for legit_domain in self.legitimate_domains:
                    if self._is_lookalike_domain(domain, legit_domain):
                        risk_score += 0.6

            except Exception:
                # Malformed URL is suspicious
                risk_score += 0.3

        return min(risk_score, 1.0)

    def _analyze_sender(self, sender):
        """Analyze sender for suspicious patterns"""
        if not sender:
            return 0.0

        risk_score = 0.0
        sender_lower = sender.lower()

        # Check for display name spoofing
        if '<' in sender and '>' in sender:
            try:
                display_name = sender.split('<')[0].strip()
                email_addr = sender.split('<')[1].split('>')[0]

                # Check if display name suggests official org but email doesn't match
                official_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'bank', 'security']
                display_has_official = any(keyword in display_name.lower() for keyword in official_keywords)
                email_has_official = any(keyword in email_addr.lower() for keyword in official_keywords)

                if display_has_official and not email_has_official:
                    risk_score += 0.5

            except Exception:
                pass

        # Check for suspicious email patterns
        # Many numbers in email address
        if len(re.findall(r'\d', sender_lower)) > 4:
            risk_score += 0.2

        # Random character patterns
        if re.search(r'[a-z]{10,}[0-9]{3,}', sender_lower):
            risk_score += 0.3

        return min(risk_score, 1.0)

    def _analyze_urgency(self, subject, body):
        """Analyze urgency-based manipulation tactics"""
        combined_text = f"{subject} {body}".lower()
        risk_score = 0.0

        urgency_indicators = [
            'urgent', 'immediate', 'asap', 'expires', 'deadline',
            'now', 'today', 'within 24', 'limited time', 'hurry'
        ]

        urgency_count = sum(1 for indicator in urgency_indicators if indicator in combined_text)
        risk_score += min(urgency_count * 0.2, 0.8)

        # Time pressure phrases
        time_pressure = [
            'expires today', 'expires in', 'last chance', 'final notice',
            'act now', 'don\'t wait', 'before it\'s too late'
        ]

        for phrase in time_pressure:
            if phrase in combined_text:
                risk_score += 0.3

        return min(risk_score, 1.0)

    def _is_lookalike_domain(self, domain, legitimate_domain):
        """Check if domain is a lookalike of a legitimate domain"""
        if domain == legitimate_domain:
            return False

        # Simple character substitution check
        for char, substitutes in self.spoofing_chars.items():
            for substitute in substitutes:
                spoofed = legitimate_domain.replace(char, substitute)
                if domain == spoofed:
                    return True

        # Check for extra characters or subdomains
        if legitimate_domain in domain and domain != legitimate_domain:
            return True

        return False

    def _get_risk_level(self, risk_score):
        """Convert risk score to human-readable level"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"

    def _get_specific_indicators(self, email_data, fraud_419_risk):
        """Get list of specific suspicious indicators found"""
        indicators = []
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        sender = email_data.get('sender', '')

        combined_text = f"{subject} {body}".lower()

        # Add 419-specific indicators first if significant risk
        if fraud_419_risk >= 0.3 and hasattr(self, '_fraud_indicators'):
            for indicator in self._fraud_indicators[:3]:
                indicators.append(f"419 pattern: {indicator}")

        # Check for specific suspicious phrases
        phrase_count = 0
        for phrase in self.suspicious_phrases:
            if phrase in combined_text and phrase_count < 3:
                indicators.append(f"Suspicious phrase: '{phrase}'")
                phrase_count += 1

        # Check for URL issues
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, body)

        for url in urls:
            for pattern in self.suspicious_url_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    indicators.append("Suspicious URL detected")
                    break

        # Check sender issues
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            if any(keyword in display_name.lower() for keyword in ['paypal', 'amazon', 'microsoft']):
                indicators.append("Potentially spoofed sender")

        return indicators[:5]  # Limit to 5 indicators

    def _get_recommendation(self, risk_level, is_phishing, fraud_419_risk):
        """Get action recommendation based on risk assessment"""
        if fraud_419_risk >= 0.8:
            return "BLOCK IMMEDIATELY - High confidence 419 fraud"
        elif fraud_419_risk >= 0.6:
            return "QUARANTINE - Likely 419 fraud, manual review required"
        elif risk_level == "critical":
            return "Block email immediately"
        elif risk_level == "high":
            return "Quarantine for manual review"
        elif risk_level == "medium":
            return "Flag as suspicious"
        else:
            return "Monitor"

# Global instance for easy import
phishing_detector = EmailPhishingDetector()

def detect_phishing(email_data):
    """Convenience function for phishing detection"""
    return phishing_detector.detect_phishing(email_data)
