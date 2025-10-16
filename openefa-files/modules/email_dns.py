#!/usr/bin/env python3
# /opt/spacyserver/modules/email_dns.py

import dns.resolver
import dns.exception
import logging
import time
import json
import os
import re
import sys

class DNSValidator:
    def __init__(self, timeout=5, config_file='/opt/spacyserver/config/dns_whitelist.json'):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.logger = logging.getLogger('email_dns')
        self.config_file = config_file
        
        # Load whitelist from config file
        self.dns_whitelist = set()
        self.config = {}
        self._load_whitelist_config()

    def _load_whitelist_config(self):
        """Load DNS whitelist configuration from JSON file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                
                # Convert list to set for faster lookups
                whitelist_domains = self.config.get('dns_whitelist', [])
                self.dns_whitelist = set(domain.lower() for domain in whitelist_domains)
                
                self.logger.info(f"Loaded {len(self.dns_whitelist)} domains from DNS whitelist config")
                if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                    self.logger.debug(f"Whitelisted domains: {', '.join(sorted(self.dns_whitelist))}")
            else:
                self.logger.warning(f"DNS whitelist config file not found: {self.config_file}")
                # Create default config file
                self._create_default_config()
                
        except Exception as e:
            self.logger.error(f"Error loading DNS whitelist config: {e}")
            self.dns_whitelist = set()
            self.config = {}

    def _create_default_config(self):
        """Create a default config file if none exists"""
        default_config = {
            "dns_whitelist": [
                "pax8.com",
                "pax8alerts.pax8.com",
                "*.pax8.com",
                "microsoftonline.com",
                "substrate.office.com",
                "*.microsoft.com",
                "*.office.com",
                "*.outlook.com",
                "*.office365.com",
                "*.onmicrosoft.com"
            ],
            "whitelist_behavior": {
                "skip_dns_validation": True,
                "return_positive_score": True,
                "log_whitelisted_domains": True
            },
            "fallback_values": {
                "mx_record": "whitelisted-mx-record",
                "spf_record": "v=spf1 include:whitelisted ~all",
                "dmarc_record": "v=DMARC1; p=quarantine",
                "reputation_score": 5
            },
            "spoofing_detection": {
                "enabled": True,
                "high_confidence_threshold": 0.7,
                "reputation_penalty_multiplier": 5
            },
            "last_updated": time.strftime("%Y-%m-%d"),
            "notes": "DNS whitelist for trusted domains that may have DNS resolution issues"
        }
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            self.logger.info(f"Created default DNS whitelist config at {self.config_file}")
            
            # Reload the config we just created
            self._load_whitelist_config()
            
        except Exception as e:
            self.logger.error(f"Failed to create default config: {e}")

    def reload_whitelist(self):
        """Reload whitelist from config file (useful for runtime updates)"""
        self.logger.info("Reloading DNS whitelist configuration")
        self._load_whitelist_config()

    def _is_whitelisted(self, domain):
        """Check if domain is in DNS whitelist or BEC whitelist"""
        if not domain:
            return False
            
        domain_lower = domain.lower()
        
        # Check DNS whitelist first (existing logic)
        if domain_lower in self.dns_whitelist:
            return True
            
        # Check for wildcard matches
        for whitelisted in self.dns_whitelist:
            if whitelisted.startswith('*.'):
                base_domain = whitelisted[2:]  # Remove *.
                if domain_lower.endswith('.' + base_domain) or domain_lower == base_domain:
                    return True
            # Check if it's a subdomain of whitelisted domain
            elif '.' in whitelisted and domain_lower.endswith('.' + whitelisted):
                return True
        
        # NEW: Check BEC configuration whitelist
        try:
            bec_config_path = '/opt/spacyserver/config/bec_config.json'
            if os.path.exists(bec_config_path):
                with open(bec_config_path, 'r') as f:
                    bec_config = json.load(f)
                    whitelisted_domains = bec_config.get('whitelisted_domains', {}).get('authentication_aware', {})
                    
                    if domain_lower in whitelisted_domains:
                        trust_level = whitelisted_domains[domain_lower].get('trust_level', 0)
                        if trust_level >= 3:  # Medium trust or higher
                            self.logger.debug(f"Domain {domain} in BEC whitelist with trust level {trust_level}")
                            return True
        except Exception as e:
            self.logger.debug(f"BEC whitelist check error: {e}")
                
        return False

    def _is_legitimate_multidomain(self, claimed_domain, sending_domain):
        """Check if domain pair is a legitimate multi-domain architecture"""
        if not claimed_domain or not sending_domain:
            return False
        
        claimed_lower = claimed_domain.lower()
        sending_lower = sending_domain.lower()
        
        # Microsoft's legitimate multi-domain architecture
        microsoft_domains = {
            'microsoft.com', 'microsoftonline.com', 'outlook.com',
            'substrate.office.com', 'office.com', 'office365.com',
            'sharepoint.com', 'onmicrosoft.com', 'accountprotection.microsoft.com',
            'azurerms.com', 'windows.net', 'azure.com', 'live.com',
            'hotmail.com', 'msn.com', 'passport.com'
        }
        
        # Both domains are Microsoft - legitimate architecture
        if claimed_lower in microsoft_domains and sending_lower in microsoft_domains:
            self.logger.info(f"✅ Microsoft multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True
        
        # Google's multi-domain architecture
        google_domains = {
            'gmail.com', 'google.com', 'googlemail.com', 
            'googleapis.com', 'gstatic.com', 'youtube.com'
        }
        
        if claimed_lower in google_domains and sending_lower in google_domains:
            self.logger.info(f"✅ Google multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True
        
        # Amazon's multi-domain architecture
        amazon_domains = {
            'amazon.com', 'amazonaws.com', 'amazonses.com',
            'aws.amazon.com', 'awscloud.com'
        }
        
        if claimed_lower in amazon_domains and sending_lower in amazon_domains:
            self.logger.info(f"✅ Amazon multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True
        
        # Check if they're related subdomains
        if '.' in claimed_lower and '.' in sending_lower:
            claimed_base = '.'.join(claimed_lower.split('.')[-2:])
            sending_base = '.'.join(sending_lower.split('.')[-2:])
            if claimed_base == sending_base:
                self.logger.debug(f"Related domains detected: {claimed_domain} / {sending_domain}")
                return True
        
        return False

    def _get_fallback_value(self, record_type):
        """Get fallback value for whitelisted domains"""
        fallback_values = self.config.get('fallback_values', {})
        
        fallback_map = {
            'mx': fallback_values.get('mx_record', 'whitelisted-mx-record'),
            'spf': fallback_values.get('spf_record', 'v=spf1 include:whitelisted ~all'),
            'dmarc': fallback_values.get('dmarc_record', 'v=DMARC1; p=quarantine'),
            'reputation': fallback_values.get('reputation_score', 5)
        }
        
        return fallback_map.get(record_type, 'whitelisted-record')

    def validate_sender_authenticity(self, msg, from_header):
        """
        Enhanced validation that checks both claimed domain and actual sending domain
        Detects domain spoofing by comparing From header domain vs Received headers
        """
        validation_results = {
            'claimed_domain': '',
            'actual_sending_domain': '',
            'claimed_domain_score': 0,
            'sending_domain_score': 0,
            'spoofing_detected': False,
            'spoofing_confidence': 0.0,
            'reputation_penalty': 0
        }
        
        # Extract claimed domain from From header
        try:
            if '@' in from_header:
                email_match = re.search(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
                if email_match:
                    validation_results['claimed_domain'] = email_match.group(1).lower()
        except Exception as e:
            self.logger.error(f"Error extracting claimed domain: {e}")
        
        # Extract actual sending domain from Received headers
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            received_str = str(received).lower()
            
            # Look for the first external sender (skip internal relays)
            if any(internal in received_str for internal in [
                'mailserver.example.com', 'mailguard.example.com', 
                '192.168.', '127.0.0.1', 'localhost', 'mailserver.local'
            ]):
                continue
                
            # Extract domain from "from domain.com" pattern
            domain_match = re.search(r'from\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', received_str)
            if domain_match:
                potential_domain = domain_match.group(1)
                # Skip IP addresses and common mail server hostnames
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', potential_domain) and \
                   not any(skip in potential_domain for skip in ['unknown', 'localhost', 'protection.outlook.com']):
                    validation_results['actual_sending_domain'] = potential_domain
                    self.logger.debug(f"Detected actual sending domain: {potential_domain}")
                    break
        
        claimed_domain = validation_results['claimed_domain']
        sending_domain = validation_results['actual_sending_domain']
        
        # Skip spoofing detection if either domain is whitelisted
        if self._is_whitelisted(claimed_domain) or self._is_whitelisted(sending_domain):
            self.logger.debug(f"Skipping spoofing detection - whitelisted domain involved")
            if claimed_domain:
                validation_results['claimed_domain_score'] = self._get_fallback_value('reputation')
            return validation_results
        
        if claimed_domain:
            validation_results['claimed_domain_score'] = self._calculate_domain_score(claimed_domain)
        
        if sending_domain:
            validation_results['sending_domain_score'] = self._calculate_domain_score(sending_domain)
        
        # Detect spoofing
        if claimed_domain and sending_domain and claimed_domain != sending_domain:
            # FIRST: Check if this is a legitimate multi-domain architecture
            if self._is_legitimate_multidomain(claimed_domain, sending_domain):
                validation_results['spoofing_detected'] = False
                validation_results['spoofing_confidence'] = 0.0
                validation_results['reputation_penalty'] = 0
                self.logger.info(f"✅ Legitimate multi-domain architecture - no spoofing")
                return validation_results
            
            # SECOND: Check if either domain is whitelisted (double-check with BEC)
            if self._is_whitelisted(claimed_domain) or self._is_whitelisted(sending_domain):
                validation_results['spoofing_detected'] = False
                validation_results['spoofing_confidence'] = 0.0
                validation_results['reputation_penalty'] = 0
                self.logger.info(f"✅ Whitelisted domain pair - no spoofing penalty")
                return validation_results
            
            # Check if they're related domains (e.g., mail.company.com vs company.com)
            is_related = (
                claimed_domain in sending_domain or 
                sending_domain in claimed_domain or
                claimed_domain.split('.')[-2:] == sending_domain.split('.')[-2:]  # Same base domain
            )
            
            if not is_related:
                validation_results['spoofing_detected'] = True
                
                # Calculate spoofing confidence based on domain reputation difference
                claimed_score = validation_results['claimed_domain_score']
                sending_score = validation_results['sending_domain_score']
                
                # Get spoofing detection config
                spoofing_config = self.config.get('spoofing_detection', {})
                enabled = spoofing_config.get('enabled', True)
                penalty_multiplier = spoofing_config.get('reputation_penalty_multiplier', 5)
                
                if enabled:
                    # High confidence if claiming to be from reputable domain but sending from unknown
                    if claimed_score > 3 and sending_score < 2:
                        validation_results['spoofing_confidence'] = 0.8
                        validation_results['reputation_penalty'] = penalty_multiplier
                    elif claimed_score > sending_score + 2:
                        validation_results['spoofing_confidence'] = 0.6
                        validation_results['reputation_penalty'] = int(penalty_multiplier * 0.6)
                    else:
                        validation_results['spoofing_confidence'] = 0.3
                        validation_results['reputation_penalty'] = int(penalty_multiplier * 0.2)
                    
                    self.logger.warning(f"Domain spoofing detected: claimed={claimed_domain} (score:{claimed_score}) actual={sending_domain} (score:{sending_score}) confidence={validation_results['spoofing_confidence']:.2f}")
        
        return validation_results

    def validate_mx(self, domain):
        # Check if whitelisted and skip validation is enabled
        if (self._is_whitelisted(domain) and 
            self.config.get('whitelist_behavior', {}).get('skip_dns_validation', True)):
            
            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - skipping MX validation")
            
            return [self._get_fallback_value('mx')]
            
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mxs = [r.exchange.to_text() for r in answers]
            return mxs
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            self.logger.warning(f"MX lookup failed for {domain}: {e}")
            return []

    def validate_spf(self, domain):
        # Check if whitelisted and skip validation is enabled
        if (self._is_whitelisted(domain) and 
            self.config.get('whitelist_behavior', {}).get('skip_dns_validation', True)):
            
            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - skipping SPF validation")
            
            return [self._get_fallback_value('spf')]
            
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            spf_records = [r.to_text().strip('"') for r in answers if r.to_text().startswith('"v=spf1')]
            return spf_records
        except Exception as e:
            self.logger.warning(f"SPF lookup failed for {domain}: {e}")
            return []

    def validate_dmarc(self, domain):
        # Check if whitelisted and skip validation is enabled
        if (self._is_whitelisted(domain) and 
            self.config.get('whitelist_behavior', {}).get('skip_dns_validation', True)):
            
            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - skipping DMARC validation")
            
            return [self._get_fallback_value('dmarc')]
            
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [r.to_text().strip('"') for r in answers]
            return dmarc_records
        except Exception as e:
            self.logger.warning(f"DMARC lookup failed for {domain}: {e}")
            return []

    def calculate_domain_reputation(self, domain, ip, is_trusted, spf_result):
        # Give whitelisted domains a good reputation score
        if (self._is_whitelisted(domain) and 
            self.config.get('whitelist_behavior', {}).get('return_positive_score', True)):
            
            reputation_score = self._get_fallback_value('reputation')
            
            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - giving positive reputation score: {reputation_score}")
            
            return reputation_score, True  # High score and trusted
            
        # Placeholder for advanced scoring logic
        score = 0
        mxs = self.validate_mx(domain)
        if not mxs:
            score -= 2
        spf = self.validate_spf(domain)
        if spf:
            score += 1
        dmarc = self.validate_dmarc(domain)
        if dmarc:
            score += 1
        return score, bool(mxs)

    def enhanced_calculate_domain_reputation(self, msg, from_header):
        """
        Enhanced reputation calculation that includes spoofing detection
        This is the NEW main entry point that should be used
        """
        # Run spoofing detection
        spoofing_results = self.validate_sender_authenticity(msg, from_header)
        
        claimed_domain = spoofing_results['claimed_domain']
        base_reputation = spoofing_results['claimed_domain_score']
        
        # Apply penalties for spoofing
        if spoofing_results['spoofing_detected']:
            reputation_penalty = spoofing_results['reputation_penalty']
            final_reputation = base_reputation - reputation_penalty
            
            self.logger.warning(f"Spoofing penalty applied: -{reputation_penalty} points")
            self.logger.info(f"Domain reputation: {base_reputation} -> {final_reputation}")
            
            return final_reputation, False, spoofing_results
        
        return base_reputation, True, spoofing_results

    def _calculate_domain_score(self, domain):
        """Legacy domain score calculation"""
        # Give whitelisted domains a positive score
        if (self._is_whitelisted(domain) and 
            self.config.get('whitelist_behavior', {}).get('return_positive_score', True)):
            
            return self._get_fallback_value('reputation')
            
        try:
            reputation, is_trusted = self.calculate_domain_reputation(domain, 'none', False, 'none')
            return reputation
        except Exception as e:
            self.logger.error(f"Domain score calculation error: {e}")
            return 3


# ============================================================================
# WRAPPER FUNCTION FOR EMAIL_FILTER.PY INTEGRATION
# ============================================================================

def analyze_dns(msg, text_content):
    """
    Wrapper function for email_filter.py integration
    This function provides the expected interface for the module system
    
    Args:
        msg: Email message object
        text_content: Extracted text content (not used in DNS analysis)
    
    Returns:
        Dictionary with dns_spam_score and other DNS analysis results
    """
    try:
        # Extract From header
        from_header = msg.get('From', '')
        
        # Use the enhanced reputation calculation which includes spoofing detection
        reputation, is_trusted, spoofing_results = dns_validator.enhanced_calculate_domain_reputation(msg, from_header)
        
        # Calculate spam score based on reputation and spoofing
        dns_spam_score = 0.0
        
        # Heavy penalty for spoofing
        if spoofing_results.get('spoofing_detected'):
            dns_spam_score += 10.0
            confidence = spoofing_results.get('spoofing_confidence', 0.0)
            if confidence > 0.7:
                dns_spam_score += 5.0  # Extra penalty for high-confidence spoofing
            
            # Log spoofing detection
            print(f"🚨 DNS Spoofing detected: claimed={spoofing_results.get('claimed_domain')} " +
                  f"actual={spoofing_results.get('actual_sending_domain')} " +
                  f"confidence={confidence:.2f}", file=sys.stderr)
        
        # Reputation-based scoring
        if reputation < -3:
            dns_spam_score += abs(reputation) * 3  # Very bad reputation
        elif reputation < 0:
            dns_spam_score += abs(reputation) * 2  # Bad reputation
        elif reputation > 3:
            dns_spam_score -= reputation * 0.5  # Good reputation reduces spam score
        
        # Ensure spam score doesn't go negative
        dns_spam_score = max(0.0, dns_spam_score)
        
        # Log results
        print(f"DNS Analysis: reputation={reputation}, trusted={is_trusted}, " +
              f"spoofing={spoofing_results.get('spoofing_detected', False)}, " +
              f"spam_score={dns_spam_score:.2f}", file=sys.stderr)
        
        # Return results in expected format
        return {
            'dns_spam_score': dns_spam_score,
            'reputation': reputation,
            'is_trusted': is_trusted,
            'spoofing_detected': spoofing_results.get('spoofing_detected', False),
            'spoofing_confidence': spoofing_results.get('spoofing_confidence', 0.0),
            'claimed_domain': spoofing_results.get('claimed_domain', ''),
            'actual_sending_domain': spoofing_results.get('actual_sending_domain', '')
        }
        
    except Exception as e:
        print(f"DNS analysis error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return {
            'dns_spam_score': 0.0,
            'error': str(e)
        }


# Create global instance for import
dns_validator = DNSValidator()

# Export the wrapper function as the primary interface
__all__ = ['analyze_dns', 'dns_validator', 'DNSValidator']
