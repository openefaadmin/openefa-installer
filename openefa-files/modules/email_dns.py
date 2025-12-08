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
import redis
from datetime import datetime, timedelta

class DNSValidator:
    def __init__(self, timeout=5, config_file='/opt/spacyserver/config/dns_whitelist.json'):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.logger = logging.getLogger('email_dns')
        self.config_file = config_file

        # Initialize Redis cache
        self.cache_enabled = True
        self.cache_ttl = {
            'mx': 3600,      # 1 hour for MX records
            'spf': 3600,     # 1 hour for SPF records
            'dmarc': 3600,   # 1 hour for DMARC records
            'negative': 300  # 5 minutes for failed lookups
        }
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'errors': 0
        }

        try:
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=1,  # Use DB 1 for DNS cache
                decode_responses=True,
                socket_timeout=1,
                socket_connect_timeout=1
            )
            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis DNS cache initialized successfully")
        except Exception as e:
            self.logger.warning(f"Redis cache unavailable, falling back to no caching: {e}")
            self.cache_enabled = False
            self.redis_client = None

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

        # Check if either domain is Microsoft (including subdomains)
        claimed_is_microsoft = any(claimed_lower == d or claimed_lower.endswith('.' + d) for d in microsoft_domains)
        sending_is_microsoft = any(sending_lower == d or sending_lower.endswith('.' + d) for d in microsoft_domains)

        if claimed_is_microsoft and sending_is_microsoft:
            self.logger.info(f"✅ Microsoft multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True

        # Google's multi-domain architecture
        google_domains = {
            'gmail.com', 'google.com', 'googlemail.com',
            'googleapis.com', 'gstatic.com', 'youtube.com'
        }

        # Check if either domain is Google (including subdomains like mail.google.com)
        claimed_is_google = any(claimed_lower == d or claimed_lower.endswith('.' + d) for d in google_domains)
        sending_is_google = any(sending_lower == d or sending_lower.endswith('.' + d) for d in google_domains)

        if claimed_is_google and sending_is_google:
            self.logger.info(f"✅ Google multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True

        # Amazon's multi-domain architecture
        amazon_domains = {
            'amazon.com', 'amazonaws.com', 'amazonses.com',
            'aws.amazon.com', 'awscloud.com'
        }

        # Check if either domain is Amazon (including subdomains)
        claimed_is_amazon = any(claimed_lower == d or claimed_lower.endswith('.' + d) for d in amazon_domains)
        sending_is_amazon = any(sending_lower == d or sending_lower.endswith('.' + d) for d in amazon_domains)

        if claimed_is_amazon and sending_is_amazon:
            self.logger.info(f"✅ Amazon multi-domain architecture: {claimed_domain} / {sending_domain}")
            return True

        # Email Service Provider (ESP) legitimate architectures
        # These are third-party email services used by companies for bulk/marketing emails
        esp_mappings = {
            # Qualtrics (used by eBay, Synchrony, and many others)
            'qemailserver.com': {'ebay.com', 'reply.ebay.com', 'qualtrics.com', 'synchronyfinancial.com', 'e.synchronyfinancial.com'},

            # Epsilon (major ESP used by financial institutions)
            'epsl1.com': {'synchronyfinancial.com', 'e.synchronyfinancial.com', 'epsilon.com'},
            'pmx1.epsl1.com': {'synchronyfinancial.com', 'e.synchronyfinancial.com', 'epsilon.com'},

            # SendGrid (major ESP)
            'sendgrid.net': set(),  # Will be populated by reverse lookup
            'sendgrid.com': set(),

            # Mailchimp
            'mcsv.net': set(),
            'mailchimp.com': set(),

            # Salesforce Marketing Cloud (ExactTarget)
            'exacttarget.com': set(),
            's10.exacttarget.com': set(),

            # Constant Contact
            'constantcontact.com': set(),
            'ctctcdn.com': set(),

            # Campaign Monitor
            'createsend.com': set(),

            # Responsys (Oracle)
            'responsys.net': set(),

            # SparkPost
            'sparkpostmail.com': set(),

            # Twilio SendGrid
            'twilio.com': set(),

            # Mailgun
            'mailgun.org': set(),
            'mailgun.net': set(),

            # Postmark
            'postmarkapp.com': set(),

            # Amazon SES (already in Amazon section but adding for completeness)
            'amazonses.com': {'amazon.com', 'aws.amazon.com'},
        }

        # Check if sending domain is a known ESP
        for esp_domain, allowed_claimed_domains in esp_mappings.items():
            if sending_lower.endswith(esp_domain) or esp_domain in sending_lower:
                # If we have specific allowed claimed domains, check them
                if allowed_claimed_domains:
                    for allowed_domain in allowed_claimed_domains:
                        if claimed_lower.endswith(allowed_domain) or allowed_domain in claimed_lower:
                            self.logger.info(f"✅ ESP architecture detected: {claimed_domain} via {sending_domain} (ESP: {esp_domain})")
                            return True
                else:
                    # For ESPs without specific mappings, we'll be more permissive
                    # but still require basic SPF/DMARC validation (checked elsewhere)
                    self.logger.info(f"✅ Known ESP detected: {sending_domain} (ESP: {esp_domain})")
                    return True

        # Check if they're related subdomains
        if '.' in claimed_lower and '.' in sending_lower:
            claimed_base = '.'.join(claimed_lower.split('.')[-2:])
            sending_base = '.'.join(sending_lower.split('.')[-2:])
            if claimed_base == sending_base:
                self.logger.debug(f"Related domains detected: {claimed_domain} / {sending_domain}")
                return True

        return False

    def _get_cache_key(self, domain, record_type):
        """Generate Redis cache key"""
        return f"dns:{record_type}:{domain.lower()}"

    def _get_from_cache(self, domain, record_type):
        """Retrieve DNS record from Redis cache"""
        if not self.cache_enabled or not self.redis_client:
            return None

        try:
            cache_key = self._get_cache_key(domain, record_type)
            cached_data = self.redis_client.get(cache_key)

            if cached_data:
                self.cache_stats['hits'] += 1
                data = json.loads(cached_data)

                # Check if it's a negative cache entry
                if data.get('is_negative_cache'):
                    self.logger.debug(f"Cache HIT (negative) for {record_type} {domain}")
                    return []  # Return empty list for negative cache

                self.logger.debug(f"Cache HIT for {record_type} {domain}")
                return data.get('records', [])

            self.cache_stats['misses'] += 1
            return None

        except Exception as e:
            self.cache_stats['errors'] += 1
            self.logger.warning(f"Cache read error for {domain} ({record_type}): {e}")
            return None

    def _save_to_cache(self, domain, record_type, records):
        """Save DNS records to Redis cache"""
        if not self.cache_enabled or not self.redis_client:
            return

        try:
            cache_key = self._get_cache_key(domain, record_type)

            # Determine if this is a negative cache (empty result)
            is_negative = not records or len(records) == 0

            cache_data = {
                'records': records,
                'is_negative_cache': is_negative,
                'cached_at': datetime.now().isoformat(),
                'domain': domain,
                'record_type': record_type
            }

            # Use appropriate TTL
            ttl = self.cache_ttl.get('negative' if is_negative else record_type, 3600)

            self.redis_client.setex(
                cache_key,
                ttl,
                json.dumps(cache_data)
            )

            cache_type = "negative" if is_negative else "positive"
            self.logger.debug(f"Cached {cache_type} {record_type} for {domain} (TTL: {ttl}s)")

        except Exception as e:
            self.cache_stats['errors'] += 1
            self.logger.warning(f"Cache write error for {domain} ({record_type}): {e}")

    def get_cache_stats(self):
        """Get cache performance statistics"""
        total_requests = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0

        stats = {
            'enabled': self.cache_enabled,
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'errors': self.cache_stats['errors'],
            'total_requests': total_requests,
            'hit_rate_percent': round(hit_rate, 2)
        }

        if self.cache_enabled and self.redis_client:
            try:
                # Get cache size from Redis
                stats['cache_size'] = self.redis_client.dbsize()
            except:
                pass

        return stats

    def get_top_domains_from_db(self, limit=30):
        """
        Query database for top sender domains to pre-warm cache
        Returns list of domain names sorted by email volume
        """
        try:
            import mysql.connector

            # Connect to database using environment variables
            db = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'spacy_user'),
                password=os.getenv('DB_PASSWORD'),
                database=os.getenv('DB_NAME', 'spacy_email_db'),
                port=int(os.getenv('DB_PORT', 3306)),
                connection_timeout=5
            )

            cursor = db.cursor()

            # Get top domains from last 30 days
            query = """
                SELECT
                    SUBSTRING_INDEX(sender, '@', -1) as domain,
                    COUNT(*) as email_count
                FROM email_analysis
                WHERE sender LIKE '%@%'
                    AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY domain
                ORDER BY email_count DESC
                LIMIT %s
            """

            cursor.execute(query, (limit,))
            results = cursor.fetchall()

            # Clean up domains (remove trailing > and duplicates)
            domains = []
            seen = set()
            for row in results:
                domain = row[0].rstrip('>').strip()
                # Skip invalid domains
                if domain and '.' in domain and domain not in seen and domain != 'example.com':
                    domains.append(domain)
                    seen.add(domain)

            cursor.close()
            db.close()

            self.logger.info(f"Found {len(domains)} unique high-volume domains for DNS pre-warming")
            return domains[:limit]  # Return up to limit after deduplication

        except Exception as e:
            self.logger.warning(f"Could not query database for top domains: {e}")
            # Return fallback list of common domains
            return [
                'gmail.com',
                'yahoo.com',
                'outlook.com',
                'hotmail.com',
                'aol.com',
                'icloud.com',
                'protonmail.com'
            ]

    def prewarm_dns_cache(self, domains=None, limit=30):
        """
        Pre-warm DNS cache with high-volume domains on startup
        This eliminates cold-start delays for frequently-seen senders

        Args:
            domains: Optional list of domains to pre-warm. If None, queries database.
            limit: Maximum number of domains to pre-warm (default: 30)
        """
        if not self.cache_enabled:
            self.logger.info("DNS cache not enabled, skipping pre-warm")
            return

        start_time = time.time()

        # Get domains from database if not provided
        if domains is None:
            domains = self.get_top_domains_from_db(limit)

        if not domains:
            self.logger.warning("No domains to pre-warm")
            return

        self.logger.info(f"Pre-warming DNS cache with {len(domains)} domains...")

        cached_count = 0
        for domain in domains:
            try:
                # Cache MX records
                self.validate_mx(domain)

                # Cache SPF records
                self.validate_spf(domain)

                # Cache DMARC records
                self.validate_dmarc(domain)

                cached_count += 1

            except Exception as e:
                # Log but continue - some domains may have DNS issues
                self.logger.debug(f"Pre-warm skipped {domain}: {e}")
                continue

        elapsed = time.time() - start_time
        self.logger.info(f"✅ DNS pre-warm complete: {cached_count}/{len(domains)} domains cached in {elapsed:.2f}s")

        return cached_count

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

        # Check cache first
        cached_result = self._get_from_cache(domain, 'mx')
        if cached_result is not None:
            return cached_result

        # Cache miss - perform DNS lookup
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mxs = [r.exchange.to_text() for r in answers]
            self._save_to_cache(domain, 'mx', mxs)
            return mxs
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
            self.logger.warning(f"MX lookup failed for {domain}: {e}")
            # Cache negative result
            self._save_to_cache(domain, 'mx', [])
            return []

    def validate_spf(self, domain):
        # Check if whitelisted and skip validation is enabled
        if (self._is_whitelisted(domain) and
            self.config.get('whitelist_behavior', {}).get('skip_dns_validation', True)):

            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - skipping SPF validation")

            return [self._get_fallback_value('spf')]

        # Check cache first
        cached_result = self._get_from_cache(domain, 'spf')
        if cached_result is not None:
            return cached_result

        # Cache miss - perform DNS lookup
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            spf_records = [r.to_text().strip('"') for r in answers if r.to_text().startswith('"v=spf1')]
            self._save_to_cache(domain, 'spf', spf_records)
            return spf_records
        except Exception as e:
            self.logger.warning(f"SPF lookup failed for {domain}: {e}")
            # Cache negative result
            self._save_to_cache(domain, 'spf', [])
            return []

    def validate_dmarc(self, domain):
        # Check if whitelisted and skip validation is enabled
        if (self._is_whitelisted(domain) and
            self.config.get('whitelist_behavior', {}).get('skip_dns_validation', True)):

            if self.config.get('whitelist_behavior', {}).get('log_whitelisted_domains', False):
                self.logger.info(f"Domain {domain} is whitelisted - skipping DMARC validation")

            return [self._get_fallback_value('dmarc')]

        # Check cache first
        cached_result = self._get_from_cache(domain, 'dmarc')
        if cached_result is not None:
            return cached_result

        # Cache miss - perform DNS lookup
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [r.to_text().strip('"') for r in answers]
            self._save_to_cache(domain, 'dmarc', dmarc_records)
            return dmarc_records
        except Exception as e:
            self.logger.warning(f"DMARC lookup failed for {domain}: {e}")
            # Cache negative result
            self._save_to_cache(domain, 'dmarc', [])
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

        # High-risk TLD penalties
        sender_domain = from_header.split('@')[-1].strip('>').lower() if '@' in from_header else ''
        HIGH_RISK_TLDS = {
            '.asia': 2.0,  # High spam volume from .asia domains
            '.cn': 3.0,    # China domains - high phishing risk
            '.top': 2.5,   # Frequently used for spam
            '.xyz': 2.0,   # High abuse rate
            '.tk': 3.0,    # Free domain - very high spam
            '.ml': 3.0,    # Free domain - very high spam
            '.ga': 3.0,    # Free domain - very high spam
            '.cf': 3.0,    # Free domain - very high spam
            '.gq': 3.0     # Free domain - very high spam
        }

        for tld, penalty in HIGH_RISK_TLDS.items():
            if sender_domain.endswith(tld):
                dns_spam_score += penalty
                print(f"⚠️  High-risk TLD detected: {tld} (+{penalty} spam points)", file=sys.stderr)
                break

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

# ============================================================================
# DNS CACHE PRE-WARMING ON STARTUP
# ============================================================================
# Pre-warm DNS cache with top domains to eliminate cold-start delays
# This runs automatically when the module is first imported
try:
    dns_validator.prewarm_dns_cache(limit=30)
except Exception as e:
    # Don't let pre-warming failure prevent module from loading
    print(f"DNS pre-warm error: {e}", file=sys.stderr)

# Export the wrapper function as the primary interface
__all__ = ['analyze_dns', 'dns_validator', 'DNSValidator']
