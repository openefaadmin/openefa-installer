#!/usr/bin/env python3
"""
Received Chain Analyzer - OpenEFA Email Security
Analyzes the Received header chain for routing anomalies

Features:
- Parse Received headers to extract routing information
- Detect forged relay chains
- Check for spam relays using RBLs
- Identify timestamp reversals (time travel)
- Detect impossible geographic routing
- Verify hostname/IP matches
- Flag excessive hop counts

Author: OpenEFA Team
Created: 2025-11-14
"""

import re
import socket
import logging
import os
import json
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from datetime import datetime
from typing import Dict, List, Optional
import sys

# GeoIP support (optional - graceful degradation if not available)
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

logger = logging.getLogger(__name__)


class ReceivedChainAnalyzer:
    """Analyzes Received headers for routing anomalies"""

    def __init__(self):
        # Configuration
        self.max_hops = 10              # Flag emails with >10 hops
        self.suspicious_hops = 8        # Warning threshold
        self.min_hop_time_seconds = 1   # Minimum realistic hop time
        self.max_geo_speed_kmh = 10000  # Max impossible speed (km/h)

        # Spam relay databases (RBL servers)
        self.spam_relay_cache = {}
        self.rbl_servers = [
            'zen.spamhaus.org',
            'b.barracudacentral.org',
            'bl.spamcop.net'
        ]
        self.rbl_timeout = 2  # seconds

        # Hostname verification cache
        self.hostname_cache = {}

        # Score weights
        self.scores = {
            'excessive_hops': 3.0,          # >10 hops
            'suspicious_hop_count': 1.5,    # 8-10 hops
            'timestamp_reversal': 5.0,      # Time travel detected
            'impossible_geography': 4.0,    # Geographic anomaly
            'spam_relay_detected': 6.0,     # Known spam relay
            'hostname_mismatch': 3.5,       # Hostname doesn't resolve to IP
            'missing_hostname': 1.0,        # No hostname in Received header
        }

        # Load configuration from unified trust policy
        self.legitimate_complex_routes = {}
        self.trusted_relay_ips = set()
        self._load_trust_policy()

        # Initialize GeoIP if available
        self.geoip_reader = None
        self.geoip_available = GEOIP_AVAILABLE
        if self.geoip_available:
            try:
                self.geoip_reader = geoip2.database.Reader('/opt/spacyserver/data/GeoLite2-City.mmdb')
                logger.info("✅ GeoIP database loaded successfully")
            except Exception as e:
                logger.warning(f"⚠️ Could not load GeoIP database: {e}")
                self.geoip_available = False

    def _load_trust_policy(self):
        """Load routing trust policy from unified config file"""
        try:
            config_file = '/opt/spacyserver/config/trust_policy.json'

            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)

                # Load complex routing patterns
                complex_routes = config.get('complex_routing_patterns', {})
                for domain, settings in complex_routes.items():
                    self.legitimate_complex_routes[domain] = {'max_hops': settings.get('max_hops', 10)}

                # Load trusted relay IPs
                trusted_ips = config.get('trusted_relay_ips', {})
                self.trusted_relay_ips = set(trusted_ips.keys())

                logger.info(f"✅ Loaded {len(self.legitimate_complex_routes)} complex routes and {len(self.trusted_relay_ips)} trusted relay IPs from trust policy")
            else:
                logger.warning(f"⚠️ Trust policy file not found: {config_file}, using defaults")

        except Exception as e:
            logger.error(f"❌ Error loading trust policy: {e}, using defaults")

    def parse_received_header(self, received_str: str) -> Dict:
        """
        Parse a Received header into structured data

        Input format examples:
        "from mail.example.com ([192.0.2.1]) by mx.destination.com with ESMTP id ABC123; Thu, 7 Nov 2025 12:34:56 -0800"
        "from [10.0.0.5] (helo=internal-server) by relay.com; 7 Nov 2025 12:30:00 +0000"

        Returns:
            {
                'from_hostname': 'mail.example.com',
                'from_ip': '192.0.2.1',
                'by_hostname': 'mx.destination.com',
                'timestamp': datetime object,
                'protocol': 'ESMTP',
                'helo': 'internal-server' (optional)
            }
        """
        result = {
            'from_hostname': None,
            'from_ip': None,
            'by_hostname': None,
            'timestamp': None,
            'protocol': None,
            'helo': None,
            'raw': received_str
        }

        # Extract "from" server
        from_match = re.search(r'from\s+(\S+)', received_str, re.IGNORECASE)
        if from_match:
            result['from_hostname'] = from_match.group(1).strip('[]')

        # Extract IP address (multiple patterns)
        ip_patterns = [
            r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?',  # Standard
            r'by.*\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)',  # In parentheses
        ]
        for pattern in ip_patterns:
            ip_match = re.search(pattern, received_str)
            if ip_match:
                result['from_ip'] = ip_match.group(1)
                break

        # Extract "by" server
        by_match = re.search(r'by\s+(\S+)', received_str, re.IGNORECASE)
        if by_match:
            result['by_hostname'] = by_match.group(1).strip(';').strip()

        # Extract protocol
        protocol_match = re.search(r'with\s+(\w+)', received_str, re.IGNORECASE)
        if protocol_match:
            result['protocol'] = protocol_match.group(1)

        # Extract HELO/EHLO
        helo_match = re.search(r'helo=(\S+)', received_str, re.IGNORECASE)
        if helo_match:
            result['helo'] = helo_match.group(1).strip('()')

        # Extract timestamp (various formats)
        try:
            # Try to find date pattern in header (after semicolon)
            date_match = re.search(r';\s*(.+)$', received_str)
            if date_match:
                date_str = date_match.group(1).strip()
                result['timestamp'] = parsedate_to_datetime(date_str)
        except Exception as e:
            logger.debug(f"Could not parse timestamp from Received header: {e}")

        return result

    def check_spam_relay(self, ip_address: str) -> bool:
        """Check if IP is listed in spam relay RBLs"""
        if not ip_address:
            return False

        # Check cache first
        if ip_address in self.spam_relay_cache:
            return self.spam_relay_cache[ip_address]

        # Skip private/local IPs
        if ip_address.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.',
                                   '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                                   '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                                   '172.29.', '172.30.', '172.31.')):
            self.spam_relay_cache[ip_address] = False
            return False

        # Skip trusted relay IPs (customer servers with known configuration)
        if ip_address in self.trusted_relay_ips:
            self.spam_relay_cache[ip_address] = False
            logger.debug(f"✓ Skipping RBL check for trusted relay IP: {ip_address}")
            return False

        # Spamhaus error codes (NOT spam listings):
        # 127.255.255.252 - Typing error in DNSBL name
        # 127.255.255.254 - Query refused (public resolver blocked)
        # 127.255.255.255 - Query refused
        # These indicate DNS query issues, not actual spam listings
        SPAMHAUS_ERROR_CODES = {'127.255.255.252', '127.255.255.254', '127.255.255.255'}

        is_spam = False
        reversed_ip = '.'.join(reversed(ip_address.split('.')))

        for rbl in self.rbl_servers:
            query = f"{reversed_ip}.{rbl}"
            try:
                # Set socket timeout
                socket.setdefaulttimeout(self.rbl_timeout)
                # Resolve the query and get the actual IP returned
                resolved_ip = socket.gethostbyname(query)

                # Check if this is a Spamhaus error code (not a real listing)
                if resolved_ip in SPAMHAUS_ERROR_CODES:
                    logger.debug(f"RBL check for {ip_address} on {rbl} returned error code: {resolved_ip}")
                    continue  # Not a real listing, try next RBL

                # Real listing found
                is_spam = True
                logger.warning(f"⚠️ Spam relay detected: IP {ip_address} found in RBL: {rbl} (code: {resolved_ip})")
                break
            except socket.gaierror:
                # Not listed in this RBL
                continue
            except socket.timeout:
                logger.debug(f"RBL timeout for {rbl}")
                continue
            except Exception as e:
                logger.debug(f"Error checking RBL {rbl}: {e}")

        self.spam_relay_cache[ip_address] = is_spam
        return is_spam

    def verify_hostname(self, hostname: str, claimed_ip: str) -> bool:
        """Verify hostname resolves to claimed IP"""
        if not hostname or not claimed_ip:
            return False

        # Remove common prefixes that might not resolve
        hostname = hostname.strip('[]').lower()

        # Skip verification for certain patterns
        if hostname in ('localhost', 'unknown', 'unavailable'):
            return True

        # Check cache
        cache_key = f"{hostname}:{claimed_ip}"
        if cache_key in self.hostname_cache:
            return self.hostname_cache[cache_key]

        try:
            socket.setdefaulttimeout(2)
            resolved_ips = socket.gethostbyname_ex(hostname)[2]
            matches = claimed_ip in resolved_ips
            self.hostname_cache[cache_key] = matches
            return matches
        except Exception as e:
            logger.debug(f"Could not resolve hostname {hostname}: {e}")
            # Don't penalize if we can't resolve (might be internal)
            return True

    def calculate_geographic_distance(self, ip1: str, ip2: str) -> Optional[float]:
        """Calculate distance in km between two IPs using GeoIP"""
        if not self.geoip_available or not self.geoip_reader:
            return None

        try:
            from math import radians, cos, sin, asin, sqrt

            # Haversine formula
            def haversine(lon1, lat1, lon2, lat2):
                lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
                dlon = lon2 - lon1
                dlat = lat2 - lat1
                a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
                c = 2 * asin(sqrt(a))
                km = 6371 * c  # Radius of earth in kilometers
                return km

            response1 = self.geoip_reader.city(ip1)
            response2 = self.geoip_reader.city(ip2)

            lat1, lon1 = response1.location.latitude, response1.location.longitude
            lat2, lon2 = response2.location.latitude, response2.location.longitude

            if None in (lat1, lon1, lat2, lon2):
                return None

            return haversine(lon1, lat1, lon2, lat2)

        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"GeoIP lookup error: {e}")
            return None

    def is_whitelisted_route(self, hops: List[Dict]) -> Optional[Dict]:
        """Check if routing matches known legitimate complex patterns"""
        for hop in hops:
            if hop.get('by_hostname'):
                hostname = hop['by_hostname'].lower()
                for domain, config in self.legitimate_complex_routes.items():
                    if domain in hostname:
                        return config
        return None

    def analyze(self, msg: EmailMessage) -> Dict:
        """
        Analyze the Received header chain for anomalies

        Returns:
            {
                'spam_score': float,
                'total_hops': int,
                'issues': List[str],
                'routing_path': List[str],
                'total_transit_time_seconds': float,
                'spam_relays_detected': List[str]
            }
        """
        received_headers = msg.get_all('Received', [])
        if not received_headers:
            return {
                'spam_score': 0.0,
                'total_hops': 0,
                'issues': ['no_received_headers'],
                'routing_path': [],
                'total_transit_time_seconds': 0,
                'spam_relays_detected': []
            }

        # Reverse to get chronological order (oldest first)
        received_headers = list(reversed(received_headers))

        issues = []
        spam_score = 0.0
        hops = []
        spam_relays = []

        # Parse all hops
        for idx, received_str in enumerate(received_headers):
            hop = self.parse_received_header(str(received_str))
            hop['index'] = idx
            hops.append(hop)

        # Check if this is a whitelisted complex route
        whitelist_config = self.is_whitelisted_route(hops)
        max_hops_threshold = whitelist_config['max_hops'] if whitelist_config else self.max_hops

        # Check hop count
        if len(hops) > max_hops_threshold:
            issues.append(f'excessive_hops: {len(hops)} hops (max: {max_hops_threshold})')
            spam_score += self.scores['excessive_hops']
        elif len(hops) >= self.suspicious_hops and not whitelist_config:
            issues.append(f'suspicious_hop_count: {len(hops)} hops')
            spam_score += self.scores['suspicious_hop_count']

        # Analyze each hop
        for idx, hop in enumerate(hops):
            # Check for spam relay (OPTION 3: skip for private/internal IPs)
            if hop['from_ip'] and self.check_spam_relay(hop['from_ip']):
                # Skip RBL checks for private IP ranges (internal infrastructure)
                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(hop['from_ip'])
                    is_private = ip_obj.is_private or ip_obj.is_loopback
                except:
                    is_private = False

                if not is_private:
                    issues.append(f'spam_relay_detected: {hop["from_ip"]} at hop {idx+1}')
                    spam_score += self.scores['spam_relay_detected']
                    spam_relays.append(hop['from_ip'])

            # Check hostname/IP match (skip for whitelisted routes and localhost to reduce false positives)
            if not whitelist_config and hop['from_hostname'] and hop['from_ip']:
                # Skip hostname verification for localhost/loopback addresses (common in Zimbra, internal relays)
                is_localhost = hop['from_ip'].startswith('127.') or hop['from_ip'] == '::1'
                if not is_localhost and not self.verify_hostname(hop['from_hostname'], hop['from_ip']):
                    issues.append(f'hostname_mismatch: {hop["from_hostname"]} != {hop["from_ip"]} (hop {idx+1})')
                    spam_score += self.scores['hostname_mismatch']

            # Check timestamp ordering (compare with previous hop)
            if idx > 0 and hop['timestamp'] and hops[idx-1]['timestamp']:
                if hop['timestamp'] < hops[idx-1]['timestamp']:
                    time_diff = (hops[idx-1]['timestamp'] - hop['timestamp']).total_seconds()
                    issues.append(f'timestamp_reversal: Hop {idx+1} is {time_diff:.0f}s before hop {idx}')
                    spam_score += self.scores['timestamp_reversal']

                # Check geographic impossibility
                time_diff = (hop['timestamp'] - hops[idx-1]['timestamp']).total_seconds()
                if time_diff > 0 and hop['from_ip'] and hops[idx-1]['from_ip']:
                    distance = self.calculate_geographic_distance(
                        hops[idx-1]['from_ip'],
                        hop['from_ip']
                    )
                    if distance:
                        # Calculate required speed in km/h
                        required_speed = (distance / (time_diff / 3600))
                        if required_speed > self.max_geo_speed_kmh:
                            issues.append(
                                f'impossible_geography: {distance:.0f}km in {time_diff:.0f}s '
                                f'({required_speed:.0f} km/h, hop {idx} to {idx+1})'
                            )
                            spam_score += self.scores['impossible_geography']

        # Calculate total transit time
        total_time = 0
        if hops and hops[0]['timestamp'] and hops[-1]['timestamp']:
            total_time = (hops[-1]['timestamp'] - hops[0]['timestamp']).total_seconds()

        # Build routing path for display
        routing_path = []
        for hop in hops:
            if hop['from_hostname'] and hop['from_ip']:
                routing_path.append(f"{hop['from_hostname']} ({hop.get('from_ip', 'no IP')})")
            elif hop['from_ip']:
                routing_path.append(hop['from_ip'])
            elif hop['from_hostname']:
                routing_path.append(hop['from_hostname'])

        return {
            'spam_score': round(spam_score, 2),
            'total_hops': len(hops),
            'issues': issues,
            'routing_path': routing_path,
            'total_transit_time_seconds': total_time,
            'spam_relays_detected': spam_relays,
            'whitelisted': whitelist_config is not None
        }


# Module entry point
def analyze_received_chain(msg: EmailMessage) -> Dict:
    """Module entry point for received chain analysis"""
    analyzer = ReceivedChainAnalyzer()
    return analyzer.analyze(msg)


if __name__ == '__main__':
    # Simple test mode
    print("Received Chain Analyzer - Test Mode")
    print("This module analyzes email Received headers for routing anomalies")
    print(f"GeoIP Available: {GEOIP_AVAILABLE}")
