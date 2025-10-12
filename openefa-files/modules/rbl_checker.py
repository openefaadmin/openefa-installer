#!/usr/bin/env python3
"""
RBL (Real-time Blackhole List) Checker Module
Performs DNS-based blacklist lookups on sender IPs before email reaches MailGuard.

Configured RBLs:
- SORBS (dnsbl.sorbs.net) - Spam/open relay/proxy detection
- SPAMHAUS (zen.spamhaus.org) - Aggregate list (SBL+XBL+PBL)
- SPAMCOP (bl.spamcop.net) - User-reported spam sources
"""

import dns.resolver
import logging
from typing import Dict, List, Tuple
import ipaddress
import socket
import json
import os

logger = logging.getLogger(__name__)

# Configuration file path
CONFIG_PATH = '/opt/spacyserver/config/rbl_config.json'

def load_rbl_config():
    """Load RBL configuration from JSON file."""
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                config = json.load(f)
                # Filter only enabled RBLs
                enabled_rbls = {
                    name: rbl_info
                    for name, rbl_info in config.get('rbl_lists', {}).items()
                    if rbl_info.get('enabled', True)
                }
                return enabled_rbls, config.get('trusted_networks', [])
        else:
            logger.warning(f"RBL config file not found: {CONFIG_PATH}, using defaults")
            return get_default_rbls(), get_default_networks()
    except Exception as e:
        logger.error(f"Error loading RBL config: {e}, using defaults")
        return get_default_rbls(), get_default_networks()

def get_default_rbls():
    """Default RBL configuration (fallback)."""
    return {
        'SORBS': {
            'host': 'dnsbl.sorbs.net',
            'weight': 3.0,
            'description': 'SORBS spam/relay/proxy list'
        },
        'SPAMHAUS': {
            'host': 'zen.spamhaus.org',
            'weight': 5.0,
            'description': 'Spamhaus ZEN aggregate list'
        },
        'SPAMCOP': {
            'host': 'bl.spamcop.net',
            'weight': 4.0,
            'description': 'SpamCop user-reported spam'
        }
    }

def get_default_networks():
    """Default trusted networks (fallback)."""
    return [
        '192.168.0.0/16',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '127.0.0.0/8',
        '100.64.0.0/10',  # Tailscale
    ]

# Load configuration at module import
RBL_LISTS, TRUSTED_NETWORKS = load_rbl_config()


def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal and should skip RBL checks."""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Check against trusted networks
        for network in TRUSTED_NETWORKS:
            if ip_obj in ipaddress.ip_network(network):
                return True

        return ip_obj.is_private
    except ValueError:
        return False


def reverse_ip(ip: str) -> str:
    """Reverse IP octets for RBL DNS query (1.2.3.4 -> 4.3.2.1)."""
    try:
        return '.'.join(reversed(ip.split('.')))
    except Exception:
        return None


def check_rbl(ip: str, rbl_host: str) -> Tuple[bool, List[str]]:
    """
    Check if IP is listed in a specific RBL.

    Returns:
        Tuple of (is_listed, return_codes)
    """
    reversed_ip = reverse_ip(ip)
    if not reversed_ip:
        return False, []

    query = f"{reversed_ip}.{rbl_host}"

    try:
        # Query the RBL
        answers = dns.resolver.resolve(query, 'A')
        return_codes = [str(rdata) for rdata in answers]
        return True, return_codes
    except dns.resolver.NXDOMAIN:
        # Not listed
        return False, []
    except dns.resolver.NoAnswer:
        # No answer (treat as not listed)
        return False, []
    except dns.resolver.Timeout:
        logger.warning(f"RBL timeout for {ip} on {rbl_host}")
        return False, []
    except Exception as e:
        logger.warning(f"RBL check error for {ip} on {rbl_host}: {e}")
        return False, []


def analyze_rbl(email_data: Dict) -> Dict:
    """
    Main RBL analysis function called by email_filter.py.

    Args:
        email_data: Dictionary containing email headers and metadata

    Returns:
        Dictionary with RBL results and spam score contribution
    """
    result = {
        'detected': False,
        'rbl_hits': [],
        'rbl_score': 0.0,
        'headers_to_add': {},
        'risk_factors': []
    }

    # Extract sender IP from email data
    sender_ip = email_data.get('sender_ip', '')

    if not sender_ip:
        logger.debug("No sender IP found, skipping RBL checks")
        return result

    # Skip RBL checks for private/internal IPs
    if is_private_ip(sender_ip):
        logger.debug(f"Sender IP {sender_ip} is private/internal, skipping RBL checks")
        result['headers_to_add']['X-RBL-Check'] = 'skipped (internal IP)'
        return result

    logger.info(f"Performing RBL checks for IP: {sender_ip}")

    # Check each RBL
    total_weight = 0.0
    rbl_details = []

    for rbl_name, rbl_config in RBL_LISTS.items():
        is_listed, return_codes = check_rbl(sender_ip, rbl_config['host'])

        if is_listed:
            weight = rbl_config['weight']
            total_weight += weight

            hit_info = {
                'name': rbl_name,
                'host': rbl_config['host'],
                'weight': weight,
                'return_codes': return_codes
            }
            result['rbl_hits'].append(hit_info)
            rbl_details.append(f"{rbl_name}({weight})")

            logger.warning(f"RBL HIT: {sender_ip} listed in {rbl_name} ({rbl_config['host']}) - codes: {return_codes}")

    # Calculate final score and detection
    if result['rbl_hits']:
        result['detected'] = True
        result['rbl_score'] = total_weight
        result['risk_factors'] = [f"listed_in_{len(result['rbl_hits'])}_rbls"]

        # Add headers
        result['headers_to_add']['X-RBL-Listed'] = 'true'
        result['headers_to_add']['X-RBL-Score'] = f"{total_weight:.1f}"
        result['headers_to_add']['X-RBL-Hits'] = ', '.join(rbl_details)

        logger.info(f"RBL detection: {sender_ip} listed in {len(result['rbl_hits'])} RBLs, total score: {total_weight}")
    else:
        result['headers_to_add']['X-RBL-Listed'] = 'false'
        result['headers_to_add']['X-RBL-Score'] = '0.0'
        logger.debug(f"RBL check passed: {sender_ip} not listed in any RBLs")

    return result


if __name__ == "__main__":
    # Test mode
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        test_ip = sys.argv[1]
    else:
        # Known spam test IP (127.0.0.2 is standard RBL test)
        test_ip = "127.0.0.2"

    print(f"\n=== RBL Check for {test_ip} ===\n")

    test_data = {'sender_ip': test_ip}
    result = analyze_rbl(test_data)

    print(f"Detected: {result['detected']}")
    print(f"RBL Score: {result['rbl_score']}")
    print(f"Hits: {len(result['rbl_hits'])}")

    for hit in result['rbl_hits']:
        print(f"\n  {hit['name']}:")
        print(f"    Host: {hit['host']}")
        print(f"    Weight: {hit['weight']}")
        print(f"    Return codes: {hit['return_codes']}")

    print(f"\nHeaders to add:")
    for header, value in result['headers_to_add'].items():
        print(f"  {header}: {value}")
