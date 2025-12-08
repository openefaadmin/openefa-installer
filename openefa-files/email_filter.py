#!/opt/spacyserver/venv/bin/python3
"""
Enhanced Email Filter with REAL Authentication Validation + REDIS QUEUE INTEGRATION + FUNDING SPAM DETECTION
FIXES: Performs actual SPF, DKIM, and DMARC validation instead of just parsing headers
ENHANCED: Added comprehensive blocking logic for thread spam repetition and critical indicators
RESTORED: Full database functionality through Redis queues (no direct DB connections)
NEW: Advanced funding/financing spam detection with multi-pattern analysis
CRITICAL: Added authentication abuse detection to prevent scammer bypass
EMERGENCY: Added Microsoft MFA email bypass for substrate.office.com issues - WITH ENCODING FIX
FIXED: Added proper timeout handling for all modules to prevent hanging
FIXED: Mail loop prevention for system emails from local mail server
- Added real SPF validation using pyspf library
- Added real DKIM validation using pydkim library
- Added real DMARC validation using dnspython library
- Generates X-SpaCy-Auth-Results headers for MailGuard compensation
- FIXED: Thread spam repetition blocking
- ENHANCED: Multi-factor spam detection with RBL, phishing, and obfuscation checks
- RESTORED: Database storage, thread awareness, analytics via Redis queues
- NEW: Comprehensive funding spam detection with 50+ patterns and intelligent scoring
- CRITICAL: Authentication abuse detection for known scammers (Victoria Chavez, etc.)
- EMERGENCY: Microsoft MFA bypass for substrate.office.com DNS issues
- FIXED: Encoding issues with Microsoft MFA emails - now uses raw bytes
- FIXED: Module timeout handling to prevent hanging
- FIXED: Mail loop prevention for system/cron emails
- SECURITY FIX: Suppress verbose startup logging to prevent information disclosure in bounce messages
"""

import sys
import os

# Redirect stderr to syslog during initialization to prevent information disclosure in bounce messages
class StderrToSyslog:
    """Redirect stderr to syslog to prevent sensitive data leakage in bounce messages"""
    def __init__(self):
        self.original_stderr = sys.stderr
        import syslog
        syslog.openlog(ident="email_filter_init", facility=syslog.LOG_MAIL)
        self.syslog = syslog

    def write(self, message):
        if message and message.strip():
            self.syslog.syslog(self.syslog.LOG_INFO, message.strip())

    def flush(self):
        pass

# Temporarily redirect stderr during initialization
sys.stderr = StderrToSyslog()
import smtplib
import datetime
import re
import json
import logging
import traceback
import signal
import time
import gc
import psutil
import functools
import subprocess
import concurrent.futures
import syslog
import ipaddress
from email.parser import BytesParser
from email.policy import default
from email.message import EmailMessage
from email.header import Header
from contextlib import contextmanager
from typing import Dict, List, Set, Optional, Tuple, Any
from bs4 import BeautifulSoup

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv('/etc/spacy-server/.env')

# Add modules path
sys.path.insert(0, '/opt/spacyserver/modules')

# Import quarantine manager (after path is set)
# DEPRECATED 2025-11-19: Quarantine consolidated into email_analysis table
# from modules.quarantine_manager import get_quarantine_manager
from modules.vip_alerts import VIPAlertSystem

# DEPRECATED 2025-11-19: No longer using separate quarantine manager
# QUARANTINE_MANAGER = get_quarantine_manager()

# Initialize VIP Alert System (initialized lazily when needed)
VIP_ALERT_SYSTEM = None

# ============================================================================
# NOTIFICATION SERVICE INTEGRATION
# ============================================================================

# Import notification service for SMS alerts
NOTIFICATION_SERVICE = None
try:
    sys.path.insert(0, '/opt/spacyserver')
    from notification_service import NotificationService
    NOTIFICATION_SERVICE = NotificationService()
    print("✅ Notification service initialized", file=sys.stderr)
except Exception as e:
    print(f"⚠️  Notification service not available: {e}", file=sys.stderr)
    NOTIFICATION_SERVICE = None

# ============================================================================
# ARC (AUTHENTICATED RECEIVED CHAIN) - SIMPLE HEADER READING
# ============================================================================
# Note: Using simple header reading instead of cryptographic verification
# to avoid timeout issues. Trusts ARC headers from known forwarders.

# ============================================================================
# REDIS QUEUE INTEGRATION FOR DATABASE OPERATIONS
# ============================================================================

# Redis queue integration for database operations
try:
    import redis
    REDIS_AVAILABLE = True
    print("✅ Redis libraries loaded", file=sys.stderr)
except ImportError as e:
    REDIS_AVAILABLE = True
    print(f"⚠️  Redis libraries not available: {e}", file=sys.stderr)

# ============================================================================
# REAL AUTHENTICATION LIBRARIES
# ============================================================================

# Real authentication imports
try:
    import spf
    import dkim
    import dns.resolver
    import dns.exception
    from email_validator import validate_email, EmailNotValidError
    REAL_AUTH_AVAILABLE = True
    print("✅ Real authentication libraries loaded", file=sys.stderr)
except ImportError as e:
    REAL_AUTH_AVAILABLE = False
    print(f"⚠️  Real authentication libraries not available: {e}", file=sys.stderr)
    print("Install with: pip3 install pyspf pydkim dnspython email-validator", file=sys.stderr)

# GeoIP2 for country blocking
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
    GEOIP_DB_PATH = '/opt/spacyserver/data/GeoLite2-Country.mmdb'
    print("✅ GeoIP2 libraries loaded", file=sys.stderr)
except ImportError as e:
    GEOIP_AVAILABLE = False
    GEOIP_DB_PATH = None
    print(f"⚠️  GeoIP2 not available: {e}", file=sys.stderr)

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class EmailFilterConfig:
    """Centralized configuration management"""
    
    def __init__(self):
        self.config = {
            # Performance settings - INCREASED TIMEOUT TO PREVENT BOUNCES
            "timeouts": {
                "total_processing": int(os.getenv('SPACY_TIMEOUT_TOTAL', 120)),  # Increased from 90 to 120
                "analysis_timeout": int(os.getenv('SPACY_TIMEOUT_ANALYSIS', 90)),  # Increased from 60 to 90
                "smtp_timeout": int(os.getenv('SPACY_SMTP_TIMEOUT', 30)),
                "module_timeout": int(os.getenv('SPACY_MODULE_TIMEOUT', 5)),  # Reduced from 10 to 5
                "auth_timeout": int(os.getenv('SPACY_AUTH_TIMEOUT', 15))
            },
            
            # Email size limits
            "size_limits": {
                "max_email_size": 104857600,  # 100MB
                "text_extraction_limit": 25000,
                "analysis_text_limit": 15000,
                "minimal_analysis_size": 10000,
                "basic_analysis_size": 25000,
                "standard_analysis_size": 50000
            },
            
            # Domain configuration
            # NOTE: These should be populated from client_domains database table
            # Example domains shown - replace with your actual client domains
            "domains": {
                "internal_domains": set(),  # Load from database: client_domains table
                "processed_domains": set(),  # Load from database: client_domains table
                "journal_addresses": set(),  # Configure per installation (e.g., 'journal@mailserver.local')
                "trusted_domains": set()  # Will be loaded from config file
            },
            
            # NEW: System bypass configuration to prevent mail loops
            "system_bypass": {
                "bypass_domains": [
                    # Add your mail server hostname here to prevent loops
                    # Example: 'mailserver.yourdomain.com',
                    'localhost',
                    'localhost.localdomain'
                ],
                "bypass_senders": [
                    'root@',
                    'cron@',
                    'postmaster@',
                    'mailer-daemon@',
                    'nobody@',
                    'www-data@',
                    'quarantine@'  # Bypass release-to-superadmin emails from any quarantine address
                ],
                "bypass_subjects": [
                    'Cron <',
                    'Cron Job',
                    'System Alert',
                    'Backup Report',
                    'Daily Backup',
                    'Monitoring Alert'
                ],
                "max_received_headers": 25,  # Maximum allowed before considering it a loop
                "warning_received_headers": 15  # Warning threshold for possible loops
            },
            
            # Server configuration
            "servers": {
                "mailguard_host": os.getenv('SPACY_MAILGUARD_HOST', 'YOUR_RELAY_SERVER'),
                "mailguard_port": int(os.getenv('SPACY_MAILGUARD_PORT', 25)),
                "internal_ips": [
                    # Add your internal mail server IPs/hostnames here
                    # Example: '10.0.0.10', 'mailserver.local'
                ],
                # Per-domain relay hosts loaded from database
                "domain_relays": {}  # Format: {'domain': {'relay_host': 'host', 'relay_port': port}}
            },
            
            # ENHANCED: Analysis thresholds with new blocking parameters + funding spam
            "thresholds": {
                "spam_threshold": float(os.getenv('SPACY_SPAM_THRESHOLD', 10.0)),
                "minimal_analysis_threshold": 50.0,
                "basic_analysis_threshold": 70.0,
                "thread_trust_score": 1,
                "thread_spam_repetition_threshold": 3,
                "rbl_block_threshold": 2,
                "funding_spam_threshold": 75.0,
                "auth_abuse_threshold": 3,
                "auth_abuse_block_score": 85.0
            }
        }
        
        # Load trusted domains after config is initialized
        self._load_trusted_domains()
        # Load processed domains from database
        self._load_processed_domains()
        # Load relay server configuration from config file
        self._load_relay_config()

    def _load_processed_domains(self):
        """Load processed domains from database (client_domains table)"""
        try:
            import pymysql
            # Try to load database credentials
            my_cnf_path = '/opt/spacyserver/config/.my.cnf'
            if not os.path.exists(my_cnf_path):
                print(f"⚠️  No database config found, using hardcoded processed_domains", file=sys.stderr)
                return

            # Parse .my.cnf for credentials
            db_config = {}
            with open(my_cnf_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('host'):
                        db_config['host'] = line.split('=')[1].strip()
                    elif line.startswith('user'):
                        db_config['user'] = line.split('=')[1].strip()
                    elif line.startswith('password'):
                        db_config['password'] = line.split('=')[1].strip()
                    elif line.startswith('database'):
                        db_config['database'] = line.split('=')[1].strip()

            # Connect and load domains
            conn = pymysql.connect(
                host=db_config.get('host', 'localhost'),
                user=db_config.get('user', 'spacy_user'),
                password=db_config.get('password', ''),
                database=db_config.get('database', 'spacy_email_db'),
                connect_timeout=5
            )
            cursor = conn.cursor()
            cursor.execute("SELECT domain, relay_host, relay_port FROM client_domains WHERE active = 1")
            rows = cursor.fetchall()
            cursor.close()
            conn.close()

            if rows:
                domains = set()
                domain_relays = {}
                for row in rows:
                    domain = row[0]
                    relay_host = row[1] if row[1] else self.config['servers']['mailguard_host']
                    relay_port = row[2] if row[2] else self.config['servers']['mailguard_port']
                    domains.add(domain)
                    domain_relays[domain] = {
                        'relay_host': relay_host,
                        'relay_port': relay_port
                    }

                # Replace hardcoded domains with database domains
                self.config['domains']['processed_domains'] = domains
                self.config['servers']['domain_relays'] = domain_relays
                print(f"✅ Loaded {len(domains)} processed domains from database", file=sys.stderr)
                for domain, relay in domain_relays.items():
                    print(f"   {domain} -> {relay['relay_host']}:{relay['relay_port']}", file=sys.stderr)
            else:
                print(f"⚠️  No active domains in database, using hardcoded processed_domains", file=sys.stderr)

        except Exception as e:
            print(f"⚠️  Could not load processed domains from database: {e}", file=sys.stderr)
            print(f"⚠️  Using hardcoded processed_domains as fallback", file=sys.stderr)

    def _load_trusted_domains(self):
        """Load trusted domains from unified trust policy config files"""
        try:
            all_trusted_domains = set()
            wildcard_trusted_domains = []  # Store wildcard patterns separately

            # Load trust_policy.json (government, institutions, specific trusted entities)
            config_file = '/opt/spacyserver/config/trust_policy.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    trust_policy = json.load(f)
                    # Extract trusted domains from new structure (keys from trusted_domains dict)
                    trusted_domains_dict = trust_policy.get('trusted_domains', {})
                    # Separate wildcards from exact domains
                    for domain in trusted_domains_dict.keys():
                        if domain.startswith('*.'):
                            # Store wildcard suffix (e.g., '*.chase.com' -> '.chase.com')
                            wildcard_trusted_domains.append(domain[1:])  # Remove the '*'
                        else:
                            all_trusted_domains.add(domain)
                    print(f"✅ Loaded {len(trusted_domains_dict)} trusted domains from trust_policy.json ({len(wildcard_trusted_domains)} wildcards)", file=sys.stderr)

                    # Load authentication policy for trusted domains
                    behavior = trust_policy.get('behavior', {})
                    dns_validation = behavior.get('dns_validation', {})
                    self.config['domains']['trusted_auth_policy'] = {
                        'require_authentication': dns_validation.get('require_authentication', True),
                        'minimum_auth_methods': dns_validation.get('minimum_auth_methods', 1)
                    }
            else:
                print(f"⚠️  No trust_policy.json found at {config_file}", file=sys.stderr)
                self.config['domains']['trusted_auth_policy'] = {'require_authentication': True, 'minimum_auth_methods': 1}

            # Load trusted_esps.json (major ESPs and SaaS platforms)
            esps_config_file = '/opt/spacyserver/config/trusted_esps.json'
            if os.path.exists(esps_config_file):
                with open(esps_config_file, 'r') as f:
                    esps_policy = json.load(f)
                    esps_domains_dict = esps_policy.get('trusted_domains', {})
                    # Filter out comment keys (keys starting with _comment_)
                    esp_domains = {k: v for k, v in esps_domains_dict.items() if not k.startswith('_comment_')}
                    # Separate wildcards from exact domains
                    for domain in esp_domains.keys():
                        if domain.startswith('*.'):
                            wildcard_trusted_domains.append(domain[1:])  # Remove the '*'
                        else:
                            all_trusted_domains.add(domain)
                    print(f"✅ Loaded {len(esp_domains)} trusted ESPs from trusted_esps.json", file=sys.stderr)

                    # Update auth policy for ESPs (they require 2 methods)
                    esps_behavior = esps_policy.get('behavior', {})
                    esps_dns_validation = esps_behavior.get('dns_validation', {})
                    if esps_dns_validation.get('minimum_auth_methods', 0) > self.config['domains']['trusted_auth_policy']['minimum_auth_methods']:
                        print(f"   ESPs require {esps_dns_validation.get('minimum_auth_methods')} auth methods (stricter than base policy)", file=sys.stderr)
            else:
                print(f"⚠️  No trusted_esps.json found at {esps_config_file}", file=sys.stderr)

            # Store merged trusted domains and wildcards
            self.config['domains']['trusted_domains'] = all_trusted_domains
            self.config['domains']['trusted_domain_wildcards'] = wildcard_trusted_domains

            print(f"✅ Total {len(all_trusted_domains)} exact trusted domains + {len(wildcard_trusted_domains)} wildcards loaded", file=sys.stderr)
            print(f"   Auth policy: require={self.config['domains']['trusted_auth_policy']['require_authentication']}, min_methods={self.config['domains']['trusted_auth_policy']['minimum_auth_methods']}", file=sys.stderr)

            if len(all_trusted_domains) == 0:
                print(f"⚠️  WARNING: No trusted domains loaded! All domains will be subject to full spam analysis.", file=sys.stderr)

        except Exception as e:
            print(f"❌ Error loading trusted domains: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            self.config['domains']['trusted_domains'] = set()
            self.config['domains']['trusted_domain_wildcards'] = []
            self.config['domains']['trusted_auth_policy'] = {'require_authentication': True, 'minimum_auth_methods': 1}

    def _load_relay_config(self):
        """Load relay server configuration from email_filter_config.json"""
        try:
            config_file = '/opt/spacyserver/config/email_filter_config.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    filter_config = json.load(f)
                    # Load server configuration if present
                    if 'servers' in filter_config:
                        servers = filter_config['servers']
                        if 'mailguard_host' in servers:
                            self.config['servers']['mailguard_host'] = servers['mailguard_host']
                        if 'mailguard_port' in servers:
                            self.config['servers']['mailguard_port'] = int(servers['mailguard_port'])
                        print(f"✅ Loaded relay config: {self.config['servers']['mailguard_host']}:{self.config['servers']['mailguard_port']}", file=sys.stderr)
                    else:
                        print(f"⚠️  No 'servers' section in {config_file}, using defaults", file=sys.stderr)
            else:
                print(f"⚠️  No email filter config found at {config_file}, using defaults", file=sys.stderr)
        except Exception as e:
            print(f"❌ Error loading relay config: {e}", file=sys.stderr)

    @property
    def db_config(self):
        """Return database configuration from environment variables for mysql.connector"""
        return {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'spacy_user'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': os.getenv('DB_NAME', 'spacy_email_db'),
            'connect_timeout': 10
        }

CONFIG = EmailFilterConfig()

# ============================================================================
# TIMEOUT HANDLER FOR MODULES
# ============================================================================

class TimeoutException(Exception):
    """Custom exception for timeout handling"""
    pass

@contextmanager
def timeout_handler(seconds):
    """Context manager for handling timeouts"""
    def timeout_occurred(signum, frame):
        raise TimeoutException(f"Operation timed out after {seconds} seconds")
    
    # Set the signal handler and alarm
    old_handler = signal.signal(signal.SIGALRM, timeout_occurred)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def with_timeout(timeout_seconds):
    """Decorator to add timeout to functions"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with timeout_handler(timeout_seconds):
                    return func(*args, **kwargs)
            except TimeoutException as e:
                safe_log(f"⏱️ Timeout in {func.__name__}: {e}")
                return None
            except Exception as e:
                safe_log(f"Error in {func.__name__}: {e}")
                return None
        return wrapper
    return decorator

def check_spf_subprocess(sender_ip: str, sender_email: str, sender_domain: str, timeout: int = 10) -> str:
    """Check SPF using subprocess with hard timeout to prevent hanging"""
    try:
        # DEBUG: Log SPF check parameters
        safe_log(f"🔍 SPF CHECK: ip={sender_ip}, email={sender_email}, domain={sender_domain}")

        # Create a simple Python script to run SPF check
        spf_check_script = f"""
import spf
result = spf.check2(i="{sender_ip}", s="{sender_email}", h="{sender_domain}")
print(result[0])
"""
        # Run the SPF check in a subprocess with timeout
        result = subprocess.run(
            [sys.executable, "-c", spf_check_script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0:
            spf_result = result.stdout.strip()
            safe_log(f"🔍 SPF RESULT: {spf_result}")
            if spf_result in ['pass', 'fail', 'softfail', 'neutral', 'permerror', 'temperror', 'none']:
                return spf_result
            else:
                safe_log(f"Invalid SPF result: {spf_result}")
                return 'temperror'
        else:
            safe_log(f"SPF subprocess error: {result.stderr}")
            return 'temperror'
            
    except subprocess.TimeoutExpired:
        safe_log(f"SPF check timed out after {timeout}s (subprocess killed)")
        return 'temperror'
    except Exception as e:
        safe_log(f"SPF subprocess check error: {e}")
        return 'temperror'

# ============================================================================
# PERFORMANCE MONITORING - RESTORED FOR DATABASE ANALYTICS
# ============================================================================

class PerformanceMonitor:
    """Track performance metrics for database analytics - RESTORED"""
    
    def __init__(self):
        self.metrics = {
            'start_time': datetime.datetime.now(),
            'phase_times': {},
            'memory_usage': {},
            'email_size': 0,
            'attachments': 0,
            'headers_added': 0,
            'modules_run': [],
            'auth_results': {},
            'final_score': 0.0
        }
        self.record_memory('start')
    
    def record_phase(self, phase: str):
        """Record time for processing phase"""
        self.metrics['phase_times'][phase] = datetime.datetime.now()
    
    def record_memory(self, phase: str):
        """Record memory usage"""
        try:
            process = psutil.Process()
            self.metrics['memory_usage'][phase] = process.memory_info().rss / 1024 / 1024  # MB
        except:
            pass
    
    def record_email_stats(self, size: int, attachments: int):
        """Record email statistics"""
        self.metrics['email_size'] = size
        self.metrics['attachments'] = attachments
    
    def record_auth_results(self, results: Dict):
        """Record authentication results"""
        self.metrics['auth_results'] = results
    
    def record_module(self, module_name: str):
        """Record module execution"""
        self.metrics['modules_run'].append(module_name)
    
    def record_final_score(self, score: float):
        """Record final spam score"""
        self.metrics['final_score'] = score
    
    def log_performance(self, log_func):
        """Log performance summary"""
        try:
            end_time = datetime.datetime.now()
            total_time = (end_time - self.metrics['start_time']).total_seconds()
            
            self.record_memory('end')
            
            log_func(f"📊 Performance: {total_time:.2f}s total")
            log_func(f"📊 Modules run: {', '.join(self.metrics['modules_run'])}")
            log_func(f"📊 Headers added: {self.metrics['headers_added']}")
            
            mem_start = self.metrics['memory_usage'].get('start', 0)
            mem_end = self.metrics['memory_usage'].get('end', 0)
            log_func(f"📊 Memory: {mem_start:.1f}MB → {mem_end:.1f}MB")
            
        except Exception as e:
            log_func(f"Performance logging error: {e}")

# ============================================================================
# REDIS QUEUE CONNECTION
# ============================================================================

REDIS_QUEUE = None

if REDIS_AVAILABLE:
    try:
        REDIS_QUEUE = redis.Redis(
            host='localhost',
            port=6379,
            db=0,
            decode_responses=False,  # Handle encoding ourselves
            socket_connect_timeout=5,
            socket_timeout=5
        )
        # Test connection
        REDIS_QUEUE.ping()
        print("✅ Redis queue connected", file=sys.stderr)
        REDIS_QUEUE.connected = True
    except Exception as e:
        print(f"⚠️  Redis queue connection failed: {e}", file=sys.stderr)
        REDIS_QUEUE = None

# ============================================================================
# SPAM RESULT CACHE - Performance Optimization
# ============================================================================

class SpamResultCache:
    """
    Redis-based cache for spam analysis results
    Caches complete analysis results for repeat sender+subject combinations
    Provides 15-25% performance improvement for repetitive emails
    """
    def __init__(self):
        self.cache_enabled = True
        self.cache_ttl = 7200  # 2 hours (reduced from 24h to prevent stale RBL/DNS results)
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'errors': 0
        }

        try:
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=2,  # Use DB 2 for spam result cache
                decode_responses=True,
                socket_timeout=1,
                socket_connect_timeout=1
            )
            # Test connection
            self.redis_client.ping()
            print("✅ Spam result cache initialized (Redis DB 2)", file=sys.stderr)
        except Exception as e:
            print(f"⚠️  Spam result cache unavailable: {e}", file=sys.stderr)
            self.cache_enabled = False
            self.redis_client = None

    def _generate_cache_key(self, sender: str, subject: str) -> str:
        """
        Generate cache key from sender + subject + date
        Format: spam:{sender}:{subject_hash}:{date}
        """
        import hashlib

        # Normalize sender (lowercase, strip whitespace)
        sender_normalized = sender.lower().strip()

        # Hash subject to handle long subjects
        subject_hash = hashlib.md5(subject.encode('utf-8', errors='ignore')).hexdigest()[:16]

        # Use current date so cache expires daily
        date_str = datetime.datetime.now().strftime('%Y-%m-%d')

        return f"spam:{sender_normalized}:{subject_hash}:{date_str}"

    def get_cached_result(self, sender: str, subject: str) -> Optional[Dict]:
        """Retrieve cached spam analysis result"""
        if not self.cache_enabled or not self.redis_client:
            return None

        try:
            cache_key = self._generate_cache_key(sender, subject)
            cached_data = self.redis_client.get(cache_key)

            if cached_data:
                self.cache_stats['hits'] += 1
                result = json.loads(cached_data)
                safe_log(f"📦 CACHE HIT: {sender[:50]} - {subject[:50]}")
                return result

            self.cache_stats['misses'] += 1
            return None

        except Exception as e:
            self.cache_stats['errors'] += 1
            safe_log(f"Cache read error: {e}")
            return None

    def save_result(self, sender: str, subject: str, analysis_results: Dict):
        """Save spam analysis result to cache"""
        if not self.cache_enabled or not self.redis_client:
            return

        try:
            cache_key = self._generate_cache_key(sender, subject)

            # Add metadata
            cache_data = {
                **analysis_results,
                '_cached_at': datetime.datetime.now().isoformat(),
                '_cache_version': '1.0'
            }

            self.redis_client.setex(
                cache_key,
                self.cache_ttl,
                json.dumps(cache_data)
            )

            safe_log(f"💾 CACHED: {sender[:50]} - {subject[:50]} (TTL: 2h)")

        except Exception as e:
            self.cache_stats['errors'] += 1
            safe_log(f"Cache write error: {e}")

    def get_stats(self) -> Dict:
        """Get cache performance statistics"""
        total = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total * 100) if total > 0 else 0

        return {
            'enabled': self.cache_enabled,
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'errors': self.cache_stats['errors'],
            'hit_rate_percent': round(hit_rate, 2)
        }

# Initialize global spam result cache
SPAM_CACHE = None
if REDIS_AVAILABLE:
    try:
        SPAM_CACHE = SpamResultCache()
    except Exception as e:
        print(f"⚠️  Failed to initialize spam cache: {e}", file=sys.stderr)
        SPAM_CACHE = None

# ============================================================================
# MySQL DATABASE CONNECTION FOR BLOCKING RULES
# ============================================================================

DB_CONN = None

try:
    import mysql.connector
    import atexit
    # Read MySQL config from environment variables
    DB_CONN = mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'spacy_user'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME', 'spacy_email_db'),
        port=int(os.getenv('DB_PORT', 3306)),
        autocommit=False,
        connection_timeout=5
    )
    print("✅ MySQL database connected for blocking rules", file=sys.stderr)

    # Register cleanup handler to properly close DB connection
    def cleanup_db_connection():
        global DB_CONN
        if DB_CONN:
            try:
                # Give any pending transactions time to complete
                import time
                time.sleep(0.1)

                # Ensure connection is still valid before closing
                if DB_CONN.is_connected():
                    DB_CONN.close()
                print("✅ Database connection closed", file=sys.stderr)
            except Exception as e:
                # Silently handle errors during cleanup
                pass

    # Register cleanup for normal exit
    atexit.register(cleanup_db_connection)

    # Register cleanup for signal termination
    def signal_handler(signum, frame):
        cleanup_db_connection()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

except Exception as e:
    print(f"⚠️  MySQL database connection failed: {e}", file=sys.stderr)
    DB_CONN = None

# ============================================================================
# GEOIP DATABASE INITIALIZATION
# ============================================================================

GEOIP_READER = None

if GEOIP_AVAILABLE and GEOIP_DB_PATH:
    try:
        if os.path.exists(GEOIP_DB_PATH):
            GEOIP_READER = geoip2.database.Reader(GEOIP_DB_PATH)
            print("✅ GeoIP2 database loaded for country blocking", file=sys.stderr)
        else:
            print(f"⚠️  GeoIP database not found at {GEOIP_DB_PATH}", file=sys.stderr)
    except Exception as e:
        print(f"⚠️  GeoIP initialization failed: {e}", file=sys.stderr)
        GEOIP_READER = None

# ============================================================================
# MODULE LOADING AND AVAILABILITY - RESTORED ALL MODULES + FUNDING SPAM
# ============================================================================

class ModuleManager:
    """Manages module loading and availability - ALL MODULES RESTORED + FUNDING SPAM"""
    
    def __init__(self):
        self.modules = {}
        self.available = {}
        self.load_all_modules()
    
    def load_all_modules(self):
        """Load all available analysis modules - ALL MODULES RESTORED + FUNDING SPAM"""
        module_imports = {
            'otp_detector': ('otp_detector', 'extract_otp'),
            'entity_extraction': ('entity_extraction', 'analyze_email_content'),
            'email_dns': ('email_dns', 'analyze_dns'),
            'email_phishing': ('phishing_detector', 'check_phishing'),
            'email_sentiment': ('email_sentiment', 'analyze_sentiment'),
            'email_language': ('email_language', 'analyze_email_language'),
            'email_obfuscation': ('email_obfuscation', 'analyze_obfuscation'),
            'marketing_spam_filter': ('marketing_spam_filter', ['filter_marketing_spam', 'get_spam_score_adjustment']),
            'bec_detector': ('bec_detector', 'check_bec'),
            'brand_impersonation': ('brand_impersonation_comprehensive', 'check_brand_impersonation'),
            'enhanced_analysis': ('analysis', ['enhanced_government_analysis', 'detect_business_context', 'detect_domain_spoofing']),
            'toad_detector': ('toad_detector', 'analyze_toad_threats'),
            'pdf_analyzer': ('pdf_analyzer', 'analyze_pdf_attachments'),
            'html_attachment_analyzer': ('html_attachment_analyzer', 'analyze_html_attachments'),
            'fraud_funding_detector': ('funding_spam_detector', 'analyze_funding_spam'),
            'url_reputation': ('url_reputation', 'analyze_email_urls'),
            'behavioral_baseline': ('behavioral_baseline', 'analyze_behavior'),
            'rbl_checker': ('rbl_checker', 'analyze_rbl'),
            'antivirus_scanner': ('antivirus_scanner', 'scan_email'),
            'attachment_inspector': ('attachment_inspector', 'analyze_attachments'),
            'header_forgery_detector': ('header_forgery_detector', 'detect_header_forgery'),
            'received_chain_analyzer': ('received_chain_analyzer', 'analyze_received_chain'),
            'html_body_analyzer': ('html_body_analyzer', 'analyze_html_body'),
            'display_name_spoofing': ('display_name_spoofing', 'analyze_display_name_spoofing'),
            'onmicrosoft_impersonation': ('onmicrosoft_impersonation', 'analyze_onmicrosoft_impersonation'),
        }
        
        for module_key, (module_name, functions) in module_imports.items():
            try:
                module = __import__(module_name)
                
                if isinstance(functions, list):
                    # Multiple functions from module
                    module_funcs = {}
                    for func_name in functions:
                        if hasattr(module, func_name):
                            module_funcs[func_name] = getattr(module, func_name)
                    if module_funcs:
                        self.modules[module_key] = module_funcs
                        self.available[module_key] = True
                        print(f"✅ Module {module_key} loaded with {len(module_funcs)} functions", file=sys.stderr)
                else:
                    # Single function from module
                    if hasattr(module, functions):
                        self.modules[module_key] = getattr(module, functions)
                        self.available[module_key] = True
                        print(f"✅ Module {module_key} loaded", file=sys.stderr)
                    
            except ImportError as e:
                self.available[module_key] = False
                print(f"⚠️  Module {module_key} not available: {e}", file=sys.stderr)
            except Exception as e:
                self.available[module_key] = False
                print(f"❌ Module {module_key} load error: {e}", file=sys.stderr)
    
    def is_available(self, module_key: str) -> bool:
        """Check if module is available"""
        return self.available.get(module_key, False)
    
    def get_module(self, module_key: str):
        """Get loaded module or function"""
        return self.modules.get(module_key, None)

MODULE_MANAGER = ModuleManager()

# ============================================================================
# SAFE LOGGING FUNCTIONS
# ============================================================================

def safe_log(message: str, max_length: int = 500):
    """Safe logging to syslog with length limit"""
    try:
        if isinstance(message, str) and len(message) > max_length:
            message = message[:max_length-3] + "..."

        # Determine syslog priority based on message content
        if any(x in message for x in ["❌", "ERROR", "CRITICAL", "FAILED"]):
            priority = syslog.LOG_ERR
        elif any(x in message for x in ["⚠️", "WARNING", "TIMEOUT"]):
            priority = syslog.LOG_WARNING
        elif any(x in message for x in ["✅", "SUCCESS", "PASSED"]):
            priority = syslog.LOG_INFO
        else:
            priority = syslog.LOG_INFO

        # Log to syslog with mail facility
        syslog.openlog(ident="email_filter", facility=syslog.LOG_MAIL)
        syslog.syslog(priority, message)
        syslog.closelog()

        # Only critical errors to stderr for postfix
        if any(x in message for x in ["ERROR", "CRITICAL", "❌", "TIMEOUT", "EXIT"]):
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}", file=sys.stderr)
    except:
        pass

def safe_header_value(value: Any, max_length: int = 200) -> str:
    """Convert any value to safe header string"""
    try:
        if value is None:
            return ""
        
        if isinstance(value, (int, float)):
            str_value = str(value)
        elif isinstance(value, bool):
            str_value = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            safe_items = [str(item)[:50] for item in value[:5]]
            str_value = "; ".join(safe_items)
        else:
            str_value = str(value)
        
        ascii_value = str_value.encode('ascii', errors='replace').decode('ascii')
        clean_value = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', ascii_value)
        
        if len(clean_value) > max_length:
            clean_value = clean_value[:max_length-3] + "..."
        
        return clean_value.strip()
    
    except Exception as e:
        safe_log(f"Error in safe_header_value: {e}")
        return "error"

def safe_add_header(msg: EmailMessage, header_name: str, header_value: Any, monitor: PerformanceMonitor = None) -> bool:
    """Safely add header to email message"""
    try:
        safe_value = safe_header_value(header_value)
        clean_header_name = re.sub(r'[^\w-]', '', header_name)
        
        if not clean_header_name:
            return False
        
        msg[clean_header_name] = safe_value
        if monitor:
            monitor.metrics['headers_added'] += 1
        
        return True
        
    except Exception as e:
        safe_log(f"Failed to add header {header_name}: {e}")
        return False

def safe_get_header(msg: EmailMessage, header_name: str, default: str = '') -> str:
    """Safely get header value with improved error handling"""
    try:
        # Special handling for Message-ID which can have malformed values
        if header_name == 'Message-ID':
            try:
                header_value = msg.get(header_name, default)
            except (IndexError, ValueError, KeyError, email.errors.HeaderParseError) as e:
                safe_log(f"Malformed Message-ID header, using default: {e}")
                # Try to get raw header instead
                try:
                    raw_headers = str(msg).split('\n')
                    for header in raw_headers:
                        if header.startswith('Message-ID:'):
                            return header[11:].strip()
                except:
                    pass
                return default
        else:
            header_value = msg.get(header_name, default)
        
        if header_value is None:
            return default
        # Handle malformed headers that can't be converted to string
        try:
            return str(header_value)
        except (UnicodeDecodeError, AttributeError) as e:
            safe_log(f"Header {header_name} has encoding issues: {e}")
            # Try to extract just the ASCII parts
            if hasattr(header_value, 'encode'):
                return header_value.encode('ascii', 'ignore').decode('ascii')
            return default
    except Exception as e:
        safe_log(f"Error parsing header {header_name}: {e}")
        return default

def extract_email_from_header(from_header: str) -> str:
    """Extract email address from From header with improved error handling"""
    try:
        if not from_header:
            return ''
        
        from_header = str(from_header).strip()
        
        # Handle malformed brackets like [email@domain]>
        if '[' in from_header and '@' in from_header and ']' in from_header:
            bracket_match = re.search(r'\[([^\]]*@[^\]]+)\]', from_header)
            if bracket_match:
                email = bracket_match.group(1).strip()
                safe_log(f"Extracted from malformed brackets: {email}")
                if '@' in email and '.' in email.split('@')[-1]:
                    return email.lower()
        
        # Standard angle brackets
        if '<' in from_header and '>' in from_header:
            email_match = re.search(r'<([^>]+)>', from_header)
            if email_match:
                email = email_match.group(1).strip()
                if '@' in email and '.' in email.split('@')[-1]:
                    return email.lower()
        
        # Try regex for standard email format
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_header)
        if email_match:
            return email_match.group(0).strip().lower()
        
        # Clean up any brackets and try again
        clean_header = re.sub(r'[\[\]<>]', '', from_header).strip()
        if '@' in clean_header and '.' in clean_header.split('@')[-1]:
            return clean_header.lower()
        
        return ''
        
    except Exception as e:
        safe_log(f"Error extracting email from header: {e}")
        return ''

def safe_extract_domain(from_header: str) -> str:
    """Safely extract domain from From header"""
    try:
        email = extract_email_from_header(from_header)
        if '@' in email:
            return email.split('@')[-1].lower()
        return ''
    except Exception as e:
        safe_log(f"Error extracting domain: {e}")
        return ''

def strip_dangerous_attachments(msg: EmailMessage) -> tuple:
    """
    Remove dangerous attachment types from email and return notification message.

    Returns:
        tuple: (modified_message, list_of_blocked_files)
    """
    try:
        # Load blocked attachments configuration
        config_path = '/opt/spacyserver/config/blocked_attachments.json'
        if not os.path.exists(config_path):
            return (msg, [])

        with open(config_path, 'r') as f:
            config = json.load(f)

        blocked_extensions = [ext.lower() for ext in config.get('blocked_extensions', [])]
        if not blocked_extensions:
            return (msg, [])

        blocked_files = []
        parts_to_keep = []

        # Walk through all message parts
        if msg.is_multipart():
            for part in msg.walk():
                # Skip the main multipart container
                if part.get_content_maintype() == 'multipart':
                    continue

                # Get filename
                filename = part.get_filename()

                if filename:
                    # Check if file extension is blocked
                    file_ext = os.path.splitext(filename.lower())[1]

                    if file_ext in blocked_extensions:
                        blocked_files.append(filename)
                        safe_log(f"🚫 Blocking dangerous attachment: {filename} ({file_ext})")
                        # Don't add this part to parts_to_keep
                        continue

                # Keep this part (not blocked)
                parts_to_keep.append(part)

            # If we blocked any attachments, rebuild the message
            if blocked_files:
                # Create new message with same headers but filtered parts
                new_msg = EmailMessage()

                # Copy all headers from original message
                for key, value in msg.items():
                    new_msg[key] = value

                # Add warning header
                new_msg['X-SpaCy-Attachments-Removed'] = ', '.join(blocked_files)

                # Rebuild multipart structure
                if len(parts_to_keep) == 1 and not parts_to_keep[0].is_multipart():
                    # Only one part left, make it the main content
                    new_msg.set_content(
                        parts_to_keep[0].get_content(),
                        maintype=parts_to_keep[0].get_content_maintype(),
                        subtype=parts_to_keep[0].get_content_subtype()
                    )
                else:
                    # Multiple parts, rebuild as multipart
                    for part in parts_to_keep:
                        new_msg.attach(part)

                return (new_msg, blocked_files)

        return (msg, blocked_files)

    except Exception as e:
        safe_log(f"⚠️  Error in attachment stripping: {e}")
        return (msg, [])

def add_attachment_notification(msg: EmailMessage, blocked_files: list) -> EmailMessage:
    """Add notification message about blocked attachments to email body."""
    try:
        if not blocked_files:
            return msg

        # Load notification template
        config_path = '/opt/spacyserver/config/blocked_attachments.json'
        with open(config_path, 'r') as f:
            config = json.load(f)

        # Format blocked files list
        blocked_list = '\n'.join([f"  • {filename}" for filename in blocked_files])

        # Get notification message and format it
        notification = config.get('notification_message', '')
        notification = notification.format(blocked_files=blocked_list)

        # Add notification to email body
        if msg.is_multipart():
            # Find text/plain or text/html part and append
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    try:
                        existing_content = part.get_content()
                        new_content = existing_content + notification
                        part.set_content(new_content, subtype='plain')
                        safe_log(f"✅ Added attachment notification to text/plain body")
                        break
                    except Exception as e:
                        safe_log(f"Could not append to text/plain: {e}")
                elif content_type == 'text/html':
                    try:
                        existing_content = part.get_content()
                        # Convert notification to HTML
                        html_notification = notification.replace('\n', '<br>\n').replace(' ', '&nbsp;')
                        new_content = existing_content + f'<pre>{html_notification}</pre>'
                        part.set_content(new_content, subtype='html')
                        safe_log(f"✅ Added attachment notification to text/html body")
                        break
                    except Exception as e:
                        safe_log(f"Could not append to text/html: {e}")
        else:
            # Simple message, just append
            try:
                existing_content = msg.get_content()
                new_content = existing_content + notification
                msg.set_content(new_content)
                safe_log(f"✅ Added attachment notification to simple message body")
            except Exception as e:
                safe_log(f"Could not append to simple message: {e}")

        return msg

    except Exception as e:
        safe_log(f"⚠️  Error adding notification: {e}")
        return msg

# ============================================================================
# CORE EMAIL PROCESSING FUNCTIONS
# ============================================================================

def html_to_text(html_content: str) -> str:
    """
    Safely convert HTML to plain text for ML analysis
    Security: Only converts to text, does NOT execute or render HTML
    """
    try:
        # Use BeautifulSoup to parse and extract text
        soup = BeautifulSoup(html_content, 'lxml')

        # Remove script and style elements (they contain no useful content)
        for script in soup(["script", "style"]):
            script.decompose()

        # Get text and clean up whitespace
        text = soup.get_text(separator=' ', strip=True)

        # Normalize whitespace (multiple spaces/newlines to single)
        text = re.sub(r'\s+', ' ', text)

        return text
    except Exception as e:
        # Fallback: simple tag stripping if BeautifulSoup fails
        try:
            text = re.sub(r'<[^>]+>', ' ', html_content)
            text = re.sub(r'\s+', ' ', text)
            return text
        except:
            return html_content  # Last resort: return as-is

def extract_text_content(msg: EmailMessage, max_length: int = 50000) -> str:
    """
    Extract text content from email message with HTML support
    Priority: text/plain > converted HTML
    Security: HTML is converted to text, NOT executed/rendered
    """
    text_content = ""
    html_content = ""

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()

                # Priority 1: Extract text/plain parts
                if content_type == 'text/plain':
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                text_content += payload.decode('utf-8', errors='replace')
                            except:
                                text_content += payload.decode('latin-1', errors='replace')
                    except:
                        text_content += str(part.get_payload())

                    if len(text_content) > max_length:
                        text_content = text_content[:max_length] + "\n[TEXT TRUNCATED FOR PROCESSING]"
                        break

                # Priority 2: Collect HTML parts (for conversion if no text/plain)
                elif content_type == 'text/html' and len(text_content) < 100:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            try:
                                html_raw = payload.decode('utf-8', errors='replace')
                            except:
                                html_raw = payload.decode('latin-1', errors='replace')
                            html_content += html_raw
                    except:
                        pass
        else:
            # Handle non-multipart messages
            payload = msg.get_payload(decode=True)
            if payload:
                try:
                    text_content = payload.decode('utf-8', errors='replace')
                except:
                    try:
                        text_content = payload.decode('latin-1', errors='replace')
                    except:
                        text_content = str(msg.get_payload())

    except Exception as e:
        safe_log(f"Error in extract_text_content: {e}")
        text_content = "Error extracting content"

    # Use text/plain if available, otherwise convert HTML to text
    if text_content and len(text_content.strip()) > 100:
        final_content = text_content
    elif html_content:
        final_content = html_to_text(html_content)
        if final_content:
            # Add marker to track HTML extraction in logs
            safe_log(f"📄 Extracted text from HTML-only email ({len(final_content)} chars)")
    else:
        final_content = text_content if text_content else "No content extracted"

    if len(final_content) > max_length:
        final_content = final_content[:max_length] + "\n[FINAL TRUNCATION]"

    return final_content

def detect_original_authentication(msg: EmailMessage, from_header: str) -> Dict[str, str]:
    """Detect authentication with real validation fallback - FIXED to prevent loops"""
    auth_status = {
        'spf': 'none',
        'dkim': 'none',
        'dmarc': 'none',
        'dmarc_policy': 'none',
        'source': 'none'  # Track where auth came from: 'none', 'upstream', 'arc-microsoft', 'arc-google', 'arc-yahoo'
    }

    try:
        sender_domain = safe_extract_domain(from_header)
        if sender_domain:
            safe_log(f"Sender domain: {sender_domain}")

        auth_results_headers = msg.get_all('Authentication-Results', [])

        # CRITICAL FIX: Limit headers to prevent accumulation from retries
        if len(auth_results_headers) > 10:
            safe_log(f"⚠️ WARNING: {len(auth_results_headers)} auth headers found (likely from retries), limiting to last 5")
            auth_results_headers = auth_results_headers[-5:]  # Only process the most recent headers
        elif len(auth_results_headers) > 5:
            safe_log(f"Note: {len(auth_results_headers)} auth headers found")

        found_existing_auth = False
        headers_processed = 0
        max_headers_to_process = 5  # Safety limit

        for auth_header in auth_results_headers:
            # Safety check to prevent excessive processing
            if headers_processed >= max_headers_to_process:
                safe_log(f"Reached max header processing limit ({max_headers_to_process})")
                break

            auth_str = str(auth_header).lower()

            # Only process headers from our mail servers
            # Check against configured internal mail servers
            internal_servers = CONFIG.config.get('servers', {}).get('internal_ips', [])
            if any(server.lower() in auth_str for server in internal_servers):
                # Only log once, not for every header
                if not found_existing_auth:
                    safe_log(f"Processing existing auth results from {len(auth_results_headers)} header(s)")
                    found_existing_auth = True

                headers_processed += 1

                # Extract authentication results
                for auth_type in ['spf', 'dkim', 'dmarc']:
                    # Skip if we already have a definitive result for this auth type
                    if auth_status[auth_type] not in ['none', 'temperror']:
                        continue

                    if f'{auth_type}=pass' in auth_str:
                        auth_status[auth_type] = 'pass'
                    elif f'{auth_type}=fail' in auth_str:
                        auth_status[auth_type] = 'fail'
                    elif f'{auth_type}=softfail' in auth_str:
                        auth_status[auth_type] = 'softfail'
                    elif f'{auth_type}=neutral' in auth_str:
                        auth_status[auth_type] = 'neutral'
                    elif f'{auth_type}=temperror' in auth_str or f'{auth_type}=tempfail' in auth_str:
                        auth_status[auth_type] = 'temperror'
                    elif f'{auth_type}=none' in auth_str:
                        auth_status[auth_type] = 'none'

                # Extract DMARC policy
                if 'dmarc=fail' in auth_str and auth_status['dmarc_policy'] == 'none':
                    if 'p=reject' in auth_str:
                        auth_status['dmarc_policy'] = 'reject'
                    elif 'p=quarantine' in auth_str:
                        auth_status['dmarc_policy'] = 'quarantine'
                    elif 'p=none' in auth_str:
                        auth_status['dmarc_policy'] = 'none'

                # Early exit if we have all the information we need
                if (auth_status['spf'] != 'none' and
                    auth_status['dkim'] != 'none' and
                    auth_status['dmarc'] != 'none'):
                    auth_status['source'] = 'upstream'
                    safe_log(f"All auth results found after processing {headers_processed} header(s)")
                    break

        if found_existing_auth:
            if auth_status['source'] == 'none':
                auth_status['source'] = 'upstream'
            safe_log(f"Auth results: SPF={auth_status['spf']}, DKIM={auth_status['dkim']}, DMARC={auth_status['dmarc']}")

        if not found_existing_auth and REAL_AUTH_AVAILABLE:
            safe_log("No existing authentication found, performing real validation")

        # Simple ARC header reading for known forwarders (Gmail, Microsoft, Yahoo)
        # This avoids timeout issues from cryptographic verification
        arc_headers = msg.get_all('ARC-Authentication-Results', [])
        if arc_headers and len(arc_headers) > 0:
            # Limit to most recent 3 ARC headers
            recent_arc = arc_headers[-3:] if len(arc_headers) > 3 else arc_headers

            for arc_header in recent_arc:
                arc_str = str(arc_header).lower()

                # Trust ARC from Gmail
                if 'mx.google.com' in arc_str or 'gmail.com' in arc_str:
                    if 'spf=pass' in arc_str or 'dkim=pass' in arc_str:
                        safe_log("✅ Gmail ARC headers detected with passing auth")
                        if 'spf=pass' in arc_str:
                            auth_status['spf'] = 'pass'
                        if 'dkim=pass' in arc_str:
                            auth_status['dkim'] = 'pass'
                        if 'dmarc=pass' in arc_str:
                            auth_status['dmarc'] = 'pass'
                        auth_status['source'] = 'arc-gmail'
                        break

                # Trust ARC from Microsoft
                elif 'protection.outlook.com' in arc_str or 'microsoft.com' in arc_str:
                    if 'spf=pass' in arc_str or 'dkim=pass' in arc_str:
                        safe_log("✅ Microsoft ARC headers detected with passing auth")
                        if 'spf=pass' in arc_str:
                            auth_status['spf'] = 'pass'
                        if 'dkim=pass' in arc_str:
                            auth_status['dkim'] = 'pass'
                        if 'dmarc=pass' in arc_str:
                            auth_status['dmarc'] = 'pass'
                        auth_status['source'] = 'arc-microsoft'
                        break

                # Trust ARC from Yahoo
                elif 'yahoo.com' in arc_str or 'yahoodns.net' in arc_str:
                    if 'spf=pass' in arc_str or 'dkim=pass' in arc_str:
                        safe_log("✅ Yahoo ARC headers detected with passing auth")
                        if 'spf=pass' in arc_str:
                            auth_status['spf'] = 'pass'
                        if 'dkim=pass' in arc_str:
                            auth_status['dkim'] = 'pass'
                        if 'dmarc=pass' in arc_str:
                            auth_status['dmarc'] = 'pass'
                        auth_status['source'] = 'arc-yahoo'
                        break

    except Exception as e:
        safe_log(f"Error in authentication detection: {e}")

    return auth_status

# ============================================================================
# REAL AUTHENTICATION VALIDATION
# ============================================================================

def perform_real_authentication(msg: EmailMessage, from_header: str, monitor: PerformanceMonitor, arc_auth: Dict = None, recipient_domains: list = None) -> Dict:
    """Perform real SPF, DKIM, and DMARC validation (respects ARC-trusted authentication)

    Args:
        msg: Email message
        from_header: From header value
        monitor: Performance monitor
        arc_auth: ARC authentication results (optional)
        recipient_domains: List of recipient domains for whitelist checking (optional)
    """
    auth_results = {
        'spf': 'none',
        'dkim': 'none',
        'dmarc': 'none',
        'dmarc_policy': 'none',
        'validation_method': 'none',
        'auth_score': 0.0
    }

    # Default to empty list if not provided
    if recipient_domains is None:
        recipient_domains = []

    # If ARC authentication is provided and trusted, use it instead of real validation
    if arc_auth and arc_auth.get('dmarc') == 'pass':
        safe_log("✅ Using ARC-trusted authentication instead of real validation")
        auth_results['spf'] = arc_auth.get('spf', 'none')
        auth_results['dkim'] = arc_auth.get('dkim', 'none')
        auth_results['dmarc'] = 'pass'
        auth_results['dmarc_policy'] = 'none'  # ARC overrides policy
        auth_results['validation_method'] = 'arc_trusted'
        auth_results['auth_score'] = 5.0  # Moderate score for ARC-trusted auth (reduced from 10.0 to prevent spam bypass)
        return auth_results

    if not REAL_AUTH_AVAILABLE:
        safe_log("Real authentication libraries not available")
        auth_results['validation_method'] = 'unavailable'
        return auth_results
    
    try:
        sender_email = extract_email_from_header(from_header)
        sender_domain = safe_extract_domain(from_header)
        
        if not sender_email or not sender_domain:
            safe_log("⚠️ Cannot extract sender information for authentication - treating as suspicious")
            auth_results['validation_method'] = 'invalid_sender'
            auth_results['spf'] = 'fail'
            auth_results['dkim'] = 'fail'
            auth_results['dmarc'] = 'fail'
            auth_results['dmarc_policy'] = 'reject'
            auth_results['auth_score'] = -12.0  # Heavy penalty for unparseable sender (negative = bad)
            return auth_results

        # Extract envelope sender from Return-Path for SPF validation
        # SPF validates the envelope sender (MAIL FROM), not the From header!
        envelope_sender = safe_get_header(msg, 'Return-Path', '')
        spf_email = sender_email  # Default to From header if no Return-Path
        spf_domain = sender_domain  # Default to From header domain

        if envelope_sender:
            # Clean up Return-Path (remove < > brackets)
            envelope_sender = envelope_sender.strip().strip('<>')

            # Extract email and domain from envelope sender
            if '@' in envelope_sender:
                spf_email = envelope_sender
                spf_domain = envelope_sender.split('@')[1].strip().lower()
                safe_log(f"📧 Envelope sender (Return-Path): {envelope_sender}")
                safe_log(f"🔍 SPF will check domain: {spf_domain} (not {sender_domain})")
            else:
                safe_log(f"⚠️ Return-Path exists but no @ sign: {envelope_sender}")
        else:
            safe_log(f"⚠️ No Return-Path header - using From header domain for SPF: {sender_domain}")

        # Get sender IP - use the IP that connected directly to OUR server
        # This is found in the FIRST (topmost/newest) Received header
        sender_ip = None
        received_headers = msg.get_all('Received', [])

        # Parse the FIRST Received header (the one OUR server added)
        # Format: "from <hostname> ([<ip>]) by our-server..."
        if received_headers:
            first_received = str(received_headers[0])
            safe_log(f"First Received header: {first_received[:200]}")

            # Extract the IP from the first Received header
            # Look for pattern: "from <hostname> (...[<ip>]...) by"
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
            if ip_match:
                sender_ip = ip_match.group(1)
                safe_log(f"✓ Found sender IP from first Received header: {sender_ip}")
            else:
                safe_log(f"⚠️ Could not extract IP from first Received header")

        if not sender_ip:
            sender_ip = CONFIG.config['servers']['internal_ips'][0]
            safe_log(f"No external sender IP found, using default: {sender_ip}")

        # Determine mail direction based on sender_ip and recipient domains
        mail_direction = 'inbound'  # Default
        sender_is_internal = False

        if sender_ip:
            try:
                sender_ip_obj = ipaddress.ip_address(sender_ip)
                # Check if sender IP is from internal network
                internal_networks_for_direction = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.0/8']
                for network in internal_networks_for_direction:
                    if sender_ip_obj in ipaddress.ip_network(network):
                        sender_is_internal = True
                        break
            except Exception as e:
                safe_log(f"Mail direction detection error: {e}")

        # Store for later use - will refine direction after we have recipient info
        mail_direction = 'outbound' if sender_is_internal else 'inbound'
        if sender_is_internal:
            safe_log(f"📤 Internal sender IP detected: {sender_ip}")
        else:
            safe_log(f"📥 External sender IP detected: {sender_ip}")

        # Check if sender IP is in trusted networks
        is_trusted_network = False
        try:
            with open('/opt/spacyserver/config/authentication_config.json', 'r') as f:
                auth_config = json.load(f)
                if auth_config.get('trusted_network_spf_bypass', False):
                    trusted_networks = auth_config.get('trusted_networks', [])
                    sender_ip_obj = ipaddress.ip_address(sender_ip)
                    for network in trusted_networks:
                        if sender_ip_obj in ipaddress.ip_network(network):
                            is_trusted_network = True
                            safe_log(f"✅ Sender IP {sender_ip} is in trusted network {network} - SPF will pass")
                            break
        except Exception as e:
            safe_log(f"Error checking trusted networks: {e}")

        # SPF Validation with subprocess timeout (more robust)
        # Temporary workaround for problematic domains with complex SPF includes
        problematic_domains = ['irwinresearch.com', 'kawancicil.com']

        if is_trusted_network:
            safe_log(f"Trusted network detected - automatically passing SPF for {spf_email}")
            auth_results['spf'] = 'pass'
        elif spf_domain in problematic_domains:
            safe_log(f"Skipping SPF check for problematic domain {spf_domain} - marking as temperror")
            auth_results['spf'] = 'temperror'
        else:
            safe_log(f"Checking SPF for {spf_email} (envelope sender) from {sender_ip}")
            auth_results['spf'] = check_spf_subprocess(
                sender_ip,
                spf_email,
                spf_domain,
                timeout=min(CONFIG.config['timeouts']['auth_timeout'], 5)  # Max 5 seconds for SPF
            )
            safe_log(f"SPF Result: {auth_results['spf']}")
        
        # DKIM Validation with timeout
        try:
            safe_log("Checking DKIM signature")
            with timeout_handler(CONFIG.config['timeouts']['auth_timeout']):
                dkim_result = dkim.verify(msg.as_bytes())
                auth_results['dkim'] = 'pass' if dkim_result else 'fail'
                safe_log(f"DKIM Result: {'pass' if dkim_result else 'fail'}")

                # Extract DKIM signing domain and check alignment
                auth_results['dkim_aligned'] = False
                if dkim_result:  # Only check alignment if DKIM passed
                    dkim_header = msg.get('DKIM-Signature', '')
                    if dkim_header:
                        # Extract d= parameter (signing domain)
                        dkim_domain_match = re.search(r'd=([^;\s]+)', dkim_header, re.IGNORECASE)
                        if dkim_domain_match:
                            dkim_domain = dkim_domain_match.group(1).strip()
                            # Check if DKIM domain matches or is subdomain of From domain
                            # e.g., dattobackup.com matches dattobackup.com
                            # or services.discover.com matches discover.com
                            if dkim_domain == sender_domain or sender_domain.endswith('.' + dkim_domain) or dkim_domain.endswith('.' + sender_domain):
                                auth_results['dkim_aligned'] = True
                                safe_log(f"✓ DKIM domain alignment: {dkim_domain} matches {sender_domain}")
                            else:
                                safe_log(f"⚠️ DKIM domain mismatch: signature from {dkim_domain}, email from {sender_domain}")
        except TimeoutException:
            safe_log(f"DKIM check timed out after {CONFIG.config['timeouts']['auth_timeout']}s")
            auth_results['dkim'] = 'temperror'
            auth_results['dkim_aligned'] = False
        except Exception as e:
            safe_log(f"DKIM check error: {e}")
            auth_results['dkim'] = 'temperror'
            auth_results['dkim_aligned'] = False
        
        # DMARC Validation
        try:
            safe_log(f"Checking DMARC policy for {sender_domain}")
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            dmarc_domain = f"_dmarc.{sender_domain}"
            try:
                dmarc_records = resolver.resolve(dmarc_domain, 'TXT')
                for record in dmarc_records:
                    record_str = str(record).strip('"')
                    if 'v=DMARC1' in record_str:
                        safe_log(f"DMARC Record found: {record_str[:100]}")
                        
                        # Extract policy
                        if 'p=reject' in record_str:
                            auth_results['dmarc_policy'] = 'reject'
                        elif 'p=quarantine' in record_str:
                            auth_results['dmarc_policy'] = 'quarantine'
                        elif 'p=none' in record_str:
                            auth_results['dmarc_policy'] = 'none'
                        
                        # Determine DMARC result based on SPF and DKIM
                        if auth_results['spf'] == 'pass' or auth_results['dkim'] == 'pass':
                            auth_results['dmarc'] = 'pass'
                        else:
                            auth_results['dmarc'] = 'fail'
                        break
            except dns.resolver.NXDOMAIN:
                safe_log("No DMARC record found")
                auth_results['dmarc'] = 'none'
            except Exception as e:
                safe_log(f"DMARC lookup error: {e}")
                auth_results['dmarc'] = 'temperror'
        
        except Exception as e:
            safe_log(f"DMARC check error: {e}")
            auth_results['dmarc'] = 'temperror'
        
        auth_results['validation_method'] = 'real'
        
        # Calculate authentication score
        # IMPORTANT: Changed scoring to prevent phishing bypass
        # Passing auth does NOT mean email is safe - phishing often comes from compromised accounts
        auth_score = 0.0
        
        # SPF scoring - reduced positive scores, increased penalties
        spf_result = auth_results['spf']
        if spf_result == 'pass':
            auth_score += 1.0  # Reduced from 5.0 - SPF pass is easily spoofed
        elif spf_result == 'softfail':
            auth_score -= 2.0  # Increased from -1.0
        elif spf_result == 'fail':
            auth_score -= 5.0  # Increased from -3.0
        elif spf_result == 'none':
            auth_score -= 2.0  # Penalty for no SPF record - legitimate senders publish SPF

        # DKIM scoring - moderate positive, strong negative
        dkim_result = auth_results['dkim']
        if dkim_result == 'pass':
            auth_score += 2.0  # Reduced from 5.0 - DKIM can be valid for compromised accounts
        elif dkim_result == 'fail':
            auth_score -= 4.0  # Increased from -2.0
        elif dkim_result == 'none':
            auth_score -= 1.0  # Penalty for no DKIM - can't verify sender authenticity

        # DMARC scoring - slightly higher positive, strong negative
        dmarc_result = auth_results['dmarc']
        if dmarc_result == 'pass':
            auth_score += 2.0  # Reduced from 4.0 - DMARC alignment doesn't prevent phishing
        elif dmarc_result == 'fail':
            auth_score -= 5.0  # Increased from -2.0, especially bad with reject policy
            if auth_results.get('dmarc_policy') == 'reject':
                auth_score -= 3.0  # Additional penalty for violating reject policy
        elif dmarc_result == 'none':
            auth_score -= 1.0  # Penalty for no DMARC - sender doesn't protect against spoofing
        
        # Cap the maximum positive score to prevent bypassing spam filters
        # Phishing emails from compromised accounts shouldn't get huge credits
        if auth_score > 3.0:
            auth_score = 3.0
            safe_log("⚠️ Auth score capped at 3.0 to prevent phishing bypass")
        
        # Apply sender reputation adjustments for known good but misconfigured senders
        try:
            from modules.sender_reputation import apply_reputation_adjustment
            subject = msg.get('Subject', '')
            adjusted_score, reputation_info = apply_reputation_adjustment(
                auth_score, sender_email, sender_ip, auth_results, subject
            )
            
            if reputation_info['adjustment'] > 0:
                safe_log(f"📊 Reputation adjustment: {auth_score} → {adjusted_score} ({', '.join(reputation_info['notes'])})")
                auth_score = adjusted_score
                auth_results['reputation_adjustment'] = reputation_info['adjustment']
                auth_results['reputation_notes'] = reputation_info['notes']
        except Exception as e:
            safe_log(f"Reputation check error: {e}")
        
        auth_results['auth_score'] = auth_score

        # Apply whitelist bonus to auth score for whitelisted senders
        # This prevents SPACY_AUTH_FAIL penalty in SpamAssassin for trusted senders
        # Check BOTH bec_config.json (legacy) AND trusted_entities database (new)
        try:
            from pathlib import Path

            # Extract sender email from From header (remove display name if present)
            sender_email_for_wl = sender_email.lower().strip()
            if '<' in sender_email_for_wl and '>' in sender_email_for_wl:
                # Extract just the email address from "Display Name <email@domain.com>" format
                sender_email_for_wl = sender_email_for_wl.split('<')[1].split('>')[0].strip()
            trust_bonus_applied = False

            # CHECK 1: Database whitelist (trusted_entities) - NEW SYSTEM
            try:
                # FIXED: Now passing recipient_domains for per-domain whitelist matching
                db_whitelist = check_trusted_entities_whitelist(sender_email_for_wl, recipient_domains)
                if db_whitelist['is_whitelisted']:
                    # Apply trust bonus based on trust_level enum
                    trust_level = db_whitelist.get('trust_level', 'reduce_scoring')

                    # Map trust_level to auth bonus
                    # skip_rbl (1-3): +5, reduce_scoring (4-6): +8, bypass_all (7-10): +12
                    if trust_level == 'skip_rbl':
                        trust_bonus = 5
                    elif trust_level == 'reduce_scoring':
                        trust_bonus = 8
                    elif trust_level == 'bypass_all':
                        trust_bonus = 12
                    else:
                        trust_bonus = 5  # Default fallback

                    original_auth_score = auth_score
                    auth_score += trust_bonus
                    auth_results['auth_score'] = auth_score
                    auth_results['whitelist_auth_bonus'] = trust_bonus
                    auth_results['whitelist_trust_level'] = trust_level
                    auth_results['whitelist_source'] = 'database'
                    auth_results['whitelist_scope'] = db_whitelist['scope']
                    safe_log(f"✅ Database whitelisted sender ({db_whitelist['scope']}, trust_level={trust_level}) - auth score boosted from {original_auth_score} to {auth_score} (+{trust_bonus})")
                    trust_bonus_applied = True
            except Exception as db_err:
                safe_log(f"Error checking database whitelist: {db_err}")

            # CHECK 1.5: blocking_rules table whitelist - NEW
            if not trust_bonus_applied and DB_CONN:
                try:
                    cursor = DB_CONN.cursor(dictionary=True)
                    # Get whitelist rules for recipient domains + global rules
                    domain_list = "','".join(recipient_domains) if recipient_domains else ""

                    # Extract sender domain from email
                    sender_domain = sender_email_for_wl.split('@')[-1] if '@' in sender_email_for_wl else ""

                    # Build WHERE clause - check global whitelists even if no recipient_domains
                    if domain_list:
                        domain_where = f"(cd.domain IN ('{domain_list}') OR br.is_global = 1)"
                    else:
                        # No recipient domains - only check global whitelists
                        domain_where = "br.is_global = 1"
                        safe_log(f"⚠️ No recipient domains found, checking global whitelists only")

                    cursor.execute(f"""
                        SELECT DISTINCT br.rule_type, br.rule_value, br.rule_pattern, br.priority, br.description
                        FROM blocking_rules br
                        LEFT JOIN client_domains cd ON br.client_domain_id = cd.id
                        WHERE {domain_where}
                        AND br.whitelist = 1
                        AND br.active = 1
                        AND (
                            (br.rule_type = 'sender' AND br.rule_value = %s)
                            OR (br.rule_type = 'sender_domain' AND br.rule_value = %s)
                        )
                        ORDER BY br.priority DESC
                        LIMIT 1
                    """, (sender_email_for_wl, sender_domain))

                    whitelist_rule = cursor.fetchone()
                    cursor.close()

                    if whitelist_rule:
                            # Apply trust bonus based on priority
                            # Priority 100 (Level 5) = bypass_all (+12)
                            # Priority 50-99 = reduce_scoring (+8)
                            # Priority 1-49 = skip_rbl (+5)
                            priority = whitelist_rule.get('priority', 10)
                            if priority >= 100:
                                trust_bonus = 12
                                trust_level = 'bypass_all'
                            elif priority >= 50:
                                trust_bonus = 8
                                trust_level = 'reduce_scoring'
                            else:
                                trust_bonus = 5
                                trust_level = 'skip_rbl'

                            original_auth_score = auth_score
                            auth_score += trust_bonus
                            auth_results['auth_score'] = auth_score
                            auth_results['whitelist_auth_bonus'] = trust_bonus
                            auth_results['whitelist_trust_level'] = trust_level
                            auth_results['whitelist_source'] = 'blocking_rules'
                            auth_results['whitelist_priority'] = priority
                            safe_log(f"✅ blocking_rules whitelisted sender (priority={priority}, trust_level={trust_level}) - auth score boosted from {original_auth_score} to {auth_score} (+{trust_bonus}) - {whitelist_rule.get('description', '')}")
                            trust_bonus_applied = True
                except Exception as br_err:
                    safe_log(f"Error checking blocking_rules whitelist: {br_err}")

            # CHECK 2: bec_config.json whitelist (legacy) - only if not already applied from database
            if not trust_bonus_applied:
                bec_config_path = Path("/opt/spacyserver/config/bec_config.json")
                if bec_config_path.exists():
                    with open(bec_config_path, 'r') as f:
                        bec_config = json.load(f)

                    # Check authentication-aware whitelist for trust bonus
                    whitelist = bec_config.get('whitelist', {})
                    if 'authentication_aware' in whitelist and 'senders' in whitelist['authentication_aware']:
                        auth_senders = whitelist['authentication_aware']['senders']
                        for email_key, sender_config in auth_senders.items():
                            if sender_email_for_wl == email_key.lower().strip():
                                trust_bonus = sender_config.get('trust_score_bonus', 0)
                                if trust_bonus > 0:
                                    original_auth_score = auth_score
                                    auth_score += trust_bonus
                                    auth_results['auth_score'] = auth_score
                                    auth_results['whitelist_auth_bonus'] = trust_bonus
                                    auth_results['whitelist_source'] = 'bec_config'
                                    safe_log(f"✅ BEC config whitelisted sender - auth score boosted from {original_auth_score} to {auth_score} (+{trust_bonus})")
                                break
        except Exception as e:
            safe_log(f"Error applying whitelist auth bonus: {e}")

        # CRITICAL: Re-apply cap AFTER all bonuses (reputation + whitelist)
        # This prevents authentication from becoming a "super trusted" signal that overwhelms risk indicators
        if auth_score > 3.0:
            original_score = auth_score
            auth_score = 3.0
            auth_results['auth_score'] = 3.0
            safe_log(f"⚠️ Auth score re-capped at 3.0 after bonuses (was {original_score:.1f})")
            safe_log(f"   Reason: Authentication should not override RBL/routing/phishing indicators")

        safe_log(f"🔐 Real authentication complete: SPF={spf_result}, DKIM={dkim_result}, DMARC={dmarc_result}, Score={auth_score}")

        try:
            monitor.record_auth_results(auth_results)
            safe_log(f"📧 Auth results recorded")
        except Exception as e:
            safe_log(f"❌ Failed to record auth results: {e}")
        
    except Exception as e:
        safe_log(f"Real authentication error: {e}")
        auth_results['validation_method'] = 'failed'
        auth_results['error'] = str(e)
    
    return auth_results

# ============================================================================
# AUTHENTICATION ABUSE DETECTION
# ============================================================================

def detect_authentication_abuse(msg: EmailMessage, from_header: str, text_content: str) -> Dict:
    """Detect authentication abuse from known scammers"""
    abuse_indicators = {
        'known_scammer': False,
        'abuse_score': 0.0,
        'abuse_reasons': []
    }
    
    try:
        # Known scammer patterns
        known_scammers = [
            ('victoria chavez', 'Known scammer: Victoria Chavez'),
            ('victoriachavez', 'Known scammer: Victoria Chavez variant'),
            ('vchavez', 'Known scammer: V Chavez variant'),
            ('rebecca thompson', 'Known scammer: Rebecca Thompson'),
            ('michael johnson', 'Known scammer: Michael Johnson (generic)'),
            ('sarah williams', 'Known scammer: Sarah Williams (generic)'),
            ('david brown', 'Known scammer: David Brown (generic)')
        ]
        
        from_lower = from_header.lower()
        text_lower = text_content[:5000].lower() if text_content else ''
        
        # Check for known scammers
        for scammer_pattern, reason in known_scammers:
            if scammer_pattern in from_lower:
                abuse_indicators['known_scammer'] = True
                abuse_indicators['abuse_score'] += 50.0
                abuse_indicators['abuse_reasons'].append(reason)
                safe_log(f"🚨 AUTHENTICATION ABUSE: {reason}")
        
        # Check for authentication spoofing attempts
        auth_spoofing_patterns = [
            ('authentication-results:', 'Fake auth header in body'),
            ('dkim=pass', 'Fake DKIM pass in body'),
            ('spf=pass', 'Fake SPF pass in body'),
            ('dmarc=pass', 'Fake DMARC pass in body'),
            ('x-spam-status: no', 'Fake spam status in body'),
            ('x-spam-score: 0', 'Fake spam score in body')
        ]
        
        for pattern, reason in auth_spoofing_patterns:
            if pattern in text_lower:
                abuse_indicators['abuse_score'] += 20.0
                abuse_indicators['abuse_reasons'].append(reason)
                safe_log(f"⚠️ Possible auth spoofing: {reason}")
        
        # Check for multiple From addresses in headers only (common in spoofing)
        # Use the actual email headers from the message object, not text content
        from_headers = msg.get_all('From', [])
        if len(from_headers) > 1:
            abuse_indicators['abuse_score'] += 15.0
            abuse_indicators['abuse_reasons'].append(f"Multiple From addresses: {len(from_headers)}")
        
        # Check for mismatched sender names
        if '<' in from_header and '>' in from_header:
            display_name = from_header.split('<')[0].strip().lower()
            if display_name:
                # Check if display name mentions a different email provider
                if ('gmail' in display_name and 'gmail.com' not in from_lower) or \
                   ('outlook' in display_name and 'outlook.com' not in from_lower) or \
                   ('yahoo' in display_name and 'yahoo.com' not in from_lower):
                    abuse_indicators['abuse_score'] += 25.0
                    abuse_indicators['abuse_reasons'].append("Display name provider mismatch")
        
        safe_log(f"Auth abuse detection - Score: {abuse_indicators['abuse_score']}, Reasons: {abuse_indicators['abuse_reasons']}")
        
    except Exception as e:
        safe_log(f"Error in auth abuse detection: {e}")
    
    return abuse_indicators

# ============================================================================
# SPAM ANALYSIS FUNCTIONS - ENHANCED WITH TIMEOUT HANDLING
# ============================================================================

def analyze_email_with_modules(msg: EmailMessage, text_content: str, from_header: str, monitor: PerformanceMonitor, auth_results: Dict = None, is_spoofed_trusted: bool = False) -> Dict:
    """Run all available analysis modules with proper timeout handling"""
    analysis_results = {
        'spam_score': 0.0,
        'headers_to_add': {},
        'modules_run': [],
        'spam_modules_detail': {}  # Track individual module contributions
    }

    # Add auth_results early so it's included in cache and always available
    if auth_results:
        analysis_results['auth_results'] = auth_results

    # ========================================================================
    # SPAM RESULT CACHE LOOKUP - Check if we've analyzed this email before
    # ========================================================================
    if SPAM_CACHE and SPAM_CACHE.cache_enabled:
        try:
            subject = safe_get_header(msg, 'Subject', '')
            cached_result = SPAM_CACHE.get_cached_result(from_header, subject)

            if cached_result:
                # Remove cache metadata before returning
                result = {k: v for k, v in cached_result.items() if not k.startswith('_')}
                result['headers_to_add']['X-SpaCy-Cache-Hit'] = 'true'
                monitor.log_event("cache_hit")

                # ML scoring disabled in this release
                # ML ensemble can be added in future versions

                return result
        except Exception as e:
            safe_log(f"Cache lookup error: {e}")
    # ========================================================================

    # Apply penalty for spoofed trusted domains (auth failed for trusted domain)
    if is_spoofed_trusted:
        spoofed_penalty = 15.0
        analysis_results['spam_score'] += spoofed_penalty
        analysis_results['spam_modules_detail']['spoofed_trusted'] = spoofed_penalty
        analysis_results['headers_to_add']['X-Spoofed-Trusted-Domain'] = 'true'
        safe_log(f"⚠️ SPOOFED TRUSTED DOMAIN PENALTY: +{spoofed_penalty} points")

    # Get module timeout from config
    module_timeout = CONFIG.config['timeouts']['module_timeout']

    # Check if this is a trusted domain - use minimal analysis
    sender_domain = safe_extract_domain(from_header)
    # Check exact match first (fast O(1) lookup)
    is_trusted = sender_domain in CONFIG.config['domains']['trusted_domains']
    # If no exact match, check wildcard patterns (e.g., *.chase.com matches mcmap.chase.com)
    if not is_trusted and sender_domain:
        for wildcard_suffix in CONFIG.config['domains'].get('trusted_domain_wildcards', []):
            if sender_domain.endswith(wildcard_suffix):
                is_trusted = True
                break

    # Debug logging for trusted domain detection
    if sender_domain:
        safe_log(f"🔍 Sender domain: {sender_domain}, Trusted: {is_trusted}")

    # Initialize sender_is_internal flag (used by some modules)
    # Note: This function doesn't have access to Received headers/IP info,
    # so we default to False (external sender)
    sender_is_internal = False

    # OPTION 1: Whitelist internal digest emails (fix for digest quarantine issue)
    sender_email = from_header
    if '<' in from_header and '>' in from_header:
        sender_email = from_header.split('<')[1].split('>')[0].strip().lower()
    else:
        sender_email = from_header.strip().lower()

    # Check for internal digest sender (configurable via INTERNAL_DIGEST_SENDER env var)
    internal_digest_sender = os.getenv('INTERNAL_DIGEST_SENDER', '').lower()
    if internal_digest_sender and sender_email == internal_digest_sender:
        is_trusted = True
        safe_log(f"✅ Internal digest sender - marking as trusted")

    if is_trusted:
        safe_log(f"Trusted domain {sender_domain} - minimal analysis")
        # Only run essential modules for trusted domains

    # Load BEC whitelist configuration early to check bypass flags
    bypass_aggressive_checks = False
    try:
        from pathlib import Path
        bec_config_path = Path("/opt/spacyserver/config/bec_config.json")
        if bec_config_path.exists():
            with open(bec_config_path, 'r') as f:
                bec_config = json.load(f)

            # Extract sender email from From header
            sender_email = from_header
            if '<' in from_header and '>' in from_header:
                sender_email = from_header.split('<')[1].split('>')[0].strip().lower()
            else:
                sender_email = from_header.strip().lower()

            # Check authentication-aware whitelist for bypass flags
            whitelist = bec_config.get('whitelist', {})
            if 'authentication_aware' in whitelist and 'senders' in whitelist['authentication_aware']:
                auth_senders = whitelist['authentication_aware']['senders']
                for email_key, sender_config in auth_senders.items():
                    if sender_email == email_key.lower().strip():
                        # Check if sender has bypass flags
                        if sender_config.get('bypass_bec_checks', False):
                            bypass_aggressive_checks = True
                            safe_log(f"✅ Sender {sender_email} has bypass_bec_checks - skipping aggressive URL and thread analysis")
                            break
    except Exception as e:
        safe_log(f"Error loading BEC whitelist for bypass check: {e}")

    # Create standardized email_data dictionary for all modules
    email_data = {
        'from': from_header,
        'to': safe_get_header(msg, 'To', ''),
        'subject': safe_get_header(msg, 'Subject', ''),
        'body': text_content[:10000],  # Limit size for performance
        'display_name': from_header.split('<')[0].strip() if '<' in from_header else '',
        'headers': dict(msg.items()),
        # Add authentication status for BEC whitelist checking
        'spf_pass': auth_results.get('spf', 'none') == 'pass' if auth_results else False,
        'dkim_valid': auth_results.get('dkim', 'none') == 'pass' if auth_results else False,
        'dmarc_pass': auth_results.get('dmarc', 'none') == 'pass' if auth_results else False
    }

    # Detect attachments
    has_attachments = False
    try:
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                has_attachments = True
                break
    except Exception as e:
        safe_log(f"Error detecting attachments: {e}")

    analysis_results['has_attachments'] = has_attachments

    try:
        # DNS validation with timeout
        if MODULE_MANAGER.is_available('email_dns') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    dns_validator = MODULE_MANAGER.get_module('email_dns')
                    # DNS expects msg and text_content
                    dns_results = dns_validator(msg, text_content)
                    if dns_results and isinstance(dns_results, dict) and 'dns_spam_score' in dns_results:
                        dns_score = dns_results['dns_spam_score']
                        analysis_results['spam_score'] += dns_score
                        if dns_score > 0:
                            analysis_results['spam_modules_detail']['dns'] = dns_score
                        analysis_results['modules_run'].append('dns')
                        analysis_results['headers_to_add']['X-Spam-Score-DNS'] = str(round(dns_score, 2))
                        monitor.record_module('dns')
                        safe_log(f"DNS module completed - score: +{dns_score}")
            except TimeoutException:
                safe_log(f"⏱️ DNS module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"DNS module error: {e}")

        # RBL (Real-time Blackhole List) checking with timeout
        if MODULE_MANAGER.is_available('rbl_checker') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_rbl = MODULE_MANAGER.get_module('rbl_checker')
                    # Extract sender IP from message headers
                    sender_ip = None
                    received_header = safe_get_header(msg, 'Received', '')
                    if received_header:
                        # Try to extract IP from first Received header
                        import re
                        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_header)
                        if ip_match:
                            sender_ip = ip_match.group(1)

                    if sender_ip:
                        rbl_data = {'sender_ip': sender_ip}
                        rbl_results = analyze_rbl(rbl_data)
                        if rbl_results and isinstance(rbl_results, dict):
                            if rbl_results.get('detected', False):
                                rbl_score = rbl_results.get('rbl_score', 0)

                                # Check if email passed all 3 authentication methods
                                if auth_results:
                                    spf_pass = auth_results.get('spf', '').lower() == 'pass'
                                    dkim_pass = auth_results.get('dkim', '').lower() == 'pass'
                                    dmarc_pass = auth_results.get('dmarc', '').lower() == 'pass'
                                    full_auth = spf_pass and dkim_pass and dmarc_pass

                                    # Reduce RBL penalty for authenticated emails
                                    if full_auth:
                                        # FULL AUTH: 80% reduction - authenticated senders shouldn't be heavily penalized for IP reputation
                                        original_rbl = rbl_score
                                        rbl_score = rbl_score * 0.20
                                        safe_log(f"RBL score reduced by 80% for full auth: {original_rbl:.1f} → {rbl_score:.1f}")

                                analysis_results['spam_score'] += rbl_score
                                if rbl_score > 0:
                                    analysis_results['spam_modules_detail']['rbl'] = rbl_score
                                analysis_results['headers_to_add']['X-Spam-Score-RBL'] = str(round(rbl_score, 2))
                                safe_log(f"RBL hits detected - score: +{rbl_score}, hits: {len(rbl_results.get('rbl_hits', []))}")

                            # Add RBL headers
                            if 'headers_to_add' in rbl_results:
                                analysis_results['headers_to_add'].update(rbl_results['headers_to_add'])

                            analysis_results['modules_run'].append('rbl')
                            monitor.record_module('rbl')
                    else:
                        safe_log("RBL check skipped - no sender IP found")
            except TimeoutException:
                safe_log(f"⏱️ RBL module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"RBL module error: {e}")

        # Phishing detection with timeout
        if MODULE_MANAGER.is_available('email_phishing'):
            try:
                with timeout_handler(module_timeout):
                    detect_phishing = MODULE_MANAGER.get_module('email_phishing')
                    # New phishing detector takes msg, text_content, from_header
                    phishing_results = detect_phishing(msg, text_content, from_header)
                    if phishing_results and isinstance(phishing_results, dict):
                        # Phishing module returns component scores (0-10+ range), not 0-1
                        # Risk thresholds: 8.0+ high, 5.0-8.0 medium, 3.0-5.0 suspicious
                        # Cap contribution at 12 points max to prevent over-scoring
                        risk_score = phishing_results.get('risk_score', 0)
                        phishing_type = phishing_results.get('phishing_type', 'unknown')

                        # Lottery/419 scams get higher cap since they often don't have URLs
                        # and may pass email authentication (sent from real gmail accounts)
                        if phishing_type == 'lottery_419_scam' and risk_score >= 10.0:
                            phishing_spam_points = min(risk_score, 18.0)  # Higher cap for lottery scams
                            safe_log(f"🎰 Lottery/419 scam detected - using higher cap: {phishing_spam_points:.1f}")
                        else:
                            phishing_spam_points = min(risk_score, 12.0)

                        # Reduce phishing score for trusted domains (invitations/verifications look like phishing)
                        if is_trusted and phishing_spam_points > 0:
                            original_phishing = phishing_spam_points
                            phishing_spam_points = phishing_spam_points * 0.10  # 90% reduction
                            safe_log(f"🔒 Trusted domain - reducing phishing score by 90%: {original_phishing:.1f} → {phishing_spam_points:.1f}")

                        if phishing_spam_points > 0:
                            analysis_results['spam_score'] += phishing_spam_points
                            analysis_results['spam_modules_detail']['phishing'] = phishing_spam_points
                            analysis_results['headers_to_add']['X-Spam-Score-Phishing'] = str(round(phishing_spam_points, 2))
                            analysis_results['modules_run'].append('phishing')
                            monitor.record_module('phishing')

                            if phishing_results.get('detected', False) or risk_score >= 0.6:
                                safe_log(f"🎣 Phishing detected - type: {phishing_results.get('phishing_type', 'unknown')}, risk: {risk_score:.3f}, points: +{phishing_spam_points:.1f}")

                            # Send notification for phishing detection
                            if NOTIFICATION_SERVICE:
                                try:
                                    email_data = {
                                        'sender': from_header,
                                        'trigger_reason': 'phishing_detected',
                                        'message_id': safe_get_header(msg, 'Message-ID', 'unknown'),
                                        'spam_score': analysis_results['spam_score']
                                    }
                                    NOTIFICATION_SERVICE.send_high_risk_alert(email_data)
                                except Exception as notif_err:
                                    safe_log(f"Notification error: {notif_err}")

                            # Add comprehensive phishing headers
                            analysis_results['headers_to_add']['X-Phishing-Detected'] = 'true' if phishing_results.get('is_phishing', False) else 'false'
                            analysis_results['headers_to_add']['X-Phishing-Score'] = str(round(risk_score, 3))
                            analysis_results['headers_to_add']['X-Phishing-Risk-Level'] = phishing_results.get('risk_level', 'unknown')

                            # Add component scores for transparency
                            component_scores = phishing_results.get('component_scores', {})
                            if component_scores:
                                score_parts = []
                                for key, value in component_scores.items():
                                    score_parts.append(f"{key}:{value:.2f}")
                                analysis_results['headers_to_add']['X-Phishing-Components'] = ', '.join(score_parts)

                            # Add original headers from module (if any)
                            for header_name, header_value in phishing_results.get('headers_to_add', {}).items():
                                analysis_results['headers_to_add'][header_name] = header_value
            except TimeoutException:
                safe_log(f"⏱️ Phishing module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Phishing module error: {e}")

        # Early thread detection for URL reputation context
        thread_info = check_thread_continuity(msg, text_content)

        # URL Reputation checking with timeout (skip if sender has bypass_bec_checks)
        if MODULE_MANAGER.is_available('url_reputation') and not bypass_aggressive_checks:
            try:
                with timeout_handler(module_timeout):
                    analyze_urls = MODULE_MANAGER.get_module('url_reputation')
                    url_results = analyze_urls(msg)
                    if url_results and isinstance(url_results, dict):
                        # Add risk score to spam score with cap to prevent marketing email false positives
                        if url_results.get('total_risk_score', 0) > 0:
                            # Get thread trust info to reduce false positives for legitimate email threads
                            thread_trust = thread_info.get('trust_score', 0)
                            is_reply = thread_info.get('is_reply', False)

                            # Check for legitimate Email Service Provider (ESP) tracking domains
                            # Common ESPs: Amazon SES, SendGrid, Mailchimp, Constant Contact, etc.
                            legitimate_esp_domains = [
                                'awstrack.me', 'amazonses.com', 'amazonaws.com',  # Amazon SES
                                'sendgrid.net', 'sendgrid.com',  # SendGrid
                                'mailchimp.com', 'list-manage.com',  # Mailchimp
                                'constantcontact.com', 'ctctcdn.com',  # Constant Contact
                                'sailthru.com', 'mailer-sailthru.com',  # Sailthru
                                'sparkpostmail.com', 'sparkpost.com',  # SparkPost
                                'mailgun.org', 'mailgun.net',  # Mailgun
                                'mandrillapp.com', 'mandrill.com',  # Mandrill
                                'postmarkapp.com',  # Postmark
                                'app.link', 'branch.io',  # Branch.io (mobile deep linking)
                                'emclick.com', 'emclick1.com',  # Email click tracking
                                'click.email',  # Generic email click tracking
                                'links.email',  # Generic email link tracking
                            ]

                            # Extract URLs from the email body to check for ESP domains
                            esp_detected = False
                            email_body = ''
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() in ['text/plain', 'text/html']:
                                        try:
                                            email_body += str(part.get_payload(decode=True), 'utf-8', errors='ignore')
                                        except:
                                            pass
                            else:
                                try:
                                    email_body = str(msg.get_payload(decode=True), 'utf-8', errors='ignore')
                                except:
                                    pass

                            # Check if any URLs contain ESP domains
                            for esp_domain in legitimate_esp_domains:
                                if esp_domain in email_body.lower():
                                    esp_detected = True
                                    break

                            # Get authentication status
                            auth_results = analysis_results.get('auth_results', {})
                            spf_pass = auth_results.get('spf', '').lower() == 'pass'
                            dkim_pass = auth_results.get('dkim', '').lower() == 'pass'
                            has_good_auth = spf_pass or dkim_pass

                            # Check if sender is a trusted domain (from trust_policy.json or trusted_esps.json)
                            sender_is_trusted = is_trusted

                            # Reduce URL risk for trusted threads (legitimate ongoing conversations)
                            if is_reply and thread_trust > 0:
                                # Trusted thread: reduce URL contribution significantly (80% reduction)
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.1, 2.0)
                                safe_log(f"🧵 Thread trust detected - reducing URL risk contribution by 80%")
                            elif sender_is_trusted and has_good_auth:
                                # TRUSTED DOMAIN (trust_policy.json or trusted_esps.json) with auth: 95% reduction
                                # Allows tracking links in invitations, verifications, receipts, etc.
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.05, 1.0)
                                safe_log(f"🔒 Trusted domain (authenticated) - reducing URL risk contribution by 95%")
                                analysis_results['headers_to_add']['X-Trusted-Domain'] = 'true'
                            elif esp_detected and has_good_auth:
                                # Legitimate ESP with valid authentication: reduce URL contribution by 70%
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.3, 5.0)
                                safe_log(f"📧 Legitimate ESP detected (authenticated) - reducing URL risk contribution by 70%")
                                analysis_results['headers_to_add']['X-ESP-Detected'] = 'true'
                            else:
                                # Non-threaded or untrusted: normal cap at 10 points
                                # TUNED 2025-11-22: Reduced from 0.5 to 0.4 (20% reduction) due to 25.5% FP rate
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.4, 10.0)

                            analysis_results['spam_score'] += url_contribution
                            if url_contribution > 0:
                                analysis_results['spam_modules_detail']['url'] = url_contribution
                            analysis_results['headers_to_add']['X-Spam-Score-URL'] = str(round(url_contribution, 2))
                            analysis_results['modules_run'].append('url_reputation')
                            monitor.record_module('url_reputation')
                            safe_log(f"🔗 URL analysis - risk score: {url_results.get('total_risk_score', 0)}, contribution: +{url_contribution}, homographs: {len(url_results.get('homograph_attacks', []))}")

                            # Add headers for SpamAssassin
                            for header_name, header_value in url_results.get('headers_to_add', {}).items():
                                safe_add_header(msg, header_name, str(header_value), monitor)

                            # For HIGH RISK URLs (exploit paths, webshells), add significant penalty
                            # These are URLs that indicate compromised hosting or active phishing infrastructure
                            if url_results.get('high_risk_urls') and url_results.get('total_risk_score', 0) >= 15:
                                high_risk_penalty = 15.0
                                analysis_results['spam_score'] += high_risk_penalty
                                if 'url' in analysis_results['spam_modules_detail']:
                                    analysis_results['spam_modules_detail']['url'] += high_risk_penalty
                                else:
                                    analysis_results['spam_modules_detail']['url'] = high_risk_penalty
                                analysis_results['headers_to_add']['X-High-Risk-URL'] = 'true'
                                analysis_results['headers_to_add']['X-Exploit-Path-Detected'] = 'true'
                                safe_log(f"🚨 HIGH RISK URL DETECTED - adding {high_risk_penalty} points: {url_results.get('high_risk_urls', [])[:2]}")

                            # For critical homograph attacks, add warning to subject
                            if url_results.get('homograph_attacks'):
                                targets = [h['target'] for h in url_results['homograph_attacks'] if h.get('target')]
                                if targets:
                                    current_subject = msg.get('Subject', '')
                                    if not current_subject.startswith('[PHISHING'):
                                        new_subject = f"[PHISHING-{targets[0].upper()}] {current_subject}"
                                        msg.replace_header('Subject', new_subject)
                                        safe_log(f"⚠️ Added phishing warning to subject for {targets[0]}")
                                    # Increase spam score significantly for homograph attacks
                                    analysis_results['spam_score'] += 20.0
                                    safe_log(f"📈 Added 20 points for homograph phishing attack")
            except TimeoutException:
                safe_log(f"⏱️ URL reputation module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"URL reputation module error: {e}")
        elif bypass_aggressive_checks:
            safe_log(f"⏭️ Skipping URL reputation module - sender has bypass_bec_checks")

        # Behavioral anomaly detection with timeout
        if MODULE_MANAGER.is_available('behavioral_baseline'):
            try:
                with timeout_handler(module_timeout):
                    analyze_behavior = MODULE_MANAGER.get_module('behavioral_baseline')
                    behavior_data = {
                        'from': from_header,
                        'recipients': safe_get_header(msg, 'To', ''),
                        'subject': safe_get_header(msg, 'Subject', ''),
                        'body': text_content,
                        'message_id': safe_get_header(msg, 'Message-ID', '')
                    }
                    behavior_results = analyze_behavior(behavior_data)
                    if behavior_results and isinstance(behavior_results, dict):
                        # Add behavioral risk to spam score with cap
                        if behavior_results.get('behavioral_risk_score', 0) > 0:
                            # Cap behavioral contribution at 10 points max
                            # TUNED 2025-11-22: Reduced from 0.7 to 0.35 (50% reduction) due to 67.5% FP rate
                            behavior_contribution = min(behavior_results.get('behavioral_risk_score', 0) * 0.35, 10.0)
                            analysis_results['spam_score'] += behavior_contribution
                            if behavior_contribution > 0:
                                analysis_results['spam_modules_detail']['behavioral'] = behavior_contribution
                            analysis_results['headers_to_add']['X-Spam-Score-Behavioral'] = str(round(behavior_contribution, 2))
                            analysis_results['modules_run'].append('behavioral')
                            monitor.record_module('behavioral')
                            safe_log(f"🔍 Behavioral analysis - risk: {behavior_results.get('behavioral_risk_score', 0)}, anomalies: {behavior_results.get('anomalies_detected', 0)}")

                            # Add headers for SpamAssassin
                            for header_name, header_value in behavior_results.get('headers_to_add', {}).items():
                                safe_add_header(msg, header_name, str(header_value), monitor)
            except TimeoutException:
                safe_log(f"⏱️ Behavioral module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Behavioral module error: {e}")

        # Sentiment analysis with timeout
        if MODULE_MANAGER.is_available('email_sentiment') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_sentiment = MODULE_MANAGER.get_module('email_sentiment')
                    sentiment_results = analyze_sentiment(email_data)
                    if sentiment_results and isinstance(sentiment_results, dict):
                        # Store full sentiment analysis results
                        analysis_results['sentiment_analysis'] = {
                            'polarity': sentiment_results.get('polarity', 0.0),
                            'subjectivity': sentiment_results.get('subjectivity', 0.0),
                            'sentiment_label': sentiment_results.get('sentiment', 'neutral'),
                            'manipulation_score': 0.0,  # Legacy field, calculated differently
                            'extremity_score': abs(sentiment_results.get('polarity', 0.0)),  # Use polarity abs value
                            'manipulation_indicators': []
                        }
                        analysis_results['modules_run'].append('sentiment')
                        monitor.record_module('sentiment')
                        safe_log(f"Sentiment module completed - polarity: {sentiment_results.get('polarity', 0.0)}, subjectivity: {sentiment_results.get('subjectivity', 0.0)}")
            except TimeoutException:
                safe_log(f"⏱️ Sentiment module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Sentiment module error: {e}")
        
        # Language detection with timeout
        if MODULE_MANAGER.is_available('email_language') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_language = MODULE_MANAGER.get_module('email_language')
                    # Language expects 3 parameters: msg, text_content, from_header
                    language_results = analyze_language(msg, text_content[:5000], from_header)
                    if language_results and isinstance(language_results, dict):
                        # Save language detection results for database storage
                        analysis_results['language_analysis'] = {
                            'detected_language': language_results.get('language', 'en'),
                            'confidence': language_results.get('confidence', 0.0),
                            'method': language_results.get('method', 'unknown')
                        }

                        # Check for spam score penalty from high-risk combinations
                        lang_penalty = 0.0
                        if 'headers_to_add' in language_results:
                            if 'X-Language-Spam-Penalty' in language_results['headers_to_add']:
                                lang_penalty = float(language_results['headers_to_add']['X-Language-Spam-Penalty'])

                        if lang_penalty > 0:
                            analysis_results['spam_score'] += lang_penalty
                            analysis_results['headers_to_add']['X-Spam-Score-Language'] = str(round(lang_penalty, 2))

                        # Add all language detection headers
                        if 'headers_to_add' in language_results:
                            analysis_results['headers_to_add'].update(language_results['headers_to_add'])

                        analysis_results['modules_run'].append('language')
                        monitor.record_module('language')
                        safe_log(f"Language module completed - detected: {language_results.get('language', 'unknown')} ({language_results.get('confidence', 0):.2f}), penalty: {lang_penalty}")
            except TimeoutException:
                safe_log(f"⏱️ Language module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Language module error: {e}")
        
        # Obfuscation detection with timeout
        if MODULE_MANAGER.is_available('email_obfuscation') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_obfuscation = MODULE_MANAGER.get_module('email_obfuscation')
                    obfuscation_results = analyze_obfuscation(email_data)
                    if obfuscation_results and isinstance(obfuscation_results, dict) and 'obfuscation_score' in obfuscation_results:
                        obf_score = obfuscation_results['obfuscation_score']
                        analysis_results['spam_score'] += obf_score
                        analysis_results['headers_to_add']['X-Spam-Score-Obfuscation'] = str(round(obf_score, 2))
                        analysis_results['modules_run'].append('obfuscation')
                        monitor.record_module('obfuscation')
                        safe_log(f"Obfuscation module completed - score: {obfuscation_results.get('obfuscation_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ Obfuscation module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Obfuscation module error: {e}")
        
        # Marketing spam filter with timeout
        if MODULE_MANAGER.is_available('marketing_spam_filter'):
            try:
                with timeout_handler(module_timeout):
                    marketing_module = MODULE_MANAGER.get_module('marketing_spam_filter')
                    if isinstance(marketing_module, dict):
                        filter_func = marketing_module.get('filter_marketing_spam')
                        if filter_func:
                            # Add extra error handling for marketing filter
                            try:
                                marketing_results = filter_func(email_data)
                                if marketing_results and isinstance(marketing_results, dict) and 'spam_score' in marketing_results:
                                    # REBALANCED: Cap marketing spam at 5 points max
                                    # Legitimate bulk email shouldn't be heavily penalized
                                    marketing_contribution = min(marketing_results['spam_score'], 5.0)
                                    analysis_results['spam_score'] += marketing_contribution
                                    if marketing_contribution > 0:
                                        analysis_results['spam_modules_detail']['marketing'] = marketing_contribution
                                    analysis_results['headers_to_add']['X-Spam-Score-Marketing'] = str(round(marketing_contribution, 2))
                                    analysis_results['modules_run'].append('marketing')
                                    monitor.record_module('marketing')
                                    safe_log(f"Marketing module completed - score: +{marketing_contribution} (capped from {marketing_results.get('spam_score', 0)})")
                            except Exception as marketing_error:
                                safe_log(f"Marketing filter internal error: {marketing_error}")
                                # Continue processing even if marketing filter fails
            except TimeoutException:
                safe_log(f"⏱️ Marketing module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Marketing module error: {e}")
        
        # BEC detection with timeout
        if MODULE_MANAGER.is_available('bec_detector'):
            try:
                with timeout_handler(module_timeout):
                    check_bec = MODULE_MANAGER.get_module('bec_detector')
                    bec_results = check_bec(email_data)
                    if bec_results and isinstance(bec_results, dict):
                        # BEC module might return different score fields
                        if 'bec_confidence' in bec_results:
                            # REBALANCED: Scale confidence more conservatively
                            # Only high confidence (>0.8) gets significant points
                            confidence = bec_results['bec_confidence']
                            if confidence >= 0.9:
                                bec_contribution = 8.0  # Very high confidence
                            elif confidence >= 0.8:
                                bec_contribution = 5.0  # High confidence
                            elif confidence >= 0.6:
                                bec_contribution = 3.0  # Medium confidence
                            elif confidence >= 0.4:
                                bec_contribution = 1.5  # Low confidence
                            else:
                                bec_contribution = 0.5  # Very low confidence

                            analysis_results['spam_score'] += bec_contribution
                            if bec_contribution > 0:
                                analysis_results['spam_modules_detail']['bec'] = bec_contribution
                            analysis_results['headers_to_add']['X-Spam-Score-BEC'] = str(round(bec_contribution, 2))
                            safe_log(f"BEC module completed - confidence: {confidence:.2f}, score: +{bec_contribution}")

                            # Send notification for high-confidence BEC detection
                            if confidence >= 0.8 and NOTIFICATION_SERVICE:
                                try:
                                    email_data = {
                                        'sender': from_header,
                                        'trigger_reason': 'bec_detected',
                                        'message_id': safe_get_header(msg, 'Message-ID', 'unknown'),
                                        'spam_score': analysis_results['spam_score']
                                    }
                                    NOTIFICATION_SERVICE.send_high_risk_alert(email_data)
                                except Exception as notif_err:
                                    safe_log(f"Notification error: {notif_err}")
                        elif 'bec_score' in bec_results:
                            # Cap BEC score at reasonable maximum
                            bec_contribution = min(bec_results['bec_score'], 8.0)
                            analysis_results['spam_score'] += bec_contribution
                            if bec_contribution > 0:
                                analysis_results['spam_modules_detail']['bec'] = bec_contribution
                            analysis_results['headers_to_add']['X-Spam-Score-BEC'] = str(round(bec_contribution, 2))
                            safe_log(f"BEC module completed - score: +{bec_contribution}")
                        
                        # Extract headers from BEC module for SpamAssassin integration
                        if 'headers_to_add' in bec_results and isinstance(bec_results['headers_to_add'], dict):
                            analysis_results['headers_to_add'].update(bec_results['headers_to_add'])
                            safe_log(f"BEC module added headers: {list(bec_results['headers_to_add'].keys())}")
                        
                        analysis_results['modules_run'].append('bec')
                        monitor.record_module('bec')
            except TimeoutException:
                safe_log(f"⏱️ BEC module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"BEC module error: {e}")

        # Brand impersonation detection with timeout
        if MODULE_MANAGER.is_available('brand_impersonation'):
            try:
                with timeout_handler(module_timeout):
                    check_brand_impersonation = MODULE_MANAGER.get_module('brand_impersonation')
                    brand_results = check_brand_impersonation(email_data)
                    if brand_results and isinstance(brand_results, dict) and brand_results.get('is_impersonation'):
                        # Add spam score for brand impersonation
                        brand_contribution = brand_results.get('spam_score_increase', 0.0)
                        analysis_results['spam_score'] += brand_contribution
                        analysis_results['headers_to_add']['X-Spam-Score-Brand-Impersonation'] = str(round(brand_contribution, 2))
                        analysis_results['headers_to_add']['X-Brand-Impersonation'] = 'true'
                        analysis_results['headers_to_add']['X-Brand-Name'] = brand_results.get('brand_detected', 'unknown')
                        analysis_results['headers_to_add']['X-Brand-Category'] = brand_results.get('brand_category', 'unknown')
                        analysis_results['modules_run'].append('brand_impersonation')
                        monitor.record_module('brand_impersonation')
                        safe_log(f"Brand impersonation detected: {brand_results.get('brand_detected')} ({brand_results.get('brand_category')}) - score: +{brand_contribution}")
            except TimeoutException:
                safe_log(f"⏱️ Brand impersonation module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Brand impersonation module error: {e}")

        # TOAD detector with timeout - skip for trusted domains
        if MODULE_MANAGER.is_available('toad_detector') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_toad = MODULE_MANAGER.get_module('toad_detector')
                    # TOAD expects 3 parameters: msg, text_content, from_header
                    toad_results = analyze_toad(msg, text_content[:5000], from_header)
                    if toad_results and isinstance(toad_results, dict) and 'toad_score' in toad_results:
                        toad_score = toad_results['toad_score']
                        analysis_results['spam_score'] += toad_score
                        analysis_results['headers_to_add']['X-Spam-Score-TOAD'] = str(round(toad_score, 2))
                        analysis_results['modules_run'].append('toad')
                        monitor.record_module('toad')
                        safe_log(f"TOAD module completed - score: {toad_results.get('toad_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ TOAD module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"TOAD module error: {e}")
        
        # PDF analyzer with timeout - skip for trusted domains
        if MODULE_MANAGER.is_available('pdf_analyzer') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_pdf = MODULE_MANAGER.get_module('pdf_analyzer')
                    pdf_results = analyze_pdf(msg)
                    if pdf_results and isinstance(pdf_results, dict) and 'pdf_spam_score' in pdf_results:
                        pdf_score = pdf_results['pdf_spam_score']
                        analysis_results['spam_score'] += pdf_score
                        analysis_results['headers_to_add']['X-Spam-Score-PDF'] = str(round(pdf_score, 2))
                        analysis_results['modules_run'].append('pdf')
                        monitor.record_module('pdf')
                        safe_log(f"PDF module completed - score: {pdf_results.get('pdf_spam_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ PDF module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"PDF module error: {e}")

        # HTML attachment analyzer with timeout - skip for trusted domains
        if MODULE_MANAGER.is_available('html_attachment_analyzer') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_html = MODULE_MANAGER.get_module('html_attachment_analyzer')
                    html_results = analyze_html(msg)
                    if html_results and isinstance(html_results, dict) and 'html_spam_score' in html_results:
                        html_score = html_results['html_spam_score']
                        analysis_results['spam_score'] += html_score
                        analysis_results['headers_to_add']['X-Spam-Score-HTML'] = str(round(html_score, 2))
                        analysis_results['modules_run'].append('html_attachment')
                        monitor.record_module('html_attachment')
                        safe_log(f"HTML attachment module completed - score: +{html_score}, attachments: {html_results.get('attachment_count', 0)}")

                        # Log threats detected
                        if html_results.get('all_threats'):
                            safe_log(f"🔴 HTML THREATS: {', '.join(html_results['all_threats'])}")
                            analysis_results['headers_to_add']['X-HTML-Threats'] = ','.join(html_results['all_threats'])

                        # Block high-risk HTML attachments
                        if html_results.get('requires_blocking'):
                            safe_log(f"⛔ HIGH-RISK HTML ATTACHMENT DETECTED - Risk: {html_results.get('overall_risk_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ HTML attachment module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"HTML attachment module error: {e}")

        # HTML Body Analyzer - analyze email body HTML for phishing
        # OPTION 2: Skip for internal emails (localhost/internal IPs)
        if MODULE_MANAGER.is_available('html_body_analyzer') and not is_trusted and not sender_is_internal:
            try:
                with timeout_handler(module_timeout):
                    analyze_html_body = MODULE_MANAGER.get_module('html_body_analyzer')
                    html_body_results = analyze_html_body(msg)
                    if html_body_results and isinstance(html_body_results, dict):
                        html_body_score = html_body_results.get('spam_score', 0)

                        # Always add to modules_run
                        analysis_results['modules_run'].append('html_body_analyzer')
                        monitor.record_module('html_body_analyzer')

                        # TUNED 2025-11-22: Add 0.6x weight multiplier (40% reduction) due to 40% FP rate
                        html_body_contribution = min(html_body_score * 0.6, 15.0)

                        # Always add header for consistency
                        analysis_results['headers_to_add']['X-Spam-Score-HTML-Body'] = str(round(html_body_contribution, 2))

                        if html_body_contribution > 0:
                            analysis_results['spam_score'] += html_body_contribution
                            analysis_results['spam_modules_detail']['html_body'] = html_body_contribution

                            # Log HTML body phishing attempts
                            safe_log(f"⚠️ HTML BODY PHISHING: score +{html_body_contribution}, "
                                   f"{len(html_body_results.get('issues', []))} issues detected")

                            # Log specific issues
                            for issue in html_body_results.get('issues', [])[:5]:  # Limit to first 5
                                safe_log(f"  🔍 {issue}")

                            # Store for analysis
                            analysis_results['html_body_analysis'] = {
                                'forms': html_body_results.get('forms_detected', 0),
                                'credential_forms': html_body_results.get('credential_forms', 0),
                                'hidden_elements': html_body_results.get('hidden_elements', []),
                                'brand_impersonation': html_body_results.get('brand_impersonation', []),
                                'link_manipulation': html_body_results.get('link_manipulation', []),
                                'unicode_attacks': html_body_results.get('unicode_attacks', [])
                            }
                        else:
                            safe_log(f"HTML body analysis completed - clean")
            except TimeoutException:
                safe_log(f"⏱️ HTML body analyzer timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"HTML body analyzer error: {e}")

        # Attachment Inspector (libmagic) - deep file type analysis
        if MODULE_MANAGER.is_available('attachment_inspector') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_attachments_deep = MODULE_MANAGER.get_module('attachment_inspector')
                    inspector_results = analyze_attachments_deep(msg)
                    if inspector_results and isinstance(inspector_results, dict):
                        inspector_score = inspector_results.get('spam_score', 0)

                        # Always add to modules_run (even if score is 0)
                        analysis_results['modules_run'].append('attachment_inspector')
                        monitor.record_module('attachment_inspector')

                        # Always add header (even if score is 0, for consistency in breakdown)
                        analysis_results['headers_to_add']['X-Spam-Score-Inspector'] = str(round(inspector_score, 2))

                        if inspector_score > 0:
                            analysis_results['spam_score'] += inspector_score

                        # Log findings (always log completion, even if no threats)
                        if inspector_results.get('dangerous_files'):
                            safe_log(f"🔴 DANGEROUS FILES: {len(inspector_results['dangerous_files'])} detected")
                            for danger in inspector_results['dangerous_files']:
                                safe_log(f"  ⚠️ {danger['filename']}: {danger['reason']}")

                            # Flag for quarantine UI display
                            analysis_results['has_dangerous_attachment'] = True
                            analysis_results['dangerous_attachment_count'] = len(inspector_results['dangerous_files'])

                        if inspector_results.get('mismatches'):
                            safe_log(f"⚠️ FILE TYPE MISMATCHES: {len(inspector_results['mismatches'])} detected")
                            for mismatch in inspector_results['mismatches']:
                                safe_log(f"  • {mismatch['filename']}: claimed {mismatch['declared']}, actually {mismatch['actual']}")

                        if inspector_results.get('archive_bombs'):
                            safe_log(f"💣 ARCHIVE BOMBS: {len(inspector_results['archive_bombs'])} detected")

                        if inspector_results.get('html_forms'):
                            safe_log(f"📝 HTML FORMS: {len(inspector_results['html_forms'])} phishing forms detected")

                        if inspector_results.get('macro_documents'):
                            safe_log(f"📄 MACRO DOCS: {len(inspector_results['macro_documents'])} macro-enabled documents")

                        # Always log completion
                        safe_log(f"Attachment Inspector completed - score: +{inspector_score}, inspected: {inspector_results.get('total_attachments', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ Attachment Inspector module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Attachment Inspector module error: {e}")

        # Header Forgery Detection - check for suspicious header patterns
        if MODULE_MANAGER.is_available('header_forgery_detector') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    detect_header_forgery_func = MODULE_MANAGER.get_module('header_forgery_detector')
                    # Pass auth_results for internal domain spoofing detection
                    forgery_results = detect_header_forgery_func(msg, from_header, auth_results)
                    if forgery_results and isinstance(forgery_results, dict):
                        forgery_score = forgery_results.get('spam_score', 0)

                        # Always add to modules_run
                        analysis_results['modules_run'].append('header_forgery_detector')
                        monitor.record_module('header_forgery_detector')

                        # Always add header (even if score is 0, for consistency in breakdown)
                        analysis_results['headers_to_add']['X-Spam-Score-Header-Forgery'] = str(round(forgery_score, 2))

                        if forgery_score > 0:
                            analysis_results['spam_score'] += forgery_score

                            # Log detected forgery issues
                            safe_log(f"⚠️ HEADER FORGERY DETECTED: {forgery_results.get('issue_count', 0)} issues, score: +{forgery_score}")
                            for issue in forgery_results.get('issues', []):
                                safe_log(f"  🔍 {issue}")

                            # Store for analysis
                            analysis_results['header_forgery'] = {
                                'detected': True,
                                'score': forgery_score,
                                'issues': forgery_results.get('issues', []),
                                'issue_count': forgery_results.get('issue_count', 0)
                            }
                        else:
                            safe_log("Header Forgery Detector completed - no issues detected")
            except TimeoutException:
                safe_log(f"⏱️ Header Forgery Detector module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Header Forgery Detector module error: {e}")

        # Received Chain Analysis - analyze email routing for anomalies
        # OPTION 2: Skip for internal emails (localhost/internal IPs)
        if MODULE_MANAGER.is_available('received_chain_analyzer') and not is_trusted and not sender_is_internal:
            try:
                with timeout_handler(module_timeout):
                    analyze_chain = MODULE_MANAGER.get_module('received_chain_analyzer')
                    chain_results = analyze_chain(msg)
                    if chain_results and isinstance(chain_results, dict):
                        chain_score = chain_results.get('spam_score', 0)

                        # Always add to modules_run
                        analysis_results['modules_run'].append('received_chain_analyzer')
                        monitor.record_module('received_chain_analyzer')

                        # TUNED 2025-11-22: Add 0.65x weight multiplier (35% reduction) due to 34.1% FP rate
                        routing_contribution = min(chain_score * 0.65, 12.0)

                        # Always add header for consistency
                        analysis_results['headers_to_add']['X-Spam-Score-Routing'] = str(round(routing_contribution, 2))

                        if routing_contribution > 0:
                            analysis_results['spam_score'] += routing_contribution
                            analysis_results['spam_modules_detail']['routing'] = routing_contribution

                            # Log routing anomalies
                            safe_log(f"⚠️ ROUTING ANOMALY: {chain_results.get('total_hops', 0)} hops, "
                                   f"{len(chain_results.get('issues', []))} issues, score: +{routing_contribution}")

                            # Log specific issues
                            for issue in chain_results.get('issues', [])[:5]:  # Limit to first 5 issues
                                safe_log(f"  🔍 {issue}")

                            # Store for analysis
                            analysis_results['routing_analysis'] = {
                                'hops': chain_results.get('total_hops', 0),
                                'issues': chain_results.get('issues', []),
                                'path': chain_results.get('routing_path', []),
                                'spam_relays': chain_results.get('spam_relays_detected', []),
                                'whitelisted': chain_results.get('whitelisted', False),
                                'transit_time': chain_results.get('total_transit_time_seconds', 0)
                            }
                        else:
                            safe_log(f"Received Chain Analysis completed - {chain_results.get('total_hops', 0)} hops, clean")
            except TimeoutException:
                safe_log(f"⏱️ Received Chain Analyzer timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Received Chain Analyzer error: {e}")

        # Funding/Financing Spam Detection with timeout
        if MODULE_MANAGER.is_available('fraud_funding_detector'):
            try:
                with timeout_handler(module_timeout):
                    analyze_funding_spam = MODULE_MANAGER.get_module('fraud_funding_detector')
                    # The funding spam detector expects email_data dict format
                    funding_results = analyze_funding_spam(email_data)
                    if funding_results and isinstance(funding_results, dict):
                        # Check for different possible score field names
                        funding_score = 0
                        if 'spam_score' in funding_results:
                            funding_score = funding_results['spam_score']
                            analysis_results['spam_score'] += funding_score
                        elif 'funding_spam_score' in funding_results:
                            funding_score = funding_results['funding_spam_score']
                            analysis_results['spam_score'] += funding_score
                        elif 'confidence_score' in funding_results:
                            # Fix: module returns confidence_score but we need spam_score
                            funding_score = funding_results['confidence_score']
                            analysis_results['spam_score'] += funding_score

                        if funding_score > 0:
                            analysis_results['headers_to_add']['X-Spam-Score-Funding'] = str(round(funding_score, 2))
                        
                        analysis_results['modules_run'].append('funding_spam')
                        monitor.record_module('funding_spam')
                        
                        if funding_results.get('is_funding_spam') or funding_results.get('is_spam'):
                            analysis_results['headers_to_add']['X-Funding-Spam'] = 'true'
                            score = funding_results.get('spam_score', funding_results.get('funding_spam_score', 0))
                            safe_log(f"💰 FUNDING SPAM DETECTED - Score: {score}")
            except TimeoutException:
                safe_log(f"⏱️ Funding spam module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"Funding spam module error: {e}")
        
        # Entity Extraction and NER Analysis with timeout
        if MODULE_MANAGER.is_available('entity_extraction'):
            try:
                with timeout_handler(module_timeout):
                    analyze_email_content = MODULE_MANAGER.get_module('entity_extraction')
                    # Pass text, subject, and sender to the NER module
                    ner_results = analyze_email_content(
                        text=text_content[:10000],  # Limit text for performance
                        subject=email_data.get('subject', safe_get_header(msg, 'Subject', '')),
                        sender=email_data.get('from', from_header)
                    )
                    if ner_results and isinstance(ner_results, dict):
                        # Store NER results for database storage
                        analysis_results['entities'] = ner_results.get('entities', [])
                        analysis_results['classification'] = {
                            'email_topics': ner_results.get('topics', []),
                            'primary_category': 'analyzed'  # Default category
                        }
                        analysis_results['content_summary'] = ner_results.get('content_summary', '')
                        
                        # Also add as headers for downstream processing
                        if ner_results.get('entities'):
                            # Store first 5 entities in header (limited for header size)
                            entities_str = ', '.join(ner_results['entities'][:5])
                            analysis_results['headers_to_add']['X-NER-Entities'] = entities_str
                            safe_log(f"🔍 NER Entities found: {len(ner_results['entities'])}")
                        
                        if ner_results.get('topics'):
                            topics_str = ', '.join(ner_results['topics'])
                            analysis_results['headers_to_add']['X-Email-Topics'] = topics_str
                            safe_log(f"📌 Topics detected: {topics_str}")
                        
                        if ner_results.get('content_summary'):
                            # Truncate summary for header safety
                            summary = ner_results['content_summary'][:100]
                            analysis_results['headers_to_add']['X-Content-Summary'] = summary
                        
                        analysis_results['modules_run'].append('ner')
                        monitor.record_module('ner')
                        safe_log(f"NER module completed - entities: {len(ner_results.get('entities', []))}, topics: {len(ner_results.get('topics', []))}")
            except TimeoutException:
                safe_log(f"⏱️ NER module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"NER module error: {e}")
        
        # ========================================================================
        # COMPLIANCE MODULE - Only for subscribed clients
        # ========================================================================
        try:
            # Extract recipient domain for module checking from Postfix headers
            recipient_domain = None
            postfix_recipients = msg.get_all('X-Postfix-Recipient', [])
            if postfix_recipients and len(postfix_recipients) > 0:
                first_recipient = postfix_recipients[0]
                if '@' in first_recipient:
                    recipient_domain = first_recipient.split('@')[1].lower()
            safe_log(f"📧 Using domain for compliance check: {recipient_domain}")
            
            if recipient_domain:
                # Check client module access
                safe_log(f"🔗 Importing module_access...")
                from modules.module_access import get_module_manager
                safe_log(f"🔗 Creating module manager...")
                module_manager = get_module_manager()
                safe_log(f"🔗 Checking client modules for {recipient_domain}...")
                client_modules = module_manager.check_client_modules(recipient_domain)
                safe_log(f"✅ Got client modules: compliance={client_modules.get('compliance_tracking', False)}")
                
                # Store module access in results for later use
                analysis_results['client_modules'] = client_modules
                
                # Run compliance module if enabled
                safe_log(f"🔍 Checking compliance module for {recipient_domain}: {client_modules.get('compliance_tracking', False)}")
                if client_modules.get('compliance_tracking', False):
                    safe_log(f"📋 Running compliance module for {recipient_domain}")
                    try:
                        with timeout_handler(module_timeout):
                            from modules.compliance_extraction import analyze_compliance_content
                            compliance_results = analyze_compliance_content(text_content[:10000], safe_get_header(msg, 'Subject', ''))
                            safe_log(f"📊 Compliance results: {compliance_results}")
                            
                            # Store compliance entities
                            analysis_results['compliance_entities'] = compliance_results.get('legal_entities', {})
                            analysis_results['financial_entities'] = compliance_results.get('financial_entities', {})
                            analysis_results['compliance_risk'] = compliance_results.get('risk_level', 'unknown')
                            safe_log(f"📝 Stored compliance data: legal={len(analysis_results['compliance_entities'].get('case_numbers', []))} cases, financial={len(analysis_results['financial_entities'].get('amounts', []))} amounts")
                            
                            if compliance_results.get('requires_attention'):
                                safe_log(f"⚠️ Compliance attention required - Risk: {compliance_results['risk_level']}")
                                analysis_results['headers_to_add']['X-Compliance-Risk'] = compliance_results['risk_level']
                            
                            analysis_results['modules_run'].append('compliance')
                            module_manager.log_module_usage(recipient_domain, 'compliance_tracking', 
                                                           len(compliance_results.get('legal_entities', {}).get('case_numbers', [])))
                    except Exception as e:
                        safe_log(f"❌ Compliance module error: {e}")
                        import traceback
                        safe_log(f"❌ Traceback: {traceback.format_exc()}")
                
                # Check for triggered alerts
                if client_modules.get('legal_alerts', False):
                    try:
                        email_alert_data = {
                            'text_content': text_content,
                            'subject': safe_get_header(msg, 'Subject', ''),
                            'entities': analysis_results.get('entities', [])
                        }
                        triggered_alerts = module_manager.check_alert_conditions(email_alert_data, recipient_domain)
                        if triggered_alerts:
                            safe_log(f"🚨 {len(triggered_alerts)} alerts triggered for {recipient_domain}")
                            analysis_results['triggered_alerts'] = triggered_alerts
                            module_manager.log_module_usage(recipient_domain, 'legal_alerts', 0, len(triggered_alerts))
                    except Exception as e:
                        safe_log(f"Alert checking error: {e}")
        except Exception as e:
            safe_log(f"❌ Module access check error: {e}")
            import traceback
            safe_log(f"❌ Module traceback: {traceback.format_exc()}")

        # ========================================================================
        # ANTIVIRUS SCANNING - ClamAV Integration
        # ========================================================================
        if MODULE_MANAGER.is_available('antivirus_scanner'):
            try:
                with timeout_handler(module_timeout):
                    scan_email = MODULE_MANAGER.get_module('antivirus_scanner')
                    av_results = scan_email(msg)

                    if av_results and isinstance(av_results, dict):
                        # Store virus detection results
                        analysis_results['virus_detected'] = av_results.get('virus_detected', False)
                        analysis_results['virus_names'] = av_results.get('virus_names', [])

                        if av_results.get('virus_detected'):
                            # Add significant spam score for virus detection
                            virus_score = av_results.get('virus_score', 20.0)
                            analysis_results['spam_score'] += virus_score
                            analysis_results['headers_to_add']['X-Spam-Score-Virus'] = str(round(virus_score, 2))
                            safe_log(f"🦠 VIRUS DETECTED: {', '.join(av_results.get('virus_names', []))} - Added +{virus_score} points")

                            # Send notification for virus detection
                            if NOTIFICATION_SERVICE:
                                try:
                                    email_data = {
                                        'sender': from_header,
                                        'trigger_reason': 'virus_detected',
                                        'message_id': safe_get_header(msg, 'Message-ID', 'unknown'),
                                        'spam_score': analysis_results['spam_score']
                                    }
                                    NOTIFICATION_SERVICE.send_high_risk_alert(email_data)
                                except Exception as notif_err:
                                    safe_log(f"Notification error: {notif_err}")

                            # Add headers for virus detection
                            analysis_results['headers_to_add']['X-Virus-Scanned'] = 'ClamAV'
                            analysis_results['headers_to_add']['X-Virus-Status'] = 'INFECTED'
                            analysis_results['headers_to_add']['X-Virus-Detected'] = 'true'
                            analysis_results['headers_to_add']['X-Virus-Names'] = ', '.join(av_results.get('virus_names', []))
                        else:
                            # Add clean scan headers
                            analysis_results['headers_to_add']['X-Virus-Scanned'] = 'ClamAV'
                            analysis_results['headers_to_add']['X-Virus-Status'] = 'CLEAN'
                            safe_log(f"✅ Antivirus scan clean - no threats detected")

                        analysis_results['modules_run'].append('antivirus')
                        monitor.record_module('antivirus')
            except TimeoutException:
                safe_log(f"⏱️ Antivirus module timed out after {module_timeout}s")
                analysis_results['virus_detected'] = False  # Default to false on timeout
            except Exception as e:
                safe_log(f"❌ Antivirus module error: {e}")
                analysis_results['virus_detected'] = False  # Default to false on error
        else:
            # Module not available - set default values
            analysis_results['virus_detected'] = False
            analysis_results['virus_names'] = []

        # ========================================================================
        # DISPLAY NAME SPOOFING DETECTION
        # ========================================================================
        if MODULE_MANAGER.is_available('display_name_spoofing'):
            try:
                with timeout_handler(module_timeout):
                    analyze_spoofing = MODULE_MANAGER.get_module('display_name_spoofing')

                    # Extract recipients for analysis
                    recipients = []
                    for to_field in ['To', 'Cc']:
                        to_header = safe_get_header(msg, to_field, '')
                        if to_header:
                            import re
                            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', to_header)
                            recipients.extend(emails)

                    spoofing_results = analyze_spoofing(msg, recipients)

                    if spoofing_results and isinstance(spoofing_results, dict):
                        # Store spoofing detection results
                        analysis_results['display_name_spoofing'] = spoofing_results.get('spoofing_detected', False)
                        analysis_results['spoofing_types'] = spoofing_results.get('spoofing_type', [])

                        if spoofing_results.get('spoofing_detected'):
                            spoofing_score = spoofing_results.get('spoofing_score', 0)
                            analysis_results['spam_score'] += spoofing_score
                            analysis_results['headers_to_add']['X-Spam-Score-Spoofing'] = str(round(spoofing_score, 2))

                            # Add detailed headers for transparency
                            analysis_results['headers_to_add']['X-Display-Name-Spoofing'] = 'true'
                            analysis_results['headers_to_add']['X-Spoofing-Types'] = ','.join(spoofing_results.get('spoofing_type', []))

                            if spoofing_results.get('indicators'):
                                indicators_str = '; '.join(spoofing_results['indicators'][:3])  # First 3 indicators
                                analysis_results['headers_to_add']['X-Spoofing-Indicators'] = indicators_str

                            safe_log(f"🎭 DISPLAY NAME SPOOFING DETECTED: {', '.join(spoofing_results.get('spoofing_type', []))} - Added +{spoofing_score} points")
                            safe_log(f"   Display: '{spoofing_results.get('display_name', '')}' | Sender: {spoofing_results.get('sender_email', '')}")

                            # Log specific spoofing types
                            for indicator in spoofing_results.get('indicators', []):
                                safe_log(f"   ⚠️  {indicator}")

                            # Send notification for recipient domain impersonation (highest risk)
                            spoofing_types = spoofing_results.get('spoofing_type', [])
                            if 'recipient_domain_impersonation' in spoofing_types or 'local_part_domain_impersonation' in spoofing_types:
                                if NOTIFICATION_SERVICE:
                                    try:
                                        trigger_type = 'local_part_domain_impersonation' if 'local_part_domain_impersonation' in spoofing_types else 'recipient_domain_impersonation'
                                        email_data = {
                                            'sender': from_header,
                                            'trigger_reason': trigger_type,
                                            'message_id': safe_get_header(msg, 'Message-ID', 'unknown'),
                                            'spam_score': analysis_results['spam_score']
                                        }
                                        NOTIFICATION_SERVICE.send_high_risk_alert(email_data)
                                    except Exception as notif_err:
                                        safe_log(f"Notification error: {notif_err}")
                        else:
                            safe_log(f"✅ Display name check passed - no spoofing detected")

                        analysis_results['modules_run'].append('display_name_spoofing')
                        monitor.record_module('display_name_spoofing')
            except TimeoutException:
                safe_log(f"⏱️ Display name spoofing module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"❌ Display name spoofing module error: {e}")

        # ========================================================================
        # ONMICROSOFT.COM BRAND IMPERSONATION DETECTION
        # ========================================================================
        # Detects abuse of Microsoft 365 tenant domains to impersonate brands
        if MODULE_MANAGER.is_available('onmicrosoft_impersonation'):
            try:
                with timeout_handler(module_timeout):
                    analyze_onmicrosoft = MODULE_MANAGER.get_module('onmicrosoft_impersonation')

                    # Extract recipients for analysis
                    recipients = []
                    for to_field in ['To', 'Cc']:
                        to_header = safe_get_header(msg, to_field, '')
                        if to_header:
                            import re
                            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', to_header)
                            recipients.extend(emails)

                    onmicrosoft_results = analyze_onmicrosoft(msg, recipients)

                    if onmicrosoft_results and isinstance(onmicrosoft_results, dict):
                        if onmicrosoft_results.get('impersonation_detected'):
                            score_increase = onmicrosoft_results.get('spam_score_increase', 0)
                            analysis_results['spam_score'] += score_increase

                            # Store detection details
                            analysis_results['onmicrosoft_impersonation'] = True
                            analysis_results['onmicrosoft_threat_level'] = onmicrosoft_results.get('threat_level', 'unknown')
                            analysis_results['onmicrosoft_brands'] = onmicrosoft_results.get('brands_found', [])

                            # Add headers for transparency
                            analysis_results['headers_to_add']['X-OnMicrosoft-Impersonation'] = 'true'
                            analysis_results['headers_to_add']['X-OnMicrosoft-Threat-Level'] = onmicrosoft_results.get('threat_level', 'unknown')
                            if onmicrosoft_results.get('brands_found'):
                                analysis_results['headers_to_add']['X-OnMicrosoft-Brands'] = ','.join(onmicrosoft_results['brands_found'])

                            safe_log(f"🚨 ONMICROSOFT BRAND IMPERSONATION: Threat={onmicrosoft_results.get('threat_level')} - Added +{score_increase} points")
                            safe_log(f"   Display: '{onmicrosoft_results.get('display_name', '')}' | Domain: {onmicrosoft_results.get('sender_domain', '')}")

                            # Log indicators
                            for indicator in onmicrosoft_results.get('indicators', []):
                                safe_log(f"   ⚠️  {indicator}")

                            # Send notification for critical threats
                            if onmicrosoft_results.get('threat_level') == 'critical':
                                if NOTIFICATION_SERVICE:
                                    try:
                                        email_data = {
                                            'sender': from_header,
                                            'trigger_reason': 'onmicrosoft_brand_impersonation',
                                            'brands': onmicrosoft_results.get('brands_found', []),
                                            'message_id': safe_get_header(msg, 'Message-ID', 'unknown'),
                                            'spam_score': analysis_results['spam_score']
                                        }
                                        NOTIFICATION_SERVICE.send_high_risk_alert(email_data)
                                    except Exception as notif_err:
                                        safe_log(f"Notification error: {notif_err}")
                        else:
                            safe_log(f"✅ OnMicrosoft check passed - no brand impersonation detected")

                        analysis_results['modules_run'].append('onmicrosoft_impersonation')
                        monitor.record_module('onmicrosoft_impersonation')
            except TimeoutException:
                safe_log(f"⏱️ OnMicrosoft impersonation module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"❌ OnMicrosoft impersonation module error: {e}")

        safe_log(f"Modules run: {', '.join(analysis_results['modules_run'])}")
        safe_log(f"Combined spam score: {analysis_results['spam_score']:.2f}")

    except Exception as e:
        safe_log(f"Module analysis error: {e}")

    # Include bypass flag in results for use in fake reply detection
    analysis_results['bypass_aggressive_checks'] = bypass_aggressive_checks

    # ========================================================================
    # WHITELIST SCORE REDUCTION - Apply final reduction for per-user whitelists
    # ========================================================================
    # The whitelist check in perform_real_authentication() only boosts auth_score
    # which is capped at 3.0. For per-user whitelists (commercial/personal senders),
    # we need a much larger reduction to the final spam score.
    if auth_results and analysis_results['spam_score'] > 0:
        whitelist_source = auth_results.get('whitelist_source')
        whitelist_priority = auth_results.get('whitelist_priority')
        whitelist_trust_level = auth_results.get('whitelist_trust_level')

        # Only apply final score reduction for blocking_rules whitelists
        # (trust_policy.json and trusted_entities use is_trusted flag for bypass)
        if whitelist_source == 'blocking_rules' and whitelist_priority:
            original_score = analysis_results['spam_score']

            # Apply score reduction based on whitelist priority
            if whitelist_priority >= 100:
                # Priority 100 (bypass_all): Reduce to near-zero (max 2.0)
                # This is for absolute trust - business partners, family, etc.
                analysis_results['spam_score'] = min(2.0, original_score * 0.05)
                reduction_pct = 95
            elif whitelist_priority >= 75:
                # Priority 75 (reduce_scoring): 70% reduction
                # This is for trusted commercial senders - MyPillow, Uber, etc.
                analysis_results['spam_score'] = original_score * 0.30
                reduction_pct = 70
            elif whitelist_priority >= 50:
                # Priority 50: 50% reduction
                analysis_results['spam_score'] = original_score * 0.50
                reduction_pct = 50
            else:
                # Priority < 50: 25% reduction
                analysis_results['spam_score'] = original_score * 0.75
                reduction_pct = 25

            final_score = analysis_results['spam_score']
            score_reduction = original_score - final_score

            # Log the whitelist reduction
            safe_log(f"✅ WHITELIST SCORE REDUCTION (priority={whitelist_priority}, {reduction_pct}%): {original_score:.2f} → {final_score:.2f} (-{score_reduction:.2f})")

            # Add header for transparency
            analysis_results['headers_to_add']['X-SpaCy-Whitelist-Reduction'] = f"{score_reduction:.2f}"
            analysis_results['headers_to_add']['X-SpaCy-Whitelist-Priority'] = str(whitelist_priority)
    # ========================================================================

    # ========================================================================
    # MAJOR SENDER INFRASTRUCTURE - Reduce scores for authenticated major senders
    # ========================================================================
    # When a major sender (Amazon, banks, etc.) passes authentication, we trust
    # the content more. This is different from a whitelist - spoofed emails fail
    # auth and don't get this benefit.
    if auth_results and analysis_results['spam_score'] > 0:
        try:
            sender_domain = auth_results.get('sender_domain', '')
            auth_score = auth_results.get('auth_score', 0)

            if sender_domain and auth_score >= 0.67:  # At least SPF+DMARC or SPF+DKIM
                # Check major_sender_infrastructure table (supports subdomains)
                # e.g., "enews.united.com" will match "united.com" in the table
                try:
                    conn = get_db_connection()
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("""
                        SELECT domain, category, trust_multiplier, notes
                        FROM major_sender_infrastructure
                        WHERE (domain = %s OR %s LIKE CONCAT('%%.', domain)) AND active = 1
                        ORDER BY LENGTH(domain) DESC
                        LIMIT 1
                    """, (sender_domain, sender_domain))
                    major_sender = cursor.fetchone()
                    cursor.close()
                    conn.close()

                    if major_sender:
                        trust_multiplier = float(major_sender.get('trust_multiplier', 0.30))
                        category = major_sender.get('category', 'other')
                        original_score = analysis_results['spam_score']

                        # Apply trust multiplier to the score
                        # This gives 70-75% reduction for authenticated major senders
                        analysis_results['spam_score'] = original_score * trust_multiplier

                        # Ensure we don't go negative (floor at 0)
                        if analysis_results['spam_score'] < 0:
                            analysis_results['spam_score'] = 0

                        new_score = analysis_results['spam_score']
                        reduction = original_score - new_score
                        reduction_pct = int((1 - trust_multiplier) * 100)

                        safe_log(f"🏢 MAJOR SENDER ({category}): {sender_domain} authenticated - score reduced {reduction_pct}%: {original_score:.2f} → {new_score:.2f}")

                        # Add header for transparency
                        analysis_results['headers_to_add']['X-SpaCy-Major-Sender'] = f"{sender_domain} ({category})"
                        analysis_results['headers_to_add']['X-SpaCy-Major-Sender-Reduction'] = f"{reduction:.2f}"

                        # Track in modules detail
                        if 'spam_modules_detail' not in analysis_results:
                            analysis_results['spam_modules_detail'] = {}
                        analysis_results['spam_modules_detail']['major_sender_bonus'] = -reduction

                except Exception as db_err:
                    safe_log(f"Error checking major_sender_infrastructure: {db_err}")
        except Exception as e:
            safe_log(f"Error in major sender check: {e}")
    # ========================================================================

    # ========================================================================
    # SPAM RESULT CACHE SAVE - Cache results for future lookups
    # ========================================================================
    if SPAM_CACHE and SPAM_CACHE.cache_enabled:
        try:
            subject = safe_get_header(msg, 'Subject', '')
            SPAM_CACHE.save_result(from_header, subject, analysis_results)
        except Exception as e:
            safe_log(f"Cache save error: {e}")
    # ========================================================================

    return analysis_results

# ============================================================================
# THREAD AWARENESS FUNCTIONS - RESTORED
# ============================================================================

def check_thread_continuity(msg: EmailMessage, text_content: str) -> Dict:
    """Check if email is part of existing thread - ENHANCED WITH DATABASE"""
    try:
        # Try to use enhanced thread analysis with database and alias support
        from modules.thread_awareness_enhanced import analyze_thread_with_database
        
        # Pass text_content for quoted content analysis
        thread_analysis = analyze_thread_with_database(msg, text_content)
        
        # Convert to legacy format for compatibility
        thread_info = {
            'is_reply': thread_analysis.get('is_thread_reply', False),
            'trust_score': min(5, int(thread_analysis.get('trust_score', 0) / 2)),  # Scale 0-10 to 0-5
            'thread_id': None,
            'references': [],
            'in_reply_to': None,
            # Enhanced fields
            'trust_level': thread_analysis.get('trust_level', 'none'),
            'thread_verified': thread_analysis.get('thread_verified', False),
            'internal_participation': thread_analysis.get('internal_participation', False),
            'thread_initiated_internally': thread_analysis.get('thread_initiated_internally', False),
            'risk_factors': thread_analysis.get('risk_factors', []),
            # NEW: Fake reply detection fields
            'is_fake_reply': thread_analysis.get('is_fake_reply', False),
            'fake_reply_confidence': thread_analysis.get('fake_reply_confidence', 0.0),
            # NEW: Quoted content detection
            'has_quoted_internal': thread_analysis.get('has_quoted_internal', False),
            'quoted_internal_addresses': thread_analysis.get('quoted_internal_addresses', [])
        }
        
        # Extract references for legacy compatibility
        references = safe_get_header(msg, 'References', '')
        if references:
            thread_info['references'] = references.split()
        
        in_reply_to = safe_get_header(msg, 'In-Reply-To', '')
        if in_reply_to:
            thread_info['in_reply_to'] = in_reply_to
        
        safe_log(f"Enhanced thread analysis: trust_level={thread_info['trust_level']}, "
                f"verified={thread_info['thread_verified']}, "
                f"internal={thread_info['internal_participation']}")
        
        return thread_info
        
    except ImportError:
        safe_log("Enhanced thread analysis not available, using basic check")
        # Fallback to original simple implementation
        thread_info = {
            'is_reply': False,
            'trust_score': 0,
            'thread_id': None,
            'references': [],
            'in_reply_to': None
        }
        
        try:
            # Check References header
            references = safe_get_header(msg, 'References', '')
            if references:
                thread_info['references'] = references.split()
                thread_info['is_reply'] = True
                thread_info['trust_score'] += 2
                safe_log(f"Found References header with {len(thread_info['references'])} messages")
            
            # Check In-Reply-To header
            in_reply_to = safe_get_header(msg, 'In-Reply-To', '')
            if in_reply_to:
                thread_info['in_reply_to'] = in_reply_to
                thread_info['is_reply'] = True
                thread_info['trust_score'] += 2
                safe_log(f"Found In-Reply-To header: {in_reply_to[:50]}")
            
            # Check subject for Re: or Fwd:
            subject = safe_get_header(msg, 'Subject', '')
            if subject.startswith('Re:') or subject.startswith('RE:'):
                thread_info['is_reply'] = True
                thread_info['trust_score'] += 1
                safe_log("Subject indicates reply")
            elif subject.startswith('Fwd:') or subject.startswith('FW:'):
                thread_info['is_reply'] = True
                thread_info['trust_score'] += 1
                safe_log("Subject indicates forward")
            
            # Check for quoted content
            if '>' in text_content[:1000] or 'On ' in text_content[:500] and 'wrote:' in text_content[:500]:
                thread_info['trust_score'] += 1
                safe_log("Found quoted content indicators")
            
            # Extract thread ID if present
            thread_id_match = re.search(r'Thread-Index:\s*([^\s]+)', str(msg))
            if thread_id_match:
                thread_info['thread_id'] = thread_id_match.group(1)
                thread_info['trust_score'] += 1
                safe_log(f"Found Thread-Index: {thread_info['thread_id'][:20]}")
            
            safe_log(f"Thread analysis - Is Reply: {thread_info['is_reply']}, Trust Score: {thread_info['trust_score']}")
            
        except Exception as e:
            safe_log(f"Thread continuity error: {e}")
        
        return thread_info

# ============================================================================
# BLOCKING LOGIC - ENHANCED WITH AUTH ABUSE
# ============================================================================

# DEPRECATED 2025-11-19: No longer needed - quarantine data now stored in email_analysis
# def store_in_quarantine(msg: EmailMessage, text_content: str, analysis_results: Dict,
#                         from_header: str, recipients: List[str]) -> bool:
#     """Store email in quarantine"""
#     # Quarantine storage is now handled by store_email_with_disposition()
#     # which writes directly to email_analysis with disposition='quarantined'
#     pass


def make_disposition_decision(analysis_results: Dict, msg: EmailMessage, recipient_domains: list = None) -> tuple:
    """
    NEW: Single decision point for email disposition
    Returns: (disposition, reason)
    Where disposition is: 'delivered', 'quarantined', 'deleted', or 'rejected'

    Args:
        analysis_results: Email analysis results
        msg: Email message object
        recipient_domains: List of recipient domains (to check quarantine settings)
    """
    try:
        spam_score = analysis_results.get('spam_score', 0.0)
        base_spam_threshold = CONFIG.config['thresholds']['spam_threshold']

        # EARLY BYPASS: Check for Priority 100 whitelist - NEVER QUARANTINE
        # If sender is whitelisted with priority >= 100, bypass ALL checks and deliver immediately
        whitelist_priority = analysis_results.get('auth_results', {}).get('whitelist_priority', 0)
        whitelist_source = analysis_results.get('auth_results', {}).get('whitelist_source', '')

        if whitelist_priority >= 100:
            safe_log(f"⚡ WHITELIST BYPASS (Priority {whitelist_priority}): Skipping ALL quarantine checks - immediate delivery (source: {whitelist_source})")
            return ('relay_pending', 'whitelist_bypass_priority_100')

        # Check if quarantine is enabled for this domain
        quarantine_enabled = True  # Default to True
        if recipient_domains and DB_CONN:
            try:
                cursor = DB_CONN.cursor(dictionary=True)
                placeholders = ','.join(['%s'] * len(recipient_domains))
                cursor.execute(f"""
                    SELECT domain, quarantine_enabled
                    FROM client_domains
                    WHERE domain IN ({placeholders}) AND active = 1
                """, recipient_domains)
                results = cursor.fetchall()
                cursor.close()

                # If ANY recipient domain has quarantine disabled, disable it
                if results and any(r['quarantine_enabled'] == 0 for r in results):
                    quarantine_enabled = False
                    safe_log(f"Quarantine disabled for domain(s): {', '.join(r['domain'] for r in results if r['quarantine_enabled'] == 0)}")
            except Exception as e:
                safe_log(f"Error checking quarantine settings: {e}")
                # Default to quarantine enabled if check fails
            finally:
                try:
                    cursor.close()
                except:
                    pass

        # Get thread analysis for threshold adjustment
        thread_info = analysis_results.get('thread_info', {})
        trust_level = thread_info.get('trust_level', 'none')
        risk_factors = thread_info.get('risk_factors', [])

        # Adjust spam threshold based on thread trust
        spam_threshold = base_spam_threshold
        if trust_level in ['none', 'low']:
            spam_threshold *= 0.7  # 30% stricter for untrusted threads
            safe_log(f"Thread trust low: adjusted threshold to {spam_threshold:.1f}")
        elif trust_level == 'medium':
            spam_threshold *= 0.85  # 15% stricter for semi-trusted
            safe_log(f"Thread trust medium: adjusted threshold to {spam_threshold:.1f}")

        # Extra strict for funding spam in threads
        if 'funding_spam_in_thread' in risk_factors:
            spam_threshold *= 0.7  # Additional 30% stricter
            safe_log(f"Funding spam in thread: further adjusted threshold to {spam_threshold:.1f}")

        # Check virus detection first
        if analysis_results.get('virus_detected', False):
            if quarantine_enabled:
                safe_log("🚫 QUARANTINE: Virus detected")
                return ('quarantined', 'virus_detected')
            else:
                safe_log("🗑️  DELETE: Virus detected (quarantine disabled)")
                return ('deleted', 'virus_detected')

        # Check for dangerous attachments (executables, malware, etc.)
        if analysis_results.get('has_dangerous_attachment', False):
            dangerous_count = analysis_results.get('dangerous_attachment_count', 1)
            if quarantine_enabled:
                safe_log(f"🚫 QUARANTINE: {dangerous_count} dangerous attachment(s) detected")
                return ('quarantined', 'dangerous_attachment')
            else:
                safe_log(f"🗑️  DELETE: {dangerous_count} dangerous attachment(s) detected (quarantine disabled)")
                return ('deleted', 'dangerous_attachment')

        # Check for high-risk country block - ALWAYS AUTO DELETE
        if analysis_results.get('force_delete_country_block', False):
            country = analysis_results.get('high_risk_country', 'UNKNOWN')
            safe_log(f"🗑️  AUTO-DELETE: High-risk country {country} blocked (intelligence preserved in database)")
            return ('deleted', f'high_risk_country_{country}')

        # Check for foreign language (non-English, non-Spanish) - AUTO DELETE
        # Check subject and sender for foreign characters
        import re
        subject = safe_get_header(msg, 'Subject', '')
        sender = safe_get_header(msg, 'From', '')

        # Unicode ranges for foreign scripts
        foreign_patterns = [
            r'[\u3040-\u309F]',  # Hiragana (Japanese)
            r'[\u30A0-\u30FF]',  # Katakana (Japanese)
            r'[\u4E00-\u9FFF]',  # CJK Unified Ideographs (Chinese/Japanese/Korean)
            r'[\uAC00-\uD7AF]',  # Hangul (Korean)
            r'[\u0400-\u04FF]',  # Cyrillic (Russian)
            r'[\u0600-\u06FF]',  # Arabic
            r'[\u0E00-\u0E7F]',  # Thai
            r'[\u0900-\u097F]',  # Devanagari (Hindi)
        ]

        for pattern in foreign_patterns:
            if re.search(pattern, subject) or re.search(pattern, sender):
                safe_log(f"🗑️  DELETE: Foreign language detected in subject/sender")
                return ('deleted', 'foreign_language')

        # Check authentication abuse
        auth_abuse_score = 0.0
        x_auth_abuse = safe_get_header(msg, 'X-Auth-Abuse-Score', '0.0')
        try:
            auth_abuse_score = float(x_auth_abuse)
        except:
            pass

        if auth_abuse_score >= CONFIG.config['thresholds']['auth_abuse_block_score']:
            if quarantine_enabled:
                safe_log(f"🚫 QUARANTINE: Authentication abuse score {auth_abuse_score}")
                return ('quarantined', 'auth_abuse')
            else:
                safe_log(f"🗑️  DELETE: Authentication abuse score {auth_abuse_score} (quarantine disabled)")
                return ('deleted', 'auth_abuse')

        # Check known scammer flag
        if safe_get_header(msg, 'X-Known-Scammer', 'false').lower() == 'true':
            if quarantine_enabled:
                safe_log("🚫 QUARANTINE: Known scammer detected")
                return ('quarantined', 'known_scammer')
            else:
                safe_log("🗑️  DELETE: Known scammer detected (quarantine disabled)")
                return ('deleted', 'known_scammer')

        # Regular spam threshold (now thread-aware)
        if spam_score >= spam_threshold:
            if quarantine_enabled:
                safe_log(f"🚫 QUARANTINE: Spam score {spam_score:.2f} exceeds threshold {spam_threshold:.1f}")
                return ('quarantined', 'high_spam_score')
            else:
                safe_log(f"🗑️  DELETE: Spam score {spam_score:.2f} exceeds threshold {spam_threshold:.1f} (quarantine disabled)")
                return ('deleted', 'high_spam_score')

        # Check funding spam with thread awareness
        if safe_get_header(msg, 'X-Funding-Spam', 'false').lower() == 'true':
            funding_threshold = CONFIG.config['thresholds']['funding_spam_threshold']
            if trust_level in ['none', 'low', 'medium']:
                funding_threshold *= 0.7
            if spam_score >= funding_threshold:
                if quarantine_enabled:
                    safe_log(f"🚫 QUARANTINE: Funding spam score {spam_score:.2f}")
                    return ('quarantined', 'funding_spam')
                else:
                    safe_log(f"🗑️  DELETE: Funding spam score {spam_score:.2f} (quarantine disabled)")
                    return ('deleted', 'funding_spam')

        # Thread spam repetition check
        x_thread_spam = safe_get_header(msg, 'X-Thread-Spam-Count', '0')
        try:
            thread_spam_count = int(x_thread_spam)
            if thread_spam_count >= CONFIG.config['thresholds']['thread_spam_repetition_threshold']:
                if quarantine_enabled:
                    safe_log(f"🚫 QUARANTINE: Thread spam repetition {thread_spam_count}")
                    return ('quarantined', 'thread_spam_repetition')
                else:
                    safe_log(f"🗑️  DELETE: Thread spam repetition {thread_spam_count} (quarantine disabled)")
                    return ('deleted', 'thread_spam_repetition')
        except:
            pass

        # Authentication failure with strict policy
        auth_results = safe_get_header(msg, 'X-SpaCy-Auth-Results', '')
        if 'dmarc=fail' in auth_results and 'p=reject' in auth_results:
            if quarantine_enabled:
                safe_log("🚫 QUARANTINE: DMARC fail with reject policy")
                return ('quarantined', 'dmarc_reject')
            else:
                safe_log("🗑️  DELETE: DMARC fail with reject policy (quarantine disabled)")
                return ('deleted', 'dmarc_reject')

        safe_log(f"✅ DELIVER: Email passed checks - Score: {spam_score:.2f}")
        # Return 'relay_pending' instead of 'delivered' - will be updated after successful relay
        return ('relay_pending', 'passed_checks')

    except Exception as e:
        safe_log(f"Error in disposition decision: {e}")
        # On error, quarantine to be safe
        return ('quarantined', 'decision_error')


def should_block_email(analysis_results: Dict, msg: EmailMessage) -> bool:
    """
    DEPRECATED: Use make_disposition_decision() instead
    Kept for backward compatibility during transition
    """
    disposition, _ = make_disposition_decision(analysis_results, msg)
    return disposition == 'quarantined'

# ============================================================================
# DATABASE OPERATIONS - NEW SYNCHRONOUS STORAGE WITH DISPOSITION
# ============================================================================

def store_email_with_disposition(msg: EmailMessage, text_content: str, analysis_results: Dict,
                                 disposition: str, reason: str) -> bool:
    """
    NEW: Store email analysis with disposition (synchronous)
    This replaces async Redis queue storage to ensure disposition is set correctly
    """
    if not DB_CONN:
        safe_log("Database connection not available")
        return False

    try:
        from datetime import timedelta

        # Calculate quarantine expiry if quarantined
        quarantine_expires_at = None
        quarantine_status = None
        if disposition == 'quarantined':
            quarantine_status = 'held'
            quarantine_expires_at = datetime.datetime.now() + timedelta(days=30)

        # Extract sender IP and mail direction
        sender_ip = None
        mail_direction = 'inbound'  # Default
        sender_is_internal = False  # Default
        try:
            # Extract sender IP from Received headers
            received_headers = msg.get_all('Received', [])
            if received_headers:
                # Check FIRST received header to determine mail direction
                first_received = str(received_headers[0])
                first_ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', first_received)
                if first_ip_match:
                    first_ip = first_ip_match.group(1)
                    try:
                        first_ip_obj = ipaddress.ip_address(first_ip)
                        # Check if first IP is from internal network (indicates outbound)
                        internal_networks = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.0/8']
                        for network in internal_networks:
                            if first_ip_obj in ipaddress.ip_network(network):
                                mail_direction = 'outbound'
                                sender_is_internal = True
                                sender_ip = first_ip
                                break
                    except:
                        pass

                # If not outbound, find first external IP for sender_ip
                if mail_direction == 'inbound':
                    for received in received_headers:
                        received_str = str(received)
                        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_str)
                        if ip_match:
                            candidate_ip = ip_match.group(1)
                            # Skip private IPs for inbound determination
                            if not (candidate_ip.startswith('192.168.') or candidate_ip.startswith('10.') or
                                    candidate_ip.startswith('172.16.') or candidate_ip == '127.0.0.1'):
                                sender_ip = candidate_ip
                                break
        except:
            pass

        # Extract recipients
        envelope_recipients = msg.get_all('X-Postfix-Recipient', [])
        if not envelope_recipients:
            to_header = safe_get_header(msg, 'To', '')
            envelope_recipients = [to_header] if to_header else []

        recipients_str = ', '.join(envelope_recipients) if envelope_recipients else ''

        # Refine mail direction based on recipient domains
        # Check if recipients are internal (hosted) domains
        if sender_is_internal and envelope_recipients:
            try:
                # Get hosted domains from database
                hosted_cursor = DB_CONN.cursor()
                hosted_cursor.execute("SELECT domain FROM client_domains WHERE active = 1")
                hosted_domains = [row[0].lower() for row in hosted_cursor.fetchall()]
                hosted_cursor.close()

                # Check if all recipients are internal domains
                all_recipients_internal = True
                for recipient in envelope_recipients:
                    if '@' in recipient:
                        recipient_domain = recipient.split('@')[-1].strip().lower().rstrip('>')
                        if recipient_domain not in hosted_domains:
                            all_recipients_internal = False
                            break

                # Refine mail direction
                if all_recipients_internal:
                    mail_direction = 'internal'
                    safe_log(f"🏠 Internal mail: {sender_ip} → {recipients_str}")
                else:
                    mail_direction = 'outbound'
                    safe_log(f"📤 Outbound mail: {sender_ip} → {recipients_str}")
            except Exception as e:
                safe_log(f"Error refining mail direction: {e}")
                # Keep mail_direction as 'outbound' (already set earlier)

        # Hybrid storage: Store large emails (>20MB) on disk
        raw_email_str = msg.as_string() if hasattr(msg, 'as_string') else str(msg)
        raw_email_size = len(raw_email_str.encode('utf-8'))
        raw_email_to_store = None
        raw_email_path = None

        DISK_STORAGE_THRESHOLD = 20 * 1024 * 1024  # 20MB

        if raw_email_size > DISK_STORAGE_THRESHOLD:
            # Store on disk for large emails
            try:
                message_id = safe_get_header(msg, 'Message-ID', '').strip('<>').replace('/', '_')
                if not message_id:
                    import hashlib
                    message_id = hashlib.md5(raw_email_str.encode()).hexdigest()

                file_path = f"/var/spool/spacy-emails/{message_id}.eml"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(raw_email_str)

                raw_email_path = file_path
                safe_log(f"📁 Large email ({raw_email_size / 1024 / 1024:.1f}MB) stored to disk: {file_path}")
            except Exception as disk_err:
                safe_log(f"⚠️  Failed to write email to disk: {disk_err}, storing in database")
                raw_email_to_store = raw_email_str
        else:
            # Store in database for emails <=20MB
            raw_email_to_store = raw_email_str

        # Prepare email data
        cursor = DB_CONN.cursor()

        # Extract sender domain from sender email
        sender_email = safe_get_header(msg, 'From', '')
        sender_domain = None
        if '@' in sender_email:
            sender_domain = sender_email.split('@')[-1].strip().rstrip('>')

        # Extract recipient domains from recipients
        recipient_domains = []
        if envelope_recipients:
            for recipient in envelope_recipients:
                if '@' in recipient:
                    domain = recipient.split('@')[-1].strip().rstrip('>')
                    if domain and domain not in recipient_domains:
                        recipient_domains.append(domain)
        recipient_domains_str = json.dumps(recipient_domains) if recipient_domains else None

        # Extract attachment info
        attachment_count = 0
        attachment_names = []
        if analysis_results.get('has_attachments', False):
            # Try to get from analysis_results if available
            attachment_count = analysis_results.get('attachment_count', 0)
            attachment_names = analysis_results.get('attachment_names', [])

        # Extract virus/phishing detection
        virus_detected = 1 if analysis_results.get('virus_detected', False) else 0
        virus_names = json.dumps(analysis_results.get('virus_names', [])) if analysis_results.get('virus_names') else None
        phishing_detected = 1 if analysis_results.get('phishing_detected', False) else 0

        # Calculate auth score
        auth_results = analysis_results.get('auth_results', {})
        auth_score = 0.0
        if auth_results.get('spf') == 'pass':
            auth_score += 0.33
        if auth_results.get('dkim') == 'pass':
            auth_score += 0.33
        if auth_results.get('dmarc') == 'pass':
            auth_score += 0.34

        # Get spam modules detail
        spam_modules_detail = json.dumps(analysis_results.get('spam_modules_detail', {})) if analysis_results.get('spam_modules_detail') else None

        insert_query = """
            INSERT INTO email_analysis (
                timestamp, message_id, sender, sender_domain, recipients, recipient_domains, subject,
                spam_score, entities, all_links_count, suspicious_links,
                raw_text_length, urgency_score, sentiment_score,
                email_category, modules_run, email_topics, content_summary,
                detected_language, language_confidence,
                sentiment_polarity, sentiment_subjectivity,
                raw_email, raw_email_path, has_attachments,
                attachment_count, attachment_names, email_size,
                virus_detected, virus_names, phishing_detected,
                auth_score, spam_modules_detail,
                text_content, html_content,
                disposition, quarantine_status, quarantine_reason, quarantine_expires_at,
                original_spf, original_dkim, original_dmarc,
                original_sender_ip, mail_direction
            ) VALUES (
                NOW(), %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s
            )
        """

        cursor.execute(insert_query, (
            safe_get_header(msg, 'Message-ID', ''),
            sender_email,
            sender_domain,
            recipients_str,
            recipient_domains_str,
            safe_get_header(msg, 'Subject', ''),
            analysis_results.get('spam_score', 0.0),
            json.dumps(analysis_results.get('entities', [])),
            analysis_results.get('all_links_count', 0),
            json.dumps(analysis_results.get('suspicious_links', [])),
            analysis_results.get('raw_text_length', len(text_content)),
            analysis_results.get('urgency_score', 0.0),
            analysis_results.get('sentiment_score', 0.0),
            analysis_results.get('email_category', 'general'),
            json.dumps(analysis_results.get('modules_run', [])),
            json.dumps(analysis_results.get('email_topics', [])),
            analysis_results.get('content_summary', ''),
            analysis_results.get('detected_language', 'en'),
            analysis_results.get('language_confidence', 1.0),
            analysis_results.get('sentiment_polarity', 0.0),
            analysis_results.get('sentiment_subjectivity', 0.0),
            raw_email_to_store,  # NULL if stored on disk
            raw_email_path,  # File path if stored on disk
            analysis_results.get('has_attachments', False),
            attachment_count,
            json.dumps(attachment_names) if attachment_names else None,
            raw_email_size,  # Email size in bytes
            virus_detected,
            virus_names,
            phishing_detected,
            auth_score,
            spam_modules_detail,
            text_content,  # Text content for quarantine UI
            analysis_results.get('html_content'),  # HTML content for quarantine UI
            disposition,
            quarantine_status,
            reason,
            quarantine_expires_at,
            auth_results.get('spf', 'none'),
            auth_results.get('dkim', 'none'),
            auth_results.get('dmarc', 'none'),
            sender_ip,
            mail_direction
        ))

        DB_CONN.commit()
        cursor.close()
        safe_log(f"✅ Email stored with disposition: {disposition} ({reason})")

        # Check for VIP recipient alerts (when email is quarantined)
        if disposition == 'quarantined' and envelope_recipients:
            safe_log(f"🔔 VIP CHECK: Starting recipient alert check for {len(envelope_recipients)} recipient(s)")
            try:
                from modules.vip_alerts import VIPAlertSystem
                safe_log("🔔 VIP CHECK: VIPAlertSystem imported successfully")
                vip_system = VIPAlertSystem()
                safe_log("🔔 VIP CHECK: VIPAlertSystem instantiated successfully")

                # Check each recipient for VIP monitoring
                for recipient in envelope_recipients:
                    safe_log(f"🔔 VIP CHECK: Processing recipient: {recipient}")
                    if '@' in recipient:
                        recipient_clean = recipient.strip().rstrip('>')
                        recipient_domain = recipient_clean.split('@')[-1].lower()
                        safe_log(f"🔔 VIP CHECK: Cleaned recipient: {recipient_clean}, domain: {recipient_domain}")

                        # Get client_domain_id for recipient
                        try:
                            check_cursor = DB_CONN.cursor()
                            check_cursor.execute(
                                "SELECT id FROM client_domains WHERE domain = %s AND active = 1",
                                (recipient_domain,)
                            )
                            result = check_cursor.fetchone()
                            check_cursor.close()
                            safe_log(f"🔔 VIP CHECK: Domain lookup result: {result}")

                            if result:
                                client_domain_id = result[0]
                                message_id = safe_get_header(msg, 'Message-ID', '')
                                subject = safe_get_header(msg, 'Subject', '')
                                spam_score = analysis_results.get('spam_score', 0.0)
                                safe_log(f"🔔 VIP CHECK: Calling check_vip_recipient for {recipient_clean}, domain_id={client_domain_id}, score={spam_score}")

                                # Send VIP recipient alert
                                alert_sent = vip_system.check_vip_recipient(
                                    recipient_email=recipient_clean,
                                    sender_email=sender_email,
                                    message_id=message_id,
                                    subject=subject,
                                    spam_score=spam_score,
                                    client_domain_id=client_domain_id,
                                    quarantine_reason=reason
                                )
                                safe_log(f"🔔 VIP CHECK: Alert sent result: {alert_sent}")
                            else:
                                safe_log(f"🔔 VIP CHECK: No active domain found for {recipient_domain}")
                        except Exception as vip_check_err:
                            safe_log(f"🔔 VIP CHECK ERROR: {vip_check_err}")
                            import traceback
                            safe_log(f"🔔 VIP CHECK TRACEBACK: {traceback.format_exc()}")

            except Exception as vip_err:
                safe_log(f"VIP alert system error: {vip_err}")

        return True

    except Exception as e:
        safe_log(f"Failed to store email with disposition: {e}")
        return False
    finally:
        # Ensure cursor is always closed, even if commit fails
        try:
            cursor.close()
        except:
            pass


def update_email_disposition(message_id: str, new_disposition: str, reason: str) -> bool:
    """
    Update email disposition after relay attempt or bounce

    Args:
        message_id: Message-ID header from email
        new_disposition: New disposition value ('delivered', 'relay_failed', 'bounced')
        reason: Reason for disposition change

    Returns:
        bool: True if update successful
    """
    if not DB_CONN:
        safe_log("Database connection not available for disposition update")
        return False

    try:
        cursor = DB_CONN.cursor()

        update_query = """
            UPDATE email_analysis
            SET disposition = %s,
                quarantine_reason = %s
            WHERE message_id = %s
        """

        cursor.execute(update_query, (new_disposition, reason, message_id))
        DB_CONN.commit()

        if cursor.rowcount > 0:
            safe_log(f"✅ Updated disposition to '{new_disposition}' for message {message_id}")
            cursor.close()
            return True
        else:
            safe_log(f"⚠️  No rows updated for message {message_id} - may not exist in database")
            cursor.close()
            return False

    except Exception as e:
        safe_log(f"Failed to update email disposition: {e}")
        return False
    finally:
        # Ensure cursor is always closed
        try:
            cursor.close()
        except:
            pass


# ============================================================================
# DATABASE OPERATIONS VIA REDIS QUEUE - DEPRECATED
# ============================================================================

def store_email_analysis_via_queue(msg: EmailMessage, text_content: str, analysis_results: Dict, monitor: PerformanceMonitor):
    """DEPRECATED: Use store_email_with_disposition() instead"""
    if not REDIS_QUEUE or not hasattr(REDIS_QUEUE, 'connected') or not REDIS_QUEUE.connected:
        safe_log("Redis queue not available for storage")
        return

    try:
        # Convert EmailMessage to string for db_processor
        msg_str = msg.as_string() if hasattr(msg, 'as_string') else str(msg)

        # Extract actual envelope recipients (not just To: header)
        envelope_recipients = msg.get_all('X-Postfix-Recipient', [])
        if not envelope_recipients:
            # Fallback to To: header if X-Postfix-Recipient not available
            to_header = safe_get_header(msg, 'To', '')
            envelope_recipients = [to_header] if to_header else []

        # Prepare data in the format expected by db_processor
        queue_message = {
            'version': '1.0',  # Required by db_processor
            'email_data': {
                'message': msg_str,  # Full message for parsing
                'message_id': safe_get_header(msg, 'Message-ID', ''),
                'from_header': safe_get_header(msg, 'From', ''),
                'recipients': envelope_recipients,  # Use actual envelope recipients
                'text_content': text_content,
                'timestamp': datetime.datetime.now().isoformat(),
                'content_summary': analysis_results.get('content_summary', '')  # Include NER summary
            },
            'analysis_results': analysis_results  # Pass through all analysis results
        }
        
        # Push to Redis queue with custom JSON encoder for datetime objects
        class DateTimeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, datetime.datetime):
                    return obj.isoformat()
                elif isinstance(obj, datetime.date):
                    return obj.isoformat()
                return super().default(obj)
        
        queue_data = json.dumps(queue_message, cls=DateTimeEncoder)
        REDIS_QUEUE.lpush('email_analysis_queue', queue_data)
        safe_log("✅ Email analysis queued for database storage")
        
    except Exception as e:
        safe_log(f"Failed to queue email analysis: {e}")

# ============================================================================
# RELAY FUNCTION - FIXED FOR ENCODING ISSUES
# ============================================================================

def relay_to_mailguard(msg: EmailMessage, recipients: List[str]) -> bool:
    """Relay email to mailguard with improved encoding handling - SUPPORTS PER-DOMAIN RELAY HOSTS"""
    try:
        processed_domains = CONFIG.config['domains']['processed_domains']
        domain_relays = CONFIG.config['servers'].get('domain_relays', {})
        default_host = CONFIG.config['servers']['mailguard_host']
        default_port = CONFIG.config['servers']['mailguard_port']
        smtp_timeout = CONFIG.config['timeouts']['smtp_timeout']

        # Group recipients by domain
        recipients_by_domain = {}
        filtered_recipients = []

        for recipient in recipients:
            try:
                if '@' in recipient:
                    domain = recipient.split('@')[1].lower()
                    if domain in processed_domains:
                        if domain not in recipients_by_domain:
                            recipients_by_domain[domain] = []
                        recipients_by_domain[domain].append(recipient)
                    else:
                        filtered_recipients.append(recipient)
                        safe_log(f"📧 Filtering external recipient (not relaying): {recipient}")
            except Exception as e:
                safe_log(f"Error validating recipient {recipient}: {e}")

        if not recipients_by_domain:
            if filtered_recipients:
                safe_log(f"✅ All {len(filtered_recipients)} recipients were external - no relay needed")
                return True  # Return success - we've handled the email correctly by not relaying it
            else:
                safe_log("❌ No valid recipients after domain validation")
                return False

        if filtered_recipients:
            total_internal = sum(len(recips) for recips in recipients_by_domain.values())
            safe_log(f"📬 Processing mixed recipients: {total_internal} internal, {len(filtered_recipients)} external (filtered)")

        # Relay to each domain's specific relay host
        all_success = True
        for domain, domain_recipients in recipients_by_domain.items():
            # Get relay host for this domain
            if domain in domain_relays:
                mailguard_host = domain_relays[domain]['relay_host']
                mailguard_port = domain_relays[domain]['relay_port']
            else:
                mailguard_host = default_host
                mailguard_port = default_port

            safe_log(f"Relaying {len(domain_recipients)} recipients for {domain} to {mailguard_host}:{mailguard_port}")

            try:
                with smtplib.SMTP(mailguard_host, mailguard_port, timeout=smtp_timeout) as smtp:
                    # Try to use STARTTLS for encryption (graceful fallback if not supported)
                    try:
                        smtp.starttls()
                        smtp.ehlo()  # Must send EHLO again after STARTTLS
                        safe_log(f"✅ TLS enabled for connection to {mailguard_host}:{mailguard_port}")
                    except Exception as tls_err:
                        safe_log(f"⚠️  TLS not available for {mailguard_host}:{mailguard_port} - continuing without encryption: {tls_err}")

                    sender = safe_get_header(msg, 'Return-Path', safe_get_header(msg, 'From', ''))
                    if sender.startswith('<') and sender.endswith('>'):
                        sender = sender[1:-1]

                    # IMPROVED ENCODING HANDLING
                    email_bytes = None

                    try:
                        # Method 1: Try as_bytes() first (preserves original encoding)
                        email_bytes = msg.as_bytes()
                        safe_log("Using as_bytes() for SMTP relay")
                    except Exception as e1:
                        safe_log(f"as_bytes() failed: {e1}")
                        try:
                            # Method 2: Try as_string() with UTF-8
                            email_string = msg.as_string(policy=default)
                            email_bytes = email_string.encode('utf-8', errors='replace')
                            safe_log("Using as_string() with UTF-8 encoding")
                        except Exception as e2:
                            safe_log(f"as_string() with UTF-8 failed: {e2}")
                            try:
                                # Method 3: Force ASCII with replacement
                                email_string = msg.as_string(policy=default)
                                email_bytes = email_string.encode('ascii', errors='replace')
                                safe_log("Using ASCII encoding with replacements")
                            except Exception as e3:
                                safe_log(f"ASCII encoding failed: {e3}")
                                # Method 4: Last resort - convert to string and clean
                                try:
                                    email_string = str(msg)
                                    # Remove non-ASCII characters
                                    email_string = ''.join(char if ord(char) < 128 else '?' for char in email_string)
                                    email_bytes = email_string.encode('ascii')
                                    safe_log("Using cleaned ASCII as last resort")
                                except Exception as e4:
                                    safe_log(f"❌ All encoding methods failed: {e4}")
                                    all_success = False
                                    continue

                    # Send the email using low-level SMTP commands to capture queue ID
                    # Use low-level commands instead of sendmail() to get DATA response
                    try:
                        smtp.ehlo_or_helo_if_needed()
                        smtp.mail(sender)
                        refused = {}
                        for recipient in domain_recipients:
                            try:
                                smtp.rcpt(recipient)
                            except smtplib.SMTPRecipientsRefused as e:
                                refused[recipient] = e

                        # Send DATA and capture response with queue ID
                        code, response = smtp.data(email_bytes)

                        # Extract queue ID from DATA response
                        upstream_queue_id = "unknown"
                        try:
                            response_str = response.decode() if isinstance(response, bytes) else str(response)
                            safe_log(f"📬 SMTP DATA response from {mailguard_host}: code={code}, response='{response_str}'")

                            # Try multiple extraction patterns for different mail servers
                            if "queued as" in response_str.lower():
                                # Postfix/Zimbra format: "250 2.0.0 Ok: queued as ABC123"
                                parts = response_str.split("queued as")
                                if len(parts) > 1:
                                    upstream_queue_id = parts[1].strip().split()[0].rstrip(')')
                                    safe_log(f"✅ Extracted queue ID (queued as): {upstream_queue_id}")
                            elif re.search(r'\b[A-Za-z0-9]{10,}[-.]?[A-Za-z0-9]*\b', response_str):
                                # Google/flexible format: Match queue IDs like "586e51a60fabf-3e833f8f9d3mr1536752fac.3"
                                # or traditional IDs like "ABC123DEF456"
                                queue_match = re.search(r'\b[A-Za-z0-9]{10,}[-.]?[A-Za-z0-9]*\b', response_str)
                                if queue_match:
                                    upstream_queue_id = queue_match.group(0)
                                    safe_log(f"✅ Extracted queue ID (pattern match): {upstream_queue_id}")
                            elif re.search(r'[A-F0-9]{8,}', response_str):
                                # Hex queue ID format
                                queue_match = re.search(r'[A-F0-9]{8,}', response_str)
                                if queue_match:
                                    upstream_queue_id = queue_match.group(0)
                                    safe_log(f"✅ Extracted queue ID (hex): {upstream_queue_id}")

                            if upstream_queue_id == "unknown":
                                # No recognizable queue ID - store the response for debugging
                                upstream_queue_id = f"{domain}: {response_str[:80]}"
                                safe_log(f"⚠️  No queue ID pattern matched, storing response: {upstream_queue_id}")
                        except Exception as e:
                            safe_log(f"⚠️  Could not extract queue ID from response: {e}")
                            upstream_queue_id = "unknown"
                    except smtplib.SMTPException as smtp_err:
                        safe_log(f"❌ SMTP error during relay: {smtp_err}")
                        refused = {}
                        upstream_queue_id = "unknown"

                    # Add forensic headers for chain of custody tracking
                    safe_add_header(msg, 'X-Upstream-Queue-ID', upstream_queue_id)
                    safe_add_header(msg, 'X-Upstream-Relay-Host', mailguard_host)
                    safe_add_header(msg, 'X-Relay-Timestamp', datetime.datetime.now().isoformat())

                    safe_log(f"✅ Relayed to {len(domain_recipients)} recipients for {domain}")
                    safe_log(f"📬 Upstream Queue ID: {upstream_queue_id} (mailguard: {mailguard_host})")

                    # Update database with upstream queue ID
                    try:
                        message_id = safe_get_header(msg, 'Message-ID', '')
                        if message_id:
                            cursor = DB_CONN.cursor()
                            cursor.execute("""
                                UPDATE email_analysis
                                SET upstream_queue_id = %s
                                WHERE message_id = %s
                            """, (upstream_queue_id, message_id))
                            DB_CONN.commit()
                            cursor.close()
                            safe_log(f"✅ Updated database with upstream queue ID: {upstream_queue_id}")
                    except Exception as db_err:
                        safe_log(f"⚠️  Could not update upstream queue ID in database: {db_err}")

                    if refused:
                        safe_log(f"⚠️  Some recipients refused: {refused}")

            except smtplib.SMTPRecipientsRefused as e:
                safe_log(f"⚠️  Mailguard rejected recipients for {domain}: {e}")
                # Continue to next domain even if this one failed

            except Exception as e:
                safe_log(f"❌ Relay error for {domain}: {e}")
                all_success = False

        return all_success

    except Exception as e:
        safe_log(f"❌ Relay error: {e}")
        return False

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_spacy_repetition(msg: EmailMessage, from_header: str) -> bool:
    """Check if sender has sent multiple blocked spams"""
    try:
        x_spacy_history = safe_get_header(msg, 'X-SpaCy-Sender-History', '')
        if x_spacy_history:
            parts = x_spacy_history.split(':')
            if len(parts) == 2:
                total_count = int(parts[0])
                spacy_count = int(parts[1])
                
                if spacy_count >= CONFIG.config['thresholds']['thread_spam_repetition_threshold']:
                    safe_log(f"⚠️ Sender marked as SpaCy {spacy_count} times")
                    return True
    except Exception as e:
        safe_log(f"Error checking SpaCy repetition: {e}")
    
    return False

def validate_internal_domain(msg: EmailMessage, from_header: str) -> bool:
    """Validate internal domain claims"""
    internal_domains = CONFIG.config['domains']['internal_domains']
    
    try:
        sender_domain = safe_extract_domain(from_header)
        
        if sender_domain in internal_domains:
            received_headers = msg.get_all('Received', [])
            internal_ips = CONFIG.config['servers']['internal_ips']
            
            for received in received_headers[:3]:
                received_str = str(received).lower()
                if any(ip in received_str for ip in internal_ips):
                    safe_log(f"Internal domain {sender_domain} validated")
                    return True
            
            safe_log(f"SPOOFED DOMAIN DETECTED: {sender_domain}")
            return False
    
    except Exception as e:
        safe_log(f"Domain validation error: {e}")
    
    return True

def extract_all_recipients(msg: EmailMessage) -> List[str]:
    """Extract ALL recipients from email headers and postfix command-line"""
    all_recipients = []
    
    # First check for recipients passed from postfix command-line
    postfix_recipients = msg.get_all('X-Postfix-Recipient', [])
    if postfix_recipients:
        all_recipients.extend([str(r) for r in postfix_recipients])
    
    # Then check standard headers
    for header in ['To', 'Cc', 'Bcc', 'X-Original-To', 'Envelope-To']:
        header_value = safe_get_header(msg, header, '')
        if '@' in header_value:
            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', header_value)
            all_recipients.extend(found_emails)
    
    for received in msg.get_all('Received', []):
        received_str = str(received)
        for_match = re.search(r'for\s+<([^>]+)>', received_str)
        if for_match:
            all_recipients.append(for_match.group(1))
    
    # Get unique recipients first
    unique_recipients = list(set([r.lower() for r in all_recipients if '@' in r]))
    safe_log(f"Found {len(unique_recipients)} total unique recipients")
    
    # Filter to only include recipients from our processed domains
    processed_domains = CONFIG.config['domains']['processed_domains']
    filtered_recipients = []
    external_recipients = []
    
    for recipient in unique_recipients:
        if '@' in recipient:
            domain = recipient.split('@')[1].lower()
            if domain in processed_domains:
                filtered_recipients.append(recipient)
            else:
                external_recipients.append(recipient)
    
    if external_recipients:
        safe_log(f"📧 Filtering out {len(external_recipients)} external recipients: {', '.join(external_recipients[:5])}{'...' if len(external_recipients) > 5 else ''}")
    
    if filtered_recipients:
        safe_log(f"✅ Processing {len(filtered_recipients)} recipients from our domains: {', '.join(filtered_recipients)}")
    else:
        safe_log(f"⚠️ No recipients from our processed domains found")
    
    return filtered_recipients

def is_outbound_from_trusted_source(msg: EmailMessage) -> bool:
    """
    Check if email is outbound mail from a trusted internal source.
    Returns True if the email came from a server in internal/RFC1918 networks.
    Configure specific trusted IPs in email_filter_config.json under 'trusted_relay_ips'.
    """
    # Get trusted IPs from config, or use empty list
    trusted_ips = CONFIG.config.get('trusted_relay_ips', [])

    # Also check standard RFC1918 private networks
    internal_networks = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']

    # Check the first Received header (most recent)
    received_headers = msg.get_all('Received', [])
    if received_headers:
        first_received = str(received_headers[0])

        # Check for specific trusted IPs
        for trusted_ip in trusted_ips:
            if f'[{trusted_ip}]' in first_received or f'({trusted_ip})' in first_received:
                safe_log(f"✅ Outbound email detected from trusted source: {trusted_ip}")
                return True

        # Check for any internal network IP
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
        if ip_match:
            try:
                ip_obj = ipaddress.ip_address(ip_match.group(1))
                for network in internal_networks:
                    if ip_obj in ipaddress.ip_network(network):
                        safe_log(f"✅ Outbound email detected from internal IP: {ip_match.group(1)}")
                        return True
            except:
                pass

    return False

def is_system_email(msg: EmailMessage, from_header: str, subject: str) -> bool:
    """Check if email is from system/cron that should bypass processing"""
    sender_domain = safe_extract_domain(from_header)
    bypass_config = CONFIG.config['system_bypass']
    
    # Check bypass domains
    if sender_domain in bypass_config['bypass_domains']:
        return True
    
    # Check bypass senders
    for bypass_sender in bypass_config['bypass_senders']:
        if from_header.lower().startswith(bypass_sender.lower()):
            return True
    
    # Check bypass subjects
    for bypass_subject in bypass_config['bypass_subjects']:
        if bypass_subject.lower() in subject.lower():
            return True
    
    return False

def check_trusted_entities_whitelist(sender_email: str, recipient_domains: list) -> Dict:
    """
    Check if sender is whitelisted in trusted_entities database for any recipient domain

    Returns dict with:
        - is_whitelisted: bool
        - trust_level: str (if whitelisted)
        - scope: str ('global' or 'per_domain')
        - recipient_domain: str (if per_domain)
    """
    result = {
        'is_whitelisted': False,
        'trust_level': None,
        'scope': None,
        'recipient_domain': None
    }

    try:
        import mysql.connector
        db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'spacy_user'),
            'password': os.getenv('DB_PASSWORD', ''),
            'database': os.getenv('DB_NAME', 'spacy_email_db')
        }

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Check for global whitelist OR per_domain whitelist for any recipient domain
        # Build query to check global + all recipient domains
        if recipient_domains:
            placeholders = ','.join(['%s'] * len(recipient_domains))
            query = f"""
                SELECT entity_value, trust_level, scope, recipient_domain
                FROM trusted_entities
                WHERE entity_type = 'sender'
                AND entity_value = %s
                AND active = 1
                AND (scope = 'global' OR (scope = 'per_domain' AND recipient_domain IN ({placeholders})))
                LIMIT 1
            """
            params = [sender_email] + recipient_domains
        else:
            # Only check global if no recipient domains
            query = """
                SELECT entity_value, trust_level, scope, recipient_domain
                FROM trusted_entities
                WHERE entity_type = 'sender'
                AND entity_value = %s
                AND active = 1
                AND scope = 'global'
                LIMIT 1
            """
            params = [sender_email]

        cursor.execute(query, params)
        entity = cursor.fetchone()

        if entity:
            result['is_whitelisted'] = True
            result['trust_level'] = entity['trust_level']
            result['scope'] = entity['scope']
            result['recipient_domain'] = entity['recipient_domain']

            # Update last_used and use_count
            cursor.execute("""
                UPDATE trusted_entities
                SET last_used = NOW(), use_count = use_count + 1
                WHERE entity_value = %s AND entity_type = 'sender'
            """, (sender_email,))
            conn.commit()

        cursor.close()
        conn.close()

    except Exception as e:
        safe_log(f"Error checking trusted_entities whitelist: {e}")

    return result

# ============================================================================
# MAIN PROCESSING FUNCTION - WITH MICROSOFT MFA BYPASS, ENCODING FIX, AND LOOP PREVENTION
# ============================================================================

def main():
    """Main email processing function - FULL FUNCTIONALITY WITH TIMEOUT HANDLING AND LOOP PREVENTION"""
    # Restore original stderr now that initialization is complete
    if hasattr(sys.stderr, 'original_stderr'):
        sys.stderr = sys.stderr.original_stderr

    monitor = PerformanceMonitor()

    # Get arguments from command line (passed by Postfix)
    # Format: email_filter.py ${queue_id} ${sender} ${recipient}
    postfix_queue_id = None
    envelope_sender = None

    if len(sys.argv) > 1:
        postfix_queue_id = sys.argv[1]
        os.environ['QUEUE_ID'] = postfix_queue_id  # Set for later use
        safe_log(f"📧 Queue ID from Postfix: {postfix_queue_id}")

    if len(sys.argv) > 2:
        envelope_sender = sys.argv[2]
        safe_log(f"📧 Envelope sender from Postfix: {envelope_sender}")

    # If envelope_sender not provided, we'll extract it from headers later when we have the message parsed

    try:
        def timeout_handler(signum, frame):
            monitor.log_performance(safe_log)
            safe_log("🚨 TIMEOUT: Processing exceeded limit")
            sys.exit(124)

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(CONFIG.config['timeouts']['total_processing'])

        email_data = sys.stdin.buffer.read()
        monitor.record_email_stats(len(email_data), 0)
        safe_log(f"Email size: {len(email_data)} bytes")
        
        # ============================================================================
        # CRITICAL EMERGENCY: Microsoft MFA Bypass - MUST BE FIRST
        # ============================================================================
        try:
            # Check raw email for Microsoft patterns
            email_str_lower = email_data.decode('utf-8', errors='ignore').lower()
            
            # Multiple Microsoft MFA detection patterns
            is_microsoft_mfa = False
            
            # Check sender
            if 'msonlineservicesteam@microsoftonline.com' in email_str_lower:
                is_microsoft_mfa = True
                safe_log("🔐 Microsoft MFA: Detected by sender")
            
            # Check for substrate.office.com
            if 'substrate.office.com' in email_str_lower:
                is_microsoft_mfa = True
                safe_log("🔐 Microsoft MFA: Detected by substrate domain")
            
            # Check for protection.outlook.com relay
            if 'protection.outlook.com' in email_str_lower and 'microsoftonline.com' in email_str_lower:
                is_microsoft_mfa = True
                safe_log("🔐 Microsoft MFA: Detected by outlook protection relay")
            
            # Check subject patterns
            if 'microsoft account security code' in email_str_lower or 'microsoft account team' in email_str_lower:
                is_microsoft_mfa = True
                safe_log("🔐 Microsoft MFA: Detected by subject")
            
            if is_microsoft_mfa:
                safe_log("🚀 MICROSOFT MFA EMERGENCY BYPASS ACTIVATED")

                # Parse minimally just to get recipients
                msg = None
                try:
                    parser = BytesParser(policy=default)
                    msg = parser.parsebytes(email_data)
                except Exception as mfa_parse_error:
                    safe_log(f"⚠️ MFA email parsing error (trying compat mode): {mfa_parse_error}")
                    try:
                        from email.policy import compat32
                        parser = BytesParser(policy=compat32)
                        msg = parser.parsebytes(email_data)
                    except Exception as mfa_parse_error2:
                        safe_log(f"❌ MFA parsing failed completely, skipping MFA bypass: {mfa_parse_error2}")
                        msg = None  # Signal that parsing failed

                # Get ALL possible recipients from various headers
                recipients = []

                # Only continue if we successfully parsed
                if msg is not None:
                    # Check multiple headers for recipients
                    for header_name in ['To', 'X-Original-To', 'Delivered-To', 'Envelope-To']:
                        header_value = msg.get(header_name, '')
                        if header_value:
                            # Extract all email addresses from the header
                            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', header_value)
                            recipients.extend(found_emails)

                    # Also check Received headers for "for <email>" patterns
                    for received in msg.get_all('Received', []):
                        received_str = str(received)
                        for_match = re.search(r'for\s+<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?', received_str)
                        if for_match:
                            recipients.append(for_match.group(1))

                    # Clean and validate recipients
                    processed_domains = CONFIG.config['domains']['processed_domains']
                    valid_recipients = []
                    for email in recipients:
                        email_lower = email.lower().strip()
                        # Check if it's one of your domains
                        for domain in processed_domains:
                            if email_lower.endswith('@' + domain):
                                if email_lower not in valid_recipients:
                                    valid_recipients.append(email_lower)
                                break

                    recipients = valid_recipients
                    safe_log(f"🔐 Found recipients: {recipients}")

                    if recipients:
                        safe_log(f"🔐 Microsoft MFA recipients: {recipients}")

                        # Direct relay using RAW BYTES - skip ALL validation
                        try:
                            # Get per-domain relay configuration
                            domain_relays = CONFIG.config['servers'].get('domain_relays', {})
                            default_host = CONFIG.config.get('servers', {}).get('mailguard_host', 'localhost')
                            default_port = CONFIG.config.get('servers', {}).get('mailguard_port', 25)

                            # Group recipients by domain to get correct relay
                            recipients_by_relay = {}
                            for recipient in recipients:
                                recipient_domain = recipient.split('@')[-1].lower()
                                if recipient_domain in domain_relays:
                                    relay_host = domain_relays[recipient_domain]['relay_host']
                                    relay_port = domain_relays[recipient_domain]['relay_port']
                                else:
                                    relay_host = default_host
                                    relay_port = default_port

                                relay_key = f"{relay_host}:{relay_port}"
                                if relay_key not in recipients_by_relay:
                                    recipients_by_relay[relay_key] = {
                                        'host': relay_host,
                                        'port': relay_port,
                                        'recipients': []
                                    }
                                recipients_by_relay[relay_key]['recipients'].append(recipient)

                            # Send to each relay destination
                            sender = 'msonlineservicesteam@microsoftonline.com'

                            for relay_key, relay_info in recipients_by_relay.items():
                                relay_host = relay_info['host']
                                relay_port = relay_info['port']
                                relay_recipients = relay_info['recipients']

                                safe_log(f"🔐 Relaying MFA to {relay_host}:{relay_port} for {relay_recipients}")

                                try:
                                    with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                                        # Try to use STARTTLS for encryption
                                        try:
                                            smtp.starttls()
                                            smtp.ehlo()  # Must send EHLO again after STARTTLS
                                            safe_log(f"✅ TLS enabled for MFA relay to {relay_host}:{relay_port}")
                                        except Exception as tls_err:
                                            safe_log(f"⚠️  TLS not available for MFA relay - continuing: {tls_err}")

                                        # CRITICAL FIX: Use raw bytes directly for Microsoft MFA
                                        # This preserves the original encoding without conversion issues
                                        smtp.sendmail(sender, relay_recipients, email_data)
                                        safe_log(f"✅ Microsoft MFA email EMERGENCY RELAYED (raw bytes) to {relay_recipients}")

                                        # Log to database for GUI visibility (while maintaining expedited delivery)
                                        try:
                                            from_email = msg.get('From', 'account-security-noreply@accountprotection.microsoft.com')
                                            subject = msg.get('Subject', 'Microsoft Account Security Code')
                                            message_id = msg.get('Message-ID', f'<mfa-{datetime.datetime.now().timestamp()}@microsoft.com>')

                                            conn = get_db_connection()
                                            cursor = conn.cursor()
                                            cursor.execute("""
                                                INSERT INTO email_analysis
                                                (message_id, sender, recipients, subject, spam_score, disposition,
                                                 raw_email, timestamp, mail_direction)
                                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                            """, (
                                                message_id,
                                                from_email,
                                                ', '.join(relay_recipients),
                                                subject,
                                                0.0,  # No spam score for MFA emails
                                                'delivered',
                                                email_data.decode('utf-8', errors='replace'),
                                                datetime.datetime.now(),
                                                'inbound'
                                            ))
                                            conn.commit()
                                            last_id = cursor.lastrowid
                                            cursor.close()
                                            conn.close()
                                            safe_log(f"✅ Microsoft MFA email logged to database (ID: {last_id})")
                                        except Exception as db_err:
                                            safe_log(f"⚠️ Failed to log MFA email to database (non-fatal): {db_err}")

                                except Exception as relay_error:
                                    safe_log(f"⚠️ Microsoft MFA raw relay failed for {relay_host}:{relay_port}: {relay_error}")
                                    # Try with as_bytes as fallback
                                    try:
                                        with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                                            # Try to use STARTTLS for encryption
                                            try:
                                                smtp.starttls()
                                                smtp.ehlo()  # Must send EHLO again after STARTTLS
                                                safe_log(f"✅ TLS enabled for MFA fallback relay to {relay_host}:{relay_port}")
                                            except Exception as tls_err:
                                                safe_log(f"⚠️  TLS not available for MFA fallback - continuing: {tls_err}")

                                            smtp.sendmail(sender, relay_recipients, msg.as_bytes())
                                            safe_log(f"✅ Microsoft MFA email EMERGENCY RELAYED (as_bytes) to {relay_recipients}")

                                            # Log to database for GUI visibility
                                            try:
                                                from_email = msg.get('From', 'account-security-noreply@accountprotection.microsoft.com')
                                                subject = msg.get('Subject', 'Microsoft Account Security Code')
                                                message_id = msg.get('Message-ID', f'<mfa-{datetime.datetime.now().timestamp()}@microsoft.com>')

                                                conn = get_db_connection()
                                                cursor = conn.cursor()
                                                cursor.execute("""
                                                    INSERT INTO email_analysis
                                                    (message_id, sender, recipients, subject, spam_score, disposition,
                                                     raw_email, timestamp, mail_direction)
                                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                """, (
                                                    message_id,
                                                    from_email,
                                                    ', '.join(relay_recipients),
                                                    subject,
                                                    0.0,
                                                    'delivered',
                                                    msg.as_string(),
                                                    datetime.datetime.now(),
                                                    'inbound'
                                                ))
                                                conn.commit()
                                                last_id = cursor.lastrowid
                                                cursor.close()
                                                conn.close()
                                                safe_log(f"✅ Microsoft MFA email logged to database (ID: {last_id})")
                                            except Exception as db_err:
                                                safe_log(f"⚠️ Failed to log MFA email to database (non-fatal): {db_err}")

                                    except Exception as e2:
                                        safe_log(f"⚠️ Microsoft MFA as_bytes relay failed for {relay_host}:{relay_port}: {e2}")
                                        # Continue to next relay destination if any
                                        continue

                            sys.exit(0)  # Success!

                        except Exception as relay_setup_error:
                            safe_log(f"⚠️ Microsoft MFA relay setup failed: {relay_setup_error}")
                            # Fall through to normal processing
                    else:
                        safe_log("⚠️ Microsoft MFA detected but no valid recipients found")
                    
        except Exception as bypass_error:
            safe_log(f"⚠️ Microsoft MFA bypass error (non-fatal): {bypass_error}")
            # Continue with normal processing
        
        # ============================================================================
        # Parse email for processing with error handling
        # ============================================================================
        try:
            parser = BytesParser(policy=default)
            msg = parser.parsebytes(email_data)
            safe_log("Email parsed successfully")
        except Exception as parse_error:
            safe_log(f"⚠️ Email parsing error: {parse_error}")
            # Try with a more lenient policy
            try:
                from email.policy import compat32
                parser = BytesParser(policy=compat32)
                msg = parser.parsebytes(email_data)
                safe_log("Email parsed with compatibility mode")
            except Exception as e2:
                safe_log(f"❌ Critical parsing error: {e2}")
                # Create a minimal message to avoid crashes
                msg = EmailMessage()
                msg['Subject'] = 'Unparseable Email'
                msg['From'] = 'unknown@unknown.invalid'
                safe_log("Using fallback minimal message")
        
        # ============================================================================
        # HANDLE COMMAND-LINE RECIPIENTS FROM POSTFIX
        # ============================================================================
        cmdline_recipients = []
        if len(sys.argv) > 3:
            # Postfix passes recipients as command-line arguments
            # argv[1] is queue_id, argv[2] is sender, argv[3+] are recipients
            cmdline_recipients = [arg for arg in sys.argv[3:] if '@' in arg]
            if cmdline_recipients:
                safe_log(f"Recipients from postfix: {cmdline_recipients}")
                # Add to message headers for later processing
                for recipient in cmdline_recipients:
                    msg['X-Postfix-Recipient'] = recipient

        # ============================================================================
        # DANGEROUS ATTACHMENT FILTERING - Strip blocked file types
        # ============================================================================
        msg, blocked_files = strip_dangerous_attachments(msg)
        if blocked_files:
            safe_log(f"🚫 Removed {len(blocked_files)} dangerous attachment(s): {', '.join(blocked_files)}")
            msg = add_attachment_notification(msg, blocked_files)

        # ============================================================================
        # NEW: LOOP DETECTION - Check for too many hops
        # ============================================================================
        received_headers = msg.get_all('Received', [])
        received_count = len(received_headers)
        max_received = CONFIG.config['system_bypass']['max_received_headers']
        warning_received = CONFIG.config['system_bypass']['warning_received_headers']
        
        if received_count > max_received:
            safe_log(f"🚫 LOOP DETECTED: {received_count} Received headers exceeds max {max_received} - dropping message")
            signal.alarm(0)
            sys.exit(0)  # Drop the message to break the loop
        elif received_count > warning_received:
            safe_log(f"⚠️ WARNING: {received_count} Received headers - possible mail loop developing")
        
        # ============================================================================
        # NEW: SYSTEM EMAIL BYPASS - Prevent mail loops for system/cron emails
        # ============================================================================
        from_header = safe_get_header(msg, 'From', '')
        subject = safe_get_header(msg, 'Subject', '')
        
        # Check if this is a system email
        if is_system_email(msg, from_header, subject):
            sender_domain = safe_extract_domain(from_header)
            safe_log(f"📧 SYSTEM EMAIL BYPASS - {from_header} - preventing mail loop")
            
            # Add bypass headers
            safe_add_header(msg, 'X-SpaCy-Bypass', 'system-email', monitor)
            safe_add_header(msg, 'X-SpaCy-Bypass-Reason', f'from={sender_domain}', monitor)
            safe_add_header(msg, 'X-SpaCy-Processed', 'bypassed', monitor)
            safe_add_header(msg, 'X-SpaCy-Timestamp', datetime.datetime.now().isoformat(), monitor)
            
            # CRITICAL: Don't relay emails from our own mail server back to ourselves
            bypass_domains = CONFIG.config.get('system_bypass', {}).get('bypass_domains', [])
            if sender_domain in bypass_domains:
                safe_log("✅ System email from SpaCy itself - dropping to prevent loop")
                signal.alarm(0)
                sys.exit(0)  # Success but don't relay back to ourselves
            else:
                # Relay system emails from other sources
                recipients = extract_all_recipients(msg)
                if relay_to_mailguard(msg, recipients):
                    safe_log("✅ System email relayed directly")
                    signal.alarm(0)
                    sys.exit(0)
                else:
                    safe_log("❌ System email relay failed")
                    signal.alarm(0)
                    sys.exit(1)
        
        # ============================================================================
        # Continue with normal email processing...
        # ============================================================================

        # ============================================================================
        # EARLY BLOCKING CHECK - Reject blocked senders BEFORE any analysis
        # ============================================================================
        try:
            # Extract sender email from From header
            sender_email = from_header.lower()
            if '<' in sender_email and '>' in sender_email:
                sender_email = sender_email.split('<')[1].split('>')[0]
            sender_email = sender_email.strip()

            # ====================================================================
            # PROTECTED DOMAIN IMPERSONATION CHECK
            # Block external emails claiming to be from our protected domains
            # ====================================================================
            if sender_email and '@' in sender_email and DB_CONN:
                sender_domain = sender_email.split('@')[1].lower()

                try:
                    # Check if sender domain is one of our protected domains
                    imperson_cursor = DB_CONN.cursor()
                    imperson_cursor.execute("""
                        SELECT domain FROM client_domains WHERE active = 1 AND domain = %s
                        UNION
                        SELECT domain FROM hosted_domains WHERE is_active = 1 AND domain = %s
                    """, (sender_domain, sender_domain))

                    is_protected_domain = imperson_cursor.fetchone() is not None
                    imperson_cursor.close()

                    if is_protected_domain:
                        # This is a protected domain - verify authentication
                        safe_log(f"🔒 Protected domain detected in sender: {sender_domain}")

                        # Check Authentication-Results header for SPF/DKIM/DMARC
                        is_authenticated = False
                        auth_results_headers = msg.get_all('Authentication-Results', [])

                        for auth_header in auth_results_headers:
                            auth_str = str(auth_header).lower()
                            # Check for SPF or DKIM pass
                            if 'spf=pass' in auth_str or 'dkim=pass' in auth_str:
                                # Verify the domain matches
                                if sender_domain in auth_str:
                                    is_authenticated = True
                                    safe_log(f"✅ Authenticated email from protected domain: {sender_domain}")
                                    break

                        # Also check if from trusted internal relay
                        received_headers = msg.get_all('Received', [])
                        from_trusted_relay = False
                        if received_headers:
                            first_received = str(received_headers[0]).lower()
                            # Check for internal relay (RFC1918 networks)
                            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
                            if ip_match:
                                try:
                                    relay_ip = ipaddress.ip_address(ip_match.group(1))
                                    internal_nets = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']
                                    for net in internal_nets:
                                        if relay_ip in ipaddress.ip_network(net):
                                            from_trusted_relay = True
                                            safe_log(f"✅ Email from trusted internal relay: {ip_match.group(1)}")
                                            break
                                except:
                                    pass

                        # If not authenticated and not from trusted relay, BLOCK
                        if not is_authenticated and not from_trusted_relay:
                            safe_log(f"🚫 BLOCKED: Unauthenticated impersonation of protected domain")
                            safe_log(f"   Sender: {sender_email}")
                            safe_log(f"   Protected domain: {sender_domain}")
                            safe_log(f"   Reason: External email claiming to be from protected domain without authentication")

                            # Log the impersonation attempt with recipient context
                            try:
                                log_cursor = DB_CONN.cursor()
                                temp_recipients = extract_all_recipients(msg)
                                for recipient in temp_recipients:
                                    if '@' in recipient:
                                        recipient_domain = recipient.split('@')[1]
                                        log_cursor.execute("""
                                            INSERT INTO blocked_attempts
                                            (client_domain_id, sender_address, sender_domain, rule_matched, rule_type, subject, message_id)
                                            SELECT cd.id, %s, %s, %s, %s, %s, %s
                                            FROM client_domains cd
                                            WHERE cd.domain = %s AND cd.active = 1
                                        """, (
                                            sender_email,
                                            sender_domain,
                                            'Protected Domain Impersonation',
                                            'impersonation',
                                            safe_get_header(msg, 'Subject', ''),
                                            safe_get_header(msg, 'Message-ID', ''),
                                            recipient_domain
                                        ))
                                DB_CONN.commit()
                                log_cursor.close()
                            except Exception as log_err:
                                safe_log(f"Warning: Could not log impersonation attempt: {log_err}")

                            # Exit with rejection
                            signal.alarm(0)
                            sys.exit(67)  # EX_NOUSER - Postfix will reject with 5xx

                except Exception as imperson_err:
                    safe_log(f"Protected domain check error (non-fatal): {imperson_err}")
                    # Continue processing on error

            # Get all recipients
            recipients = extract_all_recipients(msg)

            # Extract sender IP from Received headers for IP blocking check
            sender_ip = None
            received_headers = msg.get_all('Received', [])
            if received_headers:
                first_received = str(received_headers[0])
                # Extract the IP from the first Received header
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
                if ip_match:
                    sender_ip = ip_match.group(1)
                    safe_log(f"🔍 Sender IP for blocking check: {sender_ip}")

            # Check blocking rules if we have sender and recipients
            if sender_email and recipients and DB_CONN:
                # Get recipient domains
                recipient_domains = set()
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains.add(recipient.split('@')[1].lower())

                if recipient_domains:
                    try:
                        cursor = DB_CONN.cursor(dictionary=True)
                        # Get ALL active blocking rules (sender, domain, country, ip) for recipient domains + global rules
                        domain_list = "','".join(recipient_domains)
                        cursor.execute(f"""
                            SELECT DISTINCT br.rule_type, br.rule_value, br.rule_pattern, br.description
                            FROM blocking_rules br
                            LEFT JOIN client_domains cd ON br.client_domain_id = cd.id
                            WHERE (cd.domain IN ('{domain_list}') OR br.is_global = 1)
                            AND br.rule_type IN ('sender', 'domain', 'country', 'ip')
                            AND br.active = 1
                            AND (br.whitelist = 0 OR br.whitelist IS NULL)
                        """)

                        blocking_rules = cursor.fetchall()
                        cursor.close()

                        # Check if email matches any blocking rules
                        for rule in blocking_rules:
                            rule_type = rule['rule_type']
                            rule_value = rule['rule_value'].lower()
                            rule_pattern = rule.get('rule_pattern', 'exact')
                            rule_description = rule.get('description', '')

                            # Handle different rule types
                            is_blocked = False

                            if rule_type == 'sender':
                                # SENDER BLOCKING
                                if rule_pattern == 'wildcard':
                                    # For wildcard, check domain part (e.g., *@example.com)
                                    if '@' in rule_value:
                                        blocked_domain = rule_value.split('@')[1]
                                        if sender_email.endswith(f"@{blocked_domain}"):
                                            is_blocked = True
                                    else:
                                        # Wildcard without @ means block domain
                                        if sender_email.endswith(f"@{rule_value}"):
                                            is_blocked = True
                                elif rule_pattern == 'exact':
                                    # Exact match - block specific email address
                                    if sender_email == rule_value:
                                        is_blocked = True
                                else:
                                    # Default: exact match for sender
                                    if sender_email == rule_value:
                                        is_blocked = True

                            elif rule_type == 'domain':
                                # DOMAIN BLOCKING - check sender domain/TLD
                                sender_domain = sender_email.split('@')[1] if '@' in sender_email else ''
                                if rule_pattern == 'wildcard':
                                    # Wildcard for TLD (e.g., cn matches *.cn)
                                    if sender_domain.endswith(f".{rule_value}") or sender_domain == rule_value:
                                        is_blocked = True
                                else:
                                    # Exact domain match
                                    if sender_domain == rule_value or sender_domain.endswith(f".{rule_value}"):
                                        is_blocked = True

                            elif rule_type == 'country':
                                # COUNTRY BLOCKING - check IP-based country from headers
                                # Get country from X-Sender-Country header if available
                                sender_country = safe_get_header(msg, 'X-Sender-Country', '').upper()
                                if sender_country == rule_value.upper():
                                    is_blocked = True

                            elif rule_type == 'ip':
                                # IP BLOCKING - check sender IP against CIDR block
                                if sender_ip and rule_pattern == 'cidr':
                                    try:
                                        # Check if sender IP is in the CIDR block
                                        sender_ip_obj = ipaddress.ip_address(sender_ip)
                                        blocked_network = ipaddress.ip_network(rule_value, strict=False)
                                        if sender_ip_obj in blocked_network:
                                            is_blocked = True
                                            safe_log(f"⚠️ IP {sender_ip} matches blocked CIDR {rule_value}")
                                    except Exception as ip_err:
                                        safe_log(f"IP blocking check error: {ip_err}")

                            if is_blocked:
                                safe_log(f"🚫 BLOCKED EMAIL REJECTED: {sender_email}")
                                safe_log(f"   Rule type: {rule_type}")
                                safe_log(f"   Matched rule: {rule_value} ({rule_pattern})")
                                if rule_description:
                                    safe_log(f"   Reason: {rule_description}")

                                # Log to blocked_attempts table
                                try:
                                    log_cursor = DB_CONN.cursor()
                                    for recipient in recipients:
                                        if '@' in recipient:
                                            recipient_domain = recipient.split('@')[1]
                                            log_cursor.execute("""
                                                INSERT INTO blocked_attempts
                                                (client_domain_id, sender_address, sender_domain,
                                                 rule_matched, rule_type, subject, message_id)
                                                SELECT cd.id, %s, %s, %s, %s, %s, %s
                                                FROM client_domains cd
                                                WHERE cd.domain = %s AND cd.active = 1
                                            """, (
                                                sender_email,
                                                sender_email.split('@')[1] if '@' in sender_email else '',
                                                rule_value,
                                                rule_type,
                                                safe_get_header(msg, 'Subject', ''),
                                                safe_get_header(msg, 'Message-ID', ''),
                                                recipient_domain
                                            ))
                                    DB_CONN.commit()
                                    log_cursor.close()
                                except Exception as log_err:
                                    safe_log(f"Warning: Could not log blocked attempt: {log_err}")

                                # Exit with rejection
                                signal.alarm(0)
                                sys.exit(67)  # EX_NOUSER - Postfix will reject with 5xx

                    except Exception as db_err:
                        safe_log(f"Early blocking check database error: {db_err}")
        except Exception as e:
            safe_log(f"Early blocking check error (non-fatal): {e}")
            # Continue processing on error

        is_journal = False

        # FAST-TRACK FOR TRUSTED SENDERS (with SPF/DKIM enforcement)
        sender_domain = safe_extract_domain(from_header)
        is_trusted_domain = sender_domain in CONFIG.config['domains']['trusted_domains']
        auth_passed = False

        if is_trusted_domain:
            # Perform lightweight authentication check for trusted domains
            safe_log(f"🔒 Trusted domain detected: {sender_domain} - verifying authentication...")

            # Get authentication policy from trust_policy.json
            auth_policy = CONFIG.config['domains'].get('trusted_auth_policy', {
                'require_authentication': True,
                'minimum_auth_methods': 1
            })
            require_auth = auth_policy['require_authentication']
            min_auth_methods = auth_policy['minimum_auth_methods']

            # Quick SPF/DKIM check (use ARC if available)
            auth_status = detect_original_authentication(msg, from_header)
            quick_auth = perform_real_authentication(msg, from_header, monitor, arc_auth=auth_status)

            spf_pass = quick_auth.get('spf') == 'pass'
            dkim_pass = quick_auth.get('dkim') == 'pass'
            dkim_aligned = quick_auth.get('dkim_aligned', False)
            dmarc_pass = quick_auth.get('dmarc') == 'pass'

            # Count how many authentication methods passed
            auth_methods_passed = sum([spf_pass, dkim_pass, dmarc_pass])
            auth_methods = []
            if spf_pass:
                auth_methods.append('SPF')
            if dkim_pass:
                auth_methods.append('DKIM')
            if dmarc_pass:
                auth_methods.append('DMARC')

            # Check if authentication requirements are met
            auth_passed = auth_methods_passed >= min_auth_methods if require_auth else True

            if auth_passed:
                auth_method = "+".join(auth_methods) if auth_methods else "none-required"
                safe_log(f"✅ Authentication passed for trusted domain via {auth_method}")
                safe_log(f"   SPF:{quick_auth.get('spf')}, DKIM:{quick_auth.get('dkim')}, DKIM-aligned:{dkim_aligned}, DMARC:{quick_auth.get('dmarc')}")
                safe_log(f"   Policy: require_auth={require_auth}, min_methods={min_auth_methods}, methods_passed={auth_methods_passed}")
                safe_log(f"⚡ Fast-track approved for authenticated trusted domain: {sender_domain}")

                # Add minimal headers
                safe_add_header(msg, 'X-SpaCy-Processed', datetime.datetime.now().isoformat(), monitor)
                safe_add_header(msg, 'X-SpaCy-Trusted-Domain', 'true', monitor)
                safe_add_header(msg, 'X-SpaCy-Trusted-Auth', f"spf={quick_auth.get('spf')} dkim={quick_auth.get('dkim')} dkim-aligned={dkim_aligned} dmarc={quick_auth.get('dmarc')}", monitor)
                safe_add_header(msg, 'X-SpaCy-Auth-Method', auth_method, monitor)
                safe_add_header(msg, 'X-SpaCy-Spam-Score', '0.0', monitor)
                safe_add_header(msg, 'X-Analysis-Level', 'minimal-trusted-authenticated', monitor)
            else:
                # Authentication failed for trusted domain - BIG RED FLAG
                safe_log(f"⚠️ WARNING: Trusted domain {sender_domain} FAILED authentication policy!")
                safe_log(f"   SPF: {quick_auth.get('spf')}, DKIM: {quick_auth.get('dkim')}, DKIM-aligned: {dkim_aligned}, DMARC: {quick_auth.get('dmarc')}")
                safe_log(f"   Policy: require_auth={require_auth}, min_methods={min_auth_methods}, methods_passed={auth_methods_passed}")
                safe_log(f"   Treating as SPOOFED trusted domain - applying full analysis + penalty")
                is_trusted_domain = False  # Revoke trusted status

        if is_trusted_domain and auth_passed:
            # TRUSTED AND AUTHENTICATED - Fast track
            
            recipients = extract_all_recipients(msg)
            
            # Check if we have any valid recipients
            if not recipients:
                safe_log(f"📧 No recipients from processed domains - not relaying trusted domain email from {from_header}")
                signal.alarm(0)
                sys.exit(0)
            
            # Extract text content for database storage
            text_content = extract_text_content(msg, 10000)
            
            # Run NER analysis for trusted emails (but skip spam/phishing/BEC analysis)
            ner_entities = []
            ner_topics = []
            ner_summary = safe_get_header(msg, 'Subject', '')[:100]  # Default to subject
            
            if MODULE_MANAGER.is_available('entity_extraction'):
                try:
                    safe_log("🔍 Running NER for trusted email...")
                    analyze_email_content = MODULE_MANAGER.get_module('entity_extraction')
                    ner_results = analyze_email_content(
                        text=text_content[:10000],
                        subject=safe_get_header(msg, 'Subject', ''),
                        sender=from_header
                    )
                    if ner_results and isinstance(ner_results, dict):
                        ner_entities = ner_results.get('entities', [])
                        ner_topics = ner_results.get('topics', [])
                        ner_summary = ner_results.get('content_summary', ner_summary)
                        safe_log(f"✅ NER extracted {len(ner_entities)} entities, {len(ner_topics)} topics")
                except Exception as e:
                    safe_log(f"NER error for trusted email: {e}")
            
            # Store trusted emails in database with NER analysis results
            if REDIS_QUEUE and hasattr(REDIS_QUEUE, 'connected') and REDIS_QUEUE.connected:
                try:
                    # Create analysis results with NER data for trusted domains
                    trusted_analysis_results = {
                        'spam_score': 0.0,
                        'headers_to_add': {},
                        'modules_run': ['trusted_fast_track', 'ner'],
                        'entities': ner_entities,  # Include NER entities
                        'classification': {
                            'email_topics': ner_topics,  # Include detected topics
                            'primary_category': 'trusted'
                        },
                        'content_summary': ner_summary,  # Use NER-generated summary
                        'auth_results': quick_auth,  # Include authentication results for database storage
                        'thread_info': {
                            'is_reply': False,
                            'trust_score': 100,  # Max trust for trusted domains
                            'thread_id': None,
                            'references': [],
                            'in_reply_to': None,
                            'trust_level': 'trusted_domain',
                            'thread_verified': True,
                            'internal_participation': False,
                            'thread_initiated_internally': False,
                            'risk_factors': []
                        }
                    }
                    
                    store_email_analysis_via_queue(msg, text_content, trusted_analysis_results, monitor)
                    safe_log("✅ Trusted email queued for database storage")
                except Exception as e:
                    safe_log(f"Failed to queue trusted email: {e}")
            
            if relay_to_mailguard(msg, recipients):
                safe_log(f"✅ Trusted domain email relayed quickly")
                # Update disposition to 'delivered' after successful relay
                message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                update_email_disposition(message_id, 'delivered', 'trusted_domain_delivered')
                safe_log(f"✅ Disposition updated to 'delivered' for trusted domain message {message_id}")
                signal.alarm(0)
                sys.exit(0)
            else:
                safe_log("❌ Relay failed for trusted domain")
                # Update disposition to 'relay_failed' after failed relay
                message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                update_email_disposition(message_id, 'relay_failed', 'trusted_domain_relay_failed')
                signal.alarm(0)
                sys.exit(1)
        
        for received in received_headers:
            received_str = str(received)
            # Check against configured journal addresses
            journal_addresses = CONFIG.config.get('domains', {}).get('journal_addresses', set())
            if any(f'for <{addr}>' in received_str or f'to={addr}' in received_str.lower()
                   for addr in journal_addresses):
                safe_log("📋 JOURNAL EMAIL DETECTED - Archiving via queue")
                is_journal = True
                
                text_content = extract_text_content(msg, 10000)
                
                # RESTORED: Journal emails are stored via Redis queue
                if REDIS_QUEUE and hasattr(REDIS_QUEUE, 'connected') and REDIS_QUEUE.connected:
                    try:
                        journal_analysis_results = {
                            'spam_score': 0.0,
                            'headers_to_add': {'X-Analysis-Level': 'journal'}
                        }
                        store_email_analysis_via_queue(msg, text_content, journal_analysis_results, monitor)
                        safe_log("✅ Journal queued for database storage")
                    except Exception as e:
                        safe_log(f"Journal queue error: {e}")
                
                safe_add_header(msg, 'X-SpaCy-Journal-Archive', 'true', monitor)
                safe_add_header(msg, 'X-SpaCy-Processed', datetime.datetime.now().isoformat(), monitor)
                
                recipients = extract_all_recipients(msg)
                
                # Check if we have any valid recipients
                if not recipients:
                    safe_log(f"📧 No recipients from processed domains - not relaying journal email")
                    signal.alarm(0)
                    sys.exit(0)
                
                if relay_to_mailguard(msg, recipients):
                    safe_log("✅ Journal email relayed")
                    signal.alarm(0)
                    sys.exit(0)
                else:
                    safe_log("❌ Journal relay failed")
                    signal.alarm(0)
                    sys.exit(1)
        
        if not validate_internal_domain(msg, from_header):
            safe_log("🚫 BLOCKED: Domain spoofing detected")
            signal.alarm(0)
            sys.exit(69)  # EX_UNAVAILABLE - permanent rejection

        if check_spacy_repetition(msg, from_header):
            safe_log("🚫 BLOCKED: Sender has history of SpaCy-marked emails")
            signal.alarm(0)
            sys.exit(69)  # EX_UNAVAILABLE - permanent rejection
        
        recipients = extract_all_recipients(msg)

        # Check if we have any valid recipients for our domains
        if not recipients:
            # Check if this is outbound mail from a trusted internal source (e.g., Zimbra)
            if is_outbound_from_trusted_source(msg):
                safe_log(f"📧 Outbound email from trusted source - relaying to external recipients")
                # Get all recipients (including external ones)
                all_recipients = []
                for header in ['To', 'Cc', 'Bcc']:
                    header_value = safe_get_header(msg, header, '')
                    if '@' in header_value:
                        found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', header_value)
                        all_recipients.extend(found_emails)

                # Store outbound email in database for visibility/tracking
                try:
                    # Extract sender IP from first Received header
                    outbound_sender_ip = None
                    received_headers = msg.get_all('Received', [])
                    if received_headers:
                        first_received = str(received_headers[0])
                        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', first_received)
                        if ip_match:
                            outbound_sender_ip = ip_match.group(1)

                    if not outbound_sender_ip:
                        outbound_sender_ip = '0.0.0.0'  # Default if detection fails

                    # Store minimal record
                    cursor = DB_CONN.cursor()
                    cursor.execute("""
                        INSERT INTO email_analysis (
                            timestamp, message_id, sender, recipients, subject,
                            spam_score, disposition, mail_direction, original_sender_ip,
                            raw_email
                        ) VALUES (
                            NOW(), %s, %s, %s, %s,
                            0.0, 'delivered', 'outbound', %s,
                            %s
                        )
                    """, (
                        safe_get_header(msg, 'Message-ID', ''),
                        safe_get_header(msg, 'From', ''),
                        ', '.join(all_recipients),
                        safe_get_header(msg, 'Subject', ''),
                        outbound_sender_ip,
                        msg.as_string()
                    ))
                    DB_CONN.commit()
                    cursor.close()
                    safe_log(f"✅ Outbound email stored to database (IP: {outbound_sender_ip})")
                except Exception as db_err:
                    safe_log(f"⚠️  Failed to store outbound email to database: {db_err}")

                # Relay directly to the internet using direct SMTP (bypass local content_filter)
                if all_recipients:
                    try:
                        import dns.resolver
                        # For each recipient domain, look up MX and deliver directly
                        recipient_domains = {}
                        for recipient in all_recipients:
                            if '@' in recipient:
                                domain = recipient.split('@')[1]
                                if domain not in recipient_domains:
                                    recipient_domains[domain] = []
                                recipient_domains[domain].append(recipient)

                        relay_success = True
                        for domain, domain_recipients in recipient_domains.items():
                            try:
                                # Look up MX records for the domain
                                mx_records = dns.resolver.resolve(domain, 'MX')
                                mx_host = str(mx_records[0].exchange).rstrip('.')

                                # Relay directly to the MX host using low-level commands to capture queue ID
                                with smtplib.SMTP(mx_host, 25, timeout=30) as smtp:
                                    # Try to use STARTTLS for encryption
                                    try:
                                        smtp.starttls()
                                        smtp.ehlo()  # Must send EHLO again after STARTTLS
                                        safe_log(f"✅ TLS enabled for MX relay to {mx_host}")
                                    except Exception as tls_err:
                                        safe_log(f"⚠️  TLS not available for {mx_host} - continuing: {tls_err}")

                                    smtp.ehlo_or_helo_if_needed()
                                    smtp.mail(envelope_sender)
                                    for recipient in domain_recipients:
                                        smtp.rcpt(recipient)

                                    # Send DATA and capture response with queue ID
                                    code, response = smtp.data(msg.as_bytes())

                                    # Extract queue ID from response
                                    upstream_queue_id = "unknown"
                                    try:
                                        response_str = response.decode() if isinstance(response, bytes) else str(response)
                                        safe_log(f"DEBUG: SMTP response code={code}, response='{response_str}'")

                                        # Try multiple extraction patterns
                                        if "queued as" in response_str.lower():
                                            # Postfix/Zimbra format: "250 2.0.0 Ok: queued as ABC123"
                                            parts = response_str.split("queued as")
                                            if len(parts) > 1:
                                                upstream_queue_id = parts[1].strip().split()[0].rstrip(')')
                                        elif re.search(r'\b[A-Z0-9]{10,}\b', response_str):
                                            # Traditional queue ID pattern (10+ alphanumeric chars)
                                            queue_match = re.search(r'\b[A-Z0-9]{10,}\b', response_str)
                                            if queue_match:
                                                upstream_queue_id = queue_match.group(0)
                                        else:
                                            # No traditional queue ID - format as "Domain: response"
                                            upstream_queue_id = f"{domain}: {response_str[:50]}"
                                    except Exception as e:
                                        safe_log(f"⚠️  Could not extract queue ID from response: {e}")

                                    # Update the database record with upstream queue ID
                                    try:
                                        message_id = safe_get_header(msg, 'Message-ID', '')
                                        if message_id:
                                            cursor = DB_CONN.cursor()
                                            cursor.execute("""
                                                UPDATE email_analysis
                                                SET upstream_queue_id = %s
                                                WHERE message_id = %s
                                            """, (upstream_queue_id, message_id))
                                            DB_CONN.commit()
                                            cursor.close()
                                    except Exception as db_err:
                                        safe_log(f"⚠️  Could not update upstream queue ID: {db_err}")

                                safe_log(f"✅ Outbound direct relay to {domain} ({mx_host}) for {len(domain_recipients)} recipients")
                                safe_log(f"📬 Upstream Queue ID: {upstream_queue_id}")
                            except Exception as e:
                                safe_log(f"❌ Direct relay to {domain} failed: {e}")
                                relay_success = False

                        if relay_success:
                            signal.alarm(0)
                            sys.exit(0)
                        else:
                            signal.alarm(0)
                            sys.exit(75)  # EX_TEMPFAIL
                    except Exception as e:
                        safe_log(f"❌ Outbound relay failed: {e}")
                        signal.alarm(0)
                        sys.exit(75)  # EX_TEMPFAIL

            safe_log(f"📧 No recipients from processed domains found - rejecting email from {from_header}")
            safe_log("📧 This email was intended for external recipients only - not processing")
            signal.alarm(0)
            sys.exit(0)  # Exit successfully but don't process/relay
        
        # ============================================================================
        # DOMAIN AND COUNTRY BLOCKING CHECK
        # ============================================================================
        try:
            # Extract sender IP from Received headers
            sender_ip = None
            received_headers = msg.get_all('Received', [])
            for received in received_headers:
                received_str = str(received)
                # Look for IPv4 addresses
                ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received_str)
                if not ip_match:
                    # Try without brackets
                    ip_match = re.search(r'from\s+\S+\s+\(.*?(\d+\.\d+\.\d+\.\d+)', received_str)
                if ip_match:
                    potential_ip = ip_match.group(1)
                    # Skip internal IPs
                    if not potential_ip.startswith(('192.168.', '10.', '172.', '127.')):
                        sender_ip = potential_ip
                        break
            
            if sender_ip:
                safe_log(f"🔍 Sender IP detected: {sender_ip}")

            # MTA-LEVEL BLOCKING MODULE DISABLED
            # Note: MTA-level blocking via email_blocking.py module is disabled in favor of
            # spam-score-based quarantine approach. This provides better visibility in the GUI
            # and allows Domain Admins to release legitimate emails from blocked countries.
            #
            # Country blocking is now handled via high spam score penalties (50 points)
            # See lines 2919-2956 for high-risk country penalty implementation.
            #
            # If you need to re-enable MTA-level blocking in the future:
            # 1. Fix the SQLAlchemy import errors in modules/email_blocking.py
            # 2. Uncomment the code below
            # 3. Ensure blocking_rules table has proper rules configured

            # COMMENTED OUT - MTA-level blocking code
            # from modules.email_blocking import check_email_blocking
            # blocked_recipients = []
            # allowed_recipients = []
            # blocking_sender = envelope_sender if envelope_sender else from_header
            # safe_log(f"🔍 Checking blocking for {len(recipients)} recipients using sender: {blocking_sender}")
            # for recipient in recipients:
            #     safe_log(f"🔍 Checking blocking for recipient: {recipient}, sender: {blocking_sender}, IP: {sender_ip}")
            #     should_block, reason = check_email_blocking(recipient, blocking_sender, sender_ip)
            #     safe_log(f"🔍 Blocking result for {recipient}: should_block={should_block}, reason={reason}")
            #     if should_block:
            #         blocked_recipients.append(recipient)
            #         safe_log(f"🚫 BLOCKED for {recipient}: {reason}")
            #         safe_add_header(msg, 'X-SpaCy-Blocked', f"{recipient}: {reason}", monitor)
            #     else:
            #         allowed_recipients.append(recipient)
            # if blocked_recipients and not allowed_recipients:
            #     safe_log(f"🚫 ALL RECIPIENTS BLOCKED - Rejecting email from {from_header}")
            #     safe_add_header(msg, 'X-SpaCy-Status', 'BLOCKED', monitor)
            #     signal.alarm(0)
            #     sys.exit(99)
            # if blocked_recipients:
            #     recipients = allowed_recipients
            #     safe_log(f"✅ Allowing delivery to: {allowed_recipients}")
            #     safe_log(f"🚫 Blocked delivery to: {blocked_recipients}")

        except ImportError as e:
            safe_log(f"⚠️  Blocking module not available: {e}")
            import traceback
            safe_log(f"⚠️  Import error traceback: {traceback.format_exc()}")
        except Exception as e:
            safe_log(f"⚠️  Error checking blocking rules: {e}")
            import traceback
            safe_log(f"⚠️  Error traceback: {traceback.format_exc()}")
            # Continue processing on error - fail open
        
        # Detect original/upstream authentication
        auth_status = detect_original_authentication(msg, from_header)

        # Add ARC/Upstream authentication status headers
        if auth_status['source'] == 'none':
            safe_add_header(msg, 'X-ARC-Auth-Status', 'none (direct-delivery)', monitor)
            # No upstream/ARC authentication results available
            safe_add_header(msg, 'X-ARC-Auth-SPF', 'none', monitor)
            safe_add_header(msg, 'X-ARC-Auth-DKIM', 'none', monitor)
            safe_add_header(msg, 'X-ARC-Auth-DMARC', 'none', monitor)
        elif auth_status['source'] == 'upstream':
            safe_add_header(msg, 'X-ARC-Auth-Status', 'upstream-server', monitor)
            safe_add_header(msg, 'X-ARC-Auth-Results', f"spf={auth_status['spf']} dkim={auth_status['dkim']} dmarc={auth_status['dmarc']}", monitor)
            # Upstream authentication results received
            safe_add_header(msg, 'X-ARC-Auth-SPF', auth_status['spf'], monitor)
            safe_add_header(msg, 'X-ARC-Auth-DKIM', auth_status['dkim'], monitor)
            safe_add_header(msg, 'X-ARC-Auth-DMARC', auth_status['dmarc'], monitor)
        elif auth_status['source'].startswith('arc-'):
            provider = auth_status['source'].replace('arc-', '')
            safe_add_header(msg, 'X-ARC-Auth-Status', f'arc-trusted ({provider})', monitor)
            safe_add_header(msg, 'X-ARC-Auth-Results', f"spf={auth_status['spf']} dkim={auth_status['dkim']} dmarc={auth_status['dmarc']}", monitor)
            # ARC authentication results from trusted provider
            safe_add_header(msg, 'X-ARC-Auth-SPF', auth_status['spf'], monitor)
            safe_add_header(msg, 'X-ARC-Auth-DKIM', auth_status['dkim'], monitor)
            safe_add_header(msg, 'X-ARC-Auth-DMARC', auth_status['dmarc'], monitor)

        # Extract recipient domains BEFORE authentication for whitelist checking
        # PRIORITY 1: Use Postfix envelope recipients (most reliable - actual delivery targets)
        # PRIORITY 2: Fall back to header extraction if no envelope recipients available
        recipient_domains = []

        # First, try to use command-line recipients from Postfix (envelope recipients)
        # These are the authoritative source - who Postfix is actually delivering to
        if cmdline_recipients:
            try:
                for recipient in cmdline_recipients:
                    if '@' in recipient:
                        domain = recipient.split('@')[1].lower()
                        if domain not in recipient_domains:
                            recipient_domains.append(domain)
                if recipient_domains:
                    safe_log(f"📬 Recipient domains from Postfix envelope: {recipient_domains}")
            except Exception as e:
                safe_log(f"⚠️ Error extracting domains from envelope recipients: {e}")

        # Fall back to header extraction if no envelope recipients
        if not recipient_domains:
            try:
                for to_field in ['To', 'Cc']:
                    to_header = safe_get_header(msg, to_field, '')
                    if to_header:
                        # Extract email addresses
                        emails = re.findall(r'[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', to_header)
                        recipient_domains.extend(emails)
                # Remove duplicates
                recipient_domains = list(set(recipient_domains))
                if recipient_domains:
                    safe_log(f"📬 Recipient domains from email headers (fallback): {recipient_domains}")
            except Exception as e:
                safe_log(f"⚠️ Error extracting recipient domains from headers: {e}")

        # If still no recipient domains, log a warning (global whitelists will still be checked)
        if not recipient_domains:
            safe_log(f"⚠️ No recipient domains found - will only check global whitelists")

        # Perform real authentication if enabled (pass ARC-trusted auth_status)
        # If we already checked auth for trusted domain, reuse those results
        if is_trusted_domain and 'quick_auth' in locals():
            auth_results = quick_auth
            safe_log(f"♻️ Reusing authentication results from trusted domain check")
        else:
            auth_results = perform_real_authentication(msg, from_header, monitor, arc_auth=auth_status, recipient_domains=recipient_domains)
        safe_log(f"📧 Auth completed, generating headers...")
        
        # Generate Authentication-Results header
        # Use configured hostname or fallback to system hostname
        import socket
        mail_hostname = socket.getfqdn()
        auth_header = f"{mail_hostname}; spf={auth_results['spf']}; dkim={auth_results['dkim']}; dmarc={auth_results['dmarc']}"
        if auth_results['dmarc_policy'] != 'none':
            auth_header += f" (p={auth_results['dmarc_policy']})"
        safe_add_header(msg, 'X-SpaCy-Auth-Results', auth_header, monitor)
        safe_add_header(msg, 'X-SpaCy-Auth-Score', str(auth_results['auth_score']), monitor)
        
        # Add reputation headers if adjustment was made
        if 'reputation_adjustment' in auth_results and auth_results['reputation_adjustment'] > 0:
            safe_add_header(msg, 'X-SpaCy-Reputation-Adjustment', str(auth_results['reputation_adjustment']), monitor)
            safe_add_header(msg, 'X-SpaCy-Reputation-Notes', '; '.join(auth_results.get('reputation_notes', [])[:2]), monitor)
        
        safe_log(f"📧 Headers added, extracting text content...")
        
        # Extract text content for analysis
        text_content = extract_text_content(msg)
        safe_log(f"📧 Text extracted: {len(text_content)} chars")
        
        # CRITICAL: Detect authentication abuse
        auth_abuse = detect_authentication_abuse(msg, from_header, text_content)
        if auth_abuse['known_scammer']:
            safe_add_header(msg, 'X-Known-Scammer', 'true', monitor)
        safe_add_header(msg, 'X-Auth-Abuse-Score', str(auth_abuse['abuse_score']), monitor)
        if auth_abuse['abuse_reasons']:
            safe_add_header(msg, 'X-Auth-Abuse-Reasons', '; '.join(auth_abuse['abuse_reasons'][:3]), monitor)
        
        # RESTORED: Check thread continuity
        thread_info = check_thread_continuity(msg, text_content)
        safe_add_header(msg, 'X-Thread-Reply', str(thread_info['is_reply']), monitor)
        safe_add_header(msg, 'X-Thread-Trust', str(thread_info['trust_score']), monitor)
        
        # NEW: Add fake reply detection headers
        if thread_info.get('is_fake_reply', False):
            safe_add_header(msg, 'X-Fake-Reply-Detected', 'true', monitor)
            safe_add_header(msg, 'X-Fake-Reply-Confidence', str(thread_info.get('fake_reply_confidence', 0)), monitor)
            safe_log(f"🚨 FAKE REPLY DETECTED with confidence {thread_info.get('fake_reply_confidence', 0):.2f}")
        
        # Determine analysis level based on size
        email_size = len(email_data)
        if email_size > CONFIG.config['size_limits']['max_email_size']:
            safe_log("⚠️ Email exceeds maximum size")
            safe_add_header(msg, 'X-SpaCy-Oversized', 'true', monitor)
            safe_add_header(msg, 'X-Analysis-Level', 'none', monitor)
            recipients = extract_all_recipients(msg)
            if recipients:
                relay_to_mailguard(msg, recipients)
            else:
                safe_log("📧 No recipients from processed domains - not relaying oversized email")
            signal.alarm(0)
            sys.exit(0)
        
        # Run spam analysis with timeout handling
        # Check if this was a trusted domain that failed authentication
        sender_domain_for_check = safe_extract_domain(from_header)
        is_spoofed_trusted = (sender_domain_for_check in CONFIG.config['domains']['trusted_domains'] and
                              not (is_trusted_domain and auth_passed))

        analysis_results = analyze_email_with_modules(msg, text_content, from_header, monitor, auth_results, is_spoofed_trusted=is_spoofed_trusted)
        
        # Add authentication abuse score to spam score
        auth_abuse_score = auth_abuse['abuse_score']
        analysis_results['spam_score'] += auth_abuse_score
        if auth_abuse_score != 0:
            analysis_results['headers_to_add']['X-Spam-Score-Auth-Abuse'] = str(round(auth_abuse_score, 2))

        # Add authentication score penalties to spam score
        # Negative auth scores (failed SPF/DKIM/DMARC) should INCREASE spam score
        # Positive auth scores (passed auth) should DECREASE spam score
        auth_score_contribution = -auth_results['auth_score']  # Invert: negative auth = positive spam

        # CRITICAL FIX: Reduce auth bonus for free email providers with business/funding content
        # Scammers use Gmail/Yahoo with valid auth to bypass filters
        if auth_score_contribution < 0:  # Only if auth is giving a bonus (reducing spam score)
            sender_lower = from_header.lower()
            free_email_patterns = [
                r'@(?:gmail|googlemail)\.com',
                r'@(?:yahoo|ymail|rocketmail)\.(?:com|co\.[a-z]+)',
                r'@(?:hotmail|outlook|live|msn)\.(?:com|co\.[a-z]+)',
                r'@(?:aol|aim|mail\.com|email\.com|icloud|me)\.com'
            ]

            is_free_email = any(re.search(pattern, sender_lower) for pattern in free_email_patterns)
            has_funding_content = 'X-Spam-Score-Funding' in analysis_results.get('headers_to_add', {})

            if is_free_email and has_funding_content:
                # Reduce the authentication bonus significantly for free email + funding spam
                # This prevents scammers from using Gmail auth to bypass funding spam detection
                original_contribution = auth_score_contribution
                auth_score_contribution = auth_score_contribution * 0.25  # Reduce bonus to 25%
                safe_log(f"⚠️ Free email + funding content detected - reducing auth bonus from {original_contribution:.1f} to {auth_score_contribution:.1f}")
                analysis_results['headers_to_add']['X-Auth-Bonus-Reduced'] = 'free_email_funding_spam'

        # CRITICAL FIX 2025-12-03: Remove auth bonus for random/disposable domains
        # Spammers now set up proper SPF/DKIM/DMARC on throwaway domains to bypass filters
        # If domain was flagged as high-risk random domain, don't reward it for good auth
        if auth_score_contribution < 0:  # Only if auth is giving a bonus
            domain_entropy_penalty = analysis_results.get('domain_entropy_penalty', 0)
            if domain_entropy_penalty >= 5.0:
                # Domain was flagged as suspicious random domain - eliminate auth bonus entirely
                original_contribution = auth_score_contribution
                auth_score_contribution = 0.0
                safe_log(f"⚠️ Random domain detected (entropy penalty: {domain_entropy_penalty}) - eliminating auth bonus (was {original_contribution:.1f})")
                analysis_results['headers_to_add']['X-Auth-Bonus-Eliminated'] = f'random_domain_entropy:{domain_entropy_penalty}'
            elif domain_entropy_penalty >= 3.0:
                # Moderately suspicious domain - reduce auth bonus to 25%
                original_contribution = auth_score_contribution
                auth_score_contribution = auth_score_contribution * 0.25
                safe_log(f"⚠️ Suspicious domain (entropy penalty: {domain_entropy_penalty}) - reducing auth bonus from {original_contribution:.1f} to {auth_score_contribution:.1f}")
                analysis_results['headers_to_add']['X-Auth-Bonus-Reduced'] = f'suspicious_domain_entropy:{domain_entropy_penalty}'

        if auth_score_contribution != 0:
            analysis_results['spam_score'] += auth_score_contribution
            analysis_results['headers_to_add']['X-Spam-Score-Auth'] = str(round(auth_score_contribution, 2))
            safe_log(f"🔐 Auth score contribution: {auth_score_contribution:+.1f} (SPF:{auth_results['spf']}, DKIM:{auth_results['dkim']}, DMARC:{auth_results['dmarc']})")

        # Store authentication results for quarantine database
        analysis_results['auth_results'] = auth_results

        # Add thread info to analysis results for thread-aware blocking
        analysis_results['thread_info'] = thread_info

        # NEW: Apply fake reply spam boost (skip if sender has bypass_bec_checks)
        bypass_aggressive_checks = analysis_results.get('bypass_aggressive_checks', False)
        safe_log(f"🔍 DEBUG: bypass_aggressive_checks={bypass_aggressive_checks}")
        if not bypass_aggressive_checks:
            try:
                safe_log(f"🔍 DEBUG: Entering fake_reply detection block")
                from modules.thread_awareness_enhanced import EnhancedThreadAnalyzer
                analyzer = EnhancedThreadAnalyzer()
                fake_reply_boost = analyzer.get_spam_score_boost(thread_info)
                safe_log(f"🔍 DEBUG: fake_reply_boost={fake_reply_boost}")

                # NEW: Intelligent conversation analysis using SpaCy + sentence-transformers
                conversation_multiplier = 1.0  # Default: no reduction
                conversation_note = ""

                if fake_reply_boost > 0:  # Only analyze if fake_reply was detected
                    try:
                        safe_log(f"🔍 DEBUG: About to run conversation analyzer (fake_reply_boost={fake_reply_boost})")
                        from modules.conversation_analyzer import analyze_conversation_legitimacy
                        conv_analysis = analyze_conversation_legitimacy(text_content, subject)
                        legitimacy_score = conv_analysis.get('legitimacy_score', 0)
                        safe_log(f"🔍 DEBUG: Conversation legitimacy score: {legitimacy_score:.1f}")

                        # Apply reduction based on legitimacy score
                        if legitimacy_score >= 80:
                            conversation_multiplier = 0.05  # 95% reduction
                            conversation_note = f" | Conversation analysis: 95% reduction (score: {legitimacy_score:.1f})"
                        elif legitimacy_score >= 60:
                            conversation_multiplier = 0.10  # 90% reduction
                            conversation_note = f" | Conversation analysis: 90% reduction (score: {legitimacy_score:.1f})"
                        elif legitimacy_score >= 40:
                            conversation_multiplier = 0.50  # 50% reduction
                            conversation_note = f" | Conversation analysis: 50% reduction (score: {legitimacy_score:.1f})"
                        elif legitimacy_score >= 20:
                            conversation_multiplier = 0.75  # 25% reduction
                            conversation_note = f" | Conversation analysis: 25% reduction (score: {legitimacy_score:.1f})"
                        else:
                            conversation_multiplier = 1.0  # No reduction
                            conversation_note = f" | Conversation analysis: no reduction (score: {legitimacy_score:.1f})"

                        # Add conversation analysis details to headers
                        analysis_results['headers_to_add']['X-Conversation-Legitimacy-Score'] = str(round(legitimacy_score, 2))
                        if conv_analysis.get('has_quoted_text'):
                            analysis_results['headers_to_add']['X-Conversation-Has-Quoted-Text'] = 'true'

                    except Exception as e:
                        safe_log(f"⚠️  Conversation analysis failed: {e}")
                        conversation_multiplier = 1.0
                        conversation_note = ""

                # Check if email passed all 3 authentication methods
                spf_pass = auth_results.get('spf', '').lower() == 'pass'
                dkim_pass = auth_results.get('dkim', '').lower() == 'pass'
                dmarc_pass = auth_results.get('dmarc', '').lower() == 'pass'
                full_auth = spf_pass and dkim_pass and dmarc_pass

                # Apply weight multiplier based on authentication
                if full_auth:
                    # FULL AUTH (SPF+DKIM+DMARC): 90% reduction - legitimate orgs use "Re:" for automation
                    weight_multiplier = 0.10
                    reduction_note = "90% reduction - full auth"
                else:
                    # PARTIAL/NO AUTH: 25% reduction (original tuning)
                    weight_multiplier = 0.75
                    reduction_note = "25% reduction - partial/no auth"

                # Combine both multipliers (conversation analysis takes precedence if more lenient)
                final_multiplier = min(weight_multiplier, conversation_multiplier)
                if conversation_multiplier < weight_multiplier:
                    reduction_note += conversation_note

                fake_reply_contribution = min(fake_reply_boost * final_multiplier, 12.0)
                if fake_reply_contribution > 0:
                    analysis_results['spam_score'] += fake_reply_contribution
                    analysis_results['spam_modules_detail']['fake_reply'] = fake_reply_contribution
                    analysis_results['headers_to_add']['X-Spam-Score-Fake-Reply'] = str(round(fake_reply_contribution, 2))
                    safe_add_header(msg, 'X-Fake-Reply-Spam-Boost', str(fake_reply_contribution), monitor)
                    safe_log(f"📈 Added +{fake_reply_contribution:.1f} spam points for fake reply ({reduction_note})")
            except Exception as e:
                safe_log(f"Failed to calculate fake reply boost: {e}")
        else:
            safe_log(f"⏭️ Skipping fake reply detection - sender has bypass_bec_checks")
        
        # NEW: Conversation Pattern Learning - Reduce spam score for legitimate patterns
        try:
            from modules.conversation_learner_mysql import analyze_with_learning
            learning_results = analyze_with_learning(msg, text_content, analysis_results['spam_score'])
            
            if learning_results and 'spam_adjustment' in learning_results:
                adjustment = learning_results['spam_adjustment']
                if adjustment != 0:
                    analysis_results['spam_score'] += adjustment  # Can be negative (reduce) or positive
                    analysis_results['headers_to_add']['X-Spam-Score-Learning'] = str(round(adjustment, 2))
                    safe_add_header(msg, 'X-Conversation-Pattern-Adjustment', str(adjustment), monitor)
                    safe_add_header(msg, 'X-Conversation-Legitimacy', str(learning_results['legitimacy_scores'].get('overall_score', 0)), monitor)
                    safe_add_header(msg, 'X-Learning-Confidence', str(learning_results.get('confidence', 0)), monitor)
                    
                    if adjustment < 0:
                        safe_log(f"✅ Legitimate pattern detected - reduced spam score by {abs(adjustment):.1f} points")
                    else:
                        safe_log(f"⚠️ Unusual pattern - increased spam score by {adjustment:.1f} points")
                    
                    if learning_results.get('learned_from_email', False):
                        safe_log(f"📚 Learned from this legitimate conversation")
        except Exception as e:
            safe_log(f"Conversation learning error: {e}")

        # SPAM PATTERN LEARNING - Apply learned weights from user feedback
        try:
            if DB_CONN and recipients:
                from modules.spam_learner import spam_learner

                # Get recipient domains
                recipient_domains = set()
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains.add(recipient.split('@')[1].lower())

                if recipient_domains:
                    # For each recipient domain, get learned weights
                    for recipient_domain in recipient_domains:
                        # Get client_domain_id
                        cursor = DB_CONN.cursor(dictionary=True)
                        cursor.execute("""
                            SELECT id FROM client_domains WHERE domain = %s AND active = 1
                        """, (recipient_domain,))
                        domain_result = cursor.fetchone()
                        cursor.close()

                        if domain_result:
                            client_domain_id = domain_result['id']

                            # Extract patterns from this email
                            email_data = {
                                'subject': subject,
                                'body': text_content,
                                'sender': from_header
                            }
                            patterns = spam_learner._extract_patterns(email_data)

                            # Get learned weight adjustment
                            weight_adjustment = spam_learner.get_learned_weights(client_domain_id, patterns)

                            if weight_adjustment != 0:
                                analysis_results['spam_score'] += weight_adjustment
                                safe_add_header(msg, 'X-Learned-Pattern-Weight', str(round(weight_adjustment, 2)), monitor)

                                if weight_adjustment > 0:
                                    safe_log(f"📚 Learned spam patterns detected - increased spam score by {weight_adjustment:.1f} points")
                                else:
                                    safe_log(f"📚 Learned safe patterns detected - reduced spam score by {abs(weight_adjustment):.1f} points")

                                # Only process first domain to avoid double-counting
                                break
        except Exception as e:
            safe_log(f"Spam pattern learning error: {e}")

        # Thread Trust Reduction - Legitimate reply threads get spam score reduction
        try:
            if thread_info.get('is_reply', False) and thread_info.get('trust_score', 0) > 0:
                trust_score = thread_info.get('trust_score', 0)
                # Scale: trust_score 1-5 → reduction 3-10 points
                # trust_score 1 = -3 points, trust_score 5 = -10 points
                thread_reduction = min(3 + (trust_score * 1.4), 10.0)
                analysis_results['spam_score'] -= thread_reduction
                safe_log(f"🧵 Thread trust reduction: -{thread_reduction:.1f} points (trust score: {trust_score})")
                safe_add_header(msg, 'X-Thread-Trust-Reduction', str(round(thread_reduction, 2)), monitor)
        except Exception as e:
            safe_log(f"Thread trust reduction error: {e}")

        # PER-DOMAIN COUNTRY BLOCKING - Check blocking_rules table for each recipient domain
        # This ensures only Domain Admin or Superadmin can release these emails (client limit is 25 points)
        try:
            # Extract sender IP from Received headers
            sender_ip = None
            received_headers = msg.get_all('Received', [])

            # Look for the first external IP in Received headers
            for received in received_headers:
                # Match IP addresses in Received headers
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
                if ip_match:
                    sender_ip = ip_match.group(1)
                    # Skip private IPs (10.x, 172.16-31.x, 192.168.x)
                    if not (sender_ip.startswith('10.') or
                           sender_ip.startswith('192.168.') or
                           re.match(r'^172\.(1[6-9]|2[0-9]|3[01])\.', sender_ip)):
                        break

            if sender_ip and recipients:
                # Get recipient domains to check blocking rules
                recipient_domains = set()
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains.add(recipient.split('@')[1].lower())

                # Query blocking_rules for country blocks for these domains
                if recipient_domains and DB_CONN:
                    try:
                        cursor = DB_CONN.cursor(dictionary=True)
                        # Get all country blocking rules for recipient domains
                        domain_list = "','".join(recipient_domains)
                        cursor.execute(f"""
                            SELECT DISTINCT br.rule_value
                            FROM blocking_rules br
                            JOIN client_domains cd ON br.client_domain_id = cd.id
                            WHERE cd.domain IN ('{domain_list}')
                            AND br.rule_type = 'country'
                            AND br.active = 1
                        """)

                        blocked_countries = [row['rule_value'].upper() for row in cursor.fetchall()]
                        cursor.close()

                        if blocked_countries and GEOIP_READER:
                            # Use GeoIP2 to check country (fast, local lookup)
                            try:
                                geoip_response = GEOIP_READER.country(sender_ip)
                                sender_country = geoip_response.country.iso_code

                                if sender_country and sender_country.upper() in blocked_countries:
                                    country_penalty = 50.0  # High penalty - ensures only admins can release
                                    analysis_results['spam_score'] += country_penalty
                                    analysis_results['high_risk_country'] = sender_country
                                    analysis_results['high_risk_country_penalty'] = country_penalty
                                    analysis_results['force_delete_country_block'] = True  # AUTO-DELETE blocked countries
                                    analysis_results['headers_to_add']['X-Spam-Score-Country'] = str(round(country_penalty, 2))
                                    safe_add_header(msg, 'X-High-Risk-Country', sender_country, monitor)
                                    safe_add_header(msg, 'X-Country-Spam-Penalty', str(country_penalty), monitor)
                                    safe_add_header(msg, 'X-Sender-IP', sender_ip, monitor)
                                    safe_log(f"⚠️ HIGH-RISK COUNTRY {sender_country} detected from {sender_ip} via GeoIP2 - Will auto-delete (intelligence preserved)")
                            except geoip2.errors.AddressNotFoundError:
                                safe_log(f"GeoIP: IP {sender_ip} not found in database")
                            except Exception as geoip_err:
                                safe_log(f"GeoIP lookup error for {sender_ip}: {geoip_err}")
                    except Exception as db_err:
                        safe_log(f"Database query error for country blocking: {db_err}")
        except Exception as e:
            safe_log(f"Country penalty check error: {e}")

        # PER-DOMAIN TLD BLOCKING - Block emails from blocked TLDs based on blocking_rules
        # This catches spammers using cloud infrastructure but with suspicious domains
        try:
            # Extract sender email domain
            sender_email = from_header.lower()
            if '<' in sender_email and '>' in sender_email:
                sender_email = sender_email.split('<')[1].split('>')[0]

            # Get sender TLD (e.g., .cn, .ru)
            sender_tld = None
            if '@' in sender_email:
                sender_domain = sender_email.split('@')[1]
                if '.' in sender_domain:
                    sender_tld = '.' + sender_domain.split('.')[-1]

            # Query blocking_rules for domain/TLD blocks for recipient domains
            if sender_tld and recipients and DB_CONN:
                # Get recipient domains
                recipient_domains = set()
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains.add(recipient.split('@')[1].lower())

                if recipient_domains:
                    try:
                        cursor = DB_CONN.cursor(dictionary=True)
                        # Get all domain blocking rules for recipient domains (ONLY blocked, not whitelisted)
                        domain_list = "','".join(recipient_domains)
                        cursor.execute(f"""
                            SELECT DISTINCT br.rule_value, br.rule_pattern
                            FROM blocking_rules br
                            JOIN client_domains cd ON br.client_domain_id = cd.id
                            WHERE cd.domain IN ('{domain_list}')
                            AND br.rule_type = 'domain'
                            AND br.active = 1
                            AND (br.whitelist = 0 OR br.whitelist IS NULL)
                        """)

                        blocked_domains = cursor.fetchall()
                        cursor.close()

                        # Check if sender domain matches any blocked domains
                        for rule in blocked_domains:
                            rule_value = rule['rule_value'].lower()
                            rule_pattern = rule['rule_pattern']

                            # Handle different patterns
                            is_blocked = False
                            if rule_pattern == 'wildcard':
                                # For wildcard, check if sender_tld matches (e.g., .cn)
                                if sender_tld == f".{rule_value}":
                                    is_blocked = True
                            elif rule_pattern == 'exact':
                                # For exact, check full domain match
                                if sender_email.endswith(f"@{rule_value}"):
                                    is_blocked = True
                            else:
                                # Default: check if TLD or domain matches
                                if sender_tld == f".{rule_value}" or sender_email.endswith(f".{rule_value}"):
                                    is_blocked = True

                            if is_blocked:
                                # Only apply penalty if IP country check didn't already catch it
                                if not analysis_results.get('high_risk_country'):
                                    domain_penalty = 50.0
                                    analysis_results['spam_score'] += domain_penalty
                                    analysis_results['high_risk_domain'] = rule_value
                                    analysis_results['high_risk_domain_penalty'] = domain_penalty
                                    analysis_results['headers_to_add']['X-Spam-Score-Domain'] = str(round(domain_penalty, 2))
                                    safe_add_header(msg, 'X-High-Risk-Domain', rule_value, monitor)
                                    safe_add_header(msg, 'X-Domain-Spam-Penalty', str(domain_penalty), monitor)
                                    safe_log(f"⚠️ HIGH-RISK DOMAIN {rule_value} detected from {sender_email} - Added +{domain_penalty} spam points")
                                break
                    except Exception as db_err:
                        safe_log(f"Database query error for domain blocking: {db_err}")
        except Exception as e:
            safe_log(f"Domain penalty check error: {e}")

        # PER-DOMAIN WHITELIST BONUS - Apply spam score reduction for whitelisted domains
        try:
            sender_email_for_wl = from_header.lower()
            if '<' in sender_email_for_wl and '>' in sender_email_for_wl:
                sender_email_for_wl = sender_email_for_wl.split('<')[1].split('>')[0]
            sender_email_for_wl = sender_email_for_wl.strip()

            if '@' in sender_email_for_wl and recipients and DB_CONN:
                sender_domain_wl = sender_email_for_wl.split('@')[1]

                # Get recipient domains
                recipient_domains_wl = set()
                for recipient in recipients:
                    if '@' in recipient:
                        recipient_domains_wl.add(recipient.split('@')[1].lower())

                if recipient_domains_wl:
                    try:
                        cursor = DB_CONN.cursor(dictionary=True)
                        domain_list_wl = "','".join(recipient_domains_wl)

                        # Query database whitelist rules (domain type) for recipient domains + global rules
                        cursor.execute(f"""
                            SELECT DISTINCT br.rule_value, br.rule_pattern, br.is_global
                            FROM blocking_rules br
                            LEFT JOIN client_domains cd ON br.client_domain_id = cd.id
                            WHERE (cd.domain IN ('{domain_list_wl}') OR br.is_global = 1)
                            AND br.rule_type = 'domain'
                            AND br.whitelist = 1
                            AND br.active = 1
                        """)

                        whitelist_domains = cursor.fetchall()
                        cursor.close()

                        # Check if sender domain matches any whitelisted domains
                        for rule in whitelist_domains:
                            rule_value = rule['rule_value'].lower()
                            rule_pattern = rule.get('rule_pattern', 'exact')
                            is_global = rule.get('is_global', 0)

                            is_whitelisted = False
                            if rule_pattern == 'wildcard':
                                # Wildcard for TLD (e.g., gov matches *.gov)
                                if sender_domain_wl.endswith(f".{rule_value}") or sender_domain_wl == rule_value:
                                    is_whitelisted = True
                            else:
                                # Exact domain match
                                if sender_domain_wl == rule_value or sender_domain_wl.endswith(f".{rule_value}"):
                                    is_whitelisted = True

                            if is_whitelisted:
                                # Apply whitelist bonus (reduce spam score)
                                whitelist_bonus = -15.0  # Negative penalty = bonus
                                analysis_results['spam_score'] += whitelist_bonus
                                analysis_results['whitelisted_domain'] = rule_value
                                analysis_results['whitelist_bonus'] = whitelist_bonus
                                analysis_results['headers_to_add']['X-Whitelisted-Domain'] = rule_value
                                scope_label = "GLOBAL" if is_global else "domain-specific"
                                safe_add_header(msg, 'X-Whitelisted-Domain', rule_value, monitor)
                                safe_add_header(msg, 'X-Whitelist-Bonus', str(whitelist_bonus), monitor)
                                safe_log(f"✅ WHITELISTED DOMAIN {rule_value} ({scope_label}) - Reduced spam score by {abs(whitelist_bonus)} points")
                                break
                    except Exception as db_err:
                        safe_log(f"Database query error for domain whitelist: {db_err}")
        except Exception as e:
            safe_log(f"Domain whitelist bonus check error: {e}")

        # PER-DOMAIN SENDER BLOCKING - MOVED TO EARLY BLOCKING (line ~3152)
        # This section has been replaced with early rejection at the top of processing
        # Blocked senders are now rejected BEFORE any analysis, saving resources
        # The old code that added +50 spam points has been removed in favor of immediate rejection
        #
        # If a blocked sender somehow reaches this point, it means the early check failed
        # In that case, log a warning but don't try to block again
        try:
            if analysis_results.get('blocked_sender'):
                safe_log(f"⚠️ WARNING: Blocked sender {analysis_results['blocked_sender']} reached late processing - early check may have failed")
        except Exception as e:
            safe_log(f"Late blocking check error: {e}")

        # DOMAIN RANDOMNESS/ENTROPY CHECK
        # Detect randomly-generated domains commonly used in phishing (e.g., mjuynb.cfd, zysnor.cfd)
        try:
            from modules.domain_entropy import analyze_email_domains

            # Extract sender email
            sender_email_clean = from_header.lower()
            if '<' in sender_email_clean and '>' in sender_email_clean:
                sender_email_clean = sender_email_clean.split('<')[1].split('>')[0]

            # Get email body for link extraction
            email_body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            email_body += part.get_content()
                        except:
                            pass
                    elif part.get_content_type() == "text/html":
                        try:
                            email_body += part.get_content()
                        except:
                            pass
            else:
                try:
                    email_body = msg.get_content()
                except:
                    email_body = str(msg.get_payload())

            # Analyze domains
            entropy_results = analyze_email_domains(
                sender_email_clean,
                email_body,
                links=analysis_results.get('suspicious_links', [])
            )

            # Apply spam penalty
            if entropy_results['spam_penalty'] > 0:
                analysis_results['spam_score'] += entropy_results['spam_penalty']
                analysis_results['domain_entropy_penalty'] = entropy_results['spam_penalty']
                analysis_results['headers_to_add']['X-Spam-Score-Domain-Entropy'] = str(round(entropy_results['spam_penalty'], 2))

                # Add header with high-risk domains
                if entropy_results['high_risk_domains']:
                    high_risk_list = [f"{d['domain']}:{d['risk_score']}" for d in entropy_results['high_risk_domains']]
                    safe_add_header(msg, 'X-High-Risk-Random-Domains', ', '.join(high_risk_list), monitor)
                    safe_log(f"⚠️ RANDOM DOMAIN DETECTED: {', '.join(high_risk_list)} - Added +{entropy_results['spam_penalty']} spam points")

                # Store details for review
                analysis_results['domain_entropy_details'] = entropy_results
        except ImportError as e:
            safe_log(f"⚠️ Domain entropy module not available: {e}")
        except Exception as e:
            safe_log(f"Domain entropy check error: {e}")
            import traceback
            safe_log(f"Traceback: {traceback.format_exc()}")

        # ============================================================
        # DOMAIN AGE CHECK (Only for suspicious domains)
        # Checks whois for newly created or expiring domains
        # ============================================================
        try:
            domain_entropy_penalty = analysis_results.get('domain_entropy_penalty', 0)
            # Only check domain age if entropy module flagged it as suspicious (saves whois lookups)
            if domain_entropy_penalty >= 3.0:
                from modules.domain_age import analyze_sender_domain_age

                age_results = analyze_sender_domain_age(
                    sender_email_clean,
                    only_if_suspicious=False,  # Already filtered above
                    domain_entropy_penalty=domain_entropy_penalty
                )

                if not age_results.get('skipped') and age_results.get('spam_penalty', 0) > 0:
                    analysis_results['spam_score'] += age_results['spam_penalty']
                    analysis_results['domain_age_penalty'] = age_results['spam_penalty']
                    analysis_results['headers_to_add']['X-Spam-Score-Domain-Age'] = str(round(age_results['spam_penalty'], 2))

                    # Log details
                    age_days = age_results.get('age_days')
                    expiry_days = age_results.get('days_until_expiry')
                    indicators = age_results.get('risk_indicators', [])

                    if age_days is not None:
                        safe_add_header(msg, 'X-Domain-Age-Days', str(age_days), monitor)
                    if expiry_days is not None:
                        safe_add_header(msg, 'X-Domain-Expires-Days', str(expiry_days), monitor)
                    if indicators:
                        safe_add_header(msg, 'X-Domain-Age-Risk', ', '.join(indicators), monitor)

                    safe_log(f"⚠️ DOMAIN AGE CHECK: age={age_days}d, expires={expiry_days}d, penalty=+{age_results['spam_penalty']} ({', '.join(indicators)})")

                    # Store for review
                    analysis_results['domain_age_details'] = age_results
                elif age_results.get('skipped'):
                    safe_log(f"Domain age check skipped: {age_results.get('reason', 'unknown')}")
        except ImportError as e:
            safe_log(f"⚠️ Domain age module not available: {e}")
        except Exception as e:
            safe_log(f"Domain age check error: {e}")

        # ============================================================
        # ML ENSEMBLE SCORING - Disabled in this release
        # ML ensemble scoring can be enabled in future versions
        # ============================================================

        # Add analysis headers FIRST (before storing to database)
        safe_add_header(msg, 'X-SpaCy-Processed', datetime.datetime.now().isoformat(), monitor)
        safe_add_header(msg, 'X-Analysis-Modules', ', '.join(analysis_results['modules_run']), monitor)

        # Add relay tracking information (Postfix queue ID from environment)
        local_queue_id = os.getenv('QUEUE_ID', 'unknown')
        safe_add_header(msg, 'X-SpaCy-Local-Queue', local_queue_id, monitor)

        for header_name, header_value in analysis_results.get('headers_to_add', {}).items():
            safe_add_header(msg, header_name, header_value, monitor)

        monitor.record_final_score(analysis_results['spam_score'])

        # ADD COMPREHENSIVE SPAM SCORE BREAKDOWN HEADERS
        # This allows users to see exactly why an email was scored high
        safe_add_header(msg, 'X-Spam-Score-Total', str(round(analysis_results.get('spam_score', 0), 2)), monitor)

        # Add individual module score contributions
        score_breakdown = []
        if analysis_results.get('auth_abuse', {}).get('abuse_score', 0) != 0:
            auth_score = analysis_results['auth_abuse']['abuse_score']
            safe_add_header(msg, 'X-Spam-Score-Auth-Abuse', str(round(auth_score, 2)), monitor)
            score_breakdown.append(f"auth_abuse:{auth_score:.1f}")

        # Thread trust reduction (negative score)
        if 'thread_trust_reduction' in analysis_results:
            reduction = analysis_results['thread_trust_reduction']
            safe_add_header(msg, 'X-Spam-Score-Thread-Trust', str(round(-reduction, 2)), monitor)
            score_breakdown.append(f"thread_trust:-{reduction:.1f}")

        # Learning adjustment
        if analysis_results.get('learning_adjustment', 0) != 0:
            adjustment = analysis_results['learning_adjustment']
            safe_add_header(msg, 'X-Spam-Score-Learning', str(round(adjustment, 2)), monitor)
            score_breakdown.append(f"learning:{adjustment:.1f}")

        # Fake reply boost
        if analysis_results.get('fake_reply_boost', 0) > 0:
            boost = analysis_results['fake_reply_boost']
            safe_add_header(msg, 'X-Spam-Score-Fake-Reply', str(round(boost, 2)), monitor)
            score_breakdown.append(f"fake_reply:{boost:.1f}")

        # High-risk country penalty
        if analysis_results.get('high_risk_country_penalty', 0) > 0:
            penalty = analysis_results['high_risk_country_penalty']
            country = analysis_results.get('high_risk_country', 'Unknown')
            safe_add_header(msg, 'X-Spam-Score-Country-Risk', str(round(penalty, 2)), monitor)
            score_breakdown.append(f"country_risk:{penalty:.1f}")

        # Domain entropy penalty (random domain detection)
        if analysis_results.get('domain_entropy_penalty', 0) > 0:
            penalty = analysis_results['domain_entropy_penalty']
            safe_add_header(msg, 'X-Spam-Score-Domain-Entropy', str(round(penalty, 2)), monitor)
            score_breakdown.append(f"random_domain:{penalty:.1f}")

        # Add module-specific scores from headers_to_add
        module_scores = {
            'dns_spam_score': 'DNS',
            'phishing_score': 'Phishing',
            'risk_score': 'Risk',
            'url_risk_score': 'URL',
            'behavioral_risk_score': 'Behavioral',
            'spam_score_adjustment': 'Sentiment',
            'obfuscation_score': 'Obfuscation',
            'marketing_spam_score': 'Marketing',
            'bec_score': 'BEC',
            'toad_score': 'TOAD',
            'pdf_spam_score': 'PDF'
        }

        for key, label in module_scores.items():
            if key in analysis_results and analysis_results[key] != 0:
                score = analysis_results[key]
                safe_add_header(msg, f'X-Spam-Score-{label}', str(round(score, 2)), monitor)
                score_breakdown.append(f"{label.lower()}:{score:.1f}")

        # Add summary breakdown header
        if score_breakdown:
            safe_add_header(msg, 'X-Spam-Score-Breakdown', ', '.join(score_breakdown), monitor)

        if MODULE_MANAGER.is_available('otp_detector'):
            try:
                extract_otp = MODULE_MANAGER.get_module('otp_detector')
                provider, otp_code = extract_otp(
                    subject=safe_get_header(msg, 'Subject', ''),
                    body=text_content[:1000],
                    from_header=from_header
                )
                if otp_code:
                    safe_add_header(msg, 'X-OTP-Detected', provider, monitor)
                    safe_add_header(msg, 'X-OTP-Code', otp_code, monitor)
                    safe_log(f"OTP detected: {provider}")
            except Exception as e:
                safe_log(f"OTP detection error: {e}")

        # ============================================================================
        # VIP SENDER CHECK: Reduce spam score for VIP senders
        # ============================================================================
        try:
            global VIP_ALERT_SYSTEM
            if VIP_ALERT_SYSTEM is None:
                VIP_ALERT_SYSTEM = VIPAlertSystem()

            # Get sender email
            sender_email = from_header.lower()
            if '<' in sender_email and '>' in sender_email:
                sender_email = sender_email.split('<')[1].split('>')[0].strip()

            # Check each recipient for VIP configuration
            vip_bonus_applied = False
            for recipient in recipients:
                if '@' in recipient:
                    recipient_domain = recipient.split('@')[1].lower()
                    # Try to get actual client domain ID from database
                    client_domain_id = 1
                    if DB_CONN:
                        try:
                            cursor = DB_CONN.cursor(dictionary=True)
                            cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (recipient_domain,))
                            result = cursor.fetchone()
                            if result:
                                client_domain_id = result['id']

                            # Check if this sender is configured as VIP for this recipient
                            cursor.execute("""
                                SELECT id, vip_sender_email FROM vip_senders
                                WHERE user_email = %s AND vip_sender_email = %s AND alert_enabled = TRUE
                            """, (recipient, sender_email))
                            vip_config = cursor.fetchone()
                            cursor.close()

                            if vip_config and not vip_bonus_applied:
                                # Apply VIP whitelist bonus (reduce spam score by 15 points)
                                vip_bonus = -15.0
                                analysis_results['spam_score'] += vip_bonus
                                analysis_results['vip_sender_bonus'] = vip_bonus
                                analysis_results['headers_to_add']['X-VIP-Sender'] = sender_email
                                analysis_results['headers_to_add']['X-VIP-Bonus'] = str(round(vip_bonus, 2))
                                safe_log(f"⭐ VIP SENDER {sender_email} for {recipient} - Reduced spam score by {abs(vip_bonus)} points")
                                vip_bonus_applied = True
                                break
                        except Exception as db_err:
                            safe_log(f"VIP sender check database error: {db_err}")
        except Exception as vip_err:
            safe_log(f"VIP sender check failed (continuing): {vip_err}")

        # ============================================================================
        # NEW FLOW: MAKE DECISION → STORE WITH DISPOSITION → EXECUTE
        # ============================================================================

        spam_score = analysis_results.get('spam_score', 0.0)
        safe_log(f"🔍 Making disposition decision - spam_score: {spam_score:.2f}")

        # Extract recipient domains for quarantine check
        recipient_domains = []
        for recipient in recipients:
            if '@' in recipient:
                recipient_domains.append(recipient.split('@')[1].lower())

        # STEP 1: Make disposition decision (with recipient domains for quarantine check)
        disposition, reason = make_disposition_decision(analysis_results, msg, recipient_domains)
        safe_log(f"📋 Decision: {disposition} ({reason})")

        # AUTO-DELETE POLICY: .cn domains and non-English/Spanish languages
        # Process for ML data collection but don't show in GUI to reduce admin clutter
        auto_delete = False
        auto_delete_reason = None

        # Check sender domain
        sender_domain = ''
        if '@' in from_header:
            match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
            if match:
                sender_domain = match.group(1).lower()

        # Auto-delete .cn domains
        if sender_domain.endswith('.cn'):
            auto_delete = True
            auto_delete_reason = f"Auto-deleted: .cn domain ({sender_domain})"
            safe_log(f"🗑️  AUTO-DELETE: .cn domain detected - {sender_domain}")

        # Auto-delete non-English/Spanish languages (if detected with confidence)
        detected_lang = analysis_results.get('detected_language', 'en')
        lang_confidence = analysis_results.get('language_confidence', 0.0)

        if detected_lang not in ['en', 'es', 'unknown'] and lang_confidence > 0.3:
            auto_delete = True
            auto_delete_reason = f"Auto-deleted: Non-allowed language ({detected_lang})"
            safe_log(f"🗑️  AUTO-DELETE: Non-English/Spanish language detected - {detected_lang} (confidence: {lang_confidence:.2f})")

        # Override disposition for auto-delete cases
        if auto_delete:
            disposition = 'deleted'
            reason = auto_delete_reason
            safe_log(f"📋 Auto-delete override: {reason}")

        # STEP 2: Store email with disposition (synchronous - no race condition)
        storage_success = store_email_with_disposition(msg, text_content, analysis_results, disposition, reason)

        if not storage_success:
            # Storage failed - defer for retry
            safe_log(f"⚠️  Storage failed - deferring email for retry")
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(75)  # EX_TEMPFAIL - Postfix will retry

        # STEP 3: Execute disposition
        if disposition == 'deleted':
            safe_log(f"🗑️  Email DELETED (Reason: {reason})")

            # Email stored with disposition='deleted' in email_analysis
            # Accept but silently discard (don't relay, don't show in UI by default)
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(0)  # Success - email accepted but deleted

        elif disposition == 'quarantined':
            safe_log(f"📬 Email QUARANTINED (Score: {spam_score:.2f}, Reason: {reason})")

            # Already stored in email_analysis with disposition='quarantined'
            # No need for separate quarantine table storage (consolidated 2025-11-19)

            # Email stored in database only - NOT re-injected for relay
            # Exit 0 tells Postfix the pipe delivery succeeded
            # Email is NOT re-injected via SMTP, so won't reach Zimbra
            # Available for manual release via quarantine UI
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(0)  # Success - email handled, not relayed

        elif disposition == 'rejected':
            safe_log(f"🚫 Email REJECTED (Reason: {reason})")
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(69)  # EX_UNAVAILABLE - permanent rejection

        # If we get here, disposition == 'relay_pending'
        # Email passed checks - relay to MailGuard
        safe_log(f"✅ Email ready for relay - Score: {spam_score:.2f}")

        # VIP ALERT CHECK: Send SMS alert if this is from a VIP sender
        try:
            # VIP_ALERT_SYSTEM already initialized above in whitelist check
            if VIP_ALERT_SYSTEM is None:
                VIP_ALERT_SYSTEM = VIPAlertSystem()

            # Get sender email
            sender_email = from_header.lower()
            if '<' in sender_email and '>' in sender_email:
                sender_email = sender_email.split('<')[1].split('>')[0].strip()

            # Get message ID and subject
            message_id = safe_get_header(msg, 'Message-ID', '')
            subject = safe_get_header(msg, 'Subject', '(no subject)')

            # Check each recipient for VIP configuration
            for recipient in recipients:
                # Get client domain ID (you may need to adjust this logic)
                client_domain_id = 1  # Default - you can make this more sophisticated
                if '@' in recipient:
                    recipient_domain = recipient.split('@')[1].lower()
                    # Try to get actual client domain ID from database
                    if DB_CONN:
                        try:
                            cursor = DB_CONN.cursor(dictionary=True)
                            cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (recipient_domain,))
                            result = cursor.fetchone()
                            if result:
                                client_domain_id = result['id']
                            cursor.close()
                        except:
                            pass

                # Check if this sender is VIP for this recipient
                alert_sent = VIP_ALERT_SYSTEM.check_vip_sender(
                    recipient_email=recipient,
                    sender_email=sender_email,
                    message_id=message_id,
                    subject=subject,
                    spam_score=spam_score,
                    client_domain_id=client_domain_id
                )

                if alert_sent:
                    safe_log(f"📱 VIP SMS alert sent to {recipient} for email from {sender_email}")

        except Exception as vip_err:
            # Never fail email processing due to VIP alert failure
            safe_log(f"⚠️  VIP alert check failed (continuing): {vip_err}")

        # DEBUG: Check if recipients variable exists
        try:
            test_recipients = recipients
            safe_log(f"🔍 DEBUG: recipients variable exists: {recipients}")
        except NameError:
            safe_log(f"❌ CRITICAL: recipients variable is NOT DEFINED!")
            safe_log(f"❌ This is a bug - email cannot be relayed without recipients")
            signal.alarm(0)
            sys.exit(1)

        # DEBUG: Log recipients before relay
        safe_log(f"🔍 DEBUG: About to relay - recipients variable = {recipients}")
        safe_log(f"🔍 DEBUG: Recipients count = {len(recipients) if recipients else 0}")
        safe_log(f"🔍 DEBUG: Recipients type = {type(recipients)}")

        # Write to debug file for visibility
        try:
            with open('/tmp/spacy_relay_debug.log', 'a') as f:
                f.write(f"\n{datetime.datetime.now()} - Message-ID: {safe_get_header(msg, 'Message-ID', 'unknown')}\n")
                f.write(f"  Recipients variable: {recipients}\n")
                f.write(f"  Recipients count: {len(recipients) if recipients else 0}\n")
                f.write(f"  Spam score: {analysis_results.get('spam_score', 'unknown')}\n")
        except Exception as debug_e:
            safe_log(f"Debug file write error: {debug_e}")

        safe_log("🚀 STARTING RELAY BLOCK - Using per-domain relay hosts")

        # Ensure envelope_sender is set (fallback to From header if not provided by Postfix)
        if not envelope_sender:
            from_header = safe_get_header(msg, 'From', '')
            # Extract email from "Name <email@domain.com>" format
            if '<' in from_header and '>' in from_header:
                envelope_sender = from_header.split('<')[1].split('>')[0].strip()
            else:
                envelope_sender = from_header.strip()
            safe_log(f"📧 Using envelope sender from From header: {envelope_sender}")

        # Relay to MailGuard using per-domain relay hosts
        try:
            # Group recipients by domain and relay to each domain's specific relay host
            domain_relays = CONFIG.config['servers'].get('domain_relays', {})
            processed_domains = CONFIG.config['domains']['processed_domains']
            default_host = CONFIG.config['servers']['mailguard_host']
            default_port = CONFIG.config['servers']['mailguard_port']
            smtp_timeout = CONFIG.config['timeouts']['smtp_timeout']

                # Group recipients by domain
            recipients_by_domain = {}
            for recipient in recipients:
                if '@' in recipient:
                    domain = recipient.split('@')[1].lower()
                    if domain in processed_domains:
                        if domain not in recipients_by_domain:
                            recipients_by_domain[domain] = []
                        recipients_by_domain[domain].append(recipient)

                # Relay to each domain's specific relay host
            relay_success = True
            for domain, domain_recipients in recipients_by_domain.items():
                    # Get relay host for this domain
                if domain in domain_relays:
                    mailguard_host = domain_relays[domain]['relay_host']
                    mailguard_port = domain_relays[domain]['relay_port']
                else:
                    mailguard_host = default_host
                    mailguard_port = default_port

                safe_log(f"Relaying {len(domain_recipients)} recipients for {domain} to {mailguard_host}:{mailguard_port}")

                try:
                    with smtplib.SMTP(mailguard_host, mailguard_port, timeout=smtp_timeout) as smtp:
                            # Try to use STARTTLS for encryption
                        try:
                            smtp.starttls()
                            smtp.ehlo()  # Must send EHLO again after STARTTLS
                            safe_log(f"✅ TLS enabled for relay to {mailguard_host}:{mailguard_port}")
                        except Exception as tls_err:
                            safe_log(f"⚠️  TLS not available for {mailguard_host}:{mailguard_port} - continuing: {tls_err}")

                            # Use lower-level SMTP commands to capture queue ID
                            # First do EHLO handshake (already done by __init__, but need to be explicit for mail/rcpt)
                        smtp.ehlo_or_helo_if_needed()

                            # Send MAIL FROM
                        smtp.mail(envelope_sender)

                            # Send RCPT TO for each recipient
                        for recipient in domain_recipients:
                            smtp.rcpt(recipient)

                            # Send DATA command and capture response which contains queue ID
                        code, response = smtp.data(msg.as_bytes())

                            # Extract upstream queue ID from DATA response
                        upstream_queue_id = "unknown"
                        try:
                            response_str = response.decode() if isinstance(response, bytes) else str(response)
                            safe_log(f"📬 SMTP DATA response from {mailguard_host}: code={code}, response='{response_str}'")

                            # Try multiple extraction patterns for different mail servers
                            if "queued as" in response_str.lower():
                                # Postfix/Zimbra format: "250 2.0.0 Ok: queued as ABC123"
                                parts = response_str.split("queued as")
                                if len(parts) > 1:
                                    upstream_queue_id = parts[1].strip().split()[0].rstrip(')')
                                    safe_log(f"✅ Extracted queue ID (queued as): {upstream_queue_id}")
                            elif re.search(r'\b[A-Za-z0-9]{10,}[-.]?[A-Za-z0-9]*\b', response_str):
                                # Google/flexible format: Match queue IDs like "586e51a60fabf-3e833f8f9d3mr1536752fac.3"
                                # or traditional IDs like "ABC123DEF456"
                                queue_match = re.search(r'\b[A-Za-z0-9]{10,}[-.]?[A-Za-z0-9]*\b', response_str)
                                if queue_match:
                                    upstream_queue_id = queue_match.group(0)
                                    safe_log(f"✅ Extracted queue ID (pattern match): {upstream_queue_id}")
                            elif re.search(r'[A-F0-9]{8,}', response_str):
                                # Hex queue ID format
                                queue_match = re.search(r'[A-F0-9]{8,}', response_str)
                                if queue_match:
                                    upstream_queue_id = queue_match.group(0)
                                    safe_log(f"✅ Extracted queue ID (hex): {upstream_queue_id}")

                            if upstream_queue_id == "unknown":
                                # No recognizable queue ID - store the response for debugging
                                upstream_queue_id = f"{domain}: {response_str[:80]}"
                                safe_log(f"⚠️  No queue ID pattern matched, storing response: {upstream_queue_id}")
                        except Exception as e:
                            safe_log(f"⚠️  Could not extract queue ID: {e}")

                            # Add forensic headers for chain of custody tracking
                        safe_add_header(msg, 'X-Upstream-Queue-ID', upstream_queue_id, monitor)
                        safe_add_header(msg, 'X-Upstream-Relay-Host', f"{mailguard_host}:{mailguard_port}", monitor)
                        safe_add_header(msg, 'X-Relay-Timestamp', datetime.datetime.now().isoformat(), monitor)

                        safe_log(f"✅ Email relayed to {mailguard_host}:{mailguard_port} for {len(domain_recipients)} recipients ({domain})")
                        safe_log(f"📬 Upstream Queue ID: {upstream_queue_id}")

                        # Update database with upstream queue ID
                        try:
                            message_id = safe_get_header(msg, 'Message-ID', '')
                            if message_id:
                                cursor = DB_CONN.cursor()
                                cursor.execute("""
                                    UPDATE email_analysis
                                    SET upstream_queue_id = %s
                                    WHERE message_id = %s
                                """, (upstream_queue_id, message_id))
                                DB_CONN.commit()
                                cursor.close()
                                safe_log(f"✅ Updated database with upstream queue ID: {upstream_queue_id}")
                        except Exception as db_err:
                            safe_log(f"⚠️  Could not update upstream queue ID in database: {db_err}")
                except smtplib.SMTPRecipientsRefused as e:
                        # Recipient doesn't exist on destination server - update disposition
                    safe_log(f"⚠️  Recipients rejected by {mailguard_host}:{mailguard_port} for {domain}: {e}")
                    safe_log(f"⚠️  Updating disposition to 'relay_failed' - recipient validation failed")
                    # Update disposition to relay_failed
                    message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                    update_email_disposition(message_id, 'relay_failed', f'recipient_rejected: {str(e)[:200]}')
                    relay_success = False
                except smtplib.SMTPException as e:
                        # Other SMTP errors (connection, auth, etc.)
                    safe_log(f"❌ SMTP error relaying to {mailguard_host}:{mailguard_port} for {domain}: {e}")
                    message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                    update_email_disposition(message_id, 'relay_failed', f'smtp_error: {str(e)[:200]}')
                    relay_success = False
                except Exception as relay_error:
                    safe_log(f"❌ Failed to relay to {mailguard_host}:{mailguard_port} for {domain}: {relay_error}")
                    message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                    update_email_disposition(message_id, 'relay_failed', f'relay_error: {str(relay_error)[:200]}')
                    relay_success = False

            if relay_success:
                # All relays successful - update disposition to 'delivered'
                message_id = safe_get_header(msg, 'Message-ID', 'unknown')
                update_email_disposition(message_id, 'delivered', 'relayed_successfully')
                safe_log(f"✅ Disposition updated to 'delivered' for message {message_id}")
                monitor.log_performance(safe_log)
                signal.alarm(0)
                sys.exit(0)
            else:
                safe_log("❌ Relay failed - exiting with error code for Postfix to handle")
                monitor.log_performance(safe_log)
                signal.alarm(0)
                sys.exit(1)

        except Exception as e:
            safe_log(f"❌ Failed to relay to MailGuard: {e}")
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(1)
    
    except Exception as e:
        signal.alarm(0)
        monitor.log_performance(safe_log)
        safe_log(f"MAIN ERROR: {e}")
        safe_log(f"TRACEBACK: {traceback.format_exc()}")
        sys.exit(1)
    
    finally:
        gc.collect()

if __name__ == "__main__":
    main()

