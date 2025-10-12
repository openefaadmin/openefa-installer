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
FIXED: Added mail loop prevention for system emails from spacy.covereddata.com
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
"""

import sys
import os
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
from email.parser import BytesParser
from email.policy import default
from email.message import EmailMessage
from email.header import Header
from contextlib import contextmanager
from typing import Dict, List, Set, Optional, Tuple, Any

# Add modules path
sys.path.insert(0, '/opt/spacyserver/modules')

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

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class EmailFilterConfig:
    """Centralized configuration management"""
    
    def __init__(self):
        self.config = {
            # Performance settings - REDUCED MODULE TIMEOUT
            "timeouts": {
                "total_processing": int(os.getenv('SPACY_TIMEOUT_TOTAL', 90)),
                "analysis_timeout": int(os.getenv('SPACY_TIMEOUT_ANALYSIS', 60)),
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
            "domains": {
                "internal_domains": {
                    'covereddata.com', 'seguelogic.com', 'safesoundins.com', 'offgriddynamics.com',
                    'rdjohnsonlaw.com', 'escudolaw.com', 'barbour.tech', 'securedata247.com',
                    'chrystinakatz.com', 'epolaw.ai', 'epobot.ai', 'sd247.guardiannet.world',
                    'openefa.com', 'openefa.org', 'guardiannet.world', 'statvu.com'
                },
                "processed_domains": {
                    'seguelogic.com', 'offgriddynamics.com', 'covereddata.com', 'securedata247.com',
                    'rdjohnsonlaw.com', 'safesoundins.com', 'openefa.com', 'openefa.org',
                    'barbour.tech', 'escudolaw.com', 'chrystinakatz.com', 'epolaw.ai',
                    'epobot.ai', 'sd247.guardiannet.world', 'guardiannet.world',
                    'phoenixdefence.com', 'chipotlepublishing.com', 'statvu.com'
                },
                "journal_addresses": {
                    'journal@spacy.covereddata.com',
                    'journal@covereddata.com'
                },
                "trusted_domains": set()  # Will be loaded from config file
            },
            
            # NEW: System bypass configuration to prevent mail loops
            "system_bypass": {
                "bypass_domains": [
                    'spacy.covereddata.com',
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
                    'nagios@',
                    'zabbix@'
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
                "mailguard_host": os.getenv('SPACY_MAILGUARD_HOST', '192.168.50.37'),
                "mailguard_port": int(os.getenv('SPACY_MAILGUARD_PORT', 25)),
                "internal_ips": [
                    '192.168.50.114', '192.168.50.37',
                    'zimbra.apollomx.com', 'mailguard.covereddata.com'
                ]
            },
            
            # ENHANCED: Analysis thresholds with new blocking parameters + funding spam
            "thresholds": {
                "spam_threshold": float(os.getenv('SPACY_SPAM_THRESHOLD', 80.0)),
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
    
    def _load_trusted_domains(self):
        """Load trusted domains from external config file"""
        try:
            config_file = '/opt/spacyserver/config/trusted_domains.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    trusted_config = json.load(f)
                    # Convert list to set for faster lookups
                    self.config['domains']['trusted_domains'] = set(trusted_config.get('trusted_domains', []))
                    print(f"✅ Loaded {len(self.config['domains']['trusted_domains'])} trusted domains from {config_file}", file=sys.stderr)
            else:
                # Fallback to empty set if config file doesn't exist
                self.config['domains']['trusted_domains'] = set()
                print(f"⚠️  No trusted domains config found at {config_file}", file=sys.stderr)
        except Exception as e:
            print(f"❌ Error loading trusted domains: {e}", file=sys.stderr)
            self.config['domains']['trusted_domains'] = set()

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
            'enhanced_analysis': ('analysis', ['enhanced_government_analysis', 'detect_business_context', 'detect_domain_spoofing']),
            'toad_detector': ('toad_detector', 'analyze_toad_threats'),
            'pdf_analyzer': ('pdf_analyzer', 'analyze_pdf_attachments'),
            'fraud_funding_detector': ('funding_spam_detector', 'analyze_funding_spam'),
            'url_reputation': ('url_reputation', 'analyze_email_urls'),
            'behavioral_baseline': ('behavioral_baseline', 'analyze_behavior'),
            'rbl_checker': ('rbl_checker', 'analyze_rbl')
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
    """Safe logging to file with length limit"""
    try:
        if isinstance(message, str) and len(message) > max_length:
            message = message[:max_length-3] + "..."
        # Write to a debug file to avoid postfix output limits
        with open('/tmp/email_filter_debug.log', 'a') as f:
            f.write(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n")
        # Only critical messages to stderr for postfix
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

# ============================================================================
# CORE EMAIL PROCESSING FUNCTIONS
# ============================================================================

def extract_text_content(msg: EmailMessage, max_length: int = 50000) -> str:
    """Extract text content from email message"""
    text_content = ""
    
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
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
        else:
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
    
    if len(text_content) > max_length:
        text_content = text_content[:max_length] + "\n[FINAL TRUNCATION]"
    
    return text_content

def detect_original_authentication(msg: EmailMessage, from_header: str) -> Dict[str, str]:
    """Detect authentication with real validation fallback - FIXED to prevent loops"""
    auth_status = {
        'spf': 'none',
        'dkim': 'none',
        'dmarc': 'none',
        'dmarc_policy': 'none'
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
            if 'mailguard.covereddata.com' in auth_str or 'spacy.covereddata.com' in auth_str:
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
                    safe_log(f"All auth results found after processing {headers_processed} header(s)")
                    break

        if found_existing_auth:
            safe_log(f"Auth results: SPF={auth_status['spf']}, DKIM={auth_status['dkim']}, DMARC={auth_status['dmarc']}")

        if not found_existing_auth and REAL_AUTH_AVAILABLE:
            safe_log("No existing authentication found, performing real validation")

        # Microsoft domain special handling (unchanged)
        if sender_domain in ['microsoftonline.com', 'microsoft.com', 'outlook.com']:
            arc_headers = msg.get_all('ARC-Authentication-Results', [])
            # Limit ARC headers too
            if len(arc_headers) > 5:
                arc_headers = arc_headers[-5:]

            for arc_header in arc_headers:
                arc_str = str(arc_header).lower()
                if 'spf=pass' in arc_str or 'dkim=pass' in arc_str:
                    safe_log("Microsoft domain with passing ARC signatures")
                    auth_status['spf'] = 'pass'
                    auth_status['dkim'] = 'pass'
                    break

    except Exception as e:
        safe_log(f"Error in authentication detection: {e}")

    return auth_status

# ============================================================================
# REAL AUTHENTICATION VALIDATION
# ============================================================================

def perform_real_authentication(msg: EmailMessage, from_header: str, monitor: PerformanceMonitor) -> Dict:
    """Perform real SPF, DKIM, and DMARC validation"""
    auth_results = {
        'spf': 'none',
        'dkim': 'none',
        'dmarc': 'none',
        'dmarc_policy': 'none',
        'validation_method': 'none',
        'auth_score': 0.0
    }
    
    if not REAL_AUTH_AVAILABLE:
        safe_log("Real authentication libraries not available")
        auth_results['validation_method'] = 'unavailable'
        return auth_results
    
    try:
        sender_email = extract_email_from_header(from_header)
        sender_domain = safe_extract_domain(from_header)
        
        if not sender_email or not sender_domain:
            safe_log("Cannot extract sender information for authentication")
            auth_results['validation_method'] = 'invalid_sender'
            return auth_results
        
        # Get sender IP
        sender_ip = None
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            received_str = str(received)
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received_str)
            if ip_match:
                sender_ip = ip_match.group(1)
                break

        if not sender_ip:
            sender_ip = CONFIG.config['servers']['internal_ips'][0]
            safe_log(f"No sender IP found, using default: {sender_ip}")

        # RBL (Real-time Blackhole List) checking
        if MODULE_MANAGER.is_available('rbl_checker'):
            try:
                with timeout_handler(module_timeout):
                    analyze_rbl = MODULE_MANAGER.get_module('rbl_checker')
                    rbl_data = {'sender_ip': sender_ip}
                    rbl_results = analyze_rbl(rbl_data)

                    if rbl_results and isinstance(rbl_results, dict):
                        rbl_score = rbl_results.get('rbl_score', 0.0)
                        if rbl_score > 0:
                            analysis_results['spam_score'] += rbl_score
                            safe_log(f"🚫 RBL HIT: IP {sender_ip} listed in {len(rbl_results.get('rbl_hits', []))} blacklists - added {rbl_score} points")

                            # Add detailed RBL info to analysis
                            for hit in rbl_results.get('rbl_hits', []):
                                safe_log(f"   - {hit['name']} ({hit['host']}): weight {hit['weight']}")

                        # Add RBL headers
                        for header, value in rbl_results.get('headers_to_add', {}).items():
                            msg.add_header(header, str(value))

                        analysis_results['modules_run'].append('rbl_checker')
                        monitor.record_module('rbl_checker')
            except Exception as e:
                safe_log(f"RBL checker module error: {e}")

        # Check if sender IP is in trusted networks
        is_trusted_network = False
        try:
            import ipaddress
            with open('/opt/spacyserver/config/authentication_config.json', 'r') as f:
                import json
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
            safe_log(f"Trusted network detected - automatically passing SPF for {sender_email}")
            auth_results['spf'] = 'pass'
        elif sender_domain in problematic_domains:
            safe_log(f"Skipping SPF check for problematic domain {sender_domain} - marking as temperror")
            auth_results['spf'] = 'temperror'
        else:
            safe_log(f"Checking SPF for {sender_email} from {sender_ip}")
            auth_results['spf'] = check_spf_subprocess(
                sender_ip,
                sender_email,
                sender_domain,
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
        except TimeoutException:
            safe_log(f"DKIM check timed out after {CONFIG.config['timeouts']['auth_timeout']}s")
            auth_results['dkim'] = 'temperror'
        except Exception as e:
            safe_log(f"DKIM check error: {e}")
            auth_results['dkim'] = 'temperror'
        
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
        
        # DKIM scoring - moderate positive, strong negative
        dkim_result = auth_results['dkim']
        if dkim_result == 'pass':
            auth_score += 2.0  # Reduced from 5.0 - DKIM can be valid for compromised accounts
        elif dkim_result == 'fail':
            auth_score -= 4.0  # Increased from -2.0
        
        # DMARC scoring - slightly higher positive, strong negative  
        dmarc_result = auth_results['dmarc']
        if dmarc_result == 'pass':
            auth_score += 2.0  # Reduced from 4.0 - DMARC alignment doesn't prevent phishing
        elif dmarc_result == 'fail':
            auth_score -= 5.0  # Increased from -2.0, especially bad with reject policy
            if auth_results.get('dmarc_policy') == 'reject':
                auth_score -= 3.0  # Additional penalty for violating reject policy
        
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
        try:
            import json
            from pathlib import Path
            bec_config_path = Path("/opt/spacyserver/config/bec_config.json")
            if bec_config_path.exists():
                with open(bec_config_path, 'r') as f:
                    bec_config = json.load(f)

                # Extract sender email from From header
                sender_email_for_wl = sender_email.lower().strip()

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
                                safe_log(f"✅ Whitelisted sender - auth score boosted from {original_auth_score} to {auth_score} (+{trust_bonus})")
                            break
        except Exception as e:
            safe_log(f"Error applying whitelist auth bonus: {e}")

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

def analyze_email_with_modules(msg: EmailMessage, text_content: str, from_header: str, monitor: PerformanceMonitor, auth_results: Dict = None) -> Dict:
    """Run all available analysis modules with proper timeout handling"""
    analysis_results = {
        'spam_score': 0.0,
        'headers_to_add': {},
        'modules_run': []
    }

    # Get module timeout from config
    module_timeout = CONFIG.config['timeouts']['module_timeout']

    # Check if this is a trusted domain - use minimal analysis
    sender_domain = safe_extract_domain(from_header)
    is_trusted = sender_domain in CONFIG.config['domains']['trusted_domains']

    if is_trusted:
        safe_log(f"Trusted domain {sender_domain} - minimal analysis")
        # Only run essential modules for trusted domains

    # Load BEC whitelist configuration early to check bypass flags
    bypass_aggressive_checks = False
    try:
        import json
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
    
    try:
        # DNS validation with timeout
        if MODULE_MANAGER.is_available('email_dns') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    dns_validator = MODULE_MANAGER.get_module('email_dns')
                    # DNS expects msg and text_content
                    dns_results = dns_validator(msg, text_content)
                    if dns_results and isinstance(dns_results, dict) and 'dns_spam_score' in dns_results:
                        analysis_results['spam_score'] += dns_results['dns_spam_score']
                        analysis_results['modules_run'].append('dns')
                        monitor.record_module('dns')
                        safe_log(f"DNS module completed - score: {dns_results.get('dns_spam_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ DNS module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"DNS module error: {e}")
        
        # Phishing detection with timeout
        if MODULE_MANAGER.is_available('email_phishing'):
            try:
                with timeout_handler(module_timeout):
                    detect_phishing = MODULE_MANAGER.get_module('email_phishing')
                    # New phishing detector takes msg, text_content, from_header
                    phishing_results = detect_phishing(msg, text_content, from_header)
                    if phishing_results and isinstance(phishing_results, dict):
                        # Add risk score to spam score
                        if phishing_results.get('detected', False):
                            analysis_results['spam_score'] += phishing_results.get('risk_score', 0)
                            analysis_results['modules_run'].append('phishing')
                            monitor.record_module('phishing')
                            safe_log(f"🎣 Phishing detected - type: {phishing_results.get('phishing_type')}, score: {phishing_results.get('risk_score', 0)}")
                            
                            # Add headers for SpamAssassin
                            for header_name, header_value in phishing_results.get('headers_to_add', {}).items():
                                safe_add_header(msg, header_name, header_value, monitor)
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

                            # Reduce URL risk for trusted threads (legitimate ongoing conversations)
                            if is_reply and thread_trust > 0:
                                # Trusted thread: reduce URL contribution significantly (80% reduction)
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.1, 2.0)
                                safe_log(f"🧵 Thread trust detected - reducing URL risk contribution by 80%")
                            else:
                                # Non-threaded or untrusted: normal cap at 10 points
                                url_contribution = min(url_results.get('total_risk_score', 0) * 0.5, 10.0)

                            analysis_results['spam_score'] += url_contribution
                            analysis_results['modules_run'].append('url_reputation')
                            monitor.record_module('url_reputation')
                            safe_log(f"🔗 URL analysis - risk score: {url_results.get('total_risk_score', 0)}, homographs: {len(url_results.get('homograph_attacks', []))}")

                            # Add headers for SpamAssassin
                            for header_name, header_value in url_results.get('headers_to_add', {}).items():
                                safe_add_header(msg, header_name, str(header_value), monitor)

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
                        'recipients': recipients,
                        'subject': safe_get_header(msg, 'Subject', ''),
                        'body': text_content,
                        'message_id': safe_get_header(msg, 'Message-ID', '')
                    }
                    behavior_results = analyze_behavior(behavior_data)
                    if behavior_results and isinstance(behavior_results, dict):
                        # Add behavioral risk to spam score with cap
                        if behavior_results.get('behavioral_risk_score', 0) > 0:
                            # Cap behavioral contribution at 10 points max
                            behavior_contribution = min(behavior_results.get('behavioral_risk_score', 0) * 0.7, 10.0)
                            analysis_results['spam_score'] += behavior_contribution
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
                    if sentiment_results and isinstance(sentiment_results, dict) and 'spam_score_adjustment' in sentiment_results:
                        analysis_results['spam_score'] += sentiment_results['spam_score_adjustment']
                        analysis_results['modules_run'].append('sentiment')
                        monitor.record_module('sentiment')
                        safe_log(f"Sentiment module completed - adjustment: {sentiment_results.get('spam_score_adjustment', 0)}")
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
                    if language_results and isinstance(language_results, dict) and 'spam_score_adjustment' in language_results:
                        analysis_results['spam_score'] += language_results['spam_score_adjustment']
                        analysis_results['modules_run'].append('language')
                        monitor.record_module('language')
                        safe_log(f"Language module completed - adjustment: {language_results.get('spam_score_adjustment', 0)}")
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
                        analysis_results['spam_score'] += obfuscation_results['obfuscation_score']
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
                                    analysis_results['modules_run'].append('marketing')
                                    monitor.record_module('marketing')
                                    safe_log(f"Marketing module completed - score: {marketing_contribution} (capped from {marketing_results.get('spam_score', 0)})")
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
                            safe_log(f"BEC module completed - confidence: {confidence:.2f}, score: +{bec_contribution}")
                        elif 'bec_score' in bec_results:
                            # Cap BEC score at reasonable maximum
                            bec_contribution = min(bec_results['bec_score'], 8.0)
                            analysis_results['spam_score'] += bec_contribution
                            safe_log(f"BEC module completed - score: {bec_contribution}")
                        
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
        
        # TOAD detector with timeout - skip for trusted domains
        if MODULE_MANAGER.is_available('toad_detector') and not is_trusted:
            try:
                with timeout_handler(module_timeout):
                    analyze_toad = MODULE_MANAGER.get_module('toad_detector')
                    # TOAD expects 3 parameters: msg, text_content, from_header
                    toad_results = analyze_toad(msg, text_content[:5000], from_header)
                    if toad_results and isinstance(toad_results, dict) and 'toad_score' in toad_results:
                        analysis_results['spam_score'] += toad_results['toad_score']
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
                        analysis_results['spam_score'] += pdf_results['pdf_spam_score']
                        analysis_results['modules_run'].append('pdf')
                        monitor.record_module('pdf')
                        safe_log(f"PDF module completed - score: {pdf_results.get('pdf_spam_score', 0)}")
            except TimeoutException:
                safe_log(f"⏱️ PDF module timed out after {module_timeout}s")
            except Exception as e:
                safe_log(f"PDF module error: {e}")
        
        # Funding/Financing Spam Detection with timeout
        if MODULE_MANAGER.is_available('fraud_funding_detector'):
            try:
                with timeout_handler(module_timeout):
                    analyze_funding_spam = MODULE_MANAGER.get_module('fraud_funding_detector')
                    # The funding spam detector expects email_data dict format
                    funding_results = analyze_funding_spam(email_data)
                    if funding_results and isinstance(funding_results, dict):
                        # Check for different possible score field names
                        if 'spam_score' in funding_results:
                            analysis_results['spam_score'] += funding_results['spam_score']
                        elif 'funding_spam_score' in funding_results:
                            analysis_results['spam_score'] += funding_results['funding_spam_score']
                        
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
                        subject=email_data['subject'],
                        sender=email_data['from']
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
        
        safe_log(f"Modules run: {', '.join(analysis_results['modules_run'])}")
        safe_log(f"Combined spam score: {analysis_results['spam_score']:.2f}")

    except Exception as e:
        safe_log(f"Module analysis error: {e}")

    # Include bypass flag in results for use in fake reply detection
    analysis_results['bypass_aggressive_checks'] = bypass_aggressive_checks
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

def should_block_email(analysis_results: Dict, msg: EmailMessage) -> bool:
    """Enhanced blocking logic with thread-aware thresholds and auth abuse detection"""
    try:
        spam_score = analysis_results.get('spam_score', 0.0)
        base_spam_threshold = CONFIG.config['thresholds']['spam_threshold']
        
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
        
        # Check authentication abuse
        auth_abuse_score = 0.0
        x_auth_abuse = safe_get_header(msg, 'X-Auth-Abuse-Score', '0.0')
        try:
            auth_abuse_score = float(x_auth_abuse)
        except:
            pass
        
        # Block if auth abuse is severe
        if auth_abuse_score >= CONFIG.config['thresholds']['auth_abuse_block_score']:
            safe_log(f"🚫 BLOCKED: Authentication abuse score {auth_abuse_score} exceeds threshold")
            return True
        
        # Check known scammer flag
        if safe_get_header(msg, 'X-Known-Scammer', 'false').lower() == 'true':
            safe_log("🚫 BLOCKED: Known scammer detected")
            return True
        
        # Regular spam threshold (now thread-aware)
        if spam_score >= spam_threshold:
            safe_log(f"🚫 BLOCKED: Spam score {spam_score:.2f} exceeds adjusted threshold {spam_threshold:.1f}")
            return True
        
        # Check funding spam with thread awareness
        if safe_get_header(msg, 'X-Funding-Spam', 'false').lower() == 'true':
            funding_threshold = CONFIG.config['thresholds']['funding_spam_threshold']
            # Stricter for untrusted threads
            if trust_level in ['none', 'low', 'medium']:
                funding_threshold *= 0.7
            if spam_score >= funding_threshold:
                safe_log(f"🚫 BLOCKED: Funding spam with score {spam_score:.2f} (threshold: {funding_threshold:.1f})")
                return True
        
        # Thread spam repetition check
        x_thread_spam = safe_get_header(msg, 'X-Thread-Spam-Count', '0')
        try:
            thread_spam_count = int(x_thread_spam)
            if thread_spam_count >= CONFIG.config['thresholds']['thread_spam_repetition_threshold']:
                safe_log(f"🚫 BLOCKED: Thread spam repetition count {thread_spam_count}")
                return True
        except:
            pass
        
        # Authentication failure with strict policy
        auth_results = safe_get_header(msg, 'X-SpaCy-Auth-Results', '')
        if 'dmarc=fail' in auth_results and 'p=reject' in auth_results:
            safe_log("🚫 BLOCKED: DMARC fail with reject policy")
            return True
        
        safe_log(f"✅ Email passed blocking checks - Score: {spam_score:.2f}")
        return False
        
    except Exception as e:
        safe_log(f"Error in blocking logic: {e}")
        return False

# ============================================================================
# DATABASE OPERATIONS VIA REDIS QUEUE - RESTORED
# ============================================================================

def store_email_analysis_via_queue(msg: EmailMessage, text_content: str, analysis_results: Dict, monitor: PerformanceMonitor):
    """Store email analysis via Redis queue - FIXED FORMAT"""
    if not REDIS_QUEUE or not hasattr(REDIS_QUEUE, 'connected') or not REDIS_QUEUE.connected:
        safe_log("Redis queue not available for storage")
        return
    
    try:
        # Convert EmailMessage to string for db_processor
        msg_str = msg.as_string() if hasattr(msg, 'as_string') else str(msg)
        
        # Prepare data in the format expected by db_processor
        queue_message = {
            'version': '1.0',  # Required by db_processor
            'email_data': {
                'message': msg_str,  # Full message for parsing
                'message_id': safe_get_header(msg, 'Message-ID', ''),
                'from_header': safe_get_header(msg, 'From', ''),
                'recipients': [safe_get_header(msg, 'To', '')],
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
    """Relay email to mailguard with improved encoding handling"""
    try:
        processed_domains = CONFIG.config['domains']['processed_domains']
        mailguard_host, mailguard_port = CONFIG.config['servers']['mailguard_host'], CONFIG.config['servers']['mailguard_port']
        smtp_timeout = CONFIG.config['timeouts']['smtp_timeout']
        
        validated_recipients = []
        filtered_recipients = []
        for recipient in recipients:
            try:
                if '@' in recipient:
                    domain = recipient.split('@')[1].lower()
                    if domain in processed_domains:
                        validated_recipients.append(recipient)
                    else:
                        filtered_recipients.append(recipient)
                        safe_log(f"📧 Filtering external recipient (not relaying): {recipient}")
            except Exception as e:
                safe_log(f"Error validating recipient {recipient}: {e}")
        
        if not validated_recipients:
            if filtered_recipients:
                safe_log(f"✅ All {len(filtered_recipients)} recipients were external - no relay needed")
                return True  # Return success - we've handled the email correctly by not relaying it
            else:
                safe_log("❌ No valid recipients after domain validation")
                return False
        
        if filtered_recipients:
            safe_log(f"📬 Processing mixed recipients: {len(validated_recipients)} internal, {len(filtered_recipients)} external (filtered)")
        safe_log(f"Relaying to {mailguard_host}:{mailguard_port}")
        
        with smtplib.SMTP(mailguard_host, mailguard_port, timeout=smtp_timeout) as smtp:
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
                            return False
            
            # Send the email using bytes
            smtp.sendmail(sender, validated_recipients, email_bytes)
            safe_log(f"✅ Relayed to {len(validated_recipients)} recipients")
            return True
            
    except smtplib.SMTPRecipientsRefused as e:
        safe_log(f"⚠️  Mailguard rejected recipients: {e}")
        return True
        
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

# ============================================================================
# MAIN PROCESSING FUNCTION - WITH MICROSOFT MFA BYPASS, ENCODING FIX, AND LOOP PREVENTION
# ============================================================================

def main():
    """Main email processing function - FULL FUNCTIONALITY WITH TIMEOUT HANDLING AND LOOP PREVENTION"""
    monitor = PerformanceMonitor()

    # Get envelope sender from command line arguments (passed by Postfix)
    envelope_sender = None
    if len(sys.argv) > 1:
        envelope_sender = sys.argv[1]
        safe_log(f"📧 Envelope sender from Postfix: {envelope_sender}")

    try:
        def timeout_handler(signum, frame):
            monitor.log_performance(safe_log)
            safe_log("🚨 TIMEOUT: Processing exceeded limit")
            sys.exit(124)

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(CONFIG.config['timeouts']['total_processing'])

        safe_log("=== EMAIL FILTER WITH TIMEOUT HANDLING START ===")

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
                            with smtplib.SMTP('192.168.50.37', 25, timeout=30) as smtp:
                                # Get sender
                                sender = 'msonlineservicesteam@microsoftonline.com'

                                # CRITICAL FIX: Use raw bytes directly for Microsoft MFA
                                # This preserves the original encoding without conversion issues
                                smtp.sendmail(sender, recipients, email_data)
                                safe_log(f"✅ Microsoft MFA email EMERGENCY RELAYED (raw bytes) to {recipients}")
                                sys.exit(0)  # Success!

                        except Exception as relay_error:
                            safe_log(f"⚠️ Microsoft MFA raw relay failed: {relay_error}")
                            # Try with as_bytes as fallback
                            try:
                                with smtplib.SMTP('192.168.50.37', 25, timeout=30) as smtp:
                                    smtp.sendmail(sender, recipients, msg.as_bytes())
                                    safe_log(f"✅ Microsoft MFA email EMERGENCY RELAYED (as_bytes) to {recipients}")
                                    sys.exit(0)
                            except Exception as e2:
                                safe_log(f"⚠️ Microsoft MFA as_bytes relay failed: {e2}")
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
        if len(sys.argv) > 2:
            # Postfix passes recipients as command-line arguments (after sender)
            # argv[1] is sender, argv[2+] are recipients
            cmdline_recipients = [arg for arg in sys.argv[2:] if '@' in arg]
            if cmdline_recipients:
                safe_log(f"Recipients from postfix: {cmdline_recipients}")
                # Add to message headers for later processing
                for recipient in cmdline_recipients:
                    msg['X-Postfix-Recipient'] = recipient
        
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
            
            # CRITICAL: Don't relay emails from spacy.covereddata.com back to ourselves
            if sender_domain == 'spacy.covereddata.com':
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
        
        is_journal = False
        
        # FAST-TRACK FOR TRUSTED SENDERS
        sender_domain = safe_extract_domain(from_header)
        if sender_domain in CONFIG.config['domains']['trusted_domains']:
            safe_log(f"⚡ Fast-track for trusted domain: {sender_domain}")
            
            # Add minimal headers
            safe_add_header(msg, 'X-SpaCy-Processed', datetime.datetime.now().isoformat(), monitor)
            safe_add_header(msg, 'X-SpaCy-Trusted-Domain', 'true', monitor)
            safe_add_header(msg, 'X-SpaCy-Spam-Score', '0.0', monitor)
            safe_add_header(msg, 'X-Analysis-Level', 'minimal-trusted', monitor)
            
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
                signal.alarm(0)
                sys.exit(0)
            else:
                safe_log("❌ Relay failed for trusted domain")
                signal.alarm(0)
                sys.exit(1)
        
        for received in received_headers:
            received_str = str(received)
            if ('for <journal@spacy.covereddata.com>' in received_str or 
                'for <journal@covereddata.com>' in received_str or
                'to=journal@spacy.covereddata.com' in received_str.lower()):
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
            sys.exit(0)
        
        if check_spacy_repetition(msg, from_header):
            safe_log("🚫 BLOCKED: Sender has history of SpaCy-marked emails")
            signal.alarm(0)
            sys.exit(0)
        
        recipients = extract_all_recipients(msg)
        
        # Check if we have any valid recipients for our domains
        if not recipients:
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
                safe_log(f"🔍 Checking blocking rules for sender IP: {sender_ip}")
            
            # Import blocking module
            from modules.email_blocking import check_email_blocking
            
            # Check each recipient for blocking rules
            blocked_recipients = []
            allowed_recipients = []
            
            # Use envelope sender for blocking checks if available, fallback to from_header
            blocking_sender = envelope_sender if envelope_sender else from_header
            safe_log(f"🔍 Checking blocking for {len(recipients)} recipients using sender: {blocking_sender}")
            for recipient in recipients:
                safe_log(f"🔍 Checking blocking for recipient: {recipient}, sender: {blocking_sender}, IP: {sender_ip}")
                should_block, reason = check_email_blocking(recipient, blocking_sender, sender_ip)
                safe_log(f"🔍 Blocking result for {recipient}: should_block={should_block}, reason={reason}")
                
                if should_block:
                    blocked_recipients.append(recipient)
                    safe_log(f"🚫 BLOCKED for {recipient}: {reason}")
                    safe_add_header(msg, 'X-SpaCy-Blocked', f"{recipient}: {reason}", monitor)
                else:
                    allowed_recipients.append(recipient)
            
            # If all recipients are blocked, reject the email
            if blocked_recipients and not allowed_recipients:
                safe_log(f"🚫 ALL RECIPIENTS BLOCKED - Rejecting email from {from_header}")
                safe_add_header(msg, 'X-SpaCy-Status', 'BLOCKED', monitor)
                signal.alarm(0)
                # Exit with code 69 (EX_UNAVAILABLE) for permanent rejection
                # This tells Postfix to reject permanently and remove from queue
                sys.exit(99)
            
            # Update recipients list to only include allowed recipients
            if blocked_recipients:
                recipients = allowed_recipients
                safe_log(f"✅ Allowing delivery to: {allowed_recipients}")
                safe_log(f"🚫 Blocked delivery to: {blocked_recipients}")
                
        except ImportError as e:
            safe_log(f"⚠️  Blocking module not available: {e}")
            import traceback
            safe_log(f"⚠️  Import error traceback: {traceback.format_exc()}")
        except Exception as e:
            safe_log(f"⚠️  Error checking blocking rules: {e}")
            import traceback
            safe_log(f"⚠️  Error traceback: {traceback.format_exc()}")
            # Continue processing on error - fail open
        
        # Detect original authentication
        auth_status = detect_original_authentication(msg, from_header)
        safe_add_header(msg, 'X-Original-Auth-SPF', auth_status['spf'], monitor)
        safe_add_header(msg, 'X-Original-Auth-DKIM', auth_status['dkim'], monitor)
        safe_add_header(msg, 'X-Original-Auth-DMARC', auth_status['dmarc'], monitor)
        
        # Perform real authentication if enabled
        auth_results = perform_real_authentication(msg, from_header, monitor)
        safe_log(f"📧 Auth completed, generating headers...")
        
        # Generate Authentication-Results header
        auth_header = f"spacy.covereddata.com; spf={auth_results['spf']}; dkim={auth_results['dkim']}; dmarc={auth_results['dmarc']}"
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
        analysis_results = analyze_email_with_modules(msg, text_content, from_header, monitor, auth_results)
        
        # Add authentication abuse score to spam score
        analysis_results['spam_score'] += auth_abuse['abuse_score']
        
        # Add thread info to analysis results for thread-aware blocking
        analysis_results['thread_info'] = thread_info

        # NEW: Apply fake reply spam boost (skip if sender has bypass_bec_checks)
        bypass_aggressive_checks = analysis_results.get('bypass_aggressive_checks', False)
        if not bypass_aggressive_checks:
            try:
                from modules.thread_awareness_enhanced import EnhancedThreadAnalyzer
                analyzer = EnhancedThreadAnalyzer()
                fake_reply_boost = analyzer.get_spam_score_boost(thread_info)
                if fake_reply_boost > 0:
                    analysis_results['spam_score'] += fake_reply_boost
                    safe_add_header(msg, 'X-Fake-Reply-Spam-Boost', str(fake_reply_boost), monitor)
                    safe_log(f"📈 Added {fake_reply_boost:.1f} spam points for fake reply")
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

        # Store in database via Redis queue - RESTORED
        if REDIS_QUEUE and hasattr(REDIS_QUEUE, 'connected') and REDIS_QUEUE.connected:
            try:
                store_email_analysis_via_queue(msg, text_content, analysis_results, monitor)
                safe_log("✅ Analysis queued for database storage")
            except Exception as e:
                safe_log(f"Queue storage error: {e}")
        
        # Add analysis headers
        safe_add_header(msg, 'X-SpaCy-Spam-Score', str(analysis_results['spam_score']), monitor)
        safe_add_header(msg, 'X-SpaCy-Processed', datetime.datetime.now().isoformat(), monitor)
        safe_add_header(msg, 'X-Analysis-Modules', ', '.join(analysis_results['modules_run']), monitor)
        
        for header_name, header_value in analysis_results.get('headers_to_add', {}).items():
            safe_add_header(msg, header_name, header_value, monitor)
        
        monitor.record_final_score(analysis_results['spam_score'])
        
        # Add minimal thread headers even if analysis fails
        if thread_info['is_reply']:
            try:
                subject = safe_get_header(msg, 'Subject', '')
                is_reply = subject.startswith('Re:')
                
                safe_add_header(msg, 'X-Thread-Is-Reply', 'true' if is_reply else 'false', monitor)
                safe_add_header(msg, 'X-Thread-Trust-Score', '1' if is_reply else '0', monitor)
                safe_add_header(msg, 'X-Thread-Analysis', 'disabled', monitor)
                
            except Exception as e:
                safe_log(f"🧵 Minimal headers failed: {e}")
        
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
        
        # Enhanced blocking logic with RESTORED thread awareness + FUNDING SPAM + AUTH ABUSE
        safe_log(f"🔍 Checking if email should be blocked - spam_score: {analysis_results['spam_score']:.2f}")
        if should_block_email(analysis_results, msg):
            safe_log("🚫 Email blocked by enhanced detection (including auth abuse)")
            monitor.log_performance(safe_log)
            signal.alarm(0)
            sys.exit(0)
        else:
            # Email passed checks - relay to MailGuard
            safe_log(f"✅ Email passed SpaCy checks - Score: {analysis_results['spam_score']:.2f}")

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

            safe_log("🚀 STARTING RELAY BLOCK")

            # Relay to MailGuard
            try:
                safe_log("🚀 Inside relay try block")
                mailguard_host = CONFIG.config['servers']['mailguard_host']
                mailguard_port = CONFIG.config['servers']['mailguard_port']

                safe_log(f"Relaying to {mailguard_host}:{mailguard_port}")

                with smtplib.SMTP(mailguard_host, mailguard_port, timeout=CONFIG.config['timeouts']['smtp_timeout']) as smtp:
                    smtp.sendmail(envelope_sender, recipients, msg.as_bytes())
                    safe_log(f"✅ Email relayed to MailGuard for {len(recipients)} recipients")

                monitor.log_performance(safe_log)
                signal.alarm(0)
                sys.exit(0)

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

safe_log("=== EMAIL FILTER WITH TIMEOUT HANDLING END ===")

