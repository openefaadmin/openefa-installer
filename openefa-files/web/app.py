#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_caching import Cache
from flask_compress import Compress
from sqlalchemy import create_engine, text
import os
import json
import pandas as pd
from datetime import datetime, timedelta
import io
import csv
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64
import tempfile
import configparser
import logging
import sys
import signal
import traceback
import time
from threading import Thread, Event
from dotenv import load_dotenv

# Add parent directory to path for modules/ directory access
sys.path.insert(0, '/opt/spacyserver')
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Set up logging FIRST before any other imports that might use it
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/opt/spacyserver/logs/spacyweb.log')
    ]
)
logger = logging.getLogger(__name__)

# Import authentication system
from auth import init_auth, get_db_connection, extract_domains_from_recipients, get_domain_filter_condition, admin_required, domain_admin_required, superadmin_required
import smtplib
from email.message import EmailMessage

# Import security validators for SQL injection prevention
from security_validators import validate_email, validate_domain, validate_email_list, validate_date_string, get_user_email_filter_conditions
import secrets
import string
import bcrypt

# Enhanced report system import
from enhanced_report_system import EnhancedEmailReportGenerator

# VIP Alert system import (optional - premium module)
try:
    from modules.vip_alerts import VIPAlertSystem
    VIP_ALERTS_AVAILABLE = True
except ImportError:
    VIP_ALERTS_AVAILABLE = False
    VIPAlertSystem = None

# Configuration paths
MY_CNF_PATH = "/etc/spacy-server/.my.cnf"
APP_CONFIG_PATH = "/opt/spacyserver/config/.app_config.ini"
DB_NAME = os.getenv('DB_NAME', 'spacy_email_db')
DB_USER = os.getenv('DB_USER', 'spacy_user')
DB_HOST = os.getenv('DB_HOST', 'localhost')
HOST = "localhost"

# Centralized hosted domains configuration
# This will be populated from database at startup via get_hosted_domains()
# Empty default - domains are loaded dynamically from database
HOSTED_DOMAINS = []

def get_hosted_domains():
    """
    Dynamically fetch active domains from database.
    Called at app startup to populate HOSTED_DOMAINS list.
    This makes the system configuration-driven instead of hardcoded.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT domain
            FROM client_domains
            WHERE active = 1
            ORDER BY domain
        """)
        domains = [row['domain'] for row in cursor.fetchall()]
        cursor.close()
        conn.close()
        return domains
    except Exception as e:
        logger.error(f"Failed to load hosted domains from database: {e}")
        # Return empty list on failure - will be populated when DB is available
        return []

def get_spam_threshold():
    """
    Get spam threshold from environment variable or database.
    Priority: 1. Environment variable, 2. Database config, 3. Default (10.0)
    This ensures consistency between email filter and web UI.
    """
    # First try environment variable (same as email_filter.py uses)
    env_threshold = os.getenv('SPACY_SPAM_THRESHOLD')
    if env_threshold:
        try:
            return float(env_threshold)
        except ValueError:
            logger.warning(f"Invalid SPACY_SPAM_THRESHOLD in environment: {env_threshold}")

    # Fall back to database config
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT config_value
            FROM quarantine_config
            WHERE config_key = 'spam_threshold'
            LIMIT 1
        """)
        result = cursor.fetchone()
        cursor.close()
        conn.close()

        if result:
            return float(result['config_value'])
    except Exception as e:
        logger.warning(f"Failed to load spam threshold from database: {e}")

    # Default fallback
    return 10.0

def reload_hosted_domains():
    """
    Reload HOSTED_DOMAINS from database.
    Call this after add/edit/delete domain operations to make changes immediate.
    """
    global HOSTED_DOMAINS
    try:
        new_domains = get_hosted_domains()
        HOSTED_DOMAINS = new_domains
        logger.info(f"Reloaded {len(HOSTED_DOMAINS)} hosted domains from database")
        logger.info(f"Active domains: {', '.join(HOSTED_DOMAINS)}")
        # Clear all caches when domains change
        cache.clear()
        logger.info("Cleared all caches due to domain reload")
        return True
    except Exception as e:
        logger.error(f"Failed to reload hosted domains: {e}")
        return False

def update_postfix_transport():
    """
    Update Postfix transport file from database.
    Reads all active domains with relay_hosts and writes to /etc/postfix/transport
    """
    import subprocess
    transport_file = '/etc/postfix/transport'

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all active domains with relay hosts
        cursor.execute("""
            SELECT domain, relay_host
            FROM client_domains
            WHERE active = 1 AND relay_host IS NOT NULL AND relay_host != ''
            ORDER BY domain
        """)

        domains = cursor.fetchall()
        cursor.close()
        conn.close()

        # Build transport file content
        lines = [
            "# OpenEFA Transport Map",
            "# Routes configured domains to relay server",
            "# Auto-generated from database - do not edit manually",
            ""
        ]

        for domain_row in domains:
            domain = domain_row['domain']
            relay_host = domain_row['relay_host']
            lines.append(f"{domain}    smtp:[{relay_host}]")

        # Write transport file
        with open(transport_file, 'w') as f:
            f.write('\n'.join(lines) + '\n')

        # Run postmap to compile the transport map (requires sudo)
        result = subprocess.run(['sudo', '/usr/sbin/postmap', transport_file],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Reload Postfix to apply changes (requires sudo)
            reload_result = subprocess.run(['sudo', '/usr/sbin/postfix', 'reload'],
                                          capture_output=True, text=True, timeout=10)

            if reload_result.returncode == 0:
                logger.info(f"Updated Postfix transport file with {len(domains)} domains and reloaded Postfix")
                return True
            else:
                logger.warning(f"Transport updated but Postfix reload failed: {reload_result.stderr}")
                return True  # Still return True since transport was updated
        else:
            logger.error(f"postmap failed: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Failed to update Postfix transport: {e}")
        return False

def update_postfix_relay_domains():
    """
    Update Postfix relay_domains configuration from database.
    Reads all active domains and updates relay_domains in /etc/postfix/main.cf
    """
    import subprocess

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all active domains
        cursor.execute("""
            SELECT domain
            FROM client_domains
            WHERE active = 1
            ORDER BY domain
        """)

        domains = cursor.fetchall()
        cursor.close()
        conn.close()

        # Build relay_domains list with validation to prevent command injection
        # Valid domain pattern: alphanumeric, hyphens, dots only
        domain_pattern = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', re.IGNORECASE)
        validated_domains = []

        for domain_row in domains:
            domain = domain_row['domain']
            if domain_pattern.match(domain):
                validated_domains.append(domain)
            else:
                logger.warning(f"Invalid domain rejected from relay_domains: {domain}")

        if not validated_domains:
            logger.error("No valid domains found for relay_domains configuration")
            return False

        relay_domains_value = ', '.join(validated_domains)

        # Update relay_domains in main.cf using postconf
        # shell=False ensures no shell interpretation of command
        result = subprocess.run(['sudo', 'postconf', '-e', f'relay_domains={relay_domains_value}'],
                              capture_output=True, text=True, timeout=10, shell=False)

        if result.returncode == 0:
            # Reload Postfix to apply changes
            reload_result = subprocess.run(['sudo', '/usr/sbin/postfix', 'reload'],
                                          capture_output=True, text=True, timeout=10)

            if reload_result.returncode == 0:
                logger.info(f"Updated Postfix relay_domains with {len(domains)} domains: {relay_domains_value}")
                return True
            else:
                logger.warning(f"relay_domains updated but Postfix reload failed: {reload_result.stderr}")
                return True  # Still return True since relay_domains was updated
        else:
            logger.error(f"postconf failed: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Failed to update Postfix relay_domains: {e}")
        return False

def load_app_config():
    """Load application configuration from config file"""
    try:
        if not os.path.exists(APP_CONFIG_PATH):
            logger.error(f"Configuration file not found: {APP_CONFIG_PATH}")
            raise FileNotFoundError(f"Configuration file not found: {APP_CONFIG_PATH}")
        
        config = configparser.ConfigParser()
        config.read(APP_CONFIG_PATH)
        
        if 'flask' not in config or 'secret_key' not in config['flask']:
            logger.error("Missing flask section or secret_key in config")
            raise ValueError("SECRET_KEY not found in configuration file")
        
        return config
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        raise

# Load configuration
app_config = load_app_config()

app = Flask(__name__)

# SECURITY: Explicitly enable Jinja2 autoescape for XSS protection
# This is enabled by default for .html/.htm/.xml, but explicitly setting for clarity
app.jinja_env.autoescape = True

# Configure ProxyFix for reverse proxy (Apache)
# x_for=1: trust 1 proxy for X-Forwarded-For
# x_proto=1: trust 1 proxy for X-Forwarded-Proto
# x_host=1: trust 1 proxy for X-Forwarded-Host
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Use environment variable for secret key (fallback to config file for backwards compatibility)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', app_config['flask']['secret_key'])

# Session security configuration
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Default, overridden by role
app.config['SESSION_COOKIE_NAME'] = 'guardianmail_session'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # Refresh session cookie on every request (important for mobile)

# Role-based session timeout configuration (in minutes)
ROLE_SESSION_TIMEOUTS = {
    'admin': 30,         # Superadmin: 30 minutes of inactivity
    'domain_admin': 30,  # Domain Admin: 30 minutes of inactivity
    'client': 30,        # Regular users: 30 minutes of inactivity
    'default': 30        # Fallback: 30 minutes of inactivity
}

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting - Using Redis for persistent, multi-process rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="redis://localhost:6379"
)

# Caching - Using Redis for performance optimization
cache = Cache(app, config={
    'CACHE_TYPE': 'RedisCache',
    'CACHE_REDIS_URL': 'redis://localhost:6379/1',  # Use DB 1 for cache (DB 0 for rate limiting)
    'CACHE_DEFAULT_TIMEOUT': 300,  # 5 minutes default
    'CACHE_KEY_PREFIX': 'spacy_'
})

# HTTP Compression - Brotli (best) -> gzip (good) -> deflate (fallback)
# Compresses HTML, CSS, JS, JSON responses automatically
# Can reduce bandwidth by 60-80% for text-based content
compress = Compress()
app.config['COMPRESS_ALGORITHM'] = ['br', 'gzip', 'deflate']  # Prefer Brotli, fallback to gzip
app.config['COMPRESS_BR_LEVEL'] = 4  # Brotli compression level (0-11, 4 is good balance)
app.config['COMPRESS_LEVEL'] = 6  # gzip compression level (1-9, 6 is default)
app.config['COMPRESS_MIN_SIZE'] = 500  # Only compress responses larger than 500 bytes
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/xml', 'text/plain',
    'application/json', 'application/javascript', 'application/xml'
]
compress.init_app(app)

# Content Security Policy (CSP) - ENFORCEMENT MODE with Nonces
# Generate CSP policy dynamically with nonces for each request
def get_csp_policy_with_nonce():
    """Generate CSP policy with nonce for current request"""
    from flask import g
    nonce = f"'nonce-{g.csp_nonce}'" if hasattr(g, 'csp_nonce') and g.csp_nonce else ""

    policy = {
        'default-src': ["'self'"],
        'script-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://code.jquery.com'],
        'style-src': ["'self'", "'unsafe-hashes'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
        'font-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'data:'],
        'img-src': ["'self'", 'data:', 'blob:'],
        'connect-src': ["'self'"],
        'frame-ancestors': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'object-src': ["'none'"],
    }

    # Add nonce to script-src and style-src if available
    if nonce:
        policy['script-src'].insert(1, nonce)  # Insert after 'self'
        policy['style-src'].insert(1, nonce)

    return policy

# Security Headers - Completely disabled when behind Apache reverse proxy
# Apache now handles all security headers (HSTS, X-Frame-Options, etc.) to avoid duplicates
# Talisman is disabled by wrapping with lambda to bypass all default behavior
talisman = Talisman()
# Completely disable Talisman by removing its middleware wrapper
# We don't need it since Apache handles all security headers
# Comment out Talisman entirely to avoid duplicate headers
# Talisman(app, ...) - DISABLED

# Import wraps for decorators
from functools import wraps

# Additional security headers - Set CSP manually with nonces
@app.after_request
def set_security_headers(response):
    # Talisman already sets: X-Frame-Options, X-Content-Type-Options,
    # Strict-Transport-Security, Referrer-Policy
    # We set CSP manually to support dynamic nonces

    from flask import g
    if hasattr(g, 'csp_nonce') and g.csp_nonce:
        nonce = g.csp_nonce
        csp_parts = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://code.jquery.com",
            f"style-src 'self' 'nonce-{nonce}' 'unsafe-hashes' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com data:",
            "img-src 'self' data: blob:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
            "report-uri /csp-violation-report"
        ]
        response.headers['Content-Security-Policy'] = '; '.join(csp_parts)

    # ============================================================================
    # PERFORMANCE OPTIMIZATION: Cache-Control & ETag Headers
    # ============================================================================

    # Add Cache-Control headers for static assets
    if request.path.startswith('/static/'):
        # Static assets (CSS, JS, images) - cache for 1 year with immutable
        response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    elif request.path.startswith('/api/'):
        # API responses - never cache (always fresh data)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    elif response.status_code == 200 and request.method == 'GET':
        # HTML pages - allow browser caching with revalidation
        # Browser can cache but must check if content changed (uses ETag)
        response.headers['Cache-Control'] = 'private, max-age=300, must-revalidate'

        # Generate ETag for GET requests with 200 OK status
        # ETag allows browser to skip downloading if content hasn't changed
        # Skip ETag generation for file downloads (direct passthrough mode)
        if response.direct_passthrough:
            # File download - skip ETag generation
            pass
        elif response.data:
            import hashlib
            etag = hashlib.md5(response.data).hexdigest()
            response.headers['ETag'] = f'"{etag}"'

            # Check if client sent If-None-Match header (conditional request)
            if_none_match = request.headers.get('If-None-Match')
            if if_none_match and if_none_match.strip('"') == etag:
                # Content hasn't changed - return 304 Not Modified (no body)
                response.status_code = 304
                response.data = b''

    return response

# CSP Violation Reporting Endpoint
# Receives violation reports when CSP policy is violated
# These reports help identify legitimate resources that need to be whitelisted
# or actual XSS/injection attempts
@app.route('/csp-violation-report', methods=['POST'])
@csrf.exempt  # Browsers don't send CSRF tokens with CSP reports
def csp_violation_report():
    """
    CSP violation reporting endpoint.
    Browsers automatically POST violation reports here when CSP is violated.

    IMPORTANT: This endpoint must be accessible without authentication
    since browsers send reports automatically.
    """
    try:
        # Parse the violation report
        violation_report = request.get_json(force=True)

        # Extract useful information
        csp_report = violation_report.get('csp-report', {})

        # Log the violation for security monitoring
        logger.warning(
            f"CSP Violation Detected:\n"
            f"  Blocked URI: {csp_report.get('blocked-uri', 'unknown')}\n"
            f"  Violated Directive: {csp_report.get('violated-directive', 'unknown')}\n"
            f"  Original Policy: {csp_report.get('original-policy', 'unknown')}\n"
            f"  Document URI: {csp_report.get('document-uri', 'unknown')}\n"
            f"  Source File: {csp_report.get('source-file', 'unknown')}\n"
            f"  Line Number: {csp_report.get('line-number', 'unknown')}\n"
            f"  Referrer: {csp_report.get('referrer', 'none')}"
        )

        # Optionally store violations in a file for analysis
        # (only in report-only mode to avoid disk space issues)
        try:
            with open('/opt/spacyserver/logs/csp_violations.log', 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {json.dumps(csp_report)}\n")
        except Exception as e:
            logger.error(f"Failed to write CSP violation to file: {e}")

        # Return 204 No Content (standard response for CSP reports)
        return '', 204

    except Exception as e:
        logger.error(f"Error processing CSP violation report: {e}")
        # Still return 204 to prevent browser retries
        return '', 204

# Initialize authentication with rate limiter
login_manager = init_auth(app, limiter)

# Initialize VIP Alert System (if available - premium module)
if VIP_ALERTS_AVAILABLE:
    vip_alert_system = VIPAlertSystem()
else:
    vip_alert_system = None

# Register blueprints
from whitelist_import import whitelist_import_bp
app.register_blueprint(whitelist_import_bp)

# Role-based session timeout middleware
@app.before_request
def manage_session_timeout():
    """
    Enforce role-based session timeouts and activity tracking.
    - All roles: 30 minutes of inactivity
    - Automatic logout on timeout
    - User-friendly timeout message displayed
    """
    from flask_login import current_user
    from flask import session

    # Skip for non-authenticated requests
    if not current_user.is_authenticated:
        return

    # SECURITY: Session binding to prevent session hijacking
    # Bind session to IP address and User-Agent
    current_ip = request.remote_addr
    current_ua = request.headers.get('User-Agent', '')

    session_ip = session.get('_session_ip')
    session_ua = session.get('_session_ua')

    if session_ip and session_ua:
        # Verify session hasn't been hijacked (IP or UA mismatch)
        if session_ip != current_ip:
            logger.warning(f"Session hijacking attempt detected for {current_user.email}: IP mismatch ({session_ip} != {current_ip})")
            from flask_login import logout_user
            logout_user()
            session.clear()
            flash('Session security error: Please log in again.', 'error')
            return redirect(url_for('auth.login'))

        # Note: User-Agent can change legitimately (browser updates), so we only log mismatches
        if session_ua != current_ua:
            logger.info(f"User-Agent change detected for {current_user.email}: Old: {session_ua[:100]}, New: {current_ua[:100]}")

    else:
        # First time binding session to IP and UA
        session['_session_ip'] = current_ip
        session['_session_ua'] = current_ua
        logger.info(f"Session bound to IP {current_ip} for user {current_user.email}")

    # Get role-specific timeout
    user_role = current_user.role if hasattr(current_user, 'role') else 'client'
    timeout_minutes = ROLE_SESSION_TIMEOUTS.get(user_role, ROLE_SESSION_TIMEOUTS['default'])

    # Check last activity time
    now = datetime.now()
    last_activity = session.get('last_activity')

    # Detect mobile device from User-Agent
    user_agent = request.headers.get('User-Agent', '')
    is_mobile = any(device in user_agent.lower() for device in ['iphone', 'ipad', 'android', 'mobile'])

    if last_activity:
        # Convert string back to datetime if needed
        if isinstance(last_activity, str):
            try:
                last_activity = datetime.fromisoformat(last_activity)
            except Exception as e:
                logger.warning(f"Failed to parse last_activity timestamp: {e}")
                last_activity = now  # Reset to now if parsing fails

        # Calculate time since last activity
        inactive_time = now - last_activity
        max_inactive = timedelta(minutes=timeout_minutes)

        # Session activity logging (only log if inactive > 1 minute to reduce noise)
        if inactive_time.total_seconds() > 60:
            device_type = "Mobile" if is_mobile else "Desktop"
            logger.info(f"Session check - User: {current_user.email}, Device: {device_type}, Inactive: {inactive_time.total_seconds()/60:.1f}min, Max: {timeout_minutes}min")

        # Force logout if session expired
        if inactive_time > max_inactive:
            device_type = "Mobile" if is_mobile else "Desktop"
            logger.info(f"Session timeout - User {current_user.email} ({device_type}) inactive for {inactive_time.total_seconds()/60:.1f} minutes")
            from flask_login import logout_user
            logout_user()
            session.clear()
            flash(f'Your session expired after {timeout_minutes} minutes of inactivity.', 'warning')
            return redirect(url_for('auth.login'))

    # Update last activity time and role info
    session['last_activity'] = now.isoformat()
    session['user_role'] = user_role
    session['session_timeout_minutes'] = timeout_minutes
    session.permanent = True

    # Set session lifetime based on role (for cookie expiration)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=timeout_minutes)

# Generate CSP nonce for each request BEFORE template rendering
@app.before_request
def generate_csp_nonce():
    """Generate a unique CSP nonce for each request"""
    from flask import g
    g.csp_nonce = secrets.token_hex(16)

# Make CSP nonce available to all templates
@app.context_processor
def inject_csp_nonce():
    """Inject CSP nonce into all template contexts"""
    from flask import g
    return dict(csp_nonce=g.get('csp_nonce', ''))

# Debug mode decorator
def debug_only(f):
    """Decorator to restrict routes to debug mode only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        debug_enabled = os.getenv('DEBUG_MODE', 'False').lower() == 'true'
        if not debug_enabled:
            logger.warning(f"Attempted access to debug route: {request.path}")
            return jsonify({'error': 'Not found'}), 404
        return f(*args, **kwargs)
    return decorated_function

# Template context processor
@app.context_processor
def inject_user():
    """Make current_user and user's domains available in all templates"""
    context = dict(current_user=current_user)

    # Add user domains and selected domain for navigation
    if current_user.is_authenticated:
        user_domains = get_user_authorized_domains(current_user)
        context['user_domains'] = user_domains
        # Get selected domain from request args or use first domain
        context['selected_domain'] = request.args.get('domain', user_domains[0] if user_domains else 'default')
    else:
        context['user_domains'] = []
        context['selected_domain'] = 'default'

    return context

# Template filters for JSON handling
@app.template_filter('tojson')
def to_json_filter(value):
    """Convert a string to JSON format safely"""
    return json.dumps(value)

@app.template_filter('fromjson')
def from_json_filter(value):
    """Parse a JSON string safely"""
    try:
        return json.loads(value)
    except:
        return [value]

@app.template_filter('abs')
def abs_filter(value):
    """Return absolute value"""
    try:
        return abs(value)
    except (TypeError, ValueError):
        return 0

@app.template_filter('userdate')
def user_date_filter(value, format_type='short'):
    """
    Format date according to current user's preference (US or UK format)
    format_type can be: 'short' (date only), 'long' (date and time), 'time' (time only)
    """
    from flask_login import current_user
    from datetime import datetime

    if not value:
        return ''

    # Convert string to datetime if needed
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except:
            return value

    # Get user's date format preference (default to US)
    date_format_pref = 'US'
    try:
        if current_user and current_user.is_authenticated:
            date_format_pref = getattr(current_user, 'date_format', 'US') or 'US'
    except:
        pass

    # Format based on preference
    if format_type == 'short':
        # Short date format
        if date_format_pref == 'UK':
            return value.strftime('%d/%m/%Y')  # 28/10/2025
        else:
            return value.strftime('%m/%d/%Y')  # 10/28/2025
    elif format_type == 'long':
        # Long date and time format
        if date_format_pref == 'UK':
            return value.strftime('%d/%m/%Y %H:%M')  # 28/10/2025 15:30
        else:
            return value.strftime('%m/%d/%Y %I:%M %p')  # 10/28/2025 03:30 PM
    elif format_type == 'time':
        # Time only
        if date_format_pref == 'UK':
            return value.strftime('%H:%M')  # 15:30
        else:
            return value.strftime('%I:%M %p')  # 03:30 PM
    else:
        # Default to short
        if date_format_pref == 'UK':
            return value.strftime('%d/%m/%Y')
        else:
            return value.strftime('%m/%d/%Y')

@app.template_filter('striphtml')
def strip_html_filter(value):
    """Properly strip HTML tags including style and script content"""
    import re
    import html as html_module

    if not value:
        return ''

    value = str(value)

    # Remove style and script tags AND their contents
    value = re.sub(r'<style[^>]*>.*?</style>', '', value, flags=re.DOTALL|re.IGNORECASE)
    value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.DOTALL|re.IGNORECASE)

    # Remove all remaining HTML tags
    value = re.sub(r'<[^>]+>', '', value)

    # Decode HTML entities
    value = html_module.unescape(value)

    # Clean up excessive whitespace
    value = re.sub(r'\n\s*\n+', '\n\n', value)
    value = re.sub(r' +', ' ', value)

    return value.strip()

def validate_email_file_path(path):
    """
    Validate email file path to prevent directory traversal attacks.

    Args:
        path: File path from database

    Returns:
        str: Validated absolute path or None if invalid
    """
    if not path:
        return None

    # Define allowed directories for email storage
    allowed_dirs = [
        '/var/spool/spacy-emails/',
        '/opt/spacyserver/email_storage/',
        '/tmp/spacy-emails/'
    ]

    try:
        # Resolve to absolute path (resolves symlinks and .. references)
        real_path = os.path.realpath(path)

        # Check if path is within allowed directories
        path_is_safe = any(real_path.startswith(os.path.realpath(allowed_dir))
                          for allowed_dir in allowed_dirs)

        if not path_is_safe:
            logger.error(f"Path traversal attempt blocked: {path} -> {real_path}")
            return None

        # Ensure file exists and is a regular file (not directory, symlink, etc.)
        if not os.path.isfile(real_path):
            logger.warning(f"Email file not found or not a regular file: {real_path}")
            return None

        return real_path

    except Exception as e:
        logger.error(f"Path validation error for {path}: {e}")
        return None

def validate_email_id(email_id):
    """
    Validate email ID parameter to prevent injection and invalid values.

    Args:
        email_id: Email ID from request (int or string)

    Returns:
        int: Validated positive integer email ID

    Raises:
        ValueError: If email_id is invalid
    """
    try:
        email_id = int(email_id)
        if email_id < 1:
            raise ValueError("Email ID must be positive")
        if email_id > 2147483647:  # MySQL INT max
            raise ValueError("Email ID exceeds maximum value")
        return email_id
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid email ID parameter: {email_id}")
        raise ValueError(f"Invalid email ID: {email_id}")

def safe_json_parse(json_str, default=None):
    """
    Safely parse JSON string with validation.

    Args:
        json_str: JSON string to parse
        default: Default value if parsing fails

    Returns:
        Parsed JSON object or default value
    """
    if not json_str:
        return default

    try:
        if not isinstance(json_str, str):
            return json_str

        parsed = json.loads(json_str)

        # Validate parsed object is expected type
        if parsed is None:
            return default

        return parsed
    except json.JSONDecodeError as e:
        logger.warning(f"JSON parse error: {e}")
        return default
    except Exception as e:
        logger.error(f"Unexpected error parsing JSON: {e}")
        return default

def sanitize_email_address(email):
    """
    Sanitize email address to prevent SMTP header injection.

    Args:
        email: Email address string

    Returns:
        str: Sanitized email address

    Raises:
        ValueError: If email is invalid
    """
    if not email:
        raise ValueError("Email address is required")

    # Remove CRLF and other control characters that could inject headers
    sanitized = re.sub(r'[\r\n\x00\x08\x0B\x0C]', '', str(email))

    # Validate email format (basic validation)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, sanitized):
        raise ValueError(f"Invalid email format: {email}")

    return sanitized

def sanitize_error_message(error):
    """
    Sanitize error messages to prevent information disclosure.

    Args:
        error: Exception or error string

    Returns:
        str: Sanitized error message safe for user display
    """
    error_str = str(error)

    # List of sensitive patterns to redact
    sensitive_patterns = [
        (r'/opt/spacyserver/[^\s]+', '[REDACTED_PATH]'),  # File paths
        (r'/var/[^\s]+', '[REDACTED_PATH]'),
        (r'/etc/[^\s]+', '[REDACTED_PATH]'),
        (r'password[^\s]*', '[REDACTED]'),  # Password mentions
        (r'secret[^\s]*', '[REDACTED]'),
        (r'key[^\s]*=[\w\d]+', 'key=[REDACTED]'),  # API keys
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[REDACTED_IP]'),  # IP addresses
        (r'SELECT .* FROM', 'SELECT [REDACTED] FROM'),  # SQL queries
        (r'UPDATE .* SET', 'UPDATE [REDACTED] SET'),
        (r'INSERT INTO .*VALUES', 'INSERT INTO [REDACTED] VALUES'),
    ]

    sanitized = error_str
    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

    # If error is too detailed, return generic message
    if len(sanitized) > 200 or 'Traceback' in sanitized:
        return 'An internal error occurred. Please contact your administrator.'

    return sanitized

def get_raw_email_content(email):
    """
    Get raw email content from either database or disk storage.
    Supports hybrid storage: <20MB in database, >20MB on disk.

    Args:
        email: Dict with 'raw_email' and 'raw_email_path' keys

    Returns:
        str: Raw email content or None if not available
    """
    # Check if stored on disk (>20MB emails)
    if email.get('raw_email_path'):
        # Validate path to prevent directory traversal
        safe_path = validate_email_file_path(email['raw_email_path'])
        if not safe_path:
            logger.error(f"Invalid or unsafe email file path: {email['raw_email_path']}")
            return None

        try:
            with open(safe_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read email from disk {safe_path}: {e}")
            return None

    # Otherwise return from database (<=20MB emails)
    return email.get('raw_email')

def extract_receiving_domains(recipients_string):
    """Extract unique domains from recipients string"""
    if not recipients_string:
        return []

    # Split by semicolon or comma to handle multiple recipients
    emails = re.split(r'[;,]', recipients_string)
    domains = set()

    for email in emails:
        email = email.strip()
        if '@' in email:
            domain = email.split('@')[1].strip()
            domains.add(domain)

    return sorted(list(domains))

def get_primary_receiving_domain(recipients_string):
    """Get the primary (first) receiving domain"""
    domains = extract_receiving_domains(recipients_string)
    return domains[0] if domains else 'unknown'

def get_relay_info_from_logs(message_id):
    """
    Parse Postfix mail logs to get relay/delivery information for an email.
    Returns dict with relay details or None if not found.
    """
    logger.info(f"DEBUG: get_relay_info_from_logs called with message_id: {message_id}")

    if not message_id:
        logger.info("DEBUG: message_id is None or empty")
        return None

    # Clean message_id (remove < > if present)
    clean_message_id = message_id.strip('<>')
    logger.info(f"DEBUG: clean_message_id: {clean_message_id}")

    try:
        import subprocess
        import re

        # Check common mail log locations
        log_files = ['/var/log/mail.log', '/var/log/maillog']

        for log_file in log_files:
            logger.info(f"DEBUG: Checking log file: {log_file}")
            if not os.path.exists(log_file):
                logger.info(f"DEBUG: Log file does not exist: {log_file}")
                continue

            try:
                # Step 1: Find the queue ID by searching for message-id
                logger.info(f"DEBUG: Running grep for message_id in {log_file}")
                result = subprocess.run(
                    ['grep', '-F', clean_message_id, log_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                logger.info(f"DEBUG: grep returncode: {result.returncode}, stdout length: {len(result.stdout) if result.stdout else 0}")

                if result.returncode != 0 or not result.stdout:
                    logger.info(f"DEBUG: No match found in {log_file}, continuing")
                    continue

                # Extract queue ID from the message-id line
                queue_id = None
                for line in result.stdout.strip().split('\n'):
                    queue_match = re.search(r'postfix/[^:]+: ([A-F0-9]+):', line)
                    if queue_match:
                        queue_id = queue_match.group(1)
                        logger.info(f"DEBUG: Found queue_id: {queue_id}")
                        break

                if not queue_id:
                    logger.info("DEBUG: Could not extract queue_id from grep results")
                    continue

                # Step 2: Now search for all lines with that queue ID
                result2 = subprocess.run(
                    ['grep', '-F', queue_id, log_file],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result2.returncode != 0 or not result2.stdout:
                    continue

                lines = result2.stdout.strip().split('\n')

                # Parse relay information
                relay_info = {
                    'found': True,
                    'status': None,
                    'relay_host': None,
                    'relay_ip': None,
                    'delivered_time': None,
                    'recipient': None,
                    'queue_id': queue_id,
                    'delay': None,
                    'dsn': None,
                    'upstream_queue_id': None
                }

                for line in lines:
                    # Look for status=sent line which has delivery info
                    if 'status=sent' in line or 'status=deferred' in line or 'status=bounced' in line:
                        # Extract status
                        if 'status=sent' in line:
                            relay_info['status'] = 'delivered'
                        elif 'status=deferred' in line:
                            relay_info['status'] = 'deferred'
                        elif 'status=bounced' in line:
                            relay_info['status'] = 'bounced'

                        # Extract timestamp (beginning of line)
                        time_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                        if time_match:
                            relay_info['delivered_time'] = time_match.group(1)

                        # Extract recipient
                        to_match = re.search(r'to=<([^>]+)>', line)
                        if to_match:
                            relay_info['recipient'] = to_match.group(1)

                        # Extract relay host
                        relay_match = re.search(r'relay=([^,\s]+)', line)
                        if relay_match:
                            relay_host = relay_match.group(1)
                            # If relay is spacyfilter, get the actual upstream relay from transport map
                            if relay_host == 'spacyfilter':
                                try:
                                    import socket
                                    # Get recipient domain from the relay_info
                                    recipient_email = relay_info.get('recipient', '')
                                    if '@' in recipient_email:
                                        recipient_domain = recipient_email.split('@')[1]

                                        # Read Postfix transport map to get actual relay destination
                                        transport_file = '/etc/postfix/transport'
                                        if os.path.exists(transport_file):
                                            with open(transport_file, 'r') as tf:
                                                for transport_line in tf:
                                                    if transport_line.strip() and not transport_line.startswith('#'):
                                                        parts = transport_line.strip().split()
                                                        if len(parts) >= 2 and parts[0] == recipient_domain:
                                                            # Extract relay from smtp:[host] format
                                                            relay_entry = parts[1]
                                                            host_match = re.search(r'smtp:\[([^\]]+)\]', relay_entry)
                                                            if host_match:
                                                                upstream_host = host_match.group(1)

                                                                # Get port from database for this domain
                                                                domain_port = 25  # default
                                                                try:
                                                                    db_cursor = get_db_connection().cursor(dictionary=True)
                                                                    db_cursor.execute("SELECT relay_port FROM client_domains WHERE domain = %s AND active = 1", (recipient_domain,))
                                                                    domain_row = db_cursor.fetchone()
                                                                    if domain_row and domain_row.get('relay_port'):
                                                                        domain_port = domain_row['relay_port']
                                                                    db_cursor.close()
                                                                except Exception as db_err:
                                                                    logger.debug(f"Could not get relay port from database: {db_err}")

                                                                # Try to resolve hostname
                                                                try:
                                                                    hostname = socket.gethostbyaddr(upstream_host)[0]
                                                                    relay_info['relay_host'] = f"{hostname} ({upstream_host}:{domain_port})"
                                                                except (socket.herror, socket.gaierror):
                                                                    # DNS resolution failed, just show IP:port
                                                                    relay_info['relay_host'] = f"{upstream_host}:{domain_port}"
                                                                break

                                        # If we didn't find it in transport map, show generic message
                                        if not relay_info.get('relay_host') or relay_info['relay_host'] == relay_host:
                                            relay_info['relay_host'] = f"Mail Server (domain: {recipient_domain})"
                                    else:
                                        relay_info['relay_host'] = relay_host
                                except Exception as e:
                                    logger.warning(f"Could not get domain relay info from transport map: {e}")
                                    relay_info['relay_host'] = relay_host
                            else:
                                relay_info['relay_host'] = relay_host

                        # Extract relay IP if present
                        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
                        if ip_match:
                            relay_info['relay_ip'] = ip_match.group(1)

                        # Extract delay
                        delay_match = re.search(r'delay=([\d.]+)', line)
                        if delay_match:
                            relay_info['delay'] = delay_match.group(1)

                        # Extract DSN
                        dsn_match = re.search(r'dsn=([\d.]+)', line)
                        if dsn_match:
                            relay_info['dsn'] = dsn_match.group(1)

                # Search for upstream queue ID in journalctl logs
                # The queue_id and upstream queue ID are logged by the same process but on different lines
                if queue_id and relay_info.get('delivered_time'):
                    try:
                        # Search logs around the delivery time for the upstream queue ID
                        # Get timestamp from delivered_time and search +/- 30 seconds
                        from datetime import datetime, timedelta
                        delivery_dt = datetime.fromisoformat(relay_info['delivered_time'])
                        since_time = (delivery_dt - timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')
                        until_time = (delivery_dt + timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')

                        # Search narrower time range for better performance
                        upstream_result = subprocess.run(
                            f"journalctl --since '{since_time}' --until '{until_time}' | grep '📬 Upstream Queue ID'",
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if upstream_result.returncode == 0 and upstream_result.stdout:
                            # Extract upstream queue ID from the matched line
                            # Format: "📬 Upstream Queue ID: F3AEE2005ED0"
                            match = re.search(r'📬 Upstream Queue ID:\s+(.+?)(?:\n|$)', upstream_result.stdout)
                            if match:
                                relay_info['upstream_queue_id'] = match.group(1).strip()
                                logger.info(f"Found upstream queue ID: {relay_info['upstream_queue_id']}")
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Timeout searching for upstream queue ID for {queue_id}")
                    except Exception as upstream_err:
                        logger.warning(f"Could not extract upstream queue ID: {upstream_err}")

                logger.info(f"Relay info status: {relay_info['status']}, relay_host: {relay_info.get('relay_host')}")
                if relay_info['status']:
                    return relay_info
                else:
                    logger.warning(f"No status found in relay_info for {message_id}, checked {len(lines)} lines")

            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout searching mail logs for message_id: {message_id}")
                continue
            except Exception as e:
                logger.warning(f"Error parsing mail log {log_file}: {e}")
                continue

        return None

    except Exception as e:
        logger.error(f"Error getting relay info from logs: {e}")
        return None

def get_db_engine():
    """Create and return a database engine for MariaDB with connection pooling"""
    try:
        if not os.path.exists(MY_CNF_PATH):
            logger.error(f"MySQL config file not found: {MY_CNF_PATH}")
            return None
        db_url = f"mysql+pymysql://{HOST}/{DB_NAME}?read_default_file={MY_CNF_PATH}"
        # Add connection pooling and recycling
        engine = create_engine(
            db_url,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600,  # Recycle connections after 1 hour
            pool_pre_ping=True  # Test connections before using
        )
        return engine
    except Exception as e:
        logger.error(f"Failed to create database engine: {e}")
        return None

def get_column_info():
    """Get information about available columns in the database"""
    engine = get_db_engine()
    if not engine:
        return None

    try:
        with engine.connect() as conn:
            # Check which columns exist
            columns = conn.execute(text("DESCRIBE email_analysis")).fetchall()
            column_names = [col[0] for col in columns]

            schema_info = {
                'has_lang_col': 'detected_language' in column_names,
                'has_category': 'email_category' in column_names,
                'has_enhanced_sentiment': all(col in column_names for col in
                    ['sentiment_polarity', 'sentiment_subjectivity', 'sentiment_extremity']),
                'has_manipulation': 'sentiment_manipulation' in column_names,
                'has_recipients': 'recipients' in column_names,
            }

            return schema_info
    except Exception as e:
        print(f"Error getting column info: {e}")
        return None

@cache.memoize(timeout=300)  # Cache for 5 minutes per user
def get_user_authorized_domains(user):
    """Get list of domains user is authorized to access"""
    if user.is_admin():
        # Admins can see all hosted domains
        return HOSTED_DOMAINS
    
    # Try to get from user object first
    if hasattr(user, 'authorized_domains') and user.authorized_domains:
        domains = [domain.strip() for domain in user.authorized_domains.split(',') if domain.strip()]
        # Remove any empty strings and ensure we have at least the primary domain
        domains = [d for d in domains if d]
        if domains:
            return domains
    
    # If not found in user object, query database directly
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT authorized_domains FROM users WHERE id = %s
        """, (user.id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            domains = [domain.strip() for domain in result[0].split(',') if domain.strip()]
            domains = [d for d in domains if d]
            if domains:
                print(f"DEBUG: Found domains from database: {domains}")
                return domains
                
    except Exception as e:
        print(f"DEBUG: Error querying database for authorized domains: {e}")
        
    # Fallback to single domain
    print(f"DEBUG: Falling back to primary domain: {user.domain}")
    return [user.domain] if user.domain else []

@cache.memoize(timeout=120)  # Cache for 2 minutes per user/domain combination
def get_enhanced_dashboard_stats_for_domain(user, domain):
    """Enhanced stats for a specific domain"""
    engine = get_db_engine()
    if not engine:
        return {
            'total_emails': 0,
            'volume_metrics': {
                'last_30_days': 0,
                'daily_average': 0,
                'previous_30_days': 0,
                'volume_change': 0,
                'volume_percent_change': 0,
                'peak_day': {'date': None, 'count': 0}
            },
            'languages': {},
            'categories': {},
            'receiving_domains': {domain: 0},
            'sentiment_distribution': {},
            'manipulation_indicators': {}
        }

    try:
        # SECURITY: Validate all inputs before using in SQL queries
        try:
            safe_domain = validate_domain(domain)
            safe_user_email = validate_email(user.email)
        except ValueError as e:
            logger.error(f"Validation error in dashboard for user {user.id}: {e}")
            return {
                'total_emails': 0,
                'volume_metrics': {'last_30_days': 0, 'daily_average': 0, 'previous_30_days': 0,
                                 'volume_change': 0, 'volume_percent_change': 0,
                                 'peak_day': {'date': None, 'count': 0}},
                'languages': {}, 'categories': {}, 'receiving_domains': {domain: 0},
                'sentiment_distribution': {}, 'manipulation_indicators': {}
            }

        with engine.connect() as conn:
            # SECURITY: Build parameterized filter based on user role
            filter_params = {}
            if user.is_admin():
                # Admin sees all emails for the domain
                domain_filter = "WHERE ea.recipients LIKE :domain_pattern"
                filter_params['domain_pattern'] = f'%@{safe_domain}%'
            elif user.role == 'client':
                # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # SECURITY: Validate aliases before using in SQL
                safe_aliases = validate_email_list(aliases)

                # Build parameterized condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
                user_conditions = ["ea.sender = :user_email"]
                user_conditions.append("ea.recipients LIKE :user_email_pattern")
                filter_params['user_email'] = safe_user_email
                filter_params['user_email_pattern'] = f'%{safe_user_email}%'

                for idx, alias in enumerate(safe_aliases):
                    param_name = f'alias_{idx}'
                    user_conditions.append(f"ea.recipients LIKE :{param_name}")
                    filter_params[param_name] = f'%{alias}%'

                domain_filter = f"WHERE ({' OR '.join(user_conditions)})"
            else:
                # DOMAIN_ADMIN and other roles: see their authorized domain
                domain_filter = "WHERE ea.recipients LIKE :domain_pattern"
                filter_params['domain_pattern'] = f'%@{safe_domain}%'

            # Get last 30 days stats
            date_30_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

            # Total emails in last 30 days for this domain (parameterized)
            total_30_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {domain_filter} AND DATE(ea.timestamp) >= :date_30
            """
            filter_params['date_30'] = date_30_days_ago
            total_30_days = conn.execute(text(total_30_query), filter_params).fetchone()[0]

            # Daily average
            daily_average = total_30_days / 30 if total_30_days > 0 else 0

            # Get previous 30 days for comparison
            date_60_days_ago = (datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d')
            date_30_days_ago_end = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%d')

            previous_30_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {domain_filter}
                AND DATE(ea.timestamp) >= :date_60
                AND DATE(ea.timestamp) <= :date_30_end
            """
            filter_params['date_60'] = date_60_days_ago
            filter_params['date_30_end'] = date_30_days_ago_end
            previous_30_days = conn.execute(text(previous_30_query), filter_params).fetchone()[0]
            
            # Calculate trend
            volume_change = total_30_days - previous_30_days
            volume_percent_change = (volume_change / previous_30_days * 100) if previous_30_days > 0 else 0
            
            # Get peak day in last 30 days (parameterized)
            peak_day_query = f"""
                SELECT DATE(ea.timestamp) as email_date, COUNT(*) as count
                FROM email_analysis ea
                {domain_filter} AND DATE(ea.timestamp) >= :peak_date_30
                GROUP BY DATE(ea.timestamp)
                ORDER BY count DESC
                LIMIT 1
            """
            filter_params['peak_date_30'] = date_30_days_ago
            peak_day_result = conn.execute(text(peak_day_query), filter_params).fetchone()
            peak_day = {
                'date': peak_day_result[0] if peak_day_result else None,
                'count': peak_day_result[1] if peak_day_result else 0
            }

            # Get other stats for this domain (parameterized)
            total_query = f"SELECT COUNT(*) FROM email_analysis ea {domain_filter}"
            total_emails = conn.execute(text(total_query), filter_params).fetchone()[0]

            # Get language distribution for this domain (parameterized)
            lang_query = f"""
                SELECT ea.detected_language, COUNT(*) as count
                FROM email_analysis ea
                {domain_filter} AND ea.detected_language IS NOT NULL
                GROUP BY ea.detected_language
                ORDER BY count DESC
            """
            languages = dict(conn.execute(text(lang_query), filter_params).fetchall())

            # Get category distribution for this domain (parameterized)
            cat_query = f"""
                SELECT ea.email_category, COUNT(*) as count
                FROM email_analysis ea
                {domain_filter} AND ea.email_category IS NOT NULL
                GROUP BY ea.email_category
                ORDER BY count DESC
            """
            categories = dict(conn.execute(text(cat_query), filter_params).fetchall())

            # Get sentiment distribution for this domain (parameterized)
            sentiment_query = f"""
                SELECT
                    CASE
                        WHEN ea.sentiment_polarity > 0.3 THEN 'Very Positive'
                        WHEN ea.sentiment_polarity > 0.1 THEN 'Positive'
                        WHEN ea.sentiment_polarity > -0.1 THEN 'Neutral'
                        WHEN ea.sentiment_polarity > -0.3 THEN 'Negative'
                        ELSE 'Very Negative'
                    END as sentiment_category,
                    COUNT(*) as count
                FROM email_analysis ea
                {domain_filter} AND ea.sentiment_polarity IS NOT NULL
                GROUP BY sentiment_category
                ORDER BY count DESC
            """
            sentiment_distribution = dict(conn.execute(text(sentiment_query), filter_params).fetchall())

            return {
                'total_emails': total_emails,
                'volume_metrics': {
                    'last_30_days': total_30_days,
                    'daily_average': round(daily_average, 1),
                    'previous_30_days': previous_30_days,
                    'volume_change': volume_change,
                    'volume_percent_change': round(volume_percent_change, 1),
                    'peak_day': peak_day
                },
                'languages': languages,
                'categories': categories,
                'receiving_domains': {domain: total_emails},
                'sentiment_distribution': sentiment_distribution,
                'manipulation_indicators': {}
            }
            
    except Exception as e:
        print(f"Error getting domain-specific stats: {e}")
        return {
            'total_emails': 0,
            'volume_metrics': {
                'last_30_days': 0,
                'daily_average': 0,
                'previous_30_days': 0,
                'volume_change': 0,
                'volume_percent_change': 0,
                'peak_day': {'date': None, 'count': 0}
            },
            'languages': {},
            'categories': {},
            'receiving_domains': {domain: 0},
            'sentiment_distribution': {},
            'manipulation_indicators': {}
        }

# ROUTES
@app.route('/')
def index():
    """Root route that properly redirects based on authentication status"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('auth.login'))

@cache.cached(timeout=60, key_prefix='overall_stats')  # Cache for 1 minute
def get_overall_system_stats():
    """Get overall system statistics for all hosted domains"""
    engine = get_db_engine()
    if not engine:
        return {}

    try:
        with engine.connect() as conn:
            # Create parameterized WHERE clause for all hosted domains
            domain_conditions = []
            domain_params = {}
            for idx, domain in enumerate(HOSTED_DOMAINS):
                param_name = f'hosted_domain_{idx}'
                domain_conditions.append(f"recipients LIKE :{param_name}")
                domain_params[param_name] = f'%@{domain}%'

            hosted_domains_filter = f"WHERE ({' OR '.join(domain_conditions)})"

            # Today's stats (parameterized)
            today = datetime.now().strftime('%Y-%m-%d')
            today_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {hosted_domains_filter} AND DATE(ea.timestamp) = :today
            """
            domain_params['today'] = today

            print(f"DEBUG: Today's query: {today_query}")  # Debug output
            today_total = conn.execute(text(today_query), domain_params).fetchone()[0]
            print(f"DEBUG: Today's total: {today_total}")  # Debug output

            # Yesterday's stats for comparison (parameterized)
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            yesterday_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {hosted_domains_filter} AND DATE(ea.timestamp) = :yesterday
            """
            domain_params['yesterday'] = yesterday
            yesterday_total = conn.execute(text(yesterday_query), domain_params).fetchone()[0]

            # Last 7 days total (parameterized)
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            week_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {hosted_domains_filter} AND DATE(ea.timestamp) >= :week_ago
            """
            domain_params['week_ago'] = week_ago
            week_total = conn.execute(text(week_query), domain_params).fetchone()[0]

            # Today's threats (parameterized)
            today_threats_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                {hosted_domains_filter}
                AND DATE(ea.timestamp) = :today_threats
                AND (ea.email_category = 'spam' OR ea.email_category = 'phishing')
            """
            domain_params['today_threats'] = today
            today_threats = conn.execute(text(today_threats_query), domain_params).fetchone()[0]

            # Domain breakdown for today (parameterized)
            domain_breakdown = {}
            for domain in HOSTED_DOMAINS:
                domain_today_query = """
                    SELECT COUNT(*) FROM email_analysis ea
                    WHERE ea.recipients LIKE :domain_pattern
                    AND DATE(ea.timestamp) = :today_bd
                """
                count = conn.execute(text(domain_today_query), {
                    'domain_pattern': f'%@{domain}%',
                    'today_bd': today
                }).fetchone()[0]
                if count > 0:  # Only include domains with activity
                    domain_breakdown[domain] = count

            # Calculate change from yesterday
            change_from_yesterday = today_total - yesterday_total
            percent_change = (change_from_yesterday / yesterday_total * 100) if yesterday_total > 0 else 0

            # Debug output
            print(f"DEBUG: Domain breakdown: {domain_breakdown}")
            print(f"DEBUG: Total domains with activity: {len(domain_breakdown)}")

            return {
                'today_total': today_total,
                'yesterday_total': yesterday_total,
                'week_total': week_total,
                'today_threats': today_threats,
                'change_from_yesterday': change_from_yesterday,
                'percent_change_yesterday': round(percent_change, 1),
                'domain_breakdown': domain_breakdown,
                'daily_average_week': round(week_total / 7, 1),
                'threat_rate_today': round((today_threats / today_total * 100), 2) if today_total > 0 else 0
            }

    except Exception as e:
        print(f"Error getting overall system stats: {e}")
        import traceback
        traceback.print_exc()  # Print full traceback for debugging
        return {}

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard with enhanced email statistics - filtered by user domain"""
    print(f"DEBUG: Dashboard route called by user: {current_user.email}")
    
    schema_info = get_column_info()
    if not schema_info:
        flash('Database connection failed', 'error')
        return render_template('error.html', error="Database connection failed")

    # Get overall system stats for admin users
    print(f"DEBUG: About to check if user is admin: {current_user.is_admin()}")
    overall_stats = None
    if current_user.is_admin():
        print(f"DEBUG: User is admin, calling get_overall_system_stats()")
        overall_stats = get_overall_system_stats()
        print(f"DEBUG: get_overall_system_stats() returned: {type(overall_stats)}")

    # Get user's authorized domains for the domain selector
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain')
    
    # Debug output
    print(f"DEBUG: User {current_user.email} authorized domains: {user_domains}")
    print(f"DEBUG: Selected domain from URL: {selected_domain}")
    print(f"DEBUG: User authorized_domains field: {getattr(current_user, 'authorized_domains', 'NOT FOUND')}")
    
    # If no domain selected or user doesn't have access, use first authorized domain
    if not selected_domain or selected_domain not in user_domains:
        selected_domain = user_domains[0] if user_domains else None
        print(f"DEBUG: Using first authorized domain: {selected_domain}")
    
    if not selected_domain:
        flash('No authorized domains found for your account', 'error')
        return render_template('error.html', error="No domain access")

    # Get enhanced stats for the selected domain only
    try:
        stats = get_enhanced_dashboard_stats_for_domain(current_user, selected_domain)
    except Exception as e:
        print(f"Error getting dashboard stats: {e}")
        # Fallback to basic stats structure
        stats = {
            'total_emails': 0,
            'volume_metrics': {
                'last_30_days': 0,
                'daily_average': 0,
                'previous_30_days': 0,
                'volume_change': 0,
                'volume_percent_change': 0,
                'peak_day': {'date': None, 'count': 0}
            },
            'languages': {},
            'categories': {},
            'receiving_domains': {selected_domain: 0},
            'sentiment_distribution': {},
            'manipulation_indicators': {}
        }

    # Create sentiment chart
    sentiment_chart = None
    if stats.get('sentiment_distribution'):
        try:
            plt.figure(figsize=(10, 6))
            sentiments = list(stats['sentiment_distribution'].keys())
            counts = list(stats['sentiment_distribution'].values())

            colors = {
                'Very Positive': '#28a745',
                'Positive': '#6f42c1',
                'Neutral': '#6c757d',
                'Negative': '#fd7e14',
                'Very Negative': '#dc3545'
            }
            bar_colors = [colors.get(s, '#6c757d') for s in sentiments]

            plt.bar(sentiments, counts, color=bar_colors)
            plt.title(f'Email Sentiment Distribution - {selected_domain}')
            plt.xlabel('Sentiment Category')
            plt.ylabel('Number of Emails')
            plt.xticks(rotation=45)
            plt.tight_layout()

            # Convert plot to base64 string
            img = BytesIO()
            plt.savefig(img, format='png', dpi=100, bbox_inches='tight')
            img.seek(0)
            sentiment_chart = base64.b64encode(img.getvalue()).decode()
            plt.close()
            sentiment_chart = f"data:image/png;base64,{sentiment_chart}"
        except Exception as e:
            print(f"Error creating sentiment chart: {e}")

    # Debug lines - these will show what's being passed to the template
    print(f"DEBUG: overall_stats being passed to template: {overall_stats}")
    print(f"DEBUG: current_user.is_admin(): {current_user.is_admin()}")

    # Get recent emails for the selected domain
    recent_emails = []
    try:
        engine = get_db_engine()
        if engine:
            with engine.connect() as conn:
                # SECURITY: Build parameterized filter based on user role
                recent_params = {}
                if current_user.is_admin():
                    # Admin sees all emails for the domain
                    domain_filter = "recipients LIKE :domain_pattern"
                    recent_params['domain_pattern'] = f'%@{selected_domain}%'
                elif current_user.role == 'client':
                    # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
                    # Get user's managed aliases
                    conn_temp = get_db_connection()
                    cursor_temp = conn_temp.cursor(dictionary=True)
                    cursor_temp.execute("""
                        SELECT managed_email FROM user_managed_aliases
                        WHERE user_id = %s AND active = 1
                    """, (current_user.id,))
                    aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                    cursor_temp.close()
                    conn_temp.close()

                    # Build parameterized condition
                    user_conditions = ["sender = :user_email"]
                    user_conditions.append("recipients LIKE :user_pattern")
                    recent_params['user_email'] = current_user.email
                    recent_params['user_pattern'] = f'%{current_user.email}%'

                    for idx, alias in enumerate(aliases):
                        param_name = f'alias_{idx}'
                        user_conditions.append(f"recipients LIKE :{param_name}")
                        recent_params[param_name] = f'%{alias}%'

                    domain_filter = f"({' OR '.join(user_conditions)})"
                else:
                    # DOMAIN_ADMIN and other roles: see their authorized domain
                    domain_filter = "recipients LIKE :domain_pattern"
                    recent_params['domain_pattern'] = f'%@{selected_domain}%'

                recent_query = text(f"""
                    SELECT id, message_id, timestamp, sender, recipients, subject,
                           spam_score, email_category
                    FROM email_analysis
                    WHERE {domain_filter}
                      AND is_deleted = 0
                    ORDER BY id DESC
                    LIMIT 10
                """)

                recent_results = conn.execute(recent_query, recent_params).fetchall()
                recent_emails = [dict(row._mapping) for row in recent_results]
                print(f"DEBUG: Fetched {len(recent_emails)} recent emails for {selected_domain}")
    except Exception as e:
        print(f"Error fetching recent emails: {e}")

    return render_template('enhanced_dashboard.html',
                         stats=stats,
                         schema_info=schema_info,
                         sentiment_chart=sentiment_chart,
                         user_domains=user_domains,
                         selected_domain=selected_domain,
                         overall_stats=overall_stats,
                         recent_emails=recent_emails)

@app.route('/debug/stats')
@login_required
@admin_required
@debug_only
def debug_stats():
    """Debug route to check what's in the database"""
    engine = get_db_engine()
    if not engine:
        return jsonify({'error': 'No database connection'})

    try:
        with engine.connect() as conn:
            # Check total emails in database
            total_query = "SELECT COUNT(*) FROM email_analysis"
            total_emails = conn.execute(text(total_query)).fetchone()[0]

            # Check today's emails (all domains)
            today = datetime.now().strftime('%Y-%m-%d')
            today_all_query = "SELECT COUNT(*) FROM email_analysis ea WHERE DATE(ea.timestamp) = :today"
            today_all = conn.execute(text(today_all_query), {"today": today}).fetchone()[0]

            # Check recipients column content
            recipients_sample_query = "SELECT recipients, timestamp FROM email_analysis ORDER BY id DESC LIMIT 10"
            recipients_sample = conn.execute(text(recipients_sample_query)).fetchall()

            # Check hosted domains specifically
            domain_counts = {}
            for domain in HOSTED_DOMAINS:
                domain_query = "SELECT COUNT(*) FROM email_analysis ea WHERE ea.recipients LIKE :pattern"
                pattern = f'%@{domain}%'
                count = conn.execute(text(domain_query), {"pattern": pattern}).fetchone()[0]
                domain_counts[domain] = count

            # Check today's hosted domain emails
            # Build parameterized query with multiple LIKE conditions
            domain_conditions = [f"ea.recipients LIKE :domain_{i}" for i in range(len(HOSTED_DOMAINS))]
            hosted_filter = f"({' OR '.join(domain_conditions)})"
            today_hosted_query = f"""
                SELECT COUNT(*) FROM email_analysis ea
                WHERE {hosted_filter} AND DATE(ea.timestamp) = :today
            """
            # Build parameters dictionary
            params = {f"domain_{i}": f'%@{domain}%' for i, domain in enumerate(HOSTED_DOMAINS)}
            params['today'] = today
            today_hosted = conn.execute(text(today_hosted_query), params).fetchone()[0]

            return jsonify({
                'total_emails_in_db': total_emails,
                'today_all_domains': today_all,
                'today_hosted_only': today_hosted,
                'domain_counts': domain_counts,
                'recipients_sample': [{'recipients': r[0], 'timestamp': str(r[1])} for r in recipients_sample],
                'current_date': today
            })

    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/emails/legacy')
@login_required
def emails_legacy():
    """Legacy email list with enhanced UI and statistics"""
    schema_info = get_column_info()
    if not schema_info:
        flash('Database connection failed', 'error')
        return render_template('error.html', error="Database connection failed")

    # Get spam threshold from config (env or database)
    spam_threshold = get_spam_threshold()

    # Get filter parameters
    filters = {
        'search': request.args.get('search', ''),
        'tab': request.args.get('tab', 'all'),  # all, safe, spam
        'language': request.args.get('language', ''),
        'category': request.args.get('category', ''),
        'receiving_domain': request.args.get('receiving_domain', ''),
        'sentiment_category': request.args.get('sentiment_category', ''),
        'min_sentiment': request.args.get('min_sentiment', ''),
        'max_sentiment': request.args.get('max_sentiment', ''),
        'min_manipulation': request.args.get('min_manipulation', ''),
        'min_extremity': request.args.get('min_extremity', ''),
        'date_from': request.args.get('date_from', ''),
        'date_to': request.args.get('date_to', ''),
        'show_deleted': request.args.get('show_deleted', ''),  # show_deleted=1 to show ONLY deleted
        'sort': request.args.get('sort', 'timestamp'),  # Column to sort by
        'order': request.args.get('order', 'desc'),  # asc or desc
    }

    # SECURITY: Validate current user email before using in SQL
    try:
        safe_user_email = validate_email(current_user.email)
    except ValueError as e:
        logger.error(f"Invalid user email in session for user {current_user.id}: {e}")
        flash('Invalid session data. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    # Build WHERE clause with user domain filtering
    where_conditions = ["1=1"]  # Always true condition to start
    query_params = {}  # Initialize parameters dictionary for SQL injection prevention

    # Add user domain filtering based on role
    if not current_user.is_admin():
        # SECURITY: Different filtering based on role
        if current_user.role == 'client':
            # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
            # Get user's managed aliases
            conn_temp = get_db_connection()
            cursor_temp = conn_temp.cursor(dictionary=True)
            cursor_temp.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (current_user.id,))
            aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
            cursor_temp.close()
            conn_temp.close()

            # SECURITY: Validate aliases before using in SQL
            safe_aliases = validate_email_list(aliases)

            # Build parameterized condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
            user_conditions = ["ea.sender = :user_email"]
            query_params['user_email'] = safe_user_email
            user_conditions.append("ea.recipients LIKE :user_email_pattern")
            query_params['user_email_pattern'] = f'%{safe_user_email}%'

            for idx, alias in enumerate(safe_aliases):
                param_name = f'client_alias_{idx}'
                user_conditions.append(f"ea.recipients LIKE :{param_name}")
                query_params[param_name] = f'%{alias}%'

            where_conditions.append(f"({' OR '.join(user_conditions)})")
        else:
            # DOMAIN_ADMIN and other roles: see their authorized domains
            authorized_domains = get_user_authorized_domains(current_user)
            if authorized_domains:
                # SECURITY: Validate domains before using in SQL
                safe_domains = []
                for domain in authorized_domains:
                    try:
                        safe_domains.append(validate_domain(domain))
                    except ValueError as e:
                        logger.warning(f"Invalid authorized domain for user {current_user.id}: {e}")
                        continue

                if safe_domains:
                    # Build parameterized conditions for authorized domains
                    domain_conditions = []
                    for idx, domain in enumerate(safe_domains):
                        param_name = f'auth_domain_{idx}'
                        domain_conditions.append(f"ea.recipients LIKE :{param_name}")
                        query_params[param_name] = f'%@{domain}%'
                    where_conditions.append(f"({' OR '.join(domain_conditions)})")
                else:
                    where_conditions.append("1=0")  # No access if no valid domains
            else:
                where_conditions.append("1=0")  # No access if no authorized domains
    else:
        # Admins see all hosted domains
        # SECURITY: Validate hosted domains
        safe_hosted_domains = []
        for domain in HOSTED_DOMAINS:
            try:
                safe_hosted_domains.append(validate_domain(domain))
            except ValueError as e:
                logger.warning(f"Invalid hosted domain in config: {e}")
                continue

        if safe_hosted_domains:
            # Build parameterized conditions for hosted domains
            hosted_domain_conditions = []
            for idx, domain in enumerate(safe_hosted_domains):
                param_name = f'hosted_domain_{idx}'
                hosted_domain_conditions.append(f"ea.recipients LIKE :{param_name}")
                query_params[param_name] = f'%@{domain}%'
            where_conditions.append(f"({' OR '.join(hosted_domain_conditions)})")
        else:
            where_conditions.append("1=0")  # No access if no valid hosted domains

    # SECURITY: Validate search term
    if filters['search']:
        search_term = filters['search']
        # Remove dangerous SQL characters
        dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "\\"]
        for char in dangerous_chars:
            search_term = search_term.replace(char, "")
        # Limit length
        search_term = search_term[:100]
        if search_term:  # Only add if not empty after sanitization
            # Check if search is numeric (email ID) - parameterized
            if search_term.isdigit():
                where_conditions.append("ea.id = :search_id")
                query_params['search_id'] = int(search_term)
            # Check if search looks like a date (contains hyphen and digits)
            elif '-' in search_term and any(c.isdigit() for c in search_term):
                # Search by date - supports full dates (2025-10-22) or partial (10-22)
                where_conditions.append("DATE_FORMAT(ea.timestamp, '%Y-%m-%d') LIKE :search_date")
                query_params['search_date'] = f'%{search_term}%'
            else:
                # Check if search contains special FULLTEXT operators or email addresses
                # FULLTEXT BOOLEAN MODE has issues with @, <, >, (, ), +, -, etc.
                has_special_chars = any(c in search_term for c in ['@', '<', '>', '(', ')', '+', '-', '"', '~'])

                # Use FULLTEXT search for better performance (requires 4+ character words)
                # For shorter searches or searches with special chars, use wildcard to match partial words
                if len(search_term) >= 4 and not has_special_chars:
                    where_conditions.append("MATCH(ea.subject, ea.sender, ea.recipients, ea.message_id) AGAINST(:search_pattern IN BOOLEAN MODE)")
                    query_params['search_pattern'] = f'{search_term}*'
                else:
                    # Fall back to LIKE for very short searches or email addresses/special characters
                    where_conditions.append("(ea.subject LIKE :search_pattern OR ea.sender LIKE :search_pattern OR ea.recipients LIKE :search_pattern OR ea.message_id LIKE :search_pattern)")
                    query_params['search_pattern'] = f'%{search_term}%'

    # SECURITY: Validate language filter (alphanumeric only, max 10 chars) - parameterized
    if filters['language']:
        language = filters['language']
        if re.match(r'^[a-zA-Z]{2,10}$', language):
            where_conditions.append("ea.detected_language = :language")
            query_params['language'] = language
        else:
            logger.warning(f"Invalid language filter rejected: {language}")

    # SECURITY: Validate category filter (alphanumeric + underscore only, max 50 chars) - parameterized
    if filters['category']:
        category = filters['category']
        if re.match(r'^[a-zA-Z0-9_]{1,50}$', category):
            where_conditions.append("ea.email_category = :category")
            query_params['category'] = category
        else:
            logger.warning(f"Invalid category filter rejected: {category}")

    # SECURITY: Validate receiving_domain filter
    if filters['receiving_domain']:
        # For non-admin users, ensure they can only filter by their authorized domains
        try:
            safe_filter_domain = validate_domain(filters['receiving_domain'])
            if current_user.is_admin():
                # Admin can filter by any hosted domain
                if filters['receiving_domain'] in HOSTED_DOMAINS:
                    where_conditions.append("ea.recipients LIKE :filter_domain")
                    query_params['filter_domain'] = f'%@{safe_filter_domain}%'
            else:
                # Client can only filter by their authorized domains
                user_authorized_domains = get_user_authorized_domains(current_user)
                if filters['receiving_domain'] in user_authorized_domains:
                    where_conditions.append("ea.recipients LIKE :filter_domain")
                    query_params['filter_domain'] = f'%@{safe_filter_domain}%'
        except ValueError as e:
            logger.warning(f"Invalid receiving_domain filter rejected: {e}")
        
    # Add tab filtering (all, clean, suspicious, quarantined, spam)
    if filters['tab'] == 'spam':
        where_conditions.append(f"(ea.spam_score >= {spam_threshold} OR ea.email_category IN ('spam', 'phishing'))")
    elif filters['tab'] == 'clean':
        # Clean = emails with spam_score < 60% of threshold and not categorized as spam
        where_conditions.append(f"ea.spam_score < {spam_threshold * 0.6} AND (ea.email_category NOT IN ('spam', 'phishing') OR ea.email_category IS NULL)")
    elif filters['tab'] == 'suspicious':
        # Suspicious = emails with spam_score between 60% and threshold (6.0-9.9 with default 10.0 threshold)
        where_conditions.append(f"ea.spam_score >= {spam_threshold * 0.6} AND ea.spam_score < {spam_threshold}")
    elif filters['tab'] == 'quarantined':
        # Quarantined = emails that are currently held in quarantine
        where_conditions.append("ea.disposition = 'quarantined'")
    elif filters['tab'] == 'safe':
        # Legacy 'safe' tab - redirect to 'clean'
        where_conditions.append(f"ea.spam_score < {spam_threshold * 0.6} AND (ea.email_category NOT IN ('spam', 'phishing') OR ea.email_category IS NULL)")

    # Add sentiment category filtering
    if filters['sentiment_category']:
        if filters['sentiment_category'] == 'very_positive':
            where_conditions.append("ea.sentiment_polarity > 0.3")
        elif filters['sentiment_category'] == 'positive':
            where_conditions.append("ea.sentiment_polarity > 0.1 AND ea.sentiment_polarity <= 0.3")
        elif filters['sentiment_category'] == 'neutral':
            where_conditions.append("ea.sentiment_polarity >= -0.1 AND ea.sentiment_polarity <= 0.1")
        elif filters['sentiment_category'] == 'negative':
            where_conditions.append("ea.sentiment_polarity >= -0.3 AND ea.sentiment_polarity < -0.1")
        elif filters['sentiment_category'] == 'very_negative':
            where_conditions.append("ea.sentiment_polarity < -0.3")

    # Add security threats filter (legacy support)
    security_filter = request.args.get('security_threats', '')
    if security_filter == 'threats_only':
        where_conditions.append("(ea.email_category = 'spam' OR ea.email_category = 'phishing')")
    elif security_filter == 'safe_only':
        where_conditions.append("(ea.email_category != 'spam' AND ea.email_category != 'phishing' AND ea.email_category IS NOT NULL)")

    if filters['min_sentiment']:
        where_conditions.append("ea.sentiment_polarity >= :min_sentiment")
        query_params['min_sentiment'] = float(filters['min_sentiment'])

    if filters['max_sentiment']:
        where_conditions.append("ea.sentiment_polarity <= :max_sentiment")
        query_params['max_sentiment'] = float(filters['max_sentiment'])

    if filters['min_manipulation']:
        where_conditions.append("ea.sentiment_manipulation >= :min_manipulation")
        query_params['min_manipulation'] = float(filters['min_manipulation'])

    if filters['min_extremity']:
        where_conditions.append("ea.sentiment_extremity >= :min_extremity")
        query_params['min_extremity'] = float(filters['min_extremity'])

    # SECURITY: Validate date filters (now parameterized)
    if filters['date_from']:
        try:
            safe_date_from = validate_date_string(filters['date_from'])
            where_conditions.append("DATE(ea.timestamp) >= :date_from")
            query_params['date_from'] = safe_date_from
        except ValueError as e:
            logger.warning(f"Invalid date_from filter rejected: {e}")

    if filters['date_to']:
        try:
            safe_date_to = validate_date_string(filters['date_to'])
            where_conditions.append("DATE(ea.timestamp) <= :date_to")
            query_params['date_to'] = safe_date_to
        except ValueError as e:
            logger.warning(f"Invalid date_to filter rejected: {e}")

    # Add deleted filter - show_deleted=1 means show ONLY deleted, otherwise exclude deleted
    # Check both is_deleted and disposition fields for comprehensive filtering
    if filters['show_deleted'] == '1':
        where_conditions.append("(ea.is_deleted = 1 OR ea.disposition = 'deleted')")
    else:
        where_conditions.append("(ea.is_deleted = 0 AND (ea.disposition IS NULL OR ea.disposition != 'deleted'))")

    where_clause = " AND ".join(where_conditions)

    # Get pagination parameters with validation to prevent SQL injection
    try:
        page = int(request.args.get('page', 1))
        if page < 1:
            page = 1
        # Limit maximum page to prevent performance issues
        if page > 100000:
            page = 100000
    except (ValueError, TypeError):
        logger.warning(f"Invalid page parameter: {request.args.get('page')}")
        page = 1

    per_page = 50  # Hardcoded constant
    offset = (page - 1) * per_page

    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            # Get statistics for summary cards (parameterized)
            stats_query = text(f"""
                SELECT
                    COUNT(*) as total_count,
                    AVG(ea.spam_score) as avg_spam
                FROM email_analysis ea
                WHERE {where_clause}
            """)
            stats = conn.execute(stats_query, query_params).fetchone()

            # Get distinct recipient strings to count unique domains (parameterized)
            domain_query = text(f"""
                SELECT DISTINCT ea.recipients
                FROM email_analysis ea
                WHERE {where_clause}
            """)
            recipient_rows = conn.execute(domain_query, query_params).fetchall()

            # Extract all unique domains from recipients using Python
            all_domains = set()
            for row in recipient_rows:
                if row[0]:  # If recipients field is not null
                    domains = extract_receiving_domains(row[0])
                    all_domains.update(domains)

            statistics = {
                'total_count': stats[0] or 0,
                'avg_spam': round(stats[1], 1) if stats[1] else 0.0,
                'avg_sentiment': round(stats[2], 2) if stats[2] else 0.0,
                'domain_count': len(all_domains)
            }

            # SECURITY: Validate and sanitize sort parameters (whitelist approach)
            allowed_sort_columns = {
                'timestamp': 'ea.timestamp',
                'sender': 'ea.sender',
                'subject': 'ea.subject',
                'spam_score': 'ea.spam_score',
                'detected_language': 'ea.detected_language',
                'email_category': 'ea.email_category'
            }

            sort_column = allowed_sort_columns.get(filters['sort'], 'ea.timestamp')
            sort_order = 'ASC' if filters['order'].lower() == 'asc' else 'DESC'

            # For timestamp, use id as secondary sort for consistency
            if filters['sort'] == 'timestamp':
                order_by_clause = f"ORDER BY {sort_column} {sort_order}, ea.id {sort_order}"
            else:
                order_by_clause = f"ORDER BY {sort_column} {sort_order}, ea.timestamp DESC"

            # Get emails with receiving domains and delivery status (parameterized)
            # Note: LIMIT and OFFSET must be literal integers, not parameters in SQLAlchemy text()
            email_query = text(f"""
                SELECT
                    ea.id, ea.message_id, ea.timestamp, ea.sender, ea.recipients, ea.subject,
                    ea.detected_language, ea.email_category, ea.sentiment_polarity,
                    ea.sentiment_manipulation, ea.spam_score, ea.disposition,
                    CASE
                        -- Check for released status FIRST (both disposition and quarantine_status)
                        WHEN ea.disposition = 'released' THEN 'R'
                        WHEN eq.quarantine_status = 'released' THEN 'R'
                        -- Then check other disposition states
                        WHEN ea.disposition = 'quarantined' THEN 'Q'
                        WHEN ea.disposition = 'deleted' THEN 'X'
                        WHEN ea.disposition = 'rejected' THEN 'B'
                        WHEN ea.disposition = 'delivered' THEN 'D'
                        -- Fallback to quarantine table for legacy data
                        WHEN eq.quarantine_status = 'held' THEN 'Q'
                        WHEN eq.quarantine_status = 'deleted' THEN 'X'
                        WHEN eq.quarantine_status = 'expired' THEN 'B'
                        -- Default to delivered if no status found
                        ELSE 'D'
                    END as delivery_status
                FROM email_analysis ea
                LEFT JOIN email_quarantine eq ON ea.message_id = eq.message_id
                WHERE {where_clause}
                {order_by_clause}
                LIMIT {int(per_page)} OFFSET {int(offset)}
            """)

            emails_data = conn.execute(email_query, query_params).fetchall()

            # Add receiving domain to each email
            emails = []
            for email in emails_data:
                email_dict = dict(email._mapping)
                email_dict['primary_receiving_domain'] = get_primary_receiving_domain(email_dict['recipients'])
                email_dict['all_receiving_domains'] = extract_receiving_domains(email_dict['recipients'])
                emails.append(email_dict)

            # Get available receiving domains for filter (user-specific and hosted domains only)
            if current_user.is_admin():
                # Admin sees all hosted domains (from client_domains table via HOSTED_DOMAINS)
                available_domains = sorted(HOSTED_DOMAINS)
            else:
                # Non-admin users see their authorized domains
                user_authorized_domains = get_user_authorized_domains(current_user)
                available_domains = sorted([domain for domain in user_authorized_domains if domain in HOSTED_DOMAINS])

            total_count = statistics['total_count']
            total_pages = (total_count + per_page - 1) // per_page

            return render_template('emails.html',
                                 emails=emails,
                                 filters=filters,
                                 schema_info=schema_info,
                                 statistics=statistics,
                                 page=page,
                                 total_pages=total_pages,
                                 total_count=total_count,
                                 available_domains=available_domains)

    except Exception as e:
        flash(f'Database query failed: {e}', 'error')
        return render_template('error.html', error=f"Database query failed: {e}")

@app.route('/emails')
@login_required
def emails():
    """Email List Bulk Operations - Modern email management interface
    Columns: ID, Delivery State (Q/D/R), Recipient, Domain, Sender, Subject, Spam, Date
    """
    try:
        # Get filter parameters
        search = request.args.get('search', '')
        search_content = request.args.get('search_content', '0')
        receiving_domain = request.args.get('receiving_domain', '')
        mail_direction = request.args.get('mail_direction', 'inbound')
        tab = request.args.get('tab', 'all')
        show_deleted = request.args.get('show_deleted', '0')

        # Validate pagination parameters to prevent SQL injection
        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
            if page > 100000:
                page = 100000
        except (ValueError, TypeError):
            logger.warning(f"Invalid page parameter: {request.args.get('page')}")
            page = 1

        per_page = 50  # Fixed at 50 rows per page
        sort_by = request.args.get('sort', 'id')
        order = request.args.get('order', 'desc')

        # Get spam threshold
        spam_threshold = float(os.getenv('SPACY_SPAM_THRESHOLD', '10.0'))

        # Build WHERE clause with domain filtering
        where_conditions = ["1=1"]
        query_params = []

        # Domain filtering based on user role
        if not current_user.is_admin():
            # SECURITY: Different filtering based on role
            if current_user.role == 'client':
                # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Build condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
                user_conditions = []
                user_conditions.append("ea.sender = %s")
                query_params.append(current_user.email)
                user_conditions.append("ea.recipients LIKE %s")
                query_params.append(f'%{current_user.email}%')
                for alias in aliases:
                    user_conditions.append("ea.recipients LIKE %s")
                    query_params.append(f'%{alias}%')

                where_conditions.append(f"({' OR '.join(user_conditions)})")
            else:
                # DOMAIN_ADMIN and other roles: see their authorized domains
                authorized_domains = get_user_authorized_domains(current_user)
                if authorized_domains:
                    domain_patterns_sender = [f'%@{domain}%' for domain in authorized_domains]
                    domain_patterns_recipient = [f'%@{domain}%' for domain in authorized_domains]

                    # Two separate conditions based on mail direction
                    outbound_condition = "ea.mail_direction = 'outbound' AND (" + " OR ".join([f"ea.sender LIKE %s" for _ in authorized_domains]) + ")"
                    inbound_condition = "ea.mail_direction != 'outbound' AND (" + " OR ".join([f"ea.recipients LIKE %s" for _ in authorized_domains]) + ")"

                    where_conditions.append(f"({outbound_condition} OR {inbound_condition})")
                    query_params.extend(domain_patterns_sender)  # For outbound sender matching
                    query_params.extend(domain_patterns_recipient)  # For inbound recipient matching
                else:
                    where_conditions.append("1=0")  # No access
        else:
            # Admins see all hosted domains
            # For outbound mail, filter by SENDER domain; for inbound filter by RECIPIENT domain
            if HOSTED_DOMAINS:
                domain_patterns_sender = [f'%@{domain}%' for domain in HOSTED_DOMAINS]
                domain_patterns_recipient = [f'%@{domain}%' for domain in HOSTED_DOMAINS]

                # Two separate conditions based on mail direction
                outbound_condition = "ea.mail_direction = 'outbound' AND (" + " OR ".join([f"ea.sender LIKE %s" for _ in HOSTED_DOMAINS]) + ")"
                inbound_condition = "ea.mail_direction != 'outbound' AND (" + " OR ".join([f"ea.recipients LIKE %s" for _ in HOSTED_DOMAINS]) + ")"

                where_conditions.append(f"({outbound_condition} OR {inbound_condition})")
                query_params.extend(domain_patterns_sender)  # For outbound sender matching
                query_params.extend(domain_patterns_recipient)  # For inbound recipient matching

        # Search filter
        if search:
            search_clean = search.replace("'", "").replace('"', "").replace(";", "")[:100]
            if search_clean.isdigit():
                where_conditions.append("ea.id = %s")
                query_params.append(int(search_clean))
            elif '-' in search_clean and any(c.isdigit() for c in search_clean):
                # Date search
                where_conditions.append("DATE_FORMAT(ea.timestamp, '%Y-%m-%d') LIKE %s")
                query_params.append(f'%{search_clean}%')
            else:
                # Check if search contains special FULLTEXT operators or email addresses
                # FULLTEXT BOOLEAN MODE has issues with @, <, >, (, ), +, -, etc.
                has_special_chars = any(c in search_clean for c in ['@', '<', '>', '(', ')', '+', '-', '"', '~'])

                # Build search condition - include content if checkbox is checked
                if search_content == '1':
                    # Use FULLTEXT search for better performance (requires 4+ chars and no special chars)
                    if len(search_clean) >= 4 and not has_special_chars:
                        # FULLTEXT on indexed fields + content_summary, fall back to LIKE for raw_email
                        where_conditions.append("(MATCH(ea.subject, ea.sender, ea.recipients, ea.message_id) AGAINST(%s IN BOOLEAN MODE) OR MATCH(ea.content_summary) AGAINST(%s IN BOOLEAN MODE) OR ea.raw_email LIKE %s)")
                        search_ft = f'{search_clean}*'
                        search_pattern = f'%{search_clean}%'
                        query_params.extend([search_ft, search_ft, search_pattern])
                    else:
                        # Fall back to LIKE for very short searches or email addresses/special characters
                        where_conditions.append("(ea.subject LIKE %s OR ea.sender LIKE %s OR ea.recipients LIKE %s OR ea.message_id LIKE %s OR ea.content_summary LIKE %s OR ea.raw_email LIKE %s)")
                        search_pattern = f'%{search_clean}%'
                        query_params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])
                else:
                    # Use FULLTEXT search for better performance (4+ chars and no special chars)
                    if len(search_clean) >= 4 and not has_special_chars:
                        where_conditions.append("MATCH(ea.subject, ea.sender, ea.recipients, ea.message_id) AGAINST(%s IN BOOLEAN MODE)")
                        query_params.append(f'{search_clean}*')
                    else:
                        # Fall back to LIKE for very short searches or email addresses/special characters
                        where_conditions.append("(ea.subject LIKE %s OR ea.sender LIKE %s OR ea.recipients LIKE %s OR ea.message_id LIKE %s)")
                        search_pattern = f'%{search_clean}%'
                        query_params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

        # Receiving domain filter
        if receiving_domain:
            # SECURITY: Only apply domain filter for admin and domain_admin roles
            # Client users should NOT be able to see all emails for a domain
            if current_user.is_admin():
                where_conditions.append("ea.recipients LIKE %s")
                query_params.append(f'%@{receiving_domain}%')
            elif current_user.role == 'domain_admin' and receiving_domain in get_user_authorized_domains(current_user):
                where_conditions.append("ea.recipients LIKE %s")
                query_params.append(f'%@{receiving_domain}%')
            elif current_user.role == 'client' and receiving_domain in get_user_authorized_domains(current_user):
                # For client role: filter to show only THEIR emails related to the selected domain
                # This filters the already-authorized emails to show only those for this domain
                where_conditions.append("(ea.recipients LIKE %s OR ea.sender LIKE %s)")
                query_params.append(f'%@{receiving_domain}%')
                query_params.append(f'%@{receiving_domain}%')

        # Mail direction filter
        if mail_direction and mail_direction in ('inbound', 'outbound'):
            where_conditions.append("ea.mail_direction = %s")
            query_params.append(mail_direction)

        # Tab filtering
        if tab == 'spam':
            where_conditions.append(f"(ea.spam_score >= {spam_threshold} OR ea.email_category IN ('spam', 'phishing'))")
        elif tab == 'clean':
            where_conditions.append(f"ea.spam_score < {spam_threshold * 0.6} AND (ea.email_category NOT IN ('spam', 'phishing') OR ea.email_category IS NULL)")
        elif tab == 'suspicious':
            where_conditions.append(f"ea.spam_score >= {spam_threshold * 0.6} AND ea.spam_score < {spam_threshold}")
        elif tab == 'quarantined':
            where_conditions.append("ea.disposition = 'quarantined'")

        

        # Show deleted filter
        if show_deleted == '1':
            where_conditions.append("(ea.is_deleted = 1 OR ea.disposition = 'deleted')")
        else:
            where_conditions.append("(ea.is_deleted = 0 AND (ea.disposition IS NULL OR ea.disposition != 'deleted'))")

        where_clause = " AND ".join(where_conditions)

        # Valid sort columns
        valid_sorts = {'id': 'ea.id', 'spam_score': 'ea.spam_score', 'timestamp': 'ea.timestamp',
                      'sender': 'ea.sender', 'recipients': 'ea.recipients', 'subject': 'ea.subject',
                      'email_category': 'ea.email_category', 'country': 'ea.id'}  # country sorted in Python
        sort_column = valid_sorts.get(sort_by, 'ea.id')
        order_direction = 'DESC' if order == 'desc' else 'ASC'

        # For country sorting, we need to fetch more results and sort in Python
        sort_in_python = (sort_by == 'country')

        offset = (page - 1) * per_page

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get statistics
        stats_query = f"""
            SELECT
                COUNT(*) as total_count,
                AVG(ea.spam_score) as avg_spam
            FROM email_analysis ea
            WHERE {where_clause}
        """
        cursor.execute(stats_query, query_params)
        stats = cursor.fetchone()

        # Get distinct domains
        domain_query = f"""
            SELECT DISTINCT ea.recipients
            FROM email_analysis ea
            WHERE {where_clause}
        """
        cursor.execute(domain_query, query_params)
        recipient_rows = cursor.fetchall()

        # Extract unique domains from recipients
        all_domains = set()
        for row in recipient_rows:
            if row['recipients']:
                # Extract domains from recipients string
                for recipient in row['recipients'].split(','):
                    recipient = recipient.strip()
                    if '@' in recipient:
                        domain = recipient.split('@')[1]
                        all_domains.add(domain)

        statistics = {
            'total_count': stats['total_count'] or 0,
            'avg_spam': round(stats['avg_spam'], 1) if stats['avg_spam'] else 0.0,
            'domain_count': len(all_domains)
        }

        # Main query with new column layout
        query = f"""
            SELECT
                ea.id,
                ea.disposition,
                ea.recipients,
                ea.sender,
                ea.subject,
                ea.spam_score,
                ea.email_category,
                ea.timestamp,
                ea.quarantine_status,
                ea.quarantine_reason,
                ea.raw_email,
                ea.raw_email_path
            FROM email_analysis ea
            WHERE {where_clause}
            ORDER BY {sort_column} {order_direction}
            LIMIT %s OFFSET %s
        """

        cursor.execute(query, query_params + [per_page, offset])
        emails = cursor.fetchall()

        # Get total count and pages
        total_count = statistics['total_count']
        total_pages = (total_count + per_page - 1) // per_page

        cursor.close()
        conn.close()

        # Process emails to extract domain and format delivery state
        for email in emails:
            # Extract first recipient's domain
            recipients = email.get('recipients', '') or ''
            if recipients and '@' in recipients:
                # Handle multiple recipients - get first one
                first_recipient = recipients.split(',')[0].strip()
                if '@' in first_recipient:
                    email['recipient_email'] = first_recipient
                    email['recipient_domain'] = first_recipient.split('@')[1]
                else:
                    email['recipient_email'] = first_recipient
                    email['recipient_domain'] = 'unknown'
            else:
                email['recipient_email'] = recipients if recipients else '-'
                email['recipient_domain'] = '-'

            # Delivery state: Q=Quarantined, D=Delivered
            disposition = email.get('disposition', 'delivered')
            quarantine_status = email.get('quarantine_status', None)

            # Delivered includes: normal delivery, relay_pending, and released (manually approved)
            if disposition in ['delivered', 'relay_pending', 'released'] or quarantine_status == 'released':
                email['delivery_state'] = 'D'
                email['delivery_state_full'] = 'Delivered'
                email['delivery_state_class'] = 'success'  # Green for delivered
            elif disposition == 'quarantined':
                email['delivery_state'] = 'Q'
                email['delivery_state_full'] = 'Quarantined'
                email['delivery_state_class'] = 'warning'
            else:
                email['delivery_state'] = disposition[0].upper() if disposition else 'U'
                email['delivery_state_full'] = disposition.title() if disposition else 'Unknown'
                email['delivery_state_class'] = 'secondary'

            # Extract source IP and lookup country
            email['source_ip'] = None
            email['source_country'] = None
            email['source_country_code'] = None

            raw_email_content = get_raw_email_content(email)
            if raw_email_content:
                try:
                    import re
                    # Get the first external Received header
                    received_headers = []
                    current_header = ""
                    for line in raw_email_content.split('\n'):
                        if line.startswith('Received:'):
                            if current_header:
                                received_headers.append(current_header)
                            current_header = line
                        elif current_header and (line.startswith('\t') or line.startswith(' ')):
                            current_header += line
                        elif current_header:
                            received_headers.append(current_header)
                            current_header = ""
                    if current_header:
                        received_headers.append(current_header)

                    # Look for the oldest (last in list) Received header with an external IP
                    # Iterate in reverse to get the oldest first
                    import ipaddress
                    for header in reversed(received_headers):
                        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
                        if ip_match:
                            candidate_ip = ip_match.group(1)
                            # Skip internal/private IPs
                            try:
                                ip_obj = ipaddress.ip_address(candidate_ip)
                                if not ip_obj.is_private and not ip_obj.is_loopback:
                                    email['source_ip'] = candidate_ip
                                    break
                            except:
                                pass

                    # Lookup country for source IP
                    if email.get('source_ip'):
                        try:
                            import geoip2.database
                            geoip_db_path = '/opt/spacyserver/data/GeoLite2-Country.mmdb'
                            reader = geoip2.database.Reader(geoip_db_path)
                            response = reader.country(email['source_ip'])
                            email['source_country'] = response.country.name
                            email['source_country_code'] = response.country.iso_code
                            reader.close()
                        except:
                            pass
                except:
                    pass

        # Sort by country code in Python if requested
        if sort_in_python and sort_by == 'country':
            emails = sorted(emails, key=lambda x: x.get('source_country_code') or 'ZZZ',
                          reverse=(order == 'desc'))

        # Get available domains for dropdown
        if current_user.is_admin():
            available_domains = HOSTED_DOMAINS
        else:
            available_domains = get_user_authorized_domains(current_user)

        return render_template('emails.html',
                             emails=emails,
                             search=search,
                             search_content=search_content,
                             receiving_domain=receiving_domain,
                             mail_direction=mail_direction,
                             tab=tab,
                             show_deleted=show_deleted,
                             page=page,
                             total_pages=total_pages,
                             total_count=total_count,
                             sort_by=sort_by,
                             order=order,
                             available_domains=available_domains,
                             statistics=statistics)

    except Exception as e:
        logger.error(f"Error in emails preview: {e}")
        flash(f'Error loading email preview: {e}', 'error')
        return render_template('error.html', error=str(e))

@app.route('/export/<format>')
@login_required
def export_data(format):
    """Export email data with user domain filtering"""
    # Get same filters as email list
    filters = {
        'search': request.args.get('search', ''),
        'language': request.args.get('language', ''),
        'category': request.args.get('category', ''),
        'receiving_domain': request.args.get('receiving_domain', ''),
        'sentiment_category': request.args.get('sentiment_category', ''),
        'min_sentiment': request.args.get('min_sentiment', ''),
        'max_sentiment': request.args.get('max_sentiment', ''),
    }

    # Build WHERE clause with domain filtering (SECURE - parameterized)
    where_conditions = ["1=1"]
    query_params = {}  # Initialize parameters dictionary for SQL injection prevention

    # Add user domain filtering for non-admin users
    if not current_user.is_admin():
        # SECURITY: Different filtering based on role
        if current_user.role == 'client':
            # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
            # Get user's managed aliases
            conn_temp = get_db_connection()
            cursor_temp = conn_temp.cursor(dictionary=True)
            cursor_temp.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (current_user.id,))
            aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
            cursor_temp.close()
            conn_temp.close()

            # Build parameterized condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
            user_conditions = ["sender = :user_email"]
            query_params['user_email'] = current_user.email

            user_conditions.append("recipients LIKE :user_email_pattern")
            query_params['user_email_pattern'] = f'%{current_user.email}%'

            for idx, alias in enumerate(aliases):
                param_name = f'alias_{idx}'
                user_conditions.append(f"recipients LIKE :{param_name}")
                query_params[param_name] = f'%{alias}%'

            where_conditions.append(f"({' OR '.join(user_conditions)})")
        else:
            # DOMAIN_ADMIN and other roles: see their authorized domains
            authorized_domains = get_user_authorized_domains(current_user)
            if authorized_domains:
                # SECURITY: Validate domains before using in SQL
                safe_domains = []
                for domain in authorized_domains:
                    try:
                        safe_domains.append(validate_domain(domain))
                    except ValueError as e:
                        logger.warning(f"Invalid authorized domain for user {current_user.id}: {e}")
                        continue

                if safe_domains:
                    domain_conditions = []
                    for idx, domain in enumerate(safe_domains):
                        param_name = f'auth_domain_{idx}'
                        domain_conditions.append(f"recipients LIKE :{param_name}")
                        query_params[param_name] = f'%@{domain}%'
                    where_conditions.append(f"({' OR '.join(domain_conditions)})")
                else:
                    where_conditions.append("1=0")  # No access
            else:
                where_conditions.append("1=0")  # No access

    # SECURITY: Validate and parameterize search term
    if filters['search']:
        search_term = filters['search']
        # Remove dangerous SQL characters
        dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "\\"]
        for char in dangerous_chars:
            search_term = search_term.replace(char, "")
        # Limit length
        search_term = search_term[:100]
        if search_term:
            where_conditions.append("(subject LIKE :search_pattern OR ea.sender LIKE :search_pattern)")
            query_params['search_pattern'] = f'%{search_term}%'

    # SECURITY: Validate language filter (alphanumeric only, max 10 chars) - parameterized
    if filters['language']:
        language = filters['language']
        if re.match(r'^[a-zA-Z]{2,10}$', language):
            where_conditions.append("ea.detected_language = :language")
            query_params['language'] = language
        else:
            logger.warning(f"Invalid language filter rejected: {language}")

    # SECURITY: Validate category filter (alphanumeric + underscore only, max 50 chars) - parameterized
    if filters['category']:
        category = filters['category']
        if re.match(r'^[a-zA-Z0-9_]{1,50}$', category):
            where_conditions.append("ea.email_category = :category")
            query_params['category'] = category
        else:
            logger.warning(f"Invalid category filter rejected: {category}")

    # SECURITY: Validate receiving_domain filter
    if filters['receiving_domain']:
        try:
            safe_filter_domain = validate_domain(filters['receiving_domain'])
            if current_user.is_admin():
                if filters['receiving_domain'] in HOSTED_DOMAINS:
                    where_conditions.append("recipients LIKE :filter_domain")
                    query_params['filter_domain'] = f'%@{safe_filter_domain}%'
            else:
                user_authorized_domains = get_user_authorized_domains(current_user)
                if filters['receiving_domain'] in user_authorized_domains:
                    where_conditions.append("recipients LIKE :filter_domain")
                    query_params['filter_domain'] = f'%@{safe_filter_domain}%'
        except ValueError as e:
            logger.warning(f"Invalid receiving_domain filter rejected: {e}")

    # Add sentiment category filtering for export
    if filters['sentiment_category']:
        if filters['sentiment_category'] == 'positive':
            where_conditions.append("ea.sentiment_polarity > 0.1")
        elif filters['sentiment_category'] == 'negative':
            where_conditions.append("ea.sentiment_polarity < -0.1")
        elif filters['sentiment_category'] == 'neutral':
            where_conditions.append("ea.sentiment_polarity >= -0.1 AND sentiment_polarity <= 0.1")

    where_clause = " AND ".join(where_conditions)

    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            query = text(f"""
                SELECT ea.id, ea.timestamp, ea.sender, ea.recipients, ea.subject,
                       ea.detected_language, ea.email_category, ea.sentiment_polarity,
                       ea.sentiment_manipulation, ea.spam_score, ea.urgency_score,
                       ea.entities, ea.email_topics
                FROM email_analysis ea
                WHERE {where_clause}
                ORDER BY ea.id DESC
            """)

            result = conn.execute(query, query_params).fetchall()

            # Add receiving domains and sentiment categories to each record
            data = []
            for row in result:
                row_dict = dict(row._mapping)
                row_dict['primary_receiving_domain'] = get_primary_receiving_domain(row_dict['recipients'])
                row_dict['all_receiving_domains'] = ', '.join(extract_receiving_domains(row_dict['recipients']))

                # Add sentiment category
                polarity = row_dict.get('sentiment_polarity', 0)
                if polarity > 0.1:
                    row_dict['sentiment_category'] = 'positive'
                elif polarity < -0.1:
                    row_dict['sentiment_category'] = 'negative'
                else:
                    row_dict['sentiment_category'] = 'neutral'

                data.append(row_dict)

            if format == 'json':
                return jsonify(data)

            elif format == 'csv':
                df = pd.DataFrame(data)
                output = io.StringIO()
                df.to_csv(output, index=False)
                output.seek(0)

                user_domains = get_user_authorized_domains(current_user)
                domain_suffix = f"_{'-'.join(user_domains)}" if not current_user.is_admin() else "_all_domains"
                filename = f'email_analysis{domain_suffix}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

                return send_file(
                    io.BytesIO(output.getvalue().encode()),
                    mimetype='text/csv',
                    as_attachment=True,
                    download_name=filename
                )

    except Exception as e:
        return jsonify({"error": f"Export failed: {e}"}), 500

@app.route('/email/<int:email_id>')
@login_required
def email_detail(email_id):
    """Detailed view of a single email with domain access control"""
    schema_info = get_column_info()
    if not schema_info:
        flash('Database connection failed', 'error')
        return render_template('error.html', error="Database connection failed")

    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            query = text("SELECT * FROM email_analysis WHERE id = :email_id")
            result = conn.execute(query, {"email_id": email_id}).fetchone()

            if not result:
                flash('Email not found', 'error')
                return render_template('error.html', error="Email not found")

            email = dict(result._mapping)
            email['primary_receiving_domain'] = get_primary_receiving_domain(email['recipients'])
            email['all_receiving_domains'] = extract_receiving_domains(email['recipients'])

            # Check if email is in quarantine
            quarantine_query = text("""
                SELECT quarantine_status, quarantine_reason
                FROM email_quarantine
                WHERE message_id = :message_id
            """)
            quarantine_result = conn.execute(quarantine_query, {"message_id": email['message_id']}).fetchone()
            if quarantine_result:
                email['quarantine_status'] = quarantine_result.quarantine_status
                email['quarantine_reason'] = quarantine_result.quarantine_reason
            else:
                # Fallback to email_analysis disposition if not in quarantine table
                if email.get('disposition') == 'quarantined':
                    email['quarantine_status'] = 'held'
                    email['quarantine_reason'] = email.get('quarantine_reason', 'high_spam_score')
                else:
                    email['quarantine_status'] = 'delivered'
                    email['quarantine_reason'] = None

            # Check if user has access to this email
            if not current_user.is_admin():
                user_can_access = False

                if current_user.role == 'client':
                    # CLIENT role: Check if they are sender OR recipient OR alias recipient
                    # Check if user is the sender
                    if email.get('sender') == current_user.email:
                        user_can_access = True
                    # Check if user is in recipients
                    elif email.get('recipients') and current_user.email in email.get('recipients', ''):
                        user_can_access = True
                    else:
                        # Check if user's managed aliases are in recipients
                        conn_temp = get_db_connection()
                        cursor_temp = conn_temp.cursor(dictionary=True)
                        cursor_temp.execute("""
                            SELECT managed_email FROM user_managed_aliases
                            WHERE user_id = %s AND active = 1
                        """, (current_user.id,))
                        aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                        cursor_temp.close()
                        conn_temp.close()

                        # Check if any alias is in recipients
                        for alias in aliases:
                            if alias in email.get('recipients', ''):
                                user_can_access = True
                                break
                else:
                    # DOMAIN_ADMIN and other roles: Check domain access
                    user_authorized_domains = get_user_authorized_domains(current_user)
                    # Check recipient domains (inbound mail) OR sender domain (outbound mail)
                    user_can_access = any(domain in user_authorized_domains for domain in email['all_receiving_domains'])

                    # Also check sender domain for outbound mail
                    if not user_can_access and email.get('sender'):
                        # Extract email from "Name <email@domain.com>" format
                        import re
                        sender_match = re.search(r'<([^>]+@[^>]+)>', email['sender'])
                        if sender_match:
                            sender_email = sender_match.group(1)
                        else:
                            sender_email = email['sender']

                        sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
                        if sender_domain in user_authorized_domains:
                            user_can_access = True

                if not user_can_access:
                    flash('Access denied to this email', 'error')
                    return redirect(url_for('emails'))

            # Parse email body and headers from raw_email
            from email import message_from_string
            import re
            raw_email_for_parsing = get_raw_email_content(email)
            if raw_email_for_parsing:
                try:
                    msg = message_from_string(raw_email_for_parsing)

                    # Extract email body - prefer text/plain, fallback to text/html
                    email['full_text_content'] = ''
                    if msg.is_multipart():
                        text_parts = []
                        html_parts = []

                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == 'text/plain':
                                try:
                                    text_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                                except:
                                    pass
                            elif content_type == 'text/html':
                                try:
                                    html_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                                except:
                                    pass

                        # Prefer text/plain, fallback to stripped HTML
                        if text_parts:
                            email['full_text_content'] = '\n\n'.join(text_parts)
                        elif html_parts:
                            html_content = '\n\n'.join(html_parts)
                            # Remove style and script tags AND their contents
                            html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL|re.IGNORECASE)
                            html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL|re.IGNORECASE)
                            # Remove remaining HTML tags
                            html_content = re.sub(r'<[^>]+>', '', html_content)
                            # Decode HTML entities
                            import html
                            html_content = html.unescape(html_content)
                            # Clean up excessive whitespace
                            html_content = re.sub(r'\n\s*\n', '\n\n', html_content)
                            email['full_text_content'] = html_content.strip()
                    else:
                        try:
                            payload = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                            # Check if it's HTML content
                            if payload and ('<html' in payload.lower() or '<body' in payload.lower() or '<style' in payload.lower()):
                                # Remove style and script tags AND their contents
                                payload = re.sub(r'<style[^>]*>.*?</style>', '', payload, flags=re.DOTALL|re.IGNORECASE)
                                payload = re.sub(r'<script[^>]*>.*?</script>', '', payload, flags=re.DOTALL|re.IGNORECASE)
                                # Remove remaining HTML tags
                                payload = re.sub(r'<[^>]+>', '', payload)
                                # Decode HTML entities
                                import html
                                payload = html.unescape(payload)
                                # Clean up excessive whitespace
                                payload = re.sub(r'\n\s*\n', '\n\n', payload)
                            email['full_text_content'] = payload.strip()
                        except:
                            pass

                    # Extract ALL headers including duplicates (critical for forensics)
                    headers_text = ""
                    for key, value in msg._headers:
                        # Format multi-line headers properly
                        formatted_value = str(value).replace('\n', '\n\t')
                        headers_text += f"{key}: {formatted_value}\n"

                    # If no headers found via _headers, fallback to items()
                    if not headers_text:
                        for key, value in msg.items():
                            headers_text += f"{key}: {value}\n"

                    email['headers'] = headers_text

                    # Extract source IP from Received headers
                    email['source_ip'] = None

                    # Get the first external Received header (last one in the chain before our server)
                    received_headers = []
                    current_header = ""
                    for line in email['raw_email'].split('\n'):
                        if line.startswith('Received:'):
                            if current_header:
                                received_headers.append(current_header)
                            current_header = line
                        elif current_header and (line.startswith('\t') or line.startswith(' ')):
                            # Continuation of previous header
                            current_header += line
                        elif current_header:
                            received_headers.append(current_header)
                            current_header = ""
                    if current_header:
                        received_headers.append(current_header)

                    # Look for the first Received header with an IP address (before our server processed it)
                    my_hostname = os.getenv('MAIL_HOSTNAME', os.getenv('HOSTNAME', 'mailguard'))
                    for header in received_headers:
                        if my_hostname.lower() in header.lower() or 'by mailguard' in header.lower() or 'by openspacy' in header.lower():
                            # This is our server's header, look for the IP in it
                            # Pattern: "from hostname (hostname [IP])" or "from [IP]"
                            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
                            if ip_match:
                                email['source_ip'] = ip_match.group(1)
                                break

                    # If not found in Received headers, try X-Originating-IP
                    if not email.get('source_ip'):
                        for line in email['raw_email'].split('\n'):
                            if line.startswith('X-Originating-IP:'):
                                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                if ip_match:
                                    email['source_ip'] = ip_match.group(1)
                                    break

                    # Lookup country for source IP
                    email['source_country'] = None
                    email['source_country_code'] = None
                    if email.get('source_ip'):
                        try:
                            import geoip2.database
                            geoip_db_path = '/opt/spacyserver/data/GeoLite2-Country.mmdb'
                            reader = geoip2.database.Reader(geoip_db_path)
                            response = reader.country(email['source_ip'])
                            email['source_country'] = response.country.name
                            email['source_country_code'] = response.country.iso_code
                            reader.close()
                        except Exception as geo_e:
                            logger.debug(f"Could not lookup country for IP {email.get('source_ip')}: {geo_e}")

                except Exception as e:
                    logger.warning(f"Could not parse email for email {email.get('id')}: {e}")
                    email['full_text_content'] = email.get('content_summary', '')
                    email['headers'] = ''
            else:
                email['full_text_content'] = email.get('content_summary', '')
                email['headers'] = ''

            # Parse attachments from raw_email
            email['attachment_list'] = []
            email['attachment_count'] = 0
            raw_email_content_for_attachments = get_raw_email_content(email)
            if email.get('has_attachments') and raw_email_content_for_attachments:
                try:
                    from email import policy
                    msg = message_from_string(raw_email_content_for_attachments, policy=policy.default)

                    for part in msg.walk():
                        if part.get_content_disposition() == 'attachment':
                            filename = part.get_filename()
                            if filename:
                                email['attachment_list'].append(filename)

                    email['attachment_count'] = len(email['attachment_list'])
                    logger.info(f"Email {email.get('id')}: Found {email['attachment_count']} attachments: {email['attachment_list']}")
                except Exception as e:
                    logger.warning(f"Could not parse attachments for email {email.get('id')}: {e}")
            else:
                logger.info(f"Email {email.get('id')}: has_attachments={email.get('has_attachments')}, raw_email_len={len(email.get('raw_email', ''))}")

            # Get relay/delivery information from Postfix logs
            try:
                relay_info = get_relay_info_from_logs(email.get('message_id'))

                # If email was released/delivered but relay_info shows it went to spacyfilter (quarantined),
                # create synthetic relay info based on the release destination
                if (email.get('disposition') in ['released', 'delivered'] and
                    relay_info and relay_info.get('relay_host') == 'spacyfilter'):

                    # Extract recipient domain to lookup relay configuration
                    recipients_str = email.get('recipients', '')
                    recipient_domain = None
                    if recipients_str:
                        # Extract first recipient
                        if '@' in recipients_str:
                            try:
                                # Handle "Name <email>" format
                                if '<' in recipients_str:
                                    recipient_email = recipients_str.split('<')[1].split('>')[0]
                                else:
                                    recipient_email = recipients_str.split(',')[0].strip()
                                recipient_domain = recipient_email.split('@')[1].strip()
                            except:
                                pass

                    # Get relay host from client_domains
                    if recipient_domain:
                        try:
                            cursor2 = conn.cursor(dictionary=True)
                            cursor2.execute("""
                                SELECT relay_host, relay_port
                                FROM client_domains
                                WHERE domain = %s AND active = 1
                            """, (recipient_domain,))
                            domain_config = cursor2.fetchone()
                            cursor2.close()

                            if domain_config and domain_config.get('relay_host'):
                                # Create synthetic relay info for the release
                                relay_info = {
                                    'found': True,
                                    'status': 'delivered',
                                    'relay_host': f"{domain_config['relay_host']}:{domain_config.get('relay_port', 25)}",
                                    'relay_ip': domain_config['relay_host'],
                                    'recipient': recipients_str,
                                    'delivered_time': email.get('timestamp'),
                                    'delay': None,
                                    'queue_id': None,
                                    'upstream_queue_id': None,
                                    'dsn': '2.0.0'
                                }
                                logger.info(f"Generated synthetic relay info for released email {email_id}")
                        except Exception as lookup_err:
                            logger.error(f"Error looking up relay host for released email: {lookup_err}")

                email['relay_info'] = relay_info
            except Exception as e:
                logger.error(f"Error getting relay info for email {email_id}: {e}")
                email['relay_info'] = None

            # Debug logging
            logger.info(f"Email {email_id} template data: disposition={email.get('disposition')}, quarantine_status={email.get('quarantine_status')}, quarantine_reason={email.get('quarantine_reason')}")

            return render_template('email_detail.html',
                                 email=email,
                                 schema_info=schema_info)

    except Exception as e:
        flash(f'Database query failed: {e}', 'error')
        return render_template('error.html', error=f"Database query failed: {e}")

# ============================================================================
# EMAIL MANAGEMENT API ROUTES (Admin Only)
# ============================================================================

@app.route('/api/emails/<int:email_id>/mark-spam', methods=['POST'])
@login_required
@admin_required
def api_mark_spam(email_id):
    """Mark an email as spam and increase its spam score"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get email data for learning - try email_analysis first, then email_quarantine
        cursor.execute("""
            SELECT sender, subject, content_summary, raw_email, raw_email_path, recipients
            FROM email_analysis
            WHERE id = %s
        """, (email_id,))
        email = cursor.fetchone()
        from_quarantine = False

        # If not found in email_analysis, try email_quarantine
        if not email:
            cursor.execute("""
                SELECT sender, subject, text_content as content_summary, raw_email, recipients
                FROM email_quarantine
                WHERE id = %s
            """, (email_id,))
            email = cursor.fetchone()
            from_quarantine = True

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Extract body text from raw_email if available
        body_text = email.get('content_summary', '')
        raw_email_for_body = get_raw_email_content(email)
        if not body_text and raw_email_for_body:
            try:
                from email import message_from_string
                msg = message_from_string(raw_email_for_body)
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body_text = email.get('content_summary', '')

        # Check current spam training count (only for email_analysis)
        spam_train_count = 0
        if not from_quarantine:
            cursor.execute("SELECT spam_train_count FROM email_analysis WHERE id = %s", (email_id,))
            result = cursor.fetchone()
            spam_train_count = result.get('spam_train_count', 0) or 0

            # Check if already at max training (3)
            if spam_train_count >= 3:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Training limit reached',
                    'message': 'This email has already been marked as spam 3 times (maximum training limit)',
                    'train_count': spam_train_count,
                    'max_count': 3
                }), 400

        # Update spam score and category in the appropriate table
        if from_quarantine:
            cursor.execute("""
                UPDATE email_quarantine
                SET spam_score = GREATEST(spam_score + 5.0, 10.0),
                    user_classification = 'spam'
                WHERE id = %s
            """, (email_id,))
        else:
            spam_train_count += 1
            cursor.execute("""
                UPDATE email_analysis
                SET spam_score = GREATEST(spam_score + 5.0, 10.0),
                    email_category = 'spam',
                    spam_train_count = %s
                WHERE id = %s
            """, (spam_train_count, email_id))

        conn.commit()

        # Trigger spam learning
        try:
            logger.info(f"Starting spam learning for email {email_id}")
            from modules.spam_learner import spam_learner
            logger.info(f"spam_learner module imported successfully")

            # Extract recipient domains for learning
            recipient_domains = extract_receiving_domains(email.get('recipients', ''))
            logger.info(f"Extracted {len(recipient_domains)} recipient domains: {recipient_domains}")

            # Learn for each recipient domain
            for recipient_domain in recipient_domains:
                # Get client_domain_id
                cursor.execute("""
                    SELECT id FROM client_domains WHERE domain = %s AND active = 1
                """, (recipient_domain,))
                domain_result = cursor.fetchone()

                if domain_result:
                    client_domain_id = domain_result['id']

                    # Prepare email data for learning
                    email_data = {
                        'subject': email.get('subject', ''),
                        'body': body_text,
                        'sender': email.get('sender', '')
                    }

                    # Learn from spam
                    result = spam_learner.learn_from_spam(
                        email_data,
                        client_domain_id,
                        current_user.email
                    )

                    if result.get('success'):
                        logger.info(f"Learned {result.get('patterns_learned', 0)} spam patterns from email {email_id} for domain {recipient_domain}")
                    else:
                        logger.warning(f"Failed to learn spam patterns: {result.get('error')}")
        except Exception as learn_err:
            logger.error(f"Error during spam learning: {learn_err}")
            # Don't fail the whole operation if learning fails

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f'Email marked as spam ({spam_train_count}/3 training iterations)',
            'train_count': spam_train_count,
            'max_count': 3,
            'can_train_more': spam_train_count < 3
        })
    except Exception as e:
        logger.error(f"Error marking email as spam: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/<int:email_id>/quarantine-status', methods=['GET'])
@login_required
def api_email_quarantine_status(email_id):
    """Get quarantine status for an email from email_analysis"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get message_id from email_analysis
        cursor.execute("SELECT message_id FROM email_analysis WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'error': 'Email not found'}), 404

        # Check if it's in quarantine
        cursor.execute("""
            SELECT id, quarantine_status
            FROM email_quarantine
            WHERE message_id = %s AND quarantine_status = 'held'
        """, (email['message_id'],))

        quarantine = cursor.fetchone()

        cursor.close()
        conn.close()

        if quarantine:
            return jsonify({
                'quarantine_id': quarantine['id'],
                'status': quarantine['quarantine_status']
            })
        else:
            return jsonify({'quarantine_id': None, 'status': 'not_quarantined'})

    except Exception as e:
        logger.error(f"Error checking quarantine status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/emails/<int:email_id>/release', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Prevent release abuse
def api_release_email(email_id):
    """Release an email (mark as safe, reduce spam score)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get email data for learning - try email_analysis first, then email_quarantine
        cursor.execute("""
            SELECT sender, subject, content_summary, raw_email, raw_email_path, recipients
            FROM email_analysis
            WHERE id = %s
        """, (email_id,))
        email = cursor.fetchone()
        from_quarantine = False

        # If not found in email_analysis, try email_quarantine
        if not email:
            cursor.execute("""
                SELECT sender, subject, text_content as content_summary, raw_email, recipients
                FROM email_quarantine
                WHERE id = %s
            """, (email_id,))
            email = cursor.fetchone()
            from_quarantine = True

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # PERMISSION CHECK: Verify user has access to release this email
        if not current_user.is_admin():
            if current_user.role == 'client':
                # CLIENT role: Check if user is sender or recipient or alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Check if user is sender
                sender = email.get('sender', '')
                has_access = (current_user.email.lower() in sender.lower())

                # Check if user or aliases are in recipients
                if not has_access:
                    recipients_str = email.get('recipients', '')
                    # Check user email
                    has_access = current_user.email.lower() in recipients_str.lower()

                    # Check aliases
                    if not has_access:
                        for alias in aliases:
                            if alias.lower() in recipients_str.lower():
                                has_access = True
                                break

                if not has_access:
                    cursor.close()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            else:
                # DOMAIN_ADMIN: Check domain access
                user_domains = get_user_authorized_domains(current_user)

                # Extract recipient domains from recipients field
                import re
                recipient_domains = []
                recipients_str = email.get('recipients', '')
                if recipients_str:
                    email_pattern = r'([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))'
                    matches = re.findall(email_pattern, recipients_str)
                    recipient_domains = list(set([match[1].lower() for match in matches if match[1]]))

                # Case-insensitive domain comparison
                user_domains_lower = [d.lower() for d in user_domains]
                has_access = any(domain in user_domains_lower for domain in recipient_domains)

                if not has_access:
                    cursor.close()
                    conn.close()
                    logger.warning(f"Domain admin {current_user.email} denied release access. User domains: {user_domains}, Email domains: {recipient_domains}")
                    return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Extract body text from raw_email if available
        body_text = email.get('content_summary', '')
        raw_email_for_body = get_raw_email_content(email)
        if not body_text and raw_email_for_body:
            try:
                from email import message_from_string
                msg = message_from_string(raw_email_for_body)
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                else:
                    body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body_text = email.get('content_summary', '')

        # Mark email as safe by reducing spam score and updating category in the appropriate table
        if from_quarantine:
            cursor.execute("""
                UPDATE email_quarantine
                SET spam_score = LEAST(spam_score - 5.0, 0.0),
                    user_classification = 'ham',
                    quarantine_status = 'released',
                    released_by = %s,
                    released_at = NOW()
                WHERE id = %s
            """, (current_user.email, email_id))
        else:
            # Update disposition to 'delivered' to show it was manually approved and relayed
            cursor.execute("""
                UPDATE email_analysis
                SET spam_score = LEAST(spam_score - 5.0, 0.0),
                    disposition = 'delivered',
                    quarantine_status = NULL,
                    email_category = CASE
                        WHEN email_category IN ('spam', 'phishing') THEN 'legitimate'
                        ELSE email_category
                    END
                WHERE id = %s
            """, (email_id,))

            # Also update email_quarantine table if this email exists there
            cursor.execute("""
                UPDATE email_quarantine
                SET quarantine_status = 'released',
                    released_by = %s,
                    released_at = NOW()
                WHERE message_id = (SELECT message_id FROM email_analysis WHERE id = %s)
            """, (current_user.email, email_id))

        conn.commit()

        # SMTP Relay: Actually deliver the email if it has raw_email content
        raw_email_for_relay = get_raw_email_content(email)
        if not from_quarantine and raw_email_for_relay:
            try:
                import smtplib

                # Parse recipients first to determine domain
                recipients_str = email.get('recipients', '')
                if isinstance(recipients_str, str):
                    # Handle JSON array string or comma-separated
                    try:
                        recipients = json.loads(recipients_str)
                    except:
                        recipients = [r.strip() for r in recipients_str.split(',')]
                else:
                    recipients = recipients_str if recipients_str else []

                # Extract domain from first recipient
                recipient_domain = None
                if recipients:
                    first_recipient = recipients[0]
                    if '@' in first_recipient:
                        recipient_domain = first_recipient.split('@')[1].lower()

                # Look up relay_host from client_domains table
                relay_host = None
                relay_port = 25

                if recipient_domain:
                    cursor.execute("""
                        SELECT relay_host, relay_port
                        FROM client_domains
                        WHERE domain = %s AND active = 1
                    """, (recipient_domain,))
                    domain_config = cursor.fetchone()

                    if domain_config and domain_config.get('relay_host'):
                        relay_host = domain_config['relay_host']
                        relay_port = domain_config.get('relay_port', 25)
                        logger.info(f"Release: Using domain-specific relay {relay_host}:{relay_port} for {recipient_domain}")

                # Fallback to config file if no domain-specific relay found
                if not relay_host:
                    with open('/opt/spacyserver/config/quarantine_config.json', 'r') as f:
                        config = json.load(f)

                    release_config = config.get('release_destination', {})
                    mode = release_config.get('mode', 'mailguard')

                    if mode == 'mailguard':
                        dest = release_config.get('mailguard', {})
                    else:
                        dest = release_config.get('zimbra', {})

                    relay_host = dest.get('host', os.getenv('SPACY_RELAY_HOST', 'YOUR_EFA_SERVER_IP'))
                    relay_port = dest.get('port', 25)
                    logger.info(f"Release: Using fallback relay {relay_host}:{relay_port}")

                # Extract email addresses from "Name <email@domain.com>" format before sanitization
                sender_for_relay = email['sender']
                if '<' in sender_for_relay and '>' in sender_for_relay:
                    sender_for_relay = sender_for_relay.split('<')[1].split('>')[0].strip()

                recipients_for_relay = []
                for r in recipients:
                    if '<' in r and '>' in r:
                        recipients_for_relay.append(r.split('<')[1].split('>')[0].strip())
                    else:
                        recipients_for_relay.append(r)

                # SECURITY: Sanitize sender and recipients to prevent SMTP header injection
                try:
                    sanitized_sender = sanitize_email_address(sender_for_relay)
                    sanitized_recipients = [sanitize_email_address(r) for r in recipients_for_relay]
                except ValueError as ve:
                    logger.error(f"Email address validation failed for release {email_id}: {ve}")
                    raise  # Re-raise to trigger outer exception handler

                # Relay email using SMTP
                with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                    smtp.sendmail(sanitized_sender, sanitized_recipients, raw_email_for_relay)

                logger.info(f"Email {email_id} released and relayed by {current_user.email} to {relay_host}:{relay_port} for {len(recipients)} recipient(s)")

            except smtplib.SMTPException as smtp_err:
                logger.error(f"SMTP error relaying released email {email_id}: {smtp_err}")
                # Don't fail the whole operation if SMTP relay fails
                # Email is still marked as released in database
            except Exception as relay_err:
                logger.error(f"Error relaying released email {email_id}: {relay_err}")
                # Don't fail the whole operation if relay fails

        # Trigger ham learning (false positive learning)
        try:
            from modules.spam_learner import spam_learner

            # Extract recipient domains for learning
            recipient_domains = extract_receiving_domains(email.get('recipients', ''))

            # Learn for each recipient domain
            for recipient_domain in recipient_domains:
                # Get client_domain_id
                cursor.execute("""
                    SELECT id FROM client_domains WHERE domain = %s AND active = 1
                """, (recipient_domain,))
                domain_result = cursor.fetchone()

                if domain_result:
                    client_domain_id = domain_result['id']

                    # Prepare email data for learning
                    email_data = {
                        'subject': email.get('subject', ''),
                        'body': body_text,
                        'sender': email.get('sender', '')
                    }

                    # Learn from ham (false positive)
                    result = spam_learner.learn_from_ham(
                        email_data,
                        client_domain_id,
                        current_user.email
                    )

                    if result.get('success'):
                        logger.info(f"Learned {result.get('patterns_learned', 0)} ham patterns from released email {email_id} for domain {recipient_domain}")
                    else:
                        logger.warning(f"Failed to learn ham patterns: {result.get('error')}")
        except Exception as learn_err:
            logger.error(f"Error during ham learning on release: {learn_err}")
            # Don't fail the whole operation if learning fails

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Email released and marked as safe'})
    except Exception as e:
        logger.error(f"Error releasing email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/bulk-release', methods=['POST'])
@login_required
@limiter.limit("5 per minute")  # More restrictive for bulk operations
def api_bulk_release_emails():
    """Bulk release multiple emails (mark as safe, reduce spam score)"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No email IDs provided'}), 400

        success_count = 0
        error_count = 0
        errors = []

        for email_id in email_ids:
            try:
                logger.info(f"Bulk release: attempting to release email {email_id}")

                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)

                # Get email data for learning
                cursor.execute("""
                    SELECT sender, subject, content_summary, raw_email, raw_email_path, recipients
                    FROM email_analysis
                    WHERE id = %s
                """, (email_id,))
                email = cursor.fetchone()

                if not email:
                    cursor.close()
                    conn.close()
                    error_count += 1
                    errors.append(f"Email {email_id}: Not found")
                    continue

                # PERMISSION CHECK: Verify user has access to release this email
                if not current_user.is_admin():
                    if current_user.role == 'client':
                        # CLIENT role: Check if user is sender or recipient or alias recipient
                        conn_temp = get_db_connection()
                        cursor_temp = conn_temp.cursor(dictionary=True)
                        cursor_temp.execute("""
                            SELECT managed_email FROM user_managed_aliases
                            WHERE user_id = %s AND active = 1
                        """, (current_user.id,))
                        aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                        cursor_temp.close()
                        conn_temp.close()

                        sender = email.get('sender', '')
                        has_access = (current_user.email.lower() in sender.lower())

                        if not has_access:
                            recipients_str = email.get('recipients', '')
                            has_access = current_user.email.lower() in recipients_str.lower()

                            if not has_access:
                                for alias in aliases:
                                    if alias.lower() in recipients_str.lower():
                                        has_access = True
                                        break

                        if not has_access:
                            cursor.close()
                            conn.close()
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            continue
                    else:
                        # DOMAIN_ADMIN: Check domain access
                        user_domains = get_user_authorized_domains(current_user)

                        import re
                        recipient_domains = []
                        recipients_str = email.get('recipients', '')
                        if recipients_str:
                            email_pattern = r'([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))'
                            matches = re.findall(email_pattern, recipients_str)
                            recipient_domains = list(set([match[1].lower() for match in matches if match[1]]))

                        user_domains_lower = [d.lower() for d in user_domains]
                        has_access = any(domain in user_domains_lower for domain in recipient_domains)

                        if not has_access:
                            cursor.close()
                            conn.close()
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            continue

                # Extract body text from raw_email if available
                body_text = email.get('content_summary', '')
                raw_email_for_bulk_body = get_raw_email_content(email)
                if not body_text and raw_email_for_bulk_body:
                    try:
                        from email import message_from_string
                        msg = message_from_string(raw_email_for_bulk_body)
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break
                        else:
                            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        body_text = email.get('content_summary', '')

                # Mark email as safe by reducing spam score and updating category
                cursor.execute("""
                    UPDATE email_analysis
                    SET spam_score = LEAST(spam_score - 5.0, 0.0),
                        disposition = 'delivered',
                        quarantine_status = NULL,
                        email_category = CASE
                            WHEN email_category IN ('spam', 'phishing') THEN 'legitimate'
                            ELSE email_category
                        END
                    WHERE id = %s
                """, (email_id,))

                # Also update email_quarantine table if this email exists there
                cursor.execute("""
                    UPDATE email_quarantine
                    SET quarantine_status = 'released',
                        released_by = %s,
                        released_at = NOW()
                    WHERE message_id = (SELECT message_id FROM email_analysis WHERE id = %s)
                """, (current_user.email, email_id))

                conn.commit()

                # SMTP Relay: Actually deliver the email if it has raw_email content
                raw_email_for_bulk_relay = get_raw_email_content(email)
                if raw_email_for_bulk_relay:
                    try:
                        import smtplib

                        # Parse recipients first to determine domain
                        recipients_str = email.get('recipients', '')
                        if isinstance(recipients_str, str):
                            # Handle JSON array string or comma-separated
                            try:
                                recipients = json.loads(recipients_str)
                            except:
                                recipients = [r.strip() for r in recipients_str.split(',')]
                        else:
                            recipients = recipients_str if recipients_str else []

                        # Extract domain from first recipient
                        recipient_domain = None
                        if recipients:
                            first_recipient = recipients[0]
                            if '@' in first_recipient:
                                recipient_domain = first_recipient.split('@')[1].lower()

                        # Look up relay_host from client_domains table
                        relay_host = None
                        relay_port = 25

                        if recipient_domain:
                            cursor.execute("""
                                SELECT relay_host, relay_port
                                FROM client_domains
                                WHERE domain = %s AND active = 1
                            """, (recipient_domain,))
                            domain_config = cursor.fetchone()

                            if domain_config and domain_config.get('relay_host'):
                                relay_host = domain_config['relay_host']
                                relay_port = domain_config.get('relay_port', 25)
                                logger.info(f"Bulk release: Using domain-specific relay {relay_host}:{relay_port} for {recipient_domain}")

                        # Fallback to config file if no domain-specific relay found
                        if not relay_host:
                            with open('/opt/spacyserver/config/quarantine_config.json', 'r') as f:
                                config = json.load(f)

                            release_config = config.get('release_destination', {})
                            mode = release_config.get('mode', 'mailguard')

                            if mode == 'mailguard':
                                dest = release_config.get('mailguard', {})
                            else:
                                dest = release_config.get('zimbra', {})

                            relay_host = dest.get('host', os.getenv('SPACY_RELAY_HOST', 'YOUR_EFA_SERVER_IP'))
                            relay_port = dest.get('port', 25)
                            logger.info(f"Bulk release: Using fallback relay {relay_host}:{relay_port}")

                        # Extract email addresses from "Name <email@domain.com>" format before sanitization
                        sender_for_relay = email['sender']
                        if '<' in sender_for_relay and '>' in sender_for_relay:
                            sender_for_relay = sender_for_relay.split('<')[1].split('>')[0].strip()

                        recipients_for_relay = []
                        for r in recipients:
                            if '<' in r and '>' in r:
                                recipients_for_relay.append(r.split('<')[1].split('>')[0].strip())
                            else:
                                recipients_for_relay.append(r)

                        # SECURITY: Sanitize sender and recipients to prevent SMTP header injection
                        try:
                            sanitized_sender = sanitize_email_address(sender_for_relay)
                            sanitized_recipients = [sanitize_email_address(r) for r in recipients_for_relay]
                        except ValueError as ve:
                            logger.error(f"Email address validation failed for bulk release {email_id}: {ve}")
                            raise

                        # Relay email using SMTP
                        with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                            smtp.sendmail(sanitized_sender, sanitized_recipients, raw_email_for_bulk_relay)

                        logger.info(f"Bulk release: Email {email_id} relayed by {current_user.email} to {relay_host}:{relay_port} for {len(recipients)} recipient(s)")

                    except smtplib.SMTPException as smtp_err:
                        logger.error(f"Bulk release: SMTP error relaying email {email_id}: {smtp_err}")
                        # Don't fail the whole operation if SMTP relay fails
                        # Email is still marked as released in database
                    except Exception as relay_err:
                        logger.error(f"Bulk release: Error relaying email {email_id}: {relay_err}")
                        # Don't fail the whole operation if relay fails

                # Trigger ham learning (false positive learning)
                try:
                    from modules.spam_learner import spam_learner

                    # Extract recipient domains for learning
                    recipient_domains = extract_receiving_domains(email.get('recipients', ''))

                    # Learn for each recipient domain
                    for recipient_domain in recipient_domains:
                        # Get client_domain_id
                        cursor.execute("""
                            SELECT id FROM client_domains WHERE domain = %s AND active = 1
                        """, (recipient_domain,))
                        domain_result = cursor.fetchone()

                        if domain_result:
                            client_domain_id = domain_result['id']

                            # Prepare email data for learning
                            email_data = {
                                'subject': email.get('subject', ''),
                                'body': body_text,
                                'sender': email.get('sender', '')
                            }

                            # Learn from ham (false positive)
                            result = spam_learner.learn_from_ham(
                                email_data,
                                client_domain_id,
                                current_user.email
                            )

                            if result.get('success'):
                                logger.info(f"Bulk release: Learned {result.get('patterns_learned', 0)} ham patterns from email {email_id} for domain {recipient_domain}")
                            else:
                                logger.warning(f"Bulk release: Failed to learn ham patterns: {result.get('error')}")
                except Exception as learn_err:
                    logger.error(f"Bulk release: Error during ham learning for email {email_id}: {learn_err}")
                    # Don't fail the whole operation if learning fails

                cursor.close()
                conn.close()

                success_count += 1
                logger.info(f"Bulk release email {email_id}: SUCCESS")

            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")
                logger.error(f"Bulk release email {email_id}: EXCEPTION - {str(e)}")

        return jsonify({
            'success': True,
            'message': f'Released {success_count} emails, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors
        })

    except Exception as e:
        logger.error(f"Error in bulk release: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/whitelist-sender', methods=['POST'])
@login_required
@admin_required
@limiter.limit("20 per hour")  # Prevent whitelist abuse
def api_whitelist_sender():
    """Add a sender to the whitelist"""
    try:
        data = request.get_json()
        sender = data.get('sender')

        if not sender:
            return jsonify({'success': False, 'error': 'Sender required'}), 400

        # Load bec_config.json
        config_path = '/opt/spacyserver/config/bec_config.json'
        with open(config_path, 'r') as f:
            bec_config = json.load(f)

        # Add to authentication_aware whitelist
        if 'whitelist' not in bec_config:
            bec_config['whitelist'] = {}
        if 'authentication_aware' not in bec_config['whitelist']:
            bec_config['whitelist']['authentication_aware'] = {}
        if 'senders' not in bec_config['whitelist']['authentication_aware']:
            bec_config['whitelist']['authentication_aware']['senders'] = {}

        # Add sender with default trust settings
        bec_config['whitelist']['authentication_aware']['senders'][sender] = {
            "trust_score_bonus": 5,
            "description": f"Whitelisted via admin panel",
            "bypass_bec_checks": True
        }

        # Save back to file
        with open(config_path, 'w') as f:
            json.dump(bec_config, f, indent=2)

        return jsonify({'success': True, 'message': f'Sender {sender} added to whitelist'})
    except Exception as e:
        logger.error(f"Error whitelisting sender: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/threat-breakdown', methods=['GET'])
@login_required
def api_threat_breakdown():
    """Get detailed breakdown of security threats prevented"""
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Get user's authorized domains
        user_domains = get_user_authorized_domains(current_user)

        # Get counts for each threat category (mutually exclusive - each email counted once)
        # Hierarchy: Virus > Phishing > Critical Spam > Categorized Spam
        # Filter: Last 30 days only
        query = """
            SELECT
                SUM(CASE
                    WHEN email_category = 'virus' OR quarantine_reason = 'dangerous_attachment' THEN 0
                    WHEN email_category = 'phishing' THEN 0
                    WHEN spam_score >= 50 THEN 1
                    ELSE 0
                END) as critical_spam,
                SUM(CASE
                    WHEN email_category = 'virus' OR quarantine_reason = 'dangerous_attachment' THEN 0
                    WHEN email_category = 'phishing' THEN 0
                    WHEN spam_score >= 50 THEN 0
                    WHEN email_category = 'spam' THEN 1
                    ELSE 0
                END) as categorized_spam,
                SUM(CASE
                    WHEN email_category = 'virus' OR quarantine_reason = 'dangerous_attachment' THEN 0
                    WHEN email_category = 'phishing' THEN 1
                    ELSE 0
                END) as phishing,
                SUM(CASE
                    WHEN email_category = 'virus' OR quarantine_reason = 'dangerous_attachment' THEN 1
                    ELSE 0
                END) as virus,
                SUM(CASE WHEN spam_score >= 50 OR email_category IN ('spam', 'phishing', 'virus') THEN 1 ELSE 0 END) as total
            FROM email_analysis
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        """

        params = []

        # Filter by domain for non-admin users
        if not current_user.is_admin():
            if user_domains:
                domain_conditions = []
                for domain in user_domains:
                    domain_conditions.append("recipients LIKE %s")
                    params.append(f'%@{domain}%')
                query += f" AND ({' OR '.join(domain_conditions)})"
            else:
                # No domains = no access
                query += " AND 1=0"

        cursor.execute(query, params)
        result = cursor.fetchone()

        cursor.close()
        db.close()

        return jsonify({
            'success': True,
            'critical_spam': result['critical_spam'] or 0,
            'categorized_spam': result['categorized_spam'] or 0,
            'phishing': result['phishing'] or 0,
            'virus': result['virus'] or 0,
            'total': result['total'] or 0
        })
    except Exception as e:
        logger.error(f"Error fetching threat breakdown: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/block-sender', methods=['POST'])
@login_required
def api_block_sender():
    """Block a sender - Client can only block specific senders for their domains"""
    try:
        data = request.get_json()
        sender = data.get('sender')

        if not sender:
            return jsonify({'success': False, 'error': 'Sender required'}), 400

        # Extract email address from sender
        sender_email = sender.lower()
        if '<' in sender_email and '>' in sender_email:
            sender_email = sender_email.split('<')[1].split('>')[0]

        # Get user's domains
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if user is admin/superadmin - they get ALL domains
        if current_user.role in ['admin', 'superadmin']:
            cursor.execute("""
                SELECT id, domain FROM client_domains WHERE active = 1
            """)
            user_domains = cursor.fetchall()
        else:
            # Regular users - get their assigned domains
            cursor.execute("""
                SELECT DISTINCT cd.id, cd.domain
                FROM client_domains cd
                JOIN user_domain_assignments uda ON cd.domain = uda.domain
                WHERE uda.user_id = %s AND cd.active = 1
            """, (current_user.id,))
            user_domains = cursor.fetchall()

        if not user_domains:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No authorized domains found'}), 403

        # Add blocking rule for user's domains
        rules_added = 0
        for domain_info in user_domains:
            domain_id = domain_info['id']

            # Check if rule already exists
            cursor.execute("""
                SELECT id FROM blocking_rules
                WHERE client_domain_id = %s AND rule_type = 'sender'
                AND rule_value = %s AND active = 1
            """, (domain_id, sender_email))

            if cursor.fetchone():
                continue

            # Insert blocking rule (exact match only for all users)
            cursor.execute("""
                INSERT INTO blocking_rules
                (client_domain_id, rule_type, rule_value, rule_pattern, description, created_at, created_by, active)
                VALUES (%s, 'sender', %s, 'exact', %s, NOW(), %s, 1)
            """, (
                domain_id,
                sender_email,
                f'Blocked by {current_user.email}',
                current_user.email
            ))
            rules_added += 1

        conn.commit()
        cursor.close()
        conn.close()

        if rules_added == 0:
            return jsonify({'success': True, 'message': 'Sender already blocked'})
        else:
            return jsonify({'success': True, 'message': f'Blocked {sender_email}'})

    except Exception as e:
        logger.error(f"Error blocking sender: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/<int:email_id>/delete', methods=['DELETE'])
@login_required
@admin_required
def api_delete_email(email_id):
    """Soft delete an email (mark as deleted)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Soft delete the email
        cursor.execute("""
            UPDATE email_analysis
            SET is_deleted = 1,
                deleted_at = NOW(),
                deleted_by = %s
            WHERE id = %s
        """, (current_user.email, email_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Email deleted'})
    except Exception as e:
        logger.error(f"Error deleting email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/<int:email_id>/undelete', methods=['POST'])
@login_required
@admin_required
def api_undelete_email(email_id):
    """Undelete an email (restore from deleted state)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Restore the email by clearing deleted flags and changing disposition
        # This handles both soft-deleted emails (is_deleted=1) and
        # automatically deleted emails (disposition='deleted')
        cursor.execute("""
            UPDATE email_analysis
            SET is_deleted = 0,
                deleted_at = NULL,
                deleted_by = NULL,
                disposition = CASE
                    WHEN disposition = 'deleted' THEN 'quarantined'
                    ELSE disposition
                END
            WHERE id = %s
        """, (email_id,))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Email {email_id} undeleted by {current_user.email}")
        return jsonify({'success': True, 'message': 'Email restored successfully'})
    except Exception as e:
        logger.error(f"Error undeleting email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/bulk-mark-spam', methods=['POST'])
@login_required
@admin_required
def api_bulk_mark_spam():
    """Mark multiple emails as spam"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update spam scores for all selected emails
        # Security: Validate all IDs are integers to prevent injection
        email_ids = [int(eid) for eid in email_ids]
        placeholders = ','.join(['%s'] * len(email_ids))
        query = """
            UPDATE email_analysis
            SET spam_score = GREATEST(spam_score + 5.0, 10.0),
                email_category = 'spam'
            WHERE id IN ({})
        """.format(placeholders)
        cursor.execute(query, email_ids)

        affected = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'count': affected, 'message': f'Marked {affected} emails as spam'})
    except Exception as e:
        logger.error(f"Error bulk marking spam: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/bulk-not-spam', methods=['POST'])
@login_required
@admin_required
def api_bulk_mark_not_spam():
    """Mark multiple emails as not spam (training the filter)"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update spam scores for all selected emails - reduce score and mark as clean
        # Security: Validate all IDs are integers to prevent injection
        email_ids = [int(eid) for eid in email_ids]
        placeholders = ','.join(['%s'] * len(email_ids))
        query = """
            UPDATE email_analysis
            SET spam_score = LEAST(spam_score - 5.0, 0.0),
                email_category = 'clean'
            WHERE id IN ({})
        """.format(placeholders)
        cursor.execute(query, email_ids)

        affected = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Bulk marked {affected} emails as not spam by {current_user.email}")

        return jsonify({'success': True, 'count': affected, 'message': f'Marked {affected} emails as not spam'})
    except Exception as e:
        logger.error(f"Error bulk marking not spam: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/bulk-whitelist', methods=['POST'])
@login_required
@admin_required
def api_bulk_whitelist():
    """Add multiple senders to whitelist"""
    try:
        data = request.get_json()
        senders = data.get('senders', [])

        if not senders:
            return jsonify({'success': False, 'error': 'No senders selected'}), 400

        # Load bec_config.json
        config_path = '/opt/spacyserver/config/bec_config.json'
        with open(config_path, 'r') as f:
            bec_config = json.load(f)

        # Ensure structure exists
        if 'whitelist' not in bec_config:
            bec_config['whitelist'] = {}
        if 'authentication_aware' not in bec_config['whitelist']:
            bec_config['whitelist']['authentication_aware'] = {}
        if 'senders' not in bec_config['whitelist']['authentication_aware']:
            bec_config['whitelist']['authentication_aware']['senders'] = {}

        # Add all senders
        count = 0
        for sender in senders:
            if sender not in bec_config['whitelist']['authentication_aware']['senders']:
                bec_config['whitelist']['authentication_aware']['senders'][sender] = {
                    "trust_score_bonus": 5,
                    "description": f"Bulk whitelisted via admin panel",
                    "bypass_bec_checks": True
                }
                count += 1

        # Save back to file
        with open(config_path, 'w') as f:
            json.dump(bec_config, f, indent=2)

        return jsonify({'success': True, 'count': count, 'message': f'Added {count} sender(s) to whitelist'})
    except Exception as e:
        logger.error(f"Error bulk whitelisting: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/emails/bulk-delete', methods=['POST'])
@login_required
def api_bulk_delete():
    """Delete multiple emails"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        if len(email_ids) > 100:
            return jsonify({'success': False, 'error': 'Maximum 100 emails at once'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        success_count = 0
        error_count = 0
        errors = []

        # Get user's managed aliases for client users
        user_aliases = []
        if not current_user.is_admin() and current_user.role == 'client':
            cursor.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (current_user.id,))
            user_aliases = [row['managed_email'] for row in cursor.fetchall()]

        for email_id in email_ids:
            try:
                # Get email details
                cursor.execute("SELECT * FROM email_analysis WHERE id = %s", (email_id,))
                email = cursor.fetchone()

                if not email:
                    error_count += 1
                    errors.append(f"Email {email_id}: Not found")
                    continue

                # Check permissions
                if not current_user.is_admin():
                    if current_user.role == 'client':
                        # CLIENT: Check if user is sender or recipient or alias recipient
                        sender = email.get('sender', '')
                        recipients = email.get('recipients', '')

                        logger.info(f"Bulk delete permission check for email {email_id}: user={current_user.email}, sender={sender}, recipients={recipients}, aliases={user_aliases}")

                        has_access = (current_user.email.lower() in sender.lower() or
                                    current_user.email.lower() in recipients.lower())

                        if not has_access:
                            for alias in user_aliases:
                                logger.info(f"Checking alias {alias} in recipients {recipients}")
                                if alias.lower() in recipients.lower():
                                    has_access = True
                                    logger.info(f"Access granted via alias {alias}")
                                    break

                        if not has_access:
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            logger.warning(f"Email {email_id}: Access denied for user {current_user.email}")
                            continue
                    else:
                        # DOMAIN_ADMIN: Check domain access
                        user_domains = get_user_authorized_domains(current_user)
                        recipients = email.get('recipients', '')
                        has_access = any(f"@{domain}" in recipients for domain in user_domains)

                        if not has_access:
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            continue

                # Soft delete email
                cursor.execute("""
                    UPDATE email_analysis
                    SET is_deleted = 1,
                        deleted_at = NOW(),
                        deleted_by = %s
                    WHERE id = %s
                """, (current_user.email, email_id))
                success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Bulk delete: {success_count} success, {error_count} errors by {current_user.email}")

        return jsonify({
            'success': True,
            'message': f'Deleted {success_count} emails, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]
        })
    except Exception as e:
        logger.error(f"Error bulk deleting: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/email/<int:email_id>/attachment/<int:attachment_index>/download')
@login_required
@limiter.limit("30 per hour")  # Prevent bulk attachment download abuse
def download_email_attachment(email_id, attachment_index):
    """
    Download a specific attachment from an email
    Superadmin and domain admins only - domain admins must have access to the email's domain
    """
    try:
        # 1. Get email details first
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, message_id, sender, recipients,
                   raw_email, has_attachments
            FROM email_analysis
            WHERE id = %s
        """, (email_id,))
        email = cursor.fetchone()

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email not found'}), 404

        # 2. Verify user has access to this email (role-based authorization)
        has_access = False

        if current_user.is_admin():
            # Admin and superadmin have full access
            has_access = True
        elif current_user.role == 'domain_admin':
            # Domain admins: check if email belongs to their authorized domains
            user_domains = get_user_authorized_domains(current_user)

            # Extract sender domain (case-insensitive)
            sender_email = email.get('sender', '')
            sender_domain = sender_email.split('@')[-1].lower() if '@' in sender_email else ''

            # Extract recipient domains (case-insensitive)
            recipients_str = email.get('recipients', '')
            recipient_domains = [d.lower() for d in extract_receiving_domains(recipients_str)]

            # Case-insensitive domain comparison
            user_domains_lower = [d.lower() for d in user_domains]
            has_access = (sender_domain in user_domains_lower) or any(rd in user_domains_lower for rd in recipient_domains)

        elif current_user.role == 'client':
            # Client users: check if they are sender OR recipient OR have alias access
            sender = email.get('sender', '')
            recipients = email.get('recipients', '')

            # Check if user is sender
            if current_user.email.lower() in sender.lower():
                has_access = True
            # Check if user is in recipients
            elif current_user.email.lower() in recipients.lower():
                has_access = True
            else:
                # Check user's managed aliases
                cursor.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'].lower() for row in cursor.fetchall()]

                # Check if any alias is in recipients
                for alias in aliases:
                    if alias in recipients.lower():
                        has_access = True
                        break

        # 3. Deny access if not authorized
        if not has_access:
            cursor.close()
            conn.close()
            logger.warning(f"User {current_user.email} (role: {current_user.role}) attempted unauthorized attachment download for email {email_id}")
            return jsonify({'error': 'Access denied - You do not have permission to access this email'}), 403

        # 4. Parse email and extract attachment
        import email as email_lib
        from email import policy

        raw_email = email['raw_email']
        if not raw_email:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email content not available'}), 404

        msg = email_lib.message_from_string(raw_email, policy=policy.default)

        # Get all attachments
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content': part.get_content(),
                        'content_type': part.get_content_type()
                    })

        # Check if attachment index is valid
        if attachment_index < 0 or attachment_index >= len(attachments):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid attachment index'}), 404

        attachment = attachments[attachment_index]

        # 5. Security checks
        filename = attachment['filename']
        file_ext = os.path.splitext(filename)[1].lower()

        # High-risk file extensions
        dangerous_extensions = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js',
                              '.jar', '.scr', '.pif', '.msi', '.app', '.deb',
                              '.rpm', '.sh', '.com']

        is_dangerous = file_ext in dangerous_extensions

        # Note: Virus scanning is done on email arrival and displayed in UI
        # No need to re-scan on download

        # 6. Log the download to audit_log
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (
            current_user.id,
            'ATTACHMENT_DOWNLOAD',
            f'Downloaded attachment "{filename}" from email {email_id} (message_id: {email["message_id"]})',
            request.remote_addr
        ))
        conn.commit()

        cursor.close()
        conn.close()

        # 9. Serve the file
        from flask import send_file
        from io import BytesIO

        if isinstance(attachment['content'], bytes):
            file_data = BytesIO(attachment['content'])
        else:
            file_data = BytesIO(attachment['content'].encode('utf-8', errors='ignore'))

        # Add security headers
        response = send_file(
            file_data,
            mimetype=attachment['content_type'],
            as_attachment=True,
            download_name=filename
        )

        # Add warning header for dangerous files
        if is_dangerous:
            response.headers['X-File-Warning'] = 'Potentially dangerous file type'

        logger.info(f"User {current_user.email} (role: {current_user.role}) downloaded attachment '{filename}' from email {email_id}")

        return response

    except Exception as e:
        logger.error(f"Error downloading attachment: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to download attachment'}), 500

@app.route('/api/email/<int:email_id>/attachment/<int:attachment_index>/scan')
@login_required
def scan_email_attachment(email_id, attachment_index):
    """
    Scan an attachment for viruses without downloading
    Returns scan status: clean, infected, or error
    """
    try:
        # 1. Check if user is admin, superadmin or domain_admin
        if current_user.role not in ['admin', 'superadmin', 'domain_admin']:
            return jsonify({'error': 'Access denied'}), 403

        # 2. Get email details
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, message_id, sender, recipients,
                   raw_email, has_attachments
            FROM email_analysis
            WHERE id = %s
        """, (email_id,))
        email = cursor.fetchone()

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email not found'}), 404

        # 3. For domain admins, check if they have access to this email's domain
        if current_user.role == 'domain_admin':
            user_domains = get_user_authorized_domains(current_user)
            sender_email = email.get('sender', '')
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
            recipients_str = email.get('recipients', '')
            recipient_domains = extract_receiving_domains(recipients_str)
            has_access = (sender_domain in user_domains) or any(rd in user_domains for rd in recipient_domains)

            if not has_access:
                cursor.close()
                conn.close()
                return jsonify({'error': 'Access denied'}), 403

        # 4. Parse email and extract attachment
        import email as email_lib
        from email import policy

        raw_email = email['raw_email']
        if not raw_email:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email content not available'}), 404

        msg = email_lib.message_from_string(raw_email, policy=policy.default)

        # Get all attachments
        attachments = []
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        'filename': filename,
                        'content': part.get_content(),
                        'content_type': part.get_content_type()
                    })

        # Check if attachment index is valid
        if attachment_index < 0 or attachment_index >= len(attachments):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid attachment index'}), 404

        attachment = attachments[attachment_index]
        filename = attachment['filename']
        file_ext = os.path.splitext(filename)[1].lower()

        # 5. Save to temporary file for virus scanning
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp:
            if isinstance(attachment['content'], bytes):
                tmp.write(attachment['content'])
            else:
                tmp.write(attachment['content'].encode('utf-8', errors='ignore'))
            tmp_path = tmp.name

        # 6. Virus scan with ClamAV
        scan_status = 'clean'
        virus_name = None
        try:
            import subprocess
            result = subprocess.run(
                ['clamdscan', '--no-summary', tmp_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if 'FOUND' in result.stdout:
                scan_status = 'infected'
                # Try to extract virus name from output
                if ':' in result.stdout:
                    virus_name = result.stdout.split(':')[-1].strip()
                logger.warning(f"Virus detected in attachment scan: {filename} from email {email_id} - {virus_name}")
            else:
                logger.info(f"Attachment scan clean: {filename} from email {email_id}")
        except subprocess.TimeoutExpired:
            scan_status = 'error'
            logger.error(f"ClamAV scan timeout for attachment: {filename}")
        except Exception as e:
            scan_status = 'error'
            logger.error(f"ClamAV scan failed for attachment: {e}")

        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except:
            pass

        cursor.close()
        conn.close()

        return jsonify({
            'status': scan_status,
            'filename': filename,
            'virus_name': virus_name
        })

    except Exception as e:
        logger.error(f"Error scanning attachment: {e}")
        return jsonify({'error': 'Failed to scan attachment', 'status': 'error'}), 500

@app.route('/api/volume-metrics/<domain>')
@login_required
def get_volume_metrics_api(domain):
    """API endpoint to get volume metrics for a specific domain"""
    
    # Check domain access
    if not current_user.is_admin():
        user_authorized_domains = get_user_authorized_domains(current_user)
        if domain not in user_authorized_domains:
            return jsonify({'error': 'Access denied'}), 403
    
    try:
        engine = get_db_engine()
        if not engine:
            return jsonify({'error': 'Database connection failed'}), 500
            
        with engine.connect() as conn:
            # Get last 7 days for quick metrics (parameterized)
            date_7_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')

            daily_volume_query = """
                SELECT DATE(ea.timestamp) as email_date, COUNT(*) as count
                FROM email_analysis ea
                WHERE ea.recipients LIKE :domain_pattern
                AND DATE(ea.timestamp) >= :date_7_days
                GROUP BY DATE(ea.timestamp)
                ORDER BY email_date
            """

            results = conn.execute(text(daily_volume_query), {
                'domain_pattern': f'%@{domain}%',
                'date_7_days': date_7_days_ago
            }).fetchall()
            daily_data = [{'date': str(row[0]), 'count': row[1]} for row in results]
            
            return jsonify({
                'domain': domain,
                'daily_volume': daily_data,
                'total_week': sum(row['count'] for row in daily_data)
            })
            
    except Exception as e:
        return jsonify({'error': f'Failed to get metrics: {str(e)}'}), 500

@app.route('/reports/enhanced-domain/<domain>')
@login_required
def enhanced_domain_report(domain):
    """Generate enhanced PDF report for a specific domain with 30-day metrics and trends"""
    
    # Check if user has access to this domain
    if not current_user.is_admin():
        user_authorized_domains = get_user_authorized_domains(current_user)
        if domain not in user_authorized_domains:
            flash('Access denied for this domain report', 'error')
            return redirect(url_for('dashboard'))
    
    # Check if domain is in hosted domains
    if domain not in HOSTED_DOMAINS:
        flash('Enhanced reports are only available for hosted domains', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get date range (last 30 days)
        date_to = datetime.now().strftime('%Y-%m-%d')
        date_from = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

        # Get database engine
        engine = get_db_engine()
        if not engine:
            flash('Database connection failed', 'error')
            return redirect(url_for('dashboard'))

        # Build user-specific filter clause based on role
        user_filter_clause = None
        try:
            # Get user aliases if client role
            user_aliases = None
            if current_user.role == 'client':
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                user_aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

            # Get filter conditions based on user role
            filter_result = get_user_email_filter_conditions(
                user=current_user,
                user_aliases=user_aliases,
                authorized_domains=get_user_authorized_domains(current_user) if not current_user.is_admin() else None,
                hosted_domains=HOSTED_DOMAINS if current_user.is_admin() else None
            )
            user_filter_clause = filter_result['where_clause']
            logger.info(f"Report filter: {filter_result['description']}")
        except Exception as e:
            logger.error(f"Error building user filter: {e}")
            flash(f'Error building report filters: {str(e)}', 'error')
            return redirect(url_for('dashboard'))

        # Create enhanced report generator
        report_generator = EnhancedEmailReportGenerator()

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            temp_path = tmp_file.name

        # Generate enhanced report with user info and filtering
        user_info = {
            'name': current_user.get_display_name() if hasattr(current_user, 'get_display_name') else f"{current_user.first_name} {current_user.last_name}".strip(),
            'email': current_user.email
        }

        logger.info(f"Generating enhanced report for {domain} from {date_from} to {date_to}")
        logger.info(f"Temp path: {temp_path}")

        success = report_generator.generate_enhanced_domain_report(
            engine, domain, date_from, date_to, temp_path, user_info, user_filter_clause
        )
        
        logger.info(f"Report generation success: {success}")
        
        if not success:
            logger.error(f"Report generation returned False for {domain}")
            flash('Failed to generate enhanced report', 'error')
            return redirect(url_for('dashboard'))
        
        return send_file(
            temp_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'{domain}_enhanced_email_report_{date_from}_to_{date_to}.pdf'
        )
        
    except Exception as e:
        logger.error(f'Enhanced report generation failed for {domain}: {str(e)}')
        logger.error(traceback.format_exc())
        flash(f'Enhanced report generation failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/test')
@login_required 
def admin_test():
    """Test admin functionality"""
    try:
        # Check if user has admin access
        if not current_user.is_admin():
            return jsonify({
                'error': 'Admin access required',
                'user_id': current_user.id,
                'user_role': getattr(current_user, 'role', 'unknown'),
                'is_admin': current_user.is_admin()
            }), 403
        
        # Test database connection
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Test user query
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'user_count': user_count,
            'current_user': {
                'id': current_user.id,
                'email': current_user.email,
                'role': getattr(current_user, 'role', 'unknown'),
                'is_admin': current_user.is_admin()
            }
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'user_info': {
                'id': getattr(current_user, 'id', None),
                'authenticated': current_user.is_authenticated
            }
        }), 500

@app.route('/admin/users/simple')
@login_required
@superadmin_required  
def admin_users_simple():
    """Simple admin users page for testing"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get basic user info
        cursor.execute("SELECT id, email, domain, role, is_active FROM users ORDER BY id")
        users_raw = cursor.fetchall()
        
        # Convert to dict format
        users = []
        for user in users_raw:
            users.append({
                'id': user[0],
                'email': user[1], 
                'domain': user[2],
                'role': user[3],
                'is_active': user[4]
            })
        
        conn.close()
        
        return f"""
        <h1>Admin Users (Simple View)</h1>
        <p>Found {len(users)} users:</p>
        <ul>
        {''.join([f'<li>{user["email"]} - {user["role"]} - {"Active" if user["is_active"] else "Inactive"}</li>' for user in users])}
        </ul>
        <a href="/admin/users">Try Full Admin Page</a>
        """
        
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/admin/users')
@login_required
@superadmin_required
def admin_users():
    """Admin user management page"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all users with their stats
        cursor.execute("""
            SELECT id, email, domain, role, first_name, last_name, 
                   company_name, is_active, created_at, last_login,
                   failed_login_attempts, locked_until, authorized_domains
            FROM users
            ORDER BY role DESC, email
        """)
        
        users = []
        for row in cursor.fetchall():
            user_data = {
                'id': row[0], 'email': row[1], 'domain': row[2], 'role': row[3],
                'first_name': row[4], 'last_name': row[5], 'company_name': row[6],
                'is_active': row[7], 'created_at': row[8], 'last_login': row[9],
                'failed_login_attempts': row[10], 'locked_until': row[11], 'authorized_domains': row[12]
            }
            
            # Get email count for this user's domain
            cursor.execute("""
                SELECT COUNT(*) FROM email_analysis ea
                WHERE ea.recipients LIKE %s
            """, (f'%@{user_data["domain"]}%',))
            user_data['email_count'] = cursor.fetchone()[0]
            
            users.append(user_data)
        
        conn.close()
        
        return render_template('admin/users.html', users=users, hosted_domains=HOSTED_DOMAINS)
        
    except Exception as e:
        flash(f'Error loading users: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@superadmin_required
def admin_create_user():
    """Create new user"""
    if request.method == 'GET':
        return render_template('admin/create_user.html', hosted_domains=HOSTED_DOMAINS)
    
    try:
        # Get form data
        email = request.form.get('email', '').strip().lower()
        domain = request.form.get('domain', '').strip().lower()
        role = request.form.get('role', 'client')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        company_name = request.form.get('company_name', '').strip()
        password = request.form.get('password', '').strip()
        
        # Get authorized domains from checkboxes
        authorized_domains_list = request.form.getlist('authorized_domains')
        authorized_domains = ','.join(authorized_domains_list) if authorized_domains_list else domain
        
        # Validation
        if not email or '@' not in email:
            flash('Valid email is required', 'error')
            return render_template('admin/create_user.html', hosted_domains=HOSTED_DOMAINS)
        
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('admin/create_user.html', hosted_domains=HOSTED_DOMAINS)
        
        if role not in ['admin', 'domain_admin', 'client', 'viewer']:
            role = 'client'
        
        # If domain not provided, extract from email
        if not domain:
            domain = email.split('@')[1]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash(f'User {email} already exists', 'error')
            conn.close()
            return render_template('admin/create_user.html', hosted_domains=HOSTED_DOMAINS)
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user with authorized_domains
        cursor.execute("""
            INSERT INTO users (email, password_hash, domain, role, first_name, last_name, 
                             company_name, is_active, email_verified, authorized_domains)
            VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, TRUE, %s)
        """, (email, password_hash, domain, role, first_name, last_name, company_name or None, authorized_domains))
        
        user_id = cursor.lastrowid

        # If domain_admin, add domain assignment
        if role == 'domain_admin':
            cursor.execute("""
                INSERT INTO user_domain_assignments (user_id, domain, created_by, is_active)
                VALUES (%s, %s, %s, 1)
            """, (user_id, domain, current_user.id))

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'USER_CREATED_BY_ADMIN', %s, %s)
        """, (current_user.id, f'Created user {email}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        flash(f'User {email} created successfully', 'success')
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        flash(f'Error creating user: {e}', 'error')
        return render_template('admin/create_user.html', hosted_domains=HOSTED_DOMAINS)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@superadmin_required
def admin_edit_user(user_id):
    """Edit user details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if request.method == 'GET':
            # Get user for editing
            cursor.execute("""
                SELECT id, email, domain, role, first_name, last_name, company_name, is_active, authorized_domains
                FROM users WHERE id = %s
            """, (user_id,))
            user = cursor.fetchone()
            
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('admin_users'))
            
            user_data = {
                'id': user[0], 'email': user[1], 'domain': user[2], 'role': user[3],
                'first_name': user[4], 'last_name': user[5], 'company_name': user[6], 
                'is_active': user[7], 'authorized_domains': user[8]
            }
            
            conn.close()
            return render_template('admin/edit_user.html', user=user_data, hosted_domains=HOSTED_DOMAINS)
        
        else:  # POST - update user
            # Get form data
            email = request.form.get('email', '').strip().lower()
            domain = request.form.get('domain', '').strip().lower()
            role = request.form.get('role', 'client')
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            company_name = request.form.get('company_name', '').strip()
            is_active = request.form.get('is_active') == 'on'
            
            # Get authorized domains from checkboxes
            authorized_domains_list = request.form.getlist('authorized_domains')
            authorized_domains = ','.join(authorized_domains_list) if authorized_domains_list else domain
            
            # Validation
            if not email or '@' not in email:
                flash('Valid email is required', 'error')
                return redirect(url_for('admin_edit_user', user_id=user_id))

            if role not in ['admin', 'domain_admin', 'client', 'viewer']:
                role = 'client'
            
            # Update user including authorized_domains
            cursor.execute("""
                UPDATE users 
                SET email = %s, domain = %s, role = %s, first_name = %s, 
                    last_name = %s, company_name = %s, is_active = %s, authorized_domains = %s
                WHERE id = %s
            """, (email, domain, role, first_name, last_name, company_name or None, is_active, authorized_domains, user_id))
            
            # Log the action
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address)
                VALUES (%s, 'USER_UPDATED_BY_ADMIN', %s, %s)
            """, (current_user.id, f'Updated user {email}', request.remote_addr))
            
            conn.commit()
            conn.close()
            
            flash(f'User {email} updated successfully', 'success')
            return redirect(url_for('admin_users'))
            
    except Exception as e:
        flash(f'Error updating user: {e}', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@superadmin_required
def admin_reset_password(user_id):
    """Reset a user's password"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute("SELECT email, first_name FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        email, first_name = user
        
        # Generate new password
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password and reset failed attempts
        cursor.execute("""
            UPDATE users 
            SET password_hash = %s, failed_login_attempts = 0, locked_until = NULL
            WHERE id = %s
        """, (password_hash, user_id))
        
        # Log the action with the temporary password (securely in audit log only)
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'PASSWORD_RESET_BY_ADMIN', %s, %s)
        """, (current_user.id, f'Reset password for user {email}. Temp password: {new_password}', request.remote_addr))

        conn.commit()
        conn.close()

        # Security: Store password in session temporarily for secure display (expires after page view)
        session['temp_password'] = {
            'password': new_password,
            'email': email
        }

        # Don't show password in flash message (security risk: browser cache, screenshots, logs)
        flash(f'Password reset for {email}. The temporary password is available below - copy it now as it will only be shown once.', 'success')
        return redirect(url_for('admin_users'))
        
    except Exception as e:
        flash(f'Error resetting password: {e}', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user_status(user_id):
    """Toggle user active/inactive status"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Don't allow admin to deactivate themselves
        if user_id == current_user.id:
            flash('You cannot deactivate your own account', 'error')
            return redirect(url_for('admin_users'))
        
        # Get current status
        cursor.execute("SELECT email, is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_users'))
        
        email, current_status = user
        new_status = not current_status
        
        # Update status
        cursor.execute("UPDATE users SET is_active = %s WHERE id = %s", (new_status, user_id))
        
        # Log the action
        action = 'USER_ACTIVATED' if new_status else 'USER_DEACTIVATED'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (current_user.id, action, f'{action.replace("_", " ").title()} user {email}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        status_text = 'activated' if new_status else 'deactivated'
        flash(f'User {email} {status_text} successfully', 'success')
        return redirect(url_for('admin_users'))

    except Exception as e:
        flash(f'Error updating user status: {e}', 'error')
        return redirect(url_for('admin_users'))

#
# User Managed Aliases API Routes
#

@app.route('/api/users/<int:user_id>/managed-aliases', methods=['GET'])
@login_required
@superadmin_required
def get_user_managed_aliases(user_id):
    """Get aliases managed by a user (superadmin only)"""

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, managed_email, alias_label, created_at
            FROM user_managed_aliases
            WHERE user_id = %s AND active = 1
            ORDER BY managed_email
        """, (user_id,))

        aliases = cursor.fetchall()

        return jsonify({'success': True, 'aliases': aliases})

    except Exception as e:
        logger.error(f"Error fetching managed aliases for user {user_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/users/<int:user_id>/managed-aliases', methods=['POST'])
@login_required
@superadmin_required
def add_user_managed_alias(user_id):
    """Add managed alias to user (superadmin only)"""
    data = request.get_json()
    managed_email = data.get('managed_email', '').strip().lower()
    alias_label = data.get('alias_label', '').strip()

    if not managed_email or '@' not in managed_email:
        return jsonify({'success': False, 'error': 'Invalid email address'}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if alias already exists for this user
        cursor.execute("""
            SELECT id FROM user_managed_aliases
            WHERE user_id = %s AND managed_email = %s
        """, (user_id, managed_email))

        if cursor.fetchone():
            return jsonify({'success': False, 'error': 'This alias already exists for this user'}), 400

        # Insert new alias
        cursor.execute("""
            INSERT INTO user_managed_aliases (user_id, managed_email, alias_label, created_by)
            VALUES (%s, %s, %s, %s)
        """, (user_id, managed_email, alias_label, current_user.id))

        conn.commit()
        alias_id = cursor.lastrowid

        logger.info(f"Admin {current_user.email} added alias {managed_email} to user {user_id}")

        return jsonify({
            'success': True,
            'alias_id': alias_id,
            'message': 'Alias added successfully'
        })

    except Exception as e:
        logger.error(f"Error adding managed alias: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/users/<int:user_id>/managed-aliases/<int:alias_id>', methods=['DELETE'])
@login_required
@superadmin_required
def delete_user_managed_alias(user_id, alias_id):
    """Remove managed alias from user (superadmin only)"""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get alias details for logging
        cursor.execute("""
            SELECT managed_email FROM user_managed_aliases
            WHERE id = %s AND user_id = %s
        """, (alias_id, user_id))

        alias = cursor.fetchone()

        if not alias:
            return jsonify({'success': False, 'error': 'Alias not found'}), 404

        # Delete the alias
        cursor.execute("""
            DELETE FROM user_managed_aliases
            WHERE id = %s AND user_id = %s
        """, (alias_id, user_id))

        conn.commit()

        logger.info(f"Admin {current_user.email} removed alias {alias['managed_email']} from user {user_id}")

        return jsonify({'success': True, 'message': 'Alias removed successfully'})

    except Exception as e:
        logger.error(f"Error deleting managed alias: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/debug/user-info')
@login_required
@debug_only
def debug_user_info():
    """Debug route to check user's domain access"""
    user_info = {
        'user_id': current_user.id,
        'email': current_user.email,
        'domain': getattr(current_user, 'domain', 'NOT FOUND'),
        'role': getattr(current_user, 'role', 'NOT FOUND'),
        'is_admin': current_user.is_admin(),
        'authorized_domains_raw': getattr(current_user, 'authorized_domains', 'NOT FOUND'),
        'authorized_domains_parsed': get_user_authorized_domains(current_user),
        'all_user_attributes': [attr for attr in dir(current_user) if not attr.startswith('_')]
    }

    return jsonify(user_info)

@app.route('/user/preferences')
@login_required
def user_preferences():
    """User preferences page"""
    return render_template('user_preferences.html')

@app.route('/api/user/preferences', methods=['POST'])
@login_required
def update_user_preferences():
    """Update user preferences"""
    try:
        data = request.get_json()
        date_format = data.get('date_format', 'US')

        # Validate date format
        if date_format not in ['US', 'UK']:
            return jsonify({'success': False, 'error': 'Invalid date format'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET date_format = %s
            WHERE id = %s
        """, (date_format, current_user.id))

        conn.commit()
        conn.close()

        # Update current user object
        current_user.date_format = date_format

        return jsonify({
            'success': True,
            'message': 'Date format preference updated successfully'
        })

    except Exception as e:
        print(f"Error updating preferences: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/effectiveness')
@login_required
@superadmin_required
def effectiveness_dashboard():
    """Display spam fighting effectiveness metrics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current effectiveness (today)
        cursor.execute("""
            SELECT * FROM current_effectiveness
        """)
        current = cursor.fetchone() or {}

        # Check if we have enough data
        cursor.execute("SELECT COUNT(*) as count FROM email_analysis")
        email_count = cursor.fetchone()
        has_data = email_count and email_count.get('count', 0) > 10

        if not has_data:
            cursor.close()
            conn.close()
            flash("Not enough data yet to calculate effectiveness metrics. Process at least 10 emails first.", "info")
            return redirect(url_for('dashboard'))

        # Get 30-day trend data
        cursor.execute("""
            SELECT
                metric_date,
                effectiveness_score,
                week_avg,
                month_avg
            FROM effectiveness_trends
            ORDER BY metric_date
        """)
        trends = cursor.fetchall()

        trend_dates = []
        trend_scores = []
        trend_week_avg = []
        trend_month_avg = []

        for trend in trends:
            if trend and 'metric_date' in trend:
                trend_dates.append(trend['metric_date'].strftime('%Y-%m-%d'))
                trend_scores.append(float(trend.get('effectiveness_score', 0) or 0))
                trend_week_avg.append(float(trend.get('week_avg', 0) or 0))
                trend_month_avg.append(float(trend.get('month_avg', 0) or 0))

        # Get module stats for today
        cursor.execute("""
            SELECT
                module_name,
                triggers,
                accuracy
            FROM module_effectiveness
            WHERE metric_date = CURDATE()
            ORDER BY triggers DESC
            LIMIT 10
        """)
        module_stats = cursor.fetchall()

        # Get latest weekly summary
        cursor.execute("""
            SELECT * FROM effectiveness_weekly_summary
            ORDER BY week_end DESC
            LIMIT 1
        """)
        weekly_summary = cursor.fetchone() or {}

        # Get recipient verification stats
        recipient_verification_stats = {}
        try:
            cursor.execute("""
                SELECT COUNT(*) as today_rejections
                FROM recipient_rejections
                WHERE DATE(timestamp) = CURDATE()
            """)
            recipient_verification_stats['today_rejections'] = cursor.fetchone()['today_rejections']

            cursor.execute("""
                SELECT COUNT(*) as week_rejections
                FROM recipient_rejections
                WHERE timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY)
            """)
            recipient_verification_stats['week_rejections'] = cursor.fetchone()['week_rejections']

            cursor.execute("""
                SELECT COUNT(*) as domains_protected
                FROM client_domains
                WHERE active = 1 AND recipient_verification_status = 'supported'
            """)
            recipient_verification_stats['domains_protected'] = cursor.fetchone()['domains_protected']

            # Top rejected domains today
            cursor.execute("""
                SELECT domain, COUNT(*) as count
                FROM recipient_rejections
                WHERE DATE(timestamp) = CURDATE()
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 3
            """)
            recipient_verification_stats['top_domains'] = cursor.fetchall()

            # Check policy server status
            import subprocess
            try:
                result = subprocess.run(['systemctl', 'is-active', 'openefa-policy'],
                                      capture_output=True, text=True, timeout=5)
                recipient_verification_stats['policy_server_status'] = result.stdout.strip()
            except:
                recipient_verification_stats['policy_server_status'] = 'unknown'
        except Exception as e:
            logger.error(f"Error getting recipient verification stats: {e}")
            recipient_verification_stats = {
                'today_rejections': 0,
                'week_rejections': 0,
                'domains_protected': 0,
                'top_domains': [],
                'policy_server_status': 'unknown'
            }

        cursor.close()
        conn.close()

        return render_template('effectiveness_dashboard.html',
            current=current,
            trend_dates=trend_dates,
            trend_scores=trend_scores,
            trend_week_avg=trend_week_avg,
            trend_month_avg=trend_month_avg,
            recipient_verification=recipient_verification_stats,
            module_stats=module_stats,
            weekly_summary=weekly_summary
        )

    except Exception as e:
        app.logger.error(f"Error loading effectiveness dashboard: {e}")
        flash(f"Error loading dashboard: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/effectiveness/domain-admin')
@login_required
@domain_admin_required
def effectiveness_domain_admin():
    """Display system-wide spam fighting effectiveness metrics for domain admins
    Shows overall system performance without domain-specific details for privacy"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current effectiveness (today) - system-wide only
        cursor.execute("""
            SELECT * FROM current_effectiveness
        """)
        current = cursor.fetchone() or {}

        # Check if we have enough data
        cursor.execute("SELECT COUNT(*) as count FROM email_analysis")
        email_count = cursor.fetchone()
        has_data = email_count and email_count.get('count', 0) > 10

        if not has_data:
            cursor.close()
            conn.close()
            flash("Not enough data yet to calculate effectiveness metrics. Process at least 10 emails first.", "info")
            return redirect(url_for('dashboard'))

        # Get 30-day trend data
        cursor.execute("""
            SELECT
                metric_date,
                effectiveness_score,
                week_avg,
                month_avg
            FROM effectiveness_trends
            ORDER BY metric_date
        """)
        trends = cursor.fetchall()

        trend_dates = []
        trend_scores = []
        trend_week_avg = []
        trend_month_avg = []

        for trend in trends:
            if trend and 'metric_date' in trend:
                trend_dates.append(trend['metric_date'].strftime('%Y-%m-%d'))
                trend_scores.append(float(trend.get('effectiveness_score', 0) or 0))
                trend_week_avg.append(float(trend.get('week_avg', 0) or 0))
                trend_month_avg.append(float(trend.get('month_avg', 0) or 0))

        cursor.close()
        conn.close()

        return render_template('effectiveness_domain_admin.html',
            current=current,
            trend_dates=trend_dates,
            trend_scores=trend_scores,
            trend_week_avg=trend_week_avg,
            trend_month_avg=trend_month_avg
        )

    except Exception as e:
        app.logger.error(f"Error loading domain admin effectiveness dashboard: {e}")
        flash(f"Error loading dashboard: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/learning')
@login_required
def learning_dashboard():
    """Conversation Learning Statistics Dashboard with domain filtering"""
    try:
        from datetime import datetime, timedelta

        # Get user's authorized domains for filtering
        if current_user.is_admin():
            user_domains = HOSTED_DOMAINS
        else:
            user_domains = get_user_authorized_domains(current_user)

        if not user_domains:
            flash('No authorized domains found', 'error')
            return render_template('learning_dashboard.html', stats=None, error="No authorized domains")

        # Validate domains for SQL safety
        safe_domains = []
        for domain in user_domains:
            try:
                safe_domains.append(validate_domain(domain))
            except ValueError as e:
                logger.warning(f"Invalid domain in learning dashboard: {e}")
                continue

        if not safe_domains:
            flash('No valid authorized domains', 'error')
            return render_template('learning_dashboard.html', stats=None, error="No valid domains")

        # Build domain filter for SQL queries - PARAMETERIZED
        # For relationships, we want WHERE sender_domain IN (...) OR recipient_domain IN (...)
        query_params = {}
        sender_conditions = []
        recipient_conditions = []

        for idx, domain in enumerate(safe_domains):
            sender_param = f'sender_domain_{idx}'
            recipient_param = f'recipient_domain_{idx}'
            sender_conditions.append(f'%({sender_param})s')
            recipient_conditions.append(f'%({recipient_param})s')
            query_params[sender_param] = domain
            query_params[recipient_param] = domain

        domain_filter = f"(sender_domain IN ({','.join(sender_conditions)}) OR recipient_domain IN ({','.join(recipient_conditions)}))"

        # Use MySQL connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        stats = {}

        # Get filtered stats (relationships only, vocabulary/phrases are global)
        # Count relationships for user's domains
        cursor.execute(f'''
            SELECT COUNT(*) as relationship_count
            FROM conversation_relationships
            WHERE {domain_filter}
        ''', query_params)
        result = cursor.fetchone()
        stats['relationships'] = result['relationship_count'] if result else 0

        # Get global stats (vocabulary and phrases are learned across all emails)
        cursor.execute('SELECT * FROM conversation_learning_stats')
        view_stats = cursor.fetchone()
        if view_stats:
            stats['vocabulary'] = view_stats['vocabulary_count']
            stats['phrases'] = view_stats['phrase_count']
            stats['domains'] = len(safe_domains)  # User's domain count
            stats['new_patterns_24h'] = view_stats['new_patterns_24h']
            stats['new_patterns_7d'] = view_stats['new_patterns_7d']
            stats['avg_legitimate_score'] = view_stats['avg_legitimate_score'] or 0
        else:
            # Default values if view is empty
            stats.update({
                'vocabulary': 0, 'phrases': 0, 'domains': len(safe_domains),
                'new_patterns_24h': 0, 'new_patterns_7d': 0, 'avg_legitimate_score': 0
            })

        # Get top relationships (FILTERED by user domains)
        cursor.execute(f'''
            SELECT sender_domain, recipient_domain, message_count, avg_spam_score
            FROM conversation_relationships
            WHERE {domain_filter}
            ORDER BY message_count DESC
            LIMIT 10
        ''', query_params)
        stats['top_relationships'] = cursor.fetchall()

        # Get confidence metrics
        cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 5')
        result = cursor.fetchone()
        high_freq_vocab = result['COUNT(*)'] if result else 0

        # Count strong relationships (FILTERED by user domains)
        cursor.execute(f'''
            SELECT COUNT(*)
            FROM conversation_relationships
            WHERE message_count > 5 AND {domain_filter}
        ''', query_params)
        result = cursor.fetchone()
        strong_relationships = result['COUNT(*)'] if result else 0
        
        # Calculate confidence (0-100%)
        vocab_confidence = min(100, (stats['vocabulary'] / 500) * 100)
        relationship_confidence = min(100, (strong_relationships / 20) * 100)
        stats['overall_confidence'] = round((vocab_confidence + relationship_confidence) / 2, 1)
        
        # Determine effectiveness status based on confidence
        if stats['overall_confidence'] >= 80:
            stats['effectiveness_status'] = 'Optimal'
        elif stats['overall_confidence'] >= 50:
            stats['effectiveness_status'] = 'Effective'
        elif stats['overall_confidence'] >= 20:
            stats['effectiveness_status'] = 'Active Learning'
        else:
            stats['effectiveness_status'] = 'Initial Learning'
        
        # Initialize domain_stats as empty if not needed
        stats['domain_stats'] = []
        
        # Get most common phrases
        cursor.execute('''
            SELECT phrase, frequency 
            FROM conversation_phrases 
            ORDER BY frequency DESC 
            LIMIT 10
        ''')
        stats['top_phrases'] = cursor.fetchall()
        
        # Get learning timeline (last 7 days)
        timeline = []
        for i in range(7):
            day = datetime.now() - timedelta(days=i)
            day_str = day.strftime('%Y-%m-%d')
            
            cursor.execute('''
                SELECT COUNT(*) FROM conversation_vocabulary 
                WHERE DATE(last_seen) = %s
            ''', (day_str,))
            
            result = cursor.fetchone()
            count = result['COUNT(*)'] if result else 0
            timeline.append({
                'date': day_str,
                'patterns': count
            })
        
        stats['timeline'] = list(reversed(timeline))
        
        cursor.close()
        conn.close()
        
        return render_template('learning_dashboard.html', stats=stats)
        
    except Exception as e:
        import traceback
        app.logger.error(f"Error in learning dashboard: {e}")
        app.logger.error(f"Full traceback: {traceback.format_exc()}")
        return render_template('learning_dashboard.html', 
                             stats=None, 
                             error=f"Error loading statistics: {str(e)}")

@app.route('/learning/feed', methods=['POST'])
@login_required
def feed_email_to_learning():
    """Feed an email to the learning system by Message-ID"""
    try:
        import subprocess
        import json
        
        message_id = request.form.get('message_id', '').strip()
        override_score = request.form.get('override_score', '').strip()
        
        if not message_id:
            return jsonify({'success': False, 'error': 'Message-ID is required'}), 400
        
        # Clean up message ID (remove angle brackets if present)
        message_id = message_id.strip('<>')
        
        # Build command
        cmd = ['python3', '/opt/spacyserver/scripts/feed_email_by_id.py', message_id]
        if override_score:
            try:
                score = float(override_score)
                if 0 <= score <= 10:
                    cmd.append(str(score))
                else:
                    return jsonify({'success': False, 'error': 'Score must be between 0 and 10'}), 400
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid score format'}), 400
        
        # Execute the feed script
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and 'Successfully fed email' in result.stdout:
            # Parse the output to get details
            lines = result.stdout.strip().split('\n')
            details = {}
            for line in lines:
                if 'From:' in line:
                    details['sender'] = line.split('From:')[1].strip()
                elif 'Subject:' in line:
                    details['subject'] = line.split('Subject:')[1].strip()
                elif 'Spam Score:' in line:
                    details['spam_score'] = line.split('Spam Score:')[1].strip()
                elif 'vocabulary patterns' in line:
                    import re
                    match = re.search(r'Added (\d+) vocabulary', line)
                    if match:
                        details['patterns'] = match.group(1)
            
            return jsonify({
                'success': True,
                'message': 'Email successfully fed to learning system',
                'details': details
            })
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            if 'not found' in error_msg:
                return jsonify({'success': False, 'error': 'Email not found in database. Please check the Message-ID.'}), 404
            else:
                return jsonify({'success': False, 'error': error_msg[:200]}), 400
                
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Operation timed out'}), 500
    except Exception as e:
        app.logger.error(f"Error feeding email: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/learning/search', methods=['GET'])
@login_required
def search_emails_for_learning():
    """Search for emails to feed to learning system"""
    try:
        search_term = request.args.get('q', '').strip()
        if not search_term:
            return jsonify({'success': False, 'error': 'Search term required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if search contains special FULLTEXT operators or email addresses
        # FULLTEXT BOOLEAN MODE has issues with @, <, >, (, ), +, -, etc.
        has_special_chars = any(c in search_term for c in ['@', '<', '>', '(', ')', '+', '-', '"', '~'])

        # Search for emails by sender - use FULLTEXT for better performance (requires 4+ chars and no special chars)
        if len(search_term) >= 4 and not has_special_chars:
            query = """
                SELECT message_id, sender, recipients, subject, spam_score,
                       DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as time
                FROM email_analysis ea
                WHERE MATCH(ea.subject, ea.sender, ea.recipients, ea.message_id) AGAINST(%s IN BOOLEAN MODE)
                ORDER BY timestamp DESC
                LIMIT 20
            """
            search_pattern = f'{search_term}*'
            cursor.execute(query, (search_pattern,))
        else:
            # Fall back to LIKE for short searches or email addresses/special characters
            query = """
                SELECT message_id, sender, recipients, subject, spam_score,
                       DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as time
                FROM email_analysis ea
                WHERE ea.sender LIKE %s OR ea.message_id LIKE %s
                ORDER BY timestamp DESC
                LIMIT 20
            """
            search_pattern = f'%{search_term}%'
            cursor.execute(query, (search_pattern, search_pattern))
        
        emails = cursor.fetchall()
        
        # Format for display
        results = []
        for email in emails:
            results.append({
                'message_id': email['message_id'].strip('<>') if email['message_id'] else '',
                'sender': email['sender'],
                'subject': email['subject'][:50] + '...' if len(email['subject'] or '') > 50 else email['subject'],
                'spam_score': float(email['spam_score']) if email['spam_score'] else 0,
                'time': email['time']
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({'success': True, 'emails': results})
        
    except Exception as e:
        app.logger.error(f"Error searching emails: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Simple health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'authenticated': current_user.is_authenticated,
        'user_id': current_user.id if current_user.is_authenticated else None
    })

# ============================================================================
# MODULE-BASED ACCESS CONTROL
# ============================================================================

def check_module_access(domain, module_name):
    """Check if a domain has access to a specific module"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT enabled FROM client_modules
            WHERE client_domain = %s 
            AND module_name = %s
            AND enabled = TRUE
            AND (subscription_end IS NULL OR subscription_end > NOW())
        """
        
        cursor.execute(query, (domain, module_name))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return result is not None
    except Exception as e:
        print(f"Error checking module access: {e}")
        return False

@app.route('/compliance')
@login_required
def compliance_dashboard():
    """Compliance tracking dashboard - requires subscription"""
    
    # Get user's authorized domains
    user_domains = get_user_authorized_domains(current_user)
    
    # Try to get domain from URL parameter, or use the user's primary domain
    selected_domain = request.args.get('domain')
    if not selected_domain:
        # For admin, default to first available domain
        if current_user.role == 'admin' and user_domains:
            selected_domain = user_domains[0]
        else:
            selected_domain = user_domains[0] if user_domains else None
    
    if not selected_domain:
        flash('No domain selected', 'error')
        return redirect(url_for('dashboard'))
    
    # Check module access
    if not check_module_access(selected_domain, 'compliance_tracking'):
        return render_template('upgrade_needed.html', 
                             module='Compliance Tracking',
                             domain=selected_domain)
    
    # Get compliance data
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get recent compliance entities
        query = """
            SELECT ce.*, ea.subject, ea.sender, ea.timestamp
            FROM compliance_entities ce
            JOIN email_analysis ea ON ce.email_id = ea.id
            WHERE ce.client_domain = %s
            ORDER BY ce.extracted_date DESC
            LIMIT 100
        """
        
        cursor.execute(query, (selected_domain,))
        compliance_data = cursor.fetchall()
        
        # Get compliance statistics
        stats_query = """
            SELECT 
                entity_type,
                COUNT(*) as count,
                COUNT(DISTINCT email_id) as unique_emails
            FROM compliance_entities
            WHERE client_domain = %s
            AND extracted_date > DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY entity_type
        """
        
        cursor.execute(stats_query, (selected_domain,))
        compliance_stats = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('compliance_dashboard.html',
                             compliance_data=compliance_data,
                             compliance_stats=compliance_stats,
                             selected_domain=selected_domain,
                             user_domains=user_domains)
    except Exception as e:
        flash(f'Error loading compliance data: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/alerts')
@login_required
def alerts_dashboard():
    """Alert configuration dashboard - requires subscription"""
    
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', user_domains[0] if user_domains else None)
    
    if not selected_domain:
        flash('No domain selected', 'error')
        return redirect(url_for('dashboard'))
    
    # Check module access
    if not check_module_access(selected_domain, 'legal_alerts'):
        return render_template('upgrade_needed.html',
                             module='Legal Alerts',
                             domain=selected_domain)
    
    # Get configured alerts
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
            SELECT * FROM module_alerts
            WHERE client_domain = %s
            ORDER BY priority DESC, alert_name
        """
        
        cursor.execute(query, (selected_domain,))
        alerts = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('alerts_dashboard.html',
                             alerts=alerts,
                             selected_domain=selected_domain,
                             user_domains=user_domains)
    except Exception as e:
        flash(f'Error loading alerts: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/api/module-status/<domain>')
@login_required
def get_module_status(domain):
    """API endpoint to check module status for a domain"""

    # Verify user has access to this domain
    user_domains = get_user_authorized_domains(current_user)
    if domain not in user_domains and not current_user.is_admin():
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        query = """
            SELECT module_name, enabled, subscription_end
            FROM client_modules
            WHERE client_domain = %s
        """

        cursor.execute(query, (domain,))
        modules = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({'modules': modules})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BACKUP & RESTORE ROUTES
# ============================================================================

@app.route('/config/backup')
@login_required
@superadmin_required
def backup_management():
    """Backup and restore management page"""
    import glob
    import subprocess

    backup_dir = '/opt/spacyserver/backups'

    # Get list of existing backups
    backups = []
    try:
        # Get full system backups
        full_backups = sorted(glob.glob(f'{backup_dir}/full_backup_*.tar.gz'), reverse=True)
        for backup_file in full_backups[:10]:  # Show last 10 full backups
            stat = os.stat(backup_file)
            backups.append({
                'type': 'full',
                'filename': os.path.basename(backup_file),
                'path': backup_file,
                'size': stat.st_size,
                'size_human': f"{stat.st_size / (1024*1024):.2f} MB",
                'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

        # Get database backups
        db_backups = sorted(glob.glob(f'{backup_dir}/spacy_db_backup_*.sql.gz'), reverse=True)
        for backup_file in db_backups[:20]:  # Show last 20 backups
            stat = os.stat(backup_file)
            backups.append({
                'type': 'database',
                'filename': os.path.basename(backup_file),
                'path': backup_file,
                'size': stat.st_size,
                'size_human': f"{stat.st_size / (1024*1024):.2f} MB",
                'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })

        # Get config backups
        config_backups = sorted(glob.glob(f'{backup_dir}/*.backup.*'), reverse=True)
        for backup_file in config_backups[:10]:  # Show last 10 config backups
            stat = os.stat(backup_file)
            backups.append({
                'type': 'config',
                'filename': os.path.basename(backup_file),
                'path': backup_file,
                'size': stat.st_size,
                'size_human': f"{stat.st_size / 1024:.2f} KB",
                'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
    except Exception as e:
        logger.error(f"Error listing backups: {e}")

    # Get database size
    db_size = None
    try:
        engine = get_db_engine()
        if engine:
            with engine.connect() as conn:
                result = conn.execute(text(f"""
                    SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'size_mb'
                    FROM information_schema.tables
                    WHERE table_schema='{DB_NAME}'
                """)).fetchone()
                if result and result[0]:
                    db_size = f"{result[0]} MB"
    except Exception as e:
        logger.error(f"Error getting database size: {e}")

    # Get table statistics
    table_stats = []
    try:
        engine = get_db_engine()
        if engine:
            with engine.connect() as conn:
                results = conn.execute(text(f"""
                    SELECT table_name, table_rows
                    FROM information_schema.tables
                    WHERE table_schema='{DB_NAME}'
                    ORDER BY table_rows DESC
                    LIMIT 10
                """)).fetchall()
                table_stats = [{'name': row[0], 'rows': row[1]} for row in results]
    except Exception as e:
        logger.error(f"Error getting table stats: {e}")

    return render_template('backup_management.html',
                         backups=backups,
                         db_size=db_size,
                         table_stats=table_stats)

@app.route('/api/backup/create', methods=['POST'])
@login_required
@superadmin_required
def create_backup():
    """Create a new database backup with optional attachments"""
    import subprocess
    import tarfile

    try:
        # Get options from request
        data = request.get_json() or {}
        include_attachments = data.get('include_attachments', False)

        backup_dir = '/opt/spacyserver/backups'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'{backup_dir}/spacy_db_backup_{timestamp}.sql'
        my_cnf_path = '/etc/spacy-server/.my.cnf'

        # Create backup directory if it doesn't exist
        os.makedirs(backup_dir, exist_ok=True)

        # Run mysqldump with credentials from .my.cnf
        cmd = [
            'mysqldump',
            f'--defaults-file={my_cnf_path}',
            '--single-transaction',
            '--routines',
            '--triggers',
            '--events',
            DB_NAME
        ]

        with open(backup_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=300)

        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else 'Unknown error'
            logger.error(f"Backup failed: {error_msg}")
            return jsonify({'success': False, 'error': f'Backup failed: {error_msg}'}), 500

        # Compress the backup
        subprocess.run(['gzip', backup_file], check=True, timeout=60)
        backup_file_gz = f'{backup_file}.gz'

        final_backup_file = backup_file_gz

        # If including attachments, create a tarball with both database and attachments
        if include_attachments:
            attachments_dir = '/opt/spacyserver/quarantine/attachments'
            if os.path.exists(attachments_dir):
                tar_file = f'{backup_dir}/db_with_attachments_{timestamp}.tar.gz'

                # Filter to skip files with permission errors
                def tar_filter(tarinfo):
                    try:
                        # Try to access the file
                        os.stat(tarinfo.name)
                        return tarinfo
                    except PermissionError:
                        logger.warning(f"Skipping file in tar due to permission error: {tarinfo.name}")
                        return None

                with tarfile.open(tar_file, 'w:gz') as tar:
                    # Add database backup
                    tar.add(backup_file_gz, arcname=os.path.basename(backup_file_gz))
                    # Add attachments directory with error filtering
                    try:
                        tar.add(attachments_dir, arcname='attachments', filter=tar_filter)
                    except Exception as e:
                        logger.warning(f"Some attachments could not be added to backup: {e}")

                # Remove the standalone database backup
                os.remove(backup_file_gz)
                final_backup_file = tar_file
                logger.info(f"Created database backup with attachments: {tar_file}")

        # Get file size
        stat = os.stat(final_backup_file)
        size_mb = stat.st_size / (1024 * 1024)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        backup_type = 'with attachments' if include_attachments else 'database only'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DATABASE_BACKUP_CREATED', %s, %s)
        """, (current_user.id, f'Created backup ({backup_type}): {os.path.basename(final_backup_file)} ({size_mb:.2f} MB)', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Backup created successfully: {final_backup_file} ({size_mb:.2f} MB)")

        return jsonify({
            'success': True,
            'filename': os.path.basename(final_backup_file),
            'size': f'{size_mb:.2f} MB',
            'message': f'Backup created successfully: {os.path.basename(final_backup_file)}'
        })

    except subprocess.TimeoutExpired:
        logger.error("Backup timed out")
        return jsonify({'success': False, 'error': 'Backup operation timed out'}), 500
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/backup/download/<filename>')
@login_required
@superadmin_required
def download_backup(filename):
    """Download a backup file"""
    backup_dir = '/opt/spacyserver/backups'

    # Security: sanitize filename to prevent directory traversal
    filename = secure_filename(filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    file_path = os.path.join(backup_dir, filename)

    # Verify the resolved path is still within backup directory
    if not os.path.realpath(file_path).startswith(os.path.realpath(backup_dir)):
        logger.warning(f"Attempted path traversal attack: {filename}")
        return jsonify({'error': 'Invalid filename'}), 400

    if not os.path.exists(file_path):
        return jsonify({'error': 'Backup file not found'}), 404

    try:
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        return jsonify({'error': 'An error occurred'}), 500

@app.route('/api/backup/delete/<filename>', methods=['POST'])
@login_required
@superadmin_required
def delete_backup(filename):
    """Delete a backup file"""
    backup_dir = '/opt/spacyserver/backups'

    # Security: sanitize filename to prevent directory traversal
    filename = secure_filename(filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    # Continue with existing security check
    if '..' in filename or '/' in filename:
        return jsonify({'error': 'Invalid filename'}), 400

    file_path = os.path.join(backup_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({'error': 'Backup file not found'}), 404

    try:
        os.remove(file_path)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DATABASE_BACKUP_DELETED', %s, %s)
        """, (current_user.id, f'Deleted backup: {filename}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Backup deleted: {filename}")
        return jsonify({'success': True, 'message': f'Backup {filename} deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting backup: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/create-full', methods=['POST'])
@login_required
@superadmin_required
def create_full_backup():
    """Create a full system backup with customizable options"""
    import subprocess
    import shutil

    try:
        # Get options from request
        data = request.get_json() or {}
        include_config = data.get('include_config', True)
        include_webapp = data.get('include_webapp', True)
        include_attachments = data.get('include_attachments', False)

        backup_dir = '/opt/spacyserver/backups'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        full_backup_dir = f'{backup_dir}/full_backup_{timestamp}'
        my_cnf_path = '/etc/spacy-server/.my.cnf'
        spacy_root = '/opt/spacyserver'

        # Create backup directory
        os.makedirs(full_backup_dir, exist_ok=True)

        logger.info(f"Starting full system backup: {full_backup_dir} (config={include_config}, webapp={include_webapp}, attachments={include_attachments})")

        # 1. Backup configuration files (if selected)
        config_count = 0
        if include_config:
            logger.info("Backing up configuration files...")
            config_files = [
                '/opt/spacyserver/config/bec_config.json',
                '/opt/spacyserver/config/module_config.json',
                '/opt/spacyserver/config/email_filter_config.json',
                '/opt/spacyserver/config/authentication_config.json',
                '/opt/spacyserver/config/threshold_config.json',
                '/opt/spacyserver/config/trusted_domains.json',
                '/opt/spacyserver/config/rbl_config.json',
                '/opt/spacyserver/config/notification_config.json',
                '/opt/spacyserver/config/antivirus_config.json',
                '/opt/spacyserver/config/quarantine_config.json',
                '/opt/spacyserver/config/alias_mappings.json',
                '/opt/spacyserver/config/dns_whitelist.json'
            ]

            for config_file in config_files:
                if os.path.exists(config_file):
                    try:
                        shutil.copy2(config_file, full_backup_dir)
                        config_count += 1
                    except PermissionError:
                        logger.warning(f"Permission denied copying {config_file}, skipping...")

            # Backup /etc/spacy-server/ critical files
            logger.info("Backing up /etc/spacy-server/ files...")
            etc_spacy_dir = f'{full_backup_dir}/etc-spacy-server'
            os.makedirs(etc_spacy_dir, exist_ok=True)

            etc_files = [
                '/etc/spacy-server/.env',
                '/etc/spacy-server/.my.cnf',
                '/etc/spacy-server/.env.template',
                '/etc/spacy-server/README'
            ]

            for etc_file in etc_files:
                if os.path.exists(etc_file):
                    try:
                        shutil.copy2(etc_file, etc_spacy_dir)
                        config_count += 1
                    except PermissionError:
                        logger.warning(f"Permission denied copying {etc_file}, skipping...")
                    except Exception as e:
                        logger.warning(f"Error copying {etc_file}: {e}")

            # Backup systemd service files
            logger.info("Backing up systemd service files...")
            systemd_dir = f'{full_backup_dir}/systemd'
            os.makedirs(systemd_dir, exist_ok=True)

            systemd_services = [
                '/etc/systemd/system/spacyweb.service',
                '/etc/systemd/system/spacy-db-processor.service',
                '/etc/systemd/system/spacy-block-api.service',
                '/etc/systemd/system/spacy-release-api.service',
                '/etc/systemd/system/spacy-whitelist-api.service'
            ]

            for service_file in systemd_services:
                if os.path.exists(service_file):
                    try:
                        shutil.copy2(service_file, systemd_dir)
                        config_count += 1
                    except Exception as e:
                        logger.warning(f"Error copying {service_file}: {e}")

        # 2. Backup database
        logger.info("Backing up database...")
        db_backup_file = f'{full_backup_dir}/spacy_database.sql'

        cmd = [
            'mysqldump',
            f'--defaults-file={my_cnf_path}',
            '--single-transaction',
            '--routines',
            '--triggers',
            '--events',
            DB_NAME
        ]

        with open(db_backup_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=600)

        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else 'Database backup failed'
            logger.error(f"Database backup failed: {error_msg}")
            # Clean up partial backup
            shutil.rmtree(full_backup_dir)
            return jsonify({'success': False, 'error': f'Database backup failed: {error_msg}'}), 500

        # Compress database
        subprocess.run(['gzip', db_backup_file], check=True, timeout=180)

        # 3. Backup Python modules and web application (if selected)
        if include_webapp:
            logger.info("Backing up Python modules and web application...")
            modules_backup_dir = f'{full_backup_dir}/modules'
            os.makedirs(modules_backup_dir, exist_ok=True)

            # Error handler for copytree - skip files with permission errors
            def ignore_permission_errors(src, names):
                ignored = []
                for name in names:
                    path = os.path.join(src, name)
                    try:
                        # Try to access the file
                        os.stat(path)
                    except PermissionError:
                        logger.warning(f"Skipping file due to permission error: {path}")
                        ignored.append(name)
                return ignored

            # Copy key Python files
            python_files = ['email_filter.py', 'email_blocking.py']
            for py_file in python_files:
                src_file = f'{spacy_root}/{py_file}'
                if os.path.exists(src_file):
                    try:
                        shutil.copy2(src_file, modules_backup_dir)
                    except PermissionError:
                        logger.warning(f"Skipping {py_file} due to permission error")

            # Copy modules directory
            modules_src = f'{spacy_root}/modules'
            if os.path.exists(modules_src):
                try:
                    shutil.copytree(modules_src, f'{modules_backup_dir}/modules',
                                  dirs_exist_ok=True, ignore=ignore_permission_errors)
                except Exception as e:
                    logger.warning(f"Error copying modules directory: {e}")

            # Copy services directory
            services_src = f'{spacy_root}/services'
            if os.path.exists(services_src):
                try:
                    shutil.copytree(services_src, f'{modules_backup_dir}/services',
                                  dirs_exist_ok=True, ignore=ignore_permission_errors)
                except Exception as e:
                    logger.warning(f"Error copying services directory: {e}")

            # Copy web application (skip __pycache__ and other problematic files)
            def ignore_web_files(src, names):
                ignored = ignore_permission_errors(src, names)
                # Also ignore cache files
                ignored.extend([n for n in names if n == '__pycache__' or n.endswith('.pyc')])
                return ignored

            web_src = f'{spacy_root}/web'
            if os.path.exists(web_src):
                try:
                    shutil.copytree(web_src, f'{modules_backup_dir}/web',
                                  dirs_exist_ok=True, ignore=ignore_web_files)
                except Exception as e:
                    logger.warning(f"Error copying web directory: {e}")

            # Copy scripts directory
            scripts_src = f'{spacy_root}/scripts'
            if os.path.exists(scripts_src):
                try:
                    shutil.copytree(scripts_src, f'{modules_backup_dir}/scripts',
                                  dirs_exist_ok=True, ignore=ignore_web_files)
                except Exception as e:
                    logger.warning(f"Error copying scripts directory: {e}")

            # Copy tools directory
            tools_src = f'{spacy_root}/tools'
            if os.path.exists(tools_src):
                try:
                    shutil.copytree(tools_src, f'{modules_backup_dir}/tools',
                                  dirs_exist_ok=True, ignore=ignore_web_files)
                except Exception as e:
                    logger.warning(f"Error copying tools directory: {e}")

            # Copy root-level critical scripts
            root_scripts = ['calculate_effectiveness.py']
            for script in root_scripts:
                script_path = f'{spacy_root}/{script}'
                if os.path.exists(script_path):
                    try:
                        shutil.copy2(script_path, modules_backup_dir)
                    except Exception as e:
                        logger.warning(f"Error copying {script}: {e}")

        # 4. Backup email attachments (if selected)
        if include_attachments:
            logger.info("Backing up email attachments...")
            attachments_src = '/opt/spacyserver/quarantine/attachments'
            if os.path.exists(attachments_src):
                try:
                    # Define ignore function for attachments
                    def ignore_attachment_errors(src, names):
                        ignored = []
                        for name in names:
                            path = os.path.join(src, name)
                            try:
                                os.stat(path)
                            except PermissionError:
                                logger.warning(f"Skipping attachment due to permission error: {path}")
                                ignored.append(name)
                        return ignored

                    shutil.copytree(attachments_src, f'{full_backup_dir}/attachments',
                                  dirs_exist_ok=True, ignore=ignore_attachment_errors)
                except Exception as e:
                    logger.warning(f"Error copying attachments directory: {e}")

        # 5. Backup cron jobs
        logger.info("Backing up cron jobs...")
        try:
            cron_file = f'{full_backup_dir}/crontab_backup.txt'
            result = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0 and result.stdout:
                with open(cron_file, 'w') as f:
                    f.write(f"# Cron jobs backup - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# To restore: crontab {cron_file}\n\n")
                    f.write(result.stdout)
                logger.info("Cron jobs backed up successfully")
            else:
                logger.info("No cron jobs found or unable to read crontab")
        except Exception as e:
            logger.warning(f"Error backing up cron jobs: {e}")

        # 6. Create manifest file
        logger.info("Creating backup manifest...")
        manifest_file = f'{full_backup_dir}/MANIFEST.txt'
        with open(manifest_file, 'w') as f:
            f.write(f"SpaCy Email Security System - System Backup\n")
            f.write(f"=" * 60 + "\n\n")
            f.write(f"Backup Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Created By: {current_user.email}\n")
            f.write(f"Backup Type: Customized System Backup\n\n")
            f.write(f"Contents:\n")
            f.write(f"  - Database: {DB_NAME} (compressed)\n")
            f.write(f"    * All 56+ tables including quarantine, notifications, effectiveness metrics\n")
            f.write(f"    * Stored procedures, triggers, and events\n")
            if include_config:
                f.write(f"  - Configuration Files: {config_count} files\n")
                f.write(f"    * BEC, modules, email filter, authentication, notifications\n")
                f.write(f"    * RBL, quarantine, antivirus, trusted domains, DNS whitelist\n")
                f.write(f"    * /etc/spacy-server/: .env, .my.cnf (database credentials)\n")
                f.write(f"    * Systemd service files: spacyweb, spacy-db-processor, etc.\n")
            if include_webapp:
                f.write(f"  - Web Application: templates, static files, Python code\n")
                f.write(f"  - Python Modules: email_filter.py, modules/, services/\n")
                f.write(f"  - Scripts: scripts/ directory (all utility scripts)\n")
                f.write(f"    * behavioral_monitoring.py, calculate_daily_metrics.py\n")
                f.write(f"    * send_daily_notification_summary.py, system_health_monitor.py\n")
                f.write(f"  - Tools: tools/ directory\n")
                f.write(f"  - Root Scripts: calculate_effectiveness.py\n")
            if include_attachments:
                f.write(f"  - Email Attachments: quarantine/attachments/\n")
            f.write(f"  - Cron Jobs: crontab_backup.txt\n")
            f.write(f"\nRestore Instructions:\n")
            f.write(f"  1. Stop all SpaCy services\n")
            if include_config:
                f.write(f"  2. Restore configuration files to /opt/spacyserver/config/\n")
                f.write(f"  3. Restore /etc/spacy-server/ files (as root): sudo cp etc-spacy-server/* /etc/spacy-server/\n")
                f.write(f"     - Set permissions: sudo chown spacy-filter:spacy-filter /etc/spacy-server/.env /etc/spacy-server/.my.cnf\n")
                f.write(f"     - Set permissions: sudo chmod 600 /etc/spacy-server/.env /etc/spacy-server/.my.cnf\n")
                f.write(f"  3a. Restore systemd service files: sudo cp systemd/*.service /etc/systemd/system/\n")
                f.write(f"     - Reload systemd: sudo systemctl daemon-reload\n")
            f.write(f"  4. Restore database: gunzip spacy_database.sql.gz && mysql {DB_NAME} < spacy_database.sql\n")
            if include_webapp:
                f.write(f"  5. Restore Python modules, scripts, and web app to /opt/spacyserver/\n")
            if include_attachments:
                f.write(f"  6. Restore attachments to /opt/spacyserver/quarantine/attachments/\n")
            f.write(f"  7. Restore cron jobs: crontab crontab_backup.txt\n")
            f.write(f"  8. Restart all SpaCy services\n")

        # 5. Create tarball of the full backup
        logger.info("Creating compressed archive...")
        tar_filename = f'full_backup_{timestamp}.tar.gz'
        tar_filepath = f'{backup_dir}/{tar_filename}'

        subprocess.run([
            'tar', 'czf', tar_filepath,
            '-C', backup_dir,
            f'full_backup_{timestamp}'
        ], check=True, timeout=300)

        # Get tarball size
        tar_stat = os.stat(tar_filepath)
        size_mb = tar_stat.st_size / (1024 * 1024)

        # Clean up the uncompressed backup directory
        shutil.rmtree(full_backup_dir)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'FULL_SYSTEM_BACKUP_CREATED', %s, %s)
        """, (current_user.id, f'Created full backup: {tar_filename} ({size_mb:.2f} MB)', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Full backup created successfully: {tar_filepath} ({size_mb:.2f} MB)")

        # Build details about what was included
        details = {'database': 'included'}
        if include_config:
            details['config_files'] = config_count
        if include_webapp:
            details['webapp'] = 'included'
        if include_attachments:
            details['attachments'] = 'included'

        return jsonify({
            'success': True,
            'filename': tar_filename,
            'size': f'{size_mb:.2f} MB',
            'message': f'System backup created successfully: {tar_filename}',
            'details': details
        })

    except subprocess.TimeoutExpired:
        logger.error("Full backup timed out")
        if os.path.exists(full_backup_dir):
            shutil.rmtree(full_backup_dir)
        return jsonify({'success': False, 'error': 'Backup operation timed out'}), 500
    except Exception as e:
        logger.error(f"Error creating full backup: {e}")
        logger.error(traceback.format_exc())
        if os.path.exists(full_backup_dir):
            shutil.rmtree(full_backup_dir)
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# REPORT CONFIGURATION ROUTES
# ============================================================================

@app.route('/config/reports')
@login_required
def report_configuration():
    """Report configuration and generation page"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', user_domains[0] if user_domains else None)

    if not selected_domain:
        flash('No domain selected', 'error')
        return redirect(url_for('dashboard'))

    # Verify user has access to this domain
    if selected_domain not in user_domains and not current_user.is_admin():
        flash('Access denied to that domain', 'error')
        return redirect(url_for('config_dashboard'))

    # Get list of previously generated reports
    import glob
    reports_dir = '/opt/spacyserver/reports'
    os.makedirs(reports_dir, exist_ok=True)

    previous_reports = []
    try:
        # Look for email, activity, and comprehensive reports
        email_reports = glob.glob(f'{reports_dir}/*_email_report_*.pdf')
        activity_reports = glob.glob(f'{reports_dir}/server_activity_report_*.pdf')
        comprehensive_reports = glob.glob(f'{reports_dir}/comprehensive_security_report_*.txt')

        # Combine and sort by modification time (newest first)
        all_reports = email_reports + activity_reports + comprehensive_reports
        report_files = sorted(all_reports, key=lambda x: os.path.getmtime(x), reverse=True)

        for report_file in report_files[:20]:  # Show last 20 reports
            filename = os.path.basename(report_file)
            stat = os.stat(report_file)

            # For activity reports, only show to superadmin
            if 'server_activity_report' in filename:
                if current_user.is_superadmin():
                    previous_reports.append({
                        'filename': filename,
                        'path': report_file,
                        'size': stat.st_size,
                        'size_human': f"{stat.st_size / (1024*1024):.2f} MB" if filename.endswith('.pdf') else f"{stat.st_size / 1024:.2f} KB",
                        'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
            # For comprehensive reports, only show to admin/superadmin
            elif 'comprehensive_security_report' in filename:
                if current_user.is_admin() or current_user.is_superadmin():
                    previous_reports.append({
                        'filename': filename,
                        'path': report_file,
                        'size': stat.st_size,
                        'size_human': f"{stat.st_size / 1024:.2f} KB",
                        'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
            # For email reports, filter by domain
            elif selected_domain in filename or current_user.is_admin():
                previous_reports.append({
                    'filename': filename,
                    'path': report_file,
                    'size': stat.st_size,
                    'size_human': f"{stat.st_size / (1024*1024):.2f} MB",
                    'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
    except Exception as e:
        logger.error(f"Error listing reports: {e}")

    return render_template('report_configuration.html',
                         selected_domain=selected_domain,
                         user_domains=user_domains,
                         previous_reports=previous_reports)

@app.route('/api/reports/generate', methods=['POST'])
@login_required
def generate_report_api():
    """Generate a report via API"""
    try:
        data = request.get_json()
        domain = data.get('domain')
        date_from = data.get('date_from')
        date_to = data.get('date_to')
        report_type = data.get('report_type', 'email')  # 'email' or 'activity'

        # Activity reports are superadmin only
        if report_type == 'activity' and not current_user.is_superadmin():
            return jsonify({'success': False, 'error': 'Server activity reports are available to superadmin only'}), 403

        # Verify user has access to this domain (for email reports)
        if report_type == 'email':
            user_domains = get_user_authorized_domains(current_user)
            if domain not in user_domains and not current_user.is_admin():
                return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        # Validate dates
        try:
            datetime.strptime(date_from, '%Y-%m-%d')
            datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Create reports directory if it doesn't exist
        reports_dir = '/opt/spacyserver/reports'
        os.makedirs(reports_dir, exist_ok=True)

        # User info
        user_info = {
            'name': f"{current_user.first_name} {current_user.last_name}".strip() or current_user.email,
            'email': current_user.email
        }

        # Generate based on report type
        if report_type == 'activity':
            # Activity report (superadmin only)
            from activity_report_generator import ActivityReportGenerator

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'server_activity_report_{date_from}_to_{date_to}_{timestamp}.pdf'
            output_path = os.path.join(reports_dir, filename)

            logger.info(f"Generating activity report from {date_from} to {date_to}")

            activity_generator = ActivityReportGenerator()
            success = activity_generator.generate_activity_report(
                date_from, date_to, output_path, user_info
            )

        else:
            # Email report (default)
            # Get database engine
            engine = get_db_engine()
            if not engine:
                return jsonify({'success': False, 'error': 'Database connection failed'}), 500

            # Build user-specific filter clause based on role
            user_filter_clause = None
            try:
                # Get user aliases if client role
                user_aliases = None
                if current_user.role == 'client':
                    conn_temp = get_db_connection()
                    cursor_temp = conn_temp.cursor(dictionary=True)
                    cursor_temp.execute("""
                        SELECT managed_email FROM user_managed_aliases
                        WHERE user_id = %s AND active = 1
                    """, (current_user.id,))
                    user_aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                    cursor_temp.close()
                    conn_temp.close()

                # Get filter conditions based on user role
                filter_result = get_user_email_filter_conditions(
                    user=current_user,
                    user_aliases=user_aliases,
                    authorized_domains=user_domains if not current_user.is_admin() else None,
                    hosted_domains=HOSTED_DOMAINS if current_user.is_admin() else None
                )
                user_filter_clause = filter_result['where_clause']
                logger.info(f"API Report filter: {filter_result['description']}")
            except Exception as e:
                logger.error(f"Error building user filter: {e}")
                return jsonify({'success': False, 'error': f'Error building report filters: {str(e)}'}), 500

            # Create report generator
            report_generator = EnhancedEmailReportGenerator()

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'{domain}_email_report_{date_from}_to_{date_to}_{timestamp}.pdf'
            output_path = os.path.join(reports_dir, filename)

            logger.info(f"Generating email report for {domain} from {date_from} to {date_to}")

            # Generate report with user-specific filtering
            success = report_generator.generate_enhanced_domain_report(
                engine, domain, date_from, date_to, output_path, user_info, user_filter_clause
            )

        if not success:
            return jsonify({'success': False, 'error': 'Report generation failed'}), 500

        # Get file size
        stat = os.stat(output_path)
        size_mb = stat.st_size / (1024 * 1024)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        if report_type == 'activity':
            log_details = f'Generated server activity report: {filename} ({size_mb:.2f} MB)'
        else:
            log_details = f'Generated email report for {domain}: {filename} ({size_mb:.2f} MB)'

        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'REPORT_GENERATED', %s, %s)
        """, (current_user.id, log_details, request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Report generated successfully: {filename} ({size_mb:.2f} MB)")

        return jsonify({
            'success': True,
            'filename': filename,
            'size': f'{size_mb:.2f} MB',
            'message': f'Report generated successfully: {filename}'
        })

    except Exception as e:
        logger.error(f"Error generating report: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/reports/download/<filename>')
@login_required
def download_report(filename):
    """Download a generated report"""
    reports_dir = '/opt/spacyserver/reports'

    # Security: prevent directory traversal
    if '..' in filename or '/' in filename:
        return jsonify({'error': 'Invalid filename'}), 400

    file_path = os.path.join(reports_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({'error': 'Report not found'}), 404

    # Check if user has access to this domain's reports
    user_domains = get_user_authorized_domains(current_user)
    if not current_user.is_admin():
        # Extract domain from filename
        has_access = any(domain in filename for domain in user_domains)
        if not has_access:
            return jsonify({'error': 'Access denied'}), 403

    try:
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.error(f"Error downloading report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/delete/<filename>', methods=['POST'])
@login_required
@admin_required
def delete_report(filename):
    """Delete a generated report"""
    reports_dir = '/opt/spacyserver/reports'

    # Security: prevent directory traversal
    if '..' in filename or '/' in filename:
        return jsonify({'error': 'Invalid filename'}), 400

    file_path = os.path.join(reports_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({'error': 'Report not found'}), 404

    try:
        os.remove(file_path)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'REPORT_DELETED', %s, %s)
        """, (current_user.id, f'Deleted report: {filename}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Report deleted: {filename}")
        return jsonify({'success': True, 'message': f'Report {filename} deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting report: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/generate-comprehensive', methods=['POST'])
@login_required
@admin_required
def generate_comprehensive_report_api():
    """Generate comprehensive multi-organization security report"""
    try:
        data = request.get_json()
        days = data.get('days', 1)

        # Validate days parameter
        if not isinstance(days, int) or days < 1 or days > 90:
            return jsonify({'success': False, 'error': 'Days must be between 1 and 90'}), 400

        # Import the daily report generator
        sys.path.insert(0, '/opt/spacyserver/scripts')
        from security_daily_report import SecurityDailyReport

        # Generate report to string
        reporter = SecurityDailyReport(days=days, email_to=None)

        try:
            conn = reporter.get_connection()

            # Gather all statistics
            stats = {
                'overall': reporter.get_overall_stats(conn),
                'organizations': reporter.get_organization_breakdown(conn),
                'quarantine_reasons': reporter.get_quarantine_breakdown(conn),
                'false_positive': reporter.get_false_positive_rate(conn),
                'modules': reporter.get_module_effectiveness(conn),
                'header_forgery': reporter.get_header_forgery_stats(conn),
                'top_threats': reporter.get_top_threats(conn)
            }

            conn.close()

            # Generate report text
            report_text = reporter.generate_text_report(stats)

        except Exception as e:
            logger.error(f"Error generating comprehensive report stats: {e}")
            return jsonify({'success': False, 'error': f'Error generating report: {str(e)}'}), 500

        # Create reports directory if it doesn't exist
        reports_dir = '/opt/spacyserver/reports'
        os.makedirs(reports_dir, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        period_label = 'daily' if days == 1 else f'{days}day'
        filename = f'comprehensive_security_report_{period_label}_{timestamp}.txt'
        output_path = os.path.join(reports_dir, filename)

        # Write report to file
        with open(output_path, 'w') as f:
            f.write(report_text)

        # Get file size
        stat = os.stat(output_path)
        size_kb = stat.st_size / 1024

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        log_details = f'Generated comprehensive security report ({days} days): {filename} ({size_kb:.2f} KB)'

        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'COMPREHENSIVE_REPORT_GENERATED', %s, %s)
        """, (current_user.id, log_details, request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Comprehensive report generated successfully: {filename} ({size_kb:.2f} KB)")

        return jsonify({
            'success': True,
            'filename': filename,
            'size': f'{size_kb:.2f} KB',
            'message': f'Comprehensive security report generated successfully ({days} days of data)'
        })

    except Exception as e:
        logger.error(f"Error generating comprehensive report: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# DOMAIN MANAGEMENT ROUTES
# ============================================================================

@app.route('/config/domains')
@login_required
@superadmin_required
def domain_management():
    """Domain management page - superadmin only"""
    try:
        # Get filter parameter
        status_filter = request.args.get('status', 'all')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause based on status filter
        where_clause = ""
        if status_filter == 'active':
            where_clause = "WHERE cd.active = 1"
        elif status_filter == 'inactive':
            where_clause = "WHERE cd.active = 0"

        # Get all client domains with statistics
        query = f"""
            SELECT
                cd.id,
                cd.domain,
                cd.client_name,
                cd.relay_host,
                cd.active,
                cd.created_at,
                cd.updated_at,
                COUNT(DISTINCT br.id) as rule_count,
                COUNT(DISTINCT ba.id) as blocked_count
            FROM client_domains cd
            LEFT JOIN blocking_rules br ON cd.id = br.client_domain_id AND br.active = 1
            LEFT JOIN blocked_attempts ba ON cd.id = ba.client_domain_id
                AND ba.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            {where_clause}
            GROUP BY cd.id, cd.domain, cd.client_name, cd.relay_host, cd.active, cd.created_at, cd.updated_at
            ORDER BY cd.domain
        """

        cursor.execute(query)

        domains = cursor.fetchall()

        # Get total statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_domains,
                SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active_domains,
                SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END) as inactive_domains
            FROM client_domains
        """)

        stats = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template('domain_management.html',
                             domains=domains,
                             stats=stats,
                             status_filter=status_filter)

    except Exception as e:
        logger.error(f"Error loading domain management: {e}")
        flash(f'Error loading domains: {e}', 'error')
        return redirect(url_for('config_dashboard'))


@app.route('/api/domains/add', methods=['POST'])
@login_required
@superadmin_required
def add_domain():
    """Add a new client domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        client_name = data.get('client_name', '').strip()
        relay_host = data.get('relay_host', '').strip()
        relay_port = int(data.get('relay_port', 25))  # Default to 25 if not provided

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        # Validate domain format
        import re
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(domain_pattern, domain):
            return jsonify({'success': False, 'error': 'Invalid domain format'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if domain already exists
        cursor.execute("SELECT id, active FROM client_domains WHERE domain = %s", (domain,))
        existing = cursor.fetchone()

        if existing:
            if existing['active']:
                return jsonify({'success': False, 'error': 'Domain already exists'}), 400
            else:
                # Reactivate existing domain
                cursor.execute("""
                    UPDATE client_domains
                    SET active = 1, client_name = %s, relay_host = %s, relay_port = %s, updated_at = NOW()
                    WHERE domain = %s
                """, (client_name or domain, relay_host or None, relay_port, domain))
                conn.commit()

                # Log audit
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, details, ip_address)
                    VALUES (%s, 'DOMAIN_REACTIVATED', %s, %s)
                """, (current_user.id, f'Reactivated domain: {domain}', request.remote_addr))
                conn.commit()

                cursor.close()
                conn.close()

                # Reload HOSTED_DOMAINS to make change immediate
                reload_hosted_domains()

                # Update Postfix configuration files
                update_postfix_transport()
                update_postfix_relay_domains()

                return jsonify({'success': True, 'message': f'Domain {domain} reactivated successfully'})

        # Insert new domain
        cursor.execute("""
            INSERT INTO client_domains (domain, client_name, relay_host, relay_port, active, created_at, updated_at)
            VALUES (%s, %s, %s, %s, 1, NOW(), NOW())
        """, (domain, client_name or domain, relay_host or None, relay_port))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DOMAIN_ADDED', %s, %s)
        """, (current_user.id, f'Added domain: {domain} ({client_name})', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        # Reload HOSTED_DOMAINS to make change immediate
        reload_hosted_domains()

        # Update Postfix configuration files
        update_postfix_transport()
        update_postfix_relay_domains()

        return jsonify({'success': True, 'message': f'Domain {domain} added successfully'})

    except Exception as e:
        logger.error(f"Error adding domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/edit/<int:domain_id>', methods=['POST'])
@login_required
@superadmin_required
def edit_domain(domain_id):
    """Edit a client domain"""
    try:
        data = request.get_json()
        client_name = data.get('client_name', '').strip()
        relay_host = data.get('relay_host', '').strip()
        relay_port = int(data.get('relay_port', 25))  # Default to 25 if not provided

        if not client_name:
            return jsonify({'success': False, 'error': 'Client name is required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current domain info
        cursor.execute("SELECT domain FROM client_domains WHERE id = %s", (domain_id,))
        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Update domain
        cursor.execute("""
            UPDATE client_domains
            SET client_name = %s, relay_host = %s, relay_port = %s, updated_at = NOW()
            WHERE id = %s
        """, (client_name, relay_host or None, relay_port, domain_id))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DOMAIN_UPDATED', %s, %s)
        """, (current_user.id, f'Updated domain {domain_info["domain"]}: {client_name}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        # Update Postfix configuration files (in case relay_host changed)
        update_postfix_transport()
        update_postfix_relay_domains()

        return jsonify({'success': True, 'message': 'Domain updated successfully'})

    except Exception as e:
        logger.error(f"Error editing domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/toggle/<int:domain_id>', methods=['POST'])
@login_required
@superadmin_required
def toggle_domain(domain_id):
    """Activate/deactivate a client domain"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current status
        cursor.execute("SELECT domain, active FROM client_domains WHERE id = %s", (domain_id,))
        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        new_status = 0 if domain_info['active'] else 1

        # Update status
        cursor.execute("""
            UPDATE client_domains
            SET active = %s, updated_at = NOW()
            WHERE id = %s
        """, (new_status, domain_id))

        conn.commit()

        # Log audit
        action = 'DOMAIN_ACTIVATED' if new_status else 'DOMAIN_DEACTIVATED'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (current_user.id, action, f'{action.replace("DOMAIN_", "").title()} domain: {domain_info["domain"]}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        # Reload HOSTED_DOMAINS to make change immediate
        reload_hosted_domains()

        # Update Postfix configuration files (in case domain was activated/deactivated)
        update_postfix_transport()
        update_postfix_relay_domains()

        status_text = 'activated' if new_status else 'deactivated'
        return jsonify({'success': True, 'message': f'Domain {status_text} successfully'})

    except Exception as e:
        logger.error(f"Error toggling domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/delete/<int:domain_id>', methods=['POST'])
@login_required
@admin_required
def delete_domain(domain_id):
    """Delete a client domain"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get domain info before deleting
        cursor.execute("SELECT domain, client_name FROM client_domains WHERE id = %s", (domain_id,))
        domain_info = cursor.fetchone()

        if not domain_info:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Manually delete child records first (foreign keys may not have CASCADE)
        # Delete blocked_attempts
        cursor.execute("DELETE FROM blocked_attempts WHERE client_domain_id = %s", (domain_id,))

        # Delete blocking_rules
        cursor.execute("DELETE FROM blocking_rules WHERE client_domain_id = %s", (domain_id,))

        # Now delete the domain
        cursor.execute("DELETE FROM client_domains WHERE id = %s", (domain_id,))
        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DOMAIN_DELETED', %s, %s)
        """, (current_user.id, f'Deleted domain: {domain_info["domain"]} ({domain_info["client_name"]})', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        # Reload HOSTED_DOMAINS to make change immediate
        reload_hosted_domains()

        # Update Postfix configuration files (remove deleted domain)
        update_postfix_transport()
        update_postfix_relay_domains()

        return jsonify({'success': True, 'message': f'Domain {domain_info["domain"]} deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TRUSTED DOMAINS CONFIGURATION ROUTES
# ============================================================================

@app.route('/config/trusted')
@login_required
@superadmin_required
def trusted_domains_config():
    """Trusted domains configuration page (superadmin only)"""
    trusted_domains_file = '/opt/spacyserver/config/trusted_domains.json'

    try:
        with open(trusted_domains_file, 'r') as f:
            config = json.load(f)

        # Extract main list and notes
        domains = config.get('trusted_domains', [])
        notes = config.get('trusted_domains_notes', {})
        configuration = config.get('configuration', {})

        # Combine domains with their notes
        domains_with_notes = []
        for domain in domains:
            domains_with_notes.append({
                'domain': domain,
                'note': notes.get(domain, '')
            })

        return render_template('trusted_domains_config.html',
                             domains=domains_with_notes,
                             configuration=configuration,
                             total_domains=len(domains))

    except Exception as e:
        logger.error(f"Error loading trusted domains config: {e}")
        flash(f'Error loading configuration: {e}', 'error')
        return redirect(url_for('config_dashboard'))

@app.route('/api/trusted-domains/add', methods=['POST'])
@login_required
@superadmin_required
def add_trusted_domain():
    """Add a domain to the trusted domains list"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        note = data.get('note', '').strip()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        trusted_domains_file = '/opt/spacyserver/config/trusted_domains.json'

        # Read current config
        with open(trusted_domains_file, 'r') as f:
            config = json.load(f)

        # Check if domain already exists
        if domain in config.get('trusted_domains', []):
            return jsonify({'success': False, 'error': 'Domain already in trusted list'}), 400

        # Add domain
        if 'trusted_domains' not in config:
            config['trusted_domains'] = []
        config['trusted_domains'].append(domain)
        config['trusted_domains'].sort()

        # Add note if provided
        if note:
            if 'trusted_domains_notes' not in config:
                config['trusted_domains_notes'] = {}
            config['trusted_domains_notes'][domain] = note

        # Write back to file
        with open(trusted_domains_file, 'w') as f:
            json.dump(config, f, indent=2)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'TRUSTED_DOMAIN_ADDED', %s, %s)
        """, (current_user.id, f'Added trusted domain: {domain}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Trusted domain added: {domain} by {current_user.email}")

        return jsonify({
            'success': True,
            'message': f'Domain {domain} added to trusted list'
        })

    except Exception as e:
        logger.error(f"Error adding trusted domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trusted-domains/remove', methods=['POST'])
@login_required
@superadmin_required
def remove_trusted_domain():
    """Remove a domain from the trusted domains list"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        trusted_domains_file = '/opt/spacyserver/config/trusted_domains.json'

        # Read current config
        with open(trusted_domains_file, 'r') as f:
            config = json.load(f)

        # Check if domain exists
        if domain not in config.get('trusted_domains', []):
            return jsonify({'success': False, 'error': 'Domain not found in trusted list'}), 404

        # Remove domain
        config['trusted_domains'].remove(domain)

        # Remove note if exists
        if 'trusted_domains_notes' in config and domain in config['trusted_domains_notes']:
            del config['trusted_domains_notes'][domain]

        # Write back to file
        with open(trusted_domains_file, 'w') as f:
            json.dump(config, f, indent=2)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'TRUSTED_DOMAIN_REMOVED', %s, %s)
        """, (current_user.id, f'Removed trusted domain: {domain}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Trusted domain removed: {domain} by {current_user.email}")

        return jsonify({
            'success': True,
            'message': f'Domain {domain} removed from trusted list'
        })

    except Exception as e:
        logger.error(f"Error removing trusted domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trusted-domains/update-note', methods=['POST'])
@login_required
@admin_required
def update_trusted_domain_note():
    """Update the note for a trusted domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        note = data.get('note', '').strip()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        trusted_domains_file = '/opt/spacyserver/config/trusted_domains.json'

        # Read current config
        with open(trusted_domains_file, 'r') as f:
            config = json.load(f)

        # Check if domain exists
        if domain not in config.get('trusted_domains', []):
            return jsonify({'success': False, 'error': 'Domain not found in trusted list'}), 404

        # Update note
        if 'trusted_domains_notes' not in config:
            config['trusted_domains_notes'] = {}

        if note:
            config['trusted_domains_notes'][domain] = note
        else:
            # Remove note if empty
            if domain in config['trusted_domains_notes']:
                del config['trusted_domains_notes'][domain]

        # Write back to file
        with open(trusted_domains_file, 'w') as f:
            json.dump(config, f, indent=2)

        logger.info(f"Trusted domain note updated: {domain} by {current_user.email}")

        return jsonify({
            'success': True,
            'message': f'Note updated for {domain}'
        })

    except Exception as e:
        logger.error(f"Error updating trusted domain note: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# UNIFIED RULES MANAGEMENT (Blocking + Whitelist)
# ============================================================================

@app.route('/config/rules')
@login_required
def unified_rules_management():
    """Unified rules management page (blocking + whitelist + sender whitelist)"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', None)

    # If no domain selected, show domain selection page
    if not selected_domain:
        return render_template('blocking_rules_select_domain.html',
                             user_domains=user_domains,
                             page_title='Rules Management',
                             page_icon='fa-shield-alt',
                             page_description='Manage blocking and whitelist rules',
                             target_url='/config/rules')

    # Verify user has access to this domain
    if selected_domain not in user_domains and not current_user.is_admin():
        flash('Access denied to that domain', 'error')
        return redirect(url_for('config_dashboard'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id for the selected domain
        cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (selected_domain,))
        domain_result = cursor.fetchone()

        if not domain_result:
            flash(f'Domain {selected_domain} not found in client_domains table', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('config_dashboard'))

        client_domain_id = domain_result['id']

        # Get all BLOCKING rules for this domain + global blocking rules
        cursor.execute("""
            SELECT id, rule_type, rule_value, rule_pattern, description,
                   active, priority, created_at, created_by, is_global, whitelist
            FROM blocking_rules
            WHERE (client_domain_id = %s OR is_global = 1)
            AND (whitelist = 0 OR whitelist IS NULL)
            ORDER BY is_global DESC, priority DESC, created_at DESC
        """, (client_domain_id,))
        blocking_rules = cursor.fetchall()

        # Get all WHITELIST rules for this domain + global whitelist rules
        cursor.execute("""
            SELECT id, rule_type, rule_value, rule_pattern, description,
                   active, priority, created_at, created_by, is_global, whitelist
            FROM blocking_rules
            WHERE (client_domain_id = %s OR is_global = 1)
            AND whitelist = 1
            ORDER BY is_global DESC, priority DESC, created_at DESC
        """, (client_domain_id,))
        whitelist_rules = cursor.fetchall()

        # Get blocking statistics (last 30 days)
        cursor.execute("""
            SELECT COUNT(*) as total_blocked
            FROM blocked_attempts
            WHERE client_domain_id = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        """, (client_domain_id,))

        stats_result = cursor.fetchone()
        total_blocked = stats_result['total_blocked'] if stats_result else 0

        cursor.close()
        conn.close()

        # Get JSON-based sender whitelist
        from whitelist_manager import WhitelistManager
        wl_manager = WhitelistManager()
        sender_whitelist_data = wl_manager.get_domain_whitelist(selected_domain)
        sender_whitelist = sender_whitelist_data.get('senders', [])

        return render_template('rules_management.html',
                             selected_domain=selected_domain,
                             user_domains=user_domains,
                             blocking_rules=blocking_rules,
                             whitelist_rules=whitelist_rules,
                             sender_whitelist=sender_whitelist,
                             total_blocked=total_blocked)

    except Exception as e:
        logger.error(f"Error loading rules management: {e}")
        flash(f'Error loading rules management: {e}', 'error')
        return redirect(url_for('config_dashboard'))

# ============================================================================
# BLOCKING RULES CONFIGURATION ROUTES
# ============================================================================

@app.route('/config/blocking')
@login_required
def blocking_rules_config():
    """Blocking rules configuration page"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', None)

    # If no domain selected, show domain selection page
    if not selected_domain:
        return render_template('blocking_rules_select_domain.html',
                             user_domains=user_domains)

    # Verify user has access to this domain
    if selected_domain not in user_domains and not current_user.is_admin():
        flash('Access denied to that domain', 'error')
        return redirect(url_for('config_dashboard'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id for the selected domain
        cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (selected_domain,))
        domain_result = cursor.fetchone()

        if not domain_result:
            flash(f'Domain {selected_domain} not found in client_domains table', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('config_dashboard'))

        client_domain_id = domain_result['id']

        # Get all blocking rules for this domain + global rules (exclude whitelist rules)
        cursor.execute("""
            SELECT id, rule_type, rule_value, rule_pattern, description,
                   active, priority, created_at, created_by, is_global, whitelist
            FROM blocking_rules
            WHERE (client_domain_id = %s OR is_global = 1)
            AND (whitelist = 0 OR whitelist IS NULL)
            ORDER BY is_global DESC, priority DESC, created_at DESC
        """, (client_domain_id,))

        rules = cursor.fetchall()

        # Get blocking statistics (last 30 days)
        cursor.execute("""
            SELECT COUNT(*) as total_blocked
            FROM blocked_attempts
            WHERE client_domain_id = %s
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        """, (client_domain_id,))

        stats_result = cursor.fetchone()
        total_blocked = stats_result['total_blocked'] if stats_result else 0

        cursor.close()
        conn.close()

        return render_template('blocking_rules_config.html',
                             selected_domain=selected_domain,
                             user_domains=user_domains,
                             rules=rules,
                             total_rules=len(rules),
                             total_blocked=total_blocked)

    except Exception as e:
        logger.error(f"Error loading blocking rules: {e}")
        flash(f'Error loading blocking rules: {e}', 'error')
        return redirect(url_for('config_dashboard'))

@app.route('/api/blocking-rules/add', methods=['POST'])
@login_required
def add_blocking_rule():
    """Add a blocking rule"""
    # SECURITY: Only admins can modify blocking rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify blocking rules'}), 403

    try:
        data = request.get_json()
        domain = data.get('domain')
        rule_type = data.get('rule_type')
        rule_value = data.get('rule_value', '').strip()
        rule_pattern = data.get('rule_pattern', 'exact')
        description = data.get('description', '').strip()
        is_global = data.get('is_global', False)

        # SECURITY: Only superadmins can create global rules
        if is_global and not current_user.is_superadmin():
            return jsonify({'success': False, 'error': 'Only superadmins can create global rules'}), 403

        # Verify user has access to this domain (skip for global rules)
        if not is_global:
            user_domains = get_user_authorized_domains(current_user)
            if domain not in user_domains and not current_user.is_admin():
                return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not rule_value or not rule_type:
            return jsonify({'success': False, 'error': 'Rule type and value are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id (NULL for global rules)
        client_domain_id = None
        if not is_global:
            cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (domain,))
            domain_result = cursor.fetchone()

            if not domain_result:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': f'Domain {domain} not found'}), 404

            client_domain_id = domain_result['id']

        # Insert the blocking rule
        cursor.execute("""
            INSERT INTO blocking_rules
            (client_domain_id, rule_type, rule_value, rule_pattern, description,
             created_at, created_by, active, priority, whitelist, is_global)
            VALUES (%s, %s, %s, %s, %s, NOW(), %s, 1, 100, 0, %s)
        """, (client_domain_id, rule_type, rule_value, rule_pattern, description, current_user.email, 1 if is_global else 0))

        rule_id = cursor.lastrowid

        # Log the action
        scope = 'ALL DOMAINS (GLOBAL)' if is_global else domain
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'BLOCKING_RULE_ADDED', %s, %s)
        """, (current_user.id, f'Added {"GLOBAL " if is_global else ""}blocking rule for {scope}: {rule_type}={rule_value}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"{'Global ' if is_global else ''}blocking rule added by {current_user.email}: {rule_type}={rule_value} for {scope}")

        return jsonify({
            'success': True,
            'rule_id': rule_id,
            'message': f'{"Global " if is_global else ""}blocking rule added successfully'
        })

    except Exception as e:
        logger.error(f"Error adding blocking rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocking-rules/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_blocking_rule(rule_id):
    # SECURITY: Only admins can modify blocking rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify blocking rules'}), 403

    """Delete a blocking rule"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the rule to verify ownership
        cursor.execute("""
            SELECT br.*, cd.domain
            FROM blocking_rules br
            JOIN client_domains cd ON br.client_domain_id = cd.id
            WHERE br.id = %s
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if rule['domain'] not in user_domains and not current_user.is_admin():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Delete the rule
        cursor.execute("DELETE FROM blocking_rules WHERE id = %s", (rule_id,))

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'BLOCKING_RULE_DELETED', %s, %s)
        """, (current_user.id, f'Deleted blocking rule: {rule["rule_type"]}={rule["rule_value"]}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Blocking rule deleted by {current_user.email}: rule_id={rule_id}")

        return jsonify({'success': True, 'message': 'Blocking rule deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting blocking rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocking-rules/toggle/<int:rule_id>', methods=['POST'])
@login_required
def toggle_blocking_rule(rule_id):
    # SECURITY: Only admins can modify blocking rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify blocking rules'}), 403

    """Toggle active status of a blocking rule"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the rule to verify ownership
        cursor.execute("""
            SELECT br.*, cd.domain
            FROM blocking_rules br
            JOIN client_domains cd ON br.client_domain_id = cd.id
            WHERE br.id = %s
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if rule['domain'] not in user_domains and not current_user.is_admin():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Toggle active status
        new_status = 0 if rule['active'] else 1
        cursor.execute("UPDATE blocking_rules SET active = %s WHERE id = %s", (new_status, rule_id))

        # Log the action
        action_text = 'enabled' if new_status else 'disabled'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'BLOCKING_RULE_TOGGLED', %s, %s)
        """, (current_user.id, f'{action_text.capitalize()} blocking rule: {rule["rule_type"]}={rule["rule_value"]}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Blocking rule {action_text} by {current_user.email}: rule_id={rule_id}")

        return jsonify({
            'success': True,
            'active': new_status,
            'message': f'Blocking rule {action_text} successfully'
        })

    except Exception as e:
        logger.error(f"Error toggling blocking rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blocking-rules/update/<int:rule_id>', methods=['POST'])
@login_required
def update_blocking_rule(rule_id):
    """Update a blocking rule"""
    # SECURITY: Only admins can modify blocking rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify blocking rules'}), 403

    try:
        data = request.get_json()
        rule_type = data.get('rule_type')
        rule_value = data.get('rule_value', '').strip()
        rule_pattern = data.get('rule_pattern', 'exact')
        description = data.get('description', '').strip()
        is_global = data.get('is_global', False)

        # SECURITY: Only superadmins can update to global rules
        if is_global and not current_user.is_superadmin():
            return jsonify({'success': False, 'error': 'Only superadmins can create global rules'}), 403

        if not rule_value or not rule_type:
            return jsonify({'success': False, 'error': 'Rule type and value are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the existing rule to verify ownership
        cursor.execute("""
            SELECT br.*, cd.domain
            FROM blocking_rules br
            LEFT JOIN client_domains cd ON br.client_domain_id = cd.id
            WHERE br.id = %s AND (br.whitelist = 0 OR br.whitelist IS NULL)
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        # Verify user has access to this domain (skip for global rules)
        if not rule['is_global'] and not is_global:
            user_domains = get_user_authorized_domains(current_user)
            if rule['domain'] and rule['domain'] not in user_domains and not current_user.is_admin():
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update the rule
        if is_global:
            # Converting to global rule - set client_domain_id to NULL
            cursor.execute("""
                UPDATE blocking_rules
                SET rule_type = %s, rule_value = %s, rule_pattern = %s,
                    description = %s, is_global = %s, client_domain_id = NULL
                WHERE id = %s
            """, (rule_type, rule_value, rule_pattern, description, 1, rule_id))
        else:
            # Keep existing client_domain_id
            cursor.execute("""
                UPDATE blocking_rules
                SET rule_type = %s, rule_value = %s, rule_pattern = %s,
                    description = %s, is_global = %s
                WHERE id = %s
            """, (rule_type, rule_value, rule_pattern, description, 0, rule_id))

        # Log the action
        scope = 'ALL DOMAINS (GLOBAL)' if is_global else (rule['domain'] or 'unknown')
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'BLOCKING_RULE_UPDATED', %s, %s)
        """, (current_user.id, f'Updated {"GLOBAL " if is_global else ""}blocking rule for {scope}: {rule_type}={rule_value}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Blocking rule updated by {current_user.email}: rule_id={rule_id}")

        return jsonify({
            'success': True,
            'message': f'{"Global " if is_global else ""}Blocking rule updated successfully'
        })

    except Exception as e:
        logger.error(f"Error updating blocking rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)

# ============================================================================
# WHITELIST MANAGEMENT ROUTES
# ============================================================================

# WhitelistManager import moved to individual routes to prevent module-level initialization
# from affecting app startup if there are database connection issues

@app.route('/config/whitelist')
@login_required
def whitelist_rules_config():
    """Whitelist rules configuration page"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', None)

    # If no domain selected, show domain selection page
    if not selected_domain:
        return render_template('blocking_rules_select_domain.html',
                             user_domains=user_domains,
                             page_title='Whitelist Rules',
                             page_icon='fa-user-check',
                             page_description='Manage whitelist rules',
                             target_url='/config/whitelist')

    # Verify user has access to this domain
    if selected_domain not in user_domains and not current_user.is_admin():
        flash('Access denied to that domain', 'error')
        return redirect(url_for('config_dashboard'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id for the selected domain
        cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (selected_domain,))
        domain_result = cursor.fetchone()

        if not domain_result:
            flash(f'Domain {selected_domain} not found in client_domains table', 'error')
            cursor.close()
            conn.close()
            return redirect(url_for('config_dashboard'))

        client_domain_id = domain_result['id']

        # Get all whitelist rules for this domain + global rules
        cursor.execute("""
            SELECT id, rule_type, rule_value, rule_pattern, description,
                   active, priority, created_at, created_by, is_global, whitelist
            FROM blocking_rules
            WHERE (client_domain_id = %s OR is_global = 1)
            AND whitelist = 1
            ORDER BY is_global DESC, priority DESC, created_at DESC
        """, (client_domain_id,))

        rules = cursor.fetchall()

        # Get whitelisting statistics (last 30 days) - emails that passed due to whitelist
        # This would require tracking in blocked_attempts or a separate table
        # For now, just show rule count
        total_whitelisted = 0  # Placeholder for future implementation

        cursor.close()
        conn.close()

        return render_template('whitelist_rules_config.html',
                             selected_domain=selected_domain,
                             user_domains=user_domains,
                             rules=rules,
                             total_rules=len(rules),
                             total_whitelisted=total_whitelisted)

    except Exception as e:
        logger.error(f"Error loading whitelist rules: {e}")
        flash(f'Error loading whitelist rules: {e}', 'error')
        return redirect(url_for('config_dashboard'))

@app.route('/api/whitelist-rules/add', methods=['POST'])
@login_required
def add_whitelist_rule():
    """Add a whitelist rule"""
    # SECURITY: Only admins can modify whitelist rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist rules'}), 403

    try:
        data = request.get_json()
        domain = data.get('domain')
        rule_type = data.get('rule_type')
        rule_value = data.get('rule_value', '').strip()
        rule_pattern = data.get('rule_pattern', 'exact')
        description = data.get('description', '').strip()
        is_global = data.get('is_global', False)

        # SECURITY: Only superadmins can create global rules
        if is_global and not current_user.is_superadmin():
            return jsonify({'success': False, 'error': 'Only superadmins can create global rules'}), 403

        # Verify user has access to this domain (skip for global rules)
        if not is_global:
            user_domains = get_user_authorized_domains(current_user)
            if domain not in user_domains and not current_user.is_admin():
                return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not rule_value or not rule_type:
            return jsonify({'success': False, 'error': 'Rule type and value are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id (NULL for global rules)
        client_domain_id = None
        if not is_global:
            cursor.execute("SELECT id FROM client_domains WHERE domain = %s", (domain,))
            domain_result = cursor.fetchone()

            if not domain_result:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': f'Domain {domain} not found'}), 404

            client_domain_id = domain_result['id']

        # Insert the whitelist rule (whitelist=1)
        cursor.execute("""
            INSERT INTO blocking_rules
            (client_domain_id, rule_type, rule_value, rule_pattern, description,
             created_at, created_by, active, priority, whitelist, is_global)
            VALUES (%s, %s, %s, %s, %s, NOW(), %s, 1, 10, 1, %s)
        """, (client_domain_id, rule_type, rule_value, rule_pattern, description, current_user.email, 1 if is_global else 0))

        rule_id = cursor.lastrowid

        # Log the action
        scope = 'ALL DOMAINS (GLOBAL)' if is_global else domain
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'WHITELIST_RULE_ADDED', %s, %s)
        """, (current_user.id, f'Added {"GLOBAL " if is_global else ""}whitelist rule for {scope}: {rule_type}={rule_value}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"{'Global ' if is_global else ''}whitelist rule added by {current_user.email}: {rule_type}={rule_value} for {scope}")

        return jsonify({
            'success': True,
            'rule_id': rule_id,
            'message': f'{"Global " if is_global else ""}whitelist rule added successfully'
        })

    except Exception as e:
        logger.error(f"Error adding whitelist rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist-rules/delete/<int:rule_id>', methods=['POST'])
@login_required
def delete_whitelist_rule(rule_id):
    """Delete a whitelist rule"""
    # SECURITY: Only admins can modify whitelist rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist rules'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get rule details first
        cursor.execute("SELECT * FROM blocking_rules WHERE id = %s AND whitelist = 1", (rule_id,))
        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Whitelist rule not found'}), 404

        # Verify user has access to this domain (skip for global rules or superadmins)
        if not rule['is_global'] and not current_user.is_superadmin():
            user_domains = get_user_authorized_domains(current_user)
            cursor.execute("SELECT domain FROM client_domains WHERE id = %s", (rule['client_domain_id'],))
            domain_result = cursor.fetchone()

            if domain_result and domain_result['domain'] not in user_domains:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        # Delete the rule
        cursor.execute("DELETE FROM blocking_rules WHERE id = %s", (rule_id,))

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'WHITELIST_RULE_DELETED', %s, %s)
        """, (current_user.id, f'Deleted whitelist rule: {rule["rule_type"]}={rule["rule_value"]}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Whitelist rule deleted by {current_user.email}: rule_id={rule_id}")

        return jsonify({
            'success': True,
            'message': 'Whitelist rule deleted successfully'
        })

    except Exception as e:
        logger.error(f"Error deleting whitelist rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist-rules/toggle/<int:rule_id>', methods=['POST'])
@login_required
def toggle_whitelist_rule(rule_id):
    """Toggle a whitelist rule active/inactive status"""
    # SECURITY: Only admins can modify whitelist rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist rules'}), 403

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get rule details first
        cursor.execute("SELECT * FROM blocking_rules WHERE id = %s AND whitelist = 1", (rule_id,))
        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Whitelist rule not found'}), 404

        # Verify user has access to this domain (skip for global rules or superadmins)
        if not rule['is_global'] and not current_user.is_superadmin():
            user_domains = get_user_authorized_domains(current_user)
            cursor.execute("SELECT domain FROM client_domains WHERE id = %s", (rule['client_domain_id'],))
            domain_result = cursor.fetchone()

            if domain_result and domain_result['domain'] not in user_domains:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        # Toggle the active status
        new_status = not rule['active']
        cursor.execute("UPDATE blocking_rules SET active = %s WHERE id = %s", (new_status, rule_id))

        # Log the action
        action_text = 'enabled' if new_status else 'disabled'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'WHITELIST_RULE_TOGGLED', %s, %s)
        """, (current_user.id, f'{action_text.capitalize()} whitelist rule: {rule["rule_type"]}={rule["rule_value"]}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Whitelist rule {action_text} by {current_user.email}: rule_id={rule_id}")

        return jsonify({
            'success': True,
            'active': new_status,
            'message': f'Whitelist rule {action_text} successfully'
        })

    except Exception as e:
        logger.error(f"Error toggling whitelist rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/whitelist-rules/update/<int:rule_id>', methods=['POST'])
@login_required
def update_whitelist_rule(rule_id):
    """Update a whitelist rule"""
    # SECURITY: Only admins can modify whitelist rules
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist rules'}), 403

    try:
        data = request.get_json()
        rule_type = data.get('rule_type')
        rule_value = data.get('rule_value', '').strip()
        rule_pattern = data.get('rule_pattern', 'exact')
        description = data.get('description', '').strip()
        is_global = data.get('is_global', False)

        # SECURITY: Only superadmins can update to global rules
        if is_global and not current_user.is_superadmin():
            return jsonify({'success': False, 'error': 'Only superadmins can create global rules'}), 403

        if not rule_value or not rule_type:
            return jsonify({'success': False, 'error': 'Rule type and value are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the existing rule to verify ownership
        cursor.execute("""
            SELECT br.*, cd.domain
            FROM blocking_rules br
            LEFT JOIN client_domains cd ON br.client_domain_id = cd.id
            WHERE br.id = %s AND br.whitelist = 1
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Whitelist rule not found'}), 404

        # Verify user has access to this domain (skip for global rules)
        if not rule['is_global'] and not is_global:
            user_domains = get_user_authorized_domains(current_user)
            if rule['domain'] and rule['domain'] not in user_domains and not current_user.is_admin():
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update the rule
        if is_global:
            # Converting to global rule - set client_domain_id to NULL
            cursor.execute("""
                UPDATE blocking_rules
                SET rule_type = %s, rule_value = %s, rule_pattern = %s,
                    description = %s, is_global = %s, client_domain_id = NULL
                WHERE id = %s
            """, (rule_type, rule_value, rule_pattern, description, 1, rule_id))
        else:
            # Keep existing client_domain_id
            cursor.execute("""
                UPDATE blocking_rules
                SET rule_type = %s, rule_value = %s, rule_pattern = %s,
                    description = %s, is_global = %s
                WHERE id = %s
            """, (rule_type, rule_value, rule_pattern, description, 0, rule_id))

        # Log the action
        scope = 'ALL DOMAINS (GLOBAL)' if is_global else (rule['domain'] or 'unknown')
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'WHITELIST_RULE_UPDATED', %s, %s)
        """, (current_user.id, f'Updated {"GLOBAL " if is_global else ""}whitelist rule for {scope}: {rule_type}={rule_value}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Whitelist rule updated by {current_user.email}: rule_id={rule_id}")

        return jsonify({
            'success': True,
            'message': f'{"Global " if is_global else ""}Whitelist rule updated successfully'
        })

    except Exception as e:
        logger.error(f"Error updating whitelist rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# SENDER WHITELIST API ROUTES (JSON-based)
# ============================================================================

@app.route('/api/sender-whitelist/add', methods=['POST'])
@login_required
def add_sender_whitelist():
    """Add a sender to the JSON-based whitelist"""
    # SECURITY: Only admins can modify whitelist
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist'}), 403

    try:
        data = request.get_json()
        domain = data.get('domain')
        sender_email = data.get('sender_email', '').strip()
        trust_bonus = data.get('trust_bonus', 3)
        require_auth = data.get('require_auth', ['spf'])

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if domain not in user_domains and not current_user.is_admin():
            return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not sender_email:
            return jsonify({'success': False, 'error': 'Sender email is required'}), 400

        # Use whitelist_manager to add sender
        from whitelist_manager import WhitelistManager
        wl_manager = WhitelistManager()
        success, message = wl_manager.add_sender_whitelist(
            domain=domain,
            sender_email=sender_email,
            trust_bonus=trust_bonus,
            require_auth=require_auth,
            added_by=current_user.email
        )

        if success:
            logger.info(f"Sender {sender_email} added to whitelist for {domain} by {current_user.email}")
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({'success': False, 'error': message}), 400

    except Exception as e:
        logger.error(f"Error adding sender to whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sender-whitelist/remove', methods=['POST'])
@login_required
def remove_sender_whitelist():
    """Remove a sender from the JSON-based whitelist"""
    # SECURITY: Only admins can modify whitelist
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist'}), 403

    try:
        data = request.get_json()
        domain = data.get('domain')
        sender_email = data.get('sender_email', '').strip()

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if domain not in user_domains and not current_user.is_admin():
            return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not sender_email:
            return jsonify({'success': False, 'error': 'Sender email is required'}), 400

        # Use whitelist_manager to remove sender
        from whitelist_manager import WhitelistManager
        wl_manager = WhitelistManager()
        success, message = wl_manager.remove_sender_whitelist(
            domain=domain,
            sender_email=sender_email,
            removed_by=current_user.email
        )

        if success:
            logger.info(f"Sender {sender_email} removed from whitelist for {domain} by {current_user.email}")
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({'success': False, 'error': message}), 400

    except Exception as e:
        logger.error(f"Error removing sender from whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sender-whitelist/update', methods=['POST'])
@login_required
def update_sender_whitelist():
    """Update a sender in the JSON-based whitelist"""
    # SECURITY: Only admins can modify whitelist
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Only administrators can modify whitelist'}), 403

    try:
        data = request.get_json()
        domain = data.get('domain')
        original_email = data.get('original_email', '').strip()
        sender_email = data.get('sender_email', '').strip()
        trust_bonus = data.get('trust_bonus', 3)
        require_auth = data.get('require_auth', ['spf'])

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if domain not in user_domains and not current_user.is_admin():
            return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not original_email or not sender_email:
            return jsonify({'success': False, 'error': 'Original and new sender email are required'}), 400

        # Use whitelist_manager to update sender
        from whitelist_manager import WhitelistManager
        wl_manager = WhitelistManager()

        # If email changed, we need to remove the old one and add the new one
        if original_email != sender_email:
            # Remove the old entry
            success, message = wl_manager.remove_sender_whitelist(
                domain=domain,
                sender_email=original_email,
                removed_by=current_user.email
            )

            if not success:
                return jsonify({'success': False, 'error': f'Failed to remove old entry: {message}'}), 400

        # Add or update the entry
        success, message = wl_manager.add_sender_whitelist(
            domain=domain,
            sender_email=sender_email,
            trust_bonus=trust_bonus,
            require_auth=require_auth,
            added_by=current_user.email
        )

        if success:
            logger.info(f"Sender {sender_email} updated in whitelist for {domain} by {current_user.email}")
            return jsonify({
                'success': True,
                'message': 'Sender whitelist entry updated successfully'
            })
        else:
            return jsonify({'success': False, 'error': message}), 400

    except Exception as e:
        logger.error(f"Error updating sender whitelist: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# Cleanup Settings Routes
# ============================================================================

@app.route('/config/cleanup')
@login_required
@superadmin_required
def cleanup_settings():
    """Cleanup settings configuration page (SuperAdmin only)"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get cleanup enabled setting
        cursor.execute("""
            SELECT setting_value
            FROM system_settings
            WHERE setting_key = 'cleanup_expired_emails_enabled'
        """)
        result = cursor.fetchone()
        cleanup_enabled = result['setting_value'].lower() in ('true', '1', 'yes', 'enabled') if result else True

        # Get retention days setting
        cursor.execute("""
            SELECT setting_value
            FROM system_settings
            WHERE setting_key = 'cleanup_retention_days'
        """)
        result = cursor.fetchone()
        retention_days = int(result['setting_value']) if result else 30

        # Get count of expired emails
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM email_quarantine
            WHERE quarantine_expires_at < NOW()
        """)
        result = cursor.fetchone()
        expired_count = result['count'] if result else 0

        # Get count of emails expiring in next 7 days
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM email_quarantine
            WHERE quarantine_expires_at BETWEEN NOW() AND DATE_ADD(NOW(), INTERVAL 7 DAY)
        """)
        result = cursor.fetchone()
        expiring_count = result['count'] if result else 0

        cursor.close()
        conn.close()

        # Calculate next cleanup time (2:00 AM tomorrow)
        from datetime import datetime, timedelta
        tomorrow = datetime.now() + timedelta(days=1)
        next_cleanup = tomorrow.replace(hour=2, minute=0, second=0, microsecond=0)
        next_cleanup_time = next_cleanup.strftime('%Y-%m-%d %H:%M')

        return render_template('cleanup_settings.html',
                             cleanup_enabled=cleanup_enabled,
                             retention_days=retention_days,
                             expired_count=expired_count,
                             expiring_count=expiring_count,
                             next_cleanup_time=next_cleanup_time,
                             cleanup_logs=[])

    except Exception as e:
        logger.error(f"Error loading cleanup settings: {e}")
        flash(f'Error loading cleanup settings: {str(e)}', 'error')
        return redirect(url_for('config_dashboard'))

@app.route('/api/cleanup-settings/toggle', methods=['POST'])
@login_required
@superadmin_required
def toggle_cleanup():
    """Toggle cleanup enabled/disabled"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', True)
        setting_value = 'true' if enabled else 'false'

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Update the setting
        cursor.execute("""
            UPDATE system_settings
            SET setting_value = %s, updated_by = %s, updated_at = NOW()
            WHERE setting_key = 'cleanup_expired_emails_enabled'
        """, (setting_value, current_user.email))

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'CLEANUP_SETTING_CHANGED', %s, %s)
        """, (current_user.id, f'Cleanup {"enabled" if enabled else "disabled"}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Cleanup setting changed by {current_user.email}: enabled={enabled}")

        return jsonify({
            'success': True,
            'message': f'Cleanup {"enabled" if enabled else "disabled"} successfully'
        })

    except Exception as e:
        logger.error(f"Error toggling cleanup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/cleanup-settings/run-now', methods=['POST'])
@login_required
@superadmin_required
def run_cleanup_now():
    """Manually trigger cleanup process"""

    try:
        import subprocess

        # Run the cleanup script
        result = subprocess.run(
            ['/opt/spacyserver/venv/bin/python3', '/opt/spacyserver/cleanup_expired_emails.py'],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'CLEANUP_MANUAL_RUN', %s, %s)
        """, (current_user.id, f'Manual cleanup triggered. Exit code: {result.returncode}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        if result.returncode == 0:
            # Parse output to get deleted count
            deleted_count = 0
            for line in result.stdout.split('\n'):
                if 'Deleted:' in line:
                    try:
                        deleted_count = int(line.split('Deleted:')[1].split('emails')[0].strip())
                    except:
                        pass

            logger.info(f"Manual cleanup run by {current_user.email}: deleted {deleted_count} emails")

            return jsonify({
                'success': True,
                'message': f'Cleanup completed successfully. Deleted {deleted_count} emails.',
                'deleted_count': deleted_count
            })
        else:
            logger.error(f"Manual cleanup failed: {result.stderr}")
            return jsonify({
                'success': False,
                'error': f'Cleanup failed: {result.stderr}'
            }), 500

    except subprocess.TimeoutExpired:
        logger.error("Manual cleanup timed out")
        return jsonify({'success': False, 'error': 'Cleanup timed out (exceeded 5 minutes)'}), 500
    except Exception as e:
        logger.error(f"Error running cleanup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/cleanup-settings/logs', methods=['GET'])
@login_required
@superadmin_required
def get_cleanup_logs():
    """Get cleanup log contents"""

    try:
        log_file = '/opt/spacyserver/logs/cleanup.log'

        # Read last 100 lines of log
        with open(log_file, 'r') as f:
            lines = f.readlines()
            recent_logs = ''.join(lines[-100:])  # Last 100 lines

        return jsonify({
            'success': True,
            'logs': recent_logs
        })

    except FileNotFoundError:
        return jsonify({
            'success': True,
            'logs': 'No logs found. Cleanup has not run yet.'
        })
    except Exception as e:
        logger.error(f"Error reading cleanup logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/cleanup-settings/spam-cleanup', methods=['POST'])
@login_required
@superadmin_required
def run_spam_cleanup():
    """Manually trigger spam cleanup process (soft delete old high-scoring spam)"""

    try:
        import subprocess

        # Get dry_run parameter
        data = request.get_json() or {}
        dry_run = data.get('dry_run', False)

        # Run the spam cleanup script
        args = ['/opt/spacyserver/venv/bin/python3', '/opt/spacyserver/scripts/cleanup_old_spam.py']
        if dry_run:
            args.append('--dry-run')

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        # Parse output to get statistics
        stats = {
            'very_high_spam': 0,
            'high_spam': 0,
            'suspicious': 0,
            'total': 0
        }

        for line in result.stdout.split('\n'):
            if 'Very High Spam' in line:
                try:
                    stats['very_high_spam'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'High Spam' in line:
                try:
                    stats['high_spam'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Suspicious' in line:
                try:
                    stats['suspicious'] = int(line.split(':')[1].strip())
                except:
                    pass
            elif 'Total:' in line:
                try:
                    stats['total'] = int(line.split(':')[1].strip())
                except:
                    pass

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        action_type = 'SPAM_CLEANUP_DRY_RUN' if dry_run else 'SPAM_CLEANUP_MANUAL_RUN'
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (current_user.id, action_type, f'Spam cleanup: {stats["total"]} emails. Exit code: {result.returncode}', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        if result.returncode == 0:
            mode_text = 'would be' if dry_run else 'were'
            logger.info(f"Spam cleanup {'dry run' if dry_run else 'run'} by {current_user.email}: {stats['total']} emails {mode_text} soft deleted")

            return jsonify({
                'success': True,
                'message': f'Spam cleanup completed successfully. {stats["total"]} emails {mode_text} soft deleted.',
                'stats': stats,
                'dry_run': dry_run,
                'output': result.stdout
            })
        else:
            logger.error(f"Spam cleanup failed: {result.stderr}")
            return jsonify({
                'success': False,
                'error': f'Spam cleanup failed: {result.stderr}'
            }), 500

    except subprocess.TimeoutExpired:
        logger.error("Spam cleanup timed out")
        return jsonify({'success': False, 'error': 'Spam cleanup timed out (exceeded 5 minutes)'}), 500
    except Exception as e:
        logger.error(f"Error running spam cleanup: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/release-to-superadmin', methods=['POST'])
@login_required
@superadmin_required
def release_to_superadmin():
    """Release a quarantined email to the superadmin for analysis"""

    try:
        data = request.get_json() or {}
        message_id = data.get('message_id')

        if not message_id:
            return jsonify({'success': False, 'error': 'Message ID is required'}), 400

        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Try to fetch email from quarantine first
        cursor.execute("""
            SELECT
                id, message_id as msg_id, sender, recipients, subject,
                raw_email, spam_score, quarantine_reason,
                'quarantine' as source
            FROM email_quarantine
            WHERE id = %s
        """, (message_id,))

        email = cursor.fetchone()

        # If not in quarantine, try email_analysis (delivered/blocked emails)
        if not email:
            cursor.execute("""
                SELECT
                    id, message_id as msg_id, sender, recipients, subject,
                    raw_email, spam_score,
                    CONCAT('Delivered/Analyzed (Score: ', spam_score, ')') as quarantine_reason,
                    'analysis' as source
                FROM email_analysis
                WHERE id = %s
            """, (message_id,))

            email = cursor.fetchone()

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': f'Email ID {message_id} not found in system'}), 404

        # Parse the raw email
        import email as email_lib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        import smtplib

        raw_email = email.get('raw_email', '')
        if not raw_email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No raw email content found'}), 404

        # Get email source for labeling
        email_source = email.get('source', 'unknown')

        # Parse original email
        original_msg = email_lib.message_from_string(raw_email)

        # Create forwarding message with warning headers
        forward_msg = MIMEMultipart('mixed')
        forward_msg['From'] = 'quarantine@openefa.com'
        forward_msg['To'] = current_user.email
        subject_prefix = '[QUARANTINE]' if email_source == 'quarantine' else '[OPENEFA]'
        forward_msg['Subject'] = f'{subject_prefix} {email["subject"]}'

        # Add warning headers
        forward_msg['X-OpenEFA-Released-By'] = current_user.email
        forward_msg['X-OpenEFA-Original-Sender'] = email['sender']
        forward_msg['X-OpenEFA-Spam-Score'] = str(email['spam_score'])
        forward_msg['X-OpenEFA-Quarantine-Reason'] = email['quarantine_reason'] or 'High spam score'
        forward_msg['X-OpenEFA-Quarantine-ID'] = str(message_id)
        forward_msg['X-OpenEFA-Warning'] = 'This email was released from quarantine for analysis. Exercise caution.'

        # Add warning banner as text
        source_label = 'QUARANTINE' if email_source == 'quarantine' else 'SYSTEM'

        warning_text = f"""
========================================
⚠️  {source_label} RELEASE WARNING ⚠️
========================================

This email was released from the {source_label.lower()} for analysis.
Do not click links or open attachments without verification.

Original Sender: {email['sender']}
Original Recipients: {email['recipients']}
Spam Score: {email['spam_score']}
Status: {email['quarantine_reason'] or 'Unknown'}
Released By: {current_user.email}
Email ID: {message_id}
Source Table: {email_source}

========================================
ORIGINAL EMAIL FOLLOWS BELOW
========================================

"""

        # Add warning as first part
        warning_part = MIMEText(warning_text, 'plain')
        forward_msg.attach(warning_part)

        # Attach original email as RFC822 message
        from email.mime.message import MIMEMessage
        original_part = MIMEMessage(original_msg)
        filename_prefix = 'quarantine' if email_source == 'quarantine' else 'openefa'
        original_part.add_header('Content-Disposition', 'attachment', filename=f'{filename_prefix}_{message_id}.eml')
        forward_msg.attach(original_part)

        # Send via local SMTP
        try:
            smtp = smtplib.SMTP('localhost', 25)
            smtp.sendmail(
                'quarantine@openefa.com',
                [current_user.email],
                forward_msg.as_string()
            )
            smtp.quit()
        except Exception as smtp_err:
            logger.error(f"SMTP error releasing email: {smtp_err}")
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': f'Failed to send email: {str(smtp_err)}'}), 500

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (
            current_user.id,
            'release_to_superadmin',
            f'Released email ID {message_id} from {email_source} to {current_user.email}. Subject: {email["subject"][:100]}',
            request.remote_addr
        ))
        conn.commit()

        cursor.close()
        conn.close()

        logger.info(f"Superadmin {current_user.email} released email ID {message_id} (source: {email_source}) to their inbox")

        return jsonify({
            'success': True,
            'message': f'Email ID {message_id} successfully released to {current_user.email}'
        })

    except Exception as e:
        logger.error(f"Error releasing email to superadmin: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/report-to-collective', methods=['POST'])
@login_required
@superadmin_required
def report_to_collective():
    """Report an email to EFA Collective for analysis and community improvement"""
    import json
    import uuid

    try:
        data = request.get_json() or {}
        message_id = data.get('message_id')
        report_type = data.get('report_type', 'spam_missed')
        notes = data.get('notes', '')
        include_headers = data.get('include_headers', True)
        include_body = data.get('include_body', True)
        include_ml = data.get('include_ml', True)
        include_modules = data.get('include_modules', True)

        if not message_id:
            return jsonify({'success': False, 'error': 'Message ID is required'}), 400

        # Get or create system ID
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if system is approved for EFA Collective reporting
        cursor.execute("""
            SELECT setting_value FROM system_settings
            WHERE setting_key = 'collective_status'
        """)
        status_result = cursor.fetchone()
        collective_status = status_result['setting_value'] if status_result else None

        if collective_status != 'approved':
            cursor.close()
            conn.close()
            status_msg = collective_status if collective_status else 'not registered'
            return jsonify({
                'success': False,
                'error': f'System not approved for EFA Collective (status: {status_msg}). Please register at Cleanup Settings and wait for approval.'
            }), 403

        cursor.execute("""
            SELECT setting_value FROM system_settings
            WHERE setting_key = 'openefa_system_id'
        """)
        result = cursor.fetchone()

        if result:
            system_id = result['setting_value']
        else:
            # Generate new system ID
            system_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO system_settings (setting_key, setting_value, description)
                VALUES ('openefa_system_id', %s, 'Unique system identifier for EFA Collective')
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """, (system_id,))
            conn.commit()

        # Get OpenEFA version
        openefa_version = "Unknown"
        try:
            with open('/opt/spacyserver/VERSION', 'r') as f:
                for line in f:
                    if line.startswith('VERSION='):
                        openefa_version = line.split('=', 1)[1].strip()
                        break
        except Exception:
            pass

        # Fetch email from email_analysis (primary) or email_quarantine
        cursor.execute("""
            SELECT
                id, message_id as msg_id, sender, recipients, subject,
                raw_email, spam_score, disposition,
                spam_modules_detail, auth_score,
                original_spf as spf_result, original_dkim as dkim_result, original_dmarc as dmarc_result,
                classification_scores as ml_classification_scores,
                detected_language, language_confidence,
                sentiment_score, sentiment_polarity, sentiment_subjectivity,
                entities, email_category, content_summary,
                timestamp,
                'analysis' as source
            FROM email_analysis
            WHERE id = %s
        """, (message_id,))
        email = cursor.fetchone()

        # Try quarantine if not found
        if not email:
            cursor.execute("""
                SELECT
                    id, message_id as msg_id, sender, recipients, subject,
                    raw_email, spam_score, quarantine_reason as disposition,
                    NULL as spam_modules_detail, NULL as auth_score,
                    NULL as spf_result, NULL as dkim_result, NULL as dmarc_result,
                    NULL as ml_classification_scores,
                    NULL as detected_language, NULL as language_confidence,
                    NULL as sentiment_score, NULL as sentiment_polarity, NULL as sentiment_subjectivity,
                    NULL as entities, NULL as email_category, NULL as content_summary,
                    timestamp,
                    'quarantine' as source
                FROM email_quarantine
                WHERE id = %s
            """, (message_id,))
            email = cursor.fetchone()

        if not email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': f'Email ID {message_id} not found'}), 404

        raw_email = email.get('raw_email', '')
        if not raw_email:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'No raw email content found'}), 404

        # Build forensic metadata
        forensic_data = {
            'report_info': {
                'report_type': report_type,
                'reporter_notes': notes,
                'reported_at': datetime.now().isoformat(),
                'reported_by': current_user.email,
            },
            'system_info': {
                'system_id': system_id,
                'openefa_version': openefa_version,
            },
            'email_info': {
                'email_id': email['id'],
                'message_id': email['msg_id'],
                'sender': email['sender'],
                'recipients': email['recipients'],
                'subject': email['subject'],
                'timestamp': email['timestamp'].isoformat() if email['timestamp'] else None,
                'source_table': email['source'],
            },
            'scoring': {
                'spam_score': email['spam_score'],
                'disposition': email['disposition'],
                'auth_score': email['auth_score'],
            },
            'authentication': {
                'spf_result': email['spf_result'],
                'dkim_result': email['dkim_result'],
                'dmarc_result': email['dmarc_result'],
            },
        }

        # Add optional data based on checkboxes
        if include_modules and email.get('spam_modules_detail'):
            try:
                forensic_data['module_breakdown'] = json.loads(email['spam_modules_detail']) if isinstance(email['spam_modules_detail'], str) else email['spam_modules_detail']
            except Exception:
                forensic_data['module_breakdown'] = str(email['spam_modules_detail'])

        if include_ml and email.get('ml_classification_scores'):
            try:
                forensic_data['ml_scores'] = json.loads(email['ml_classification_scores']) if isinstance(email['ml_classification_scores'], str) else email['ml_classification_scores']
            except Exception:
                forensic_data['ml_scores'] = str(email['ml_classification_scores'])

        # Add content analysis
        forensic_data['content_analysis'] = {
            'detected_language': email['detected_language'],
            'language_confidence': email['language_confidence'],
            'sentiment_score': email['sentiment_score'],
            'sentiment_polarity': email['sentiment_polarity'],
            'sentiment_subjectivity': email['sentiment_subjectivity'],
            'email_category': email['email_category'],
            'content_summary': email['content_summary'],
        }

        if email.get('entities'):
            try:
                forensic_data['entities'] = json.loads(email['entities']) if isinstance(email['entities'], str) else email['entities']
            except Exception:
                forensic_data['entities'] = str(email['entities'])

        # Parse raw email to extract forensic headers
        import email as email_lib
        import re
        original_msg = email_lib.message_from_string(raw_email)

        # Extract source IP from Received headers
        source_ip = None
        received_headers = original_msg.get_all('Received', [])
        if received_headers:
            # First Received header typically has the originating IP
            first_received = received_headers[0] if received_headers else ''
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', first_received)
            if ip_match:
                source_ip = ip_match.group(1)

        # Extract all X-SpaCy-* and X-Spam-* headers
        spacy_headers = {}
        for header_name, header_value in original_msg.items():
            header_lower = header_name.lower()
            if header_lower.startswith('x-spacy-') or header_lower.startswith('x-spam-') or \
               header_lower.startswith('x-ml-') or header_lower.startswith('x-url-') or \
               header_lower.startswith('x-auth-') or header_lower.startswith('x-phishing-') or \
               header_lower.startswith('x-ner-') or header_lower.startswith('x-virus-') or \
               header_lower.startswith('x-thread-') or header_lower.startswith('x-high-risk-') or \
               header_lower.startswith('x-trusted-') or header_lower.startswith('x-analysis-') or \
               header_lower.startswith('x-email-') or header_lower.startswith('x-content-') or \
               header_lower.startswith('x-arc-'):
                # Normalize header name to lowercase with underscores
                key = header_name.lower().replace('-', '_')
                spacy_headers[key] = header_value

        # Add forensic headers to the data
        forensic_data['network_info'] = {
            'source_ip': source_ip,
            'received_chain': received_headers[:3] if received_headers else [],  # First 3 hops
        }

        forensic_data['spacy_headers'] = spacy_headers

        # Build the report email
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email.mime.message import MIMEMessage
        from email import encoders
        import smtplib

        # Parse original email
        original_msg = email_lib.message_from_string(raw_email)

        # Create report message
        report_msg = MIMEMultipart('mixed')
        report_msg['From'] = f'openefa-report@{os.getenv("MAIL_DOMAIN", "openefa.com")}'
        report_msg['To'] = 'efacollective@openefa.com'
        report_msg['Subject'] = f'[EFA-REPORT] [{report_type.upper()}] {email["subject"][:50]}'

        # Add custom headers for validation
        report_msg['X-OpenEFA-System-ID'] = system_id
        report_msg['X-OpenEFA-Version'] = openefa_version
        report_msg['X-OpenEFA-Report-Type'] = report_type
        report_msg['X-OpenEFA-Email-ID'] = str(message_id)
        report_msg['X-OpenEFA-Reporter'] = current_user.email

        # Build report body text
        report_type_labels = {
            'spam_missed': 'Spam Got Through',
            'false_positive': 'False Positive',
            'new_pattern': 'New Spam Pattern',
            'bug': 'Bug / Unexpected Behavior'
        }

        # Extract key SpaCy headers for quick summary
        url_risk = spacy_headers.get('x_url_risk_score', 'N/A')
        ml_status = spacy_headers.get('x_ml_status', 'N/A')
        score_breakdown = spacy_headers.get('x_spam_score_breakdown', 'N/A')
        high_risk_domains = spacy_headers.get('x_high_risk_random_domains', 'None')

        report_body = f"""
========================================
EFA COLLECTIVE REPORT
========================================

Report Type: {report_type_labels.get(report_type, report_type)}
Reported By: {current_user.email}
Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System ID: {system_id}
OpenEFA Version: {openefa_version}

----------------------------------------
EMAIL DETAILS
----------------------------------------
Email ID: {email['id']}
Message-ID: {email['msg_id']}
From: {email['sender']}
To: {email['recipients']}
Subject: {email['subject']}
Received: {email['timestamp']}
Source IP: {source_ip or 'Unknown'}

----------------------------------------
SCORING
----------------------------------------
Spam Score: {email['spam_score']}
Disposition: {email['disposition']}
Auth Score: {email['auth_score']}

SPF: {email['spf_result']}
DKIM: {email['dkim_result']}
DMARC: {email['dmarc_result']}

----------------------------------------
SPACY ANALYSIS SUMMARY
----------------------------------------
URL Risk Score: {url_risk}
Score Breakdown: {score_breakdown}
High Risk Domains: {high_risk_domains}
ML Status: {ml_status}

----------------------------------------
REPORTER NOTES
----------------------------------------
{notes if notes else '(No additional notes provided)'}

========================================
ATTACHMENTS:
1. forensic_data.json - Complete analysis + all X-SpaCy headers
2. original_email.eml - Full original email
3. headers.txt - All headers (easy to read)
========================================
"""

        # Add report body
        body_part = MIMEText(report_body, 'plain')
        report_msg.attach(body_part)

        # Add forensic data as JSON attachment
        json_data = json.dumps(forensic_data, indent=2, default=str)
        json_part = MIMEBase('application', 'json')
        json_part.set_payload(json_data.encode('utf-8'))
        encoders.encode_base64(json_part)
        json_part.add_header('Content-Disposition', 'attachment', filename=f'forensic_data_{message_id}.json')
        report_msg.attach(json_part)

        # Add original email as attachment (if body included)
        if include_body:
            original_part = MIMEMessage(original_msg)
            original_part.add_header('Content-Disposition', 'attachment', filename=f'original_email_{message_id}.eml')
            report_msg.attach(original_part)

        # Always add headers.txt for easy reading (when headers checkbox is checked)
        if include_headers:
            headers_only = '\n'.join(f'{k}: {v}' for k, v in original_msg.items())
            headers_part = MIMEText(headers_only, 'plain')
            headers_part.add_header('Content-Disposition', 'attachment', filename=f'headers_{message_id}.txt')
            report_msg.attach(headers_part)

        # Send via local SMTP
        try:
            smtp = smtplib.SMTP('localhost', 25)
            smtp.sendmail(
                report_msg['From'],
                ['efacollective@openefa.com'],
                report_msg.as_string()
            )
            smtp.quit()
        except Exception as smtp_err:
            logger.error(f"SMTP error sending to EFA Collective: {smtp_err}")
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': f'Failed to send report: {str(smtp_err)}'}), 500

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, %s, %s, %s)
        """, (
            current_user.id,
            'report_to_collective',
            f'Reported email ID {message_id} to EFA Collective. Type: {report_type}. Subject: {email["subject"][:100]}',
            request.remote_addr
        ))
        conn.commit()

        cursor.close()
        conn.close()

        logger.info(f"Superadmin {current_user.email} reported email ID {message_id} to EFA Collective (type: {report_type})")

        return jsonify({
            'success': True,
            'message': f'Email ID {message_id} successfully reported to EFA Collective. Thank you for contributing!'
        })

    except Exception as e:
        logger.error(f"Error reporting to EFA Collective: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# EFA Collective Registration API
# ============================================================================

COLLECTIVE_API_BASE = 'https://openefa.com/api/collective'

def get_or_create_system_id():
    """Get existing system ID or generate a new one"""
    import uuid

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT setting_value FROM system_settings
        WHERE setting_key = 'openefa_system_id'
    """)
    result = cursor.fetchone()

    if result:
        system_id = result['setting_value']
    else:
        system_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO system_settings (setting_key, setting_value, description)
            VALUES ('openefa_system_id', %s, 'Unique system identifier for EFA Collective')
        """, (system_id,))
        conn.commit()

    cursor.close()
    conn.close()
    return system_id


def get_public_ip():
    """Detect the server's public IP address"""
    import requests

    # Try multiple services for reliability
    ip_services = [
        'https://api.ipify.org?format=json',
        'https://httpbin.org/ip',
        'https://api.myip.com',
    ]

    for service in ip_services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Handle different response formats
                if 'ip' in data:
                    return data['ip']
                elif 'origin' in data:
                    return data['origin'].split(',')[0].strip()
        except Exception as e:
            logger.debug(f"Failed to get IP from {service}: {e}")
            continue

    return None


def get_collective_registration_status():
    """Get local registration status from system_settings"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    status_data = {
        'status': 'unregistered',
        'registered_at': None,
        'admin_email': None,
        'organization_name': None,
        'rejection_reason': None
    }

    cursor.execute("""
        SELECT setting_key, setting_value FROM system_settings
        WHERE setting_key LIKE 'collective_%'
    """)
    results = cursor.fetchall()

    for row in results:
        key = row['setting_key'].replace('collective_', '')
        status_data[key] = row['setting_value']

    cursor.close()
    conn.close()
    return status_data


def save_collective_registration_status(status, **kwargs):
    """Save registration status to system_settings"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Save status
    cursor.execute("""
        INSERT INTO system_settings (setting_key, setting_value, description)
        VALUES ('collective_status', %s, 'EFA Collective registration status')
        ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
    """, (status,))

    # Save any additional fields
    for key, value in kwargs.items():
        if value is not None:
            cursor.execute("""
                INSERT INTO system_settings (setting_key, setting_value, description)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """, (f'collective_{key}', str(value), f'EFA Collective {key}'))

    conn.commit()
    cursor.close()
    conn.close()


@app.route('/api/collective/status', methods=['GET'])
@login_required
@superadmin_required
def collective_status():
    """Get current EFA Collective registration status"""
    try:
        system_id = get_or_create_system_id()
        public_ip = get_public_ip()
        status_data = get_collective_registration_status()

        return jsonify({
            'success': True,
            'system_id': system_id,
            'public_ip': public_ip,
            'status': status_data.get('status', 'unregistered'),
            'registered_at': status_data.get('registered_at'),
            'admin_email': status_data.get('admin_email'),
            'organization_name': status_data.get('organization_name'),
            'rejection_reason': status_data.get('rejection_reason')
        })

    except Exception as e:
        logger.error(f"Error getting collective status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/collective/register', methods=['POST'])
@login_required
@superadmin_required
def collective_register():
    """Register this OpenEFA instance with the EFA Collective"""
    import requests

    try:
        data = request.get_json() or {}
        admin_email = data.get('admin_email')
        organization_name = data.get('organization_name', '')

        if not admin_email:
            return jsonify({'success': False, 'error': 'Admin email is required'}), 400

        system_id = get_or_create_system_id()
        public_ip = get_public_ip()

        if not public_ip:
            return jsonify({'success': False, 'error': 'Unable to detect public IP address'}), 500

        # Get OpenEFA version
        openefa_version = "Unknown"
        try:
            with open('/opt/spacyserver/VERSION', 'r') as f:
                for line in f:
                    if line.startswith('VERSION='):
                        openefa_version = line.split('=', 1)[1].strip()
                        break
        except Exception:
            pass

        # Get hostname
        import socket
        hostname = socket.gethostname()

        # Prepare registration payload
        registration_data = {
            'system_id': system_id,
            'public_ip': public_ip,
            'hostname': hostname,
            'admin_email': admin_email,
            'organization_name': organization_name,
            'openefa_version': openefa_version,
            'registered_by': current_user.email
        }

        # Submit to openefa.com API
        try:
            response = requests.post(
                f'{COLLECTIVE_API_BASE}/register',
                json=registration_data,
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    # Save local status
                    save_collective_registration_status(
                        'pending',
                        registered_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        admin_email=admin_email,
                        organization_name=organization_name,
                        public_ip=public_ip
                    )

                    # Log the action
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO audit_log (user_id, action, details, ip_address)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        current_user.id,
                        'collective_registration',
                        f'Registered with EFA Collective. System ID: {system_id}, Public IP: {public_ip}',
                        request.remote_addr
                    ))
                    conn.commit()
                    cursor.close()
                    conn.close()

                    logger.info(f"Registered with EFA Collective: {system_id} ({public_ip})")

                    return jsonify({
                        'success': True,
                        'message': 'Registration submitted successfully. Awaiting approval.',
                        'system_id': system_id
                    })
                else:
                    return jsonify({'success': False, 'error': result.get('error', 'Registration failed')}), 400

            elif response.status_code == 409:
                # Already registered
                save_collective_registration_status('pending')
                return jsonify({
                    'success': True,
                    'message': 'This system is already registered. Check status for updates.',
                    'system_id': system_id
                })
            else:
                logger.error(f"Collective API error: {response.status_code} - {response.text}")
                return jsonify({'success': False, 'error': f'API error: {response.status_code}'}), 500

        except requests.exceptions.ConnectionError:
            # API not available yet - save as pending locally for testing
            logger.warning("EFA Collective API not available, saving registration locally")
            save_collective_registration_status(
                'pending',
                registered_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                admin_email=admin_email,
                organization_name=organization_name,
                public_ip=public_ip
            )
            return jsonify({
                'success': True,
                'message': 'Registration saved locally. API endpoint not yet available - registration will be processed when API is ready.',
                'system_id': system_id
            })

        except requests.exceptions.Timeout:
            return jsonify({'success': False, 'error': 'Registration request timed out'}), 504

    except Exception as e:
        logger.error(f"Error registering with collective: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/collective/check-status', methods=['POST'])
@login_required
@superadmin_required
def collective_check_status():
    """Check registration status with EFA Collective API"""
    import requests

    try:
        system_id = get_or_create_system_id()
        current_status = get_collective_registration_status()
        old_status = current_status.get('status', 'unregistered')

        # Query openefa.com API for status
        try:
            response = requests.get(
                f'{COLLECTIVE_API_BASE}/status/{system_id}',
                timeout=15
            )

            if response.status_code == 200:
                result = response.json()
                new_status = result.get('status', old_status)

                if new_status != old_status:
                    # Status changed - update local
                    save_collective_registration_status(
                        new_status,
                        rejection_reason=result.get('rejection_reason')
                    )

                    # Log status change
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO audit_log (user_id, action, details, ip_address)
                        VALUES (%s, %s, %s, %s)
                    """, (
                        current_user.id,
                        'collective_status_change',
                        f'EFA Collective status changed: {old_status} -> {new_status}',
                        request.remote_addr
                    ))
                    conn.commit()
                    cursor.close()
                    conn.close()

                return jsonify({
                    'success': True,
                    'status': new_status,
                    'status_changed': new_status != old_status,
                    'message': result.get('message', '')
                })

            elif response.status_code == 404:
                # Not registered on server side
                return jsonify({
                    'success': True,
                    'status': 'unregistered',
                    'status_changed': old_status != 'unregistered',
                    'message': 'System not found in EFA Collective registry'
                })
            else:
                return jsonify({'success': False, 'error': f'API error: {response.status_code}'}), 500

        except requests.exceptions.ConnectionError:
            # API not available - return current local status
            return jsonify({
                'success': True,
                'status': old_status,
                'status_changed': False,
                'message': 'Unable to reach EFA Collective API. Showing local status.'
            })

        except requests.exceptions.Timeout:
            return jsonify({'success': False, 'error': 'Status check timed out'}), 504

    except Exception as e:
        logger.error(f"Error checking collective status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)

# ============================================================================
# Configuration Dashboard Routes
# ============================================================================

@app.route('/config/system-info')
@login_required
@superadmin_required
def system_info():
    """System information page - superadmin only"""
    import platform
    import subprocess

    # Read version from installation directory
    version = "Unknown"
    try:
        with open('/opt/spacyserver/VERSION', 'r') as f:
            for line in f:
                if line.startswith('VERSION='):
                    version = line.split('=', 1)[1].strip()
                    break
    except Exception as e:
        logger.error(f"Error reading version file: {e}")

    # Get system information
    system_info_data = {
        'version': version,
        'platform': platform.system(),
        'platform_version': platform.release(),
        'python_version': platform.python_version(),
        'hostname': platform.node()
    }

    # Get component versions
    components = []

    # Check SpaCy version
    try:
        import spacy
        components.append({'name': 'spaCy', 'version': spacy.__version__, 'status': 'active'})
    except:
        components.append({'name': 'spaCy', 'version': 'Not installed', 'status': 'error'})

    # Check ClamAV version
    try:
        result = subprocess.run(['clamdscan', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            clam_version = result.stdout.strip().split()[1] if len(result.stdout.split()) > 1 else 'Unknown'
            components.append({'name': 'ClamAV', 'version': clam_version, 'status': 'active'})
        else:
            components.append({'name': 'ClamAV', 'version': 'Not configured', 'status': 'warning'})
    except:
        components.append({'name': 'ClamAV', 'version': 'Not installed', 'status': 'error'})

    # Check MySQL version
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION()")
            mysql_version = cursor.fetchone()[0]
            components.append({'name': 'MySQL', 'version': mysql_version, 'status': 'active'})
            cursor.close()
            conn.close()
    except:
        components.append({'name': 'MySQL', 'version': 'Connection error', 'status': 'error'})

    # Check Postfix version
    try:
        result = subprocess.run(['postconf', 'mail_version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            postfix_version = result.stdout.strip().split('=')[1].strip() if '=' in result.stdout else 'Unknown'
            components.append({'name': 'Postfix', 'version': postfix_version, 'status': 'active'})
        else:
            components.append({'name': 'Postfix', 'version': 'Not configured', 'status': 'warning'})
    except:
        components.append({'name': 'Postfix', 'version': 'Not installed', 'status': 'error'})

    # Check Gunicorn version
    try:
        import gunicorn
        # Get number of workers from systemd
        result = subprocess.run(['systemctl', 'status', 'spacyweb', '--no-pager'], capture_output=True, text=True, timeout=5)
        worker_count = result.stdout.count('gunicorn -c') - 1 if result.returncode == 0 else 0
        gunicorn_info = f"{gunicorn.__version__} ({worker_count} workers)" if worker_count > 0 else gunicorn.__version__
        components.append({'name': 'Gunicorn', 'version': gunicorn_info, 'status': 'active'})
    except:
        components.append({'name': 'Gunicorn', 'version': 'Not installed', 'status': 'error'})

    # Check Recipient Verification Policy Server
    try:
        result = subprocess.run(['systemctl', 'is-active', 'openefa-policy'], capture_output=True, text=True, timeout=5)
        if result.stdout.strip() == 'active':
            # Get additional stats
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM recipient_rejections WHERE DATE(timestamp) = CURDATE()")
                today_rejections = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM client_domains WHERE active = 1 AND recipient_verification_status = 'supported'")
                domains_protected = cursor.fetchone()[0]
                cursor.close()
                conn.close()

                version_info = f"{domains_protected} domains protected, {today_rejections} rejections today"
                components.append({'name': 'Recipient Verification', 'version': version_info, 'status': 'active'})
            except:
                components.append({'name': 'Recipient Verification', 'version': 'Active', 'status': 'active'})
        else:
            components.append({'name': 'Recipient Verification', 'version': 'Service stopped', 'status': 'warning'})
    except:
        components.append({'name': 'Recipient Verification', 'version': 'Not configured', 'status': 'warning'})

    # Check Mail Queue (filtered for client emails)
    queue_info = {
        'total_messages': 0,
        'client_messages': 0,
        'backscatter_messages': 0,
        'status': 'ok',
        'status_text': 'Queue empty'
    }
    try:
        result = subprocess.run(['mailq'], capture_output=True, text=True, timeout=10)
        output = result.stdout

        if 'queue is empty' not in output.lower():
            # Get client domains
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM client_domains WHERE active = 1")
            client_domains = [row[0] for row in cursor.fetchall()]
            cursor.close()
            conn.close()

            # Parse queue output
            lines = output.split('\n')
            client_count = 0
            backscatter_count = 0
            is_bounce = False

            for line in lines:
                # Check if this is a MAILER-DAEMON sender line
                if 'MAILER-DAEMON' in line:
                    is_bounce = True
                    continue

                # Check recipient lines (lines with @ that aren't headers)
                if '@' in line and not line.startswith('-'):
                    is_client_mail = False
                    for domain in client_domains:
                        if f'@{domain}' in line.lower():
                            is_client_mail = True
                            break

                    if is_client_mail:
                        client_count += 1
                        is_bounce = False  # Reset for next entry
                    elif is_bounce:
                        backscatter_count += 1
                        is_bounce = False  # Reset for next entry

            # Get total count
            import re
            match = re.search(r'(\d+)\s+Request', output, re.IGNORECASE)
            total_count = int(match.group(1)) if match else 0

            queue_info['total_messages'] = total_count
            queue_info['client_messages'] = client_count
            queue_info['backscatter_messages'] = backscatter_count

            if client_count > 50:
                queue_info['status'] = 'critical'
                queue_info['status_text'] = f'{client_count} client emails stuck in queue!'
            elif client_count > 20:
                queue_info['status'] = 'warning'
                queue_info['status_text'] = f'{client_count} client emails in queue'
            elif client_count > 0:
                queue_info['status'] = 'ok'
                queue_info['status_text'] = f'{client_count} client emails, {backscatter_count} spam bounces'
            else:
                queue_info['status'] = 'ok'
                queue_info['status_text'] = f'{backscatter_count} spam bounces (no client mail)'
    except Exception as e:
        logger.error(f"Error checking mail queue: {e}")
        queue_info['status'] = 'error'
        queue_info['status_text'] = f'Error checking queue: {str(e)}'

    # Check Retention/Cleanup Status
    retention_info = {
        'enabled': False,
        'retention_days': 30,
        'total_emails': 0,
        'emails_to_expire': 0,
        'days_until_first_expiration': 0,
        'oldest_email_date': None,
        'last_cleanup_time': None,
        'last_cleanup_deleted': 0,
        'status': 'ok'
    }
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get cleanup settings
        cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'cleanup_expired_emails_enabled'")
        enabled_row = cursor.fetchone()
        retention_info['enabled'] = enabled_row['setting_value'].lower() == 'true' if enabled_row else False

        cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'cleanup_retention_days'")
        days_row = cursor.fetchone()
        retention_info['retention_days'] = int(days_row['setting_value']) if days_row else 30

        # Get email counts and oldest email
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN timestamp < DATE_SUB(NOW(), INTERVAL %s DAY) THEN 1 END) as expired,
                MIN(timestamp) as oldest
            FROM email_analysis
        """, (retention_info['retention_days'],))
        email_stats = cursor.fetchone()

        retention_info['total_emails'] = email_stats['total'] or 0
        retention_info['emails_to_expire'] = email_stats['expired'] or 0

        if email_stats['oldest']:
            retention_info['oldest_email_date'] = email_stats['oldest']
            from datetime import datetime, timedelta
            expire_date = email_stats['oldest'] + timedelta(days=retention_info['retention_days'])
            days_until = (expire_date - datetime.now()).days
            retention_info['days_until_first_expiration'] = max(0, days_until)
            retention_info['first_expiration_date'] = expire_date

        # Check last cleanup run from logs
        try:
            import os
            log_file = '/opt/spacyserver/logs/cleanup.log'
            if os.path.exists(log_file):
                # Get last few lines
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    for line in reversed(lines[-50:]):  # Check last 50 lines
                        if 'Cleanup complete' in line and 'Total deleted:' in line:
                            # Extract deleted count
                            import re
                            match = re.search(r'Total deleted: (\d+)', line)
                            if match:
                                retention_info['last_cleanup_deleted'] = int(match.group(1))
                            break
                        elif line.startswith('2025-') and 'Cleanup complete' in line:
                            # Try to parse timestamp
                            try:
                                time_str = line.split(' - ')[0]
                                retention_info['last_cleanup_time'] = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S,%f')
                            except:
                                pass
        except Exception as log_err:
            logger.debug(f"Could not read cleanup log: {log_err}")

        cursor.close()
        conn.close()

        # Set status
        if not retention_info['enabled']:
            retention_info['status'] = 'warning'
        elif retention_info['emails_to_expire'] > 100:
            retention_info['status'] = 'warning'
        else:
            retention_info['status'] = 'ok'

    except Exception as e:
        logger.error(f"Error getting retention info: {e}")
        retention_info['status'] = 'error'

    # Check Fail2ban Status
    security_info = {
        'fail2ban_active': False,
        'jails': [],
        'total_banned': 0,
        'currently_banned_ips': [],
        'client_ip': request.remote_addr,
        'client_is_banned': False,
        'status': 'error'
    }
    try:
        # Check if fail2ban is running
        result = subprocess.run(['sudo', 'systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True, timeout=5)
        if result.stdout.strip() == 'active':
            security_info['fail2ban_active'] = True

            # Get jail status
            result = subprocess.run(['sudo', 'fail2ban-client', 'status'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Parse jail list
                import re
                jail_match = re.search(r'Jail list:\s+(.+)', result.stdout)
                if jail_match:
                    jail_names = [j.strip() for j in jail_match.group(1).split(',')]

                    # Get details for each jail
                    total_banned_count = 0
                    all_banned_ips = []
                    for jail_name in jail_names:
                        try:
                            jail_result = subprocess.run(['sudo', 'fail2ban-client', 'status', jail_name],
                                                        capture_output=True, text=True, timeout=5)
                            if jail_result.returncode == 0:
                                # Parse jail status
                                currently_banned = 0
                                total_banned = 0
                                banned_ips = []

                                banned_match = re.search(r'Currently banned:\s+(\d+)', jail_result.stdout)
                                if banned_match:
                                    currently_banned = int(banned_match.group(1))

                                total_match = re.search(r'Total banned:\s+(\d+)', jail_result.stdout)
                                if total_match:
                                    total_banned = int(total_match.group(1))

                                # Parse banned IP list
                                ip_list_match = re.search(r'Banned IP list:\s*(.*)$', jail_result.stdout, re.MULTILINE)
                                if ip_list_match and ip_list_match.group(1).strip():
                                    banned_ips = [ip.strip() for ip in ip_list_match.group(1).strip().split()]
                                    all_banned_ips.extend([{'ip': ip, 'jail': jail_name} for ip in banned_ips])

                                security_info['jails'].append({
                                    'name': jail_name,
                                    'currently_banned': currently_banned,
                                    'total_banned': total_banned,
                                    'banned_ips': banned_ips
                                })
                                total_banned_count += total_banned
                        except Exception as jail_err:
                            logger.debug(f"Error getting status for jail {jail_name}: {jail_err}")

                    security_info['total_banned'] = total_banned_count
                    security_info['currently_banned_ips'] = all_banned_ips

                    # Check if client's IP is currently banned
                    client_ip = security_info['client_ip']
                    if client_ip != 'unknown':
                        for banned_entry in all_banned_ips:
                            if banned_entry['ip'] == client_ip:
                                security_info['client_is_banned'] = True
                                break

                    security_info['status'] = 'active'

            # Get recent ban history from logs
            ban_history = []
            try:
                # Check current and previous log file
                log_files = ['/var/log/fail2ban.log', '/var/log/fail2ban.log.1']
                for log_file in log_files:
                    try:
                        result = subprocess.run(['sudo', 'grep', '-E', 'Ban|Unban', log_file],
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            for line in result.stdout.strip().split('\n'):
                                if line:
                                    # Parse line format: 2025-11-07 13:35:32,475 fail2ban.actions [714]: NOTICE [spacyweb] Ban 98.188.178.129
                                    parts = line.split()
                                    if len(parts) >= 8:
                                        date = parts[0]
                                        time = parts[1].split(',')[0]  # Remove milliseconds
                                        jail = parts[5].strip('[]')  # [spacyweb]
                                        action = parts[6]  # Ban or Unban
                                        ip = parts[7]  # IP address

                                        ban_history.append({
                                            'timestamp': f"{date} {time}",
                                            'action': action,
                                            'jail': jail,
                                            'ip': ip
                                        })
                    except Exception as log_err:
                        logger.debug(f"Could not read {log_file}: {log_err}")

                # Sort by timestamp descending and limit to last 20
                ban_history.sort(key=lambda x: x['timestamp'], reverse=True)
                security_info['ban_history'] = ban_history[:20]
            except Exception as history_err:
                logger.debug(f"Error getting ban history: {history_err}")
                security_info['ban_history'] = []

        else:
            security_info['status'] = 'inactive'
    except Exception as e:
        logger.error(f"Error getting fail2ban info: {e}")
        security_info['status'] = 'error'

    return render_template('system_info.html',
                         system_info=system_info_data,
                         components=components,
                         queue_info=queue_info,
                         retention_info=retention_info,
                         security_info=security_info)

@app.route('/config')
@login_required
def config_dashboard():
    """Main configuration dashboard"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', user_domains[0] if user_domains else 'default')

    # Verify user has access to selected domain
    if selected_domain not in user_domains and not current_user.is_admin():
        flash('Access denied to that domain', 'error')
        return redirect(url_for('config_dashboard', domain=user_domains[0]))

    # Get statistics for the dashboard
    stats = {
        'whitelisted_senders': 0,
        'blocked_patterns': 0,
        'trusted_domains': 0,
        'active_domains': len(user_domains)
    }

    # Count whitelisted senders
    try:
        with open('/opt/spacyserver/config/bec_config.json', 'r') as f:
            bec_config = json.load(f)
            if 'whitelist' in bec_config:
                if 'authentication_aware' in bec_config['whitelist']:
                    if 'senders' in bec_config['whitelist']['authentication_aware']:
                        # Count senders for this domain
                        for sender, config in bec_config['whitelist']['authentication_aware']['senders'].items():
                            if config.get('for_domain') == selected_domain or (
                                '@' in sender and sender.split('@')[1] == selected_domain
                            ):
                                stats['whitelisted_senders'] += 1
    except Exception as e:
        logger.error(f"Error counting whitelisted senders: {e}")

    # Count blocked patterns
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(DISTINCT pattern)
                FROM blocking_rules
                WHERE domain = %s OR domain = '*'
            """, (selected_domain,))
            result = cursor.fetchone()
            if result:
                stats['blocked_patterns'] = result[0]
            cursor.close()
            conn.close()
    except Exception as e:
        logger.error(f"Error counting blocked patterns: {e}")

    # Count trusted domains
    try:
        with open('/opt/spacyserver/config/trusted_domains.json', 'r') as f:
            trusted_domains = json.load(f)
            stats['trusted_domains'] = len(trusted_domains.get('trusted_domains', []))
    except Exception as e:
        logger.error(f"Error counting trusted domains: {e}")

    # Get recent configuration changes (placeholder - implement logging later)
    recent_changes = []

    return render_template('config_dashboard.html',
                         selected_domain=selected_domain,
                         user_domains=user_domains,
                         stats=stats,
                         recent_changes=recent_changes)

@app.route('/whitelist/<domain>')
@login_required
def whitelist_management(domain):
    """Main whitelist management page for a domain"""
    user_domains = get_user_authorized_domains(current_user)

    # Check if user has access to this domain
    if domain not in user_domains:
        flash('Access denied: You are not authorized to manage this domain', 'error')
        return redirect(url_for('dashboard'))

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # If user has multiple domains, show whitelists for all their domains
    # This allows domain admins to see entries across all their managed domains
    if len(user_domains) > 1:
        whitelist_data = whitelist_mgr.get_multi_domain_whitelist(user_domains)
        # Combine stats for all domains
        stats = {
            'total_senders': len(whitelist_data['senders']),
            'total_domains': len(whitelist_data['domains']),
            'recent_additions': [],
            'most_active': []
        }
        # Get stats for each domain and combine
        for d in user_domains:
            domain_stats = whitelist_mgr.get_whitelist_stats(d)
            stats['recent_additions'].extend(domain_stats.get('recent_additions', []))
            stats['most_active'].extend(domain_stats.get('most_active', []))
        # Sort and limit combined lists
        stats['recent_additions'] = sorted(stats['recent_additions'],
                                          key=lambda x: x.get('added_date', ''),
                                          reverse=True)[:7]
        stats['most_active'] = sorted(stats['most_active'],
                                      key=lambda x: x.get('email_count', 0),
                                      reverse=True)[:10]
    else:
        # Single domain user - use existing behavior
        whitelist_data = whitelist_mgr.get_domain_whitelist(domain)
        stats = whitelist_mgr.get_whitelist_stats(domain)

    return render_template('whitelist_management.html',
                         domain=domain,
                         whitelist=whitelist_data,
                         stats=stats,
                         user_domains=user_domains,
                         multi_domain=len(user_domains) > 1)

@app.route('/whitelist/<domain>/add_sender', methods=['POST'])
@login_required
def add_whitelist_sender(domain):
    """Add a sender to the whitelist"""
    # Check authorization
    if domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # Get form data
    sender_email = request.form.get('sender_email', '').strip().lower()
    trust_bonus = int(request.form.get('trust_bonus', 3))
    require_auth = request.form.getlist('require_auth')
    # Get the specific domain this whitelist is for (important for multi-domain users)
    for_domain = request.form.get('for_domain', domain).strip().lower()

    if not sender_email:
        return jsonify({'success': False, 'error': 'Email address required'})

    # Verify user has access to the for_domain
    if for_domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized for that domain'}), 403

    # Add to whitelist with proper domain association
    success, message = whitelist_mgr.add_sender_whitelist(
        domain=for_domain,  # Use the for_domain, not the URL domain
        sender_email=sender_email,
        trust_bonus=trust_bonus,
        require_auth=require_auth if require_auth else ['spf'],
        added_by=current_user.email
    )

    return jsonify({'success': success, 'message': message})

@app.route('/whitelist/<domain>/remove_sender', methods=['POST'])
@login_required
def remove_whitelist_sender(domain):
    """Remove a sender from the whitelist"""
    # Check authorization
    if domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # Get sender email
    sender_email = request.form.get('sender_email', '').strip().lower()

    if not sender_email:
        return jsonify({'success': False, 'error': 'Email address required'})

    # Remove from whitelist
    success, message = whitelist_mgr.remove_sender_whitelist(
        domain=domain,
        sender_email=sender_email,
        removed_by=current_user.email
    )

    return jsonify({'success': success, 'message': message})

@app.route('/whitelist/<domain>/remove_domain', methods=['POST'])
@login_required
def remove_whitelist_domain(domain):
    """Remove a domain from the whitelist"""
    # Check authorization
    if domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # Get domain to remove
    whitelist_domain = request.form.get('whitelist_domain', '').strip().lower()

    if not whitelist_domain:
        return jsonify({'success': False, 'error': 'Domain required'})

    # Remove from whitelist
    success, message = whitelist_mgr.remove_domain_whitelist(
        domain=domain,
        target_domain=whitelist_domain,
        removed_by=current_user.email
    )

    return jsonify({'success': success, 'message': message})

@app.route('/whitelist/<domain>/search_sender', methods=['POST'])
@login_required
def search_sender_emails(domain):
    """Search for emails from a specific sender"""
    # Check authorization
    if domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # Get search parameters
    sender_email = request.form.get('sender_email', '').strip()
    days = int(request.form.get('days', 30))

    if not sender_email:
        return jsonify({'success': False, 'error': 'Email address required'})

    # Search for emails
    results = whitelist_mgr.search_sender_in_emails(domain, sender_email, days)

    return jsonify({
        'success': True,
        'results': results,
        'count': len(results)
    })

@app.route('/whitelist/<domain>/add_domain', methods=['POST'])
@login_required
def add_whitelist_domain(domain):
    """Add a domain to the whitelist"""
    # Check authorization - only admins can add domain-level whitelists
    if not current_user.is_admin():
        return jsonify({'success': False, 'error': 'Admin access required'}), 403

    # Lazy import to avoid module-level initialization issues
    from whitelist_manager import WhitelistManager
    whitelist_mgr = WhitelistManager()

    # Get form data
    target_domain = request.form.get('target_domain', '').strip().lower()
    trust_level = int(request.form.get('trust_level', 5))
    require_auth = request.form.getlist('require_auth')
    bypass_checks = request.form.get('bypass_checks', 'false').lower() == 'true'

    if not target_domain:
        return jsonify({'success': False, 'error': 'Domain required'})

    # Add to whitelist
    success, message = whitelist_mgr.add_domain_whitelist(
        domain=domain,
        target_domain=target_domain,
        trust_level=trust_level,
        require_auth=require_auth if require_auth else ['spf'],
        bypass_checks=bypass_checks,
        added_by=current_user.email
    )

    return jsonify({'success': success, 'message': message})



# ============================================================================
# QUARANTINE ROUTES
# ============================================================================

@app.route('/quarantine')
@login_required
def quarantine_view():
    """Email Status Page - list of all processed emails (like EFA status.php)"""
    try:
        # Get spam threshold from config (env or database)
        spam_threshold = get_spam_threshold()

        # Get filter parameters
        domain_filter = request.args.get('domain', '')
        status_filter = request.args.get('status', 'all')  # Default to 'all' emails
        search_query = request.args.get('search', '')
        search_content = request.args.get('search_content', '0')
        show_deleted = request.args.get('show_deleted', '')  # show_deleted=1 to show ONLY deleted

        # Validate pagination parameters to prevent SQL injection
        try:
            page = int(request.args.get('page', 1))
            if page < 1:
                page = 1
            if page > 100000:
                page = 100000
        except (ValueError, TypeError):
            logger.warning(f"Invalid page parameter: {request.args.get('page')}")
            page = 1

        per_page = 50

        # Get user's authorized domains
        user_domains = get_user_authorized_domains(current_user)

        # Build query
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Query email_analysis as primary table with LEFT JOIN to email_quarantine for status
        # PERFORMANCE OPTIMIZED:
        # 1. Exclude heavy blob columns (raw_email, text_content, html_content) from list view
        # 2. Use LEFT JOIN to email_quarantine for quarantine status
        # 3. Leverages indexes on message_id, timestamp, spam_score
        # 4. Uses unified ID system from email_analysis
        query = """
            SELECT
                ea.id, ea.message_id, ea.timestamp, ea.sender,
                ea.recipients, ea.subject, ea.spam_score,
                ea.email_category,
                ea.detected_language,
                ea.sentiment_polarity,
                ea.content_summary,
                ea.raw_email,
                ea.not_spam_train_count,
                ea.spam_train_count,
                COALESCE(eq.sender_domain, '') as sender_domain,
                COALESCE(eq.quarantine_status, 'delivered') as quarantine_status,
                COALESCE(eq.quarantine_reason, 'N/A') as quarantine_reason,
                COALESCE(eq.quarantine_expires_at, DATE_ADD(ea.timestamp, INTERVAL 30 DAY)) as quarantine_expires_at,
                ea.has_attachments,
                COALESCE(eq.attachment_count, 0) as attachment_count,
                COALESCE(eq.virus_detected, 0) as virus_detected,
                COALESCE(eq.phishing_detected, CASE WHEN ea.email_category = 'phishing' THEN 1 ELSE 0 END) as phishing_detected,
                eq.reviewed_by,
                eq.reviewed_at,
                COALESCE(DATEDIFF(eq.quarantine_expires_at, NOW()), DATEDIFF(DATE_ADD(ea.timestamp, INTERVAL 30 DAY), NOW())) as days_until_expiry,
                COALESCE(ea.is_deleted, 0) as is_deleted,
                ea.disposition,
                CASE WHEN eq.id IS NOT NULL THEN 'quarantine' ELSE 'analysis' END as source_table
            FROM email_analysis ea
            LEFT JOIN email_quarantine eq ON ea.message_id = eq.message_id
            WHERE 1=1
        """
        params = []

        # Filter by spam score (status filter) - matches /emails page logic
        if status_filter == 'quarantined':
            # Quarantined = emails that are actually in quarantine (disposition='quarantined' OR eq.quarantine_status='held')
            query += " AND (ea.disposition = 'quarantined' OR eq.quarantine_status = 'held')"
        elif status_filter == 'spam':
            # Spam = emails with spam_score >= threshold OR categorized as spam/phishing
            query += f" AND (ea.spam_score >= {spam_threshold} OR ea.email_category IN ('spam', 'phishing'))"
        elif status_filter == 'clean':
            # Clean = emails with spam_score < 30% of threshold and not categorized as spam
            query += f" AND ea.spam_score < {spam_threshold * 0.3} AND (ea.email_category NOT IN ('spam', 'phishing') OR ea.email_category IS NULL)"
        elif status_filter == 'suspicious':
            # Suspicious = emails with spam_score between 60% and threshold (6.0-9.9 with default 10.0 threshold)
            query += f" AND ea.spam_score >= {spam_threshold * 0.6} AND ea.spam_score < {spam_threshold}"
        # 'all' = no additional filter

        # Filter by domain (user access control)
        if not current_user.is_admin():
            # SECURITY: Different filtering based on role
            if current_user.role == 'client':
                # CLIENT role: ONLY see emails where they are sender OR recipient OR alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Build condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
                user_conditions = []
                user_conditions.append("ea.sender = %s")
                params.append(current_user.email)
                user_conditions.append("ea.recipients LIKE %s")
                params.append(f'%{current_user.email}%')
                for alias in aliases:
                    user_conditions.append("ea.recipients LIKE %s")
                    params.append(f'%{alias}%')

                query += f" AND ({' OR '.join(user_conditions)})"
            else:
                # DOMAIN_ADMIN and other roles: see their authorized domains
                if user_domains:
                    # Check recipient domains
                    domain_conditions = []
                    for domain in user_domains:
                        domain_conditions.append("ea.recipients LIKE %s")
                        params.append(f'%@{domain}%')
                    query += f" AND ({' OR '.join(domain_conditions)})"
                else:
                    # User has no domains - show nothing
                    query += " AND 1=0"
        else:
            # Admin can filter by specific domain if requested
            if domain_filter:
                query += " AND ea.recipients LIKE %s"
                params.append(f'%@{domain_filter}%')

        # Search filter
        if search_query:
            # Check if search is numeric (email ID)
            if search_query.isdigit():
                query += " AND ea.id = %s"
                params.append(int(search_query))
            # Check if search looks like a date (contains hyphen and digits)
            elif '-' in search_query and any(c.isdigit() for c in search_query):
                # Search by date - supports full dates (2025-10-22) or partial (10-22)
                query += " AND DATE_FORMAT(ea.timestamp, '%Y-%m-%d') LIKE %s"
                params.append(f'%{search_query}%')
            else:
                # Build search condition - include content if checkbox is checked
                if search_content == '1':
                    # Search both content_summary and raw_email (fallback when content_summary is empty)
                    query += """ AND (
                        ea.sender LIKE %s OR
                        ea.subject LIKE %s OR
                        ea.recipients LIKE %s OR
                        ea.message_id LIKE %s OR
                        ea.content_summary LIKE %s OR
                        ea.raw_email LIKE %s
                    )"""
                    search_param = f'%{search_query}%'
                    params.extend([search_param, search_param, search_param, search_param, search_param, search_param])
                else:
                    query += """ AND (
                        ea.sender LIKE %s OR
                        ea.subject LIKE %s OR
                        ea.recipients LIKE %s OR
                        ea.message_id LIKE %s
                    )"""
                    search_param = f'%{search_query}%'
                    params.extend([search_param, search_param, search_param, search_param])

        # Add deleted filter - show_deleted=1 means show ONLY deleted, otherwise exclude deleted
        # Check quarantine_status, is_deleted, AND disposition fields
        logger.info(f"QUARANTINE VIEW FILTER: show_deleted='{show_deleted}'")
        if show_deleted == '1':
            # Show ONLY deleted items: either quarantine_status = 'deleted' OR is_deleted = 1 OR disposition = 'deleted'
            query += " AND (eq.quarantine_status = 'deleted' OR ea.is_deleted = 1 OR ea.disposition = 'deleted')"
            logger.info("QUARANTINE VIEW: Applying SHOW ONLY DELETED filter")
        else:
            # Hide deleted items: quarantine_status != 'deleted' AND is_deleted = 0 AND disposition != 'deleted'
            query += " AND (eq.quarantine_status IS NULL OR eq.quarantine_status != 'deleted') AND ea.is_deleted = 0 AND (ea.disposition IS NULL OR ea.disposition != 'deleted')"
            logger.info("QUARANTINE VIEW: Applying HIDE DELETED filter")

        # Order by timestamp (newest first)
        query += " ORDER BY ea.timestamp DESC"

        # Count total for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as filtered"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Add pagination
        offset = (page - 1) * per_page
        query += f" LIMIT {per_page} OFFSET {offset}"

        # Execute main query
        cursor.execute(query, params)
        quarantined_emails = cursor.fetchall()

        # Parse email bodies from raw_email for brief content preview (first 3-5 lines)
        from email import message_from_string
        for email in quarantined_emails:
            raw_email_for_preview = get_raw_email_content(email)
            if raw_email_for_preview:
                try:
                    msg = message_from_string(raw_email_for_preview)
                    # Extract email body
                    email_text = ''
                    if msg.is_multipart():
                        # Get text/plain parts
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == 'text/plain':
                                try:
                                    email_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break  # Just get the first text part
                                except:
                                    pass
                    else:
                        # Single part message
                        try:
                            email_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            pass

                    # Extract just first 3-5 lines (approximately 200 chars)
                    if email_text:
                        lines = email_text.strip().split('\n')
                        preview_lines = []
                        char_count = 0
                        for line in lines[:10]:  # Check first 10 lines
                            line = line.strip()
                            if line:  # Skip empty lines
                                preview_lines.append(line)
                                char_count += len(line)
                                if len(preview_lines) >= 3 or char_count >= 200:
                                    break
                        email['content_preview'] = ' '.join(preview_lines)[:250] + '...' if preview_lines else email.get('text_content', '')
                    else:
                        email['content_preview'] = email.get('text_content', '')
                except Exception as e:
                    logger.warning(f"Could not parse email body for preview: {e}")
                    email['content_preview'] = email.get('text_content', '')
            else:
                email['content_preview'] = email.get('text_content', '')

            # Extract source IP and lookup country
            email['source_ip'] = None
            email['source_country'] = None
            email['source_country_code'] = None

            raw_email_content = get_raw_email_content(email)
            if raw_email_content:
                try:
                    import re
                    # Get the first external Received header
                    received_headers = []
                    current_header = ""
                    for line in raw_email_content.split('\n'):
                        if line.startswith('Received:'):
                            if current_header:
                                received_headers.append(current_header)
                            current_header = line
                        elif current_header and (line.startswith('\t') or line.startswith(' ')):
                            current_header += line
                        elif current_header:
                            received_headers.append(current_header)
                            current_header = ""
                    if current_header:
                        received_headers.append(current_header)

                    # Look for the oldest (last in list) Received header with an external IP
                    # Iterate in reverse to get the oldest first
                    import ipaddress
                    for header in reversed(received_headers):
                        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
                        if ip_match:
                            candidate_ip = ip_match.group(1)
                            # Skip internal/private IPs
                            try:
                                ip_obj = ipaddress.ip_address(candidate_ip)
                                if not ip_obj.is_private and not ip_obj.is_loopback:
                                    email['source_ip'] = candidate_ip
                                    break
                            except:
                                pass

                    # Lookup country for source IP
                    if email.get('source_ip'):
                        try:
                            import geoip2.database
                            geoip_db_path = '/opt/spacyserver/data/GeoLite2-Country.mmdb'
                            reader = geoip2.database.Reader(geoip_db_path)
                            response = reader.country(email['source_ip'])
                            email['source_country'] = response.country.name
                            email['source_country_code'] = response.country.iso_code
                            reader.close()
                        except:
                            pass
                except:
                    pass

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page

        # Get statistics for email_analysis table
        stats_query = """
            SELECT
                COUNT(*) as total_held,
                COUNT(CASE WHEN timestamp < DATE_SUB(NOW(), INTERVAL 23 DAY) THEN 1 END) as expiring_soon,
                COALESCE(AVG(spam_score), 0) as avg_spam_score,
                COALESCE(SUM(CASE WHEN spam_score >= 50 OR email_category IN ('spam', 'phishing', 'virus') THEN 1 ELSE 0 END), 0) as security_threats
            FROM email_analysis
            WHERE 1=1
        """

        stats_params = []
        if not current_user.is_admin():
            if user_domains:
                domain_conditions = []
                for domain in user_domains:
                    domain_conditions.append("recipients LIKE %s")
                    stats_params.append(f'%@{domain}%')
                stats_query += f" AND ({' OR '.join(domain_conditions)})"
                cursor.execute(stats_query, stats_params)
            else:
                # User has no domains - return zero stats
                stats_query += " AND 1=0"
                cursor.execute(stats_query)
        else:
            if domain_filter:
                stats_query += " AND recipients LIKE %s"
                stats_params.append(f'%@{domain_filter}%')
            cursor.execute(stats_query, stats_params)

        stats = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template('quarantine.html',
                             quarantined_emails=quarantined_emails,
                             stats=stats,
                             page=page,
                             total_pages=total_pages,
                             total_count=total_count,
                             status_filter=status_filter,
                             domain_filter=domain_filter,
                             search_query=search_query,
                             show_deleted=show_deleted,
                             user_domains=user_domains,
                             selected_domain=domain_filter or (user_domains[0] if user_domains else ''),
                             search_content=search_content)

    except Exception as e:
        logger.error(f"Error loading quarantine view: {e}")
        flash(f'Error loading quarantine: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/quarantine/<int:email_id>')
@login_required
def quarantine_detail(email_id):
    """Detailed view of a single quarantined email"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Try email_analysis table first (primary table shown in quarantine view)
        query_analysis = """
            SELECT
                ea.id, ea.message_id, ea.timestamp, ea.sender,
                ea.recipients, ea.subject,
                ea.raw_email, ea.content_summary as text_content,
                ea.has_attachments,
                ea.spam_score, ea.email_category,
                ea.detected_language, ea.sentiment_polarity,
                ea.original_spf, ea.original_dkim, ea.original_dmarc,
                ea.disposition, ea.is_deleted, ea.quarantine_status as ea_quarantine_status,
                ea.not_spam_train_count,
                COALESCE(eq.quarantine_status, ea.quarantine_status, 'delivered') as quarantine_status,
                COALESCE(eq.quarantine_reason, 'N/A') as quarantine_reason,
                COALESCE(eq.quarantine_expires_at, DATE_ADD(ea.timestamp, INTERVAL 30 DAY)) as quarantine_expires_at,
                eq.reviewed_by,
                eq.reviewed_at,
                COALESCE(DATEDIFF(eq.quarantine_expires_at, NOW()), DATEDIFF(DATE_ADD(ea.timestamp, INTERVAL 30 DAY), NOW())) as days_until_expiry
            FROM email_analysis ea
            LEFT JOIN email_quarantine eq ON ea.message_id = eq.message_id
            WHERE ea.id = %s
        """

        cursor.execute(query_analysis, (email_id,))
        email = cursor.fetchone()
        from_quarantine_table = False

        # Check if email is deleted - redirect with appropriate message
        if email and (email.get('disposition') == 'deleted' or email.get('is_deleted') == 1):
            cursor.close()
            conn.close()
            flash('This email has been automatically deleted and is not in quarantine. View it in the Emails page with "Show Deleted" enabled.', 'warning')
            return redirect(url_for('quarantine_view'))

        # If not found in email_analysis, try email_quarantine table
        if not email:
            query_quarantine = """
                SELECT
                    id, message_id, timestamp, sender, sender_domain,
                    recipients, recipient_domains, subject,
                    raw_email, email_size, text_content, html_content,
                    has_attachments, attachment_count, attachment_names,
                    spam_score, spam_modules_detail, virus_detected, virus_names,
                    phishing_detected, spf_result, dkim_result, dmarc_result,
                    auth_score, quarantine_status, quarantine_reason,
                    quarantine_expires_at, user_classification,
                    reviewed_by, reviewed_at, released_by, released_at,
                    admin_notes,
                    DATEDIFF(quarantine_expires_at, NOW()) as days_until_expiry,
                    text_content, html_content, raw_email
                FROM email_quarantine
                WHERE id = %s
            """
            cursor.execute(query_quarantine, (email_id,))
            email = cursor.fetchone()
            from_quarantine_table = True

        if not email:
            flash('Email not found', 'warning')
            return redirect(url_for('quarantine_view'))

        # Check access permissions
        if not current_user.is_admin():
            has_access = False

            if current_user.role == 'client':
                # CLIENT role: Check if they are sender OR recipient OR alias recipient
                sender_email = email.get('sender', '')
                recipients_str = email.get('recipients', '')

                # Check if user is the sender
                if sender_email == current_user.email:
                    has_access = True
                # Check if user is in recipients
                elif current_user.email in recipients_str:
                    has_access = True
                else:
                    # Check if user's managed aliases are in recipients
                    conn_temp = get_db_connection()
                    cursor_temp = conn_temp.cursor(dictionary=True)
                    cursor_temp.execute("""
                        SELECT managed_email FROM user_managed_aliases
                        WHERE user_id = %s AND active = 1
                    """, (current_user.id,))
                    aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                    cursor_temp.close()
                    conn_temp.close()

                    # Check if any alias is in recipients
                    for alias in aliases:
                        if alias in recipients_str:
                            has_access = True
                            break
            else:
                # DOMAIN_ADMIN and other roles: Check domain access
                user_domains = get_user_authorized_domains(current_user)

                # For email_analysis table, recipients is a string, not JSON
                if from_quarantine_table:
                    sender_domain = email.get('sender_domain', '')
                    recipient_domains = json.loads(email['recipient_domains']) if email.get('recipient_domains') else []
                else:
                    # email_analysis table - extract domain from sender
                    sender_email = email.get('sender', '')
                    sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
                    # Extract domains from recipients string
                    recipient_domains = extract_receiving_domains(email.get('recipients', ''))

                # User must have access to sender domain or one of recipient domains
                has_access = (sender_domain in user_domains) or any(rd in user_domains for rd in recipient_domains)

            if not has_access:
                flash('Access denied', 'danger')
                return redirect(url_for('quarantine_view'))

        # Parse JSON fields (only for quarantine table)
        if from_quarantine_table:
            if email.get('recipients'):
                email['recipients_list'] = json.loads(email['recipients'])
            else:
                email['recipients_list'] = []

            if email.get('attachment_names'):
                email['attachment_names_list'] = json.loads(email['attachment_names'])
            else:
                email['attachment_names_list'] = []

            if email.get('spam_modules_detail'):
                email['spam_modules'] = json.loads(email['spam_modules_detail'])
            else:
                email['spam_modules'] = {}
        else:
            # email_analysis table - recipients is a comma-separated string
            email['recipients_list'] = [r.strip() for r in email.get('recipients', '').split(',') if r.strip()]
            email['attachment_names_list'] = []
            email['spam_modules'] = {}

        # Get action history
        history_query = """
            SELECT
                action_type, action_timestamp, performed_by,
                user_role, action_details, reason
            FROM quarantine_actions_log
            WHERE quarantine_id = %s
            ORDER BY action_timestamp DESC
        """
        cursor.execute(history_query, (email_id,))
        email['action_history'] = cursor.fetchall()

        # Sanitize text content for preview (limit to 10KB)
        if email['text_content']:
            email['text_preview'] = email['text_content'][:10000]
        else:
            email['text_preview'] = ''

        # Extract ALL headers from raw_email (critical for forensics)
        from email import message_from_string
        from email.policy import default as email_policy
        raw_email_for_headers = get_raw_email_content(email)
        if raw_email_for_headers:
            try:
                msg = message_from_string(raw_email_for_headers)
                headers_text = ""
                # Get ALL headers including duplicates using _headers
                for key, value in msg._headers:
                    # Format multi-line headers properly
                    formatted_value = str(value).replace('\n', '\n\t')
                    headers_text += f"{key}: {formatted_value}\n"

                # If no headers found via _headers, fallback to items()
                if not headers_text:
                    for key, value in msg.items():
                        headers_text += f"{key}: {value}\n"

                email['headers'] = headers_text

                # Extract text content from email body if text_content is empty
                if not email.get('text_content') or not email['text_content'].strip():
                    text_parts = []
                    html_parts = []

                    # Walk through email parts to extract text
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get('Content-Disposition', ''))

                            # Skip attachments
                            if 'attachment' in content_disposition:
                                continue

                            try:
                                if content_type == 'text/plain':
                                    text_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                                elif content_type == 'text/html':
                                    html_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                            except Exception:
                                pass
                    else:
                        # Single part email
                        try:
                            payload = msg.get_payload(decode=True)
                            if payload:
                                text_parts.append(payload.decode('utf-8', errors='ignore'))
                        except Exception:
                            pass

                    # Set text_content and text_preview from extracted parts
                    if text_parts:
                        email['text_content'] = '\n\n'.join(text_parts)
                        email['text_preview'] = email['text_content'][:10000]
                    elif html_parts:
                        # If no plain text, use HTML (will be displayed as-is)
                        email['html_content'] = html_parts[0]
                        email['text_preview'] = ''

                # Extract authentication results from headers
                # Parse X-SpaCy-Auth-Results header from the headers_text since msg.get() doesn't work with folded headers
                auth_results_match = None
                for line in headers_text.split('\n'):
                    if line.startswith('X-SpaCy-Auth-Results:'):
                        # Get this line and any continuation lines
                        auth_results_match = line.replace('X-SpaCy-Auth-Results:', '').strip()
                        break

                if auth_results_match:
                    # Example: "openspacy; spf=pass; dkim=fail; dmarc=pass (p=reject)"
                    email['spf_result'] = 'none'
                    email['dkim_result'] = 'none'
                    email['dmarc_result'] = 'none'

                    if 'spf=' in auth_results_match:
                        spf_part = auth_results_match.split('spf=')[1].split(';')[0].strip()
                        email['spf_result'] = spf_part

                    if 'dkim=' in auth_results_match:
                        dkim_part = auth_results_match.split('dkim=')[1].split(';')[0].strip()
                        email['dkim_result'] = dkim_part

                    if 'dmarc=' in auth_results_match:
                        dmarc_part = auth_results_match.split('dmarc=')[1].split('(')[0].strip()
                        email['dmarc_result'] = dmarc_part
                else:
                    email['spf_result'] = None
                    email['dkim_result'] = None
                    email['dmarc_result'] = None

                # Get auth score from headers_text
                auth_score_str = None
                for line in headers_text.split('\n'):
                    if line.startswith('X-SpaCy-Auth-Score:'):
                        auth_score_str = line.replace('X-SpaCy-Auth-Score:', '').strip()
                        break

                if auth_score_str:
                    try:
                        email['auth_score'] = float(auth_score_str)
                    except (ValueError, TypeError):
                        email['auth_score'] = None
                else:
                    email['auth_score'] = None

            except Exception as e:
                logger.warning(f"Could not parse headers for quarantine email {email_id}: {e}")
                email['headers'] = 'Headers not available'
        else:
            email['headers'] = 'Headers not available (raw email not stored)'
            email['spf_result'] = None
            email['dkim_result'] = None
            email['dmarc_result'] = None
            email['auth_score'] = None

        # Get relay/delivery information from Postfix logs
        try:
            relay_info = get_relay_info_from_logs(email.get('message_id'))
            logger.info(f"Relay info for email {email_id}: {relay_info}")

            # If email was released/delivered but relay_info shows it went to spacyfilter (quarantined),
            # create synthetic relay info based on the release destination
            if (email.get('disposition') in ['released', 'delivered'] and
                relay_info and relay_info.get('relay_host') == 'spacyfilter'):

                # Extract recipient domain to lookup relay configuration
                recipients_str = email.get('recipients', '')
                recipient_domain = None
                if recipients_str:
                    # Extract first recipient
                    if '@' in recipients_str:
                        try:
                            # Handle "Name <email>" format or JSON array
                            import json as json_module
                            try:
                                recipients_list = json_module.loads(recipients_str) if isinstance(recipients_str, str) and recipients_str.startswith('[') else [recipients_str]
                                recipient_email = recipients_list[0] if recipients_list else recipients_str
                            except:
                                recipient_email = recipients_str

                            if '<' in recipient_email:
                                recipient_email = recipient_email.split('<')[1].split('>')[0]
                            else:
                                recipient_email = recipient_email.split(',')[0].strip()
                            recipient_domain = recipient_email.split('@')[1].strip()
                        except:
                            pass

                # Get relay host from client_domains
                if recipient_domain:
                    try:
                        cursor2 = conn.cursor(dictionary=True)
                        cursor2.execute("""
                            SELECT relay_host, relay_port
                            FROM client_domains
                            WHERE domain = %s AND active = 1
                        """, (recipient_domain,))
                        domain_config = cursor2.fetchone()
                        cursor2.close()

                        if domain_config and domain_config.get('relay_host'):
                            # Create synthetic relay info for the release
                            relay_info = {
                                'found': True,
                                'status': 'delivered',
                                'relay_host': f"{domain_config['relay_host']}:{domain_config.get('relay_port', 25)}",
                                'relay_ip': domain_config['relay_host'],
                                'recipient': recipients_str,
                                'delivered_time': email.get('timestamp'),
                                'delay': None,
                                'queue_id': None,
                                'upstream_queue_id': None,
                                'dsn': '2.0.0'
                            }
                            logger.info(f"Generated synthetic relay info for released quarantine email {email_id}")
                    except Exception as lookup_err:
                        logger.error(f"Error looking up relay host for released quarantine email: {lookup_err}")

            email['relay_info'] = relay_info
        except Exception as e:
            logger.error(f"Error getting relay info for email {email_id}: {e}")
            email['relay_info'] = None

        cursor.close()
        conn.close()

        return render_template('quarantine_detail.html', email=email)

    except Exception as e:
        logger.error(f"Error loading email detail: {e}")
        flash(f'Error loading email: {str(e)}', 'danger')
        return redirect(url_for('quarantine_view'))


@app.route('/api/quarantine/<int:email_id>/release', methods=['POST'])
@login_required
def api_quarantine_release(email_id):
    """Release email from quarantine and relay to destination"""
    conn = None
    cursor = None
    try:
        # Get spam threshold from config (env or database)
        spam_threshold = get_spam_threshold()

        # Get release destination config
        relay_host = os.getenv('SPACY_RELAY_HOST', 'YOUR_RELAY_SERVER')
        relay_port = 25
        mode = 'mailguard'  # Default release mode

        # Try to load from config file if exists
        config_file = '/opt/spacyserver/config/quarantine_config.json'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
            release_config = config.get('release', {})
            mailguard_config = release_config.get('mailguard', {})
            relay_host = mailguard_config.get('host', relay_host)
            relay_port = mailguard_config.get('port', relay_port)

        # Get email from database
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if email exists - try email_analysis first (quarantine page shows this table)
        cursor.execute("SELECT * FROM email_analysis WHERE id = %s", (email_id,))
        email = cursor.fetchone()
        table_name = 'email_analysis'

        # If not in email_analysis, try email_quarantine
        if not email:
            cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
            email = cursor.fetchone()
            table_name = 'email_quarantine'

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # SPAM RELEASE PREVENTION: Check if spam emails should be blocked from release
        cursor.execute("""
            SELECT setting_value
            FROM system_settings
            WHERE setting_key = 'prevent_spam_release'
        """)
        result = cursor.fetchone()
        prevent_spam_release = result and result['setting_value'].lower() in ('true', '1', 'yes', 'enabled')

        if prevent_spam_release:
            spam_score = float(email.get('spam_score', 0))
            if spam_score >= spam_threshold:
                logger.warning(f"Attempted to release spam email (ID: {email_id}, spam_score: {spam_score}) by {current_user.email}")
                return jsonify({
                    'success': False,
                    'error': f'Cannot release spam emails (spam score: {spam_score:.1f}). Spam release is disabled in system settings.'
                }), 400

        # REMOVED RESTRICTION: Allow releasing deleted emails for recovery purposes
        # Deleted emails can be released within retention period (30 days) for recovery
        # if table_name == 'email_quarantine' and email.get("quarantine_status") == "deleted":
        #     return jsonify({'success': False, 'error': 'Cannot release a deleted email'}), 400

        # Check permissions - verify user has access to this email
        if not current_user.is_admin():
            if current_user.role == 'client':
                # CLIENT role: Check if user is sender or recipient or alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Check if user is sender
                sender = email.get('sender', '')
                has_access = (current_user.email.lower() in sender.lower())

                # Check if user or aliases are in recipients
                if not has_access:
                    recipients_str = email.get('recipients', '[]')
                    try:
                        recipients = json.loads(recipients_str) if isinstance(recipients_str, str) else recipients_str
                        recipients_str = ' '.join(recipients).lower()
                    except:
                        recipients_str = str(recipients_str).lower()

                    # Check user email
                    has_access = current_user.email.lower() in recipients_str

                    # Check aliases
                    if not has_access:
                        for alias in aliases:
                            if alias.lower() in recipients_str:
                                has_access = True
                                break

                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            else:
                # DOMAIN_ADMIN: Check domain access
                user_domains = get_user_authorized_domains(current_user)
                logger.info(f"DEBUG Release: User {current_user.email} authorized domains: {user_domains}")

                # Parse recipient_domains (JSON array) - or extract from recipients if missing
                import json as json_module
                import re
                recipient_domains = []

                # First try recipient_domains field (newer format)
                if email.get('recipient_domains'):
                    try:
                        recipient_domains = json_module.loads(email.get('recipient_domains', '[]'))
                    except:
                        pass

                # If recipient_domains is empty, extract from recipients field
                if not recipient_domains:
                    recipients_str = email.get('recipients', '')
                    if recipients_str:
                        # Extract email addresses and get their domains
                        email_pattern = r'([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))'
                        matches = re.findall(email_pattern, recipients_str)
                        recipient_domains = list(set([match[1].lower() for match in matches if match[1]]))

                logger.info(f"DEBUG Release: Email {email_id} recipient_domains: {recipient_domains}")

                # Case-insensitive domain comparison
                user_domains_lower = [d.lower() for d in user_domains]
                has_access = any(domain in user_domains_lower for domain in recipient_domains)
                logger.info(f"DEBUG Release: has_access={has_access}")

                if not has_access:
                    logger.warning(f"Domain admin {current_user.email} denied release access. User domains: {user_domains}, Email domains: {recipient_domains}")
                    return jsonify({'success': False, 'error': 'Access denied'}), 403

        # CRITICAL SECURITY RESTRICTION: Very high-risk emails (spam >= 90) can only be released by admins
        spam_score = float(email.get('spam_score', 0))
        if spam_score >= 90.0:
            # Only allow superadmin, admin, or domain_admin to release critical threats
            if not (current_user.is_superadmin() or current_user.is_admin() or current_user.role == 'domain_admin'):
                logger.warning(f"Client user {current_user.email} attempted to release critical threat email (ID: {email_id}, spam_score: {spam_score})")
                return jsonify({
                    'success': False,
                    'error': f'Critical security threat detected (spam score: {spam_score:.1f}). Only administrators can release very high-risk emails. Please contact your domain administrator.',
                    'requires_admin': True
                }), 403

        # Parse recipients - handle both table formats
        if table_name == 'email_analysis':
            # email_analysis stores recipients as string like '"user@example.com" <user@example.com>'
            recipients_str = email.get('recipients', '')
            # Extract email addresses using regex - prefer addresses in angle brackets
            import re
            # First try to extract from angle brackets
            email_pattern = r'<([^>]+)>'
            matches = re.findall(email_pattern, recipients_str)
            if matches:
                recipients = matches
            else:
                # Fallback: extract plain email addresses (but filter out those with quotes)
                email_pattern = r'(?<!")([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?!")'
                matches = re.findall(email_pattern, recipients_str)
                recipients = matches if matches else [recipients_str.strip()]
        else:
            # email_quarantine stores recipients as JSON array
            recipients = json.loads(email['recipients']) if email['recipients'] else []

        # Extract email address from sender (handle "Name <email@domain.com>" format)
        sender = email['sender']
        if '<' in sender and '>' in sender:
            # Extract email from "Name <email@domain.com>" format
            sender = sender.split('<')[1].split('>')[0].strip()

        # Get raw_email
        raw_email = email.get('raw_email', '')
        if not raw_email:
            return jsonify({'success': False, 'error': 'Email content not available for relay'}), 400

        # Get the actual destination relay host from client_domains table
        # Extract recipient domain to lookup relay configuration
        recipient_domain = None
        if recipients:
            first_recipient = recipients[0] if isinstance(recipients, list) else recipients
            if '@' in str(first_recipient):
                recipient_domain = str(first_recipient).split('@')[1].strip()

        # Lookup relay host for this domain
        actual_relay_host = relay_host  # Fallback to default
        actual_relay_port = relay_port
        if recipient_domain:
            cursor.execute("""
                SELECT relay_host, relay_port
                FROM client_domains
                WHERE domain = %s AND active = 1
            """, (recipient_domain,))
            domain_config = cursor.fetchone()
            if domain_config:
                actual_relay_host = domain_config['relay_host']
                actual_relay_port = domain_config.get('relay_port', 25)
                logger.info(f"Using relay {actual_relay_host}:{actual_relay_port} for domain {recipient_domain}")

        # SECURITY: Sanitize sender and recipients to prevent SMTP header injection
        try:
            sanitized_sender = sanitize_email_address(sender)
            sanitized_recipients = [sanitize_email_address(r) for r in recipients]
        except ValueError as ve:
            logger.error(f"Email address validation failed for quarantine release {email_id}: {ve}")
            return jsonify({'success': False, 'error': 'Invalid email address format'}), 400

        # Relay email using SMTP
        try:
            # Encode raw_email properly to handle non-ASCII characters (Japanese, etc.)
            if isinstance(raw_email, str):
                raw_email_bytes = raw_email.encode('utf-8')
            else:
                raw_email_bytes = raw_email

            # Connect and send using domain-specific relay configuration
            with smtplib.SMTP(actual_relay_host, actual_relay_port, timeout=30) as smtp:
                smtp.sendmail(sanitized_sender, sanitized_recipients, raw_email_bytes)

            # Update database (only for email_quarantine table)
            if table_name == 'email_quarantine':
                # Recovery feature: If email was deleted, change status back to released
                # This allows admins to recover deleted emails within retention period
                update_query = """
                    UPDATE email_quarantine
                    SET quarantine_status = 'released',
                        released_by = %s,
                        released_at = NOW(),
                        released_to = %s
                    WHERE id = %s
                """
                cursor.execute(update_query, (current_user.email, mode, email_id))

                # Log action
                log_query = """
                    INSERT INTO quarantine_actions_log
                    (quarantine_id, action_type, performed_by, user_role, action_details)
                    VALUES (%s, %s, %s, %s, %s)
                """
                log_data = json.dumps({
                    'released_to': actual_relay_host,
                    'recipient_count': len(recipients),
                    'mode': mode
                })
                cursor.execute(log_query, (email_id, 'released', current_user.email,
                                          'admin' if current_user.is_admin() else 'user', log_data))
            elif table_name == 'email_analysis':
                # Update email_analysis table to mark as delivered and remove from quarantine
                update_query = """
                    UPDATE email_analysis
                    SET disposition = 'delivered',
                        quarantine_status = NULL
                    WHERE id = %s
                """
                cursor.execute(update_query, (email_id,))

                # ALSO update email_quarantine table for status badge display on quarantine page
                # The quarantine page joins email_analysis to email_quarantine and displays eq.quarantine_status
                message_id = email.get('message_id')
                if message_id:
                    cursor.execute("""
                        UPDATE email_quarantine
                        SET quarantine_status = 'released',
                            released_by = %s,
                            released_at = NOW(),
                            released_to = %s
                        WHERE message_id = %s
                    """, (current_user.email, mode, message_id))

            # Trigger ham learning (user releasing email = marking as safe)
            try:
                from modules.spam_learner import spam_learner

                # Extract recipient domains for learning
                recipient_domains_list = []
                try:
                    recipient_domains_list = json.loads(email.get('recipient_domains', '[]'))
                except:
                    pass

                # Learn for each recipient domain
                for recipient_domain in recipient_domains_list:
                    # Get client_domain_id
                    cursor.execute("""
                        SELECT id FROM client_domains WHERE domain = %s AND active = 1
                    """, (recipient_domain,))
                    domain_result = cursor.fetchone()

                    if domain_result:
                        client_domain_id = domain_result['id']

                        # Prepare email data for learning
                        email_data = {
                            'subject': email.get('subject', ''),
                            'body': email.get('body_plain', '') or email.get('body_html', ''),
                            'sender': email.get('sender', '')
                        }

                        # Learn from ham (false positive)
                        result = spam_learner.learn_from_ham(
                            email_data,
                            client_domain_id,
                            current_user.email
                        )

                        if result.get('success'):
                            logger.info(f"Learned {result.get('patterns_learned', 0)} ham patterns from released email {email_id} for domain {recipient_domain}")
                        else:
                            logger.warning(f"Failed to learn ham patterns: {result.get('error')}")
            except Exception as learn_err:
                logger.error(f"Error during ham learning on release: {learn_err}")
                # Don't fail the whole operation if learning fails

            conn.commit()

            logger.info(f"Email {email_id} released by {current_user.email} to {actual_relay_host}")

            return jsonify({
                'success': True,
                'message': 'Email released and delivered successfully',
                'released_to': actual_relay_host
            })

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error releasing email {email_id}: {e}")
            error_str = str(e)

            # Parse SMTP errors for user-friendly messages
            if 'Recipient address rejected' in error_str or '550' in error_str or '450' in error_str:
                # Extract recipient email if possible
                import re
                email_match = re.search(r'<([^>]+@[^>]+)>', error_str)
                recipient = email_match.group(1) if email_match else 'recipient'
                user_msg = f'The recipient address ({recipient}) was rejected by the mail server. The email address may not exist or may not accept mail.'
            elif 'Connection refused' in error_str or 'Connection timed out' in error_str:
                user_msg = 'Unable to connect to the mail server. The server may be temporarily unavailable.'
            elif 'Authentication failed' in error_str:
                user_msg = 'Mail server authentication failed. Please contact your administrator.'
            else:
                user_msg = f'Failed to deliver email: {error_str}'

            return jsonify({'success': False, 'error': user_msg}), 500

    except Exception as e:
        logger.error(f"Error releasing email {email_id}: {e}")
        error_msg = str(e)

        # Provide user-friendly error messages
        if 'Access denied' in error_msg or 'permission' in error_msg.lower():
            user_msg = 'You do not have permission to release this email.'
        elif 'not found' in error_msg.lower():
            user_msg = 'The email could not be found. It may have already been released or deleted.'
        else:
            user_msg = f'An error occurred: {error_msg}'

        return jsonify({'success': False, 'error': user_msg}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/quarantine/<int:email_id>/delete', methods=['POST'])
@login_required
def api_quarantine_delete(email_id):
    """Delete email from quarantine (mark as spam)"""
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'User confirmed spam')

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if email exists - try email_analysis first (quarantine page shows this table)
        cursor.execute("SELECT * FROM email_analysis WHERE id = %s", (email_id,))
        email = cursor.fetchone()
        table_name = 'email_analysis'

        # If not in email_analysis, try email_quarantine
        if not email:
            cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
            email = cursor.fetchone()
            table_name = 'email_quarantine'

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions - verify user has access to this email
        if not current_user.is_admin():
            if current_user.role == 'client':
                # CLIENT role: Check if user is sender or recipient or alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Check if user is sender
                sender = email.get('sender', '')
                has_access = (current_user.email.lower() in sender.lower())

                # Check if user or aliases are in recipients
                if not has_access:
                    recipients_str = email.get('recipients', '[]')
                    try:
                        recipients = json.loads(recipients_str) if isinstance(recipients_str, str) else recipients_str
                        recipients_str = ' '.join(recipients).lower()
                    except:
                        recipients_str = str(recipients_str).lower()

                    # Check user email
                    has_access = current_user.email.lower() in recipients_str

                    # Check aliases
                    if not has_access:
                        for alias in aliases:
                            if alias.lower() in recipients_str:
                                has_access = True
                                break

                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            else:
                # DOMAIN_ADMIN: Check domain access
                user_domains = get_user_authorized_domains(current_user)
                # Parse recipient_domains (stored as JSON array like ["domain.com"])
                import json
                try:
                    recipient_domains = json.loads(email.get('recipient_domains', '[]'))
                except:
                    recipient_domains = []

                # If recipient_domains is empty (e.g., from email_analysis table), extract from recipients
                if not recipient_domains:
                    recipients_str = email.get('recipients', '')
                    try:
                        # Parse recipients (could be JSON array or plain string)
                        if isinstance(recipients_str, str):
                            recipients = json.loads(recipients_str) if recipients_str.startswith('[') else [recipients_str]
                        else:
                            recipients = recipients_str if isinstance(recipients_str, list) else [str(recipients_str)]

                        # Extract domains from email addresses
                        recipient_domains = []
                        for recip in recipients:
                            if '@' in str(recip):
                                domain = str(recip).split('@')[-1].strip().lower()
                                if domain and domain not in recipient_domains:
                                    recipient_domains.append(domain)
                    except:
                        pass

                # Check if user has access to any of the recipient domains
                has_access = False
                for domain in recipient_domains:
                    if domain in user_domains:
                        has_access = True
                        break

                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Delete from appropriate table
        if table_name == 'email_analysis':
            # For email_analysis, just delete the record
            cursor.execute("DELETE FROM email_analysis WHERE id = %s", (email_id,))
        else:
            # For email_quarantine, mark as deleted (soft delete)
            update_query = """
                UPDATE email_quarantine
                SET quarantine_status = 'deleted',
                    user_classification = 'spam',
                    deleted_by = %s,
                    deleted_at = NOW()
                WHERE id = %s
            """
            cursor.execute(update_query, (current_user.email, email_id))

            # Log action for quarantine table
            log_query = """
                INSERT INTO quarantine_actions_log
                (quarantine_id, action_type, performed_by, user_role, reason)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(log_query, (email_id, 'marked_spam', current_user.email,
                                      'admin' if current_user.is_admin() else 'user', reason))

        conn.commit()

        logger.info(f"Email {email_id} marked as spam by {current_user.email}")

        return jsonify({'success': True, 'message': 'Email marked as spam and deleted'})

    except Exception as e:
        logger.error(f"Error deleting email {email_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()




@login_required
@app.route('/api/quarantine/<int:email_id>/headers', methods=['GET'])
@login_required
def api_quarantine_headers(email_id):
    """Get email headers"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Try email_quarantine first (has raw_email and recipient_domains)
        cursor.execute("SELECT raw_email, recipient_domains FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        # If not in quarantine, try email_analysis (now also has raw_email)
        if not email:
            cursor.execute("SELECT raw_email, raw_email_path, recipients FROM email_analysis WHERE id = %s", (email_id,))
            email_analysis = cursor.fetchone()

            if not email_analysis:
                return jsonify({'success': False, 'error': 'Email not found'}), 404

            # Check permissions for email_analysis
            if not current_user.is_admin():
                user_domains = get_user_authorized_domains(current_user)
                recipients = email_analysis.get('recipients', '')

                # Check if any authorized domain is in recipients
                has_access = any(f"@{domain}" in recipients for domain in user_domains)
                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403

            # Parse headers from email_analysis raw_email
            from email import message_from_string
            try:
                raw_email = get_raw_email_content(email_analysis)
                if not raw_email:
                    headers_text = "Headers not available (raw email not stored)"
                else:
                    msg = message_from_string(raw_email)
                    headers_text = ""

                    # Get ALL headers including duplicates (critical for forensics)
                    # Using msg._headers to preserve order and get all instances
                    for key, value in msg._headers:
                        # Format multi-line headers properly
                        formatted_value = str(value).replace('\n', '\n\t')
                        headers_text += f"{key}: {formatted_value}\n"

                    # If no headers found via _headers, fallback to items()
                    if not headers_text:
                        for key, value in msg.items():
                            headers_text += f"{key}: {value}\n"
            except Exception as parse_error:
                headers_text = f"Could not parse headers: {str(parse_error)}"

            cursor.close()
            conn.close()
            return jsonify({'success': True, 'headers': headers_text or 'No headers available'})

        # Original quarantine logic
        # Check permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            try:
                recipient_domains = json.loads(email.get('recipient_domains', '[]'))
            except:
                recipient_domains = []

            has_access = any(domain in user_domains for domain in recipient_domains)
            if not has_access:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Parse headers from raw email
        from email import message_from_string
        try:
            msg = message_from_string(email['raw_email'])
            headers_text = ""
            for key, value in msg.items():
                headers_text += f"{key}: {value}\n"
        except:
            headers_text = "Could not parse headers"

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'headers': headers_text or 'No headers available'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/quarantine/<int:email_id>/not-spam', methods=['POST'])
@login_required
def api_quarantine_mark_not_spam(email_id):
    """Mark email as not spam (for learning) and release"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if email exists - try email_analysis first (quarantine page shows this table)
        cursor.execute("SELECT * FROM email_analysis WHERE id = %s", (email_id,))
        email = cursor.fetchone()
        table_name = 'email_analysis'

        # If not in email_analysis, try email_quarantine
        if not email:
            cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
            email = cursor.fetchone()
            table_name = 'email_quarantine'

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions - verify user has access to this email
        if not current_user.is_admin():
            if current_user.role == 'client':
                # CLIENT role: Check if user is sender or recipient or alias recipient
                # Get user's managed aliases
                conn_temp = get_db_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                cursor_temp.execute("""
                    SELECT managed_email FROM user_managed_aliases
                    WHERE user_id = %s AND active = 1
                """, (current_user.id,))
                aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
                cursor_temp.close()
                conn_temp.close()

                # Check if user is sender
                sender = email.get('sender', '')
                has_access = (current_user.email.lower() in sender.lower())

                # Check if user or aliases are in recipients
                if not has_access:
                    recipients_str = email.get('recipients', '[]')
                    try:
                        recipients = json.loads(recipients_str) if isinstance(recipients_str, str) else recipients_str
                        recipients_str = ' '.join(recipients).lower()
                    except:
                        recipients_str = str(recipients_str).lower()

                    # Check user email
                    has_access = current_user.email.lower() in recipients_str

                    # Check aliases
                    if not has_access:
                        for alias in aliases:
                            if alias.lower() in recipients_str:
                                has_access = True
                                break

                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403
            else:
                # DOMAIN_ADMIN: Check domain access
                user_domains = get_user_authorized_domains(current_user)

                # Extract domains from recipients field
                import re
                recipients_str = email.get('recipients', '')
                # Extract email addresses and get their domains (lowercase)
                email_pattern = r'[\w\.-]+@([\w\.-]+)'
                recipient_domains = list(set([d.lower() for d in re.findall(email_pattern, recipients_str)]))

                # Also check sender domain for outbound emails
                sender_str = email.get('sender', '')
                sender_domains = list(set([d.lower() for d in re.findall(email_pattern, sender_str)]))

                # Check if user has access to any of the recipient or sender domains (case-insensitive)
                user_domains_lower = [d.lower() for d in user_domains]
                has_access = False
                for domain in recipient_domains + sender_domains:
                    if domain in user_domains_lower:
                        has_access = True
                        break

                if not has_access:
                    return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update classification (only for email_quarantine table)
        if table_name == 'email_quarantine':
            update_query = """
                UPDATE email_quarantine
                SET user_classification = 'not_spam',
                    spam_score = CASE WHEN spam_score - 5.0 < 0.0 THEN 0.0 ELSE spam_score - 5.0 END,
                    reviewed_by = %s,
                    reviewed_at = NOW()
                WHERE id = %s
            """
            cursor.execute(update_query, (current_user.email, email_id))

            # Log action
            log_query = """
                INSERT INTO quarantine_actions_log
                (quarantine_id, action_type, performed_by, user_role)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(log_query, (email_id, 'marked_not_spam', current_user.email,
                                      'admin' if current_user.is_admin() else 'user'))
            logger.info(f"Email {email_id} from email_quarantine marked as not spam by {current_user.email} (spam_score reduced by 5.0)")
        else:
            # For email_analysis, check training count and update
            # Get current training count
            current_train_count = email.get('not_spam_train_count', 0) or 0

            # Check if we can train more (max 3 times)
            if current_train_count >= 3:
                return jsonify({
                    'success': False,
                    'error': 'Training limit reached',
                    'message': 'This email has already been marked as not spam 3 times (maximum training limit)',
                    'train_count': current_train_count,
                    'max_count': 3
                }), 400

            # Increment training count and reduce spam score
            new_train_count = current_train_count + 1
            update_query = """
                UPDATE email_analysis
                SET spam_score = LEAST(spam_score - 5.0, 0.0),
                    email_category = 'clean',
                    not_spam_train_count = %s
                WHERE id = %s
            """
            cursor.execute(update_query, (new_train_count, email_id))
            logger.info(f"Email {email_id} from email_analysis marked as not spam by {current_user.email} (spam_score reduced, train_count: {new_train_count}/3)")

        conn.commit()

        # Extract body text based on table
        if table_name == 'email_quarantine':
            body_text = email.get('text_content', '') or email.get('body_plain', '') or email.get('body_html', '')
        else:  # email_analysis
            body_text = email.get('content_summary', '')
            raw_email_for_export = get_raw_email_content(email)
            if not body_text and raw_email_for_export:
                try:
                    from email import message_from_string
                    msg = message_from_string(raw_email_for_export)
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == 'text/plain':
                                body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                break
                    else:
                        body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    body_text = email.get('content_summary', '')

        # Trigger ham learning (false positive learning)
        try:
            from modules.spam_learner import spam_learner

            # Extract recipient domains for learning
            if table_name == 'email_quarantine':
                # email_quarantine has recipient_domains as JSON
                recipient_domains = []
                try:
                    recipient_domains_str = email.get('recipient_domains', '[]')
                    recipient_domains = json.loads(recipient_domains_str) if isinstance(recipient_domains_str, str) else recipient_domains_str
                except:
                    pass
            else:
                # email_analysis has recipients as string
                recipient_domains = extract_receiving_domains(email.get('recipients', ''))

            # Learn for each recipient domain
            for recipient_domain in recipient_domains:
                # Get client_domain_id
                cursor.execute("""
                    SELECT id FROM client_domains WHERE domain = %s AND active = 1
                """, (recipient_domain,))
                domain_result = cursor.fetchone()

                if domain_result:
                    client_domain_id = domain_result['id']

                    # Prepare email data for learning
                    email_data = {
                        'subject': email.get('subject', ''),
                        'body': body_text,
                        'sender': email.get('sender', '')
                    }

                    # Learn from ham (false positive)
                    result = spam_learner.learn_from_ham(
                        email_data,
                        client_domain_id,
                        current_user.email
                    )

                    if result.get('success'):
                        logger.info(f"Learned {result.get('patterns_learned', 0)} ham patterns from email {email_id} for domain {recipient_domain}")
                    else:
                        logger.warning(f"Failed to learn ham patterns: {result.get('error')}")
        except Exception as learn_err:
            logger.error(f"Error during ham learning: {learn_err}")
            # Don't fail the whole operation if learning fails

        logger.info(f"Email {email_id} marked as not spam by {current_user.email}")

        # Return training count information
        train_count = email.get('not_spam_train_count', 0) or 0
        if table_name == 'email_analysis':
            train_count = new_train_count if 'new_train_count' in locals() else train_count

        return jsonify({
            'success': True,
            'message': f'Email marked as not spam ({train_count}/3 training iterations). Release separately if needed.',
            'train_count': train_count,
            'max_count': 3,
            'can_train_more': train_count < 3
        })

    except Exception as e:
        logger.error(f"Error marking email {email_id} as not spam: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/api/quarantine/bulk-release', methods=['POST'])
@login_required
def api_quarantine_bulk_release():
    """Bulk release multiple emails"""
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        if len(email_ids) > 100:
            return jsonify({'success': False, 'error': 'Maximum 100 emails at once'}), 400

        success_count = 0
        error_count = 0
        errors = []

        for email_id in email_ids:
            # Call single release function for each email
            try:
                logger.info(f"Bulk release: attempting to release email {email_id}")
                response = api_quarantine_release(email_id)
                # Check if response is successful (either just jsonify object or tuple with 200)
                is_success = False
                error_msg = None

                if isinstance(response, tuple):
                    # Tuple format: (response_object, status_code)
                    response_obj, status_code = response
                    logger.info(f"Bulk release email {email_id}: got tuple response with status {status_code}")
                    if status_code == 200:
                        is_success = True
                    else:
                        error_msg = response_obj.get_json().get('error', 'Unknown error')
                else:
                    # Just a response object (Flask defaults to 200)
                    response_json = response.get_json()
                    logger.info(f"Bulk release email {email_id}: got response {response_json}")
                    if response_json.get('success', False):
                        is_success = True
                    else:
                        error_msg = response_json.get('error', 'Unknown error')

                if is_success:
                    success_count += 1
                    logger.info(f"Bulk release email {email_id}: SUCCESS")
                else:
                    error_count += 1
                    errors.append(f"Email {email_id}: {error_msg}")
                    logger.warning(f"Bulk release email {email_id}: FAILED - {error_msg}")

            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")
                logger.error(f"Bulk release email {email_id}: EXCEPTION - {str(e)}")

        return jsonify({
            'success': True,
            'message': f'Released {success_count} emails, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Limit error messages
        })

    except Exception as e:
        logger.error(f"Error in bulk release: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/quarantine/bulk-delete', methods=['POST'])
@login_required
def api_quarantine_bulk_delete():
    """Bulk delete multiple emails"""
    conn = None
    cursor = None
    try:
        data = request.get_json()
        email_ids = data.get('email_ids', [])
        reason = data.get('reason', 'Bulk delete by user')

        if not email_ids:
            return jsonify({'success': False, 'error': 'No emails selected'}), 400

        if len(email_ids) > 100:
            return jsonify({'success': False, 'error': 'Maximum 100 emails at once'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        success_count = 0
        error_count = 0
        errors = []

        # Get user's managed aliases for client users
        user_aliases = []
        if not current_user.is_admin() and current_user.role == 'client':
            cursor_temp = conn.cursor(dictionary=True)
            cursor_temp.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (current_user.id,))
            user_aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
            cursor_temp.close()

        for email_id in email_ids:
            try:
                # Check if email exists - try email_analysis first (quarantine page shows this table)
                cursor.execute("SELECT * FROM email_analysis WHERE id = %s", (email_id,))
                email = cursor.fetchone()
                table_name = 'email_analysis'

                # If not in email_analysis, try email_quarantine
                if not email:
                    cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
                    email = cursor.fetchone()
                    table_name = 'email_quarantine'

                if not email:
                    error_count += 1
                    errors.append(f"Email {email_id}: Not found")
                    continue

                # Check permissions - verify user has access to this email
                if not current_user.is_admin():
                    if current_user.role == 'client':
                        # CLIENT role: Check if user is sender or recipient or alias recipient
                        sender = email.get('sender', '')
                        has_access = (current_user.email.lower() in sender.lower())

                        # Check if user or aliases are in recipients
                        if not has_access:
                            recipients_str = email.get('recipients', '[]')
                            try:
                                recipients = json.loads(recipients_str) if isinstance(recipients_str, str) else recipients_str
                                recipients_str = ' '.join(recipients).lower()
                            except:
                                recipients_str = str(recipients_str).lower()

                            # Check user email
                            has_access = current_user.email.lower() in recipients_str

                            # Check aliases
                            if not has_access:
                                for alias in user_aliases:
                                    if alias.lower() in recipients_str:
                                        has_access = True
                                        break

                        if not has_access:
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            continue
                    else:
                        # DOMAIN_ADMIN: Check domain access
                        user_domains = get_user_authorized_domains(current_user)
                        # Parse recipient_domains (stored as JSON array like ["domain.com"])
                        import json
                        try:
                            recipient_domains = json.loads(email.get('recipient_domains', '[]'))
                        except:
                            recipient_domains = []

                        # Check if user has access to any of the recipient domains
                        has_access = any(domain in user_domains for domain in recipient_domains)

                        if not has_access:
                            error_count += 1
                            errors.append(f"Email {email_id}: Access denied")
                            continue

                # Delete from appropriate table
                if table_name == 'email_analysis':
                    # For email_analysis, just delete the record
                    cursor.execute("DELETE FROM email_analysis WHERE id = %s", (email_id,))
                else:
                    # For email_quarantine, mark as deleted (soft delete)
                    update_query = """
                        UPDATE email_quarantine
                        SET quarantine_status = 'deleted',
                            user_classification = 'spam',
                            deleted_by = %s,
                            deleted_at = NOW()
                        WHERE id = %s
                    """
                    cursor.execute(update_query, (current_user.email, email_id))

                    # Log action for quarantine table
                    log_query = """
                        INSERT INTO quarantine_actions_log
                        (quarantine_id, action_type, performed_by, user_role, reason)
                        VALUES (%s, %s, %s, %s, %s)
                    """
                    cursor.execute(log_query, (email_id, 'marked_spam', current_user.email,
                                              'admin' if current_user.is_admin() else 'user', reason))

                success_count += 1

            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")

        # Commit all changes
        conn.commit()

        logger.info(f"Bulk delete: {success_count} success, {error_count} errors by {current_user.email}")

        return jsonify({
            'success': True,
            'message': f'Deleted {success_count} emails, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Limit error messages
        })

    except Exception as e:
        logger.error(f"Error in bulk delete: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# ============================================================================
# Email Status Route (EFA-like)
# ============================================================================

@app.route('/emails-status')
@login_required
def emails_status_view():
    """Email Status Page - list of all processed emails (like EFA status.php)"""
    try:
        # Get spam threshold from config (env or database)
        spam_threshold = get_spam_threshold()

        # Get filter parameters
        domain_filter = request.args.get('domain', '')
        status_filter = request.args.get('status', 'all')  # Default to 'all' emails
        search_query = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        per_page = 50

        # Get user's authorized domains
        user_domains = get_user_authorized_domains(current_user)

        # Build query
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Base query - query email_analysis table (all emails)
        query = """
            SELECT
                id, message_id, timestamp, sender,
                recipients, subject, spam_score, email_category,
                detected_language, sentiment_polarity,
                '' as sender_domain,
                'delivered' as quarantine_status,
                'N/A' as quarantine_reason,
                DATE_ADD(timestamp, INTERVAL 30 DAY) as quarantine_expires_at,
                has_attachments,
                0 as attachment_count,
                0 as virus_detected,
                CASE WHEN email_category = 'phishing' THEN 1 ELSE 0 END as phishing_detected,
                NULL as reviewed_by,
                NULL as reviewed_at,
                DATEDIFF(DATE_ADD(timestamp, INTERVAL 30 DAY), NOW()) as days_until_expiry,
                content_summary as text_content,
                '' as html_content,
                raw_email
            FROM email_analysis
            WHERE 1=1
        """
        params = []

        # Filter by spam score (status filter) - matches /emails page logic
        if status_filter == 'spam':
            # Spam = emails with spam_score >= threshold OR categorized as spam/phishing
            query += f" AND (spam_score >= {spam_threshold} OR email_category IN ('spam', 'phishing'))"
        elif status_filter == 'clean':
            # Clean = emails with spam_score < 30% of threshold and not categorized as spam
            query += f" AND spam_score < {spam_threshold * 0.3} AND (email_category NOT IN ('spam', 'phishing') OR email_category IS NULL)"
        elif status_filter == 'suspicious':
            # Suspicious = emails with spam_score between 60% and threshold (6.0-9.9 with default 10.0 threshold)
            query += f" AND spam_score >= {spam_threshold * 0.6} AND spam_score < {spam_threshold}"
        # 'all' = no additional filter

        # Filter by domain (user access control)
        if current_user.is_admin():
            # Admin can filter by specific domain if requested
            if domain_filter:
                query += " AND ea.recipients LIKE %s"
                params.append(f'%@{domain_filter}%')
        elif current_user.is_client():
            # Clients ONLY see emails where they are sender or recipient OR alias recipient
            # Get user's managed aliases
            conn_temp = get_db_connection()
            cursor_temp = conn_temp.cursor(dictionary=True)
            cursor_temp.execute("""
                SELECT managed_email FROM user_managed_aliases
                WHERE user_id = %s AND active = 1
            """, (current_user.id,))
            aliases = [row['managed_email'] for row in cursor_temp.fetchall()]
            cursor_temp.close()
            conn_temp.close()

            # Build condition: sender = user OR ea.recipients LIKE user email OR ea.recipients LIKE any alias
            user_conditions = []
            user_conditions.append("sender = %s")
            params.append(current_user.email)
            user_conditions.append("recipients LIKE %s")
            params.append(f'%{current_user.email}%')
            for alias in aliases:
                user_conditions.append("recipients LIKE %s")
                params.append(f'%{alias}%')

            query += f" AND ({' OR '.join(user_conditions)})"
        else:
            # Domain admins see their authorized domains
            if user_domains:
                # Check recipient domains
                domain_conditions = []
                for domain in user_domains:
                    domain_conditions.append("recipients LIKE %s")
                    params.append(f'%@{domain}%')
                query += f" AND ({' OR '.join(domain_conditions)})"
            else:
                # User has no domains - show nothing
                query += " AND 1=0"

        # Search filter
        if search_query:
            # Check if search is numeric (email ID)
            if search_query.isdigit():
                query += " AND id = %s"
                params.append(int(search_query))
            else:
                query += """ AND (
                    ea.sender LIKE %s OR
                    subject LIKE %s OR
                    ea.recipients LIKE %s OR
                    ea.message_id LIKE %s
                )"""
                search_param = f'%{search_query}%'
                params.extend([search_param, search_param, search_param, search_param])

        # Add deleted filter - show_deleted=1 means show ONLY deleted, otherwise exclude deleted
        # For email_quarantine: check quarantine_status = 'deleted'
        # For email_analysis: check is_deleted field
        logger.info(f"QUARANTINE FILTER: show_deleted='{show_deleted}'")
        if show_deleted == '1':
            # Show ONLY deleted items
            query += " AND ((source_table = 'quarantine' AND quarantine_status = 'deleted') OR (source_table = 'analysis' AND is_deleted = 1))"
            logger.info("QUARANTINE: Applying SHOW ONLY DELETED filter")
        else:
            # Hide deleted items
            query += " AND ((source_table = 'quarantine' AND quarantine_status != 'deleted') OR (source_table = 'analysis' AND is_deleted = 0))"
            logger.info("QUARANTINE: Applying HIDE DELETED filter")

        # Order by timestamp (newest first)
        query += " ORDER BY timestamp DESC"

        # Count total for pagination
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as filtered"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Add pagination
        offset = (page - 1) * per_page
        query += f" LIMIT {per_page} OFFSET {offset}"

        # Execute main query
        cursor.execute(query, params)
        quarantined_emails = cursor.fetchall()

        # Parse email bodies from raw_email for brief content preview
        from email import message_from_string
        for email in quarantined_emails:
            raw_email_for_digest_preview = get_raw_email_content(email)
            if raw_email_for_digest_preview:
                try:
                    msg = message_from_string(raw_email_for_digest_preview)
                    # Extract email body
                    email_text = ''
                    if msg.is_multipart():
                        # Get text/plain parts
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == 'text/plain':
                                try:
                                    email_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                    break
                                except:
                                    pass
                    else:
                        # Single part message
                        try:
                            email_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                        except:
                            pass

                    # Extract first 3-5 lines
                    if email_text:
                        lines = email_text.strip().split('\n')
                        preview_lines = []
                        char_count = 0
                        for line in lines[:10]:
                            line = line.strip()
                            if line:
                                preview_lines.append(line)
                                char_count += len(line)
                                if len(preview_lines) >= 3 or char_count >= 200:
                                    break
                        email['content_preview'] = ' '.join(preview_lines)[:250] + '...' if preview_lines else email.get('text_content', '')
                    else:
                        email['content_preview'] = email.get('text_content', '')
                except Exception as e:
                    logger.warning(f"Could not parse email body for preview: {e}")
                    email['content_preview'] = email.get('text_content', '')
            else:
                email['content_preview'] = email.get('text_content', '')

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page

        # Get statistics
        stats_query = """
            SELECT
                COUNT(DISTINCT ea.id) as total_held,
                0 as expiring_soon,
                AVG(ea.spam_score) as avg_spam_score,
                SUM(CASE WHEN ea.spam_score >= 50 OR ea.email_category IN ('spam', 'phishing', 'virus') THEN 1 ELSE 0 END) as security_threats
            FROM email_analysis ea
            WHERE 1=1
        """

        stats_params = []
        if not current_user.is_admin():
            if user_domains:
                domain_conditions = []
                for domain in user_domains:
                    domain_conditions.append("ea.recipients LIKE %s")
                    stats_params.append(f'%@{domain}%')
                stats_query += f" AND ({' OR '.join(domain_conditions)})"
            else:
                stats_query += " AND 1=0"

        cursor.execute(stats_query, stats_params)
        stats = cursor.fetchone()

        cursor.close()
        conn.close()

        return render_template('quarantine.html',
                             quarantined_emails=quarantined_emails,
                             stats=stats,
                             page=page,
                             total_pages=total_pages,
                             total_count=total_count,
                             status_filter=status_filter,
                             domain_filter=domain_filter,
                             search_query=search_query,
                             show_deleted=show_deleted,
                             user_domains=user_domains,
                             selected_domain=domain_filter or (user_domains[0] if user_domains else ''),
                             search_content=search_content)

    except Exception as e:
        logger.error(f"Error loading quarantine view: {e}")
        flash(f'Error loading quarantine: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


# ==================== VIP ALERT ROUTES ====================

@app.route('/vip-alerts')
@login_required
def vip_alerts_page():
    """VIP Alerts management page"""
    if not VIP_ALERTS_AVAILABLE or vip_alert_system is None:
        flash('VIP Alerts is a premium module. Contact support to enable this feature.', 'info')
        return redirect(url_for('dashboard'))

    try:
        user_email = current_user.email
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get user's VIP senders with statistics
        cursor.execute("""
            SELECT * FROM vip_sender_stats
            WHERE user_email = %s
            ORDER BY last_alert_at DESC
        """, (user_email,))
        vip_senders = cursor.fetchall()

        # Get current month usage
        current_month = datetime.now().strftime('%Y-%m')
        current_month_usage = vip_alert_system.get_monthly_billing(
            client_domain_id=get_client_domain_id(user_email),
            user_email=user_email,
            billing_cycle=current_month
        )

        cursor.close()
        conn.close()

        # Check if ClickSend is configured
        clicksend_configured = bool(os.getenv('CLICKSEND_USERNAME')) and bool(os.getenv('CLICKSEND_API_KEY'))

        return render_template('vip_alerts.html',
                             vip_senders=vip_senders,
                             current_month_usage=current_month_usage,
                             clicksend_configured=clicksend_configured)

    except Exception as e:
        logger.error(f"Error loading VIP alerts page: {e}", exc_info=True)
        flash('Error loading VIP alerts', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/vip-alerts/add', methods=['POST'])
@login_required
def vip_alerts_add():
    """Add new VIP sender"""
    try:
        user_email = current_user.email
        vip_sender_email = request.form.get('vip_sender_email')
        vip_sender_name = request.form.get('vip_sender_name')
        mobile_number = request.form.get('mobile_number')
        alert_hours_start = request.form.get('alert_hours_start', '08:00')
        alert_hours_end = request.form.get('alert_hours_end', '22:00')

        # Validate inputs
        if not vip_sender_email or not mobile_number:
            flash('Email and mobile number are required', 'danger')
            return redirect(url_for('vip_alerts_page'))

        # Validate phone number format (server-side)
        try:
            mobile_number = validate_e164_phone(mobile_number)
        except ValueError as ve:
            flash(str(ve), 'danger')
            return redirect(url_for('vip_alerts_page'))

        client_domain_id = get_client_domain_id(user_email)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO vip_senders (
                user_email, client_domain_id, vip_sender_email, vip_sender_name,
                mobile_number, alert_hours_start, alert_hours_end, alert_enabled, created_by
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, %s)
        """, (user_email, client_domain_id, vip_sender_email, vip_sender_name,
              mobile_number, alert_hours_start, alert_hours_end, user_email))

        conn.commit()
        cursor.close()
        conn.close()

        flash(f'VIP alert added for {vip_sender_email}', 'success')
        return redirect(url_for('vip_alerts_page'))

    except Exception as e:
        logger.error(f"Error adding VIP sender: {e}", exc_info=True)
        flash('Error adding VIP sender', 'danger')
        return redirect(url_for('vip_alerts_page'))


@app.route('/vip-alerts/toggle/<int:vip_id>', methods=['POST'])
@login_required
def vip_alerts_toggle(vip_id):
    """Toggle VIP alert on/off"""
    try:
        user_email = current_user.email
        data = request.get_json()
        enabled = data.get('enabled', False)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership
        cursor.execute("""
            SELECT id FROM vip_senders
            WHERE id = %s AND user_email = %s
        """, (vip_id, user_email))

        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'VIP sender not found'}), 404

        # Update status
        cursor.execute("""
            UPDATE vip_senders
            SET alert_enabled = %s
            WHERE id = %s
        """, (enabled, vip_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Error toggling VIP alert: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/vip-alerts/get/<int:vip_id>')
@login_required
def vip_alerts_get(vip_id):
    """Get VIP sender details for editing"""
    try:
        user_email = current_user.email
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, vip_sender_email, vip_sender_name, mobile_number,
                   alert_hours_start, alert_hours_end
            FROM vip_senders
            WHERE id = %s AND user_email = %s
        """, (vip_id, user_email))

        vip = cursor.fetchone()
        cursor.close()
        conn.close()

        if not vip:
            return jsonify({'success': False, 'message': 'VIP sender not found'}), 404

        # Convert time objects to HH:MM string format for JSON
        from datetime import timedelta

        # Handle alert_hours_start
        if vip['alert_hours_start'] is not None:
            if isinstance(vip['alert_hours_start'], timedelta):
                total_seconds = int(vip['alert_hours_start'].total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                vip['alert_hours_start'] = f"{hours:02d}:{minutes:02d}"
            else:
                vip['alert_hours_start'] = str(vip['alert_hours_start'])[:5]
        else:
            vip['alert_hours_start'] = '08:00'

        # Handle alert_hours_end
        if vip['alert_hours_end'] is not None:
            if isinstance(vip['alert_hours_end'], timedelta):
                total_seconds = int(vip['alert_hours_end'].total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                vip['alert_hours_end'] = f"{hours:02d}:{minutes:02d}"
            else:
                vip['alert_hours_end'] = str(vip['alert_hours_end'])[:5]
        else:
            vip['alert_hours_end'] = '22:00'

        return jsonify({'success': True, 'vip': vip})

    except Exception as e:
        logger.error(f"Error getting VIP sender: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/vip-alerts/edit/<int:vip_id>', methods=['POST'])
@login_required
def vip_alerts_edit(vip_id):
    """Edit VIP sender"""
    try:
        user_email = current_user.email
        vip_sender_name = request.form.get('vip_sender_name')
        mobile_number = request.form.get('mobile_number')
        alert_hours_start = request.form.get('alert_hours_start') or '08:00'
        alert_hours_end = request.form.get('alert_hours_end') or '22:00'

        # Validate phone number format (server-side)
        try:
            mobile_number = validate_e164_phone(mobile_number)
        except ValueError as ve:
            flash(str(ve), 'danger')
            return redirect(url_for('vip_alerts_page'))

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership
        cursor.execute("""
            SELECT id FROM vip_senders
            WHERE id = %s AND user_email = %s
        """, (vip_id, user_email))

        if not cursor.fetchone():
            flash('VIP sender not found', 'danger')
            return redirect(url_for('vip_alerts_page'))

        # Update
        cursor.execute("""
            UPDATE vip_senders
            SET vip_sender_name = %s, mobile_number = %s,
                alert_hours_start = %s, alert_hours_end = %s
            WHERE id = %s
        """, (vip_sender_name, mobile_number, alert_hours_start, alert_hours_end, vip_id))

        conn.commit()
        cursor.close()
        conn.close()

        flash('VIP sender updated successfully', 'success')
        return redirect(url_for('vip_alerts_page'))

    except Exception as e:
        logger.error(f"Error editing VIP sender: {e}", exc_info=True)
        flash('Error updating VIP sender', 'danger')
        return redirect(url_for('vip_alerts_page'))


@app.route('/vip-alerts/delete/<int:vip_id>', methods=['POST'])
@login_required
def vip_alerts_delete(vip_id):
    """Delete VIP sender"""
    try:
        user_email = current_user.email
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify ownership and delete
        cursor.execute("""
            DELETE FROM vip_senders
            WHERE id = %s AND user_email = %s
        """, (vip_id, user_email))

        affected_rows = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()

        if affected_rows == 0:
            return jsonify({'success': False, 'message': 'VIP sender not found'}), 404

        return jsonify({'success': True})

    except Exception as e:
        logger.error(f"Error deleting VIP sender: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/vip-billing')
@login_required
def vip_billing():
    """VIP Alerts billing dashboard"""
    if not VIP_ALERTS_AVAILABLE or vip_alert_system is None:
        flash('VIP Alerts is a premium module. Contact support to enable this feature.', 'info')
        return redirect(url_for('dashboard'))

    try:
        user_email = current_user.email
        client_domain_id = get_client_domain_id(user_email)

        # Get current month usage
        current_month = datetime.now().strftime('%Y-%m')
        current_usage = vip_alert_system.get_monthly_billing(
            client_domain_id=client_domain_id,
            user_email=user_email,
            billing_cycle=current_month
        )

        # Get breakdown by VIP sender
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                vs.vip_sender_email,
                vs.vip_sender_name,
                COUNT(*) as total_alerts,
                SUM(CASE WHEN sal.delivery_status = 'delivered' THEN 1 ELSE 0 END) as delivered_count,
                SUM(CASE WHEN sal.delivery_status = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN sal.delivery_status = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited_count,
                SUM(sal.billable_amount_usd) as total_billed
            FROM sms_alert_log sal
            JOIN vip_senders vs ON sal.vip_sender_id = vs.id
            WHERE sal.recipient_email = %s
            AND sal.billing_cycle = %s
            GROUP BY vs.vip_sender_email, vs.vip_sender_name
            ORDER BY total_billed DESC
        """, (user_email, current_month))
        vip_breakdown = cursor.fetchall()

        # Get recent alerts
        cursor.execute("""
            SELECT * FROM sms_alert_log
            WHERE recipient_email = %s
            ORDER BY sent_at DESC
            LIMIT 50
        """, (user_email,))
        recent_alerts = cursor.fetchall()

        # Get historical usage (last 6 months)
        cursor.execute("""
            SELECT
                billing_cycle,
                COUNT(*) as alert_count,
                SUM(billable_amount_usd) as total_billed
            FROM sms_alert_log
            WHERE recipient_email = %s
            AND sent_at >= DATE_SUB(NOW(), INTERVAL 6 MONTH)
            GROUP BY billing_cycle
            ORDER BY billing_cycle ASC
        """, (user_email,))
        historical_data = cursor.fetchall()

        cursor.close()
        conn.close()

        # Prepare chart data
        historical_labels = [row['billing_cycle'] for row in historical_data]
        historical_counts = [row['alert_count'] for row in historical_data]
        historical_billing = [float(row['total_billed']) for row in historical_data]

        return render_template('vip_billing.html',
                             current_month=current_month,
                             current_usage=current_usage,
                             vip_breakdown=vip_breakdown,
                             recent_alerts=recent_alerts,
                             historical_usage=historical_data,
                             historical_labels=historical_labels,
                             historical_counts=historical_counts,
                             historical_billing=historical_billing)

    except Exception as e:
        logger.error(f"Error loading VIP billing: {e}", exc_info=True)
        flash('Error loading billing information', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/vip-billing/export')
@login_required
def vip_billing_export():
    """Export billing data as CSV"""
    try:
        user_email = current_user.email
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                sent_at, sender_email, email_subject, mobile_number,
                delivery_status, billable_amount_usd, billing_cycle
            FROM sms_alert_log
            WHERE recipient_email = %s
            ORDER BY sent_at DESC
        """, (user_email,))
        alerts = cursor.fetchall()

        cursor.close()
        conn.close()

        # Create CSV using csv.writer for proper escaping
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)

        # Write header
        writer.writerow(['Date', 'VIP Sender', 'Subject', 'Mobile', 'Status', 'Charge', 'Billing Cycle'])

        # Write data rows
        for alert in alerts:
            writer.writerow([
                str(alert['sent_at']),
                alert['sender_email'],
                alert['email_subject'],
                alert['mobile_number'],
                alert['delivery_status'],
                f"${alert['billable_amount_usd']:.2f}",
                alert['billing_cycle']
            ])

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'vip_alerts_billing_{datetime.now().strftime("%Y%m%d")}.csv'
        )

    except Exception as e:
        logger.error(f"Error exporting billing data: {e}", exc_info=True)
        flash('Error exporting data', 'danger')
        return redirect(url_for('vip_billing'))


@app.route('/admin/vip-billing')
@login_required
def admin_vip_billing():
    """Superadmin comprehensive VIP billing overview"""
    try:
        # Check superadmin access
        if not current_user.is_superadmin():
            flash('Access denied. Superadmin privileges required.', 'danger')
            return redirect(url_for('dashboard'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current month
        current_month = datetime.now().strftime('%Y-%m')

        # Allow filtering by billing cycle
        billing_cycle = request.args.get('billing_cycle', current_month)

        # Overall platform statistics
        cursor.execute("""
            SELECT
                COUNT(DISTINCT recipient_email) as total_users,
                COUNT(DISTINCT CASE WHEN billing_cycle = %s THEN recipient_email END) as active_users_this_month,
                COUNT(*) as total_alerts_all_time,
                COUNT(CASE WHEN billing_cycle = %s THEN 1 END) as alerts_this_month,
                SUM(CASE WHEN billing_cycle = %s AND delivery_status IN ('sent', 'delivered') THEN billable_amount_usd ELSE 0 END) as revenue_this_month,
                SUM(CASE WHEN billing_cycle = %s AND delivery_status IN ('sent', 'delivered') THEN cost_usd ELSE 0 END) as cost_this_month,
                COUNT(CASE WHEN billing_cycle = %s AND delivery_status = 'delivered' THEN 1 END) as delivered_this_month,
                COUNT(CASE WHEN billing_cycle = %s AND delivery_status = 'failed' THEN 1 END) as failed_this_month,
                COUNT(CASE WHEN billing_cycle = %s AND delivery_status = 'rate_limited' THEN 1 END) as rate_limited_this_month
            FROM sms_alert_log
        """, (billing_cycle, billing_cycle, billing_cycle, billing_cycle, billing_cycle, billing_cycle, billing_cycle))
        platform_stats = cursor.fetchone()

        # Calculate profit margin
        revenue = float(platform_stats['revenue_this_month'] or 0)
        cost = float(platform_stats['cost_this_month'] or 0)
        profit = revenue - cost
        profit_margin = (profit / revenue * 100) if revenue > 0 else 0

        platform_stats['profit_this_month'] = profit
        platform_stats['profit_margin_pct'] = profit_margin

        # Usage by user (for current billing cycle)
        cursor.execute("""
            SELECT
                sal.recipient_email,
                u.first_name,
                u.last_name,
                u.company_name,
                u.domain,
                COUNT(*) as total_alerts,
                COUNT(CASE WHEN sal.delivery_status IN ('sent', 'delivered') THEN 1 END) as billable_alerts,
                COUNT(CASE WHEN sal.delivery_status = 'delivered' THEN 1 END) as delivered_alerts,
                COUNT(CASE WHEN sal.delivery_status = 'failed' THEN 1 END) as failed_alerts,
                COUNT(CASE WHEN sal.delivery_status = 'rate_limited' THEN 1 END) as rate_limited_alerts,
                SUM(sal.cost_usd) as total_cost,
                SUM(sal.billable_amount_usd) as total_revenue,
                MAX(sal.sent_at) as last_alert,
                COUNT(DISTINCT sal.vip_sender_id) as vip_count
            FROM sms_alert_log sal
            LEFT JOIN users u ON sal.recipient_email = u.email
            WHERE sal.billing_cycle = %s
            GROUP BY sal.recipient_email, u.first_name, u.last_name, u.company_name, u.domain
            ORDER BY total_revenue DESC
        """, (billing_cycle,))
        user_billing = cursor.fetchall()

        # Calculate per-user profit
        for user in user_billing:
            user_revenue = float(user['total_revenue'] or 0)
            user_cost = float(user['total_cost'] or 0)
            user['profit'] = user_revenue - user_cost

        # Usage by domain
        cursor.execute("""
            SELECT
                cd.domain,
                cd.id as domain_id,
                COUNT(DISTINCT sal.recipient_email) as user_count,
                COUNT(*) as total_alerts,
                COUNT(CASE WHEN sal.delivery_status IN ('sent', 'delivered') THEN 1 END) as billable_alerts,
                SUM(sal.cost_usd) as total_cost,
                SUM(sal.billable_amount_usd) as total_revenue
            FROM sms_alert_log sal
            JOIN client_domains cd ON sal.client_domain_id = cd.id
            WHERE sal.billing_cycle = %s
            GROUP BY cd.domain, cd.id
            ORDER BY total_revenue DESC
        """, (billing_cycle,))
        domain_billing = cursor.fetchall()

        # Calculate per-domain profit
        for domain in domain_billing:
            domain_revenue = float(domain['total_revenue'] or 0)
            domain_cost = float(domain['total_cost'] or 0)
            domain['profit'] = domain_revenue - domain_cost

        # Monthly trend (last 12 months)
        cursor.execute("""
            SELECT
                billing_cycle,
                COUNT(DISTINCT recipient_email) as active_users,
                COUNT(*) as total_alerts,
                COUNT(CASE WHEN delivery_status IN ('sent', 'delivered') THEN 1 END) as billable_alerts,
                SUM(cost_usd) as total_cost,
                SUM(billable_amount_usd) as total_revenue
            FROM sms_alert_log
            WHERE sent_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
            GROUP BY billing_cycle
            ORDER BY billing_cycle ASC
        """)
        monthly_trend = cursor.fetchall()

        # Calculate profit for each month
        for month in monthly_trend:
            month_revenue = float(month['total_revenue'] or 0)
            month_cost = float(month['total_cost'] or 0)
            month['profit'] = month_revenue - month_cost

        # Unbilled alerts (for invoicing)
        cursor.execute("""
            SELECT
                sal.recipient_email,
                u.first_name,
                u.last_name,
                u.company_name,
                COUNT(*) as unbilled_alert_count,
                SUM(sal.billable_amount_usd) as unbilled_amount
            FROM sms_alert_log sal
            LEFT JOIN users u ON sal.recipient_email = u.email
            WHERE sal.billing_status = 'unbilled'
            AND sal.delivery_status IN ('sent', 'delivered')
            AND sal.billing_cycle = %s
            GROUP BY sal.recipient_email, u.first_name, u.last_name, u.company_name
            HAVING unbilled_amount > 0
            ORDER BY unbilled_amount DESC
        """, (billing_cycle,))
        unbilled_users = cursor.fetchall()

        # Get available billing cycles for filtering
        cursor.execute("""
            SELECT DISTINCT billing_cycle
            FROM sms_alert_log
            WHERE billing_cycle IS NOT NULL
            ORDER BY billing_cycle DESC
            LIMIT 24
        """)
        available_cycles = [row['billing_cycle'] for row in cursor.fetchall()]

        # Top VIP senders (most active)
        cursor.execute("""
            SELECT
                vs.vip_sender_email,
                vs.vip_sender_name,
                COUNT(DISTINCT vs.user_email) as user_count,
                COUNT(sal.id) as alert_count,
                SUM(sal.billable_amount_usd) as total_revenue
            FROM vip_senders vs
            LEFT JOIN sms_alert_log sal ON vs.id = sal.vip_sender_id AND sal.billing_cycle = %s
            WHERE vs.alert_enabled = TRUE
            GROUP BY vs.vip_sender_email, vs.vip_sender_name
            HAVING alert_count > 0
            ORDER BY alert_count DESC
            LIMIT 20
        """, (billing_cycle,))
        top_vip_senders = cursor.fetchall()

        cursor.close()
        conn.close()

        # Prepare chart data for monthly trend
        trend_labels = [row['billing_cycle'] for row in monthly_trend]
        trend_revenue = [float(row['total_revenue'] or 0) for row in monthly_trend]
        trend_cost = [float(row['total_cost'] or 0) for row in monthly_trend]
        trend_profit = [float(row['profit'] or 0) for row in monthly_trend]
        trend_users = [row['active_users'] for row in monthly_trend]

        return render_template('admin_vip_billing.html',
                             billing_cycle=billing_cycle,
                             current_month=current_month,
                             platform_stats=platform_stats,
                             user_billing=user_billing,
                             domain_billing=domain_billing,
                             monthly_trend=monthly_trend,
                             unbilled_users=unbilled_users,
                             available_cycles=available_cycles,
                             top_vip_senders=top_vip_senders,
                             trend_labels=trend_labels,
                             trend_revenue=trend_revenue,
                             trend_cost=trend_cost,
                             trend_profit=trend_profit,
                             trend_users=trend_users)

    except Exception as e:
        logger.error(f"Error loading admin VIP billing: {e}", exc_info=True)
        flash('Error loading billing information', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/admin/vip-billing/export')
@login_required
def admin_vip_billing_export():
    """Export comprehensive billing data as CSV (superadmin only)"""
    try:
        # Check superadmin access
        if not current_user.is_superadmin():
            flash('Access denied. Superadmin privileges required.', 'danger')
            return redirect(url_for('dashboard'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        billing_cycle = request.args.get('billing_cycle', datetime.now().strftime('%Y-%m'))
        export_type = request.args.get('type', 'detailed')  # 'detailed' or 'summary'

        if export_type == 'summary':
            # Summary by user
            cursor.execute("""
                SELECT
                    sal.recipient_email,
                    u.first_name,
                    u.last_name,
                    u.company_name,
                    u.domain,
                    COUNT(*) as total_alerts,
                    COUNT(CASE WHEN sal.delivery_status IN ('sent', 'delivered') THEN 1 END) as billable_alerts,
                    SUM(sal.billable_amount_usd) as total_charges,
                    sal.billing_cycle
                FROM sms_alert_log sal
                LEFT JOIN users u ON sal.recipient_email = u.email
                WHERE sal.billing_cycle = %s
                GROUP BY sal.recipient_email, u.first_name, u.last_name, u.company_name, u.domain, sal.billing_cycle
                ORDER BY total_charges DESC
            """, (billing_cycle,))
            data = cursor.fetchall()

            output = io.StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_ALL)

            writer.writerow(['Email', 'First Name', 'Last Name', 'Company', 'Domain',
                           'Total Alerts', 'Billable Alerts', 'Total Charges', 'Billing Cycle'])

            for row in data:
                writer.writerow([
                    row['recipient_email'],
                    row['first_name'] or '',
                    row['last_name'] or '',
                    row['company_name'] or '',
                    row['domain'] or '',
                    row['total_alerts'],
                    row['billable_alerts'],
                    f"${row['total_charges']:.2f}",
                    row['billing_cycle']
                ])

            filename = f'vip_billing_summary_{billing_cycle}.csv'

        else:
            # Detailed transaction log
            cursor.execute("""
                SELECT
                    sal.sent_at,
                    sal.recipient_email,
                    u.first_name,
                    u.last_name,
                    u.company_name,
                    u.domain,
                    sal.sender_email,
                    sal.email_subject,
                    sal.mobile_number,
                    sal.delivery_status,
                    sal.cost_usd,
                    sal.billable_amount_usd,
                    sal.billing_status,
                    sal.billing_cycle,
                    sal.clicksend_message_id
                FROM sms_alert_log sal
                LEFT JOIN users u ON sal.recipient_email = u.email
                WHERE sal.billing_cycle = %s
                ORDER BY sal.sent_at DESC
            """, (billing_cycle,))
            data = cursor.fetchall()

            output = io.StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_ALL)

            writer.writerow(['Date', 'User Email', 'First Name', 'Last Name', 'Company', 'Domain',
                           'VIP Sender', 'Subject', 'Mobile', 'Status', 'Cost', 'Charge',
                           'Billing Status', 'Cycle', 'SMS ID'])

            for row in data:
                writer.writerow([
                    str(row['sent_at']),
                    row['recipient_email'],
                    row['first_name'] or '',
                    row['last_name'] or '',
                    row['company_name'] or '',
                    row['domain'] or '',
                    row['sender_email'],
                    row['email_subject'],
                    row['mobile_number'],
                    row['delivery_status'],
                    f"${row['cost_usd']:.4f}",
                    f"${row['billable_amount_usd']:.2f}",
                    row['billing_status'],
                    row['billing_cycle'],
                    row['clicksend_message_id'] or ''
                ])

            filename = f'vip_billing_detailed_{billing_cycle}.csv'

        cursor.close()
        conn.close()

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        logger.error(f"Error exporting admin billing data: {e}", exc_info=True)
        flash('Error exporting data', 'danger')
        return redirect(url_for('admin_vip_billing'))


@app.route('/admin/vip-billing/mark-billed', methods=['POST'])
@login_required
def admin_vip_billing_mark_billed():
    """Mark alerts as billed (superadmin only)"""
    try:
        # Check superadmin access
        if not current_user.is_superadmin():
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        billing_cycle = request.form.get('billing_cycle')
        user_email = request.form.get('user_email')  # Optional: specific user or all

        conn = get_db_connection()
        cursor = conn.cursor()

        if user_email:
            # Mark specific user as billed
            cursor.execute("""
                UPDATE sms_alert_log
                SET billing_status = 'billed'
                WHERE billing_cycle = %s
                AND recipient_email = %s
                AND billing_status = 'unbilled'
                AND delivery_status IN ('sent', 'delivered')
            """, (billing_cycle, user_email))
            message = f"Marked {cursor.rowcount} alerts as billed for {user_email}"
        else:
            # Mark entire billing cycle as billed
            cursor.execute("""
                UPDATE sms_alert_log
                SET billing_status = 'billed'
                WHERE billing_cycle = %s
                AND billing_status = 'unbilled'
                AND delivery_status IN ('sent', 'delivered')
            """, (billing_cycle,))
            message = f"Marked {cursor.rowcount} alerts as billed for {billing_cycle}"

        conn.commit()
        cursor.close()
        conn.close()

        flash(message, 'success')
        return jsonify({'success': True, 'message': message})

    except Exception as e:
        logger.error(f"Error marking alerts as billed: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


# Helper function to validate phone number
def validate_e164_phone(mobile_number):
    """
    Validate phone number in E.164 format (+1XXXXXXXXXX for US)

    Args:
        mobile_number: Phone number string to validate

    Returns:
        str: Validated phone number

    Raises:
        ValueError: If phone number format is invalid
    """
    if not mobile_number:
        raise ValueError('Phone number is required')

    # E.164 format for US: +1 followed by 10 digits
    pattern = r'^\+1[0-9]{10}$'
    if not re.match(pattern, mobile_number):
        raise ValueError('Invalid phone number format. Must be +1 followed by 10 digits (e.g., +17025551234)')

    return mobile_number


# Helper function to get client domain ID
def get_client_domain_id(user_email):
    """Get client domain ID from user email"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Extract domain from email
        domain = user_email.split('@')[1] if '@' in user_email else None
        if not domain:
            return 1  # Default domain

        cursor.execute("""
            SELECT id FROM client_domains
            WHERE domain = %s
        """, (domain,))

        result = cursor.fetchone()
        cursor.close()
        conn.close()

        return result['id'] if result else 1

    except Exception as e:
        logger.error(f"Error getting client domain ID: {e}")
        return 1  # Default fallback


# ============================================================================
# QUARANTINE DIGEST NOTIFICATION ROUTES
# ============================================================================

@app.route('/settings/quarantine-notifications', methods=['GET'])
@login_required
def quarantine_notifications_settings():
    """Settings page for quarantine email digests"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get or create user preferences
        cursor.execute("""
            SELECT * FROM user_quarantine_notifications
            WHERE user_id = %s
        """, (current_user.id,))

        preferences = cursor.fetchone()

        # If no preferences exist, create default
        if not preferences:
            cursor.execute("""
                INSERT INTO user_quarantine_notifications
                (user_id, email, domain, enabled, frequency, delivery_time, min_spam_score, max_emails)
                VALUES (%s, %s, %s, 0, 'daily', '08:00:00', 5.0, 50)
            """, (current_user.id, current_user.email, current_user.domain))
            conn.commit()

            # Fetch the newly created preferences
            cursor.execute("""
                SELECT * FROM user_quarantine_notifications
                WHERE user_id = %s
            """, (current_user.id,))
            preferences = cursor.fetchone()

        # Get recent digest log
        cursor.execute("""
            SELECT * FROM quarantine_digest_log
            WHERE user_id = %s
            ORDER BY sent_at DESC
            LIMIT 10
        """, (current_user.id,))
        recent_digests = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template('quarantine_notifications.html',
                             preferences=preferences,
                             recent_digests=recent_digests)

    except Exception as e:
        logger.error(f"Error loading quarantine notification settings: {e}")
        flash('Error loading notification settings', 'danger')
        return redirect(url_for('index'))


@app.route('/api/quarantine-notifications/save', methods=['POST'])
@login_required
def save_quarantine_notifications():
    """Save quarantine notification preferences"""
    try:
        data = request.get_json()

        enabled = data.get('enabled', False)
        frequency = data.get('frequency', 'daily')
        delivery_time = data.get('delivery_time', '08:00:00')
        delivery_day = data.get('delivery_day', 1)
        min_spam_score = float(data.get('min_spam_score', 5.0))
        max_emails = int(data.get('max_emails', 50))
        include_released = data.get('include_released', False)

        # Validate inputs
        if frequency not in ['daily', 'weekly', 'realtime']:
            return jsonify({'success': False, 'message': 'Invalid frequency'}), 400

        if min_spam_score < 0 or min_spam_score > 100:
            return jsonify({'success': False, 'message': 'Invalid spam score'}), 400

        if max_emails < 1 or max_emails > 100:
            return jsonify({'success': False, 'message': 'Invalid max emails'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update or insert preferences
        cursor.execute("""
            INSERT INTO user_quarantine_notifications
            (user_id, email, domain, enabled, frequency, delivery_time, delivery_day,
             min_spam_score, max_emails, include_released)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                enabled = VALUES(enabled),
                frequency = VALUES(frequency),
                delivery_time = VALUES(delivery_time),
                delivery_day = VALUES(delivery_day),
                min_spam_score = VALUES(min_spam_score),
                max_emails = VALUES(max_emails),
                include_released = VALUES(include_released)
        """, (current_user.id, current_user.email, current_user.domain,
              enabled, frequency, delivery_time, delivery_day,
              min_spam_score, max_emails, include_released))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Updated quarantine notification preferences for user {current_user.email}")
        return jsonify({'success': True, 'message': 'Preferences saved successfully'})

    except Exception as e:
        logger.error(f"Error saving quarantine notification preferences: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/quarantine-notifications/send-test', methods=['POST'])
@login_required
def send_test_digest():
    """Send a test digest immediately to the current user"""
    try:
        import sys
        sys.path.insert(0, '/opt/spacyserver/scripts')

        # Import the digest generator
        from quarantine_digest import QuarantineDigestGenerator

        # Get user preferences
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT uqn.*, u.first_name, u.last_name, u.company_name, u.authorized_domains, u.role
            FROM user_quarantine_notifications uqn
            JOIN users u ON uqn.user_id = u.id
            WHERE uqn.user_id = %s
        """, (current_user.id,))

        user_prefs = cursor.fetchone()

        if not user_prefs:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'message': 'No notification preferences found. Please save your preferences first.'}), 400

        # Create generator
        generator = QuarantineDigestGenerator()

        # Get quarantined emails for this user
        emails = generator.get_quarantine_emails_for_user(user_prefs)

        # Generate HTML digest
        html = generator.generate_digest_html(user_prefs, emails, user_prefs)

        # Send email
        success, error_msg = generator.send_digest_email(user_prefs, html)

        if success:
            # Log the test digest
            generator.log_digest_sent(user_prefs, len(emails), 'sent', None)
            logger.info(f"Test digest sent to {current_user.email} with {len(emails)} emails")
            return jsonify({
                'success': True,
                'message': f'Test digest sent with {len(emails)} quarantined email(s)'
            })
        else:
            logger.error(f"Test digest failed for {current_user.email}: {error_msg}")
            return jsonify({'success': False, 'message': f'Failed to send: {error_msg}'}), 500

        cursor.close()
        conn.close()
        generator.close()

    except Exception as e:
        logger.error(f"Error sending test digest: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/digest/action/<token>', methods=['GET'])
def digest_action(token):
    """Handle action from digest email (release, whitelist, etc.)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Validate token
        cursor.execute("""
            SELECT * FROM quarantine_digest_tokens
            WHERE token = %s
        """, (token,))

        token_data = cursor.fetchone()

        if not token_data:
            return render_template('digest_action_result.html',
                                 success=False,
                                 message='Invalid or expired token'), 404

        # SECURITY: Use constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(token, token_data['token']):
            logger.warning(f"Token mismatch detected (possible timing attack)")
            return render_template('digest_action_result.html',
                                 success=False,
                                 message='Invalid or expired token'), 404

        # Check if token is expired
        if datetime.now() > token_data['expires_at']:
            return render_template('digest_action_result.html',
                                 success=False,
                                 message='This link has expired (tokens valid for 72 hours)')

        # Check if token already used
        if token_data['used_at']:
            return render_template('digest_action_result.html',
                                 success=False,
                                 message='This link has already been used')

        # Get email details
        cursor.execute("""
            SELECT * FROM email_analysis WHERE id = %s
        """, (token_data['email_id'],))

        email = cursor.fetchone()

        if not email:
            return render_template('digest_action_result.html',
                                 success=False,
                                 message='Email not found')

        # Perform the action
        action = token_data['action']
        user_id = token_data['user_id']

        if action == 'release':
            # Release the email - update disposition and relay via SMTP
            try:
                # Update disposition to released
                cursor.execute("""
                    UPDATE email_analysis
                    SET disposition = 'released'
                    WHERE id = %s
                """, (email['id'],))
                conn.commit()

                # Get raw_email for SMTP relay (from email_analysis table)
                cursor.execute("""
                    SELECT raw_email, raw_email_path FROM email_analysis WHERE id = %s
                """, (email['id'],))
                raw_email_row = cursor.fetchone()

                raw_email_content = get_raw_email_content(raw_email_row) if raw_email_row else None
                if raw_email_content:
                    # Parse recipients
                    recipients_str = email.get('recipients', '')
                    if isinstance(recipients_str, str):
                        try:
                            recipients = json.loads(recipients_str)
                        except:
                            recipients = [r.strip() for r in recipients_str.split(',') if r.strip()]
                    else:
                        recipients = recipients_str if recipients_str else []

                    # Get relay host for domain
                    recipient_domain = None
                    if recipients:
                        first_recipient = recipients[0]
                        if '@' in first_recipient:
                            recipient_domain = first_recipient.split('@')[1].lower()

                    relay_host = None
                    relay_port = 25

                    if recipient_domain:
                        cursor.execute("""
                            SELECT relay_host, relay_port
                            FROM client_domains
                            WHERE domain = %s AND active = 1
                        """, (recipient_domain,))
                        domain_config = cursor.fetchone()

                        if domain_config and domain_config.get('relay_host'):
                            relay_host = domain_config['relay_host']
                            relay_port = domain_config.get('relay_port', 25)

                    # Fallback to config file
                    if not relay_host:
                        with open('/opt/spacyserver/config/quarantine_config.json', 'r') as f:
                            config = json.load(f)
                        release_config = config.get('release_destination', {})
                        dest = release_config.get('mailguard', {})
                        relay_host = dest.get('host', 'localhost')
                        relay_port = dest.get('port', 25)

                    # SECURITY: Sanitize sender and recipients to prevent SMTP header injection
                    try:
                        sanitized_sender = sanitize_email_address(email['sender'])
                        sanitized_recipients = [sanitize_email_address(r) for r in recipients]
                    except ValueError as ve:
                        logger.error(f"Email address validation failed for digest release {email['id']}: {ve}")
                        return render_template('digest_action_result.html',
                                             success=False,
                                             message=f'Invalid email address format'), 400

                    # Relay via SMTP
                    with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                        smtp.sendmail(sanitized_sender, sanitized_recipients, raw_email_content)

                    logger.info(f"Digest release: Email {email['id']} relayed to {relay_host}:{relay_port}")
                    message = f"Email from {email['sender']} has been released and delivered"
                    success = True
                else:
                    logger.warning(f"No raw_email found for email ID {email['id']}")
                    message = f"Email from {email['sender']} marked as released (raw email not available for delivery)"
                    success = True

                # Mark token as used
                cursor.execute("""
                    UPDATE quarantine_digest_tokens
                    SET used_at = NOW(), ip_address = %s, user_agent = %s
                    WHERE id = %s
                """, (request.remote_addr, request.headers.get('User-Agent', ''), token_data['id']))
                conn.commit()

            except Exception as e:
                logger.error(f"Error releasing email from digest: {e}")
                message = f"Error releasing email: {str(e)}"
                success = False

        elif action == 'whitelist':
            # Whitelist the sender
            sender = email['sender']
            cursor.execute("""
                INSERT INTO trusted_senders (email, domain, added_by, added_at)
                VALUES (%s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE updated_at = NOW()
            """, (sender, email.get('domain', 'unknown'), user_id))

            # Mark token as used
            cursor.execute("""
                UPDATE quarantine_digest_tokens
                SET used_at = NOW(), ip_address = %s, user_agent = %s
                WHERE id = %s
            """, (request.remote_addr, request.headers.get('User-Agent', ''), token_data['id']))
            conn.commit()

            message = f"Sender {sender} has been added to your whitelist"
            success = True

        else:
            message = f"Unknown action: {action}"
            success = False

        # Update digest log with action taken
        cursor.execute("""
            UPDATE quarantine_digest_log
            SET actions_taken = actions_taken + 1
            WHERE user_id = %s
            ORDER BY sent_at DESC
            LIMIT 1
        """, (user_id,))
        conn.commit()

        cursor.close()
        conn.close()

        return render_template('digest_action_result.html',
                             success=success,
                             message=message,
                             email=email,
                             action=action)

    except Exception as e:
        logger.error(f"Error processing digest action: {e}")
        return render_template('digest_action_result.html',
                             success=False,
                             message=f'Error: {str(e)}'), 500


if __name__ == '__main__':
    import ssl
    import os

    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Test database connection on startup
        logger.info("Testing database connection...")
        conn = get_db_connection()
        if conn:
            conn.close()
            logger.info("Database connection successful")
        else:
            logger.error("Failed to connect to database on startup")
            sys.exit(1)

        # Load hosted domains from database
        HOSTED_DOMAINS = get_hosted_domains()
        logger.info(f"Loaded {len(HOSTED_DOMAINS)} hosted domains from database")
        if HOSTED_DOMAINS:
            logger.info(f"Active domains: {', '.join(HOSTED_DOMAINS)}")
        else:
            logger.warning("No hosted domains found in database - please configure domains via SpacyWeb")

        # Check if SSL certificates exist
        cert_path = '/opt/spacyserver/web/certs/cert.pem'
        key_path = '/opt/spacyserver/web/certs/key.pem'
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            try:
                # Create SSL context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert_path, key_path)
                
                logger.info(f"Starting Flask app with HTTPS on port 5500")
                logger.info(f"Access via: https://<server-ip>:5500")

                # Run with SSL on localhost only (Apache reverse proxy handles external access)
                app.run(host='0.0.0.0', port=5500, debug=False, ssl_context=context)
            except Exception as e:
                logger.error(f"Failed to start HTTPS server: {e}")
                logger.info("Falling back to HTTP mode")
                app.run(host='0.0.0.0', port=5500, debug=False)
        else:
            logger.warning(f"SSL certificates not found at {cert_path}")
            logger.info(f"Running in HTTP mode on port 5500")
            app.run(host='0.0.0.0', port=5500, debug=False)
    except Exception as e:
        logger.error(f"Failed to start Flask application: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
