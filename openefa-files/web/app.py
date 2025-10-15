#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import create_engine, text
import os
import json
import pandas as pd
from datetime import datetime, timedelta
import io
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
from auth import init_auth, get_db_connection, extract_domains_from_recipients, get_domain_filter_condition, admin_required
import smtplib
from email.message import EmailMessage
import secrets
import string
import bcrypt

# Enhanced report system import
from enhanced_report_system import EnhancedEmailReportGenerator

# Configuration paths
MY_CNF_PATH = "/opt/spacyserver/config/.my.cnf"
APP_CONFIG_PATH = "/opt/spacyserver/config/.app_config.ini"
DB_NAME = "spacy_email_db"
HOST = "localhost"

# Centralized hosted domains configuration
# This will be populated from database at startup via get_hosted_domains()
# Updated during installation with configured domains
HOSTED_DOMAINS = [
    # Add your client domains here during installation
    # Example: 'example.com', 'client1.com', 'client2.com'
    # These should match domains in your client_domains database table
]

def get_hosted_domains():
    """
    Dynamically fetch active domains from database.
    Called at app startup to populate HOSTED_DOMAINS list.
    This makes the system configuration-driven instead of hardcoded.
    """
    try:
        db_connection = mysql.connector.connect(option_files=MY_CNF_PATH)
        cursor = db_connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT domain
            FROM client_domains
            WHERE is_active = 1
            ORDER BY domain
        """)
        domains = [row['domain'] for row in cursor.fetchall()]
        cursor.close()
        db_connection.close()
        return domains
    except Exception as e:
        logger.error(f"Failed to load hosted domains from database: {e}")
        # Return empty list on failure - will be populated when DB is available
        return []

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
app.config['SECRET_KEY'] = app_config['flask']['secret_key']

# Initialize authentication
login_manager = init_auth(app)

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
        with engine.connect() as conn:
            # Domain-specific filter
            domain_filter = f"WHERE recipients LIKE '%@{domain}%'"
            
            # Get last 30 days stats
            date_30_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Total emails in last 30 days for this domain
            total_30_query = f"""
                SELECT COUNT(*) FROM email_analysis 
                {domain_filter} AND DATE(timestamp) >= '{date_30_days_ago}'
            """
            total_30_days = conn.execute(text(total_30_query)).fetchone()[0]
            
            # Daily average
            daily_average = total_30_days / 30 if total_30_days > 0 else 0
            
            # Get previous 30 days for comparison
            date_60_days_ago = (datetime.now() - timedelta(days=60)).strftime('%Y-%m-%d')
            date_30_days_ago_end = (datetime.now() - timedelta(days=31)).strftime('%Y-%m-%d')
            
            previous_30_query = f"""
                SELECT COUNT(*) FROM email_analysis 
                {domain_filter} 
                AND DATE(timestamp) >= '{date_60_days_ago}' 
                AND DATE(timestamp) <= '{date_30_days_ago_end}'
            """
            previous_30_days = conn.execute(text(previous_30_query)).fetchone()[0]
            
            # Calculate trend
            volume_change = total_30_days - previous_30_days
            volume_percent_change = (volume_change / previous_30_days * 100) if previous_30_days > 0 else 0
            
            # Get peak day in last 30 days
            peak_day_query = f"""
                SELECT DATE(timestamp) as email_date, COUNT(*) as count
                FROM email_analysis
                {domain_filter} AND DATE(timestamp) >= '{date_30_days_ago}'
                GROUP BY DATE(timestamp)
                ORDER BY count DESC
                LIMIT 1
            """
            peak_day_result = conn.execute(text(peak_day_query)).fetchone()
            peak_day = {
                'date': peak_day_result[0] if peak_day_result else None,
                'count': peak_day_result[1] if peak_day_result else 0
            }

            # Get other stats for this domain
            total_query = f"SELECT COUNT(*) FROM email_analysis {domain_filter}"
            total_emails = conn.execute(text(total_query)).fetchone()[0]

            # Get language distribution for this domain
            lang_query = f"""
                SELECT detected_language, COUNT(*) as count
                FROM email_analysis
                {domain_filter} AND detected_language IS NOT NULL
                GROUP BY detected_language
                ORDER BY count DESC
            """
            languages = dict(conn.execute(text(lang_query)).fetchall())

            # Get category distribution for this domain
            cat_query = f"""
                SELECT email_category, COUNT(*) as count
                FROM email_analysis
                {domain_filter} AND email_category IS NOT NULL
                GROUP BY email_category
                ORDER BY count DESC
            """
            categories = dict(conn.execute(text(cat_query)).fetchall())

            # Get sentiment distribution for this domain
            sentiment_query = f"""
                SELECT
                    CASE
                        WHEN sentiment_polarity > 0.3 THEN 'Very Positive'
                        WHEN sentiment_polarity > 0.1 THEN 'Positive'
                        WHEN sentiment_polarity > -0.1 THEN 'Neutral'
                        WHEN sentiment_polarity > -0.3 THEN 'Negative'
                        ELSE 'Very Negative'
                    END as sentiment_category,
                    COUNT(*) as count
                FROM email_analysis
                {domain_filter} AND sentiment_polarity IS NOT NULL
                GROUP BY sentiment_category
                ORDER BY count DESC
            """
            sentiment_distribution = dict(conn.execute(text(sentiment_query)).fetchall())

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

def get_overall_system_stats():
    """Get overall system statistics for all hosted domains"""
    engine = get_db_engine()
    if not engine:
        return {}

    try:
        with engine.connect() as conn:
            # Create WHERE clause for all hosted domains
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in HOSTED_DOMAINS]
            hosted_domains_filter = f"WHERE ({' OR '.join(domain_conditions)})"

            # Today's stats
            today = datetime.now().strftime('%Y-%m-%d')
            today_query = f"""
                SELECT COUNT(*) FROM email_analysis
                {hosted_domains_filter} AND DATE(timestamp) = '{today}'
            """
            
            print(f"DEBUG: Today's query: {today_query}")  # Debug output
            today_total = conn.execute(text(today_query)).fetchone()[0]
            print(f"DEBUG: Today's total: {today_total}")  # Debug output

            # Yesterday's stats for comparison
            yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            yesterday_query = f"""
                SELECT COUNT(*) FROM email_analysis
                {hosted_domains_filter} AND DATE(timestamp) = '{yesterday}'
            """
            yesterday_total = conn.execute(text(yesterday_query)).fetchone()[0]

            # Last 7 days total
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            week_query = f"""
                SELECT COUNT(*) FROM email_analysis
                {hosted_domains_filter} AND DATE(timestamp) >= '{week_ago}'
            """
            week_total = conn.execute(text(week_query)).fetchone()[0]

            # Today's threats
            today_threats_query = f"""
                SELECT COUNT(*) FROM email_analysis
                {hosted_domains_filter}
                AND DATE(timestamp) = '{today}'
                AND (email_category = 'spam' OR email_category = 'phishing')
            """
            today_threats = conn.execute(text(today_threats_query)).fetchone()[0]

            # Domain breakdown for today
            domain_breakdown = {}
            for domain in HOSTED_DOMAINS:
                domain_today_query = f"""
                    SELECT COUNT(*) FROM email_analysis
                    WHERE recipients LIKE '%@{domain}%'
                    AND DATE(timestamp) = '{today}'
                """
                count = conn.execute(text(domain_today_query)).fetchone()[0]
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

    return render_template('enhanced_dashboard.html',
                         stats=stats,
                         schema_info=schema_info,
                         sentiment_chart=sentiment_chart,
                         user_domains=user_domains,
                         selected_domain=selected_domain,
                         overall_stats=overall_stats)

@app.route('/debug/stats')
@login_required
@admin_required
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
            today_all_query = f"SELECT COUNT(*) FROM email_analysis WHERE DATE(timestamp) = '{today}'"
            today_all = conn.execute(text(today_all_query)).fetchone()[0]

            # Check recipients column content
            recipients_sample_query = "SELECT recipients, timestamp FROM email_analysis ORDER BY id DESC LIMIT 10"
            recipients_sample = conn.execute(text(recipients_sample_query)).fetchall()

            # Check hosted domains specifically
            domain_counts = {}
            for domain in HOSTED_DOMAINS:
                domain_query = f"SELECT COUNT(*) FROM email_analysis WHERE recipients LIKE '%@{domain}%'"
                count = conn.execute(text(domain_query)).fetchone()[0]
                domain_counts[domain] = count

            # Check today's hosted domain emails
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in HOSTED_DOMAINS]
            hosted_filter = f"({' OR '.join(domain_conditions)})"
            today_hosted_query = f"""
                SELECT COUNT(*) FROM email_analysis 
                WHERE {hosted_filter} AND DATE(timestamp) = '{today}'
            """
            today_hosted = conn.execute(text(today_hosted_query)).fetchone()[0]

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

@app.route('/emails')
@login_required
def emails():
    """Email list with filtering and domain restrictions"""
    schema_info = get_column_info()
    if not schema_info:
        flash('Database connection failed', 'error')
        return render_template('error.html', error="Database connection failed")

    # Get filter parameters
    filters = {
        'search': request.args.get('search', ''),
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
    }

    # Build WHERE clause with user domain filtering
    where_conditions = ["1=1"]  # Always true condition to start

    # Add user domain filtering based on role
    if not current_user.is_admin():
        # Non-admin users ONLY see their authorized domains
        authorized_domains = get_user_authorized_domains(current_user)
        if authorized_domains:
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in authorized_domains]
            where_conditions.append(f"({' OR '.join(domain_conditions)})")
        else:
            where_conditions.append("1=0")  # No access if no authorized domains
    else:
        # Admins see all hosted domains
        hosted_domains_filter = " OR ".join([f"recipients LIKE '%@{domain}%'" for domain in HOSTED_DOMAINS])
        where_conditions.append(f"({hosted_domains_filter})")

    if filters['search']:
        search_term = filters['search'].replace("'", "''")  # Escape single quotes
        where_conditions.append(f"(subject LIKE '%{search_term}%' OR sender LIKE '%{search_term}%')")

    if filters['language']:
        where_conditions.append(f"detected_language = '{filters['language']}'")

    if filters['category']:
        where_conditions.append(f"email_category = '{filters['category']}'")

    if filters['receiving_domain']:
        # For non-admin users, ensure they can only filter by their authorized domains
        if current_user.is_admin():
            # Admin can filter by any hosted domain
            if filters['receiving_domain'] in HOSTED_DOMAINS:
                where_conditions.append(f"recipients LIKE '%@{filters['receiving_domain']}%'")
        else:
            # Client can only filter by their authorized domains
            user_authorized_domains = get_user_authorized_domains(current_user)
            if filters['receiving_domain'] in user_authorized_domains:
                where_conditions.append(f"recipients LIKE '%@{filters['receiving_domain']}%'")
        
    # Add sentiment category filtering
    if filters['sentiment_category']:
        if filters['sentiment_category'] == 'positive':
            where_conditions.append("sentiment_polarity > 0.1")
        elif filters['sentiment_category'] == 'negative':
            where_conditions.append("sentiment_polarity < -0.1")
        elif filters['sentiment_category'] == 'neutral':
            where_conditions.append("sentiment_polarity >= -0.1 AND sentiment_polarity <= 0.1")

    # Add security threats filter
    security_filter = request.args.get('security_threats', '')
    if security_filter == 'threats_only':
        where_conditions.append("(email_category = 'spam' OR email_category = 'phishing')")
    elif security_filter == 'safe_only':
        where_conditions.append("(email_category != 'spam' AND email_category != 'phishing' AND email_category IS NOT NULL)")

    if filters['min_sentiment']:
        where_conditions.append(f"sentiment_polarity >= {float(filters['min_sentiment'])}")

    if filters['max_sentiment']:
        where_conditions.append(f"sentiment_polarity <= {float(filters['max_sentiment'])}")

    if filters['min_manipulation']:
        where_conditions.append(f"sentiment_manipulation >= {float(filters['min_manipulation'])}")

    if filters['min_extremity']:
        where_conditions.append(f"sentiment_extremity >= {float(filters['min_extremity'])}")

    if filters['date_from']:
        where_conditions.append(f"DATE(timestamp) >= '{filters['date_from']}'")

    if filters['date_to']:
        where_conditions.append(f"DATE(timestamp) <= '{filters['date_to']}'")

    where_clause = " AND ".join(where_conditions)

    # Get pagination parameters
    page = int(request.args.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page

    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            # Get total count
            count_query = text(f"SELECT COUNT(*) FROM email_analysis WHERE {where_clause}")
            total_count = conn.execute(count_query).fetchone()[0]

            # Get emails with receiving domains
            email_query = text(f"""
                SELECT id, message_id, timestamp, sender, recipients, subject,
                       detected_language, email_category, sentiment_polarity,
                       sentiment_manipulation, spam_score
                FROM email_analysis
                WHERE {where_clause}
                ORDER BY id DESC
                LIMIT {per_page} OFFSET {offset}
            """)

            emails_data = conn.execute(email_query).fetchall()

            # Add receiving domain to each email
            emails = []
            for email in emails_data:
                email_dict = dict(email._mapping)
                email_dict['primary_receiving_domain'] = get_primary_receiving_domain(email_dict['recipients'])
                email_dict['all_receiving_domains'] = extract_receiving_domains(email_dict['recipients'])
                emails.append(email_dict)

            # Get available receiving domains for filter (user-specific and hosted domains only)
            if current_user.is_admin():
                # Admin sees all hosted domains that have emails
                domains_query = text("SELECT DISTINCT recipients FROM email_analysis WHERE recipients IS NOT NULL")
                all_recipients = conn.execute(domains_query).fetchall()
                
                all_domains = set()
                for row in all_recipients:
                    receiving_domains = extract_receiving_domains(row[0])
                    # Only include hosted domains
                    for domain in receiving_domains:
                        if domain in HOSTED_DOMAINS:
                            all_domains.add(domain)
                
                available_domains = sorted(list(all_domains))
            else:
                # Non-admin users see their authorized domains
                user_authorized_domains = get_user_authorized_domains(current_user)
                available_domains = [domain for domain in user_authorized_domains if domain in HOSTED_DOMAINS]

            total_pages = (total_count + per_page - 1) // per_page

            return render_template('emails.html',
                                 emails=emails,
                                 filters=filters,
                                 schema_info=schema_info,
                                 page=page,
                                 total_pages=total_pages,
                                 total_count=total_count,
                                 available_domains=available_domains)

    except Exception as e:
        flash(f'Database query failed: {e}', 'error')
        return render_template('error.html', error=f"Database query failed: {e}")

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

    # Build WHERE clause with domain filtering
    where_conditions = ["1=1"]

    # Add user domain filtering for non-admin users
    if not current_user.is_admin():
        authorized_domains = get_user_authorized_domains(current_user)
        if authorized_domains:
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in authorized_domains]
            where_conditions.append(f"({' OR '.join(domain_conditions)})")
        else:
            where_conditions.append("1=0")  # No access

    if filters['search']:
        search_term = filters['search'].replace("'", "''")
        where_conditions.append(f"(subject LIKE '%{search_term}%' OR sender LIKE '%{search_term}%')")

    if filters['language']:
        where_conditions.append(f"detected_language = '{filters['language']}'")

    if filters['category']:
        where_conditions.append(f"email_category = '{filters['category']}'")

    if filters['receiving_domain']:
        # Ensure non-admin users can only export their authorized domains
        if current_user.is_admin():
            if filters['receiving_domain'] in HOSTED_DOMAINS:
                where_conditions.append(f"recipients LIKE '%@{filters['receiving_domain']}%'")
        else:
            user_authorized_domains = get_user_authorized_domains(current_user)
            if filters['receiving_domain'] in user_authorized_domains:
                where_conditions.append(f"recipients LIKE '%@{filters['receiving_domain']}%'")

    # Add sentiment category filtering for export
    if filters['sentiment_category']:
        if filters['sentiment_category'] == 'positive':
            where_conditions.append("sentiment_polarity > 0.1")
        elif filters['sentiment_category'] == 'negative':
            where_conditions.append("sentiment_polarity < -0.1")
        elif filters['sentiment_category'] == 'neutral':
            where_conditions.append("sentiment_polarity >= -0.1 AND sentiment_polarity <= 0.1")

    where_clause = " AND ".join(where_conditions)

    engine = get_db_engine()
    try:
        with engine.connect() as conn:
            query = text(f"""
                SELECT id, timestamp, sender, recipients, subject,
                       detected_language, email_category, sentiment_polarity,
                       sentiment_manipulation, spam_score, urgency_score,
                       entities, email_topics
                FROM email_analysis
                WHERE {where_clause}
                ORDER BY id DESC
            """)

            result = conn.execute(query).fetchall()

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

            # Check if user has access to this email
            if not current_user.is_admin():
                user_authorized_domains = get_user_authorized_domains(current_user)
                user_can_access = any(domain in user_authorized_domains for domain in email['all_receiving_domains'])
                if not user_can_access:
                    flash('Access denied to this email', 'error')
                    return redirect(url_for('emails'))

            return render_template('email_detail.html',
                                 email=email,
                                 schema_info=schema_info)

    except Exception as e:
        flash(f'Database query failed: {e}', 'error')
        return render_template('error.html', error=f"Database query failed: {e}")

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
            # Get last 7 days for quick metrics
            date_7_days_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            
            daily_volume_query = f"""
                SELECT DATE(timestamp) as email_date, COUNT(*) as count
                FROM email_analysis
                WHERE recipients LIKE '%@{domain}%'
                AND DATE(timestamp) >= '{date_7_days_ago}'
                GROUP BY DATE(timestamp)
                ORDER BY email_date
            """
            
            results = conn.execute(text(daily_volume_query)).fetchall()
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
        
        # Create enhanced report generator
        report_generator = EnhancedEmailReportGenerator()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
            temp_path = tmp_file.name
        
        # Generate enhanced report with user info
        user_info = {
            'name': current_user.get_display_name() if hasattr(current_user, 'get_display_name') else f"{current_user.first_name} {current_user.last_name}".strip(),
            'email': current_user.email
        }
        
        logger.info(f"Generating enhanced report for {domain} from {date_from} to {date_to}")
        logger.info(f"Temp path: {temp_path}")
        
        success = report_generator.generate_enhanced_domain_report(
            engine, domain, date_from, date_to, temp_path, user_info
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
@admin_required  
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
@admin_required
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
                SELECT COUNT(*) FROM email_analysis 
                WHERE recipients LIKE %s
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
@admin_required
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
        
        if role not in ['admin', 'client', 'viewer']:
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
@admin_required
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
            
            if role not in ['admin', 'client', 'viewer']:
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
@admin_required
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
        
        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'PASSWORD_RESET_BY_ADMIN', %s, %s)
        """, (current_user.id, f'Reset password for user {email}', request.remote_addr))
        
        conn.commit()
        conn.close()
        
        flash(f'Password reset for {email}. New password: {new_password}', 'success')
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

@app.route('/debug/user-info')
@login_required
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

@app.route('/effectiveness')
@login_required
@admin_required
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
            trend_dates.append(trend['metric_date'].strftime('%Y-%m-%d'))
            trend_scores.append(float(trend['effectiveness_score'] or 0))
            trend_week_avg.append(float(trend['week_avg'] or 0))
            trend_month_avg.append(float(trend['month_avg'] or 0))

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

        cursor.close()
        conn.close()

        return render_template('effectiveness_dashboard.html',
            current=current,
            trend_dates=trend_dates,
            trend_scores=trend_scores,
            trend_week_avg=trend_week_avg,
            trend_month_avg=trend_month_avg,
            module_stats=module_stats,
            weekly_summary=weekly_summary
        )

    except Exception as e:
        app.logger.error(f"Error loading effectiveness dashboard: {e}")
        flash(f"Error loading dashboard: {e}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/learning')
@login_required
def learning_dashboard():
    """Conversation Learning Statistics Dashboard"""
    try:
        from datetime import datetime, timedelta
        
        # Use MySQL connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        stats = {}
        
        # Get all stats from the view
        cursor.execute('SELECT * FROM conversation_learning_stats')
        view_stats = cursor.fetchone()
        if view_stats:
            stats['vocabulary'] = view_stats['vocabulary_count']
            stats['relationships'] = view_stats['relationship_count']
            stats['phrases'] = view_stats['phrase_count']
            stats['domains'] = view_stats['domain_count']
            stats['new_patterns_24h'] = view_stats['new_patterns_24h']
            stats['new_patterns_7d'] = view_stats['new_patterns_7d']
            stats['avg_legitimate_score'] = view_stats['avg_legitimate_score'] or 0
        else:
            # Default values if view is empty
            stats = {
                'vocabulary': 0, 'relationships': 0, 'phrases': 0, 'domains': 0,
                'new_patterns_24h': 0, 'new_patterns_7d': 0, 'avg_legitimate_score': 0
            }
        
        # Get top relationships
        cursor.execute('''
            SELECT sender_domain, recipient_domain, message_count, avg_spam_score 
            FROM conversation_relationships 
            ORDER BY message_count DESC 
            LIMIT 10
        ''')
        stats['top_relationships'] = cursor.fetchall()
        
        # Get confidence metrics
        cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 5')
        result = cursor.fetchone()
        high_freq_vocab = result['COUNT(*)'] if result else 0
        
        cursor.execute('SELECT COUNT(*) FROM conversation_relationships WHERE message_count > 5')
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
        
        # Search for emails by sender
        query = """
            SELECT message_id, sender, recipients, subject, spam_score,
                   DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as time
            FROM email_analysis
            WHERE sender LIKE %s OR message_id LIKE %s
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
@admin_required
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
                result = conn.execute(text("""
                    SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'size_mb'
                    FROM information_schema.tables
                    WHERE table_schema='spacy_email_db'
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
                results = conn.execute(text("""
                    SELECT table_name, table_rows
                    FROM information_schema.tables
                    WHERE table_schema='spacy_email_db'
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
@admin_required
def create_backup():
    """Create a new database backup"""
    import subprocess

    try:
        backup_dir = '/opt/spacyserver/backups'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f'{backup_dir}/spacy_db_backup_{timestamp}.sql'
        my_cnf_path = '/opt/spacyserver/config/.my.cnf'

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
            'spacy_email_db'
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

        # Get file size
        stat = os.stat(backup_file_gz)
        size_mb = stat.st_size / (1024 * 1024)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DATABASE_BACKUP_CREATED', %s, %s)
        """, (current_user.id, f'Created backup: {os.path.basename(backup_file_gz)} ({size_mb:.2f} MB)', request.remote_addr))
        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Backup created successfully: {backup_file_gz} ({size_mb:.2f} MB)")

        return jsonify({
            'success': True,
            'filename': os.path.basename(backup_file_gz),
            'size': f'{size_mb:.2f} MB',
            'message': f'Backup created successfully: {os.path.basename(backup_file_gz)}'
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
@admin_required
def download_backup(filename):
    """Download a backup file"""
    backup_dir = '/opt/spacyserver/backups'

    # Security: prevent directory traversal
    if '..' in filename or '/' in filename:
        return jsonify({'error': 'Invalid filename'}), 400

    file_path = os.path.join(backup_dir, filename)

    if not os.path.exists(file_path):
        return jsonify({'error': 'Backup file not found'}), 404

    try:
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/backup/delete/<filename>', methods=['POST'])
@login_required
@admin_required
def delete_backup(filename):
    """Delete a backup file"""
    backup_dir = '/opt/spacyserver/backups'

    # Security: prevent directory traversal
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
@admin_required
def create_full_backup():
    """Create a full system backup (configs + database + modules)"""
    import subprocess
    import shutil

    try:
        backup_dir = '/opt/spacyserver/backups'
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        full_backup_dir = f'{backup_dir}/full_backup_{timestamp}'
        my_cnf_path = '/opt/spacyserver/config/.my.cnf'
        spacy_root = '/opt/spacyserver'

        # Create backup directory
        os.makedirs(full_backup_dir, exist_ok=True)

        logger.info(f"Starting full system backup: {full_backup_dir}")

        # 1. Backup configuration files
        logger.info("Backing up configuration files...")
        config_files = [
            '/opt/spacyserver/config/bec_config.json',
            '/opt/spacyserver/config/module_config.json',
            '/opt/spacyserver/config/email_filter_config.json',
            '/opt/spacyserver/config/authentication_config.json',
            '/opt/spacyserver/config/threshold_config.json',
            '/opt/spacyserver/config/trusted_domains.json',
            '/opt/spacyserver/config/rbl_config.json'
        ]

        config_count = 0
        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, full_backup_dir)
                config_count += 1

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
            'spacy_email_db'
        ]

        with open(db_backup_file, 'w') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=300)

        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else 'Database backup failed'
            logger.error(f"Database backup failed: {error_msg}")
            # Clean up partial backup
            shutil.rmtree(full_backup_dir)
            return jsonify({'success': False, 'error': f'Database backup failed: {error_msg}'}), 500

        # Compress database
        subprocess.run(['gzip', db_backup_file], check=True, timeout=60)

        # 3. Backup Python modules
        logger.info("Backing up Python modules...")
        modules_backup_dir = f'{full_backup_dir}/modules'
        os.makedirs(modules_backup_dir, exist_ok=True)

        # Copy key Python files
        python_files = ['email_filter.py', 'email_blocking.py']
        for py_file in python_files:
            src_file = f'{spacy_root}/{py_file}'
            if os.path.exists(src_file):
                shutil.copy2(src_file, modules_backup_dir)

        # Copy modules directory
        modules_src = f'{spacy_root}/modules'
        if os.path.exists(modules_src):
            shutil.copytree(modules_src, f'{modules_backup_dir}/modules', dirs_exist_ok=True)

        # Copy services directory
        services_src = f'{spacy_root}/services'
        if os.path.exists(services_src):
            shutil.copytree(services_src, f'{modules_backup_dir}/services', dirs_exist_ok=True)

        # 4. Create manifest file
        logger.info("Creating backup manifest...")
        manifest_file = f'{full_backup_dir}/MANIFEST.txt'
        with open(manifest_file, 'w') as f:
            f.write(f"SpaCy Email Security System - Full Backup\n")
            f.write(f"=" * 60 + "\n\n")
            f.write(f"Backup Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Created By: {current_user.email}\n")
            f.write(f"Backup Type: Full System Backup\n\n")
            f.write(f"Contents:\n")
            f.write(f"  - Configuration Files: {config_count} files\n")
            f.write(f"  - Database: spacy_email_db (compressed)\n")
            f.write(f"  - Python Modules: email_filter.py, modules/, services/\n\n")
            f.write(f"Restore Instructions:\n")
            f.write(f"  1. Stop all SpaCy services\n")
            f.write(f"  2. Restore configuration files to /opt/spacyserver/config/\n")
            f.write(f"  3. Restore database: gunzip spacy_database.sql.gz && mysql spacy_email_db < spacy_database.sql\n")
            f.write(f"  4. Restore Python modules to /opt/spacyserver/\n")
            f.write(f"  5. Restart all SpaCy services\n")

        # 5. Create tarball of the full backup
        logger.info("Creating compressed archive...")
        tar_filename = f'full_backup_{timestamp}.tar.gz'
        tar_filepath = f'{backup_dir}/{tar_filename}'

        subprocess.run([
            'tar', 'czf', tar_filepath,
            '-C', backup_dir,
            f'full_backup_{timestamp}'
        ], check=True, timeout=120)

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

        return jsonify({
            'success': True,
            'filename': tar_filename,
            'size': f'{size_mb:.2f} MB',
            'message': f'Full system backup created successfully: {tar_filename}',
            'details': {
                'config_files': config_count,
                'database': 'included',
                'modules': 'included'
            }
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
        # Look for PDF reports
        report_files = sorted(glob.glob(f'{reports_dir}/*_email_report_*.pdf'), reverse=True)
        for report_file in report_files[:20]:  # Show last 20 reports
            # Extract domain from filename
            filename = os.path.basename(report_file)
            if selected_domain in filename or current_user.is_admin():
                stat = os.stat(report_file)
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

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if domain not in user_domains and not current_user.is_admin():
            return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        # Validate dates
        try:
            datetime.strptime(date_from, '%Y-%m-%d')
            datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

        # Get database engine
        engine = get_db_engine()
        if not engine:
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        # Create report generator
        report_generator = EnhancedEmailReportGenerator()

        # Create reports directory if it doesn't exist
        reports_dir = '/opt/spacyserver/reports'
        os.makedirs(reports_dir, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'{domain}_email_report_{date_from}_to_{date_to}_{timestamp}.pdf'
        output_path = os.path.join(reports_dir, filename)

        # User info
        user_info = {
            'name': f"{current_user.first_name} {current_user.last_name}".strip() or current_user.email,
            'email': current_user.email
        }

        logger.info(f"Generating report for {domain} from {date_from} to {date_to}")

        # Generate report
        success = report_generator.generate_enhanced_domain_report(
            engine, domain, date_from, date_to, output_path, user_info
        )

        if not success:
            return jsonify({'success': False, 'error': 'Report generation failed'}), 500

        # Get file size
        stat = os.stat(output_path)
        size_mb = stat.st_size / (1024 * 1024)

        # Log the action
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'REPORT_GENERATED', %s, %s)
        """, (current_user.id, f'Generated report for {domain}: {filename} ({size_mb:.2f} MB)', request.remote_addr))
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

# ============================================================================
# DOMAIN MANAGEMENT ROUTES
# ============================================================================

@app.route('/config/domains')
@login_required
@admin_required
def domain_management():
    """Domain management page - admin only"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all client domains with statistics
        cursor.execute("""
            SELECT
                cd.id,
                cd.domain,
                cd.client_name,
                cd.active,
                cd.created_at,
                cd.updated_at,
                COUNT(DISTINCT br.id) as rule_count,
                COUNT(DISTINCT ba.id) as blocked_count
            FROM client_domains cd
            LEFT JOIN blocking_rules br ON cd.id = br.client_domain_id AND br.active = 1
            LEFT JOIN blocked_attempts ba ON cd.id = ba.client_domain_id
                AND ba.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY cd.id, cd.domain, cd.client_name, cd.active, cd.created_at, cd.updated_at
            ORDER BY cd.domain
        """)

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
                             stats=stats)

    except Exception as e:
        logger.error(f"Error loading domain management: {e}")
        flash(f'Error loading domains: {e}', 'error')
        return redirect(url_for('config_dashboard'))


@app.route('/api/domains/add', methods=['POST'])
@login_required
@admin_required
def add_domain():
    """Add a new client domain"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip().lower()
        client_name = data.get('client_name', '').strip()

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
                    SET active = 1, client_name = %s, updated_at = NOW()
                    WHERE domain = %s
                """, (client_name or domain, domain))
                conn.commit()

                # Log audit
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, details, ip_address)
                    VALUES (%s, 'DOMAIN_REACTIVATED', %s, %s)
                """, (current_user.id, f'Reactivated domain: {domain}', request.remote_addr))
                conn.commit()

                cursor.close()
                conn.close()
                return jsonify({'success': True, 'message': f'Domain {domain} reactivated successfully'})

        # Insert new domain
        cursor.execute("""
            INSERT INTO client_domains (domain, client_name, active, created_at, updated_at)
            VALUES (%s, %s, 1, NOW(), NOW())
        """, (domain, client_name or domain))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DOMAIN_ADDED', %s, %s)
        """, (current_user.id, f'Added domain: {domain} ({client_name})', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': f'Domain {domain} added successfully'})

    except Exception as e:
        logger.error(f"Error adding domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/edit/<int:domain_id>', methods=['POST'])
@login_required
@admin_required
def edit_domain(domain_id):
    """Edit a client domain"""
    try:
        data = request.get_json()
        client_name = data.get('client_name', '').strip()

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
            SET client_name = %s, updated_at = NOW()
            WHERE id = %s
        """, (client_name, domain_id))

        conn.commit()

        # Log audit
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'DOMAIN_UPDATED', %s, %s)
        """, (current_user.id, f'Updated domain {domain_info["domain"]}: {client_name}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Domain updated successfully'})

    except Exception as e:
        logger.error(f"Error editing domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/domains/toggle/<int:domain_id>', methods=['POST'])
@login_required
@admin_required
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

        return jsonify({'success': True, 'message': f'Domain {domain_info["domain"]} deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting domain: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# TRUSTED DOMAINS CONFIGURATION ROUTES
# ============================================================================

@app.route('/config/trusted')
@login_required
@admin_required
def trusted_domains_config():
    """Trusted domains configuration page (admin only)"""
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
@admin_required
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
@admin_required
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
# BLOCKING RULES CONFIGURATION ROUTES
# ============================================================================

@app.route('/config/blocking')
@login_required
def blocking_rules_config():
    """Blocking rules configuration page"""
    user_domains = get_user_authorized_domains(current_user)
    selected_domain = request.args.get('domain', user_domains[0] if user_domains else None)

    if not selected_domain:
        flash('No domain selected', 'error')
        return redirect(url_for('dashboard'))

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

        # Get all blocking rules for this domain
        cursor.execute("""
            SELECT id, rule_type, rule_value, rule_pattern, description,
                   active, priority, created_at, created_by
            FROM blocking_rules
            WHERE client_domain_id = %s
            ORDER BY priority DESC, created_at DESC
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

        # Verify user has access to this domain
        user_domains = get_user_authorized_domains(current_user)
        if domain not in user_domains and not current_user.is_admin():
            return jsonify({'success': False, 'error': 'Access denied to this domain'}), 403

        if not rule_value or not rule_type:
            return jsonify({'success': False, 'error': 'Rule type and value are required'}), 400

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get client_domain_id
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
             created_at, created_by, active, priority, whitelist)
            VALUES (%s, %s, %s, %s, %s, NOW(), %s, 1, 100, 0)
        """, (client_domain_id, rule_type, rule_value, rule_pattern, description, current_user.email))

        rule_id = cursor.lastrowid

        # Log the action
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'BLOCKING_RULE_ADDED', %s, %s)
        """, (current_user.id, f'Added blocking rule for {domain}: {rule_type}={rule_value}', request.remote_addr))

        conn.commit()
        cursor.close()
        conn.close()

        logger.info(f"Blocking rule added by {current_user.email}: {rule_type}={rule_value} for {domain}")

        return jsonify({
            'success': True,
            'rule_id': rule_id,
            'message': f'Blocking rule added successfully'
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

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)

# ============================================================================
# WHITELIST MANAGEMENT ROUTES
# ============================================================================

from whitelist_manager import WhitelistManager

# ============================================================================
# Configuration Dashboard Routes
# ============================================================================

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

    whitelist_mgr = WhitelistManager()

    # If user has multiple domains, show whitelists for all their domains
    # This allows Rob to see both rdjohnsonlaw.com and escudolaw.com entries
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

@app.route('/whitelist/<domain>/search_sender', methods=['POST'])
@login_required
def search_sender_emails(domain):
    """Search for emails from a specific sender"""
    # Check authorization
    if domain not in get_user_authorized_domains(current_user):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

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
    """Main quarantine view - list of quarantined emails"""
    try:
        # Get filter parameters
        domain_filter = request.args.get('domain', '')
        status_filter = request.args.get('status', 'active')  # Changed default to 'active'
        search_query = request.args.get('search', '')
        page = int(request.args.get('page', 1))
        per_page = 50

        # Get user's authorized domains
        user_domains = get_user_authorized_domains(current_user)

        # Build query
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Base query
        query = """
            SELECT
                id, message_id, timestamp, sender, sender_domain,
                recipients, subject, spam_score, quarantine_status,
                quarantine_reason, quarantine_expires_at, has_attachments,
                attachment_count, virus_detected, phishing_detected,
                reviewed_by, reviewed_at,
                DATEDIFF(quarantine_expires_at, NOW()) as days_until_expiry,
                text_content, html_content, raw_email
            FROM email_quarantine
            WHERE 1=1
        """
        params = []

        # Filter by status
        if status_filter == 'active':
            # Active = only held emails (not released or deleted)
            query += " AND quarantine_status = 'held'"
        elif status_filter == 'spam':
            # Spam = emails with spam_score >= 5.0
            query += " AND spam_score >= 5.0 AND quarantine_status != 'deleted'"
        elif status_filter == 'clean':
            # Clean = emails with spam_score < 3.0
            query += " AND spam_score < 3.0 AND quarantine_status != 'deleted'"
        elif status_filter == 'all':
            # All = exclude deleted emails
            query += " AND quarantine_status != 'deleted'"
        elif status_filter and status_filter != 'all':
            # Specific status (held, released, deleted)
            query += " AND quarantine_status = %s"
            params.append(status_filter)

        # Filter by domain (user access control)
        if not current_user.is_admin():
            # Non-admin users only see emails for their authorized domains
            if user_domains:
                domain_placeholders = ','.join(['%s'] * len(user_domains))
                query += f" AND (sender_domain IN ({domain_placeholders})"
                params.extend(user_domains)

                # Also check recipient domains
                for domain in user_domains:
                    query += " OR recipients LIKE %s"
                    params.append(f'%{domain}%')
                query += ")"
            else:
                # User has no domains - show nothing
                query += " AND 1=0"
        else:
            # Admin can filter by specific domain if requested
            if domain_filter:
                query += " AND (sender_domain = %s OR recipients LIKE %s)"
                params.extend([domain_filter, f'%{domain_filter}%'])

        # Search filter
        if search_query:
            query += """ AND (
                sender LIKE %s OR
                subject LIKE %s OR
                recipients LIKE %s
            )"""
            search_param = f'%{search_query}%'
            params.extend([search_param, search_param, search_param])

        # Only show non-expired
        query += " AND quarantine_expires_at > NOW()"

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

        # Calculate pagination
        total_pages = (total_count + per_page - 1) // per_page

        # Get statistics
        stats_query = """
            SELECT
                COUNT(*) as total_held,
                COUNT(CASE WHEN quarantine_expires_at < DATE_ADD(NOW(), INTERVAL 7 DAY) THEN 1 END) as expiring_soon,
                AVG(spam_score) as avg_spam_score,
                SUM(CASE WHEN virus_detected = 1 THEN 1 ELSE 0 END) as virus_count
            FROM email_quarantine
            WHERE quarantine_status = 'held'
            AND quarantine_expires_at > NOW()
        """

        if not current_user.is_admin():
            if user_domains:
                domain_placeholders = ','.join(['%s'] * len(user_domains))
                stats_query += f" AND sender_domain IN ({domain_placeholders})"
                cursor.execute(stats_query, user_domains)
            else:
                # User has no domains - return zero stats
                stats_query += " AND 1=0"
                cursor.execute(stats_query)
        else:
            cursor.execute(stats_query)

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
                             user_domains=user_domains,
                             selected_domain=domain_filter or (user_domains[0] if user_domains else ''))

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

        # Get email details
        query = """
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

        cursor.execute(query, (email_id,))
        email = cursor.fetchone()

        if not email:
            flash('Email not found', 'warning')
            return redirect(url_for('quarantine_view'))

        # Check access permissions
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            sender_domain = email['sender_domain']
            recipient_domains = json.loads(email['recipient_domains']) if email['recipient_domains'] else []

            # User must have access to sender domain or one of recipient domains
            has_access = (sender_domain in user_domains) or any(rd in user_domains for rd in recipient_domains)

            if not has_access:
                flash('Access denied', 'danger')
                return redirect(url_for('quarantine_view'))

        # Parse JSON fields
        if email['recipients']:
            email['recipients_list'] = json.loads(email['recipients'])
        else:
            email['recipients_list'] = []

        if email['attachment_names']:
            email['attachment_names_list'] = json.loads(email['attachment_names'])
        else:
            email['attachment_names_list'] = []

        if email['spam_modules_detail']:
            email['spam_modules'] = json.loads(email['spam_modules_detail'])
        else:
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
        # Get release destination config
        relay_host = os.getenv('SPACY_RELAY_HOST', '192.168.50.37')
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

        query = "SELECT * FROM email_quarantine WHERE id = %s"
        cursor.execute(query, (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        if email["quarantine_status"] == "deleted":
            return jsonify({'success': False, 'error': 'Cannot release a deleted email'}), 400

        # Check permissions - verify user has access to recipient domain
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            # Parse recipient_domains (JSON array)
            import json as json_module
            try:
                recipient_domains = json_module.loads(email.get('recipient_domains', '[]'))
            except:
                recipient_domains = []

            has_access = any(domain in user_domains for domain in recipient_domains)
            if not has_access:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Parse recipients
        recipients = json.loads(email['recipients']) if email['recipients'] else []

        # Extract email address from sender (handle "Name <email@domain.com>" format)
        sender = email['sender']
        if '<' in sender and '>' in sender:
            # Extract email from "Name <email@domain.com>" format
            sender = sender.split('<')[1].split('>')[0].strip()

        # Relay email using SMTP
        try:
            # Connect and send
            with smtplib.SMTP(relay_host, relay_port, timeout=30) as smtp:
                smtp.sendmail(sender, recipients, email['raw_email'])

            # Update database
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
                'released_to': relay_host,
                'recipient_count': len(recipients),
                'mode': mode
            })
            cursor.execute(log_query, (email_id, 'released', current_user.email,
                                      'admin' if current_user.is_admin() else 'user', log_data))

            conn.commit()

            logger.info(f"Email {email_id} released by {current_user.email} to {relay_host}")

            return jsonify({
                'success': True,
                'message': f'Email released and sent to {mode}',
                'released_to': relay_host
            })

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error releasing email {email_id}: {e}")
            return jsonify({'success': False, 'error': f'Failed to relay email: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Error releasing email {email_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
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

        # Check if email exists and get details
        cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions - verify user has access to recipient domain
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            # Parse recipient_domains (stored as JSON array like ["domain.com"])
            import json
            try:
                recipient_domains = json.loads(email.get('recipient_domains', '[]'))
            except:
                recipient_domains = []

            # Check if user has access to any of the recipient domains
            has_access = False
            for domain in recipient_domains:
                if domain in user_domains:
                    has_access = True
                    break

            if not has_access:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update status
        update_query = """
            UPDATE email_quarantine
            SET quarantine_status = 'deleted',
                user_classification = 'spam',
                deleted_by = %s,
                deleted_at = NOW()
            WHERE id = %s
        """
        cursor.execute(update_query, (current_user.email, email_id))

        # Log action
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

        # Get email
        cursor.execute("SELECT raw_email, recipient_domains FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

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

        # Get email
        cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
        email = cursor.fetchone()

        if not email:
            return jsonify({'success': False, 'error': 'Email not found'}), 404

        # Check permissions - verify user has access to recipient domain
        if not current_user.is_admin():
            user_domains = get_user_authorized_domains(current_user)
            # Parse recipient_domains (stored as JSON array like ["domain.com"])
            import json
            try:
                recipient_domains = json.loads(email.get('recipient_domains', '[]'))
            except:
                recipient_domains = []

            # Check if user has access to any of the recipient domains
            has_access = False
            for domain in recipient_domains:
                if domain in user_domains:
                    has_access = True
                    break

            if not has_access:
                return jsonify({'success': False, 'error': 'Access denied'}), 403

        # Update classification
        update_query = """
            UPDATE email_quarantine
            SET user_classification = 'not_spam',
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

        conn.commit()

        logger.info(f"Email {email_id} marked as not spam by {current_user.email}")

        return jsonify({
            'success': True,
            'message': 'Email marked as not spam. Release separately if needed.'
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
                response = api_quarantine_release(email_id)
                if isinstance(response, tuple) and response[1] == 200:  # Success
                    success_count += 1
                else:
                    error_count += 1
                    if isinstance(response, tuple):
                        errors.append(f"Email {email_id}: {response[0].get_json().get('error')}")
                    else:
                        errors.append(f"Email {email_id}: Unknown error")
            except Exception as e:
                error_count += 1
                errors.append(f"Email {email_id}: {str(e)}")

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

        # Get user's authorized domains for permission checking
        user_domains = get_user_authorized_domains(current_user) if not current_user.is_admin() else None

        for email_id in email_ids:
            try:
                # Check if email exists and get details
                cursor.execute("SELECT * FROM email_quarantine WHERE id = %s", (email_id,))
                email = cursor.fetchone()

                if not email:
                    error_count += 1
                    errors.append(f"Email {email_id}: Not found")
                    continue

                # Check permissions - verify user has access to recipient domain
                if not current_user.is_admin():
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

                # Update status
                update_query = """
                    UPDATE email_quarantine
                    SET quarantine_status = 'deleted',
                        user_classification = 'spam',
                        deleted_by = %s,
                        deleted_at = NOW()
                    WHERE id = %s
                """
                cursor.execute(update_query, (current_user.email, email_id))

                # Log action
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
        # HOSTED_DOMAINS = get_hosted_domains()  # Disabled - using hardcoded list
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
                logger.info(f"Access via: https://localhost:5500 (local) or https://<server-ip>:5500 (remote)")
                
                # Run with SSL
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
