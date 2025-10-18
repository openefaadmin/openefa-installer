"""
Flask Authentication System for GuardianMail
Save this as: auth.py
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, has_request_context
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
import bcrypt
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import re

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__)

class User(UserMixin):
    def __init__(self, id, email, domain, role, first_name, last_name, company_name=None, authorized_domains=None):
        self.id = id
        self.email = email
        self.domain = domain
        self.role = role
        self.first_name = first_name
        self.last_name = last_name
        self.company_name = company_name
        self.authorized_domains = authorized_domains
    
    def get_id(self):
        return str(self.id)
    
    def is_admin(self):
        return self.role == 'admin'

    def is_superadmin(self):
        """Check if user is a superadmin (same as admin in this system)"""
        return self.role == 'admin'

    def is_client(self):
        return self.role == 'client'

    def is_domain_admin(self):
        return self.role == 'domain_admin'

    def has_admin_access(self):
        """Check if user has admin or domain_admin access"""
        return self.role in ['admin', 'domain_admin']

    def can_see_domain(self, domain):
        return self.is_admin() or self.domain.lower() == domain.lower()
    
    def get_display_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email.split('@')[0].title()

def get_db_connection():
    """Get database connection using same config as main app"""
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            option_files='/opt/spacyserver/config/.my.cnf',
            option_groups=['client'],
            user='spacy_user',
            database='spacy_email_db'
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def load_user_by_id(user_id):
    """Load user by ID for Flask-Login"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, email, domain, role, first_name, last_name, company_name, authorized_domains
            FROM users 
            WHERE id = %s AND is_active = TRUE
            """, (user_id,))     
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return User(*result)
        return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

def authenticate_user(email, password):
    """Authenticate user with email and password"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user data
        cursor.execute("""
            SELECT id, email, password_hash, domain, role, first_name, last_name,
                   company_name, authorized_domains, failed_login_attempts, locked_until
            FROM users
            WHERE email = %s AND is_active = TRUE
        """, (email.lower(),))

        result = cursor.fetchone()

        if not result:
            return None, "Invalid email or password"

        user_id, email, password_hash, domain, role, first_name, last_name, company_name, authorized_domains, failed_attempts, locked_until = result
        
        # Check if account is locked
        if locked_until and locked_until > datetime.now():
            return None, f"Account locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Verify password - try both Werkzeug and bcrypt for compatibility
        password_valid = False
        try:
            # Try Werkzeug first (for newer passwords)
            if password_hash.startswith('scrypt:'):
                password_valid = check_password_hash(password_hash, password)
            else:
                # Fall back to bcrypt for older passwords
                password_valid = bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            password_valid = False

        if not password_valid:
            # Increment failed attempts
            new_failed_attempts = failed_attempts + 1
            lock_until = None
            
            if new_failed_attempts >= 5:
                lock_until = datetime.now() + timedelta(minutes=30)
            
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = %s, locked_until = %s
                WHERE id = %s
            """, (new_failed_attempts, lock_until, user_id))
            
            # Log failed attempt (only if we have request context)
            try:
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, details, ip_address)
                    VALUES (%s, 'LOGIN_FAILED', 'Invalid password', %s)
                """, (user_id, request.remote_addr if request else 'unknown'))
            except:
                # Skip logging if no request context
                pass
            
            conn.commit()
            conn.close()
            
            if lock_until:
                return None, "Too many failed attempts. Account locked for 30 minutes."
            
            return None, "Invalid email or password"
        
        # Successful login - reset failed attempts and update last login
        cursor.execute("""
            UPDATE users 
            SET failed_login_attempts = 0, locked_until = NULL, last_login = %s
            WHERE id = %s
        """, (datetime.now(), user_id))
        
        # Log successful login (only if we have request context)
        try:
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address, user_agent)
                VALUES (%s, 'LOGIN_SUCCESS', 'User logged in', %s, %s)
            """, (user_id, request.remote_addr if request else 'unknown', request.headers.get('User-Agent', '') if request else 'unknown'))
        except:
            # Skip logging if no request context
            pass
        
        conn.commit()
        conn.close()

        return User(user_id, email, domain, role, first_name, last_name, company_name, authorized_domains), None
        
    except Exception as e:
        print(f"Authentication error: {e}")
        return None, "Authentication system error"

def extract_domains_from_recipients(recipients_text):
    """Extract domains from recipients field"""
    if not recipients_text:
        return set()
    
    email_pattern = r'\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
    domains = set()
    matches = re.findall(email_pattern, recipients_text)
    
    for domain in matches:
        domains.add(domain.lower())
    
    return domains

def get_domain_filter_condition(user):
    """Get SQL condition for filtering by user's domain"""
    if user.is_admin():
        return "", []  # No filter for admin
    else:
        return "WHERE recipients LIKE %s", [f'%@{user.domain}%']

# Authentication decorators
def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))

        if not current_user.is_admin():
            flash('Administrator privileges required to access this feature.', 'error')
            return render_template('error.html',
                                 error='Access Denied',
                                 message='You do not have permission to access this feature. Please contact your system administrator if you need access.')

        return f(*args, **kwargs)
    return decorated_function

def domain_access_required(domain):
    """Decorator to check domain access"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            
            if not current_user.can_see_domain(domain):
                flash('Access denied for this domain.', 'error')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Authentication routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('auth/login.html')
        
        user, error = authenticate_user(email, password)
        
        if user:
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.get_display_name()}!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash(error, 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (%s, 'LOGOUT', 'User logged out', %s)
        """, (current_user.id, request.remote_addr))
        conn.commit()
        conn.close()
    except:
        pass  # Don't fail logout if logging fails
    
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html')

@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password:
            flash('Please fill in all fields.', 'error')
            return render_template('auth/change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('auth/change_password.html')
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('auth/change_password.html')
        
        # Verify current password
        user, error = authenticate_user(current_user.email, current_password)
        if not user:
            flash('Current password is incorrect.', 'error')
            return render_template('auth/change_password.html')
        
        # Update password
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            cursor.execute("""
                UPDATE users SET password_hash = %s WHERE id = %s
            """, (new_password_hash, current_user.id))
            
            # Log password change
            cursor.execute("""
                INSERT INTO audit_log (user_id, action, details, ip_address)
                VALUES (%s, 'PASSWORD_CHANGED', 'User changed password', %s)
            """, (current_user.id, request.remote_addr))
            
            conn.commit()
            conn.close()
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('auth.profile'))
            
        except Exception as e:
            flash('Error changing password. Please try again.', 'error')
            print(f"Password change error: {e}")
    
    return render_template('auth/change_password.html')

def init_auth(app):
    """Initialize authentication with Flask app"""
    # Configure Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        return load_user_by_id(user_id)
    
    # Register blueprint
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    return login_manager
