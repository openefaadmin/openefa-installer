"""
Security Validators for OpenEFA
Provides input validation to prevent SQL injection and other attacks
"""

import re
from flask import abort
import logging

logger = logging.getLogger(__name__)

def validate_email(email):
    """
    Validate email address format to prevent injection

    Args:
        email: Email address to validate

    Returns:
        str: Validated email address

    Raises:
        ValueError: If email format is invalid
    """
    if not email or not isinstance(email, str):
        raise ValueError("Email must be a non-empty string")

    # RFC 5322 simplified pattern
    pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'

    if not re.match(pattern, email):
        logger.warning(f"Invalid email format rejected: {email[:20]}...")
        raise ValueError("Invalid email format")

    # Check for SQL injection attempts
    sql_keywords = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP"]
    email_upper = email.upper()

    for keyword in sql_keywords:
        if keyword.upper() in email_upper:
            logger.error(f"Potential SQL injection attempt in email: {email[:20]}...")
            raise ValueError(f"Invalid characters in email")

    # Length check
    if len(email) > 255:
        raise ValueError("Email too long")

    return email

def validate_domain(domain):
    """
    Validate domain name format to prevent injection

    Args:
        domain: Domain name to validate

    Returns:
        str: Validated domain name (lowercase)

    Raises:
        ValueError: If domain format is invalid
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain must be a non-empty string")

    domain = domain.lower().strip()

    # RFC 1035 domain name pattern
    pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'

    if not re.match(pattern, domain):
        logger.warning(f"Invalid domain format rejected: {domain}")
        raise ValueError("Invalid domain format")

    # Check for SQL injection attempts
    sql_chars = ["'", '"', ";", "--", "/*", "*/", " OR ", " AND "]
    for char in sql_chars:
        if char in domain:
            logger.error(f"Potential SQL injection attempt in domain: {domain}")
            raise ValueError("Invalid characters in domain")

    # Length check
    if len(domain) > 253:
        raise ValueError("Domain name too long")

    # Check TLD exists
    if '.' not in domain:
        raise ValueError("Domain must have a TLD")

    return domain

def validate_email_list(emails):
    """
    Validate a list of email addresses

    Args:
        emails: List of email addresses

    Returns:
        list: List of validated email addresses
    """
    if not isinstance(emails, list):
        raise ValueError("emails must be a list")

    validated = []
    for email in emails:
        try:
            validated.append(validate_email(email))
        except ValueError as e:
            logger.warning(f"Invalid email in list: {str(e)}")
            # Skip invalid emails rather than failing
            continue

    return validated

def sanitize_sql_like_pattern(pattern):
    """
    Sanitize a LIKE pattern to prevent SQL injection

    Args:
        pattern: LIKE pattern string

    Returns:
        str: Sanitized pattern
    """
    if not pattern or not isinstance(pattern, str):
        raise ValueError("Pattern must be a non-empty string")

    # Escape SQL special characters
    # Note: % and _ are valid LIKE wildcards
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "\\"]

    for char in dangerous_chars:
        if char in pattern:
            logger.warning(f"Dangerous character in LIKE pattern: {char}")
            pattern = pattern.replace(char, "")

    return pattern

def validate_date_string(date_str):
    """
    Validate date string format (YYYY-MM-DD)

    Args:
        date_str: Date string to validate

    Returns:
        str: Validated date string

    Raises:
        ValueError: If date format is invalid
    """
    if not date_str or not isinstance(date_str, str):
        raise ValueError("Date must be a non-empty string")

    # Strict YYYY-MM-DD format
    pattern = r'^\d{4}-\d{2}-\d{2}$'

    if not re.match(pattern, date_str):
        logger.warning(f"Invalid date format rejected: {date_str}")
        raise ValueError("Invalid date format (use YYYY-MM-DD)")

    # Validate ranges
    year, month, day = date_str.split('-')
    year, month, day = int(year), int(month), int(day)

    if year < 1900 or year > 2100:
        raise ValueError("Year out of range")
    if month < 1 or month > 12:
        raise ValueError("Month out of range")
    if day < 1 or day > 31:
        raise ValueError("Day out of range")

    return date_str

def get_user_email_filter_conditions(user, user_aliases=None, authorized_domains=None, hosted_domains=None):
    """
    Generate SQL WHERE conditions for filtering emails based on user role and permissions.

    This ensures consistent permission enforcement across email lists, reports, and exports.

    Args:
        user: User object with role and email
        user_aliases: List of user's managed email aliases (for client role)
        authorized_domains: List of domains user is authorized to access (for non-admin)
        hosted_domains: List of all hosted domains (for admin)

    Returns:
        dict: {
            'where_clause': SQL WHERE clause string (e.g., "recipients LIKE '%@domain.com%'"),
            'description': Human-readable description of what user can see
        }

    Raises:
        ValueError: If validation fails or user has no access
    """
    conditions = []
    description = ""

    # Admin sees everything in hosted domains
    if hasattr(user, 'is_admin') and user.is_admin():
        if not hosted_domains:
            raise ValueError("No hosted domains available for admin")

        # Validate hosted domains
        safe_hosted_domains = []
        for domain in hosted_domains:
            try:
                safe_hosted_domains.append(validate_domain(domain))
            except ValueError as e:
                logger.warning(f"Invalid hosted domain for admin: {e}")
                continue

        if safe_hosted_domains:
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in safe_hosted_domains]
            conditions.append(f"({' OR '.join(domain_conditions)})")
            description = f"All emails for {len(safe_hosted_domains)} hosted domains"
        else:
            raise ValueError("No valid hosted domains for admin")

    # Client role: only their own emails and aliases
    elif user.role == 'client':
        # Validate user email
        safe_user_email = validate_email(user.email)

        # Build conditions for client
        user_conditions = [f"sender = '{safe_user_email}'"]
        user_conditions.append(f"recipients LIKE '%{safe_user_email}%'")

        # Add managed aliases
        if user_aliases:
            safe_aliases = validate_email_list(user_aliases)
            for alias in safe_aliases:
                user_conditions.append(f"recipients LIKE '%{alias}%'")

            description = f"Emails for {safe_user_email} and {len(safe_aliases)} alias(es)"
        else:
            description = f"Emails for {safe_user_email}"

        conditions.append(f"({' OR '.join(user_conditions)})")

    # Domain admin and other roles: authorized domains
    else:
        if not authorized_domains:
            raise ValueError(f"User {user.email} has no authorized domains")

        # Validate authorized domains
        safe_domains = []
        for domain in authorized_domains:
            try:
                safe_domains.append(validate_domain(domain))
            except ValueError as e:
                logger.warning(f"Invalid authorized domain for user {user.id}: {e}")
                continue

        if safe_domains:
            domain_conditions = [f"recipients LIKE '%@{domain}%'" for domain in safe_domains]
            conditions.append(f"({' OR '.join(domain_conditions)})")
            description = f"All emails for {len(safe_domains)} authorized domain(s)"
        else:
            raise ValueError(f"No valid authorized domains for user {user.email}")

    if not conditions:
        raise ValueError("No filter conditions could be generated")

    return {
        'where_clause': ' OR '.join(conditions) if len(conditions) > 1 else conditions[0],
        'description': description
    }

# Convenience function for Flask routes
def validate_or_abort(validator_func, value, error_message=None):
    """
    Validate a value or abort the request with 400 Bad Request

    Args:
        validator_func: Validation function to call
        value: Value to validate
        error_message: Custom error message (optional)

    Returns:
        Validated value
    """
    try:
        return validator_func(value)
    except ValueError as e:
        msg = error_message or str(e)
        logger.error(f"Validation failed: {msg}")
        abort(400, description=msg)
