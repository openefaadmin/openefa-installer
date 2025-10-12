#!/usr/bin/env python3
"""
BEC (Business Email Compromise) Detector
ENHANCED: Added domain-level whitelisting with FULL trust level implementation (0-5)
FIXED: Proper whitelist checking before impersonation detection
FIXED: Robust data type handling to prevent 'dict' object errors
UPDATED: Now checks ONLY authentication_aware.senders from menu entries (removed simple array)
NEW: Complete trust level graduated security system
IMPLEMENTED: Trust levels 0-5 with different security thresholds
ADDED: Comprehensive brand impersonation detection across multiple categories
"""
import sys
import json
import re
import datetime
import logging
from pathlib import Path

# Import comprehensive brand detection if available
try:
    from brand_impersonation_comprehensive import check_brand_impersonation as check_comprehensive_brand
    COMPREHENSIVE_BRAND_DETECTION = True
except ImportError:
    COMPREHENSIVE_BRAND_DETECTION = False

# Import typosquatting detection - DISABLED
# Typosquatting is now handled separately, not as part of BEC
try:
    from typosquatting_detector import check_typosquatting, get_typosquatting_score
    TYPOSQUATTING_DETECTION = False  # Explicitly disabled in BEC module
except ImportError:
    TYPOSQUATTING_DETECTION = False
    safe_log = lambda x: print(f"DEBUG: {x}", file=sys.stderr)
    safe_log("Warning: Typosquatting detector not available")

# Safe logging function
def safe_log(message, max_length=500):
    """Safe logging to stderr with length limit"""
    try:
        if isinstance(message, str) and len(message) > max_length:
            message = message[:max_length-3] + "..."
        print(f"DEBUG: {message}", file=sys.stderr)
    except:
        pass

# Load BEC configuration
def load_bec_config():
    """Load BEC configuration from JSON file"""
    config_path = Path("/opt/spacyserver/config/bec_config.json")
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        safe_log(f"BEC config file not found at {config_path}")
        return None
    except json.JSONDecodeError as e:
        safe_log(f"Error parsing BEC config: {e}")
        return None

def extract_domain_from_email(email):
    """Extract domain from email address"""
    try:
        if not email or '@' not in email:
            return ''
        # Handle email addresses in various formats
        email = str(email).strip().lower()
        # Remove any angle brackets that might be present
        email = email.strip('<>')
        domain = email.split('@')[-1]
        # Remove any trailing characters that might be present
        domain = re.sub(r'[<>\[\]()]', '', domain)
        return domain
    except Exception as e:
        safe_log(f"Error extracting domain from {email}: {e}")
        return ''

def check_authentication_requirements(auth_status, required_auth):
    """
    Check if authentication requirements are met
    
    Args:
        auth_status: Dictionary containing authentication results from email_filter.py
        required_auth: List of required authentication methods
        
    Returns:
        True if all requirements are met, False otherwise
    """
    if not required_auth:
        return True
    
    try:
        for auth_type in required_auth:
            if auth_type == 'internal_domain':
                # This will be handled by the calling function
                continue
            elif auth_type in ['spf', 'dkim', 'dmarc']:
                # Check if the authentication passed
                if auth_status.get(auth_type, '').lower() != 'pass':
                    safe_log(f"Authentication requirement not met: {auth_type} = {auth_status.get(auth_type, 'none')}")
                    return False
            else:
                safe_log(f"Unknown authentication type: {auth_type}")
        
        return True
    except Exception as e:
        safe_log(f"Error checking authentication requirements: {e}")
        return False

def is_internal_domain(domain, config):
    """Check if domain is internal to the organization"""
    try:
        if not domain or not config:
            return False
        
        # Check company domains
        company_domains = config.get('company_domains', [])
        
        # Check internal domains from authentication config
        internal_domains = config.get('authentication', {}).get(
            'requirements', {}
        ).get('internal_domain', {}).get('domains', [])
        
        all_internal = set(company_domains + internal_domains)
        return domain.lower() in [d.lower() for d in all_internal]
    except Exception as e:
        safe_log(f"Error checking internal domain {domain}: {e}")
        return False

def check_domain_whitelist(sender_email, auth_status, config):
    """
    ENHANCED: Check if sender domain is whitelisted with trust level support
    
    Args:
        sender_email: Sender's email address
        auth_status: Authentication status dictionary from email_filter.py
        config: BEC configuration
        
    Returns:
        Tuple of (is_whitelisted, bypass_reason, trust_level)
    """
    try:
        domain = extract_domain_from_email(sender_email)
        if not domain or not config:
            return False, None, 0
        
        # Check if whitelisted_domains section exists
        whitelisted_domains = config.get('whitelisted_domains', {})
        if not whitelisted_domains:
            return False, None, 0
        
        # Check authentication-aware domain whitelist
        auth_aware_domains = whitelisted_domains.get('authentication_aware', {})
        
        if domain in auth_aware_domains:
            domain_config = auth_aware_domains[domain]
            required_auth = domain_config.get('require_auth', [])
            trust_level = domain_config.get('trust_level', 0)  # NEW: Extract trust level
            
            safe_log(f"Checking domain {domain} with auth requirements: {required_auth}, trust level: {trust_level}")
            
            # Special handling for internal domains
            if 'internal_domain' in required_auth and is_internal_domain(domain, config):
                safe_log(f"Domain whitelisted: {domain} (internal, trust level {trust_level})")
                return True, f"Internal domain {domain} authenticated", trust_level
            
            # Check other authentication requirements
            if check_authentication_requirements(auth_status, required_auth):
                safe_log(f"Domain whitelisted: {domain} (auth passed, trust level {trust_level})")
                return True, f"Domain {domain} authentication requirements met", trust_level
            else:
                safe_log(f"Domain whitelist auth failed: {domain} (trust level {trust_level})")
                return False, f"Domain {domain} authentication requirements not met", 0
        
        # Check trusted no-auth domains (use with extreme caution)
        trusted_domains = whitelisted_domains.get('trusted_no_auth', {}).get('domains', [])
        
        if domain in [d.lower() for d in trusted_domains]:
            safe_log(f"Domain whitelisted without auth: {domain} (trust level 5 - no auth required)")
            return True, f"Domain {domain} in trusted no-auth list", 5  # Maximum trust for no-auth domains
        
        return False, None, 0
        
    except Exception as e:
        safe_log(f"Error checking domain whitelist for {sender_email}: {e}")
        return False, None, 0

def is_whitelisted_sender(sender_email, sender_name, config, auth_status=None):
    """
    UPDATED: Check if sender is whitelisted using ONLY authentication-aware whitelist
    REMOVED: Simple array checking (no longer part of OpenSpacyMenu)
    Returns tuple of (is_whitelisted, trust_level)
    """
    if not config:
        return False, 0

    whitelist = config.get('whitelist', {})

    # Check ONLY authentication-aware sender whitelist (from menu)
    if ('authentication_aware' in whitelist and 
        'senders' in whitelist['authentication_aware']):
        auth_senders = whitelist['authentication_aware']['senders']
        sender_email_lower = sender_email.lower().strip()
        
        for email_key in auth_senders.keys():
            if sender_email_lower == email_key.lower().strip():
                sender_config = auth_senders[email_key]
                required_auth = sender_config.get('require_auth', [])
                description = sender_config.get('description', 'No description')
                trust_level = sender_config.get('trust_level', 5)  # Default to max trust
                
                safe_log(f"Found {sender_email} in authentication-aware whitelist: {description}")
                
                # Check authentication requirements if provided
                if auth_status and required_auth:
                    if check_authentication_requirements(auth_status, required_auth):
                        safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} is whitelisted (auth-aware passed - trust level {trust_level})")
                        return True, trust_level
                    else:
                        safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} auth-aware whitelist failed authentication")
                        return False, 0
                else:
                    # No auth status provided or no auth required, trust the whitelist
                    safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} is whitelisted (auth-aware no auth check - trust level {trust_level})")
                    return True, trust_level

    # Check if sender domain is in company domains (existing functionality)
    if 'company_domains' in config:
        sender_domain = sender_email.split('@')[1].lower() if '@' in sender_email else ''
        if sender_domain in [d.lower() for d in config['company_domains']]:
            safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} is from company domain {sender_domain} (trust level 5)")
            return True, 5  # Company domains get maximum trust

    # Check trusted vendors (existing functionality)
    if 'trusted_vendors' in config:
        sender_domain = sender_email.split('@')[1].lower() if '@' in sender_email else ''
        if sender_domain in [d.lower() for d in config['trusted_vendors']]:
            safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} is from trusted vendor {sender_domain} (trust level 4)")
            return True, 4  # Trusted vendors get high trust

    # Check domain-level whitelist with trust levels
    if auth_status is not None:
        is_domain_whitelisted, whitelist_reason, trust_level = check_domain_whitelist(sender_email, auth_status, config)
        if is_domain_whitelisted:
            safe_log(f"Sender {sender_email[:50]}{'...' if len(sender_email) > 50 else ''} domain whitelisted: {whitelist_reason}")
            return True, trust_level

    return False, 0

def get_trust_level_adjustments(trust_level):
    """
    NEW: Get security adjustments based on trust level (0-5)
    
    Returns:
        Dictionary with adjustment parameters
    """
    adjustments = {
        0: {  # Default - Strictest
            'confidence_threshold_adjustment': 0.0,
            'financial_keyword_multiplier': 1.0,
            'urgency_multiplier': 1.0,
            'executive_impersonation_multiplier': 1.0,
            'bypass_financial_checks': False,
            'description': 'Default security - full detection'
        },
        1: {  # Minimal Trust
            'confidence_threshold_adjustment': 0.05,
            'financial_keyword_multiplier': 1.0,
            'urgency_multiplier': 1.0,
            'executive_impersonation_multiplier': 1.0,
            'bypass_financial_checks': False,
            'description': 'Minimal trust - slightly reduced sensitivity'
        },
        2: {  # Low Trust
            'confidence_threshold_adjustment': 0.1,
            'financial_keyword_multiplier': 0.8,
            'urgency_multiplier': 0.9,
            'executive_impersonation_multiplier': 1.0,
            'bypass_financial_checks': False,
            'description': 'Low trust - moderately reduced sensitivity'
        },
        3: {  # Medium Trust
            'confidence_threshold_adjustment': 0.15,
            'financial_keyword_multiplier': 0.6,
            'urgency_multiplier': 0.7,
            'executive_impersonation_multiplier': 0.9,
            'bypass_financial_checks': True,
            'description': 'Medium trust - reduced sensitivity, bypass financial'
        },
        4: {  # High Trust
            'confidence_threshold_adjustment': 0.2,
            'financial_keyword_multiplier': 0.3,
            'urgency_multiplier': 0.5,
            'executive_impersonation_multiplier': 0.7,
            'bypass_financial_checks': True,
            'description': 'High trust - significantly reduced sensitivity'
        },
        5: {  # Maximum Trust
            'confidence_threshold_adjustment': 0.3,
            'financial_keyword_multiplier': 0.1,
            'urgency_multiplier': 0.3,
            'executive_impersonation_multiplier': 0.5,
            'bypass_financial_checks': True,
            'description': 'Maximum trust - minimal detection (use sparingly)'
        }
    }
    
    return adjustments.get(trust_level, adjustments[0])

def check_vague_proposal_patterns(email_data, config, trust_level=0):
    """
    Check for vague proposal patterns that are common in BEC attempts
    ENHANCED: Now considers trust level adjustments

    Args:
        email_data: Dictionary containing email content and metadata
        config: BEC configuration settings
        trust_level: Trust level (0-5) for adjustments

    Returns:
        tuple: (confidence_score, risk_factors_list)
    """
    try:
        content = email_data.get('content', '').lower()
        subject = email_data.get('subject', '').lower()
        full_text = f"{content} {subject}"

        # Vague proposal patterns commonly used in BEC attacks
        vague_patterns = {
            'urgent_proposal': r'urgent\s+(?:business\s+)?proposal',
            'investment_opportunity': r'investment\s+opportunity',
            'business_partnership': r'business\s+(?:partnership|collaboration)',
            'confidential_deal': r'confidential\s+(?:business|deal|proposal)',
            'mutual_benefit': r'mutual\s+(?:benefit|interest)',
            'profitable_venture': r'profitable\s+(?:venture|business)',
            'immediate_response': r'(?:immediate|urgent)\s+response\s+(?:required|needed)',
            'time_sensitive': r'time\s+sensitive\s+(?:matter|proposal)',
            'exclusive_offer': r'exclusive\s+(?:offer|opportunity)',
            'limited_time': r'limited\s+time\s+offer',
            # Document phishing patterns
            'document_shared': r'document.{0,20}(?:has been|is)\s+shared',
            'review_document': r'(?:review|sign)\s+(?:the\s+)?document',
            'agreement_ready': r'agreement.{0,20}ready.{0,20}(?:for\s+)?(?:review|signature)',
            'contract_review': r'contract.{0,20}(?:ready|available).{0,20}(?:for\s+)?(?:review|signature)',
            'shared_folder': r'shared.{0,20}folder|folder.{0,20}shared',
            'click_to_view': r'click.{0,20}to.{0,20}(?:view|access|download)',
            'document_ready': r'document.{0,20}(?:is\s+)?ready.{0,20}(?:for\s+)?(?:your\s+)?review',
            'sign_asap': r'sign.{0,20}as.{0,20}soon.{0,20}as.{0,20}possible'
        }

        detected_patterns = []
        confidence_score = 0.0

        for pattern_name, pattern in vague_patterns.items():
            if re.search(pattern, full_text):
                detected_patterns.append(f"Vague proposal pattern: {pattern_name}")
                confidence_score += 0.15  # Each pattern adds 15% confidence

        # Additional scoring for multiple patterns
        if len(detected_patterns) > 2:
            confidence_score += 0.2  # Bonus for multiple vague patterns

        # NEW: Apply trust level adjustments
        adjustments = get_trust_level_adjustments(trust_level)
        if trust_level >= 3:  # Medium+ trust reduces vague proposal sensitivity
            confidence_score *= 0.7

        # Cap confidence at 1.0
        confidence_score = min(confidence_score, 1.0)

        if detected_patterns and trust_level > 0:
            safe_log(f"Vague proposal patterns detected (trust level {trust_level} adjustments applied)")

        return confidence_score, detected_patterns

    except Exception as e:
        safe_log(f"Error in check_vague_proposal_patterns: {e}")
        return 0.0, []

def is_subject_whitelisted(subject, config):
    """Check if subject is whitelisted"""
    if not config or 'whitelist' not in config or 'subjects' not in config['whitelist']:
        return False

    subject_lower = subject.lower().strip()
    for whitelisted_subject in config['whitelist']['subjects']:
        if whitelisted_subject.lower().strip() in subject_lower:
            safe_log(f"Subject contains whitelisted phrase: {whitelisted_subject}")
            return True

    return False

def extract_display_name(from_header):
    """Extract display name from email From header"""
    try:
        if '<' in from_header and '>' in from_header:
            # Format: "Display Name" <email@domain.com>
            display_part = from_header.split('<')[0].strip()
            return display_part.strip('"').strip("'").strip()
        elif '"' in from_header:
            # Format: "Display Name" email@domain.com
            match = re.search(r'"([^"]+)"', from_header)
            if match:
                return match.group(1).strip()
    except Exception as e:
        safe_log(f"Error extracting display name: {e}")
    return ''

def check_executive_impersonation(email_data, config, trust_level=0):
    """
    Check for executive impersonation - ENHANCED with trust level adjustments
    """
    if not config or 'executives' not in config:
        return 0.0, [], None

    try:
        # Safely extract data with type checking
        sender_email = email_data.get('from', '')
        if isinstance(sender_email, dict):
            sender_email = sender_email.get('email', '') or str(sender_email)
        sender_email = str(sender_email).lower().strip()

        display_name = email_data.get('display_name', '')
        if isinstance(display_name, dict):
            display_name = display_name.get('name', '') or str(display_name)
        display_name = str(display_name).strip()

        if not display_name:
            return 0.0, [], None

        impersonation_confidence = 0.0
        risk_factors = []
        impersonated_exec = None

        # Check against each executive
        for exec_email, exec_info in config['executives'].items():
            exec_name = exec_info.get('name', '')
            exec_title = exec_info.get('title', '')
            exec_aliases = exec_info.get('aliases', [])

            # Check if display name matches executive name
            display_name_lower = display_name.lower()
            exec_name_lower = exec_name.lower()

            # Exact name match
            if display_name_lower == exec_name_lower:
                # Check if the email address matches the executive's email
                if sender_email != exec_email.lower():
                    impersonation_confidence += 0.8
                    risk_factors.append(f"Display name impersonates {exec_name}")
                    impersonated_exec = exec_name

            # Partial name match (first name + last name)
            elif exec_name_lower in display_name_lower or display_name_lower in exec_name_lower:
                if sender_email != exec_email.lower():
                    impersonation_confidence += 0.6
                    risk_factors.append(f"Display name similar to {exec_name}")
                    impersonated_exec = exec_name

            # Check against executive titles and aliases
            for alias in exec_aliases:
                if alias.lower() in display_name_lower:
                    if sender_email != exec_email.lower():
                        impersonation_confidence += 0.5
                        risk_factors.append(f"Display name uses executive title: {alias}")
                        impersonated_exec = exec_name
                        break

        # NEW: Apply trust level adjustments
        adjustments = get_trust_level_adjustments(trust_level)
        impersonation_confidence *= adjustments['executive_impersonation_multiplier']

        if impersonation_confidence > 0 and trust_level > 0:
            safe_log(f"Executive impersonation detected (trust level {trust_level} adjustment: {adjustments['executive_impersonation_multiplier']})")

        return min(impersonation_confidence, 1.0), risk_factors, impersonated_exec

    except Exception as e:
        safe_log(f"Error in executive impersonation check: {e}")
        return 0.0, [f"Impersonation check error: {str(e)[:100]}"], None

def check_financial_keywords(email_data, config, trust_level=0):
    """Check for financial keywords that indicate BEC attempt - ENHANCED with trust level"""
    if not config or 'financial_keywords' not in config:
        return 0.0, []

    # NEW: Check if financial checks should be bypassed
    adjustments = get_trust_level_adjustments(trust_level)
    if adjustments['bypass_financial_checks']:
        safe_log(f"Financial keyword checks bypassed due to trust level {trust_level}")
        return 0.0, []

    try:
        # Safely extract content with type checking
        subject = email_data.get('subject', '')
        if isinstance(subject, dict):
            subject = str(subject)

        body = email_data.get('body', '')
        if isinstance(body, dict):
            body = str(body)

        content = f"{subject} {body}".lower()
        risk_factors = []
        confidence = 0.0

        for keyword in config['financial_keywords']:
            if keyword.lower() in content:
                confidence += 0.1
                risk_factors.append(f"Contains financial keyword: {keyword}")

        # NEW: Apply trust level adjustments
        confidence *= adjustments['financial_keyword_multiplier']

        if confidence > 0 and trust_level > 0:
            safe_log(f"Financial keywords detected (trust level {trust_level} adjustment: {adjustments['financial_keyword_multiplier']})")

        return min(confidence, 0.8), risk_factors

    except Exception as e:
        safe_log(f"Error in financial keywords check: {e}")
        return 0.0, [f"Financial check error: {str(e)[:100]}"]

def check_company_impersonation(email_data, config, trust_level=0):
    """
    Check for company/department impersonation attempts
    Detects external senders claiming to be from company IT, HR, etc.
    """
    if not config or 'company_impersonation' not in config:
        return 0.0, [], None
    
    try:
        # Extract sender information
        sender_email = email_data.get('from', '')
        if isinstance(sender_email, dict):
            sender_email = sender_email.get('email', '') or str(sender_email)
        sender_email = str(sender_email).lower().strip()
        
        display_name = email_data.get('display_name', '')
        if isinstance(display_name, dict):
            display_name = display_name.get('name', '') or str(display_name)
        display_name = str(display_name).strip()
        
        subject = email_data.get('subject', '')
        if isinstance(subject, dict):
            subject = str(subject)
        subject = str(subject).strip()
        
        # Get sender domain
        sender_domain = extract_domain_from_email(sender_email)
        
        # Get company configuration
        company_config = config['company_impersonation']
        company_names = company_config.get('company_names', [])
        protected_departments = company_config.get('protected_departments', [])
        company_domains = company_config.get('company_domains', [])
        
        if not company_names:
            return 0.0, [], None
        
        # Check if sender is from internal domain
        if sender_domain in [d.lower() for d in company_domains]:
            safe_log(f"Sender {sender_domain} is from internal domain, skipping company impersonation check")
            return 0.0, [], None
        
        risk_factors = []
        confidence = 0.0
        impersonated_entity = None
        
        # Check display name and subject for company+department combinations
        check_text = f"{display_name} {subject}".lower()
        
        for company_name in company_names:
            company_lower = company_name.lower()
            if company_lower in check_text:
                # Found company name, check for department
                for dept in protected_departments:
                    dept_lower = dept.lower()
                    if dept_lower in check_text:
                        # External sender claiming to be company department!
                        confidence = 0.9  # High confidence
                        impersonated_entity = f"{company_name} {dept}"
                        risk_factors.append(f"External sender claiming to be '{company_name} {dept}'")
                        risk_factors.append(f"Sender domain ({sender_domain}) is not a company domain")
                        safe_log(f"COMPANY IMPERSONATION DETECTED: {impersonated_entity} from {sender_email}")
                        break
                
                # Even without department, flag if using company name suspiciously
                if confidence == 0 and any(word in check_text for word in ['support', 'team', 'department', 'administrator', 'admin']):
                    confidence = 0.7
                    impersonated_entity = company_name
                    risk_factors.append(f"External sender using company name '{company_name}' suspiciously")
                    risk_factors.append(f"Sender domain ({sender_domain}) is not a company domain")
        
        # Check for common scam patterns if configured
        if 'scam_patterns' in company_config:
            scam_patterns = company_config['scam_patterns']
            for pattern_type, patterns in scam_patterns.items():
                if pattern_type == 'subjects':
                    for pattern in patterns:
                        if pattern.lower() in subject.lower():
                            confidence = max(confidence, 0.6)
                            risk_factors.append(f"Subject contains known scam pattern: '{pattern}'")
        
        # Apply trust level adjustments if needed
        if trust_level >= 3:
            confidence *= 0.5  # Reduce confidence for trusted senders
            safe_log(f"Company impersonation confidence reduced due to trust level {trust_level}")
        
        return confidence, risk_factors, impersonated_entity
        
    except Exception as e:
        safe_log(f"Error in company impersonation check: {e}")
        return 0.0, [f"Company impersonation check error: {str(e)[:100]}"], None

def check_financial_institution_impersonation(email_data, config, trust_level=0):
    """
    Check if email is impersonating a financial institution
    Detects when sender claims to be from a bank but domain doesn't match
    """
    try:
        if not config or 'financial_institution_impersonation' not in config:
            return 0.0, []
        
        # Extract sender info
        sender_email = email_data.get('from', '')
        if isinstance(sender_email, dict):
            sender_email = sender_email.get('email', '') or str(sender_email)
        sender_email = str(sender_email).lower().strip()
        
        display_name = email_data.get('display_name', '')
        if isinstance(display_name, dict):
            display_name = display_name.get('name', '') or str(display_name)
        display_name = str(display_name).lower().strip()
        
        subject = email_data.get('subject', '').lower()
        content = email_data.get('content', '').lower()
        
        # Extract domain from sender email
        sender_domain = extract_domain_from_email(sender_email)
        
        # Get list of legitimate financial institutions
        legitimate_institutions = config['financial_institution_impersonation'].get('legitimate_institutions', [])
        
        risk_factors = []
        confidence = 0.0
        
        # Check if display name or subject contains financial institution names
        for institution in legitimate_institutions:
            institution_lower = institution.lower()
            
            # Check if institution name appears in display name or subject
            if institution_lower in display_name or institution_lower in subject:
                # Now check if the sender domain is legitimate for this institution
                is_legitimate_domain = False
                
                # Common legitimate domains for financial institutions
                legitimate_domains = {
                    'capital one': ['capitalone.com', 'capitalonebank.com'],
                    'capitalone': ['capitalone.com', 'capitalonebank.com'],
                    'chase': ['chase.com', 'jpmchase.com', 'jpmorgan.com'],
                    'bank of america': ['bankofamerica.com', 'bofa.com'],
                    'wells fargo': ['wellsfargo.com', 'wf.com'],
                    'citibank': ['citi.com', 'citibank.com', 'citigroup.com'],
                    'us bank': ['usbank.com'],
                    'american express': ['americanexpress.com', 'aexp.com'],
                    'discover': ['discover.com', 'discovercard.com'],
                    'paypal': ['paypal.com'],
                }
                
                # Check if sender domain matches legitimate domains for this institution
                if institution_lower in legitimate_domains:
                    for legit_domain in legitimate_domains[institution_lower]:
                        if sender_domain == legit_domain or sender_domain.endswith('.' + legit_domain):
                            is_legitimate_domain = True
                            break
                
                if not is_legitimate_domain:
                    # This is likely impersonation!
                    confidence = 0.95  # Very high confidence
                    risk_factors.append(f"Claims to be '{institution}' but sending from '{sender_domain}'")
                    risk_factors.append(f"Financial institution impersonation detected")
                    
                    # Check for common phishing keywords in subject/content
                    phishing_keywords = [
                        'verify', 'suspended', 'restricted', 'locked', 'expired',
                        'update', 'confirm', 'secure', 'alert', 'urgent',
                        'click here', 'act now', 'immediate action'
                    ]
                    
                    for keyword in phishing_keywords:
                        if keyword in subject or keyword in content[:1000]:
                            confidence = min(1.0, confidence + 0.05)
                            risk_factors.append(f"Contains phishing keyword: '{keyword}'")
                            break
                    
                    safe_log(f"FINANCIAL IMPERSONATION DETECTED: {institution} from {sender_domain}")
                    break
        
        # Apply trust level adjustments
        if trust_level >= 3:
            confidence *= 0.8  # Slightly reduce for trusted senders
        
        return confidence, risk_factors
        
    except Exception as e:
        safe_log(f"Error in financial institution impersonation check: {e}")
        return 0.0, []

def check_urgency_indicators(email_data, config, trust_level=0):
    """Check for urgency indicators - ENHANCED with trust level"""
    if not config or 'urgency_multipliers' not in config:
        return 0.0, []

    try:
        # Safely extract content with type checking
        subject = email_data.get('subject', '')
        if isinstance(subject, dict):
            subject = str(subject)

        body = email_data.get('body', '')
        if isinstance(body, dict):
            body = str(body)

        content = f"{subject} {body}".lower()
        risk_factors = []
        confidence = 0.0

        for urgency_word, multiplier in config['urgency_multipliers'].items():
            if urgency_word.lower() in content:
                confidence += 0.1 * multiplier
                risk_factors.append(f"Contains urgency indicator: {urgency_word}")

        # NEW: Apply trust level adjustments
        adjustments = get_trust_level_adjustments(trust_level)
        confidence *= adjustments['urgency_multiplier']

        if confidence > 0 and trust_level > 0:
            safe_log(f"Urgency indicators detected (trust level {trust_level} adjustment: {adjustments['urgency_multiplier']})")

        return min(confidence, 0.6), risk_factors

    except Exception as e:
        safe_log(f"Error in urgency indicators check: {e}")
        return 0.0, [f"Urgency check error: {str(e)[:100]}"]

def check_bec(email_data):
    """
    Main BEC detection function
    ENHANCED: Now supports complete trust level graduated security (0-5)
    FIXED: Robust handling of email_data dictionary to prevent 'dict' object errors
    UPDATED: Now works ONLY with menu entries via authentication_aware.senders
    """
    config = load_bec_config()
    if not config or not config.get('enabled', False):
        return {
            'bec_detected': False,
            'bec_confidence': 0.0,
            'bec_type': 'none',
            'bec_risk_factors': [],
            'impersonated_executive': None,
            'trust_level': 0
        }

    # CRITICAL FIX: Safely extract sender information with proper type checking
    try:
        # Handle cases where email_data values might be dicts or other objects
        sender_email = email_data.get('from', '')
        if isinstance(sender_email, dict):
            # If it's a dict, try to extract email from common keys
            sender_email = sender_email.get('email', '') or sender_email.get('address', '') or str(sender_email)
        elif not isinstance(sender_email, str):
            sender_email = str(sender_email)

        sender_name = email_data.get('display_name', '')
        if isinstance(sender_name, dict):
            sender_name = sender_name.get('name', '') or str(sender_name)
        elif not isinstance(sender_name, str):
            sender_name = str(sender_name)

        # IMMEDIATE CHECK: Skip BEC for company domain emails
        sender_domain = sender_email.split('@')[1].lower() if '@' in sender_email else ''
        company_domains = config.get('company_domains', [])
        if sender_domain and sender_domain in [d.lower() for d in company_domains]:
            safe_log(f"Sender from company domain {sender_domain} - bypassing BEC checks entirely")
            return {
                'bec_detected': False,
                'bec_confidence': 0.0,
                'bec_type': 'internal_company_email',
                'bec_risk_factors': [f'Internal company email from {sender_domain}'],
                'impersonated_executive': None,
                'trust_level': 5
            }

        subject = email_data.get('subject', '')
        if isinstance(subject, dict):
            subject = str(subject)
        elif not isinstance(subject, str):
            subject = str(subject)

        # Ensure all are strings and properly formatted
        sender_email = str(sender_email).strip().lower()
        sender_name = str(sender_name).strip()
        subject = str(subject).strip()

        # NEW: Extract authentication status for domain whitelisting
        auth_status = {
            'spf': 'pass' if email_data.get('spf_pass', False) else 'fail',
            'dkim': 'pass' if email_data.get('dkim_valid', False) else 'fail',
            'dmarc': 'pass' if email_data.get('dmarc_pass', False) else 'fail'
        }

        safe_log(f"BEC check - Sender: {sender_email[:50]}{'...' if len(sender_email) > 50 else ''}")

    except Exception as e:
        safe_log(f"Error extracting BEC data: {e}")
        # Return safe defaults if extraction fails
        return {
            'bec_detected': False,
            'bec_confidence': 0.0,
            'bec_type': 'extraction_error',
            'bec_risk_factors': [f'Data extraction error: {str(e)[:100]}'],
            'impersonated_executive': None,
            'trust_level': 0
        }

    # ENHANCED: Check whitelist with trust level support
    is_whitelisted, trust_level = is_whitelisted_sender(sender_email, sender_name, config, auth_status)
    
    if is_whitelisted:
        safe_log(f"Sender {sender_email[:30]}{'...' if len(sender_email) > 30 else ''} is whitelisted with trust level {trust_level}")
        
        # NEW: Trust level 5 (maximum) bypasses BEC detection entirely
        if trust_level >= 5:
            return {
                'bec_detected': False,
                'bec_confidence': 0.0,
                'bec_type': 'maximum_trust_whitelist',
                'bec_risk_factors': [f'Sender has maximum trust level {trust_level}'],
                'impersonated_executive': None,
                'trust_level': trust_level
            }

    # Check if subject is whitelisted
    if is_subject_whitelisted(subject, config):
        safe_log(f"Subject is whitelisted - bypassing BEC detection")
        return {
            'bec_detected': False,
            'bec_confidence': 0.0,
            'bec_type': 'whitelisted_subject',
            'bec_risk_factors': ['Subject is whitelisted'],
            'impersonated_executive': None,
            'trust_level': trust_level
        }

    # Initialize detection results
    total_confidence = 0.0
    all_risk_factors = []
    bec_type = 'none'
    impersonated_executive = None
    headers_to_add = {}  # Initialize headers dictionary early for brand detection

    # NEW: Get trust level adjustments
    adjustments = get_trust_level_adjustments(trust_level)
    safe_log(f"Running BEC checks with trust level {trust_level}: {adjustments['description']}")

    try:
        # TYPOSQUATTING DETECTION REMOVED FROM BEC MODULE
        # Typosquatting is now handled separately by typosquatting_detector.py
        # This prevents false positives like Delta Airlines being marked as Facebook typosquatting
        skip_typosquatting = True  # Always skip in BEC module
        
        # Check if domain should bypass typosquatting checks
        sender_domain = extract_domain_from_email(sender_email)
        if sender_domain and config:
            # Check domain-level bypass
            auth_aware_domains = config.get('whitelisted_domains', {}).get('authentication_aware', {})
            if sender_domain in auth_aware_domains:
                domain_config = auth_aware_domains[sender_domain]
                if domain_config.get('bypass_typosquatting', False) or domain_config.get('bypass_bec_checks', False):
                    skip_typosquatting = True
                    safe_log(f"Skipping typosquatting check for whitelisted domain: {sender_domain}")
            
            # Check sender-level bypass
            whitelist = config.get('whitelist', {})
            if 'authentication_aware' in whitelist and 'senders' in whitelist['authentication_aware']:
                auth_senders = whitelist['authentication_aware']['senders']
                sender_email_lower = sender_email.lower().strip()
                for email_key in auth_senders.keys():
                    if sender_email_lower == email_key.lower().strip():
                        sender_config = auth_senders[email_key]
                        if sender_config.get('bypass_typosquatting', False) or sender_config.get('bypass_bec_checks', False):
                            skip_typosquatting = True
                            safe_log(f"Skipping typosquatting check for whitelisted sender: {sender_email}")
                            break
        
        # Typosquatting check disabled in BEC - handled separately
        if False:  # Was: TYPOSQUATTING_DETECTION and not skip_typosquatting
            # Extract domain from sender email
            if sender_domain:
                typo_result = check_typosquatting(sender_domain, sender_name)
                if typo_result['is_typosquatting']:
                    typo_confidence = typo_result['confidence']
                    # Add significant confidence for typosquatting
                    total_confidence += typo_confidence * 0.9  # High weight for typosquatting
                    all_risk_factors.extend(typo_result['risk_factors'])
                    
                    # Set BEC type based on typosquatting
                    if bec_type == 'none' or typo_confidence >= 0.90:
                        bec_type = f"{typo_result['matched_brand']}_typosquatting"
                    
                    # Add typosquatting score to headers
                    headers_to_add['X-Typosquatting-Detected'] = 'true'
                    headers_to_add['X-Typosquatting-Brand'] = typo_result['matched_brand']
                    headers_to_add['X-Typosquatting-Score'] = str(get_typosquatting_score(typo_result))
                    headers_to_add['X-Typosquatting-Confidence'] = f"{typo_confidence:.3f}"
                    
                    safe_log(f"Typosquatting detected: {sender_domain} impersonating {typo_result['legitimate_domain']} "
                            f"(brand: {typo_result['matched_brand']}, confidence: {typo_confidence:.2%})")
        
        # Check for executive impersonation (with trust level adjustments)
        exec_confidence, exec_factors, exec_name = check_executive_impersonation(email_data, config, trust_level)
        if exec_confidence > 0:
            total_confidence += exec_confidence
            all_risk_factors.extend(exec_factors)
            bec_type = 'executive_impersonation'
            impersonated_executive = exec_name

        # Check for vague proposal patterns (with trust level adjustments)
        vague_confidence, vague_factors = check_vague_proposal_patterns(email_data, config, trust_level)
        if vague_confidence > 0:
            total_confidence += vague_confidence
            all_risk_factors.extend(vague_factors)
            if bec_type == 'none':
                bec_type = 'vague_proposal_scam'

        # Check for financial keywords (with trust level adjustments)
        fin_confidence, fin_factors = check_financial_keywords(email_data, config, trust_level)
        if fin_confidence > 0:
            total_confidence += fin_confidence * 0.5  # Weight financial keywords less
            all_risk_factors.extend(fin_factors)
            if bec_type == 'none':
                bec_type = 'financial_fraud'

        # Check for urgency indicators (with trust level adjustments)
        urgency_confidence, urgency_factors = check_urgency_indicators(email_data, config, trust_level)
        if urgency_confidence > 0:
            total_confidence += urgency_confidence * 0.3  # Weight urgency even less
            all_risk_factors.extend(urgency_factors)
            if bec_type == 'none':
                bec_type = 'urgency_scam'
        
        # Check for comprehensive brand impersonation if available
        if COMPREHENSIVE_BRAND_DETECTION:
            brand_result = check_comprehensive_brand(email_data)
            if brand_result.get('is_impersonation', False):
                brand_confidence = brand_result.get('confidence', 0)
                total_confidence += brand_confidence
                all_risk_factors.extend(brand_result.get('risk_factors', []))
                if bec_type == 'none' or brand_confidence >= 0.9:
                    bec_type = f"{brand_result.get('brand_category', 'brand')}_impersonation"
                # Add any headers from brand detection
                if 'headers_to_add' in brand_result:
                    headers_to_add.update(brand_result['headers_to_add'])
                safe_log(f"Brand impersonation detected: {brand_result.get('brand_detected')} ({brand_result.get('brand_category')})")
        else:
            # Fallback to original financial institution check if comprehensive module not available
            fin_inst_confidence, fin_inst_factors = check_financial_institution_impersonation(email_data, config, trust_level)
            if fin_inst_confidence > 0:
                total_confidence += fin_inst_confidence
                all_risk_factors.extend(fin_inst_factors)
                if bec_type == 'none' or fin_inst_confidence >= 0.9:  # Override if very high confidence
                    bec_type = 'financial_institution_impersonation'
        
        # Check for company/department impersonation (NEW)
        company_confidence, company_factors, company_entity = check_company_impersonation(email_data, config, trust_level)
        if company_confidence > 0:
            total_confidence += company_confidence
            all_risk_factors.extend(company_factors)
            if bec_type == 'none' or company_confidence >= 0.9:  # Override if high confidence
                bec_type = 'company_impersonation'
                if company_entity:
                    impersonated_executive = company_entity  # Store impersonated entity

    except Exception as e:
        safe_log(f"Error during BEC analysis: {e}")
        all_risk_factors.append(f"Analysis error: {str(e)[:100]}")

    # Cap total confidence at 1.0
    total_confidence = min(total_confidence, 1.0)

    # NEW: Apply trust level threshold adjustments
    base_threshold = config.get('confidence_threshold', 0.7)
    adjusted_threshold = base_threshold + adjustments['confidence_threshold_adjustment']
    bec_detected = total_confidence >= adjusted_threshold

    safe_log(f"BEC Detection Complete - Detected: {bec_detected}, Confidence: {total_confidence:.3f}, "
             f"Threshold: {adjusted_threshold:.3f} (base: {base_threshold:.3f} + trust adjustment: {adjustments['confidence_threshold_adjustment']:.3f}), "
             f"Type: {bec_type}, Trust Level: {trust_level}")
    
    if all_risk_factors:
        safe_log(f"BEC Risk Factors: {all_risk_factors[:3]}")  # Limit log output

    # Add whitelist and trust level headers if whitelisted
    if is_whitelisted and trust_level > 0:
        headers_to_add['X-SpaCy-Whitelisted'] = 'true'
        headers_to_add['X-SpaCy-Trust-Level'] = str(trust_level)
        headers_to_add['X-SpaCy-Whitelist-Reason'] = adjustments['description']
    
    # Add BEC detection headers
    headers_to_add['X-BEC-Detected'] = 'true' if bec_detected else 'false'
    headers_to_add['X-BEC-Confidence'] = f"{total_confidence:.3f}"
    headers_to_add['X-BEC-Type'] = bec_type
    
    return {
        'bec_detected': bec_detected,
        'bec_confidence': total_confidence,
        'bec_type': bec_type,
        'bec_risk_factors': all_risk_factors,
        'impersonated_executive': impersonated_executive,
        'trust_level': trust_level,
        'confidence_threshold_used': adjusted_threshold,
        'trust_level_adjustments': adjustments['description'],
        'headers_to_add': headers_to_add
    }

# For backward compatibility
def detect_bec(email_data):
    """Alias for check_bec function"""
    return check_bec(email_data)

# ENHANCED: Utility function for managing domain whitelist with trust levels
def add_domain_to_whitelist(domain, auth_requirements=None, trust_level=0, bypass_financial=False, description=""):
    """
    ENHANCED: Utility function to add a domain to the whitelist with trust level support

    Args:
        domain: Domain to whitelist (e.g., 'example.com')
        auth_requirements: List of required auth methods ['spf', 'dkim', 'dmarc'] or None for no auth
        trust_level: Trust level 0-5 (0=strictest, 5=most lenient)
        bypass_financial: Whether to bypass financial keyword checks
        description: Description for audit purposes
    """
    config_path = Path("/opt/spacyserver/config/bec_config.json")

    try:
        # Validate trust level
        if not isinstance(trust_level, int) or trust_level < 0 or trust_level > 5:
            safe_log(f"Invalid trust level {trust_level}. Must be 0-5. Using default 0.")
            trust_level = 0

        # Load existing config
        config = load_bec_config()
        if not config:
            safe_log("Could not load BEC config")
            return False

        # Ensure structure exists
        if 'whitelisted_domains' not in config:
            config['whitelisted_domains'] = {
                'authentication_aware': {},
                'trusted_no_auth': {'domains': [], 'warning': 'Use with extreme caution'}
            }

        if auth_requirements:
            # Add to authentication-aware whitelist with trust level
            config['whitelisted_domains']['authentication_aware'][domain] = {
                'require_auth': auth_requirements,
                'trust_level': trust_level,  # NEW: Trust level support
                'description': description or f"Domain {domain} - trust level {trust_level}",
                'bypass_financial_checks': bypass_financial or trust_level >= 3  # Auto-enable for trust 3+
            }
            safe_log(f"Added {domain} to authentication-aware whitelist with trust level {trust_level}")
        else:
            # Add to no-auth whitelist (trust level 5 - not recommended)
            if domain not in config['whitelisted_domains']['trusted_no_auth']['domains']:
                config['whitelisted_domains']['trusted_no_auth']['domains'].append(domain)
            safe_log(f"Added {domain} to no-auth whitelist (trust level 5 - not recommended)")

        # Save updated config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)

        safe_log(f"Configuration updated successfully for domain: {domain} (trust level: {trust_level})")
        return True

    except Exception as e:
        safe_log(f"Error updating configuration: {e}")
        return False

def list_whitelisted_domains():
    """
    NEW: Utility function to list all whitelisted domains with their trust levels
    """
    config = load_bec_config()
    if not config:
        safe_log("Could not load BEC config")
        return

    print("=== Whitelisted Domains ===", file=sys.stderr)
    
    # Authentication-aware domains
    auth_aware = config.get('whitelisted_domains', {}).get('authentication_aware', {})
    if auth_aware:
        print("Authentication-Aware Domains:", file=sys.stderr)
        for domain, settings in auth_aware.items():
            trust_level = settings.get('trust_level', 0)
            auth_req = settings.get('require_auth', [])
            desc = settings.get('description', 'No description')
            print(f"  {domain}: Trust Level {trust_level}, Auth: {auth_req}, Desc: {desc}", file=sys.stderr)
    
    # No-auth domains
    no_auth = config.get('whitelisted_domains', {}).get('trusted_no_auth', {}).get('domains', [])
    if no_auth:
        print("No-Auth Domains (Trust Level 5):", file=sys.stderr)
        for domain in no_auth:
            print(f"  {domain}: Trust Level 5 (No authentication required)", file=sys.stderr)
    
    # Legacy whitelists
    company_domains = config.get('company_domains', [])
    if company_domains:
        print("Company Domains (Trust Level 5):", file=sys.stderr)
        for domain in company_domains:
            print(f"  {domain}: Trust Level 5 (Company domain)", file=sys.stderr)
    
    trusted_vendors = config.get('trusted_vendors', [])
    if trusted_vendors:
        print("Trusted Vendors (Trust Level 4):", file=sys.stderr)
        for domain in trusted_vendors:
            print(f"  {domain}: Trust Level 4 (Trusted vendor)", file=sys.stderr)

# For testing the enhanced functionality
if __name__ == "__main__":
    # Test the enhanced BEC detector with trust levels
    safe_log("Enhanced BEC Detector with Authentication-Aware Only Implementation - Testing")

    # Test email data
    test_email = {
        'from': 'scottabarbour@gmail.com',
        'display_name': 'Scott Barbour',
        'subject': 'Test message',
        'body': 'This is a test message',
        'spf_pass': True,
        'dkim_valid': True,
        'dmarc_pass': True
    }

    result = check_bec(test_email)
    safe_log(f"Test result: {result}")
    
    # Test domain listing
    list_whitelisted_domains()
