#!/usr/bin/env python3
"""
Enhanced Thread Awareness Module for SpaCy Email Filter
Implements database-backed thread verification with email alias recognition

This module provides robust thread analysis by:
1. Verifying thread continuity through database lookups
2. Recognizing email aliases and mapping them to primary accounts
3. Tracking internal user participation across all aliases
4. Assigning trust scores based on conversation history
5. Preventing thread hijacking and spoofing
"""

import re
import json
import os
from typing import Dict, List, Optional, Set, Tuple
from email.message import EmailMessage
from datetime import datetime, timedelta
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from modules.email_database import EmailDatabaseHandler, SpacyAnalysis
    from sqlalchemy import text, and_, or_, func
except ImportError:
    EmailDatabaseHandler = None
    SpacyAnalysis = None

def safe_log(message: str, level: str = "INFO"):
    """Safe logging function"""
    if level in ["ERROR", "WARNING", "DEBUG"]:
        print(f"[THREAD-{level}] {message}", flush=True)

def extract_email_address(email_string: str) -> str:
    """Extract email address from a full email string"""
    if not email_string:
        return ''
    if '<' in email_string and '>' in email_string:
        return email_string.split('<')[1].split('>')[0].lower().strip()
    return email_string.strip().lower()

def normalize_subject(subject: str) -> str:
    """Normalize subject by removing Re:, Fwd:, etc."""
    if not subject:
        return ''
    # Remove common reply/forward prefixes
    pattern = r'^(?:Re:|RE:|Fwd:|FW:|Fw:|\[.*?\])\s*'
    normalized = re.sub(pattern, '', subject, flags=re.IGNORECASE)
    # Remove multiple occurrences
    while re.match(pattern, normalized):
        normalized = re.sub(pattern, '', normalized, flags=re.IGNORECASE)
    return normalized.strip()

def extract_message_ids(header_value: str) -> List[str]:
    """Extract message IDs from References or In-Reply-To headers"""
    if not header_value:
        return []
    # Extract all message IDs (format: <id@domain>)
    ids = re.findall(r'<[^>]+>', header_value)
    return [id.strip() for id in ids]

class AliasManager:
    """Manages email aliases and their relationships"""
    
    def __init__(self, config_path: str = "/opt/spacyserver/config/alias_mappings.json"):
        """Initialize alias manager with configuration"""
        self.alias_to_primary = {}
        self.primary_to_aliases = {}
        self.internal_domains = set()
        self.load_config(config_path)
    
    def load_config(self, config_path: str):
        """Load alias mappings from configuration file"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Load internal domains
                self.internal_domains = set(config.get('internal_domains', []))
                
                # Build alias mappings
                for primary_email, account_info in config.get('primary_accounts', {}).items():
                    primary = primary_email.lower()
                    aliases = account_info.get('aliases', [])
                    
                    # Map primary to its aliases
                    self.primary_to_aliases[primary] = set([a.lower() for a in aliases])
                    
                    # Map each alias to its primary
                    for alias in aliases:
                        self.alias_to_primary[alias.lower()] = primary
                    
                    # Also map primary to itself
                    self.alias_to_primary[primary] = primary
                
                safe_log(f"Loaded {len(self.alias_to_primary)} alias mappings")
            else:
                safe_log(f"Alias config not found at {config_path}, using defaults", "WARNING")
                # Default internal domains if config not found
                self.internal_domains = {
                    'seguelogic.com', 'securedata247.com', 'covereddata.com'
                }
        except Exception as e:
            safe_log(f"Error loading alias config: {e}", "ERROR")
            # Fallback to defaults
            self.internal_domains = {
                'seguelogic.com', 'securedata247.com', 'covereddata.com'
            }
    
    def get_primary_account(self, email: str) -> str:
        """Get primary account for an email address"""
        email_addr = extract_email_address(email).lower()
        return self.alias_to_primary.get(email_addr, email_addr)
    
    def get_all_related_addresses(self, email: str) -> Set[str]:
        """Get all email addresses related to this one (primary + all aliases)"""
        email_addr = extract_email_address(email).lower()
        primary = self.get_primary_account(email_addr)
        
        # Get all aliases for this primary account
        related = self.primary_to_aliases.get(primary, set())
        # Add the primary itself
        related = related.copy()
        related.add(primary)
        
        # If this email isn't in our mappings, just return itself
        if primary == email_addr and email_addr not in self.primary_to_aliases:
            return {email_addr}
        
        return related
    
    def is_internal_address(self, email: str) -> bool:
        """Check if email address belongs to internal domain"""
        email_addr = extract_email_address(email)
        if '@' in email_addr:
            domain = email_addr.split('@')[1].lower()
            return domain in self.internal_domains
        return False

class EnhancedThreadAnalyzer:
    """Enhanced thread analysis with database verification and alias support"""
    
    def __init__(self, alias_manager: Optional[AliasManager] = None):
        """Initialize thread analyzer
        
        Args:
            alias_manager: Optional AliasManager instance
        """
        self.alias_manager = alias_manager or AliasManager()
        
        self.db_handler = None
        if EmailDatabaseHandler:
            try:
                self.db_handler = EmailDatabaseHandler()
                if self.db_handler.test_connection():
                    safe_log("Database connection established for thread analysis")
                else:
                    self.db_handler = None
                    safe_log("Database connection failed", "WARNING")
            except Exception as e:
                safe_log(f"Failed to initialize database: {e}", "ERROR")
                self.db_handler = None

    def get_thread_history(self, message_ids: List[str], subject: str,
                          sender: str, recipients: List[str]) -> Dict:
        """Query database for thread history with alias awareness

        Returns:
            Dict with thread history information
        """
        if not self.db_handler or not self.db_handler.db_ready:
            return {
                'found_messages': 0,
                'internal_participation': False,
                'thread_initiated_internally': False,
                'conversation_count': 0,
                'references_spam': False,
                'max_referenced_spam_score': 0.0
            }

        session = None
        try:
            session = self.db_handler.get_db_session()

            # Get all related addresses for sender
            sender_addr = extract_email_address(sender)
            sender_related = self.alias_manager.get_all_related_addresses(sender_addr)

            # Get all related addresses for recipients
            all_recipient_related = set()
            for recip in recipients:
                recip_addr = extract_email_address(recip)
                all_recipient_related.update(self.alias_manager.get_all_related_addresses(recip_addr))

            # Look for messages with matching message IDs in thread
            found_messages = []
            max_spam_score = 0.0
            references_spam = False

            for msg_id in message_ids:
                result = session.query(SpacyAnalysis).filter(
                    SpacyAnalysis.message_id == msg_id
                ).first()
                if result:
                    found_messages.append(result)
                    # Check if referenced message was spam
                    msg_spam_score = float(result.spam_score) if result.spam_score else 0.0
                    max_spam_score = max(max_spam_score, msg_spam_score)
                    if msg_spam_score >= 5.0:  # Threshold for spam
                        references_spam = True
                        safe_log(f"WARNING: Thread references spam message {msg_id} (score: {msg_spam_score})")
            
            # ENHANCED: Only look for exact thread relationships, not just similar subjects
            # This prevents scammers from exploiting common phrases
            normalized_subject = normalize_subject(subject)
            if normalized_subject and len(normalized_subject) > 10 and len(found_messages) > 0:
                # Only search for related messages if we already found some by message ID
                # This ensures we're extending a real thread, not finding false matches
                thirty_days_ago = datetime.utcnow() - timedelta(days=30)
                
                # Build query for related addresses - must include sender
                sender_conditions = []
                sender_email = extract_email_address(sender)
                
                # STRICT: Only look for messages FROM or TO the current sender
                sender_conditions.append(
                    or_(
                        SpacyAnalysis.sender.like(f"%{sender_email}%"),
                        SpacyAnalysis.recipients.like(f"%{sender_email}%")
                    )
                )
                
                similar_subjects = session.query(SpacyAnalysis).filter(
                    and_(
                        SpacyAnalysis.timestamp > thirty_days_ago,
                        or_(
                            SpacyAnalysis.subject == normalized_subject,  # Exact match only
                            SpacyAnalysis.subject == f"Re: {normalized_subject}",
                            SpacyAnalysis.subject == f"RE: {normalized_subject}"
                        ),
                        or_(*sender_conditions) if sender_conditions else True
                    )
                ).limit(5).all()  # Reduced limit
                
                # Add relevant messages to found_messages
                for msg in similar_subjects:
                    if msg not in found_messages:
                        found_messages.append(msg)
            elif normalized_subject and len(found_messages) == 0:
                # No message IDs found - DO NOT search by subject alone
                # This is likely a fake reply attempt
                safe_log(f"WARNING: Reply claimed but no message IDs found in DB")
            
            # Analyze thread participation with alias awareness
            internal_participation = False
            thread_initiated_internally = False
            earliest_message = None
            
            for msg in found_messages:
                msg_sender = extract_email_address(msg.sender or '')
                
                # Check if sender is internal (considering aliases)
                if self.alias_manager.is_internal_address(msg_sender):
                    internal_participation = True
                    
                    # Track earliest message
                    if not earliest_message or msg.timestamp < earliest_message.timestamp:
                        earliest_message = msg
                
                # Check recipients for internal addresses
                if msg.recipients:
                    recipients_list = msg.recipients.split(',') if ',' in msg.recipients else [msg.recipients]
                    for recip in recipients_list:
                        if self.alias_manager.is_internal_address(recip):
                            internal_participation = True
            
            # Check if thread was initiated internally
            if earliest_message and self.alias_manager.is_internal_address(earliest_message.sender or ''):
                thread_initiated_internally = True
            
            return {
                'found_messages': len(found_messages),
                'internal_participation': internal_participation,
                'thread_initiated_internally': thread_initiated_internally,
                'conversation_count': len(found_messages),
                'message_ids_found': [m.message_id for m in found_messages if m.message_id],
                'earliest_timestamp': earliest_message.timestamp if earliest_message else None,
                'references_spam': references_spam,
                'max_referenced_spam_score': max_spam_score
            }

        except Exception as e:
            safe_log(f"Database query error: {e}", "ERROR")
            return {
                'found_messages': 0,
                'internal_participation': False,
                'thread_initiated_internally': False,
                'conversation_count': 0,
                'references_spam': False,
                'max_referenced_spam_score': 0.0
            }
        finally:
            if session:
                session.close()

    def check_quoted_internal_content(self, msg: EmailMessage, text_content: str = None) -> Dict:
        """Check if email contains quoted content from internal users
        
        This is a strong indicator of a legitimate reply as it shows
        the actual conversation history with internal email addresses.
        """
        result = {
            'has_quoted_internal': False,
            'quoted_internal_addresses': [],
            'has_email_headers_in_quote': False,
            'quote_patterns_found': []
        }
        
        # Get email body content if not provided
        if text_content is None:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == 'text/plain':
                        try:
                            text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            break
                        except:
                            continue
            else:
                try:
                    text_content = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    text_content = str(msg.get_payload())
        
        if not text_content:
            return result
        
        # Common quote patterns in legitimate replies
        quote_patterns = [
            # Outlook/Exchange style
            r'From:\s*([^\n]+@(?:seguelogic\.com|securedata247\.com|covereddata\.com))',
            r'Sent:\s*[^\n]+\s+To:\s*([^\n]+@(?:seguelogic\.com|securedata247\.com|covereddata\.com))',
            
            # Gmail/standard style  
            r'On .+ <([^>]+@(?:seguelogic\.com|securedata247\.com|covereddata\.com))> wrote:',
            
            # Generic email patterns in quoted content (with > prefix)
            r'>.*?([a-zA-Z0-9._%+-]+@(?:seguelogic\.com|securedata247\.com|covereddata\.com))',
            
            # Scott's specific emails
            r'scott@(?:seguelogic\.com|securedata247\.com|covereddata\.com)',
            r'sbarbour@(?:seguelogic\.com|securedata247\.com|covereddata\.com)',
        ]
        
        # Check for quoted internal emails
        internal_emails_found = set()
        for pattern in quote_patterns:
            matches = re.findall(pattern, text_content[:5000], re.IGNORECASE)  # Check first 5000 chars
            if matches:
                result['quote_patterns_found'].append(pattern.split('\\s*')[0])  # Store pattern type
                for match in matches:
                    if isinstance(match, str) and '@' in match:
                        internal_emails_found.add(match.lower())
        
        # Check for email header patterns in quotes
        header_patterns = [
            r'[-]{3,}\s*Original Message\s*[-]{3,}',
            r'From:\s*[^\n]+\nSent:\s*[^\n]+\nTo:',
            r'On .+ at .+ wrote:',
            r'>{2,}',  # Multiple levels of quoting
        ]
        
        for pattern in header_patterns:
            if re.search(pattern, text_content[:3000], re.IGNORECASE):
                result['has_email_headers_in_quote'] = True
                break
        
        if internal_emails_found:
            result['has_quoted_internal'] = True
            result['quoted_internal_addresses'] = list(internal_emails_found)
            safe_log(f"Found quoted internal emails: {internal_emails_found}")
        
        return result
    
    def analyze_thread(self, msg: EmailMessage, text_content: str = None) -> Dict:
        """Perform comprehensive thread analysis with alias support
        
        Args:
            msg: Email message to analyze
            
        Returns:
            Dict with thread analysis results
        """
        result = {
            'is_thread_reply': False,
            'trust_level': 'none',  # none, low, medium, high
            'trust_score': 0,  # 0-10 scale
            'thread_verified': False,
            'internal_participation': False,
            'thread_initiated_internally': False,
            'conversation_depth': 0,
            'risk_factors': [],
            'headers_found': [],
            'related_addresses': [],
            'is_fake_reply': False,  # NEW: Explicit fake reply detection
            'fake_reply_confidence': 0.0  # NEW: Confidence score for fake reply
        }
        
        # Extract headers
        references = msg.get('References', '')
        in_reply_to = msg.get('In-Reply-To', '')
        subject = msg.get('Subject', '')
        from_header = msg.get('From', '')
        to_header = msg.get('To', '')
        cc_header = msg.get('Cc', '')
        
        # Extract sender and recipients
        sender = extract_email_address(from_header)
        recipients = []
        if to_header:
            recipients.extend([extract_email_address(r) for r in to_header.split(',')])
        if cc_header:
            recipients.extend([extract_email_address(r) for r in cc_header.split(',')])
        
        # Get all related addresses for analysis
        sender_related = self.alias_manager.get_all_related_addresses(sender)
        result['related_addresses'] = list(sender_related)
        
        # Check for thread indicators
        has_references = bool(references)
        has_reply_to = bool(in_reply_to)
        has_re_subject = bool(re.match(r'^(Re:|RE:|Fwd:|FW:)', subject))
        
        if not (has_references or has_reply_to or has_re_subject):
            # Not a thread reply
            return result
        
        result['is_thread_reply'] = True
        
        # NEW: Check for quoted internal content
        quoted_content_check = self.check_quoted_internal_content(msg, text_content)
        result['has_quoted_internal'] = quoted_content_check['has_quoted_internal']
        result['quoted_internal_addresses'] = quoted_content_check['quoted_internal_addresses']
        
        # Also check for ANY quoted content (not just internal)
        has_any_quoted_content = (
            quoted_content_check.get('has_email_headers_in_quote', False) or
            bool(quoted_content_check.get('quote_patterns_found', []))
        )
        result['has_any_quoted_content'] = has_any_quoted_content
        
        # Collect message IDs from thread
        thread_message_ids = []
        if references:
            thread_message_ids.extend(extract_message_ids(references))
            result['headers_found'].append('References')
        if in_reply_to:
            thread_message_ids.extend(extract_message_ids(in_reply_to))
            result['headers_found'].append('In-Reply-To')
        
        # Remove duplicates while preserving order
        thread_message_ids = list(dict.fromkeys(thread_message_ids))
        
        # Query database for thread history with alias awareness
        thread_history = self.get_thread_history(
            thread_message_ids, subject, sender, recipients
        )
        
        # Calculate trust score based on findings
        trust_score = 0
        
        # Base score for having thread headers
        if has_references:
            trust_score += 1
        if has_reply_to:
            trust_score += 1
        if has_re_subject:
            trust_score += 0.5
        
        # Database verification bonus
        if thread_history['found_messages'] > 0:
            result['thread_verified'] = True

            # Check if thread references spam messages
            if thread_history.get('references_spam', False):
                result['risk_factors'].append('references_previous_spam')
                result['is_fake_reply'] = True
                result['fake_reply_confidence'] = 0.95
                max_spam = thread_history.get('max_referenced_spam_score', 0)
                safe_log(f"SPAM CONTINUATION: Thread references blocked spam (score: {max_spam})")
                # Major penalty - this is a spam campaign continuation
                trust_score -= 8
            else:
                # Only give trust bonus if NOT referencing spam
                trust_score += min(3, thread_history['found_messages'])  # Max 3 points

            result['conversation_depth'] = thread_history['conversation_count']
        else:
            result['risk_factors'].append('thread_not_in_database')
            
            # Check if sender is from a legitimate business domain
            sender_domain = extract_email_address(sender).split('@')[1] if '@' in extract_email_address(sender) else ''
            
            # Known suspicious patterns for fake replies
            suspicious_tlds = ['.info', '.biz', '.click', '.download', '.email', '.loan',
                              '.work', '.party', '.racing', '.win', '.stream', '.gdn']
            suspicious_keywords = ['marketing', 'deals', 'promo', 'offer', 'casino', 'crypto']
            
            is_suspicious_domain = (
                any(sender_domain.endswith(tld) for tld in suspicious_tlds) or
                any(keyword in sender_domain.lower() for keyword in suspicious_keywords) or
                len(sender_domain.split('.')) > 3  # Subdomain abuse like x.y.z.com
            )
            
            # Only flag as fake reply if it's actually suspicious
            if has_re_subject and not (has_references or has_reply_to):
                # Re: with no thread headers at all - highly suspicious
                result['risk_factors'].append('fake_reply_no_headers')
                result['is_fake_reply'] = True
                result['fake_reply_confidence'] = 0.95
                trust_score -= 5  # Major penalty
                safe_log(f"FAKE REPLY DETECTED: Re: subject with NO thread headers")
            elif has_re_subject and (has_references or has_reply_to) and is_suspicious_domain:
                # Suspicious domain claiming to be a reply - likely fake
                result['risk_factors'].append('fake_reply_suspicious_domain')
                result['is_fake_reply'] = True
                result['fake_reply_confidence'] = 0.7
                trust_score -= 2  # Moderate penalty
                safe_log(f"SUSPICIOUS REPLY: Re: from suspicious domain {sender_domain}")
            else:
                # Legitimate external reply - no penalty for missing DB history
                # This is expected behavior for external email conversations
                safe_log(f"External reply from {sender_domain} - no DB history (normal behavior)")
                trust_score -= 0.5  # Very minor trust reduction only
        
        # Internal participation bonus (with alias awareness)
        if thread_history['internal_participation']:
            result['internal_participation'] = True
            trust_score += 2
            
            if thread_history['thread_initiated_internally']:
                result['thread_initiated_internally'] = True
                trust_score += 2  # Extra bonus for internal initiation
        else:
            result['risk_factors'].append('no_internal_participation')
        
        # Check if sender is internal (current message, with alias check)
        if self.alias_manager.is_internal_address(sender):
            trust_score += 1
            if 'no_internal_participation' in result['risk_factors']:
                result['risk_factors'].remove('no_internal_participation')
        
        # Cap trust score at 10
        trust_score = min(10, trust_score)
        result['trust_score'] = trust_score
        
        # Determine trust level
        if trust_score >= 8:
            result['trust_level'] = 'high'
        elif trust_score >= 5:
            result['trust_level'] = 'medium'
        elif trust_score >= 2:
            result['trust_level'] = 'low'
        else:
            result['trust_level'] = 'none'
            
        # Add risk factors for suspicious patterns
        if result['is_thread_reply'] and not result['thread_verified']:
            result['risk_factors'].append('unverified_thread_headers')
        
        if result['trust_level'] in ['none', 'low'] and has_references:
            result['risk_factors'].append('suspicious_thread_attempt')
        
        # Check for funding spam pattern in untrusted threads
        if 'funding' in subject.lower() or 'loan' in subject.lower() or 'credit' in subject.lower():
            if result['trust_level'] in ['none', 'low', 'medium']:
                result['risk_factors'].append('funding_spam_in_thread')
        
        # NEW: Major trust boost for quoted internal content
        if result.get('has_quoted_internal', False):
            trust_score += 3  # Significant boost
            result['trust_score'] = min(10, trust_score)
            safe_log(f"Found quoted internal emails - boosting trust +3")
            # Remove fake reply flag if we have real quoted content
            if result.get('is_fake_reply', False):
                result['is_fake_reply'] = False
                result['fake_reply_confidence'] = 0.0
                safe_log(f"Quoted internal content found - not a fake reply")
        elif result.get('has_any_quoted_content', False):
            # Has quoted content (even if not internal) - likely legitimate
            trust_score += 1  # Small boost
            if result.get('is_fake_reply', False) and result.get('fake_reply_confidence', 0) < 0.9:
                # Reduce fake reply confidence if there's quoted content
                result['fake_reply_confidence'] *= 0.5
                safe_log(f"Found quoted content - reducing fake reply confidence")
        elif has_re_subject and not result['thread_verified'] and not result.get('has_any_quoted_content', False):
            # Re: with no quoted content AND no DB history - check if domain is suspicious
            sender_domain = extract_email_address(sender).split('@')[1] if '@' in extract_email_address(sender) else ''
            
            # Re-check suspicious patterns
            suspicious_tlds = ['.info', '.biz', '.click', '.download', '.email', '.loan',
                              '.work', '.party', '.racing', '.win', '.stream', '.gdn']
            suspicious_keywords = ['marketing', 'deals', 'promo', 'offer', 'casino', 'crypto']
            
            is_suspicious = (
                any(sender_domain.endswith(tld) for tld in suspicious_tlds) or
                any(keyword in sender_domain.lower() for keyword in suspicious_keywords) or
                len(sender_domain.split('.')) > 3
            )
            
            # Only increase suspicion if domain looks sketchy
            if is_suspicious:
                result['risk_factors'].append('reply_no_quoted_suspicious')
                result['is_fake_reply'] = True
                result['fake_reply_confidence'] = max(result.get('fake_reply_confidence', 0), 0.85)
                safe_log(f"FAKE REPLY: Re: with no quoted content from suspicious domain {sender_domain}")
            else:
                # Regular domain with Re: but no quotes - mild suspicion only
                safe_log(f"Reply from {sender_domain} lacks quoted content but domain appears legitimate")
        
        # NEW: Check for common fake reply patterns
        sender_domain = extract_email_address(sender).split('@')[1] if '@' in extract_email_address(sender) else ''
        
        # Check for suspicious domains commonly used in fake replies
        suspicious_domains = [
            '.info', '.biz', '.click', '.download', '.email', '.loan',
            '.work', '.party', '.racing', '.win', '.stream', '.gdn',
            'dealpackagingonline.info', 'marketingpro.info', 'businessdeals.biz'
        ]
        
        for suspicious in suspicious_domains:
            if suspicious in sender_domain:
                result['risk_factors'].append(f'suspicious_domain_{suspicious}')
                if result['is_thread_reply'] and not result['thread_verified']:
                    result['is_fake_reply'] = True
                    result['fake_reply_confidence'] = max(result['fake_reply_confidence'], 0.7)
                    safe_log(f"Suspicious domain in fake reply: {sender_domain}")
                break
        
        # NEW: Check for fake conversational phrases in subject
        fake_phrases = ['quick idea for', 'following up on', 'as discussed', 
                       'per our conversation', 'touching base', 'circling back']
        subject_lower = subject.lower()
        for phrase in fake_phrases:
            if phrase in subject_lower and not result['thread_verified']:
                result['risk_factors'].append(f'fake_phrase_{phrase.replace(" ", "_")}')
                result['is_fake_reply'] = True
                result['fake_reply_confidence'] = max(result['fake_reply_confidence'], 0.6)
                safe_log(f"Fake conversational phrase detected: {phrase}")
        
        return result

    def get_adjusted_spam_threshold(self, thread_analysis: Dict, base_threshold: float) -> float:
        """Calculate adjusted spam threshold based on thread trust
        
        Args:
            thread_analysis: Thread analysis results
            base_threshold: Original spam threshold
            
        Returns:
            Adjusted threshold (lower for less trusted threads)
        """
        trust_level = thread_analysis.get('trust_level', 'none')
        
        # Stricter thresholds for less trusted threads
        adjustments = {
            'none': 0.7,      # 30% stricter
            'low': 0.8,       # 20% stricter  
            'medium': 0.9,    # 10% stricter
            'high': 1.0       # No adjustment for highly trusted
        }
        
        adjusted = base_threshold * adjustments.get(trust_level, 0.7)
        
        # Extra strict for funding spam in semi-trusted threads
        if 'funding_spam_in_thread' in thread_analysis.get('risk_factors', []):
            adjusted *= 0.7  # Additional 30% stricter
        
        # If no internal participation at all, be stricter
        if not thread_analysis.get('internal_participation', False):
            adjusted *= 0.85  # Additional 15% stricter
        
        # NEW: VERY strict for detected fake replies
        if thread_analysis.get('is_fake_reply', False):
            confidence = thread_analysis.get('fake_reply_confidence', 0.5)
            # Scale adjustment based on confidence (0.3 to 0.6)
            adjusted *= (0.6 - (confidence * 0.3))
            safe_log(f"Fake reply detected - threshold adjusted to {adjusted:.1f} (confidence: {confidence:.2f})")
        
        return adjusted
    
    def get_spam_score_boost(self, thread_analysis: Dict) -> float:
        """NEW: Calculate additional spam score for fake replies

        Args:
            thread_analysis: Thread analysis results

        Returns:
            Additional spam score to add (0-15 points)
        """
        boost = 0.0
        risk_factors = thread_analysis.get('risk_factors', [])

        # Check for spam continuation - this gets immediate penalty
        if 'references_previous_spam' in risk_factors:
            boost = 15.0  # Maximum penalty - this is a spam campaign
            safe_log(f"Spam continuation detected - adding maximum penalty: +{boost:.1f} points")
            return boost

        if not thread_analysis.get('is_fake_reply', False):
            return boost
        
        # Base boost for fake reply
        confidence = thread_analysis.get('fake_reply_confidence', 0.5)
        boost = 5.0 * confidence  # 0-5 points based on confidence
        
        # Additional penalties for specific risk factors
        risk_factors = thread_analysis.get('risk_factors', [])
        
        factor_penalties = {
            'references_previous_spam': 10.0,  # NEW: Spam campaign continuation
            'fake_reply_no_headers': 5.0,  # REBALANCED: Reduced from 10.0
            'fake_reply_suspicious_domain': 3.0,  # REBALANCED: Reduced from 5.0
            'reply_no_quoted_suspicious': 2.0,  # REBALANCED: Reduced from 3.0
            'suspicious_domain_': 1.0,  # REBALANCED: Reduced from 2.0
            'fake_phrase_': 0.5,  # REBALANCED: Reduced from 1.5
            'thread_not_in_database': 0.0,  # REBALANCED: Removed - too many false positives
            'no_internal_participation': 0.0  # REBALANCED: Removed - normal for new conversations
        }
        
        for factor in risk_factors:
            for pattern, penalty in factor_penalties.items():
                if factor.startswith(pattern):
                    boost += penalty
                    break
        
        # Cap at 15 points (increased from 8 to handle spam continuations)
        boost = min(boost, 15.0)
        
        if boost > 0:
            safe_log(f"Fake reply spam boost: +{boost:.1f} points")
        
        return boost


def analyze_thread_with_database(msg: EmailMessage, text_content: str = None) -> Dict:
    """Main entry point for thread analysis with alias support
    
    Args:
        msg: Email message to analyze
        text_content: Optional pre-extracted text content
        
    Returns:
        Thread analysis results dictionary
    """
    analyzer = EnhancedThreadAnalyzer()
    return analyzer.analyze_thread(msg, text_content)