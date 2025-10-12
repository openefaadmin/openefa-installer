#!/usr/bin/env python3
"""
Email Blocking Module for SpaCy Email System

Provides domain and country-based blocking capabilities on a per-client basis.
Features:
- Per-client domain blocking (exact match, wildcard, regex)
- Per-client country blocking using GeoIP
- IP/CIDR range blocking
- Whitelist exceptions
- Caching for performance
- Detailed logging of blocked attempts

Author: SpaCy Email Security Team
Location: /opt/spacyserver/modules/email_blocking.py
"""

import os
import sys
import re
import json
import ipaddress
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set, Tuple, Any
from functools import lru_cache
import threading

# Database imports
try:
    from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, Boolean, text, ForeignKey, Index
    from sqlalchemy.orm import declarative_base, sessionmaker, relationship
    from sqlalchemy.exc import SQLAlchemyError
    DB_AVAILABLE = True
except ImportError as e:
    DB_AVAILABLE = False
    print(f"SQLAlchemy not available: {e}", file=sys.stderr)

# GeoIP imports
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("GeoIP2 not available. Install with: pip install geoip2", file=sys.stderr)

# Redis for caching
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("Redis not available for caching", file=sys.stderr)

# Base class for database models
Base = declarative_base()


# ============================================================================
# DATABASE MODELS
# ============================================================================

class ClientDomain(Base):
    """Client domains that we manage"""
    __tablename__ = 'client_domains'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    client_name = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = Column(Boolean, default=True)
    
    # Relationships
    blocking_rules = relationship("BlockingRule", back_populates="client_domain", cascade="all, delete-orphan")
    blocked_attempts = relationship("BlockedAttempt", back_populates="client_domain", cascade="all, delete-orphan")


class BlockingRule(Base):
    """Blocking rules per client domain"""
    __tablename__ = 'blocking_rules'

    id = Column(Integer, primary_key=True)
    client_domain_id = Column(Integer, ForeignKey('client_domains.id'), nullable=False)
    rule_type = Column(String(50), nullable=False)  # 'domain', 'country', 'ip', 'cidr'
    rule_value = Column(String(255), nullable=False)  # .cn, CN, 192.168.1.1, etc.
    rule_pattern = Column(String(50), default='exact')  # 'exact', 'wildcard', 'regex'
    recipient_pattern = Column(String(255))  # Optional: specific recipient pattern to apply rule to
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100))
    active = Column(Boolean, default=True)
    priority = Column(Integer, default=100)  # Lower number = higher priority
    whitelist = Column(Boolean, default=False)  # If True, this is an exception to blocking
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_blocking_rules_lookup', 'client_domain_id', 'rule_type', 'active'),
        Index('idx_blocking_rules_priority', 'priority'),
    )
    
    # Relationship
    client_domain = relationship("ClientDomain", back_populates="blocking_rules")


class BlockedAttempt(Base):
    """Log of blocked email attempts"""
    __tablename__ = 'blocked_attempts'
    
    id = Column(Integer, primary_key=True)
    client_domain_id = Column(Integer, ForeignKey('client_domains.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    sender_address = Column(String(255))
    sender_domain = Column(String(255), index=True)
    sender_ip = Column(String(45))  # Support IPv6
    sender_country = Column(String(2))  # ISO country code
    rule_matched = Column(String(255))  # Which rule caused the block
    rule_type = Column(String(50))
    smtp_session_id = Column(String(100))
    message_id = Column(String(255))
    subject = Column(Text)
    
    # Relationship
    client_domain = relationship("ClientDomain", back_populates="blocked_attempts")
    
    # Index for reporting
    __table_args__ = (
        Index('idx_blocked_attempts_reporting', 'client_domain_id', 'timestamp'),
        Index('idx_blocked_attempts_sender', 'sender_domain', 'timestamp'),
    )


# ============================================================================
# BLOCKING ENGINE
# ============================================================================

class EmailBlockingEngine:
    """Main blocking engine with caching and GeoIP support"""
    
    def __init__(self, config_path="/opt/spacyserver/config/.my.cnf", 
                 geoip_db_path="/opt/spacyserver/data/GeoLite2-Country.mmdb"):
        """Initialize blocking engine"""
        self.config_path = config_path
        self.geoip_db_path = geoip_db_path
        self.engine = None
        self.SessionLocal = None
        self.geoip_reader = None
        self.redis_client = None
        self.rules_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.last_cache_refresh = {}
        self._lock = threading.Lock()
        
        # Initialize components
        self._initialize_database()
        self._initialize_geoip()
        self._initialize_redis()
    
    def _initialize_database(self):
        """Initialize database connection"""
        if not DB_AVAILABLE:
            return
            
        try:
            # Read MySQL config from my.cnf file
            import configparser
            config = configparser.ConfigParser()
            config.read(self.config_path)
            
            if config.has_section('client'):
                user = config.get('client', 'user', fallback='root')
                password = config.get('client', 'password', fallback='')
                host = config.get('client', 'host', fallback='localhost')
                database = config.get('client', 'database', fallback='spacy_email_db')
            else:
                # Fallback to reading file manually
                user = 'root'
                password = ''
                with open(self.config_path, 'r') as f:
                    for line in f:
                        if line.startswith('user'):
                            user = line.split('=')[1].strip()
                        elif line.startswith('password'):
                            password = line.split('=')[1].strip()
            
            # Build connection string with credentials
            if password:
                db_url = f"mysql+pymysql://{user}:{password}@localhost:3306/spacy_email_db"
            else:
                db_url = f"mysql+pymysql://{user}@localhost:3306/spacy_email_db"
            
            self.engine = create_engine(
                db_url,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            # Create tables if they don't exist
            Base.metadata.create_all(self.engine)
            
            # Create session factory
            self.SessionLocal = sessionmaker(bind=self.engine)
            
            print("✅ Blocking database initialized", file=sys.stderr)
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}", file=sys.stderr)
            self.SessionLocal = None
    
    def _initialize_geoip(self):
        """Initialize GeoIP database"""
        if not GEOIP_AVAILABLE:
            return
            
        try:
            if os.path.exists(self.geoip_db_path):
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                print("✅ GeoIP database loaded", file=sys.stderr)
            else:
                print(f"⚠️  GeoIP database not found at {self.geoip_db_path}", file=sys.stderr)
                print("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data", file=sys.stderr)
        except Exception as e:
            print(f"❌ GeoIP initialization failed: {e}", file=sys.stderr)
    
    def _initialize_redis(self):
        """Initialize Redis for caching"""
        if not REDIS_AVAILABLE:
            return
            
        try:
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=2,  # Use different DB for blocking cache
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1
            )
            self.redis_client.ping()
            print("✅ Redis cache connected", file=sys.stderr)
        except Exception as e:
            print(f"⚠️  Redis cache not available: {e}", file=sys.stderr)
            self.redis_client = None
    
    def get_country_from_ip(self, ip_address: str) -> Optional[str]:
        """Get country code from IP address"""
        if not self.geoip_reader:
            return None
            
        try:
            response = self.geoip_reader.country(ip_address)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return None
        except Exception as e:
            print(f"GeoIP lookup error for {ip_address}: {e}", file=sys.stderr)
            return None
    
    def _get_cached_rules(self, client_domain: str) -> Optional[List[Dict]]:
        """Get rules from cache"""
        # Check memory cache first
        cache_key = f"rules:{client_domain}"
        
        if cache_key in self.rules_cache:
            last_refresh = self.last_cache_refresh.get(cache_key, 0)
            if time.time() - last_refresh < self.cache_ttl:
                return self.rules_cache[cache_key]
        
        # Check Redis cache
        if self.redis_client:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    rules = json.loads(cached)
                    self.rules_cache[cache_key] = rules
                    self.last_cache_refresh[cache_key] = time.time()
                    return rules
            except Exception:
                pass
        
        return None
    
    def _cache_rules(self, client_domain: str, rules: List[Dict]):
        """Cache rules in memory and Redis"""
        cache_key = f"rules:{client_domain}"
        
        # Memory cache
        self.rules_cache[cache_key] = rules
        self.last_cache_refresh[cache_key] = time.time()
        
        # Redis cache
        if self.redis_client:
            try:
                self.redis_client.setex(
                    cache_key,
                    self.cache_ttl,
                    json.dumps(rules)
                )
            except Exception:
                pass
    
    def load_rules_for_domain(self, client_domain: str) -> List[Dict]:
        """Load blocking rules for a specific client domain"""
        # Check cache first
        cached_rules = self._get_cached_rules(client_domain)
        if cached_rules is not None:
            return cached_rules
        
        if not self.SessionLocal:
            return []
        
        rules = []
        session = None
        
        try:
            session = self.SessionLocal()
            
            # Get client domain
            client = session.query(ClientDomain).filter_by(
                domain=client_domain,
                active=True
            ).first()
            
            if not client:
                return []
            
            # Get active rules ordered by priority
            db_rules = session.query(BlockingRule).filter_by(
                client_domain_id=client.id,
                active=True
            ).order_by(BlockingRule.priority).all()
            
            # Convert to dict for easier processing
            for rule in db_rules:
                rules.append({
                    'id': rule.id,
                    'type': rule.rule_type,
                    'value': rule.rule_value,
                    'pattern': rule.rule_pattern,
                    'recipient_pattern': rule.recipient_pattern,
                    'whitelist': rule.whitelist,
                    'priority': rule.priority,
                    'description': rule.description
                })
            
            # Cache the rules
            self._cache_rules(client_domain, rules)
            
        except Exception as e:
            print(f"Error loading rules for {client_domain}: {e}", file=sys.stderr)
        finally:
            if session:
                session.close()
        
        return rules
    
    def check_domain_block(self, sender_domain: str, rules: List[Dict]) -> Optional[Dict]:
        """Check if sender domain should be blocked"""
        for rule in rules:
            if rule['type'] != 'domain':
                continue
            
            if rule['pattern'] == 'exact':
                if sender_domain.lower() == rule['value'].lower():
                    return rule
            elif rule['pattern'] == 'wildcard':
                # Convert wildcard to regex (*.cn becomes .*\.cn$)
                pattern = rule['value'].replace('.', r'\.')
                pattern = pattern.replace('*', '.*')
                if not pattern.startswith('.*'):
                    pattern = '^' + pattern
                if not pattern.endswith('$'):
                    pattern = pattern + '$'
                
                if re.match(pattern, sender_domain, re.IGNORECASE):
                    return rule
            elif rule['pattern'] == 'regex':
                try:
                    if re.match(rule['value'], sender_domain, re.IGNORECASE):
                        return rule
                except re.error:
                    print(f"Invalid regex pattern: {rule['value']}", file=sys.stderr)
        
        return None
    
    def check_country_block(self, sender_ip: str, rules: List[Dict]) -> Optional[Dict]:
        """Check if sender country should be blocked"""
        if not sender_ip:
            return None
        
        country_code = self.get_country_from_ip(sender_ip)
        if not country_code:
            return None
        
        for rule in rules:
            if rule['type'] == 'country' and rule['value'].upper() == country_code.upper():
                return rule
        
        return None
    
    def check_ip_block(self, sender_ip: str, rules: List[Dict]) -> Optional[Dict]:
        """Check if sender IP should be blocked"""
        if not sender_ip:
            return None
        
        try:
            ip_obj = ipaddress.ip_address(sender_ip)
        except ValueError:
            return None
        
        for rule in rules:
            if rule['type'] == 'ip':
                if sender_ip == rule['value']:
                    return rule
            elif rule['type'] == 'cidr':
                try:
                    network = ipaddress.ip_network(rule['value'], strict=False)
                    if ip_obj in network:
                        return rule
                except ValueError:
                    print(f"Invalid CIDR: {rule['value']}", file=sys.stderr)
        
        return None
    
    def should_block_email(self, recipient_domain: str, sender_address: str,
                          sender_ip: Optional[str] = None, recipient_address: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Main function to check if an email should be blocked

        Args:
            recipient_domain: The domain receiving the email
            sender_address: The sender's email address
            sender_ip: Optional sender IP address
            recipient_address: Optional full recipient address for recipient-specific rules

        Returns:
            Tuple of (should_block, reason, matched_rule)
        """
        # Extract sender domain
        # Handle display name format: "Name <email@domain>"
        import re
        email_match = re.search(r'<([^>]+)>', sender_address)
        if email_match:
            sender_email = email_match.group(1)
        else:
            sender_email = sender_address

        if '@' in sender_email:
            sender_domain = sender_email.split('@')[1].lower()
        else:
            sender_domain = sender_email.lower()

        # Load rules for recipient domain
        rules = self.load_rules_for_domain(recipient_domain)
        if not rules:
            return (False, None, None)

        # Filter rules by recipient if specified
        if recipient_address:
            filtered_rules = []
            for rule in rules:
                # If rule has no recipient pattern, it applies to all
                if not rule.get('recipient_pattern'):
                    filtered_rules.append(rule)
                    continue

                # Check if recipient matches the pattern
                recipient_pattern = rule['recipient_pattern'].lower()
                recipient_lower = recipient_address.lower()

                # Support wildcard patterns
                if '*' in recipient_pattern:
                    import fnmatch
                    if fnmatch.fnmatch(recipient_lower, recipient_pattern):
                        filtered_rules.append(rule)
                elif recipient_lower == recipient_pattern:
                    filtered_rules.append(rule)
            rules = filtered_rules

        # Separate whitelist and blocklist rules
        whitelist_rules = [r for r in rules if r['whitelist']]
        blocklist_rules = [r for r in rules if not r['whitelist']]
        
        # Check whitelist first (exceptions)
        for check_func, check_arg in [
            (self.check_domain_block, sender_domain),
            (self.check_ip_block, sender_ip),
            (self.check_country_block, sender_ip)
        ]:
            if check_arg:
                matched = check_func(check_arg, whitelist_rules)
                if matched:
                    # Whitelisted - don't block
                    return (False, f"Whitelisted by {matched['type']} rule", matched)
        
        # Check blocklist
        checks = [
            (self.check_domain_block, sender_domain, "domain"),
            (self.check_ip_block, sender_ip, "IP"),
            (self.check_country_block, sender_ip, "country")
        ]
        
        for check_func, check_arg, block_type in checks:
            if check_arg:
                matched = check_func(check_arg, blocklist_rules)
                if matched:
                    reason = f"Blocked by {block_type} rule: {matched['value']}"
                    if matched.get('description'):
                        reason += f" ({matched['description']})"
                    return (True, reason, matched)
        
        return (False, None, None)
    
    def log_blocked_attempt(self, recipient_domain: str, sender_address: str,
                           sender_ip: Optional[str], rule_matched: Dict,
                           message_id: Optional[str] = None, subject: Optional[str] = None):
        """Log a blocked email attempt to the database"""
        if not self.SessionLocal:
            return
        
        session = None
        try:
            session = self.SessionLocal()
            
            # Get client domain
            client = session.query(ClientDomain).filter_by(
                domain=recipient_domain,
                active=True
            ).first()
            
            if not client:
                return
            
            # Extract sender domain
            sender_domain = None
            # Handle display name format: "Name <email@domain>"
            email_match = re.search(r'<([^>]+)>', sender_address)
            if email_match:
                sender_email = email_match.group(1)
            else:
                sender_email = sender_address
            
            if '@' in sender_email:
                sender_domain = sender_email.split('@')[1]
            
            # Get country if available
            sender_country = None
            if sender_ip and self.geoip_reader:
                sender_country = self.get_country_from_ip(sender_ip)
            
            # Create blocked attempt record
            blocked = BlockedAttempt(
                client_domain_id=client.id,
                sender_address=sender_address,
                sender_domain=sender_domain,
                sender_ip=sender_ip,
                sender_country=sender_country,
                rule_matched=rule_matched['value'],
                rule_type=rule_matched['type'],
                message_id=message_id,
                subject=subject
            )
            
            session.add(blocked)
            session.commit()
            
        except Exception as e:
            print(f"Error logging blocked attempt: {e}", file=sys.stderr)
            if session:
                session.rollback()
        finally:
            if session:
                session.close()
    
    def add_client_domain(self, domain: str, client_name: Optional[str] = None) -> bool:
        """Add a new client domain"""
        if not self.SessionLocal:
            return False
        
        session = None
        try:
            session = self.SessionLocal()
            
            # Check if domain already exists
            existing = session.query(ClientDomain).filter_by(domain=domain).first()
            if existing:
                if not existing.active:
                    existing.active = True
                    existing.updated_at = datetime.utcnow()
                    session.commit()
                return True
            
            # Create new client domain
            client = ClientDomain(
                domain=domain,
                client_name=client_name or domain
            )
            
            session.add(client)
            session.commit()
            return True
            
        except Exception as e:
            print(f"Error adding client domain: {e}", file=sys.stderr)
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def add_blocking_rule(self, client_domain: str, rule_type: str, rule_value: str,
                         rule_pattern: str = 'exact', description: Optional[str] = None,
                         whitelist: bool = False, priority: int = 100,
                         recipient_pattern: Optional[str] = None) -> bool:
        """Add a blocking rule for a client domain

        Args:
            client_domain: The domain this rule applies to
            rule_type: Type of rule (domain, country, ip, cidr)
            rule_value: The value to match (e.g., *.pd25.com)
            rule_pattern: Pattern type (exact, wildcard, regex)
            description: Optional description
            whitelist: If True, this is an exception rule
            priority: Lower number = higher priority
            recipient_pattern: Optional recipient pattern (e.g., douglas@covereddata.com)
        """
        if not self.SessionLocal:
            return False

        session = None
        try:
            session = self.SessionLocal()

            # Get client domain
            client = session.query(ClientDomain).filter_by(
                domain=client_domain,
                active=True
            ).first()

            if not client:
                print(f"Client domain {client_domain} not found", file=sys.stderr)
                return False

            # Check for duplicate rule
            existing = session.query(BlockingRule).filter_by(
                client_domain_id=client.id,
                rule_type=rule_type,
                rule_value=rule_value,
                recipient_pattern=recipient_pattern,
                active=True
            ).first()
            
            if existing:
                print(f"Rule already exists for {rule_value}", file=sys.stderr)
                return True
            
            # Create new rule
            rule = BlockingRule(
                client_domain_id=client.id,
                rule_type=rule_type,
                rule_value=rule_value,
                rule_pattern=rule_pattern,
                recipient_pattern=recipient_pattern,
                description=description,
                whitelist=whitelist,
                priority=priority,
                created_by='system'
            )
            
            session.add(rule)
            session.commit()
            
            # Clear cache for this domain
            self._clear_cache(client_domain)
            
            return True
            
        except Exception as e:
            print(f"Error adding blocking rule: {e}", file=sys.stderr)
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()
    
    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove (deactivate) a blocking rule by ID"""
        if not self.SessionLocal:
            return False

        session = None
        try:
            session = self.SessionLocal()

            # Find the rule
            rule = session.query(BlockingRule).filter_by(id=rule_id).first()

            if not rule:
                print(f"Rule ID {rule_id} not found", file=sys.stderr)
                return False

            # Get client domain for cache clearing
            client = session.query(ClientDomain).filter_by(id=rule.client_domain_id).first()

            # Deactivate the rule (soft delete)
            rule.active = False
            session.commit()

            # Clear cache
            if client:
                self._clear_cache(client.domain)

            return True

        except Exception as e:
            print(f"Error removing rule: {e}", file=sys.stderr)
            if session:
                session.rollback()
            return False
        finally:
            if session:
                session.close()

    def list_blocking_rules(self, client_domain: str, include_inactive: bool = False) -> List[Dict]:
        """List all blocking rules for a domain"""
        if not self.SessionLocal:
            return []

        session = None
        try:
            session = self.SessionLocal()

            # Get client domain
            client = session.query(ClientDomain).filter_by(
                domain=client_domain,
                active=True
            ).first()

            if not client:
                print(f"Client domain {client_domain} not found", file=sys.stderr)
                return []

            # Query rules
            query = session.query(BlockingRule).filter_by(client_domain_id=client.id)

            if not include_inactive:
                query = query.filter_by(active=True)

            rules = query.order_by(BlockingRule.priority, BlockingRule.id).all()

            # Convert to dict list
            result = []
            for rule in rules:
                result.append({
                    'id': rule.id,
                    'type': rule.rule_type,
                    'value': rule.rule_value,
                    'pattern': rule.rule_pattern,
                    'recipient': rule.recipient_pattern or 'all',
                    'description': rule.description or '',
                    'whitelist': rule.whitelist,
                    'priority': rule.priority,
                    'active': rule.active,
                    'created': rule.created_at.strftime('%Y-%m-%d %H:%M') if rule.created_at else ''
                })

            return result

        except Exception as e:
            print(f"Error listing rules: {e}", file=sys.stderr)
            return []
        finally:
            if session:
                session.close()

    def _clear_cache(self, client_domain: str):
        """Clear cached rules for a domain"""
        cache_key = f"rules:{client_domain}"
        
        # Clear memory cache
        if cache_key in self.rules_cache:
            del self.rules_cache[cache_key]
        if cache_key in self.last_cache_refresh:
            del self.last_cache_refresh[cache_key]
        
        # Clear Redis cache
        if self.redis_client:
            try:
                self.redis_client.delete(cache_key)
            except Exception:
                pass
    
    def get_blocking_stats(self, client_domain: str, days: int = 7) -> Dict:
        """Get blocking statistics for a client domain"""
        if not self.SessionLocal:
            return {}
        
        session = None
        try:
            session = self.SessionLocal()
            
            # Get client domain
            client = session.query(ClientDomain).filter_by(
                domain=client_domain,
                active=True
            ).first()
            
            if not client:
                return {}
            
            # Calculate date range
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get blocked attempts
            blocked_count = session.query(BlockedAttempt).filter(
                BlockedAttempt.client_domain_id == client.id,
                BlockedAttempt.timestamp >= start_date
            ).count()
            
            # Get top blocked domains
            top_domains = session.query(
                BlockedAttempt.sender_domain,
                text('COUNT(*) as count')
            ).filter(
                BlockedAttempt.client_domain_id == client.id,
                BlockedAttempt.timestamp >= start_date,
                BlockedAttempt.sender_domain.isnot(None)
            ).group_by(
                BlockedAttempt.sender_domain
            ).order_by(
                text('count DESC')
            ).limit(10).all()
            
            # Get blocking by rule type
            by_rule_type = session.query(
                BlockedAttempt.rule_type,
                text('COUNT(*) as count')
            ).filter(
                BlockedAttempt.client_domain_id == client.id,
                BlockedAttempt.timestamp >= start_date
            ).group_by(
                BlockedAttempt.rule_type
            ).all()
            
            return {
                'total_blocked': blocked_count,
                'top_blocked_domains': [{'domain': d[0], 'count': d[1]} for d in top_domains],
                'by_rule_type': {r[0]: r[1] for r in by_rule_type},
                'period_days': days
            }
            
        except Exception as e:
            print(f"Error getting blocking stats: {e}", file=sys.stderr)
            return {}
        finally:
            if session:
                session.close()


# ============================================================================
# INTEGRATION FUNCTIONS
# ============================================================================

def check_email_blocking(recipient_address: str, sender_address: str, 
                        sender_ip: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Simple function to check if an email should be blocked
    
    Args:
        recipient_address: Email address of the recipient
        sender_address: Email address of the sender
        sender_ip: IP address of the sending server
    
    Returns:
        Tuple of (should_block, reason)
    """
    # Extract recipient domain
    if '@' in recipient_address:
        recipient_domain = recipient_address.split('@')[1].lower()
    else:
        return (False, None)
    
    # Initialize engine (singleton pattern would be better in production)
    engine = EmailBlockingEngine()
    
    # Check blocking rules
    should_block, reason, rule = engine.should_block_email(
        recipient_domain,
        sender_address,
        sender_ip,
        recipient_address  # Pass full recipient address for recipient-specific rules
    )
    
    # Log if blocked
    if should_block and rule:
        engine.log_blocked_attempt(
            recipient_domain,
            sender_address,
            sender_ip,
            rule
        )
    
    return (should_block, reason)


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Command-line interface for managing blocking rules"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Email Blocking Management')
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Add client domain
    add_client = subparsers.add_parser('add-client', help='Add a client domain')
    add_client.add_argument('domain', help='Client domain')
    add_client.add_argument('--name', help='Client name')
    
    # Add blocking rule
    add_rule = subparsers.add_parser('add-rule', help='Add a blocking rule')
    add_rule.add_argument('domain', help='Client domain')
    add_rule.add_argument('type', choices=['domain', 'country', 'ip', 'cidr'], help='Rule type')
    add_rule.add_argument('value', help='Rule value (e.g., .cn, CN, 192.168.1.1)')
    add_rule.add_argument('--pattern', choices=['exact', 'wildcard', 'regex'], default='exact', help='Pattern type')
    add_rule.add_argument('--description', help='Rule description')
    add_rule.add_argument('--whitelist', action='store_true', help='This is a whitelist rule')
    add_rule.add_argument('--priority', type=int, default=100, help='Rule priority (lower = higher)')
    add_rule.add_argument('--recipient', help='Specific recipient pattern (e.g., douglas@covereddata.com)')
    
    # Test blocking
    test = subparsers.add_parser('test', help='Test if an email would be blocked')
    test.add_argument('recipient', help='Recipient email address')
    test.add_argument('sender', help='Sender email address')
    test.add_argument('--ip', help='Sender IP address')
    
    # Get stats
    stats = subparsers.add_parser('stats', help='Get blocking statistics')
    stats.add_argument('domain', help='Client domain')
    stats.add_argument('--days', type=int, default=7, help='Number of days to look back')

    # List rules
    list_rules = subparsers.add_parser('list-rules', help='List blocking rules for a domain')
    list_rules.add_argument('domain', help='Client domain')
    list_rules.add_argument('--all', action='store_true', help='Include inactive rules')

    # Remove rule
    remove_rule = subparsers.add_parser('remove-rule', help='Remove a blocking rule')
    remove_rule.add_argument('rule_id', type=int, help='Rule ID to remove')

    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    engine = EmailBlockingEngine()
    
    if args.command == 'add-client':
        success = engine.add_client_domain(args.domain, args.name)
        if success:
            print(f"✅ Added client domain: {args.domain}")
        else:
            print(f"❌ Failed to add client domain: {args.domain}")
    
    elif args.command == 'add-rule':
        success = engine.add_blocking_rule(
            args.domain,
            args.type,
            args.value,
            args.pattern,
            args.description,
            args.whitelist,
            args.priority,
            recipient_pattern=args.recipient if hasattr(args, 'recipient') else None
        )
        if success:
            print(f"✅ Added {'whitelist' if args.whitelist else 'blocking'} rule: {args.type}={args.value}")
        else:
            print(f"❌ Failed to add rule")
    
    elif args.command == 'test':
        should_block, reason = check_email_blocking(args.recipient, args.sender, args.ip)
        if should_block:
            print(f"🚫 BLOCK: {reason}")
        else:
            print(f"✅ ALLOW: Email would be delivered")
            if reason:
                print(f"   Note: {reason}")
    
    elif args.command == 'stats':
        stats = engine.get_blocking_stats(args.domain, args.days)
        if stats:
            print(f"\n📊 Blocking Statistics for {args.domain} (last {args.days} days)")
            print(f"   Total blocked: {stats['total_blocked']}")

            if stats['by_rule_type']:
                print("\n   By rule type:")
                for rule_type, count in stats['by_rule_type'].items():
                    print(f"      {rule_type}: {count}")

            if stats['top_blocked_domains']:
                print("\n   Top blocked domains:")
                for item in stats['top_blocked_domains'][:5]:
                    print(f"      {item['domain']}: {item['count']}")
        else:
            print(f"No statistics available for {args.domain}")

    elif args.command == 'list-rules':
        rules = engine.list_blocking_rules(args.domain, include_inactive=args.all)
        if rules:
            print(f"\n📋 Blocking Rules for {args.domain}")
            print("-" * 80)
            for rule in rules:
                status = "✅" if rule['active'] else "❌"
                wl = "[WL]" if rule['whitelist'] else ""
                print(f"{status} ID: {rule['id']:4} | {rule['type']:8} | {rule['value']:30} | {rule['recipient']:20}")
                if rule['description']:
                    print(f"         Description: {rule['description']}")
            print("-" * 80)
            print(f"Total: {len(rules)} rules")
        else:
            print(f"No rules found for {args.domain}")

    elif args.command == 'remove-rule':
        success = engine.remove_blocking_rule(args.rule_id)
        if success:
            print(f"✅ Successfully removed rule ID {args.rule_id}")
        else:
            print(f"❌ Failed to remove rule ID {args.rule_id}")


if __name__ == "__main__":
    main()