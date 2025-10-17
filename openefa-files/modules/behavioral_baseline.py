#!/usr/bin/env python3
"""
Behavioral Baseline and Anomaly Detection Module
Tracks normal sender behavior and detects account compromise indicators
Extends the existing conversation learning system
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import statistics
import hashlib
from collections import defaultdict

# Database imports
try:
    from sqlalchemy import create_engine, text, Column, Integer, String, Float, DateTime, Boolean, JSON
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import SQLAlchemyError
    import pymysql
    DB_AVAILABLE = True
except ImportError as e:
    DB_AVAILABLE = False
    print(f"Database libraries not available: {e}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BehavioralBaseline:
    """
    Tracks and analyzes sender behavioral patterns for anomaly detection
    """

    def __init__(self):
        self.engine = None
        self.session = None
        self.config = {}
        self._init_database()
        self._load_config()

    def _init_database(self):
        """Initialize database connection"""
        if not DB_AVAILABLE:
            logger.error("Database libraries not available")
            return

        try:
            # Read MySQL credentials
            with open('/opt/spacyserver/config/.my.cnf', 'r') as f:
                lines = f.readlines()
                config = {}
                for line in lines:
                    if '=' in line and not line.strip().startswith('['):
                        key, value = line.strip().split('=', 1)
                        config[key.strip()] = value.strip().strip('"')

            # Create database connection
            connection_string = f"mysql+pymysql://{config.get('user', 'spacy_user')}:{config.get('password', '')}@localhost/spacy_email_db"
            self.engine = create_engine(
                connection_string,
                pool_size=5,
                max_overflow=10,
                pool_recycle=3600
            )
            Session = sessionmaker(bind=self.engine)
            self.session = Session()

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    def _load_config(self):
        """Load configuration from database"""
        if not self.session:
            return

        # Default config values
        default_config = {
            'min_emails_for_baseline': '20',
            'volume_spike_threshold': '3.0',
            'new_recipient_threshold': '0.5',
            'time_anomaly_hours': '3',
            'anomaly_score_threshold': '7.0',
            'auto_quarantine_score': '9.0'
        }

        try:
            result = self.session.execute(
                text("SELECT config_key, config_value FROM behavioral_config")
            )
            for row in result:
                self.config[row[0]] = row[1]

            # If no config loaded from database, use defaults
            if not self.config:
                logger.warning("No behavioral_config found in database, using defaults")
                self.config = default_config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default config on error
            self.config = default_config

    def update_baseline(self, email_data: Dict) -> None:
        """
        Update sender's behavioral baseline with new email data
        """
        if not self.session:
            return

        try:
            sender_email = email_data.get('from', '').lower()
            if not sender_email or '@' not in sender_email:
                return

            sender_domain = sender_email.split('@')[1]
            current_hour = datetime.now().hour
            current_day = datetime.now().weekday()

            # Get or create baseline record
            baseline = self.session.execute(
                text("""
                    SELECT * FROM sender_behavior_baseline
                    WHERE sender_email = :email
                """),
                {'email': sender_email}
            ).fetchone()

            if baseline:
                # Update existing baseline
                self._update_existing_baseline(sender_email, email_data, baseline)
            else:
                # Create new baseline
                self._create_new_baseline(sender_email, sender_domain, email_data)

            # Update sending patterns
            self._update_sending_patterns(sender_email, current_hour)

            self.session.commit()

        except Exception as e:
            logger.error(f"Failed to update baseline: {e}")
            self.session.rollback()

    def _update_existing_baseline(self, sender_email: str, email_data: Dict, baseline: Any):
        """Update existing baseline record"""

        # Parse existing JSON fields
        typical_hours = json.loads(baseline.typical_send_hours or '[]')
        typical_days = json.loads(baseline.typical_send_days or '[]')
        typical_domains = json.loads(baseline.typical_recipient_domains or '{}')

        # Update time patterns
        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()

        if current_hour not in typical_hours:
            typical_hours.append(current_hour)
        if current_day not in typical_days:
            typical_days.append(current_day)

        # Update recipient patterns
        recipients = email_data.get('recipients', [])
        for recipient in recipients:
            if '@' in recipient:
                domain = recipient.split('@')[1].lower()
                typical_domains[domain] = typical_domains.get(domain, 0) + 1

        # Calculate new averages
        total_emails = baseline.total_emails_analyzed + 1
        avg_recipients = (baseline.avg_recipients_per_email * baseline.total_emails_analyzed +
                         len(recipients)) / total_emails

        # Update content patterns
        body_length = len(email_data.get('body', ''))
        avg_length = (baseline.avg_email_length * baseline.total_emails_analyzed +
                     body_length) / total_emails

        # Calculate consistency score
        consistency_score = self._calculate_consistency_score(
            typical_hours, typical_days, total_emails
        )

        # Update database
        self.session.execute(
            text("""
                UPDATE sender_behavior_baseline SET
                    typical_send_hours = :hours,
                    typical_send_days = :days,
                    typical_recipient_domains = :domains,
                    avg_recipients_per_email = :avg_recipients,
                    avg_email_length = :avg_length,
                    total_emails_analyzed = :total,
                    consistency_score = :consistency,
                    learning_confidence = :confidence,
                    last_updated = NOW()
                WHERE sender_email = :email
            """),
            {
                'hours': json.dumps(typical_hours),
                'days': json.dumps(typical_days),
                'domains': json.dumps(typical_domains),
                'avg_recipients': avg_recipients,
                'avg_length': avg_length,
                'total': total_emails,
                'consistency': consistency_score,
                'confidence': min(1.0, total_emails / float(self.config['min_emails_for_baseline'])),
                'email': sender_email
            }
        )

    def _create_new_baseline(self, sender_email: str, sender_domain: str, email_data: Dict):
        """Create new baseline record"""

        current_hour = datetime.now().hour
        current_day = datetime.now().weekday()

        recipients = email_data.get('recipients', [])
        recipient_domains = {}
        for recipient in recipients:
            if '@' in recipient:
                domain = recipient.split('@')[1].lower()
                recipient_domains[domain] = 1

        self.session.execute(
            text("""
                INSERT INTO sender_behavior_baseline (
                    sender_email, sender_domain, typical_send_hours, typical_send_days,
                    typical_recipient_domains, avg_recipients_per_email, avg_email_length,
                    total_emails_analyzed, learning_confidence
                ) VALUES (
                    :email, :domain, :hours, :days, :domains,
                    :avg_recipients, :avg_length, 1, 0.05
                )
            """),
            {
                'email': sender_email,
                'domain': sender_domain,
                'hours': json.dumps([current_hour]),
                'days': json.dumps([current_day]),
                'domains': json.dumps(recipient_domains),
                'avg_recipients': len(recipients),
                'avg_length': len(email_data.get('body', ''))
            }
        )

    def _update_sending_patterns(self, sender_email: str, current_hour: int):
        """Update hourly sending patterns"""

        today = datetime.now().date()

        # Try to update existing record
        result = self.session.execute(
            text(f"""
                UPDATE sending_patterns
                SET hour_{current_hour} = hour_{current_hour} + 1,
                    total_day = total_day + 1
                WHERE sender_email = :email AND pattern_date = :date
            """),
            {'email': sender_email, 'date': today}
        )

        # If no existing record, create new one
        if result.rowcount == 0:
            self.session.execute(
                text(f"""
                    INSERT INTO sending_patterns (sender_email, pattern_date, hour_{current_hour}, total_day)
                    VALUES (:email, :date, 1, 1)
                """),
                {'email': sender_email, 'date': today}
            )

    def check_anomalies(self, email_data: Dict) -> Dict[str, Any]:
        """
        Check for behavioral anomalies in email
        Returns anomaly details and risk score
        """

        if not self.session:
            return {'anomalies': [], 'risk_score': 0, 'should_flag': False}

        anomalies = []
        risk_score = 0

        try:
            sender_email = email_data.get('from', '').lower()
            if not sender_email or '@' not in sender_email:
                return {'anomalies': [], 'risk_score': 0, 'should_flag': False}

            # Get sender's baseline
            baseline = self.session.execute(
                text("""
                    SELECT * FROM sender_behavior_baseline
                    WHERE sender_email = :email
                """),
                {'email': sender_email}
            ).fetchone()

            if not baseline:
                # No baseline yet, can't detect anomalies
                return {'anomalies': [], 'risk_score': 0, 'should_flag': False}

            # Only check anomalies if we have enough data
            if baseline.learning_confidence < 0.3:
                return {'anomalies': [], 'risk_score': 0, 'should_flag': False}

            # Check time anomaly
            time_anomaly = self._check_time_anomaly(baseline)
            if time_anomaly:
                anomalies.append(time_anomaly)
                risk_score += time_anomaly['score']

            # Check volume anomaly
            volume_anomaly = self._check_volume_anomaly(sender_email, baseline)
            if volume_anomaly:
                anomalies.append(volume_anomaly)
                risk_score += volume_anomaly['score']

            # Check recipient anomaly
            recipient_anomaly = self._check_recipient_anomaly(email_data, baseline)
            if recipient_anomaly:
                anomalies.append(recipient_anomaly)
                risk_score += recipient_anomaly['score']

            # Check content anomaly
            content_anomaly = self._check_content_anomaly(email_data, baseline)
            if content_anomaly:
                anomalies.append(content_anomaly)
                risk_score += content_anomaly['score']

            # Log anomalies if significant
            if risk_score >= float(self.config['anomaly_score_threshold']):
                self._log_anomalies(sender_email, email_data, anomalies, risk_score)

            return {
                'anomalies': anomalies,
                'risk_score': risk_score,
                'should_flag': risk_score >= float(self.config['anomaly_score_threshold']),
                'should_quarantine': risk_score >= float(self.config['auto_quarantine_score']),
                'baseline_confidence': baseline.learning_confidence
            }

        except Exception as e:
            logger.error(f"Failed to check anomalies: {e}")
            return {'anomalies': [], 'risk_score': 0, 'should_flag': False}

    def _check_time_anomaly(self, baseline: Any) -> Optional[Dict]:
        """Check if email sent at unusual time"""

        current_hour = datetime.now().hour
        typical_hours = json.loads(baseline.typical_send_hours or '[]')

        if not typical_hours:
            return None

        # Check if current hour is within typical range
        min_hour = min(typical_hours)
        max_hour = max(typical_hours)
        threshold = int(self.config['time_anomaly_hours'])

        # Handle wrap-around (e.g., typical hours are 22,23,0,1,2)
        if max_hour - min_hour > 12:
            # Likely wraps around midnight
            if current_hour > max_hour and current_hour < min_hour:
                hours_outside = min(current_hour - max_hour, min_hour - current_hour)
            else:
                hours_outside = 0
        else:
            # Normal range
            if current_hour < min_hour - threshold or current_hour > max_hour + threshold:
                hours_outside = min(abs(current_hour - min_hour), abs(current_hour - max_hour))
            else:
                hours_outside = 0

        if hours_outside > threshold:
            severity = 'high' if hours_outside > threshold * 2 else 'medium'
            score = 4 if severity == 'high' else 2

            return {
                'type': 'time',
                'severity': severity,
                'score': score,
                'description': f'Email sent {hours_outside} hours outside typical window',
                'expected': f'Hours {min_hour}-{max_hour}',
                'actual': f'Hour {current_hour}'
            }

        return None

    def _check_volume_anomaly(self, sender_email: str, baseline: Any) -> Optional[Dict]:
        """Check for volume spikes"""

        # Get today's volume
        today = datetime.now().date()
        result = self.session.execute(
            text("""
                SELECT total_day FROM sending_patterns
                WHERE sender_email = :email AND pattern_date = :date
            """),
            {'email': sender_email, 'date': today}
        ).fetchone()

        if not result:
            return None

        current_volume = result[0]
        threshold = float(self.config['volume_spike_threshold'])

        # Compare to average
        if baseline.avg_daily_volume > 0 and current_volume > baseline.avg_daily_volume * threshold:
            severity = 'critical' if current_volume > baseline.avg_daily_volume * threshold * 2 else 'high'
            score = 6 if severity == 'critical' else 4

            return {
                'type': 'volume',
                'severity': severity,
                'score': score,
                'description': f'Volume spike detected: {current_volume} emails today',
                'expected': f'Average {baseline.avg_daily_volume:.1f} emails/day',
                'actual': f'{current_volume} emails',
                'deviation': f'{(current_volume / baseline.avg_daily_volume - 1) * 100:.0f}% increase'
            }

        return None

    def _check_recipient_anomaly(self, email_data: Dict, baseline: Any) -> Optional[Dict]:
        """Check for unusual recipients"""

        recipients = email_data.get('recipients', [])
        if not recipients:
            return None

        typical_domains = json.loads(baseline.typical_recipient_domains or '{}')
        if not typical_domains:
            return None

        # Check for new domains
        new_domains = []
        suspicious_domains = []

        for recipient in recipients:
            if '@' in recipient:
                domain = recipient.split('@')[1].lower()
                if domain not in typical_domains:
                    new_domains.append(domain)
                    # Extra suspicious if financial/sensitive domain
                    if any(keyword in domain for keyword in ['bank', 'finance', 'pay', 'money', 'wire']):
                        suspicious_domains.append(domain)

        if new_domains:
            new_ratio = len(new_domains) / len(recipients)
            threshold = float(self.config['new_recipient_threshold'])

            if new_ratio > threshold or suspicious_domains:
                severity = 'critical' if suspicious_domains else ('high' if new_ratio > 0.8 else 'medium')
                score = 5 if suspicious_domains else (3 if new_ratio > 0.8 else 2)

                description = f'Emailing {len(new_domains)} new domain(s)'
                if suspicious_domains:
                    description += f' including suspicious: {", ".join(suspicious_domains)}'

                return {
                    'type': 'recipient',
                    'severity': severity,
                    'score': score,
                    'description': description,
                    'new_domains': new_domains,
                    'suspicious': suspicious_domains
                }

        return None

    def _check_content_anomaly(self, email_data: Dict, baseline: Any) -> Optional[Dict]:
        """Check for content anomalies"""

        body_length = len(email_data.get('body', ''))
        subject = email_data.get('subject', '').lower()

        anomalies = []

        # Check length deviation
        if baseline.avg_email_length > 0:
            length_ratio = body_length / baseline.avg_email_length
            if length_ratio > 3 or length_ratio < 0.2:
                anomalies.append(f'Unusual length ({length_ratio:.1f}x normal)')

        # Check for suspicious content changes
        suspicious_keywords = [
            'urgent', 'wire', 'transfer', 'payment', 'invoice',
            'click here', 'verify', 'suspended', 'expired'
        ]

        found_keywords = [kw for kw in suspicious_keywords if kw in subject or kw in email_data.get('body', '').lower()]

        if found_keywords and baseline.consistency_score > 0.7:
            # High consistency sender suddenly using suspicious words
            anomalies.append(f'Suspicious keywords: {", ".join(found_keywords)}')

        if anomalies:
            return {
                'type': 'content',
                'severity': 'high' if len(found_keywords) > 2 else 'medium',
                'score': 4 if len(found_keywords) > 2 else 2,
                'description': '; '.join(anomalies)
            }

        return None

    def _calculate_consistency_score(self, typical_hours: List[int], typical_days: List[int],
                                    total_emails: int) -> float:
        """Calculate how consistent a sender's behavior is"""

        if total_emails < 10:
            return 0.0

        # Factor 1: Time consistency (fewer different hours = more consistent)
        hour_consistency = 1.0 - (len(typical_hours) / 24.0)

        # Factor 2: Day consistency (fewer different days = more consistent)
        day_consistency = 1.0 - (len(typical_days) / 7.0)

        # Factor 3: Volume consistency (would need historical data)
        volume_consistency = 0.5  # Placeholder

        # Weighted average
        consistency = (hour_consistency * 0.4 + day_consistency * 0.3 + volume_consistency * 0.3)

        # Boost by confidence (more emails = more reliable)
        confidence_boost = min(1.0, total_emails / 100.0)

        return min(1.0, consistency * (1 + confidence_boost * 0.2))

    def _log_anomalies(self, sender_email: str, email_data: Dict, anomalies: List[Dict], risk_score: float):
        """Log detected anomalies to database"""

        try:
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'low')
                action = 'quarantined' if risk_score >= float(self.config['auto_quarantine_score']) else 'flagged'

                self.session.execute(
                    text("""
                        INSERT INTO behavioral_anomalies (
                            sender_email, recipient_email, message_id,
                            anomaly_type, anomaly_severity, anomaly_score,
                            expected_value, actual_value, description, action_taken
                        ) VALUES (
                            :sender, :recipient, :message_id,
                            :type, :severity, :score,
                            :expected, :actual, :description, :action
                        )
                    """),
                    {
                        'sender': sender_email,
                        'recipient': json.dumps(email_data.get('recipients', [])),
                        'message_id': email_data.get('message_id', ''),
                        'type': anomaly['type'],
                        'severity': severity,
                        'score': anomaly['score'],
                        'expected': json.dumps({'value': anomaly.get('expected', '')}),
                        'actual': json.dumps({'value': anomaly.get('actual', '')}),
                        'description': anomaly['description'],
                        'action': action
                    }
                )

            # Update baseline anomaly count
            self.session.execute(
                text("""
                    UPDATE sender_behavior_baseline
                    SET anomaly_count = anomaly_count + 1,
                        last_anomaly_date = NOW()
                    WHERE sender_email = :email
                """),
                {'email': sender_email}
            )

            # Check for compromise indicators
            if risk_score >= 7:
                self._check_compromise_indicators(sender_email, anomalies)

            self.session.commit()

        except Exception as e:
            logger.error(f"Failed to log anomalies: {e}")
            self.session.rollback()

    def _check_compromise_indicators(self, sender_email: str, anomalies: List[Dict]):
        """Check if anomalies indicate account compromise"""

        indicators = {
            'sudden_volume_spike': any(a['type'] == 'volume' and a['severity'] in ['high', 'critical'] for a in anomalies),
            'unusual_send_time': any(a['type'] == 'time' and a['severity'] in ['high', 'critical'] for a in anomalies),
            'new_recipient_pattern': any(a['type'] == 'recipient' for a in anomalies),
            'suspicious_content_change': any(a['type'] == 'content' for a in anomalies)
        }

        total_indicators = sum(indicators.values())

        if total_indicators >= 2:
            # Multiple indicators - possible compromise
            self.session.execute(
                text("""
                    INSERT INTO compromise_indicators (
                        sender_email, sudden_volume_spike, unusual_send_time,
                        new_recipient_pattern, suspicious_content_change,
                        total_indicators, risk_score, details
                    ) VALUES (
                        :email, :volume, :time, :recipient, :content,
                        :total, :risk, :details
                    )
                """),
                {
                    'email': sender_email,
                    'volume': indicators['sudden_volume_spike'],
                    'time': indicators['unusual_send_time'],
                    'recipient': indicators['new_recipient_pattern'],
                    'content': indicators['suspicious_content_change'],
                    'total': total_indicators,
                    'risk': sum(a['score'] for a in anomalies),
                    'details': json.dumps([a['description'] for a in anomalies])
                }
            )

    def get_sender_status(self, sender_email: str) -> Dict[str, Any]:
        """Get current behavioral status for a sender"""

        if not self.session:
            return {}

        try:
            result = self.session.execute(
                text("""
                    SELECT * FROM sender_anomaly_status
                    WHERE sender_email = :email
                """),
                {'email': sender_email}
            ).fetchone()

            if result:
                return {
                    'sender': result.sender_email,
                    'baseline_status': result.baseline_status,
                    'emails_analyzed': result.total_emails_analyzed,
                    'confidence': result.learning_confidence,
                    'recent_anomalies': result.recent_anomalies_7d,
                    'highest_severity': result.highest_severity_7d
                }

            return {'sender': sender_email, 'baseline_status': 'No baseline'}

        except Exception as e:
            logger.error(f"Failed to get sender status: {e}")
            return {}


# Integration function for SpaCy email filter
def analyze_behavior(email_data: Dict) -> Dict[str, Any]:
    """
    Main entry point for behavioral analysis
    Compatible with SpaCy email filter
    """

    analyzer = BehavioralBaseline()

    # Check for anomalies
    anomaly_results = analyzer.check_anomalies(email_data)

    # Update baseline (learning)
    analyzer.update_baseline(email_data)

    # Prepare results for email filter
    results = {
        'behavioral_risk_score': anomaly_results['risk_score'],
        'anomalies_detected': len(anomaly_results['anomalies']),
        'should_flag': anomaly_results['should_flag'],
        'should_quarantine': anomaly_results['should_quarantine'],
        'headers_to_add': {}
    }

    # Add headers for MailGuard
    if anomaly_results['risk_score'] > 0:
        results['headers_to_add']['X-Behavioral-Risk'] = str(anomaly_results['risk_score'])
        results['headers_to_add']['X-Behavioral-Anomalies'] = str(len(anomaly_results['anomalies']))

        if anomaly_results['should_flag']:
            results['headers_to_add']['X-Behavioral-Flag'] = 'suspicious'

        if anomaly_results['should_quarantine']:
            results['headers_to_add']['X-Behavioral-Action'] = 'quarantine'

        # Add specific anomaly types
        anomaly_types = list(set([a['type'] for a in anomaly_results['anomalies']]))
        if anomaly_types:
            results['headers_to_add']['X-Behavioral-Types'] = ','.join(anomaly_types)

    return results