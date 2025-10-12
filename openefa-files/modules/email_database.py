#!/usr/bin/env python3
"""
Email Database Module for SpaCy Email Analytics System

Handles MariaDB database operations for storing email analysis results.
Features proper session management to prevent connection leaks.

Author: SpaCy Email Analytics Team
Location: /opt/spacyserver/modules/email_database.py
"""

import os
import sys
import json
import email.utils
import configparser
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

# Database imports
try:
    from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, Boolean, text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import SQLAlchemyError
except ImportError as e:
    print(f"SQLAlchemy import error: {e}")
    sys.exit(1)

# Base class for database models
Base = declarative_base()

def safe_log(message, level="INFO"):
    if level in ["ERROR", "WARNING"]:
        print(f"[{level}] {message}", flush=True)
        return
    """Silent logging - does nothing to avoid console spam"""
    pass


class SpacyAnalysis(Base):
    """Database model for SpaCy email analysis results"""
    __tablename__ = 'email_analysis'  # Updated to match renamed table

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    message_id = Column(String(255), nullable=False)
    sender = Column(String(255))
    recipients = Column(Text)
    subject = Column(String(500))
    spam_score = Column(Float, default=0.0)
    entities = Column(Text)  # JSON string of entities
    all_links_count = Column(Integer, default=0)
    suspicious_links = Column(Text)  # JSON string
    model_name = Column(String(100), default="en_core_web_lg")
    raw_text_length = Column(Integer, default=0)
    urgency_score = Column(Float, default=0.0)
    entity_combos = Column(Text)  # JSON string
    sentiment_score = Column(Float, default=0.0)
    email_category = Column(String(100), default="general")
    email_topics = Column(Text)  # JSON string
    content_summary = Column(Text)
    detected_language = Column(String(10), default="en")
    language_confidence = Column(Float, default=1.0)
    sentiment_polarity = Column(Float, default=0.0)
    sentiment_subjectivity = Column(Float, default=0.0)
    sentiment_extremity = Column(Float, default=0.0)
    sentiment_manipulation = Column(Float, default=0.0)
    manipulation_indicators = Column(Text)  # JSON string
    category_confidence = Column(Float, default=1.0)
    secondary_categories = Column(Text)  # JSON string
    classification_scores = Column(Text)  # JSON string
    has_attachments = Column(Boolean, default=False)
    training_data_saved = Column(Integer, default=0)

    def __repr__(self):
        return f"<SpacyAnalysis(id={self.id}, message_id='{self.message_id[:30]}...', timestamp='{self.timestamp}')>"


class EmailDatabaseHandler:
    """Handles database operations for email analytics"""

    def __init__(self, config_path="/opt/spacyserver/config/.my.cnf"):
        """Initialize database connection"""
        self.config_path = config_path
        self.engine = None
        self.SessionLocal = None
        self.db_ready = False

        # Initialize database connection
        self._initialize_database()

    def _load_database_config(self):
        """Load database configuration from .my.cnf file"""
        try:
            # Try ConfigParser first
            config = configparser.ConfigParser()
            config.read(self.config_path)

            if config.has_section('client'):
                # Extract connection details using ConfigParser
                user = config.get('client', 'user', fallback='spacy_user')
                password = config.get('client', 'password', fallback='')
                host = config.get('client', 'host', fallback='localhost')
                try:
                    port = config.getint('client', 'port', fallback=3306)
                except ValueError:
                    port = 3306

                db_config = {
                    'user': user,
                    'password': password,
                    'host': host,
                    'port': port,
                    'database': 'spacy_email_db'
                }

                return db_config
            else:
                return None

        except Exception as e:
            # Fallback: try manual parsing
            try:
                return self._manual_parse_config()
            except Exception as e2:
                return None

    def _manual_parse_config(self):
        """Manually parse .my.cnf file as fallback"""
        db_config = {
            'user': 'spacy_user',
            'password': '',
            'host': 'localhost',
            'port': 3306,
            'database': 'spacy_email_db'
        }

        with open(self.config_path, 'r') as f:
            in_client_section = False
            for line in f:
                line = line.strip()
                if line == '[client]':
                    in_client_section = True
                    continue
                elif line.startswith('[') and line.endswith(']'):
                    in_client_section = False
                    continue

                if in_client_section and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')  # Remove quotes

                    if key in db_config:
                        if key == 'port':
                            try:
                                db_config[key] = int(value)
                            except ValueError:
                                db_config[key] = 3306
                        else:
                            db_config[key] = value

        return db_config

    def _initialize_database(self):
        """Initialize database connection and create tables if needed"""
        try:
            db_config = self._load_database_config()
            if not db_config:
                return

            # Create database URL
            db_url = (f"mysql+pymysql://{db_config['user']}:{db_config['password']}"
                     f"@{db_config['host']}:{db_config['port']}/{db_config['database']}")

            # Create engine with connection pooling
            self.engine = create_engine(
                db_url,
                pool_size=5,
                max_overflow=10,
                pool_pre_ping=True,  # Verify connections before use
                pool_recycle=3600,   # Recycle connections every hour
                echo=False
            )

            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )

            # Create tables if they don't exist
            Base.metadata.create_all(bind=self.engine)

            self.db_ready = True

        except Exception as e:
            self.db_ready = False

    def get_db_session(self):
        """Get a new database session"""
        if not self.db_ready:
            raise RuntimeError("Database not ready")

        return self.SessionLocal()

    def test_connection(self):
        """Test database connectivity"""
        if not self.db_ready:
            return False

        session = None
        try:
            session = self.get_db_session()
            # Simple query to test connection - SQLAlchemy 2.0 compatible
            result = session.execute(text("SELECT 1")).fetchone()
            return True

        except Exception as e:
            return False

        finally:
            if session:
                session.close()

    def store_analysis(self, msg, text_content, spam_score, entities, all_links, suspicious_links,
                      urgency_score=0.0, entity_combos=None, sentiment_analysis=None, classification=None,
                      email_topics=None, content_summary="", detected_language="en", language_confidence=1.0,
                      model_name="en_core_web_lg", has_attachments=False, training_data_saved=0):
        """Store analysis in MariaDB database with proper session management"""
        if not self.db_ready:
            return False

        session = None
        try:
            session = self.get_db_session()

            message_id = msg.get('Message-ID', '')
            sender = msg.get('From', '')
            recipients = '; '.join([addr for name, addr in email.utils.getaddresses(msg.get_all('To', []))])
            subject = msg.get('Subject', '')
            entity_strings = [f"{ent.get('text')} ({ent.get('label')})" for ent in entities]

            # Set default objects if None to prevent JSON serialization errors
            sentiment_analysis = sentiment_analysis or {
                "polarity": 0.0,
                "subjectivity": 0.0,
                "extremity_score": 0.0,
                "manipulation_score": 0.0,
                "manipulation_indicators": []
            }

            classification = classification or {
                "primary_category": "general",
                "confidence": 1.0,
                "top_categories": [("general", 1.0)],
                "all_scores": {}
            }

            # Create new SpacyAnalysis object
            new_analysis = SpacyAnalysis(
                message_id=message_id,
                sender=sender,
                recipients=recipients,
                subject=subject,
                spam_score=spam_score,
                entities=json.dumps(entity_strings),
                all_links_count=len(all_links),
                suspicious_links=json.dumps(suspicious_links[:10]),
                model_name=model_name,
                raw_text_length=len(text_content),
                urgency_score=urgency_score,
                entity_combos=json.dumps(entity_combos or []),
                sentiment_score=sentiment_analysis["polarity"],
                email_category=classification["primary_category"],
                email_topics=json.dumps(email_topics or []),
                content_summary=content_summary,
                detected_language=detected_language,
                language_confidence=language_confidence,
                sentiment_polarity=sentiment_analysis["polarity"],
                sentiment_subjectivity=sentiment_analysis["subjectivity"],
                sentiment_extremity=sentiment_analysis["extremity_score"],
                sentiment_manipulation=sentiment_analysis["manipulation_score"],
                manipulation_indicators=json.dumps(sentiment_analysis["manipulation_indicators"]),
                category_confidence=classification["confidence"],
                secondary_categories=json.dumps([cat for cat, score in classification["top_categories"][1:3]] if len(classification["top_categories"]) > 1 else []),
                classification_scores=json.dumps(classification["all_scores"]),
                has_attachments=1 if has_attachments else 0,
                training_data_saved=training_data_saved
            )

            # Add to session and commit
            session.add(new_analysis)
            session.commit()

            return True

        except Exception as e:
            if session:
                try:
                    session.rollback()
                except Exception as rollback_error:
                    pass
            return False
        finally:
            # CRITICAL: Always close the session regardless of success/failure
            if session:
                try:
                    session.close()
                except Exception as close_error:
                    pass

    def get_recent_analyses(self, limit=10):
        """Retrieve recent email analyses"""
        if not self.db_ready:
            return []

        session = None
        try:
            session = self.get_db_session()
            analyses = session.query(SpacyAnalysis)\
                             .order_by(SpacyAnalysis.timestamp.desc())\
                             .limit(limit)\
                             .all()

            results = []
            for analysis in analyses:
                results.append({
                    'id': analysis.id,
                    'timestamp': analysis.timestamp,
                    'message_id': analysis.message_id,
                    'sender': analysis.sender,
                    'subject': analysis.subject,
                    'spam_score': analysis.spam_score,
                    'sentiment_score': analysis.sentiment_score,
                    'email_category': analysis.email_category
                })

            return results

        except Exception as e:
            return []
        finally:
            if session:
                session.close()

    def get_stats(self):
        """Get database statistics"""
        if not self.db_ready:
            return {'error': 'Database not ready'}

        session = None
        try:
            session = self.get_db_session()

            # Total count
            total_count = session.query(SpacyAnalysis).count()

            # Today's count
            today = datetime.now().date()
            today_count = session.query(SpacyAnalysis)\
                               .filter(SpacyAnalysis.timestamp >= today)\
                               .count()

            # Latest timestamp
            latest = session.query(SpacyAnalysis)\
                           .order_by(SpacyAnalysis.timestamp.desc())\
                           .first()

            latest_timestamp = latest.timestamp if latest else None

            return {
                'total_emails': total_count,
                'todays_emails': today_count,
                'latest_timestamp': latest_timestamp
            }

        except Exception as e:
            return {'error': str(e)}
        finally:
            if session:
                session.close()


# Global database handler instance
database_handler = EmailDatabaseHandler()


def get_database_handler():
    """Get the global database handler instance"""
    return database_handler


# Test functions for debugging
def test_database_connection():
    """Test database connectivity - for debugging"""
    handler = get_database_handler()
    if handler.test_connection():
        stats = handler.get_stats()
        return True
    return False


def main():
    """Main function for testing the database module"""
    # Test connection
    if test_database_connection():
        pass
    else:
        sys.exit(1)

    # Test basic functionality
    handler = get_database_handler()
    stats = handler.get_stats()

    recent = handler.get_recent_analyses(5)


if __name__ == "__main__":
    main()
