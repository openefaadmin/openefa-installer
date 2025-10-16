#!/opt/spacyserver/venv/bin/python3
"""
Production SpaCy Database Processor - FIXED SENDER EXTRACTION
Processes Redis queue messages from the production email filter and stores them in spacy_analysis table
"""

import json
import time
import logging
import redis
import pymysql
import traceback
import re
from datetime import datetime
from typing import Dict, Any, Optional
from email.parser import BytesParser
from email.policy import default

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/spacyserver/logs/db_processor.log')
    ]
)
logger = logging.getLogger(__name__)

class ProductionSpaCyDatabaseProcessor:
    def __init__(self):
        self.redis_client = None
        self.db_connection = None
        self.last_connection_time = None
        self.connection_lifetime = 240  # Close connection after 4 minutes (less than wait_timeout=300)
        self.connect_to_services()
    
    def connect_to_services(self):
        """Connect to Redis and MySQL"""
        try:
            # Connect to Redis
            self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            self.redis_client.ping()
            logger.info("✅ Connected to Redis")
            
            # Connect to MySQL using config file with auto-reconnect
            self.db_connection = pymysql.connect(
                read_default_file='/opt/spacyserver/config/.my.cnf',
                database='spacy_email_db',
                charset='utf8mb4',
                autocommit=False,
                connect_timeout=10,
                read_timeout=30,
                write_timeout=30
            )
            self.last_connection_time = time.time()
            logger.info("✅ Connected to MySQL database")
            
        except Exception as e:
            logger.error(f"❌ Connection error: {e}")
            raise
    
    def ensure_db_connection(self):
        """Ensure database connection is alive, reconnect if necessary"""
        try:
            # Check if connection is too old (prevent timeout issues)
            if self.last_connection_time and (time.time() - self.last_connection_time) > self.connection_lifetime:
                logger.info("🔄 Connection lifetime exceeded, creating fresh connection")
                if self.db_connection:
                    try:
                        self.db_connection.close()
                    except:
                        pass
                self.db_connection = None
            
            # If no connection or connection is dead, create new one
            if not self.db_connection:
                self.db_connection = pymysql.connect(
                    read_default_file='/opt/spacyserver/config/.my.cnf',
                    database='spacy_email_db',
                    charset='utf8mb4',
                    autocommit=False,
                    connect_timeout=10,
                    read_timeout=30,
                    write_timeout=30
                )
                self.last_connection_time = time.time()
                logger.info("✅ Created new MySQL connection")
            else:
                # Try to ping the database
                self.db_connection.ping(reconnect=True)
        except Exception as e:
            logger.warning(f"⚠️ Database connection issue, creating new connection: {e}")
            try:
                if self.db_connection:
                    try:
                        self.db_connection.close()
                    except:
                        pass
                
                self.db_connection = pymysql.connect(
                    read_default_file='/opt/spacyserver/config/.my.cnf',
                    database='spacy_email_db',
                    charset='utf8mb4',
                    autocommit=False,
                    connect_timeout=10,
                    read_timeout=30,
                    write_timeout=30
                )
                self.last_connection_time = time.time()
                logger.info("✅ Reconnected to MySQL database")
            except Exception as reconnect_error:
                logger.error(f"❌ Failed to reconnect: {reconnect_error}")
                raise
    
    def safe_json_value(self, value: Any, default: str = '') -> str:
        """Safely convert value to JSON string for database storage"""
        try:
            if value is None:
                return default
            elif isinstance(value, (dict, list)):
                return json.dumps(value)
            else:
                return str(value)
        except Exception:
            return default
    
    def extract_email_from_header(self, from_header: str) -> str:
        """Extract email address from From header"""
        try:
            if not from_header:
                return ''
            
            from_header = str(from_header).strip()
            
            if '<' in from_header and '>' in from_header:
                email_match = re.search(r'<([^>]+)>', from_header)
                if email_match:
                    email = email_match.group(1).strip()
                    if '@' in email and '.' in email.split('@')[-1]:
                        return email
            
            email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_header)
            if email_match:
                return email_match.group(0).strip()
            
            clean_header = from_header.strip('<>')
            if '@' in clean_header and '.' in clean_header:
                return clean_header
            
            return from_header.strip()
            
        except Exception as e:
            logger.error(f"Error extracting email from header: {e}")
            return str(from_header).strip() if from_header else ''
    
    def parse_email_message(self, message_str: str) -> Dict[str, Any]:
        """Parse email message string to extract metadata"""
        try:
            parser = BytesParser(policy=default)
            msg = parser.parsebytes(message_str.encode('utf-8'))
            
            return {
                'subject': str(msg.get('Subject', '')),
                'sender': self.extract_email_from_header(str(msg.get('From', ''))),
                'message_id': str(msg.get('Message-ID', '')),
                'has_attachments': 1 if len([part for part in msg.walk() if part.get_content_disposition() == 'attachment']) > 0 else 0
            }
        except Exception as e:
            logger.error(f"Error parsing email message: {e}")
            return {
                'subject': '',
                'sender': '',
                'message_id': '',
                'has_attachments': 0
            }
    
    def process_production_email_data(self, queue_data: Dict[str, Any]) -> bool:
        """Process email data from production email filter and insert into database - FIXED SENDER EXTRACTION"""
        try:
            # Ensure database connection is alive
            self.ensure_db_connection()
            
            with self.db_connection.cursor() as cursor:
                # Extract data from the production email filter format
                email_data = queue_data.get('email_data', {})
                analysis_results = queue_data.get('analysis_results', {})
                
                # DEBUG: Log the incoming data structure
                logger.info(f"📧 Processing email_data keys: {list(email_data.keys())}")
                
                # Parse the email message to extract additional metadata
                message_str = email_data.get('message', '')
                parsed_email = self.parse_email_message(message_str) if message_str else {}
                
                # Extract core email information
                timestamp = datetime.now()
                message_id = email_data.get('message_id', parsed_email.get('message_id', ''))
                if not message_id:
                    # Generate a message ID if none exists
                    timestamp_str = datetime.now().strftime('%Y%m%d%H%M%S')
                    message_id = f"<spacy-production-{timestamp_str}@example.com>"
                
                # FIXED: Better sender extraction logic
                sender = ''
                
                # Try multiple sources for sender information
                from_header = email_data.get('from_header', '')
                if from_header:
                    sender = self.extract_email_from_header(from_header)
                    logger.info(f"🔍 Extracted sender from from_header: '{from_header}' → '{sender}'")
                
                # Fallback to parsed email sender
                if not sender and parsed_email.get('sender'):
                    sender = parsed_email.get('sender', '')
                    logger.info(f"🔍 Using parsed email sender: '{sender}'")
                
                # Final fallback - try to extract from message
                if not sender and message_str:
                    # Try to find From: line in message
                    from_match = re.search(r'^From:\s*(.+)$', message_str, re.MULTILINE | re.IGNORECASE)
                    if from_match:
                        sender = self.extract_email_from_header(from_match.group(1))
                        logger.info(f"🔍 Extracted sender from message From line: '{sender}'")
                
                # If still no sender, use a placeholder
                if not sender:
                    sender = 'unknown@unknown.com'
                    logger.warning(f"⚠️  No sender found, using placeholder: '{sender}'")
                
                recipients = email_data.get('recipients', [])
                if isinstance(recipients, list):
                    recipients = ', '.join(recipients)
                elif not recipients:
                    recipients = ''
                
                subject = parsed_email.get('subject', '')
                
                # Try to extract subject from message if not in parsed_email
                if not subject and message_str:
                    subject_match = re.search(r'^Subject:\s*(.+)$', message_str, re.MULTILINE | re.IGNORECASE)
                    if subject_match:
                        subject = subject_match.group(1).strip()
                
                spam_score = float(analysis_results.get('spam_score', 0.0))
                
                # Text content and analysis
                text_content = email_data.get('text_content', '')
                raw_text_length = len(text_content)
                
                # Handle analysis results
                entities = self.safe_json_value(analysis_results.get('entities', []), '[]')
                all_links_count = int(analysis_results.get('all_links_count', 0))
                suspicious_links = self.safe_json_value(analysis_results.get('suspicious_links', []), '[]')
                
                # Analysis metadata
                model_name = analysis_results.get('model_name', 'en_core_web_lg')
                urgency_score = float(analysis_results.get('urgency_score', 0.0))
                entity_combos = self.safe_json_value(analysis_results.get('entity_combos', []), '[]')
                
                # Sentiment analysis
                sentiment_analysis = analysis_results.get('sentiment_analysis', {})
                sentiment_score = float(sentiment_analysis.get('polarity', 0.0))
                sentiment_polarity = float(sentiment_analysis.get('polarity', 0.0))
                sentiment_subjectivity = float(sentiment_analysis.get('subjectivity', 0.0))
                sentiment_extremity = float(sentiment_analysis.get('extremity_score', 0.0))
                sentiment_manipulation = float(sentiment_analysis.get('manipulation_score', 0.0))
                manipulation_indicators = self.safe_json_value(sentiment_analysis.get('manipulation_indicators', []), '[]')
                
                # Classification
                classification = analysis_results.get('classification', {})
                email_category = email_data.get('analysis_level', classification.get('primary_category', 'unknown'))
                if email_data.get('is_journal', False):
                    email_category = 'journal_archive'
                
                email_topics = self.safe_json_value(classification.get('email_topics', []), '[]')
                content_summary = email_data.get('content_summary', '')
                category_confidence = float(classification.get('confidence', 0.0))
                secondary_categories = self.safe_json_value(classification.get('top_categories', []), '[]')
                classification_scores = self.safe_json_value(classification.get('all_scores', {}), '{}')
                
                # Language detection
                language_results = analysis_results.get('language_analysis', {})
                detected_language = language_results.get('detected_language', 'en')
                language_confidence = float(language_results.get('confidence', 1.0))
                
                # Attachments and training data
                has_attachments = parsed_email.get('has_attachments', 0)
                training_data_saved = int(analysis_results.get('training_data_saved', 0))
                
                # Extract authentication headers (SPF, DKIM, DMARC) from raw email
                original_spf = None
                original_dkim = None
                original_dmarc = None

                if message_str:
                    try:
                        from email import message_from_string
                        import re
                        msg = message_from_string(message_str)

                        # Check for custom X-SpaCy-Auth-Results header first (our system's results)
                        spacy_auth = msg.get('X-SpaCy-Auth-Results', '')
                        if spacy_auth:
                            # Parse format: "openspacy; spf=pass; dkim=fail; dmarc=pass (p=reject)"
                            if 'spf=' in spacy_auth:
                                spf_match = re.search(r'spf=(\w+)', spacy_auth, re.IGNORECASE)
                                if spf_match:
                                    original_spf = spf_match.group(1)

                            if 'dkim=' in spacy_auth:
                                dkim_match = re.search(r'dkim=(\w+)', spacy_auth, re.IGNORECASE)
                                if dkim_match:
                                    original_dkim = dkim_match.group(1)

                            if 'dmarc=' in spacy_auth:
                                dmarc_match = re.search(r'dmarc=(\w+)', spacy_auth, re.IGNORECASE)
                                if dmarc_match:
                                    original_dmarc = dmarc_match.group(1)

                        # Fallback: Check standard headers if custom headers not found
                        if not original_spf:
                            spf_header = msg.get('Received-SPF', '')
                            if spf_header:
                                spf_parts = spf_header.lower().split()
                                if spf_parts:
                                    original_spf = spf_parts[0]

                        if not original_dkim or not original_dmarc:
                            auth_results = msg.get('Authentication-Results', '')
                            if auth_results:
                                if not original_dkim:
                                    if 'dkim=pass' in auth_results.lower():
                                        original_dkim = 'pass'
                                    elif 'dkim=fail' in auth_results.lower():
                                        original_dkim = 'fail'
                                    elif 'dkim=neutral' in auth_results.lower():
                                        original_dkim = 'neutral'
                                    elif 'dkim=none' in auth_results.lower():
                                        original_dkim = 'none'

                                if not original_dmarc:
                                    if 'dmarc=pass' in auth_results.lower():
                                        original_dmarc = 'pass'
                                    elif 'dmarc=fail' in auth_results.lower():
                                        original_dmarc = 'fail'
                                    elif 'dmarc=none' in auth_results.lower():
                                        original_dmarc = 'none'

                        logger.info(f"🔐 Extracted auth headers: SPF={original_spf}, DKIM={original_dkim}, DMARC={original_dmarc}")
                    except Exception as e:
                        logger.warning(f"Could not extract auth headers: {e}")

                # Log what we're about to insert
                logger.info(f"📝 Inserting: sender='{sender}', subject='{subject}', category='{email_category}'")

                # Insert into database with comprehensive schema
                insert_sql = """
                INSERT INTO email_analysis (
                    timestamp, message_id, sender, recipients, subject, spam_score,
                    entities, all_links_count, suspicious_links, model_name, raw_text_length,
                    urgency_score, entity_combos, sentiment_score, email_category, email_topics,
                    content_summary, detected_language, language_confidence, sentiment_polarity,
                    sentiment_subjectivity, sentiment_extremity, sentiment_manipulation,
                    manipulation_indicators, category_confidence, secondary_categories,
                    classification_scores, has_attachments, training_data_saved, raw_email,
                    original_spf, original_dkim, original_dmarc
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
                """

                # Execute the insert
                cursor.execute(insert_sql, (
                    timestamp, message_id, sender, recipients, subject, spam_score,
                    entities, all_links_count, suspicious_links, model_name, raw_text_length,
                    urgency_score, entity_combos, sentiment_score, email_category, email_topics,
                    content_summary, detected_language, language_confidence, sentiment_polarity,
                    sentiment_subjectivity, sentiment_extremity, sentiment_manipulation,
                    manipulation_indicators, category_confidence, secondary_categories,
                    classification_scores, has_attachments, training_data_saved, message_str,
                    original_spf, original_dkim, original_dmarc
                ))
                
                self.db_connection.commit()
                email_id = cursor.lastrowid
                logger.info(f"✅ Processed production email from {sender} (ID: {email_id})")
                
                # Store compliance entities if present
                compliance_entities = analysis_results.get('compliance_entities', {})
                financial_entities = analysis_results.get('financial_entities', {})
                
                if compliance_entities or financial_entities:
                    self.store_compliance_entities(email_id, recipients, compliance_entities, financial_entities)
                
                return True
                
        except Exception as e:
            logger.error(f"❌ Database insert error: {e}")
            logger.error(f"Queue data: {queue_data}")
            logger.error(traceback.format_exc())
            self.db_connection.rollback()
            return False
    
    def store_compliance_entities(self, email_id: int, recipients: str, compliance_entities: Dict, financial_entities: Dict) -> None:
        """Store compliance entities in separate table"""
        try:
            # Ensure database connection is alive
            self.ensure_db_connection()
            
            # Extract domain from recipients
            client_domain = None
            if recipients and '@' in recipients:
                # Take first recipient's domain
                first_recipient = recipients.split(',')[0].strip()
                # Remove angle brackets if present
                first_recipient = first_recipient.strip('<>')
                if '@' in first_recipient:
                    client_domain = first_recipient.split('@')[-1].lower().strip('>')
            
            if not client_domain:
                logger.warning(f"Could not extract domain from recipients: {recipients}")
                return
            
            with self.db_connection.cursor() as cursor:
                # Store legal entities
                if compliance_entities:
                    # Case numbers
                    for case_num in compliance_entities.get('case_numbers', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'case_number', case_num, 0.9))
                    
                    # Attorneys
                    for attorney in compliance_entities.get('attorneys', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'attorney', attorney, 0.85))
                    
                    # Court dates
                    for court_date in compliance_entities.get('court_dates', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'court_date', court_date, 0.8))
                    
                    # Legal deadlines
                    for deadline in compliance_entities.get('legal_deadlines', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'legal_deadline', deadline, 0.85))
                
                # Store financial entities
                if financial_entities:
                    # Amounts
                    for amount in financial_entities.get('amounts', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'amount', amount, 0.9))
                    
                    # Invoice numbers
                    for invoice in financial_entities.get('invoice_numbers', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'invoice', invoice, 0.85))
                    
                    # Account numbers
                    for account in financial_entities.get('account_numbers', []):
                        cursor.execute("""
                            INSERT INTO compliance_entities 
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (email_id, client_domain, 'account', account, 0.8))
                
                self.db_connection.commit()
                
                total_entities = len(compliance_entities.get('case_numbers', [])) + \
                               len(compliance_entities.get('attorneys', [])) + \
                               len(financial_entities.get('amounts', [])) + \
                               len(financial_entities.get('invoice_numbers', []))
                
                if total_entities > 0:
                    logger.info(f"📋 Stored {total_entities} compliance entities for {client_domain}")
                    
        except Exception as e:
            logger.error(f"❌ Failed to store compliance entities: {e}")
            logger.error(traceback.format_exc())
    
    def process_queue(self):
        """Main processing loop for production email filter data"""
        logger.info("🚀 Starting Production SpaCy database processor (FIXED SENDER EXTRACTION)")
        
        while True:
            try:
                # Check Redis connection
                self.redis_client.ping()
                
                # Wait for and process messages from the queue
                message = self.redis_client.brpop('email_analysis_queue', timeout=5)
                
                if message:
                    queue_name, message_data = message
                    logger.info(f"📨 Received production message from {queue_name}")
                    
                    try:
                        # Parse the JSON message from production email filter
                        queue_data = json.loads(message_data)
                        
                        # Validate it's from the production email filter
                        if queue_data.get('version') == '1.0' and 'email_data' in queue_data:
                            logger.info("📧 Processing production email filter data")
                            
                            # Process and store in database
                            if self.process_production_email_data(queue_data):
                                logger.info("✅ Successfully processed production email data")
                            else:
                                logger.error("❌ Failed to process production email data")
                        else:
                            logger.warning("⚠️  Received non-production format message, skipping")
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"❌ Invalid JSON in message: {e}")
                    except Exception as e:
                        logger.error(f"❌ Error processing message: {e}")
                        logger.error(traceback.format_exc())
                else:
                    # No message received within timeout - just continue
                    pass
                    
            except redis.ConnectionError:
                logger.error("❌ Redis connection lost, attempting to reconnect...")
                time.sleep(5)
                self.connect_to_services()
                
            except KeyboardInterrupt:
                logger.info("🛑 Shutdown requested")
                break
                
            except Exception as e:
                logger.error(f"❌ Unexpected error: {e}")
                logger.error(traceback.format_exc())
                time.sleep(5)
        
        # Clean shutdown
        if self.db_connection:
            self.db_connection.close()
        logger.info("🏁 Production database processor stopped")

def main():
    """Main entry point"""
    try:
        processor = ProductionSpaCyDatabaseProcessor()
        processor.process_queue()
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()
