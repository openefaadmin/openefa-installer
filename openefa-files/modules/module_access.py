#!/usr/bin/env python3
"""
Module Access Control System
Checks which premium modules are enabled for each client domain
"""

import os
import pymysql
import json
from datetime import datetime
from typing import Dict, List, Optional
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ModuleAccessManager:
    def __init__(self, db_config=None):
        """Initialize with database configuration"""
        self.db_config = db_config or {
            'read_default_file': '/opt/spacyserver/config/.my.cnf',
            'database': os.getenv('DB_NAME', 'spacy_email_db'),
            'charset': 'utf8mb4'
        }
        self.cache = {}  # Simple cache to avoid repeated DB queries
        self.cache_ttl = 300  # Cache for 5 minutes
        self.last_cache_time = {}
    
    def get_connection(self):
        """Create database connection"""
        return pymysql.connect(**self.db_config)
    
    def check_client_modules(self, client_domain: str) -> Dict[str, bool]:
        """Check which modules are enabled for a client domain"""
        
        # Check cache first
        cache_key = f"modules_{client_domain}"
        if cache_key in self.cache:
            if (datetime.now() - self.last_cache_time.get(cache_key, datetime.min)).seconds < self.cache_ttl:
                return self.cache[cache_key]
        
        # Default modules (everyone gets basic features)
        modules = {
            'basic_ner': True,
            'email_storage': True,
            'basic_search': True,
            'compliance_tracking': False,
            'debt_monitoring': False,
            'legal_alerts': False,
            'payment_tracking': False,
            'advanced_analytics': False
        }
        
        try:
            logger.info(f"🔗 DEBUG: Connecting to check modules for {client_domain}")
            conn = self.get_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            # Query active modules for this domain
            query = """
                SELECT module_name, enabled, subscription_end, config
                FROM client_modules
                WHERE client_domain = %s
                AND enabled = TRUE
                AND (subscription_end IS NULL OR subscription_end > NOW())
            """
            
            logger.info(f"🔍 DEBUG: Executing query for {client_domain}")
            cursor.execute(query, (client_domain,))
            results = cursor.fetchall()
            logger.info(f"📊 DEBUG: Found {len(results)} modules for {client_domain}: {results}")
            
            for row in results:
                modules[row['module_name']] = True
                logger.info(f"✅ DEBUG: Enabled {row['module_name']} for {client_domain}")
            
            cursor.close()
            conn.close()
            
            # Update cache
            self.cache[cache_key] = modules
            self.last_cache_time[cache_key] = datetime.now()
            
            logger.info(f"📦 Final modules for {client_domain}: {modules}")
            
        except Exception as e:
            logger.error(f"❌ Error checking client modules: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Return default modules on error
        
        return modules
    
    def get_client_alerts(self, client_domain: str) -> List[Dict]:
        """Get configured alerts for a client"""
        alerts = []
        
        try:
            conn = self.get_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            
            query = """
                SELECT * FROM module_alerts
                WHERE client_domain = %s
                AND active = TRUE
                ORDER BY priority DESC, alert_type
            """
            
            cursor.execute(query, (client_domain,))
            alerts = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error fetching client alerts: {e}")
        
        return alerts
    
    def log_module_usage(self, client_domain: str, module_name: str, 
                        entities_count: int = 0, alerts_count: int = 0):
        """Log module usage statistics"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            query = """
                INSERT INTO module_usage_stats 
                (client_domain, module_name, usage_date, usage_count, entities_extracted, alerts_triggered)
                VALUES (%s, %s, CURDATE(), 1, %s, %s)
                ON DUPLICATE KEY UPDATE
                usage_count = usage_count + 1,
                entities_extracted = entities_extracted + VALUES(entities_extracted),
                alerts_triggered = alerts_triggered + VALUES(alerts_triggered)
            """
            
            cursor.execute(query, (client_domain, module_name, entities_count, alerts_count))
            conn.commit()
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging module usage: {e}")
    
    def store_compliance_entities(self, email_id: int, client_domain: str, 
                                 entities: Dict[str, List], confidence: float = 1.0):
        """Store extracted compliance entities for tracking"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Flatten entities for storage
            for entity_type, values in entities.items():
                for value in values:
                    if value:  # Skip empty values
                        query = """
                            INSERT INTO compliance_entities
                            (email_id, client_domain, entity_type, entity_value, confidence_score)
                            VALUES (%s, %s, %s, %s, %s)
                        """
                        cursor.execute(query, (email_id, client_domain, entity_type, str(value), confidence))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error storing compliance entities: {e}")
    
    def check_alert_conditions(self, email_data: Dict, client_domain: str) -> List[Dict]:
        """Check if email triggers any configured alerts"""
        triggered_alerts = []
        alerts = self.get_client_alerts(client_domain)
        
        for alert in alerts:
            triggered = False
            
            # Check entity pattern matching
            if alert.get('entity_pattern'):
                import re
                pattern = alert['entity_pattern']
                entities_text = ' '.join(str(e) for e in email_data.get('entities', []))
                if re.search(pattern, entities_text, re.IGNORECASE):
                    triggered = True
            
            # Check keyword matching
            if alert.get('keywords') and not triggered:
                keywords = [k.strip().lower() for k in alert['keywords'].split(',')]
                email_text = (email_data.get('text_content', '') + ' ' + 
                            email_data.get('subject', '')).lower()
                if any(keyword in email_text for keyword in keywords):
                    triggered = True
            
            if triggered:
                triggered_alerts.append(alert)
                logger.info(f"Alert triggered: {alert['alert_name']} for {client_domain}")
        
        return triggered_alerts

# Singleton instance for use in email_filter.py
_module_manager = None

def get_module_manager():
    """Get singleton instance of ModuleAccessManager"""
    global _module_manager
    if _module_manager is None:
        _module_manager = ModuleAccessManager()
    return _module_manager

# Test function
if __name__ == "__main__":
    manager = ModuleAccessManager()
    
    # Test module checking
    print("Testing module access for example.com:")
    modules = manager.check_client_modules('example.com')
    print(json.dumps(modules, indent=2))
    
    # Test alert fetching
    print("\nConfigured alerts:")
    alerts = manager.get_client_alerts('example.com')
    for alert in alerts:
        print(f"- {alert['alert_name']}: {alert['alert_type']}")