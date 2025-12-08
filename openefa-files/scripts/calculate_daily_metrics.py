#!/usr/bin/env python3
"""
Daily Effectiveness Metrics Calculator
Calculates and stores spam fighting effectiveness metrics
"""

import sys
import os
import json
import logging
from datetime import datetime, timedelta, date
from typing import Dict, Any, Optional, Tuple
import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

# Add parent directory to path
sys.path.insert(0, '/opt/spacyserver')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/opt/spacyserver/logs/effectiveness_metrics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EffectivenessCalculator:
    def __init__(self):
        self.db_config = self._load_db_config()
        self.weights = {
            'detection_rate': 0.4,      # 40% weight on catching spam
            'false_positive_rate': 0.4,  # 40% weight on not blocking legitimate email
            'learning_rate': 0.2         # 20% weight on system improvement
        }
        
    def _load_db_config(self) -> Dict[str, Any]:
        """Load database configuration"""
        try:
            # Try to read from .my.cnf first
            config_path = '/opt/spacyserver/config/.my.cnf'
            if os.path.exists(config_path):
                config = {}
                with open(config_path, 'r') as f:
                    for line in f:
                        if '=' in line and not line.startswith('['):
                            key, value = line.strip().split('=', 1)
                            config[key.strip()] = value.strip().strip('"')
                
                return {
                    'host': config.get('host', os.getenv('DB_HOST', 'localhost')),
                    'user': config.get('user', os.getenv('DB_USER', 'spacy_user')),
                    'password': config.get('password', ''),
                    'database': config.get('database', os.getenv('DB_NAME', 'spacy_email_db'))
                }
            else:
                # Fallback to environment variables
                return {
                    'host': os.getenv('DB_HOST', 'localhost'),
                    'user': os.getenv('DB_USER', 'spacy_user'),
                    'password': os.getenv('DB_PASSWORD', ''),
                    'database': os.getenv('DB_NAME', 'spacy_email_db')
                }
        except Exception as e:
            logger.error(f"Error loading DB config: {e}")
            raise
    
    def get_connection(self):
        """Get database connection"""
        return pymysql.connect(
            **self.db_config,
            cursorclass=DictCursor,
            charset='utf8mb4'
        )
    
    def calculate_metrics_for_date(self, target_date: date) -> Dict[str, Any]:
        """
        Calculate effectiveness metrics for a specific date
        
        Returns:
            Dict containing all calculated metrics
        """
        metrics = {
            'metric_date': target_date,
            'total_emails': 0,
            'spam_caught': 0,
            'clean_passed': 0,
            'gray_area': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'avg_spam_score': 0.0,
            'detection_rate': 0.0,
            'false_positive_rate': 0.0,
            'true_positive_rate': 0.0,
            'precision_score': 0.0,
            'recall_score': 0.0,
            'f1_score': 0.0,
            'effectiveness_score': 0.0,
            'auto_whitelists_added': 0,
            'unique_senders_released': 0,
            'learning_rate': 0.0
        }
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get total emails for the day
                cursor.execute("""
                    SELECT COUNT(*) as count, AVG(spam_score) as avg_score
                    FROM email_analysis
                    WHERE DATE(timestamp) = %s
                """, (target_date,))
                result = cursor.fetchone()
                metrics['total_emails'] = result['count'] or 0
                metrics['avg_spam_score'] = float(result['avg_score'] or 0)
                
                if metrics['total_emails'] == 0:
                    logger.info(f"No emails found for {target_date}")
                    return metrics
                
                # Count emails by spam score categories
                # Using spam threshold of 7.0 to match quarantine threshold
                cursor.execute("""
                    SELECT
                        SUM(CASE WHEN spam_score >= 7.0 THEN 1 ELSE 0 END) as spam_caught,
                        SUM(CASE WHEN spam_score < 2.0 THEN 1 ELSE 0 END) as clean_passed,
                        SUM(CASE WHEN spam_score >= 2.0 AND spam_score < 7.0 THEN 1 ELSE 0 END) as gray_area
                    FROM email_analysis
                    WHERE DATE(timestamp) = %s
                """, (target_date,))
                result = cursor.fetchone()
                metrics['spam_caught'] = int(result['spam_caught'] or 0)
                metrics['clean_passed'] = int(result['clean_passed'] or 0)
                metrics['gray_area'] = int(result['gray_area'] or 0)
                
                # Get false positives (clean emails incorrectly quarantined/deleted)
                # Clean emails are those with spam_score < 2.0
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM email_analysis
                    WHERE DATE(timestamp) = %s
                    AND spam_score < 2.0
                    AND disposition IN ('quarantined', 'deleted')
                """, (target_date,))
                result = cursor.fetchone()
                metrics['false_positives'] = result['count'] or 0
                
                # Get unique senders released
                cursor.execute("""
                    SELECT COUNT(DISTINCT sender_email) as count
                    FROM false_positive_tracking
                    WHERE DATE(release_timestamp) = %s
                """, (target_date,))
                result = cursor.fetchone()
                metrics['unique_senders_released'] = result['count'] or 0
                
                # Get auto-whitelists added today
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM false_positive_tracking
                    WHERE DATE(release_timestamp) = %s
                    AND auto_whitelisted = TRUE
                """, (target_date,))
                result = cursor.fetchone()
                metrics['auto_whitelists_added'] = result['count'] or 0
                
                # Get false negatives (spam emails that were delivered)
                # Spam emails are those with spam_score >= 7.0
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM email_analysis
                    WHERE DATE(timestamp) = %s
                    AND spam_score >= 7.0
                    AND disposition = 'delivered'
                """, (target_date,))
                result = cursor.fetchone()
                metrics['false_negatives'] = result['count'] or 0
                
                # Calculate rates
                total = metrics['total_emails']
                if total > 0:
                    # Detection rate: percentage of actual spam caught
                    actual_spam = metrics['spam_caught'] + metrics['false_negatives']
                    if actual_spam > 0:
                        metrics['detection_rate'] = metrics['spam_caught'] / actual_spam
                    
                    # False positive rate: legitimate emails marked as spam
                    legitimate_emails = metrics['clean_passed'] + metrics['false_positives']
                    if legitimate_emails > 0:
                        metrics['false_positive_rate'] = metrics['false_positives'] / legitimate_emails
                    
                    # True positive rate (sensitivity/recall)
                    metrics['true_positive_rate'] = metrics['detection_rate']
                    metrics['recall_score'] = metrics['detection_rate']
                    
                    # Precision: of emails marked as spam, how many were actually spam
                    total_marked_spam = metrics['spam_caught'] + metrics['false_positives']
                    if total_marked_spam > 0:
                        metrics['precision_score'] = metrics['spam_caught'] / total_marked_spam
                    
                    # F1 Score: harmonic mean of precision and recall
                    if metrics['precision_score'] + metrics['recall_score'] > 0:
                        metrics['f1_score'] = 2 * (metrics['precision_score'] * metrics['recall_score']) / \
                                             (metrics['precision_score'] + metrics['recall_score'])
                
                # Calculate learning rate
                # Compare to 7 days ago
                week_ago = target_date - timedelta(days=7)
                cursor.execute("""
                    SELECT false_positive_rate, detection_rate
                    FROM effectiveness_metrics
                    WHERE metric_date = %s
                """, (week_ago,))
                week_ago_metrics = cursor.fetchone()

                if week_ago_metrics:
                    # Learning rate: improvement in effectiveness over time
                    old_effectiveness = (1 - float(week_ago_metrics['false_positive_rate'])) * 0.5 + \
                                      float(week_ago_metrics['detection_rate']) * 0.5
                    new_effectiveness = (1 - metrics['false_positive_rate']) * 0.5 + \
                                      metrics['detection_rate'] * 0.5
                    metrics['learning_rate'] = max(0, new_effectiveness - old_effectiveness)
                
                # Calculate overall effectiveness score (0-100 scale)
                effectiveness = (
                    self.weights['detection_rate'] * metrics['detection_rate'] +
                    self.weights['false_positive_rate'] * (1 - metrics['false_positive_rate']) +
                    self.weights['learning_rate'] * min(1, metrics['learning_rate'] * 10)  # Scale learning rate
                ) * 100
                
                metrics['effectiveness_score'] = round(effectiveness, 2)
                
                # Log summary
                logger.info(f"Metrics for {target_date}:")
                logger.info(f"  Total emails: {metrics['total_emails']}")
                logger.info(f"  Spam caught: {metrics['spam_caught']}")
                logger.info(f"  False positives: {metrics['false_positives']}")
                logger.info(f"  Detection rate: {metrics['detection_rate']:.2%}")
                logger.info(f"  False positive rate: {metrics['false_positive_rate']:.2%}")
                logger.info(f"  Effectiveness score: {metrics['effectiveness_score']:.1f}/100")
                
                return metrics
                
        except Exception as e:
            logger.error(f"Error calculating metrics: {e}")
            raise
        finally:
            conn.close()
    
    def store_metrics(self, metrics: Dict[str, Any]):
        """
        Store calculated metrics in the database
        """
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Use INSERT ... ON DUPLICATE KEY UPDATE for idempotency
                cursor.execute("""
                    INSERT INTO effectiveness_metrics (
                        metric_date, total_emails, spam_caught, clean_passed, gray_area,
                        false_positives, false_negatives, avg_spam_score, detection_rate,
                        false_positive_rate, true_positive_rate, precision_score,
                        recall_score, f1_score, effectiveness_score, auto_whitelists_added,
                        unique_senders_released, learning_rate
                    ) VALUES (
                        %(metric_date)s, %(total_emails)s, %(spam_caught)s, %(clean_passed)s,
                        %(gray_area)s, %(false_positives)s, %(false_negatives)s, %(avg_spam_score)s,
                        %(detection_rate)s, %(false_positive_rate)s, %(true_positive_rate)s,
                        %(precision_score)s, %(recall_score)s, %(f1_score)s, %(effectiveness_score)s,
                        %(auto_whitelists_added)s, %(unique_senders_released)s, %(learning_rate)s
                    )
                    ON DUPLICATE KEY UPDATE
                        total_emails = VALUES(total_emails),
                        spam_caught = VALUES(spam_caught),
                        clean_passed = VALUES(clean_passed),
                        gray_area = VALUES(gray_area),
                        false_positives = VALUES(false_positives),
                        false_negatives = VALUES(false_negatives),
                        avg_spam_score = VALUES(avg_spam_score),
                        detection_rate = VALUES(detection_rate),
                        false_positive_rate = VALUES(false_positive_rate),
                        true_positive_rate = VALUES(true_positive_rate),
                        precision_score = VALUES(precision_score),
                        recall_score = VALUES(recall_score),
                        f1_score = VALUES(f1_score),
                        effectiveness_score = VALUES(effectiveness_score),
                        auto_whitelists_added = VALUES(auto_whitelists_added),
                        unique_senders_released = VALUES(unique_senders_released),
                        learning_rate = VALUES(learning_rate),
                        created_at = CURRENT_TIMESTAMP
                """, metrics)
                conn.commit()
                logger.info(f"Stored metrics for {metrics['metric_date']}")
                
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def calculate_weekly_summary(self, end_date: date):
        """
        Calculate and store weekly summary metrics
        """
        start_date = end_date - timedelta(days=6)
        
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                # Get week's metrics
                cursor.execute("""
                    SELECT 
                        AVG(effectiveness_score) as avg_effectiveness,
                        SUM(total_emails) as total_emails,
                        SUM(spam_caught) as total_spam_caught,
                        SUM(false_positives) as total_false_positives,
                        MAX(effectiveness_score) as best_day,
                        MIN(effectiveness_score) as worst_day
                    FROM effectiveness_metrics
                    WHERE metric_date BETWEEN %s AND %s
                """, (start_date, end_date))
                
                week_metrics = cursor.fetchone()
                
                if not week_metrics or week_metrics['total_emails'] is None:
                    logger.info(f"No data for week ending {end_date}")
                    return
                
                # Get previous week's average for comparison
                prev_start = start_date - timedelta(days=7)
                prev_end = start_date - timedelta(days=1)
                cursor.execute("""
                    SELECT AVG(effectiveness_score) as avg_effectiveness
                    FROM effectiveness_metrics
                    WHERE metric_date BETWEEN %s AND %s
                """, (prev_start, prev_end))
                
                prev_week = cursor.fetchone()
                improvement = None
                if prev_week and prev_week['avg_effectiveness']:
                    improvement = week_metrics['avg_effectiveness'] - prev_week['avg_effectiveness']
                
                # Store weekly summary
                cursor.execute("""
                    INSERT INTO effectiveness_weekly_summary (
                        week_start, week_end, avg_effectiveness, total_emails,
                        total_spam_caught, total_false_positives, improvement_from_previous,
                        best_day_effectiveness, worst_day_effectiveness
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON DUPLICATE KEY UPDATE
                        avg_effectiveness = VALUES(avg_effectiveness),
                        total_emails = VALUES(total_emails),
                        total_spam_caught = VALUES(total_spam_caught),
                        total_false_positives = VALUES(total_false_positives),
                        improvement_from_previous = VALUES(improvement_from_previous),
                        best_day_effectiveness = VALUES(best_day_effectiveness),
                        worst_day_effectiveness = VALUES(worst_day_effectiveness)
                """, (
                    start_date, end_date,
                    week_metrics['avg_effectiveness'],
                    week_metrics['total_emails'],
                    week_metrics['total_spam_caught'],
                    week_metrics['total_false_positives'],
                    improvement,
                    week_metrics['best_day'],
                    week_metrics['worst_day']
                ))
                conn.commit()
                
                logger.info(f"Stored weekly summary for week ending {end_date}")
                logger.info(f"  Average effectiveness: {week_metrics['avg_effectiveness']:.1f}/100")
                if improvement is not None:
                    logger.info(f"  Improvement from previous week: {improvement:+.1f}")
                
        except Exception as e:
            logger.error(f"Error calculating weekly summary: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def run_daily_calculation(self, days_back: int = 1):
        """
        Run daily calculation for specified number of days back
        
        Args:
            days_back: Number of days to calculate backwards from today
        """
        today = date.today()
        
        for i in range(days_back):
            target_date = today - timedelta(days=i)
            logger.info(f"\nCalculating metrics for {target_date}")
            
            try:
                metrics = self.calculate_metrics_for_date(target_date)
                if metrics['total_emails'] > 0:
                    self.store_metrics(metrics)
                    
                    # Calculate weekly summary if it's Sunday
                    if target_date.weekday() == 6:  # Sunday
                        self.calculate_weekly_summary(target_date)
                else:
                    logger.info(f"No emails to process for {target_date}")
                    
            except Exception as e:
                logger.error(f"Failed to process {target_date}: {e}")
                continue

def main():
    """
    Main execution function
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Calculate SpaCy effectiveness metrics')
    parser.add_argument(
        '--days-back',
        type=int,
        default=1,
        help='Number of days to calculate backwards from today (default: 1)'
    )
    parser.add_argument(
        '--date',
        type=str,
        help='Calculate for specific date (YYYY-MM-DD)'
    )
    
    args = parser.parse_args()
    
    try:
        calculator = EffectivenessCalculator()
        
        if args.date:
            # Calculate for specific date
            target_date = datetime.strptime(args.date, '%Y-%m-%d').date()
            logger.info(f"Calculating metrics for {target_date}")
            metrics = calculator.calculate_metrics_for_date(target_date)
            if metrics['total_emails'] > 0:
                calculator.store_metrics(metrics)
            else:
                logger.info(f"No emails found for {target_date}")
        else:
            # Run daily calculation
            calculator.run_daily_calculation(args.days_back)
        
        logger.info("\nEffectiveness calculation completed successfully")
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()