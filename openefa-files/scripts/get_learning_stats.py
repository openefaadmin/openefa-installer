#!/usr/bin/env python3
"""Get learning statistics for OpenSpacyMenu"""

import mysql.connector
import json
from datetime import datetime, timedelta

try:
    # MySQL connection using config file
    conn = mysql.connector.connect(
        option_files='/opt/spacyserver/config/.my.cnf'
    )
    cursor = conn.cursor()
    
    stats = {}
    
    # Get basic counts from MySQL tables
    cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 1')
    stats['vocabulary'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM conversation_relationships')
    stats['relationships'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM conversation_phrases')
    stats['phrases'] = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(DISTINCT domain) FROM conversation_domain_stats')
    stats['domains'] = cursor.fetchone()[0]
    
    # Get learning rate (last 24 hours)
    cursor.execute("SELECT COUNT(*) FROM conversation_vocabulary WHERE last_seen > DATE_SUB(NOW(), INTERVAL 1 DAY)")
    stats['new_patterns_24h'] = cursor.fetchone()[0]
    
    # Get top relationships
    cursor.execute('''
        SELECT sender_domain, recipient_domain, message_count, avg_spam_score 
        FROM conversation_relationships 
        ORDER BY message_count DESC 
        LIMIT 10
    ''')
    relationships = []
    for row in cursor.fetchall():
        relationships.append([
            row[0],  # sender_domain
            row[1],  # recipient_domain
            int(row[2]),  # message_count
            float(row[3]) if row[3] else 0  # avg_spam_score
        ])
    stats['top_relationships'] = relationships
    
    # Get confidence metrics
    cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 5')
    high_freq_vocab = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM conversation_relationships WHERE message_count > 5')
    strong_relationships = cursor.fetchone()[0]
    
    # Calculate confidence (0-100%)
    vocab_confidence = min(100, (stats['vocabulary'] / 500) * 100)
    relationship_confidence = min(100, (strong_relationships / 20) * 100)
    stats['confidence'] = (vocab_confidence + relationship_confidence) / 2
    
    # Get learning progression
    cursor.execute('SELECT AVG(total_messages), MAX(total_messages) FROM conversation_domain_stats')
    result = cursor.fetchone()
    stats['avg_messages'] = float(result[0]) if result[0] else 0
    stats['max_messages'] = int(result[1]) if result[1] else 0
    
    # Get most common phrases
    cursor.execute('''
        SELECT phrase, frequency 
        FROM conversation_phrases 
        ORDER BY frequency DESC 
        LIMIT 5
    ''')
    stats['top_phrases'] = cursor.fetchall()
    
    conn.close()
    print(json.dumps(stats))
    
except Exception as e:
    print(json.dumps({'error': str(e)}))