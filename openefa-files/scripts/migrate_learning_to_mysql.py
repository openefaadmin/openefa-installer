#!/usr/bin/env python3
"""
Migrate conversation learning data from SQLite to MySQL
"""

import sqlite3
import mysql.connector
import json
import sys
from datetime import datetime

def migrate_data():
    """Migrate data from SQLite to MySQL"""
    
    # SQLite connection
    sqlite_path = '/opt/spacyserver/data/conversation_patterns.db'
    try:
        sqlite_conn = sqlite3.connect(sqlite_path)
        sqlite_cursor = sqlite_conn.cursor()
        print(f"✅ Connected to SQLite: {sqlite_path}")
    except Exception as e:
        print(f"❌ No SQLite database found or error: {e}")
        print("Starting fresh with MySQL - no migration needed")
        return
    
    # MySQL connection
    try:
        mysql_conn = mysql.connector.connect(
            option_files='/opt/spacyserver/config/.my.cnf'
        )
        mysql_cursor = mysql_conn.cursor()
        print("✅ Connected to MySQL: spacy_email_db")
    except Exception as e:
        print(f"❌ MySQL connection failed: {e}")
        return
    
    # Migrate vocabulary patterns
    try:
        sqlite_cursor.execute('SELECT word_hash, frequency, last_seen FROM vocabulary_patterns')
        vocab_data = sqlite_cursor.fetchall()
        
        if vocab_data:
            print(f"📦 Migrating {len(vocab_data)} vocabulary patterns...")
            for row in vocab_data:
                mysql_cursor.execute("""
                    INSERT INTO conversation_vocabulary (word_hash, frequency, last_seen)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                        frequency = VALUES(frequency),
                        last_seen = VALUES(last_seen)
                """, row)
            mysql_conn.commit()
            print(f"✅ Migrated {len(vocab_data)} vocabulary patterns")
    except Exception as e:
        print(f"⚠️ Error migrating vocabulary: {e}")
    
    # Migrate domain relationships
    try:
        sqlite_cursor.execute("""
            SELECT sender_domain, recipient_domain, message_count, 
                   avg_spam_score, last_communication 
            FROM domain_relationships
        """)
        relationship_data = sqlite_cursor.fetchall()
        
        if relationship_data:
            print(f"📦 Migrating {len(relationship_data)} domain relationships...")
            for row in relationship_data:
                mysql_cursor.execute("""
                    INSERT INTO conversation_relationships 
                    (sender_domain, recipient_domain, message_count, avg_spam_score, last_communication)
                    VALUES (%s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                        message_count = VALUES(message_count),
                        avg_spam_score = VALUES(avg_spam_score),
                        last_communication = VALUES(last_communication)
                """, row)
            mysql_conn.commit()
            print(f"✅ Migrated {len(relationship_data)} domain relationships")
    except Exception as e:
        print(f"⚠️ Error migrating relationships: {e}")
    
    # Migrate phrase patterns
    try:
        sqlite_cursor.execute("""
            SELECT phrase, frequency, avg_spam_score, last_seen 
            FROM phrase_patterns
        """)
        phrase_data = sqlite_cursor.fetchall()
        
        if phrase_data:
            print(f"📦 Migrating {len(phrase_data)} phrase patterns...")
            for row in phrase_data:
                mysql_cursor.execute("""
                    INSERT INTO conversation_phrases 
                    (phrase, frequency, avg_spam_score, last_seen)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                        frequency = VALUES(frequency),
                        avg_spam_score = VALUES(avg_spam_score),
                        last_seen = VALUES(last_seen)
                """, row)
            mysql_conn.commit()
            print(f"✅ Migrated {len(phrase_data)} phrase patterns")
    except Exception as e:
        print(f"⚠️ Error migrating phrases: {e}")
    
    # Migrate domain stats
    try:
        sqlite_cursor.execute("""
            SELECT domain, total_messages, avg_length, avg_spam_score, 
                   common_topics, last_updated 
            FROM conversation_stats
        """)
        stats_data = sqlite_cursor.fetchall()
        
        if stats_data:
            print(f"📦 Migrating {len(stats_data)} domain statistics...")
            for row in stats_data:
                mysql_cursor.execute("""
                    INSERT INTO conversation_domain_stats 
                    (domain, total_messages, avg_message_length, avg_spam_score, 
                     common_topics, last_updated)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                        total_messages = VALUES(total_messages),
                        avg_message_length = VALUES(avg_message_length),
                        avg_spam_score = VALUES(avg_spam_score),
                        common_topics = VALUES(common_topics),
                        last_updated = VALUES(last_updated)
                """, row)
            mysql_conn.commit()
            print(f"✅ Migrated {len(stats_data)} domain statistics")
    except Exception as e:
        print(f"⚠️ Error migrating domain stats: {e}")
    
    # Add initial progress record for today
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        mysql_cursor.execute("""
            INSERT INTO conversation_learning_progress 
            (date, patterns_learned, relationships_formed, phrases_identified, emails_processed)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
                patterns_learned = VALUES(patterns_learned)
        """, (today, len(vocab_data) if 'vocab_data' in locals() else 0,
              len(relationship_data) if 'relationship_data' in locals() else 0,
              len(phrase_data) if 'phrase_data' in locals() else 0,
              0))
        mysql_conn.commit()
        print("✅ Created learning progress record")
    except Exception as e:
        print(f"⚠️ Error creating progress record: {e}")
    
    # Show final statistics
    mysql_cursor.execute("SELECT * FROM conversation_learning_stats")
    stats = mysql_cursor.fetchone()
    if stats:
        print("\n📊 Final Migration Statistics:")
        print(f"  Vocabulary patterns: {stats[0]}")
        print(f"  Domain relationships: {stats[1]}")
        print(f"  Professional phrases: {stats[2]}")
        print(f"  Client domains tracked: {stats[3]}")
        print(f"  New patterns (24h): {stats[4]}")
        print(f"  New patterns (7d): {stats[5]}")
        print(f"  Avg legitimate score: {stats[6]:.2f}" if stats[6] else "  Avg legitimate score: N/A")
    
    # Close connections
    sqlite_conn.close()
    mysql_conn.close()
    
    print("\n✅ Migration complete! The system now uses MySQL for conversation learning.")
    print("💡 The SQLite database can be removed: rm /opt/spacyserver/data/conversation_patterns.db")

if __name__ == "__main__":
    migrate_data()