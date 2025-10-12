#!/usr/bin/env python3
"""Test learning statistics retrieval"""

import mysql.connector
import json

try:
    conn = mysql.connector.connect(
        option_files='/opt/spacyserver/config/.my.cnf'
    )
    cursor = conn.cursor()
    
    # Get vocabulary count
    cursor.execute('SELECT COUNT(*) FROM conversation_vocabulary WHERE frequency > 1')
    vocab = cursor.fetchone()[0]
    
    # Get relationships
    cursor.execute('SELECT COUNT(*) FROM conversation_relationships')
    relationships = cursor.fetchone()[0]
    
    print(f"Vocabulary: {vocab}")
    print(f"Relationships: {relationships}")
    
    conn.close()
    print("✅ Test successful")
except Exception as e:
    print(f"Error: {e}")