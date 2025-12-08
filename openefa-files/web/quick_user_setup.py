#!/usr/bin/env python3
"""
Quick Admin User Setup for GuardianMail
"""

import os
import mysql.connector
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/spacy-server/.env')

def create_admin_user():
    print("🔐 Creating Admin User for GuardianMail")
    print("=" * 40)
    
    # Get admin details
    admin_email = input("Admin email: ")
    admin_password = input("Admin password: ")
    
    # Hash password
    password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Extract domain
    domain = admin_email.split('@')[1] if '@' in admin_email else 'admin.local'
    
    try:
        # Connect to database using configured user
        db_user = os.getenv('DB_USER', 'spacy_user')
        db_name = os.getenv('DB_NAME', 'spacy_email_db')
        print(f"Connecting to MySQL with {db_user}...")
        conn = mysql.connector.connect(
            option_files='/etc/spacy-server/.my.cnf',
            option_groups=['client'],
            user=db_user,
            database=db_name
        )
        
        cursor = conn.cursor()
        
        # Create admin user
        cursor.execute("""
            INSERT INTO users (email, password_hash, domain, role, first_name, last_name, is_active, email_verified)
            VALUES (%s, %s, %s, 'admin', 'Admin', 'User', TRUE, TRUE)
        """, (admin_email, password_hash, domain))
        
        user_id = cursor.lastrowid
        
        # Log the creation
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, details)
            VALUES (%s, 'USER_CREATED', 'Admin user created during setup')
        """, (user_id,))
        
        conn.commit()
        print(f"✅ Admin user created: {admin_email}")
        
        # Create a test client user (optional)
        create_test = input("Create test client user? (y/n): ").lower() == 'y'
        if create_test:
            test_email = input("Enter test client email (e.g., admin@yourdomain.com): ")
            test_domain = test_email.split('@')[-1]
            test_password_hash = bcrypt.hashpw("test123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("""
                INSERT INTO users (email, password_hash, domain, role, first_name, last_name, company_name, is_active, email_verified)
                VALUES (%s, %s, %s, 'client', 'Test', 'User', 'Test Company', TRUE, TRUE)
            """, (test_email, test_password_hash, test_domain))
            conn.commit()
            print(f"✅ Test client created: {test_email} (password: test123)")
        
        # Show created users
        cursor.execute("SELECT email, domain, role FROM users ORDER BY role DESC")
        users = cursor.fetchall()
        
        print("\n📋 Created Users:")
        for email, domain, role in users:
            print(f"  {role.upper()}: {email} ({domain})")
            
        conn.close()
        
        print("\n🎉 Setup complete! Ready for Flask-Login integration.")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    create_admin_user()
