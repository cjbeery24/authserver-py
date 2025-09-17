#!/usr/bin/env python3
"""
Database setup script to create the authserver database and user.
This script should be run after the PostgreSQL container is running.
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def setup_database():
    """Set up the authserver database and user."""
    
    # Connect to the default postgres database as superuser
    conn = psycopg2.connect(
        host='localhost',
        port=5432,
        user='postgres',
        password='postgres',
        database='postgres'
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()
    
    try:
        # Create the authserver database
        print("Creating authserver database...")
        cursor.execute("CREATE DATABASE authserver")
        print("✅ Database 'authserver' created successfully")
        
        # Create the authuser
        print("Creating authuser...")
        cursor.execute("CREATE USER authuser WITH PASSWORD 'authpass'")
        print("✅ User 'authuser' created successfully")
        
        # Grant privileges to authuser on authserver database
        print("Granting privileges...")
        cursor.execute("GRANT ALL PRIVILEGES ON DATABASE authserver TO authuser")
        print("✅ Privileges granted successfully")
        
        # Connect to the authserver database to set up schema privileges
        conn.close()
        
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            user='postgres',
            password='postgres',
            database='authserver'
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Grant schema privileges
        cursor.execute("GRANT ALL ON SCHEMA public TO authuser")
        cursor.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO authuser")
        cursor.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO authuser")
        cursor.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO authuser")
        print("✅ Schema privileges granted successfully")
        
        print("\n🎉 Database setup completed successfully!")
        print("You can now use the following connection string:")
        print("postgresql://authuser:authpass@localhost:5432/authserver")
        
    except psycopg2.Error as e:
        if "already exists" in str(e):
            print("⚠️  Database or user already exists, skipping creation")
        else:
            print(f"❌ Error setting up database: {e}")
            raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    setup_database()

