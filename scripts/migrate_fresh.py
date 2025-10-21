#!/usr/bin/env python3
"""
Fresh database migration script.

This script drops all existing tables and recreates the database schema from scratch,
then runs all migrations to ensure the database is up to date.

Usage:
    python scripts/migrate_fresh.py
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy import text
from app.core.database import engine, Base
from app.models import *  # Import all models to register them with Base


def migrate_fresh():
    """Drop all tables and recreate the database from scratch using alembic."""
    print("🗄️  Starting fresh database migration...")

    try:
        # First, drop all tables directly using SQL
        print("🗑️  Dropping all existing tables...")
        with engine.connect() as conn:
            # Get all table names from the public schema
            result = conn.execute(text("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
            """))
            tables = [row[0] for row in result]

            if tables:
                # Disable foreign key checks temporarily
                conn.execute(text("SET session_replication_role = 'replica'"))

                # Drop all tables
                for table in tables:
                    if table != 'alembic_version':  # Keep alembic version table
                        conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                        print(f"  Dropped table: {table}")

                # Re-enable foreign key checks
                conn.execute(text("SET session_replication_role = 'origin'"))

                conn.commit()
                print(f"✅ Dropped {len([t for t in tables if t != 'alembic_version'])} tables")
            else:
                print("✅ No tables to drop")

        # Reset alembic version to base
        print("🔄 Resetting alembic version to base...")
        result = os.system("poetry run alembic stamp base")
        if result != 0:
            print("⚠️  Could not stamp alembic version, continuing...")

        # Run alembic migrations to recreate everything
        print("📈 Running alembic migrations to recreate schema...")
        result = os.system("poetry run alembic upgrade head")
        if result != 0:
            raise Exception("Failed to run alembic upgrade head")
        print("✅ Migrations completed")

        print("\n🎉 Fresh database migration completed successfully!")
        print("The database has been reset and all migrations have been applied.")

    except Exception as e:
        print(f"❌ Error during fresh migration: {e}")
        sys.exit(1)


if __name__ == "__main__":
    migrate_fresh()
