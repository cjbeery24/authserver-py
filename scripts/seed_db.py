#!/usr/bin/env python3
"""
Database seeder script to create initial roles and users.

This script creates:
- Two roles: 'user' and 'admin'
- A regular user with the 'user' role
- An admin user with the 'admin' role

Usage:
    python scripts/seed_db.py
"""

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.core.crypto import PasswordHasher
from app.models.role import Role
from app.models.user import User
from app.models.user_role import UserRole


def create_roles(db: Session):
    """Create the basic roles if they don't exist."""
    roles_data = [
        {"name": "user", "description": "Regular user with basic permissions"},
        {"name": "admin", "description": "Administrator with full permissions"}
    ]

    created_roles = []
    for role_data in roles_data:
        # Check if role already exists
        existing_role = db.query(Role).filter(Role.name == role_data["name"]).first()
        if existing_role:
            print(f"⚠️  Role '{role_data['name']}' already exists, skipping")
            created_roles.append(existing_role)
        else:
            role = Role(**role_data)
            db.add(role)
            created_roles.append(role)
            print(f"✅ Created role '{role_data['name']}'")

    db.commit()
    return created_roles


def create_users(db: Session):
    """Create initial users with their roles."""
    users_data = [
        {
            "username": "user",
            "email": "user@example.com",
            "password": "Str0ngP@ssw0rd!",
            "role_names": ["user"]
        },
        {
            "username": "admin",
            "email": "admin@example.com",
            "password": "Str0ngP@ssw0rd!",
            "role_names": ["admin"]
        }
    ]

    created_users = []
    for user_data in users_data:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.username == user_data["username"]) | (User.email == user_data["email"])
        ).first()

        if existing_user:
            print(f"⚠️  User '{user_data['username']}' already exists, skipping")
            created_users.append(existing_user)
            continue

        # Hash the password
        hashed_password = PasswordHasher.hash_password(user_data["password"])

        # Create the user
        user = User(
            username=user_data["username"],
            email=user_data["email"],
            password_hash=hashed_password,
            is_active=True
        )

        db.add(user)
        db.flush()  # Flush to get the user ID

        # Assign roles to the user
        for role_name in user_data["role_names"]:
            role = db.query(Role).filter(Role.name == role_name).first()
            if role:
                user_role = UserRole(user_id=user.id, role_id=role.id)
                db.add(user_role)
                print(f"✅ Assigned role '{role_name}' to user '{user.username}'")
            else:
                print(f"❌ Role '{role_name}' not found, skipping assignment")

        created_users.append(user)
        print(f"✅ Created user '{user.username}' with email '{user.email}'")

    db.commit()
    return created_users


def main():
    """Main function to run the database seeding."""
    print("🌱 Starting database seeding...")

    # Create database session
    db = SessionLocal()
    try:
        # Create roles
        print("\n📝 Creating roles...")
        roles = create_roles(db)

        # Create users
        print("\n👤 Creating users...")
        users = create_users(db)

        print("\n🎉 Database seeding completed successfully!")
        print("\nCreated roles:")
        for role in roles:
            print(f"  - {role.name}: {role.description}")

        print("\nCreated users:")
        for user in users:
            # Get user's roles
            user_roles = db.query(Role).join(UserRole).filter(UserRole.user_id == user.id).all()
            role_names = [r.name for r in user_roles]
            print(f"  - {user.username} ({user.email}) - Roles: {', '.join(role_names)}")

        print("\n🔐 User credentials:")
        print("  Regular user: user@example.com / Str0ngP@ssw0rd!")
        print("  Admin user: admin@example.com / Str0ngP@ssw0rd!")

    except IntegrityError as e:
        print(f"❌ Database integrity error: {e}")
        db.rollback()
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
