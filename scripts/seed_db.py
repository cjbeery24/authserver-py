#!/usr/bin/env python3
"""
Database seeder script to create initial roles, users, and OAuth clients.

This script creates:
- Two roles: 'user' and 'admin'
- A regular user with the 'user' role
- An admin user with the 'admin' role
- An OAuth client for frontend demo (with consistent client secret for development)

Note: The OAuth client secret is consistent across runs for demo purposes.
In production, client secrets should be randomly generated and stored securely.

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
from app.core.oauth import generate_client_credentials
from app.models.role import Role
from app.models.user import User
from app.models.user_role import UserRole
from app.models.oauth2_client import OAuth2Client


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


def create_oauth_clients(db: Session):
    """Create OAuth clients for development/demo purposes."""
    oauth_clients_data = [
        {
            "name": "OAuth Frontend Demo",
            "redirect_uris": [
                "http://localhost:8000/oauth-demo/callback",  # Integrated frontend (Docker/local)
                "http://localhost:3000/callback.html",        # Standalone frontend
                "http://localhost:8080/callback.html",
                "http://127.0.0.1:3000/callback.html",
                "http://127.0.0.1:8000/oauth-demo/callback"
            ],
            "scopes": ["openid", "profile", "email", "offline_access"],
            "grant_types": ["authorization_code", "refresh_token", "password"]
        }
    ]

    created_clients = []
    for client_data in oauth_clients_data:
        # Check if a client with this name already exists
        existing_client = db.query(OAuth2Client).filter(
            OAuth2Client.name == client_data["name"]
        ).first()

        if existing_client:
            print(f"⚠️  OAuth client '{client_data['name']}' already exists, skipping")
            created_clients.append(existing_client)
            continue

        # Generate client credentials - use consistent secret for demo purposes
        import secrets
        client_id = secrets.token_urlsafe(32)  # Random client_id
        client_secret = "demo_client_secret_1234567890123456789012345678901234567890"  # Consistent secret for demo

        # Create OAuth client
        client = OAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            name=client_data["name"],
            redirect_uris=[],
            scopes=[]
        )

        # Set redirect URIs, scopes, and grant types
        client.set_redirect_uris(client_data["redirect_uris"])
        client.set_scopes(client_data["scopes"])
        client.set_grant_types(client_data["grant_types"])

        db.add(client)
        db.flush()  # Flush to get the client ID

        created_clients.append(client)
        print(f"✅ Created OAuth client '{client.name}'")

        # Store credentials for display later
        client._plain_client_id = client_id
        client._plain_client_secret = client_secret

    db.commit()
    return created_clients


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

        # Create OAuth clients
        print("\n🔑 Creating OAuth clients...")
        oauth_clients = create_oauth_clients(db)

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

        # Display OAuth client credentials
        print("\n🔑 OAuth Clients:")
        for client in oauth_clients:
            print(f"  - {client.name}")
            if hasattr(client, '_plain_client_id'):
                print(f"    Client ID: {client._plain_client_id}")
                print(f"    Client Secret: {client._plain_client_secret}")
                print(f"    Redirect URIs: {', '.join(client.get_redirect_uris())}")
                print(f"    Scopes: {', '.join(client.get_scopes())}")
                print(f"    Grant Types: {', '.join(client.get_grant_types())}")

        # Write OAuth credentials to file for easy reference
        if oauth_clients and hasattr(oauth_clients[0], '_plain_client_id'):
            credentials_file = project_root / "frontend" / "oauth_credentials.txt"
            with open(credentials_file, "w") as f:
                f.write("# OAuth Client Credentials for Development\n")
                f.write("# NOTE: Client secret is consistent across seed runs for demo purposes\n")
                f.write("# In production, secrets should be randomly generated and stored securely\n\n")
                for client in oauth_clients:
                    if hasattr(client, '_plain_client_id'):
                        f.write(f"# {client.name}\n")
                        f.write(f"CLIENT_ID={client._plain_client_id}\n")
                        f.write(f"CLIENT_SECRET={client._plain_client_secret}\n")
                        f.write(f"GRANT_TYPES={','.join(client.get_grant_types())}\n")
                        f.write(f"\n# Update these values in:\n")
                        f.write(f"# - frontend/index.html (CLIENT_ID)\n")
                        f.write(f"# - frontend/callback.html (CLIENT_ID and CLIENT_SECRET)\n\n")
            print(f"\n💾 OAuth credentials saved to: {credentials_file}")

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
