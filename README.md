# Python Authentication & Authorization Server

A robust, production-ready authentication and authorization server built with FastAPI, SQLAlchemy, and PostgreSQL. This server provides comprehensive OAuth 2.0, OpenID Connect, and multi-factor authentication capabilities.

## 🎉 OAuth Demo UI

The project includes an **integrated OAuth demo frontend** served directly from the FastAPI application!

**Quick Access**:

- 🔗 Local/Docker: `http://localhost:8000/oauth-demo`
- 📖 Standalone Mode: [frontend/README.md](frontend/README.md)

**Features**:

- ✅ OAuth 2.0 Authorization Code Flow with PKCE
- ✅ Integrated into Docker container (no separate frontend server needed)
- ✅ Auto-configuration based on deployment environment
- ✅ Modern, responsive UI with real-time token display

## 🚀 Features

- **OAuth 2.0 & OpenID Connect** - Full implementation with PKCE support
- **Multi-Factor Authentication** - TOTP with backup codes
- **Role-Based Access Control** - Granular permission management
- **JWT Token Management** - Secure token generation and validation
- **Database Migrations** - Alembic-based schema management
- **Docker Support** - Complete development environment
- **Comprehensive Testing** - Unit, integration, and end-to-end tests
- **Security Features** - Rate limiting, audit logging, security headers

## 🛠️ Tech Stack

- **Framework**: FastAPI (Python 3.13+)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Cache**: Redis
- **Authentication**: JWT, OAuth 2.0, OpenID Connect
- **MFA**: PyOTP for TOTP implementation
- **Migrations**: Alembic
- **Testing**: pytest
- **Code Quality**: Black, Flake8, MyPy
- **Containerization**: Docker & Docker Compose

## 📋 Prerequisites

- **Docker Desktop** (includes Docker and Docker Compose)
- **Git**
- That's it! Everything else runs in Docker containers

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd authserver-py
```

### 2. Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration (use the defaults for quick start)
# Most important: Set JWT_SECRET_KEY, JWT_PRIVATE_KEY, JWT_PUBLIC_KEY
```

### 3. Start Everything with Docker

```bash
# Start all services (API, PostgreSQL, Redis, Frontend)
make docker-up

# Initialize the database (run migrations + seed data)
make docker-setup-db
```

That's it! 🎉 Everything is now running:

- 🌐 **API Server**: http://localhost:8000
- 📱 **OAuth Demo UI**: http://localhost:8000/oauth-demo
- 📚 **API Documentation**: http://localhost:8000/docs
- 🏥 **Health Check**: http://localhost:8000/health

### Daily Development

```bash
# Check container status
make docker-ps

# View logs
make docker-logs

# Restart services (after code changes)
# Note: Most Python changes auto-reload!
make docker-restart

# Stop everything
make docker-down
```

## 📚 API Documentation

Once the server is running, you can access:

- **Interactive API Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

## 🗄️ Database Management

### Common Database Operations

```bash
# Complete database setup (fresh migrations + seed data)
make docker-setup-db

# Run migrations only
make docker-migrate

# Reset database (drops all tables + runs migrations)
make docker-migrate-fresh

# Seed database with test data
make docker-seed
```

### Advanced Database Operations

```bash
# Open a shell in the container to run custom commands
make docker-shell

# Then inside the container:
alembic revision --autogenerate -m "Description of changes"
alembic upgrade head
alembic downgrade -1
alembic current
```

### Database Connection

The application connects to PostgreSQL running in Docker:

- **Host**: postgres (container name) / localhost (from host)
- **Port**: 5432
- **Database**: authserver
- **User**: authuser

## 🧪 Testing

### Run All Tests

```bash
# Run all tests in Docker (recommended)
make test-docker

# Run unit tests only
make test-docker-unit

# Run integration tests only
make test-docker-int

# Run specific test file
make test-docker-file FILE=test_mfa_flows.py TYPE=int

# Run specific test class/method
make test-docker-file FILE=test_mfa_flows.py TYPE=int NAME=TestMFAStatus::test_get_mfa_status_disabled
```

## 🔍 Code Quality

### Linting and Formatting

```bash
# Run linting checks
make docker-lint

# Format code (black + isort)
make docker-format

# Security checks
make docker-security-check
```

### CI/CD Pipeline

```bash
# Run full CI pipeline (lint + security + tests)
make ci
```

## 🛠️ Available Make Commands

For a complete list of available commands:

```bash
make help
```

Common commands:

```bash
# Start services
make docker-up

# Initialize database
make docker-setup-db

# Run tests
make test-docker

# View logs
make docker-logs

# Stop services
make docker-down

# Clean up temporary files
make clean
```

## 📁 Project Structure

```
authserver-py/
├── alembic/                 # Database migrations
├── app/                     # Application code
│   ├── api/                # API endpoints
│   │   └── v1/            # API version 1
│   ├── core/               # Core functionality
│   ├── models/             # Database models
│   ├── repositories/       # Data access layer
│   ├── schemas/            # Pydantic schemas
│   └── middleware/         # Custom middleware
├── docker/                  # Docker configuration
├── scripts/                 # Utility scripts
├── tests/                   # Test suite
├── tasks/                   # Project task management
├── pyproject.toml          # Project configuration
├── docker-compose.yml      # Development services
└── README.md               # This file
```

## 🔐 Environment Variables

### Required Variables

```bash
# Database
DATABASE_URL=postgresql://user:password@host:port/database
JWT_SECRET_KEY=your-secret-key-here

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=true
```

### Optional Variables

```bash
# Redis
REDIS_URL=redis://localhost:6379/0

# Security
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# MFA
MFA_TOTP_ISSUER=AuthServer
MFA_TOTP_DIGITS=6
MFA_TOTP_PERIOD=30
```

## 🚀 Deployment

### Production Docker

```bash
# Build production image
docker build -t authserver:latest .

# Run with environment variables
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL=your-production-db-url \
  -e JWT_SECRET_KEY=your-production-secret \
  authserver:latest
```

### Environment-Specific Configuration

The application automatically loads configuration based on the `APP_ENV` environment variable:

- `development` - Development settings with debug enabled
- `production` - Production settings with security optimizations
- `testing` - Test-specific configuration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Write comprehensive tests for new features
- Update documentation for API changes
- Use conventional commit messages
- Ensure all tests pass before submitting PRs

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

- Check the [API documentation](http://localhost:8000/docs) when running locally
- Review the [task list](tasks/tasks-prd-auth-server.md) for development progress
- Open an issue for bugs or feature requests

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes and releases.
