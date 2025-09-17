# Python Authentication & Authorization Server

A robust, production-ready authentication and authorization server built with FastAPI, SQLAlchemy, and PostgreSQL. This server provides comprehensive OAuth 2.0, OpenID Connect, and multi-factor authentication capabilities.

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

- Python 3.13 or higher
- Docker and Docker Compose
- Poetry (for dependency management)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd authserver-py
```

### 2. Install Dependencies

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install project dependencies
poetry install
```

### 3. Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
# Required variables:
# - DATABASE_URL
# - JWT_SECRET_KEY
# - Other database and security settings
```

### 4. Start Development Environment

```bash
# Start PostgreSQL and Redis containers
make docker-up

# Wait for services to be ready, then run migrations
poetry run alembic upgrade head
```

### 5. Run the Application

```bash
# Development mode with auto-reload
make run

# Or manually
poetry run python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will be available at `http://localhost:8000`

## 📚 API Documentation

Once the server is running, you can access:

- **Interactive API Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

## 🗄️ Database Management

### Running Migrations

```bash
# Create a new migration
poetry run alembic revision --autogenerate -m "Description of changes"

# Apply migrations
poetry run alembic upgrade head

# Rollback migrations
poetry run alembic downgrade -1

# Check current migration status
poetry run alembic current
```

### Database Connection

The application automatically connects to the database using the configuration in your `.env` file. The default development setup uses:

- **Host**: localhost
- **Port**: 5432
- **Database**: authserver
- **User**: authuser

## 🧪 Testing

### Run All Tests

```bash
make test
# or
poetry run pytest
```

### Run Specific Test Categories

```bash
# Unit tests only
poetry run pytest tests/unit/

# Integration tests
poetry run pytest tests/integration/

# With coverage
poetry run pytest --cov=app
```

### Test Database

Tests use a separate test database. Ensure your `.env` file includes:

```bash
TESTING=true
TEST_DATABASE_URL=postgresql://authuser:authpass@localhost:5432/authserver_test
```

## 🐳 Docker Commands

```bash
# Start services
make docker-up

# Stop services
make docker-down

# Restart services
make docker-restart

# View logs
make docker-logs

# Check status
make docker-status

# Clean up (removes volumes)
make docker-clean
```

## 🔧 Development Commands

```bash
# Install dependencies
make install-dev

# Add new dependency
make add package=package-name

# Add development dependency
make add-dev package=package-name

# Update dependencies
make update

# Code formatting
poetry run black app/ tests/
poetry run isort app/ tests/

# Linting
poetry run flake8 app/ tests/
poetry run mypy app/

# Clean up cache files
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
