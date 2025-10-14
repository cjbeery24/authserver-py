# 🧪 Testing Guide

This document explains how to run tests for the Authentication Server, including both local and Docker-based testing approaches.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Testing Approaches](#testing-approaches)
- [Local Testing (SQLite)](#local-testing-sqlite)
- [Docker Testing (PostgreSQL)](#docker-testing-postgresql)
- [Test Types](#test-types)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

### For New Developers (Recommended: Docker)

```bash
# 1. Clone and setup
git clone <repository>
cd authserver-py

# 2. Run tests in Docker (no local setup needed!)
make test-docker

# 3. Or run specific test types
make test-docker-unit        # Unit tests only
make test-docker-int         # Integration tests only
```

### For Local Development

```bash
# 1. Setup local environment
make dev

# 2. Start local Redis (required)
redis-server

# 3. Run tests locally
make test                    # All tests with SQLite
make test-unit              # Unit tests only
make test-integration       # Integration tests only
```

## 🔄 Testing Approaches

We support two testing approaches to accommodate different development workflows:

| Approach   | Database           | Redis                 | Pros                                       | Cons                                     |
| ---------- | ------------------ | --------------------- | ------------------------------------------ | ---------------------------------------- |
| **Local**  | SQLite (in-memory) | Local Redis           | Fast, Simple setup                         | Requires local Redis, SQLite differences |
| **Docker** | PostgreSQL         | Redis (containerized) | Production-like, Consistent, No local deps | Slower startup, Requires Docker          |

## 🏠 Local Testing (SQLite)

### Prerequisites

- Python 3.13+
- Poetry
- Redis server running locally

### Setup

```bash
# Install dependencies
make install

# Setup development environment
make dev

# Start Redis
redis-server
# Or on macOS with Homebrew:
brew services start redis
```

### Running Tests

```bash
# All tests
make test

# Specific test types
make test-unit              # Unit tests only
make test-integration       # Integration tests only

# With coverage report
poetry run pytest tests/ --cov=app --cov-report=html

# Specific test file
poetry run pytest tests/unit/test_security.py -v

# Specific test method
poetry run pytest tests/integration/test_auth_flows.py::TestUserRegistrationFlow::test_successful_registration -v
```

### Configuration

Local tests use:

- **Database**: In-memory SQLite (recreated for each test)
- **Redis**: Local Redis instance (localhost:6379)
- **Config**: Test-specific settings in `tests/conftest.py`

## 🐳 Docker Testing (PostgreSQL)

### Prerequisites

- Docker
- Docker Compose

### Setup

No additional setup required! Docker handles everything.

### Running Tests

```bash
# All tests (recommended for CI/CD)
make test-docker

# Specific test types
make test-docker-unit       # Unit tests only
make test-docker-int        # Integration tests only

# Rebuild images and test
make test-docker-rebuild

# Manual Docker commands
./scripts/test.sh           # Full test suite
./scripts/test.sh --unit    # Unit tests only
./scripts/test.sh --integration  # Integration tests only
./scripts/test.sh --rebuild      # Rebuild images first
```

### Configuration

Docker tests use:

- **Database**: PostgreSQL 17 (localhost:5433)
- **Redis**: Redis 7 (localhost:6380)
- **Environment**: Isolated test containers
- **Config**: Environment variables in `docker-compose.test.yml`

### Docker Services

The test environment includes:

```yaml
# Test Database
postgres-test:
  - Port: 5433 (to avoid conflicts)
  - Database: authserver_test
  - User: testuser
  - Optimized for testing speed

# Test Redis
redis-test:
  - Port: 6380 (to avoid conflicts)
  - No persistence (faster)
  - Isolated from development Redis

# Test Runner
test-runner:
  - Runs migrations automatically
  - Executes test suite
  - Generates coverage reports
```

## 🧪 Test Types

### Unit Tests (`tests/unit/`)

Fast, isolated tests for individual components:

```bash
# Examples
tests/unit/test_security.py      # Password hashing, tokens, etc.
tests/unit/test_rbac.py          # Role-based access control
tests/unit/test_cache.py         # Redis caching utilities
tests/unit/test_authentication.py # Authentication manager
```

**Characteristics:**

- No external dependencies
- Mock external services
- Fast execution (< 1 second each)
- Test business logic in isolation

### Integration Tests (`tests/integration/`)

End-to-end tests with real services:

```bash
# Examples
tests/integration/test_auth_flows.py  # Complete authentication flows
```

**Characteristics:**

- Use real database and Redis
- Test complete user journeys
- Slower execution (1-5 seconds each)
- Test service interactions

### Test Markers

Use pytest markers to run specific test categories:

```bash
# Run only unit tests
poetry run pytest -m unit

# Run only integration tests
poetry run pytest -m integration

# Run only authentication tests
poetry run pytest -m auth

# Run only RBAC tests
poetry run pytest -m rbac

# Skip slow tests
poetry run pytest -m "not slow"
```

## 🔄 CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run Docker Tests
        run: |
          make test-docker

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
```

### Local CI Simulation

```bash
# Run the same checks as CI
make ci
```

## 🛠️ Development Workflow

### Test-Driven Development

```bash
# 1. Write a failing test
poetry run pytest tests/unit/test_new_feature.py::test_new_function -v

# 2. Implement the feature
# ... code changes ...

# 3. Run tests until they pass
poetry run pytest tests/unit/test_new_feature.py::test_new_function -v

# 4. Run full test suite
make test
```

### Before Committing

```bash
# Quick development check
make dev-test  # Format + Lint + Test

# Or comprehensive check
make ci        # Full CI workflow locally
```

## 🐛 Troubleshooting

### Common Issues

#### "Redis connection failed"

```bash
# Check if Redis is running
redis-cli ping

# Start Redis
redis-server
# Or on macOS:
brew services start redis
```

#### "Port already in use" (Docker)

```bash
# Check what's using the ports
lsof -i :5433  # Test PostgreSQL
lsof -i :6380  # Test Redis

# Stop conflicting services
make docker-test-down
```

#### "Permission denied" on test script

```bash
# Make script executable
chmod +x scripts/test.sh
```

#### Tests fail with "Event loop is closed"

```bash
# This usually indicates async fixture issues
# Try running tests individually:
poetry run pytest tests/integration/test_auth_flows.py::TestUserRegistrationFlow -v
```

#### Database migration errors

```bash
# Reset test database
make docker-test-down
make docker-test-up
make migrate-test
```

### Performance Issues

#### Slow Docker tests

```bash
# Use local testing for development
make test

# Or run specific test files
poetry run pytest tests/unit/test_security.py -v
```

#### Out of memory errors

```bash
# Clean up Docker resources
docker system prune -a
make clean
```

### Debug Mode

#### Enable SQL logging

```python
# In tests/conftest_docker.py, change:
echo=True  # Shows all SQL queries
```

#### Verbose test output

```bash
# More detailed output
poetry run pytest tests/ -v -s --tb=long

# Show print statements
poetry run pytest tests/ -s
```

#### Keep containers running for debugging

```bash
# Don't cleanup containers
./scripts/test.sh --no-cleanup

# Then inspect:
docker-compose -f docker-compose.test.yml exec postgres-test psql -U testuser -d authserver_test
docker-compose -f docker-compose.test.yml exec redis-test redis-cli
```

## 📊 Coverage Reports

### Generate Coverage Reports

```bash
# HTML report (opens in browser)
poetry run pytest tests/ --cov=app --cov-report=html
open htmlcov/index.html

# Terminal report
poetry run pytest tests/ --cov=app --cov-report=term-missing

# XML report (for CI)
poetry run pytest tests/ --cov=app --cov-report=xml
```

### Coverage Goals

- **Minimum**: 80% overall coverage
- **Target**: 90%+ for core business logic
- **Critical**: 100% for security-related code

## 🔧 Configuration Files

| File                       | Purpose                           |
| -------------------------- | --------------------------------- |
| `pytest.ini`               | Local testing configuration       |
| `pytest-docker.ini`        | Docker testing configuration      |
| `tests/conftest.py`        | Local test fixtures (SQLite)      |
| `tests/conftest_docker.py` | Docker test fixtures (PostgreSQL) |
| `docker-compose.test.yml`  | Test environment services         |
| `Dockerfile.test`          | Test runner container             |
| `scripts/test.sh`          | Test execution script             |

## 📚 Best Practices

### Writing Tests

1. **Use descriptive test names**

   ```python
   def test_user_registration_with_valid_data_creates_user_successfully():
   ```

2. **Follow AAA pattern** (Arrange, Act, Assert)

   ```python
   def test_password_hashing():
       # Arrange
       password = "test_password"
       username = "testuser"

       # Act
       hashed = PasswordHasher.hash_password(password, username)

       # Assert
       assert PasswordHasher.verify_password(password, hashed, username)
   ```

3. **Use appropriate test markers**

   ```python
   @pytest.mark.unit
   @pytest.mark.auth
   def test_token_validation():
   ```

4. **Mock external dependencies in unit tests**
   ```python
   @pytest.fixture
   def mock_redis():
       return AsyncMock()
   ```

### Test Organization

```
tests/
├── unit/                    # Fast, isolated tests
│   ├── test_security.py
│   ├── test_rbac.py
│   └── test_cache.py
├── integration/             # End-to-end tests
│   └── test_auth_flows.py
├── conftest.py             # Local fixtures
└── conftest_docker.py      # Docker fixtures
```

### Performance

- **Unit tests**: < 1 second each
- **Integration tests**: < 5 seconds each
- **Total test suite**: < 2 minutes

---

## 🎯 Summary

**For daily development**: Use `make test` (local SQLite)
**For CI/CD and final validation**: Use `make test-docker` (PostgreSQL)
**For new team members**: Start with `make test-docker` (no setup required)

This dual approach ensures fast development cycles while maintaining production-like testing when needed.
