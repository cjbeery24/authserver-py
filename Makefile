# Authentication Server - Development Makefile

.PHONY: help install dev test test-unit test-integration test-docker clean lint format security-check docker-build docker-up docker-down migrate migrate-fresh migrate-test seed setup-db

# Default target
help:
	@echo "🔐 Authentication Server - Available Commands"
	@echo ""
	@echo "📦 Setup & Installation:"
	@echo "  make install          Install dependencies with Poetry"
	@echo "  make dev              Set up development environment"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test                      Run all tests (local SQLite)"
	@echo "  make test-unit                 Run unit tests only"
	@echo "  make test-integration          Run integration tests only"
	@echo "  make test-unit-file            Run specific unit test file"
	@echo "  make test-integration-file     Run specific integration test file"
	@echo "  make test-docker               Run all tests in Docker (PostgreSQL)"
	@echo "  make test-docker-unit          Run unit tests in Docker"
	@echo "  make test-docker-int           Run integration tests in Docker"
	@echo "  make test-docker-file          Run specific test file in Docker"
	@echo ""
	@echo "📝 Test File Examples:"
	@echo "  make test-docker-file FILE=test_mfa_flows.py TYPE=int"
	@echo "  make test-docker-file FILE=test_mfa_flows.py TYPE=int NAME=TestMFAStatus::test_get_mfa_status_disabled"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  make docker-build     Build Docker images"
	@echo "  make docker-up        Start development services"
	@echo "  make docker-down      Stop all services"
	@echo "  make docker-test-up   Start test services"
	@echo "  make docker-test-down Stop test services"
	@echo ""
	@echo "🗄️  Database:"
	@echo "  make migrate          Run database migrations"
	@echo "  make migrate-fresh    Run fresh database migrations (drops all tables first)"
	@echo "  make migrate-test     Run migrations on test database"
	@echo "  make seed             Run database seeder to create initial data"
	@echo "  make setup-db         Run fresh migrations and seed data (complete setup)"
	@echo ""
	@echo "🔍 Code Quality:"
	@echo "  make lint             Run linting checks"
	@echo "  make format           Format code with black and isort"
	@echo "  make security-check   Run security vulnerability checks"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean            Clean up temporary files and caches"

# Installation and setup
install:
	@echo "📦 Installing dependencies..."
	poetry install --with dev

dev: install
	@echo "🛠️  Setting up development environment..."
	@echo "Creating .env file if it doesn't exist..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env file from .env.example"; \
		echo "⚠️  Please update .env with your configuration"; \
	else \
		echo "✅ .env file already exists"; \
	fi
	@echo "🔑 Generating RSA keys..."
	poetry run python scripts/generate_rsa_keys.py
	@echo "✅ Development environment ready!"

# Local testing (SQLite)
test:
	@echo "🧪 Running all tests (local SQLite)..."
	poetry run pytest tests/ -v --tb=short --cov=app --cov-report=term-missing

test-unit:
	@echo "🧪 Running unit tests..."
	poetry run pytest tests/unit/ -v --tb=short --cov=app --cov-report=term-missing

test-integration:
	@echo "🧪 Running integration tests..."
	poetry run pytest tests/integration/ -v --tb=short --cov=app --cov-report=term-missing

test-integration-file:
	@echo "🧪 Running specific integration test file..."
	@if [ -z "$(FILE)" ] || [ -z "$(TYPE)" ]; then \
		echo "❌ ERROR: Please specify FILE and TYPE variables"; \
		echo "Usage: make test-integration-file FILE=test_mfa_flows.py TYPE=int [NAME=TestMFAStatus::test_get_mfa_status_disabled]"; \
		exit 1; \
	fi; \
	if [ "$(TYPE)" != "int" ] && [ "$(TYPE)" != "unit" ]; then \
		echo "❌ ERROR: TYPE must be 'int' or 'unit'"; \
		exit 1; \
	fi; \
	if [[ "$(FILE)" == tests/* ]]; then \
		FULL_PATH="$(FILE)"; \
	else \
		if [ "$(TYPE)" = "int" ]; then \
			FULL_PATH="tests/integration/$(FILE)"; \
		else \
			FULL_PATH="tests/unit/$(FILE)"; \
		fi; \
	fi; \
	if [ ! -f "$$FULL_PATH" ]; then \
		echo "❌ ERROR: Test file $$FULL_PATH does not exist"; \
		exit 1; \
	fi; \
	if [ -n "$(NAME)" ]; then \
		poetry run pytest $$FULL_PATH::$(NAME) -v --tb=short --cov=app --cov-report=term-missing; \
	else \
		poetry run pytest $$FULL_PATH -v --tb=short --cov=app --cov-report=term-missing; \
	fi

test-unit-file:
	@echo "🧪 Running specific unit test file..."
	@if [ -z "$(FILE)" ] || [ -z "$(TYPE)" ]; then \
		echo "❌ ERROR: Please specify FILE and TYPE variables"; \
		echo "Usage: make test-unit-file FILE=test_authentication.py TYPE=unit [NAME=TestAuthentication::test_verify_password]"; \
		exit 1; \
	fi; \
	if [ "$(TYPE)" != "int" ] && [ "$(TYPE)" != "unit" ]; then \
		echo "❌ ERROR: TYPE must be 'int' or 'unit'"; \
		exit 1; \
	fi; \
	if [[ "$(FILE)" == tests/* ]]; then \
		FULL_PATH="$(FILE)"; \
	else \
		if [ "$(TYPE)" = "int" ]; then \
			FULL_PATH="tests/integration/$(FILE)"; \
		else \
			FULL_PATH="tests/unit/$(FILE)"; \
		fi; \
	fi; \
	if [ ! -f "$$FULL_PATH" ]; then \
		echo "❌ ERROR: Test file $$FULL_PATH does not exist"; \
		exit 1; \
	fi; \
	if [ -n "$(NAME)" ]; then \
		poetry run pytest $$FULL_PATH::$(NAME) -v --tb=short --cov=app --cov-report=term-missing; \
	else \
		poetry run pytest $$FULL_PATH -v --tb=short --cov=app --cov-report=term-missing; \
	fi

# Docker-based testing (PostgreSQL)
test-docker:
	@echo "🐳 Running all tests in Docker..."
	./scripts/test.sh

test-docker-unit:
	@echo "🐳 Running unit tests in Docker..."
	./scripts/test.sh --unit

test-docker-int:
	@echo "🐳 Running integration tests in Docker..."
	./scripts/test.sh --integration

test-docker-file:
	@echo "🐳 Running specific test file in Docker..."
	@if [ -z "$(FILE)" ] || [ -z "$(TYPE)" ]; then \
		echo "❌ ERROR: Please specify FILE and TYPE variables"; \
		echo "Usage: make test-docker-file FILE=test_mfa_flows.py TYPE=int [NAME=TestMFAStatus::test_get_mfa_status_disabled]"; \
		exit 1; \
	fi; \
	if [ "$(TYPE)" != "int" ] && [ "$(TYPE)" != "unit" ]; then \
		echo "❌ ERROR: TYPE must be 'int' or 'unit'"; \
		exit 1; \
	fi; \
	if [[ "$(FILE)" == tests/* ]]; then \
		FULL_PATH="$(FILE)"; \
	else \
		if [ "$(TYPE)" = "int" ]; then \
			FULL_PATH="tests/integration/$(FILE)"; \
		else \
			FULL_PATH="tests/unit/$(FILE)"; \
		fi; \
	fi; \
	if [ ! -f "$$FULL_PATH" ]; then \
		echo "❌ ERROR: Test file $$FULL_PATH does not exist"; \
		exit 1; \
	fi; \
	ARGS="--file $$FULL_PATH"; \
	if [ -n "$(NAME)" ]; then \
		ARGS="$$ARGS --name $(NAME)"; \
	fi; \
	./scripts/test.sh $$ARGS

test-docker-rebuild:
	@echo "🐳 Running tests in Docker (rebuilding images)..."
	./scripts/test.sh --rebuild

# Docker services
docker-build:
	@echo "🐳 Building Docker images..."
	docker compose build

docker-up:
	@echo "🐳 Starting development services..."
	docker compose up -d
	@echo "✅ Services started. Check with: docker compose ps"

docker-down:
	@echo "🐳 Stopping all services..."
	docker compose down --volumes

docker-test-up:
	@echo "🐳 Starting test services..."
	docker compose -f docker-compose.test.yml up -d postgres-test redis-test
	@echo "✅ Test services started"

docker-test-down:
	@echo "🐳 Stopping test services..."
	docker compose -f docker-compose.test.yml down --volumes

# Database migrations
migrate:
	@echo "🗄️  Running database migrations..."
	poetry run alembic upgrade head

migrate-fresh:
	@echo "🗄️  Running fresh database migrations (drops all tables first)..."
	poetry run python scripts/migrate_fresh.py

migrate-test:
	@echo "🗄️  Running migrations on test database..."
	DATABASE_URL="postgresql://testuser:testpass@localhost:5433/authserver_test" poetry run alembic upgrade head

seed:
	@echo "🌱 Running database seeder..."
	poetry run python scripts/seed_db.py

setup-db: migrate-fresh seed
	@echo "✅ Database setup complete with fresh migrations and seed data"

# Code quality
lint:
	@echo "🔍 Running linting checks..."
	poetry run flake8 app tests
	poetry run mypy app
	poetry run bandit -r app -f json -o bandit-report.json || true

format:
	@echo "🎨 Formatting code..."
	poetry run black app tests
	poetry run isort app tests

security-check:
	@echo "🔒 Running security checks..."
	poetry run safety check
	poetry run bandit -r app

# Cleanup
clean:
	@echo "🧹 Cleaning up..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf dist
	rm -rf build
	@echo "✅ Cleanup complete"

# Development server
run:
	@echo "🚀 Starting development server..."
	poetry run python run.py

run-prod:
	@echo "🚀 Starting production server..."
	poetry run uvicorn app.main:app --host 0.0.0.0 --port 8000

# Quick development workflow
dev-test: format lint test
	@echo "✅ Development workflow complete!"

# CI/CD workflow
ci: install lint security-check test-docker
	@echo "✅ CI workflow complete!"