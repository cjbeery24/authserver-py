# Authentication Server - Docker-First Development Makefile

.PHONY: help clean docker-build docker-up docker-down docker-ps docker-logs docker-restart docker-setup-db docker-migrate docker-migrate-fresh docker-seed test-docker test-docker-unit test-docker-int test-docker-file test-docker-rebuild docker-lint docker-format docker-security-check docker-shell ci

# Default target
help:
	@echo "🔐 Authentication Server - Available Commands"
	@echo ""
	@echo "🚀 Quick Start:"
	@echo "  make docker-up         Start all services (API + DB + Redis + Frontend)"
	@echo "  make docker-setup-db   Initialize database (migrations + seed data)"
	@echo ""
	@echo "🐳 Docker Services:"
	@echo "  make docker-build      Build Docker images"
	@echo "  make docker-up         Start development services"
	@echo "  make docker-down       Stop all services and remove volumes"
	@echo "  make docker-restart    Restart all services"
	@echo "  make docker-ps         Show running containers"
	@echo "  make docker-logs       View logs from all services"
	@echo "  make docker-shell      Open shell in web container"
	@echo ""
	@echo "🗄️  Database:"
	@echo "  make docker-setup-db          Complete database setup (fresh migrations + seed)"
	@echo "  make docker-migrate           Run database migrations"
	@echo "  make docker-migrate-fresh     Run fresh migrations (drops all tables first)"
	@echo "  make docker-seed              Run database seeder"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test-docker              Run all tests in Docker"
	@echo "  make test-docker-unit         Run unit tests only"
	@echo "  make test-docker-int          Run integration tests only"
	@echo "  make test-docker-file         Run specific test file"
	@echo "  make test-docker-rebuild      Run tests with image rebuild"
	@echo ""
	@echo "📝 Test File Examples:"
	@echo "  make test-docker-file FILE=test_mfa_flows.py TYPE=int"
	@echo "  make test-docker-file FILE=test_mfa_flows.py TYPE=int NAME=TestMFAStatus::test_get_mfa_status_disabled"
	@echo ""
	@echo "🔍 Code Quality:"
	@echo "  make docker-lint              Run linting checks"
	@echo "  make docker-format            Format code with black and isort"
	@echo "  make docker-security-check    Run security vulnerability checks"
	@echo ""
	@echo "🧹 Cleanup:"
	@echo "  make clean                    Clean up temporary files and caches"
	@echo ""
	@echo "🔧 CI/CD:"
	@echo "  make ci                       Run full CI pipeline (lint + security + tests)"
	@echo ""
	@echo "💡 Useful URLs:"
	@echo "  API: http://localhost:8000"
	@echo "  OAuth Demo: http://localhost:8000/oauth-demo"
	@echo "  API Docs: http://localhost:8000/docs"

# Docker services
docker-build:
	@echo "🐳 Building Docker images..."
	docker compose build

docker-up:
	@echo "🐳 Starting development services..."
	docker compose up -d
	@echo "✅ Services started. Check with: docker compose ps"
	@echo ""
	@echo "💡 Useful URLs:"
	@echo "  📱 OAuth Demo UI: http://localhost:8000/oauth-demo"
	@echo "  📚 API Documentation: http://localhost:8000/docs"
	@echo "  🏥 Health Check: http://localhost:8000/health"

docker-down:
	@echo "🐳 Stopping all services..."
	docker compose down --volumes

docker-restart:
	@echo "🔄 Restarting services..."
	docker compose restart

docker-ps:
	@echo "📊 Running containers:"
	@docker compose ps

docker-logs:
	@echo "📋 Showing logs (Ctrl+C to exit)..."
	docker compose logs -f

docker-shell:
	@echo "🐚 Opening shell in web container..."
	docker compose exec authserver-web /bin/bash

# Database operations (Docker)
docker-migrate:
	@echo "🗄️  Running database migrations in Docker..."
	docker compose exec authserver-web alembic upgrade head

docker-migrate-fresh:
	@echo "🗄️  Running fresh database migrations in Docker (drops all tables first)..."
	docker compose exec authserver-web python scripts/migrate_fresh.py

docker-seed:
	@echo "🌱 Running database seeder in Docker..."
	docker compose exec authserver-web python scripts/seed_db.py

docker-setup-db: docker-migrate-fresh docker-seed
	@echo "✅ Database setup complete with fresh migrations and seed data"

# Testing (Docker)
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

# Code quality (Docker)
docker-lint:
	@echo "🔍 Running linting checks in Docker..."
	docker compose exec authserver-web flake8 app tests
	docker compose exec authserver-web mypy app
	docker compose exec authserver-web bandit -r app -f json -o bandit-report.json || true

docker-format:
	@echo "🎨 Formatting code in Docker..."
	docker compose exec authserver-web black app tests
	docker compose exec authserver-web isort app tests

docker-security-check:
	@echo "🔒 Running security checks in Docker..."
	docker compose exec authserver-web safety check
	docker compose exec authserver-web bandit -r app

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

# CI/CD workflow
ci: docker-lint docker-security-check test-docker
	@echo "✅ CI workflow complete!"
