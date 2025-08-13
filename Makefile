.PHONY: help install install-dev add add-dev remove remove-dev update update-dev clean test run docker-up docker-down

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	poetry install --only main

install-dev: ## Install all dependencies (including dev)
	poetry install

add: ## Add a production dependency (usage: make add package=package-name)
	poetry add $(package)

add-dev: ## Add a development dependency (usage: make add-dev package=package-name)
	poetry add --group dev $(package)

remove: ## Remove a dependency (usage: make remove package=package-name)
	poetry remove $(package)

remove-dev: ## Remove a development dependency (usage: make remove-dev package=package-name)
	poetry remove --group dev $(package)

update: ## Update all dependencies
	poetry update

update-dev: ## Update development dependencies only
	poetry update --only dev

lock: ## Regenerate poetry.lock file
	poetry lock

show: ## Show dependency tree
	poetry show --tree

show-outdated: ## Show outdated dependencies
	poetry show --outdated

clean: ## Clean up Python cache files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.pyd" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".coverage" -delete 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true

test: ## Run tests
	poetry run pytest

run: ## Run the application
	poetry run python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

docker-up: ## Start Docker services
	./scripts/dev.sh up

docker-down: ## Stop Docker services
	./scripts/dev.sh down

docker-restart: ## Restart Docker services
	./scripts/dev.sh restart

docker-logs: ## Show Docker logs
	./scripts/dev.sh logs

docker-status: ## Show Docker status
	./scripts/dev.sh status

docker-clean: ## Clean up Docker environment
	./scripts/dev.sh clean
