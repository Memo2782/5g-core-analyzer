.PHONY: help build up down restart logs shell test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker images
	docker compose build

up: ## Start all services
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@echo "Application: http://localhost:8000"
	@echo "PostgreSQL: localhost:5432"
	@echo "Redis: localhost:6379"

down: ## Stop all services
	docker compose down

restart: ## Restart all services
	docker compose restart

logs: ## Show logs from all services
	docker compose logs -f

logs-app: ## Show app logs only
	docker compose logs -f app

shell: ## Open shell in app container
	docker compose exec app bash

test: ## Run tests
	docker compose exec app python -m pytest tests/ -v

test-watch: ## Run tests in watch mode
	docker compose exec app python -m pytest tests/ -v --watch

db-migrate: ## Run database migrations
	docker compose exec app python -c "from core.database import init_db; init_db(); print('Database initialized')"

clean: ## Remove all containers, volumes, and images
	docker compose down -v
	docker system prune -f
