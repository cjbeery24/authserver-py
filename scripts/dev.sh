#!/bin/bash

# Development environment management script

case "$1" in
    "up")
        echo "Starting development environment..."
        docker compose up -d
        echo "Waiting for services to be ready..."
        sleep 10
        echo "Development environment is ready!"
        echo "PostgreSQL: localhost:5432"
        echo "Redis: localhost:6379"
        ;;
    "down")
        echo "Stopping development environment..."
        docker compose down
        ;;
    "restart")
        echo "Restarting development environment..."
        docker compose restart
        ;;
    "logs")
        docker compose logs -f
        ;;
    "status")
        docker compose ps
        ;;
    "clean")
        echo "Cleaning up development environment..."
        docker compose down -v
        docker system prune -f
        ;;
    *)
        echo "Usage: $0 {up|down|restart|logs|status|clean}"
        echo ""
        echo "Commands:"
        echo "  up      - Start development environment"
        echo "  down    - Stop development environment"
        echo "  restart - Restart development environment"
        echo "  logs    - Show logs from all services"
        echo "  status  - Show status of all services"
        echo "  clean   - Stop and remove all containers and volumes"
        exit 1
        ;;
esac
