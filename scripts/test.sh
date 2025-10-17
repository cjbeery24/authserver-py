#!/bin/bash

# Test runner script for Docker-based testing
set -e

echo "🧪 Starting Docker-based test suite..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Parse command line arguments
TEST_TYPE="all"
REBUILD=false
CLEANUP=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            TEST_TYPE="unit"
            shift
            ;;
        --integration)
            TEST_TYPE="integration"
            shift
            ;;
        --rebuild)
            REBUILD=true
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --unit          Run only unit tests"
            echo "  --integration   Run only integration tests"
            echo "  --rebuild       Rebuild Docker images before testing"
            echo "  --no-cleanup    Don't clean up containers after testing"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect docker-compose command
if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    print_error "Neither 'docker-compose' nor 'docker compose' is available"
    exit 1
fi

# Set unique project name for test environment
PROJECT_NAME="authserver-test"
COMPOSE_ARGS="-f docker-compose.test.yml --project-name $PROJECT_NAME"

# Cleanup function
cleanup() {
    if [ "$CLEANUP" = true ]; then
        print_status "Cleaning up test containers..."
        $DOCKER_COMPOSE $COMPOSE_ARGS down --volumes --remove-orphans 2>/dev/null || true
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Rebuild images if requested
if [ "$REBUILD" = true ]; then
    print_status "Rebuilding Docker images..."
    $DOCKER_COMPOSE $COMPOSE_ARGS build --no-cache
fi

# Start test environment
print_status "Starting test environment..."
$DOCKER_COMPOSE $COMPOSE_ARGS up -d postgres-test redis-test

# Wait for services to be ready
print_status "Waiting for services to be ready..."
timeout=60
counter=0

while ! $DOCKER_COMPOSE $COMPOSE_ARGS exec -T postgres-test pg_isready -U testuser -d authserver_test > /dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        print_error "Timeout waiting for PostgreSQL to be ready"
        exit 1
    fi
    sleep 1
    counter=$((counter + 1))
done

while ! $DOCKER_COMPOSE $COMPOSE_ARGS exec -T redis-test redis-cli ping > /dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        print_error "Timeout waiting for Redis to be ready"
        exit 1
    fi
    sleep 1
    counter=$((counter + 1))
done

print_success "Services are ready!"

# Determine test command based on type
case $TEST_TYPE in
    "unit")
        TEST_CMD="pytest tests/unit/ -v --tb=short --cov=app --cov-report=term-missing"
        ;;
    "integration")
        TEST_CMD="pytest tests/integration/ -v --tb=short --cov=app --cov-report=term-missing"
        ;;
    "all")
        TEST_CMD="pytest tests/ -v --tb=short --cov=app --cov-report=term-missing --cov-report=html"
        ;;
esac

# Run tests
print_status "Running $TEST_TYPE tests..."
$DOCKER_COMPOSE $COMPOSE_ARGS run --rm test-runner sh -c "
    echo 'Running database migrations...' &&
    alembic upgrade head &&
    echo 'Starting tests...' &&
    $TEST_CMD
"

TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    print_success "All tests passed! ✅"
else
    print_error "Some tests failed! ❌"
fi

exit $TEST_EXIT_CODE
