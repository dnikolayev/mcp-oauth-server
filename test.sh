#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Activate venv if present
if [ -d "venv" ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi

export PYTHONPATH="${PYTHONPATH:-.}"

log "Running Pytest with Coverage..."
if pytest --cov=mcp_oauth_server --cov=tests --cov-report=term-missing --disable-warnings; then
    echo -e "${GREEN}✓ Tests Passed${NC}"
else
    error "Tests Failed"
    exit 1
fi

log "Running Flake8..."
if flake8 mcp_oauth_server tests; then
    echo -e "${GREEN}✓ Flake8 Passed${NC}"
else
    error "Flake8 Failed"
    exit 1
fi

log "Checking Imports with Isort..."
if isort --check-only .; then
    echo -e "${GREEN}✓ Isort Passed${NC}"
else
    error "Isort Failed"
    exit 1
fi

log "Running Pylint (Errors Only)..."
if pylint --jobs 0 --errors-only mcp_oauth_server tests; then
    echo -e "${GREEN}✓ Pylint Passed${NC}"
else
    error "Pylint Failed"
    exit 1
fi

echo -e "\n${GREEN}All checks passed successfully!${NC}"
