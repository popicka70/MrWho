#!/bin/bash

# ============================================================================
# MrWhoOidc Health Check Script
# ============================================================================
# Verifies that the MrWhoOidc deployment is healthy and operational
# Usage: ./scripts/health-check.sh [base_url]
# Example: ./scripts/health-check.sh https://localhost:8443
# ============================================================================

set -e

# Configuration
BASE_URL="${1:-https://localhost:8443}"
TIMEOUT=10
MAX_RETRIES=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "$1"
}

# Function to check HTTP endpoint
check_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    local description="$3"
    
    print_info "Checking $description..."
    
    local response_code=$(curl -k -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" "$url" || echo "000")
    
    if [ "$response_code" = "$expected_status" ]; then
        print_success "$description returned HTTP $response_code"
        return 0
    else
        print_error "$description returned HTTP $response_code (expected $expected_status)"
        return 1
    fi
}

# Function to check JSON endpoint
check_json_endpoint() {
    local url="$1"
    local json_field="$2"
    local description="$3"
    
    print_info "Checking $description..."
    
    local response=$(curl -k -s --connect-timeout "$TIMEOUT" "$url" || echo "{}")
    
    if echo "$response" | grep -q "\"$json_field\""; then
        print_success "$description contains required field: $json_field"
        return 0
    else
        print_error "$description missing required field: $json_field"
        print_info "Response: $response"
        return 1
    fi
}

# Function to check Docker containers
check_docker_containers() {
    print_info "Checking Docker containers..."
    
    if ! command -v docker &> /dev/null; then
        print_warning "Docker not found in PATH - skipping container checks"
        return 0
    fi
    
    if ! docker compose ps &> /dev/null; then
        print_warning "No docker-compose deployment found - skipping container checks"
        return 0
    fi
    
    local containers=$(docker compose ps --format json 2>/dev/null || echo "[]")
    
    if [ "$containers" = "[]" ]; then
        print_warning "No containers running"
        return 1
    fi
    
    # Check webauth container
    if docker compose ps webauth | grep -q "running"; then
        print_success "webauth container is running"
    else
        print_error "webauth container is not running"
        return 1
    fi
    
    # Check postgres container
    if docker compose ps postgres | grep -q "healthy\|running"; then
        print_success "postgres container is healthy"
    else
        print_error "postgres container is not healthy"
        return 1
    fi
    
    # Check redis container (optional)
    if docker compose ps redis &> /dev/null; then
        if docker compose ps redis | grep -q "healthy\|running"; then
            print_success "redis container is healthy (optional)"
        else
            print_warning "redis container is not healthy (optional - may not be enabled)"
        fi
    fi
    
    return 0
}

# Main health check execution
main() {
    echo "============================================================================"
    echo "MrWhoOidc Health Check"
    echo "============================================================================"
    echo "Base URL: $BASE_URL"
    echo "Timeout: ${TIMEOUT}s"
    echo ""
    
    local failed_checks=0
    
    # Check 1: OpenID Discovery Endpoint
    if check_json_endpoint "$BASE_URL/.well-known/openid-configuration" "issuer" "OpenID Discovery"; then
        :
    else
        ((failed_checks++))
    fi
    echo ""
    
    # Check 2: JWKS Endpoint
    if check_json_endpoint "$BASE_URL/jwks" "keys" "JWKS Endpoint"; then
        :
    else
        ((failed_checks++))
    fi
    echo ""
    
    # Check 3: Health Endpoint
    if check_endpoint "$BASE_URL/health" "200" "Health Endpoint"; then
        :
    else
        ((failed_checks++))
    fi
    echo ""
    
    # Check 4: Admin UI (should return HTML)
    if check_endpoint "$BASE_URL/admin" "200" "Admin UI"; then
        :
    else
        print_warning "Admin UI check failed - may require authentication"
    fi
    echo ""
    
    # Check 5: Docker Containers
    if check_docker_containers; then
        :
    else
        ((failed_checks++))
    fi
    echo ""
    
    # Summary
    echo "============================================================================"
    if [ $failed_checks -eq 0 ]; then
        print_success "All health checks passed!"
        echo "============================================================================"
        echo ""
        echo "Your MrWhoOidc deployment is healthy and operational."
        echo ""
        echo "Next steps:"
        echo "  - Access admin UI: $BASE_URL/admin"
        echo "  - View OpenID configuration: $BASE_URL/.well-known/openid-configuration"
        echo "  - Configure your first OIDC client in the admin UI"
        echo ""
        exit 0
    else
        print_error "$failed_checks health check(s) failed"
        echo "============================================================================"
        echo ""
        echo "Troubleshooting:"
        echo "  - Check container logs: docker compose logs"
        echo "  - Verify environment variables in .env file"
        echo "  - Ensure PostgreSQL is healthy: docker compose ps postgres"
        echo "  - Check deployment guide: /docs/deployment-guide.md"
        echo ""
        exit 1
    fi
}

# Run main function
main "$@"
