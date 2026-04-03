#!/bin/bash

# ============================================================================
# MrWhoOidc Health Check Script
# ============================================================================
# Verifies that a post-bootstrap MrWhoOidc deployment is healthy and operational
# Usage: bash ./scripts/health-check.sh [base_url] [tenant_slug]
# Example: bash ./scripts/health-check.sh https://localhost:8443 default
# ============================================================================

set -uo pipefail

# Configuration
BASE_URL="${1:-https://localhost:8443}"
TENANT_SLUG="${2:-${MRWHO_TENANT_SLUG:-default}}"
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
    local follow_redirects="${4:-false}"
    
    print_info "Checking $description..."

    local curl_args=(-k -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT")
    if [ "$follow_redirects" = "true" ]; then
        curl_args+=(-L)
    fi

    local response_code=$(curl "${curl_args[@]}" "$url" || echo "000")
    
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

    local services
    services=$(docker compose config --services 2>/dev/null || true)

    if [ -z "$services" ]; then
        print_warning "No containers running"
        return 1
    fi

    if echo "$services" | grep -qx "mrwho-oidc"; then
        if docker compose ps mrwho-oidc | grep -qiE "running|healthy"; then
            print_success "mrwho-oidc container is running"
        else
            print_error "mrwho-oidc container is not running"
            return 1
        fi
    else
        print_warning "mrwho-oidc service not found in current compose configuration"
        return 1
    fi

    if echo "$services" | grep -qx "mrwho-postgres"; then
        if docker compose ps mrwho-postgres | grep -qiE "running|healthy"; then
            print_success "mrwho-postgres container is healthy"
        else
            print_error "mrwho-postgres container is not healthy"
            return 1
        fi
    else
        print_warning "mrwho-postgres service not found in current compose configuration"
        return 1
    fi

    if echo "$services" | grep -qx "mrwho-redis"; then
        if docker compose ps mrwho-redis | grep -qiE "running|healthy"; then
            print_success "mrwho-redis container is healthy (optional)"
        else
            print_warning "mrwho-redis container is not healthy (optional - may not be enabled)"
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
    echo "Tenant Slug: $TENANT_SLUG"
    echo "Timeout: ${TIMEOUT}s"
    echo "Checks are intended for a post-bootstrap deployment."
    echo ""
    
    local failed_checks=0
    
    # Check 1: Root JWKS Endpoint
    if check_json_endpoint "$BASE_URL/jwks" "keys" "Root JWKS Endpoint"; then
        :
    else
        failed_checks=$((failed_checks + 1))
    fi
    echo ""
    
    # Check 2: Tenant OpenID Discovery Endpoint
    if check_json_endpoint "$BASE_URL/t/$TENANT_SLUG/.well-known/openid-configuration" "issuer" "Tenant OpenID Discovery"; then
        :
    else
        print_warning "Tenant discovery usually requires a completed bootstrap for slug '$TENANT_SLUG'."
        failed_checks=$((failed_checks + 1))
    fi
    echo ""

    # Check 3: Tenant JWKS Endpoint
    if check_json_endpoint "$BASE_URL/t/$TENANT_SLUG/jwks" "keys" "Tenant JWKS Endpoint"; then
        :
    else
        failed_checks=$((failed_checks + 1))
    fi
    echo ""
    
    # Check 4: Admin UI (follow login redirect if authentication is required)
    if check_endpoint "$BASE_URL/admin/clients" "200" "Admin UI (redirect resolved)" "true"; then
        :
    else
        print_error "Admin UI did not resolve to the login page or admin experience"
        failed_checks=$((failed_checks + 1))
    fi
    echo ""
    
    # Check 5: Docker Containers
    if check_docker_containers; then
        :
    else
        failed_checks=$((failed_checks + 1))
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
        echo "  - Access admin UI: $BASE_URL/admin/clients"
        echo "  - View tenant OpenID configuration: $BASE_URL/t/$TENANT_SLUG/.well-known/openid-configuration"
        echo "  - Use tenant JWKS: $BASE_URL/t/$TENANT_SLUG/jwks"
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
        echo "  - Ensure PostgreSQL is healthy: docker compose ps mrwho-postgres"
        echo "  - Check deployment guide: /docs/deployment-guide.md"
        echo ""
        exit 1
    fi
}

# Run main function
main "$@"
