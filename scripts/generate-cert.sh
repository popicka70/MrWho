#!/bin/bash

# ============================================================================
# MrWhoOidc TLS Certificate Generator
# ============================================================================
# Generates self-signed TLS certificates for development and testing
# For production: Use certificates from a trusted Certificate Authority
# Usage: ./scripts/generate-cert.sh [domain] [password]
# Example: ./scripts/generate-cert.sh localhost changeit
# ============================================================================

set -e

# Configuration
DOMAIN="${1:-localhost}"
PASSWORD="${2:-changeit}"
CERT_DIR="./certs"
CERT_FILE="$CERT_DIR/aspnetapp.pfx"
DAYS_VALID=365

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

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    print_error "OpenSSL is not installed"
    echo "Please install OpenSSL:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  macOS: brew install openssl"
    echo "  Windows: Install from https://slproweb.com/products/Win32OpenSSL.html"
    exit 1
fi

# Main certificate generation
main() {
    echo "============================================================================"
    echo "MrWhoOidc TLS Certificate Generator"
    echo "============================================================================"
    echo "Domain: $DOMAIN"
    echo "Valid for: $DAYS_VALID days"
    echo "Output: $CERT_FILE"
    echo ""
    
    # Create certs directory if it doesn't exist
    if [ ! -d "$CERT_DIR" ]; then
        mkdir -p "$CERT_DIR"
        print_success "Created $CERT_DIR directory"
    fi
    
    # Generate private key and certificate
    print_info "Generating private key and self-signed certificate..."
    
    openssl req -x509 -newkey rsa:4096 -sha256 -days $DAYS_VALID \
        -nodes -keyout "$CERT_DIR/aspnetapp.key" -out "$CERT_DIR/aspnetapp.crt" \
        -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=DNS:$DOMAIN,DNS:www.$DOMAIN,DNS:*.${DOMAIN},IP:127.0.0.1" \
        2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Generated certificate and private key"
    else
        print_error "Failed to generate certificate"
        exit 1
    fi
    
    # Convert to PFX format (required by ASP.NET Core)
    print_info "Converting to PFX format..."
    
    openssl pkcs12 -export -out "$CERT_FILE" \
        -inkey "$CERT_DIR/aspnetapp.key" \
        -in "$CERT_DIR/aspnetapp.crt" \
        -password "pass:$PASSWORD" \
        2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Created PFX certificate: $CERT_FILE"
    else
        print_error "Failed to create PFX certificate"
        exit 1
    fi
    
    # Clean up intermediate files
    rm -f "$CERT_DIR/aspnetapp.key" "$CERT_DIR/aspnetapp.crt"
    
    echo ""
    echo "============================================================================"
    print_success "Certificate generated successfully!"
    echo "============================================================================"
    echo ""
    echo "Certificate details:"
    echo "  File: $CERT_FILE"
    echo "  Domain: $DOMAIN"
    echo "  Password: $PASSWORD"
    echo "  Valid for: $DAYS_VALID days"
    echo ""
    echo "⚠️  WARNING: This is a SELF-SIGNED certificate for DEVELOPMENT ONLY"
    echo ""
    echo "Usage:"
    echo "  1. Update .env file with certificate password:"
    echo "     CERT_PASSWORD=$PASSWORD"
    echo ""
    echo "  2. Mount certificate in docker-compose.yml (already configured by default)"
    echo ""
    echo "  3. Trust the certificate (optional for development):"
    echo "     - macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CERT_FILE"
    echo "     - Windows: Import to Trusted Root Certification Authorities store"
    echo "     - Linux: sudo cp $CERT_DIR/aspnetapp.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
    echo ""
    echo "For production:"
    echo "  - Obtain certificate from trusted CA (Let's Encrypt, DigiCert, etc.)"
    echo "  - Replace $CERT_FILE with your production certificate"
    echo "  - Update CERT_PASSWORD in .env with production certificate password"
    echo ""
}

# Run main function
main "$@"
