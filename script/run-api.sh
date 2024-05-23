#!/bin/bash

# Set environment variables
export CLIENT_ID='test-client'
export CLIENT_SECRET='EPgv2q0H2fjG1VlHfrVkk5sVQPxLVzOW'

export AUTH_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/auth'
export TOKEN_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/token'

# Check if the Keycloak container is running and the realm exists
if ! docker ps | grep -q keycloak; then
    echo "Keycloak container is not running."
    exit 1
fi

if ! docker exec keycloak /opt/keycloak/bin/kcadm.sh get realms/test-realm; then
    echo "Realm test-realm does not exist."
    exit 1
fi

# Run the application
go run ../cmd/main.go
