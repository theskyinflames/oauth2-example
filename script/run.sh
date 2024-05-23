#!/bin/bash

# Set environment variables
export CLIENT_ID='test-client'
export CLIENT_SECRET='EPgv2q0H2fjG1VlHfrVkk5sVQPxLVzOW'

export AUTH_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/auth'
export TOKEN_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/token'

export KEYCLOAK_REALM="master"
export KEYCLOAK_NEW_REALM="test-realm"
export KEYCLOAK_CONTAINER="keycloak"
export KEYCLOAK_URL="http://localhost:8080"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="admin"
export JWKS_URL="http://localhost:8070/realms/test-realm/protocol/openid-connect/certs"
export REDIRECT_URI="http://localhost:9000/callback"
export WEB_ORIGIN="http://localhost:9000"

# Start Keycloak container
docker run -p 8080:8080 -d --name keycloak -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:24.0.1 start-dev

# Wait for Keycloak to start and create the realm 
./create-realm.sh

# Run the application
./run-api.sh