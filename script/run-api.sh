#!/bin/bash

# Set environment variables
export CLIENT_ID='test-client'
export CLIENT_SECRET='RRrNlBzKzEbpYSCUbSBkwzkiYfcCSSqS'
export AUTH_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/auth'
export TOKEN_URL='http://localhost:8080/realms/test-realm/protocol/openid-connect/token'

# Run the application
go run ./cmd/main.go