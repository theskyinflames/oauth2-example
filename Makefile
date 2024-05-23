
lint:
	@golangci-lint run ./...

test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

run:
	@cd script && ./run.sh

shutdown-oauth2:
	@docker stop keycloak
	@docker rm keycloak


