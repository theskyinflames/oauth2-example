
lint:
	@golangci-lint run ./...

test:
	@go test ./...

test-coverage:
	@go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out

run:
	@cd script && ./run.sh

shutdown-oauth2:
	@docker stop keycloak
	@docker rm keycloak


