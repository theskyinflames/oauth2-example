
lint:
	golangci-lint run ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

run-oauth2:
	docker run -p 8080:8080 --name keycloak -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev

shutdown-oauth2:
	docker stop keycloak
	docker rm keycloak

create-realm:
	cd ./script && ./create-realm.sh

run-api:
	./script/run-api.sh

