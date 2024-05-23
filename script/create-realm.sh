#!/bin/bash

set -e

# Function to run kcadm.sh inside the Docker container
kcadm() {
    docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kcadm.sh "$@"
}

kc() {
    docker exec $KEYCLOAK_CONTAINER /opt/keycloak/bin/kc.sh "$@"
}

# Waiting for Keycloak to start for a maximum of 30 seconds
echo "Waiting for Keycloak to start, please be patient..."
for i in {1..30}; do
    if docker logs $KEYCLOAK_CONTAINER 2>&1 | grep -q "Admin console listening"; then
        break
    fi
    sleep 1
done

# Check if the Keycloak container is running
if ! docker ps | grep -q $KEYCLOAK_CONTAINER; then
    echo "Keycloak container is not running."
    exit 1
fi

# Log in to Keycloak
echo "Logging in to Keycloak..."
kcadm config credentials --server $KEYCLOAK_URL --realm $KEYCLOAK_REALM --user $ADMIN_USERNAME --password $ADMIN_PASSWORD

# Create a new realm
echo "Creating realm $KEYCLOAK_NEW_REALM..."
kcadm create realms -s realm=$KEYCLOAK_NEW_REALM -s enabled=true 

# Check if the realm exists
if kcadm get realms/$KEYCLOAK_NEW_REALM; then
    echo "Realm $KEYCLOAK_NEW_REALM created successfully."
else
    echo "Failed to create realm $KEYCLOAK_NEW_REALM."
    exit 1
fi

# Create a confidential client on the realm using jwks url
echo "Creating confidential client on realm $KEYCLOAK_NEW_REALM..."
kcadm create clients -r $KEYCLOAK_NEW_REALM \
    -s "clientId=$CLIENT_ID" \
    -s "secret=$CLIENT_SECRET" \
    -s 'enabled=true' \
    -s "redirectUris=[\"$REDIRECT_URI\"]" \
    -s "webOrigins=[\"$WEB_ORIGINS\"]" \
    -s 'publicClient=false' \
    -s 'protocol=openid-connect' \
    -s 'bearerOnly=false' \
    -s 'serviceAccountsEnabled=true' \
    -s 'authorizationServicesEnabled=true' \



# Retrieve the client ID
CLIENT_UUID=$(kcadm get clients -r $KEYCLOAK_NEW_REALM -q clientId=$CLIENT_ID | jq -r '.[0].id')

# Update the client to use JWKS URL
kcadm update clients/$CLIENT_UUID -r $KEYCLOAK_NEW_REALM \
    -s 'attributes.jwksUrl='"$JWKS_URL" \
    -s 'attributes.useJwksUrl=true' \

echo "Client '$CLIENT_ID' updated to use JWKS URL '$JWKS_URL' in realm '$KEYCLOAK_NEW_REALM'."

# Create a user on the realm with username jarus and password jarus and email jarus@jarus.com and email verified
echo "Creating user on realm $KEYCLOAK_NEW_REALM..."
kcadm create users -r $KEYCLOAK_NEW_REALM -s username=jarus -s enabled=true -s email=jarus@jarus.com -s emailVerified=true
kcadm set-password -r $KEYCLOAK_NEW_REALM --username jarus --new-password jarus
