package http

import (
	"crypto/rsa" // Add missing import statement
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt"

	"theskyinflames/oauth2-example/pkg/fixtures" // Add missing import statement
)

func TestExtractRoles(t *testing.T) {
	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin", "user"},
			},
		},
	}

	roles := extractRoles(token)

	expectedRoles := []Role{"admin", "user"}
	if !reflect.DeepEqual(roles, expectedRoles) {
		t.Fatalf("Roles mismatch. Expected: %v, got: %v", expectedRoles, roles)
	}
}

func TestParseJWT(t *testing.T) {
	// Generate RSA keys pair
	privKey, pubKey, err := fixtures.RSAKeysPairFixture()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys pair: %v", err)
	}

	// Generate a signed JWT token
	tokenString, err := fixtures.TokenFixture(privKey)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Parse the token
	parsedToken, _, err := parseJWT(tokenString, []*rsa.PublicKey{pubKey})
	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	if parsedToken == nil {
		t.Fatalf("Token is nil")
	}

	if !parsedToken.Valid {
		t.Fatalf("Token is invalid")
	}
}

func TestConvertOAuth2TokenToJWT(t *testing.T) {
	// Generate RSA keys pair
	privKey, _, err := fixtures.RSAKeysPairFixture()
	if err != nil {
		t.Fatalf("Failed to generate RSA keys pair: %v", err)
	}

	// Generate a signed JWT token
	accessToken, err := fixtures.TokenFixture(privKey)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Generate an OAuth2 token with a JWT access token
	oauth2Token := fixtures.OAuth2TokenFixture(accessToken)

	gotToken, err := convertOAuth2TokenToJWT(oauth2Token)
	if err != nil {
		t.Fatalf("Failed to convert OAuth2 token to JWT: %v", err)
	}

	if !reflect.DeepEqual(gotToken.Raw, accessToken) {
		t.Fatalf("Converted token mismatch. Expected: %v, got: %v", accessToken, gotToken.Raw)
	}
}
