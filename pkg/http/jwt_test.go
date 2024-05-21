package http_test

import (
	"crypto/rand"
	"crypto/rsa" // Add missing import statement
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"

	httpx "theskyinflames/oauth2-example/pkg/http"
)

func TestExtractRoles(t *testing.T) {
	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin", "user"},
			},
		},
	}

	roles := httpx.ExtractRoles(token)

	expectedRoles := []httpx.Role{"admin", "user"}
	if !reflect.DeepEqual(roles, expectedRoles) {
		t.Fatalf("Roles mismatch. Expected: %v, got: %v", expectedRoles, roles)
	}
}

func rsaKeysPairFixture(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA private key: %v", err)
	}

	return privateKey, &privateKey.PublicKey
}

// TokenFixtures returns a signed JWT token string for testing purposes
func tokenFixture(t *testing.T, privKey *rsa.PrivateKey) string {
	claims := jwt.MapClaims{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "user"},
		},
		"exp":                time.Now().Add(1 * time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"aud":                "account",
		"iss":                "http://localhost:8080/realms/test-realm",
		"sub":                "16da38bb-4dd8-4b51-96ab-a4ba4e69d2cf",
		"typ":                "Bearer",
		"azp":                "test-client",
		"session_state":      "b255e3e9-53ac-4626-a5b9-04a8f5a1ad63",
		"acr":                "1",
		"allowed-origins":    []interface{}{"http://localhost:9000"},
		"scope":              "email profile",
		"email_verified":     true,
		"name":               "jarus-fn jarus-ln",
		"preferred_username": "jarus",
		"given_name":         "jarus-fn",
		"family_name":        "jarus-ln",
		"email":              "jaume@jaume.com",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	return tokenString
}

func TestParseJWT(t *testing.T) {
	// Generate RSA keys pair
	privKey, pubKey := rsaKeysPairFixture(t)

	// Generate a signed JWT token
	tokenString := tokenFixture(t, privKey)

	// Parse the token
	parsedToken, _, err := httpx.ParseJWT(tokenString, []*rsa.PublicKey{pubKey})
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

// Generate an oauth2.Token with a provided JWT access token
func oauth2TokenFixture(_ *testing.T, token string) *oauth2.Token {
	oauth2Token := &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	}

	return oauth2Token
}

func TestConvertOAuth2TokenToJWT(t *testing.T) {
	// Generate RSA keys pair
	privKey, _ := rsaKeysPairFixture(t)

	// Generate a signed JWT token
	accessToken := tokenFixture(t, privKey)

	// Generate an OAuth2 token with a JWT access token
	oauth2Token := oauth2TokenFixture(t, accessToken)

	gotToken, err := httpx.ConvertOAuth2TokenToJWT(oauth2Token)
	if err != nil {
		t.Fatalf("Failed to convert OAuth2 token to JWT: %v", err)
	}

	if !reflect.DeepEqual(gotToken.Raw, accessToken) {
		t.Fatalf("Converted token mismatch. Expected: %v, got: %v", accessToken, gotToken.Raw)
	}
}
