package fixtures

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
)

// OAuth2TokenFixture returns an OAuth2 token with the given access token for testing purposes
func OAuth2TokenFixture(token string) *oauth2.Token {
	oauth2Token := &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
	}

	return oauth2Token
}

// RSAKeysPairFixture returns a pair of RSA keys for testing purposes
func RSAKeysPairFixture() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate RSA private key: %v", err)
	}

	return privateKey, &privateKey.PublicKey, nil
}

// TokenFixture returns a signed JWT token string for testing purposes
func TokenFixture(privKey *rsa.PrivateKey) (string, error) {
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
		return "", fmt.Errorf("Failed to sign the token: %v", err)
	}

	return tokenString, nil
}
