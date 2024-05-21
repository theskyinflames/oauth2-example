package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"theskyinflames/oauth2-example/pkg/fixtures"
	httpx "theskyinflames/oauth2-example/pkg/http"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestLoginHandler(t *testing.T) {
	// Create a new Echo instance
	e := echo.New()

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	// Create a new HTTP response recorder
	rec := httptest.NewRecorder()

	// Create an Echo context
	c := e.NewContext(req, rec)

	// Call the LoginHandler function
	err := httpx.LoginHandler(httpx.OAuthConfig(
		"test-client",
		"EPgv2q0H2fjG1VlHfrVkk5sVQPxLVzOW",
		"http://localhost:8080/realms/test-realm/protocol/openid-connect/auth",
		"http://localhost:8080/realms/test-realm/protocol/openid-connect/token"))(c)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check the response status code
	assert.Equal(t, http.StatusPermanentRedirect, rec.Code)

	// Check the redirect URL
	assert.Equal(t,
		"http://localhost:8080/realms/test-realm/protocol/openid-connect/auth?access_type=offline&client_id=test-client&response_type=code&state=state",
		rec.Header().Get("Location"),
	)
}

func TestCallbackHandler(t *testing.T) {
	// Create the callback handler
	callbackHandler := httpx.CallbackHandler(
		httpx.OAuthConfigExchangeFunc(
			func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
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
				return oauth2Token, nil
			},
		),
	)

	// Create a new Echo instance
	e := echo.New()

	// Create a new HTTP request
	req := httptest.NewRequest(http.MethodGet, "/callback?code=123", nil)

	// Create a new HTTP response recorder
	rec := httptest.NewRecorder()

	// Create an Echo context
	c := e.NewContext(req, rec)

	// Call the CallbackHandler function
	err := callbackHandler(c)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check the response status code
	assert.Equal(t, http.StatusFound, rec.Code)

	// Check for the auth cookie
	cookie := rec.Result().Cookies()[0]
	assert.Equal(t, "my-auth-cookie", cookie.Name)
}
