package main

import (
	"fmt"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	httpx "theskyinflames/oauth2-example/pkg/http"
)

const (
	dfclientID     = "test-client"
	dfclientSecret = "EPgv2q0H2fjG1VlHfrVkk5sVQPxLVzOW"
	dfauthURL      = "http://localhost:8080/realms/test-realm/protocol/openid-connect/auth"
	dftokenURL     = "http://localhost:8080/realms/test-realm/protocol/openid-connect/token"
)

func main() {
	// Parse the needed parameters to set the OAuth2 configuration from environment variables
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	authURL := os.Getenv("AUTH_URL")
	tokenURL := os.Getenv("TOKEN_URL")

	rsaPublicKeys, err := httpx.GetRSAKeys(httpx.GetJWKSet)
	if err != nil {
		fmt.Printf("Failed to get JWKS: %v\n", err)
		os.Exit(1)
	}

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(httpx.AuthMiddleware(rsaPublicKeys))

	oauthConfig := httpx.OAuthConfig(clientID, clientSecret, authURL, tokenURL)

	// Routes
	e.GET("/protected", httpx.ProtectedHandler)
	e.GET("/login", httpx.LoginHandler(oauthConfig))
	e.GET("/callback", httpx.CallbackHandler(oauthConfig.Exchange))

	// Start server
	e.Logger.Fatal(e.Start(":9000"))
}
