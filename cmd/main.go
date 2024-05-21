package main

import (
	"fmt"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	httpx "theskyinflames/oauth2-example/pkg/http"
)

func main() {
	rsaPublicKeys, err := httpx.GetRSAKeys(httpx.GetJWKSet)
	if err != nil {
		fmt.Printf("Failed to get JWKS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Public keys: \n%#v\n", rsaPublicKeys)

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(httpx.AuthMiddleware(rsaPublicKeys))

	// Routes
	e.GET("/protected", httpx.ProtectedHandler)
	e.GET("/login", httpx.LoginHandler)
	e.GET("/callback", httpx.CallbackHandler(httpx.OAuthConfig.Exchange))

	// Start server
	e.Logger.Fatal(e.Start(":9000"))
}
