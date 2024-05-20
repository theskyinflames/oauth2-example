package http

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

var oauthConfig = &oauth2.Config{
	ClientID:     "test-client",
	ClientSecret: "EPgv2q0H2fjG1VlHfrVkk5sVQPxLVzOW",
	// RedirectURL:  "http://localhost:9000/callback",
	// Scopes: []string{"openid", "profile", "email"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:8080/realms/test-realm/protocol/openid-connect/auth",
		TokenURL: "http://localhost:8080/realms/test-realm/protocol/openid-connect/token",
	},
}

const (
	authCookieName = "my-auth-cookie" // Name of the cookie to store the token
)

// AuthMiddleware is a middleware to check if the user is authenticated
func AuthMiddleware(rsaPublicKey []*rsa.PublicKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Avoid infinite redirect loop
			if c.Path() == "/login" || c.Path() == "/callback" {
				return next(c)
			}

			// look for the token in the cookie
			cookie, err := c.Cookie(authCookieName)
			if err != nil {
				c.Logger().Errorf("Failed to get cookie: %v", err)
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			// get the token from the cookie
			token := cookie.Value
			if token == "" {
				c.Logger().Error("Token not found")
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			// parse the token
			_, roles, err := parseJWT(token, rsaPublicKey)
			if err != nil {
				c.Logger().Errorf("Failed to parse token: %v", err)
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			// TODO: Check if the user has the required roles
			for _, role := range roles {
				fmt.Printf("Role: %s\n", role)
			}
			_ = roles

			// Return the next handler
			return next(c)
		}
	}
}

// LoginHandler is the handler for the login page
func LoginHandler(c echo.Context) error {
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	return c.Redirect(http.StatusPermanentRedirect, url)
}

// CallbackHandler is the handler for the callback page
func CallbackHandler(c echo.Context) error {
	code := c.QueryParam("code")
	if code == "" {
		return c.String(http.StatusBadRequest, "Code not found")
	}

	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to exchange token: %v", err))
	}

	c.SetCookie(&http.Cookie{
		Name:  authCookieName,
		Value: token.AccessToken,
	})

	return c.Redirect(http.StatusFound, "/protected")
}
