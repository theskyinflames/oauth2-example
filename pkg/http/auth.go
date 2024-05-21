package http

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

// OAuthConfig is the OAuth2 configuration
var OAuthConfig = &oauth2.Config{
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

			// parse the token received in the auth cookie
			_, roles, err := ParseJWT(token, rsaPublicKey)
			if err != nil {
				c.Logger().Errorf("Failed to parse token: %v", err)
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}

			// TODO: Check if the user has the required roles to access the resource
			for _, role := range roles {
				fmt.Printf("Role: %s\n", role)
			}

			_ = roles

			// Return the next handler
			return next(c)
		}
	}
}

// OAuthConfigExchangeFunc is a function to exchange the OAuth2 code for a token
type OAuthConfigExchangeFunc func(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)

// LoginHandler is the handler for the login page
func LoginHandler(c echo.Context) error {
	url := OAuthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	return c.Redirect(http.StatusPermanentRedirect, url)
}

// CallbackHandler is a decorator for the callback handler
func CallbackHandler(f OAuthConfigExchangeFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		code := c.QueryParam("code")
		if code == "" {
			return c.String(http.StatusBadRequest, "Code not found")
		}

		// iamToken, err := oauthConfig.Exchange(context.Background(), code)
		iamToken, err := f(context.Background(), code)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to exchange token: %v", err))
		}
		accessToken, err := ConvertOAuth2TokenToJWT(iamToken)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to convert token: %v", err))
		}

		// Extract the roles from the token
		roles := ExtractRoles(accessToken)

		// Create a new token
		newToken := NewCustomToken(accessToken, roles)

		fmt.Printf("New token: %v\n", newToken.Raw)

		// Set the auth cookie with the new token
		c.SetCookie(&http.Cookie{
			Name:  authCookieName,
			Value: accessToken.Raw,
		})

		for _, role := range roles {
			fmt.Printf("Role: %s\n", role)
		}

		return c.Redirect(http.StatusFound, "/protected")
	}
}
