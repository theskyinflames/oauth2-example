package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
)

var oauthConfig = &oauth2.Config{
	ClientID:     "test-client",
	ClientSecret: "SHDxwMGfD5QOUU3ryde1a4s55TRZEZ8Z",
	// RedirectURL:  "http://localhost:9000/callback",
	// Scopes: []string{"openid", "profile", "email"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "http://localhost:8080/realms/test-realm/protocol/openid-connect/auth",
		TokenURL: "http://localhost:8080/realms/test-realm/protocol/openid-connect/token",
	},
}

var rsaPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0QO/496zLiPYuCG5Rsk63jDvp2hYv0UKP2zRgvs0GCUcUDW3Zg9gVUvrL89FNR17lmMOSZ53fqQtKkYNGGWlyjBZZdCa2RNLQgasKhtzY2HRcO2fPGcazYp9l0hQd738s4KafsPIY0INVX1qgppQVSS4wDI1BWXAfg42wt/0bsuQmU/LgY4vJ9vCNZj7c2VUegU+B0y+BC8M4XblL7fbAiVBEqY5K04Ook/Btw0fUjcNn50HLDlax9LCuDZUSR2kjKWbJWImNT6ZT7HdwF5pN74hsdwQ8BTCbLqQNYia7UX99DQC9QaNZn7X2StCWnm/zAmHffS9nDSpSL1hHFebqQIDAQAB"

const authCookieName = "KEYCLOAK_IDENTITY"

// CustomClaims contains the custom claims for the JWT token
type CustomClaims struct {
	jwt.StandardClaims
}

func middlewareLogging(next echo.HandlerFunc) echo.HandlerFunc {
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
		//userClaims := CustomClaims{}
		//_, err = jwt.ParseWithClaims(token, &userClaims, func(token *jwt.Token) (interface{}, error) {
		//	c.Logger().Error("Token method: %v", token.Method)
		//	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		//		return nil, echo.ErrUnauthorized
		//	}
		//	return rsaPublicKey, nil
		//})
		//if err != nil {
		//	c.Logger().Errorf("Failed to parse token: %v", err)
		//	return c.Redirect(http.StatusTemporaryRedirect, "/login")
		//}

		// Return the next handler
		return next(c)
	}
}

func protectedHandler(c echo.Context) error {
	// try to get the token from the context
	//token := c.Get("user")
	//if token == nil {
	//	return c.Redirect(http.StatusTemporaryRedirect, "/login")
	//}

	msg := ""
	cookies := c.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == authCookieName {
			msg = cookie.Value
		}
	}

	return c.String(http.StatusOK, fmt.Sprintf("Protected endpoint: %s", msg))
}

func loginHandler(c echo.Context) error {
	url := oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func callbackHandler(c echo.Context) error {
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

	return c.Redirect(http.StatusPermanentRedirect, "/protected")
	// return c.String(http.StatusOK, token.AccessToken)
}

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middlewareLogging)

	// Routes
	e.GET("/protected", protectedHandler)
	e.GET("/login", loginHandler)
	e.GET("/callback", callbackHandler)

	// Start server
	e.Logger.Fatal(e.Start(":9000"))
}
