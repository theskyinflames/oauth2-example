package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"

	//"github.com/golang-jwt/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
	oauth2CookieName = "KEYCLOAK_IDENTITY"
	authCookieName   = "my-auth-cookie"
)

// Middleware to check if the user is authenticated
func authMiddleware(rsaPublicKey []*rsa.PublicKey) echo.MiddlewareFunc {
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
			parsedToken, err := parseJWT(token, rsaPublicKey)
			fmt.Printf("received token: %v\n", token)
			if err != nil {
				c.Logger().Errorf("Failed to parse token: %v", err)
				return c.Redirect(http.StatusTemporaryRedirect, "/login")
			}
			fmt.Printf("parsedToken: %v\n", parsedToken)

			// Return the next handler
			return next(c)
		}
	}
}

// ----------------- Handlers -----------------

func protectedHandler(c echo.Context) error {
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
	return c.Redirect(http.StatusPermanentRedirect, url)
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

	return c.Redirect(http.StatusFound, "/protected")
}

// ----------------- Helper functions -----------------

// CustomClaims contains the custom claims for the JWT token
//type CustomClaims struct {
//	jwt.RegisteredClaims
//}

func parseJWT(receivedToken string, rsaPublicKey []*rsa.PublicKey) (*jwt.Token, error) {
	// Parse the token
	var (
		// useerClaims = CustomClaims{}
		claims jwt.MapClaims
		token  *jwt.Token
		err    error
	)
	for _, pk := range rsaPublicKey {
		token, err = jwt.ParseWithClaims(receivedToken, claims, func(token *jwt.Token) (interface{}, error) {
			// Make sure that the token's algorithm corresponds to RS256
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return pk, nil
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	// Print the claims
	fmt.Println("Claims:")
	for key, value := range token.Claims.(jwt.MapClaims) {
		fmt.Printf("Key: %v, Value: %v\n", key, value)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return token, nil
}

// ----------------- Main -----------------

func main() {
	rsaPublicKeys, err := GetJWKSet(jwksURI)
	if err != nil {
		fmt.Printf("Failed to get JWK set: %v\n", err)
		os.Exit(1)
	}
	var pks []*rsa.PublicKey
	for _, v := range rsaPublicKeys {
		pks = append(pks, v)
	}
	fmt.Printf("Public keys: \n%#v\n", rsaPublicKeys)

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(authMiddleware(pks))

	// Routes
	e.GET("/protected", protectedHandler)
	e.GET("/login", loginHandler)
	e.GET("/callback", callbackHandler)

	// Start server
	e.Logger.Fatal(e.Start(":9000"))
}
