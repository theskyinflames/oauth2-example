package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	//"github.com/golang-jwt/jwt/v5"
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

// var rsaPublicKey = convertPublicKey("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA85GAs21dL31GhcWzx2efsMqrVbajBCWg7g+afVS6ntZWBC8p+fig3KaxQCjETS+I9ZemKxj2jT4qJ/JS3uSN7lCX7NK8t8w2Ib/1vbLaOnHglNiiQWx3Qj3XW17/yCy9PLuvHgoA53lRpNst859n8/QIJ+PyJnzWzJM6UmeiZNQxibGUjUlAQi+8WqOcT/ao7RdLhyJlUy4eqGoWBKjz41FbqzOr9pHuw1t6qCyd9MAuYMZCpYFCkVwqGg090aBjOyI3gBDZGOWffPJSS+7pLDKXN3nbDvaD7HNr2+7Y4/p5ABi+XraRLvZZuJmkMCjMyXqfEvR8HF+U+mUeJ5IutQIDAQAB")
var rsaPublicKey = "MIICozCCAYsCBgGPlOdYEDANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAp0ZXN0LXJlYWxtMB4XDTI0MDUyMDA3MjcyMFoXDTM0MDUyMDA3MjkwMFowFTETMBEGA1UEAwwKdGVzdC1yZWFsbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPORgLNtXS99RoXFs8dnn7DKq1W2owQloO4Pmn1Uup7WVgQvKfn4oNymsUAoxE0viPWXpisY9o0+KifyUt7kje5Ql+zSvLfMNiG/9b2y2jpx4JTYokFsd0I911te/8gsvTy7rx4KAOd5UaTbLfOfZ/P0CCfj8iZ81syTOlJnomTUMYmxlI1JQEIvvFqjnE/2qO0XS4ciZVMuHqhqFgSo8+NRW6szq/aR7sNbeqgsnfTALmDGQqWBQpFcKhoNPdGgYzsiN4AQ2Rjln3zyUkvu6Swylzd52w72g+xza9vu2OP6eQAYvl62kS72WbiZpDAozMl6nxL0fBxflPplHieSLrUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAdu4tyEPX3yGq+Fwoui4tNAgXML+89AHus+ad+Gdy6pbQ+edgpZaoZ2AMOo4xZU2OPF4wbXU13p0aw9QqO38W6MFFMxXMFoYHJ6abnDPnhXjhsLA1D0t7hRg2Mth5gkeQoCb/qmpmDKVHxmzj+OP5cXCMX/7rPG16YR697SvOgH35/ombe4jdIahYHUPAntsIaM1SxFqeqC5Fmq4vpRGF0IgVuZiLOcSXI6SVQMS4xS9pH27f57cIjkQ1LbVVGdv7UBq54tR6zgikTCPiVcuAVzjKEolBSigVVxI//f0mlZWduXaoHhseru9AUlVbmy0VjBOzAhDAQinKT0oM5Zu5WA=="

const authCookieName = "KEYCLOAK_IDENTITY"

// CustomClaims contains the custom claims for the JWT token
type CustomClaims struct {
	jwt.StandardClaims
}

func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
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
		parsedToken, err := parseJWT(token)
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

func convertPublicKey(text string) string {
	lineLength := 64
	var lines []string
	for i := 0; i < len(text); i += lineLength {
		end := i + lineLength
		if end > len(text) {
			end = len(text)
		}
		lines = append(lines, text[i:end]+"\n")
	}
	return "-----BEGIN PUBLIC KEY-----\n" + strings.Join(lines, "") + "-----END PUBLIC KEY-----\n"
}

func parseJWT(receivedToken string) (*jwt.Token, error) {
	//userClaims := CustomClaims{}
	//_, err = jwt.ParseWithClaims(token, &userClaims, func(token *jwt.Token) (interface{}, error) {
	//	c.Logger().Error("Token method: %v", token.Method)
	//	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
	//		return nil, echo.ErrUnauthorized
	//	}
	//	return rsaPublicKey, nil
	//})

	// Parse the token
	token, err := jwt.Parse(receivedToken, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token's algorithm corresponds to RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// return rsaPublicKey, nil
		return []byte{}, nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return token, nil
}

func main() {
	// fmt.Printf("Public key: \n%s\n", rsaPublicKey)

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(authMiddleware)

	// Routes
	e.GET("/protected", protectedHandler)
	e.GET("/login", loginHandler)
	e.GET("/callback", callbackHandler)

	// Start server
	e.Logger.Fatal(e.Start(":9000"))
}
