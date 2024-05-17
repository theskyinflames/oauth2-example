//go:build go1.18
// +build go1.18

// main package is the entry point for the application.
package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt/v4"
	jwtx "github.com/labstack/echo-jwt"
	"github.com/labstack/echo/v4"
)

// Config contains the configuration for the application
type Config struct {
	ClientID     string
	TenantID     string
	ClientSecret string
	RedirectURI  string
	AuthURL      string
}

var config = Config{
	ClientID:     "YOUR_CLIENT_ID",
	TenantID:     "YOUR_TENANT_ID",
	ClientSecret: "YOUR_CLIENT_SECRET",
	RedirectURI:  "http://localhost:8080/callback",
	AuthURL:      "https://login.microsoftonline.com/YOUR_TENANT_ID/oauth2/v2.0/authorize",
}

// CustomClaims contains the custom claims for the JWT token
type CustomClaims struct {
	jwt.StandardClaims
}

func main() {
	e := echo.New()

	// Load RSA public key from PEM file
	rsaPublicKey := loadRSAPublicKey("path/to/your/public_key.pem")

	// JWT middleware configuration
	jwtConfig := jwtx.Config{
		SigningKey: rsaPublicKey,
		ParseTokenFunc: func(_ echo.Context, auth string) (interface{}, error) {
			token, err := jwt.ParseWithClaims(auth, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, echo.ErrUnauthorized
				}
				return rsaPublicKey, nil
			})
			if err != nil {
				return nil, err
			}
			return token, nil
		},
		ErrorHandler: func(c echo.Context, _ error) error {
			// redirect to Azure AD login page and then to come back to callback endpoint
			return c.Redirect(
				http.StatusFound,
				fmt.Sprintf(
					"%s?client_id=%s&response_type=code&redirect_uri=%s",
					config.AuthURL,
					config.ClientID,
					config.RedirectURI))
		},
	}

	e.Use(jwtx.WithConfig(
		jwtConfig,
	))

	// Routes
	e.GET("/secure", secureEndpoint(rsaPublicKey))
	e.GET("/callback", callbackFunc(rsaPublicKey))

	e.Logger.Fatal(e.Start(":8080"))
}

func secureEndpoint(rsaPublicKey *rsa.PublicKey) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*CustomClaims)

		// Create new customized JWT
		newClaims := CustomClaims{
			StandardClaims: jwt.StandardClaims{
				Subject:   claims.Subject,
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, newClaims)
		signedToken, err := token.SignedString(rsaPublicKey)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to sign token"})
		}

		// Set the JWT as a cookie
		cookie := &http.Cookie{
			Name:     "jwt",
			Value:    signedToken,
			Path:     "/",
			Expires:  time.Now().Add(1 * time.Hour),
			HttpOnly: true,
		}
		c.SetCookie(cookie)

		return c.JSON(http.StatusOK, map[string]string{
			"message": "You are authenticated",
			"user":    claims.Subject,
		})
	}
}

func callbackFunc(rsaPublicKey *rsa.PublicKey) echo.HandlerFunc {
	return func(c echo.Context) error {
		code := c.QueryParam("code")
		if code == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization code not found"})
		}

		cred, err := azidentity.NewClientSecretCredential(config.TenantID, config.ClientID, config.ClientSecret, nil)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create credential"})
		}

		tokenReq := policy.TokenRequestOptions{
			Scopes: []string{"https://graph.microsoft.com/.default"},
		}

		// Exchange authorization code for tokens
		token, err := cred.GetToken(context.Background(), tokenReq)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get token"})
		}

		parsedToken, err := jwt.ParseWithClaims(token.Token, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, echo.ErrUnauthorized
			}
			return rsaPublicKey, nil
		})
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse token"})
		}

		if claims, ok := parsedToken.Claims.(*CustomClaims); ok && parsedToken.Valid {
			_ = claims
			// Store token and claims in session or database
			// Redirect to secure endpoint
			return c.Redirect(http.StatusFound, "/secure")
		}

		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
	}
}

func loadRSAPublicKey(path string) *rsa.PublicKey {
	keyData, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Failed to load RSA public key: %v", err))
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse RSA public key: %v", err))
	}
	return pubKey
}
