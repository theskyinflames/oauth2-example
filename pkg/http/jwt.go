package http

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
)

type (
	// Role represents the role of a user
	Role string

	// Email represents the email of a user
	Email string
)

func (e Email) String() string {
	return string(e)
}

const rolesClaimKey = "realm_access"

// extractRoles extracts the roles from the JWT token and returns them as a list of strings
func extractRoles(token *jwt.Token) (Email, []Role) {
	// Extract the claims from the token
	tokenRoles := token.Claims.(jwt.MapClaims)[rolesClaimKey].(map[string]interface{})["roles"].([]interface{})
	roles := make([]Role, len(tokenRoles))
	for i, v := range tokenRoles {
		roles[i] = Role(fmt.Sprintf("%s", v))
	}

	// Extract the email from the token
	email := Email(token.Claims.(jwt.MapClaims)["email"].(string))

	return email, roles
}

// KeyFunc returns a jwt.Keyfunc that can be used to parse the JWT token
var KeyFunc = func(pk *rsa.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token's algorithm corresponds to RS256
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pk, nil
	}
}

// parseJWT parses the JWT token and returns the token if it is valid along with the roles of the user
func parseJWT(receivedToken string, rsaPublicKey []*rsa.PublicKey) (*jwt.Token, Email, []Role, error) {
	// Parse the token
	var (
		token *jwt.Token
		err   error
	)
	for _, pk := range rsaPublicKey {
		token, err = jwt.Parse(receivedToken, KeyFunc(pk))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, "", nil, err
	}

	if !token.Valid {
		return nil, "", nil, fmt.Errorf("token is invalid")
	}

	email, roles := extractRoles(token)

	return token, email, roles, nil
}

var _ jwt.Claims = &CustomToken{}

// CustomToken represents a custom token with additional fields
type CustomToken struct {
	jwt.Claims
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Roles     []Role    `json:"roles"`
	ExpiresAt time.Time `json:"exp"`
}

// NewCustomToken creates a new *jwt.Token from the given JWT token
func NewCustomToken(token *jwt.Token, email Email, roles []Role) *jwt.Token {
	expiresAt := time.Unix(int64(token.Claims.(jwt.MapClaims)["exp"].(float64)), 0)
	fmt.Printf("Expires at: %v\n", expiresAt)
	return &jwt.Token{
		Header: token.Header,
		Claims: &CustomToken{
			Claims:    token.Claims,
			Username:  email.String(),
			Email:     email.String(),
			Roles:     roles,
			ExpiresAt: expiresAt,
		},
		Method: token.Method,
		Valid:  token.Valid,
	}
}

// convertOAuth2TokenToJWT converts an OAuth2 token to a JWT token
func convertOAuth2TokenToJWT(oauth2Token *oauth2.Token) (*jwt.Token, error) {
	// Extract the access token, which we assume to be a JWT
	accessToken := oauth2Token.AccessToken

	// Parse the access token to convert it into a jwt.Token
	token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	return token, nil
}
