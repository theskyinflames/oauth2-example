package http

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt"
)

// parseJWT parses the JWT token and returns the token if it is valid along with the roles of the user
func parseJWT(receivedToken string, rsaPublicKey []*rsa.PublicKey) (*jwt.Token, []Role, error) {
	// Parse the token
	var (
		token *jwt.Token
		err   error
	)
	for _, pk := range rsaPublicKey {
		token, err = jwt.Parse(receivedToken, func(token *jwt.Token) (interface{}, error) {
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
		return nil, nil, err
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("token is invalid")
	}

	return token, extractRoles(token), nil
}

// Role represents the role of a user
type Role string

const rolesClaimKey = "realm_access"

// extractRoles extracts the roles from the JWT token and returns them as a list of strings
func extractRoles(token *jwt.Token) []Role {
	// Extract the claims from the token
	tokenRoles := token.Claims.(jwt.MapClaims)[rolesClaimKey].(map[string]interface{})["roles"].([]interface{})
	roles := make([]Role, len(tokenRoles))
	for i, v := range tokenRoles {
		roles[i] = Role(fmt.Sprintf("%s", v))
	}
	return roles
}
