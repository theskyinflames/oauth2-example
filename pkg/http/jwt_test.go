package http

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestExtractRoles(t *testing.T) {
	token := &jwt.Token{
		Claims: jwt.MapClaims{
			"realm_access": map[string]interface{}{
				"roles": []interface{}{"admin", "user"},
			},
		},
	}

	roles := extractRoles(token)

	expectedRoles := []Role{"admin", "user"}
	if !reflect.DeepEqual(roles, expectedRoles) {
		t.Errorf("Roles mismatch. Expected: %v, got: %v", expectedRoles, roles)
	}
}

func TestParseJWT(t *testing.T) {
	tokenString := `eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4WGhtVjFXSUxjSWZmank5MXF1cHlzSENjTG5fdmZHdDQ5ZThJYU84UnZZIn0.eyJleHAiOjE3MTYyODI3MjUsImlhdCI6MTcxNjI4MjQyNSwiYXV0aF90aW1lIjoxNzE2MjgyNDI1LCJqdGkiOiIwMjllYzhjMy04Zjg0LTRhZmEtYjUyOC1hYjE3ZDFiMzE3YWIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL3Rlc3QtcmVhbG0iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMTZkYTM4YmItNGRkOC00YjUxLTk2YWItYTRiYTRlNjlkMmNmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdC1jbGllbnQiLCJzZXNzaW9uX3N0YXRlIjoiYjI1NWUzZTktNTNhYy00NjI2LWE1YjktMDRhOGY1YTFhZDYzIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjkwMDAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdGVzdC1yZWFsbSIsInRlc3Qtcm9sZSIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJzaWQiOiJiMjU1ZTNlOS01M2FjLTQ2MjYtYTViOS0wNGE4ZjVhMWFkNjMiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6ImphcnVzLWZuIGphcnVzLWxuIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiamFydXMiLCJnaXZlbl9uYW1lIjoiamFydXMtZm4iLCJmYW1pbHlfbmFtZSI6ImphcnVzLWxuIiwiZW1haWwiOiJqYXJ1c0ByYW5kb20uY29tIn0.iq9ySIfrjRT4nOidh6DMZ92CRRw05Q6ULEUZJ67-ezvOEy8KkBgZoyzAbmft1a9_rtueKZ_eagFf3h0KhH58Y3c_LYyv5ZoyZLVtRQkwUaDLxaHlgIXcDERmP8ExEkO27sS1xb7B9cJqOgb_UMIzozJizBKaY5bHpv9IeLE2H9Knv8Gfxrhig7CwnKJZ5-gY_D01iHG3XZNHQ7MJ9kXGimJTH0ShE6I6fm-TVdw1qXtsF-5US1AzodG78gXH_qIXD451GLEgyDbRbMMsAZ8_c8nHyF0wjaqeFZ1XfXy_866uybywHHBzEpItWNoD4NfmB5iuMKWZ34Gp2ufwoHh35g`

	// The modulus and exponent from your string
	modulus := "30176484511129316794492919331950187333128713731141506726370984597716245190388967624575034677666383583376724744986886277689300742984109090139132677294109175281424311040834385081903753790246764846134967796361810871500130965133668043588558396336259228489844726735370903723408446176426203309681134232442375101372165581620346032689518349485385913905189964737710741132321203542067549407527614070997604799075907674008566865348516459398845028015307690233081282874378176189490350580214614175296399686253163146493836355326946298788553452555705594705324548891622489240247693974474562521298929107481363656697715648359824368267841"
	exponent := 65537

	// Convert the modulus to a big.Int
	N := new(big.Int)
	N.SetString(modulus, 10)

	// Create the rsa.PublicKey
	pubKey := &rsa.PublicKey{
		N: N,
		E: exponent,
	}
	rsaPublicKeys := []*rsa.PublicKey{
		pubKey,
	}

	// Create a new token object
	token := jwt.New(jwt.SigningMethodRS256)

	// Set some claims
	token.Claims = jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Now().Unix(),
	}

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(pubKey)
	if err != nil {
		fmt.Println("Error signing token: ", err)
		return
	}

	parsedToken, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return rsaPublicKeys[0], nil
	})
	if err != nil {
		t.Errorf("Failed to parse JWT: %v", err)
	}

	if parsedToken == nil {
		t.Error("Token is nil")
	}

	if !parsedToken.Valid {
		t.Error("Token is invalid")
	}
}
