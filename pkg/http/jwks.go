package http

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
)

// jwksURI is the URL of the JWK for the client the IAM server is configured with.
const jwksURI = "http://localhost:8080/realms/test-realm/protocol/openid-connect/certs"

type getJWKSetFunc func(url string) (map[string]*rsa.PublicKey, error)

// GetRSAKeys retrieves the RSA public keys from the JWK set and returns a slice of *rsa.PublicKey.
func GetRSAKeys(f getJWKSetFunc) ([]*rsa.PublicKey, error) {
	rsaPublicKeys, err := f(jwksURI)
	if err != nil {
		fmt.Printf("Failed to get JWK set: %v\n", err)
		os.Exit(1)
	}
	var pks []*rsa.PublicKey
	for _, v := range rsaPublicKeys {
		pks = append(pks, v)
	}

	return pks, nil
}

// GetJWKSet retrieves the JWK set from the specified URL and returns a map of RSA public keys.
func GetJWKSet(url string) (map[string]*rsa.PublicKey, error) {
	// Make the GET request
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error making GET request: %v", err)
	}
	defer response.Body.Close()

	// Decode the JSON response
	var jwkSet struct {
		Keys []struct {
			Kid string   `json:"kid"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5C []string `json:"x5c"`
		} `json:"keys"`
	}

	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&jwkSet); err != nil {
		return nil, fmt.Errorf("Error decoding JSON: %v", err)
	}

	// Create a map to store RSA public keys
	jwkMap := make(map[string]*rsa.PublicKey)

	// Iterate through each key in the JWK set
	for _, key := range jwkSet.Keys {
		// Decode base64url-encoded modulus (N) and exponent (E)
		modulus, err := DecodeBase64URL(key.N)
		if err != nil {
			return nil, fmt.Errorf("Error decoding modulus: %v", err)
		}

		exponent, err := DecodeBase64URL(key.E)
		if err != nil {
			return nil, fmt.Errorf("Error decoding exponent: %v", err)
		}

		// Create RSA public key
		pubKey := &rsa.PublicKey{
			N: modulus,
			E: int(exponent.Int64()),
		}

		// Store the public key in the map using the key ID (Kid)
		jwkMap[key.Kid] = pubKey
	}

	return jwkMap, nil
}

// DecodeBase64URL decodes a base64url-encoded string and returns a big.Int
func DecodeBase64URL(input string) (*big.Int, error) {
	// Convert base64url to base64
	base64Str := strings.ReplaceAll(input, "-", "+")
	base64Str = strings.ReplaceAll(base64Str, "_", "/")

	// Pad the base64 string with "="
	switch len(base64Str) % 4 {
	case 2:
		base64Str += "=="
	case 3:
		base64Str += "="
	}

	// Decode base64 string
	data, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, err
	}

	// Convert bytes to big.Int
	result := new(big.Int).SetBytes(data)
	return result, nil
}
