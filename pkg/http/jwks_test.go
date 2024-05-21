package http_test

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	httpx "theskyinflames/oauth2-example/pkg/http"
)

func TestDecodeBase64URL(t *testing.T) {
	input := "SGVsbG8gd29ybGQh"
	expectedOutput := big.NewInt(0).SetBytes([]byte("Hello world!"))

	result, err := httpx.DecodeBase64URL(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Cmp(expectedOutput) != 0 {
		t.Fatalf("Expected %v, but got %v", expectedOutput, result)
	}
}

func TestGetJWKSet(t *testing.T) {
	expectedKeys := map[string]*rsa.PublicKey{
		"key1": {
			N: big.NewInt(123),
			E: 65537,
		},
		"key2": {
			N: big.NewInt(456),
			E: 65537,
		},
	}

	// Mock HTTP response
	mockResponse := `{
		"keys": [
			{
				"kid": "key1",
				"n": "ew==",
				"e": "AQAB",
				"x5c": []
			},
			{
				"kid": "key2",
				"n": "Acg=",
				"e": "AQAB",
				"x5c": []
			}
		]
	}`

	// Create a mock HTTP server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, mockResponse)
	}))
	defer mockServer.Close()

	// Call the function
	keys, err := httpx.GetJWKSet(mockServer.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Compare the keys
	if len(keys) != len(expectedKeys) {
		t.Fatalf("Expected %d keys, but got %d", len(expectedKeys), len(keys))
	}

	for kid, expectedKey := range expectedKeys {
		actualKey, ok := keys[kid]
		if !ok {
			t.Fatalf("Key with kid %s not found", kid)
			continue
		}

		if actualKey.N.Cmp(expectedKey.N) != 0 {
			t.Fatalf("Expected N value %v, but got %v", expectedKey.N, actualKey.N)
		}

		if actualKey.E != expectedKey.E {
			t.Fatalf("Expected E value %v, but got %v", expectedKey.E, actualKey.E)
		}
	}
}

func TestGetRSAKeys(t *testing.T) {
	// Mock
	getJWKSetFunc := func(url string) (map[string]*rsa.PublicKey, error) {
		return map[string]*rsa.PublicKey{
			"key1": {
				N: big.NewInt(123),
				E: 65537,
			},
			"key2": {
				N: big.NewInt(456),
				E: 65537,
			},
		}, nil
	}

	// Call the function
	keys, err := httpx.GetRSAKeys(getJWKSetFunc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Compare the keys
	expectedKeys := map[string]*rsa.PublicKey{
		"key1": {
			N: big.NewInt(123),
			E: 65537,
		},
		"key2": {
			N: big.NewInt(456),
			E: 65537,
		},
	}

	if len(keys) != len(expectedKeys) {
		t.Fatalf("Expected %d keys, but got %d", len(expectedKeys), len(keys))
	}

	for _, expectedKey := range expectedKeys {
		var found bool
		for _, key := range keys {
			if key.N.Cmp(expectedKey.N) == 0 && key.E == expectedKey.E {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Key not found: %v", expectedKey)
		}
	}
}
