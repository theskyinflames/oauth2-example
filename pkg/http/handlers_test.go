package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	httpx "theskyinflames/oauth2-example/pkg/http"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestProtectedHandler(t *testing.T) {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	res := httptest.NewRecorder()

	// Create a new context
	c := e.NewContext(req, res)
	c.Set(httpx.UserCtxKey, httpx.User{
		Email: httpx.Email("email"),
		Roles: []httpx.Role{
			httpx.Role("admin"),
		},
	})

	// Call the handler function
	err := httpx.ProtectedHandler(c)
	assert.NoError(t, err)

	// Check the response
	assert.Equal(t, http.StatusOK, res.Code)
}
