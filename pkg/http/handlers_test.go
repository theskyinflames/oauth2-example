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
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Call the handler function
	err := httpx.ProtectedHandler(c)
	assert.NoError(t, err)

	// Check the response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Protected endpoint: ", rec.Body.String())
}
