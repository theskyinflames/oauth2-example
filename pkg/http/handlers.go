package http

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

// ProtectedHandler is a handler for the protected endpoint
func ProtectedHandler(c echo.Context) error {
	msg := ""
	cookies := c.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == authCookieName {
			msg = cookie.Value
		}
	}

	return c.String(http.StatusOK, fmt.Sprintf("Protected endpoint: %s", msg))
}
