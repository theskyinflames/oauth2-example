package http

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// ProtectedHandler is a handler for the protected endpoint
func ProtectedHandler(c echo.Context) error {
	msg := ""
	cookies := c.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == authCookieName {
			msg = cookie.Value
			break
		}
	}

	user := c.Get(UserCtxKey).(User)

	sb := strings.Builder{}
	sb.WriteString("<h1>Protected endpoint</h1>")
	sb.WriteString("<h2>User info</h2>")
	sb.WriteString("<p>")
	sb.WriteString(user.String())
	sb.WriteString("</p>")
	sb.WriteString("<h2>Token</h2>")
	sb.WriteString("<p>JWT token: " + msg + "</p>")

	return c.HTML(http.StatusOK, sb.String())
}
