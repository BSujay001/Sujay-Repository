package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		loggedInEmail := session.Get("user")
		fromName := session.Get("from_name") // ✅ get from_name from session

		if loggedInEmail == nil || fromName == nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		// Store in context for use in handlers
		c.Set("loggedInEmail", loggedInEmail.(string))
		c.Set("fromName", fromName.(string))
		c.Next()
	}
}
