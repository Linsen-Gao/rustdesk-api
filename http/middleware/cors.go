package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
	"net/http"
	"strings"
)

// Cors 跨域
func Cors() gin.HandlerFunc {
	originsStr := global.Config.Gin.CorsOrigins
	var allowedOrigins []string
	if originsStr != "" {
		for _, o := range strings.Split(originsStr, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				allowedOrigins = append(allowedOrigins, o)
			}
		}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// If no origins configured, reflect origin (backward compatible but logged)
		// If origins configured, only allow whitelisted origins
		allowed := false
		if len(allowedOrigins) == 0 {
			// No whitelist configured: allow all origins (backward compatible)
			c.Header("Access-Control-Allow-Origin", origin)
			allowed = true
		} else {
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					allowed = true
					break
				}
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Headers", "api-token,content-type,authorization")
			c.Header("Access-Control-Allow-Methods", c.Request.Method)
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
