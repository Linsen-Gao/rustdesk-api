package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
	"github.com/lejianwen/rustdesk-api/v2/http/response"
)

func Limiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		loginLimiter := global.LoginLimiter
		clientIp := c.ClientIP()
		banned, _ := loginLimiter.CheckSecurityStatus(clientIp)
		if banned {
			response.Fail(c, response.CodeLocked, response.TranslateMsg(c, "Banned"))
			c.Abort()
			return
		}
		c.Next()
	}
}
