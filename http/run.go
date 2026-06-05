//go:build !windows

package http

import (
	"crypto/tls"

	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
)

func Run(g *gin.Engine, addr string) {
	if global.Config.Gin.TlsEnable {
		tlsConfig := getTLSConfig()
		if tlsConfig != nil {
			server := endless.NewServer(addr, g)
			server.TLSConfig = tlsConfig
			server.ListenAndServeTLS("", "")
			return
		}
		global.Logger.Warn("TLS enabled but no valid cert configured, falling back to HTTP")
	}
	endless.ListenAndServe(addr, g)
}

// getTLSConfig loads or generates TLS configuration
func getTLSConfig() *tls.Config {
	cfg := &global.Config.Gin

	// Load existing or auto-generate
	tlsConfig, err := loadOrGenerateTLS(cfg.TlsCertFile, cfg.TlsKeyFile, cfg.TlsAutoCert)
	if err != nil {
		global.Logger.Errorf("Failed to configure TLS: %v", err)
		return nil
	}
	return tlsConfig
}
