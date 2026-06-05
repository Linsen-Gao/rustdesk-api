//go:build windows

package http

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
)

func Run(g *gin.Engine, addr string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: g,
	}

	if global.Config.Gin.TlsEnable {
		tlsConfig := getTLSConfig()
		if tlsConfig != nil {
			srv.TLSConfig = tlsConfig
		} else {
			global.Logger.Warn("TLS enabled but no valid cert configured, falling back to HTTP")
		}
	}

	// Graceful shutdown on Windows
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		global.Logger.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	if srv.TLSConfig != nil {
		global.Logger.Infof("Starting HTTPS server on %s", addr)
		srv.ListenAndServeTLS("", "")
	} else {
		global.Logger.Infof("Starting HTTP server on %s", addr)
		srv.ListenAndServe()
	}
}
