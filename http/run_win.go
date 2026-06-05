//go:build windows

package http

import (
	"context"
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

	// Graceful shutdown
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		global.Logger.Info("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	if global.Config.Gin.TlsEnable {
		cfg := &global.Config.Gin
		global.Logger.Infof("Starting HTTPS server on %s", addr)
		srv.ListenAndServeTLS(cfg.TlsCertFile, cfg.TlsKeyFile)
	} else {
		global.Logger.Infof("Starting HTTP server on %s", addr)
		srv.ListenAndServe()
	}
}
