package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/toucan/toucan-calls/internal/server"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

func main() {
	log := logger.NewLogger(logger.LoggerOpts{Filename: ""})
	host := "127.0.0.1"
	port := "3000"
	srv, err := server.New(log)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.WithField("signal", sig.String()).Warn("shutdown signal received")
		cancel()
	}()
	err = srv.Run(ctx, host, port)
	if err != nil {
		log.Errorf("server stopped with error: %v", err)
	}
	log.Events.Reset(true)
}
