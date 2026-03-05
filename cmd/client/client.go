package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/toucan/toucan-calls/internal/client"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

func main() {
	log := logger.NewLogger(logger.LoggerOpts{
		Filename: "",
	})
	host := os.Getenv("HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.WithFields(logger.Fields{
		"host": host,
		"port": port,
	}).Info("starting toucan client")
	c := client.New(host, port, log)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Warn("shutdown signal received")
		c.Shutdown()
		log.Info("client shutdown complete")
		log.Events.Reset(true)
		os.Exit(0)
	}()
	if err := c.Run(); err != nil {
		log.Fatalf("client failed: %v", err)
	}
}
