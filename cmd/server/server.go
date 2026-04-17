package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/toucan/toucan-calls/internal/server"
	"github.com/toucan/toucan-calls/internal/utils/events"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

func main() {
	var writer events.EventWriter[logger.Log]
	stdoutWriter, err := logger.NewDefaultWriter("")
	if err != nil {
		panic(err)
	}

	lokiURL := os.Getenv("LOKI_URL")
	if lokiURL != "" {
		lokiWriter := logger.NewLokiWriter(lokiURL, map[string]string{
			"job":     "toucan-calls",
			"service": "server",
		})
		writer = logger.NewMultiWriter(stdoutWriter, lokiWriter)
	} else {
		writer = stdoutWriter
	}

	log := logger.NewLogger(logger.LoggerOpts{CustomWriter: writer})

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := "3000"

	srv, err := server.New(log)
	if err != nil {
		log.Fatalf("server init failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start the event queue consumer goroutine
	go log.Events.Run(ctx)

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

	// Stop consumer, then flush remaining logs
	cancel()
	log.Events.Reset(true)
}
