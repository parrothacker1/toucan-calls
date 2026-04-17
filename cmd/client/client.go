package main

import (
	"context"
	"flag"
	"io/fs"
	"os"
	"os/signal"
	"syscall"

	"github.com/toucan/toucan-calls/internal/client"
	"github.com/toucan/toucan-calls/internal/utils/logger"
	"github.com/toucan/toucan-calls/ui"
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

	model := flag.String("model", "vad", "The model to use for audio processing (vad or ml)")
	useUI := flag.Bool("ui", false, "Launch the web UI instead of the CLI")
	webPort := flag.String("port", "8080", "Port for the web UI (only used with --ui)")
	vadURL := flag.String("vad-url", "", "Base URL for the VAD/ML service (default: http://localhost:5001)")
	flag.Parse()

	// Resolve VAD URL: flag > env > default
	resolvedVadURL := *vadURL
	if resolvedVadURL == "" {
		resolvedVadURL = os.Getenv("VAD_URL")
	}
	if resolvedVadURL == "" {
		resolvedVadURL = "http://localhost:5001"
	}

	log.WithFields(logger.Fields{
		"host":  host,
		"port":  port,
		"model": *model,
	}).Info("starting toucan client")
	c := client.New(host, port, *model, resolvedVadURL, log)

	// Start log consumer goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go log.Events.Run(ctx)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigs
		log.Warn("shutdown signal received")
		c.Shutdown()
		log.Info("client shutdown complete")
		cancel()
		log.Events.Reset(true)
		os.Exit(0)
	}()

	if *useUI {
		uiFS, err := fs.Sub(ui.DistFS, "dist")
		if err != nil {
			log.Fatalf("failed to load UI assets: %v", err)
		}
		if err := c.RunWithUI(uiFS, *webPort); err != nil {
			log.Fatalf("client UI failed: %v", err)
		}
	} else {
		if err := c.Run(); err != nil {
			log.Fatalf("client failed: %v", err)
		}
	}
}
