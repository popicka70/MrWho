package main

import (
	"log/slog"
	"net/http"
	"os"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("failed to load config", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.Issuer == "" || cfg.ClientID == "" {
		logger.Error("issuer and client_id are required")
		os.Exit(1)
	}

	application, err := newApp(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize app", slog.Any("error", err))
		os.Exit(1)
	}

	mux := http.NewServeMux()
	application.registerRoutes(mux)

	logger.Info("starting Go web client", slog.String("listen_addr", cfg.ListenAddr), slog.String("issuer", cfg.Issuer))
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		logger.Error("server exited", slog.Any("error", err))
		os.Exit(1)
	}
}
