package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type app struct {
	cfg             config
	provider        *oidc.Provider
	oauth2Config    oauth2.Config
	idTokenVerifier *oidc.IDTokenVerifier
	sessionStore    *sessionStore
	templates       *templates
	logger          *slog.Logger
	httpClient      *http.Client
	oboCacheTTL     time.Duration
	pkceEnabled     bool
}

func newApp(cfg config, logger *slog.Logger) (*app, error) {
	ctx := context.Background()

	// Create HTTP client with optional TLS skip for development/Docker environments
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if cfg.SkipTLSVerify {
		logger.Warn("TLS certificate verification is disabled - use only for development!")
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Use custom HTTP client for OIDC discovery
	ctx = oidc.ClientContext(ctx, httpClient)

	provider := waitForProvider(ctx, cfg.Issuer, logger)

	verifierConfig := &oidc.Config{ClientID: cfg.ClientID}
	idTokenVerifier := provider.Verifier(verifierConfig)

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       ensureDefaultScopes(cfg.Scopes),
		RedirectURL:  cfg.RedirectURL,
	}

	parsedTemplates, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	oboCacheTTL := 5 * time.Minute
	if cfg.OBO != nil && strings.TrimSpace(cfg.OBO.CacheLifetime) != "" {
		if parsed, err := time.ParseDuration(cfg.OBO.CacheLifetime); err == nil {
			oboCacheTTL = parsed
		}
	}

	pkceEnabled := true
	if cfg.UsePKCE != nil {
		pkceEnabled = *cfg.UsePKCE
	} else if cfg.ClientSecret != "" {
		pkceEnabled = false
	}

	return &app{
		cfg:             cfg,
		provider:        provider,
		oauth2Config:    oauth2Config,
		idTokenVerifier: idTokenVerifier,
		sessionStore:    &sessionStore{sessions: make(map[string]*sessionData)},
		templates:       parsedTemplates,
		logger:          logger,
		httpClient:      httpClient,
		oboCacheTTL:     oboCacheTTL,
		pkceEnabled:     pkceEnabled,
	}, nil
}
