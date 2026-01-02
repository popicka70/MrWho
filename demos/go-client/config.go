package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultConfigPath = "config.json"
	configEnvVar      = "MRWHO_GO_WEB_CONFIG"
)

type config struct {
	Issuer        string     `json:"issuer"`
	ClientID      string     `json:"client_id"`
	ClientSecret  string     `json:"client_secret"`
	RedirectURL   string     `json:"redirect_url"`
	Scopes        []string   `json:"scopes"`
	UsePKCE       *bool      `json:"use_pkce"`
	ListenAddr    string     `json:"listen_addr"`
	APIBaseURL    string     `json:"api_base_url"`
	SkipTLSVerify bool       `json:"skip_tls_verify"`
	OBO           *oboConfig `json:"obo"`
}

type oboConfig struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	Scope         string `json:"scope"`
	Audience      string `json:"audience"`
	CacheLifetime string `json:"cache_lifetime"`
}

func loadConfig() (config, error) {
	path := os.Getenv(configEnvVar)
	if strings.TrimSpace(path) == "" {
		path = defaultConfigPath
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return config{}, err
	}

	raw, err := os.ReadFile(abs)
	if err != nil {
		return config{}, err
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return config{}, err
	}

	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "http://localhost:5080/callback"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":5080"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "offline_access"}
	}
	if !strings.Contains(strings.Join(cfg.Scopes, " "), "openid") {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}

	return cfg, nil
}
