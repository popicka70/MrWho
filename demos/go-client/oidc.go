package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func waitForProvider(ctx context.Context, issuer string, logger *slog.Logger) *oidc.Provider {
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		provider, err := oidc.NewProvider(ctx, issuer)
		if err == nil {
			return provider
		}

		// In Docker Compose, exiting hard causes container restart loops. For demo UX,
		// keep the process alive and keep retrying until the OIDC provider is ready
		// (or config is fixed).
		logger.Error(
			"failed to connect to issuer; will retry",
			slog.String("issuer", issuer),
			slog.Duration("retry_in", backoff),
			slog.Any("error", err),
		)

		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func ensureDefaultScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return []string{"openid", "profile"}
	}
	m := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		m[scope] = struct{}{}
	}
	if _, ok := m["openid"]; !ok {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

func (a *app) exchangeOnBehalfOf(ctx context.Context, session *sessionData, subjectToken string) (string, time.Time, error) {
	session.mu.RLock()
	cachedToken := session.APIToken
	expiry := session.APITokenExpiry
	session.mu.RUnlock()

	if cachedToken != "" && time.Now().Add(10*time.Second).Before(expiry) {
		return cachedToken, expiry, nil
	}

	if a.cfg.OBO == nil {
		return subjectToken, time.Time{}, nil
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	if strings.TrimSpace(a.cfg.OBO.Scope) != "" {
		form.Set("scope", a.cfg.OBO.Scope)
	}
	if strings.TrimSpace(a.cfg.OBO.Audience) != "" {
		form.Set("audience", a.cfg.OBO.Audience)
	}
	if strings.TrimSpace(a.cfg.OBO.ClientID) != "" && strings.TrimSpace(a.cfg.OBO.ClientSecret) == "" {
		form.Set("client_id", a.cfg.OBO.ClientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.oauth2Config.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if strings.TrimSpace(a.cfg.OBO.ClientSecret) != "" {
		req.SetBasicAuth(a.cfg.OBO.ClientID, a.cfg.OBO.ClientSecret)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", time.Time{}, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", time.Time{}, fmt.Errorf("parse token response: %w", err)
	}
	if strings.ToLower(parsed.TokenType) != "bearer" {
		return "", time.Time{}, fmt.Errorf("unexpected token type %q", parsed.TokenType)
	}
	if parsed.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	} else if a.oboCacheTTL > 0 {
		expiry = time.Now().Add(a.oboCacheTTL)
	}

	session.mu.Lock()
	session.APIToken = parsed.AccessToken
	session.APITokenExpiry = expiry
	session.mu.Unlock()

	return parsed.AccessToken, expiry, nil
}

func (a *app) exchangeCode(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	opts := []oauth2.AuthCodeOption{}
	if a.pkceEnabled && codeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}
	// Use custom HTTP client for token exchange (important for TLS skip)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	return a.oauth2Config.Exchange(ctx, code, opts...)
}

func (a *app) fetchUserInfo(ctx context.Context, token *oauth2.Token) (map[string]any, error) {
	if token == nil {
		return nil, nil
	}
	// Use custom HTTP client for userinfo endpoint (important for TLS skip)
	ctx = oidc.ClientContext(ctx, a.httpClient)
	userInfo, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, err
	}
	raw := map[string]any{}
	if err := userInfo.Claims(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}
