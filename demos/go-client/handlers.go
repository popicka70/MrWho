package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *app) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.wrapSession(a.handleHome))
	mux.HandleFunc("/login", a.wrapSession(a.handleLogin))
	mux.HandleFunc("/callback", a.wrapSession(a.handleCallback))
	mux.HandleFunc("/logout", a.wrapSession(a.handleLogout))
	mux.HandleFunc("/call-api", a.wrapSession(a.handleCallAPI))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request, sessionID string, session *sessionData) {
	vm := homeViewModel{
		Issuer:      a.cfg.Issuer,
		ClientID:    a.cfg.ClientID,
		RedirectURL: a.cfg.RedirectURL,
		Scopes:      a.oauth2Config.Scopes,
		APIBaseURL:  a.cfg.APIBaseURL,
		OBOEnabled:  a.cfg.OBO != nil,
	}

	session.mu.RLock()
	if session.AccessToken != "" {
		vm.LoggedIn = true
		vm.AccessToken = session.AccessToken
		if !session.TokenExpiry.IsZero() {
			vm.AccessExpiry = session.TokenExpiry.UTC().Format(time.RFC3339)
		}
		vm.RefreshToken = session.RefreshToken
		vm.RawIDToken = session.RawIDToken
		vm.IDTokenJSON = prettyJSON(session.IDTokenClaims)
		vm.UserInfoJSON = prettyJSON(session.UserInfo)
		vm.APILastJSON = session.APILastResponse
		vm.Error = session.LastError
	} else {
		vm.Error = session.LastError
	}
	session.mu.RUnlock()

	vm.LastUpdatedUTC = time.Now().UTC().Format(time.RFC3339)

	if err := a.templates.ExecuteHome(w, vm); err != nil {
		a.logger.Error("failed to render home", "error", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request, sessionID string, session *sessionData) {
	state, err := randomString(stateEntropyBytes)
	if err != nil {
		a.failSession(session, fmt.Errorf("generate state: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	nonce, err := randomString(nonceEntropyBytes)
	if err != nil {
		a.failSession(session, fmt.Errorf("generate nonce: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var codeVerifier, codeChallenge string
	if a.pkceEnabled {
		codeVerifier, err = pkceCodeVerifier()
		if err != nil {
			a.failSession(session, fmt.Errorf("generate pkce: %w", err))
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		codeChallenge = pkceCodeChallenge(codeVerifier)
	}

	session.mu.Lock()
	session.State = state
	session.Nonce = nonce
	session.CodeVerifier = codeVerifier
	session.LastError = ""
	session.mu.Unlock()

	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}
	if a.pkceEnabled {
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	authURL := a.oauth2Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request, sessionID string, session *sessionData) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		description := r.URL.Query().Get("error_description")
		a.failSession(session, fmt.Errorf("authorization server returned %s: %s", errParam, description))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" {
		a.failSession(session, errors.New("missing authorization code"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session.mu.RLock()
	expectedState := session.State
	codeVerifier := session.CodeVerifier
	session.mu.RUnlock()

	if expectedState == "" || state != expectedState {
		a.failSession(session, errors.New("state mismatch"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	token, err := a.exchangeCode(r.Context(), code, codeVerifier)
	if err != nil {
		a.failSession(session, fmt.Errorf("token exchange failed: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.failSession(session, errors.New("token response missing id_token"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	verifyCtx := oidc.ClientContext(r.Context(), a.httpClient)
	idToken, err := a.idTokenVerifier.Verify(verifyCtx, rawIDToken)
	if err != nil {
		a.failSession(session, fmt.Errorf("id token validation failed: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session.mu.RLock()
	expectedNonce := session.Nonce
	session.mu.RUnlock()
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		a.failSession(session, errors.New("nonce mismatch"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	idTokenClaims := map[string]any{}
	if err := idToken.Claims(&idTokenClaims); err != nil {
		a.failSession(session, fmt.Errorf("read id token claims: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	userInfo, err := a.fetchUserInfo(r.Context(), token)
	if err != nil {
		a.logger.Warn("user info fetch failed", "error", err)
	}

	session.mu.Lock()
	session.State = ""
	session.Nonce = ""
	session.CodeVerifier = ""
	session.AccessToken = token.AccessToken
	session.RefreshToken = token.RefreshToken
	session.TokenExpiry = token.Expiry
	session.RawIDToken = rawIDToken
	session.IDTokenClaims = idTokenClaims
	if userInfo != nil {
		session.UserInfo = userInfo
	}
	session.LastError = ""
	session.APIToken = ""
	session.APITokenExpiry = time.Time{}
	session.mu.Unlock()

	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request, sessionID string, session *sessionData) {
	a.sessionStore.set(sessionID, &sessionData{})
	a.logger.Info("session cleared", slog.String("session_id", sessionID))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *app) handleCallAPI(w http.ResponseWriter, r *http.Request, sessionID string, session *sessionData) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session.mu.RLock()
	accessToken := session.AccessToken
	session.mu.RUnlock()

	if accessToken == "" {
		a.failSession(session, errors.New("sign in before calling the API"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if strings.TrimSpace(a.cfg.APIBaseURL) == "" {
		a.failSession(session, errors.New("api_base_url is not configured"))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tokenToUse := accessToken
	var expiry time.Time

	if a.cfg.OBO != nil {
		var err error
		tokenToUse, expiry, err = a.exchangeOnBehalfOf(r.Context(), session, accessToken)
		if err != nil {
			a.failSession(session, fmt.Errorf("on-behalf-of exchange failed: %w", err))
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	apiURL := strings.TrimRight(a.cfg.APIBaseURL, "/") + "/me"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, apiURL, nil)
	if err != nil {
		a.failSession(session, fmt.Errorf("create api request: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	req.Header.Set("Authorization", "Bearer "+tokenToUse)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.failSession(session, fmt.Errorf("call api: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.failSession(session, fmt.Errorf("read api response: %w", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	session.mu.Lock()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		session.LastError = ""
	} else {
		session.LastError = fmt.Sprintf("API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	session.APILastResponse = string(body)
	if !expiry.IsZero() {
		session.APIToken = tokenToUse
		session.APITokenExpiry = expiry
	}
	session.mu.Unlock()

	http.Redirect(w, r, "/", http.StatusFound)
}
