package main

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

const sessionCookieName = "mrwho_go_session"

type sessionData struct {
	mu              sync.RWMutex
	State           string
	Nonce           string
	CodeVerifier    string
	AccessToken     string
	RefreshToken    string
	TokenExpiry     time.Time
	RawIDToken      string
	IDTokenClaims   map[string]any
	UserInfo        map[string]any
	APIToken        string
	APITokenExpiry  time.Time
	APILastResponse string
	LastError       string
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionData
}

func (a *app) wrapSession(next func(http.ResponseWriter, *http.Request, string, *sessionData)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, session := a.getOrCreateSession(w, r)
		next(w, r, sessionID, session)
	}
}

func (a *app) getOrCreateSession(w http.ResponseWriter, r *http.Request) (string, *sessionData) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		sessionID := uuid.NewString()
		session := &sessionData{}
		a.sessionStore.set(sessionID, session)
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		return sessionID, session
	}

	session := a.sessionStore.get(cookie.Value)
	if session == nil {
		session = &sessionData{}
		a.sessionStore.set(cookie.Value, session)
	}
	return cookie.Value, session
}

func (s *sessionStore) get(id string) *sessionData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

func (s *sessionStore) set(id string, data *sessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = data
}

func (a *app) failSession(session *sessionData, err error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	session.LastError = err.Error()
	a.logger.Error("session error", slog.Any("error", err))
}
