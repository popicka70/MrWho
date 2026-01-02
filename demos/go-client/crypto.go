package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	stateEntropyBytes  = 32
	nonceEntropyBytes  = 32
	codeVerifierLength = 64
)

func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func pkceCodeVerifier() (string, error) {
	allowed := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	bytes := make([]byte, codeVerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = allowed[int(bytes[i])%len(allowed)]
	}
	return string(bytes), nil
}

func pkceCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
