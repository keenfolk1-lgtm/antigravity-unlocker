package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed ui_assets.html
var embeddedUIHTML string

const uiSessionCookieName = "pixel_ui_session"

type webUISession struct {
	csrfToken string
	expiresAt time.Time
}

// WebSessionStore tracks bootstrap auth token and HttpOnly SameSite=Strict cookie + CSRF sessions.
type WebSessionStore struct {
	mu             sync.RWMutex
	bootstrapToken string
	sessions       map[string]webUISession
}

// NewWebSessionStore creates a store with a fresh cryptographically random bootstrap token.
func NewWebSessionStore() *WebSessionStore {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return &WebSessionStore{
		bootstrapToken: hex.EncodeToString(b[:]),
		sessions:       make(map[string]webUISession),
	}
}

func (ws *WebSessionStore) BootstrapToken() string {
	return ws.bootstrapToken
}

func (ws *WebSessionStore) ValidateBootstrapToken(tok string) bool {
	if tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(ws.bootstrapToken)) == 1
}

func (ws *WebSessionStore) CreateSession() (sessionID, csrfToken string) {
	var sidRaw, csrfRaw [24]byte
	_, _ = rand.Read(sidRaw[:])
	_, _ = rand.Read(csrfRaw[:])
	sessionID = hex.EncodeToString(sidRaw[:])
	csrfToken = hex.EncodeToString(csrfRaw[:])

	ws.mu.Lock()
	ws.sessions[sessionID] = webUISession{
		csrfToken: csrfToken,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	ws.mu.Unlock()
	return sessionID, csrfToken
}

func (ws *WebSessionStore) GetCSRF(sessionID string) (string, bool) {
	if sessionID == "" {
		return "", false
	}
	ws.mu.RLock()
	sess, ok := ws.sessions[sessionID]
	ws.mu.RUnlock()
	if !ok || time.Now().After(sess.expiresAt) {
		return "", false
	}
	return sess.csrfToken, true
}

// ValidateRequest requires valid HttpOnly cookie AND matching X-Pixel-CSRF header.
func (ws *WebSessionStore) ValidateRequest(r *http.Request) bool {
	ck, err := r.Cookie(uiSessionCookieName)
	if err != nil || ck == nil || ck.Value == "" {
		return false
	}
	expectedCSRF, ok := ws.GetCSRF(ck.Value)
	if !ok {
		return false
	}
	gotCSRF := r.Header.Get("X-Pixel-CSRF")
	return gotCSRF != "" && subtle.ConstantTimeCompare([]byte(gotCSRF), []byte(expectedCSRF)) == 1
}

func (s *LocalProxyServer) buildWebUIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Security headers blocking framing/clickjacking and external script execution
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")

		var csrf string
		if qTok := r.URL.Query().Get("t"); qTok != "" {
			if !s.uiCSRFStore.ValidateBootstrapToken(qTok) {
				http.Error(w, "Invalid bootstrap token", http.StatusUnauthorized)
				return
			}
			sid, newCSRF := s.uiCSRFStore.CreateSession()
			http.SetCookie(w, &http.Cookie{
				Name:     uiSessionCookieName,
				Value:    sid,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			csrf = newCSRF
		} else {
			ck, err := r.Cookie(uiSessionCookieName)
			if err != nil || ck == nil {
				http.Error(w, "Unauthorized: open Web-UI URL with ?t=<bootstrap_token> from PixelTunnel CLI", http.StatusUnauthorized)
				return
			}
			var ok bool
			csrf, ok = s.uiCSRFStore.GetCSRF(ck.Value)
			if !ok {
				http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page := strings.Replace(embeddedUIHTML, "__PIXEL_CSRF__", csrf, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page))
	})
}
