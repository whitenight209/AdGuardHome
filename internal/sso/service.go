package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// ConfigPath is the public login-options endpoint.
	ConfigPath = "/control/auth/config"
	// StartPath begins an OIDC browser flow.
	StartPath = "/control/sso/oidc/start"
	// CallbackPath receives the provider response.
	CallbackPath      = "/control/sso/oidc/callback"
	transactionCookie = "agh_sso_transaction"
	sessionCookie     = "agh_session"
	transactionTTL    = 5 * time.Minute
	maxTransactions   = 1024
	RefreshPath       = "/control/sso/refresh"
	DevicesPath       = "/control/sso/devices"
	RevokeDevicePath  = "/control/sso/devices/revoke"
	refreshCookie     = "agh_sso_refresh"
)

// Host is the narrow boundary to the application's existing local users.
type Host interface {
	UserExists(context.Context, string) (bool, error)
	LocalTokenExists(context.Context, string) (bool, error)
	RevokeSession(context.Context, string) error
}

// LoginOptions is intentionally safe to expose before authentication.
type LoginOptions struct {
	LocalLoginEnabled bool   `json:"local_login_enabled"`
	SSOEnabled        bool   `json:"sso_enabled"`
	SSODisplayName    string `json:"sso_display_name,omitempty"`
	SSOStartURL       string `json:"sso_start_url,omitempty"`
}

type transaction struct {
	binding, nonce, verifier, peer string
	expires                        time.Time
	remember                       bool
}
type providerState struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// Service owns the OIDC lifecycle and SSO session policy.
type Service struct {
	logger     *slog.Logger
	config     Config
	store      *Store
	host       Host
	secret     string
	now        func() time.Time
	client     *http.Client
	mu         sync.Mutex
	pending    map[string]transaction
	providerMu sync.Mutex
	provider   *providerState
	retryAfter time.Time
}

// New constructs SSO without contacting the provider, keeping DNS startup offline.
func New(c Config, store *Store, host Host, logger *slog.Logger) (*Service, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Enabled && (store == nil || host == nil) {
		return nil, errors.Error("sso: enabled service requires store and host")
	}
	c.OIDC.Mappings = append([]Mapping(nil), c.OIDC.Mappings...)
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Service{logger: logger, config: c, store: store, host: host, now: time.Now, pending: map[string]transaction{}}
	s.client = &http.Client{Timeout: 10 * time.Second, Transport: limitedTransport{http.DefaultTransport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.Enabled {
		secret, err := os.ReadFile(c.OIDC.ClientSecretFile)
		if err != nil {
			return nil, errors.Error("sso: cannot read client_secret_file")
		}
		s.secret = strings.TrimSpace(string(secret))
		if s.secret == "" {
			return nil, errors.Error("sso: empty client secret")
		}
	}
	return s, nil
}

// Enabled reports the immutable startup policy.
func (s *Service) Enabled() bool { return s != nil && s.config.Enabled }

// Options returns the public login configuration.
func (s *Service) Options() LoginOptions {
	o := LoginOptions{LocalLoginEnabled: true, SSOEnabled: s.Enabled()}
	if o.SSOEnabled {
		o.SSODisplayName = s.config.OIDC.DisplayName
		if o.SSODisplayName == "" {
			o.SSODisplayName = "SSO"
		}
		o.SSOStartURL = s.ExternalPath(StartPath)
	}
	return o
}

// PublicPath is an exact route predicate, never a prefix exception.
func PublicPath(path string) bool {
	return path == ConfigPath || path == StartPath || path == CallbackPath || path == RefreshPath
}

// ServeHTTP handles exact SSO routes; device management also requires a session.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !PublicPath(r.URL.Path) && r.URL.Path != DevicesPath && r.URL.Path != RevokeDevicePath {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == RefreshPath || r.URL.Path == DevicesPath || r.URL.Path == RevokeDevicePath {
		s.serveRemember(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == ConfigPath {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Options())
		return
	}
	if !s.Enabled() {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == StartPath {
		s.start(w, r)
	} else {
		s.callback(w, r)
	}
}

func randomHex(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	remember := r.URL.Query()["remember"]
	if len(remember) > 1 || (len(remember) == 1 && remember[0] != "1") {
		http.Error(w, "Invalid remember option", http.StatusBadRequest)
		return
	}
	state, t, err := s.newTransaction(r.RemoteAddr)
	t.remember = len(remember) == 1
	if err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	if !s.reserveTransaction(state, t) {
		w.Header().Set("Retry-After", "300")
		http.Error(w, "Too many sign-in attempts", http.StatusTooManyRequests)
		return
	}
	p, err := s.getProvider(r.Context())
	if err != nil {
		s.mu.Lock()
		delete(s.pending, state)
		s.mu.Unlock()
		s.fail(w, r, "unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: transactionCookie, Value: t.binding, Path: s.ExternalPath("/control/sso/oidc"), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	http.Redirect(w, r, p.oauth.AuthCodeURL(state, oidc.Nonce(t.nonce), oauth2.S256ChallengeOption(t.verifier)), http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	q, err := parseCallback(r)
	if err != nil {
		s.fail(w, r, "failed")
		return
	}
	t, err := s.consumeTransaction(q.Get("state"), r)
	if err != nil {
		s.fail(w, r, "expired")
		return
	}
	if q.Get("error") != "" {
		s.fail(w, r, "failed")
		return
	}
	id, err := s.exchangeIdentity(r.Context(), q.Get("code"), t)
	if err != nil {
		s.fail(w, r, "failed")
		return
	}
	login, err := s.authorize(r.Context(), id.Subject)
	if err != nil {
		s.fail(w, r, "denied")
		return
	}
	if err = s.LogoutRemembered(w, r); err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	cookie, err := s.issueSession(r, login)
	if err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	if t.remember {
		if err = s.rememberSession(w, r, login, cookie); err != nil {
			s.fail(w, r, "unavailable")
			return
		}
	}
	s.logger.InfoContext(r.Context(), "sign-in succeeded", "method", "oidc", "user", login)
	s.clearTransaction(w)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, s.BasePath(), http.StatusFound)
}

func (s *Service) authorize(ctx context.Context, subject string) (string, error) {
	for _, m := range s.config.OIDC.Mappings {
		if m.Subject != subject {
			continue
		}
		exists, err := s.host.UserExists(ctx, m.Username)
		if err != nil {
			return "", err
		}
		if exists {
			return m.Username, nil
		}
	}
	return "", errors.Error("sso: unauthorized identity")
}

func (s *Service) issueSession(r *http.Request, login string) (*http.Cookie, error) {
	value, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	collision, err := s.host.LocalTokenExists(r.Context(), value)
	if err != nil {
		return nil, err
	}
	if collision {
		return nil, errors.Error("sso: token collision")
	}
	if old, e := r.Cookie(sessionCookie); e == nil {
		if e = s.host.RevokeSession(r.Context(), old.Value); e != nil {
			return nil, e
		}
	}
	ttl, _ := s.config.TTL()
	expires := s.now().Add(ttl)
	err = s.store.put(value, Session{Login: login, Expires: expires, Policy: s.config.fingerprint()})
	if err != nil {
		return nil, err
	}
	return &http.Cookie{Name: sessionCookie, Value: value, Path: s.BasePath(), Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}, nil
}

func (s *Service) clearTransaction(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: transactionCookie, Path: s.ExternalPath("/control/sso/oidc"), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, code string) {
	s.logger.InfoContext(r.Context(), "sign-in failed", "method", "oidc", "reason", code)
	s.clearTransaction(w)
	http.Redirect(w, r, s.ExternalPath("/login.html")+"?sso_error="+code, http.StatusFound)
}

type limitedTransport struct{ base http.RoundTripper }

func (t limitedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, errors.Error("sso: HTTPS required")
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{Reader: io.LimitReader(resp.Body, 1<<20), Closer: resp.Body}
	return resp, nil
}

type limitedBody struct {
	io.Reader
	io.Closer
}
