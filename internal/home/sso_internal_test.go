package home

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/sso"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestSSOAdapterLocalContract(t *testing.T) {
	ctx := context.Background()
	auth, err := newAuth(ctx, &authConfig{baseLogger: testSSOLogger(), rateLimiter: emptyRateLimiter{}, dbFilename: filepath.Join(t.TempDir(), "sessions.db"), users: []webUser{{Name: "admin", PasswordHash: "hash"}}, sessionTTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { auth.close(ctx) })
	current, err := auth.users.ByLogin(ctx, "admin")
	require.NoError(t, err)
	// An existing browser cookie may refer to a session absent from a fresh DB.
	adapter := auth.sessions.(*ssoSessions)
	require.NoError(t, adapter.RevokeSession(ctx, "00000000000000000000000000000000"))
	session, err := auth.sessions.New(ctx, current)
	require.NoError(t, err)
	restored, err := auth.sessions.FindByToken(ctx, session.Token)
	require.NoError(t, err)
	require.Equal(t, current.Login, restored.UserLogin)
	exists, err := adapter.LocalTokenExists(ctx, hex.EncodeToString(session.Token[:]))
	require.NoError(t, err)
	require.True(t, exists)
	require.NoError(t, adapter.RevokeSession(ctx, hex.EncodeToString(session.Token[:])))
	restored, err = auth.sessions.FindByToken(ctx, session.Token)
	require.NoError(t, err)
	require.Nil(t, restored)
}

func TestSSORejectsUnsafeHostConfiguration(t *testing.T) {
	for _, name := range []string{"userless", "glinet", "missing mapping"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			secret := filepath.Join(dir, "secret")
			require.NoError(t, os.WriteFile(secret, []byte("test"), 0o600))
			conf := &authConfig{baseLogger: testSSOLogger(), rateLimiter: emptyRateLimiter{}, dbFilename: filepath.Join(dir, "sessions.db"), sessionTTL: time.Hour, users: []webUser{{Name: "admin", PasswordHash: "hash"}}, sso: sso.Config{Enabled: true, OIDC: sso.OIDCConfig{Issuer: "https://accounts.google.com", ClientID: "test", ClientSecretFile: secret, PublicURL: "https://dns.example.com", Mappings: []sso.Mapping{{Subject: "id", Username: "admin"}}}}}
			switch name {
			case "userless":
				conf.users = nil
			case "glinet":
				conf.isGLiNet = true
			case "missing mapping":
				conf.sso.OIDC.Mappings[0].Username = "absent"
			}
			_, err := newAuth(context.Background(), conf)
			require.Error(t, err)
		})
	}
}

func TestSSOPublicPathsAreExact(t *testing.T) {
	for _, path := range []string{sso.ConfigPath, sso.StartPath, sso.CallbackPath} {
		require.True(t, isPublicResource(path))
		require.False(t, isPublicResource(path+"/evil"))
	}
}

func testSSOLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSSORedactsCallbackBeforeSharedLogger(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "secret-code", r.URL.Query().Get("code"))
		require.Equal(t, sso.CallbackPath, r.RequestURI)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := redactSSORequestURI(httputil.NewLogMiddleware(logger, slog.LevelDebug).Wrap(inner))
	req := httptest.NewRequest(http.MethodGet, sso.CallbackPath+"?code=secret-code&state=secret-state", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	require.NotContains(t, logs.String(), "secret-code")
	require.NotContains(t, logs.String(), "secret-state")
	require.Contains(t, logs.String(), sso.CallbackPath)
}

func TestSSORedirectWriter(t *testing.T) {
	for _, tc := range []struct{ location, want string }{
		{"/", "/vault/"},
		{"/login.html", "/vault/login.html"},
		{"login.html", "/vault/login.html"},
		{"https://id.example.com/", "https://id.example.com/"},
		{"//id.example.com/", "//id.example.com/"},
	} {
		response := httptest.NewRecorder()
		writer := &ssoRedirectWriter{ResponseWriter: response, base: "/vault/"}
		http.Redirect(writer, httptest.NewRequest(http.MethodGet, "/login.html", nil), tc.location, http.StatusFound)
		require.Equal(t, tc.want, response.Header().Get("Location"))
	}
}

func TestSSOSubpathLocalCookieAndLogout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test"), 0o600))
	conf := &authConfig{
		baseLogger: testSSOLogger(), rateLimiter: emptyRateLimiter{}, dbFilename: filepath.Join(dir, "sessions.db"), sessionTTL: time.Hour,
		users: []webUser{{Name: "admin", PasswordHash: "hash"}},
		sso:   sso.Config{Enabled: true, OIDC: sso.OIDCConfig{Issuer: "https://accounts.google.com", ClientID: "test", ClientSecretFile: secret, PublicURL: "https://dns.example.com/vault/", Mappings: []sso.Mapping{{Subject: "id", Username: "admin"}}}},
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	require.NoError(t, err)
	conf.users[0].PasswordHash = string(hash)
	a, err := newAuth(ctx, conf)
	require.NoError(t, err)
	t.Cleanup(func() { a.close(ctx) })
	cookie, err := newCookie(ctx, a, loginJSON{Name: "admin", Password: "test-password"}, "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "/vault/", cookie.Path)
	require.True(t, cookie.Secure)
	web := &webAPI{auth: a, logger: testSSOLogger()}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/control/logout", nil)
	request.AddCookie(cookie)
	web.handleSSOLogout(response, request)
	require.Equal(t, "/vault/login.html", response.Header().Get("Location"))
	require.Equal(t, "/vault/", response.Result().Cookies()[0].Path)
	token, err := sessionTokenFromHex(cookie.Value)
	require.NoError(t, err)
	session, err := a.sessions.FindByToken(ctx, token)
	require.NoError(t, err)
	require.Nil(t, session)
	handler := web.wrapSSORedirects(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) }))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login.html", nil))
	require.Equal(t, "/vault/", response.Header().Get("Location"))
}

func TestSSORejectsPasswordAuthentication(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test"), 0o600))
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.MinCost)
	require.NoError(t, err)
	a, err := newAuth(ctx, &authConfig{baseLogger: testSSOLogger(), rateLimiter: emptyRateLimiter{}, dbFilename: filepath.Join(dir, "sessions.db"), sessionTTL: time.Hour, users: []webUser{{Name: "admin", PasswordHash: string(hash)}}, sso: sso.Config{Enabled: true, OIDC: sso.OIDCConfig{Issuer: "https://accounts.google.com", ClientID: "test", ClientSecretFile: secret, PublicURL: "https://dns.example.com", Mappings: []sso.Mapping{{Subject: "id", Username: "admin"}}}}})
	require.NoError(t, err)
	t.Cleanup(func() { a.close(ctx) })
	web := &webAPI{auth: a}
	w := httptest.NewRecorder()
	web.handleLogin(w, httptest.NewRequest(http.MethodPost, "/control/login", bytes.NewBufferString(`{"name":"admin","password":"correct-password"}`)))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Result().Cookies())
	handler := a.middleware().Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodGet, "/control/status", nil)
	r.SetBasicAuth("admin", "correct-password")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	user, err := a.users.ByLogin(ctx, "admin")
	require.NoError(t, err)
	local, err := a.sessions.(*ssoSessions).local.New(ctx, user)
	require.NoError(t, err)
	restored, err := a.sessions.FindByToken(ctx, local.Token)
	require.NoError(t, err)
	require.Nil(t, restored)
}
