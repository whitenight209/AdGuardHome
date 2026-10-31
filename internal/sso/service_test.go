package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

type testHost struct {
	revoked   []string
	exists    bool
	collision bool
}

func (h *testHost) UserExists(context.Context, string) (bool, error)       { return h.exists, nil }
func (h *testHost) LocalTokenExists(context.Context, string) (bool, error) { return h.collision, nil }

func (h *testHost) RevokeSession(_ context.Context, t string) error {
	h.revoked = append(h.revoked, t)
	return nil
}

func testConfig(t *testing.T) Config {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0o600))
	return Config{Enabled: true, OIDC: OIDCConfig{Issuer: "https://id.example.com", ClientID: "test-client", ClientSecretFile: secret, PublicURL: "https://dns.example.com/", Mappings: []Mapping{{Subject: "allowed", Username: "admin"}}}}
}

type fixture struct {
	service          *Service
	host             *testHost
	server           *httptest.Server
	mu               sync.Mutex
	claims           map[string]any
	nonce, challenge string
	exchanges        int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fixture{host: &testHost{exists: true}, claims: map[string]any{}}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	require.NoError(t, err)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			require.NoError(t, r.ParseForm())
			f.mu.Lock()
			defer f.mu.Unlock()
			f.exchanges++
			require.Equal(t, f.challenge, pkceChallenge(r.Form.Get("code_verifier")))
			require.Equal(t, strings.TrimRight(f.service.config.OIDC.PublicURL, "/")+CallbackPath, r.Form.Get("redirect_uri"))
			claims := map[string]any{"iss": f.server.URL, "sub": "allowed", "aud": "test-client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": f.nonce}
			for k, v := range f.claims {
				claims[k] = v
			}
			data, e := json.Marshal(claims)
			require.NoError(t, e)
			signed, e := signer.Sign(data)
			require.NoError(t, e)
			token, e := signed.CompactSerialize()
			require.NoError(t, e)
			if f.claims["bad_signature"] == true {
				parts := strings.Split(token, ".")
				parts[2] = "AAAA"
				token = strings.Join(parts, ".")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "discard-me", "token_type": "Bearer", "id_token": token})
		default:
			http.NotFound(w, r)
		}
	})
	f.server = httptest.NewTLSServer(handler)
	t.Cleanup(f.server.Close)
	c := testConfig(t)
	c.OIDC.Issuer = f.server.URL
	store, err := OpenStore(filepath.Join(t.TempDir(), "sso.db"), c, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	f.service, err = New(c, store, f.host, nil)
	require.NoError(t, err)
	f.service.client = f.server.Client()
	return f
}

func (f *fixture) begin(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, StartPath, nil)
	f.service.ServeHTTP(w, r)
	require.Equal(t, 302, w.Code)
	target, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "S256", target.Query().Get("code_challenge_method"))
	f.nonce = target.Query().Get("nonce")
	f.challenge = target.Query().Get("code_challenge")
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	return target.Query().Get("state"), cookies[0]
}

func (f *fixture) finish(state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=code&state="+state, nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	return w
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	state, cookie := f.begin(t)
	w := f.finish(state, cookie)
	require.Equal(t, "/", w.Header().Get("Location"))
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	require.NotNil(t, session)
	require.True(t, session.HttpOnly)
	require.True(t, session.Secure)
	record, err := f.service.store.Find(session.Value)
	require.NoError(t, err)
	require.Equal(t, "admin", record.Login)
	require.NotContains(t, w.Body.String(), "discard-me")
	require.Equal(t, "/login.html?sso_error=expired", f.finish(state, cookie).Header().Get("Location"))
	require.Equal(t, 1, f.exchanges)
}

func TestRejectIDTokens(t *testing.T) {
	cases := map[string]map[string]any{
		"signature": {"bad_signature": true},
		"issuer":    {"iss": "https://attacker.example"}, "audience": {"aud": "other"}, "nonce": {"nonce": "wrong"},
		"expired": {"exp": time.Now().Add(-time.Hour).Unix()}, "unknown": {"sub": "unmapped"}, "empty subject": {"sub": ""},
		"azp": {"azp": "other"}, "multi audience without azp": {"aud": []string{"test-client", "other"}},
		"future nbf": {"nbf": time.Now().Add(time.Hour).Unix()}, "future issued": {"iat": time.Now().Add(time.Hour).Unix()},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.claims = claims
			state, c := f.begin(t)
			w := f.finish(state, c)
			require.Contains(t, w.Header().Get("Location"), "/login.html?sso_error=")
			for _, cookie := range w.Result().Cookies() {
				require.NotEqual(t, sessionCookie, cookie.Name)
			}
		})
	}
}

func TestBrowserBindingAndExpiry(t *testing.T) {
	f := newFixture(t)
	state, c := f.begin(t)
	require.Contains(t, f.finish(state, nil).Header().Get("Location"), "expired")
	wrong := *c
	wrong.Value = "other-browser"
	require.Contains(t, f.finish(state, &wrong).Header().Get("Location"), "expired")
	require.Zero(t, f.exchanges)
	f.service.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	require.Contains(t, f.finish(state, c).Header().Get("Location"), "expired")
	require.Zero(t, f.exchanges)
}

func TestCallbackParameters(t *testing.T) {
	for _, q := range []string{"", "state=a", "state=a&code=x&code=y", "state=a&state=b&code=x", "state=a&code=x&error=denied", "state=a&code=%zz", strings.Repeat("x", 9000)} {
		_, err := parseCallback(httptest.NewRequest(http.MethodGet, CallbackPath+"?"+q, nil))
		require.Error(t, err)
	}
}

func TestDisabledRoutesAndOptions(t *testing.T) {
	s, err := New(Config{}, nil, nil, nil)
	require.NoError(t, err)
	for _, p := range []string{StartPath, CallbackPath, "/control/sso/oidc/evil"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		require.Equal(t, 404, w.Code)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, ConfigPath, nil))
	require.Equal(t, 200, w.Code)
	require.JSONEq(t, `{"local_login_enabled":true,"sso_enabled":false}`, w.Body.String())
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, StartPath, nil))
	require.Equal(t, 405, w.Code)
}

func TestStartLimits(t *testing.T) {
	f := newFixture(t)
	for range 10 {
		f.begin(t)
	}
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, httptest.NewRequest(http.MethodGet, StartPath, nil))
	require.Equal(t, 429, w.Code)
}

func TestHostDenialAndCollision(t *testing.T) {
	for _, collision := range []bool{false, true} {
		f := newFixture(t)
		f.host.exists = collision
		f.host.collision = collision
		state, c := f.begin(t)
		require.Contains(t, f.finish(state, c).Header().Get("Location"), "/login.html?sso_error=")
	}
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestConcurrentCallbackIsConsumedOnce(t *testing.T) {
	f := newFixture(t)
	state, cookie := f.begin(t)
	results := make(chan string, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { results <- f.finish(state, cookie).Header().Get("Location") })
	}
	wg.Wait()
	close(results)
	successes := 0
	for target := range results {
		if target == "/" {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, f.exchanges)
}

func TestCancellationConsumesTransaction(t *testing.T) {
	f := newFixture(t)
	state, cookie := f.begin(t)
	r := httptest.NewRequest(http.MethodGet, CallbackPath+"?state="+state+"&error=access_denied&error_description=secret-description", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, "/login.html?sso_error=failed", w.Header().Get("Location"))
	require.NotContains(t, w.Body.String(), "secret-description")
	require.Contains(t, f.finish(state, cookie).Header().Get("Location"), "expired")
	require.Zero(t, f.exchanges)
}

func TestSessionRotation(t *testing.T) {
	f := newFixture(t)
	state, cookie := f.begin(t)
	r := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=code&state="+state, nil)
	r.AddCookie(cookie)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "previous-token"})
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, "/", w.Header().Get("Location"))
	require.Equal(t, []string{"previous-token"}, f.host.revoked)
	for _, c := range w.Result().Cookies() {
		require.NotEqual(t, "previous-token", c.Value)
	}
}

func TestProviderOutageDoesNotBreakStartup(t *testing.T) {
	c := testConfig(t)
	c.OIDC.Issuer = "https://127.0.0.1:1"
	store, err := OpenStore(filepath.Join(t.TempDir(), "sso.db"), c, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	s, err := New(c, store, &testHost{exists: true}, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, StartPath, nil))
	require.Equal(t, "/login.html?sso_error=unavailable", w.Header().Get("Location"))
	require.True(t, s.Options().LocalLoginEnabled)
	require.Empty(t, s.pending)
}

func TestGoogleIssuerAlias(t *testing.T) {
	s := &Service{config: Config{OIDC: OIDCConfig{Issuer: "https://accounts.google.com"}}}
	require.True(t, s.matchesIssuer("accounts.google.com"))
	require.True(t, s.matchesIssuer("https://accounts.google.com"))
	require.False(t, s.matchesIssuer("https://accounts.google.com.attacker.example"))
	s.config.OIDC.Issuer = "https://other.example"
	require.False(t, s.matchesIssuer("accounts.google.com"))
}
