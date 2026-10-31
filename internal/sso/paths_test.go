package sso

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicURLPaths(t *testing.T) {
	for _, base := range []string{"https://dns.example.com", "https://dns.example.com/", "https://dns.example.com/vault", "https://dns.example.com/vault/", "https://dns.example.com/tools/adguard/"} {
		c := testConfig(t)
		c.OIDC.PublicURL = base
		require.NoError(t, c.Validate())
	}
	for _, base := range []string{"https://dns.example.com//vault/", "https://dns.example.com/a/../vault/", "https://dns.example.com/%2Fvault/", "https://dns.example.com/vault%20path/", "https://dns.example.com/vault\\evil/", "https://dns.example.com/vault/?next=evil"} {
		c := testConfig(t)
		c.OIDC.PublicURL = base
		require.Error(t, c.Validate(), base)
	}
	var disabled *Service
	require.Equal(t, "/", disabled.BasePath())
	require.Equal(t, "/login.html", disabled.ExternalPath("/login.html"))
}

func TestSubpathOIDCRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.service.config.OIDC.PublicURL = "https://dns.example.com/vault/"
	// Match the store policy to the immutable startup config used by this fixture.
	f.service.store.policy = f.service.config.fingerprint()
	state, cookie := f.begin(t)
	require.Equal(t, "/vault/control/sso/oidc", cookie.Path)
	require.Equal(t, "/vault/control/sso/oidc/start", f.service.Options().SSOStartURL)
	require.Equal(t, "https://dns.example.com/vault/control/sso/oidc/callback", f.service.provider.oauth.RedirectURL)
	response := f.finish(state, cookie)
	require.Equal(t, "/vault/", response.Header().Get("Location"))
	for _, c := range response.Result().Cookies() {
		switch c.Name {
		case sessionCookie:
			require.Equal(t, "/vault/", c.Path)
			require.True(t, c.Secure)
		case transactionCookie:
			require.Equal(t, "/vault/control/sso/oidc", c.Path)
			require.Equal(t, -1, c.MaxAge)
		}
	}
	response = f.finish(state, cookie)
	require.Equal(t, "/vault/login.html?sso_error=expired", response.Header().Get("Location"))
	require.Equal(t, http.StatusFound, response.Code)
}
