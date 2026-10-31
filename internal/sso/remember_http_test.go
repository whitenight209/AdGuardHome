package sso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	cookies := w.Result().Cookies()
	for i := len(cookies) - 1; i >= 0; i-- {
		if cookies[i].Name == name {
			return cookies[i]
		}
	}
	t.Fatalf("missing cookie %s", name)
	return nil
}

func rememberedLogin(t *testing.T, f *fixture) (*http.Cookie, *http.Cookie) {
	t.Helper()
	state, transaction := f.beginAt(t, StartPath+"?remember=1")
	response := f.finish(state, transaction)
	require.Equal(t, f.service.BasePath(), response.Header().Get("Location"))
	return responseCookie(t, response, sessionCookie), responseCookie(t, response, refreshCookie)
}

func refreshRequest(f *fixture, token *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, RefreshPath, nil)
	r.Header.Set("Origin", origin)
	if token != nil {
		r.AddCookie(token)
	}
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	return w
}

func TestRememberedCookieAndRotation(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.service.now = func() time.Time { return now }
	f.service.store.now = f.service.now
	access, refresh := rememberedLogin(t, f)
	require.Equal(t, now.Add(15*time.Minute), access.Expires)
	require.Equal(t, now.Add(180*24*time.Hour), refresh.Expires)
	require.True(t, refresh.HttpOnly)
	require.True(t, refresh.Secure)
	require.Equal(t, http.SameSiteLaxMode, refresh.SameSite)
	require.Equal(t, "/", refresh.Path)
	require.Empty(t, refresh.Domain)
	require.NoError(t, f.service.store.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(deviceBucket).ForEach(func(_, value []byte) error {
			require.NotContains(t, string(value), refresh.Value)
			require.NotContains(t, string(value), strings.Split(refresh.Value, ".")[1])
			return nil
		})
	}))
	now = now.Add(16 * time.Minute)
	expired, err := f.service.store.Find(access.Value)
	require.NoError(t, err)
	require.Nil(t, expired)
	response := refreshRequest(f, refresh, "https://dns.example.com")
	require.Equal(t, http.StatusNoContent, response.Code)
	nextAccess := responseCookie(t, response, sessionCookie)
	nextRefresh := responseCookie(t, response, refreshCookie)
	require.NotEqual(t, refresh.Value, nextRefresh.Value)
	require.NotEqual(t, access.Value, nextAccess.Value)
	require.Equal(t, refresh.Expires, nextRefresh.Expires)
	require.Equal(t, now.Add(15*time.Minute), nextAccess.Expires)
	current, err := f.service.store.Find(nextAccess.Value)
	require.NoError(t, err)
	require.NotNil(t, current)
	// Replay of a consumed refresh token revokes its entire device, including access.
	response = refreshRequest(f, refresh, "https://dns.example.com")
	require.Equal(t, http.StatusUnauthorized, response.Code)
	current, err = f.service.store.Find(nextAccess.Value)
	require.NoError(t, err)
	require.Nil(t, current)
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, nextRefresh, "https://dns.example.com").Code)
}

func TestRememberedOriginAndMethod(t *testing.T) {
	f := newFixture(t)
	_, refresh := rememberedLogin(t, f)
	for _, origin := range []string{"", "null", "https://attacker.example", "https://dns.example.com.attacker.example"} {
		response := refreshRequest(f, refresh, origin)
		require.Equal(t, http.StatusForbidden, response.Code)
		require.Empty(t, response.Result().Cookies())
	}
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, httptest.NewRequest(http.MethodGet, RefreshPath, nil))
	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	require.Equal(t, http.StatusNoContent, refreshRequest(f, refresh, "https://dns.example.com").Code)
}

func TestRememberedAbsoluteExpiryAndLifetime(t *testing.T) {
	c := testConfig(t)
	duration, err := c.RememberDuration()
	require.NoError(t, err)
	require.Equal(t, 180*24*time.Hour, duration)
	c.OIDC.RememberTTL = "8760h"
	require.NoError(t, c.Validate())
	c.OIDC.RememberTTL = "8761h"
	require.Error(t, c.Validate())
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.service.now = func() time.Time { return now }
	f.service.store.now = f.service.now
	_, refresh := rememberedLogin(t, f)
	now = refresh.Expires.Add(-time.Minute)
	response := refreshRequest(f, refresh, "https://dns.example.com")
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, refresh.Expires, responseCookie(t, response, sessionCookie).Expires)
	next := responseCookie(t, response, refreshCookie)
	now = refresh.Expires
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, next, "https://dns.example.com").Code)
}

func TestRememberedDeviceRevocationAndIsolation(t *testing.T) {
	f := newFixture(t)
	firstAccess, firstRefresh := rememberedLogin(t, f)
	secondAccess, secondRefresh := rememberedLogin(t, f)
	r := httptest.NewRequest(http.MethodGet, DevicesPath, nil)
	r.AddCookie(firstAccess)
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), firstRefresh.Value)
	var devices []DeviceInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &devices))
	require.Len(t, devices, 2)
	id := strings.Split(secondRefresh.Value, ".")[0]
	r = httptest.NewRequest(http.MethodPost, RevokeDevicePath, strings.NewReader(`{"id":"`+id+`"}`))
	r.Header.Set("Origin", "https://dns.example.com")
	r.AddCookie(firstAccess)
	w = httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code)
	invalid, err := f.service.store.Find(secondAccess.Value)
	require.NoError(t, err)
	require.Nil(t, invalid)
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, secondRefresh, "https://dns.example.com").Code)
	valid, err := f.service.store.Find(firstAccess.Value)
	require.NoError(t, err)
	require.NotNil(t, valid)
	// Logout still revokes the remembered family when its access cookie is absent.
	r = httptest.NewRequest(http.MethodGet, "/control/logout", nil)
	r.AddCookie(firstRefresh)
	require.NoError(t, f.service.LogoutRemembered(httptest.NewRecorder(), r))
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, firstRefresh, "https://dns.example.com").Code)
}

func TestRememberedUserRemovalAndBadToken(t *testing.T) {
	f := newFixture(t)
	access, refresh := rememberedLogin(t, f)
	guessed := *refresh
	guessed.Value = refresh.Value[:33] + strings.Repeat("0", 64)
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, &guessed, "https://dns.example.com").Code)
	valid, err := f.service.store.Find(access.Value)
	require.NoError(t, err)
	require.NotNil(t, valid)
	f.host.exists = false
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, refresh, "https://dns.example.com").Code)
	f.host.exists = true
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, refresh, "https://dns.example.com").Code)
}

func TestRememberedConcurrentReplay(t *testing.T) {
	f := newFixture(t)
	_, token := rememberedLogin(t, f)
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { results <- refreshRequest(f, token, "https://dns.example.com").Code })
	}
	wg.Wait()
	close(results)
	statuses := []int{}
	for result := range results {
		statuses = append(statuses, result)
	}
	require.ElementsMatch(t, []int{204, 401}, statuses)
	devices, err := f.service.store.devices("admin", "")
	require.NoError(t, err)
	require.Empty(t, devices)
}

func TestRememberedReplayDoesNotRevokeAnotherDevice(t *testing.T) {
	f := newFixture(t)
	_, first := rememberedLogin(t, f)
	secondAccess, second := rememberedLogin(t, f)
	response := refreshRequest(f, first, "https://dns.example.com")
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, first, "https://dns.example.com").Code)
	valid, err := f.service.store.Find(secondAccess.Value)
	require.NoError(t, err)
	require.NotNil(t, valid)
	require.Equal(t, http.StatusNoContent, refreshRequest(f, second, "https://dns.example.com").Code)
}

func TestRememberedOwnershipAndPrefix(t *testing.T) {
	f := newFixture(t)
	f.service.config.OIDC.PublicURL = "https://dns.example.com/adguard/"
	f.service.store.policy = f.service.config.fingerprint()
	access, refresh := rememberedLogin(t, f)
	require.Equal(t, "/adguard/", access.Path)
	require.Equal(t, "/adguard/", refresh.Path)
	id := strings.Split(refresh.Value, ".")[0]
	require.ErrorIs(t, f.service.store.revokeOwnedDevice("someone-else", id), errRefresh)
	devices, err := f.service.store.devices("someone-else", "")
	require.NoError(t, err)
	require.Empty(t, devices)
	for _, path := range []string{DevicesPath, RevokeDevicePath} {
		w := httptest.NewRecorder()
		method := http.MethodGet
		if path == RevokeDevicePath {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, path, strings.NewReader(`{"id":"`+id+`"}`))
		r.Header.Set("Origin", "https://dns.example.com")
		f.service.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, RevokeDevicePath, strings.NewReader(`{"id":"`+id+`"}`))
	r.AddCookie(access)
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	r.Header.Set("Origin", "https://dns.example.com")
	w = httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.Equal(t, -1, responseCookie(t, w, refreshCookie).MaxAge)
	require.Equal(t, -1, responseCookie(t, w, sessionCookie).MaxAge)
}

func TestRememberedOptOutRevokesPreviousDevice(t *testing.T) {
	f := newFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.service.now = func() time.Time { return now }
	f.service.store.now = f.service.now
	oldAccess, oldRefresh := rememberedLogin(t, f)
	state, transaction := f.begin(t)
	r := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=code&state="+state, nil)
	r.AddCookie(transaction)
	r.AddCookie(oldAccess)
	r.AddCookie(oldRefresh)
	w := httptest.NewRecorder()
	f.service.ServeHTTP(w, r)
	require.Equal(t, "/", w.Header().Get("Location"))
	require.Equal(t, -1, responseCookie(t, w, refreshCookie).MaxAge)
	require.Equal(t, now.Add(8*time.Hour), responseCookie(t, w, sessionCookie).Expires)
	require.Equal(t, http.StatusUnauthorized, refreshRequest(f, oldRefresh, "https://dns.example.com").Code)
}

func TestRememberedInvalidRequestsAndStorageFailure(t *testing.T) {
	f := newFixture(t)
	for _, query := range []string{"?remember=0", "?remember=true", "?remember=1&remember=1"} {
		w := httptest.NewRecorder()
		f.service.ServeHTTP(w, httptest.NewRequest(http.MethodGet, StartPath+query, nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	}
	for _, value := range []string{"", "invalid", strings.Repeat("a", 1000)} {
		w := refreshRequest(f, &http.Cookie{Name: refreshCookie, Value: value}, "https://dns.example.com")
		require.Equal(t, http.StatusUnauthorized, w.Code)
	}
	// A storage failure must not be misreported as a missing cookie and delete it.
	_, token := rememberedLogin(t, f)
	// Replace only this fixture's store with an independently closed store.
	closed, err := OpenStore(t.TempDir()+"/closed.db", f.service.config, nil)
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	original := f.service.store
	f.service.store = closed
	response := refreshRequest(f, token, "https://dns.example.com")
	f.service.store = original
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.Empty(t, response.Result().Cookies())
}
