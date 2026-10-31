package sso

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSessionPersistenceAndRevocation(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "sso.db")
	now := time.Now()
	clock := func() time.Time { return now }
	store, err := OpenStore(path, c, clock)
	require.NoError(t, err)
	require.NoError(t, store.put("token", Session{Login: "admin", Expires: now.Add(time.Hour), Policy: c.fingerprint()}))
	require.NoError(t, store.Close())
	store, err = OpenStore(path, c, clock)
	require.NoError(t, err)
	sess, err := store.Find("token")
	require.NoError(t, err)
	require.NotNil(t, sess)
	require.Error(t, store.put("token", *sess))
	require.NoError(t, store.Close())
	// A policy change permanently removes prior sessions, even if changed back.
	changed := c
	changed.OIDC.ClientID = "other"
	store, err = OpenStore(path, changed, clock)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store, err = OpenStore(path, c, clock)
	require.NoError(t, err)
	sess, err = store.Find("token")
	require.NoError(t, err)
	require.Nil(t, sess)
	require.NoError(t, store.put("token", Session{Login: "admin", Expires: now.Add(time.Hour), Policy: c.fingerprint()}))
	now = now.Add(time.Hour)
	sess, err = store.Find("token")
	require.NoError(t, err)
	require.Nil(t, sess)
	require.NoError(t, store.Close())
}

func TestDisablePermanentlyPurgesSessions(t *testing.T) {
	c := testConfig(t)
	path := filepath.Join(t.TempDir(), "sso.db")
	store, err := OpenStore(path, c, nil)
	require.NoError(t, err)
	require.NoError(t, store.put("token", Session{Login: "admin", Expires: time.Now().Add(time.Hour), Policy: c.fingerprint()}))
	require.NoError(t, store.Close())
	store, err = OpenStore(path, Config{}, nil)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store, err = OpenStore(path, c, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	sess, err := store.Find("token")
	require.NoError(t, err)
	require.Nil(t, sess)
}

func TestDisabledDoesNotCreateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sso.db")
	store, err := OpenStore(path, Config{}, nil)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
}

func TestConfigValidation(t *testing.T) {
	require.NoError(t, Config{}.Validate())
	cases := map[string]func(*Config){
		"http issuer":    func(c *Config) { c.OIDC.Issuer = "http://example.com" },
		"userinfo":       func(c *Config) { c.OIDC.PublicURL = "https://user:pass@example.com" },
		"dot path":       func(c *Config) { c.OIDC.PublicURL = "https://example.com/vault/../other" },
		"query":          func(c *Config) { c.OIDC.PublicURL = "https://example.com/?x=y" },
		"empty mappings": func(c *Config) { c.OIDC.Mappings = nil },
		"duplicate":      func(c *Config) { c.OIDC.Mappings = append(c.OIDC.Mappings, c.OIDC.Mappings[0]) },
		"ttl":            func(c *Config) { c.OIDC.SessionTTL = "25h" },
		"negative ttl":   func(c *Config) { c.OIDC.SessionTTL = "-1h" },
		"missing client": func(c *Config) { c.OIDC.ClientID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) { c := testConfig(t); mutate(&c); require.Error(t, c.Validate()) })
	}
	c := testConfig(t)
	require.NoError(t, c.Validate())
	ttl, err := c.TTL()
	require.NoError(t, err)
	require.Equal(t, 8*time.Hour, ttl)
}
