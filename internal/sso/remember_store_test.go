package sso

import (
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
	"strings"
	"testing"
	"time"
)

func TestRememberedStoreRestart(t *testing.T) {
	c := testConfig(t)
	path := t.TempDir() + "/sso.db"
	store, err := OpenStore(path, c, nil)
	require.NoError(t, err)
	token := strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)
	access := strings.Repeat("c", 32)
	_, _, err = store.remember("admin", "test device", access, token, 180*24*time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store, err = OpenStore(path, c, nil)
	require.NoError(t, err)
	next := strings.Repeat("a", 32) + "." + strings.Repeat("d", 64)
	_, _, err = store.refreshDevice(token, next, strings.Repeat("e", 32))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store, err = OpenStore(path, c, nil)
	require.NoError(t, err)
	defer store.Close()
	_, _, err = store.refreshDevice(token, next, strings.Repeat("f", 32))
	require.ErrorIs(t, err, errRefresh)
	invalid, err := store.Find(strings.Repeat("e", 32))
	require.NoError(t, err)
	require.Nil(t, invalid)
}

func TestRememberedRotationFailureIsAtomic(t *testing.T) {
	c := testConfig(t)
	store, err := OpenStore(t.TempDir()+"/sso.db", c, nil)
	require.NoError(t, err)
	defer store.Close()
	old := strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)
	next := strings.Repeat("a", 32) + "." + strings.Repeat("d", 64)
	access := strings.Repeat("c", 32)
	_, _, err = store.remember("admin", "device", access, old, 180*24*time.Hour)
	require.NoError(t, err)
	// A colliding access token must roll back the consumed-refresh write too.
	_, _, err = store.refreshDevice(old, next, access)
	require.Error(t, err)
	owner, err := store.refreshOwner(old)
	require.NoError(t, err)
	require.Equal(t, "admin", owner)
	session, err := store.Find(access)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, store.db.View(func(tx *bbolt.Tx) error {
		require.Nil(t, tx.Bucket(spentBucket).Get([]byte(refreshHash(old))))
		return nil
	}))
	_, _, err = store.refreshDevice(old, next, strings.Repeat("e", 32))
	require.NoError(t, err)
}

func TestRememberedAccessDeletionRevokesRefresh(t *testing.T) {
	c := testConfig(t)
	store, err := OpenStore(t.TempDir()+"/sso.db", c, nil)
	require.NoError(t, err)
	defer store.Close()
	token := strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)
	access := strings.Repeat("c", 32)
	_, _, err = store.remember("admin", "device", access, token, 180*24*time.Hour)
	require.NoError(t, err)
	require.NoError(t, store.Delete(access))
	_, err = store.refreshOwner(token)
	require.ErrorIs(t, err, errRefresh)
	devices, err := store.devices("admin", "")
	require.NoError(t, err)
	require.Empty(t, devices)
}

func TestRememberedPolicyChangesPurgeFamilies(t *testing.T) {
	for _, change := range []string{"disabled", "mapping", "lifetime", "issuer", "client", "public URL"} {
		t.Run(change, func(t *testing.T) {
			c := testConfig(t)
			path := t.TempDir() + "/sso.db"
			store, err := OpenStore(path, c, nil)
			require.NoError(t, err)
			token := strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)
			_, _, err = store.remember("admin", "device", strings.Repeat("c", 32), token, 180*24*time.Hour)
			require.NoError(t, err)
			require.NoError(t, store.Close())
			changed := c
			switch change {
			case "disabled":
				changed.Enabled = false
			case "mapping":
				changed.OIDC.Mappings = []Mapping{{Subject: "new", Username: "admin"}}
			case "lifetime":
				changed.OIDC.RememberTTL = "8760h"
			case "issuer":
				changed.OIDC.Issuer = "https://other.example.com"
			case "client":
				changed.OIDC.ClientID = "other"
			case "public URL":
				changed.OIDC.PublicURL = "https://dns.example.com/adguard/"
			}
			store, err = OpenStore(path, changed, nil)
			require.NoError(t, err)
			require.NoError(t, store.Close())
			store, err = OpenStore(path, c, nil)
			require.NoError(t, err)
			defer store.Close()
			devices, err := store.devices("admin", "")
			require.NoError(t, err)
			require.Empty(t, devices)
			_, err = store.refreshOwner(token)
			require.ErrorIs(t, err, errRefresh)
		})
	}
}
