package sso

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

const rememberedAccessTTL = 15 * time.Minute

var (
	deviceBucket = []byte("sso-devices-v1")
	spentBucket  = []byte("sso-spent-refresh-v1")
	errRefresh   = errors.New("sso: invalid refresh token")
)

// DeviceInfo contains no credentials and can be shown to its owner.
type DeviceInfo struct {
	ID        string    `json:"id"`
	UserAgent string    `json:"user_agent"`
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used"`
	Expires   time.Time `json:"expires"`
	Current   bool      `json:"current"`
}

type rememberedDevice struct {
	DeviceInfo
	Login       string
	Policy      string
	RefreshHash string
	AccessToken string
	Rotations   uint64
}

type spentRefresh struct {
	DeviceID string
	Expires  time.Time
}

func refreshHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) initDevices(tx *bbolt.Tx, enabled bool) error {
	devices, err := tx.CreateBucketIfNotExists(deviceBucket)
	if err != nil {
		return err
	}
	spent, err := tx.CreateBucketIfNotExists(spentBucket)
	if err != nil {
		return err
	}
	c := devices.Cursor()
	var obsolete []string
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var d rememberedDevice
		if !enabled || json.Unmarshal(v, &d) != nil || d.Policy != s.policy || !s.now().Before(d.Expires) {
			obsolete = append(obsolete, string(k))
		}
	}
	for _, id := range obsolete {
		if err = s.revokeDevice(tx, id); err != nil {
			return err
		}
	}
	c = spent.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		var record spentRefresh
		if json.Unmarshal(v, &record) != nil || devices.Get([]byte(record.DeviceID)) == nil || !s.now().Before(record.Expires) {
			if err = c.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) deviceValid(tx *bbolt.Tx, id string) bool {
	var d rememberedDevice
	value := tx.Bucket(deviceBucket).Get([]byte(id))
	return value != nil && json.Unmarshal(value, &d) == nil && d.Policy == s.policy && s.now().Before(d.Expires)
}

func (s *Store) revokeDevice(tx *bbolt.Tx, id string) error {
	b := tx.Bucket(deviceBucket)
	var d rememberedDevice
	if v := b.Get([]byte(id)); v != nil {
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		if err := tx.Bucket(sessionBucket).Delete([]byte(d.AccessToken)); err != nil {
			return err
		}
	}
	return b.Delete([]byte(id))
}

func (s *Store) putDevice(tx *bbolt.Tx, d rememberedDevice, access string) (time.Time, error) {
	expires := minTime(s.now().Add(rememberedAccessTTL), d.Expires)
	record, err := json.Marshal(Session{Login: d.Login, Expires: expires, Policy: s.policy, DeviceID: d.ID})
	if err != nil {
		return time.Time{}, err
	}
	sessions := tx.Bucket(sessionBucket)
	if sessions.Get([]byte(access)) != nil {
		return time.Time{}, fmt.Errorf("sso: token collision")
	}
	if err = sessions.Delete([]byte(d.AccessToken)); err != nil {
		return time.Time{}, err
	}
	if err = sessions.Put([]byte(access), record); err != nil {
		return time.Time{}, err
	}
	d.AccessToken = access
	data, err := json.Marshal(d)
	if err != nil {
		return time.Time{}, err
	}
	return expires, tx.Bucket(deviceBucket).Put([]byte(d.ID), data)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Store) remember(login, agent, access, refresh string, lifetime time.Duration) (time.Time, time.Time, error) {
	id := strings.SplitN(refresh, ".", 2)[0]
	absolute := s.now().Add(lifetime)
	var accessExpires time.Time
	err := s.db.Update(func(tx *bbolt.Tx) error {
		if err := s.initDevices(tx, true); err != nil {
			return err
		}
		b := tx.Bucket(deviceBucket)
		if b.Stats().KeyN >= 1024 || b.Get([]byte(id)) != nil {
			return fmt.Errorf("sso: device capacity or collision")
		}
		d := rememberedDevice{
			DeviceInfo: DeviceInfo{ID: id, UserAgent: agent, Created: s.now(), LastUsed: s.now(), Expires: absolute},
			Login:      login, Policy: s.policy, RefreshHash: refreshHash(refresh),
		}
		var err error
		accessExpires, err = s.putDevice(tx, d, access)
		return err
	})
	return accessExpires, absolute, err
}

// refreshDevice commits replay revocation even though the caller receives an error.
// Consumed token hashes are retained until the family's absolute deadline.
func (s *Store) refreshDevice(old, next, access string) (time.Time, time.Time, error) {
	var accessExpires, absolute time.Time
	invalid := false
	err := s.db.Update(func(tx *bbolt.Tx) error {
		id := strings.SplitN(old, ".", 2)[0]
		b := tx.Bucket(deviceBucket)
		var d rememberedDevice
		v := b.Get([]byte(id))
		if v == nil || json.Unmarshal(v, &d) != nil || !s.deviceValid(tx, id) {
			invalid = true
			return nil
		}
		digest := refreshHash(old)
		spent := tx.Bucket(spentBucket)
		if d.RefreshHash != digest {
			invalid = true
			if spent.Get([]byte(digest)) != nil {
				return s.revokeDevice(tx, id)
			}
			return nil
		}
		if d.Rotations >= 65536 {
			return fmt.Errorf("sso: refresh capacity reached")
		}
		data, err := json.Marshal(spentRefresh{DeviceID: id, Expires: d.Expires})
		if err != nil {
			return err
		}
		if err = spent.Put([]byte(digest), data); err != nil {
			return err
		}
		d.Rotations++
		d.RefreshHash = refreshHash(next)
		d.LastUsed = s.now()
		absolute = d.Expires
		accessExpires, err = s.putDevice(tx, d, access)
		return err
	})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if invalid {
		return time.Time{}, time.Time{}, errRefresh
	}
	return accessExpires, absolute, nil
}

func (s *Store) refreshOwner(token string) (string, error) {
	var login string
	err := s.db.View(func(tx *bbolt.Tx) error {
		id := strings.SplitN(token, ".", 2)[0]
		var d rememberedDevice
		v := tx.Bucket(deviceBucket).Get([]byte(id))
		if v == nil || json.Unmarshal(v, &d) != nil || !s.deviceValid(tx, id) {
			return errRefresh
		}
		// Permit a consumed token to reach the atomic replay check, but never a guess.
		digest := refreshHash(token)
		if d.RefreshHash != digest && tx.Bucket(spentBucket).Get([]byte(digest)) == nil {
			return errRefresh
		}
		login = d.Login
		return nil
	})
	return login, err
}

func (s *Store) revokeRefresh(token string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		id := strings.SplitN(token, ".", 2)[0]
		var d rememberedDevice
		v := tx.Bucket(deviceBucket).Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		digest := refreshHash(token)
		if digest == d.RefreshHash || tx.Bucket(spentBucket).Get([]byte(digest)) != nil {
			return s.revokeDevice(tx, id)
		}
		return nil
	})
}

func (s *Store) devices(login, current string) ([]DeviceInfo, error) {
	list := []DeviceInfo{}
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(deviceBucket).ForEach(func(k, v []byte) error {
			var d rememberedDevice
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			if d.Login == login && s.deviceValid(tx, string(k)) {
				d.Current = d.ID == current
				list = append(list, d.DeviceInfo)
			}
			return nil
		})
	})
	return list, err
}

func (s *Store) revokeOwnedDevice(login, id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		var d rememberedDevice
		v := tx.Bucket(deviceBucket).Get([]byte(id))
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &d); err != nil {
			return err
		}
		if d.Login != login {
			return errRefresh
		}
		return s.revokeDevice(tx, id)
	})
}
