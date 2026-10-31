package sso

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"go.etcd.io/bbolt"
)

var sessionBucket = []byte("sso-sessions-v1")

// Session contains only local authorization information, never provider tokens.
type Session struct {
	Login    string    `json:"login"`
	DeviceID string    `json:"device_id,omitempty"`
	Expires  time.Time `json:"expires"`
	Policy   string    `json:"policy"`
}

// Store owns the separate embedded SSO session database.
type Store struct {
	db     *bbolt.DB
	policy string
	now    func() time.Time
}

// OpenStore opens SSO persistence and permanently purges obsolete policies.
// Disabled startup does not create a file but clears an existing store.
func OpenStore(path string, config Config, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if !config.Enabled {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return &Store{now: now}, nil
		} else if err != nil {
			return nil, err
		}
	}
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("sso: open session store: %w", err)
	}
	s := &Store{db: db, policy: config.fingerprint(), now: now}
	err = db.Update(func(tx *bbolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(sessionBucket)
		if e != nil {
			return e
		}
		if e := s.purge(b, config.Enabled); e != nil {
			return e
		}
		return s.initDevices(tx, config.Enabled)
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Find returns a valid session or nil. Database failures are never misses.
func (s *Store) Find(token string) (*Session, error) {
	if s.db == nil {
		return nil, nil
	}
	var sess *Session
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(sessionBucket).Get([]byte(token))
		if v == nil {
			return nil
		}
		var record Session
		if e := json.Unmarshal(v, &record); e != nil {
			return e
		}
		if record.Policy == s.policy && s.now().Before(record.Expires) {
			if record.DeviceID != "" && !s.deviceValid(tx, record.DeviceID) {
				return nil
			}
			sess = &record
		}
		return nil
	})
	return sess, err
}

func (s *Store) put(token string, sess Session) error {
	if s.db == nil {
		return fmt.Errorf("sso: store is disabled")
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(sessionBucket)
		if purgeErr := s.purge(b, true); purgeErr != nil {
			return purgeErr
		}
		if b.Stats().KeyN >= 4096 {
			return fmt.Errorf("sso: session capacity reached")
		}
		if b.Get([]byte(token)) != nil {
			return fmt.Errorf("sso: token collision")
		}
		return b.Put([]byte(token), data)
	})
}

// Delete revokes a session and is safe for an unknown token.
func (s *Store) Delete(token string) error {
	if s.db == nil {
		return nil
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(sessionBucket)
		var record Session
		if v := b.Get([]byte(token)); v != nil {
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			if record.DeviceID != "" {
				return s.revokeDevice(tx, record.DeviceID)
			}
		}
		return b.Delete([]byte(token))
	})
}

// Close releases the store.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) purge(b *bbolt.Bucket, enabled bool) error {
	cursor := b.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var sess Session
		valid := json.Unmarshal(v, &sess) == nil && sess.Policy == s.policy && s.now().Before(sess.Expires)
		if !enabled || !valid {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}
