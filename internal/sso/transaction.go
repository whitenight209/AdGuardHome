package sso

import (
	"crypto/subtle"
	"net/http"
	"net/netip"

	"github.com/AdguardTeam/golibs/errors"
	"golang.org/x/oauth2"
)

func (s *Service) newTransaction(remote string) (string, transaction, error) {
	peer, err := netip.ParseAddrPort(remote)
	if err != nil {
		return "", transaction{}, err
	}
	// One CSPRNG read supplies three independent 256-bit values.
	material, err := randomHex(96)
	if err != nil {
		return "", transaction{}, err
	}
	return material[:64], transaction{
		binding: material[64:128], nonce: material[128:],
		verifier: oauth2.GenerateVerifier(), peer: peer.Addr().Unmap().String(),
		expires: s.now().Add(transactionTTL),
	}, nil
}

func (s *Service) reserveTransaction(state string, t transaction) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for k, v := range s.pending {
		if !s.now().Before(v.expires) {
			delete(s.pending, k)
		} else if v.peer == t.peer {
			count++
		}
	}
	if len(s.pending) >= maxTransactions || count >= 10 {
		return false
	}
	s.pending[state] = t
	return true
}

func (s *Service) consumeTransaction(state string, r *http.Request) (transaction, error) {
	cookie, err := r.Cookie(transactionCookie)
	if err != nil {
		return transaction{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.pending[state]
	if !ok || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(t.binding)) != 1 {
		return transaction{}, errors.Error("sso: invalid browser binding")
	}
	delete(s.pending, state)
	if !s.now().Before(t.expires) {
		return transaction{}, errors.Error("sso: transaction expired")
	}
	return t, nil
}
