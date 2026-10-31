package sso

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func parseCallback(r *http.Request) (url.Values, error) {
	if len(r.URL.RawQuery) > 8192 {
		return nil, errors.Error("oversized callback")
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"state", "code", "error"} {
		if len(q[key]) > 1 {
			return nil, errors.Error("duplicate callback parameter")
		}
	}
	if q.Get("state") == "" || (q.Get("code") == "") == (q.Get("error") == "") {
		return nil, errors.Error("invalid callback")
	}
	return q, nil
}

func (s *Service) getProvider(ctx context.Context) (*providerState, error) {
	s.providerMu.Lock()
	defer s.providerMu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	if s.now().Before(s.retryAfter) {
		return nil, errors.Error("sso: provider unavailable")
	}
	s.retryAfter = s.now().Add(30 * time.Second)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, s.client), s.config.OIDC.Issuer)
	if err != nil {
		return nil, errors.Error("sso: discovery failed")
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if err = p.Claims(&metadata); err != nil {
		return nil, errors.Error("sso: invalid discovery")
	}
	if err = validateEndpoints(p, metadata.JWKS); err != nil {
		return nil, err
	}

	// Use a service-lifetime context for cached key refresh, not the discovery
	// request context which is canceled when this function returns.
	verifyCtx := oidc.ClientContext(context.Background(), s.client)
	s.provider = &providerState{
		oauth:    oauth2.Config{ClientID: s.config.OIDC.ClientID, ClientSecret: s.secret, RedirectURL: strings.TrimRight(s.config.OIDC.PublicURL, "/") + CallbackPath, Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID}},
		verifier: p.VerifierContext(verifyCtx, &oidc.Config{ClientID: s.config.OIDC.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}, Now: s.now}),
	}
	return s.provider, nil
}

func validateEndpoints(p *oidc.Provider, jwks string) error {
	for _, raw := range []string{p.Endpoint().AuthURL, p.Endpoint().TokenURL, jwks} {
		if _, err := httpsURL(raw); err != nil {
			return errors.Error("sso: unsafe provider endpoint")
		}
	}
	return nil
}

func (s *Service) exchangeIdentity(ctx context.Context, code string, t transaction) (*oidc.IDToken, error) {
	p, err := s.getProvider(ctx)
	if err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(ctx, s.client)
	token, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(t.verifier))
	if err != nil {
		return nil, errors.Error("sso: exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Error("sso: missing ID token")
	}
	id, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, errors.Error("sso: verification failed")
	}
	if id.Subject == "" || id.Nonce != t.nonce || !s.matchesIssuer(id.Issuer) {
		return nil, errors.Error("sso: invalid identity")
	}
	if err = s.validateClaims(id); err != nil {
		return nil, err
	}
	return id, nil
}

func (s *Service) validateClaims(id *oidc.IDToken) error {
	var claims struct {
		AZP string `json:"azp"`
		NBF int64  `json:"nbf"`
	}
	if err := id.Claims(&claims); err != nil {
		return errors.Error("sso: invalid claims")
	}
	if claims.AZP != "" && claims.AZP != s.config.OIDC.ClientID {
		return errors.Error("sso: incorrect authorized party")
	}
	if len(id.Audience) > 1 && claims.AZP != s.config.OIDC.ClientID {
		return errors.Error("sso: missing authorized party")
	}
	if claims.NBF != 0 && s.now().Before(time.Unix(claims.NBF, 0)) {
		return errors.Error("sso: token not yet valid")
	}
	if id.IssuedAt.After(s.now().Add(time.Minute)) {
		return errors.Error("sso: invalid issue time")
	}
	return nil
}

// Google documents both spellings; go-oidc validates the same narrow alias.
// All authorization mappings still belong to the configured canonical issuer.
func (s *Service) matchesIssuer(issuer string) bool {
	if issuer == s.config.OIDC.Issuer {
		return true
	}
	return s.config.OIDC.Issuer == "https://accounts.google.com" && issuer == "accounts.google.com"
}
