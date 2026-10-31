// Package sso implements optional web single sign-on independently of the host.
package sso

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Config is the optional YAML configuration. Its zero value disables SSO.
type Config struct {
	Enabled bool       `yaml:"enabled"`
	OIDC    OIDCConfig `yaml:"oidc"`
}

// OIDCConfig describes one confidential OpenID Connect client.
type OIDCConfig struct {
	DisplayName      string    `yaml:"display_name"`
	Issuer           string    `yaml:"issuer"`
	ClientID         string    `yaml:"client_id"`
	ClientSecretFile string    `yaml:"client_secret_file"`
	PublicURL        string    `yaml:"public_url"`
	SessionTTL       string    `yaml:"session_ttl"`
	Mappings         []Mapping `yaml:"mappings"`
}

// Mapping explicitly authorizes a provider subject as a local administrator.
type Mapping struct {
	Subject  string `yaml:"subject"`
	Username string `yaml:"username"`
}

// TTL returns the fixed lifetime of an SSO session.
func (c Config) TTL() (time.Duration, error) {
	if c.OIDC.SessionTTL == "" {
		return 8 * time.Hour, nil
	}
	d, err := time.ParseDuration(c.OIDC.SessionTTL)
	if err != nil || d <= 0 || d > 24*time.Hour {
		return 0, fmt.Errorf("sso: session_ttl must be positive and at most 24h")
	}
	return d, nil
}

// Validate checks syntax; the host adapter separately checks local users.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if _, err := httpsURL(c.OIDC.Issuer); err != nil {
		return fmt.Errorf("sso: invalid issuer: %w", err)
	}
	u, err := httpsURL(c.OIDC.PublicURL)
	if err != nil {
		return fmt.Errorf("sso: invalid public_url: %w", err)
	}
	if !validBasePath(u) {
		return fmt.Errorf("sso: public_url must use a root or simple directory path")
	}

	if strings.TrimSpace(c.OIDC.ClientID) == "" || c.OIDC.ClientSecretFile == "" {
		return fmt.Errorf("sso: client_id and client_secret_file are required")
	}
	if err = validateMappings(c.OIDC.Mappings); err != nil {
		return err
	}
	_, err = c.TTL()
	return err
}

func httpsURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return nil, fmt.Errorf("expected an HTTPS URL without credentials, query or fragment")
	}
	return u, nil
}

func validateMappings(mappings []Mapping) error {
	if len(mappings) == 0 {
		return fmt.Errorf("sso: explicit subject mappings are required")
	}
	seen := map[string]bool{}
	for _, m := range mappings {
		if m.Subject == "" || m.Username == "" || seen[m.Subject] {
			return fmt.Errorf("sso: mappings must contain unique nonempty subjects and usernames")
		}
		seen[m.Subject] = true
	}
	return nil
}

func (c Config) fingerprint() string {
	mappings := append([]Mapping(nil), c.OIDC.Mappings...)
	slices.SortFunc(mappings, func(a, b Mapping) int { return cmp.Compare(a.Subject, b.Subject) })
	ttl, _ := c.TTL()
	data, _ := json.Marshal(struct {
		Issuer, ClientID, PublicURL string
		TTL                         time.Duration
		Mappings                    []Mapping
	}{c.OIDC.Issuer, c.OIDC.ClientID, c.OIDC.PublicURL, ttl, mappings})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
