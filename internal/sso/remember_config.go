package sso

import (
	"fmt"
	"time"
)

// RememberDuration is the absolute lifetime of a remembered device.
func (c Config) RememberDuration() (time.Duration, error) {
	if c.OIDC.RememberTTL == "" {
		return 180 * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(c.OIDC.RememberTTL)
	if err != nil || d < time.Hour || d > 365*24*time.Hour {
		return 0, fmt.Errorf("sso: remember_ttl must be between 1h and 8760h")
	}
	return d, nil
}
