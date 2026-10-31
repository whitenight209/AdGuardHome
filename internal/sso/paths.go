package sso

import (
	"net/url"
	"regexp"
	"strings"
)

// Restrict prefixes to simple directory names so redirects and cookie paths
// cannot disagree about URL decoding, dot segments, or path normalization.
var basePathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+/?$`)

func validBasePath(u *url.URL) bool {
	if u.RawPath != "" {
		return false
	}
	return u.Path == "" || u.Path == "/" || basePathPattern.MatchString(u.Path)
}

// BasePath returns the configured external application directory. The reverse
// proxy strips this prefix before forwarding requests to the upstream server.
func (s *Service) BasePath() string {
	if !s.Enabled() {
		return "/"
	}
	u, err := url.Parse(s.config.OIDC.PublicURL)
	if err != nil {
		return "/"
	}
	return strings.TrimRight(u.Path, "/") + "/"
}

// ExternalPath maps a fixed application route to the public application path.
// Callers must supply an application-owned route, never a request parameter.
func (s *Service) ExternalPath(route string) string {
	return s.BasePath() + strings.TrimPrefix(route, "/")
}
