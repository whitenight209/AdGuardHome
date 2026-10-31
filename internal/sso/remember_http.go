package sso

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (s *Service) clearRefresh(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Path: s.BasePath(), MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// LogoutRemembered revokes this device even when its short access cookie expired.
func (s *Service) LogoutRemembered(w http.ResponseWriter, r *http.Request) error {
	if !s.Enabled() {
		return nil
	}
	cookie, err := r.Cookie(refreshCookie)
	if err == nil {
		if err = s.store.revokeRefresh(cookie.Value); err != nil {
			return err
		}
	}
	s.clearRefresh(w)
	return nil
}

func (s *Service) setRefresh(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: token, Path: s.BasePath(), Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

func (s *Service) rememberSession(w http.ResponseWriter, r *http.Request, login string, access *http.Cookie) error {
	id, err := randomHex(16)
	if err != nil {
		return err
	}
	secret, err := randomHex(32)
	if err != nil {
		return err
	}
	lifetime, err := s.config.RememberDuration()
	if err != nil {
		return err
	}
	if err = s.store.Delete(access.Value); err != nil {
		return err
	}
	agent := r.UserAgent()
	if len(agent) > 256 {
		agent = agent[:256]
	}
	token := id + "." + secret
	short, absolute, err := s.store.remember(login, agent, access.Value, token, lifetime)
	if err != nil {
		return err
	}
	access.Expires = short
	s.setRefresh(w, token, absolute)
	return nil
}

func (s *Service) sameOrigin(r *http.Request) bool {
	u, err := url.Parse(s.config.OIDC.PublicURL)
	return err == nil && r.Header.Get("Origin") == u.Scheme+"://"+u.Host
}

func (s *Service) serveRemember(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		http.NotFound(w, r)
		return
	}
	method := http.MethodPost
	if r.URL.Path == DevicesPath {
		method = http.MethodGet
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if method == http.MethodPost && !s.sameOrigin(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.URL.Path == RefreshPath {
		s.refresh(w, r)
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	session, err := s.store.Find(cookie.Value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if session == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	exists, err := s.host.UserExists(r.Context(), session.Login)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Path == DevicesPath {
		devices, err := s.store.devices(session.Login, session.DeviceID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(devices)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || len(body.ID) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err = s.store.revokeOwnedDevice(session.Login, body.ID); err != nil {
		if errors.Is(err, errRefresh) {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	if body.ID == session.DeviceID {
		s.clearRememberCookies(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) clearRememberCookies(w http.ResponseWriter) {
	s.clearRefresh(w)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: s.BasePath(), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Service) refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookie)
	if err != nil || len(cookie.Value) != 97 || strings.Count(cookie.Value, ".") != 1 {
		s.clearRememberCookies(w)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	login, err := s.store.refreshOwner(cookie.Value)
	if err != nil {
		if errors.Is(err, errRefresh) {
			s.clearRememberCookies(w)
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	exists, err := s.host.UserExists(r.Context(), login)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !exists {
		if err = s.store.revokeRefresh(cookie.Value); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.clearRememberCookies(w)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	secret, err := randomHex(32)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	next := strings.SplitN(cookie.Value, ".", 2)[0] + "." + secret
	access, err := randomHex(16)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	collision, err := s.host.LocalTokenExists(r.Context(), access)
	if err != nil || collision {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	short, absolute, err := s.store.refreshDevice(cookie.Value, next, access)
	if err != nil {
		if errors.Is(err, errRefresh) {
			s.clearRememberCookies(w)
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	s.setRefresh(w, next, absolute)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: access, Path: s.BasePath(), Expires: short, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}
