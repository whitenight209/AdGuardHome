package home

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/aghuser"
	"github.com/AdguardTeam/AdGuardHome/internal/sso"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// ssoSessions adapts the isolated SSO store to the upstream session contract.
// Local session creation and persistence remain owned by aghuser.
type ssoSessions struct {
	local   aghuser.SessionStorage
	store   *sso.Store
	users   aghuser.DB
	enabled bool
}

var (
	_ aghuser.SessionStorage = (*ssoSessions)(nil)
	_ sso.Host               = (*ssoSessions)(nil)
)

func (a *auth) initSSO(ctx context.Context, conf *authConfig) error {
	c := conf.sso
	if err := c.Validate(); err != nil {
		return err
	}
	if err := a.validateSSOUsers(ctx, conf); err != nil {
		return err
	}

	store, err := sso.OpenStore(filepath.Join(filepath.Dir(conf.dbFilename), "sso-sessions.db"), c, nil)
	if err != nil {
		return err
	}
	sessions := &ssoSessions{local: a.sessions, store: store, users: a.users, enabled: c.Enabled}
	service, err := sso.New(c, store, sessions, conf.baseLogger.With("component", "sso"))
	if err != nil {
		_ = store.Close()
		return err
	}
	a.sso = service
	a.sessions = sessions
	return nil
}

func (s *ssoSessions) New(ctx context.Context, u *aghuser.User) (*aghuser.Session, error) {
	session, err := s.local.New(ctx, u)
	if err != nil {
		return nil, err
	}
	other, err := s.store.Find(hex.EncodeToString(session.Token[:]))
	if err != nil || other != nil {
		_ = s.local.DeleteByToken(ctx, session.Token)
		return nil, fmt.Errorf("sso: cannot safely issue local session")
	}
	return session, nil
}

func (s *ssoSessions) FindByToken(ctx context.Context, t aghuser.SessionToken) (*aghuser.Session, error) {
	local, err := s.local.FindByToken(ctx, t)
	if err != nil {
		return nil, err
	}
	if !s.enabled {
		return local, nil
	}
	external, err := s.store.Find(hex.EncodeToString(t[:]))
	if err != nil {
		return nil, err
	}
	if external == nil {
		return local, nil
	}
	if local != nil {
		return nil, fmt.Errorf("sso: ambiguous session token")
	}
	u, err := s.users.ByLogin(ctx, aghuser.Login(external.Login))
	if err != nil || u == nil {
		return nil, err
	}
	return &aghuser.Session{Token: t, UserLogin: u.Login, UserID: u.ID, Expire: external.Expires}, nil
}

func (s *ssoSessions) DeleteByToken(ctx context.Context, t aghuser.SessionToken) error {
	return errors.Join(s.local.DeleteByToken(ctx, t), s.store.Delete(hex.EncodeToString(t[:])))
}
func (s *ssoSessions) Close() error { return errors.Join(s.local.Close(), s.store.Close()) }
func (s *ssoSessions) UserExists(ctx context.Context, login string) (bool, error) {
	u, err := s.users.ByLogin(ctx, aghuser.Login(login))
	return u != nil, err
}

func (s *ssoSessions) LocalTokenExists(ctx context.Context, token string) (bool, error) {
	t, err := sessionTokenFromHex(token)
	if err != nil {
		return false, err
	}
	session, err := s.local.FindByToken(ctx, t)
	return session != nil, err
}

func (s *ssoSessions) RevokeSession(ctx context.Context, token string) error {
	t, err := sessionTokenFromHex(token)
	if err != nil {
		return nil
	}
	return s.DeleteByToken(ctx, t)
}

// handleSSOLogout adds remembered-device revocation around the upstream handler.
func (web *webAPI) handleSSOLogout(w http.ResponseWriter, r *http.Request) {
	if err := web.auth.sso.LogoutRemembered(w, r); err != nil {
		web.logger.ErrorContext(r.Context(), "revoking remembered device", slogutil.KeyError, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	web.handleLogout(w, r)
}

func (web *webAPI) registerSSOHandlers() {
	for _, path := range []string{sso.ConfigPath, sso.StartPath, sso.CallbackPath, sso.RefreshPath, sso.DevicesPath, sso.RevokeDevicePath} {
		web.conf.mux.Handle(path, web.postInstallHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			web.auth.sso.ServeHTTP(w, r)
		})))
	}
}

func (a *auth) validateSSOUsers(ctx context.Context, conf *authConfig) error {
	if !conf.sso.Enabled {
		return nil
	}
	if conf.isGLiNet || len(conf.users) == 0 {
		return fmt.Errorf("sso requires local users and is incompatible with GL.iNet authentication")
	}
	for _, m := range conf.sso.OIDC.Mappings {
		u, err := a.users.ByLogin(ctx, aghuser.Login(m.Username))
		if err != nil {
			return err
		}
		if u == nil {
			return fmt.Errorf("sso mapping references an unknown local user")
		}
	}
	return nil
}

// redactSSORequestURI runs outside the shared request logger. Keep URL.RawQuery
// for OIDC processing, but never expose authorization codes in request logs.
func redactSSORequestURI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sso.PublicPath(r.URL.Path) {
			r = r.Clone(r.Context())
			r.RequestURI = r.URL.Path
		}
		next.ServeHTTP(w, r)
	})
}

// wrapSSORedirects adapts upstream login-page redirects without teaching the
// upstream middleware about proxy paths. Only fixed HTML entry points wrap.
func (web *webAPI) wrapSSORedirects(next http.Handler) http.Handler {
	base := web.auth.sso.BasePath()
	if base == "/" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/index.html", "/login.html", "/forgot_password.html":
			w = &ssoRedirectWriter{ResponseWriter: w, base: base}
		}
		next.ServeHTTP(w, r)
	})
}

type ssoRedirectWriter struct {
	http.ResponseWriter
	base    string
	written bool
}

func (w *ssoRedirectWriter) WriteHeader(code int) {
	if !w.written {
		location := w.Header().Get("Location")
		if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
			w.Header().Set("Location", w.base+strings.TrimPrefix(location, "/"))
		}
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *ssoRedirectWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *ssoRedirectWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
