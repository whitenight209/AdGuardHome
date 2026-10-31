# Installing the web UI as an app

The SolidJS web UI supports installation as a standalone PWA. Serve it over
HTTPS with a valid certificate, or use localhost for development.

- Android Chrome: open the dashboard or login page, then choose **Install
  app** or **Add to Home screen** from the browser menu.
- Desktop Chrome or Edge: use the address bar's install button or the
  browser menu's app installation option.
- iOS Safari: choose **Share → Add to Home Screen**.

The home-screen label uses the short name **AG Home** to fit mobile launchers.
Both manifest name fields and the Apple home-screen title use this label.

The installed app uses the existing AdGuard Home login, including SSO when
configured. It requires a connection to the server; installation does not
enable offline DNS administration or cache query logs and configuration.

The manifest and icon URLs are relative to the installation path, so a
reverse proxy can serve the UI at `/adguard/` as well as `/`. Keep the
trailing slash on the public base URL. The manifest and icons are public
static assets so installation also works before signing in.

Build the frontend and include `build/static/` in the AdGuard Home binary
using the normal build process. A running binary with an embedded frontend
must be rebuilt and restarted before the installation metadata is served.

## Login persistence

SSO uses a persistent `HttpOnly`, `Secure`, `SameSite=Lax` cookie and stores
sessions in `data/sso-sessions.db`. Closing and reopening the app, or
restarting the server with the same configuration and data, does not revoke
an unexpired session. Clearing site data or using a separate browser profile
requires another login. Browser and installed-app cookie sharing depends on
the platform; verify the installed app on the device you use.

Selecting **Keep me signed in on this device** enables a remembered device
for 180 days by default, configurable up to 365 days with
`sso.oidc.remember_ttl`. A 15-minute session is renewed automatically using a
rotating HttpOnly cookie. The absolute remembered-device deadline does not
move forward when you use the app. Without this option, the existing
8-hour SSO session policy remains in effect. Google's own session is
separate and does not extend the AdGuard Home deadline.

Use **General settings → Remembered devices** to sign out individual devices.
Reusing an old refresh token revokes that device's entire session family.
The app restores remembered login after reopening and retries expired API
requests once after renewal. Temporary renewal outages preserve the long
cookie and do not force sign-out. See the [SSO setup guide](web-ui-sso-setup.md)
for configuration and the module boundaries used for upstream sync.

When the app becomes visible again, it checks the server status. An expired
session returns to login promptly; temporary connectivity failures retain
the existing retry behavior. Ordinary API authentication failures also return
to login, preserving reverse-proxy prefixes and removing hash routes.

Logging out revokes the current server-side session, including copies of its
token in other tabs. Other devices with different sessions remain signed in.
It does not sign out of Google. Disabling SSO or changing its authorization
policy purges affected SSO sessions on the next server startup.

Automated coverage checks signed OIDC cookie issuance and expiration,
server-side persistence and revocation, recreated browser contexts, logout,
and returning to an app whose cookie is gone. A real Google login and actual
Android/iOS installed-app lifecycle still require device validation.
