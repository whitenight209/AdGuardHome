# Installing the web UI as an app

The SolidJS web UI supports installation as a standalone PWA. Serve it over
HTTPS with a valid certificate, or use localhost for development.

- Android Chrome: open the dashboard or login page, then choose **Install
  app** or **Add to Home screen** from the browser menu.
- Desktop Chrome or Edge: use the address bar's install button or the
  browser menu's app installation option.
- iOS Safari: choose **Share → Add to Home Screen**.

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
