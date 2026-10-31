# Web UI SSO setup for this fork

The implementation is opt-in and uses OIDC Authorization Code with PKCE.
Keep a local password account for recovery. All mapped users are full admins;
SSO does not enforce provider MFA on local password or Basic authentication.

## Google Cloud project and client

Created and verified on 2026-10-25:

- Display name: `homelab`
- Project ID: `homelab-whitenight209`
- Project number: `792562849883`
- State: `ACTIVE`

The project was created using `gcloud projects create`. No billing account,
paid resources, or service-account keys were configured for this task.
The operator has created the `adguardhome` web OAuth client. A local
`secret` file is referenced by the git-ignored `AdGuardHome.yaml.sso` fragment.
Both files use mode `0600`; no secret value is stored in this documentation.
The confirmed Google account was mapped using the subject from a
cryptographically verified Google ID token obtained through authenticated
`gcloud`. The fragment assumes the existing local administrator is `admin`.
It is disabled until the public route is resolved: the supplied `/vault/` URL
currently serves Vaultwarden. Do not replace that route accidentally.

Google's `gcloud iam oauth-clients` manages Workforce Identity Federation
clients, not standard Google Sign-In clients. Google directs standard client
creation to the Console; see the
[official limitation](https://docs.cloud.google.com/iam/docs/workforce-manage-oauth-app).
Do not substitute an IAP or Workforce client for this application.

In [Google Auth Platform](https://console.cloud.google.com/auth/overview?project=homelab-whitenight209):

1. Configure branding with an application name and the operator's support and
   contact email. Choose the audience appropriate to the Google account. For
   a personal account this is External; restrict initial testing to intended
   test users if the app remains in testing mode.
2. Create a **Web application** client named `adguardhome`.
3. Register exactly `https://YOUR-DNS-HOST/control/sso/oidc/callback` as the
   authorized redirect URI, including the chosen application prefix. The
   supplied hostname is `whitenight209.asuscomm.com`; its `/vault/` prefix is
   already in use, so confirm a free route before updating this value.
   No JavaScript origin is needed for this server-side code flow.
4. Save the client ID and the downloaded client secret securely. Put only the
   client secret value (not the entire downloaded JSON) in the secret file.
5. Obtain each intended user's verified Google `sub` identifier. Never use an
   email address as the mapping key. For the currently authenticated CLI user,
   `gcloud auth print-identity-token` obtains an ID token; inspect its `sub`
   locally without uploading or logging the token. This is an operator setup
   step, not a substitute for the application's own ID-token verification.

See [Google's OIDC setup](https://developers.google.com/identity/openid-connect/openid-connect)
for the provider's client and redirect requirements. Real Google
interoperability remains to be verified after the client is provisioned.

## AdGuard Home configuration

Stop the service before editing its YAML. Preserve existing `users` and add:

```yaml
sso:
  enabled: true
  oidc:
    display_name: Google
    issuer: https://accounts.google.com
    client_id: YOUR-CLIENT-ID.apps.googleusercontent.com
    client_secret_file: /etc/AdGuardHome/oidc-client-secret
    public_url: https://YOUR-DNS-HOST/
    session_ttl: 8h
    remember_ttl: 4320h # 180 days; use 8760h for 365 days
    mappings:
      - subject: "YOUR-GOOGLE-SUB"
        username: admin
```

`admin` must already exist in `users`. The secret file must be readable only
by the service account (for example, mode `0600`). Do not commit credentials.
The private local fragment references the workstation's absolute `secret`
path. For Raspberry Pi deployment, copy the secret securely to a protected
path on the Pi and change `client_secret_file` accordingly; the workstation
path will not work on the Pi. This fragment is merged into an existing config,
not used as a complete replacement for DNS and local-user settings.

Restart after changing configuration or rotating the secret. The service
validates mappings and reads the secret before accepting SSO traffic.

HTTPS public URLs may use a root or a simple directory prefix, such as
`https://dns.example.com/adguard/`. For a prefix, configure the reverse proxy
to strip `/adguard` before forwarding to AdGuard Home: the external callback
`/adguard/control/sso/oidc/callback` reaches `/control/sso/oidc/callback` on the
backend. Redirect `/adguard` to `/adguard/` at the proxy. Do not rewrite cookie
paths or Location headers again: this fork already uses the configured
prefix for authentication cookies and redirects. Public prefixes permit only
ASCII letters, digits, hyphens, underscores, and directory separators. Do not
construct the callback from arbitrary incoming Host or forwarded headers.
Use the HTTPS URL for local login too when SSO is enabled: all login cookies
then have Secure set. Configure proxy access logs to omit callback query
strings; the application redacts these before its shared request logger.

The server needs outbound HTTPS to Google's discovery, token, and signing-key
endpoints. Provider outages prevent new SSO logins, but do not prevent DNS or
local authentication from starting. Error pages show generic messages.

SSO sessions use `data/sso-sessions.db`; local sessions still use
`data/sessions.db`. Back up both with the service stopped. No external database
service is needed. Without **Keep me signed in on this device**, SSO sessions retain the
existing fixed lifetime: eight hours by default, with a maximum of 24 hours.
With that option selected, the app issues a 15-minute access session and a
separate rotating device cookie. The remembered-device lifetime defaults to
180 days (`4320h`) and is configurable from one hour up to 365 days (`8760h`)
using `sso.oidc.remember_ttl`. Go duration syntax uses hours, not `d` or `y`.
The absolute deadline never slides forward during renewal.

Both cookies are host-only, `HttpOnly`, `Secure`, and `SameSite=Lax`. The
refresh cookie is scoped to the configured application path. Only a digest
of the random refresh credential is stored in the device database. These
are AdGuard Home credentials, not Google access or refresh tokens. Provider
tokens are not persisted and Google is not contacted during device renewal.

Renewal requires a same-origin POST to `/control/sso/refresh` with an exact
Origin match to `public_url`. Access failures retry once after renewal.
Concurrent requests share one renewal operation; Web Locks serialize it
across tabs and recheck the shared access cookie before rotating. When an
expired access cookie redirects a reopened app to login, the login page
tries device renewal before requiring Google sign-in again.

Every successful renewal replaces both credentials and invalidates the
previous access session. Reusing a consumed refresh credential revokes its
entire device family. Expiration, removal of the local mapped user, SSO
disabling, or authorization-policy changes also invalidate device access.
Device renewal does not recheck Google's account status: revoke a device
explicitly when access must end before its absolute deadline.

Open **General settings → Remembered devices** to view your SSO devices and
sign out one device, including the current device. Device listing and
revocation are restricted to the signed-in SSO user's own devices. Logout
revokes the current device even if its access cookie has already expired.
Other independently signed-in devices are not affected.

To revoke all SSO sessions, set `sso.enabled: false` and restart. A restart
also applies mapping, issuer, client-ID, public-URL, or lifetime changes and
purges sessions created under the previous policy. Re-enabling SSO does not
restore purged sessions. Changing only the secret does not revoke sessions.
Logout only ends the current AdGuard Home session; the Google login remains.
Google account suspension takes effect on the next SSO login, not immediately
for an already-issued application session.

## Keeping upstream synchronization small

Remembered-device behavior is isolated in:

- `internal/sso/remember_config.go`: long-session duration policy.
- `internal/sso/remember_store.go`: device persistence, rotation and replay
  detection; no HTTP or host dependencies.
- `internal/sso/remember_http.go`: cookie and HTTP handling.
- `client_v2/src/api/sessionRenewal.ts`: browser renewal coordination.
- `client_v2/src/features/sso/`: login choice and device-management UI.

The existing auth store and SSO callback contain only integration points.
The general settings page mounts the separate device-management component.
The OpenAPI spec owns the generated client and types. Tests live alongside
these boundaries instead of adding remember-me policy to DNS code.

The policy fingerprint includes remembered-device lifetime. Deploying this
version requires one new login for sessions issued under the old policy.
Rebuild the embedded frontend and restart the binary after deployment.
Existing sessions are not silently upgraded to long-lived credentials.

## Raspberry Pi 4 builds

Check `uname -m` on the Raspberry Pi:

| OS architecture | Artifact |
| --- | --- |
| `aarch64` (64-bit) | `AdGuardHome-linux-arm64` |
| `armv7l` (32-bit) | `AdGuardHome-linux-armv7` |

Hardware capability alone does not determine which binary matches the OS.
Both targets are statically linked Go builds with embedded frontend assets.
ARMv7 uses `GOARCH=arm GOARM=7`; ARM64 uses `GOARCH=arm64`.

The upstream workflows require an upstream organization and the `team-go`
runner, so they do not build this fork. The separate
[Homelab ARM workflow](../.github/workflows/homelab-arm.yaml) uses ordinary
GitHub-hosted Ubuntu runners, tests on x86-64, cross-compiles both targets,
and uploads tarballs plus SHA-256 checksum files. It does not deploy, publish
releases, or need Google credentials. Native ARM runners are also available
according to [GitHub's runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
but cross-compilation does not require them.

After the workflow has been committed and pushed, run **Homelab ARM build**
from Actions. No Actions run has been triggered by the local implementation
work. Download the archive for the Pi's OS, verify its checksum, stop the
existing service, back up the binary and config, replace the binary, and
restart. Validate `--version`, DNS answers, local login, then SSO. Raspberry Pi
runtime validation and production deployment remain operator rollout steps.

## Verification and release status

Local validation includes signed-token round trips with a TLS OIDC fixture,
negative token/transaction tests, session restart and revocation tests,
package dependency boundaries, host adapter tests, frontend unit tests,
built-UI browser tests against Go, and ARM64/ARMv7 compilation.

The browser tests cover login presentation and local recovery; the provider
button test supplies login metadata. They do not claim a real Google login.
The Go fixture independently exercises discovery, PKCE exchange, signature
verification, authorization, and session issuance.

The upstream Go 1.27.2 pin currently produces the existing `GO-2026-6809`
certificate-validation diagnostic during `make go-lint`. Review and update
that toolchain before production deployment; the scanner reports Go 1.27.3
as the fixed version. This is separate from SSO protocol verification.

When SSO is enabled, the login page hides the local username, password,
submit button, and forgot-password link. The Google button follows the theme
and includes its icon. Disable `sso.enabled` and restart to restore the local
form; an options-request failure also shows the local form for recovery.
This is a presentation choice: password login APIs and Basic authentication
remain available. It does not enforce SSO-only authentication.
