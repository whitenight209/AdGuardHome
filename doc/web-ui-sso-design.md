# Web UI SSO design

Status: initial implementation added; production provider validation pending.
See [setup and validation status](web-ui-sso-setup.md).
Date: 2026-10-25.

See the [implementation plan](web-ui-sso-plan.md) for delivery and validation.

## Objective and scope

Allow operators of this AdGuard Home fork to sign into the web UI through
their identity provider while retaining a working local recovery account.
The proposed first release supports one OpenID Connect (OIDC) provider,
configured in YAML, with explicit subject-to-local-user mappings. Every
mapped user has the existing full administrator privileges.

These are planning assumptions, not requirements supplied by the operator.
Google is the selected provider; the external application path must not
conflict with the existing Vaultwarden deployment.
Use Authorization Code flow with PKCE S256 and a confidential backend client.
The Go backend handles discovery, token exchange, verification, and sessions;
the browser only starts sign-in and receives the existing session cookie.
Use a maintained OIDC implementation, selected and version-pinned during
implementation; do not implement JWT verification from scratch.

Excluded from the first release: SAML, LDAP, trusted-header authentication,
multiple providers, automatic user provisioning, group-based authorization,
Server-enforced SSO-only mode, role-based access, provider-wide logout, refresh tokens, and
an SSO configuration screen. DNS clients and DNS protocol authentication are
outside this feature's scope. MFA remains the identity provider's policy.

## Repository evidence

- [Makefile](../Makefile) defaults to `CLIENT_DIR = client_v2`. The primary
  frontend is SolidJS; `client/` remains a selectable legacy frontend.
- [auth.go](../internal/home/auth.go) constructs the local user database and
  session store. `webUser.UserID` is not serialized to YAML.
- [authhttp.go](../internal/home/authhttp.go) implements password login,
  Basic authentication, public-resource checks, and cookie authentication.
  `needsAuthentication` returns false when there are no local users.
- The existing `agh_session` cookie is HttpOnly, SameSite=Lax, path `/`,
  with a 365-day browser expiry. Its constructor does not set Secure.
- [session.go](../internal/aghuser/session.go) and
  [sessionstorage.go](../internal/aghuser/sessionstorage.go) persist sessions
  in `sessions.db`, including login and expiry. Restoring a session looks up
  its local user by login. Server session TTL is configured separately.
- [profilehttp.go](../internal/home/profilehttp.go) reads the user from
  request context, and skips that lookup in userless or GL.iNet mode.
- [config.go](../internal/home/config.go) owns users and serializes the user
  list. External identities must not become password users through this path.
- [login store](../client_v2/src/stores/login.ts) uses the generated API client
  and navigates to the dashboard after password login.
- [OpenAPI](../openapi/openapi.yaml) is the contract used to generate the
  SolidJS API client. Add contracts before regenerating the client.

## Package boundaries and upstream merge strategy

Low coupling, high cohesion, and minimal upstream merge impact are explicit
requirements for this fork. Keep SSO in a separate `internal/sso` Go package
within the existing module; a separate repository or `go.mod` is not needed.
Do not distribute OIDC behavior across AdGuard Home's existing auth files.

```text
internal/home (composition root and thin AdGuard Home adapter)
    -> internal/sso (SSO service, policy, HTTP flow, dedicated persistence)
    -> internal/aghuser (existing local users and sessions)

internal/sso must not import internal/home or internal/aghuser.
```

`internal/sso` owns its config and validation, provider integration, subject
mapping policy, transaction lifecycle, SSO session expiry/revocation, and
sanitized errors. Keep these responsibilities in cohesive files such as
`config.go`, `service.go`, `oidc.go`, `transaction.go`, `session.go`, and
`http.go`. Export only the types and entry points the adapter actually needs;
keep provider SDK types private. No global config access or initialization
side effects. Inject clock, HTTP transport, logger, and persistence at
construction, with explicit lifecycle cleanup.

Define narrow host-facing ports in `internal/sso` using its own value types:
local-user existence lookup and previous-session revocation are examples.
The adapter implements these ports and translates usernames/session tokens
into existing AdGuard Home types. Avoid a general-purpose auth framework,
plugin loader, or interface for every internal helper.

Add `internal/home/sso.go` as the integration boundary. It constructs the
service, registers exact routes under existing installer gates, and adapts
session lookup/deletion to the existing `aghuser.SessionStorage` interface.
Use a decorator around local session storage: ordinary `New` stays local;
SSO creation goes through the SSO service; lookup and deletion dispatch to
local or SSO storage and translate results to existing session values.
Resolve current local users through the host adapter before granting access.
Keep provider policy out of upstream session types and encoders.

Expected edits to existing upstream files are limited to configuration field
and validation wiring, auth construction/cleanup, exact public-route hooks,
the authentication-required guard, and the HTTPS cookie-policy hook. Keep
these edits small and adjacent to existing initialization or dispatch points.
Do not refactor unrelated authentication code, change profile contracts, or
modify `internal/aghuser` just to accommodate SSO. Any additional upstream
edit must document why the adapter cannot satisfy the requirement.

Frontend SSO state and components belong in a dedicated
`client_v2/src/features/sso/` directory, mounted by the existing login page.
Use the generated API contract; keep password-login state independent. Apply
an equivalent isolated feature directory in the legacy client. Keep shared
login markup, translation files, and generated API changes narrowly scoped.

Maintain an integration-point inventory in the implementation plan. Test the
package independently, then contract-test the adapter against the current
upstream interfaces. After each upstream merge, review that inventory and
run the disabled-SSO regression suite plus enabled-SSO integration tests.
This reduces conflict scope; it does not promise conflict-free merges.

## Authentication and authorization

Identify external users by the exact `(issuer, subject)` pair from a verified
ID token (accepting Google's documented `accounts.google.com` alias only
when the configured issuer is `https://accounts.google.com`). Map that pair explicitly to an existing local username. Never link
accounts by email, display name, or `preferred_username`. Unknown subjects
are denied, even when their identity provider authentication succeeds.

This deliberately keeps local users as the authorization and profile model.
It avoids synthetic passwords, changing user persistence, and treating every
member of an identity provider as an administrator. Audit records include
the authentication method and mapped local login; subject identifiers are
restricted to debug diagnostics when needed, not exposed in public errors.

SSO requires at least one valid local user and a nonempty mapping list.
Every mapping must reference an existing user, with no duplicate subjects.
Local password login and Basic authentication remain available and unchanged
in purpose. Consequently, provider MFA does not protect those alternate
authentication paths; SSO-only enforcement would require a separate design.

Reject enabled SSO combined with GL.iNet authentication. Before installation
is complete, retain the existing installer flow and do not enable SSO routes.
An invalid enabled SSO configuration must never fall back to userless access.
Add an explicit authentication-required guard for enabled SSO as defense in
depth, rather than relying only on startup validation.

## Proposed configuration

This schema is implemented. Replace example values before use. Merge it
with existing local `users`; `admin` must already exist with a password hash.

```yaml
sso:
  enabled: false
  oidc:
    display_name: Homelab SSO
    issuer: https://id.example.com/realms/homelab
    client_id: adguard-home
    client_secret_file: /run/secrets/adguard_oidc_client_secret
    public_url: https://dns.example.com/
    session_ttl: 8h
    mappings:
      - subject: replace-with-provider-subject
        username: admin
```

- Absence of `sso` means disabled, preserving current behavior.
- Request only `openid`; email and group claims are unnecessary for mapping.
- Read the secret from the named file at startup. Never persist its contents
  in YAML, configuration exports, API responses, frontend assets, or logs.
  Document service-account read permissions and reject an empty secret.
- Require HTTPS for issuer and public URL in supported deployments. Test
  fixtures may inject an HTTP test transport without a production bypass.
- Public URLs may use the root or a simple directory prefix, without
  userinfo, query, fragment, encoded separators, or dot segments. A reverse
  proxy strips the prefix before forwarding requests; auth cookies and
  redirects use the configured external prefix. Never trust a request header
  to select that prefix.
- Derive the callback exclusively from the configured public URL:
  `https://dns.example.com/control/sso/oidc/callback`. Register that exact URI
  at the provider. Never construct it from Host or forwarded headers.
- Proposed session TTL default: eight hours, positive and capped at 24 hours.
  Local sessions retain their existing TTL.
- Changes require restart. Reject invalid local configuration with actionable
  errors. Provider network failures disable new SSO attempts temporarily,
  but must not prevent DNS service or local login from starting.

## Request flow and API contract

| Route | Access | Behavior |
| --- | --- | --- |
| `GET /control/auth/config` | Public, post-install | Minimal login options |
| `GET /control/sso/oidc/start` | Public, post-install | Begin browser redirect |
| `GET /control/sso/oidc/callback` | Public, post-install | Verify and create session |
| `POST /control/login` | Existing | Local password login |
| `GET /control/logout` | Existing | Invalidate current local session |

The options response contains only `local_login_enabled`, `sso_enabled`,
`sso_display_name`, and a relative `sso_start_url`. It contains no secret,
issuer details, subjects, or mapping list. Configuration and SSO responses
use `Cache-Control: no-store`. Disabled SSO start/callback routes return 404;
wrong methods return 405. Preserve installer gating for every new route.

1. The login page fetches the options and shows a localized provider button
   instead of the local form when SSO is enabled. It never redirects
   automatically. While loading, neither login method flashes on screen.
2. Start creates random state, nonce, PKCE verifier, and a browser-binding
   secret. Store the transaction server-side with a five-minute expiry.
   Bind it to an HttpOnly, Secure, SameSite=Lax temporary cookie. Keep the
   store bounded, clean up expired entries, and rate-limit starts by peer IP.
3. Redirect to the configured provider with `response_type=code`, `openid`,
   PKCE S256, state, nonce, and the fixed callback URI. Support query response
   mode only in v1, compatible with the Lax cookie on top-level navigation.
4. Callback requires matching state and browser binding, and atomically
   consumes the transaction before exchange. Missing, expired, duplicated,
   replayed, or malformed responses cannot issue a session. A new start in
   the same browser may replace its pending flow; document this behavior.
5. Exchange the code server-side with the verifier and client credentials.
   Verify the ID token's signature, permitted algorithm, issuer, audience,
   applicable authorized party, time claims, and nonce. Require a nonempty
   subject and an exact mapping to a current local user.
6. Issue a fresh opaque application session and invalidate any previous
   application session presented by that browser. Discard provider tokens;
   do not expose them to JavaScript or store them in browser storage.
7. Clear the temporary cookie and redirect to the configured application root. Do not accept arbitrary
   return URLs in v1. Failures redirect to the login page with a fixed,
   sanitized error code; never reflect provider error descriptions.

The code flow, token checks, and stable issuer/subject identity follow
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
PKCE and exact redirect matching follow
[OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html).

## Session integration and revocation

Reuse the `agh_session` cookie and existing middleware contract through the
host adapter. Keep SSO records in a separate versioned `sso-sessions.db`,
owned by `internal/sso`, using the existing embedded bbolt dependency. Leave
`internal/aghuser` session records and `sessions.db` encoding unchanged.
This supersedes the earlier proposal to extend upstream session structures.
SSO tokens must never be written into the local store; old binaries cannot
authorize them on rollback because they only read the local store.

SSO records contain mapped login, absolute expiry, and a policy fingerprint
covering issuer, client ID, mappings, and session policy, never the secret.
Check enabled state and fingerprint when restoring and authorizing sessions.
Disabling SSO or changing those fields invalidates SSO sessions while leaving
local sessions intact. Persistently purge invalidated SSO records, including
on disabled startup, so re-enabling an old policy cannot resurrect sessions.
A removed local user also denies access. Document the dedicated store in
backup, permissions, cleanup, and rollback procedures.

The adapter preserves the existing token wire format, using cryptographically
random tokens and checking both stores before issuance to avoid collisions.
Treat ambiguous matches or storage errors as failures, never as permission to
fall back to another identity. Lookup/deletion must be concurrency-safe;
logout and session rotation must revoke the appropriate record. Add adapter
contract tests so changes to upstream session interfaces fail visibly.

SSO sessions have a fixed absolute expiry, with browser cookie expiry aligned
to server expiry. Keep cookie attributes consistent through a small host policy hook.
Do not move upstream cookie handling into the SSO package. Set Secure for all session cookies when SSO's HTTPS public URL
is enabled, including local login; retain existing HTTP behavior when SSO is
disabled. Use host-only cookies. The backend may receive HTTP from a TLS
proxy, so cookie security must derive from configured deployment policy.

Logout clears the application cookie and deletes its server session. It does
not log the user out of the provider; another explicit click may sign in
without a password. Provider account suspension is enforced on the next
SSO login, not instantly for an existing session. Document this limitation
and the maximum session lifetime. Global or back-channel logout is deferred.

## Operational and security boundaries

- Permit only configured discovery; never accept request-supplied issuers or
  endpoints. Validate discovery issuer equality and HTTPS endpoint schemes.
  Private homelab IdPs are legitimate. Use request deadlines, response-size
  limits, bounded JWKS refresh, and a restricted redirect policy for outbound
  requests; do not permit redirects to arbitrary destinations.
- Keep state and PKCE material in memory only. Restart invalidates pending
  flows and the user retries. Do not require an external database service or
  Node runtime; the SSO store is an embedded file.
- Support signing-key rotation through the chosen OIDC library and test
  unknown-key refresh behavior without unbounded outbound requests.
- Do not log callback query strings, authorization codes, tokens, secrets,
  cookies, or raw provider errors. Check shared HTTP logging and reverse
  proxy access-log configuration, not only the new handlers.
- Set `Referrer-Policy: no-referrer` on callback responses. Return to a clean
  URL immediately without loading third-party content on callback pages.
- Only exact new routes become public; all other control APIs retain the
  existing authentication checks. Review cookie-based mutation protection
  before exposing this UI publicly; SSO is not a substitute for that review.
- Provider timeouts or discovery failures produce a generic retryable login
  error. Local recovery login remains visible. Do not couple DNS readiness
  to provider availability; recovery retries must be bounded.
- Existing trusted-proxy settings concern IP attribution, not identity.
  Never treat incoming user/email headers as proof of authentication.

## Frontend and compatibility

Implement the feature in `client_v2/src/features/sso/` and mount it from
`client_v2/src/login/Login/`; keep the existing password-login store separate.
Generate the typed options API from OpenAPI. Use the returned relative start
URL for top-level navigation, not an XHR token flow. Show loading, provider
unavailable, cancellation, expired attempt, and generic denial states with
localized accessible text. If the options request fails, keep local login
usable and show an error without guessing SSO availability.

Keep profile response shape unchanged: it reports the mapped local name.
The forgot-password page continues to describe local account recovery;
provider passwords are managed at the provider. Add a minimal equivalent
provider button and error handling to the selectable legacy `client/` build,
or explicitly remove that build from supported SSO releases. The proposed
plan chooses parity so selecting the old frontend does not hide SSO.

## Decisions to confirm during implementation

- Deployment IdP, exact issuer and subject values, and public HTTPS hostname.
- Confirm the public proxy route before deployment. Subpath authentication
  support is implemented; SSO-only enforcement remains out of scope.
- OIDC library/version and provider client-authentication method, verified
  against current official documentation and repository Go compatibility.
- Whether the proposed eight-hour SSO lifetime fits operator policy.

These choices do not block the documentation. The proposed MVP uses the
defaults above until implementation evidence requires a revision.
