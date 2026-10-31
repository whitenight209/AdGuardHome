# Web UI SSO implementation plan

Status: initial implementation and tests added; deployment validation pending.
See [setup and validation status](web-ui-sso-setup.md).
Unchecked release items below remain acceptance criteria, not claims of coverage.
Date: 2026-10-25.

The [design](web-ui-sso-design.md) defines the proposed OIDC scope, config,
routes, session policy, security boundaries, and unresolved deployment choices.
Deliver the following steps in order, keeping SSO disabled by default.

## Implementation evidence

- Isolated code: `internal/sso`; host adapter: `internal/home/sso.go`.
- Local user/session types and persistence encoding remain unchanged.
- New Go tests cover package boundaries, signed OIDC flows, rejection paths,
  browser binding, replay, concurrency, session policy, and log redaction.
- Both frontend variants show only SSO when enabled, with a themed Google
  button. Disabled SSO or a metadata failure restores the local form. The SolidJS
  component has unit and built-UI browser tests.
- Added `.github/workflows/homelab-arm.yaml`; local ARM64 and ARMv7 builds
  verified as Linux ARM ELF binaries. Remote Actions execution is pending push.
- Google project created: `homelab-whitenight209`; the operator created the
  web OAuth client. Local credential references and verified subject mapping
  are prepared. Resolve the public route conflict with Vaultwarden before
  enabling the deployment configuration.
- Remaining release work: real-provider/key-rotation interoperability, full
  TLS-proxy end-to-end flow, Pi runtime validation, and rollout/rollback drill.

## Phase 0: Package isolation and integration inventory

- [ ] Create `internal/sso` inside the existing Go module, with package-owned
      config, service, protocol flow, policy, and persistence. Do not import
      `internal/home` or `internal/aghuser` from it.
- [ ] Define the small host-facing ports and value types needed by the service.
      Implement them in a thin `internal/home/sso.go` adapter. Keep provider
      libraries and SSO business rules out of the host adapter.
- [ ] Write independent package tests with fake host ports and an adapter
      contract suite. Add an import-boundary check to prevent coupling drift.
- [ ] Record each existing upstream file changed, its exact integration point,
      and why the hook is necessary. Require review for additions to this list.

Initial integration inventory:

| Existing surface | Permitted integration |
| --- | --- |
| `internal/home/config.go` | Optional package config and validation wiring |
| `internal/home/auth.go` | Service lifecycle and session-storage decorator |
| `internal/home/authhttp.go` | Exact route access, auth-required and cookie hooks |
| Web API initialization | Route registration through `sso.go` |
| `internal/home/web.go` | Redact SSO RequestURI before shared request logging |
| Login entry components | Mount isolated SSO components |
| OpenAPI, generated clients, locales | Additive endpoint and presentation contract |
| `go.mod`, `go.sum` | Reviewed OIDC dependency additions |

No planned changes to `internal/aghuser` or the profile response contract.
Do not restructure unrelated upstream code. Keep package implementation and
host wiring in separate reviewable commits where practical.

Exit: dependency direction and integration inventory are agreed in code
review; SSO can be tested without constructing the AdGuard Home runtime.

## Phase 1: Configuration and contracts

- [ ] Select and pin a maintained Go OIDC verifier and OAuth client dependency.
      Confirm discovery, PKCE S256, client authentication, JWKS rotation, and
      strict token validation with a small local provider fixture.
- [ ] Add the proposed optional YAML configuration in `internal/home/config.go`
      using package-owned types and wire it through the adapter. Trace copying,
      writing, upgrades, and restart behavior; add a schema migration only if
      required by the repository's configuration-version conventions.
- [ ] Validate HTTPS public URL and safe optional prefix, issuer, secret file, local users,
      subject mappings, session lifetime, and GL.iNet incompatibility.
- [ ] Update userless-mode checks and warnings so enabled SSO can never imply
      unauthenticated control access, even if validation is bypassed in tests.
- [ ] Define options/start/callback responses and errors in
      `openapi/openapi.yaml`, including unauthenticated access explicitly.

Exit: disabled configuration round-trips unchanged in behavior; invalid
enabled configuration is rejected; exported configuration contains no secret.

## Phase 2: Session foundation

- [ ] Implement versioned SSO records and fixed expiry in `internal/sso`,
      persisted to a dedicated `sso-sessions.db`. Leave the local store and
      upstream `aghuser` structures/encoding unchanged.
- [ ] Implement the host session-storage decorator with explicit local versus
      SSO creation, lookup/deletion dispatch, and current-user resolution.
      Test collision rejection, concurrency, storage errors, and cleanup.
- [ ] Add the minimum HTTPS cookie-policy hook while preserving upstream
      cookie creation/deletion behavior and matching attributes.
- [ ] Purge disabled or policy-invalidated SSO sessions persistently so a later
      re-enable cannot restore revoked access.
- [ ] Enforce enabled state, fingerprint, current local-user existence, and
      expiry whenever an SSO session is restored or used.
- [ ] Preserve request-context user resolution and `/control/profile` behavior.

Exit: local fixtures still load; new SSO sessions survive restart only under
the same policy; revocation, expiry, logout, and rollback tests pass.

## Phase 3: Backend OIDC flow

- [ ] Implement the OIDC service and HTTP handlers in `internal/sso`, with
      injected clock, HTTP client, randomness, and verifier seams for tests.
      Keep `internal/home/sso.go` limited to wiring and type adaptation.
- [ ] Implement bounded pending transactions, browser binding, cleanup,
      per-peer start limits, one-time consumption, and callback validation.
- [ ] Add exact public post-install routes and keep disabled routes at 404.
- [ ] Implement discovery, code exchange, token verification, explicit mapping,
      session rotation, and sanitized redirects described in the design.
- [ ] Keep DNS and local authentication available during provider outages;
      retry discovery on demand with bounded backoff and concurrency.
- [ ] Audit logs across new handlers, shared middleware, and proxy examples.
      Add stable failure categories without recording credentials or tokens.

Exit: an allowed subject signs in; an authenticated but unmapped subject is
denied; adverse protocol inputs cannot create a session or bypass middleware.

## Phase 4: Web UI integration

- [ ] Run `npm run api:generate` from `client_v2` after updating OpenAPI.
- [ ] Add options state and an accessible provider button in
      `client_v2/src/features/sso/`, with top-level browser navigation.
- [ ] Mount the feature from `client_v2/src/login/Login/` with minimal changes;
      keep the existing password-login store independent.
- [ ] Add English translation keys and tests for other locale fallback,
      keyboard operation, provider labels, and sanitized failure messages.
- [ ] Preserve local recovery when metadata cannot load; prevent automatic
      sign-in loops after logout or provider cancellation.
- [ ] Add equivalent login affordances to `client/` using its API and i18n
      conventions. Verify both frontend build selections.

Exit: both login paths work against the real Go backend, profile is correct,
and logout returns to a usable login page without silent SSO re-entry.

## Phase 5: Verification and release gates

Use a disposable config, session database, local OIDC test provider, and test
accounts. Never run authentication experiments against the operator's live
DNS installation or copy production client secrets into fixtures.

| Area | Required cases |
| --- | --- |
| Defaults | No SSO config; disabled SSO; existing local login and Basic auth |
| Access | No users; invalid mappings; GL.iNet; pre-install routes; protected API |
| Transactions | Missing/wrong state or cookie; expiry; replay; concurrent callbacks |
| Protocol | Wrong issuer/audience/nonce; bad signature; expiry; missing subject |
| Exchange | PKCE failure; reused code; provider cancellation; timeout; malformed reply |
| Discovery | Issuer mismatch; unsafe endpoint; bounded failure retries; key rotation |
| Authorization | Unknown subject; same email with different subject; removed user |
| Sessions | Rotation; restart; absolute TTL; policy change; disable; old DB fixtures |
| Cookies | Secure/HttpOnly/Lax; matching deletion; HTTPS proxy; disabled HTTP mode |
| Redirects | Host/header spoofing; external return target; sanitized callback errors |
| Exposure | No tokens in logs, browser storage, metadata, exports, or built assets |
| UI | Enabled/disabled/loading/error; local fallback; keyboard; legacy parity |
| Operations | IdP unavailable at startup; DNS remains available; recovery; rollback |

Backend checks, from repository root:

```sh
go test ./internal/sso/... ./internal/home ./internal/aghuser
go test -race ./internal/sso/... ./internal/home ./internal/aghuser
make go-lint
```

Frontend checks, from `client_v2`, following its `AGENTS.md`:

```sh
npm run translations:check
npm run check
npm run build-prod
npm run test:e2e
```

Run focused tests during development and the full checks once at completion.
Keep protocol and SSO persistence tests inside `internal/sso`; add host
adapter contract tests and frontend feature/mount tests separately. Extend Playwright with a local provider fixture to
exercise the whole redirect round trip, not just a mocked options response.
Verify the built UI served by Go, including TLS proxy behavior. Use the legacy
client's declared scripts for its changed files and build. Run OpenAPI and
Markdown checks using repository tooling, explicitly including these docs.

Release additionally requires one manual interoperability pass with the
actual deployment IdP. Record its version, client settings, callback URI,
successful allowed login, denied subject, key rotation, and outage behavior.

## Rollout and recovery runbook to deliver

1. Back up configuration, `sessions.db`, and any existing `sso-sessions.db`
   while the service is stopped.
   Deploy the new binary with SSO disabled and verify local login and DNS.
2. Create a confidential OIDC application at the provider with the exact
   callback URI and code flow/PKCE support. Configure only intended subjects.
3. Place the client secret in a service-readable protected file. Configure
   HTTPS and proxy forwarding; restrict direct backend access as appropriate.
4. Add explicit mappings to existing local users. Retain and test a recovery
   password, then enable SSO and restart during a maintenance window.
5. Verify allowed login, denied login, profile, logout, local recovery, and
   DNS health. Monitor sanitized failure categories and provider timeouts.
6. To disable SSO, set `sso.enabled: false` and restart. Confirm SSO cookies no
   longer authorize requests and local password login still works.
7. For binary rollback, stop the service, restore compatible configuration
   and the pre-upgrade database backup, then start the previous binary.
   Keep the separate SSO database out of the old local store. Before returning
   to an SSO-capable binary, discard stale SSO sessions to prevent resurrection.
   Sessions created after the backup may be lost; communicate re-login.

Document that provider logout does not revoke the application's existing
sessions. For urgent bulk revocation, disable SSO and restart. Changing the
mapped-subject policy also invalidates all SSO sessions under the proposed
fingerprint policy. Rotating only the client secret does not revoke sessions.

## Upstream merge maintenance gate

- [ ] Compare upstream auth/session interfaces against the integration inventory
      after each merge; adapt only the host boundary where possible.
- [ ] Run package/import-boundary checks, adapter contracts, local-only
      regressions, and the full SSO browser round trip after merging.
- [ ] Verify local session file compatibility and that an upstream-only binary
      cannot authenticate SSO tokens from the separate store.
- [ ] Update the inventory when a hook changes, including the reason and tests.
      Reject unrelated refactors bundled with SSO maintenance.

## Completion criteria

- [ ] SSO policy and protocol code reside in the separate package; upstream
      edits match the reviewed inventory and dependency-boundary checks pass.
- [ ] All phase exits and test cases above pass with recorded evidence.
- [ ] Current local-only installations require no configuration changes.
- [ ] SSO failure never grants anonymous administrative access.
- [ ] No provider credential or token reaches frontend code or persistent logs.
- [ ] An operator can enable, recover, disable, and roll back using shipped docs.
- [ ] Update user-facing configuration documentation and the changelog when
      functionality ships; these planning documents alone do not claim support.
