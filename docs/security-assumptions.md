# Security assumptions and their proofs

This is the register of what the security chain assumes, what enforces each
assumption, and which test proves it. A change that touches the chain updates
this file in the same pull request. A review starts here.

The chain is: a browser, Caddy with the guard snippets in `deploy/auth.caddy`,
the gateway, and the app behind the guard. The unit tests prove what the
gateway decides. The end-to-end suite (`scripts/e2e.sh`, `e2e/chain_test.go`)
proves what the chain delivers to the browser and to the app, using the
production Caddy and the image built from this repository.

## The attacker

Every review assumes an attacker with all of these capabilities, at once.

- **They control their own browser completely.** They can send any header,
  present any cookie value they have been issued under any cookie name, replay
  a request, and skip or reorder any step of a flow. The October 2026 finding
  needed nothing more than this.
- **They have many network addresses.** Any limit keyed on one address can be
  spread across many.
- **They receive mail at addresses they own**, and may control one staff
  member's inbox.
- **They may control one app on the cookie domain.** That app can set cookies
  for the whole domain, serve pages, and make a visitor's browser post forms
  to the gateway. Browsers count it as the same site.
- **They can photograph a break-glass card.**
- **They may hold a copy of the database file**, but not the server's settings
  or keys.

The attacker cannot read the server's settings, reach the gateway or an app
except through Caddy, or break TLS. If a design relies on anything else being
out of the attacker's reach, write it down here.

## The chain: Caddy, the gateway and the app

| | Assumption | Enforced by | Proven by |
|---|---|---|---|
| C1 | An app receives identity only from the gateway, never from the client. | `strip_client_identity`, then the gate's `handle_response` copying the gateway's headers | e2e: *signing in lands on the app with the gateway's identity only*, *forged identity and rule headers do not admit a visitor*; the server repos' `ci-forward-auth-test.sh` for a gateway that omits a header |
| C2 | A public route never hands its app a forged identity. | `strip_public` | e2e: *forged identity and rule headers…* (public and mixed hosts) |
| C3 | The session cookie never reaches an app, guarded or public, and the app's own cookies do. | `strip_auth_cookie` in every guard; `strip_public` | e2e: *signing in lands…*, *the session cookie never reaches a public app or a public path* |
| C4 | A client cannot set or widen a route's rule. | `header_up X-Auth-Policy` replaces the client's copy | e2e: *a forged rule header cannot widen a guard* |
| C5 | A missing or malformed rule closes the route. | `parsePolicy`'s exact grammar | `FuzzParsePolicy`, `TestMalformedPolicyDeniesSignedInUser`, `TestMissingPolicyFailsClosed`; e2e: the `broken` host |
| C6 | A renewed session reaches the browser, beside the app's own cookies. | the gate's `@renewed` response handler | e2e: *a renewed session reaches the browser beside the app's own cookie* |
| C7 | The post-login destination is the request the browser made, and stays on the domain as a browser reads it. | Caddy sets `X-Forwarded-*` itself; `ValidateRedirect` | e2e: *forged forwarding headers do not change the destination*; `FuzzValidateRedirect` |
| C8 | The per-network limits key on the real client address. | The auth host overwrites `X-Forwarded-For`; the gateway reads only its right-most entry | e2e: *a forged forwarded address does not escape the per-network limit*; `TestClientIP_TrustsRightmostXFF` |
| C9 | Only Caddy can reach the gateway and the apps. | No published ports; one private network per app | Not provable here: the server repo's CI and on-server compose audit |

C1 and C8 are each held by two layers. Removing one layer leaves the other
holding, so the end-to-end suite passes with either layer alone. Each layer
has its own test, named in the table.

## The gateway

| | Assumption | Enforced by | Proven by |
|---|---|---|---|
| G1 | A token is accepted only for the purpose it was issued for. | The typed envelope in `session.decode` | `TestEveryTokenIsReadOnlyForItsOwnPurpose`, `TestLegacyUntypedTokenRejected`; e2e: *the cookie given to anyone who asks for a code is not a session* |
| G2 | A request with two session cookies has no session. | `ReadSession` | `TestDuplicateSessionCookieIsRefused`, `TestVerifyDoesNotClearAmbiguousSessionCookies` |
| G3 | Every public form refuses a post from a sibling or foreign host; real browsers' own posts pass. | `requireSameOrigin`; the activation's CSRF token | `TestEveryPublicPostRefusesASiblingHost`, `TestSignInCompletesForEveryBrowserProfile`, `TestSignInRefusedForForeignShapes`; e2e: *a sign-in form posted from a sibling host is refused*, and every e2e sign-in posts with `Origin: null` |
| G4 | Every admin change needs a form token bound to the admin's session. | `checkCSRF` | `TestEveryAdminPostRequiresCSRF`, `TestCSRFBindingAndExpiry`; e2e: *an admin change through Caddy…* |
| G5 | The admin pages admit only a current administrator who has passed the second factor. | `requireAdmin` | `TestRemovedAdminLosesAdminUI`, `TestBreakGlassSessionRejectedFromAdminUI`, `TestGuestNeverAdmin`, `TestEnablingTOTPReChallengesExistingAdminSession`; e2e: *staff cannot open the admin pages*, the guest step |
| G6 | An administrator's second factor is required, rate-limited per account, and single-use. | `handleTOTP` | `TestTOTPAttemptCapHoldsUnderConcurrency`, `TestTOTPCodeCannotBeReplayed`, `TestTOTPNoSelfEnrolment`, `TestTOTPRefusesWhenAttemptCannotBeRecorded`; e2e: *an administrator must pass the second factor* |
| G7 | A break-glass session reaches only routes naming its group, never by domain, never the admin tier. | `CanAccessApp`, `IsReservedGroup`, `requireAdmin` | `FuzzCanAccessApp`, `TestBreakGlassScopedToItsGroup`, `TestBreakGlassCannotTargetReservedGroup` |
| G8 | A guest reaches only routes that allow guests, or name a group the guest is in. | `CanAccessApp` | `FuzzCanAccessApp`, `TestVerifyGuestPolicies`; e2e: *a guest reaches only the app open to the public* |
| G9 | No group can carry a reserved role into the groups header. | `ValidGroupName`, `IsReservedGroup` | `FuzzBuildGroupsKeepsRoleFirst`, `TestGroupNameWithSeparatorRejected` |
| G10 | Guessing at a code is bounded per network and in total, and a stranger cannot destroy or reset an owner's code. | `ConsumeCode`, the resend cooldown | `TestConsumeCodeAggregateCapAcrossIPs`, `TestConsumeCodeAttemptCapPerIP`, `TestResendWithinCooldownDoesNotResetAttempts`, `TestOverLimitDecoyDoesNotBlockOwner` |
| G11 | The sign-in flow does not reveal which addresses are allowed. | Decoy codes; mail sent after the response | `TestVerifyCodeDoesNotEnumerate`, `TestDisallowedEmailNoCodeButSameResponse`, `TestResendTransitionsMatchForDecoy` |
| G12 | Renewal re-checks the rules and recalculates groups. | `handleVerify`, `renewalRole` | `TestRevokedPrincipalNotRenewed`, `TestDemotedAdminLosesAdminGroupAtRenewal`; e2e: *an admin change through Caddy reaches a session at its next renewal* |
| G13 | No code, cookie value or card token reaches the log. | No logging of them; the log mail backend refused outside development | `TestSecretsNeverReachTheLog`, `TestLoadLogBackendRequiresInsecure` |
| G14 | The gateway refuses to start on an unsafe or malformed setting. | `config.validate` | the `TestLoad…` tests, `TestMalformedBooleanRefused` |
| G15 | One anonymous visitor cannot exhaust the gateway. | Body and header caps, upload checks, the logo cache | `TestPublicFormsCapBodies`, `TestDeclaredOversizeIsRefused`, `TestCheckRasterRefusesCraftedPNGs`, `TestCheckSVG` |
| G16 | Mail is never sent unencrypted, and a notification webhook cannot reach the host or cloud metadata. | `email/smtp.go`, `breakglass.dialGuarded` | `TestWebhookRefusesNameResolvingToBlockedAddress`, `TestWebhookDoesNotFollowRedirects` |

## What this repository cannot prove

- **C9, reachability.** Only the server can show that the gateway and apps
  publish no ports and share networks only with Caddy.
- **The server repos' guard snippets.** Each server keeps its own copy of
  `auth.caddy`, and the copies have diverged. Run this suite against a copy
  with `E2E_AUTH_CADDY=/path/to/apps/auth/auth.caddy scripts/e2e.sh`. The
  copy must define `strip_public`.
- **The Secure attribute and HSTS through Caddy.** The end-to-end stack uses
  the log mail backend, which needs the insecure-cookie mode. Both are proven
  by unit tests instead (`TestHSTSHeaderOnlyUnderTLS`).
- **Break-glass cards end to end.** A card's token exists only in its QR image.
  Card behaviour is gateway logic, proven by the unit tests under G7. The
  group guard a card depends on is proven end to end under the `reports` host.
- **Keeping card tokens out of Caddy's access log.** This depends on the
  server's logging configuration.

## Accepted, and why

These risks are known. The design docs explain each one for the department.

- A visitor who calls `/verify` on the public auth host learns only their own
  identity, and can make the access log record a visit to the auth host.
- An older Safari, which sends no `Sec-Fetch-Site`, can be made to sign out or
  start a sign-in by another site. It cannot complete one.
- A stolen session works until it expires or the person's listing is removed.
  Sessions have no absolute lifetime yet.
- A sibling app can overwrite the session cookie outright.
- One administrator can act as another, because the person who issues a
  second-factor secret sees it once.

## Reviewing a change

Every pull request that touches the chain answers these questions (the pull
request template repeats them).

1. Which assumptions above does the change touch? Is each still enforced, and
   is the named test still the proof?
2. What does the change now permit that was refused before? A fix for one
   finding has loosened another before: the July 2026 per-network guess cap
   ended targeted lockout but allowed guessing from many networks.
3. Does the change add a token, cookie, header, route or setting? If so, which
   row covers it? The token matrix and the route census include new tokens and
   routes automatically; a new header or setting needs a row of its own.
4. Has each new test been seen to fail? Break the code it protects, run the
   test, and restore the code.
