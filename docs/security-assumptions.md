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
| C10 | A role guard asks the gateway for its own app and role, never the client's, and the app receives only the gateway's `Remote-Roles`. | `(role)` deletes the client's identity, role and rule headers; `auth_gate_role` sets `X-Auth-App` and `X-Auth-Role` with `header_up`, removes `X-Auth-Policy` and copies `Remote-Roles` | e2e: *a role guard names its app and role to the gateway and gives the app the roles*; `TestRoleGuardRefusesMisconfiguredGuards` |

C1 and C8 are each held by two layers. Removing one layer leaves the other
holding, so the end-to-end suite passes with either layer alone. Each layer
has its own test, named in the table.

## The gateway

| | Assumption | Enforced by | Proven by |
|---|---|---|---|
| G1 | A token is accepted only for the purpose it was issued for. | The typed envelope in `session.decode` | `TestEveryTokenIsReadOnlyForItsOwnPurpose`, `TestLegacyUntypedTokenRejected`; e2e: *the cookie given to anyone who asks for a code is not a session* |
| G2 | A request with two session cookies has no session, and a token under any other cookie name is no session. | `ReadSession` | `TestDuplicateSessionCookieIsRefused`, `TestVerifyDoesNotClearAmbiguousSessionCookies`; e2e: *the session cookie in odd forms admits no one and reaches no app* |
| G3 | Every public form refuses a post from a sibling or foreign host; real browsers' own posts pass. | `requireSameOrigin`; the activation's CSRF token | `TestEveryPublicPostRefusesASiblingHost`, `TestSignInCompletesForEveryBrowserProfile`, `TestSignInRefusedForForeignShapes`; e2e: *a sign-in form posted from a sibling host is refused*, and every e2e sign-in posts with `Origin: null` |
| G4 | Every admin change needs a form token bound to the admin's session. | `checkCSRF` | `TestEveryAdminPostRequiresCSRF`, `TestCSRFBindingAndExpiry`; e2e: *an admin change through Caddy…* |
| G5 | The admin pages, and the `admin` group in any app's headers, are held only by a current administrator who passed the second step within the last 12 hours; without it an administrator is an ordinary user, and losing the step or the admin listing takes `admin` away at the next request. | `requireAdmin`, `adminStepFresh`, `tierRole`, `tierStale` | `TestRemovedAdminLosesAdminUI`, `TestBreakGlassSessionRejectedFromAdminUI`, `TestGuestNeverAdmin`, `TestEnablingTOTPReChallengesExistingAdminSession`, `TestAdminSignsInWithoutTOTP`, `TestAdminTierLapsesAfterTwelveHours`, `TestDemotedAdminLosesAdminGroupAtNextRequest`, `TestGroupRecheckGivesNewAdminNoAdminTier`; e2e: *staff cannot open the admin pages*, the guest step |
| G6 | The second step at the admin door is a provisioned authenticator code (rate-limited per account, single-use, CSRF- and origin-checked) or an admin passkey; it is never self-enrolled. | `handleStepUp`, `handleTOTP`, `checkAdminCode` | `TestTOTPAttemptCapHoldsUnderConcurrency`, `TestTOTPCodeCannotBeReplayed`, `TestTOTPNoSelfEnrolment`, `TestTOTPRefusesWhenAttemptCannotBeRecorded`, `TestAdminDoorNeedsTokenAndSession`, `TestAdminDoorGivesAdminTier`; e2e: *an administrator signs in like staff and takes the second step at the admin door* |
| G7 | A break-glass session reaches only routes naming its group, never by domain, never the admin tier, and never a group an app reads as its own role, even when the group became one after the card was made. | `CanAccessApp`, `IsReservedGroup`, `refusedTargets`, `refuseRetargetedCard`, `requireAdmin` | `FuzzCanAccessApp`, `TestBreakGlassCardRefusedOnceTargetIsAppRole`, `TestBreakGlassScopedToItsGroup`, `TestBreakGlassSessionCannotActOutsideItsCard`, `TestBreakGlassCannotTargetReservedGroup`, `TestBreakGlassRefusesGroupListedWithAdmin`, `TestBreakGlassRefusesDeclaredGroup`, `TestGuestMembershipRefusedForAppRoleGroup` |
| G8 | A guest reaches only routes that allow guests, or name a group the guest is in; no path, an include among them, gives a guest a group an app reads as its own role: the filter runs again at every guest request, so a group that becomes a role reaches the guest at once, and while a configured route file cannot be read it keeps only feed groups. An include that would bring an outsider into such a group is refused. | `CanAccessApp`, `withoutAppRolesForOutsider`, `guestGroupsNow`, `routeFilesReadable`, `handleAdminAddInclude` | `FuzzCanAccessApp`, `TestVerifyGuestPolicies`, `TestGuestCannotReachAppRoleThroughInclude`, `TestReviewGuestKeepsGroupThatBecomesAppRole`, `TestReviewGuestFilterFailsOpenOnUnreadableManifest`, `TestIncludeBringingOutsidersIntoAppRoleRefused`; e2e: *a guest reaches only the app open to the public* |
| G9 | No group can carry a reserved role into the groups header. | `ValidGroupName`, `IsReservedGroup` | `FuzzBuildGroupsKeepsRoleFirst`, `TestGroupNameWithSeparatorRejected` |
| G10 | Guessing at a code is bounded per network and in total, and a stranger cannot destroy or reset an owner's code. | `ConsumeCode`, the resend cooldown | `TestConsumeCodeAggregateCapAcrossIPs`, `TestConsumeCodeAttemptCapPerIP`, `TestResendWithinCooldownDoesNotResetAttempts`, `TestOverLimitDecoyDoesNotBlockOwner` |
| G11 | The sign-in flow does not reveal which addresses are allowed. | Decoy codes; mail sent after the response | `TestVerifyCodeDoesNotEnumerate`, `TestDisallowedEmailNoCodeButSameResponse`, `TestResendTransitionsMatchForDecoy` |
| G12 | Renewal re-checks the rules and recalculates groups. | `handleVerify`, `renewalRole` | `TestRevokedPrincipalNotRenewed`, `TestDemotedAdminLosesAdminGroupAtRenewal`; e2e: *an admin change through Caddy reaches a session at its next request* |
| G13 | No code, cookie value or card token reaches the log. | No logging of them; the log mail backend refused outside development | `TestSecretsNeverReachTheLog`, `TestLoadLogBackendRequiresInsecure` |
| G14 | The gateway refuses to start on an unsafe or malformed setting. | `config.validate` | the `TestLoad…` tests, `TestMalformedBooleanRefused` |
| G15 | One anonymous visitor cannot exhaust the gateway. | Body and header caps, upload checks, the logo cache | `TestPublicFormsCapBodies`, `TestDeclaredOversizeIsRefused`, `TestCheckRasterRefusesCraftedPNGs`, `TestCheckSVG` |
| G16 | Mail is never sent unencrypted, and a notification webhook cannot reach the host or cloud metadata. | `email/smtp.go`, `breakglass.dialGuarded` | `TestWebhookRefusesNameResolvingToBlockedAddress`, `TestWebhookDoesNotFollowRedirects` |
| G17 | A passkey signs in only through a ceremony on the sign-in host itself, with the person verified, answering a fresh challenge used once even across a restart, signed by the stored key. | `passkey.VerifyAssertion`, `challengeGuard`, `handlePasskeyLogin` | `TestChallengeGuardExpiryRestartAndCap`, `TestSignInRefusals`, `TestRegistrationRefusals`, `FuzzVerifyNeverAcceptsWithoutTheKey`, `TestPasskeySignInRefusals`; e2e: *a passkey made on a phone signs in on its own…* (a whole-domain ceremony is refused) |
| G18 | Adding a passkey needs a recent sign-in with an emailed code (a passkey sign-in never counts), the challenge minted for that account, and for an administrator the second factor, checked before any ceremony. | `freshSignIn`, `mayAddPasskeyNow`, `handlePasskeyConfirmCode`, `handlePasskeyRegister` | `TestAddingAPasskeyNeedsARecentSignIn`, `TestAPasskeySessionCannotAddAnotherPasskey`, `TestRegistrationChallengeIsBoundToItsAccount`, `TestAdminPasskeys`, `TestRegistrationPostsDoNotSpendAdminCodeAttempts` |
| G19 | A passkey is the admin second step only if it was added, with TOTP on, by an administrator who had passed it; no passkey is ever upgraded in place (a session's cookie could have been planted), and the door offers a new one instead; a passkey sign-in re-checks the current rules and never makes a guest. | `adminGrade` in `handlePasskeyRegister`, `offerAdminPasskey`, `handlePasskeyLogin` | `TestPasskeyFromBeforePromotionIsReplacedAtTheDoor`, `TestReviewDoorUpgradesPasskeyOfPlantedSession`, `TestPasskeyAddedWhileTOTPOffIsNotAdminGrade`, `TestAdminPasskeys`, `TestAdminWithoutSecondStepCannotAddPasskeyDirectly`, `TestPasskeySignInRefusals` |
| G20 | Once a passkey is removed, the sessions it started end at their next request, everywhere; passkey IDs are never reused. | `passkeyKey` in `sessionEnded`; `passkeyStillValid` in `requireAdmin`, `passkeySession` and `renewSessionWith`; `AUTOINCREMENT` | `TestRemovingAPasskeyEndsItsSessions`, `TestRemovedPasskeyLosesAdminPagesAtOnce`, `TestPasskeyIDsAreNeverReused`; e2e: *…until it is removed* |
| G21 | Scripts run only on the pages that use a passkey, only from the gateway itself, and only when passkeys are on. | `render`, `passkeyPages` | `TestPasskeysOffByDefault`; e2e: *the sign-in pages carry their security headers through Caddy* |
| G22 | An app learns who is in a group only for the groups listed for its own token, only on a port Caddy never proxies and only from a private address, and only as the gateway applies membership now; the base roles are never readable, a group it may not read looks the same as one that does not exist, and every read is recorded. | `parseMemberReaders`, `MembersHandler`, `handleGroupMembers`, `GroupMembersResolved` | `TestMemberReadersRefused`, `TestMembersEndpointAnswersOnlyTheAppsOwnGroups`, `TestMembersEndpointRefusals`, `TestMembersAreNotServedOnThePublicListener`, `TestMembersReadsAreAudited`, `TestGroupMembersResolved` |
| G27 | An app on its members network reaches only the members endpoint: the members listener binds only to the gateway's own addresses under the members alias, and the public listener closes connections that arrive on them; a members alias that names none of the gateway's addresses stops start-up. | `netsplit.OwnAddrs`, `netsplit.Refusing`, `main.go` | `TestOwnAddrsKeepsOnlyThisHostsAddresses`, `TestOwnAddrsRefusesANameThatIsNotOurs`, `TestRefusingClosesMembersConnections`, `TestMemberReadersRefused`; e2e: `TestMembersNetworkReachesOnlyTheMembersEndpoint` |
| G23 | A session ends at its next request once its person signs out everywhere, their authenticator is replaced or removed, its passkey is removed, or its break-glass card is revoked or re-minted; none outlives `SESSION_MAX_AGE`; a membership change, a domain removed from the allow-list, or an address removed from the admin listing reaches every session at its next request. | `readSession`, `sessionEnded`, `groupsStale`, `policyWithdrawn`, `endSessions` | `TestPolicyRemovalTakesEffectAtNextRequest`, `TestSignOutEverywhere`, `TestAdminSignsAPersonOutEverywhere`, `TestSessionMaxAge`, `TestGroupRemovalTakesEffectAtOnce`, `TestRevokingACardEndsItsSessions`, `TestReplacingAnAuthenticatorEndsSessions`, `TestRemovingAPasskeyEndsItsSessions` |
| G24 | A flood of sign-in requests from many networks cannot start more than a fixed number of email sends at once. | `sendMail` | `TestMailSendsAreBounded` |
| G25 | Opening a card's address grants nothing; only the button on that page, posted from the gateway's own origin, grants, so a link preview or a mail scanner cannot start a session or a notification. The page and the grant have separate per-address limits, so one use spends one grant. A card whose group has become a role is reported to the administrators at most once an hour. | `handleBreakGlassScan`, `handleBreakGlass`, `refuseRetargetedCard` | `TestBreakGlassScanAsksBeforeGranting`, `TestBreakGlassPostRefusesCrossSiteAndBadTokens`, `TestReviewBreakGlassChargesTwice`, `TestBreakGlassCardRefusedOnceTargetIsAppRole` |
| G26 | The account holder is emailed whenever a passkey is added to their account, and whenever they remove one themselves. | `notifyPasskeyAdded`, `notifyPasskeyRemoved` | `TestAddingAPasskeySendsANotice`, `TestRemovingAPasskeySendsANotice` |
| G28 | A code's count of wrong guesses survives a restart, and a code whose total is spent stays destroyed. Codes sent to one address from unfamiliar networks are bounded per day as well as per hour, and the administrators are emailed, at most once a day for each permitted address and ten times a day in all, when an address reaches the daily limit or a code is destroyed; the first alert held back says that alerts have stopped. | `ConsumeCode`, `allowSend`, `alertAboutCodes` | `TestCodeAttemptBudgetSurvivesRestart`, `TestDailyCeilingBoundsASlowFlood`, `TestDailyCeilingAlertsAdministratorsOnce`, `TestNoCodeAlertForAnAddressNotPermitted`, `TestCodeAlertsAreCappedPerDay`, `TestBurnedCodeAlertsAdministrators` |

## What this repository cannot prove

- **C9, reachability.** Only the server can show that the gateway and apps
  publish no ports and share networks only with Caddy.
- **The server repos' guard snippets.** Each server keeps its own copy of
  `auth.caddy`, and the copies have diverged. Each server's CI runs this suite
  against its own copy with
  `E2E_AUTH_CADDY=/absolute/path/to/apps/auth/auth.caddy scripts/e2e.sh`. The
  copy is tested as written, with two allowances that carry no security: a
  hard-coded auth host is renamed to the test domain, and `protected_open` is
  taken from the reference copy if the server has no guest sign-in. A copy
  missing any other snippet, `strip_public` included, fails the run. The
  public routes themselves live in each app's own Caddy file, which this suite
  does not see.
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
- A visitor with no session who sends a role guard's headers to `/verify`
  learns the domains of a role whose assignments are domain groups only, in
  the login URL's hint, as a domain guard has always shown its domains. Any
  other holder of a role, and an open invitation or a card, shows only as
  the role guard's mark (`rqr=1`), and an undeclared app or role is answered
  in the same way, so app and role names cannot be tried out
  (`roleLoginHint`, `TestRoleGuardLoginHint`,
  `TestRoleGuardNetworkWithoutSession`).
- An older Safari, which sends no `Sec-Fetch-Site`, can be made to sign out or
  start a sign-in by another site. It cannot complete one.
- A stolen session works until it expires, the person's listing is removed, or
  the person (or an administrator) signs them out on every device. One device's
  session cannot be ended on its own. No session outlives `SESSION_MAX_AGE`.
- Ending sessions early needs one gateway process per database: the cutoffs
  are held in memory and written through to SQLite. The gateway enforces it:
  a second process on the same database refuses to start
  (`lockDatabase`, `TestOneGatewayPerDatabase`). The lock needs a local
  volume; a network file system may not honour it.
- A sibling app can overwrite the session cookie outright. Every site on the
  shared cookie domain must be one the department trusts; a third-party or
  untrusted app belongs on a separate domain with its own gateway.
- Cutoffs and sign-in times are whole seconds, and a session that began in
  the same second as a cutoff counts as ended. The edge fails safe: a sign-in
  in the same second as "sign out on every device" is refused (a real sign-in
  takes longer), and a group change in the same second as a renewal costs a
  few extra renewals within that second. Finer times would change the
  session format and sign everyone out.
- While every sign-in mail slot is busy, a code request sends nothing and
  stores only an insert-if-absent decoy that leaves no cooldown, for every
  address alike, as when over the send limit; a wrong guess is answered as at
  any other time, so the flood cannot be seen (`mailSaturated`,
  `TestCodeRequestDuringAFloodCannotBeSeen`). The person asks again once the
  flood drains. A code saved just as the last slot fills may go unsent; the
  person asks again after the cooldown.
- One administrator can act as another, because the person who issues a
  second-factor secret sees it once.
- A passkey is as safe as the phone and the Apple or Google account that
  syncs it. Registration asks for no attestation, so the gateway cannot tell
  which device made a key; registration is only as strong as the session that
  asks for it, which is why G18 requires a recent sign-in.
- A stolen session cookie used within 15 minutes of an emailed-code sign-in
  can register a software key, since attestation is "none" and nothing at
  registration is signed. The account holder is emailed whenever a passkey
  is added (`notifyPasskeyAdded`, `TestAddingAPasskeySendsANotice`), and the
  key is listed on their passkeys page and the access page until removed.
- Rolling back to a build without passkeys keeps passkey sessions renewing
  whatever happens to their passkeys, and keeps an admin passkey session's
  second-factor mark. If a passkey compromise coincides with a rollback,
  rotate `SESSION_SECRET`.

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
