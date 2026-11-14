# Architecture

How Gateweave Guard is built today, and the shape it is planned to take. This file changes with
the code.

## What exists

One Worker (`apps/web`), the same shape as Gateweave Track, Gateweave Agents and Gateweave Mail:

- **TanStack Start** renders pages on the server and hydrates them in the browser. Server
  functions are the API: each one checks the session and, for workspace data, the caller's
  membership before doing anything.
- **Better Auth** owns accounts, sessions, workspaces (its organizations), members, roles and
  invitations, stored in **D1**. There is one Better Auth instance per isolate, built on first
  use, because workerd forbids I/O in global scope. It can also sign people in through an OpenID
  Connect provider, and through GitHub: see "Signing in through a provider" below.
- **Rate limits** on sign-in, password reset, invitations and email are counted in a
  `RateLimiter` Durable Object per client address or recipient, so they hold across isolates and
  locations. Everything else is limited in memory per isolate. Every Worker reaches another zone
  from one address, `2a06:98c0:3600::103`, so a request with that address and a `cf-worker` header
  is counted by the zone it names, which Cloudflare sets and a sender cannot change
  (`workers-address.ts`). Better Auth counts a request before anything in it can step in, so the
  request is changed before it gets there.
- **Email** goes through Cloudflare Email Service when `EMAIL_FROM` is set: password reset,
  verification and invitations. Without it, invitations are links to share.
- **What is past its time** goes once a day, on a Cron Trigger every deployment inherits from
  `wrangler.jsonc` (`apps/web/src/server/db/prune.ts`). Better Auth removes a session or a
  verification only when something looks it up, so those nobody comes back for would otherwise
  stay, with the address and browser a session holds, and invitations with the address they were
  sent to. The privacy policy states these, so a change there is a change to it.
- **Security headers** go on every answer, and a page also gets a policy that names its scripts by
  a nonce of that response (`security-headers.ts`). Nothing is framed and no host is allowed by
  default; a member's picture may come from GitHub or the sign-in provider's own host.
- **Origin checks.** A request that changes something from a browser must carry this deployment's
  own `Origin`, which Better Auth checks for its routes.

What a workspace shows today is the shell and no more: a page each for **Findings** and
**Connections**, **Settings** (members, invitations, the workspace itself) and, for whoever runs
the deployment, **Server**. A workspace with nothing connected says so, and a workspace with
connections and nothing wrong says "No open findings." Guard reads from a Cloudflare account
or a repository only once an admin has connected it: see the next section.

### Connections, scans and findings

An owner or admin connects a **Cloudflare account** (its id and an account API token) or a **GitHub
repository** (`owner/name` and a fine-grained token). Everyone in the workspace sees the connections
and findings, without tokens. Guard only reads: it asks for the least access that reads (Account ›
Security Center Insights › Read, with Zone › Security Center Insights › Read and Zone › Analytics ›
Read on all the account's zones; Contents: Read-only on one repository), and nothing in it changes a
setting, a rule or a file. The endpoints are `/api/connections/<workspace>` and
`/api/findings/<workspace>` (`apps/web/src/server/connections/`), the pages are the Connections and
Findings screens, and the schemas both agree on are in `apps/web/src/lib/connection-schemas.ts`.

- **Every request asks first.** A change needs the app's own `Origin`, a session, and
  `isAdminRole` for the member's role; a non-member gets the same "not found" as a missing
  workspace. Input is checked with zod at the boundary: a Cloudflare account id is 32 hex
  characters, a repository goes through `parseRepositoryName`, a token is 20 to 400 printable
  characters without spaces, and a reason for dismissing is at most 200.
- **A token is checked before it is kept.** Cloudflare: one `listInsights` call, where a refusal
  names the permission Account › Security Center Insights › Read (Guard cannot read a Cloudflare
  token's own permissions, so a call that needs it is the only proof). The zone permission can't be
  proved this way: a token without it is accepted, and Cloudflare then answers with the account's
  own insights only, leaving out those of its zones (measured on 2026-11-14: 29 of an account's 111
  active insights, and none of its 4 critical ones). So the form asks for the permissions in words.
  The zone permission for Analytics is proved: the check also lists the account's zones and, when
  one is active, asks it a small real GraphQL question (`probeTraffic`), and a refusal there names
  Zone › Analytics › Read. GitHub: `getRepository`, then
  `branchHead`, which proves Contents read; the repository's id is kept, since a rename keeps it. A
  workspace has up to 50 connections (checked in the endpoint, held by the trigger
  `connection_is_capped` in `0004_connection_cap.sql`), each target once, and a repository once
  however its name is written (`connection_repository_unique`). Checking tokens is rate limited per
  workspace (20 at once, refilling over an hour), since each goes to a third party.
- **A token is sealed** (`secrets.ts`, `secrets-key.ts`, ported from Gateweave Mail). `SECRETS_KEY`
  is 32 random bytes; each use gets its own AES-256-GCM key by HKDF from it and the workspace's id,
  and the connection's id is the additional data (`connection/<id>/token`), so a sealed token copied
  into another row or workspace does not open. A seal is `v2.<key id>.<iv>.<data>`; the key id is a
  keyed digest of the key, so a seal names the key that opens it. `SECRETS_KEY_PREVIOUS` only opens.
  After the key changes, the daily run seals each token again under the new key
  (`reseal-secrets.ts`: up to 500 a run, in pages so tokens that open with neither key never hold up
  the rest, each written only if it is still the value that was read), and logs `secrets:` with
  counts only. Without a usable `SECRETS_KEY`, connecting is refused with the reason and the page
  says the server is not set up for it. A token is opened only inside a scan or a check, never
  returned: pages get `token_hint`, its last four characters. Nothing logs a token, and
  `packages/scan`'s errors carry the status and no body.
- **A scan reads, then writes in one D1 batch.** Cloudflare: `listInsights`, where an insight that is
  `active` and not `dismissed` in Cloudflare's dashboard is present. GitHub: `scanRepository`, one
  finding per lockfile, package and advisory. Each present problem has a **fingerprint**
  (`insightFingerprint`: account, class and subject; `dependencyFingerprint`: repository id,
  lockfile, package and advisory, without the installed version, so moving to another affected
  version is the same finding). A present finding that is new is inserted; one already known has its
  severity, title, subject, link and last-seen time updated and is **reopened** if it was resolved;
  an open one that is no longer present is **resolved**. What a scan could not see does not count as
  gone: a lockfile Guard cannot read or that is too large keeps its findings as they are, and so does
  a repository GitHub listed only in part. **A dismissed finding stays dismissed whatever a scan
  sees**, until an admin un-dismisses it, and so is kept up to date underneath. A scan that fails
  changes no finding, and records its kind on the connection (`unauthorized`, `forbidden` and
  `not_found` mean it needs attention, and the page says what to fix; `rate_limited` and
  `unavailable` are tried again within the hour; `unreadable` means the stored token no longer
  opens). The last 30 scans of a connection are kept, with how many problems were found, new and
  closed.
- **Findings hold what a page shows and nothing of what was read:** the severity, a kind (the
  insight's class, or the advisory's id), the subject (hostname or zone, or `package@versions in
  lockfile`), a title, a link, the fixed version, and when it was first and last seen, resolved and
  dismissed. No insight payload and no lockfile content is stored. The title of a Security Insight
  is Guard's own short English text per class (`server/connections/titles.ts`), since the API
  sometimes sends translation keys; a class Guard has not seen gets its name made readable. The
  link is the dashboard URL `packages/scan` builds, which can only point at `dash.cloudflare.com`,
  or the advisory on osv.dev. Removing a connection deletes its token, findings and scans at once,
  by foreign-key cascade.
- **Scans without a Queue.** The hourly Cron Trigger (`0 * * * *`) scans the connections whose
  `next_scan_at` has passed, oldest first, at most 10 a run, one after another, and then sets
  the next scan a day ahead (an hour ahead after a failure that passes with time). "Scan now" runs
  the scan inside the request, for admins, at most once in five minutes per connection (the
  `RateLimiter`). A connection is never scanned twice at once: a conditional `UPDATE` sets
  `scan_started_at` before the token is read, and only the scan that set it goes on; a scan that
  dies lets go by itself after ten minutes. There is no Queue because a self-hoster then gets no
  extra resource to create and pay for, and a scan is a few seconds and a handful of subrequests
  (one for Cloudflare; a few for GitHub plus OSV's batched lookups), which one Worker invocation
  carries. A Queue would be needed when scans stop fitting: more than 240 connections on one
  deployment (10 an hour), a repository whose scan outruns an invocation's CPU or subrequest limits,
  or scans that must not wait for the hour. Each scan would then be a message, with retries and
  backoff for the failures that pass with time, and the claim in D1 would stay as it is.
- **The first scan runs when the token is connected,** in that request, so the page has something
  to show; if it fails, the connection stays and says what failed.
- **An admin can replace a token** (`replace-token`): the new one is checked the same way, for the
  same repository, then sealed and scanned. It is how a connection that needs attention is mended
  without losing what has been dismissed.

### Traffic

Guard counts what a Cloudflare account's WAF and bot features did to each zone's requests, per UTC
day, and raises a finding when a zone's day is far above its usual. It needs the zone permission
Analytics › Read, on all zones. The code is `packages/scan/src/traffic.ts` (what is asked of
Cloudflare), `apps/web/src/server/connections/traffic.ts` (what a scan reads, judges and writes) and
`traffic-gateway.ts` with the Traffic page (what members see).

- **What is read.** After Insights, a scan lists the account's zones (REST `GET /zones`, paged;
  only `active` ones are kept). For the full UTC days not stored yet, from yesterday back to 8 days
  ago (so a first scan already has the week the spike rule needs), it reads
  `httpRequestsAdaptiveGroups` with `securityAction_neq: "unknown"`, grouped by `date`: counts by
  action and security feature, and the top 10 countries and hosts among the mitigated requests.
  Today is incomplete and is never read or stored. For yesterday only, and only for the 20 zones with
  the most acted-on requests, it reads the rules that acted, from sampled events
  (`firewallEventsAdaptive`): at most two pages of `min(10000, maxPageSize)`, each event weighted
  by its `sampleInterval`, the top 10 by count, marked `partial` when the cap cut the day short.
  A zone's `last_day` is the last complete day read, so a scan with nothing new to read asks
  Cloudflare for no counts.
- **What is stored, and what never is.** D1 holds counts and nothing that names a visitor:
  `traffic_count` (connection, zone, UTC day, dimension `action`, `country`, `host` or `rule`, key,
  count, and for a rule its description, source and whether it is partial) and `traffic_zone` (the
  zones a connection last saw: id, name, plan, the first and last day of the contiguous run of days read, last failure). Both cascade from the
  workspace and from the connection, so removing a connection removes its traffic, and a zone that
  leaves the account takes its counts with it. A scan deletes the connection's days older than 90.
  Guard asks only for `ruleId description source action sampleInterval datetime` of an event, and
  never for an address, a user agent, a path, a query, a ray id or an ASN;
  `packages/scan/test/traffic.test.ts` and `apps/web/test/traffic.test.ts` fail if a query names one,
  or a column could hold one. Host names are the customer's own zones'. No traffic is ever logged.
- **What was measured** on 2026-11-14, on an account of 30 Free zones, since the docs state little:
  `firewallEventsAdaptiveGroups` is off on the Free plan (`settings` says `enabled: false` and a
  query fails), so it is never asked for; `httpRequestsAdaptiveGroups` works on Free (30 days a
  query, up to 10,000 groups a page, a `count` already scaled for sampling, no rule id) and its
  `botScoreBucketBy10` is refused; `firewallEventsAdaptive` works on Free and has `ruleId`. A query
  may name 10 zones at most, so zones are asked ten at a time, nested in the account
  (`viewer.accounts(filter: {accountTag}).zones(filter: {zoneTag_in})`), with
  `X-Rate-Limit-Type: account-based` so each zone has its own budget. At most four calls are in
  flight. Errors come back as HTTP 200 with an `errors` array: a missing permission is
  `zones [<tag>] are not authorized` or `Actor … does not have permission`, and a spent budget has
  `extensions.code` `budget`. They become `forbidden` and `rate_limited`; only the kind is kept,
  never the message, which may carry a token's id.
- **It never fails the Insights.** The token's traffic failure is kept on the connection
  (`connection.traffic_outcome`: `ok` or a failure kind) and, for a zone that failed alone, on the
  zone (`traffic_zone.last_failure`), and the Connections and Traffic pages say what to fix. The
  traffic is written in a batch of its own before the findings are changed, so a failing write cannot
  keep the insights from being recorded. A failure that passes with time brings the next scan within
  the hour; the days already read are not read again.
- **The spike rule.** `waf_spike`, source `cloudflare`, one finding per zone, severity `low`
  (the WAF is working; it is worth a look, not an alarm). Yesterday's mitigated requests are more
  than 5 times the median of the 7 days before, with at least 3 of those days known and at least
  500 mitigated requests yesterday. A known day is one Guard has read: in the run from `first_day` to
  `last_day`, a day with no rows had nothing acted on and counts as 0, while a gap (a long pause or a
  failing token) starts a new run so unread days are never zeros. Mitigated means the actions `block`, `challenge`, `jschallenge`,
  `managedChallenge` and `connectionClose` (the API lists its `securityAction` values nowhere, so
  anything else, such as `log` or `skip`, counts as the request getting through). The fingerprint is
  `traffic:<account>:waf_spike:<zone id>`, so it is one finding while it lasts and resolves on the
  first scan where yesterday is no longer a spike. Like an unreadable lockfile, a zone Guard could not
  read keeps its finding open, and a connection whose traffic could not be read keeps all of its
  traffic findings open (`held` in `scan.ts`).
- **The Traffic page** (`/$workspace/traffic`, `GET /api/traffic/<workspace>`) is for any member and
  answers a non-member as a missing workspace. Per zone it draws the stored days as inline SVG bars
  with a text summary beside it, and lists yesterday's top rules (marked "sampled", or "partial"), the
  top countries and hosts of the last seven days, and this week against last week. A zone with nothing
  stored says why: not scanned yet, no permission, or nothing acted on.

### Protection

Guard shows what each Cloudflare zone has: which protections are on, the zone's custom WAF rules,
and what those rules have done. It is for people who do not live in the dashboard, so the page
speaks in plain sentences, shows at a glance what is wrong, and links each fix to the zone's page in
Cloudflare. It needs three read permissions on all zones, all optional: Zone › WAF › Read, Zone ›
Bot Management › Read and Zone › Zone Settings › Read. Connecting still needs only the first three
(Insights and Analytics). The code is `packages/scan/src/protection.ts` (what is asked of
Cloudflare), `apps/web/src/server/connections/protection.ts` (what a scan reads, judges and writes),
`protection-gateway.ts` with the Protection page (what members see), and
`apps/web/src/lib/protection.ts` (the statuses, sentences and overview counts, which are plain
functions with unit tests).

- **What is read.** After Traffic, a scan reads each of the zones Traffic listed (the active ones),
  one zone at a time, with five requests made together: the entrypoint rulesets of the phases
  `http_request_firewall_custom`, `http_request_firewall_managed` and `http_ratelimit`
  (`GET /zones/{zone}/rulesets/phases/<phase>/entrypoint`, which answers 404 when the zone has
  nothing there), `GET /zones/{zone}/bot_management` (`fight_mode`) and
  `GET /zones/{zone}/settings/security_level`. When a managed ruleset is deployed, a sixth request,
  `GET /zones/{zone}/rulesets`, gives its name. DDoS is not read (it needs another permission and is
  always on), and `http_request_sbfm` is not a phase on these zones.
- **What was measured** on 2026-11-14, on an account of 30 Free zones: the custom entrypoint
  answers 200 with `rules[]` (`id`, `ref`, `version`, `action`, `description`, `enabled`,
  `expression`, `last_updated`) or 404 when there are none; the managed one is 404 on all 30; the
  rate limiting one is 404 when there are no rules; bot management and the security level answer
  200 with the permission and 403 without it.
- **A rule's expression is never read or kept.** An expression can hold the customer's own secrets
  (a header value, an address in a skip rule). The field is left out of every schema in
  `packages/scan/src/protection.ts`, so zod strips it at the boundary, no column could hold it, and
  tests fail if one is stored, returned or shown. Of a custom rule Guard keeps its id, action,
  description (cut to 200 characters), whether it is on, and when it changed.
- **Each part stands alone.** Every part is `ok`, `none` (a 404 on an entrypoint) or `failed` with a
  failure kind, and one failing never spoils the others: a token with WAF but not Zone Settings
  still shows the rules. A failure never fails the scan or the Insights. The zone's row says which
  parts failed, the page says which permission is missing, and a failure that passes with time brings
  the next scan within the hour. Only a failure's kind is kept, never a message.
- **What is stored.** `protection_zone` (one row per connection and zone: each part's state, its
  values or failure kind, and when it was read) and `protection_rule` (the zone's custom rules,
  replaced on every scan, so a rule deleted in Cloudflare, or one that can no longer be read, does
  not linger). Both cascade from the workspace and the connection, and a zone that leaves the account
  takes its rows with it. They are written in a batch of their own before the findings change, as the
  traffic is.
- **Subrequests.** A zone costs five requests (six with a managed ruleset), on top of what Insights
  and Traffic cost. A Worker on Workers Paid may make 10,000 subrequests an invocation, so an account
  of a few hundred zones is within it; on the Free plan's 50 only a handful of zones fit. Requests
  are made five at once, one zone after another.
- **One finding, from configuration.** `security_level_off`, severity `low`, one per zone, when the
  security level is `essentially_off`; the fingerprint is
  `protection:<account>:security_level_off:<zone id>`, so it is one finding while it lasts and
  resolves on the first scan where the level has changed. Like the spike finding, it is held when
  the level could not be read, and every one is held when the zones could not be listed or the write
  failed. Insights already raises Bot Fight Mode and AI-bot findings (`manage_bot_fight_mode`,
  `no_challenge_ai_bots`) and Guard has seen no class for the security level or for managed rules on a
  real account (`titles.ts` lists the classes seen), so it raises no finding for managed rules being
  off: the Protection page shows it, and the overview counts it.
- **The Protection page** (`/$workspace/protection`, `GET /api/protection/<workspace>`) is for any
  member and answers a non-member as a missing workspace. At the top, one line per issue across all
  zones ("Bot Fight Mode off on 21 of 30 zones"); each is a filter on the zone list below. Per zone,
  a checklist of five lines (managed rules, custom rules, rate limiting, Bot Fight Mode, security
  level), each with a status in words (Good, Worth a look, Not set up, Not readable, Not read yet),
  one sentence on why it matters, and where action is needed a "Fix in Cloudflare" link
  (`apps/web/src/lib/dashboard-links.ts`, the one module that knows the dashboard's paths). A part
  Guard cannot read says which permission to add and links to Connections. Under the checklist are
  the zone's custom rules: description, action, on or off, when it changed, and how much it acted.
- **A rule's activity comes from Traffic.** The page joins `protection_rule.rule_id` with the
  `traffic_count` rows of dimension `rule` (their key is the rule's id). Traffic keeps only the top
  10 rules of the 20 busiest zones for each day, from sampled events, so a rule with no row may still
  have acted. The page therefore says "No activity recorded" and never that a rule did nothing.
- **Token links.** Cloudflare's docs describe template URLs that pre-fill the token form
  (`https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=[…]&name=…`, with keys
  such as `analytics` and `zone_settings`), but list the keys of only a few permissions, and none
  for WAF, Bot Management or Security Center Insights. A link with guessed keys would tick the wrong
  boxes without saying so, so the connect form links to the token page and lists the permissions in
  words.

### Words and numbers

Every user-facing string of a screen sits in one object (`TEXT`) near the top of its module, and
dates and numbers go through `Intl` (`apps/web/src/lib/dates.ts`, `numbers.ts`), so that
translating a screen is a matter of one place and no library. The new screens (Findings,
Connections, Server and the navigation) do this. The screens that came from Mail (sign-in, the
account page, members) still have their strings inline, and move over when they are translated.

### Where the data lives

Gateweave Cloud keeps its data in the EU. Its D1 databases were created in the `eu` jurisdiction,
and `DURABLE_OBJECT_JURISDICTION=eu` keeps the Durable Objects there, so the rate limits' objects,
which are named after hashed addresses, stay beside them (`apps/web/src/server/jurisdiction.ts`).
An unknown jurisdiction fails loudly rather than count in no jurisdiction at all: the operator
asked for their data to stay somewhere. Each Cloud environment runs its Worker near its database
(`placement` in `wrangler.jsonc`: Warsaw for production, Milan for staging, as `served_by_colo`
showed when each database was made), because every query goes to the database's one primary.
Self-hosters set neither and get Cloudflare's defaults.

### Who owns a deployment

**One account runs the deployment, and decides who else may make an account.** A row in
`deployment` (one row, `id` = 1) names the owner (`owner_id`), says whether sign-up is `open` or
`closed`, and whether the sign-in provider is trusted (`trust_provider`). A second table,
`sign_up_allow`, is the owner's list. `apps/web/src/server/auth/deployment.ts` asks, and the
triggers in `0002_sign_up_hold.sql` hold it. It came from Gateweave Agents, with its tests, and is
owned here now.

- **A new deployment is open.** Its first account becomes the owner
  (`first_account_owns_deployment`). D1 runs writes one at a time, so there is only one first. The
  owner closes sign-up on the Server page.
- **Closed means an address needs a way in.** The first account of a deployment with none; an
  address on the list, or at a domain on it; an address with a pending, unexpired invitation to a
  workspace, from any workspace's admin; or, where the owner trusts the provider, an account made
  through it. GitHub is never trusted that way. People who already have an account sign in as ever.
- **The list holds an address, lowercased, or a domain written with a leading `@`.** A domain
  covers addresses at exactly that domain, which is the part after the last `@`, and not its
  subdomains. Entries are checked with zod at the owner's endpoint
  (`apps/web/src/lib/sign-up-allow.ts`). A note of at most 200 characters is the owner's own. At
  most 5,000 entries, which the endpoint says and the trigger `sign_up_allow_is_capped` holds.
  Taking an entry off lets no more people in; an account it already made stays. It names people
  who may have no account, so it is personal data.
- **Every path that makes an account asks.** `databaseHooks.user.create.before` in
  `auth/config.ts` covers email and password sign-up, GitHub, the sign-in provider and accepting
  an invitation. `mayMakeAccount` is the one function that decides. A `before` hook on
  `/sign-up/email` asks first, so that "that address is taken" does not tell a stranger which
  addresses have an account.
- **The database refuses the rest.** The trigger `user_needs_a_way_in` has the same rule for a path
  that forgets to ask, and a missing `deployment` row counts as closed. Whether an account comes
  from the provider is known only when its sign-in is linked, which is after the row is written,
  so the hook writes a pass for the address in `sign_up_pass`, good for a minute, and only where
  the owner trusts the provider. With trust on, the trigger lets an insert through only while an
  unexpired pass exists.
- **The refusal says one thing for every address:** "This server takes new accounts by invitation.
  Ask whoever runs it to invite you." With `SIGN_UP_REQUEST_URL` set to an https address, the
  sign-in pages add "Ask for access", which leads there.
- **Everything the owner does needs a recent sign-in** and is the owner's alone: anyone else gets
  the same 404 as for a path that does not exist (`/deployment/*` in `deployment.ts`).
- **The owner's account stays while sign-up is closed.** Without it nobody could open sign-up or
  change the list. `deployment_keeps_its_owner` holds it, and deleting an account says so. While
  sign-up is open the account may go, and ownership passes to the earliest account left
  (`deployment_hands_over_its_owner`).

### Workspaces

Workspaces are Better Auth organizations. Members have a role: `owner`, `admin` or `member`.
What only owners and admins may do is decided with `isAdminRole` (`apps/web/src/lib/roles.ts`),
never by comparing a role with `member`. A role this version does not know counts as a member's,
the least there is. Every server function that touches a workspace starts at `currentMember`, and
a non-member gets the same "not found" as a missing workspace.

Two triggers on `member` (`apps/web/migrations/0001_owner_triggers.sql`) make sure a workspace
keeps an owner however a row comes to change, because the plugin and the account deletion endpoint
both count owners and then act, and two owners leaving at once could each see the other still
there. They let go of a workspace that is being deleted, which is why
`beforeDeleteOrganization` deletes the organization row first and its members follow by cascade.

### Signing in through a provider

With `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` set, Guard is a client of an OpenID
Connect provider, through Better Auth's `generic-oauth` plugin
(`apps/web/src/server/auth/oidc-sign-in.ts`). What comes out of it is an account row and an
ordinary session, so nothing past the sign-in page knows the difference. Gateweave Track,
Agents and Mail have the same code, and the same reasons.

- **Discovery waits until someone needs it.** The plugin's `init` waits for the provider's discovery
  document with no time limit, and every request to a new isolate waits for `init`, so a slow
  provider would stop password sign-in and every session check. Guard replaces `init` so that each
  isolate starts as the plugin does after a failed discovery, which it retries, within 10 seconds,
  for a request that names the provider. That sets a field of the plugin's that is not public, so an
  upgrade that moves it fails the tests rather than the deployment.
- **Linking is never assumed.** The provider is not in `trustedProviders`, so an existing account
  links only when the provider says the address is verified and Guard's account has verified it
  too. Anything but a JSON `true` in `email_verified` counts as unverified.
- **Guard keeps no tokens of the sign-in.** It signs people in and never acts for them at the
  provider, so the account hook clears them all, and the ID token too, as soon as it has served its
  purpose. The same goes for signing in with GitHub. (Tokens for the accounts and repositories
  Guard will read are another matter, and are sealed: see "Connections, scans and findings".)
- **The provider can end sessions.** `POST /api/auth/backchannel-logout/oidc` takes a logout token,
  checked against the provider's keys: issuer, audience, at most 5 minutes old, the logout event and
  no nonce. A session row keeps the `sid` of the ID token it came from (`session.oidc_sid`, never
  sent to the browser). Once a token has arrived it is seen through with `waitUntil`, even if the
  provider stops waiting.
- **Signing out of Guard stays in Guard.**

### Deleting an account

People delete their own account on `/settings/account`, through `POST /api/auth/account/delete`
(`apps/web/src/server/auth/delete-account.ts`). Better Auth's `/delete-user` stays off: it lets
someone with a password through without it.

- **What it asks for.** A session from the last day, and the password if the account has one.
  Better Auth's `/unlink-account` is disabled, because it removes a password on a recent session
  alone. So are the other routes it offers any session and the app has no use for. The list is
  `disabledPaths` in `apps/web/src/server/auth/config.ts`, and
  `apps/web/src/server/auth/routes.test.ts` fails when an upgrade adds a route to what answers, so
  someone decides about it.
- **A workspace keeps an owner.** The only owner of a workspace is refused and told which.
- **The deployment keeps its owner while sign-up is closed.** See "Who owns a deployment".
- **D1 goes in one batch:** the user is deleted and the invitations addressed to them are taken.
  Foreign keys take the sessions, sign-ins, memberships and the invitations they sent. A trigger's
  refusal leaves everything in place.

### Changing a name or password

People change both on `/settings/account`, through Better Auth's `/update-user` and
`/change-password`, and what stands behind either may be a stolen cookie. The rules are in
`apps/web/src/server/auth/account-changes.ts` and the hooks of `config.ts`.

- **A rename takes a name and nothing else:** 1 to 100 characters once trimmed, which sign-up keeps
  to as well. The route would otherwise set a picture too, whose address everyone in someone's
  workspaces fetches. It allows ten a minute.
- **A new password needs the current one,** at five tries a minute from one client address, and
  sends the person an email, which may be how they first hear that someone else has it.
- **Tries at a password are also held per person,** since a stolen cookie can be sent from many
  addresses (`apps/web/src/server/auth/password-tries.ts`). This and deleting an account share an
  allowance of 10 at once, refilling over an hour, within 30 that refill over a day. Only a request
  with a session for that account spends it, so nobody can lock a person out with their address
  alone, and signing in is not part of it.
- **It ends every session,** whatever the request asks, since whoever knew the old password may be
  why it is changing and may be the one asking.

## Not built yet

This is where it is going, and it may change. What is above stays as it is: one Worker for the UI,
the API and auth, with D1 for accounts and workspaces.

- **More rules from configuration and traffic.** Only the spike and the security level are built
  (see "Traffic" and "Protection"). A finding for managed rules being off waits for a measurement of
  which insight class says so; until then the Protection page shows it. Guard does not yet read
  account-level rulesets, DDoS overrides or Super Bot Fight Mode's settings.
- **Token links with the permissions ticked** wait for Cloudflare to document the template keys of
  the WAF, Bot Management and Security Center Insights permissions.
- **A finding becomes a Gateweave Track issue**, or a fix pull request from Gateweave Agents.
- **An MCP server**, so agents can read findings.
