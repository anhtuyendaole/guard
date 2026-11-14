# Changelog

Notable changes to Gateweave Guard, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org). Until 1.0, any release may change how things work:
read its entry before updating a self-hosted copy.

Each version's [GitHub release](https://github.com/gateweavehq/guard/releases) carries the same
notes. Publishing a release deploys it.

## [0.1.0] - 2026-11-14

The first release of Gateweave Guard: security in one place for teams on Cloudflare. It reads a
Cloudflare account and GitHub repositories with read-only tokens, shows what is wrong, what
protects each zone and what got blocked, tells people when something new and serious appears, and
turns a finding into an issue in Gateweave Track. It never changes a setting, a rule or a file.

### Added

- **Workspaces and sign-in.** Email and password, or an OpenID Connect provider such as Gateweave
  ID; workspaces with owners, admins and members; invitations; a deployment owner who decides who
  may make an account. ([#1](https://github.com/gateweavehq/guard/pull/1))
- **Connections and findings.** A Cloudflare account connects with a read-only API token (Account
  and Zone Security Center Insights Read, Zone Analytics Read), a GitHub repository with a
  fine-grained token that reads Contents. Tokens are checked, sealed with `SECRETS_KEY` and never
  shown again. Scans run every day and on "Scan now", and list Security Insights and known
  vulnerabilities in pnpm and npm lockfiles (from OSV) as findings by severity, which close by
  themselves when a scan no longer sees them.
  ([#2](https://github.com/gateweavehq/guard/pull/2), [#4](https://github.com/gateweavehq/guard/pull/4),
  [#5](https://github.com/gateweavehq/guard/pull/5))
- **Traffic.** Daily counts of what the WAF and bot protection stopped or challenged in each zone,
  by action, rule, country and host, kept 90 days, with a finding when a zone's WAF stops far more
  than usual. Never IPs, user agents or paths.
  ([#7](https://github.com/gateweavehq/guard/pull/7))
- **Protection.** What protects each zone, in plain words: WAF managed rules, custom rules and what
  each did, rate limiting, Bot Fight Mode and Under Attack mode, with "Fix in Cloudflare" links and
  an overview across zones. Three more read permissions turn it on; a rule's expression is never
  stored. ([#9](https://github.com/gateweavehq/guard/pull/9), [#11](https://github.com/gateweavehq/guard/pull/11))
- **Alerts.** A count of new findings in the sidebar, an email for new critical and high findings
  (at most one an hour per workspace), a weekly summary on Mondays, switches in Settings and a
  one-click unsubscribe. ([#10](https://github.com/gateweavehq/guard/pull/10))
- **From a finding to work.** Connect a Gateweave Track workspace with an agent member's key, and
  "File in Track" makes one issue per finding; for a dependency with a fixed version, "Ask Agents
  for a fix" adds the label a Gateweave Agents trigger watches.
  ([#12](https://github.com/gateweavehq/guard/pull/12))

### If you run your own

- See [docs/self-hosting.md](docs/self-hosting.md): it needs Workers Paid, a D1 database and, to
  connect anything, `SECRETS_KEY`. Keep a copy of `SECRETS_KEY` outside Cloudflare: without it, the
  tokens in the database and its backups cannot be opened.
