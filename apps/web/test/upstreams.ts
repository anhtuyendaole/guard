/**
 * Stands in for Cloudflare's API, GitHub's and OSV, with answers shaped as the real ones are (the
 * shapes `packages/scan` is tested against), so that the Worker's tests never reach the internet.
 * State is plain data a test changes between scans: an insight appears, a package is fixed, a token
 * is revoked.
 */

export const ACCOUNT_ID = "023e105f4ecef8ad9ca31a8372d0c353";
export const OTHER_ACCOUNT_ID = "5fb0a1a1b2c3d4e5f60718293a4b5c6d";

export interface FakeInsight {
	id: string;
	issue_class: string;
	subject: string;
	severity?: string;
	status?: "active" | "resolved";
	dismissed?: boolean;
}

/** What a zone's security features did on one UTC day, as Cloudflare's analytics groups it. */
export interface FakeDay {
	actions: { action: string; source: string; count: number }[];
	countries?: { name: string; action: string; count: number }[];
	hosts?: { name: string; action: string; count: number }[];
}

/** One sampled firewall event, with the fields Guard asks for and no others. */
export interface FakeEvent {
	ruleId: string;
	description: string;
	source: string;
	action: string;
	sampleInterval: number;
	/** `2026-11-13T10:00:00Z`. */
	datetime: string;
}

/** A rule of a zone's WAF as Cloudflare lists it, expression and all. */
export interface FakeRule {
	id: string;
	action: string;
	description?: string;
	enabled?: boolean;
	expression?: string;
	last_updated?: string;
	action_parameters?: Record<string, unknown>;
}

/** The parts of a zone's protection Guard reads, each of which may be refused alone. */
export type ProtectionPart = "custom" | "managed" | "rateLimit" | "bot" | "level";

export interface FakeZone {
	id: string;
	name: string;
	status: string;
	plan: string;
	/** Whether the token has Analytics › Read on this zone. */
	analytics: boolean;
	/** `YYYY-MM-DD` to what happened. A day left out had nothing acted on. */
	days: Record<string, FakeDay>;
	events: FakeEvent[];
	eventsEnabled: boolean;
	maxPageSize: number;
	/** The entrypoint of each WAF phase. A phase left out answers 404, as a zone with no rules does. */
	custom?: FakeRule[];
	managed?: FakeRule[];
	rateLimit?: FakeRule[];
	/** The zone's rulesets, which name the managed ones. */
	rulesets: { id: string; name: string }[];
	botFightMode: boolean;
	securityLevel: string;
	/** Whether the token has Zone WAF, Bot Management and Zone Settings: Read on this zone. */
	permissions: { waf: boolean; bots: boolean; settings: boolean };
	/** An HTTP status to answer a part with instead, such as 500. */
	protectionStatus: Partial<Record<ProtectionPart, number>>;
}

interface FakeAccount {
	token: string;
	insights: FakeInsight[];
	zones: FakeZone[];
	/** An answer to give instead of the insights, such as 500. */
	status?: number;
	/** An answer to give instead of the zone list, such as 500. */
	zonesStatus?: number;
	/** Answer GraphQL with Cloudflare's `budget` error, as an account over its limit does. */
	budget?: boolean;
}

/** A GraphQL request that reached the stand-in. */
export interface SeenQuery {
	query: string;
	variables: Record<string, unknown>;
	rateLimitType: string | null;
}

interface FakeRepository {
	id: number;
	token: string;
	branch: string;
	/** Whether the token may read contents, or only the repository itself. */
	contents: boolean;
	/** path to text */
	lockfiles: Record<string, string>;
	status?: number;
}

export interface FakeAdvisory {
	id: string;
	packageName: string;
	severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW";
	summary: string;
	fixed: string;
}

export interface Seen {
	method: string;
	host: string;
	path: string;
	authorization: string | null;
}

const COMMIT = "c".repeat(40);

/** An npm lockfile (version 3) that installs these packages. */
export function npmLock(packages: Record<string, string>): string {
	return JSON.stringify({
		name: "app",
		lockfileVersion: 3,
		packages: {
			"": { name: "app" },
			...Object.fromEntries(
				Object.entries(packages).map(([name, version]) => [
					`node_modules/${name}`,
					{ version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` },
				]),
			),
		},
	});
}

const blobSha = (path: string) => Buffer.from(path).toString("hex").padEnd(40, "0").slice(0, 40);

export function startUpstreams() {
	const accounts = new Map<string, FakeAccount>();
	const repositories = new Map<string, FakeRepository>();
	const advisories = new Map<string, FakeAdvisory>();
	const seen: Seen[] = [];
	const queries: SeenQuery[] = [];
	/** Set to make OSV fail, as when it is down. */
	const osv = { down: false };
	/** While set, Cloudflare answers only once it is done, as a slow account does. */
	const hold: { until: Promise<void> | null } = { until: null };

	/** GraphQL, as Cloudflare answers it: HTTP 200 with errors beside the data. */
	async function graphql(request: Request, account: FakeAccount | undefined): Promise<Response> {
		const body = (await request.json()) as { query: string; variables: Record<string, unknown> };
		queries.push({
			query: body.query,
			variables: body.variables,
			rateLimitType: request.headers.get("x-rate-limit-type"),
		});
		if (!account || request.headers.get("authorization") !== `Bearer ${account.token}`) {
			return Response.json({ success: false }, { status: 403 });
		}
		if (account.budget) {
			return Response.json({
				data: null,
				errors: [{ message: "Zone has exceeded its rate limit", extensions: { code: "budget" } }],
			});
		}
		const { variables } = body;
		if (Array.isArray(variables.zones)) {
			const tags = variables.zones as string[];
			if (tags.length > 10) {
				return Response.json({ data: null, errors: [{ message: "too many zones requested" }] });
			}
			const since = String(variables.since).slice(0, 10);
			const until = String(variables.until).slice(0, 10);
			const refused = tags.filter(
				(tag) => !account.zones.some((zone) => zone.id === tag && zone.analytics),
			);
			const zones = tags.flatMap((tag) => {
				const zone = account.zones.find((one) => one.id === tag && one.analytics);
				if (!zone) return [];
				const groups = (pick: (day: FakeDay) => Record<string, unknown>[]) =>
					Object.entries(zone.days)
						.filter(([date]) => date >= since && date < until)
						.flatMap(([date, day]) =>
							pick(day).map(({ count, ...dimensions }) => ({
								count,
								dimensions: { date, ...dimensions },
							})),
						);
				return [
					{
						zoneTag: tag,
						byAction: groups((day) =>
							day.actions.map((row) => ({
								securityAction: row.action,
								securitySource: row.source,
								count: row.count,
							})),
						),
						byCountry: groups((day) =>
							(day.countries ?? []).map((row) => ({
								securityAction: row.action,
								clientCountryName: row.name,
								count: row.count,
							})),
						),
						byHost: groups((day) =>
							(day.hosts ?? []).map((row) => ({
								securityAction: row.action,
								clientRequestHTTPHost: row.name,
								count: row.count,
							})),
						),
					},
				];
			});
			return Response.json({
				data: { viewer: { accounts: [{ zones }] } },
				errors:
					refused.length > 0
						? [{ message: `zones [${refused.join(", ")}] are not authorized` }]
						: null,
			});
		}
		const zone = account.zones.find((one) => one.id === variables.zone);
		if (!zone?.analytics) {
			return Response.json({
				data: null,
				errors: [
					{
						message:
							"Actor does not have permission 'com.cloudflare.api.account.zone.analytics.read'",
					},
				],
			});
		}
		if (body.query.includes("settings {")) {
			return Response.json({
				data: {
					viewer: {
						zones: [
							{
								settings: {
									firewallEventsAdaptive: {
										enabled: zone.eventsEnabled,
										maxPageSize: zone.maxPageSize,
									},
								},
							},
						],
					},
				},
			});
		}
		const since = String(variables.since);
		const until = String(variables.until);
		const inclusive = body.query.includes("datetime_leq");
		const rows = zone.events
			.filter(
				(event) =>
					event.datetime >= since && (inclusive ? event.datetime <= until : event.datetime < until),
			)
			.sort((a, b) => (a.datetime < b.datetime ? 1 : a.datetime > b.datetime ? -1 : 0))
			.slice(0, Number(variables.limit));
		return Response.json({ data: { viewer: { zones: [{ firewallEventsAdaptive: rows }] } } });
	}

	function zonesList(request: Request, account: FakeAccount): Response {
		if (request.headers.get("authorization") !== `Bearer ${account.token}`) {
			return Response.json({ success: false }, { status: 403 });
		}
		if (account.zonesStatus) return new Response(null, { status: account.zonesStatus });
		const url = new URL(request.url);
		const page = Number(url.searchParams.get("page") ?? 1);
		const perPage = Number(url.searchParams.get("per_page") ?? 20);
		return Response.json({
			success: true,
			result: account.zones.slice((page - 1) * perPage, page * perPage).map((zone) => ({
				id: zone.id,
				name: zone.name,
				status: zone.status,
				plan: { name: zone.plan },
			})),
			result_info: {
				page,
				per_page: perPage,
				total_pages: Math.max(1, Math.ceil(account.zones.length / perPage)),
			},
		});
	}

	/** A zone's protection, REST: entrypoints, rulesets, bot management and the security level. */
	function zoneRest(request: Request, zoneId: string, rest: string): Response {
		const account = [...accounts.values()].find((one) =>
			one.zones.some((zone) => zone.id === zoneId),
		);
		const zone = account?.zones.find((one) => one.id === zoneId);
		if (!account || !zone || request.headers.get("authorization") !== `Bearer ${account.token}`) {
			return Response.json({ success: false }, { status: 403 });
		}
		const reply = (part: ProtectionPart, allowed: boolean, answer: () => Response): Response => {
			const status = zone.protectionStatus[part];
			if (status) return new Response(null, { status });
			if (!allowed) return Response.json({ success: false }, { status: 403 });
			return answer();
		};
		const entrypoint = (part: ProtectionPart, rules: FakeRule[] | undefined) =>
			reply(part, zone.permissions.waf, () =>
				rules
					? Response.json({ success: true, result: { id: "set", rules } })
					: Response.json({ success: false }, { status: 404 }),
			);
		switch (rest) {
			case "rulesets/phases/http_request_firewall_custom/entrypoint":
				return entrypoint("custom", zone.custom);
			case "rulesets/phases/http_request_firewall_managed/entrypoint":
				return entrypoint("managed", zone.managed);
			case "rulesets/phases/http_ratelimit/entrypoint":
				return entrypoint("rateLimit", zone.rateLimit);
			case "rulesets":
				return zone.permissions.waf
					? Response.json({ success: true, result: zone.rulesets })
					: Response.json({ success: false }, { status: 403 });
			case "bot_management":
				return reply("bot", zone.permissions.bots, () =>
					Response.json({
						success: true,
						result: { fight_mode: zone.botFightMode, enable_js: true },
					}),
				);
			case "settings/security_level":
				return reply("level", zone.permissions.settings, () =>
					Response.json({
						success: true,
						result: { id: "security_level", value: zone.securityLevel },
					}),
				);
			default:
				return Response.json({ success: false }, { status: 404 });
		}
	}

	async function cloudflare(request: Request, path: string): Promise<Response> {
		await hold.until;
		const zonePath = /^\/client\/v4\/zones\/([0-9a-f]{32})\/(.+)$/.exec(path);
		if (zonePath?.[1] && zonePath[2]) return zoneRest(request, zonePath[1], zonePath[2]);
		if (path === "/client/v4/graphql") {
			// The nested query names the account; the single-zone ones name a zone of it.
			const probe = (await request.clone().json()) as { variables: Record<string, unknown> };
			const byAccount = accounts.get(String(probe.variables.account));
			const byZone = [...accounts.values()].find((one) =>
				one.zones.some((zone) => zone.id === probe.variables.zone),
			);
			return graphql(request, byAccount ?? byZone);
		}
		if (path === "/client/v4/zones") {
			const account = accounts.get(new URL(request.url).searchParams.get("account.id") ?? "");
			return account
				? zonesList(request, account)
				: Response.json({ success: false }, { status: 403 });
		}
		const match = /^\/client\/v4\/accounts\/([0-9a-f]{32})\/security-center\/insights$/.exec(path);
		const account = match?.[1] ? accounts.get(match[1]) : undefined;
		if (!account) return Response.json({ success: false }, { status: 403 });
		if (request.headers.get("authorization") !== `Bearer ${account.token}`) {
			return Response.json({ success: false }, { status: 403 });
		}
		if (account.status) return new Response(null, { status: account.status });
		return Response.json({
			success: true,
			result: {
				count: account.insights.length,
				issues: account.insights.map((insight) => ({
					issue_type: "insecure_configuration",
					severity: "Moderate",
					status: "active",
					dismissed: false,
					resolve_link: "/:account_id/:zone_name/ssl-tls",
					source: "cloudflare",
					...insight,
				})),
			},
		});
	}

	function github(request: Request, path: string): Response {
		const match = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(path);
		const repository = match
			? repositories.get(`${match[1]}/${match[2]}`.toLowerCase())
			: undefined;
		if (!match || !repository) return new Response(null, { status: 404 });
		if (request.headers.get("authorization") !== `Bearer ${repository.token}`) {
			return new Response(null, { status: 401 });
		}
		if (repository.status) return new Response(null, { status: repository.status });
		const rest = match[3] ?? "";
		if (rest === "") {
			return Response.json({
				id: repository.id,
				name: match[2],
				owner: { login: match[1] },
				default_branch: repository.branch,
				private: true,
			});
		}
		if (!repository.contents) return new Response(null, { status: 403 });
		if (rest === `/git/ref/heads/${repository.branch}`) {
			return Response.json({ object: { sha: COMMIT } });
		}
		if (rest.startsWith(`/git/trees/${COMMIT}`)) {
			return Response.json({
				truncated: false,
				tree: Object.entries(repository.lockfiles).map(([lockfile, text]) => ({
					path: lockfile,
					type: "blob",
					sha: blobSha(lockfile),
					size: text.length,
				})),
			});
		}
		const blob = /^\/git\/blobs\/([0-9a-f]{40})$/.exec(rest)?.[1];
		const lockfile = Object.keys(repository.lockfiles).find((one) => blobSha(one) === blob);
		if (lockfile) return new Response(repository.lockfiles[lockfile]);
		return new Response(null, { status: 404 });
	}

	async function osvAnswer(request: Request, path: string): Promise<Response> {
		if (osv.down) return new Response(null, { status: 503 });
		if (path === "/v1/querybatch") {
			const { queries } = (await request.json()) as { queries: { package: { name: string } }[] };
			return Response.json({
				results: queries.map((query) => {
					const found = [...advisories.values()].filter(
						(advisory) => advisory.packageName === query.package.name,
					);
					return found.length > 0
						? { vulns: found.map((advisory) => ({ id: advisory.id, modified: "m" })) }
						: {};
				}),
			});
		}
		const advisory = advisories.get(decodeURIComponent(path.slice("/v1/vulns/".length)));
		if (!advisory) return new Response(null, { status: 404 });
		return Response.json({
			id: advisory.id,
			modified: "2026-10-01T00:00:00Z",
			summary: advisory.summary,
			database_specific: { severity: advisory.severity },
			affected: [
				{
					package: { ecosystem: "npm", name: advisory.packageName },
					ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: advisory.fixed }] }],
				},
			],
		});
	}

	const handlers = {
		"cloudflare.test": cloudflare,
		"github.test": github,
		"osv.test": osvAnswer,
	};

	const hosts: Record<string, (request: Request) => Response | Promise<Response>> = {};
	for (const [host, handler] of Object.entries(handlers)) {
		hosts[host] = (request) => {
			const path = new URL(request.url).pathname;
			seen.push({
				method: request.method,
				host,
				path,
				authorization: request.headers.get("authorization"),
			});
			return handler(request, path);
		};
	}

	return {
		accounts,
		repositories,
		advisories,
		osv,
		hold,
		/** Every request that reached a stand-in, oldest first. */
		seen,
		/** The GraphQL queries among them, with their variables. */
		queries,
		hosts,
		/** The Worker's settings that point it here. */
		settings: {
			CLOUDFLARE_API_URL: "https://cloudflare.test/client/v4",
			GITHUB_API_URL: "https://github.test",
			OSV_API_URL: "https://osv.test/v1",
		},
		/** A Cloudflare account that accepts this token. */
		addAccount(accountId: string, token: string, insights: FakeInsight[] = []) {
			accounts.set(accountId, { token, insights, zones: [] });
			return accounts.get(accountId) as FakeAccount;
		},
		/** A zone of an account, which a test fills with days and events. */
		addZone(accountId: string, name: string, fields: Partial<FakeZone> = {}) {
			const account = accounts.get(accountId);
			if (!account) throw new Error("add the account first");
			const zone: FakeZone = {
				id: crypto.randomUUID().replaceAll("-", ""),
				name,
				status: "active",
				plan: "Free Website",
				analytics: true,
				days: {},
				events: [],
				eventsEnabled: true,
				maxPageSize: 10_000,
				rulesets: [],
				botFightMode: true,
				securityLevel: "medium",
				permissions: { waf: true, bots: true, settings: true },
				protectionStatus: {},
				...fields,
			};
			account.zones.push(zone);
			return zone;
		},
		/** A repository, as `owner/name`, that accepts this token. */
		addRepository(name: string, token: string, id: number, lockfiles: Record<string, string> = {}) {
			repositories.set(name.toLowerCase(), {
				id,
				token,
				branch: "main",
				contents: true,
				lockfiles,
			});
			return repositories.get(name.toLowerCase()) as FakeRepository;
		},
		addAdvisory(advisory: FakeAdvisory) {
			advisories.set(advisory.id, advisory);
		},
	};
}

export type Upstreams = ReturnType<typeof startUpstreams>;
