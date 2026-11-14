import { z } from "zod";
import { CLOUDFLARE_API, isAccountId } from "./cloudflare";
import { UpstreamError, type UpstreamFailure } from "./errors";
import { apiBase, type FetchOptions, readJson, send } from "./http";

// What Cloudflare's WAF and bot features did to a zone's requests, as daily counts. Guard reads
// them with the zone permission Analytics › Read, and asks for aggregates and for nothing that
// names a visitor: no address, user agent, path, query, ray id or ASN, in any query. That is
// invariant 3 of AGENTS.md, and `test/traffic.test.ts` fails if a query's text names one.
//
// Measured on 2026-11-14 on an account of 30 Free zones (the docs state little of this):
// - `firewallEventsAdaptiveGroups` is off on Free, so it is never asked for.
// - `httpRequestsAdaptiveGroups` works on Free: 30 days a query, up to 10,000 groups a page, a
//   `count` already scaled for sampling, no rule id. `securityAction_neq: "unknown"` leaves the
//   requests a security feature acted on.
// - `firewallEventsAdaptive` works on Free and gives single sampled events with a rule id; each
//   stands for `sampleInterval` requests.
// - A query may name 10 zones at most, and only when they sit inside the account:
//   `viewer.accounts(filter: {accountTag}).zones(filter: {zoneTag_in})`. That is also what
//   account-based rate limiting wants (`X-Rate-Limit-Type: account-based`).
// - Errors come back as HTTP 200 with an `errors` array and `data` null or partial.

/** Most zones one query may name. */
export const MAX_ZONES_PER_QUERY = 10;
/** Groups one `httpRequestsAdaptiveGroups` page returns, at most. */
const MAX_GROUPS = 10_000;
/** Zones are listed 50 a page, so a hundred pages is 5,000 zones. */
const MAX_ZONE_PAGES = 100;
const ZONES_PER_PAGE = 50;
/** Pages of events read for one zone and day. More would cost more than a sample is worth. */
const MAX_EVENT_PAGES = 2;
const EVENTS_PAGE_SIZE = 10_000;
/** How many countries, hosts and rules a day keeps. */
export const TOP = 10;
const MAX_HOST = 253;
const MAX_DESCRIPTION = 200;

/**
 * The actions that stopped or tested a request, from Cloudflare's rule actions: `block`,
 * `challenge`, `js_challenge` and `managed_challenge` (GraphQL spells the last two `jschallenge`
 * and `managedChallenge`; the docs name the four as the terminating actions in
 * developers.cloudflare.com/logs/reference/change-notices/2023-02-01-security-fields-updates/) and
 * `connectionClose`, which closes a connection without an answer. Others, such as `log`, `skip`
 * and the `...Solved` ones, mean the request got through. The API does not list its
 * `securityAction` values in one place, so a value not named here is not counted as mitigated,
 * which can only make Guard quieter.
 */
export const MITIGATED_ACTIONS: readonly string[] = [
	"block",
	"challenge",
	"jschallenge",
	"managedChallenge",
	"connectionClose",
];

export const isMitigated = (action: string): boolean => MITIGATED_ACTIONS.includes(action);

export interface Zone {
	readonly id: string;
	readonly name: string;
	readonly status: string;
	/** The plan's name, such as "Free Website", when the API said. */
	readonly plan: string | null;
}

export type Credentials = { readonly accountId: string; readonly token: string };

const ZONE_ID = /^[0-9a-f]{32}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** The UTC day a time falls on, as `YYYY-MM-DD`. */
export function utcDay(time: number): string {
	return new Date(time).toISOString().slice(0, 10);
}

/** The day `days` after (or, negative, before) this one. */
export function addDays(day: string, days: number): string {
	return utcDay(Date.parse(`${day}T00:00:00Z`) + days * 86_400_000);
}

const notAccount = () =>
	new UpstreamError("cloudflare", "not_found", "That is not a Cloudflare account id");

const unexpected = () =>
	new UpstreamError("cloudflare", "invalid_response", "cloudflare sent an unexpected answer");

const zonesResponse = z.object({
	success: z.literal(true),
	result: z.array(
		z.object({
			id: z.string().min(1),
			name: z.string().min(1),
			status: z.string().catch("unknown"),
			plan: z
				.object({ name: z.string().nullish().catch(null) })
				.nullish()
				.catch(null),
		}),
	),
	result_info: z
		.object({ total_pages: z.number().int().optional().catch(undefined) })
		.nullish()
		.catch(null),
});

/** Every zone of the account the token can see, any status: Guard scans the `active` ones. */
export async function listZones(account: Credentials, options: FetchOptions = {}): Promise<Zone[]> {
	if (!isAccountId(account.accountId)) throw notAccount();
	const zones: Zone[] = [];
	for (let page = 1; ; page++) {
		if (page > MAX_ZONE_PAGES) {
			throw new UpstreamError(
				"cloudflare",
				"invalid_response",
				"cloudflare kept sending more pages",
			);
		}
		const url = new URL(`${apiBase(options, "cloudflare", CLOUDFLARE_API)}/zones`);
		url.searchParams.set("account.id", account.accountId);
		url.searchParams.set("per_page", String(ZONES_PER_PAGE));
		url.searchParams.set("page", String(page));
		const response = await send(
			"cloudflare",
			url.href,
			{ headers: { Authorization: `Bearer ${account.token}`, Accept: "application/json" } },
			options,
		);
		const body = await readJson("cloudflare", response, zonesResponse);
		for (const zone of body.result) {
			zones.push({
				id: zone.id,
				name: zone.name,
				status: zone.status,
				plan: zone.plan?.name ?? null,
			});
		}
		const pages = body.result_info?.total_pages;
		if (body.result.length < ZONES_PER_PAGE || (pages !== undefined && page >= pages)) {
			return zones;
		}
	}
}

// --- GraphQL ----------------------------------------------------------------------------------

const graphqlResponse = z.object({
	data: z.unknown().nullish(),
	errors: z
		.array(
			z.object({
				message: z.string().catch(""),
				extensions: z
					.object({ code: z.string().nullish().catch(null) })
					.nullish()
					.catch(null),
			}),
		)
		.nullish()
		.catch(null),
});

interface GraphqlError {
	readonly message: string;
	readonly extensions?: { readonly code?: string | null } | null;
}

/**
 * What an `errors` array in a 200 means. The messages are matched and never kept: one may carry
 * a token's id, and a failure here records its kind only.
 */
function classify(errors: readonly GraphqlError[]) {
	let failure: UpstreamFailure | null = null;
	const forbiddenZones = new Set<string>();
	const fail = (kind: UpstreamFailure) => {
		failure ??= kind;
	};
	for (const error of errors) {
		const message = error.message;
		if (error.extensions?.code === "budget" || /exceeded its rate limit/i.test(message)) {
			fail("rate_limited");
		} else if (/zones? \[[^\]]*\] (?:is|are) not authorized/i.test(message)) {
			const tags = (/\[([^\]]*)\]/.exec(message)?.[1] ?? "")
				.split(/[\s,]+/)
				.filter((tag) => ZONE_ID.test(tag));
			for (const tag of tags) forbiddenZones.add(tag);
			// A message that names no zone we can read is a refusal of the whole request.
			if (tags.length === 0) fail("forbidden");
		} else if (/does not have (?:permission|access)/i.test(message)) {
			fail("forbidden");
		} else if (/authenticat|invalid (?:api )?token/i.test(message)) {
			fail("unauthorized");
		} else {
			// Includes "too many zones requested": a bug here, not the account's doing.
			fail("invalid_response");
		}
	}
	return { failure, forbiddenZones };
}

async function graphql(
	account: Credentials,
	query: string,
	variables: Record<string, unknown>,
	options: FetchOptions,
): Promise<{ data: unknown; forbiddenZones: Set<string> }> {
	const response = await send(
		"cloudflare",
		`${apiBase(options, "cloudflare", CLOUDFLARE_API)}/graphql`,
		{
			method: "POST",
			headers: {
				Authorization: `Bearer ${account.token}`,
				"Content-Type": "application/json",
				Accept: "application/json",
				// One budget for each zone rather than one for the token.
				"X-Rate-Limit-Type": "account-based",
			},
			body: JSON.stringify({ query, variables }),
		},
		options,
	);
	const body = await readJson("cloudflare", response, graphqlResponse);
	const { failure, forbiddenZones } = body.errors?.length
		? classify(body.errors)
		: { failure: null, forbiddenZones: new Set<string>() };
	if (failure) {
		throw new UpstreamError("cloudflare", failure, `cloudflare refused the query (${failure})`, {
			status: response.status,
		});
	}
	// With every zone refused there may be no data at all, which is then an answer, not a fault.
	if ((body.data === null || body.data === undefined) && forbiddenZones.size === 0) {
		throw new UpstreamError("cloudflare", "invalid_response", "cloudflare sent no data");
	}
	return { data: body.data ?? null, forbiddenZones };
}

// --- Daily counts by zone ---------------------------------------------------------------------

export interface ActionCount {
	readonly action: string;
	/** Which security feature acted: `firewallCustom`, `firewallManaged`, `bic`... */
	readonly source: string;
	readonly count: number;
}

export interface NamedCount {
	/** A country code, or one of the zone's own host names. */
	readonly name: string;
	readonly action: string;
	readonly count: number;
}

export interface TrafficDay {
	/** `YYYY-MM-DD`, UTC. */
	readonly day: string;
	readonly actions: ActionCount[];
	/** The 10 countries with the most mitigated requests, each with its actions. */
	readonly countries: NamedCount[];
	readonly hosts: NamedCount[];
}

export type ZoneTraffic =
	| { readonly ok: true; readonly days: TrafficDay[] }
	| { readonly ok: false; readonly failure: UpstreamFailure };

const date = z.string().regex(DAY);
const groups = <T extends z.ZodRawShape>(dimensions: T) =>
	z.array(z.object({ count: z.number().nonnegative(), dimensions: z.object(dimensions) }));

const trafficData = z.object({
	viewer: z.object({
		accounts: z.array(
			z.object({
				zones: z.array(
					z.object({
						zoneTag: z.string(),
						byAction: groups({ date, securityAction: z.string(), securitySource: z.string() }),
						byCountry: groups({
							date,
							securityAction: z.string(),
							clientCountryName: z.string(),
						}),
						byHost: groups({
							date,
							securityAction: z.string(),
							clientRequestHTTPHost: z.string(),
						}),
					}),
				),
			}),
		),
	}),
});

/**
 * Only these dimensions are ever asked for. `securityAction_neq: "unknown"` keeps the requests a
 * security feature acted on. The groups arrive biggest first, so a page cut at 10,000 loses the
 * smallest.
 */
const TRAFFIC_QUERY = `query($account: string!, $zones: [string!], $since: Time!, $until: Time!) {
  viewer { accounts(filter: { accountTag: $account }) {
    zones(filter: { zoneTag_in: $zones }) {
      zoneTag
      byAction: httpRequestsAdaptiveGroups(limit: ${MAX_GROUPS},
        filter: { datetime_geq: $since, datetime_lt: $until, securityAction_neq: "unknown" },
        orderBy: [count_DESC]) { count dimensions { date securityAction securitySource } }
      byCountry: httpRequestsAdaptiveGroups(limit: ${MAX_GROUPS},
        filter: { datetime_geq: $since, datetime_lt: $until, securityAction_neq: "unknown" },
        orderBy: [count_DESC]) { count dimensions { date securityAction clientCountryName } }
      byHost: httpRequestsAdaptiveGroups(limit: ${MAX_GROUPS},
        filter: { datetime_geq: $since, datetime_lt: $until, securityAction_neq: "unknown" },
        orderBy: [count_DESC]) { count dimensions { date securityAction clientRequestHTTPHost } }
    } } } }`;

function merge<T extends { count: number }>(rows: readonly T[], keyOf: (row: T) => string): T[] {
	const merged = new Map<string, T>();
	for (const row of rows) {
		const key = keyOf(row);
		const known = merged.get(key);
		merged.set(key, known ? { ...known, count: known.count + row.count } : row);
	}
	return [...merged.values()];
}

const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** The top `TOP` names by their mitigated total, each with its rows per action. */
function top(rows: readonly NamedCount[]): NamedCount[] {
	const totals = new Map<string, number>();
	for (const row of rows) totals.set(row.name, (totals.get(row.name) ?? 0) + row.count);
	const best = new Set(
		[...totals.entries()]
			.sort((a, b) => b[1] - a[1] || compare(a[0], b[0]))
			.slice(0, TOP)
			.map(([name]) => name),
	);
	return rows
		.filter((row) => best.has(row.name))
		.sort((a, b) => compare(a.name, b.name) || compare(a.action, b.action));
}

interface DayRows {
	actions: ActionCount[];
	countries: NamedCount[];
	hosts: NamedCount[];
}

/**
 * Per zone and UTC day, counts by action and source, and the top countries and hosts among the
 * mitigated requests, for the days from `since` up to but not including `until` (`YYYY-MM-DD`; at
 * most 30 days apart, which is as far as a Free zone may ask). Up to {@link MAX_ZONES_PER_QUERY}
 * zones, in one request.
 *
 * A zone Cloudflare names as not authorized comes back as `forbidden` and does not spoil the
 * others. Any other failure in the answer throws, with only its kind. A day on which nothing was
 * acted on has no entry.
 */
export async function readTraffic(
	account: Credentials,
	zoneIds: readonly string[],
	range: { since: string; until: string },
	options: FetchOptions = {},
): Promise<Map<string, ZoneTraffic>> {
	if (!isAccountId(account.accountId)) throw notAccount();
	if (zoneIds.length === 0) return new Map();
	if (zoneIds.length > MAX_ZONES_PER_QUERY) {
		throw new RangeError(`A query names ${MAX_ZONES_PER_QUERY} zones at most`);
	}
	if (
		!zoneIds.every((id) => ZONE_ID.test(id)) ||
		!DAY.test(range.since) ||
		!DAY.test(range.until)
	) {
		throw new RangeError("Zone ids and days must be well formed");
	}
	const { data, forbiddenZones } = await graphql(
		account,
		TRAFFIC_QUERY,
		{
			account: account.accountId,
			zones: zoneIds,
			since: `${range.since}T00:00:00Z`,
			until: `${range.until}T00:00:00Z`,
		},
		options,
	);
	const parsed = data === null ? null : trafficData.safeParse(data);
	if (parsed && !parsed.success) throw unexpected();
	const answered = new Map(
		(parsed?.data.viewer.accounts[0]?.zones ?? []).map((zone) => [zone.zoneTag, zone]),
	);
	const out = new Map<string, ZoneTraffic>();
	for (const id of zoneIds) {
		const zone = answered.get(id);
		if (forbiddenZones.has(id)) {
			out.set(id, { ok: false, failure: "forbidden" });
			continue;
		}
		if (!zone) {
			out.set(id, { ok: false, failure: "not_found" });
			continue;
		}
		const days = new Map<string, DayRows>();
		const rowsOf = (day: string) => {
			const known = days.get(day);
			if (known) return known;
			const fresh: DayRows = { actions: [], countries: [], hosts: [] };
			days.set(day, fresh);
			return fresh;
		};
		for (const { count, dimensions: d } of zone.byAction) {
			rowsOf(d.date).actions.push({ action: d.securityAction, source: d.securitySource, count });
		}
		for (const { count, dimensions: d } of zone.byCountry) {
			if (isMitigated(d.securityAction) && d.clientCountryName) {
				rowsOf(d.date).countries.push({
					name: d.clientCountryName,
					action: d.securityAction,
					count,
				});
			}
		}
		for (const { count, dimensions: d } of zone.byHost) {
			if (isMitigated(d.securityAction) && d.clientRequestHTTPHost) {
				rowsOf(d.date).hosts.push({
					name: d.clientRequestHTTPHost.slice(0, MAX_HOST),
					action: d.securityAction,
					count,
				});
			}
		}
		const named = (row: NamedCount) => `${row.name}/${row.action}`;
		out.set(id, {
			ok: true,
			days: [...days.entries()]
				.sort(([a], [b]) => compare(a, b))
				.map(([day, one]) => ({
					day,
					actions: merge(one.actions, (row) => `${row.action}/${row.source}`),
					countries: top(merge(one.countries, named)),
					hosts: top(merge(one.hosts, named)),
				})),
		});
	}
	return out;
}

/**
 * A small real query on one zone, for a token being connected: it proves Zone › Analytics › Read
 * where the zone listing cannot. Throws an {@link UpstreamError} when the zone refuses.
 */
export async function probeTraffic(
	account: Credentials,
	zoneId: string,
	options: FetchOptions = {},
	now = Date.now(),
): Promise<void> {
	const today = utcDay(now);
	const result = (
		await readTraffic(account, [zoneId], { since: addDays(today, -1), until: today }, options)
	).get(zoneId);
	if (result && !result.ok) {
		throw new UpstreamError(
			"cloudflare",
			result.failure,
			`cloudflare refused the zone (${result.failure})`,
		);
	}
}

// --- Rules ------------------------------------------------------------------------------------

export interface RuleCount {
	readonly ruleId: string;
	readonly description: string;
	readonly source: string;
	readonly action: string;
	/** Sampled events, each weighted by its `sampleInterval`: an estimate of requests. */
	readonly count: number;
}

export interface RuleTraffic {
	/** The top rules of the day by weighted count. */
	readonly rules: RuleCount[];
	/** The page cap cut the events short, so the counts are of a part of the day. */
	readonly partial: boolean;
}

const settingsData = z.object({
	viewer: z.object({
		zones: z.array(
			z.object({
				settings: z.object({
					firewallEventsAdaptive: z.object({
						enabled: z.boolean(),
						maxPageSize: z.number().int().positive().nullish().catch(null),
					}),
				}),
			}),
		),
	}),
});

const eventsData = z.object({
	viewer: z.object({
		zones: z.array(
			z.object({
				firewallEventsAdaptive: z.array(
					z.object({
						ruleId: z.string().catch(""),
						description: z.string().nullish().catch(null),
						source: z.string().catch(""),
						action: z.string().catch(""),
						sampleInterval: z.number().catch(1),
						datetime: z.string(),
					}),
				),
			}),
		),
	}),
});

const SETTINGS_QUERY = `query($zone: string!) {
  viewer { zones(filter: { zoneTag: $zone }) {
    settings { firewallEventsAdaptive { enabled maxPageSize } }
  } } }`;

/**
 * The only fields of an event Guard asks for. The event has more, among them the visitor's
 * address, user agent and path; none of those is ever named here.
 */
const eventsQuery = (upper: "datetime_lt" | "datetime_leq") =>
	`query($zone: string!, $since: Time!, $until: Time!, $limit: uint64!) {
  viewer { zones(filter: { zoneTag: $zone }) {
    firewallEventsAdaptive(limit: $limit, filter: { datetime_geq: $since, ${upper}: $until },
      orderBy: [datetime_DESC]) { ruleId description source action sampleInterval datetime }
  } } }`;

type Event = z.infer<
	typeof eventsData
>["viewer"]["zones"][number]["firewallEventsAdaptive"][number];

/**
 * The rules that acted in one zone on one UTC day, from sampled events. Pages of events run
 * newest first, up to two of them; a full last page means the day was cut, which `partial` says.
 * Throws when the zone has no event access (`forbidden`) or Cloudflare refuses.
 */
export async function readRules(
	account: Credentials,
	zoneId: string,
	day: string,
	options: FetchOptions = {},
): Promise<RuleTraffic> {
	if (!isAccountId(account.accountId)) throw notAccount();
	if (!ZONE_ID.test(zoneId) || !DAY.test(day)) {
		throw new RangeError("Zone id and day must be well formed");
	}

	const refused = () =>
		new UpstreamError("cloudflare", "forbidden", "cloudflare refused this zone's events");
	const first = await graphql(account, SETTINGS_QUERY, { zone: zoneId }, options);
	if (first.forbiddenZones.size > 0) throw refused();
	const settings = settingsData.safeParse(first.data);
	const node = settings.success
		? settings.data.viewer.zones[0]?.settings.firewallEventsAdaptive
		: undefined;
	if (!node) throw unexpected();
	if (!node.enabled) {
		throw new UpstreamError("cloudflare", "forbidden", "cloudflare has no events for this zone");
	}
	const limit = Math.min(EVENTS_PAGE_SIZE, node.maxPageSize ?? EVENTS_PAGE_SIZE);

	const events: Event[] = [];
	let partial = false;
	let until = `${addDays(day, 1)}T00:00:00Z`;
	let upper: "datetime_lt" | "datetime_leq" = "datetime_lt";
	for (let page = 1; ; page++) {
		const reply = await graphql(
			account,
			eventsQuery(upper),
			{ zone: zoneId, since: `${day}T00:00:00Z`, until, limit },
			options,
		);
		if (reply.forbiddenZones.size > 0) throw refused();
		const answer = eventsData.safeParse(reply.data);
		if (!answer.success) throw unexpected();
		const rows = answer.data.viewer.zones[0]?.firewallEventsAdaptive ?? [];
		if (rows.length < limit) {
			events.push(...rows);
			break;
		}
		const boundary = rows[rows.length - 1]?.datetime ?? "";
		// The next page starts at the boundary's second again, so what was read of it is dropped now
		// rather than counted twice. A page made of one second only cannot be passed.
		const kept = rows.filter((row) => row.datetime !== boundary);
		if (page >= MAX_EVENT_PAGES || kept.length === 0) {
			events.push(...rows);
			partial = true;
			break;
		}
		events.push(...kept);
		until = boundary;
		upper = "datetime_leq";
	}

	const counted = new Map<string, RuleCount>();
	for (const event of events) {
		const key = `${event.ruleId}/${event.source}/${event.action}`;
		// A sample stands for `sampleInterval` requests; a missing or odd one stands for itself.
		const weight = event.sampleInterval >= 1 ? Math.round(event.sampleInterval) : 1;
		const description = (event.description ?? "").slice(0, MAX_DESCRIPTION);
		const known = counted.get(key);
		counted.set(
			key,
			known
				? { ...known, count: known.count + weight, description: known.description || description }
				: {
						ruleId: event.ruleId,
						description,
						source: event.source,
						action: event.action,
						count: weight,
					},
		);
	}
	return {
		rules: [...counted.values()]
			.sort((a, b) => b.count - a.count || compare(a.ruleId, b.ruleId))
			.slice(0, TOP),
		partial,
	};
}
