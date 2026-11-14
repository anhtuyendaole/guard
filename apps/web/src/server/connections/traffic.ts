import {
	addDays,
	type FetchOptions,
	isMitigated,
	listZones,
	MAX_ZONES_PER_QUERY,
	MITIGATED_ACTIONS,
	type RuleTraffic,
	readRules,
	readTraffic,
	type TrafficDay,
	UpstreamError,
	type UpstreamFailure,
	utcDay,
	type Zone,
	type ZoneTraffic,
} from "@gateweave/guard-scan";
import type { Database } from "../db";
import { KEPT_TRAFFIC_DAYS, type TrafficDimension } from "../db/connections-schema";
import type { PresentFinding } from "./findings";

/**
 * Reading what a Cloudflare connection's zones saw of WAF and bot activity, as daily counts
 * (docs/architecture.md, "Traffic"). Counts only: nothing here asks for, keeps or logs an address, a
 * user agent, a path, a query, a ray id or an ASN (invariant 3).
 */

/** Complete UTC days read on a first scan: yesterday and the seven before it, which the spike rule needs. */
export const READ_DAYS = 8;
/** Rules are read for this many zones, the ones with the most acted-on requests yesterday. */
export const RULE_ZONES = 20;
/** GraphQL calls in flight at once. */
const PARALLEL = 4;
/** Traffic rows written by one statement, bound as one JSON value. */
const ROWS_PER_STATEMENT = 200;
const ZONES_PER_STATEMENT = 100;

/** Yesterday's mitigated requests must be more than this many times the median of the week before. */
export const SPIKE_FACTOR = 5;
/** At least this many of the seven days before must be stored, or there is no usual to compare with. */
export const SPIKE_MIN_DAYS = 3;
/** A spike needs at least this many mitigated requests yesterday: a zone's few hundred are noise. */
export const SPIKE_FLOOR = 500;

export const SPIKE_KIND = "waf_spike";

/** A finding's fingerprint, which names the zone and so stays one finding while the spike lasts. */
export const spikeFingerprint = (accountId: string, zoneId: string) =>
	`${trafficPrefix(accountId)}${SPIKE_KIND}:${zoneId}`;

/** What every traffic finding of an account's fingerprint starts with. */
export const trafficPrefix = (accountId: string) => `traffic:${accountId}:`;

export interface TrafficRow {
	zone: string;
	day: string;
	dimension: TrafficDimension;
	key: string;
	action: string;
	source: string;
	description: string | null;
	partial: boolean;
	count: number;
}

/** The rows one day of one zone becomes. Counts are whole numbers; sampling can leave a fraction. */
export function rowsOfDay(zone: string, day: TrafficDay): TrafficRow[] {
	const base = { zone, day: day.day, description: null, partial: false };
	return [
		...day.actions.map(
			(row): TrafficRow => ({
				...base,
				dimension: "action",
				key: row.action,
				action: row.action,
				source: row.source,
				count: Math.round(row.count),
			}),
		),
		...day.countries.map(
			(row): TrafficRow => ({
				...base,
				dimension: "country",
				key: row.name,
				action: row.action,
				source: "",
				count: Math.round(row.count),
			}),
		),
		...day.hosts.map(
			(row): TrafficRow => ({
				...base,
				dimension: "host",
				key: row.name,
				action: row.action,
				source: "",
				count: Math.round(row.count),
			}),
		),
	];
}

function rowsOfRules(zone: string, day: string, rules: RuleTraffic): TrafficRow[] {
	return rules.rules.map(
		(rule): TrafficRow => ({
			zone,
			day,
			dimension: "rule",
			key: rule.ruleId,
			action: rule.action,
			source: rule.source,
			description: rule.description,
			partial: rules.partial,
			count: rule.count,
		}),
	);
}

/** The mitigated requests in a day's action counts. */
export function mitigatedIn(day: TrafficDay): number {
	return day.actions.reduce((sum, row) => (isMitigated(row.action) ? sum + row.count : sum), 0);
}

const compact = (value: number) => Math.round(value).toLocaleString("en-US");

function median(values: readonly number[]): number {
	const sorted = [...values].sort((a, b) => a - b);
	const middle = Math.floor(sorted.length / 2);
	if (sorted.length % 2 === 1) return sorted[middle] ?? 0;
	return ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
}

/**
 * The spike finding for a zone, or null. Yesterday's mitigated requests (the actions in
 * `MITIGATED_ACTIONS`) must be more than {@link SPIKE_FACTOR} times the median of the seven days
 * before it, with at least {@link SPIKE_MIN_DAYS} of those days stored and at least
 * {@link SPIKE_FLOOR} mitigated requests yesterday. Severity is low: the WAF is working, and this
 * is worth a look, not an alarm. `byDay` holds the mitigated count of each stored day.
 */
export function spikeFinding(
	accountId: string,
	zone: { id: string; name: string },
	byDay: ReadonlyMap<string, number>,
	yesterday: string,
): PresentFinding | null {
	const latest = byDay.get(yesterday) ?? 0;
	if (latest < SPIKE_FLOOR) return null;
	const before: number[] = [];
	for (let back = 1; back <= 7; back++) {
		const count = byDay.get(addDays(yesterday, -back));
		if (count !== undefined) before.push(count);
	}
	if (before.length < SPIKE_MIN_DAYS) return null;
	const usual = median(before);
	if (!(latest > SPIKE_FACTOR * usual)) return null;
	const factor = usual > 0 ? latest / usual : null;
	const how =
		factor === null
			? `rose to ${compact(latest)} yesterday, against a median of 0 in the week before`
			: `were ${factor < 10 ? factor.toFixed(1) : compact(factor)} times the usual: ${compact(latest)} yesterday, against a median of ${compact(usual)} in the week before`;
	return {
		fingerprint: spikeFingerprint(accountId, zone.id),
		source: "cloudflare",
		severity: "low",
		kind: SPIKE_KIND,
		subject: zone.name,
		title: `Blocked and challenged requests on ${zone.name} ${how}`,
		url: `https://dash.cloudflare.com/${accountId}/${encodeURIComponent(zone.name)}/security/events`,
		fixedVersion: null,
	};
}

export interface TrafficRead {
	/** `ok`, or why no zone could be read. A zone that failed alone says so in its own row. */
	outcome: "ok" | UpstreamFailure;
	/** The spike findings of zones that were judged. */
	findings: PresentFinding[];
	/**
	 * Fingerprint prefixes whose findings this scan could not judge, so that they stay as they are,
	 * as an unreadable lockfile's do.
	 */
	held: string[];
	/** Something failed in a way that passes with time: try again within the hour. */
	retry: boolean;
	/** What to write, to run in a batch of their own before the findings are changed. */
	statements: D1PreparedStatement[];
}

interface ConnectionRef {
	id: string;
	organization_id: string;
	target: string;
}

/** The failure to record for something that went wrong. Never carries a message: tokens are near. */
function failureOf(error: unknown): UpstreamFailure {
	if (error instanceof UpstreamError) return error.failure;
	console.error(`traffic: unexpected ${error instanceof Error ? error.name : "failure"}`);
	return "invalid_response";
}

const retryable = (failure: UpstreamFailure) =>
	failure === "rate_limited" || failure === "unavailable";

/** Runs `work` over `items`, at most `limit` at a time. */
async function inParallel<T, R>(
	items: readonly T[],
	limit: number,
	work: (item: T) => Promise<R>,
): Promise<R[]> {
	const out: R[] = new Array(items.length);
	let next = 0;
	const worker = async () => {
		while (next < items.length) {
			const at = next++;
			out[at] = await work(items[at] as T);
		}
	};
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
	return out;
}

function chunks<T>(items: readonly T[], size: number): T[][] {
	const out: T[][] = [];
	for (let start = 0; start < items.length; start += size)
		out.push(items.slice(start, start + size));
	return out;
}

/** What a scan that could not store its traffic leaves: nothing judged, everything held. */
export function unstored(connection: ConnectionRef): TrafficRead {
	return {
		outcome: "unavailable",
		findings: [],
		held: [trafficPrefix(connection.target)],
		retry: true,
		statements: [],
	};
}

const MITIGATED_SQL = MITIGATED_ACTIONS.map((action) => `'${action}'`).join(", ");

/**
 * Reads the traffic of a Cloudflare connection: lists its active zones, reads the full UTC days
 * not stored yet (yesterday and back to {@link READ_DAYS} days ago; today is incomplete and is
 * never stored), reads yesterday's rules for the busiest zones, judges each zone for a spike and
 * returns the statements that store it all. Nothing here fails the scan: what went wrong comes
 * back as an outcome, in the zone's row, and in the findings it keeps open.
 */
export async function readConnectionTraffic(
	db: Database,
	connection: ConnectionRef,
	token: string,
	options: FetchOptions,
	now: number,
): Promise<TrafficRead> {
	const account = { accountId: connection.target, token };
	const held = [trafficPrefix(connection.target)];
	const today = utcDay(now);
	const yesterday = addDays(today, -1);
	const oldest = addDays(today, -READ_DAYS);

	let listed: Zone[];
	try {
		listed = await listZones(account, options);
	} catch (error) {
		const outcome = failureOf(error);
		return { outcome, findings: [], held, retry: retryable(outcome), statements: [] };
	}
	const zones = listed.filter((zone) => zone.status === "active");

	const { results: knownZones } = await db.$client
		.prepare("SELECT zone_id, last_day FROM traffic_zone WHERE connection_id = ?1")
		.bind(connection.id)
		.all<{ zone_id: string; last_day: string | null }>();
	const lastDay = new Map(knownZones.map((row) => [row.zone_id, row.last_day]));
	const { results: storedDays } = await db.$client
		.prepare(
			`SELECT zone_id, day,
				SUM(CASE WHEN action IN (${MITIGATED_SQL}) THEN count ELSE 0 END) AS mitigated
			FROM traffic_count WHERE connection_id = ?1 AND dimension = 'action' AND day >= ?2
			GROUP BY zone_id, day`,
		)
		.bind(connection.id, oldest)
		.all<{ zone_id: string; day: string; mitigated: number }>();
	/** zone id to day to mitigated requests, for the days that hold anything. */
	const mitigated = new Map<string, Map<string, number>>();
	for (const row of storedDays) {
		const days = mitigated.get(row.zone_id) ?? new Map<string, number>();
		days.set(row.day, row.mitigated);
		mitigated.set(row.zone_id, days);
	}

	// The first day each zone still needs; none when it is up to date.
	const needs = new Map<string, string>();
	for (const zone of zones) {
		const last = lastDay.get(zone.id);
		const from = last && last >= oldest ? addDays(last, 1) : oldest;
		if (from <= yesterday) needs.set(zone.id, from);
	}

	const failures = new Map<string, UpstreamFailure>();
	const fresh = new Map<string, TrafficDay[]>();
	const batches = chunks(
		zones.filter((zone) => needs.has(zone.id)),
		MAX_ZONES_PER_QUERY,
	);
	await inParallel(batches, PARALLEL, async (batch) => {
		// Days sort as text, so the first of them is the earliest any zone of the batch needs.
		const since = batch.map((zone) => needs.get(zone.id) ?? yesterday).sort()[0] ?? yesterday;
		let answered: Map<string, ZoneTraffic>;
		try {
			// `until` is today, which is excluded: a day that is not over is never read.
			answered = await readTraffic(
				account,
				batch.map((zone) => zone.id),
				{ since, until: today },
				options,
			);
		} catch (error) {
			const failure = failureOf(error);
			for (const zone of batch) failures.set(zone.id, failure);
			return;
		}
		for (const zone of batch) {
			const result = answered.get(zone.id);
			if (!result) failures.set(zone.id, "invalid_response");
			else if (!result.ok) failures.set(zone.id, result.failure);
			else {
				const from = needs.get(zone.id) ?? oldest;
				fresh.set(
					zone.id,
					result.days.filter((day) => day.day >= from && day.day <= yesterday),
				);
			}
		}
	});

	const rows: TrafficRow[] = [];
	for (const [zoneId, days] of fresh) {
		for (const day of days) {
			rows.push(...rowsOfDay(zoneId, day));
			const known = mitigated.get(zoneId) ?? new Map<string, number>();
			// A stored day stays as it is; only days not stored are added.
			if (!known.has(day.day)) known.set(day.day, mitigatedIn(day));
			mitigated.set(zoneId, known);
		}
	}

	// Rules, for the busiest zones among those whose yesterday was read now.
	const actedOnYesterday = (zoneId: string) =>
		(fresh.get(zoneId) ?? [])
			.filter((day) => day.day === yesterday)
			.reduce((sum, day) => sum + day.actions.reduce((total, row) => total + row.count, 0), 0);
	const busiest = [...fresh.keys()]
		.filter((zoneId) => actedOnYesterday(zoneId) > 0)
		.sort((a, b) => actedOnYesterday(b) - actedOnYesterday(a) || (a < b ? -1 : 1))
		.slice(0, RULE_ZONES);
	await inParallel(busiest, PARALLEL, async (zoneId) => {
		try {
			rows.push(
				...rowsOfRules(zoneId, yesterday, await readRules(account, zoneId, yesterday, options)),
			);
		} catch (error) {
			// The rules are the extra: a zone whose events cannot be read keeps its counts.
			failureOf(error);
		}
	});

	const findings: PresentFinding[] = [];
	const kept: string[] = [];
	for (const zone of zones) {
		if (failures.has(zone.id)) {
			kept.push(spikeFingerprint(connection.target, zone.id));
			continue;
		}
		const found = spikeFinding(
			connection.target,
			zone,
			mitigated.get(zone.id) ?? new Map(),
			yesterday,
		);
		if (found) findings.push(found);
	}

	const attempted = batches.flat().length;
	const allFailed = attempted > 0 && failures.size === attempted;
	const firstFailure = [...failures.values()][0];
	const outcome: TrafficRead["outcome"] = allFailed && firstFailure ? firstFailure : "ok";

	const finishedAt = Date.now();
	const statements: D1PreparedStatement[] = [];
	const prepare = (sql: string) => db.$client.prepare(sql);
	const zoneRows = zones.map((zone) => {
		const failure = failures.get(zone.id) ?? null;
		const last = lastDay.get(zone.id) ?? null;
		return {
			id: zone.id,
			name: zone.name,
			plan: zone.plan,
			lastDay: failure ? last : yesterday,
			failure,
		};
	});
	const listedIds = JSON.stringify(zones.map((zone) => zone.id));
	// A zone that is gone from the account, or not active, takes its counts with it.
	statements.push(
		prepare(
			"DELETE FROM traffic_count WHERE connection_id = ?1 AND zone_id NOT IN (SELECT value FROM json_each(?2))",
		).bind(connection.id, listedIds),
		prepare(
			"DELETE FROM traffic_zone WHERE connection_id = ?1 AND zone_id NOT IN (SELECT value FROM json_each(?2))",
		).bind(connection.id, listedIds),
		prepare("DELETE FROM traffic_count WHERE connection_id = ?1 AND day < ?2").bind(
			connection.id,
			addDays(today, -KEPT_TRAFFIC_DAYS),
		),
	);
	const upsertZones = prepare(
		`INSERT INTO traffic_zone (connection_id, organization_id, zone_id, name, plan, last_day, last_failure, seen_at)
		SELECT ?1, ?2, json_extract(value, '$.id'), json_extract(value, '$.name'),
			json_extract(value, '$.plan'), json_extract(value, '$.lastDay'),
			json_extract(value, '$.failure'), ?3
		FROM json_each(?4) WHERE true
		ON CONFLICT (connection_id, zone_id) DO UPDATE SET name = excluded.name, plan = excluded.plan,
			last_day = excluded.last_day, last_failure = excluded.last_failure, seen_at = excluded.seen_at`,
	);
	for (const chunk of chunks(zoneRows, ZONES_PER_STATEMENT)) {
		statements.push(
			upsertZones.bind(
				connection.id,
				connection.organization_id,
				finishedAt,
				JSON.stringify(chunk),
			),
		);
	}
	// A day already stored is never written again.
	const insertRows = prepare(
		`INSERT INTO traffic_count (connection_id, organization_id, zone_id, day, dimension, key, action,
			source, description, partial, count)
		SELECT ?1, ?2, json_extract(value, '$.zone'), json_extract(value, '$.day'),
			json_extract(value, '$.dimension'), json_extract(value, '$.key'), json_extract(value, '$.action'),
			json_extract(value, '$.source'), json_extract(value, '$.description'),
			json_extract(value, '$.partial'), json_extract(value, '$.count')
		FROM json_each(?3) WHERE true
		ON CONFLICT DO NOTHING`,
	);
	for (const chunk of chunks(rows, ROWS_PER_STATEMENT)) {
		statements.push(
			insertRows.bind(
				connection.id,
				connection.organization_id,
				JSON.stringify(chunk.map((row) => ({ ...row, partial: row.partial ? 1 : 0 }))),
			),
		);
	}

	return {
		outcome,
		findings,
		// Every zone that failed keeps its own spike finding; a failure of all of them, or of the
		// listing, keeps all of them.
		held: outcome === "ok" ? kept : held,
		retry: [...failures.values()].some(retryable),
		statements,
	};
}
