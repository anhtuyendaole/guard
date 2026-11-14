import { addDays, MITIGATED_ACTIONS, utcDay } from "@gateweave/guard-scan";
import type {
	TrafficConnectionView,
	TrafficNameView,
	TrafficPage,
	TrafficRuleView,
	TrafficZoneStatus,
	TrafficZoneView,
} from "../../lib/connection-schemas";
import { buildSeries, buildWeek } from "../../lib/traffic-series";
import { currentMember } from "../access";
import { db } from "../auth";

/** How many countries, hosts and rules a zone's card lists. */
const LISTED = 10;

/** The same whether the workspace doesn't exist or the caller isn't in it. */
const notFound = () => answer({ ok: false, error: "Not found" }, 404);

function answer(body: unknown, status = 200): Response {
	return Response.json(body, { status, headers: { "cache-control": "private, no-store" } });
}

const MITIGATED_SQL = MITIGATED_ACTIONS.map((action) => `'${action}'`).join(", ");

interface ConnectionRow {
	id: string;
	name: string;
	traffic_outcome: string | null;
}
interface ZoneRow {
	connection_id: string;
	zone_id: string;
	name: string;
	plan: string | null;
	first_day: string | null;
	last_day: string | null;
	last_failure: string | null;
}
interface DayRow {
	connection_id: string;
	zone_id: string;
	day: string;
	mitigated: number;
}
interface RuleRow {
	connection_id: string;
	zone_id: string;
	key: string;
	description: string | null;
	source: string;
	action: string;
	partial: number;
	count: number;
}
interface NameRow {
	connection_id: string;
	zone_id: string;
	dimension: "country" | "host";
	key: string;
	total: number;
}

const zoneKey = (connectionId: string, zoneId: string) => `${connectionId}/${zoneId}`;

function statusOf(zone: ZoneRow, days: number): TrafficZoneStatus {
	if (days > 0) return "ok";
	if (zone.last_failure) return "failed";
	return zone.last_day === null ? "not_scanned" : "no_events";
}

/**
 * The workspace's Cloudflare zones with the counts Guard has stored for them, for any member.
 * Everything is scoped by the workspace's id in each query. Null when the caller is not a member.
 */
export async function listTraffic(slug: string, now = Date.now()): Promise<TrafficPage | null> {
	const member = await currentMember(slug);
	if (!member) return null;
	const org = member.membership.workspaceId;
	const yesterday = addDays(utcDay(now), -1);
	const weekStart = addDays(yesterday, -6);

	const [connections, zones, days, rules, names] = await Promise.all([
		db.$client
			.prepare(
				"SELECT id, name, traffic_outcome FROM connection WHERE organization_id = ?1 AND kind = 'cloudflare' ORDER BY added_at, id",
			)
			.bind(org)
			.all<ConnectionRow>(),
		db.$client
			.prepare(
				"SELECT connection_id, zone_id, name, plan, first_day, last_day, last_failure FROM traffic_zone WHERE organization_id = ?1",
			)
			.bind(org)
			.all<ZoneRow>(),
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, day,
					SUM(CASE WHEN action IN (${MITIGATED_SQL}) THEN count ELSE 0 END) AS mitigated
				FROM traffic_count WHERE organization_id = ?1 AND dimension = 'action'
				GROUP BY connection_id, zone_id, day ORDER BY day`,
			)
			.bind(org)
			.all<DayRow>(),
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, key, description, source, action, partial, count
				FROM traffic_count WHERE organization_id = ?1 AND dimension = 'rule' AND day = ?2
				ORDER BY count DESC, key`,
			)
			.bind(org, yesterday)
			.all<RuleRow>(),
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, dimension, key, SUM(count) AS total
				FROM traffic_count
				WHERE organization_id = ?1 AND dimension IN ('country', 'host') AND day >= ?2 AND day <= ?3
				GROUP BY connection_id, zone_id, dimension, key ORDER BY total DESC, key`,
			)
			.bind(org, weekStart, yesterday)
			.all<NameRow>(),
	]);

	const daysOf = new Map<string, { day: string; mitigated: number }[]>();
	for (const row of days.results) {
		const key = zoneKey(row.connection_id, row.zone_id);
		const list = daysOf.get(key) ?? [];
		list.push({ day: row.day, mitigated: row.mitigated });
		daysOf.set(key, list);
	}
	const rulesOf = new Map<string, TrafficRuleView[]>();
	for (const row of rules.results) {
		const key = zoneKey(row.connection_id, row.zone_id);
		const list = rulesOf.get(key) ?? [];
		if (list.length < LISTED) {
			list.push({
				ruleId: row.key,
				description: row.description ?? "",
				source: row.source,
				action: row.action,
				count: row.count,
				partial: row.partial === 1,
			});
		}
		rulesOf.set(key, list);
	}
	const namesOf = new Map<string, TrafficNameView[]>();
	for (const row of names.results) {
		const key = `${zoneKey(row.connection_id, row.zone_id)}/${row.dimension}`;
		const list = namesOf.get(key) ?? [];
		if (list.length < LISTED) list.push({ name: row.key, count: row.total });
		namesOf.set(key, list);
	}

	const views: TrafficConnectionView[] = connections.results.map((connection) => ({
		id: connection.id,
		name: connection.name,
		outcome: connection.traffic_outcome,
		zones: zones.results
			.filter((zone) => zone.connection_id === connection.id)
			.map((zone): TrafficZoneView => {
				const key = zoneKey(zone.connection_id, zone.zone_id);
				const list = daysOf.get(key) ?? [];
				const series = buildSeries(list, zone.first_day, zone.last_day, yesterday);
				const week = buildWeek(series);
				return {
					zoneId: zone.zone_id,
					name: zone.name,
					plan: zone.plan,
					status: statusOf(zone, list.length),
					failure: zone.last_failure,
					series,
					rules: rulesOf.get(key) ?? [],
					countries: namesOf.get(`${key}/country`) ?? [],
					hosts: namesOf.get(`${key}/host`) ?? [],
					week,
				};
			})
			.sort((a, b) => b.week.thisSum - a.week.thisSum || (a.name < b.name ? -1 : 1)),
	}));

	return { hasConnections: views.length > 0, yesterday, connections: views };
}

export async function readTrafficPage(slug: string): Promise<Response> {
	const page = await listTraffic(slug);
	return page ? answer(page) : notFound();
}
