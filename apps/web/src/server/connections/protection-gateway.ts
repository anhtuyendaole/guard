import type {
	ProtectionPage,
	ProtectionPartView,
	ProtectionRuleView,
	ProtectionZoneView,
} from "../../lib/connection-schemas";
import { currentMember } from "../access";
import { db } from "../auth";

/** The same whether the workspace does not exist or the caller is not in it. */
const notFound = () => answer({ ok: false, error: "Not found" }, 404);

function answer(body: unknown, status = 200): Response {
	return Response.json(body, { status, headers: { "cache-control": "private, no-store" } });
}

interface ZoneRow {
	connection_id: string;
	connection_name: string;
	account_id: string;
	zone_id: string;
	name: string;
	plan: string | null;
	read_at: number | null;
	custom_state: string | null;
	custom_failure: string | null;
	managed_state: string | null;
	managed_failure: string | null;
	managed_rulesets: string | null;
	rate_limit_state: string | null;
	rate_limit_failure: string | null;
	rate_limit_total: number | null;
	rate_limit_enabled: number | null;
	bot_state: string | null;
	bot_failure: string | null;
	bot_fight_mode: number | null;
	security_level_state: string | null;
	security_level_failure: string | null;
	security_level: string | null;
}
interface RuleRow {
	connection_id: string;
	zone_id: string;
	rule_id: string;
	description: string;
	action: string;
	enabled: number;
	last_updated: string | null;
}
interface ActedRow {
	connection_id: string;
	zone_id: string;
	key: string;
	total: number;
	days: number;
}
interface DaysRow {
	connection_id: string;
	zone_id: string;
	days: number;
}

const zoneKey = (connectionId: string, zoneId: string) => `${connectionId}/${zoneId}`;

/** A part from its columns: no state at all is a zone no scan has read yet. */
function partOf<T>(
	state: string | null,
	failure: string | null,
	value: () => T,
): ProtectionPartView<T> {
	if (state === "ok") return { state: "ok", value: value() };
	if (state === "none") return { state: "none" };
	if (state === "failed") return { state: "failed", failure: failure ?? "invalid_response" };
	return { state: "unread" };
}

interface StoredRuleset {
	id: string;
	name: string | null;
	enabled: boolean;
}

/** The column is Guard's own JSON, but a damaged value reads as no rulesets rather than throwing. */
function rulesetsOf(text: string | null): StoredRuleset[] {
	try {
		const parsed: unknown = JSON.parse(text ?? "[]");
		if (!Array.isArray(parsed)) return [];
		return parsed.flatMap((item): StoredRuleset[] => {
			if (typeof item !== "object" || item === null) return [];
			const { id, name, enabled } = item as Record<string, unknown>;
			if (typeof id !== "string") return [];
			return [{ id, name: typeof name === "string" ? name : null, enabled: enabled === true }];
		});
	} catch {
		return [];
	}
}

/**
 * What protects each of the workspace's Cloudflare zones, with the custom rules and what Traffic
 * recorded of them, for any member. Everything is scoped by the workspace's id in each query.
 * Null when the caller is not a member. A rule's expression is not here: Guard never reads it.
 */
export async function listProtection(slug: string): Promise<ProtectionPage | null> {
	const member = await currentMember(slug);
	if (!member) return null;
	const org = member.membership.workspaceId;

	const [connections, zones, rules, acted, days] = await Promise.all([
		db.$client
			.prepare(
				"SELECT COUNT(*) AS n FROM connection WHERE organization_id = ?1 AND kind = 'cloudflare'",
			)
			.bind(org)
			.first<{ n: number }>(),
		// Zones come from the traffic read, so one no scan has reached for protection yet still
		// shows, as not read.
		db.$client
			.prepare(
				`SELECT z.connection_id, c.name AS connection_name, c.target AS account_id, z.zone_id, z.name, z.plan,
					p.read_at, p.custom_state, p.custom_failure, p.managed_state, p.managed_failure, p.managed_rulesets,
					p.rate_limit_state, p.rate_limit_failure, p.rate_limit_total, p.rate_limit_enabled,
					p.bot_state, p.bot_failure, p.bot_fight_mode,
					p.security_level_state, p.security_level_failure, p.security_level
				FROM traffic_zone z
				JOIN connection c ON c.id = z.connection_id AND c.kind = 'cloudflare'
				LEFT JOIN protection_zone p ON p.connection_id = z.connection_id AND p.zone_id = z.zone_id
				WHERE z.organization_id = ?1`,
			)
			.bind(org)
			.all<ZoneRow>(),
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, rule_id, description, action, enabled, last_updated
				FROM protection_rule WHERE organization_id = ?1 ORDER BY position`,
			)
			.bind(org)
			.all<RuleRow>(),
		// A rule's own id is the key of its `rule` rows, whichever feature and action they carry.
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, key, SUM(count) AS total, COUNT(DISTINCT day) AS days
				FROM traffic_count WHERE organization_id = ?1 AND dimension = 'rule'
				GROUP BY connection_id, zone_id, key`,
			)
			.bind(org)
			.all<ActedRow>(),
		db.$client
			.prepare(
				`SELECT connection_id, zone_id, COUNT(DISTINCT day) AS days
				FROM traffic_count WHERE organization_id = ?1 AND dimension = 'rule'
				GROUP BY connection_id, zone_id`,
			)
			.bind(org)
			.all<DaysRow>(),
	]);

	const actedOf = new Map(
		acted.results.map((row) => [
			`${zoneKey(row.connection_id, row.zone_id)}/${row.key}`,
			{ count: row.total, days: row.days },
		]),
	);
	const daysOf = new Map(
		days.results.map((row) => [zoneKey(row.connection_id, row.zone_id), row.days]),
	);
	const rulesOf = new Map<string, ProtectionRuleView[]>();
	for (const row of rules.results) {
		const key = zoneKey(row.connection_id, row.zone_id);
		const list = rulesOf.get(key) ?? [];
		list.push({
			ruleId: row.rule_id,
			description: row.description,
			action: row.action,
			enabled: row.enabled === 1,
			lastUpdated: row.last_updated,
			acted: actedOf.get(`${key}/${row.rule_id}`) ?? null,
		});
		rulesOf.set(key, list);
	}

	const views = zones.results.map((row): ProtectionZoneView => {
		const key = zoneKey(row.connection_id, row.zone_id);
		const listed = rulesOf.get(key) ?? [];
		return {
			connectionId: row.connection_id,
			connectionName: row.connection_name,
			accountId: row.account_id,
			zoneId: row.zone_id,
			name: row.name,
			plan: row.plan,
			readAt: row.read_at,
			custom: partOf(row.custom_state, row.custom_failure, () => ({
				total: listed.length,
				enabled: listed.filter((rule) => rule.enabled).length,
			})),
			managed: partOf(row.managed_state, row.managed_failure, () => ({
				rulesets: rulesetsOf(row.managed_rulesets),
			})),
			rateLimit: partOf(row.rate_limit_state, row.rate_limit_failure, () => ({
				total: row.rate_limit_total ?? 0,
				enabled: row.rate_limit_enabled ?? 0,
			})),
			bot: partOf(row.bot_state, row.bot_failure, () => ({
				fightMode: row.bot_fight_mode === null ? null : row.bot_fight_mode === 1,
			})),
			securityLevel: partOf(row.security_level_state, row.security_level_failure, () => ({
				level: row.security_level ?? "",
			})),
			rules: listed,
			ruleDays: daysOf.get(key) ?? 0,
		};
	});

	return { hasConnections: (connections?.n ?? 0) > 0, zones: views };
}

export async function readProtectionPage(slug: string): Promise<Response> {
	const page = await listProtection(slug);
	return page ? answer(page) : notFound();
}
