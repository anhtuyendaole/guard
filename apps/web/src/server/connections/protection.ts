import {
	type FetchOptions,
	type Part,
	type Protection,
	readProtection,
	UpstreamError,
	type UpstreamFailure,
	type Zone,
} from "@gateweave/guard-scan";
import { zoneDashboardUrl } from "../../lib/dashboard-links";
import type { Database } from "../db";
import type { PresentFinding } from "./findings";

/**
 * Reading what protects each zone of a Cloudflare connection: managed rules, custom rules, rate
 * limiting, Bot Fight Mode and the security level (docs/architecture.md, "Protection"). Never a
 * rule's expression: `packages/scan` does not read it, and no column here could hold it.
 */

export const LEVEL_OFF_KIND = "security_level_off";
/** The value Cloudflare gives a security level that challenges nobody on reputation. */
export const LEVEL_OFF = "essentially_off";

/** What every protection finding of an account's fingerprint starts with. */
export const protectionPrefix = (accountId: string) => `protection:${accountId}:`;

export const levelOffFingerprint = (accountId: string, zoneId: string) =>
	`${protectionPrefix(accountId)}${LEVEL_OFF_KIND}:${zoneId}`;

/** Rows written by one statement, which D1 binds as one JSON value. */
const ROWS_PER_STATEMENT = 200;
const ZONES_PER_STATEMENT = 50;

export interface ProtectionRead {
	/** The findings of zones whose security level could be read. */
	findings: PresentFinding[];
	/** Fingerprints (or prefixes) whose findings this scan could not judge, which stay as they are. */
	held: string[];
	/** Something failed in a way that passes with time: try again within the hour. */
	retry: boolean;
	/** What to write, in a batch of their own before the findings are changed. */
	statements: D1PreparedStatement[];
}

interface ConnectionRef {
	id: string;
	organization_id: string;
	target: string;
}

/** What a scan that has no zones to read, or could not store them, leaves: nothing judged. */
export function unstoredProtection(connection: ConnectionRef): ProtectionRead {
	return {
		findings: [],
		held: [protectionPrefix(connection.target)],
		retry: false,
		statements: [],
	};
}

function chunks<T>(items: readonly T[], size: number): T[][] {
	const out: T[][] = [];
	for (let start = 0; start < items.length; start += size)
		out.push(items.slice(start, start + size));
	return out;
}

const retryable = (failure: UpstreamFailure) =>
	failure === "rate_limited" || failure === "unavailable";

const parts = (protection: Protection): Part<unknown>[] => [
	protection.custom,
	protection.managed,
	protection.rateLimit,
	protection.bot,
	protection.securityLevel,
];

/** The security level finding for a zone, or null. Low: it is a setting, not a breach. */
export function securityLevelFinding(
	accountId: string,
	zone: { id: string; name: string },
	level: string,
): PresentFinding | null {
	if (level !== LEVEL_OFF) return null;
	return {
		fingerprint: levelOffFingerprint(accountId, zone.id),
		source: "cloudflare",
		severity: "low",
		kind: LEVEL_OFF_KIND,
		subject: zone.name,
		title: `The security level of ${zone.name} is Essentially Off`,
		url: zoneDashboardUrl(accountId, zone.name, "security_settings"),
		fixedVersion: null,
	};
}

/**
 * Reads the protection of each of `zones`, one zone at a time with its five requests made
 * together, so five are in flight at once. A zone, or a part of one, that cannot be read is
 * recorded as such and never fails the scan. Returns the statements that store it all, and the
 * `security_level_off` findings of the zones whose level was read.
 */
export async function readConnectionProtection(
	db: Database,
	connection: ConnectionRef,
	token: string,
	options: FetchOptions,
	zones: readonly Zone[] | null,
): Promise<ProtectionRead> {
	if (zones === null) return unstoredProtection(connection);
	const account = { accountId: connection.target, token };

	const findings: PresentFinding[] = [];
	const held: string[] = [];
	let retry = false;
	const read: { zone: Zone; protection: Protection }[] = [];
	for (const zone of zones) {
		let protection: Protection;
		try {
			protection = await readProtection(account, zone.id, options);
		} catch (error) {
			// A bad id, or an abort: nothing to record for this zone, and its finding stays as it is.
			if (error instanceof UpstreamError || error instanceof RangeError) {
				held.push(levelOffFingerprint(connection.target, zone.id));
				continue;
			}
			throw error;
		}
		read.push({ zone, protection });
		for (const part of parts(protection)) {
			if (part.state === "failed" && retryable(part.failure)) retry = true;
		}
		const level = protection.securityLevel;
		if (level.state === "ok") {
			const found = securityLevelFinding(connection.target, zone, level.value.level);
			if (found) findings.push(found);
		} else if (level.state === "failed") {
			held.push(levelOffFingerprint(connection.target, zone.id));
		}
	}

	const failure = (part: Part<unknown>) => (part.state === "failed" ? part.failure : null);
	const zoneRows = read.map(({ zone, protection: p }) => ({
		id: zone.id,
		name: zone.name,
		plan: zone.plan,
		customState: p.custom.state,
		customFailure: failure(p.custom),
		managedState: p.managed.state,
		managedFailure: failure(p.managed),
		managedRulesets: p.managed.state === "ok" ? JSON.stringify(p.managed.value.rulesets) : null,
		rateLimitState: p.rateLimit.state,
		rateLimitFailure: failure(p.rateLimit),
		rateLimitTotal: p.rateLimit.state === "ok" ? p.rateLimit.value.total : null,
		rateLimitEnabled: p.rateLimit.state === "ok" ? p.rateLimit.value.enabled : null,
		botState: p.bot.state,
		botFailure: failure(p.bot),
		botFightMode:
			p.bot.state === "ok" && p.bot.value.fightMode !== null
				? p.bot.value.fightMode
					? 1
					: 0
				: null,
		securityLevelState: p.securityLevel.state,
		securityLevelFailure: failure(p.securityLevel),
		securityLevel: p.securityLevel.state === "ok" ? p.securityLevel.value.level : null,
	}));
	const ruleRows = read.flatMap(({ zone, protection: p }) =>
		p.custom.state === "ok"
			? p.custom.value.rules.map((rule, position) => ({
					zone: zone.id,
					id: rule.id,
					position,
					action: rule.action,
					description: rule.description,
					enabled: rule.enabled ? 1 : 0,
					lastUpdated: rule.lastUpdated,
				}))
			: [],
	);

	const prepare = (sql: string) => db.$client.prepare(sql);
	const listedIds = JSON.stringify(zones.map((zone) => zone.id));
	const readAt = Date.now();
	const statements: D1PreparedStatement[] = [
		// A zone that is gone from the account takes its rows with it.
		prepare(
			"DELETE FROM protection_zone WHERE connection_id = ?1 AND zone_id NOT IN (SELECT value FROM json_each(?2))",
		).bind(connection.id, listedIds),
		// Rules are replaced as a whole, so a rule deleted in Cloudflare, or a zone whose rules can no
		// longer be read, leaves none behind.
		prepare("DELETE FROM protection_rule WHERE connection_id = ?1").bind(connection.id),
	];
	const upsertZones = prepare(
		`INSERT INTO protection_zone (connection_id, organization_id, zone_id, name, plan, read_at,
			custom_state, custom_failure, managed_state, managed_failure, managed_rulesets,
			rate_limit_state, rate_limit_failure, rate_limit_total, rate_limit_enabled,
			bot_state, bot_failure, bot_fight_mode,
			security_level_state, security_level_failure, security_level)
		SELECT ?1, ?2, json_extract(value, '$.id'), json_extract(value, '$.name'), json_extract(value, '$.plan'), ?3,
			json_extract(value, '$.customState'), json_extract(value, '$.customFailure'),
			json_extract(value, '$.managedState'), json_extract(value, '$.managedFailure'), json_extract(value, '$.managedRulesets'),
			json_extract(value, '$.rateLimitState'), json_extract(value, '$.rateLimitFailure'),
			json_extract(value, '$.rateLimitTotal'), json_extract(value, '$.rateLimitEnabled'),
			json_extract(value, '$.botState'), json_extract(value, '$.botFailure'), json_extract(value, '$.botFightMode'),
			json_extract(value, '$.securityLevelState'), json_extract(value, '$.securityLevelFailure'), json_extract(value, '$.securityLevel')
		FROM json_each(?4) WHERE true
		ON CONFLICT (connection_id, zone_id) DO UPDATE SET name = excluded.name, plan = excluded.plan,
			read_at = excluded.read_at, custom_state = excluded.custom_state,
			custom_failure = excluded.custom_failure, managed_state = excluded.managed_state,
			managed_failure = excluded.managed_failure, managed_rulesets = excluded.managed_rulesets,
			rate_limit_state = excluded.rate_limit_state, rate_limit_failure = excluded.rate_limit_failure,
			rate_limit_total = excluded.rate_limit_total, rate_limit_enabled = excluded.rate_limit_enabled,
			bot_state = excluded.bot_state, bot_failure = excluded.bot_failure,
			bot_fight_mode = excluded.bot_fight_mode, security_level_state = excluded.security_level_state,
			security_level_failure = excluded.security_level_failure, security_level = excluded.security_level`,
	);
	for (const chunk of chunks(zoneRows, ZONES_PER_STATEMENT)) {
		statements.push(
			upsertZones.bind(connection.id, connection.organization_id, readAt, JSON.stringify(chunk)),
		);
	}
	const insertRules = prepare(
		`INSERT INTO protection_rule (connection_id, organization_id, zone_id, rule_id, position, action,
			description, enabled, last_updated)
		SELECT ?1, ?2, json_extract(value, '$.zone'), json_extract(value, '$.id'), json_extract(value, '$.position'),
			json_extract(value, '$.action'), json_extract(value, '$.description'), json_extract(value, '$.enabled'),
			json_extract(value, '$.lastUpdated')
		FROM json_each(?3) WHERE true
		ON CONFLICT DO NOTHING`,
	);
	for (const chunk of chunks(ruleRows, ROWS_PER_STATEMENT)) {
		statements.push(
			insertRules.bind(connection.id, connection.organization_id, JSON.stringify(chunk)),
		);
	}
	return { findings, held, retry, statements };
}
