import { z } from "zod";
import { CLOUDFLARE_API, isAccountId } from "./cloudflare";
import { UpstreamError, type UpstreamFailure } from "./errors";
import { apiBase, type FetchOptions, readJson, send } from "./http";
import type { Credentials } from "./traffic";

// What protects a zone: its custom WAF rules, managed rulesets and rate limiting rules, whether
// Bot Fight Mode is on, and its security level. Guard reads them with three optional zone
// permissions (Zone WAF: Read, Bot Management: Read, Zone Settings: Read) and nothing more.
//
// Measured on 2026-11-14 on an account of 30 Free zones:
// - `GET /zones/{zone}/rulesets/phases/<phase>/entrypoint` answers 200 with `result.rules[]`, or 404
//   when the zone has nothing in that phase. Phases read: `http_request_firewall_custom`,
//   `http_request_firewall_managed` and `http_ratelimit`. Managed rules are `execute` rules whose
//   `action_parameters.id` names the managed ruleset; `GET /zones/{zone}/rulesets` gives its name.
// - `GET /zones/{zone}/bot_management` answers 200 with `result.fight_mode`, `GET
//   /zones/{zone}/settings/security_level` with `result.value`. Without the permission, both 403.
// - DDoS needs another permission and is always on, so it is not read; `http_request_sbfm` is not
//   a phase on these zones (400).
//
// A rule's `expression` is never read. It can hold the customer's own secrets (a header value, an
// address in a skip rule), so it is left out of every schema here and the parser strips it. The
// tests fail if one is stored or returned.

/** Requests a zone costs: three entrypoints, bot management and the security level. */
export const PROTECTION_REQUESTS_PER_ZONE = 5;
/** A zone's custom rules kept, at most. Free has 5 and Enterprise 1,000. */
export const MAX_CUSTOM_RULES = 200;
const MAX_DESCRIPTION = 200;
const MAX_NAME = 200;

const ZONE_ID = /^[0-9a-f]{32}$/;

/** One thing Guard tried to read: its value, "nothing there" (a 404), or why it failed. */
export type Part<T> =
	| { readonly state: "ok"; readonly value: T }
	| { readonly state: "none" }
	| { readonly state: "failed"; readonly failure: UpstreamFailure };

export interface CustomRule {
	readonly id: string;
	/** `block`, `managed_challenge`, `skip`, `log`... as Cloudflare names it. */
	readonly action: string;
	/** Cut to 200 characters. Empty when the rule has none. */
	readonly description: string;
	readonly enabled: boolean;
	/** When Cloudflare says the rule last changed. */
	readonly lastUpdated: string | null;
}

export interface ManagedRuleset {
	readonly id: string;
	/** From the zone's rulesets; null when the list could not be read. */
	readonly name: string | null;
	readonly enabled: boolean;
}

export interface RateLimits {
	readonly total: number;
	readonly enabled: number;
}

export interface Protection {
	/** `none` for a zone without custom rules. */
	readonly custom: Part<{ rules: CustomRule[] }>;
	/** `none` when no managed ruleset is deployed. */
	readonly managed: Part<{ rulesets: ManagedRuleset[] }>;
	readonly rateLimit: Part<RateLimits>;
	/** `fightMode` is null when Cloudflare did not say, as on zones that use another bot product. */
	readonly bot: Part<{ fightMode: boolean | null }>;
	/** `essentially_off`, `low`, `medium`, `high`, `under_attack` or what Cloudflare adds. */
	readonly securityLevel: Part<{ level: string }>;
}

const rule = z.object({
	id: z.string().min(1),
	action: z.string().catch(""),
	description: z.string().nullish().catch(null),
	enabled: z.boolean().catch(true),
	last_updated: z.string().nullish().catch(null),
	// Only the id of what an `execute` rule runs, which names a managed ruleset.
	action_parameters: z
		.object({ id: z.string().nullish().catch(null) })
		.nullish()
		.catch(null),
});

type Rule = z.infer<typeof rule>;

const entrypoint = z.object({
	success: z.literal(true),
	result: z.object({ rules: z.array(rule).nullish().catch(null) }),
});

const rulesets = z.object({
	success: z.literal(true),
	result: z.array(z.object({ id: z.string(), name: z.string().nullish().catch(null) })),
});

const botManagement = z.object({
	success: z.literal(true),
	result: z.object({ fight_mode: z.boolean().nullish().catch(null) }),
});

const securityLevel = z.object({
	success: z.literal(true),
	result: z.object({ value: z.string().min(1) }),
});

function url(options: FetchOptions, zoneId: string, path: string): string {
	return `${apiBase(options, "cloudflare", CLOUDFLARE_API)}/zones/${zoneId}/${path}`;
}

async function get<T>(
	account: Credentials,
	address: string,
	schema: z.ZodType<T>,
	options: FetchOptions,
): Promise<T> {
	const response = await send(
		"cloudflare",
		address,
		{ headers: { Authorization: `Bearer ${account.token}`, Accept: "application/json" } },
		options,
	);
	return readJson("cloudflare", response, schema);
}

/**
 * Runs one read as a part of the answer: a failure of Cloudflare's becomes that part's state and
 * never throws, so one part failing does not spoil the others. `notFoundIsNone` is for an
 * entrypoint, where a 404 means the zone has nothing there.
 */
async function part<T>(read: () => Promise<Part<T>>, notFoundIsNone: boolean): Promise<Part<T>> {
	try {
		return await read();
	} catch (error) {
		if (!(error instanceof UpstreamError)) throw error;
		if (notFoundIsNone && error.failure === "not_found") return { state: "none" };
		return { state: "failed", failure: error.failure };
	}
}

const rulesOf = (body: { result: { rules?: Rule[] | null } }): Rule[] => body.result.rules ?? [];

/**
 * What protects one zone. Five requests, made together; each part is its own result, so a token
 * with Zone WAF: Read but not Zone Settings: Read still gets the rules. Throws only for a bad id
 * or when `options.signal` aborts.
 */
export async function readProtection(
	account: Credentials,
	zoneId: string,
	options: FetchOptions = {},
): Promise<Protection> {
	if (!isAccountId(account.accountId)) {
		throw new UpstreamError("cloudflare", "not_found", "That is not a Cloudflare account id");
	}
	if (!ZONE_ID.test(zoneId)) throw new RangeError("Zone id must be well formed");
	const phase = (name: string) => url(options, zoneId, `rulesets/phases/${name}/entrypoint`);

	const [custom, managed, rateLimit, bot, level] = await Promise.all([
		part<{ rules: CustomRule[] }>(async () => {
			const rules = rulesOf(
				await get(account, phase("http_request_firewall_custom"), entrypoint, options),
			);
			if (rules.length === 0) return { state: "none" };
			return {
				state: "ok",
				value: {
					rules: rules.slice(0, MAX_CUSTOM_RULES).map((one) => ({
						id: one.id,
						action: one.action,
						description: (one.description ?? "").slice(0, MAX_DESCRIPTION),
						enabled: one.enabled,
						lastUpdated: one.last_updated ?? null,
					})),
				},
			};
		}, true),
		part<{ rulesets: ManagedRuleset[] }>(async () => {
			const rules = rulesOf(
				await get(account, phase("http_request_firewall_managed"), entrypoint, options),
			);
			// An `execute` rule runs a ruleset; one rule per ruleset is typical, and a ruleset run by
			// several counts as on when any of them is.
			const deployed = new Map<string, boolean>();
			for (const one of rules) {
				const id = one.action_parameters?.id;
				if (one.action !== "execute" || !id) continue;
				deployed.set(id, (deployed.get(id) ?? false) || one.enabled);
			}
			if (deployed.size === 0) return { state: "none" };
			// The names are a courtesy: a list that cannot be read leaves them out.
			const names = new Map<string, string>();
			try {
				for (const one of (await get(account, url(options, zoneId, "rulesets"), rulesets, options))
					.result) {
					if (one.name) names.set(one.id, one.name.slice(0, MAX_NAME));
				}
			} catch (error) {
				if (!(error instanceof UpstreamError)) throw error;
			}
			return {
				state: "ok",
				value: {
					rulesets: [...deployed].map(([id, enabled]) => ({
						id,
						name: names.get(id) ?? null,
						enabled,
					})),
				},
			};
		}, true),
		part<RateLimits>(async () => {
			const rules = rulesOf(await get(account, phase("http_ratelimit"), entrypoint, options));
			if (rules.length === 0) return { state: "none" };
			return {
				state: "ok",
				value: { total: rules.length, enabled: rules.filter((one) => one.enabled).length },
			};
		}, true),
		part<{ fightMode: boolean | null }>(async () => {
			const body = await get(
				account,
				url(options, zoneId, "bot_management"),
				botManagement,
				options,
			);
			return { state: "ok", value: { fightMode: body.result.fight_mode ?? null } };
		}, false),
		part<{ level: string }>(async () => {
			const body = await get(
				account,
				url(options, zoneId, "settings/security_level"),
				securityLevel,
				options,
			);
			return { state: "ok", value: { level: body.result.value } };
		}, false),
	]);
	return { custom, managed, rateLimit, bot, securityLevel: level };
}
