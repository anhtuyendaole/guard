import { describe, expect, it } from "vitest";
import type { ProtectionZoneView } from "./connection-schemas";
import { zoneDashboardUrl } from "./dashboard-links";
import {
	actionName,
	activityOf,
	checksOf,
	filterZones,
	issuesOf,
	overviewOf,
	sortZones,
} from "./protection";

/** A zone that is protected as well as Free allows, to be changed one thing at a time. */
function zone(name: string, fields: Partial<ProtectionZoneView> = {}): ProtectionZoneView {
	return {
		connectionId: "c1",
		connectionName: "Main",
		accountId: "a".repeat(32),
		zoneId: `${name}-id`,
		name,
		plan: "Free Website",
		readAt: 1,
		custom: { state: "none" },
		managed: { state: "ok", value: { rulesets: [{ id: "m", name: "Managed", enabled: true }] } },
		rateLimit: { state: "none" },
		bot: { state: "ok", value: { fightMode: true } },
		securityLevel: { state: "ok", value: { level: "medium" } },
		rules: [],
		ruleDays: 0,
		...fields,
	};
}

const status = (z: ProtectionZoneView) =>
	Object.fromEntries(checksOf(z).map((one) => [one.key, one.status]));

describe("a zone's checklist", () => {
	it("is good where a protection is on, and not set up where a choice was never made", () => {
		expect(status(zone("a"))).toEqual({
			managed: "good",
			custom: "neutral",
			rate_limit: "neutral",
			bot: "good",
			under_attack: "good",
		});
	});

	it("says what is worth a look, with a Fix link only there", () => {
		const bad = zone("bad", {
			managed: { state: "none" },
			bot: { state: "ok", value: { fightMode: false } },
			securityLevel: { state: "ok", value: { level: "under_attack" } },
			custom: { state: "ok", value: { total: 2, enabled: 0 } },
		});
		const checks = checksOf(bad);
		expect(checks.map((one) => [one.key, one.status, one.fix])).toEqual([
			["managed", "look", true],
			["custom", "look", true],
			["rate_limit", "neutral", false],
			["bot", "look", true],
			["under_attack", "look", true],
		]);
		expect(checks[0]?.headline).toBe("Off");
		expect(checks[1]?.headline).toBe("2 rules, all off");
		expect(checks[4]?.headline).toBe("On: every visitor gets a challenge page");
		expect(checks[4]?.why).toContain("Turn it off once an attack is over.");
		for (const one of checks) expect(one.why.length).toBeGreaterThan(20);
	});

	it("reads the security level as Under Attack mode only: any other value is Off, and fine", () => {
		// The old values no longer change who is challenged, so none of them is worth a look.
		for (const level of ["essentially_off", "low", "medium", "high", "something_new"]) {
			const check = checksOf(zone("a", { securityLevel: { state: "ok", value: { level } } }))[4];
			expect(check?.label, level).toBe("Under Attack mode");
			expect(check?.status, level).toBe("good");
			expect(check?.headline, level).toBe("Off");
			expect(check?.fix, level).toBe(false);
			expect(check?.why, level).toBe("Turn it on only while a site is under a DDoS attack.");
		}
		expect(
			issuesOf(zone("a", { securityLevel: { state: "ok", value: { level: "essentially_off" } } })),
		).toEqual([]);
		const on = checksOf(
			zone("a", { securityLevel: { state: "ok", value: { level: "under_attack" } } }),
		)[4];
		expect(on).toMatchObject({ status: "look", fix: true, label: "Under Attack mode" });
		expect(on?.why).toContain("can block API clients");
	});

	it("counts custom and rate limiting rules in words", () => {
		const some = checksOf(
			zone("a", {
				custom: { state: "ok", value: { total: 3, enabled: 3 } },
				rateLimit: { state: "ok", value: { total: 3, enabled: 1 } },
			}),
		);
		expect(some[1]?.headline).toBe("3 rules, all on");
		expect(some[2]?.headline).toBe("3 rules, 1 on");
		const one = checksOf(zone("b", { custom: { state: "ok", value: { total: 1, enabled: 1 } } }));
		expect(one[1]?.headline).toBe("1 rule, all on");
	});

	it("names managed rulesets that are on, and a deployed one that is off", () => {
		const on = checksOf(
			zone("a", {
				managed: {
					state: "ok",
					value: {
						rulesets: [
							{ id: "1", name: "Cloudflare Managed Ruleset", enabled: true },
							{ id: "2", name: null, enabled: true },
						],
					},
				},
			}),
		);
		expect(on[0]?.headline).toBe("On: Cloudflare Managed Ruleset, A managed ruleset");
		const off = checksOf(
			zone("b", {
				managed: { state: "ok", value: { rulesets: [{ id: "1", name: "X", enabled: false }] } },
			}),
		);
		expect(off[0]?.status).toBe("look");
		expect(off[0]?.headline).toBe("Deployed, but switched off");
	});

	it("does not call Bot Fight Mode off when Cloudflare did not say", () => {
		const unknown = checksOf(zone("a", { bot: { state: "ok", value: { fightMode: null } } }));
		expect(unknown[3]?.status).toBe("neutral");
		expect(issuesOf(zone("a", { bot: { state: "ok", value: { fightMode: null } } }))).toEqual([]);
	});

	it("says which permission is missing for what could not be read, and only then", () => {
		const blind = zone("blind", {
			managed: { state: "failed", failure: "forbidden" },
			bot: { state: "failed", failure: "forbidden" },
			securityLevel: { state: "failed", failure: "rate_limited" },
		});
		const checks = checksOf(blind);
		expect(checks[0]?.status).toBe("unreadable");
		expect(checks[0]?.problem).toContain("Zone › WAF › Read");
		expect(checks[3]?.problem).toContain("Zone › Bot Management › Read");
		// A failure that is not a missing permission does not ask for one.
		expect(checks[4]?.problem).not.toContain("Zone › Zone Settings › Read");
		expect(checks[4]?.problem).toContain("within the hour");
		expect(checks.every((one) => !one.fix || one.status !== "unreadable")).toBe(true);
	});

	it("says a zone no scan has read is not read yet, not that it is fine", () => {
		const fresh = zone("fresh", {
			readAt: null,
			custom: { state: "unread" },
			managed: { state: "unread" },
			rateLimit: { state: "unread" },
			bot: { state: "unread" },
			securityLevel: { state: "unread" },
		});
		expect(checksOf(fresh).every((one) => one.status === "unread" && !one.fix)).toBe(true);
		expect(issuesOf(fresh)).toEqual([]);
	});

	it("reads levels and actions as words, and unknown ones as Cloudflare writes them", () => {
		expect(actionName("managed_challenge")).toBe("Managed challenge");
		expect(actionName("new_action")).toBe("new action");
		expect(actionName("")).toBe("No action");
	});
});

describe("the overview", () => {
	const zones = [
		zone("a", { managed: { state: "none" }, bot: { state: "ok", value: { fightMode: false } } }),
		zone("b", { managed: { state: "none" } }),
		zone("c", {
			managed: { state: "none" },
			securityLevel: { state: "ok", value: { level: "under_attack" } },
		}),
		zone("d", { bot: { state: "failed", failure: "forbidden" } }),
		zone("unread", { readAt: null, managed: { state: "unread" } }),
	];

	it("counts each issue against the zones that were read", () => {
		expect(overviewOf(zones).map((line) => [line.id, line.zones, line.text])).toEqual([
			["managed_off", 3, "WAF managed rules off on 3 of 4 zones"],
			["bot_off", 1, "Bot Fight Mode off on 1 of 4 zones"],
			["under_attack_on", 1, "Under Attack mode on for 1 of 4 zones"],
			[
				"missing_bot",
				1,
				"Bot Fight Mode not readable on 1 of 4 zones: add Zone › Bot Management › Read to the token",
			],
		]);
	});

	it("says 1 zone when that is all there is, and is empty when all is well", () => {
		expect(overviewOf([zone("only", { managed: { state: "none" } })])[0]?.text).toBe(
			"WAF managed rules off on 1 zone",
		);
		expect(overviewOf([zone("fine")])).toEqual([]);
		expect(overviewOf([])).toEqual([]);
	});

	it("narrows the zone list to the zones an issue is about, and sorts the worst first", () => {
		expect(filterZones(zones, "bot_off").map((one) => one.name)).toEqual(["a"]);
		expect(filterZones(zones, "managed_off").map((one) => one.name)).toEqual(["a", "b", "c"]);
		expect(filterZones(zones, null)).toHaveLength(5);
		expect(sortZones(zones).map((one) => one.name)).toEqual(["a", "c", "b", "d", "unread"]);
	});
});

describe("a rule's activity", () => {
	it("is an estimate over recorded days, and never says a rule did nothing", () => {
		expect(activityOf({ acted: { count: 1240, days: 3 } })).toEqual({
			text: "About 1,240 requests over 3 recorded days",
			recorded: true,
		});
		expect(activityOf({ acted: { count: 1, days: 1 } }).text).toBe(
			"About 1 request over 1 recorded day",
		);
		expect(activityOf({ acted: null })).toEqual({ text: "No activity recorded", recorded: false });
	});
});

describe("dashboard links", () => {
	it("point at the zone's page, with the account and zone encoded", () => {
		expect(zoneDashboardUrl("a".repeat(32), "shop.example", "security_settings")).toBe(
			`https://dash.cloudflare.com/${"a".repeat(32)}/shop.example/security/settings`,
		);
		expect(zoneDashboardUrl("acc", "shop.example", "security_events")).toBe(
			"https://dash.cloudflare.com/acc/shop.example/security/analytics/events",
		);
		expect(zoneDashboardUrl("acc", "x/../y", "security_rules")).toBe(
			"https://dash.cloudflare.com/acc/x%2F..%2Fy/security/security-rules",
		);
	});
});
