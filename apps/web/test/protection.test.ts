import { utcDay } from "@gateweave/guard-scan";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createWorkspace } from "./accounts";
import { cloudflareToken, origin, startWorld, type World } from "./connections-world";
import type { FakeRule, FakeZone } from "./upstreams";

const DAY_MS = 86_400_000;
const day = (back: number) => utcDay(Date.now() - back * DAY_MS);

let accounts = 0;
/** A Cloudflare account id of its own, so each test connects without meeting another's. */
const nextAccount = () => (0x700 + ++accounts).toString(16).padStart(32, "b");

/** An expression a customer might write, with a secret in it that must never be kept. */
const SECRET = 'http.request.headers["x-internal-key"][0] eq "s3cr3t-header-value"';

const rule = (id: string, fields: Partial<FakeRule> = {}): FakeRule => ({
	id: id.repeat(32).slice(0, 32),
	action: "block",
	description: `Rule ${id}`,
	enabled: true,
	expression: SECRET,
	last_updated: "2026-11-01T10:00:00.000000Z",
	...fields,
});

const protectionRequests = (world: World) =>
	world.upstream.seen.filter((seen) => /\/zones\/[0-9a-f]{32}\//.test(seen.path));

const levelOffOf = async (world: World, connectionId: string) =>
	(await world.findingRows(connectionId)).filter((row) => row.kind === "security_level_off");

/**
 * A `security_level_off` finding as an earlier Guard raised it, for a scan to find open. The kind
 * was dropped when the security level came to mean only Under Attack mode.
 */
async function openOldLevelFinding(
	world: World,
	connectionId: string,
	account: string,
	zone: FakeZone,
) {
	await world.guard.db
		.prepare(
			`INSERT INTO finding (id, organization_id, connection_id, fingerprint, source, severity, kind, subject, title, url, first_seen_at, last_seen_at)
			VALUES (?1, ?2, ?3, ?4, 'cloudflare', 'low', 'security_level_off', ?5, 'The security level is Essentially Off', 'https://dash.cloudflare.com/x', 1, 1)`,
		)
		.bind(
			crypto.randomUUID(),
			world.workspaceId,
			connectionId,
			`protection:${account}:security_level_off:${zone.id}`,
			zone.name,
		)
		.run();
}

async function connect(world: World, n: number, zones: (account: string) => FakeZone[]) {
	const account = nextAccount();
	const token = cloudflareToken(n);
	world.upstream.addAccount(account, token);
	const made = zones(account);
	const { connection } = await world.connectCloudflare(account, token);
	return { account, token, zones: made, connection };
}

describe("reading protection", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("stores each zone's protection and custom rules, five requests a zone, and never an expression", async () => {
		const { zones, connection, token } = await connect(world, 50, (account) => {
			const zone = world.upstream.addZone(account, "shop.example", {
				custom: [
					rule("a"),
					rule("b", { enabled: false, action: "skip", description: "d".repeat(300) }),
				],
				managed: [
					{
						id: "m1",
						action: "execute",
						enabled: true,
						expression: SECRET,
						action_parameters: { id: "set-1" },
					},
				],
				rulesets: [{ id: "set-1", name: "Cloudflare Managed Ruleset" }],
				rateLimit: [rule("c"), rule("d", { enabled: false })],
				botFightMode: false,
				securityLevel: "high",
			});
			world.upstream.addZone(account, "second.example");
			return [zone];
		});
		const zone = zones[0] as FakeZone;

		// Two zones, each with its three entrypoints, bot management and security level; the
		// rulesets list is asked only for the zone that deploys one.
		expect(
			protectionRequests(world).filter((seen) => !seen.path.endsWith("/rulesets")),
		).toHaveLength(10);
		expect(
			protectionRequests(world).filter((seen) => seen.path.endsWith("/rulesets")),
		).toHaveLength(1);

		const shop = (await world.protectionZones(connection.id)).find(
			(row) => row.name === "shop.example",
		);
		expect(shop).toMatchObject({
			zone_id: zone.id,
			name: "shop.example",
			custom_state: "ok",
			managed_state: "ok",
			rate_limit_state: "ok",
			rate_limit_total: 2,
			rate_limit_enabled: 1,
			bot_state: "ok",
			bot_fight_mode: 0,
			security_level_state: "ok",
			security_level: "high",
		});
		expect(JSON.parse(String(shop?.managed_rulesets))).toEqual([
			{ id: "set-1", name: "Cloudflare Managed Ruleset", enabled: true },
		]);
		const rules = await world.protectionRules(connection.id);
		expect(rules.map((one) => [one.rule_id, one.position, one.action, one.enabled])).toEqual([
			["a".repeat(32), 0, "block", 1],
			["b".repeat(32), 1, "skip", 0],
		]);
		expect(rules[1]?.description).toHaveLength(200);
		expect(rules[0]?.last_updated).toBe("2026-11-01T10:00:00.000000Z");

		// The expression is nowhere: not in a table, not in a page's data, not in a column's name.
		const page = await world.protection();
		expect(page.text).not.toContain("s3cr3t");
		expect(page.text.toLowerCase()).not.toContain("expression");
		expect(await world.dump()).not.toContain("s3cr3t");
		expect((await world.dump()).toLowerCase()).not.toContain("expression");
		const columns = [
			...(await world.guard.db.prepare("PRAGMA table_info(protection_zone)").all()).results,
			...(await world.guard.db.prepare("PRAGMA table_info(protection_rule)").all()).results,
		] as { name: string }[];
		expect(columns.filter((column) => /expression|filter|match/i.test(column.name))).toEqual([]);
		expect(await world.dump()).not.toContain(token);
	});

	it("says none for a zone without custom rules, and keeps the rest", async () => {
		const { connection, zones } = await connect(world, 51, (account) => [
			world.upstream.addZone(account, "plain.example"),
		]);

		const [row] = await world.protectionZones(connection.id);
		expect(row).toMatchObject({
			custom_state: "none",
			managed_state: "none",
			rate_limit_state: "none",
			bot_state: "ok",
			security_level_state: "ok",
		});
		expect(await world.protectionRules(connection.id)).toEqual([]);
		const view = (await world.protectionPage()).body.zones.find(
			(one) => one.zoneId === zones[0]?.id,
		);
		expect(view?.custom).toEqual({ state: "none" });
		expect(view?.rules).toEqual([]);
	});

	it("keeps the parts apart: a refusal or a failure of one never spoils the others", async () => {
		const { connection, zones } = await connect(world, 52, (account) => [
			world.upstream.addZone(account, "mixed.example", {
				custom: [rule("a")],
				securityLevel: "low",
				permissions: { waf: true, bots: false, settings: true },
				protectionStatus: { rateLimit: 500, level: 429 },
			}),
		]);

		const [row] = await world.protectionZones(connection.id);
		expect(row).toMatchObject({
			custom_state: "ok",
			managed_state: "none",
			rate_limit_state: "failed",
			rate_limit_failure: "unavailable",
			bot_state: "failed",
			bot_failure: "forbidden",
			bot_fight_mode: null,
			security_level_state: "failed",
			security_level_failure: "rate_limited",
			security_level: null,
		});
		// The scan is fine, and the rules that could be read are stored. A failure that passes with
		// time brings the next scan within the hour.
		expect((await world.connectionRow(connection.id))?.last_scan_outcome).toBe("ok");
		expect((await world.connectionRow(connection.id))?.next_scan_at).toBeLessThan(
			Date.now() + 2 * 3600_000,
		);
		expect(await world.protectionRules(connection.id)).toHaveLength(1);
		const view = (await world.protectionPage()).body.zones.find(
			(one) => one.zoneId === zones[0]?.id,
		);
		expect(view?.bot).toEqual({ state: "failed", failure: "forbidden" });
		expect(view?.rateLimit).toEqual({ state: "failed", failure: "unavailable" });
	});

	it("connects with none of the three optional permissions", async () => {
		const { connection } = await connect(world, 53, (account) => [
			world.upstream.addZone(account, "closed.example", {
				permissions: { waf: false, bots: false, settings: false },
			}),
		]);

		const [row] = await world.protectionZones(connection.id);
		expect(row).toMatchObject({
			custom_failure: "forbidden",
			managed_failure: "forbidden",
			rate_limit_failure: "forbidden",
			bot_failure: "forbidden",
			security_level_failure: "forbidden",
		});
		expect((await world.connectionRow(connection.id))?.last_scan_outcome).toBe("ok");
	});

	it("replaces the rules on every scan, and a zone that leaves the account takes its rows", async () => {
		const { account, connection, zones } = await connect(world, 54, (account) => [
			world.upstream.addZone(account, "stays.example", { custom: [rule("a"), rule("b")] }),
			world.upstream.addZone(account, "leaves.example", { custom: [rule("c")] }),
		]);
		expect(await world.protectionRules(connection.id)).toHaveLength(3);

		const [stays, leaves] = zones as [FakeZone, FakeZone];
		stays.custom = [rule("b", { description: "Renamed" })];
		const fake = world.upstream.accounts.get(account);
		if (!fake) throw new Error("the account is known");
		fake.zones = fake.zones.filter((one) => one.id !== leaves.id);
		await world.scanDue([connection.id]);

		expect((await world.protectionZones(connection.id)).map((row) => row.name)).toEqual([
			"stays.example",
		]);
		const rules = await world.protectionRules(connection.id);
		expect(rules.map((one) => [one.zone_id, one.rule_id, one.description])).toEqual([
			[stays.id, "b".repeat(32), "Renamed"],
		]);
	});

	it("drops a zone's rules when they can no longer be read, so none are shown stale", async () => {
		const { connection, zones } = await connect(world, 55, (account) => [
			world.upstream.addZone(account, "revoked.example", { custom: [rule("a")] }),
		]);
		expect(await world.protectionRules(connection.id)).toHaveLength(1);

		(zones[0] as FakeZone).permissions.waf = false;
		await world.scanDue([connection.id]);

		expect(await world.protectionRules(connection.id)).toEqual([]);
		expect((await world.protectionZones(connection.id))[0]?.custom_state).toBe("failed");
	});
});

describe("the rules and what Traffic recorded of them", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("joins a rule with its recorded activity by id, and never says a quiet one did nothing", async () => {
		const loud = "c".repeat(32);
		const { zones } = await connect(world, 60, (account) => {
			const zone = world.upstream.addZone(account, "shop.example", {
				custom: [rule("c", { description: "Block scanners" }), rule("d", { description: "Quiet" })],
			});
			zone.days[day(1)] = {
				actions: [{ action: "block", source: "firewallCustom", count: 100 }],
			};
			zone.events = [10, 5].map((sampleInterval, i) => ({
				ruleId: loud,
				description: "Block scanners",
				source: "firewallCustom",
				action: "block",
				sampleInterval,
				datetime: `${day(1)}T09:0${i}:00Z`,
			}));
			return [zone];
		});

		const view = (await world.protectionPage()).body.zones.find(
			(one) => one.zoneId === zones[0]?.id,
		);

		expect(view?.rules.map((one) => [one.description, one.acted])).toEqual([
			["Block scanners", { count: 15, days: 1 }],
			// Not recorded is null, which the page words as "No activity recorded".
			["Quiet", null],
		]);
		expect(view?.ruleDays).toBe(1);
		const page = await world.page(`/${world.slug}/protection`);
		expect(page.text).toContain("About 15 requests over 1 recorded day");
		expect(page.text).toContain("No activity recorded");
		expect(page.text.toLowerCase()).not.toContain("never acted");
	});
});

describe("the old security level finding", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("is no longer raised, whatever the level, and Under Attack mode raises nothing either", async () => {
		const { connection } = await connect(world, 70, (acct) => [
			world.upstream.addZone(acct, "open.example", { securityLevel: "essentially_off" }),
			world.upstream.addZone(acct, "attacked.example", { securityLevel: "under_attack" }),
		]);

		expect(await levelOffOf(world, connection.id)).toEqual([]);
		expect((await world.findings()).body.findings.map((one) => one.kind)).not.toContain(
			"security_level_off",
		);
	});

	it("resolves on the next scan when an earlier Guard left it open", async () => {
		const { account, connection, zones } = await connect(world, 71, (acct) => [
			world.upstream.addZone(acct, "stale.example", { securityLevel: "essentially_off" }),
		]);
		const zone = zones[0] as FakeZone;
		await openOldLevelFinding(world, connection.id, account, zone);
		expect((await levelOffOf(world, connection.id))[0]?.resolved_at).toBeNull();

		await world.scanDue([connection.id]);

		const [found] = await levelOffOf(world, connection.id);
		expect(found?.resolved_at).not.toBeNull();
		// Resolved even though the level is still "essentially_off": it no longer means anything.
		expect((await world.findings()).body.findings.map((one) => one.kind)).not.toContain(
			"security_level_off",
		);
	});

	it("resolves even when the level or the zone list cannot be read, since nothing judges it now", async () => {
		const { account, connection, zones } = await connect(world, 72, (acct) => [
			world.upstream.addZone(acct, "unreadable.example", {
				permissions: { waf: true, bots: true, settings: false },
			}),
		]);
		await openOldLevelFinding(world, connection.id, account, zones[0] as FakeZone);

		await world.scanDue([connection.id]);

		expect((await levelOffOf(world, connection.id))[0]?.resolved_at).not.toBeNull();
	});
});

describe("who may see the page", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("shows the overview, a fix link and the plain words, to any member", async () => {
		await connect(world, 80, (account) => [
			world.upstream.addZone(account, "bare.example", { botFightMode: false }),
			world.upstream.addZone(account, "guarded.example", {
				botFightMode: true,
				securityLevel: "under_attack",
				custom: [rule("a")],
				permissions: { waf: true, bots: true, settings: true },
			}),
			world.upstream.addZone(account, "blind.example", {
				permissions: { waf: false, bots: true, settings: true },
			}),
		]);
		const member = await world.addMember("mia");

		const mine = await world.page(`/${world.slug}/protection`, member);

		expect(mine.status).toBe(200);
		expect(mine.text).toContain("Bot Fight Mode off on 1 of 3 zones");
		expect(mine.text).toContain("WAF managed rules off on 2 of 3 zones");
		expect(mine.text).toContain("Under Attack mode on for 1 of 3 zones");
		expect(mine.text).not.toContain("Security level");
		expect(mine.text).toContain("Turn it on only while a site is under a DDoS attack.");
		expect(mine.text).toContain("Turn it off once an attack is over.");
		expect(mine.text).toContain("WAF rules not readable on 1 of 3 zones");
		expect(mine.text).toContain("Zone › WAF › Read");
		expect(mine.text).toContain("Fix in Cloudflare");
		expect(mine.text).toContain("1 rule, all on");
		expect(mine.text).toContain("Rule a");
		expect(mine.text).toContain("Worth a look");
		expect(mine.text).toContain("Not readable");
		expect(mine.text).toContain("/security/settings");
		expect(mine.text).toContain("bare.example");
	});

	it("answers a non-member, a stranger and a signed-out visitor as a missing workspace", async () => {
		await connect(world, 81, (account) => [world.upstream.addZone(account, "private.example")]);
		const stranger = await world.stranger("sam");
		const missing = await world.protection(world.owner, "no-such-workspace");
		const notMember = await world.protection(stranger);

		expect(notMember.status).toBe(404);
		expect(missing.status).toBe(404);
		expect(notMember.text).toBe(missing.text);
		expect((await world.guard.fetch(`${origin}/api/protection/${world.slug}`)).status).toBe(404);
		expect((await world.page(`/${world.slug}/protection`, stranger)).text).not.toContain(
			"private.example",
		);

		// Another workspace's member sees that workspace's, which has nothing of this one's.
		const slug = `${world.slug}-other`;
		await createWorkspace(world.guard, origin, stranger.headers, slug);
		const theirs = await world.protectionPage(stranger, slug);
		expect(theirs.body.hasConnections).toBe(false);
		expect(JSON.stringify(theirs.body)).not.toContain("private.example");
		expect((await world.protection(stranger, world.slug)).text).toBe(missing.text);
	});

	it("tells a workspace with nothing connected to connect an account", async () => {
		const other = await startWorld();
		try {
			const page = await other.page(`/${other.slug}/protection`);
			expect(page.status).toBe(200);
			expect(page.text).toContain("No Cloudflare account connected.");
		} finally {
			await other.dispose();
		}
	});
});
