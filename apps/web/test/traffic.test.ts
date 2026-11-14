import { utcDay } from "@gateweave/guard-scan";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createWorkspace } from "./accounts";
import { cloudflareToken, origin, startWorld, type World } from "./connections-world";
import type { FakeZone } from "./upstreams";

const DAY_MS = 86_400_000;
/** The UTC day `back` days ago; 1 is yesterday, the last complete day, and 0 is today. */
const day = (back: number) => utcDay(Date.now() - back * DAY_MS);
const at = (back: number, time = "10:00:00") => `${day(back)}T${time}Z`;

let accounts = 0;
/** A Cloudflare account id of its own, so each test connects without meeting another's. */
const nextAccount = () => (++accounts).toString(16).padStart(32, "a");

/** What a zone's WAF stopped on a day, with a country and a host beside it. */
function blocked(zone: FakeZone, back: number, count: number, action = "block") {
	zone.days[day(back)] = {
		actions: [{ action, source: "firewallCustom", count }],
		countries: [{ name: "US", action, count }],
		hosts: [{ name: zone.name, action, count }],
	};
}

/** Days 2 to 8 ago, then yesterday. */
function week(zone: FakeZone, before: number[], yesterday: number) {
	before.forEach((count, index) => {
		blocked(zone, index + 2, count);
	});
	blocked(zone, 1, yesterday);
}

/** Time moves on a day: what is stored is a day older than it was. */
async function rollForward(world: World, connectionId: string) {
	// Through a marker, since moving every day at once would meet itself in the primary key.
	for (const sql of [
		"UPDATE traffic_count SET day = 'x' || day WHERE connection_id = ?1",
		"UPDATE traffic_count SET day = date(substr(day, 2), '-1 day') WHERE connection_id = ?1",
		"UPDATE traffic_zone SET first_day = date(first_day, '-1 day'), last_day = date(last_day, '-1 day') WHERE connection_id = ?1",
	]) {
		await world.guard.db.prepare(sql).bind(connectionId).run();
	}
}

const trafficQueries = (world: World) =>
	world.upstream.queries.filter((query) => query.query.includes("zoneTag_in"));

const spikeOf = async (world: World, connectionId: string) =>
	(await world.findingRows(connectionId)).filter((row) => row.kind === "waf_spike");

describe("reading traffic", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("stores each complete day once, never today, and nothing older than a week and a day", async () => {
		const account = nextAccount();
		const token = cloudflareToken(1);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "shop.example");
		for (let back = 0; back <= 10; back++) blocked(zone, back, 100 + back);

		const { connection } = await world.connectCloudflare(account, token);

		const rows = await world.trafficRows(connection.id);
		const days = [...new Set(rows.map((row) => row.day))].sort();
		// Yesterday and the seven days before it: eight days.
		expect(days).toEqual([8, 7, 6, 5, 4, 3, 2, 1].map(day));
		expect(days).not.toContain(day(0));
		expect(rows.filter((row) => row.day === day(1))).toEqual([
			{
				zone_id: zone.id,
				day: day(1),
				dimension: "action",
				key: "block",
				action: "block",
				source: "firewallCustom",
				description: null,
				partial: 0,
				count: 101,
			},
			{
				zone_id: zone.id,
				day: day(1),
				dimension: "country",
				key: "US",
				action: "block",
				source: "",
				description: null,
				partial: 0,
				count: 101,
			},
			{
				zone_id: zone.id,
				day: day(1),
				dimension: "host",
				key: "shop.example",
				action: "block",
				source: "",
				description: null,
				partial: 0,
				count: 101,
			},
		]);
		expect(await world.trafficZones(connection.id)).toEqual([
			{
				zone_id: zone.id,
				name: "shop.example",
				plan: "Free Website",
				first_day: day(8),
				last_day: day(1),
				last_failure: null,
			},
		]);
		expect(await world.trafficOutcome(connection.id)).toBe("ok");

		// A second scan has nothing new to read, so it asks for nothing and writes nothing, even
		// though the upstream's numbers have moved.
		blocked(zone, 3, 99_999);
		const asked = world.upstream.queries.length;
		await world.scanDue([connection.id]);
		expect(world.upstream.queries.length).toBe(asked);
		expect(await world.trafficRows(connection.id)).toEqual(rows);

		// The next day brings one more, and reads only that.
		await rollForward(world, connection.id);
		blocked(zone, 1, 7);
		await world.scanDue([connection.id]);
		const latest = trafficQueries(world).at(-1);
		expect(latest?.variables.since).toBe(`${day(1)}T00:00:00Z`);
		expect(latest?.variables.until).toBe(`${day(0)}T00:00:00Z`);
		const after = await world.trafficRows(connection.id);
		expect(after.filter((row) => row.day === day(1) && row.dimension === "action")).toHaveLength(1);
		expect(after.filter((row) => row.day === day(2)).map((row) => row.count)).toEqual([
			101, 101, 101,
		]);
		// What was stored before is untouched by the new numbers.
		expect(after.find((row) => row.day === day(4) && row.dimension === "action")?.count).toBe(103);
	});

	it("scans only active zones, ten to a query, inside the account, with the account-based budget", async () => {
		const account = nextAccount();
		const token = cloudflareToken(2);
		world.upstream.addAccount(account, token);
		// More than a page of zones (the stand-in pages by 50), one of them not active.
		const zones = Array.from({ length: 52 }, (_, i) =>
			world.upstream.addZone(account, `site-${i}.example`, i === 7 ? { status: "pending" } : {}),
		);
		const before = world.upstream.queries.length;

		const { connection } = await world.connectCloudflare(account, token);

		const stored = await world.trafficZones(connection.id);
		expect(stored).toHaveLength(51);
		expect(stored.map((row) => row.zone_id)).not.toContain(zones[7]?.id);
		// The connect's probe names one zone; the scan's batches name ten at most.
		const queries = trafficQueries(world).slice(-6);
		const sizes = queries.map((query) => (query.variables.zones as string[]).length);
		expect(sizes).toEqual([10, 10, 10, 10, 10, 1]);
		for (const query of world.upstream.queries.slice(before)) {
			expect(query.rateLimitType).toBe("account-based");
			if ("zones" in query.variables) {
				expect(query.query).toContain("accounts(filter: { accountTag: $account })");
			}
		}
		const asked = new Set(queries.flatMap((query) => query.variables.zones as string[]));
		expect(asked.has(zones[7]?.id ?? "")).toBe(false);
		const zonesRequests = world.upstream.seen.filter((seen) => seen.path === "/client/v4/zones");
		expect(zonesRequests.length).toBeGreaterThanOrEqual(4);
	});

	it("reads rules for yesterday only, for the 20 busiest zones, weighted by their samples", async () => {
		const account = nextAccount();
		const token = cloudflareToken(3);
		world.upstream.addAccount(account, token);
		const rule = (n: number) => n.toString(16).padStart(32, "0");
		const zones = Array.from({ length: 22 }, (_, i) => {
			const zone = world.upstream.addZone(account, `busy-${String(i).padStart(2, "0")}.example`);
			blocked(zone, 1, (i + 1) * 10);
			blocked(zone, 2, 5);
			zone.events = [
				{
					ruleId: rule(1),
					description: "Block bad bots",
					source: "firewallCustom",
					action: "block",
					sampleInterval: 10,
					datetime: at(1, "09:00:00"),
				},
				{
					ruleId: rule(1),
					description: "Block bad bots",
					source: "firewallCustom",
					action: "block",
					sampleInterval: 5,
					datetime: at(1, "09:30:00"),
				},
				{
					ruleId: rule(2),
					description: "Managed rules",
					source: "firewallManaged",
					action: "managedChallenge",
					sampleInterval: 1,
					datetime: at(1, "11:00:00"),
				},
				// The day before: never read.
				{
					ruleId: rule(3),
					description: "Old",
					source: "firewallCustom",
					action: "block",
					sampleInterval: 1,
					datetime: at(2, "09:00:00"),
				},
			];
			return zone;
		});

		const { connection } = await world.connectCloudflare(account, token);

		const rules = (await world.trafficRows(connection.id)).filter(
			(row) => row.dimension === "rule",
		);
		const withRules = new Set(rules.map((row) => row.zone_id));
		expect(withRules.size).toBe(20);
		// The two with the fewest acted-on requests yesterday are left out.
		expect(withRules.has(zones[0]?.id ?? "")).toBe(false);
		expect(withRules.has(zones[1]?.id ?? "")).toBe(false);
		expect(rules.every((row) => row.day === day(1))).toBe(true);
		const mine = rules.filter((row) => row.zone_id === zones[21]?.id);
		expect(mine).toEqual([
			{
				zone_id: zones[21]?.id,
				day: day(1),
				dimension: "rule",
				key: rule(1),
				action: "block",
				source: "firewallCustom",
				description: "Block bad bots",
				partial: 0,
				// Two samples that stand for 10 and 5 requests.
				count: 15,
			},
			{
				zone_id: zones[21]?.id,
				day: day(1),
				dimension: "rule",
				key: rule(2),
				action: "managedChallenge",
				source: "firewallManaged",
				description: "Managed rules",
				partial: 0,
				count: 1,
			},
		]);
		// At most four calls were in flight is a property of the scan; here, that every query named
		// one zone for its events and at most ten for its counts.
		for (const query of world.upstream.queries) {
			if ("zones" in query.variables) {
				expect((query.variables.zones as string[]).length).toBeLessThanOrEqual(10);
			}
		}
	});

	it("marks a day's rules partial when the page cap cut its events short", async () => {
		const account = nextAccount();
		const token = cloudflareToken(4);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "loud.example", { maxPageSize: 3 });
		blocked(zone, 1, 5000);
		zone.events = Array.from({ length: 10 }, (_, i) => ({
			ruleId: "d".repeat(32),
			description: "Rate limit",
			source: "firewallCustom",
			action: "block",
			sampleInterval: 1,
			datetime: at(1, `10:00:${String(10 + i)}`),
		}));

		const { connection } = await world.connectCloudflare(account, token);

		const rules = (await world.trafficRows(connection.id)).filter(
			(row) => row.dimension === "rule",
		);
		// Two pages of three, the first without its last second (the next page starts there), not ten.
		expect(rules).toHaveLength(1);
		expect(rules[0]?.count).toBe(5);
		expect(rules[0]?.partial).toBe(1);
		const page = (await world.trafficPage()).body;
		const view = page.connections
			.flatMap((one) => one.zones)
			.find((one) => one.name === "loud.example");
		expect(view?.rules[0]?.partial).toBe(true);
	});

	it("keeps 90 days, and removes a connection's traffic with it", async () => {
		const account = nextAccount();
		const other = nextAccount();
		world.upstream.addAccount(account, cloudflareToken(5));
		world.upstream.addAccount(other, cloudflareToken(6));
		const zone = world.upstream.addZone(account, "old.example");
		blocked(zone, 1, 10);
		const bystander = world.upstream.addZone(other, "keep.example");
		blocked(bystander, 1, 10);
		const { connection } = await world.connectCloudflare(account, cloudflareToken(5));
		const { connection: kept } = await world.connectCloudflare(other, cloudflareToken(6));

		for (const [back, id] of [
			[89, connection.id],
			[91, connection.id],
			[400, connection.id],
			[91, kept.id],
		] as const) {
			await world.guard.db
				.prepare(
					"INSERT INTO traffic_count (connection_id, organization_id, zone_id, day, dimension, key, action, source, count) VALUES (?1, ?2, ?3, ?4, 'action', 'block', 'block', 'firewallCustom', 1)",
				)
				.bind(id, world.workspaceId, zone.id, day(back))
				.run();
		}
		await world.scanDue([connection.id]);

		const days = new Set((await world.trafficRows(connection.id)).map((row) => row.day));
		expect(days.has(day(89))).toBe(true);
		expect(days.has(day(91))).toBe(false);
		expect(days.has(day(400))).toBe(false);
		// Only the connection that was scanned is pruned.
		expect((await world.trafficRows(kept.id)).some((row) => row.day === day(91))).toBe(true);

		const removed = await world.act(world.owner, { action: "remove", id: connection.id });
		expect(removed.body.ok).toBe(true);
		expect(await world.trafficRows(connection.id)).toEqual([]);
		expect(await world.trafficZones(connection.id)).toEqual([]);
		expect((await world.trafficRows(kept.id)).length).toBeGreaterThan(0);
		expect((await world.trafficZones(kept.id)).length).toBe(1);
	});
});

describe("the spike finding", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	async function connectWith(name: string, before: number[], yesterday: number, action = "block") {
		const account = nextAccount();
		const token = cloudflareToken(10);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, name);
		before.forEach((count, index) => {
			blocked(zone, index + 2, count);
		});
		blocked(zone, 1, yesterday, action);
		const { connection } = await world.connectCloudflare(account, token);
		return { account, token, zone, connection };
	}

	it("is raised for a zone, stays one finding, and resolves when yesterday is usual again", async () => {
		const { account, zone, connection } = await connectWith(
			"shop.example",
			[100, 100, 100, 100, 100, 100, 100],
			1000,
		);

		const [found] = await spikeOf(world, connection.id);
		expect(await spikeOf(world, connection.id)).toHaveLength(1);
		expect(found?.fingerprint).toBe(`traffic:${account}:waf_spike:${zone.id}`);
		expect(found?.severity).toBe("low");
		expect(found?.subject).toBe("shop.example");
		expect(found?.title).toContain("shop.example");
		expect(found?.title).toContain("10 times");
		expect(found?.title).toContain("1,000 yesterday");
		expect(found?.title).toContain("median of 100");
		expect(found?.url).toBe(`https://dash.cloudflare.com/${account}/shop.example/security/events`);
		expect(found?.resolved_at).toBeNull();
		const listed = await world.findings();
		expect(listed.body.findings.map((one) => one.kind)).toContain("waf_spike");

		// The next scan, a day on, with another spiking day: the same finding, not a second.
		await rollForward(world, connection.id);
		blocked(zone, 1, 2000);
		await world.scanDue([connection.id]);
		const second = await spikeOf(world, connection.id);
		expect(second).toHaveLength(1);
		expect(second[0]?.id).toBe(found?.id);
		expect(second[0]?.title).toContain("2,000 yesterday");
		// Judged against the days stored a scan ago, not only against what this scan read.
		expect(second[0]?.title).toContain("20 times");
		expect(second[0]?.title).toContain("median of 100");

		// And a day on again, back to usual: the median of the week before holds, so it closes.
		await rollForward(world, connection.id);
		blocked(zone, 1, 110);
		await world.scanDue([connection.id]);
		const resolved = await spikeOf(world, connection.id);
		expect(resolved).toHaveLength(1);
		expect(resolved[0]?.resolved_at).not.toBeNull();
		expect((await world.findings()).body.findings.map((one) => one.kind)).not.toContain(
			"waf_spike",
		);
	});

	it("needs 3 stored days before it, 500 mitigated requests, and more than 5 times the median", async () => {
		const cases = [
			// Under the floor, however large the factor.
			{ name: "floor-499.example", before: [10, 10, 10, 10], yesterday: 499, spike: false },
			{ name: "floor-500.example", before: [10, 10, 10, 10], yesterday: 500, spike: true },
			// Exactly five times is not more than five times.
			{ name: "factor-5.example", before: [200, 200, 200, 200], yesterday: 1000, spike: false },
			{ name: "factor-5-plus.example", before: [200, 200, 200, 200], yesterday: 1001, spike: true },
		];
		for (const one of cases) {
			const { connection } = await connectWith(one.name, one.before, one.yesterday);
			expect((await spikeOf(world, connection.id)).length > 0, one.name).toBe(one.spike);
		}
	});

	it("counts a quiet day as 0, so a normally quiet zone that suddenly blocks 600 is a spike", async () => {
		const account = nextAccount();
		const token = cloudflareToken(12);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "quiet.example");
		// Nothing acted on in the week before: those days have no rows at all.
		blocked(zone, 1, 600);
		const { connection } = await world.connectCloudflare(account, token);

		const rows = await spikeOf(world, connection.id);
		expect(rows).toHaveLength(1);
		expect(rows[0]?.title).toContain("rose to 600 yesterday, against a median of 0");
		expect((await world.trafficRows(connection.id)).map((row) => row.day)).toEqual(
			Array(3).fill(day(1)),
		);
	});

	it("does not make up zeros for a gap: the run starts again at the scan's first day", async () => {
		const account = nextAccount();
		const token = cloudflareToken(13);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "paused.example");
		const { connection } = await world.connectCloudflare(account, token);

		// Guard was away for weeks (or its token failed): what it last read is long ago.
		await world.guard.db
			.prepare("UPDATE traffic_zone SET first_day = ?2, last_day = ?3 WHERE connection_id = ?1")
			.bind(connection.id, day(40), day(30))
			.run();
		blocked(zone, 1, 600);
		await world.scanDue([connection.id]);

		// It read 8 days from the oldest, and those count as read; the gap does not.
		const [row] = await world.trafficZones(connection.id);
		expect(row?.first_day).toBe(day(8));
		expect(row?.last_day).toBe(day(1));
		expect(await spikeOf(world, connection.id)).toHaveLength(1);

		// A scan that carries on keeps the run's start.
		await rollForward(world, connection.id);
		blocked(zone, 1, 0);
		await world.scanDue([connection.id]);
		expect((await world.trafficZones(connection.id))[0]?.first_day).toBe(day(9));
	});

	it("needs 3 known days before yesterday: a zone read for 2, both quiet, is not a spike", async () => {
		const account = nextAccount();
		const token = cloudflareToken(14);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "new-run.example");
		const { connection } = await world.connectCloudflare(account, token);

		// Its run is a single read day, day 3; this scan reads days 2 and 1: two before yesterday.
		await world.guard.db
			.prepare("UPDATE traffic_zone SET first_day = ?2, last_day = ?2 WHERE connection_id = ?1")
			.bind(connection.id, day(3))
			.run();
		blocked(zone, 1, 600);
		await world.scanDue([connection.id]);
		expect(await spikeOf(world, connection.id)).toEqual([]);

		// With one more read day it would be.
		await world.guard.db
			.prepare("UPDATE traffic_zone SET first_day = ?2, last_day = ?3 WHERE connection_id = ?1")
			.bind(connection.id, day(4), day(4))
			.run();
		await world.scanDue([connection.id]);
		expect(await spikeOf(world, connection.id)).toHaveLength(1);
	});

	it("counts only requests that were stopped or challenged", async () => {
		const stopped = ["block", "challenge", "jschallenge", "managedChallenge", "connectionClose"];
		for (const action of stopped) {
			const { connection } = await connectWith(`${action}.example`, [10, 10, 10, 10], 5000, action);
			expect((await spikeOf(world, connection.id)).length, action).toBe(1);
		}
		for (const action of ["log", "skip", "allow"]) {
			const { connection } = await connectWith(`${action}.example`, [10, 10, 10, 10], 5000, action);
			expect(await spikeOf(world, connection.id), action).toEqual([]);
		}
	});

	it("keeps a finding open for a zone it could not read, and judges the others", async () => {
		const account = nextAccount();
		const token = cloudflareToken(11);
		world.upstream.addAccount(account, token);
		const a = world.upstream.addZone(account, "a.example");
		const b = world.upstream.addZone(account, "b.example");
		for (const zone of [a, b]) week(zone, [100, 100, 100, 100, 100, 100, 100], 1000);
		const { connection } = await world.connectCloudflare(account, token);
		expect(await spikeOf(world, connection.id)).toHaveLength(2);

		// A's permission goes; a day on, both are usual.
		a.analytics = false;
		await rollForward(world, connection.id);
		blocked(a, 1, 100);
		blocked(b, 1, 100);
		await world.scanDue([connection.id]);

		const rows = await spikeOf(world, connection.id);
		expect(rows.find((row) => row.subject === "a.example")?.resolved_at).toBeNull();
		expect(rows.find((row) => row.subject === "b.example")?.resolved_at).not.toBeNull();
		const zones = await world.trafficZones(connection.id);
		expect(zones.find((row) => row.name === "a.example")?.last_failure).toBe("forbidden");
		expect(zones.find((row) => row.name === "b.example")?.last_failure).toBeNull();
		// One zone failing is not the connection failing.
		expect(await world.trafficOutcome(connection.id)).toBe("ok");
	});
});

describe("a token without Analytics Read", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("is refused when connecting, in words that name the permission", async () => {
		const account = nextAccount();
		const token = cloudflareToken(20);
		world.upstream.addAccount(account, token);
		world.upstream.addZone(account, "shut.example", { analytics: false });

		const result = await world.act(world.owner, {
			action: "connect-cloudflare",
			accountId: account,
			token,
		});

		expect(result.status).toBe(400);
		expect(result.body.error).toContain("Zone › Analytics › Read");
		expect(result.body.error).toContain("Account › Security Center Insights › Read");
		expect(result.body.error).toContain("Zone › Security Center Insights › Read");
		expect((await world.connections()).body.connections).toEqual([]);
		expect(await world.dump()).not.toContain(token);
	});

	it("connects an account with no zones, and with none that are active", async () => {
		const empty = nextAccount();
		world.upstream.addAccount(empty, cloudflareToken(21));
		const none = await world.connectCloudflare(empty, cloudflareToken(21));
		expect(await world.trafficZones(none.connection.id)).toEqual([]);
		expect(await world.trafficOutcome(none.connection.id)).toBe("ok");

		const pending = nextAccount();
		world.upstream.addAccount(pending, cloudflareToken(22));
		world.upstream.addZone(pending, "soon.example", { status: "pending", analytics: false });
		const asked = trafficQueries(world).length;
		await world.connectCloudflare(pending, cloudflareToken(22));
		expect(trafficQueries(world).length).toBe(asked);
	});

	it("loses its traffic but not its insights, shows why, and keeps the spike finding open", async () => {
		const account = nextAccount();
		const token = cloudflareToken(23);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "shop.example");
		week(zone, [100, 100, 100, 100, 100, 100, 100], 1000);
		const { connection } = await world.connectCloudflare(account, token);
		expect(await spikeOf(world, connection.id)).toHaveLength(1);

		// The permission is revoked, and the account's insights change meanwhile.
		zone.analytics = false;
		world.upstream.accounts.get(account)?.insights.push({
			id: "i1",
			issue_class: "dmarc_record_missing",
			subject: "shop.example",
		});
		await rollForward(world, connection.id);
		blocked(zone, 1, 100);
		await world.scanDue([connection.id]);

		// The Security Insights part went through.
		const row = await world.connectionRow(connection.id);
		expect(row?.last_scan_outcome).toBe("ok");
		const rows = await world.findingRows(connection.id);
		expect(rows.filter((one) => one.kind === "dmarc_record_missing")).toHaveLength(1);
		// The traffic part says what failed, on the connection and on the zone.
		expect(await world.trafficOutcome(connection.id)).toBe("forbidden");
		expect((await world.trafficZones(connection.id))[0]?.last_failure).toBe("forbidden");
		const listed = await world.connections();
		expect(listed.body.connections.find((one) => one.id === connection.id)?.trafficOutcome).toBe(
			"forbidden",
		);
		const page = (await world.trafficPage()).body;
		expect(page.connections.find((one) => one.id === connection.id)?.outcome).toBe("forbidden");
		// Nothing was judged, so the spike stays open however usual the data now looks.
		expect((await spikeOf(world, connection.id))[0]?.resolved_at).toBeNull();
		// The days it could not read are not marked read.
		expect((await world.trafficZones(connection.id))[0]?.last_day).toBe(day(2));

		// The permission comes back: the missed day is read, the failure clears, and it resolves.
		zone.analytics = true;
		await world.scanDue([connection.id]);
		expect(await world.trafficOutcome(connection.id)).toBe("ok");
		expect((await world.trafficZones(connection.id))[0]?.last_failure).toBeNull();
		expect((await spikeOf(world, connection.id))[0]?.resolved_at).not.toBeNull();
	});

	it("tries again within the hour when Cloudflare is limiting requests, and keeps what it has", async () => {
		const account = nextAccount();
		const token = cloudflareToken(24);
		world.upstream.addAccount(account, token);
		const zone = world.upstream.addZone(account, "limited.example");
		week(zone, [100, 100, 100, 100, 100, 100, 100], 1000);
		const { connection } = await world.connectCloudflare(account, token);

		const fake = world.upstream.accounts.get(account);
		if (!fake) throw new Error("the account is known");
		fake.budget = true;
		await rollForward(world, connection.id);
		await world.scanDue([connection.id]);
		fake.budget = false;

		expect(await world.trafficOutcome(connection.id)).toBe("rate_limited");
		const row = await world.connectionRow(connection.id);
		expect(row?.last_scan_outcome).toBe("ok");
		expect(row?.next_scan_at).toBeLessThan(Date.now() + 2 * 3600_000);
		expect((await spikeOf(world, connection.id))[0]?.resolved_at).toBeNull();
		// Nothing of the answer's message, which may name a token, is kept.
		expect(await world.dump()).not.toContain("exceeded its rate limit");
	});
});

describe("what a person sees and who may see it", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("shows the weeks side by side, the top lists over the last seven days, and why a zone is empty", async () => {
		const account = nextAccount();
		world.upstream.addAccount(account, cloudflareToken(30));
		const { connection } = await world.connectCloudflare(account, cloudflareToken(30));
		const org = world.workspaceId;
		const db = world.guard.db;
		const zoneRow = (
			id: string,
			name: string,
			firstDay: string | null,
			lastDay: string | null,
			failure: string | null,
		) =>
			db
				.prepare(
					"INSERT INTO traffic_zone (connection_id, organization_id, zone_id, name, plan, first_day, last_day, last_failure, seen_at) VALUES (?1, ?2, ?3, ?4, 'Free Website', ?5, ?6, ?7, ?8)",
				)
				.bind(connection.id, org, id, name, firstDay, lastDay, failure, Date.now())
				.run();
		const count = (
			zone: string,
			back: number,
			dimension: string,
			key: string,
			action: string,
			source: string,
			n: number,
			extra: { description?: string; partial?: number } = {},
		) =>
			db
				.prepare(
					"INSERT INTO traffic_count (connection_id, organization_id, zone_id, day, dimension, key, action, source, description, partial, count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
				)
				.bind(
					connection.id,
					org,
					zone,
					day(back),
					dimension,
					key,
					action,
					source,
					extra.description ?? null,
					extra.partial ?? 0,
					n,
				)
				.run();

		await zoneRow("z1", "busy.example", day(14), day(1), null);
		await zoneRow("z2", "new.example", day(3), day(1), null);
		await zoneRow("z3", "unread.example", null, null, null);
		await zoneRow("z4", "quiet.example", day(5), day(1), null);
		await zoneRow("z5", "refused.example", null, null, "forbidden");
		for (let back = 1; back <= 14; back++) {
			await count("z1", back, "action", "block", "block", "firewallCustom", back <= 7 ? 100 : 50);
			// Not a mitigated action: it never counts.
			await count("z1", back, "action", "log", "log", "firewallManaged", 9999);
		}
		for (let back = 1; back <= 7; back++) {
			await count("z1", back, "country", "US", "block", "", 10);
			await count("z1", back, "country", "DE", "block", "", 5);
			await count("z1", back, "host", "www.busy.example", "block", "", 8);
		}
		// Outside the last seven days.
		await count("z1", 9, "country", "FR", "block", "", 999);
		await count("z1", 1, "rule", "r".repeat(32), "block", "firewallCustom", 40, {
			description: "Block scanners",
		});
		await count("z1", 1, "rule", "s".repeat(32), "managedChallenge", "firewallManaged", 12, {
			description: "Managed rules",
			partial: 1,
		});
		// Yesterday's rules only.
		await count("z1", 3, "rule", "t".repeat(32), "block", "firewallCustom", 999, {
			description: "Older",
		});
		// A zone with this week and nothing before it.
		for (let back = 1; back <= 3; back++) {
			await count("z2", back, "action", "block", "block", "firewallCustom", 10);
		}

		const { status, body } = await world.trafficPage();

		expect(status).toBe(200);
		expect(body.hasConnections).toBe(true);
		expect(body.yesterday).toBe(day(1));
		const zones = new Map(
			body.connections.flatMap((one) => one.zones).map((one) => [one.name, one]),
		);
		const busy = zones.get("busy.example");
		expect(busy?.status).toBe("ok");
		expect(busy?.series).toHaveLength(14);
		expect(busy?.series[13]).toEqual({ day: day(1), state: "read", mitigated: 100 });
		expect(busy?.week).toEqual({
			thisSum: 700,
			thisRead: 7,
			lastSum: 350,
			lastRead: 7,
			change: 100,
		});
		expect(busy?.countries).toEqual([
			{ name: "US", count: 70 },
			{ name: "DE", count: 35 },
		]);
		expect(busy?.hosts).toEqual([{ name: "www.busy.example", count: 56 }]);
		expect(busy?.rules.map((rule) => [rule.description, rule.count, rule.partial])).toEqual([
			["Block scanners", 40, false],
			["Managed rules", 12, true],
		]);
		// Three days read, the other eleven not: not zeros, and no percentage.
		const fresh = zones.get("new.example");
		expect(fresh?.week).toEqual({
			thisSum: 30,
			thisRead: 3,
			lastSum: 0,
			lastRead: 0,
			change: null,
		});
		expect(fresh?.series.filter((one) => one.state === "unread")).toHaveLength(11);
		expect(zones.get("unread.example")?.status).toBe("not_scanned");
		expect(zones.get("quiet.example")?.status).toBe("no_events");
		expect(zones.get("refused.example")?.status).toBe("failed");
		expect(zones.get("refused.example")?.failure).toBe("forbidden");
		// The busiest zone is first.
		expect(body.connections[0]?.zones[0]?.name).toBe("busy.example");

		const page = await world.page(`/${world.slug}/traffic`);
		expect(page.status).toBe(200);
		expect(page.text).toContain("busy.example");
		expect(page.text).toContain("Block scanners");
		expect(page.text).toContain("sampled");
		expect(page.text).toContain("partial");
		expect(page.text).toContain("No data for last week");
		expect(page.text).toContain("30 this week (3 of 7 days read)");
		expect(page.text).toContain("11 not read yet");
		expect(page.text).toContain("Zone › Analytics › Read");
	});

	it("is for members alone, and another workspace's members get nothing", async () => {
		const account = nextAccount();
		world.upstream.addAccount(account, cloudflareToken(31));
		const zone = world.upstream.addZone(account, "private.example");
		blocked(zone, 1, 50);
		await world.connectCloudflare(account, cloudflareToken(31));

		const member = await world.addMember("mia");
		const mine = await world.trafficPage(member);
		expect(mine.status).toBe(200);
		expect(JSON.stringify(mine.body)).toContain("private.example");

		const stranger = await world.stranger("sam");
		const missing = await world.traffic(world.owner, "no-such-workspace");
		const notMember = await world.traffic(stranger);
		expect(notMember.status).toBe(404);
		expect(missing.status).toBe(404);
		expect(notMember.text).toBe(missing.text);
		const signedOut = await world.guard.fetch(`${origin}/api/traffic/${world.slug}`);
		expect(signedOut.status).toBe(404);
		const strangerPage = await world.page(`/${world.slug}/traffic`, stranger);
		expect(strangerPage.text).not.toContain("private.example");

		// A member of another workspace sees that one's traffic, which is none of this one's.
		const slug = `${world.slug}-other`;
		await createWorkspace(world.guard, origin, stranger.headers, slug);
		const theirs = await world.trafficPage(stranger, slug);
		expect(theirs.status).toBe(200);
		expect(theirs.body.hasConnections).toBe(false);
		expect(JSON.stringify(theirs.body)).not.toContain("private.example");
		// And asking this workspace's slug is still the same answer as a missing one.
		expect((await world.traffic(stranger, world.slug)).text).toBe(missing.text);
	});
});

describe("what Guard never asks for or keeps", () => {
	let world: World;
	beforeAll(async () => {
		world = await startWorld();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("names no visitor field in any query, and has no column for one", async () => {
		const account = nextAccount();
		world.upstream.addAccount(account, cloudflareToken(40));
		const zone = world.upstream.addZone(account, "shop.example");
		week(zone, [100, 100, 100, 100], 1000);
		zone.events = [
			{
				ruleId: "e".repeat(32),
				description: "Block bad bots",
				source: "firewallCustom",
				action: "block",
				sampleInterval: 1,
				datetime: at(1),
			},
		];
		await world.connectCloudflare(account, cloudflareToken(40));

		const forbidden = [
			"clientIP",
			"userAgent",
			"clientRequestPath",
			"clientRequestQuery",
			"rayName",
			"clientRefererPath",
			"clientRefererQuery",
			"clientAsn",
			"clientASNDescription",
			"metadata_value",
		];
		expect(world.upstream.queries.length).toBeGreaterThan(3);
		for (const { query } of world.upstream.queries) {
			for (const field of forbidden) {
				expect(query.toLowerCase(), field).not.toContain(field.toLowerCase());
			}
		}
		// Free zones refuse these, so they are never asked for.
		for (const { query } of world.upstream.queries) {
			expect(query).not.toContain("firewallEventsAdaptiveGroups");
			expect(query).not.toContain("botScoreBucketBy10");
		}
		for (const table of ["traffic_count", "traffic_zone"]) {
			const columns = (
				(await world.guard.db.prepare(`PRAGMA table_info(${table})`).all()).results as {
					name: string;
				}[]
			).map((column) => column.name.toLowerCase());
			for (const word of ["ip", "agent", "path", "query", "ray", "asn", "referer", "user"]) {
				expect(
					columns.filter((name) => name.split("_").includes(word) || name.startsWith(word)),
					`${table}.${word}`,
				).toEqual([]);
			}
		}
	});
});
