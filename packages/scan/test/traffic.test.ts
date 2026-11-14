import { describe, expect, it } from "vitest";
import { UpstreamError } from "../src/errors";
import {
	addDays,
	isMitigated,
	listZones,
	MAX_ZONES_PER_QUERY,
	probeTraffic,
	readRules,
	readTraffic,
	utcDay,
} from "../src/traffic";
import { fakeFetch, json } from "./fake-fetch";

const ACCOUNT = "023e105f4ecef8ad9ca31a8372d0c353";
const TOKEN = "test-token-that-must-not-leak";
const ZONE_A = "a".repeat(32);
const ZONE_B = "b".repeat(32);
const RULE = "c".repeat(32);

const credentials = { accountId: ACCOUNT, token: TOKEN };

/** What a request to the GraphQL endpoint carries. */
async function sent(request: Request) {
	return (await request.json()) as { query: string; variables: Record<string, unknown> };
}

const group = (count: number, dimensions: Record<string, string>) => ({ count, dimensions });

/** The answer in the shape measured on 2026-11-14: accounts, then zones, with each node's groups. */
function trafficAnswer(zones: Record<string, unknown>[]) {
	return json({ data: { viewer: { accounts: [{ zones }] } }, errors: null });
}

function zoneNode(tag: string, fields: Record<string, unknown[]> = {}) {
	return { zoneTag: tag, byAction: [], byCountry: [], byHost: [], ...fields };
}

describe("listZones", () => {
	it("reads every page of the account's zones, with its token and nothing else", async () => {
		const zone = (n: number) => ({
			id: n.toString(16).padStart(32, "0"),
			name: `site-${n}.example`,
			status: n === 51 ? "pending" : "active",
			plan: n === 52 ? undefined : { name: "Free Website" },
		});
		const { fetch, requests } = fakeFetch((request) => {
			const page = Number(new URL(request.url).searchParams.get("page"));
			const result = Array.from({ length: page === 1 ? 50 : 2 }, (_, i) =>
				zone((page - 1) * 50 + i + 1),
			);
			return json({ success: true, result, result_info: { page, per_page: 50, total_pages: 2 } });
		});

		const zones = await listZones(credentials, { fetch });

		expect(zones).toHaveLength(52);
		expect(zones[50]).toEqual({
			id: (51).toString(16).padStart(32, "0"),
			name: "site-51.example",
			status: "pending",
			plan: "Free Website",
		});
		expect(zones[51]?.plan).toBeNull();
		expect(requests.map((request) => request.url)).toEqual([
			`https://api.cloudflare.com/client/v4/zones?account.id=${ACCOUNT}&per_page=50&page=1`,
			`https://api.cloudflare.com/client/v4/zones?account.id=${ACCOUNT}&per_page=50&page=2`,
		]);
		expect(requests.every((request) => request.method === "GET")).toBe(true);
		expect(requests[0]?.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
	});

	it("turns a refusal into a failure that names no body", async () => {
		const { fetch } = fakeFetch(() =>
			json({ success: false, errors: [{ message: TOKEN }] }, { status: 403 }),
		);
		const error = await listZones(credentials, { fetch }).catch((caught) => caught);
		expect(error).toBeInstanceOf(UpstreamError);
		expect(error.failure).toBe("forbidden");
		expect(String(error.message)).not.toContain(TOKEN);
	});
});

describe("readTraffic", () => {
	const range = { since: "2026-11-06", until: "2026-11-14" };

	it("asks for the zones inside the account, with the account-based budget header", async () => {
		const { fetch, requests } = fakeFetch(() =>
			trafficAnswer([zoneNode(ZONE_A), zoneNode(ZONE_B)]),
		);

		await readTraffic(credentials, [ZONE_A, ZONE_B], range, { fetch });

		const [request] = requests;
		expect(request?.url).toBe("https://api.cloudflare.com/client/v4/graphql");
		expect(request?.method).toBe("POST");
		expect(request?.headers.get("x-rate-limit-type")).toBe("account-based");
		expect(request?.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
		const body = await sent(request as Request);
		expect(body.variables).toEqual({
			account: ACCOUNT,
			zones: [ZONE_A, ZONE_B],
			since: "2026-11-06T00:00:00Z",
			until: "2026-11-14T00:00:00Z",
		});
		expect(body.query).toContain("accounts(filter: { accountTag: $account })");
		expect(body.query).toContain("zoneTag_in: $zones");
		expect(body.query).toContain('securityAction_neq: "unknown"');
		// Measured: Free zones refuse this field and the bot score.
		expect(body.query).not.toContain("firewallEventsAdaptiveGroups");
		expect(body.query).not.toContain("botScoreBucketBy10");
	});

	it("counts by action and source per day, and keeps the top ten countries and hosts", async () => {
		const countries = Array.from({ length: 12 }, (_, i) =>
			group(100 - i, {
				date: "2026-11-13",
				securityAction: "block",
				clientCountryName: `C${String(i).padStart(2, "0")}`,
			}),
		);
		const { fetch } = fakeFetch(() =>
			trafficAnswer([
				zoneNode(ZONE_A, {
					byAction: [
						group(700, {
							date: "2026-11-13",
							securityAction: "block",
							securitySource: "firewallCustom",
						}),
						group(40, {
							date: "2026-11-13",
							securityAction: "managedChallenge",
							securitySource: "bic",
						}),
						group(9, {
							date: "2026-11-13",
							securityAction: "log",
							securitySource: "firewallManaged",
						}),
						group(5, {
							date: "2026-11-12",
							securityAction: "block",
							securitySource: "firewallManaged",
						}),
					],
					byCountry: [
						...countries,
						// Only what stopped a request counts toward the top lists.
						group(5000, { date: "2026-11-13", securityAction: "log", clientCountryName: "XX" }),
						group(30, {
							date: "2026-11-13",
							securityAction: "managedChallenge",
							clientCountryName: "C00",
						}),
					],
					byHost: [
						group(60, {
							date: "2026-11-13",
							securityAction: "block",
							clientRequestHTTPHost: "www.example.com",
						}),
						group(3, { date: "2026-11-13", securityAction: "block", clientRequestHTTPHost: "" }),
					],
				}),
				zoneNode(ZONE_B),
			]),
		);

		const result = await readTraffic(credentials, [ZONE_A, ZONE_B], range, { fetch });

		const a = result.get(ZONE_A);
		expect(a?.ok).toBe(true);
		if (!a?.ok) return;
		expect(a.days.map((day) => day.day)).toEqual(["2026-11-12", "2026-11-13"]);
		expect(a.days[1]?.actions).toEqual([
			{ action: "block", source: "firewallCustom", count: 700 },
			{ action: "managedChallenge", source: "bic", count: 40 },
			{ action: "log", source: "firewallManaged", count: 9 },
		]);
		const names = new Set(a.days[1]?.countries.map((row) => row.name));
		expect(names.size).toBe(10);
		expect(names.has("XX")).toBe(false);
		expect(names.has("C10")).toBe(false);
		expect(names.has("C09")).toBe(true);
		expect(
			a.days[1]?.countries.filter((row) => row.name === "C00").map((row) => row.action),
		).toEqual(["block", "managedChallenge"]);
		expect(a.days[1]?.hosts).toEqual([{ name: "www.example.com", action: "block", count: 60 }]);
		// A zone with nothing acted on has no days.
		expect(result.get(ZONE_B)).toEqual({ ok: true, days: [] });
	});

	it("says which zones the token may not read, and still returns the others", async () => {
		const { fetch } = fakeFetch(() =>
			json({
				data: { viewer: { accounts: [{ zones: [zoneNode(ZONE_A)] }] } },
				errors: [{ message: `zones [${ZONE_B}] are not authorized` }],
			}),
		);
		const result = await readTraffic(credentials, [ZONE_A, ZONE_B], range, { fetch });
		expect(result.get(ZONE_A)).toEqual({ ok: true, days: [] });
		expect(result.get(ZONE_B)).toEqual({ ok: false, failure: "forbidden" });
	});

	it("treats a zone the answer leaves out as not found", async () => {
		const { fetch } = fakeFetch(() => trafficAnswer([zoneNode(ZONE_A)]));
		const result = await readTraffic(credentials, [ZONE_A, ZONE_B], range, { fetch });
		expect(result.get(ZONE_B)).toEqual({ ok: false, failure: "not_found" });
	});

	it("turns an error in a 200 into a failure of its kind, with no message kept", async () => {
		const cases: [unknown[], string][] = [
			[
				[
					{
						message: `Actor 'com.cloudflare.api.token.${TOKEN}' does not have permission 'com.cloudflare.api.account.zone.analytics.read'`,
					},
				],
				"forbidden",
			],
			[[{ message: `zone '${ZONE_A}' does not have access to the path` }], "forbidden"],
			[
				[
					{
						message: `Zone ${ZONE_A} has exceeded its rate limit (${TOKEN})`,
						extensions: { code: "budget" },
					},
				],
				"rate_limited",
			],
			[[{ message: "too many zones requested" }], "invalid_response"],
			[[{ message: "something new" }], "invalid_response"],
		];
		for (const [errors, failure] of cases) {
			const { fetch } = fakeFetch(() => json({ data: null, errors }));
			const error = await readTraffic(credentials, [ZONE_A], range, { fetch }).catch(
				(caught) => caught,
			);
			expect(error, JSON.stringify(errors)).toBeInstanceOf(UpstreamError);
			expect(error.failure).toBe(failure);
			expect(String(error.message)).not.toContain(TOKEN);
			expect(JSON.stringify(error.cause ?? null)).not.toContain(TOKEN);
		}
	});

	it("maps HTTP 429 to rate_limited and an answer with neither data nor errors to invalid_response", async () => {
		const limited = fakeFetch(() => new Response(null, { status: 429 }));
		await expect(
			readTraffic(credentials, [ZONE_A], range, { fetch: limited.fetch }),
		).rejects.toMatchObject({
			failure: "rate_limited",
		});
		const empty = fakeFetch(() => json({}));
		await expect(
			readTraffic(credentials, [ZONE_A], range, { fetch: empty.fetch }),
		).rejects.toMatchObject({
			failure: "invalid_response",
		});
		const odd = fakeFetch(() => json({ data: { viewer: { accounts: "no" } } }));
		await expect(
			readTraffic(credentials, [ZONE_A], range, { fetch: odd.fetch }),
		).rejects.toMatchObject({
			failure: "invalid_response",
		});
	});

	it("never names more than ten zones in a query", async () => {
		const { fetch, requests } = fakeFetch(() => trafficAnswer([]));
		const zones = Array.from({ length: MAX_ZONES_PER_QUERY + 1 }, (_, i) =>
			i.toString(16).padStart(32, "0"),
		);
		await expect(readTraffic(credentials, zones, range, { fetch })).rejects.toBeInstanceOf(
			RangeError,
		);
		expect(requests).toHaveLength(0);
	});
});

describe("probeTraffic", () => {
	it("passes when the zone answers and fails with the zone's refusal otherwise", async () => {
		const ok = fakeFetch(() => trafficAnswer([zoneNode(ZONE_A)]));
		await expect(probeTraffic(credentials, ZONE_A, { fetch: ok.fetch })).resolves.toBeUndefined();
		const refused = fakeFetch(() =>
			json({ data: null, errors: [{ message: `zones [${ZONE_A}] are not authorized` }] }),
		);
		// With the only zone refused there may be no data at all, which is a refusal too.
		await expect(probeTraffic(credentials, ZONE_A, { fetch: refused.fetch })).rejects.toMatchObject(
			{
				failure: "forbidden",
			},
		);
		const partial = fakeFetch(() =>
			json({
				data: { viewer: { accounts: [{ zones: [] }] } },
				errors: [{ message: `zones [${ZONE_A}] are not authorized` }],
			}),
		);
		await expect(probeTraffic(credentials, ZONE_A, { fetch: partial.fetch })).rejects.toMatchObject(
			{
				failure: "forbidden",
			},
		);
	});
});

describe("readRules", () => {
	const settings = (fields: Record<string, unknown>) =>
		json({
			data: {
				viewer: {
					zones: [
						{
							settings: {
								firewallEventsAdaptive: { enabled: true, maxPageSize: 10000, ...fields },
							},
						},
					],
				},
			},
		});
	const events = (rows: Record<string, unknown>[]) =>
		json({ data: { viewer: { zones: [{ firewallEventsAdaptive: rows }] } } });
	const event = (fields: Record<string, unknown> = {}) => ({
		ruleId: RULE,
		description: "Block bad bots",
		source: "firewallCustom",
		action: "block",
		sampleInterval: 1,
		datetime: "2026-11-13T10:00:00Z",
		...fields,
	});

	/** Answers the settings query, then pages of events from `pages`. */
	function stand(pages: Record<string, unknown>[][], maxPageSize = 10000) {
		let next = 0;
		return fakeFetch(async (request) => {
			const { query } = await sent(request);
			if (query.includes("settings {")) return settings({ maxPageSize });
			return events(pages[next++] ?? []);
		});
	}

	it("weights each sample by its sampleInterval and keeps the top ten rules", async () => {
		const rows = [
			event({ sampleInterval: 10 }),
			event({ sampleInterval: 5, datetime: "2026-11-13T09:00:00Z" }),
			// Same rule, another source and action: counted apart.
			event({ source: "firewallManaged", action: "managedChallenge", sampleInterval: 2 }),
			...Array.from({ length: 12 }, (_, i) =>
				event({ ruleId: String(i).padStart(32, "0"), description: null, sampleInterval: 1 }),
			),
		];
		const { fetch } = stand([rows]);

		const result = await readRules(credentials, ZONE_A, "2026-11-13", { fetch });

		expect(result.partial).toBe(false);
		expect(result.rules).toHaveLength(10);
		expect(result.rules[0]).toEqual({
			ruleId: RULE,
			description: "Block bad bots",
			source: "firewallCustom",
			action: "block",
			count: 15,
		});
		expect(result.rules[1]).toMatchObject({
			source: "firewallManaged",
			action: "managedChallenge",
			count: 2,
		});
	});

	it("reads a day's events in pages, newest first, without counting a second twice", async () => {
		const page1 = [
			event({ datetime: "2026-11-13T12:00:03Z" }),
			event({ datetime: "2026-11-13T12:00:02Z" }),
			// Shares its second with the next page's first rows: dropped here, read there.
			event({ datetime: "2026-11-13T12:00:01Z" }),
		];
		const page2 = [
			event({ datetime: "2026-11-13T12:00:01Z" }),
			event({ datetime: "2026-11-13T12:00:01Z" }),
		];
		const { fetch, requests } = stand([page1, page2], 3);

		const result = await readRules(credentials, ZONE_A, "2026-11-13", { fetch });

		expect(result.partial).toBe(false);
		expect(result.rules[0]?.count).toBe(4);
		const queries = await Promise.all(requests.map((request) => sent(request)));
		expect(queries.map((one) => one.variables.limit ?? null)).toEqual([null, 3, 3]);
		expect(queries[2]?.variables.until).toBe("2026-11-13T12:00:01Z");
		expect(queries[2]?.query).toContain("datetime_leq: $until");
		expect(queries[1]?.query).toContain("datetime_lt: $until");
	});

	it("stops after two pages and says the day is partial", async () => {
		const full = (second: number) =>
			Array.from({ length: 3 }, (_, i) =>
				event({ datetime: `2026-11-13T12:00:${String(second - i).padStart(2, "0")}Z` }),
			);
		const { fetch, requests } = stand([full(30), full(20), full(10)], 3);

		const result = await readRules(credentials, ZONE_A, "2026-11-13", { fetch });

		expect(result.partial).toBe(true);
		// The settings query and two pages.
		expect(requests).toHaveLength(3);
	});

	it("uses the page size the zone's settings allow, never more than 10,000", async () => {
		const { fetch, requests } = stand([[event()]], 500);
		await readRules(credentials, ZONE_A, "2026-11-13", { fetch });
		expect((await sent(requests[1] as Request)).variables.limit).toBe(500);
		const huge = stand([[event()]], 50_000);
		await readRules(credentials, ZONE_A, "2026-11-13", { fetch: huge.fetch });
		expect((await sent(huge.requests[1] as Request)).variables.limit).toBe(10_000);
	});

	it("fails as forbidden when the zone's events are off, and asks for no events", async () => {
		const { fetch, requests } = fakeFetch(() => settings({ enabled: false }));
		await expect(readRules(credentials, ZONE_A, "2026-11-13", { fetch })).rejects.toMatchObject({
			failure: "forbidden",
		});
		expect(requests).toHaveLength(1);
	});
});

describe("what Guard asks about a visitor", () => {
	it("never names a field that identifies one, in any query it sends", async () => {
		const queries: string[] = [];
		const { fetch } = fakeFetch(async (request) => {
			const body = await sent(request);
			queries.push(body.query);
			if (body.query.includes("settings {")) {
				return json({
					data: {
						viewer: {
							zones: [
								{ settings: { firewallEventsAdaptive: { enabled: true, maxPageSize: 10000 } } },
							],
						},
					},
				});
			}
			if (body.query.includes("firewallEventsAdaptive(")) {
				return json({ data: { viewer: { zones: [{ firewallEventsAdaptive: [] }] } } });
			}
			return trafficAnswer([zoneNode(ZONE_A)]);
		});
		await readTraffic(
			credentials,
			[ZONE_A],
			{ since: "2026-11-06", until: "2026-11-14" },
			{ fetch },
		);
		await probeTraffic(credentials, ZONE_A, { fetch });
		await readRules(credentials, ZONE_A, "2026-11-13", { fetch });
		await listZones(credentials, {
			fetch: fakeFetch(() => json({ success: true, result: [] })).fetch,
		});

		expect(queries.length).toBeGreaterThanOrEqual(4);
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
		for (const query of queries) {
			for (const field of forbidden) {
				expect(query.toLowerCase(), `${field} in ${query}`).not.toContain(field.toLowerCase());
			}
		}
		// And the events query asks for exactly the six fields.
		const events = queries.find((query) => query.includes("firewallEventsAdaptive("));
		expect(events).toContain("{ ruleId description source action sampleInterval datetime }");
	});
});

describe("days and actions", () => {
	it("counts UTC days", () => {
		expect(utcDay(Date.parse("2026-11-14T23:59:59Z"))).toBe("2026-11-14");
		expect(utcDay(Date.parse("2026-11-15T00:00:00Z"))).toBe("2026-11-15");
		expect(addDays("2026-11-01", -1)).toBe("2026-10-31");
		expect(addDays("2026-12-31", 1)).toBe("2027-01-01");
	});

	it("calls an action mitigated only when it stopped or tested the request", () => {
		for (const action of [
			"block",
			"challenge",
			"jschallenge",
			"managedChallenge",
			"connectionClose",
		]) {
			expect(isMitigated(action)).toBe(true);
		}
		for (const action of ["log", "skip", "allow", "unknown", "challengeSolved", "somethingNew"]) {
			expect(isMitigated(action)).toBe(false);
		}
	});
});
