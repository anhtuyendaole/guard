import { describe, expect, it } from "vitest";
import { readProtection } from "../src/protection";
import { fakeFetch, json } from "./fake-fetch";

const ACCOUNT = "023e105f4ecef8ad9ca31a8372d0c353";
const TOKEN = "test-token-that-must-not-leak";
const ZONE = "a".repeat(32);
const SECRET = 'http.request.headers["x-internal-key"][0] eq "s3cr3t-value"';

const credentials = { accountId: ACCOUNT, token: TOKEN };

const ok = (result: unknown) => json({ success: true, result });
const missing = () => json({ success: false, errors: [{ code: 10003 }] }, { status: 404 });
const refused = () => json({ success: false, errors: [{ code: 9109 }] }, { status: 403 });

interface Answers {
	custom?: () => Response;
	managed?: () => Response;
	rateLimit?: () => Response;
	rulesets?: () => Response;
	bot?: () => Response;
	level?: () => Response;
}

/** The stand-in: what the five paths answer, 404 for an entrypoint left unsaid. */
function cloudflare(answers: Answers) {
	return fakeFetch((request) => {
		const path = new URL(request.url).pathname.replace("/client/v4/zones/", "");
		const by: Record<string, (() => Response) | undefined> = {
			[`${ZONE}/rulesets/phases/http_request_firewall_custom/entrypoint`]: answers.custom,
			[`${ZONE}/rulesets/phases/http_request_firewall_managed/entrypoint`]: answers.managed,
			[`${ZONE}/rulesets/phases/http_ratelimit/entrypoint`]: answers.rateLimit,
			[`${ZONE}/rulesets`]: answers.rulesets,
			[`${ZONE}/bot_management`]: answers.bot,
			[`${ZONE}/settings/security_level`]: answers.level,
		};
		const answer = by[path];
		return answer ? answer() : missing();
	});
}

describe("readProtection", () => {
	it("reads a zone's custom rules, never their expressions, with its token only", async () => {
		const { fetch, requests } = cloudflare({
			custom: () =>
				ok({
					id: "set",
					rules: [
						{
							id: "r1",
							ref: "r1",
							version: "3",
							action: "block",
							description: "d".repeat(300),
							enabled: true,
							expression: SECRET,
							last_updated: "2026-11-01T10:00:00.000000Z",
						},
						{
							id: "r2",
							action: "skip",
							enabled: false,
							expression: SECRET,
							action_parameters: { ruleset: "current", phases: ["http_ratelimit"] },
						},
					],
				}),
			bot: () => ok({ fight_mode: false, enable_js: true }),
			level: () => ok({ id: "security_level", value: "essentially_off" }),
		});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(protection.custom).toEqual({
			state: "ok",
			value: {
				rules: [
					{
						id: "r1",
						action: "block",
						description: "d".repeat(200),
						enabled: true,
						lastUpdated: "2026-11-01T10:00:00.000000Z",
					},
					{ id: "r2", action: "skip", description: "", enabled: false, lastUpdated: null },
				],
			},
		});
		// Not in the result in any form, so it can reach neither a table nor a page.
		expect(JSON.stringify(protection)).not.toContain("s3cr3t");
		expect(JSON.stringify(protection)).not.toContain("expression");
		expect(protection.bot).toEqual({ state: "ok", value: { fightMode: false } });
		expect(protection.securityLevel).toEqual({ state: "ok", value: { level: "essentially_off" } });
		expect(protection.rateLimit).toEqual({ state: "none" });
		expect(protection.managed).toEqual({ state: "none" });
		// Five requests: three entrypoints, bot management and the security level.
		expect(requests).toHaveLength(5);
		for (const request of requests) {
			expect(request.method).toBe("GET");
			expect(request.headers.get("authorization")).toBe(`Bearer ${TOKEN}`);
		}
	});

	it("says none for a zone with nothing in a phase, and for a phase with no rules", async () => {
		const { fetch } = cloudflare({
			custom: () => ok({ id: "set", rules: [] }),
			rateLimit: () => ok({ id: "set" }),
			bot: () => ok({ fight_mode: true }),
			level: () => ok({ value: "medium" }),
		});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(protection.custom).toEqual({ state: "none" });
		expect(protection.managed).toEqual({ state: "none" });
		expect(protection.rateLimit).toEqual({ state: "none" });
	});

	it("counts rate limiting rules, and names the managed rulesets that are deployed", async () => {
		const { fetch, requests } = cloudflare({
			rateLimit: () =>
				ok({ rules: [{ id: "a", enabled: true }, { id: "b", enabled: false }, { id: "c" }] }),
			managed: () =>
				ok({
					rules: [
						{ id: "m1", action: "execute", enabled: true, action_parameters: { id: "set-1" } },
						{ id: "m2", action: "execute", enabled: false, action_parameters: { id: "set-2" } },
						// A skip rule does not deploy a ruleset.
						{ id: "m3", action: "skip", enabled: true, action_parameters: { id: "set-3" } },
					],
				}),
			rulesets: () =>
				ok([
					{ id: "set-1", name: "Cloudflare Managed Ruleset", kind: "managed" },
					{ id: "other", name: "Not deployed" },
				]),
		});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(protection.rateLimit).toEqual({ state: "ok", value: { total: 3, enabled: 2 } });
		expect(protection.managed).toEqual({
			state: "ok",
			value: {
				rulesets: [
					{ id: "set-1", name: "Cloudflare Managed Ruleset", enabled: true },
					{ id: "set-2", name: null, enabled: false },
				],
			},
		});
		// The rulesets list is asked only when something is deployed.
		expect(
			requests.filter((one) => new URL(one.url).pathname.endsWith(`${ZONE}/rulesets`)),
		).toHaveLength(1);
	});

	it("keeps the managed rulesets when their names cannot be read", async () => {
		const { fetch } = cloudflare({
			managed: () =>
				ok({
					rules: [
						{ id: "m1", action: "execute", enabled: true, action_parameters: { id: "set-1" } },
					],
				}),
			rulesets: refused,
		});

		const { managed } = await readProtection(credentials, ZONE, { fetch });

		expect(managed).toEqual({
			state: "ok",
			value: { rulesets: [{ id: "set-1", name: null, enabled: true }] },
		});
	});

	it("keeps each part apart: a refusal of one does not spoil the others", async () => {
		const { fetch } = cloudflare({
			custom: () => ok({ rules: [{ id: "r1", action: "block", enabled: true }] }),
			bot: refused,
			level: () => new Response(null, { status: 500 }),
			rateLimit: refused,
			managed: () => new Response("not json", { status: 200 }),
		});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(protection.custom.state).toBe("ok");
		expect(protection.bot).toEqual({ state: "failed", failure: "forbidden" });
		expect(protection.securityLevel).toEqual({ state: "failed", failure: "unavailable" });
		expect(protection.rateLimit).toEqual({ state: "failed", failure: "forbidden" });
		expect(protection.managed).toEqual({ state: "failed", failure: "invalid_response" });
	});

	it("treats a 404 as nothing only for the entrypoints", async () => {
		const { fetch } = cloudflare({});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(protection.custom).toEqual({ state: "none" });
		expect(protection.bot).toEqual({ state: "failed", failure: "not_found" });
		expect(protection.securityLevel).toEqual({ state: "failed", failure: "not_found" });
	});

	it("does not say whether Bot Fight Mode is on when Cloudflare does not", async () => {
		const { fetch } = cloudflare({ bot: () => ok({ sbfm_definitely_automated: "block" }) });

		expect((await readProtection(credentials, ZONE, { fetch })).bot).toEqual({
			state: "ok",
			value: { fightMode: null },
		});
	});

	it("never carries a message or the token into a failure", async () => {
		const { fetch } = cloudflare({
			bot: () => json({ success: false, errors: [{ message: TOKEN }] }, { status: 403 }),
		});

		const protection = await readProtection(credentials, ZONE, { fetch });

		expect(JSON.stringify(protection)).not.toContain(TOKEN);
	});

	it("refuses an account or zone id that is not one, before any request", async () => {
		const { fetch, requests } = cloudflare({});
		await expect(
			readProtection({ accountId: "nope", token: TOKEN }, ZONE, { fetch }),
		).rejects.toThrow();
		await expect(readProtection(credentials, "../../x", { fetch })).rejects.toThrow(RangeError);
		expect(requests).toHaveLength(0);
	});
});
