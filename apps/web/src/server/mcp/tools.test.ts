import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { beforeEach, describe, expect, it } from "vitest";
import type { FindingView, TrafficPage } from "../../lib/connection-schemas";
import type { MemberRole } from "../../lib/roles";
import type { FindingDetail, FindingsWindow } from "../connections/findings-gateway";
import { createGuardServer, type GuardAccess, offsetOf, type WorkspaceAccess } from "./tools";

const connection = {
	id: "conn-cf",
	name: "Main account",
	kind: "cloudflare",
	target: "a".repeat(32),
};
const repository = { id: "conn-gh", name: "shop", kind: "github", target: "acme/shop" };

function finding(n: number, patch: Partial<FindingDetail> = {}): FindingDetail {
	return {
		id: `finding-${n}`,
		source: "cloudflare",
		severity: "high",
		kind: "dmarc",
		subject: "example.com",
		title: "DMARC is missing or misconfigured",
		url: "https://dash.cloudflare.com/x",
		fixedVersion: null,
		firstSeenAt: Date.UTC(2026, 10, 1),
		lastSeenAt: Date.UTC(2026, 10, 13),
		raisedAt: Date.UTC(2026, 10, 1),
		status: "open",
		dismissReason: null,
		connectionId: connection.id,
		connectionName: connection.name,
		connectionKind: "cloudflare",
		connectionTarget: connection.target,
		track: null,
		dismissedAt: null,
		dismissedBy: null,
		...patch,
	};
}

const dependency = finding(100, {
	source: "dependency",
	severity: "critical",
	kind: "GHSA-aaaa-bbbb-cccc",
	subject: "@scope/pkg@1.2.3, 1.2.4 in apps/web/pnpm-lock.yaml",
	title: "Prototype pollution",
	url: "https://osv.dev/GHSA-aaaa-bbbb-cccc",
	fixedVersion: "1.2.5",
	connectionId: repository.id,
	connectionName: repository.name,
	connectionKind: "github",
	connectionTarget: repository.target,
	track: {
		state: "filed",
		key: "SEC-4",
		url: "https://track.example.com/x/issue/SEC-4",
		fixRequested: false,
	},
});

const trafficPage: TrafficPage = {
	hasConnections: true,
	yesterday: "2026-11-13",
	connections: [
		{
			id: connection.id,
			name: connection.name,
			outcome: "ok",
			zones: ["example.com", "example.org"].map((name, i) => ({
				zoneId: `zone-${i}`,
				name,
				plan: "Free",
				status: "ok" as const,
				failure: null,
				series: [{ day: "2026-11-13", state: "read" as const, mitigated: 7 }],
				rules: [
					{
						ruleId: "r1",
						description: "Block bots",
						source: "waf",
						action: "block",
						count: 5,
						partial: false,
					},
				],
				countries: [{ name: "DE", count: 3 }],
				hosts: [{ name, count: 9 }],
				week: { thisSum: 7, thisRead: 7, lastSum: 5, lastRead: 7, change: 40 },
			})),
		},
	],
};

class FakeWorkspace implements WorkspaceAccess {
	readonly slug = "acme";
	askedFor: { filters: unknown; window: FindingsWindow } | undefined;
	dismissed: { id: string; reason: string }[] = [];
	scanned: string[] = [];
	items = [1, 2, 3, 4, 5].map((n) => finding(n));
	constructor(readonly role: MemberRole) {}

	async findings(filters: object, window: FindingsWindow) {
		this.askedFor = { filters, window };
		const from = window.offset ?? 0;
		return {
			total: this.items.length,
			findings: this.items.slice(from, from + (window.limit ?? 500)) as FindingView[],
		};
	}
	async finding(id: string) {
		return [...this.items, dependency].find((one) => one.id === id) ?? null;
	}
	async connections() {
		return [connection, repository] as {
			id: string;
			name: string;
			kind: "cloudflare" | "github";
			target: string;
		}[];
	}
	async dismiss(id: string, reason: string) {
		if (this.role === "member") {
			return {
				ok: false as const,
				status: 403,
				error: "Only an owner or admin can dismiss findings.",
			};
		}
		this.dismissed.push({ id, reason });
		return { ok: true as const };
	}
	async scan(connectionId: string) {
		if (this.role === "member") {
			return {
				ok: false as const,
				status: 403,
				error: "Only an owner or admin can change connections.",
			};
		}
		if (this.scanned.includes(connectionId)) {
			return { ok: false as const, status: 429, error: "This was scanned a moment ago." };
		}
		this.scanned.push(connectionId);
		return { ok: true as const, scan: { outcome: "ok", found: 4, added: 1, resolved: 2 } };
	}
	async traffic() {
		return {
			page: trafficPage,
			actions: [
				{ connectionId: connection.id, zoneId: "zone-0", action: "block", count: 12 },
				{ connectionId: connection.id, zoneId: "zone-1", action: "challenge", count: 2 },
			],
		};
	}
}

let workspace: FakeWorkspace;
let client: Client;

async function connect(role: MemberRole) {
	workspace = new FakeWorkspace(role);
	const access: GuardAccess = {
		workspaces: async () => [{ slug: "acme", name: "Acme", role }],
		workspace: async (slug) => (slug === workspace.slug ? workspace : null),
	};
	const handler = createMcpHandler(() => createGuardServer(access));
	client = new Client({ name: "test", version: "1.0.0" });
	await client.connect(
		new StreamableHTTPClientTransport(new URL("https://guard.example.com/mcp"), {
			fetch: (url, init) => handler.fetch(new Request(url, init)),
		}),
	);
}

beforeEach(() => connect("owner"));

const call = (name: string, args: Record<string, unknown> = {}) =>
	client.callTool({ name, arguments: args });

describe("Guard MCP tools", () => {
	it("lists the six tools, none of which can change a connection", async () => {
		const { tools } = await client.listTools();
		expect(tools.map((tool) => tool.name).sort()).toEqual([
			"dismiss_finding",
			"get_finding",
			"list_findings",
			"list_workspaces",
			"start_scan",
			"traffic_summary",
		]);
	});

	it("lists workspaces with the person's role", async () => {
		expect((await call("list_workspaces")).structuredContent).toEqual({
			workspaces: [{ slug: "acme", name: "Acme", role: "owner" }],
		});
	});

	describe("list_findings", () => {
		it("passes the page's filters and the extra ones on, and says what each finding is", async () => {
			const result = await call("list_findings", {
				workspace: "acme",
				severity: "high",
				source: "cloudflare",
				status: "dismissed",
				kind: "dmarc",
				connection: "main ACCOUNT",
				new_only: true,
				limit: 2,
			});
			expect(workspace.askedFor).toEqual({
				filters: { severity: "high", source: "cloudflare", status: "dismissed" },
				window: { limit: 2, offset: 0, connectionId: "conn-cf", kind: "dmarc", newOnly: true },
			});
			expect(result.structuredContent).toMatchObject({
				total: 5,
				nextCursor: "o2",
				findings: [
					{
						id: "finding-1",
						title: "DMARC is missing or misconfigured",
						subject: "example.com",
						severity: "high",
						source: "cloudflare",
						connection: { id: "conn-cf", name: "Main account" },
						status: "open",
						firstSeenAt: "2026-11-01T00:00:00.000Z",
						lastSeenAt: "2026-11-13T00:00:00.000Z",
						url: "https://dash.cloudflare.com/x",
						track: null,
					},
					{ id: "finding-2" },
				],
			});
		});

		it("pages with the cursor until the list ends, and defaults to 50", async () => {
			const first = (await call("list_findings", { workspace: "acme", limit: 2 }))
				.structuredContent as { nextCursor: string };
			const second = (
				await call("list_findings", { workspace: "acme", limit: 2, cursor: first.nextCursor })
			).structuredContent as { nextCursor: string; findings: { id: string }[] };
			expect(second.findings.map((one) => one.id)).toEqual(["finding-3", "finding-4"]);
			const last = (
				await call("list_findings", { workspace: "acme", limit: 2, cursor: second.nextCursor })
			).structuredContent as { nextCursor: string | null; findings: unknown[] };
			expect(last.findings).toHaveLength(1);
			expect(last.nextCursor).toBeNull();

			await call("list_findings", { workspace: "acme" });
			expect(workspace.askedFor?.window.limit).toBe(50);
		});

		it("refuses a limit over 200, a cursor it did not make and a connection it does not know", async () => {
			expect((await call("list_findings", { workspace: "acme", limit: 201 })).isError).toBe(true);
			const cursor = await call("list_findings", { workspace: "acme", cursor: "o-1; DROP TABLE" });
			expect(cursor.isError).toBe(true);
			expect(cursor.structuredContent).toMatchObject({ error: { code: "invalid" } });
			const unknown = await call("list_findings", { workspace: "acme", connection: "nope" });
			expect(unknown.structuredContent).toMatchObject({ error: { code: "not_found" } });
			expect(unknown.structuredContent).toMatchObject({
				error: { message: expect.stringContaining('"Main account", "shop"') },
			});
		});
	});

	describe("get_finding", () => {
		it("gives a dependency's package, versions, fix, lockfile, repository, advisory and Track issue", async () => {
			const result = await call("get_finding", { workspace: "acme", id: "finding-100" });
			expect(result.structuredContent).toMatchObject({
				finding: {
					id: "finding-100",
					severity: "critical",
					connection: { name: "shop", kind: "github", target: "acme/shop" },
					dependency: {
						package: "@scope/pkg",
						installed: ["1.2.3", "1.2.4"],
						fixedVersion: "1.2.5",
						lockfile: "apps/web/pnpm-lock.yaml",
						repository: "acme/shop",
						advisories: [{ id: "GHSA-aaaa-bbbb-cccc", url: "https://osv.dev/GHSA-aaaa-bbbb-cccc" }],
					},
					track: { key: "SEC-4" },
					dismissal: null,
				},
			});
		});

		it("says who dismissed a finding and why, and has no dependency for a Cloudflare one", async () => {
			workspace.items[0] = finding(1, {
				status: "dismissed",
				dismissReason: "Handled in the proxy",
				dismissedAt: Date.UTC(2026, 10, 12),
				dismissedBy: "Maya",
			});
			const result = await call("get_finding", { workspace: "acme", id: "finding-1" });
			expect(result.structuredContent).toMatchObject({
				finding: {
					dependency: null,
					dismissal: { reason: "Handled in the proxy", at: "2026-11-12T00:00:00.000Z", by: "Maya" },
				},
			});
		});

		it("answers an unknown finding and an unknown workspace with not_found", async () => {
			const finding = await call("get_finding", { workspace: "acme", id: "nope" });
			expect(finding.structuredContent).toMatchObject({ error: { code: "not_found" } });
			const other = await call("get_finding", { workspace: "else", id: "finding-1" });
			expect(other.structuredContent).toMatchObject({
				error: { code: "not_found", message: 'Workspace "else" not found. See list_workspaces.' },
			});
		});
	});

	describe("dismiss_finding", () => {
		it("dismisses with the reason as an owner", async () => {
			const result = await call("dismiss_finding", {
				workspace: "acme",
				id: "finding-1",
				reason: "  Not reachable  ",
			});
			expect(result.structuredContent).toEqual({ id: "finding-1", status: "dismissed" });
			expect(workspace.dismissed).toEqual([{ id: "finding-1", reason: "Not reachable" }]);
		});

		it("holds the reason to the page's bounds", async () => {
			const bare = await call("dismiss_finding", {
				workspace: "acme",
				id: "finding-1",
				reason: "   ",
			});
			expect(bare.isError).toBe(true);
			const long = await call("dismiss_finding", {
				workspace: "acme",
				id: "finding-1",
				reason: "x".repeat(201),
			});
			expect(long.isError).toBe(true);
			expect(workspace.dismissed).toEqual([]);
		});

		it("says forbidden to a member", async () => {
			await connect("member");
			const result = await call("dismiss_finding", {
				workspace: "acme",
				id: "finding-1",
				reason: "ok",
			});
			expect(result.structuredContent).toMatchObject({ error: { code: "forbidden" } });
			expect(workspace.dismissed).toEqual([]);
		});
	});

	describe("start_scan", () => {
		it("scans the connection it finds by name, id or target, and reports the outcome", async () => {
			const result = await call("start_scan", { workspace: "acme", connection: "SHOP" });
			expect(result.structuredContent).toEqual({
				connection: { id: "conn-gh", name: "shop" },
				outcome: "ok",
				found: 4,
				added: 1,
				resolved: 2,
			});
			expect(
				(await call("start_scan", { workspace: "acme", connection: "conn-cf" })).isError,
			).toBeFalsy();
			expect(workspace.scanned).toEqual(["conn-gh", "conn-cf"]);
		});

		it("maps the limit to rate_limited, a member to forbidden and an unknown connection to not_found", async () => {
			await call("start_scan", { workspace: "acme", connection: "shop" });
			const again = await call("start_scan", { workspace: "acme", connection: "acme/shop" });
			expect(again.structuredContent).toMatchObject({ error: { code: "rate_limited" } });
			const unknown = await call("start_scan", { workspace: "acme", connection: "nope" });
			expect(unknown.structuredContent).toMatchObject({ error: { code: "not_found" } });
			await connect("member");
			const member = await call("start_scan", { workspace: "acme", connection: "shop" });
			expect(member.structuredContent).toMatchObject({ error: { code: "forbidden" } });
		});
	});

	describe("traffic_summary", () => {
		it("gives each zone's week, days, actions, rules, countries and hosts", async () => {
			const result = await call("traffic_summary", { workspace: "acme" });
			expect(result.structuredContent).toMatchObject({
				yesterday: "2026-11-13",
				connections: [{ id: "conn-cf", name: "Main account", outcome: "ok" }],
				zones: [
					{
						name: "example.com",
						week: { stoppedOrChallenged: 7, previousWeek: 5, changePercent: 40 },
						daily: [{ day: "2026-11-13", state: "read", stoppedOrChallenged: 7 }],
						actions: [{ action: "block", count: 12 }],
						rules: [{ ruleId: "r1", description: "Block bots", action: "block", count: 5 }],
						countries: [{ name: "DE", count: 3 }],
						hosts: [{ name: "example.com", count: 9 }],
					},
					{ name: "example.org", actions: [{ action: "challenge", count: 2 }] },
				],
			});
		});

		it("narrows to one zone by name or id", async () => {
			const byName = (await call("traffic_summary", { workspace: "acme", zone: "EXAMPLE.org" }))
				.structuredContent as { zones: { name: string }[] };
			expect(byName.zones.map((zone) => zone.name)).toEqual(["example.org"]);
			const byId = (await call("traffic_summary", { workspace: "acme", zone: "zone-0" }))
				.structuredContent as { zones: { name: string }[] };
			expect(byId.zones.map((zone) => zone.name)).toEqual(["example.com"]);
			const none = await call("traffic_summary", { workspace: "acme", zone: "nope" });
			expect(none.structuredContent).toMatchObject({ error: { code: "not_found" } });
		});
	});

	it("keeps outputs loose, so a field added later does not fail a client that connected before", async () => {
		const { tools } = await client.listTools();
		for (const tool of tools) {
			expect(tool.outputSchema, tool.name).toMatchObject({ type: "object" });
			expect(tool.outputSchema?.additionalProperties, tool.name).not.toBe(false);
		}
	});
});

describe("offsetOf", () => {
	it("reads only the cursors the list makes", () => {
		expect(offsetOf(undefined)).toBe(0);
		expect(offsetOf("o0")).toBe(0);
		expect(offsetOf("o150")).toBe(150);
		for (const bad of ["", "150", "o", "o-1", "o1.5", "o12345678", "x1"]) {
			expect(() => offsetOf(bad), bad).toThrow();
		}
	});
});
