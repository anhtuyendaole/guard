import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FindingsPage } from "../src/lib/connection-schemas";
import { isNewSince } from "../src/lib/new-findings";
import { cloudflareToken, origin, startWorld, type World } from "./connections-world";
import type { SentEmail } from "./guard-worker";
import { ACCOUNT_ID } from "./upstreams";

// Alerts, the weekly summary, the "New" badge and the switches, against the built Worker, with
// Cloudflare stood in and email landing in the test's outbox.

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

const insight = (id: string, issueClass: string, subject: string, severity: string) => ({
	id,
	issue_class: issueClass,
	subject,
	severity,
});

/** The token's last four characters, which pages show and email must not. */
const HINT = cloudflareToken(1).slice(-4);

type Person = Awaited<ReturnType<World["addMember"]>>;

const addressOf = (name: string) => `${name}@example.com`;

async function alertsTo(world: World, name: string): Promise<SentEmail[]> {
	return (await world.guard.emails()).filter(
		(email) => email.to === addressOf(name) && email.subject.includes("serious finding"),
	);
}

async function digestsTo(world: World, name: string): Promise<SentEmail[]> {
	return (await world.guard.emails()).filter(
		(email) => email.to === addressOf(name) && email.subject.includes("weekly Guard summary"),
	);
}

/** An owner (owner), an admin (ada) and a member (mia), with one critical finding already known. */
async function workspaceWithFinding() {
	const world = await startWorld();
	const ada = await world.addMember("ada", "admin");
	const mia = await world.addMember("mia");
	const account = world.upstream.addAccount(ACCOUNT_ID, cloudflareToken(1), [
		insight("i1", "hsts_not_enabled", "example.com", "Critical"),
	]);
	const { connection } = await world.connectCloudflare(ACCOUNT_ID, cloudflareToken(1), "Main");
	return { world, ada, mia, account, connection };
}

/** What a person is told about their own notification settings. */
async function settings(world: World, person: Person, slug = world.slug) {
	const response = await world.guard.fetch(`${origin}/api/notifications/${slug}`, {
		headers: person.headers,
	});
	return {
		status: response.status,
		body: (await response.json()) as { ok: boolean; alertEmail: boolean; digestEmail: boolean },
	};
}

function change(world: World, person: Person, body: object, slug = world.slug) {
	return world.guard.fetch(`${origin}/api/notifications/${slug}`, {
		method: "POST",
		headers: person.headers,
		body: JSON.stringify(body),
	});
}

async function newCount(world: World, person: Person) {
	const response = await world.guard.fetch(`${origin}/api/findings/${world.slug}/new`, {
		headers: person.headers,
	});
	return { status: response.status, count: ((await response.json()) as { count?: number }).count };
}

describe("the New badge", () => {
	let world: World;
	let mia: Person;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, mia, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("counts what was raised since the member last opened Findings, and clears when they do", async () => {
		// The owner joined before the scan found anything, so it is all new to them.
		expect(await newCount(world, world.owner)).toEqual({ status: 200, count: 1 });
		const page = (await world.findings()).body;
		expect(page.findings.map((finding) => isNewSince(finding, page.seenAt))).toEqual([true]);

		const seen = await world.guard.fetch(`${origin}/api/findings/${world.slug}`, {
			method: "POST",
			headers: world.owner.headers,
			body: JSON.stringify({ action: "seen", at: page.loadedAt }),
		});
		expect(seen.status).toBe(200);
		expect(await newCount(world, world.owner)).toEqual({ status: 200, count: 0 });
		const after = (await world.findings()).body as FindingsPage;
		expect(after.findings.map((finding) => isNewSince(finding, after.seenAt))).toEqual([false]);

		// A finding a later scan raises is new again, and only to those who have not seen it.
		account.insights.push(insight("i2", "dmarc", "example.com", "Moderate"));
		await world.scanDue([connectionId]);
		expect(await newCount(world, world.owner)).toEqual({ status: 200, count: 1 });
	});

	it("does not light up everything that was there before a member joined", async () => {
		const late = await world.addMember("zed");
		expect(await newCount(world, late)).toEqual({ status: 200, count: 0 });
	});

	it("keeps a finding new that a scan raised after the page was read", async () => {
		const page = (await world.findings()).body;
		account.insights.push(insight("i3", "spf", "example.com", "Low"));
		await world.scanDue([connectionId]);
		await world.guard.fetch(`${origin}/api/findings/${world.slug}`, {
			method: "POST",
			headers: world.owner.headers,
			body: JSON.stringify({ action: "seen", at: page.loadedAt }),
		});
		expect(await newCount(world, world.owner)).toEqual({ status: 200, count: 1 });
	});

	it("is every member's own, and for no one outside the workspace", async () => {
		const stranger = await world.stranger("sam");
		expect((await newCount(world, stranger)).status).toBe(404);
		const looking = await world.guard.fetch(`${origin}/api/findings/${world.slug}`, {
			method: "POST",
			headers: stranger.headers,
			body: JSON.stringify({ action: "seen" }),
		});
		expect(looking.status).toBe(404);
		// A member may look, though they may not dismiss.
		const member = await world.guard.fetch(`${origin}/api/findings/${world.slug}`, {
			method: "POST",
			headers: mia.headers,
			body: JSON.stringify({ action: "seen" }),
		});
		expect(member.status).toBe(200);
		const dismiss = await world.changeFinding(mia, { action: "dismiss", id: "x", reason: "no" });
		expect(dismiss.status).toBe(403);
	});
});

describe("the email about new serious findings", () => {
	let world: World;
	let ada: Person;
	let mia: Person;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, ada, mia, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("says nothing about what a connection already had when it was first scanned", async () => {
		await world.scanDue([connectionId]);
		expect(await alertsTo(world, "owner")).toEqual([]);
	});

	it("goes to owners and admins and not, by default, to members", async () => {
		account.insights.push(insight("i2", "dmarc", "example.com", "Critical"));
		await world.scanDue([connectionId]);
		const [toOwner, ...more] = await alertsTo(world, "owner");
		expect(more).toEqual([]);
		expect(await alertsTo(world, "ada")).toHaveLength(1);
		expect(await alertsTo(world, "mia")).toEqual([]);

		expect(toOwner?.subject).toBe(`${world.slug}: 1 new serious finding (1 critical)`);
		expect(toOwner?.text).toContain("DMARC is missing or misconfigured (example.com, Main)");
		expect(toOwner?.text).not.toContain("HSTS is off");
		expect(toOwner?.text).toContain(`Open Findings: ${origin}/${world.slug}/findings`);
		expect(toOwner?.html).toContain(`href="${origin}/${world.slug}/findings"`);
		expect(toOwner?.headers?.["List-Unsubscribe"]).toMatch(
			new RegExp(`^<${origin}/api/unsubscribe/alert\\.`),
		);
		expect(toOwner?.headers?.["List-Unsubscribe-Post"]).toBe("List-Unsubscribe=One-Click");
		expect(ada).toBeDefined();
		expect(mia).toBeDefined();
	});

	it("never carries a token, its hint or the account", async () => {
		const sent = (await world.guard.emails()).filter((email) =>
			email.subject.includes("serious finding"),
		);
		expect(sent.length).toBeGreaterThan(0);
		for (const email of sent) {
			const everything = JSON.stringify(email);
			expect(everything).not.toContain(cloudflareToken(1));
			expect(everything).not.toContain(HINT);
			expect(everything).not.toContain(ACCOUNT_ID);
		}
	});
});

describe("a finding that flaps", () => {
	let world: World;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("is not news again within a day, and is after a longer absence", async () => {
		const known = account.insights;
		account.insights = [];
		await world.scanDue([connectionId]);
		account.insights = known;
		await world.scanDue([connectionId]);
		expect(await alertsTo(world, "owner")).toEqual([]);
		expect(await newCount(world, world.owner)).toEqual({ status: 200, count: 1 });

		// Gone for two days.
		account.insights = [];
		await world.scanDue([connectionId]);
		await world.guard.db
			.prepare("UPDATE finding SET resolved_at = resolved_at - ?1")
			.bind(2 * DAY)
			.run();
		account.insights = known;
		await world.scanDue([connectionId]);
		expect(await alertsTo(world, "owner")).toHaveLength(1);
	});
});

describe("how often alerts go", () => {
	let world: World;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("sends one an hour for a workspace and folds the rest into the next", async () => {
		account.insights.push(insight("i2", "dmarc", "example.com", "Critical"));
		await world.scanDue([connectionId]);
		account.insights.push(insight("i3", "tls_not_enabled", "api.example.com", "Critical"));
		await world.scanDue([connectionId]);
		const first = await alertsTo(world, "owner");
		expect(first).toHaveLength(1);
		expect(first[0]?.text).not.toContain("TLS is off");

		// An hour on, the next run tells what waited.
		await world.guard.db
			.prepare("UPDATE notification_log SET sent_at = sent_at - ?1")
			.bind(HOUR + 1000)
			.run();
		await world.guard.runScheduled(0, "0 * * * *");
		const both = await alertsTo(world, "owner");
		expect(both).toHaveLength(2);
		expect(both[1]?.text).toContain("TLS is off (api.example.com, Main)");
		expect(both[1]?.text).not.toContain("DMARC");

		// And nothing is told twice.
		await world.guard.db
			.prepare("UPDATE notification_log SET sent_at = sent_at - ?1")
			.bind(HOUR + 1000)
			.run();
		await world.guard.runScheduled(0, "0 * * * *");
		expect(await alertsTo(world, "owner")).toHaveLength(2);
	});
});

/** The Monday at 08:00 UTC after now, and a time that is not that. */
function nextMonday(from = Date.now()) {
	const day = new Date(from);
	day.setUTCHours(8, 0, 0, 0);
	do day.setUTCDate(day.getUTCDate() + 1);
	while (day.getUTCDay() !== 1);
	return day;
}

describe("the weekly summary", () => {
	let world: World;
	let connectionId: string;
	let monday: Date;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world } = fixture);
		connectionId = fixture.connection.id;
		monday = nextMonday();
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("is sent on Monday from 08:00 UTC, even when the 08:00 run did not send it", async () => {
		for (const wrong of [
			new Date(monday.getTime() - DAY), // Sunday
			new Date(monday.getTime() + DAY), // Tuesday
			new Date(monday.getTime() - HOUR), // Monday, 07:00
		]) {
			await world.guard.runScheduled(0, "0 * * * *", wrong);
		}
		expect(await digestsTo(world, "owner")).toEqual([]);

		// The 08:00 run never happened; the one at 09:00 sends it.
		await world.guard.runScheduled(0, "0 * * * *", new Date(monday.getTime() + HOUR));
		const [digest, ...more] = await digestsTo(world, "owner");
		expect(more).toEqual([]);
		expect(digest?.text).toContain("1 finding is open in");
		expect(digest?.text).toContain("- Critical: 1");
		expect(digest?.text).toContain("- New: 1");
		expect(digest?.text).toContain("- Resolved: 0");
		expect(digest?.text).not.toContain("Traffic");
		expect(digest?.headers?.["List-Unsubscribe"]).toMatch(/\/api\/unsubscribe\/digest\./);
		// Admins by default, members not.
		expect(await digestsTo(world, "ada")).toHaveLength(1);
		expect(await digestsTo(world, "mia")).toEqual([]);
		expect(JSON.stringify(digest)).not.toContain(HINT);
	});

	it("is sent once a week however often the run repeats", async () => {
		await world.guard.runScheduled(0, "0 * * * *", monday);
		await world.guard.runScheduled(0, "0 * * * *", new Date(monday.getTime() + 15 * HOUR));
		expect(await digestsTo(world, "owner")).toHaveLength(1);
		await world.scanDue([connectionId]);
		expect(await digestsTo(world, "owner")).toHaveLength(1);

		const nextWeek = new Date(monday.getTime() + 7 * DAY);
		await world.guard.runScheduled(0, "0 * * * *", nextWeek);
		expect(await digestsTo(world, "owner")).toHaveLength(2);
	});

	it("skips a workspace with no connection", async () => {
		const { createWorkspace } = await import("./accounts");
		await createWorkspace(world.guard, origin, world.owner.headers, `${world.slug}-empty`);
		await world.guard.runScheduled(0, "0 * * * *", new Date(monday.getTime() + 14 * DAY));
		// The owner has two workspaces, and one summary for the one with a connection.
		const sent = await digestsTo(world, "owner");
		expect(sent).toHaveLength(3);
		expect(sent.filter((email) => email.subject.includes("-empty"))).toEqual([]);
	});
});

describe("the switches", () => {
	let world: World;
	let ada: Person;
	let mia: Person;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, ada, mia, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	it("start from the role's default and save as they are moved", async () => {
		expect((await settings(world, world.owner)).body).toMatchObject({
			alertEmail: true,
			digestEmail: true,
		});
		expect((await settings(world, mia)).body).toMatchObject({
			alertEmail: false,
			digestEmail: false,
		});

		expect((await change(world, mia, { alertEmail: true })).status).toBe(200);
		expect((await settings(world, mia)).body).toMatchObject({
			alertEmail: true,
			digestEmail: false,
		});
		expect((await change(world, ada, { alertEmail: false })).status).toBe(200);
		expect((await settings(world, ada)).body).toMatchObject({
			alertEmail: false,
			digestEmail: true,
		});
		// Nobody else's moved.
		expect((await settings(world, world.owner)).body).toMatchObject({
			alertEmail: true,
			digestEmail: true,
		});
	});

	it("decide who is told", async () => {
		account.insights.push(insight("i2", "dmarc", "example.com", "Critical"));
		await world.scanDue([connectionId]);
		expect(await alertsTo(world, "owner")).toHaveLength(1);
		expect(await alertsTo(world, "ada")).toEqual([]);
		expect(await alertsTo(world, "mia")).toHaveLength(1);

		const monday = nextMonday();
		await change(world, world.owner, { digestEmail: false });
		await change(world, mia, { digestEmail: true });
		await world.guard.runScheduled(0, "0 * * * *", monday);
		expect(await digestsTo(world, "owner")).toEqual([]);
		expect(await digestsTo(world, "ada")).toHaveLength(1);
		expect(await digestsTo(world, "mia")).toHaveLength(1);
	});

	it("refuse a stranger, another site and a change that is not one", async () => {
		const stranger = await world.stranger("sam");
		expect((await change(world, stranger, { alertEmail: false })).status).toBe(404);
		expect((await settings(world, stranger)).status).toBe(404);
		const elsewhere = await world.guard.fetch(`${origin}/api/notifications/${world.slug}`, {
			method: "POST",
			headers: { ...mia.headers, origin: "https://evil.test" },
			body: JSON.stringify({ alertEmail: false }),
		});
		expect(elsewhere.status).toBe(403);
		expect((await change(world, mia, {})).status).toBe(400);
		expect((await change(world, mia, { alertEmail: "yes" })).status).toBe(400);
		// A person is their session's, never a field of the request.
		await change(world, mia, { alertEmail: false, userId: world.owner.userId });
		expect((await settings(world, world.owner)).body.alertEmail).toBe(true);
	});
});

describe("the unsubscribe link", () => {
	let world: World;
	let ada: Person;
	let mia: Person;
	let account: Awaited<ReturnType<typeof workspaceWithFinding>>["account"];
	let connectionId: string;

	beforeAll(async () => {
		const fixture = await workspaceWithFinding();
		({ world, ada, mia, account } = fixture);
		connectionId = fixture.connection.id;
	});
	afterAll(async () => {
		await world?.dispose();
	});

	const linkIn = (email: SentEmail | undefined) =>
		/https:\/\/guard\.test\/api\/unsubscribe\/\S+/.exec(email?.text ?? "")?.[0] ?? "";

	/** What the Worker would sign, to forge a token the way someone without the secret cannot. */
	const signToken = (
		kind: string,
		workspaceId: string,
		userId: string,
		secret = world.guard.secret,
	) =>
		`${kind}.${workspaceId}.${userId}.${createHmac("sha256", secret)
			.update(`guard-unsubscribe:${kind}:${workspaceId}:${userId}`)
			.digest("base64url")}`;

	it("turns off that kind for that member in that workspace, and nothing else", async () => {
		account.insights.push(insight("i2", "dmarc", "example.com", "Critical"));
		await world.scanDue([connectionId]);
		const link = linkIn((await alertsTo(world, "ada"))[0]);
		expect(link).toContain("/api/unsubscribe/alert.");

		// Looking at the link, as a scanner does, changes nothing.
		const shown = await world.guard.fetch(link);
		expect(shown.status).toBe(200);
		expect(await shown.text()).toContain("Stop these emails");
		expect((await settings(world, ada)).body).toMatchObject({
			alertEmail: true,
			digestEmail: true,
		});

		// The mail client's one-click post does.
		const done = await world.guard.fetch(link, {
			method: "POST",
			body: "List-Unsubscribe=One-Click",
		});
		expect(done.status).toBe(200);
		const page = await done.text();
		expect(page).toContain("These emails are off");
		expect(page).toContain(`${origin}/${world.slug}/settings/notifications`);
		expect((await settings(world, ada)).body).toMatchObject({
			alertEmail: false,
			digestEmail: true,
		});
		expect((await settings(world, world.owner)).body).toMatchObject({
			alertEmail: true,
			digestEmail: true,
		});

		// Doing it again changes nothing, and the next alert skips only them.
		expect((await world.guard.fetch(link, { method: "POST" })).status).toBe(200);
		account.insights.push(insight("i3", "tls_not_enabled", "example.com", "Critical"));
		await world.guard.db
			.prepare("UPDATE notification_log SET sent_at = sent_at - ?1")
			.bind(HOUR + 1000)
			.run();
		await world.scanDue([connectionId]);
		expect(await alertsTo(world, "ada")).toHaveLength(1);
		expect(await alertsTo(world, "owner")).toHaveLength(2);
	});

	it("turns off the Monday summary alone when it comes from one", async () => {
		await world.guard.runScheduled(0, "0 * * * *", nextMonday());
		const link = linkIn((await digestsTo(world, "ada"))[0]);
		expect(link).toContain("/api/unsubscribe/digest.");
		expect((await world.guard.fetch(link, { method: "POST" })).status).toBe(200);
		expect((await settings(world, ada)).body).toMatchObject({
			alertEmail: false,
			digestEmail: false,
		});
		expect((await settings(world, world.owner)).body.digestEmail).toBe(true);
	});

	it("refuses a token that was changed, and says no more than it does for nonsense", async () => {
		const link = linkIn((await alertsTo(world, "owner"))[0]);
		const token = link.split("/api/unsubscribe/")[1] ?? "";
		// A character in the middle: the last one of a signature has bits that decoding ignores.
		const at = token.length - 10;
		const flipped = `${token.slice(0, at)}${token[at] === "A" ? "B" : "A"}${token.slice(at + 1)}`;
		const [kind, workspaceId, userId] = token.split(".");
		const forged = [
			flipped,
			// Another person's, under this signature.
			`${kind}.${workspaceId}.${mia.userId}.${token.split(".")[3]}`,
			// Another kind's.
			`digest.${workspaceId}.${userId}.${token.split(".")[3]}`,
			// Signed with a secret that is not the Worker's.
			signToken("alert", workspaceId ?? "", userId ?? "", "not-the-secret"),
			"nonsense",
		];
		const answers = [];
		for (const bad of forged) {
			const response = await world.guard.fetch(`${origin}/api/unsubscribe/${bad}`, {
				method: "POST",
			});
			answers.push({ status: response.status, text: await response.text() });
		}
		for (const answer of answers) {
			expect(answer.status).toBe(404);
			expect(answer.text).toBe(answers[0]?.text);
		}
		expect(answers[0]?.text).toContain("This link does not work");
		expect((await settings(world, world.owner)).body).toMatchObject({
			alertEmail: true,
			digestEmail: true,
		});
	});

	it("can only turn email off, never on", async () => {
		// Mia has nothing on. A valid link for her leaves her off.
		const token = signToken("alert", world.workspaceId, mia.userId);
		expect(
			(await world.guard.fetch(`${origin}/api/unsubscribe/${token}`, { method: "POST" })).status,
		).toBe(200);
		expect((await settings(world, mia)).body).toMatchObject({
			alertEmail: false,
			digestEmail: false,
		});
		// And a link for someone who is in no such workspace writes nothing.
		const stranger = await world.stranger("sam");
		const nothing = await world.guard.fetch(
			`${origin}/api/unsubscribe/${signToken("alert", world.workspaceId, stranger.userId)}`,
			{ method: "POST" },
		);
		expect(nothing.status).toBe(404);
		const rows = await world.guard.db
			.prepare("SELECT COUNT(*) AS n FROM notification_preference WHERE user_id = ?1")
			.bind(stranger.userId)
			.first<{ n: number }>();
		expect(rows?.n).toBe(0);
	});
});
