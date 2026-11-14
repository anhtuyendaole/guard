import type { Database } from "../db";
import type { Mailer } from "../email/mailer";
import type { Message } from "../email/templates";
import { toRole } from "../workspaces";
import { alertEmail, digestEmail, type Told } from "./emails";
import {
	ALERT_EVERY_MS,
	ALERT_STALE_MS,
	type DigestNumbers,
	digestDays,
	digestIsDue,
	digestSince,
	emailIsOn,
	isoWeek,
	trafficTotals,
} from "./rules";
import { KINDS, type Kind, unsubscribeToken } from "./unsubscribe";

export interface NotifyDeps {
	db: Database;
	/** Undefined when email is not set up, which leaves everything as it is. */
	mailer: Mailer | undefined;
	/** The app's public origin, which links need. Undefined when the deployment has not set one. */
	origin: string | undefined;
}

/** Workspaces one run handles. The rest wait for the next hour: each is a few queries and sends. */
const WORKSPACES_PER_RUN = 200;

/** Findings that make an alert: open, not dismissed, serious, raised since they were last told. */
const PENDING = `resolved_at IS NULL AND dismissed_at IS NULL AND severity IN ('critical', 'high')
	AND (notified_at IS NULL OR notified_at < raised_at)`;

interface Recipient {
	userId: string;
	email: string;
}

interface Workspace {
	id: string;
	slug: string;
	name: string;
}

/** The members of a workspace who get this kind of email: their switch, else their role's default. */
async function recipientsOf(db: Database, workspaceId: string, kind: Kind): Promise<Recipient[]> {
	const { results } = await db.$client
		.prepare(
			`SELECT u.id AS user_id, u.email, m.role, p.${KINDS[kind]} AS choice
			FROM member m
			JOIN user u ON u.id = m.user_id
			LEFT JOIN notification_preference p
				ON p.organization_id = m.organization_id AND p.user_id = m.user_id
			WHERE m.organization_id = ?1 ORDER BY m.created_at, u.id`,
		)
		.bind(workspaceId)
		.all<{ user_id: string; email: string; role: string; choice: number | null }>();
	return results
		.filter((row) => emailIsOn(row.choice, toRole(row.role)))
		.map((row) => ({ userId: row.user_id, email: row.email }));
}

type Links = Parameters<typeof alertEmail>[0]["links"];

/** The links and headers for one recipient's email. */
async function linksFor(
	{ origin }: NotifyDeps,
	kind: Kind,
	workspace: Workspace,
	userId: string,
): Promise<{ links: Links; headers: Record<string, string> | undefined }> {
	if (!origin) return { links: {}, headers: undefined };
	const unsubscribe = `${origin}/api/unsubscribe/${await unsubscribeToken(kind, workspace.id, userId)}`;
	return {
		links: { open: `${origin}/${encodeURIComponent(workspace.slug)}/findings`, unsubscribe },
		// Email Service accepts these only with an HTTPS link, which a local server does not have.
		headers: unsubscribe.startsWith("https:")
			? {
					"List-Unsubscribe": `<${unsubscribe}>`,
					"List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
				}
			: undefined,
	};
}

/** Sends to each recipient in turn; one that fails does not stop the rest. Returns how many went. */
async function sendTo(
	deps: NotifyDeps,
	kind: Kind,
	workspace: Workspace,
	recipients: Recipient[],
	build: (links: Links) => Message,
): Promise<number> {
	let sent = 0;
	for (const recipient of recipients) {
		try {
			const { links, headers } = await linksFor(deps, kind, workspace, recipient.userId);
			await deps.mailer?.send({
				to: recipient.email,
				...build(links),
				...(headers && { headers }),
			});
			sent++;
		} catch {
			// The mailer has logged why, by code. Nothing here may carry an address.
		}
	}
	return sent;
}

function workspaceOf(db: Database, id: string): Promise<Workspace | null> {
	return db.$client
		.prepare("SELECT id, slug, name FROM organization WHERE id = ?1")
		.bind(id)
		.first<Workspace>();
}

/**
 * Emails the members who have it on about findings that are new and critical or high: one email per
 * workspace, at most one an hour. Findings raised in between wait and go in the next. The hourly run
 * calls this after the scans, so a finding from "Scan now" is told by the next hour at the latest.
 * A finding is settled when its email is claimed, so a send that fails is not retried: an alert
 * that arrives twice is worse than one that does not, and the page and the digest still show it.
 */
export async function sendAlerts(
	deps: NotifyDeps,
	now = Date.now(),
): Promise<{ workspaces: number; sent: number }> {
	const { db, mailer } = deps;
	if (!mailer) return { workspaces: 0, sent: 0 };
	const stale = now - ALERT_STALE_MS;
	const { results } = await db.$client
		.prepare(
			`SELECT DISTINCT organization_id FROM finding WHERE ${PENDING} AND raised_at > ?1
			ORDER BY organization_id LIMIT ${WORKSPACES_PER_RUN}`,
		)
		.bind(stale)
		.all<{ organization_id: string }>();
	let workspaces = 0;
	let sent = 0;
	for (const { organization_id: id } of results) {
		// The slot comes first, in one statement, so that two runs at once cannot both take it.
		const slot = await db.$client
			.prepare(
				`INSERT INTO notification_log (organization_id, kind, period, sent_at)
				SELECT ?1, 'alert', ?2, ?3 WHERE NOT EXISTS (
					SELECT 1 FROM notification_log WHERE organization_id = ?1 AND kind = 'alert' AND sent_at > ?4
				)`,
			)
			.bind(id, crypto.randomUUID(), now, now - ALERT_EVERY_MS)
			.run();
		if (slot.meta.changes === 0) continue;
		const { results: told } = await db.$client
			.prepare(
				`UPDATE finding SET notified_at = ?3 WHERE organization_id = ?1 AND ${PENDING} AND raised_at > ?2
				RETURNING severity, title, subject, connection_id`,
			)
			.bind(id, stale, now)
			.all<{ severity: string; title: string; subject: string; connection_id: string }>();
		const workspace = await workspaceOf(db, id);
		if (told.length === 0 || !workspace) continue;
		const { results: connections } = await db.$client
			.prepare("SELECT id, name FROM connection WHERE organization_id = ?1")
			.bind(id)
			.all<{ id: string; name: string }>();
		const names = new Map(connections.map((one) => [one.id, one.name]));
		const findings: Told[] = told
			.map((row) => ({
				severity: row.severity,
				title: row.title,
				subject: row.subject,
				connection: names.get(row.connection_id) ?? "",
			}))
			.sort((a, b) => Number(a.severity !== "critical") - Number(b.severity !== "critical"));
		const recipients = await recipientsOf(db, id, "alert");
		workspaces++;
		sent += await sendTo(deps, "alert", workspace, recipients, (links) =>
			alertEmail({ workspace: workspace.name, findings, links }),
		);
	}
	return { workspaces, sent };
}

/** The week's numbers for one workspace. */
export async function digestNumbers(
	db: Database,
	workspaceId: string,
	time: number,
): Promise<{ numbers: DigestNumbers; newest: Told[] }> {
	const since = digestSince(time);
	const { first, last } = digestDays(time);
	const open = "organization_id = ?1 AND resolved_at IS NULL AND dismissed_at IS NULL";
	const [bySeverity, raised, resolved, actions, zones, newest] = await Promise.all([
		db.$client
			.prepare(`SELECT severity, COUNT(*) AS n FROM finding WHERE ${open} GROUP BY severity`)
			.bind(workspaceId)
			.all<{ severity: string; n: number }>(),
		db.$client
			.prepare(`SELECT COUNT(*) AS n FROM finding WHERE ${open} AND raised_at > ?2`)
			.bind(workspaceId, since)
			.first<{ n: number }>(),
		db.$client
			.prepare(
				`SELECT COUNT(*) AS n FROM finding
				WHERE organization_id = ?1 AND dismissed_at IS NULL AND resolved_at > ?2`,
			)
			.bind(workspaceId, since)
			.first<{ n: number }>(),
		db.$client
			.prepare(
				`SELECT action, SUM(count) AS count FROM traffic_count
				WHERE organization_id = ?1 AND dimension = 'action' AND day >= ?2 AND day <= ?3
				GROUP BY action`,
			)
			.bind(workspaceId, first, last)
			.all<{ action: string; count: number }>(),
		db.$client
			.prepare(
				"SELECT COUNT(*) AS n FROM traffic_zone WHERE organization_id = ?1 AND last_day >= ?2",
			)
			.bind(workspaceId, last)
			.first<{ n: number }>(),
		db.$client
			.prepare(
				`SELECT f.severity, f.title, f.subject, c.name AS connection
				FROM finding f JOIN connection c ON c.id = f.connection_id
				WHERE f.organization_id = ?1 AND f.resolved_at IS NULL AND f.dismissed_at IS NULL
					AND f.raised_at > ?2
				ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'moderate' THEN 2
					WHEN 'low' THEN 3 ELSE 4 END, f.raised_at DESC, f.id LIMIT 5`,
			)
			.bind(workspaceId, since)
			.all<Told>(),
	]);
	return {
		numbers: {
			open: Object.fromEntries(bySeverity.results.map((row) => [row.severity, row.n])),
			raised: raised?.n ?? 0,
			resolved: resolved?.n ?? 0,
			traffic: trafficTotals(actions.results, zones?.n ?? 0),
		},
		newest: newest.results,
	};
}

/**
 * The Monday summary, from any hourly run on Monday from 08:00 UTC: once per workspace per ISO week,
 * which a row keyed by both guarantees however often the run repeats, and which lets a later run
 * that day send what a missed one did not. A workspace with no connection has
 * nothing to summarize and is skipped, as is any run at another time.
 */
export async function sendDigests(
	deps: NotifyDeps,
	time = Date.now(),
): Promise<{ workspaces: number; sent: number }> {
	const { db, mailer } = deps;
	if (!mailer || !digestIsDue(time)) return { workspaces: 0, sent: 0 };
	const week = isoWeek(time);
	const { results } = await db.$client
		.prepare("SELECT DISTINCT organization_id FROM connection ORDER BY organization_id")
		.all<{ organization_id: string }>();
	let workspaces = 0;
	let sent = 0;
	for (const { organization_id: id } of results) {
		const claim = await db.$client
			.prepare(
				`INSERT OR IGNORE INTO notification_log (organization_id, kind, period, sent_at)
				VALUES (?1, 'digest', ?2, ?3)`,
			)
			.bind(id, week, time)
			.run();
		if (claim.meta.changes === 0) continue;
		const workspace = await workspaceOf(db, id);
		if (!workspace) continue;
		const recipients = await recipientsOf(db, id, "digest");
		if (recipients.length === 0) continue;
		const { numbers, newest } = await digestNumbers(db, id, time);
		workspaces++;
		sent += await sendTo(deps, "digest", workspace, recipients, (links) =>
			digestEmail({ workspace: workspace.name, numbers, newest, links }),
		);
	}
	return { workspaces, sent };
}
