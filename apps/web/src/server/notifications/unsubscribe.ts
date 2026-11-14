import { env } from "cloudflare:workers";
import type { Database } from "../db";
import { appOrigin } from "../origin";

/** The two kinds of email a member can turn off, and the column of each. */
export const KINDS = { alert: "alert_email", digest: "digest_email" } as const;
export type Kind = keyof typeof KINDS;

const ID = /^[\w-]{1,64}$/;

/**
 * The link in an alert or digest that turns that kind of email off for its recipient, in that
 * workspace, without signing in:
 *
 *   GET  /api/unsubscribe/:token  a page with a button, so that link scanners change nothing
 *   POST /api/unsubscribe/:token  turns the email off; mail clients post here for one-click
 *                                 unsubscribe (RFC 8058), as the email's `List-Unsubscribe` says
 *
 * The token names the kind, the workspace and the member and is signed with `BETTER_AUTH_SECRET`,
 * which stands in for a session. It can only turn email off, and every answer that is not a success
 * is the same page, so nothing says whether a workspace or a member exists.
 */
export async function handleUnsubscribe(request: Request, token: string, db: Database) {
	const target = await readToken(token);
	if (!target) return notWorking();
	if (request.method === "GET" || request.method === "HEAD") {
		return page(
			200,
			"Stop these emails?",
			target.kind === "alert"
				? "You will no longer get an email when a scan finds new critical or high findings. Nothing else changes."
				: "You will no longer get the Monday summary. Nothing else changes.",
			{ button: "Stop these emails" },
		);
	}
	if (request.method !== "POST") return page(405, "Method not allowed", "");
	const column = KINDS[target.kind];
	// Only a current member's row is written, and only ever to 0.
	const { meta } = await db.$client
		.prepare(
			`INSERT INTO notification_preference (organization_id, user_id, ${column})
			SELECT ?1, ?2, 0 WHERE EXISTS (
				SELECT 1 FROM member WHERE organization_id = ?1 AND user_id = ?2
			)
			ON CONFLICT (organization_id, user_id) DO UPDATE SET ${column} = 0`,
		)
		.bind(target.workspaceId, target.userId)
		.run();
	if (meta.changes === 0) return notWorking();
	const workspace = await db.$client
		.prepare("SELECT slug FROM organization WHERE id = ?1")
		.bind(target.workspaceId)
		.first<{ slug: string }>();
	return page(
		200,
		"These emails are off",
		target.kind === "alert"
			? "You will no longer get an email about new critical or high findings. You can turn it back on in the workspace's notification settings."
			: "You will no longer get the Monday summary. You can turn it back on in the workspace's notification settings.",
		workspace
			? { link: { label: "Notification settings", href: settingsUrl(workspace.slug) } }
			: {},
	);
}

/** Where a member turns these on again. A relative link when the app has no address of its own. */
function settingsUrl(slug: string): string {
	return `${env.BETTER_AUTH_URL ? appOrigin() : ""}/${encodeURIComponent(slug)}/settings/notifications`;
}

const notWorking = () =>
	page(
		404,
		"This link does not work",
		"It may have been copied wrongly, or it is no longer valid.",
	);

/** The token for one kind of email to one member of a workspace. */
export async function unsubscribeToken(
	kind: Kind,
	workspaceId: string,
	userId: string,
): Promise<string> {
	const mac = await crypto.subtle.sign(
		"HMAC",
		await signingKey(),
		signed(kind, workspaceId, userId),
	);
	const signature = btoa(String.fromCharCode(...new Uint8Array(mac)))
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
	return `${kind}.${workspaceId}.${userId}.${signature}`;
}

async function readToken(token: string) {
	const [kind = "", workspaceId = "", userId = "", signature = "", ...rest] = token.split(".");
	if (rest.length > 0 || !isKind(kind) || !ID.test(workspaceId) || !ID.test(userId)) return null;
	const mac = fromBase64Url(signature);
	if (!mac) return null;
	// `verify` compares in constant time.
	const valid = await crypto.subtle.verify(
		"HMAC",
		await signingKey(),
		mac,
		signed(kind, workspaceId, userId),
	);
	return valid ? { kind, workspaceId, userId } : null;
}

const isKind = (value: string): value is Kind => value === "alert" || value === "digest";

function signingKey() {
	return crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(env.BETTER_AUTH_SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);
}

/** What a token signs. Its purpose is part of it, so other uses of the secret make no tokens. */
function signed(kind: Kind, workspaceId: string, userId: string) {
	return new TextEncoder().encode(`guard-unsubscribe:${kind}:${workspaceId}:${userId}`);
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> | null {
	if (!/^[\w-]{43}$/.test(value)) return null;
	const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
	return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

const escapeHtml = (value: string) =>
	value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");

/** A small page of its own: the person may not be signed in, and the app is not needed. */
function page(
	status: number,
	heading: string,
	text: string,
	more: { button?: string; link?: { label: string; href: string } } = {},
): Response {
	const form = more.button
		? `<form method="post"><button type="submit" style="padding:10px 16px;background:#171717;color:#ffffff;border:0;border-radius:6px;font:inherit;font-weight:600;cursor:pointer">${escapeHtml(more.button)}</button></form>`
		: "";
	const link = more.link
		? `<p style="margin:0"><a href="${escapeHtml(more.link.href)}" style="color:#171717;font-weight:600">${escapeHtml(more.link.label)}</a></p>`
		: "";
	const html = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="robots" content="noindex"><title>${escapeHtml(heading)} · Gateweave Guard</title></head>
<body style="margin:0;padding:24px;background:#f5f5f5;color:#171717;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif">
<main style="max-width:480px;margin:48px auto;padding:32px;background:#ffffff;border:1px solid #e5e5e5;border-radius:8px">
<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3">${escapeHtml(heading)}</h1>
<p style="margin:0 0 24px">${escapeHtml(text)}</p>
${form}${link}
</main>
</body>
</html>`;
	return new Response(html, {
		status,
		headers: {
			"Content-Type": "text/html; charset=utf-8",
			"Cache-Control": "no-store",
			"Referrer-Policy": "no-referrer",
		},
	});
}
