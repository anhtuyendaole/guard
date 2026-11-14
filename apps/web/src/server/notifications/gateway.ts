import { NotificationChange, type NotificationsView } from "../../lib/notification-schemas";
import { currentMember } from "../access";
import { db, emailEnabled } from "../auth";
import { appOrigin } from "../origin";
import { emailIsOn } from "./rules";

/** The same whether the workspace doesn't exist or the caller isn't in it. */
const notFound = () => answer({ ok: false, error: "Not found" }, 404);

function answer(body: unknown, status = 200): Response {
	return Response.json(body, { status, headers: { "cache-control": "private, no-store" } });
}

/** The caller's own notification settings in this workspace. Null when they are not a member. */
export async function listNotifications(slug: string): Promise<NotificationsView | null> {
	const member = await currentMember(slug);
	if (!member) return null;
	const { workspaceId, role } = member.membership;
	const choice = await db.$client
		.prepare(
			"SELECT alert_email, digest_email FROM notification_preference WHERE organization_id = ?1 AND user_id = ?2",
		)
		.bind(workspaceId, member.user.id)
		.first<{ alert_email: number | null; digest_email: number | null }>();
	return {
		alertEmail: emailIsOn(choice?.alert_email ?? null, role),
		digestEmail: emailIsOn(choice?.digest_email ?? null, role),
		email: member.user.email,
		emailConfigured: emailEnabled,
	};
}

export async function readNotifications(slug: string): Promise<Response> {
	const view = await listNotifications(slug);
	return view ? answer({ ok: true, ...view }) : notFound();
}

/**
 * Saves one or both switches for the caller, in this workspace only. Everyone changes their own and
 * nobody else's: the person is the session's, never a field of the request.
 */
export async function changeNotifications(request: Request, slug: string): Promise<Response> {
	if (request.headers.get("origin") !== appOrigin()) {
		return answer({ ok: false, error: "Not allowed from there" }, 403);
	}
	const member = await currentMember(slug);
	if (!member) return notFound();
	const parsed = NotificationChange.safeParse(await request.json().catch(() => null));
	if (!parsed.success) {
		return answer({ ok: false, error: parsed.error.issues[0]?.message ?? "Not a change." }, 400);
	}
	const { alertEmail, digestEmail } = parsed.data;
	const bit = (value: boolean | undefined) => (value === undefined ? null : value ? 1 : 0);
	// A switch left out keeps its value, including the role's default it has not left yet.
	await db.$client
		.prepare(
			`INSERT INTO notification_preference (organization_id, user_id, alert_email, digest_email)
			VALUES (?1, ?2, ?3, ?4)
			ON CONFLICT (organization_id, user_id) DO UPDATE SET
				alert_email = COALESCE(?3, alert_email), digest_email = COALESCE(?4, digest_email)`,
		)
		.bind(member.membership.workspaceId, member.user.id, bit(alertEmail), bit(digestEmail))
		.run();
	return answer({ ok: true });
}
