import type { Database } from "../db";

/**
 * When this member last opened Findings in this workspace, or when they joined if they never have:
 * what the "New" badge counts from. Nothing to set up, and a new member is not shown everything
 * that was there before them.
 */
export async function findingsSeenAt(
	db: Database,
	workspaceId: string,
	userId: string,
	memberId: string,
): Promise<number> {
	const row = await db.$client
		.prepare(
			`SELECT COALESCE(
				(SELECT findings_seen_at FROM notification_preference WHERE organization_id = ?1 AND user_id = ?2),
				(SELECT created_at FROM member WHERE id = ?3), 0) AS seen`,
		)
		.bind(workspaceId, userId, memberId)
		.first<{ seen: number }>();
	return row?.seen ?? 0;
}

/**
 * Records that the member has seen Findings up to `at` (never later than now, never earlier than
 * before). The page says when its list was read, so a finding a scan added after that stays new.
 */
export async function markFindingsSeen(
	db: Database,
	workspaceId: string,
	userId: string,
	at: number | undefined,
	now = Date.now(),
): Promise<void> {
	const seen = Math.min(at ?? now, now);
	await db.$client
		.prepare(
			`INSERT INTO notification_preference (organization_id, user_id, findings_seen_at)
			VALUES (?1, ?2, ?3)
			ON CONFLICT (organization_id, user_id) DO UPDATE SET
				findings_seen_at = MAX(COALESCE(findings_seen_at, 0), excluded.findings_seen_at)`,
		)
		.bind(workspaceId, userId, seen)
		.run();
}

/** How many open findings were raised after `seenAt`. */
export async function countNewFindings(
	db: Database,
	workspaceId: string,
	seenAt: number,
): Promise<number> {
	const row = await db.$client
		.prepare(
			`SELECT COUNT(*) AS n FROM finding
			WHERE organization_id = ?1 AND resolved_at IS NULL AND dismissed_at IS NULL AND raised_at > ?2`,
		)
		.bind(workspaceId, seenAt)
		.first<{ n: number }>();
	return row?.n ?? 0;
}
