import type { FindingStatus } from "./connection-schemas";

/**
 * Whether a finding is new to a member: open, and raised after they last opened Findings. A
 * dismissed or resolved finding is never new, whatever its time.
 */
export function isNewSince(
	finding: { raisedAt: number; status: FindingStatus },
	seenAt: number,
): boolean {
	return finding.status === "open" && finding.raisedAt > seenAt;
}

/** The sidebar's count: a number up to 99, then "99+". */
export function badgeText(count: number): string {
	return count > 99 ? "99+" : String(count);
}

/** Fired on the window when the member has opened Findings, so the sidebar can clear its badge. */
export const FINDINGS_SEEN_EVENT = "guard:findings-seen";
