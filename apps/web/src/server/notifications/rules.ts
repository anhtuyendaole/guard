import { addDays, MITIGATED_ACTIONS, utcDay } from "@gateweave/guard-scan";
import { isAdminRole, type MemberRole } from "../../lib/roles";

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/**
 * A finding that comes back within this long of being resolved is the same news, not new: a flaky
 * insight, a token that lost a scope for a day, or a package that was pinned and unpinned. It keeps
 * its first time, so it is neither badged nor emailed twice.
 */
export const FLAP_QUIET_MS = DAY;

/** At most one alert email per workspace in this long. Findings raised in between wait for the next. */
export const ALERT_EVERY_MS = HOUR;

/**
 * A finding raised longer ago than this and never told is dropped from alerts: it would be stale by
 * the time it is sent, as when email was off for a week. The digest still counts it.
 */
export const ALERT_STALE_MS = 7 * DAY;

/** Findings an alert email names in full. The rest are counted, and Findings lists them. */
export const ALERT_LISTED = 15;

/** Severities that send an email. The others are for the page and the digest. */
export const ALERT_SEVERITIES = ["critical", "high"] as const;

export interface KnownFinding {
	raisedAt: number;
	resolvedAt: number | null;
}

/**
 * When a finding a scan sees now became news. A finding Guard has not seen is news now, one that
 * has been open stays as it was, and one that was resolved comes back as news only after
 * `FLAP_QUIET_MS`: a shorter absence is the same problem flapping.
 */
export function raisedAtFor(known: KnownFinding | undefined, now: number): number {
	if (!known) return now;
	if (known.resolvedAt !== null && now - known.resolvedAt > FLAP_QUIET_MS) return now;
	return known.raisedAt;
}

/** Whether a member gets an email of one kind: their own switch, else the default for their role. */
export function emailIsOn(choice: number | null, role: MemberRole): boolean {
	return choice === null ? isAdminRole(role) : choice === 1;
}

/** The ISO 8601 week of a UTC time, such as `2026-W46`. The week belongs to the year of its Thursday. */
export function isoWeek(time: number): string {
	const date = new Date(time);
	const day = (date.getUTCDay() + 6) % 7; // Monday is 0.
	const thursday = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
	thursday.setUTCDate(thursday.getUTCDate() - day + 3);
	const year = thursday.getUTCFullYear();
	const jan4 = Date.UTC(year, 0, 4);
	const firstThursday = new Date(jan4);
	firstThursday.setUTCDate(firstThursday.getUTCDate() - ((firstThursday.getUTCDay() + 6) % 7) + 3);
	const week = 1 + Math.round((thursday.getTime() - firstThursday.getTime()) / (7 * DAY));
	return `${year}-W${String(week).padStart(2, "0")}`;
}

/**
 * Whether the digest is due at this time: Monday from 08:00 UTC to midnight. Any hourly run in that
 * stretch may send it, so a run at 08:00 that fails or is skipped does not cost the week its digest;
 * the per-week key in `notification_log` keeps it to one.
 */
export function digestIsDue(time: number): boolean {
	const date = new Date(time);
	return date.getUTCDay() === 1 && date.getUTCHours() >= 8;
}

/** The week the digest looks back over: the seven days up to the run. */
export function digestSince(time: number): number {
	return time - 7 * DAY;
}

/** The seven complete UTC days before the run, as `YYYY-MM-DD` bounds, for the traffic totals. */
export function digestDays(time: number): { first: string; last: string } {
	const last = addDays(utcDay(time), -1);
	return { first: addDays(last, -6), last };
}

/** What the digest says about the week, in numbers. */
export interface DigestNumbers {
	open: Record<string, number>;
	raised: number;
	resolved: number;
	/** Null when no traffic has been read for the week. */
	traffic: { stopped: number; challenged: number } | null;
}

/** Whether an action stopped a request. Others in `MITIGATED_ACTIONS` challenged it. */
export const STOPPED_ACTIONS: readonly string[] = ["block", "connectionClose"];
export const CHALLENGED_ACTIONS: readonly string[] = MITIGATED_ACTIONS.filter(
	(action) => !STOPPED_ACTIONS.includes(action),
);

/**
 * Sums a week's per-action counts into the digest's two totals. Null when no zone has been read
 * that far, so that "not read yet" is not said as "nothing was stopped". A zone read with nothing
 * acted on is a real zero.
 */
export function trafficTotals(
	rows: readonly { action: string; count: number }[],
	zonesRead: number,
): DigestNumbers["traffic"] {
	if (zonesRead === 0) return null;
	let stopped = 0;
	let challenged = 0;
	for (const row of rows) {
		if (STOPPED_ACTIONS.includes(row.action)) stopped += row.count;
		else if (CHALLENGED_ACTIONS.includes(row.action)) challenged += row.count;
	}
	return { stopped, challenged };
}
