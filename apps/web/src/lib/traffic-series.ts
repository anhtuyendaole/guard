import type { TrafficDayView, TrafficSeriesDay, TrafficWeek } from "./connection-schemas";

/** The chart's window: this many UTC days, ending yesterday. Two weeks, to set one against the other. */
export const SERIES_DAYS = 14;

/** The day `days` after (or, negative, before) this one, `YYYY-MM-DD` in UTC. */
function shift(day: string, days: number): string {
	return new Date(Date.parse(`${day}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10);
}

/**
 * The fixed window of days ending `yesterday`, oldest first. A day Guard has read is `read`, with
 * its mitigated count, and is 0 when it stored no rows (nothing was acted on). A day outside the run
 * of read days (`firstDay` to `lastDay`) and with no rows was never read, so it is `unread` and not
 * a zero. A day with rows is read whatever the run says, since rows only come from a read.
 */
export function buildSeries(
	rows: readonly TrafficDayView[],
	firstDay: string | null,
	lastDay: string | null,
	yesterday: string,
): TrafficSeriesDay[] {
	const counts = new Map(rows.map((row) => [row.day, row.mitigated]));
	return Array.from({ length: SERIES_DAYS }, (_, index) => {
		const day = shift(yesterday, index - (SERIES_DAYS - 1));
		const inRun = firstDay !== null && lastDay !== null && day >= firstDay && day <= lastDay;
		const count = counts.get(day);
		if (count !== undefined) return { day, state: "read", mitigated: count };
		return inRun ? { day, state: "read", mitigated: 0 } : { day, state: "unread", mitigated: 0 };
	});
}

function figures(days: readonly TrafficSeriesDay[]) {
	const read = days.filter((day) => day.state === "read");
	return { sum: read.reduce((total, day) => total + day.mitigated, 0), read: read.length };
}

/**
 * This week (the last 7 days of the series) against the 7 before it, from the days that were
 * read. A percentage only when all 14 days are known and last week was not empty: with fewer, the
 * two sums are not of the same thing.
 */
export function buildWeek(series: readonly TrafficSeriesDay[]): TrafficWeek {
	const half = SERIES_DAYS / 2;
	const last = figures(series.slice(0, half));
	const current = figures(series.slice(half));
	const complete = last.read === half && current.read === half;
	return {
		thisSum: current.sum,
		thisRead: current.read,
		lastSum: last.sum,
		lastRead: last.read,
		change:
			complete && last.sum > 0 ? Math.round(((current.sum - last.sum) / last.sum) * 100) : null,
	};
}
