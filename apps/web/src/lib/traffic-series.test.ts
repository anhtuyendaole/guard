import { describe, expect, it } from "vitest";
import { buildSeries, buildWeek, SERIES_DAYS } from "./traffic-series";

const YESTERDAY = "2026-11-13";
const day = (n: number) =>
	new Date(Date.parse(`${YESTERDAY}T00:00:00Z`) - n * 86_400_000).toISOString().slice(0, 10);

describe("buildSeries", () => {
	it("is always the 14 days ending yesterday, oldest first", () => {
		const series = buildSeries([], null, null, YESTERDAY);
		expect(series).toHaveLength(SERIES_DAYS);
		expect(series[0]?.day).toBe(day(13));
		expect(series[13]?.day).toBe(YESTERDAY);
	});

	it("shows one read day as one slot of fourteen, the others unread", () => {
		const series = buildSeries([{ day: day(0), mitigated: 12 }], day(0), day(0), YESTERDAY);
		expect(series.filter((one) => one.state === "read")).toEqual([
			{ day: day(0), state: "read", mitigated: 12 },
		]);
		expect(series.filter((one) => one.state === "unread")).toHaveLength(13);
	});

	it("counts a read day with no rows as 0, and a day outside the run as unread", () => {
		const series = buildSeries([{ day: day(0), mitigated: 600 }], day(7), day(0), YESTERDAY);
		const states = series.map((one) => one.state);
		expect(states.slice(0, 6)).toEqual(Array(6).fill("unread"));
		expect(states.slice(6)).toEqual(Array(8).fill("read"));
		expect(series.slice(6, 13).map((one) => one.mitigated)).toEqual(Array(7).fill(0));
		expect(series[13]?.mitigated).toBe(600);
	});

	it("keeps a spike as it is", () => {
		const rows = [1, 2, 3, 4, 5, 6, 7].map((n) => ({ day: day(n), mitigated: 100 }));
		const series = buildSeries(
			[...rows, { day: day(0), mitigated: 1000 }],
			day(13),
			day(0),
			YESTERDAY,
		);
		expect(Math.max(...series.map((one) => one.mitigated))).toBe(1000);
		expect(series.filter((one) => one.state === "read")).toHaveLength(14);
	});

	it("treats a day with rows as read even when no run is recorded", () => {
		const series = buildSeries([{ day: day(2), mitigated: 3 }], null, null, YESTERDAY);
		expect(series[11]).toEqual({ day: day(2), state: "read", mitigated: 3 });
	});
});

describe("buildWeek", () => {
	const week = (
		rows: { day: string; mitigated: number }[],
		first: string | null,
		last: string | null,
	) => buildWeek(buildSeries(rows, first, last, YESTERDAY));

	it("gives a percentage only when all fourteen days are known", () => {
		const rows = Array.from({ length: 14 }, (_, n) => ({
			day: day(n),
			mitigated: n < 7 ? 100 : 50,
		}));
		expect(week(rows, day(13), day(0))).toEqual({
			thisSum: 700,
			thisRead: 7,
			lastSum: 350,
			lastRead: 7,
			change: 100,
		});
	});

	it("says nothing of last week when none of it was read", () => {
		const result = week([{ day: day(0), mitigated: 12 }], day(0), day(0));
		expect(result).toMatchObject({
			thisSum: 12,
			thisRead: 1,
			lastSum: 0,
			lastRead: 0,
			change: null,
		});
	});

	it("counts how many days were read when only some were, and gives no percentage", () => {
		const result = week([{ day: day(0), mitigated: 5 }], day(9), day(0));
		expect(result).toMatchObject({ thisRead: 7, lastRead: 3, change: null });
	});

	it("gives no percentage when last week was quiet throughout", () => {
		const result = week([{ day: day(0), mitigated: 5 }], day(13), day(0));
		expect(result).toMatchObject({ lastRead: 7, lastSum: 0, change: null });
	});
});
