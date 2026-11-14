import { describe, expect, it } from "vitest";
import {
	digestDays,
	digestIsDue,
	emailIsOn,
	FLAP_QUIET_MS,
	isoWeek,
	raisedAtFor,
	trafficTotals,
} from "./rules";

const DAY = 24 * 60 * 60 * 1000;
const at = (iso: string) => Date.parse(iso);

describe("raisedAtFor", () => {
	const now = at("2026-11-13T10:00:00Z");

	it("makes a finding Guard has not seen news now", () => {
		expect(raisedAtFor(undefined, now)).toBe(now);
	});

	it("keeps the time of a finding that has stayed open", () => {
		expect(raisedAtFor({ raisedAt: now - 5 * DAY, resolvedAt: null }, now)).toBe(now - 5 * DAY);
	});

	it("does not make news twice of a finding that flaps within a day", () => {
		const known = { raisedAt: now - 9 * DAY, resolvedAt: now - 2 * 60 * 60 * 1000 };
		expect(raisedAtFor(known, now)).toBe(known.raisedAt);
		expect(raisedAtFor({ ...known, resolvedAt: now - FLAP_QUIET_MS }, now)).toBe(known.raisedAt);
	});

	it("makes a finding that comes back after more than a day news again", () => {
		const known = { raisedAt: now - 9 * DAY, resolvedAt: now - FLAP_QUIET_MS - 1 };
		expect(raisedAtFor(known, now)).toBe(now);
	});
});

describe("emailIsOn", () => {
	it("follows the role until the member chooses", () => {
		expect(emailIsOn(null, "owner")).toBe(true);
		expect(emailIsOn(null, "admin")).toBe(true);
		expect(emailIsOn(null, "member")).toBe(false);
	});

	it("follows the choice over the role", () => {
		expect(emailIsOn(0, "owner")).toBe(false);
		expect(emailIsOn(1, "member")).toBe(true);
	});
});

describe("isoWeek", () => {
	it("names the ISO week, which belongs to the year of its Thursday", () => {
		expect(isoWeek(at("2026-11-16T08:00:00Z"))).toBe("2026-W47");
		expect(isoWeek(at("2026-11-22T23:59:59Z"))).toBe("2026-W47");
		expect(isoWeek(at("2026-11-23T00:00:00Z"))).toBe("2026-W48");
		expect(isoWeek(at("2026-01-01T12:00:00Z"))).toBe("2026-W01");
		expect(isoWeek(at("2021-01-03T12:00:00Z"))).toBe("2020-W53");
		expect(isoWeek(at("2024-12-30T08:00:00Z"))).toBe("2025-W01");
	});
});

describe("digestIsDue", () => {
	it("is Monday from 08:00 UTC to midnight, and no other time", () => {
		expect(digestIsDue(at("2026-11-16T08:00:00Z"))).toBe(true);
		expect(digestIsDue(at("2026-11-16T09:00:00Z"))).toBe(true);
		expect(digestIsDue(at("2026-11-16T23:59:59Z"))).toBe(true);
		expect(digestIsDue(at("2026-11-16T07:59:59Z"))).toBe(false);
		expect(digestIsDue(at("2026-11-17T08:00:00Z"))).toBe(false);
		expect(digestIsDue(at("2026-11-15T08:00:00Z"))).toBe(false);
	});
});

describe("digestDays", () => {
	it("is the seven complete UTC days before the run", () => {
		expect(digestDays(at("2026-11-16T08:00:00Z"))).toEqual({
			first: "2026-11-09",
			last: "2026-11-15",
		});
	});
});

describe("trafficTotals", () => {
	it("splits stopped from challenged, and counts what it does not know as neither", () => {
		expect(
			trafficTotals(
				[
					{ action: "block", count: 10 },
					{ action: "connectionClose", count: 2 },
					{ action: "managedChallenge", count: 5 },
					{ action: "jschallenge", count: 1 },
					{ action: "challenge", count: 1 },
					{ action: "log", count: 999 },
				],
				2,
			),
		).toEqual({ stopped: 12, challenged: 7 });
	});

	it("says a zone read with nothing acted on is zero, and no zone read is not said at all", () => {
		expect(trafficTotals([], 1)).toEqual({ stopped: 0, challenged: 0 });
		expect(trafficTotals([], 0)).toBeNull();
	});
});
