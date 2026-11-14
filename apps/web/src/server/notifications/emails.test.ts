import { describe, expect, it } from "vitest";
import { alertEmail, digestEmail, severityCounts, subjectForEmail } from "./emails";

const finding = (severity: string, title: string, subject: string, connection = "Main") => ({
	severity,
	title,
	subject,
	connection,
});

describe("subjectForEmail", () => {
	it("keeps a lockfile's path out", () => {
		expect(subjectForEmail("lodash@4.17.20 in apps/web/package-lock.json")).toBe("lodash@4.17.20");
	});

	it("leaves a zone or an account as it is", () => {
		expect(subjectForEmail("example.com")).toBe("example.com");
		expect(subjectForEmail("023e105f4ecef8ad9ca31a8372d0c353")).toBe(
			"023e105f4ecef8ad9ca31a8372d0c353",
		);
	});
});

describe("severityCounts", () => {
	it("counts most severe first", () => {
		const found = [{ severity: "high" }, { severity: "critical" }, { severity: "high" }];
		expect(severityCounts(found)).toBe("1 critical, 2 high");
	});
});

describe("alertEmail", () => {
	const links = {
		open: "https://guard.example/ws/findings",
		unsubscribe: "https://guard.example/api/unsubscribe/x",
	};

	it("names each finding by title and where it is, and links to Findings", () => {
		const email = alertEmail({
			workspace: "Acme",
			findings: [
				finding("critical", "DMARC is missing or misconfigured", "example.com"),
				finding("high", "A vulnerable package", "lodash@4.17.20 in package-lock.json", "api"),
			],
			links,
		});
		expect(email.subject).toBe("Acme: 2 new serious findings (1 critical, 1 high)");
		expect(email.text).toContain("DMARC is missing or misconfigured (example.com, Main)");
		expect(email.text).toContain("A vulnerable package (lodash@4.17.20, api)");
		expect(email.text).not.toContain("package-lock.json");
		expect(email.text).toContain("Open Findings: https://guard.example/ws/findings");
		expect(email.html).toContain('href="https://guard.example/api/unsubscribe/x"');
	});

	it("escapes what people typed", () => {
		const email = alertEmail({
			workspace: "<b>Acme</b>",
			findings: [finding("critical", "<script>alert(1)</script>", "a&b.com", "Main")],
			links,
		});
		expect(email.html).not.toContain("<script>");
		expect(email.html).not.toContain("<b>Acme</b>");
		expect(email.html).toContain("a&amp;b.com");
	});

	it("lists a few in full and counts the rest", () => {
		const findings = Array.from({ length: 20 }, (_, n) =>
			finding("critical", `Problem ${n}`, `zone${n}.com`),
		);
		const email = alertEmail({ workspace: "Acme", findings, links });
		expect(email.text).toContain("Problem 14");
		expect(email.text).not.toContain("Problem 15");
		expect(email.text).toContain("And 5 more");
	});

	it("works without an address to link to", () => {
		const email = alertEmail({
			workspace: "Acme",
			findings: [finding("critical", "A problem", "example.com")],
			links: {},
		});
		expect(email.text).not.toContain("http");
	});
});

describe("digestEmail", () => {
	it("says what is open, new and resolved, and the week's traffic when it was read", () => {
		const email = digestEmail({
			workspace: "Acme",
			numbers: {
				open: { critical: 1, moderate: 4 },
				raised: 3,
				resolved: 2,
				traffic: { stopped: 12_345, challenged: 6 },
			},
			newest: [finding("critical", "DMARC is missing or misconfigured", "example.com")],
			links: {},
		});
		expect(email.text).toContain("5 findings are open in Acme.");
		expect(email.text).toContain("- Critical: 1");
		expect(email.text).toContain("- Moderate: 4");
		expect(email.text).toContain("- New: 3");
		expect(email.text).toContain("- Resolved: 2");
		expect(email.text).toContain("12,345");
	});

	it("leaves traffic out when none was read", () => {
		const email = digestEmail({
			workspace: "Acme",
			numbers: { open: {}, raised: 0, resolved: 0, traffic: null },
			newest: [],
			links: {},
		});
		expect(email.text).toContain("Nothing is open in Acme.");
		expect(email.text).not.toContain("Traffic");
	});
});
