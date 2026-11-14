import { clip, compose, type Message, type Section } from "../email/templates";
import { ALERT_LISTED, type DigestNumbers } from "./rules";

/**
 * What an alert or digest may say about a finding: its title and where it is, as a person named
 * them (a zone, a repository, a package), and never anything a scan read. A dependency's subject
 * is `package@versions in path/to/lockfile`, and the path stays out.
 */
export interface Told {
	severity: string;
	title: string;
	subject: string;
	connection: string;
}

const SEVERITY_NAME: Record<string, string> = {
	critical: "Critical",
	high: "High",
	moderate: "Moderate",
	low: "Low",
	unknown: "Unknown",
};

const nameOf = (severity: string) => SEVERITY_NAME[severity] ?? "Unknown";
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

/** `package@1.0.0 in package-lock.json` as `package@1.0.0`: the lockfile's path is not for email. */
export function subjectForEmail(subject: string): string {
	const at = subject.indexOf(" in ");
	return at > 0 && !subject.slice(0, at).includes(" ") ? subject.slice(0, at) : subject;
}

function describe(finding: Told): string {
	const where = [subjectForEmail(finding.subject), finding.connection]
		.map((part) => clip(part, 80))
		.filter((part, index, all) => part && all.indexOf(part) === index)
		.join(", ");
	return `${clip(finding.title, 120)} (${where})`;
}

/** Severities with counts, most severe first: `2 critical, 1 high`. */
export function severityCounts(findings: readonly { severity: string }[]): string {
	const counts = new Map<string, number>();
	for (const { severity } of findings) counts.set(severity, (counts.get(severity) ?? 0) + 1);
	return ["critical", "high", "moderate", "low", "unknown"]
		.filter((severity) => counts.has(severity))
		.map((severity) => `${counts.get(severity)} ${severity}`)
		.join(", ");
}

interface Links {
	/** Findings. Undefined when the deployment has no public address to link to. */
	open?: string | undefined;
	unsubscribe?: string | undefined;
}

function footerFor(reason: string, links: Links) {
	const footer = `${reason} You can change this in the workspace's notification settings.`;
	return links.unsubscribe
		? { footer, footerLink: { label: "Unsubscribe from these emails", url: links.unsubscribe } }
		: { footer };
}

/** One workspace's new critical and high findings, after a scan. */
export function alertEmail({
	workspace,
	findings,
	links,
}: {
	workspace: string;
	findings: readonly Told[];
	links: Links;
}): Message {
	const name = clip(workspace, 60);
	const counts = severityCounts(findings);
	const listed = findings.slice(0, ALERT_LISTED);
	const sections: Section[] = [];
	for (const severity of ["critical", "high"]) {
		const lines = listed.filter((one) => one.severity === severity).map(describe);
		if (lines.length > 0) sections.push({ title: nameOf(severity), lines });
	}
	const more = findings.length - listed.length;
	if (more > 0) {
		sections.push({ title: `And ${plural(more, "more")}`, lines: ["Findings lists all of them."] });
	}
	return compose({
		subject: `${name}: ${plural(findings.length, "new serious finding")} (${counts})`,
		heading: "New serious findings",
		body: [
			`Guard found ${plural(findings.length, "new critical or high finding")} in ${name}: ${counts}.`,
		],
		sections,
		...(links.open && { action: { label: "Open Findings", url: links.open } }),
		...footerFor(`You get this because findings like these are sent to you in ${name}.`, links),
	});
}

/** The Monday summary of one workspace. */
export function digestEmail({
	workspace,
	numbers,
	newest,
	links,
}: {
	workspace: string;
	numbers: DigestNumbers;
	/** A few of the week's new findings, most severe first. */
	newest: readonly Told[];
	links: Links;
}): Message {
	const name = clip(workspace, 60);
	const open = ["critical", "high", "moderate", "low", "unknown"]
		.map((severity) => [severity, numbers.open[severity] ?? 0] as const)
		.filter(([, count]) => count > 0);
	const totalOpen = open.reduce((sum, [, count]) => sum + count, 0);
	const sections: Section[] = [
		{
			title: "Open now",
			lines:
				totalOpen === 0
					? ["Nothing is open."]
					: open.map(([severity, count]) => `${nameOf(severity)}: ${count}`),
		},
		{
			title: "This week",
			lines: [`New: ${numbers.raised}`, `Resolved: ${numbers.resolved}`],
		},
	];
	if (newest.length > 0) {
		sections.push({ title: "Newest findings", lines: newest.map(describe) });
	}
	if (numbers.traffic) {
		sections.push({
			title: "Traffic, the last 7 days",
			lines: [
				`Stopped by the WAF and bot features: ${numbers.traffic.stopped.toLocaleString("en-US")}`,
				`Challenged: ${numbers.traffic.challenged.toLocaleString("en-US")}`,
			],
		});
	}
	return compose({
		subject: `${name}: your weekly Guard summary`,
		heading: "Your week in Guard",
		body: [
			totalOpen === 0
				? `Nothing is open in ${name}.`
				: `${plural(totalOpen, "finding")} ${totalOpen === 1 ? "is" : "are"} open in ${name}.`,
		],
		sections,
		...(links.open && { action: { label: "Open Findings", url: links.open } }),
		...footerFor(`You get this summary every Monday for ${name}.`, links),
	});
}
