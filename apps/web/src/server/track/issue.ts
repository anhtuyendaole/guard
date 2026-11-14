import type { FindingSeverity, FindingSource } from "../../lib/connection-schemas";

/**
 * What Guard writes in a Track issue about a finding. Everything here is a pure function of the
 * facts it is handed, and `IssueFacts` lists those facts: a finding's own columns and its
 * connection's name and target. A token, its hint, a secret or anything from the request that asked
 * is not among them, so no code path from here can send one.
 */

export type TrackPriority = "urgent" | "high" | "medium" | "low";

export interface IssueFacts {
	source: FindingSource;
	severity: FindingSeverity;
	/** An insight's class, or an advisory's id. */
	kind: string;
	subject: string;
	title: string;
	/** Cloudflare's dashboard, or the advisory. */
	url: string;
	fixedVersion: string | null;
	/** The connection it came from: a Cloudflare account id, or `owner/name`. */
	connectionKind: "cloudflare" | "github";
	connectionTarget: string;
	connectionName: string;
	/** The Findings page of the workspace, with this finding's anchor. */
	guardUrl: string;
}

/** Track's own title limit. */
const MAX_TITLE = 512;

/** Track's priorities; an unknown severity leaves the issue without one. */
export function priorityFor(severity: FindingSeverity): TrackPriority | undefined {
	switch (severity) {
		case "critical":
			return "urgent";
		case "high":
			return "high";
		case "moderate":
			return "medium";
		case "low":
			return "low";
		case "unknown":
			return undefined;
	}
}

const SEVERITY_NAME: Record<FindingSeverity, string> = {
	critical: "Critical",
	high: "High",
	moderate: "Moderate",
	low: "Low",
	unknown: "Unknown",
};

/** The finding's title and where it is, which is what tells two issues of one advisory apart. */
export function issueTitle(facts: Pick<IssueFacts, "title" | "subject">): string {
	const title = facts.title.trim();
	// A spike's title already names its zone.
	const text =
		facts.subject && !title.includes(facts.subject) ? `${title} (${facts.subject})` : title;
	return text.length > MAX_TITLE ? `${text.slice(0, MAX_TITLE - 1)}…` : text;
}

/**
 * Text from a scan or an advisory, which a third party wrote, as plain Markdown: nothing in it
 * can open a link, a mention (`[@Name](mention:id)`), a heading or a list.
 */
export function plain(text: string): string {
	return text
		.replace(/\s+/g, " ")
		.trim()
		.replace(/[\\`*_{}[\]()<>#+!|~]/g, (character) => `\\${character}`);
}

/** Text as a code span, which needs no escaping, only a fence longer than any run inside it. */
export function code(text: string): string {
	const flat = text.replace(/\s+/g, " ").trim();
	const runs = flat.match(/`+/g) ?? [];
	const fence = "`".repeat(Math.max(0, ...runs.map((run) => run.length)) + 1);
	return `${fence} ${flat} ${fence}`;
}

/** Only https addresses become links: what a scan stored is not trusted to be one. */
function link(label: string, url: string): string {
	try {
		return new URL(url).protocol === "https:" ? `[${plain(label)}](${new URL(url).href})` : "";
	} catch {
		return "";
	}
}

/** A dependency finding's subject, `name@1.0.0, 1.1.0 in path/to/lockfile`, as its parts. */
export function parseDependencySubject(
	subject: string,
): { name: string; versions: string; lockfile: string } | null {
	const inAt = subject.indexOf(" in ");
	if (inAt < 0) return null;
	const spec = subject.slice(0, inAt);
	// A scoped package starts with its own @.
	const at = spec.indexOf("@", 1);
	if (at < 1) return null;
	return {
		name: spec.slice(0, at),
		versions: spec.slice(at + 1),
		lockfile: subject.slice(inAt + 4),
	};
}

/** The issue's description, Markdown, from the finding and where Guard found it. */
export function issueDescription(facts: IssueFacts): string {
	const lines: string[] = [];
	const add = (label: string, value: string) => value && lines.push(`- **${label}:** ${value}`);

	add("Severity", SEVERITY_NAME[facts.severity]);
	if (facts.source === "dependency") {
		add("Source", `Dependency, in the GitHub repository ${code(facts.connectionTarget)}`);
		const parts = parseDependencySubject(facts.subject);
		if (parts) {
			add("Package", code(parts.name));
			add("Installed", code(parts.versions));
			add(
				"Fixed in",
				facts.fixedVersion
					? code(facts.fixedVersion)
					: "no fix is known for every version installed",
			);
			add("Lockfile", code(parts.lockfile));
		} else {
			add("Subject", code(facts.subject));
			// Agents needs the version to bump to even when the subject is not in the usual shape.
			if (facts.fixedVersion) add("Fixed in", code(facts.fixedVersion));
		}
		add("Advisory", [code(facts.kind), link("read it", facts.url)].filter(Boolean).join(" · "));
	} else {
		add("Source", `Cloudflare, account ${code(facts.connectionTarget)}`);
		add("Subject", code(facts.subject));
		add("Class", code(facts.kind));
		add("Fix it in Cloudflare", link("open the dashboard", facts.url));
	}
	add("Connection", plain(facts.connectionName));

	const found = `Guard found this: ${plain(facts.title)}`;
	const back = link("Open the finding in Guard", facts.guardUrl);
	return [found, "", ...lines, "", back].join("\n").trim();
}

/** The address of an issue, which must be on Track's own origin: Track's word is not a link to trust. */
export function issueUrl(
	reported: string,
	integration: { address: string; workspaceSlug: string },
	key: string,
): string {
	try {
		const url = new URL(reported);
		if (url.origin === integration.address) return url.href;
	} catch {
		// Falls through to the address Guard knows how to build.
	}
	return `${integration.address}/${encodeURIComponent(integration.workspaceSlug)}/issue/${encodeURIComponent(key)}`;
}
