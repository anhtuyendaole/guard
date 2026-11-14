import { z } from "zod";
import type { TrackPriority } from "./issue";
import { TrackError, type TrackSession } from "./mcp";

/**
 * The three tools of Track's MCP server Guard calls, with the parts of their answers it uses. The
 * schemas are loose objects, as Track's own are, so a field added there later does not fail Guard.
 */

const WorkspaceAnswer = z.looseObject({
	teams: z.array(z.looseObject({ key: z.string(), name: z.string() })),
	labels: z.array(z.looseObject({ name: z.string() })),
});

/** An issue Track made or changed. `proposed` lists what an agent that proposes only suggested. */
const IssueAnswer = z.looseObject({
	key: z.string().min(1),
	url: z.string(),
	labels: z.array(z.string()).default([]),
	proposed: z.array(z.looseObject({ change: z.string() })).optional(),
});

export interface TrackWorkspace {
	teams: { key: string; name: string }[];
	labels: string[];
}

export interface TrackIssue {
	key: string;
	url: string;
	/** Something Guard asked for waits for a person, because an admin set the agent to propose. */
	proposed: boolean;
}

export async function getWorkspace(session: TrackSession, slug: string): Promise<TrackWorkspace> {
	const answer = await session.call("get_workspace", { workspace: slug }, WorkspaceAnswer);
	return { teams: answer.teams, labels: answer.labels.map((label) => label.name) };
}

const issueOf = (answer: z.output<typeof IssueAnswer>): TrackIssue => ({
	key: answer.key,
	url: answer.url,
	proposed: (answer.proposed?.length ?? 0) > 0,
});

export async function createIssue(
	session: TrackSession,
	input: {
		workspace: string;
		team: string;
		title: string;
		description: string;
		priority?: TrackPriority;
		labels: string[];
	},
): Promise<TrackIssue> {
	const answer = await session.call(
		"create_issue",
		{
			workspace: input.workspace,
			team: input.team,
			title: input.title,
			description: input.description,
			...(input.priority && { priority: input.priority }),
			...(input.labels.length > 0 && { labels: input.labels }),
		},
		IssueAnswer,
	);
	return issueOf(answer);
}

export async function addLabel(
	session: TrackSession,
	input: { workspace: string; key: string; label: string },
): Promise<TrackIssue> {
	const answer = await session.call(
		"update_issue",
		{ workspace: input.workspace, key: input.key, add_labels: [input.label] },
		IssueAnswer,
	);
	return issueOf(answer);
}

/** The label as Track spells it, when it has one by that name ignoring case. */
export function findLabel(labels: readonly string[], wanted: string): string | null {
	const lower = wanted.trim().toLowerCase();
	return labels.find((label) => label.toLowerCase() === lower) ?? null;
}

/**
 * What a failed call says to the person who pressed the button: one sentence that names what to
 * fix. A tool's own message is Track's wording and passes through, since it knows best.
 */
export function failureSentence(error: TrackError, doing: "check" | "file"): string {
	switch (error.failure) {
		case "unauthorized":
			return "Track refused the key: it was revoked, or its agent was deleted. Make a new key in Track and replace it here.";
		case "not_mcp":
			return "Nothing at that address answers as Gateweave Track does. Check the address.";
		case "unreachable":
			return doing === "check"
				? "Track could not be reached just now. Check the address, or try again in a minute."
				: "Track could not be reached just now, so nothing was filed. Try again in a minute.";
		case "invalid_response":
			return "Track answered in a way Guard does not understand, so nothing was changed. If this keeps happening, Track may be a version Guard does not know yet.";
		case "tool_error":
			return `Track said: ${error.message}`;
	}
}

export type Checked<T> = { ok: true; value: T } | { ok: false; error: string; outcome: string };

export interface CheckedTrack {
	/** Track's own spelling of the team and of the label, or null for none. */
	teamName: string;
	fixLabel: string | null;
	labels: string[];
}

/**
 * Whether this key reaches this workspace and team in Track, and whether the fix label exists
 * there. Used before anything is saved, so what is saved works.
 */
export async function checkTrack(
	session: TrackSession,
	target: { workspace: string; team: string; fixLabel: string | null },
): Promise<Checked<CheckedTrack>> {
	let workspace: TrackWorkspace;
	try {
		workspace = await getWorkspace(session, target.workspace);
	} catch (error) {
		if (!(error instanceof TrackError)) throw error;
		// The only refusal get_workspace has is a workspace the key cannot see, which is also what a
		// missing one looks like, so that slugs cannot be probed.
		if (error.failure === "tool_error") {
			return {
				ok: false,
				outcome: "not_found",
				error: `There is no workspace "${target.workspace}" in Track for this key. Check the slug, and that the key was made in that workspace.`,
			};
		}
		return { ok: false, outcome: error.failure, error: failureSentence(error, "check") };
	}
	const team = workspace.teams.find((candidate) => candidate.key === target.team);
	if (!team) {
		return {
			ok: false,
			outcome: "not_found",
			error: `There is no team with the key ${target.team} in that workspace. Its teams are ${workspace.teams.map(({ key }) => key).join(", ") || "none yet"}.`,
		};
	}
	let fixLabel: string | null = null;
	if (target.fixLabel) {
		fixLabel = findLabel(workspace.labels, target.fixLabel);
		if (!fixLabel) {
			return {
				ok: false,
				outcome: "no_label",
				error: `There is no label "${target.fixLabel}" in that workspace yet. Make it in Track first, since Guard never makes labels.`,
			};
		}
	}
	return { ok: true, value: { teamName: team.name, fixLabel, labels: workspace.labels } };
}
