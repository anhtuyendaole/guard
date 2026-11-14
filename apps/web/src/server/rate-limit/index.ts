import { env } from "cloudflare:workers";
import type { BetterAuthRateLimitOptions } from "better-auth";
import { DEFAULT_AUTH_LIMIT } from "../auth/config";
import type { Mailer } from "../email/mailer";
import { deploymentJurisdiction, objectsIn } from "../jurisdiction";
import { type Decision, LocalLimiter, type Rule } from "./gcra";

export { RateLimiter } from "./durable-object";

/**
 * Each auth rule also gets an hourly allowance of this many times its burst, so a client cannot
 * keep going by pacing itself to the short window: sign-in attempts are held to 60 an hour
 * instead of 3 every 10 seconds, which would be 1,080.
 */
export const HOURLY_MULTIPLE = 20;

/**
 * Emails one address can be sent, whatever they are: 5 at once, refilling over an hour, within
 * 10 that refill over a day.
 */
export const EMAILS_PER_RECIPIENT: Rule[] = [
	{ window: 60 * 60, max: 5 },
	{ window: 24 * 60 * 60, max: 10 },
];

/**
 * Passwords one person's sessions can offer, from however many addresses: 10 at once, refilling over
 * an hour, within 30 that refill over a day. Someone who has forgotten theirs will have gone for a
 * reset long before this.
 */
export const PASSWORD_TRIES_PER_PERSON: Rule[] = [
	{ window: 60 * 60, max: 10 },
	{ window: 24 * 60 * 60, max: 30 },
];

/** Whether someone signed in as this person may offer another password, wherever from. */
export async function allowPasswordTry(userId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(`password-try:${userId}`, PASSWORD_TRIES_PER_PERSON);
	return allowed;
}

/** Emails one person gets about those tries running out: one a day, since each says the same. */
export const SPENT_TRIES_EMAILS_PER_PERSON: Rule[] = [{ window: 24 * 60 * 60, max: 1 }];

/** Whether this person may be emailed about those tries running out. Counts this one if so. */
export async function allowSpentTriesEmail(userId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(
		`password-tries-told:${userId}`,
		SPENT_TRIES_EMAILS_PER_PERSON,
	);
	return allowed;
}

/** "Scan now" on one connection: once in five minutes, however many admins press it. */
export const SCAN_NOW_PER_CONNECTION: Rule[] = [{ window: 5 * 60, max: 1 }];

/** Whether an admin may start a scan of this connection now. Counts this one if so. */
export async function allowScanNow(connectionId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(`scan-now:${connectionId}`, SCAN_NOW_PER_CONNECTION);
	return allowed;
}

/**
 * Tokens a workspace may offer for checking: each is sent to Cloudflare or GitHub, so a stolen
 * session cannot use Guard to try them quickly. 20 at once, refilling over an hour.
 */
export const CONNECTS_PER_WORKSPACE: Rule[] = [{ window: 60 * 60, max: 20 }];

/** Whether this workspace may try another token. Counts this one if so. */
export async function allowConnect(workspaceId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(`connect:${workspaceId}`, CONNECTS_PER_WORKSPACE);
	return allowed;
}

/**
 * Findings a workspace may file in Track, or ask Agents to fix: 30 at once, refilling over a
 * minute. Each is a call to a server the workspace named, so a stolen session cannot use Guard to
 * flood it.
 */
export const TRACK_FILINGS_PER_WORKSPACE: Rule[] = [{ window: 60, max: 30 }];

/** Whether this workspace may file another finding in Track. Counts this one if so. */
export async function allowTrackFiling(workspaceId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(
		`track-filing:${workspaceId}`,
		TRACK_FILINGS_PER_WORKSPACE,
	);
	return allowed;
}

/**
 * Times a workspace may offer Track an address and a key for checking: each is sent to that
 * address, so a stolen session cannot use Guard to try keys quickly. 20 at once, refilling over an
 * hour.
 */
export const TRACK_CHECKS_PER_WORKSPACE: Rule[] = [{ window: 60 * 60, max: 20 }];

/** Whether this workspace may check another Track address and key. Counts this one if so. */
export async function allowTrackCheck(workspaceId: string): Promise<boolean> {
	const { allowed } = await consumeDurably(
		`track-check:${workspaceId}`,
		TRACK_CHECKS_PER_WORKSPACE,
	);
	return allowed;
}

/**
 * What one assistant may ask of `/mcp` for one person: 60 calls at once, refilling over a minute,
 * within 600 that refill over an hour. A model working through a list of findings makes bursts, and
 * a runaway loop or a stolen token should still be stopped well before it matters to the database.
 */
export const MCP_CALLS_PER_GRANT: Rule[] = [
	{ window: 60, max: 60 },
	{ window: 60 * 60, max: 600 },
];

/**
 * Whether this assistant may make another call for this person. Counted per person and OAuth
 * client rather than per access token, since a client gets a new token on every refresh, which
 * would start the count again.
 */
export function allowMcpCall(userId: string, clientId: string): Promise<Decision> {
	return consumeDurably(`mcp:${userId}:${clientId}`, MCP_CALLS_PER_GRANT);
}

const local = new LocalLimiter();

/**
 * Better Auth's rate limit storage. Better Auth counts per client address and path. Paths with
 * a rule of their own (sign-in, sign-up, password reset, invitations, OAuth) are counted in a
 * Durable Object, so their limits hold across every isolate and location; in memory, each
 * isolate would give an attacker a fresh allowance. Everything else, mostly session checks,
 * keeps the default limit in this isolate, which costs nothing per request.
 */
export const authRateLimits: NonNullable<BetterAuthRateLimitOptions["customStorage"]> = {
	async consume(key, rule) {
		if (rule.window === DEFAULT_AUTH_LIMIT.window && rule.max === DEFAULT_AUTH_LIMIT.max) {
			return local.consume(key, [rule], Date.now());
		}
		return consumeDurably(`auth:${key}`, [
			rule,
			{ window: 60 * 60, max: rule.max * HOURLY_MULTIPLE },
		]);
	},
};

/**
 * Caps how many emails any one address gets, however many clients ask for them. Over the cap,
 * an email is dropped without telling the requester, as a reset for an unknown address is.
 */
export function limitRecipients(mailer: Mailer | undefined): Mailer | undefined {
	if (!mailer) return undefined;
	return {
		async send(email) {
			const { allowed } = await consumeDurably(
				`email:${email.to.trim().toLowerCase()}`,
				EMAILS_PER_RECIPIENT,
			);
			if (!allowed) {
				console.warn("email: not sent, this address got too many emails recently");
				return;
			}
			await mailer.send(email);
		},
	};
}

async function consumeDurably(key: string, rules: Rule[]): Promise<Decision> {
	try {
		// Keys hold addresses, so they are hashed before they become Durable Object names, which
		// the dashboard can show. Counted where the deployment keeps its data, as the keys hold
		// addresses.
		const limiters = objectsIn(env.RATE_LIMITER, deploymentJurisdiction());
		return await limiters.getByName(await sha256(key)).consume(rules);
	} catch (error) {
		// Counting in this isolate alone is weaker, but better than refusing everyone or no one.
		console.error("rate limit: Durable Object unavailable, counting in this isolate", error);
		return local.consume(key, rules, Date.now());
	}
}

async function sha256(text: string) {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
