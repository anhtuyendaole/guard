import type { ProtectionPartView, ProtectionZoneView } from "./connection-schemas";

// What the Protection page says about a zone, decided here and not in the page, so that the
// words, the statuses and the overview counts can be tested without a browser.

export type CheckKey = "managed" | "custom" | "rate_limit" | "bot" | "under_attack";

/**
 * How a check stands. `good` is as it should be, `look` is worth a look, `neutral` is a choice
 * (no custom rules, say) and not a fault, `unreadable` is what Guard could not read, and `unread`
 * is a zone no scan has reached yet.
 */
export type CheckStatus = "good" | "look" | "neutral" | "unreadable" | "unread";

export interface Check {
	key: CheckKey;
	/** What this check is called. */
	label: string;
	status: CheckStatus;
	/** What it is, in a few words: "3 rules, all on". */
	headline: string;
	/** One sentence on why it matters. */
	why: string;
	/** Whether the check has a "Fix in Cloudflare" link. */
	fix: boolean;
	/** For a check Guard could not read, what to do about it, in a line. */
	problem: string | null;
}

export const STATUS_LABEL: Readonly<Record<CheckStatus, string>> = {
	good: "Good",
	look: "Worth a look",
	neutral: "Not set up",
	unreadable: "Not readable",
	unread: "Not read yet",
};

/** The permission each check needs, as the connect form names it. */
export const PERMISSION: Readonly<Record<CheckKey, string>> = {
	managed: "Zone › WAF › Read",
	custom: "Zone › WAF › Read",
	rate_limit: "Zone › WAF › Read",
	bot: "Zone › Bot Management › Read",
	under_attack: "Zone › Zone Settings › Read",
};

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** What went wrong with a read. Names the permission only when it is the one that is missing. */
function problemOf(key: CheckKey, failure: string): string {
	switch (failure) {
		case "forbidden":
			return `The token cannot read this. Add ${PERMISSION[key]} (all zones) to it.`;
		case "unauthorized":
			return "Cloudflare refused the token. It may have been revoked or have expired.";
		case "rate_limited":
		case "unavailable":
			return "Cloudflare could not be reached or was limiting requests. Guard tries again within the hour.";
		case "not_found":
			return "Cloudflare did not show this to the token.";
		default:
			return "Cloudflare answered in a way Guard does not understand.";
	}
}

const WORDS: Readonly<Record<CheckKey, { label: string; why: string }>> = {
	managed: {
		label: "WAF managed rules",
		why: "Cloudflare keeps these rules up to date to stop common attacks on your sites without you writing anything.",
	},
	custom: {
		label: "Custom rules",
		why: "Your own rules for what to block, challenge or let through. A rule that is off does nothing.",
	},
	rate_limit: {
		label: "Rate limiting rules",
		why: "They slow down anyone who sends too many requests, such as a script guessing passwords.",
	},
	bot: {
		label: "Bot Fight Mode",
		why: "It challenges visitors that look like known bots, with no setup.",
	},
	// Cloudflare's "security level" now only turns Under Attack mode on or off: its other values
	// (essentially off to high) no longer change who is challenged
	// (developers.cloudflare.com/waf/tools/security-level/).
	under_attack: {
		label: "Under Attack mode",
		why: "It gives every visitor a challenge page, which is for a site under a DDoS attack and can block API clients.",
	},
};

type Judged = Pick<Check, "status" | "headline" | "fix"> & { why?: string };

function check(key: CheckKey, part: ProtectionPartView<unknown>, judge: () => Judged): Check {
	const base = { key, ...WORDS[key] };
	if (part.state === "unread") {
		return {
			...base,
			status: "unread",
			headline: "Not read yet",
			fix: false,
			problem: "The next scan reads this zone.",
		};
	}
	if (part.state === "failed") {
		return {
			...base,
			status: "unreadable",
			headline: "Guard could not read this",
			fix: false,
			problem: problemOf(key, part.failure),
		};
	}
	return { ...base, ...judge(), problem: null };
}

/** "3 rules, all on", "3 rules, 1 on" or "2 rules, all off", with the status they deserve. */
function rulesJudged(total: number, enabled: number): Judged {
	const rules = plural(total, "rule", "rules");
	if (enabled === 0) return { status: "look", headline: `${rules}, all off`, fix: true };
	return {
		status: "good",
		headline: enabled === total ? `${rules}, all on` : `${rules}, ${enabled} on`,
		fix: false,
	};
}

/** The five checks of a zone, in the order the page lists them. */
export function checksOf(zone: ProtectionZoneView): Check[] {
	return [
		check("managed", zone.managed, () => {
			const rulesets = zone.managed.state === "ok" ? zone.managed.value.rulesets : [];
			const on = rulesets.filter((set) => set.enabled);
			if (on.length === 0) {
				return {
					status: "look",
					headline: rulesets.length === 0 ? "Off" : "Deployed, but switched off",
					fix: true,
				};
			}
			const names = on.map((set) => set.name ?? "A managed ruleset");
			return { status: "good", headline: `On: ${names.join(", ")}`, fix: false };
		}),
		check("custom", zone.custom, () =>
			zone.custom.state === "ok"
				? rulesJudged(zone.custom.value.total, zone.custom.value.enabled)
				: { status: "neutral", headline: "No custom rules", fix: false },
		),
		check("rate_limit", zone.rateLimit, () =>
			zone.rateLimit.state === "ok"
				? rulesJudged(zone.rateLimit.value.total, zone.rateLimit.value.enabled)
				: { status: "neutral", headline: "No rate limiting rules", fix: false },
		),
		check("bot", zone.bot, () => {
			const fightMode = zone.bot.state === "ok" ? zone.bot.value.fightMode : null;
			if (fightMode === null) {
				return { status: "neutral", headline: "Cloudflare did not say", fix: false };
			}
			return fightMode
				? { status: "good", headline: "On", fix: false }
				: { status: "look", headline: "Off", fix: true };
		}),
		check("under_attack", zone.securityLevel, () => {
			const level = zone.securityLevel.state === "ok" ? zone.securityLevel.value.level : "";
			// Only `under_attack` is on. Any other value is the old security level, which does nothing.
			if (level === "under_attack") {
				return {
					status: "look",
					headline: "On: every visitor gets a challenge page",
					why: "Every visitor gets a challenge page, which can block API clients. Turn it off once an attack is over.",
					fix: true,
				};
			}
			return {
				status: "good",
				headline: "Off",
				why: "Turn it on only while a site is under a DDoS attack.",
				fix: false,
			};
		}),
	];
}

// --- The overview across zones -----------------------------------------------------------------

/** What a filter on the overview matches. */
export type IssueId =
	| "managed_off"
	| "bot_off"
	| "under_attack_on"
	| "missing_waf"
	| "missing_bot"
	| "missing_level";

export const ISSUE_IDS: readonly IssueId[] = [
	"managed_off",
	"bot_off",
	"under_attack_on",
	"missing_waf",
	"missing_bot",
	"missing_level",
];

const forbidden = (part: ProtectionPartView<unknown>) =>
	part.state === "failed" && part.failure === "forbidden";

/** The issues one zone has, which the overview counts and its filters match. */
export function issuesOf(zone: ProtectionZoneView): IssueId[] {
	const issues: IssueId[] = [];
	if (checksOf(zone).find((one) => one.key === "managed")?.status === "look") {
		issues.push("managed_off");
	}
	if (zone.bot.state === "ok" && zone.bot.value.fightMode === false) issues.push("bot_off");
	if (zone.securityLevel.state === "ok" && zone.securityLevel.value.level === "under_attack") {
		issues.push("under_attack_on");
	}
	if ([zone.custom, zone.managed, zone.rateLimit].some(forbidden)) issues.push("missing_waf");
	if (forbidden(zone.bot)) issues.push("missing_bot");
	if (forbidden(zone.securityLevel)) issues.push("missing_level");
	return issues;
}

export interface OverviewLine {
	id: IssueId;
	/** "Bot Fight Mode off on 21 of 30 zones". */
	text: string;
	zones: number;
	tone: "look" | "unreadable";
}

const ISSUE_TEXT: Readonly<
	Record<IssueId, { tone: OverviewLine["tone"]; text: (on: string) => string }>
> = {
	managed_off: { tone: "look", text: (on) => `WAF managed rules off on ${on}` },
	bot_off: { tone: "look", text: (on) => `Bot Fight Mode off on ${on}` },
	under_attack_on: { tone: "look", text: (on) => `Under Attack mode on for ${on}` },
	missing_waf: {
		tone: "unreadable",
		text: (on) => `WAF rules not readable on ${on}: add ${PERMISSION.managed} to the token`,
	},
	missing_bot: {
		tone: "unreadable",
		text: (on) => `Bot Fight Mode not readable on ${on}: add ${PERMISSION.bot} to the token`,
	},
	missing_level: {
		tone: "unreadable",
		text: (on) =>
			`Under Attack mode not readable on ${on}: add ${PERMISSION.under_attack} to the token`,
	},
};

/** "21 of 30 zones", or "1 zone" when that is all there is. */
function zonesText(n: number, of: number): string {
	return of === 1 ? "1 zone" : `${n} of ${of} zones`;
}

/**
 * One line per issue that any zone has, in a fixed order, each with how many of the zones it is
 * on. A zone no scan has read yet is left out of the count: it is not known to be fine or not.
 */
export function overviewOf(zones: readonly ProtectionZoneView[]): OverviewLine[] {
	const read = zones.filter((zone) => zone.readAt !== null);
	const counts = new Map<IssueId, number>();
	for (const zone of read) {
		for (const issue of issuesOf(zone)) counts.set(issue, (counts.get(issue) ?? 0) + 1);
	}
	return ISSUE_IDS.flatMap((id) => {
		const n = counts.get(id) ?? 0;
		if (n === 0) return [];
		const words = ISSUE_TEXT[id];
		return [{ id, zones: n, tone: words.tone, text: words.text(zonesText(n, read.length)) }];
	});
}

/** Zones that have the issue, or all of them for no filter. */
export function filterZones(
	zones: readonly ProtectionZoneView[],
	issue: IssueId | null,
): ProtectionZoneView[] {
	return issue === null ? [...zones] : zones.filter((zone) => issuesOf(zone).includes(issue));
}

/** Zones with the most that is worth a look first, then by name. */
export function sortZones(zones: readonly ProtectionZoneView[]): ProtectionZoneView[] {
	const looks = (zone: ProtectionZoneView) =>
		checksOf(zone).filter((one) => one.status === "look").length;
	return [...zones].sort(
		(a, b) => looks(b) - looks(a) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0),
	);
}

const ACTIONS: Readonly<Record<string, string>> = {
	block: "Block",
	challenge: "Challenge",
	js_challenge: "JS challenge",
	managed_challenge: "Managed challenge",
	skip: "Skip other rules",
	log: "Log only",
	allow: "Allow",
	execute: "Run a ruleset",
	connection_close: "Close the connection",
};

/** How a rule's action reads. One Cloudflare adds later is shown as it writes it. */
export function actionName(action: string): string {
	if (action === "") return "No action";
	return Object.hasOwn(ACTIONS, action) ? (ACTIONS[action] as string) : action.replaceAll("_", " ");
}

/**
 * What the page says of a rule's activity. Traffic keeps the top 10 rules of the 20 busiest zones
 * for each day, from sampled events, so a rule it has no row for may still have acted: the words
 * never say it did not.
 */
export function activityOf(rule: { acted: { count: number; days: number } | null }): {
	text: string;
	recorded: boolean;
} {
	if (rule.acted === null) return { text: "No activity recorded", recorded: false };
	const { count, days } = rule.acted;
	return {
		text: `About ${count.toLocaleString("en-US")} ${count === 1 ? "request" : "requests"} over ${plural(days, "recorded day", "recorded days")}`,
		recorded: true,
	};
}
