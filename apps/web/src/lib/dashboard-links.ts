/**
 * Where in the Cloudflare dashboard each protection is changed. The dashboard moves its pages from
 * time to time, so every path Guard links to is here and nowhere else. Paths follow the docs
 * (developers.cloudflare.com/waf/, /bots/get-started/bot-fight-mode/, /security/settings/), which
 * link to `…/<account>/<zone>/security/settings` and `…/security/security-rules`.
 */

const DASHBOARD = "https://dash.cloudflare.com";

export type DashboardPlace = "security_rules" | "security_settings" | "security_events";

const PATHS: Readonly<Record<DashboardPlace, string>> = {
	/** WAF custom rules, rate limiting rules and managed rules. */
	security_rules: "security/security-rules",
	/** Bot Fight Mode and the security level. */
	security_settings: "security/settings",
	/** What the rules did, as Cloudflare lists it. */
	security_events: "security/events",
};

/** A page of one zone, which the dashboard opens once the person is signed in. */
export function zoneDashboardUrl(
	accountId: string,
	zoneName: string,
	place: DashboardPlace,
): string {
	return `${DASHBOARD}/${encodeURIComponent(accountId)}/${encodeURIComponent(zoneName)}/${PATHS[place]}`;
}
