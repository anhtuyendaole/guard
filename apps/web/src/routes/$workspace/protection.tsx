import { createFileRoute, Link, notFound } from "@tanstack/react-router";
import { CircleCheck, CircleDashed, CircleMinus, EyeOff, TriangleAlert } from "lucide-react";
import { type ReactNode, useState } from "react";
import { Button } from "#/components/ui/button";
import { useWorkspace } from "#/components/workspace/context";
import { Notice } from "#/components/workspace/notice";
import { getProtection, type ProtectionRuleView, type ProtectionZoneView } from "#/lib/connections";
import { zoneDashboardUrl } from "#/lib/dashboard-links";
import { formatDateTime, formatRelative } from "#/lib/dates";
import {
	actionName,
	activityOf,
	type Check,
	type CheckStatus,
	checksOf,
	filterZones,
	type IssueId,
	overviewOf,
	STATUS_LABEL,
	sortZones,
} from "#/lib/protection";
import { useDocumentTitle } from "#/lib/title";
import { cn } from "#/lib/utils";

/** Everything this screen says, in one place, so it can be translated without hunting for it. */
const TEXT = {
	title: "Protection",
	intro:
		"What protects each of your Cloudflare zones, in plain words, and what its own rules have done. Guard only reads: every fix is made in Cloudflare.",
	empty: "No Cloudflare account connected.",
	hint: "Connect one to see what protects its zones.",
	toConnections: "Connections",
	missing: "Page not found",
	missingHint: "Check the address, or go back to your workspace.",
	noZones: "Guard has not listed any zone yet. The next scan does.",
	overviewHeading: "Across all zones",
	allFine: "Everything Guard can read looks fine on every zone.",
	allFineUnread: "Guard has not read any zone's protection yet. The next scan does.",
	filterHint: "Pick a line to show only the zones it is about.",
	showing: (shown: number, of: number) => `Showing ${shown} of ${of} zones`,
	showAll: "Show all zones",
	zonesHeading: "Zones",
	plan: (name: string) => `Plan: ${name}`,
	fromConnection: (name: string) => `From ${name}`,
	readAt: (when: string) => `Read ${when}`,
	notRead: "Not read yet",
	fix: "Fix in Cloudflare",
	fixLabel: (what: string, zone: string) => `Fix ${what} for ${zone} in Cloudflare`,
	toConnection: "Open Connections",
	checklist: "Checklist",
	rulesHeading: (n: number) => `Custom rules (${n})`,
	rulesNone: "This zone has no custom rules.",
	rulesUnread: "Custom rules are listed once Guard can read them.",
	ruleOn: "On",
	ruleOff: "Off",
	noDescription: "No description",
	changed: (when: string) => `Changed ${when}`,
	changedUnknown: "Change date not given",
	activityNote:
		"Activity comes from Traffic, which keeps only the top 10 rules of the 20 busiest zones for each day, from sampled events. A rule with no activity recorded may still have acted.",
	activityHint: "From sampled events, an estimate. A quiet rule may not be recorded at all.",
	status: STATUS_LABEL,
};

export const Route = createFileRoute("/$workspace/protection")({
	loader: async ({ params }) => {
		const page = await getProtection({ data: params.workspace });
		if (!page) throw notFound();
		return page;
	},
	component: ProtectionPage,
	notFoundComponent: () => <Notice title={TEXT.missing}>{TEXT.missingHint}</Notice>,
});

function ProtectionPage() {
	useDocumentTitle(TEXT.title);
	const page = Route.useLoaderData();
	const { slug } = useWorkspace();
	const [issue, setIssue] = useState<IssueId | null>(null);

	if (!page.hasConnections) {
		return (
			<div className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
				<h1 className="text-xl font-semibold tracking-tight">{TEXT.title}</h1>
				<Notice
					title={TEXT.empty}
					action={
						<Button asChild variant="outline">
							<Link to="/$workspace/connections" params={{ workspace: slug }}>
								{TEXT.toConnections}
							</Link>
						</Button>
					}
				>
					{TEXT.hint}
				</Notice>
			</div>
		);
	}

	const lines = overviewOf(page.zones);
	const shown = sortZones(filterZones(page.zones, issue));
	const anyRead = page.zones.some((zone) => zone.readAt !== null);
	const manyConnections = new Set(page.zones.map((zone) => zone.connectionId)).size > 1;

	return (
		<div className="mx-auto max-w-4xl space-y-6 px-4 py-10 sm:px-6">
			<div className="space-y-1">
				<h1 className="text-xl font-semibold tracking-tight">{TEXT.title}</h1>
				<p className="text-sm text-muted-foreground">{TEXT.intro}</p>
			</div>

			{page.zones.length === 0 ? (
				<p className="rounded-lg border p-4 text-sm text-muted-foreground">{TEXT.noZones}</p>
			) : (
				<>
					<section aria-labelledby="overview-heading" className="space-y-2">
						<h2 id="overview-heading" className="text-base font-semibold">
							{TEXT.overviewHeading}
						</h2>
						{lines.length === 0 ? (
							<p className="rounded-lg border p-4 text-sm text-muted-foreground">
								{anyRead ? TEXT.allFine : TEXT.allFineUnread}
							</p>
						) : (
							<>
								<ul className="space-y-2">
									{lines.map((line) => (
										<li key={line.id}>
											<button
												type="button"
												aria-pressed={issue === line.id}
												onClick={() => setIssue(issue === line.id ? null : line.id)}
												className={cn(
													"flex w-full items-start gap-3 rounded-lg border p-3 text-left text-sm transition-colors hover:bg-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring",
													issue === line.id && "border-foreground bg-accent",
												)}
											>
												{line.tone === "look" ? (
													<TriangleAlert
														className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
														aria-hidden
													/>
												) : (
													<EyeOff
														className="mt-0.5 size-4 shrink-0 text-muted-foreground"
														aria-hidden
													/>
												)}
												<span className="min-w-0 flex-1">{line.text}</span>
											</button>
										</li>
									))}
								</ul>
								<p className="text-xs text-muted-foreground">{TEXT.filterHint}</p>
							</>
						)}
					</section>

					<section aria-labelledby="zones-heading" className="space-y-3">
						<div className="flex flex-wrap items-center justify-between gap-2">
							<h2 id="zones-heading" className="text-base font-semibold">
								{TEXT.zonesHeading}
							</h2>
							<p role="status" className="text-sm text-muted-foreground">
								{TEXT.showing(shown.length, page.zones.length)}
								{issue !== null && (
									<>
										{" "}
										<button
											type="button"
											onClick={() => setIssue(null)}
											className="underline underline-offset-2"
										>
											{TEXT.showAll}
										</button>
									</>
								)}
							</p>
						</div>
						<ul className="space-y-4">
							{shown.map((zone) => (
								<ZoneCard
									key={`${zone.connectionId}/${zone.zoneId}`}
									zone={zone}
									showConnection={manyConnections}
									slug={slug}
								/>
							))}
						</ul>
					</section>
				</>
			)}
		</div>
	);
}

const STATUS_STYLE: Record<CheckStatus, { icon: ReactNode; text: string }> = {
	good: {
		icon: <CircleCheck className="size-4" aria-hidden />,
		text: "text-emerald-700 dark:text-emerald-400",
	},
	look: {
		icon: <TriangleAlert className="size-4" aria-hidden />,
		text: "text-amber-700 dark:text-amber-400",
	},
	neutral: {
		icon: <CircleMinus className="size-4" aria-hidden />,
		text: "text-muted-foreground",
	},
	unreadable: {
		icon: <EyeOff className="size-4" aria-hidden />,
		text: "text-muted-foreground",
	},
	unread: {
		icon: <CircleDashed className="size-4" aria-hidden />,
		text: "text-muted-foreground",
	},
};

/** The place in the dashboard where each check is changed. */
const FIX_PLACE = {
	managed: "security_rules",
	custom: "security_rules",
	rate_limit: "security_rules",
	bot: "security_settings",
	security_level: "security_settings",
} as const;

function ZoneCard({
	zone,
	showConnection,
	slug,
}: {
	zone: ProtectionZoneView;
	showConnection: boolean;
	slug: string;
}) {
	const checks = checksOf(zone);
	return (
		<li className="space-y-4 rounded-lg border p-4">
			<div className="space-y-1">
				<h3 className="wrap-anywhere font-medium">{zone.name}</h3>
				<p className="text-xs text-muted-foreground">
					{[
						showConnection ? TEXT.fromConnection(zone.connectionName) : null,
						zone.plan ? TEXT.plan(zone.plan) : null,
						zone.readAt === null ? TEXT.notRead : TEXT.readAt(formatRelative(zone.readAt)),
					]
						.filter(Boolean)
						.join(" · ")}
				</p>
			</div>
			<ul aria-label={TEXT.checklist} className="divide-y rounded-md border">
				{checks.map((one) => (
					<CheckRow key={one.key} check={one} zone={zone} slug={slug} />
				))}
			</ul>
			<Rules zone={zone} />
		</li>
	);
}

function CheckRow({ check, zone, slug }: { check: Check; zone: ProtectionZoneView; slug: string }) {
	const style = STATUS_STYLE[check.status];
	return (
		<li className="space-y-1 p-3 text-sm">
			<div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
				<p className="font-medium">{check.label}</p>
				<p className={cn("flex items-center gap-1.5 font-medium", style.text)}>
					{style.icon}
					<span>{TEXT.status[check.status]}</span>
				</p>
			</div>
			<p>{check.headline}</p>
			<p className="text-muted-foreground">{check.why}</p>
			{check.problem && <p className="text-muted-foreground">{check.problem}</p>}
			<div className="flex flex-wrap gap-x-4 gap-y-1 pt-0.5">
				{check.fix && (
					<a
						href={zoneDashboardUrl(zone.accountId, zone.name, FIX_PLACE[check.key])}
						target="_blank"
						rel="noreferrer noopener"
						aria-label={TEXT.fixLabel(check.label, zone.name)}
						className="underline underline-offset-2"
					>
						{TEXT.fix}
					</a>
				)}
				{check.status === "unreadable" && (
					<Link
						to="/$workspace/connections"
						params={{ workspace: slug }}
						className="underline underline-offset-2"
					>
						{TEXT.toConnection}
					</Link>
				)}
			</div>
		</li>
	);
}

function Rules({ zone }: { zone: ProtectionZoneView }) {
	const readable = zone.custom.state === "ok" || zone.custom.state === "none";
	return (
		<details className="group rounded-md border">
			<summary className="cursor-pointer p-3 text-sm font-medium focus-visible:outline-2 focus-visible:outline-ring">
				{TEXT.rulesHeading(zone.rules.length)}
			</summary>
			<div className="space-y-3 border-t p-3">
				{!readable ? (
					<p className="text-sm text-muted-foreground">{TEXT.rulesUnread}</p>
				) : zone.rules.length === 0 ? (
					<p className="text-sm text-muted-foreground">{TEXT.rulesNone}</p>
				) : (
					<>
						<ol className="space-y-3">
							{zone.rules.map((rule) => (
								<RuleItem key={rule.ruleId} rule={rule} />
							))}
						</ol>
						<p className="text-xs text-muted-foreground">{TEXT.activityNote}</p>
					</>
				)}
			</div>
		</details>
	);
}

function RuleItem({ rule }: { rule: ProtectionRuleView }) {
	const activity = activityOf(rule);
	const changed = rule.lastUpdated ? Date.parse(rule.lastUpdated) : Number.NaN;
	return (
		<li className="space-y-0.5 text-sm">
			<p className="wrap-anywhere font-medium">{rule.description || TEXT.noDescription}</p>
			<p className="text-xs text-muted-foreground">
				{actionName(rule.action)} ·{" "}
				<span className="font-medium">{rule.enabled ? TEXT.ruleOn : TEXT.ruleOff}</span> ·{" "}
				{Number.isNaN(changed) ? (
					TEXT.changedUnknown
				) : (
					<span title={formatDateTime(changed)}>{TEXT.changed(formatRelative(changed))}</span>
				)}
			</p>
			<p className="text-xs text-muted-foreground" title={TEXT.activityHint}>
				{activity.text}
			</p>
		</li>
	);
}
